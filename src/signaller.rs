//! Custom matchbox signaller that speaks the Symbios relay's wire format and
//! optionally authenticates with an ATProto JWT.
//!
//! Implements the [`SignallerBuilder`] and [`Signaller`] traits from
//! `matchbox_socket`, bridging between the matchbox `PeerRequest`/`PeerEvent`
//! protocol and the relay's [`SignalEnvelope`]/[`SignalPayload`] wire format.
//!
//! The plugin **always** uses this signaller (via
//! [`signaller_with_token_source`], [`signaller_for_session`], or
//! [`signaller_anonymous`]) so that the relay receives the expected
//! `SignalEnvelope` JSON, rather than matchbox's incompatible default format.
//! When a [`TokenSourceRes`] resource is present, the signaller uses the shared
//! token source for automatic refresh on reconnect. Otherwise, if an
//! [`AtprotoSession`](crate::auth::AtprotoSession) resource is present, the JWT
//! is cloned once and included in the WebSocket handshake. If neither is
//! available, the signaller connects without authentication (anonymous mode).
//!
//! # Platform Support
//!
//! On native targets, the WebSocket connection uses `async-tungstenite` with
//! the JWT passed as an `Authorization: Bearer <token>` header during the
//! upgrade handshake.
//!
//! On WASM targets, the browser's `WebSocket` API (via `ws_stream_wasm`) is
//! used instead. Because the browser `WebSocket` constructor does not support
//! custom headers, the JWT is passed via the `Sec-WebSocket-Protocol`
//! subprotocol trick: the client sends `["access_token", "<jwt>"]` as the
//! requested subprotocols during the handshake. The relay extracts the token
//! from the second element.
//!
//! # Token Refresh
//!
//! ATProto access tokens are short-lived. [`signaller_for_session`] clones the
//! JWT once at construction, so reconnects after token expiry will fail. For
//! long-lived applications, use [`signaller_with_token_source`] instead: it
//! accepts a shared [`TokenSource`] that the application can update externally
//! (e.g. after calling [`crate::auth::refresh_session`]), ensuring the
//! signaller always uses the latest token on reconnect.

use crate::protocol::{SignalEnvelope, SignalPayload};
#[allow(unused_imports)] // SinkExt is used by .send() inside async_trait impls
use futures_util::SinkExt;
use futures_util::StreamExt;
use matchbox_socket::async_trait::async_trait;
use matchbox_socket::{
    PeerEvent, PeerId, PeerRequest, PeerSignal, SignalingError, Signaller, SignallerBuilder,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// ── Native-only imports ──────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
use async_tungstenite::WebSocketStream;
#[cfg(not(target_arch = "wasm32"))]
use async_tungstenite::async_std::{ConnectStream, connect_async};
#[cfg(not(target_arch = "wasm32"))]
use async_tungstenite::tungstenite;

// ── WASM-only imports ────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
use ws_stream_wasm::{WsMessage as WasmWsMessage, WsMeta, WsStream};

// ── Shared constants & helpers ───────────────────────────────────────────────

/// Namespace UUID for deterministic `PeerId` generation from DID strings.
/// Produced by `Uuid::new_v5(Uuid::NAMESPACE_URL, b"symbios:did")`.
const DID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// Convert a session ID string to a [`PeerId`].
///
/// If the string is a valid UUID it is used directly. Otherwise (e.g. a DID),
/// a deterministic UUID v5 is derived so that the same session ID always
/// produces the same `PeerId`.
fn session_id_to_peer_id(session_id: &str) -> PeerId {
    match Uuid::parse_str(session_id) {
        Ok(uuid) => PeerId(uuid),
        Err(_) => PeerId(Uuid::new_v5(&DID_NAMESPACE, session_id.as_bytes())),
    }
}

// ── SignallerBuilder ─────────────────────────────────────────────────────────

/// Bevy [`Resource`](bevy::prelude::Resource) wrapper around a [`TokenSource`].
///
/// Insert this resource into the Bevy world to enable automatic token refresh
/// when using [`SymbiosMultiuserPlugin`](crate::plugin::SymbiosMultiuserPlugin).
/// The plugin prefers this over a static [`AtprotoSession`](crate::auth::AtprotoSession)
/// clone, so reconnects after token expiry use the latest refreshed JWT.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::{Arc, RwLock};
/// use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};
///
/// let source: TokenSource = Arc::new(RwLock::new(Some(session.access_jwt.clone())));
/// app.insert_resource(TokenSourceRes(source.clone()));
///
/// // Later, after refreshing:
/// *source.write().unwrap() = Some(new_jwt);
/// ```
#[derive(bevy::prelude::Resource, Clone)]
pub struct TokenSourceRes(pub TokenSource);

/// A shared, externally-refreshable token source.
///
/// The host application updates this (e.g. after an ATProto token refresh)
/// and the signaller reads the latest value on each reconnect attempt,
/// avoiding stale-JWT failures when short-lived access tokens expire
/// between the initial connection and a later reconnect.
///
/// # Safety note on `std::sync::RwLock` in async code
///
/// This intentionally uses `std::sync::RwLock` rather than `tokio::sync::RwLock`
/// because the lock is only held for a brief `.clone()` (never across `.await`
/// points). Do **not** hold a guard from this lock across an `.await` — if you
/// need longer-lived access, clone the inner value first and release the guard.
pub type TokenSource = Arc<std::sync::RwLock<Option<String>>>;

/// A [`SignallerBuilder`] that injects an ATProto JWT into the WebSocket
/// upgrade request's `Authorization` header.
///
/// Supports two token modes:
/// - **Static**: a fixed JWT cloned at construction (via [`signaller_for_session`]).
/// - **Refreshable**: a shared [`TokenSource`] that the application can update
///   externally (via [`signaller_with_token_source`]). On each reconnect the
///   builder reads the latest token, avoiding stale-JWT rejections.
#[derive(Debug, Clone)]
pub struct SymbiosSignallerBuilder {
    /// Static JWT, used when no `token_source` is provided.
    access_jwt: Option<String>,
    /// Shared, externally-refreshable token. When present, takes priority
    /// over `access_jwt` so reconnects use the latest refreshed token.
    token_source: Option<TokenSource>,
}

impl SymbiosSignallerBuilder {
    /// Return the current JWT, preferring the refreshable [`TokenSource`]
    /// over the static `access_jwt`.
    fn current_token(&self) -> Option<String> {
        if let Some(source) = &self.token_source {
            source.read().unwrap_or_else(|e| e.into_inner()).clone()
        } else {
            self.access_jwt.clone()
        }
    }
}

#[async_trait]
impl SignallerBuilder for SymbiosSignallerBuilder {
    async fn new_signaller(
        &self,
        mut attempts: Option<u16>,
        room_url: String,
    ) -> Result<Box<dyn Signaller>, SignalingError> {
        let signaller = 'connect: loop {
            let ws = match self.try_connect(&room_url).await {
                Ok(stream) => stream,
                Err(e) => {
                    if let Some(ref mut remaining) = attempts {
                        if *remaining <= 1 {
                            return Err(SignalingError::NegotiationFailed(Box::new(e)));
                        }
                        *remaining -= 1;
                        tracing::warn!(
                            attempts_remaining = *remaining,
                            "connection to relay failed, retrying in 3s"
                        );
                        futures_timer::Delay::new(Duration::from_secs(3)).await;
                        continue 'connect;
                    }
                    // Unlimited retries
                    tracing::warn!("connection to relay failed, retrying in 3s");
                    futures_timer::Delay::new(Duration::from_secs(3)).await;
                    continue 'connect;
                }
            };

            let mut signaller = SymbiosSignaller {
                ws,
                local_peer_id: PeerId(Uuid::nil()),
                session_to_peer: HashMap::new(),
                peer_to_session: HashMap::new(),
                pending_events: VecDeque::new(),
            };

            // Read the relay's welcome messages (session_id + peer_list).
            // If this fails, treat it like a connection failure and retry.
            match signaller.read_welcome().await {
                Ok(()) => break signaller,
                Err(e) => {
                    if let Some(ref mut remaining) = attempts {
                        if *remaining <= 1 {
                            return Err(e);
                        }
                        *remaining -= 1;
                        tracing::warn!(
                            attempts_remaining = *remaining,
                            "welcome handshake failed, retrying in 3s"
                        );
                        futures_timer::Delay::new(Duration::from_secs(3)).await;
                        continue 'connect;
                    }
                    tracing::warn!("welcome handshake failed, retrying in 3s");
                    futures_timer::Delay::new(Duration::from_secs(3)).await;
                    continue 'connect;
                }
            }
        };

        Ok(Box::new(signaller))
    }
}

/// Maximum time to wait for a WebSocket handshake to complete.
/// Without this, a tarpitted or firewall-dropped TCP connection can hold the
/// future pending forever, bypassing the retry loop entirely.
#[cfg(not(target_arch = "wasm32"))]
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

// ── Native connection ────────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
impl SymbiosSignallerBuilder {
    async fn try_connect(
        &self,
        room_url: &str,
    ) -> Result<WebSocketStream<ConnectStream>, SignalingError> {
        use futures_util::future::Either;

        let token = self.current_token();
        let request = build_ws_request(room_url, token.as_deref())
            .map_err(|e| SignalingError::UserImplementationError(e.to_string()))?;

        let connect_fut = connect_async(request);
        let timeout_fut = futures_timer::Delay::new(WS_CONNECT_TIMEOUT);
        futures_util::pin_mut!(connect_fut);
        futures_util::pin_mut!(timeout_fut);

        match futures_util::future::select(connect_fut, timeout_fut).await {
            Either::Left((result, _)) => {
                let (stream, _) = result.map_err(SignalingError::from)?;
                Ok(stream)
            }
            Either::Right(_) => Err(SignalingError::UserImplementationError(
                "WebSocket connection timed out".to_string(),
            )),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn build_ws_request(
    url: &str,
    access_jwt: Option<&str>,
) -> Result<tungstenite::http::Request<()>, tungstenite::http::Error> {
    let mut builder = tungstenite::http::Request::builder().uri(url);
    if let Some(token) = access_jwt {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    builder.body(())
}

// ── WASM connection ──────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
impl SymbiosSignallerBuilder {
    async fn try_connect(&self, room_url: &str) -> Result<WsStream, SignalingError> {
        // The browser WebSocket API does not support custom headers. We pass
        // the JWT via the Sec-WebSocket-Protocol header using the two-element
        // subprotocol trick: `["access_token", "<jwt>"]`. This avoids leaking
        // the token in URL query parameters (which are logged by proxies and
        // load balancers).
        let token = self.current_token();
        let protocols: Vec<&str> = match token.as_deref() {
            Some(t) => vec!["access_token", t],
            None => vec![],
        };

        let proto_refs: Vec<&str> = protocols.iter().copied().collect();
        let (_meta, stream) = WsMeta::connect(room_url, Some(proto_refs.as_slice()))
            .await
            .map_err(|e| SignalingError::UserImplementationError(e.to_string()))?;

        Ok(stream)
    }
}

// ── Signaller ────────────────────────────────────────────────────────────────

/// A [`Signaller`] that bridges between the matchbox protocol and the Symbios
/// relay's [`SignalEnvelope`] wire format.
pub struct SymbiosSignaller {
    #[cfg(not(target_arch = "wasm32"))]
    ws: WebSocketStream<ConnectStream>,
    #[cfg(target_arch = "wasm32")]
    ws: WsStream,
    local_peer_id: PeerId,
    session_to_peer: HashMap<String, PeerId>,
    peer_to_session: HashMap<PeerId, String>,
    pending_events: VecDeque<PeerEvent>,
}

impl SymbiosSignaller {
    /// Read the relay's two initial messages (`session_id` and `peer_list`)
    /// and buffer the corresponding `PeerEvent`s.
    async fn read_welcome(&mut self) -> Result<(), SignalingError> {
        // 1. session_id message
        let session_msg = self.read_text().await?;
        let session_json: serde_json::Value = serde_json::from_str(&session_msg).map_err(|e| {
            SignalingError::UserImplementationError(format!("invalid session_id message: {e}"))
        })?;

        let session_id = session_json
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SignalingError::UserImplementationError("missing 'id' in session_id message".into())
            })?;

        self.local_peer_id = session_id_to_peer_id(session_id);
        self.track_session(session_id.to_owned(), self.local_peer_id);
        self.pending_events
            .push_back(PeerEvent::IdAssigned(self.local_peer_id));

        // 2. peer_list message
        let peer_list_msg = self.read_text().await?;
        let peer_list_json: serde_json::Value =
            serde_json::from_str(&peer_list_msg).map_err(|e| {
                SignalingError::UserImplementationError(format!("invalid peer_list message: {e}"))
            })?;

        if let Some(peers) = peer_list_json.get("peers").and_then(|v| v.as_array()) {
            for peer_val in peers {
                if let Some(sid) = peer_val.as_str() {
                    let pid = self.get_or_create_peer_id(sid);
                    self.pending_events.push_back(PeerEvent::NewPeer(pid));
                }
            }
        }

        Ok(())
    }

    /// Look up or create a `PeerId` for the given session ID string.
    fn get_or_create_peer_id(&mut self, session_id: &str) -> PeerId {
        if let Some(&pid) = self.session_to_peer.get(session_id) {
            return pid;
        }
        let pid = session_id_to_peer_id(session_id);
        self.track_session(session_id.to_owned(), pid);
        pid
    }

    /// Insert a bidirectional mapping between session ID and PeerId.
    fn track_session(&mut self, session_id: String, peer_id: PeerId) {
        self.session_to_peer.insert(session_id.clone(), peer_id);
        self.peer_to_session.insert(peer_id, session_id);
    }

    /// Remove a peer from the ID maps and return its `PeerId`.
    fn remove_peer(&mut self, session_id: &str) -> PeerId {
        let pid = self
            .session_to_peer
            .remove(session_id)
            .unwrap_or_else(|| session_id_to_peer_id(session_id));
        self.peer_to_session.remove(&pid);
        pid
    }
}

// ── Platform-specific read_text / Signaller impl ─────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
impl SymbiosSignaller {
    /// Read the next text frame from the WebSocket (native).
    async fn read_text(&mut self) -> Result<String, SignalingError> {
        loop {
            match self.ws.next().await {
                Some(Ok(tungstenite::Message::Text(t))) => return Ok(t.to_string()),
                Some(Ok(tungstenite::Message::Close(_))) | None => {
                    return Err(SignalingError::StreamExhausted);
                }
                Some(Ok(_)) => continue, // skip pings, binary, etc.
                Some(Err(e)) => return Err(SignalingError::from(e)),
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl SymbiosSignaller {
    /// Read the next text frame from the WebSocket (WASM).
    async fn read_text(&mut self) -> Result<String, SignalingError> {
        loop {
            match self.ws.next().await {
                Some(WasmWsMessage::Text(t)) => return Ok(t),
                Some(WasmWsMessage::Binary(_)) => continue,
                None => return Err(SignalingError::StreamExhausted),
            }
        }
    }
}

#[async_trait]
impl Signaller for SymbiosSignaller {
    async fn send(&mut self, request: PeerRequest) -> Result<(), SignalingError> {
        match request {
            PeerRequest::Signal { receiver, data } => {
                let target_session = match self.peer_to_session.get(&receiver) {
                    Some(s) => s.clone(),
                    None => {
                        // Peer disconnected between the signal being queued and
                        // sent — this is a normal race condition, not fatal.
                        tracing::debug!(%receiver, "dropping signal to unknown peer (likely disconnected)");
                        return Ok(());
                    }
                };

                let signal = match data {
                    PeerSignal::Offer(sdp) => SignalPayload::Offer(sdp),
                    PeerSignal::Answer(sdp) => SignalPayload::Answer(sdp),
                    PeerSignal::IceCandidate(c) => SignalPayload::IceCandidate(c),
                };

                let envelope = SignalEnvelope {
                    peer_id: target_session,
                    signal,
                };
                let json = serde_json::to_string(&envelope)
                    .map_err(|e| SignalingError::UserImplementationError(e.to_string()))?;

                self.send_text(json).await
            }
            PeerRequest::KeepAlive => self.send_ping().await,
        }
    }

    async fn next_message(&mut self) -> Result<PeerEvent, SignalingError> {
        // Drain buffered events first (from welcome handshake).
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(event);
        }

        loop {
            let text = self.read_text().await?;

            // Try parsing as a SignalEnvelope (the normal case).
            if let Ok(envelope) = serde_json::from_str::<SignalEnvelope>(&text) {
                let sender_id = &envelope.peer_id;

                return match envelope.signal {
                    SignalPayload::Offer(sdp) => {
                        let pid = self.get_or_create_peer_id(sender_id);
                        Ok(PeerEvent::Signal {
                            sender: pid,
                            data: PeerSignal::Offer(sdp),
                        })
                    }
                    SignalPayload::Answer(sdp) => {
                        let pid = self.get_or_create_peer_id(sender_id);
                        Ok(PeerEvent::Signal {
                            sender: pid,
                            data: PeerSignal::Answer(sdp),
                        })
                    }
                    SignalPayload::IceCandidate(c) => {
                        let pid = self.get_or_create_peer_id(sender_id);
                        Ok(PeerEvent::Signal {
                            sender: pid,
                            data: PeerSignal::IceCandidate(c),
                        })
                    }
                    SignalPayload::PeerJoined(ref id) => {
                        let pid = self.get_or_create_peer_id(id);
                        Ok(PeerEvent::NewPeer(pid))
                    }
                    SignalPayload::PeerLeft(ref id) => {
                        let pid = self.remove_peer(id);
                        Ok(PeerEvent::PeerLeft(pid))
                    }
                };
            }

            // Unknown message format — skip and read the next one.
            tracing::debug!(msg = %text, "ignoring unrecognized relay message");
        }
    }
}

// ── Platform-specific send helpers ───────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
impl SymbiosSignaller {
    async fn send_text(&mut self, text: String) -> Result<(), SignalingError> {
        self.ws
            .send(tungstenite::Message::Text(text.into()))
            .await
            .map_err(SignalingError::from)
    }

    async fn send_ping(&mut self) -> Result<(), SignalingError> {
        self.ws
            .send(tungstenite::Message::Ping(vec![].into()))
            .await
            .map_err(SignalingError::from)
    }
}

#[cfg(target_arch = "wasm32")]
impl SymbiosSignaller {
    async fn send_text(&mut self, text: String) -> Result<(), SignalingError> {
        self.ws
            .send(WasmWsMessage::Text(text))
            .await
            .map_err(|e| SignalingError::UserImplementationError(e.to_string()))
    }

    async fn send_ping(&mut self) -> Result<(), SignalingError> {
        // The browser handles WebSocket pings/pongs automatically — no-op.
        Ok(())
    }
}

// ── Public constructor ───────────────────────────────────────────────────────

/// Create an [`Arc`]-wrapped [`SymbiosSignallerBuilder`] ready for use with
/// [`WebRtcSocketBuilder::signaller_builder`](matchbox_socket::WebRtcSocket).
///
/// The JWT is cloned once at construction. If the token expires before a
/// reconnect, prefer [`signaller_with_token_source`] instead.
pub fn signaller_for_session(session: &crate::auth::AtprotoSession) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: Some(session.access_jwt.clone()),
        token_source: None,
    })
}

/// Create a [`SymbiosSignallerBuilder`] backed by a shared [`TokenSource`].
///
/// On each reconnect attempt, the builder reads the latest token from the
/// source. The host application is responsible for updating the source when
/// tokens are refreshed (e.g. via [`crate::auth::refresh_session`]).
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::{Arc, RwLock};
/// use bevy_symbios_multiuser::signaller::{signaller_with_token_source, TokenSource};
///
/// let token_source: TokenSource = Arc::new(RwLock::new(Some(session.access_jwt.clone())));
/// let builder = signaller_with_token_source(token_source.clone());
///
/// // Later, after refreshing the session:
/// *token_source.write().unwrap() = Some(new_session.access_jwt.clone());
/// ```
pub fn signaller_with_token_source(source: TokenSource) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: None,
        token_source: Some(source),
    })
}

/// Create an anonymous [`SymbiosSignallerBuilder`] that connects without
/// authentication but still speaks the relay's [`SignalEnvelope`] wire format.
///
/// This ensures anonymous clients are understood by the relay, rather than
/// falling back to matchbox's default signaller which uses an incompatible
/// JSON format.
pub fn signaller_anonymous() -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: None,
        token_source: None,
    })
}
