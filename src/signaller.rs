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
//! token source for automatic refresh on reconnect. If no token source is
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

/// Namespace UUID for deterministic `PeerId` generation from DID strings
/// (`Uuid::NAMESPACE_X500` — `6ba7b814-9dad-11d1-80b4-00c04fd430c8`).
/// Using a fixed, well-known namespace ensures the same DID always maps to
/// the same `PeerId` regardless of when or where it is computed.
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

// ── Peer session map (PeerId → authenticated session_id / DID) ───────────────

/// Shared map from [`PeerId`] to the relay session identifier (typically the
/// authenticated DID) that the relay assigned to that peer.
///
/// The [`SymbiosSignaller`] mints a fresh random [`PeerId`] for every remote
/// peer it sees so that matchbox's per-peer WebRTC state machine cannot confuse
/// a reconnecting peer with stale state from the previous connection. That
/// choice breaks any attempt by the application to recover the real DID of a
/// peer directly from its `PeerId`, which in turn blocks DID-based identity
/// verification over the (unauthenticated) WebRTC data channel.
///
/// This map restores that binding: the signaller writes `(PeerId, session_id)`
/// pairs as peers join and removes them as peers leave, and the application
/// reads from it through [`PeerSessionMapRes`] to verify that a self-reported
/// identity payload really belongs to the peer the relay authenticated.
pub type PeerSessionMap = Arc<std::sync::RwLock<HashMap<PeerId, String>>>;

/// Bevy [`Resource`](bevy::prelude::Resource) wrapper around a
/// [`PeerSessionMap`].
///
/// The [`crate::plugin::SymbiosMultiuserPlugin`] inserts this resource
/// automatically and passes the inner [`PeerSessionMap`] to the signaller
/// builder so that the application and the signaller observe the same
/// `PeerId → session_id` view.
///
/// # Example — verifying a peer's DID claim
///
/// ```rust,ignore
/// use bevy::prelude::*;
/// use bevy_symbios_multiuser::prelude::*;
///
/// fn verify_identity(
///     map: Res<PeerSessionMapRes>,
///     peer_id: PeerId,
///     claimed_did: &str,
/// ) -> bool {
///     map.session_id(&peer_id).as_deref() == Some(claimed_did)
/// }
/// ```
#[derive(bevy::prelude::Resource, Clone)]
pub struct PeerSessionMapRes(pub PeerSessionMap);

impl Default for PeerSessionMapRes {
    fn default() -> Self {
        Self(Arc::new(std::sync::RwLock::new(HashMap::new())))
    }
}

impl PeerSessionMapRes {
    /// Look up the session ID (typically the authenticated DID) that the relay
    /// assigned to `peer_id`, if the signaller currently knows that peer.
    ///
    /// Returns `None` for unknown peers, and for the brief window between
    /// matchbox surfacing a [`PeerState::Connected`] event and the signaller
    /// recording the underlying session ID. Callers that need a strict check
    /// should treat `None` as "not yet verified" rather than "verified absent".
    pub fn session_id(&self, peer_id: &matchbox_socket::PeerId) -> Option<String> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_id)
            .cloned()
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
/// // Use the service auth token from `get_service_auth`, not `access_jwt`.
/// // Relay servers verify service auth tokens via DID document resolution;
/// // `access_jwt` is signed by the PDS service key and cannot be verified
/// // by a third-party relay.
/// let source: TokenSource = Arc::new(RwLock::new(Some(service_token)));
/// app.insert_resource(TokenSourceRes(source.clone()));
///
/// // Later, after refreshing the session and calling get_service_auth again:
/// *source.write().unwrap() = Some(new_service_token);
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
///
/// In particular, **never hold the write guard while awaiting a network call**
/// (e.g. `get_service_auth`). The signaller's `new_signaller` task acquires the
/// read lock on every reconnect attempt; if the write lock is held for the
/// duration of an async HTTP request, that reconnect will block indefinitely.
/// The correct pattern is to complete the async call first, then acquire the
/// write lock only for the instant needed to swap the value:
///
/// ```rust,ignore
/// let new_token = get_service_auth(...).await?;   // network call — no lock held
/// *token_source.write().unwrap() = Some(new_token); // lock held only for swap
/// ```
pub type TokenSource = Arc<std::sync::RwLock<Option<String>>>;

/// A [`SignallerBuilder`] that injects an ATProto JWT into the WebSocket
/// upgrade request's `Authorization` header.
///
/// Supports three token modes:
/// - **Static**: a fixed JWT cloned at construction (via [`signaller_for_session`]).
/// - **Refreshable**: a shared [`TokenSource`] that the application can update
///   externally (via [`signaller_with_token_source`]). On each reconnect the
///   builder reads the latest token, avoiding stale-JWT rejections.
/// - **Anonymous**: no JWT at all (via [`signaller_anonymous`]). Still speaks
///   the relay's `SignalEnvelope` wire format; connects without authentication.
#[derive(Debug, Clone)]
pub struct SymbiosSignallerBuilder {
    /// Static JWT, used when no `token_source` is provided.
    access_jwt: Option<String>,
    /// Shared, externally-refreshable token. When present, takes priority
    /// over `access_jwt` so reconnects use the latest refreshed token.
    token_source: Option<TokenSource>,
    /// Shared `PeerId → session_id` map updated by the signaller as peers
    /// join and leave. When present, the application can resolve the real
    /// (relay-authenticated) DID for any active peer.
    session_map: Option<PeerSessionMap>,
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

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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
                    // HTTP 4xx errors are permanent client-side rejections (e.g. 401
                    // Invalid JWT). Retrying won't help — surface them immediately.
                    if is_http_client_error(&e) {
                        return Err(e);
                    }
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
                session_map: self.session_map.clone(),
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

/// Returns `true` if the error was tagged by `try_connect` as an HTTP 4xx response.
///
/// 4xx errors are permanent client-side rejections (e.g. 401 Invalid JWT,
/// 403 Forbidden). The retry loop uses this to bail out immediately instead
/// of burning through all reconnect attempts on a deterministic failure.
fn is_http_client_error(e: &SignalingError) -> bool {
    matches!(e, SignalingError::UserImplementationError(s) if s.starts_with("http_client_error:"))
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
                let (stream, _) = result.map_err(|e| {
                    // Surface HTTP 4xx errors as a distinct variant so the retry loop
                    // can fast-fail without wasting reconnect attempts on auth failures.
                    if let tungstenite::Error::Http(ref resp) = e {
                        let code = resp.status().as_u16();
                        if resp.status().is_client_error() {
                            tracing::error!(
                                status = code,
                                "relay rejected connection (HTTP 4xx) — not retrying"
                            );
                            return SignalingError::UserImplementationError(format!(
                                "http_client_error:{code}"
                            ));
                        }
                    }
                    SignalingError::from(e)
                })?;
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
) -> Result<tungstenite::http::Request<()>, tungstenite::Error> {
    // <-- Changed return type here
    use tungstenite::client::IntoClientRequest;

    // 1. Let tungstenite parse the URL and automatically generate all the
    // mandatory WebSocket headers (Upgrade, Connection, Sec-WebSocket-Key)
    let mut request = url.into_client_request()?;

    // 2. Inject our ATProto JWT into the pre-formatted request
    if let Some(token) = access_jwt {
        let header_value = format!("Bearer {token}")
            .parse::<tungstenite::http::HeaderValue>()
            .map_err(|e| tungstenite::Error::HttpFormat(e.into()))?;
        request.headers_mut().insert("Authorization", header_value);
    }

    Ok(request)
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

        let (_meta, stream) = WsMeta::connect(room_url, Some(protocols))
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
    /// Shared `PeerId → session_id` view that the application reads through
    /// [`PeerSessionMapRes`]. `None` if no map was threaded through the
    /// builder (e.g. crate consumers that never need DID verification).
    session_map: Option<PeerSessionMap>,
}

impl SymbiosSignaller {
    /// Publish a peer → session binding to the shared map, if the application
    /// provided one. Called whenever the signaller learns a new peer.
    fn publish_peer(&self, peer: PeerId, session_id: &str) {
        if let Some(map) = &self.session_map {
            map.write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer, session_id.to_owned());
        }
    }

    /// Remove a peer binding from the shared map when the relay reports the
    /// peer has left.
    fn unpublish_peer(&self, peer: &PeerId) {
        if let Some(map) = &self.session_map {
            map.write().unwrap_or_else(|e| e.into_inner()).remove(peer);
        }
    }
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
    ///
    /// A fresh random UUID is assigned to each new mapping so that reconnecting
    /// peers (same session ID after `PeerLeft`) receive a distinct `PeerId`.
    /// This prevents matchbox's per-peer WebRTC state machine from confusing a
    /// new connection attempt with the stale state left by the previous one.
    fn get_or_create_peer_id(&mut self, session_id: &str) -> PeerId {
        if let Some(&pid) = self.session_to_peer.get(session_id) {
            return pid;
        }
        let pid = PeerId(Uuid::new_v4());
        self.track_session(session_id.to_owned(), pid);
        pid
    }

    /// Insert a bidirectional mapping between session ID and PeerId.
    ///
    /// Also publishes the mapping to the shared [`PeerSessionMap`] (if
    /// present) so the host application can verify identity claims from this
    /// peer. The only entry that is *not* exposed via the map is the local
    /// peer — the map is intended for identifying *remote* peers that signed
    /// messages over the data channel, which the local peer never needs to do
    /// against itself.
    fn track_session(&mut self, session_id: String, peer_id: PeerId) {
        self.session_to_peer.insert(session_id.clone(), peer_id);
        self.peer_to_session.insert(peer_id, session_id.clone());
        if peer_id != self.local_peer_id {
            self.publish_peer(peer_id, &session_id);
        }
    }

    /// Remove a peer from the ID maps and return its `PeerId`.
    fn remove_peer(&mut self, session_id: &str) -> PeerId {
        let pid = self
            .session_to_peer
            .remove(session_id)
            .unwrap_or_else(|| session_id_to_peer_id(session_id));
        self.peer_to_session.remove(&pid);
        self.unpublish_peer(&pid);
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

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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
                        let _pid = self.get_or_create_peer_id(id);
                        continue;
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
///
/// # Note on relay authentication
///
/// This function stores the `access_jwt` from the session. The Symbios relay
/// verifies tokens by resolving the user's DID document and checking the
/// `#atproto` signing key — it **cannot** verify `access_jwt`, because that
/// token is signed by the PDS's own service key, not the user's key. For
/// authenticated relay connections (`auth_required = true`), obtain a service
/// auth token via [`crate::auth::get_service_auth`] and use
/// [`signaller_with_token_source`] with a [`TokenSource`] wrapping that token.
pub fn signaller_for_session(session: &crate::auth::AtprotoSession) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: Some(session.access_jwt.clone()),
        token_source: None,
        session_map: None,
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
/// use bevy_symbios_multiuser::auth::{get_service_auth, refresh_session};
///
/// // Use the service auth token from `get_service_auth`, not `access_jwt`.
/// // The Symbios relay verifies tokens via DID document resolution; `access_jwt`
/// // is signed by the PDS service key and cannot be verified that way.
/// let service_token = get_service_auth(&client, &session, pds_url, relay_did).await?;
/// let token_source: TokenSource = Arc::new(RwLock::new(Some(service_token)));
/// let builder = signaller_with_token_source(token_source.clone());
///
/// // Later, when the service token is near expiry, refresh both tokens and update:
/// let new_session = refresh_session(&client, &session, pds_url).await?;
/// let new_token = get_service_auth(&client, &new_session, pds_url, relay_did).await?;
/// *token_source.write().unwrap() = Some(new_token);
/// ```
pub fn signaller_with_token_source(source: TokenSource) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: None,
        token_source: Some(source),
        session_map: None,
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
        session_map: None,
    })
}

/// Create a [`SymbiosSignallerBuilder`] with a shared [`PeerSessionMap`].
///
/// The builder carries `session_map` forward to every [`SymbiosSignaller`] it
/// produces, so reconnects keep populating the same map and the application's
/// [`PeerSessionMapRes`] view stays consistent.
///
/// Anonymous (no-JWT) variant. For authenticated variants, prefer
/// [`signaller_for_session_with_map`] or
/// [`signaller_with_token_source_and_map`].
pub fn signaller_anonymous_with_map(session_map: PeerSessionMap) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: None,
        token_source: None,
        session_map: Some(session_map),
    })
}

/// Authenticated static-JWT variant of [`signaller_anonymous_with_map`].
pub fn signaller_for_session_with_map(
    session: &crate::auth::AtprotoSession,
    session_map: PeerSessionMap,
) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: Some(session.access_jwt.clone()),
        token_source: None,
        session_map: Some(session_map),
    })
}

/// Refreshable-token variant of [`signaller_anonymous_with_map`].
pub fn signaller_with_token_source_and_map(
    source: TokenSource,
    session_map: PeerSessionMap,
) -> Arc<dyn SignallerBuilder> {
    Arc::new(SymbiosSignallerBuilder {
        access_jwt: None,
        token_source: Some(source),
        session_map: Some(session_map),
    })
}
