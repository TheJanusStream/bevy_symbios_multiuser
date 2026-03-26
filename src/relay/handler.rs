use super::auth;
use super::did_resolver::DidResolver;
use super::{PeerEntry, RelayState};
use crate::protocol::{SignalEnvelope, SignalPayload};
use axum::{
    extract::{
        OriginalUri, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

/// RAII guard that decrements an atomic counter on drop.
///
/// Used for both the active connection counter and the handshake counter.
/// Ensures the counter is always decremented even if the task panics or the
/// `on_upgrade` callback is never executed.
struct AtomicGuard(Arc<AtomicUsize>);

impl Drop for AtomicGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Maximum number of queued outbound messages per peer before backpressure.
const RELAY_CHANNEL_CAPACITY: usize = 256;

/// Maximum size of a single incoming WebSocket message in bytes (64 KiB).
/// SDP offers/answers and ICE candidates are typically a few KiB at most.
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;

/// Total number of invalid messages (cumulative, not consecutive) before
/// disconnecting a peer. Not reset on valid messages to prevent attackers
/// from alternating valid/invalid messages to avoid the limit.
const MAX_INVALID_MESSAGES: usize = 10;

/// Number of consecutive backpressure hits (channel-full drops) on the same
/// target before the sender stops attempting delivery to that target for
/// the remainder of this connection. Truly stalled peers are reaped by
/// WS_IDLE_TIMEOUT rather than by sender-driven eviction, which would allow
/// a malicious sender to kick arbitrary targets by flooding their channel.
const MAX_BACKPRESSURE_STRIKES: usize = 50;

/// Maximum time a WebSocket connection may be idle (no messages received)
/// before the server disconnects it. Prevents Slowloris-style attacks where
/// an attacker opens `max_peers` connections and sends nothing, holding
/// connection slots indefinitely.
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Interval between server-initiated WebSocket Ping frames.
/// Browsers cannot initiate WebSocket pings (the API only supports *responding*
/// to pings), so WASM clients rely on the server to send pings to keep the
/// connection alive and prevent the [`WS_IDLE_TIMEOUT`] from firing.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum burst of messages a peer may send before being throttled.
/// Must accommodate WebRTC mesh initialization: joining a room with N peers
/// generates N SDP offers + ~3-10 ICE candidates each, all within milliseconds.
/// A burst of 500 allows joining rooms of ~40 peers without throttling.
const RATE_BURST_CAPACITY: u32 = 500;

/// Steady-state token refill rate (tokens per second). After the initial burst
/// is spent, peers are limited to this rate. Legitimate signalling rarely
/// exceeds a few messages per second outside the initial mesh setup.
const RATE_REFILL_PER_SECOND: u32 = 20;

/// Maximum time allowed for the authentication/identity extraction phase of
/// the WebSocket handshake. Prevents attackers from exhausting connection
/// slots by presenting DIDs that tarpit the HTTP fetch (e.g. a server that
/// holds the connection open for the full 10s DID fetch timeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Optional query parameters on the WebSocket upgrade URL.
///
/// Used as a legacy fallback for WASM clients that pass the ATProto JWT via
/// `?token=<jwt>`. The preferred WASM transport is the `Sec-WebSocket-Protocol`
/// subprotocol trick; this query parameter exists for compatibility.
#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    token: Option<String>,
}

/// Axum handler that upgrades an HTTP request to a WebSocket connection.
///
/// The URL path determines the peer's **room** — e.g. `wss://relay/game_A`
/// joins room `"game_A"`. Connecting to `/` joins the `"default"` room. Peers
/// only see and communicate with other peers in the same room.
///
/// When `auth_required` is enabled on the relay, the handler extracts an
/// ATProto JWT from one of three sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
/// 3. `?token=<token>` query parameter (legacy WASM fallback).
///
/// The token is validated and the authenticated DID becomes the peer's session
/// identity. Unauthenticated requests receive HTTP 401.
///
/// When `auth_required` is disabled, authentication is opportunistic: a valid
/// JWT will still be used for identity, but missing or invalid tokens are
/// silently ignored and a random UUID is assigned instead.
///
/// Connection capacity is enforced atomically *before* the async identity
/// extraction step to prevent concurrent handshakes from bypassing the limit.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(query): Query<WsQueryParams>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    // Extract the room from the URL path. Normalize so "/" and "" both map to
    // the same default room, and strip trailing slashes for consistency.
    let room = uri.path().trim_matches('/').to_string();
    let room = if room.is_empty() {
        "default".to_string()
    } else {
        room
    };
    // Atomically reserve a connection slot *before* the async identity
    // extraction to prevent TOCTOU bypasses where thousands of concurrent
    // handshakes all see `len < max_peers` before any inserts happen.
    let _conn_guard = if state.max_peers > 0 {
        let prev = state
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= state.max_peers {
            state
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return (StatusCode::SERVICE_UNAVAILABLE, "Relay is at capacity").into_response();
        }
        // RAII guard: if the on_upgrade callback is never executed (e.g. TCP
        // drops during the HTTP upgrade handshake), the guard's Drop impl
        // ensures the counter is still decremented.
        Some(AtomicGuard(Arc::clone(&state.active_connections)))
    } else {
        None
    };

    // Enforce a separate handshake slot limit so that tarpitted DID fetches
    // (e.g. attacker-controlled did:web servers that hold connections open)
    // cannot exhaust all connection slots. At most max_peers/4 connections
    // may be in the handshake phase simultaneously.
    let _handshake_guard = if state.max_handshakes > 0 {
        let prev = state
            .active_handshakes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= state.max_handshakes {
            state
                .active_handshakes
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            // _conn_guard drops here, decrementing the connection counter.
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many pending handshakes",
            )
                .into_response();
        }
        Some(AtomicGuard(Arc::clone(&state.active_handshakes)))
    } else {
        None
    };

    let identity = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        extract_identity(
            &headers,
            query.token.as_deref(),
            state.auth_required,
            state.did_resolver.as_ref(),
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!("identity extraction timed out, dropping connection");
            // _conn_guard drops here, decrementing the counter.
            return (StatusCode::GATEWAY_TIMEOUT, "Authentication timed out").into_response();
        }
    };

    // Handshake phase is over — release the handshake slot so it can be
    // reused by other incoming connections. The connection slot (_conn_guard)
    // remains held for the lifetime of the WebSocket session.
    drop(_handshake_guard);

    // If the client used the Sec-WebSocket-Protocol subprotocol trick to pass
    // the JWT, we must echo "access_token" back or the browser will abort.
    let used_subprotocol = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let parts: Vec<&str> = s.split(',').map(str::trim).collect();
            parts.len() == 2 && parts[0] == "access_token"
        })
        .unwrap_or(false);

    match identity {
        Err(rejection) => {
            // _conn_guard drops here, decrementing the counter.
            rejection.into_response()
        }
        Ok(id) => {
            let upgrade = ws.max_message_size(MAX_WS_MESSAGE_SIZE);
            let upgrade = if used_subprotocol {
                upgrade.protocols(["access_token"])
            } else {
                upgrade
            };
            upgrade
                .on_upgrade(move |socket| handle_socket(socket, state, id, room, _conn_guard))
                .into_response()
        }
    }
}

/// Attempt to extract a [`ValidatedIdentity`](auth::ValidatedIdentity) from
/// one of three sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
/// 3. `?token=<token>` query parameter (legacy WASM fallback).
///
/// Returns `Err` with a 401 response only when `auth_required` is true and
/// no valid token is found in any source.
async fn extract_identity(
    headers: &HeaderMap,
    query_token: Option<&str>,
    auth_required: bool,
    resolver: Option<&DidResolver>,
) -> Result<Option<auth::ValidatedIdentity>, (StatusCode, &'static str)> {
    // 1. Try the Authorization header first (native clients).
    let header_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    // 2. Fall back to Sec-WebSocket-Protocol subprotocol (WASM clients).
    //    The browser sends `Sec-WebSocket-Protocol: access_token, <jwt>`.
    let protocol_token = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let parts: Vec<&str> = s.split(',').map(str::trim).collect();
            if parts.len() == 2 && parts[0] == "access_token" {
                Some(parts[1])
            } else {
                None
            }
        });

    // 3. Fall back to query parameter (legacy WASM clients).
    let token = header_token.or(protocol_token).or(query_token);

    let Some(token) = token else {
        if auth_required {
            return Err((StatusCode::UNAUTHORIZED, "Authorization required"));
        }
        return Ok(None);
    };

    // Without a resolver, signature verification is impossible — trusting
    // unverified JWT claims would let anyone spoof any DID. Treat the token
    // as absent (caller gets a random UUID) unless auth is required, in
    // which case reject outright since we can't verify.
    let Some(resolver) = resolver else {
        if auth_required {
            return Err((StatusCode::UNAUTHORIZED, "No DID resolver configured"));
        }
        tracing::debug!("ignoring JWT — no DID resolver available to verify signature");
        return Ok(None);
    };

    match auth::validate_atproto_jwt(token, &resolver).await {
        Ok(identity) => Ok(Some(identity)),
        Err(e) => {
            tracing::warn!(error = %e, "JWT validation failed");
            if auth_required {
                Err((StatusCode::UNAUTHORIZED, "Invalid JWT"))
            } else {
                Ok(None)
            }
        }
    }
}

async fn handle_socket(
    socket: WebSocket,
    state: RelayState,
    identity: Option<auth::ValidatedIdentity>,
    room: String,
    _conn_guard: Option<AtomicGuard>,
) {
    let session_id = match identity {
        Some(ref id) => id.did.clone(),
        None => Uuid::new_v4().to_string(),
    };
    let conn_id = Uuid::new_v4();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (relay_tx, mut relay_rx) = mpsc::channel::<SignalEnvelope>(RELAY_CHANNEL_CAPACITY);

    // Atomically replace any existing connection for this session ID.
    // Using the `entry` API avoids a TOCTOU race where two concurrent
    // reconnects could both see `None` from `get()` and both `insert()`,
    // orphaning the first connection's write task.
    let old_entry_info = {
        use dashmap::mapref::entry::Entry;
        let new_peer = PeerEntry {
            tx: relay_tx,
            conn_id,
            room: room.clone(),
        };
        match state.peers.entry(session_id.clone()) {
            Entry::Occupied(mut occ) => {
                let old = occ.insert(new_peer);
                Some((old.room, old.tx))
            }
            Entry::Vacant(vac) => {
                vac.insert(new_peer);
                None
            }
        }
    };

    // If we replaced an old connection, notify peers in the OLD room and
    // drop the old sender (which will cause its write task to terminate).
    if let Some((old_room, _old_tx)) = old_entry_info {
        let leave_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
            .peers
            .iter()
            .filter(|entry| *entry.key() != session_id && entry.value().room == old_room)
            .map(|entry| entry.value().tx.clone())
            .collect();
        for sender in leave_senders {
            let envelope = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: SignalPayload::PeerLeft(session_id.clone()),
            };
            let _ = sender.try_send(envelope);
        }
        // _old_tx is dropped here, closing the old connection's relay channel.
        // Its write task will see `None` from `relay_rx.recv()` and exit.
    }

    // Announce the assigned session ID to the connecting client.
    let welcome = serde_json::json!({ "type": "session_id", "id": session_id });
    if ws_tx
        .send(Message::Text(welcome.to_string().into()))
        .await
        .is_err()
    {
        state
            .peers
            .remove_if(&session_id, |_, entry| entry.conn_id == conn_id);
        // _conn_guard drops here, decrementing the counter.
        return;
    }

    // Broadcast peer list to the new peer (same room only).
    let existing_peers: Vec<String> = state
        .peers
        .iter()
        .filter(|entry| *entry.key() != session_id && entry.value().room == room)
        .map(|entry| entry.key().clone())
        .collect();
    let peer_list = serde_json::json!({ "type": "peer_list", "peers": existing_peers });
    let _ = ws_tx
        .send(Message::Text(peer_list.to_string().into()))
        .await;

    // Notify existing peers in the same room about the new peer.
    // Collect senders first to avoid holding DashMap read locks across channel sends.
    let peer_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
        .peers
        .iter()
        .filter(|entry| *entry.key() != session_id && entry.value().room == room)
        .map(|entry| entry.value().tx.clone())
        .collect();
    for sender in peer_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id.clone(),
            signal: SignalPayload::PeerJoined(session_id.clone()),
        };
        let _ = sender.try_send(envelope);
    }

    let session_id_write = session_id.clone();
    let state_write = state.clone();

    // Forward messages from the relay channel to the WebSocket, and
    // periodically send Ping frames to keep the connection alive.
    // WASM clients (browsers) cannot initiate WebSocket pings — they only
    // *respond* to server pings — so without server-side pings, idle WASM
    // connections would be reaped by WS_IDLE_TIMEOUT.
    let write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(WS_PING_INTERVAL);
        // The first tick fires immediately; skip it so the first ping is
        // sent after one full interval.
        ping_interval.tick().await;

        loop {
            tokio::select! {
                envelope = relay_rx.recv() => {
                    let Some(envelope) = envelope else { break };
                    let json = match serde_json::to_string(&envelope) {
                        Ok(j) => j,
                        Err(_) => continue,
                    };
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                _ = ping_interval.tick() => {
                    if ws_tx.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Read messages from the WebSocket and route them to the target peer.
    // If the write task dies (e.g. broken connection), stop reading too.
    // Each read is wrapped in an idle timeout to reap Slowloris connections
    // that hold a slot without sending any data.
    let read_task = async {
        let mut invalid_count: usize = 0;
        // Per-target backpressure strike counters. When a target's channel is
        // full across many consecutive routing attempts, we stop trying to
        // deliver to that target from this sender. Stalled peers are reaped
        // by WS_IDLE_TIMEOUT instead of sender-driven eviction, preventing
        // a malicious sender from kicking arbitrary targets.
        let mut backpressure_strikes: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        // Per-sender token-bucket rate limiter with high burst capacity.
        // The burst allows WebRTC mesh initialization (N offers + N*K ICE
        // candidates) while the low refill rate caps sustained throughput.
        let mut rate_tokens: u32 = RATE_BURST_CAPACITY;
        let mut rate_last_refill = tokio::time::Instant::now();
        loop {
            let msg = match tokio::time::timeout(WS_IDLE_TIMEOUT, ws_rx.next()).await {
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(_))) => break, // WebSocket error
                Ok(None) => break,         // Stream ended
                Err(_) => {
                    tracing::info!(
                        session = %session_id,
                        timeout_secs = WS_IDLE_TIMEOUT.as_secs(),
                        "disconnecting idle peer (no messages received within timeout)"
                    );
                    break;
                }
            };
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                // Ping/Pong are legitimate keep-alive frames (axum/tungstenite
                // handles pong replies automatically but still yields them).
                // Do NOT count them toward invalid_count.
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => {
                    // Unexpected frame types (e.g. Binary) count as invalid
                    // to prevent attackers from spinning the loop.
                    invalid_count += 1;
                    if invalid_count >= MAX_INVALID_MESSAGES {
                        tracing::warn!(
                            session = %session_id,
                            "disconnecting peer after {MAX_INVALID_MESSAGES} invalid messages"
                        );
                        break;
                    }
                    continue;
                }
            };

            let envelope: SignalEnvelope = match serde_json::from_str(&text) {
                Ok(e) => e,
                Err(err) => {
                    invalid_count += 1;
                    tracing::warn!(
                        error = %err,
                        count = invalid_count,
                        "invalid signal envelope from peer"
                    );
                    if invalid_count >= MAX_INVALID_MESSAGES {
                        tracing::warn!(
                            session = %session_id,
                            "disconnecting peer after {MAX_INVALID_MESSAGES} invalid messages"
                        );
                        break;
                    }
                    continue;
                }
            };

            // Reject control signals from clients — only the relay may
            // originate PeerJoined/PeerLeft to prevent mesh spoofing.
            if matches!(
                envelope.signal,
                SignalPayload::PeerJoined(_) | SignalPayload::PeerLeft(_)
            ) {
                tracing::warn!(
                    session = %session_id,
                    signal = ?envelope.signal,
                    "dropping forged control signal from client"
                );
                continue;
            }

            // Per-sender token-bucket rate limiting: refill proportionally
            // to elapsed time, capped at RATE_BURST_CAPACITY.
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(rate_last_refill);
            if elapsed >= Duration::from_millis(50) {
                let refill = (elapsed.as_millis() as u32 * RATE_REFILL_PER_SECOND / 1000).max(1);
                rate_tokens = (rate_tokens + refill).min(RATE_BURST_CAPACITY);
                rate_last_refill = now;
            }
            if rate_tokens == 0 {
                tracing::warn!(
                    session = %session_id,
                    "disconnecting peer: rate limit exhausted (burst {RATE_BURST_CAPACITY}, \
                     refill {RATE_REFILL_PER_SECOND}/s)"
                );
                break;
            }
            rate_tokens -= 1;

            // Route to target peer, rewriting peer_id to the sender's ID.
            let target_id = envelope.peer_id.clone();

            // Reject self-targeting: a peer sending an SDP offer to itself
            // would force a pointless self-negotiation loop.
            if target_id == session_id {
                tracing::warn!(
                    session = %session_id,
                    "dropping self-targeted signal"
                );
                continue;
            }

            let forwarded = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: envelope.signal,
            };

            // Skip targets we've already given up on (backpressure maxed).
            if backpressure_strikes
                .get(&target_id)
                .is_some_and(|s| *s >= MAX_BACKPRESSURE_STRIKES)
            {
                continue;
            }

            if let Some(entry) = state_write.peers.get(&target_id) {
                if entry.value().room != room {
                    tracing::warn!(
                        session = %session_id,
                        target = %target_id,
                        "dropping cross-room signal"
                    );
                } else if let Err(mpsc::error::TrySendError::Full(_)) =
                    entry.value().tx.try_send(forwarded)
                {
                    let strikes = backpressure_strikes.entry(target_id.clone()).or_insert(0);
                    *strikes += 1;
                    tracing::warn!(
                        target = %target_id,
                        sender = %session_id,
                        strikes = *strikes,
                        "relay channel full for target, dropping signal (backpressure)"
                    );
                    if *strikes >= MAX_BACKPRESSURE_STRIKES {
                        tracing::warn!(
                            target = %target_id,
                            sender = %session_id,
                            "giving up on target after {MAX_BACKPRESSURE_STRIKES} \
                             consecutive backpressure hits (will drop future messages)"
                        );
                        // Don't remove the target — that would let a malicious
                        // sender kick other peers. Stalled peers will be reaped
                        // by WS_IDLE_TIMEOUT. We just stop trying from this sender.
                    }
                } else {
                    // Successful send — reset strike counter for this target.
                    backpressure_strikes.remove(&target_id);
                }
            } else {
                tracing::debug!(target = %target_id, "target peer not found, dropping signal");
            }
        }
    };

    // Either task finishing causes the other to be cleaned up.
    tokio::select! {
        _ = write_task => {
            tracing::debug!(session = %session_id_write, "write task ended, stopping read");
        }
        _ = read_task => {
            tracing::debug!(session = %session_id_write, "read task ended");
        }
    }

    // Cleanup: only remove the peer entry if it still belongs to *this*
    // connection. A reconnect may have already replaced it with a new sender.
    let was_removed = state
        .peers
        .remove_if(&session_id_write, |_, entry| entry.conn_id == conn_id);
    if was_removed.is_none() {
        // Another connection owns this session ID now — skip broadcast.
        // _conn_guard drops here, decrementing the counter.
        tracing::debug!(
            session = %session_id_write,
            "stale connection cleanup skipped (session was replaced)"
        );
        return;
    }
    let remaining_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
        .peers
        .iter()
        .filter(|entry| entry.value().room == room)
        .map(|entry| entry.value().tx.clone())
        .collect();
    for sender in remaining_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id_write.clone(),
            signal: SignalPayload::PeerLeft(session_id_write.clone()),
        };
        let _ = sender.try_send(envelope);
    }

    // _conn_guard drops here, decrementing the counter.
    tracing::info!(session = %session_id_write, "peer disconnected");
}
