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

/// Number of consecutive channel-full (`TrySendError::Full`) drops on the same
/// target before further failures are silently discarded (no more log output).
/// The send is still attempted on every message so the channel can recover:
/// a successful send resets the counter back to zero. Only channel-full errors
/// accumulate strikes; closed channels (disconnected peers) are skipped
/// per-message without accumulating strikes, so reconnected peers can
/// immediately receive signals again. Truly stalled peers are reaped by
/// [`WS_IDLE_TIMEOUT`] rather than by sender-driven eviction, which would
/// allow a malicious sender to kick arbitrary targets by flooding their
/// channel.
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

/// Maximum messages a single sender may route to a single target within one
/// per-target window before further messages to that target are dropped.
/// Prevents one sender from filling a target's relay channel
/// ([`RELAY_CHANNEL_CAPACITY`] = 256) with garbage, which would cause
/// legitimate signalling messages from other peers to be silently dropped.
/// Set to 64: generous for legitimate mesh setup (~1 SDP + ~10 ICE per target)
/// but well below the channel capacity, leaving room for other senders.
const PER_TARGET_BURST_LIMIT: u32 = 64;

/// Interval at which per-target message counters are reset. Decoupled from
/// the token-bucket refill to prevent an attacker from keeping the bucket
/// below capacity (preventing the clear) while inserting unbounded unique
/// target keys.
const PER_TARGET_WINDOW: Duration = Duration::from_secs(1);

/// Maximum number of unique targets a single sender may address within one
/// [`PER_TARGET_WINDOW`]. Legitimate peers target at most the number of
/// peers in their room; an attacker forging random target IDs would quickly
/// exceed this cap. Set to 256 to comfortably cover large rooms while
/// bounding the memory footprint of the per-target map.
const MAX_UNIQUE_TARGETS: usize = 256;

/// Maximum allowed length (in bytes) for the `peer_id` field in a
/// [`SignalEnvelope`]. DIDs and UUIDs are well under 256 bytes; anything
/// larger is either malformed or an attempt to bloat per-target maps and
/// log output. Checked after deserialization to reject oversized fields
/// that fit within [`MAX_WS_MESSAGE_SIZE`] but are still abusive.
const MAX_PEER_ID_LENGTH: usize = 512;

/// Maximum time allowed for the authentication/identity extraction phase of
/// the WebSocket handshake. Prevents attackers from exhausting connection
/// slots by presenting DIDs that tarpit the HTTP fetch (e.g. a server that
/// holds the connection open for the full 10s DID fetch timeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time allowed for a single WebSocket write to complete.
/// Prevents a Slowloris variant where an attacker opens connections and
/// intentionally never drains their TCP receive buffer: the OS-level send
/// buffer fills, `ws_tx.send` blocks indefinitely, and the write task stalls
/// while the attacker's periodic client-side Pings keep the read-task idle
/// timeout from firing — permanently holding a connection slot.
const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
/// JWT will still be used for identity, and a missing token results in a random
/// UUID being assigned. However, an explicitly invalid (malformed, expired, or
/// signature-failing) token is always rejected with HTTP 401 regardless of
/// `auth_required`, to prevent split-brain where the client believes it is
/// authenticated by its DID while peers see it as an anonymous UUID.
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
            state.service_did.as_deref(),
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
    service_did: Option<&str>,
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

    match auth::validate_atproto_jwt(token, &resolver, service_did).await {
        Ok(identity) => Ok(Some(identity)),
        Err(e) => {
            tracing::warn!(error = %e, "JWT validation failed");
            // A token was explicitly provided — always reject it if invalid,
            // regardless of auth_required. Silently downgrading to a guest UUID
            // would create split-brain: the client believes it is authenticated
            // as its DID while peers see it as an anonymous UUID.
            Err((StatusCode::UNAUTHORIZED, "Invalid JWT"))
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
    // Both sends are wrapped in WS_WRITE_TIMEOUT: without it an attacker that
    // freezes their TCP receive window blocks these awaits indefinitely while
    // holding a connection slot — a Slowloris variant that bypasses the idle
    // timeout because the read/write tasks haven't been spawned yet.
    let welcome = serde_json::json!({ "type": "session_id", "id": session_id });
    if !matches!(
        tokio::time::timeout(
            WS_WRITE_TIMEOUT,
            ws_tx.send(Message::Text(welcome.to_string().into())),
        )
        .await,
        Ok(Ok(()))
    ) {
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
    if !matches!(
        tokio::time::timeout(
            WS_WRITE_TIMEOUT,
            ws_tx.send(Message::Text(peer_list.to_string().into())),
        )
        .await,
        Ok(Ok(()))
    ) {
        state
            .peers
            .remove_if(&session_id, |_, entry| entry.conn_id == conn_id);
        return;
    }

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
                    if !matches!(
                        tokio::time::timeout(WS_WRITE_TIMEOUT, ws_tx.send(Message::Text(json.into()))).await,
                        Ok(Ok(()))
                    ) {
                        tracing::warn!("disconnecting peer: write timeout or error");
                        break;
                    }
                }
                _ = ping_interval.tick() => {
                    if !matches!(
                        tokio::time::timeout(WS_WRITE_TIMEOUT, ws_tx.send(Message::Ping(vec![].into()))).await,
                        Ok(Ok(()))
                    ) {
                        tracing::warn!("disconnecting peer: write timeout or error");
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
        // Per-target message counters within the current per-target window.
        // Prevents a single sender from filling one target's relay channel
        // with garbage, which would cause legitimate signals from other senders
        // to be silently dropped (WebRTC negotiation sabotage).
        // Cleared on a fixed timer (PER_TARGET_WINDOW) rather than tied to
        // the token bucket refill, preventing an attacker from keeping the
        // bucket below capacity to avoid the clear while inserting unbounded
        // unique target keys.
        let mut per_target_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        let mut per_target_last_reset = tokio::time::Instant::now();
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

            // Reject oversized peer_id fields. DIDs and UUIDs are well
            // under 512 bytes; larger values bloat per-target maps, log
            // output, and tracing allocations.
            if envelope.peer_id.len() > MAX_PEER_ID_LENGTH {
                invalid_count += 1;
                tracing::warn!(
                    session = %session_id,
                    peer_id_len = envelope.peer_id.len(),
                    count = invalid_count,
                    "dropping signal with oversized peer_id (max {MAX_PEER_ID_LENGTH} bytes)"
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

            // Reject control signals from clients — only the relay may
            // originate PeerJoined/PeerLeft to prevent mesh spoofing.
            // Counts toward the invalid message limit to prevent attackers
            // from generating unlimited server-side log output.
            if matches!(
                envelope.signal,
                SignalPayload::PeerJoined(_) | SignalPayload::PeerLeft(_)
            ) {
                invalid_count += 1;
                tracing::warn!(
                    session = %session_id,
                    count = invalid_count,
                    "dropping forged control signal from client"
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

            // Per-sender token-bucket rate limiting: refill proportionally
            // to elapsed time, capped at RATE_BURST_CAPACITY.
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(rate_last_refill);
            if elapsed >= Duration::from_millis(50) {
                // Cap elapsed milliseconds to avoid u32 overflow on long-idle
                // connections (Ping/Pong keep-alive resets WS_IDLE_TIMEOUT but
                // not the rate limiter clock). The cap is high enough that the
                // refill always saturates RATE_BURST_CAPACITY.
                let elapsed_ms = (elapsed.as_millis() as u64).min(u32::MAX as u64) as u32;
                let refill = elapsed_ms.saturating_mul(RATE_REFILL_PER_SECOND) / 1000;
                // When integer division truncates to 0 (refill rate is low and
                // insufficient time has accumulated), skip the update entirely.
                // Advancing the timestamp without minting tokens would push
                // `rate_last_refill` into the future, causing
                // `now.duration_since(rate_last_refill)` to panic on the next
                // packet. The check fires again once enough time has elapsed.
                if refill > 0 {
                    let new_tokens = (rate_tokens + refill).min(RATE_BURST_CAPACITY);
                    rate_tokens = new_tokens;
                    // When the bucket fills to capacity, reset the clock to `now`
                    // so that saturating_mul overflow on very long-idle connections
                    // (e.g. ping-kept-alive for 49+ days) cannot cause the timer
                    // to fall behind and grant successive free max bursts. When
                    // the bucket is not full, advance proportionally to tokens
                    // minted to preserve sub-token remainder accumulation.
                    if new_tokens == RATE_BURST_CAPACITY {
                        rate_last_refill = now;
                    } else {
                        rate_last_refill += Duration::from_millis(
                            refill as u64 * 1000 / RATE_REFILL_PER_SECOND as u64,
                        );
                    }
                }
            }

            // Per-target window reset: clear counters on a fixed timer,
            // decoupled from the token bucket. This prevents an attacker
            // from suppressing the clear by keeping the bucket below capacity
            // while inserting unbounded unique target keys.
            if now.duration_since(per_target_last_reset) >= PER_TARGET_WINDOW {
                per_target_counts.clear();
                per_target_last_reset = now;
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

            // Unique target cap: reject senders addressing an absurd number
            // of distinct targets within one window. Legitimate peers target
            // at most the number of peers in their room; an attacker forging
            // random target IDs to bloat the map will hit this cap.
            if !per_target_counts.contains_key(&target_id)
                && per_target_counts.len() >= MAX_UNIQUE_TARGETS
            {
                tracing::warn!(
                    session = %session_id,
                    unique_targets = per_target_counts.len(),
                    "disconnecting peer: exceeded unique target cap ({MAX_UNIQUE_TARGETS})"
                );
                break;
            }

            // Per-target burst limit: prevent one sender from monopolising a
            // target's relay channel, which would starve legitimate signals
            // from other peers (WebRTC negotiation sabotage).
            let target_count = per_target_counts.entry(target_id.clone()).or_insert(0);
            if *target_count >= PER_TARGET_BURST_LIMIT {
                tracing::debug!(
                    session = %session_id,
                    target = %target_id,
                    limit = PER_TARGET_BURST_LIMIT,
                    "per-target burst limit reached, dropping signal"
                );
                continue;
            }
            *target_count += 1;

            let forwarded = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: envelope.signal,
            };

            // Check strike count but do NOT skip the send: we always probe
            // try_send so that a recovered (drained) channel resets the counter
            // via the Ok(()) arm. Skipping the send permanently blackholes the
            // target for the lifetime of the connection even after recovery.
            let at_strike_limit = backpressure_strikes
                .get(&target_id)
                .is_some_and(|s| *s >= MAX_BACKPRESSURE_STRIKES);

            if let Some(entry) = state_write.peers.get(&target_id) {
                if entry.value().room != room {
                    tracing::warn!(
                        session = %session_id,
                        target = %target_id,
                        "dropping cross-room signal"
                    );
                } else {
                    match entry.value().tx.try_send(forwarded) {
                        Ok(()) => {
                            // Successful send — reset strike counter for this target.
                            backpressure_strikes.remove(&target_id);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            if !at_strike_limit {
                                let strikes =
                                    backpressure_strikes.entry(target_id.clone()).or_insert(0);
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
                                        "target hit {MAX_BACKPRESSURE_STRIKES} backpressure \
                                         strikes; silencing logs until channel drains"
                                    );
                                }
                            }
                            // If already at limit, drop silently — the send was
                            // still attempted above so Ok(()) can still fire.
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Target peer disconnected but hasn't been cleaned
                            // up from the DashMap yet. Skip this message but do
                            // NOT permanently ban the target — if they reconnect,
                            // they'll get a fresh channel in the DashMap and we
                            // need to be able to deliver to it. The stale entry
                            // will be removed when its connection task finishes
                            // cleanup.
                            tracing::debug!(
                                target = %target_id,
                                "target channel closed, dropping this message"
                            );
                        }
                    }
                }
            } else {
                // Target disconnected — remove any orphaned backpressure
                // strike entry so it doesn't accumulate permanently over
                // long-lived connections that interact with many transient peers.
                backpressure_strikes.remove(&target_id);
                tracing::debug!(target = %target_id, "target peer not found, dropping signal");
            }
        }
    };

    // Either task finishing causes the other to be cleaned up.
    // Explicitly abort the write task when the read task ends (and vice
    // versa via channel closure) to avoid relying on implicit drop
    // propagation, which would silently leak the write task if any code
    // path accidentally held onto a Sender clone.
    let mut write_task = write_task;
    tokio::select! {
        _ = &mut write_task => {
            tracing::debug!(session = %session_id_write, "write task ended, stopping read");
        }
        _ = read_task => {
            tracing::debug!(session = %session_id_write, "read task ended, aborting write task");
            write_task.abort();
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
