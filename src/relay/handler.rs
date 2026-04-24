use super::auth;
use super::did_resolver::DidResolver;
use super::{PeerEntry, RelayState};
use crate::protocol::{SignalEnvelope, SignalPayload};
use axum::{
    extract::{
        OriginalUri, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
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

/// Cumulative channel-full (`TrySendError::Full`) drops on the same target
/// after which further channel-full warnings are silenced for that target
/// (the silencer "arms"). The send is still attempted on every message so
/// the channel can recover: each successful send is treated as a leaky-bucket
/// drip that decrements the strike count by one. Once the counter reaches
/// [`SILENCER_REARM_THRESHOLD`] the silencer disarms again.
///
/// Reset-on-success was deliberately replaced with leaky decrement to defeat
/// a log-amplification attack where the attacker oscillates around the
/// channel-full boundary: at the old behavior, draining a single message
/// would zero the counter and re-arm the per-strike logging path, letting
/// the attacker emit a fresh batch of warnings on every cycle. The leaky
/// bucket plus a `silenced` flag bound the worst case to two log lines per
/// (silencer-disarm → silencer-rearm) cycle, regardless of how the attacker
/// times the flood.
///
/// Only channel-full errors accumulate strikes; closed channels (disconnected
/// peers) are skipped per-message without accumulating strikes, so reconnected
/// peers can immediately receive signals again. Truly stalled peers are reaped
/// by [`WS_IDLE_TIMEOUT`] rather than by sender-driven eviction, which would
/// allow a malicious sender to kick arbitrary targets by flooding their channel.
const MAX_BACKPRESSURE_STRIKES: usize = 50;

/// Hard cap on the per-target leaky-bucket strike counter. Once the silencer
/// is armed, further channel-full events keep incrementing the counter (so
/// that recovery requires a sustained drain rather than a single success),
/// but capping at this value bounds the number of subsequent successful
/// sends required to disarm the silencer. Set to twice [`MAX_BACKPRESSURE_STRIKES`]
/// so a sustained flood is bounded but recovery is still possible without
/// the connection lingering in a perpetually-silenced state.
const MAX_BACKPRESSURE_STRIKE_CAP: usize = MAX_BACKPRESSURE_STRIKES * 2;

/// Strike count at which a previously-armed silencer disarms. Set to zero
/// so the silencer only resets after a full drain, preventing the attacker
/// from maintaining a steady-state strike count just below
/// [`MAX_BACKPRESSURE_STRIKES`] that triggers fresh logging on every dip.
const SILENCER_REARM_THRESHOLD: usize = 0;

/// Minimum time between successive "channel full" warnings for the same
/// target. Entries in the backpressure map are retained for at least this
/// long after the strike counter drains to zero, preventing an attacker from
/// bypassing the silencer by draining a single message (strikes = 1 → 0 →
/// entry removed → fresh entry → `was_clean` → log). With this hysteresis,
/// the worst case is one warning per target per cooldown window regardless
/// of how the attacker times the flood.
const BACKPRESSURE_LOG_COOLDOWN: Duration = Duration::from_secs(30);

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

/// Per-peer signal budget assumed for full WebRTC mesh initialization. A peer
/// joining a room of N other peers needs to exchange roughly:
/// - 1 SDP offer per remote peer
/// - 1 SDP answer per remote peer (for the inbound side)
/// - ~10 trickled ICE candidates per remote peer
///
/// Round to 16 messages per peer to leave headroom. Used to scale both the
/// per-sender token-bucket burst and the unique-target cap from the operator's
/// configured `max_peers`, so legitimate mesh init never trips the limiter
/// regardless of room size. Without this, the hard-coded burst (previously 500)
/// silently dropped signaling messages for any room larger than ~40 peers,
/// permanently fragmenting the WebRTC mesh.
const SIGNALS_PER_REMOTE_PEER: u32 = 16;

/// Floor on the per-sender token-bucket burst capacity. The actual burst is
/// `max(RATE_BURST_FLOOR, max_peers * SIGNALS_PER_REMOTE_PEER)` so small relays
/// still get a generous initial burst, and large relays scale automatically.
const RATE_BURST_FLOOR: u32 = 1024;

/// Cap on the per-sender token-bucket burst capacity. Bounds the worst-case
/// memory footprint and per-connection log noise while still being far above
/// any plausible mesh init for the largest realistic relay deployments.
const RATE_BURST_CEILING: u32 = 16_384;

/// Steady-state token refill rate (tokens per second). After the initial burst
/// is spent, peers are limited to this rate. Legitimate signalling rarely
/// exceeds a few messages per second outside the initial mesh setup.
const RATE_REFILL_PER_SECOND: u32 = 20;

/// Maximum messages a single sender may route to a single target within one
/// per-target window before further messages to that target are dropped.
/// Prevents one sender from filling a target's relay channel
/// ([`RELAY_CHANNEL_CAPACITY`] = 256) with garbage, which would cause
/// legitimate signalling messages from other peers to be silently dropped.
///
/// Set to 16 — tight enough that a single sender can contribute at most
/// ~6% of [`RELAY_CHANNEL_CAPACITY`]. Combined with [`TARGET_KICK_STRIKES`],
/// filling a victim's channel to the point of eviction now requires ~16
/// coordinated attackers within one per-target window, an order of magnitude
/// harder than the previous 4-attacker threshold at `PER_TARGET_BURST_LIMIT = 64`.
/// Still comfortably above a legitimate mesh-init cost of ~1 SDP + ~10 ICE
/// candidates per target.
const PER_TARGET_BURST_LIMIT: u32 = 16;

/// Aggregate backpressure strikes (across all senders) after which the
/// target peer is kicked. Strikes are incremented on every `TrySendError::Full`
/// and decremented on every successful send, so a target whose channel is
/// genuinely draining never reaches this threshold.
///
/// Set equal to [`RELAY_CHANNEL_CAPACITY`] so that triggering requires the
/// channel to have held at full capacity for an equivalent number of failed
/// sends net of recoveries — a transient burst during mesh init cannot
/// trigger eviction. The rationale for kicking (rather than silently
/// dropping) is that WebRTC's signaling layer does not retransmit SDP
/// offers or ICE candidates: blackholing them permanently stalls the mesh,
/// while disconnecting the target surfaces a hard error that the client's
/// reconnect logic can recover from.
///
/// This reopens the "kick arbitrary target by flooding" vector that the
/// leaky-bucket silencer was originally designed to avoid, but [`PER_TARGET_BURST_LIMIT`]
/// caps each attacker's contribution to `PER_TARGET_BURST_LIMIT` strikes per
/// window, so no single peer can trigger the kick on its own.
const TARGET_KICK_STRIKES: u64 = RELAY_CHANNEL_CAPACITY as u64;

/// Interval at which per-target message counters are reset. Decoupled from
/// the token-bucket refill to prevent an attacker from keeping the bucket
/// below capacity (preventing the clear) while inserting unbounded unique
/// target keys.
const PER_TARGET_WINDOW: Duration = Duration::from_secs(1);

/// Floor on the unique-target cap. The actual cap is
/// `max(MAX_UNIQUE_TARGETS_FLOOR, max_peers)` so the limit always covers a
/// full-mesh send to every other peer in the room, regardless of how the
/// operator has configured `max_peers`. Without this scaling, a hard-coded
/// 256 cap caused any peer joining a room with >256 participants to be
/// instantly disconnected on its very first burst of SDP offers.
const MAX_UNIQUE_TARGETS_FLOOR: usize = 256;

/// Cap on the unique-target limit even when `max_peers` is `0` (unlimited)
/// or extremely large. Bounds the per-connection HashMap memory footprint
/// while still being well above any realistic single-room peer count.
const MAX_UNIQUE_TARGETS_CEILING: usize = 4096;

/// Compute the per-sender token-bucket burst capacity for the configured
/// relay capacity. Scaled so that joining a maximally-full room never trips
/// the rate limiter on legitimate WebRTC mesh setup.
fn rate_burst_for(max_peers: usize) -> u32 {
    let scaled = (max_peers as u64).saturating_mul(SIGNALS_PER_REMOTE_PEER as u64);
    let scaled = scaled.min(RATE_BURST_CEILING as u64) as u32;
    scaled.max(RATE_BURST_FLOOR)
}

/// Compute the unique-target cap for the configured relay capacity. Sized so
/// that a peer can address every other peer in the room within a single
/// [`PER_TARGET_WINDOW`] without tripping the cap.
fn unique_targets_for(max_peers: usize) -> usize {
    if max_peers == 0 {
        return MAX_UNIQUE_TARGETS_CEILING;
    }
    max_peers.clamp(MAX_UNIQUE_TARGETS_FLOOR, MAX_UNIQUE_TARGETS_CEILING)
}

/// Maximum time allowed for the authentication/identity extraction phase of
/// the WebSocket handshake. Prevents attackers from exhausting connection
/// slots by presenting DIDs that tarpit the HTTP fetch (e.g. a server that
/// holds the connection open for the full 10s DID fetch timeout).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard cap on simultaneously in-flight handshakes when `max_peers` is `0`
/// ("unlimited"). Without this cap, an unlimited-peers configuration would
/// disable the handshake tarpit budget entirely, allowing an attacker to
/// open tens of thousands of TCP connections and tie them all up in the
/// 15-second authentication phase before any idle timeout could reap them.
/// The fixed value is high enough to never throttle legitimate traffic
/// against a normally-loaded relay while still bounding attacker resource
/// consumption.
const UNLIMITED_HANDSHAKE_BUDGET: usize = 256;

/// Maximum time allowed for a single WebSocket write to complete.
/// Prevents a Slowloris variant where an attacker opens connections and
/// intentionally never drains their TCP receive buffer: the OS-level send
/// buffer fills, `ws_tx.send` blocks indefinitely, and the write task stalls
/// while the attacker's periodic client-side Pings keep the read-task idle
/// timeout from firing — permanently holding a connection slot.
const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Remove this connection's entry from the room's inner map if it still
/// belongs to `conn_id` (i.e. a reconnect has not already replaced us) and
/// GC the room itself when the removal leaves it empty.
///
/// The room GC uses [`DashMap::remove_if`] with an `is_empty()` predicate so
/// that the outer shard write lock is held across the empty check and the
/// removal, preventing a concurrent join from dropping a new session into
/// the inner map between those two steps (which would then be silently
/// dropped along with the map).
///
/// Return `(total authenticated peers across all rooms, active room count)`.
///
/// Aggregates the two-level `peers` map at the moment of the call. The outer
/// length is the room count; summing inner lengths gives peers. The walk is
/// O(rooms) so this is only appropriate for sporadic observability logs, not
/// a per-signal hot path.
///
/// This deliberately does *not* use `state.active_connections`: that counter
/// also tracks TCP connections still in the authentication phase which have
/// not yet joined a room. Aggregating over `peers` keeps the "peers" number
/// aligned with the "rooms" number (both enumerate the same structure at the
/// same instant), so the two never drift apart in the suffix we emit.
fn capacity_snapshot(state: &RelayState) -> (usize, usize) {
    let rooms = state.peers.len();
    let peers = state.peers.iter().map(|r| r.value().len()).sum::<usize>();
    (peers, rooms)
}

/// Format the per-event capacity suffix that trailing observability log lines
/// append to their message. `max_peers == 0` is the relay's "unlimited" flag
/// and is rendered as the word rather than a literal zero.
fn format_capacity_suffix(peers: usize, rooms: usize, max_peers: usize) -> String {
    if max_peers == 0 {
        format!("({peers} / unlimited peers connected in {rooms} active rooms)")
    } else {
        format!("({peers} / {max_peers} peers connected in {rooms} active rooms)")
    }
}

/// Returns `true` iff this call removed our entry — callers use this to
/// decide whether to broadcast `PeerLeft` (a caller that lost the race has
/// nothing to clean up and nothing to announce).
fn remove_own_entry(state: &RelayState, room: &str, session_id: &str, conn_id: Uuid) -> bool {
    let removed = state
        .peers
        .get(room)
        .and_then(|inner| inner.remove_if(session_id, |_, entry| entry.conn_id == conn_id))
        .is_some();
    if removed {
        state.peers.remove_if(room, |_, inner| inner.is_empty());
    }
    removed
}

/// Clone the outbound senders of every peer currently in `room` except the
/// one identified by `exclude_session`.
///
/// Briefly holds the outer shard read lock to clone the inner `Arc` handle,
/// then releases it before iterating the inner map. This keeps broadcasts
/// against one room from serialising against inserts or lookups targeting
/// unrelated rooms on the same outer shard.
fn collect_same_room_senders(
    state: &RelayState,
    room: &str,
    exclude_session: &str,
) -> Vec<mpsc::Sender<SignalEnvelope>> {
    let inner = match state.peers.get(room) {
        Some(r) => Arc::clone(r.value()),
        None => return Vec::new(),
    };
    inner
        .iter()
        .filter(|e| e.key() != exclude_session)
        .map(|e| e.value().tx.clone())
        .collect()
}

/// Session IDs of every peer currently in `room` except `exclude_session`.
/// Same locking discipline as [`collect_same_room_senders`].
fn collect_same_room_session_ids(
    state: &RelayState,
    room: &str,
    exclude_session: &str,
) -> Vec<String> {
    let inner = match state.peers.get(room) {
        Some(r) => Arc::clone(r.value()),
        None => return Vec::new(),
    };
    inner
        .iter()
        .filter(|e| e.key() != exclude_session)
        .map(|e| e.key().clone())
        .collect()
}

/// Axum handler that upgrades an HTTP request to a WebSocket connection.
///
/// The URL path determines the peer's **room** — e.g. `wss://relay/game_A`
/// joins room `"game_A"`. Connecting to `/` joins the `"default"` room. Peers
/// only see and communicate with other peers in the same room.
///
/// When `auth_required` is enabled on the relay, the handler extracts an
/// ATProto JWT from one of two sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
///
/// Bearer tokens are intentionally **not** accepted via query string: query
/// parameters are logged in plaintext by reverse proxies, edge load balancers,
/// and intermediate firewalls, which would leak ATProto session credentials
/// into operator-side logs that the user never consented to share.
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
    State(state): State<RelayState>,
) -> impl IntoResponse {
    // Extract the room from the URL path. Normalize so "/" and "" both map to
    // the same default room, and strip trailing slashes for consistency.
    // Percent-decode the path so that `/my%20room` and `/my room` (which an
    // overly-permissive client might transmit) resolve to the same room rather
    // than splitting peers across two parallel rooms by accident. Reject any
    // path that decodes to non-UTF-8 bytes outright: a lossy decode would
    // collapse all distinct invalid sequences (`%FE`, `%FF`, …) onto the same
    // U+FFFD-bearing string, silently merging unrelated client requests into
    // the same WebRTC mesh.
    let raw_room = uri.path().trim_matches('/');
    let room = match percent_encoding::percent_decode_str(raw_room).decode_utf8() {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "room path is not valid UTF-8").into_response();
        }
    };
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

    // Reserve a handshake slot: at most max_peers / 4 connections may be in
    // the auth/DID-resolution phase simultaneously. Prevents DID tarpit
    // attacks from exhausting the entire connection budget while legitimate
    // peers are blocked waiting for slow DID-hosting servers to respond.
    //
    // When max_peers == 0 ("unlimited"), the operator only intends to lift the
    // overall connection cap — they still need protection against handshake
    // tarpits, which would otherwise pin tens of thousands of TCP connections
    // in the 15-second authentication phase. Fall back to a fixed budget so the
    // tarpit cap is always enforced regardless of `max_peers`.
    let handshake_limit = if state.max_peers > 0 {
        (state.max_peers / 4).max(1)
    } else {
        UNLIMITED_HANDSHAKE_BUDGET
    };
    let _handshake_guard = {
        let prev = state
            .active_handshakes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= handshake_limit {
            state
                .active_handshakes
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many connections pending authentication",
            )
                .into_response();
        }
        AtomicGuard(Arc::clone(&state.active_handshakes))
    };

    let identity = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        extract_identity(
            &headers,
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
            // _conn_guard and _handshake_guard both drop here.
            return (StatusCode::GATEWAY_TIMEOUT, "Authentication timed out").into_response();
        }
    };

    // Auth complete — release the handshake slot. The connection slot
    // (_conn_guard) is kept for the lifetime of the WebSocket session.
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
            // JWT was successfully verified (if one was presented). Log the
            // verification here rather than inside `validate_atproto_jwt` so
            // the log line can carry a relay-capacity snapshot — this is a
            // natural observability checkpoint and the auth module has no
            // business pulling in `RelayState` just to annotate its logs.
            // The snapshot reflects the state *before* this peer joins a
            // room, which is still meaningful: it is the headroom they found
            // when they connected.
            if let Some(ref validated) = id {
                let (peers, rooms) = capacity_snapshot(&state);
                let suffix = format_capacity_suffix(peers, rooms, state.max_peers);
                tracing::debug!(
                    did = %validated.did,
                    peers_connected = peers,
                    active_rooms = rooms,
                    max_peers = state.max_peers,
                    "JWT signature verified via DID document {suffix}"
                );
            }
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
/// one of two sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
///
/// Returns `Err` with a 401 response only when `auth_required` is true and
/// no valid token is found in either source.
async fn extract_identity(
    headers: &HeaderMap,
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

    let token = header_token.or(protocol_token);

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

    match auth::validate_atproto_jwt(token, resolver, service_did).await {
        Ok(identity) => Ok(Some(identity)),
        Err(auth::AuthError::Transient(e)) => {
            // DID resolver is overloaded or the DID hosting server is
            // temporarily unreachable. This is not the client's fault —
            // returning 401 here would cause signallers to permanently abort
            // reconnects on what is actually a transient load spike.
            tracing::warn!(error = %e, "JWT validation failed: transient resolver error");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable, please retry",
            ))
        }
        Err(auth::AuthError::InvalidToken(e)) => {
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
    let self_backpressure_strikes = Arc::new(AtomicU64::new(0));
    let self_shutdown = Arc::new(Notify::new());

    // Atomically get-or-create the room's inner map and replace any existing
    // connection for this `session_id` within it.
    //
    // The outer shard write lock is deliberately held across the inner
    // `entry` call: if we cloned the inner `Arc` and released the outer lock
    // first, a concurrent same-room departure could GC the (then-empty) room
    // via [`try_remove_empty_room`] and we would insert into an orphaned
    // inner map that no other thread can find.
    //
    // Using the nested `entry` API also avoids the classic TOCTOU where two
    // concurrent reconnects with the same `session_id` both observe `None`
    // from `get()` and both `insert()`, orphaning the first one's write task.
    let old_entry_info = {
        use dashmap::mapref::entry::Entry;
        let new_peer = PeerEntry {
            tx: relay_tx,
            conn_id,
            backpressure_strikes: Arc::clone(&self_backpressure_strikes),
            shutdown: Arc::clone(&self_shutdown),
        };
        let room_ref = state
            .peers
            .entry(room.clone())
            .or_insert_with(|| Arc::new(dashmap::DashMap::new()));
        let inner = room_ref.value();
        match inner.entry(session_id.clone()) {
            Entry::Occupied(mut occ) => {
                let old = occ.insert(new_peer);
                Some(old.tx)
            }
            Entry::Vacant(vac) => {
                vac.insert(new_peer);
                None
            }
        }
        // `room_ref` drops here, releasing the outer shard write lock.
    };

    // If we replaced an old connection (same identity reconnecting to the
    // same room), notify the other peers in that room so their WebRTC mesh
    // state for this session_id is torn down before the new PeerJoined fires.
    // Peers in *other* rooms are unaffected because the old connection there
    // (if any) lives under a different (room, session_id) key.
    if let Some(_old_tx) = old_entry_info {
        let leave_senders = collect_same_room_senders(&state, &room, &session_id);
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
        remove_own_entry(&state, &room, &session_id, conn_id);
        // _conn_guard drops here, decrementing the counter.
        return;
    }

    // Broadcast peer list to the new peer (same room only).
    let existing_peers = collect_same_room_session_ids(&state, &room, &session_id);
    tracing::debug!(
        session = %session_id,
        room = %room,
        peer_count = existing_peers.len(),
        peers = ?existing_peers,
        "sending peer_list to new peer",
    );
    let peer_list = serde_json::json!({ "type": "peer_list", "peers": existing_peers });
    if !matches!(
        tokio::time::timeout(
            WS_WRITE_TIMEOUT,
            ws_tx.send(Message::Text(peer_list.to_string().into())),
        )
        .await,
        Ok(Ok(()))
    ) {
        remove_own_entry(&state, &room, &session_id, conn_id);
        return;
    }

    // Notify existing peers in the same room about the new peer.
    // Collect senders first to avoid holding DashMap read locks across channel sends.
    let peer_senders = collect_same_room_senders(&state, &room, &session_id);
    tracing::debug!(
        session = %session_id,
        room = %room,
        notify_count = peer_senders.len(),
        "broadcasting PeerJoined to room",
    );
    for sender in peer_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id.clone(),
            signal: SignalPayload::PeerJoined(session_id.clone()),
        };
        let _ = sender.try_send(envelope);
    }

    let session_id_write = session_id.clone();
    let room_write = room.clone();
    let state_write = state.clone();

    // Forward messages from the relay channel to the WebSocket, and
    // periodically send Ping frames to keep the connection alive.
    // WASM clients (browsers) cannot initiate WebSocket pings — they only
    // *respond* to server pings — so without server-side pings, idle WASM
    // connections would be reaped by WS_IDLE_TIMEOUT.
    //
    // The task also listens on `self_shutdown` so that when too many senders
    // pile up on this peer's channel (aggregate strikes exceed
    // `TARGET_KICK_STRIKES`), the write loop terminates and the client
    // receives a hard WebSocket close — allowing reconnect logic to rebuild
    // the WebRTC mesh rather than stalling silently on blackholed SDP/ICE.
    let shutdown_for_write = Arc::clone(&self_shutdown);
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
                _ = shutdown_for_write.notified() => {
                    tracing::warn!(
                        "disconnecting peer: sustained channel-full backpressure \
                         ({TARGET_KICK_STRIKES} aggregate strikes)"
                    );
                    // Best-effort close frame so the client knows to reconnect
                    // instead of assuming the network dropped.
                    let _ = tokio::time::timeout(
                        WS_WRITE_TIMEOUT,
                        ws_tx.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                            code: 1013, // "Try Again Later"
                            reason: "relay queue saturated".into(),
                        }))),
                    ).await;
                    break;
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
        // Per-target backpressure state. When a target's channel is full across
        // many consecutive routing attempts, log emission for that target is
        // silenced (`silenced = true`). Successful sends drip the strike
        // counter back down via leaky-bucket decrement; the silencer only
        // disarms when the counter returns to zero. Stalled peers are reaped
        // by WS_IDLE_TIMEOUT instead of sender-driven eviction, preventing
        // a malicious sender from kicking arbitrary targets.
        #[derive(Default)]
        struct BackpressureState {
            strikes: usize,
            silenced: bool,
            last_warning_at: Option<tokio::time::Instant>,
        }
        let mut backpressure_strikes: std::collections::HashMap<String, BackpressureState> =
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
        // Per-sender token-bucket rate limiter. Burst capacity is scaled from
        // the relay's `max_peers` so that joining a maximally-full room never
        // exhausts the budget on legitimate WebRTC mesh init, regardless of
        // how the operator sized the relay. The low refill rate caps sustained
        // throughput once the initial burst is spent.
        let rate_burst_capacity = rate_burst_for(state_write.max_peers);
        let max_unique_targets = unique_targets_for(state_write.max_peers);
        let mut rate_tokens: u32 = rate_burst_capacity;
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

            // Note: oversized `peer_id` fields are rejected during JSON
            // deserialization above by `protocol::deserialize_bounded_peer_id`,
            // which short-circuits `from_str` from the borrowed string visitor
            // before any owned String for the offending field is allocated.
            // The error path falls through to the generic "invalid envelope"
            // branch, so no separate post-parse length check is needed here.

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
            // `saturating_duration_since` avoids panicking on rare clock
            // anomalies (OS suspend, VM clock adjustment) where
            // `rate_last_refill` could marginally overtake `now`.
            let elapsed = now.saturating_duration_since(rate_last_refill);
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
                // `rate_last_refill` into the future and silently discard the
                // sub-interval. The check fires again once enough time has
                // elapsed.
                if refill > 0 {
                    let new_tokens = (rate_tokens + refill).min(rate_burst_capacity);
                    rate_tokens = new_tokens;
                    // When the bucket fills to capacity, reset the clock to `now`
                    // so that saturating_mul overflow on very long-idle connections
                    // (e.g. ping-kept-alive for 49+ days) cannot cause the timer
                    // to fall behind and grant successive free max bursts. When
                    // the bucket is not full, advance proportionally to tokens
                    // minted to preserve sub-token remainder accumulation.
                    if new_tokens == rate_burst_capacity {
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
            if now.saturating_duration_since(per_target_last_reset) >= PER_TARGET_WINDOW {
                per_target_counts.clear();
                per_target_last_reset = now;
            }
            if rate_tokens == 0 {
                // Disconnect the peer rather than silently dropping the
                // signal. SDP offers/answers and trickled ICE candidates are
                // not retransmitted by `RTCPeerConnection` or by Matchbox over
                // the signaling channel — STUN's retry logic only covers
                // candidate-pair probing on the data path, not the SDP/ICE
                // exchange itself. Dropping a signaling message therefore
                // permanently fragments the WebRTC mesh: targeted peers stall
                // forever in the "connecting" state. The burst capacity is
                // scaled from `max_peers` (`rate_burst_for`) to comfortably
                // cover full mesh init for the operator's configured room
                // size, so legitimate peers should never reach this branch.
                // A peer that does has either misbehaved or been compromised;
                // dropping the connection is the correct failure signal so
                // the client surfaces a hard error instead of stalling.
                tracing::warn!(
                    session = %session_id,
                    burst = rate_burst_capacity,
                    refill_per_sec = RATE_REFILL_PER_SECOND,
                    "disconnecting peer: signal rate budget exhausted"
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
            // random target IDs to bloat the map will hit this cap. The cap
            // is scaled from `max_peers` (`unique_targets_for`) so that any
            // legitimate full-mesh send fits comfortably under the limit
            // regardless of how the operator sized the relay.
            if !per_target_counts.contains_key(&target_id)
                && per_target_counts.len() >= max_unique_targets
            {
                tracing::warn!(
                    session = %session_id,
                    unique_targets = per_target_counts.len(),
                    cap = max_unique_targets,
                    "disconnecting peer: exceeded unique target cap"
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

            let signal_kind = match &envelope.signal {
                SignalPayload::Offer(_) => "Offer",
                SignalPayload::Answer(_) => "Answer",
                SignalPayload::IceCandidate(_) => "IceCandidate",
                SignalPayload::PeerJoined(_) => "PeerJoined",
                SignalPayload::PeerLeft(_) => "PeerLeft",
            };
            tracing::debug!(
                sender = %session_id,
                target = %target_id,
                room = %room,
                signal = signal_kind,
                "relay forwarding signal",
            );

            let forwarded = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: envelope.signal,
            };

            // We always probe try_send so a recovered (drained) channel can
            // drip the leaky-bucket counter back down via the Ok(()) arm.
            // Skipping the send permanently blackholes the target for the
            // lifetime of the connection even after recovery.

            // Look up the target by room first, then session_id, so
            // cross-room forwarding is impossible by construction: a peer in
            // room A cannot synthesise a key into room B. We clone handles
            // for the channel, the target's aggregate strike counter, and
            // its shutdown notify so the inner DashMap reference can be
            // released before the send.
            let target_entry = state_write.peers.get(&room).and_then(|inner| {
                inner.get(&target_id).map(|e| {
                    let entry = e.value();
                    (
                        entry.tx.clone(),
                        Arc::clone(&entry.backpressure_strikes),
                        Arc::clone(&entry.shutdown),
                    )
                })
            });
            if let Some((target_tx, target_strikes, target_shutdown)) = target_entry {
                match target_tx.try_send(forwarded) {
                    Ok(()) => {
                        // Net-positive progress: relax the aggregate strike
                        // counter on the target. Underflow is avoided by the
                        // fetch_update clamp at zero.
                        let _ = target_strikes.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |v| Some(v.saturating_sub(1)),
                        );
                        if let Some(state) = backpressure_strikes.get_mut(&target_id) {
                            state.strikes = state.strikes.saturating_sub(1);
                            if state.strikes == SILENCER_REARM_THRESHOLD {
                                let cooldown_expired = state
                                    .last_warning_at
                                    .map(|t| {
                                        now.saturating_duration_since(t)
                                            >= BACKPRESSURE_LOG_COOLDOWN
                                    })
                                    .unwrap_or(true);
                                if cooldown_expired {
                                    backpressure_strikes.remove(&target_id);
                                }
                            }
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Charge a strike against the *target* (aggregate
                        // across all senders). If the total crosses the kick
                        // threshold, fire the target's shutdown signal so the
                        // client reconnects rather than stalling on dropped
                        // SDP/ICE. Using fetch_add with a post-increment
                        // comparison ensures exactly one sender triggers the
                        // kick even under concurrency.
                        let prev = target_strikes.fetch_add(1, Ordering::Relaxed);
                        if prev + 1 >= TARGET_KICK_STRIKES {
                            target_shutdown.notify_waiters();
                        }

                        let state = backpressure_strikes.entry(target_id.clone()).or_default();
                        state.strikes = state
                            .strikes
                            .saturating_add(1)
                            .min(MAX_BACKPRESSURE_STRIKE_CAP);
                        let cooldown_elapsed = state
                            .last_warning_at
                            .map(|t| now.saturating_duration_since(t) >= BACKPRESSURE_LOG_COOLDOWN)
                            .unwrap_or(true);
                        if cooldown_elapsed && !state.silenced {
                            tracing::warn!(
                                target = %target_id,
                                sender = %session_id,
                                "relay channel full for target, dropping signal (backpressure)"
                            );
                            state.last_warning_at = Some(now);
                        }
                        if !state.silenced && state.strikes >= MAX_BACKPRESSURE_STRIKES {
                            state.silenced = true;
                            tracing::warn!(
                                target = %target_id,
                                sender = %session_id,
                                "target hit {MAX_BACKPRESSURE_STRIKES} backpressure \
                                 strikes; silencing logs until channel drains"
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Target peer disconnected but hasn't been cleaned
                        // up from the DashMap yet. Clear any accumulated
                        // strike state — the channel is gone so the strikes
                        // would never be reset via Ok(()), causing a
                        // permanent memory leak on long-lived connections
                        // that interact with many transient peers.
                        backpressure_strikes.remove(&target_id);
                        tracing::debug!(
                            target = %target_id,
                            "target channel closed, dropping this message"
                        );
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
    // `remove_own_entry` also GCs the room's inner map when the removal
    // leaves it empty, so that long-lived relays hosting many short-lived
    // rooms do not accumulate empty inner maps indefinitely.
    let was_removed = remove_own_entry(&state, &room_write, &session_id_write, conn_id);
    if !was_removed {
        // Another connection owns this (room, session_id) now — skip broadcast.
        // _conn_guard drops here, decrementing the counter.
        tracing::debug!(
            session = %session_id_write,
            room = %room_write,
            "stale connection cleanup skipped (session was replaced)"
        );
        return;
    }
    // The room may have just been GC'd by `remove_own_entry`; if so, there
    // are no remaining peers to notify. A new peer that joins the same room
    // after GC will land in a freshly-created inner map and therefore
    // correctly not receive a stale `PeerLeft` from our departure.
    let remaining_senders = collect_same_room_senders(&state, &room_write, &session_id_write);
    for sender in remaining_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id_write.clone(),
            signal: SignalPayload::PeerLeft(session_id_write.clone()),
        };
        let _ = sender.try_send(envelope);
    }

    // The peer was removed from `state.peers` back at `remove_own_entry`, so
    // `capacity_snapshot` already reflects the post-disconnect counts — the
    // suffix reads "after this departure, N peers remain in R rooms".
    //
    // `_conn_guard` (which decrements `state.active_connections`) is dropped
    // explicitly here so the counter decrement is fully ordered before the
    // log emits. We don't surface that counter in the suffix (it includes
    // handshakes-in-progress and would disagree with the room-aggregated
    // `peers` figure), but dropping deterministically keeps any out-of-band
    // observer who reads `active_connections` right after this log from
    // seeing a phantom extra connection that has already "said goodbye".
    drop(_conn_guard);
    let (peers, rooms) = capacity_snapshot(&state);
    let suffix = format_capacity_suffix(peers, rooms, state.max_peers);
    tracing::info!(
        session = %session_id_write,
        peers_connected = peers,
        active_rooms = rooms,
        max_peers = state.max_peers,
        "peer disconnected {suffix}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_burst_floor_applies_for_small_relays() {
        // Tiny relays still get the floor so even single-peer rooms have
        // headroom for re-negotiation bursts.
        assert_eq!(rate_burst_for(1), RATE_BURST_FLOOR);
        assert_eq!(rate_burst_for(8), RATE_BURST_FLOOR);
    }

    #[test]
    fn rate_burst_scales_with_max_peers() {
        // Default-config relay (max_peers = 512) should comfortably fit a
        // full-mesh init: 512 * 16 signals = 8192, which is below the ceiling
        // and well above the legacy hard-coded burst of 500 that triggered
        // silent drops in larger rooms.
        let burst = rate_burst_for(512);
        assert!(burst >= 512 * SIGNALS_PER_REMOTE_PEER);
        assert!(burst <= RATE_BURST_CEILING);
        assert!(burst > 500);
    }

    #[test]
    fn rate_burst_caps_at_ceiling() {
        // Pathologically large `max_peers` must not produce an unbounded
        // per-connection token budget — keeps the worst-case memory and log
        // noise bounded.
        assert_eq!(rate_burst_for(1_000_000), RATE_BURST_CEILING);
    }

    #[test]
    fn rate_burst_for_unlimited_uses_floor() {
        // `max_peers == 0` ("unlimited") still needs *some* burst budget; we
        // pick the floor here because the unique-target ceiling already caps
        // legitimate full-mesh sends.
        assert_eq!(rate_burst_for(0), RATE_BURST_FLOOR);
    }

    #[test]
    fn unique_targets_cover_default_max_peers() {
        // Critical regression check for the "instant ban after joining a
        // 512-peer room" bug: with the default max_peers of 512, the cap
        // must be at least 512 so a peer can address every other peer in
        // the room within a single PER_TARGET_WINDOW.
        assert!(unique_targets_for(512) >= 512);
    }

    #[test]
    fn unique_targets_floor_for_small_rooms() {
        // Small relays still get the floor so legitimate per-target sends
        // never trip the cap on a tiny room.
        assert_eq!(unique_targets_for(8), MAX_UNIQUE_TARGETS_FLOOR);
        assert_eq!(unique_targets_for(256), MAX_UNIQUE_TARGETS_FLOOR);
    }

    #[test]
    fn unique_targets_caps_at_ceiling() {
        // Bounded per-connection HashMap memory even when max_peers is huge.
        assert_eq!(unique_targets_for(1_000_000), MAX_UNIQUE_TARGETS_CEILING);
    }

    #[test]
    fn unique_targets_unlimited_uses_ceiling() {
        // `max_peers == 0` ("unlimited") falls back to the ceiling rather
        // than the floor, since the operator has explicitly opted out of a
        // configured cap and we still want to comfortably accommodate large
        // rooms without trapping legitimate clients.
        assert_eq!(unique_targets_for(0), MAX_UNIQUE_TARGETS_CEILING);
    }

    #[test]
    fn per_target_burst_limit_well_below_channel_capacity() {
        // The whole point of PER_TARGET_BURST_LIMIT is to keep any single
        // sender from monopolising a target's relay channel. If the burst
        // limit ever creeps up to (or past) RELAY_CHANNEL_CAPACITY, one sender
        // alone could fill the channel — negating the protection. We enforce
        // at least a 16× headroom so at least 16 coordinated senders are
        // required to saturate a victim's queue.
        assert!(
            RELAY_CHANNEL_CAPACITY as u32 / PER_TARGET_BURST_LIMIT >= 16,
            "PER_TARGET_BURST_LIMIT must leave at least 16× headroom below \
             RELAY_CHANNEL_CAPACITY so a single sender cannot fill the channel"
        );
    }

    #[test]
    fn target_kick_threshold_bounds_single_sender_contribution() {
        // A single sender can contribute at most PER_TARGET_BURST_LIMIT
        // strikes within one per-target window (the sender gets disconnected
        // or throttled after that). The kick threshold must be strictly
        // greater than this single-sender ceiling, or a single flooding
        // attacker could evict any target they choose — re-introducing the
        // "kick arbitrary target" attack the earlier silencer design
        // deliberately rejected.
        assert!(
            TARGET_KICK_STRIKES > PER_TARGET_BURST_LIMIT as u64,
            "TARGET_KICK_STRIKES ({TARGET_KICK_STRIKES}) must exceed one sender's \
             contribution ({PER_TARGET_BURST_LIMIT}) so no single peer can kick a target"
        );
    }
}
