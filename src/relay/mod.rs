//! XRPC Relay — a WebRTC signaling broker built on Axum with optional
//! ATProto JWT authentication and DID-based signature verification.
//!
//! The relay accepts WebSocket connections, optionally verifies ATProto JWT
//! bearer tokens, and routes WebRTC SDP offers/answers and ICE candidates
//! between peers using an in-memory connection map.
//!
//! # Authentication
//!
//! When [`RelayConfig::auth_required`] is `true`, every connecting client must
//! present a valid ATProto access JWT. The relay accepts the token from three
//! sources, checked in order:
//!
//! 1. `Authorization: Bearer <token>` header (native clients).
//! 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients
//!    using the subprotocol trick — the relay echoes the selected subprotocol
//!    back per RFC 6455).
//! 3. `?token=<token>` query parameter (legacy WASM fallback).
//!
//! The relay resolves the issuer's DID document (via `plc.directory` for
//! `did:plc`, or HTTPS for `did:web` — domain-only DIDs use
//! `/.well-known/did.json`, path-based DIDs like `did:web:example.com:u:alice`
//! use `/{path}/did.json`), extracts the `#atproto` signing key (P-256/ES256
//! or secp256k1/ES256K), and cryptographically verifies the JWT signature.
//! Resolved keys are cached in memory with a 5-minute TTL.
//! The authenticated DID becomes the peer's session identity.
//!
//! When `auth_required` is `false` (the default), authentication is
//! opportunistic — clients presenting a valid, signature-verified token are
//! identified by their DID, while unauthenticated clients fall back to random
//! UUIDs. Tokens are only trusted when a DID resolver is configured.
//!
//! # Room Isolation
//!
//! The URL path used during WebSocket upgrade determines the peer's **room**.
//! For example, `wss://relay/game_A` and `wss://relay/game_B` are separate
//! rooms — peers only see `PeerJoined`/`PeerLeft` events and can only exchange
//! signals with other peers in the same room. Cross-room signals are dropped.
//! Connecting to `/` (or with no path) places the peer in a `"default"` room.
//!
//! # Hardening
//!
//! - **HTTP request timeout** — A `tower-http` `TimeoutLayer` drops any HTTP
//!   connection that has not completed the request (including header parsing and
//!   WebSocket upgrade) within 10 seconds, mitigating Slowloris-style attacks
//!   that trickle headers slowly to hold TCP connections without ever reaching
//!   the WebSocket handler.
//! - **Connection limits** — [`RelayConfig::max_peers`] caps the number of
//!   concurrent connections (default `512`). The limit is enforced via an atomic
//!   counter that reserves a slot *before* async identity extraction, preventing
//!   TOCTOU bypasses from concurrent handshakes. An RAII `ConnectionGuard`
//!   ensures the counter is decremented even if the WebSocket upgrade callback
//!   is never executed (e.g. TCP drops during the HTTP handshake). New
//!   connections are rejected with HTTP 503 once the limit is reached.
//! - **Message size cap** — Incoming WebSocket messages are limited to 64 KiB.
//!   SDP offers/answers and ICE candidates are typically a few KiB at most.
//! - **Control signal filtering** — Clients cannot forge `PeerJoined`/`PeerLeft`
//!   control signals; only the relay may originate these.
//! - **SSRF protection** — `did:web` domain resolution validates against
//!   private/loopback IPs and pins the resolved address to prevent DNS rebinding.
//! - **DID document size limit** — Responses are streamed with an incremental
//!   256 KiB cap, aborting before buffering oversized payloads.
//! - **Idle timeout** — WebSocket connections that receive no messages for 120
//!   seconds are disconnected, preventing Slowloris-style attacks that hold
//!   connection slots indefinitely.
//! - **Handshake timeout** — The authentication/identity extraction phase is
//!   capped at 15 seconds, preventing connection slot exhaustion from DIDs that
//!   tarpit the HTTP fetch.
//! - **Self-targeting rejection** — SDP offers/answers addressed to the sender's
//!   own session ID are dropped, preventing pointless self-negotiation loops.
//! - **Invalid message disconnect** — Peers that send 10 cumulative invalid
//!   messages (malformed JSON, binary frames, forged control signals) are
//!   disconnected, preventing log exhaustion attacks.
//! - **Negative DID cache** — Failed DID resolutions are cached for 60 seconds,
//!   preventing attackers from using the relay as a DDoS reflector by spamming
//!   handshakes with the same DID pointing at a victim server.
//! - **DID request coalescing** — The key cache uses [`moka::future::Cache`]
//!   with `try_get_with`, deduplicating concurrent lookups for the same DID.
//!   This prevents the relay from amplifying connection bursts into outbound
//!   HTTP floods against DID hosting servers.
//! - **Domain client cap** — Per-domain `reqwest::Client` instances (DNS-pinned
//!   for SSRF protection) are capped at 100. Each client holds a connection
//!   pool and background workers, so the low cap prevents resource exhaustion
//!   from an attacker feeding many unique `did:web` domains.
//! - **Server-side WebSocket pings** — The relay sends Ping frames every 30
//!   seconds. Browsers cannot initiate WebSocket pings (the API only supports
//!   *responding* to pings), so without server-side pings, idle WASM clients
//!   would be reaped by the idle timeout.
//! - **Backpressure** — When the per-peer relay channel (256 slots)
//!   is full, signals are dropped and logged. Each sender tracks per-target
//!   strike counters independently. If a sender accumulates 50 consecutive
//!   channel-full strikes against the same target, the sender silently stops
//!   delivering to that target for the remainder of the connection. Stalled
//!   peers are reaped by the idle timeout rather than by sender-driven eviction,
//!   preventing a malicious sender from kicking arbitrary targets by flooding
//!   their channel. Successful sends reset the strike counter, so live peers
//!   that are merely slow will not be affected. Closed channels (peer
//!   disconnected but not yet cleaned up) are skipped per-message without
//!   accumulating strikes, so a peer that reconnects can immediately receive
//!   signals again.
//! - **Handshake slot budget** — At most `max_peers / 4` connections may be
//!   in the authentication/DID-resolution phase simultaneously. This prevents
//!   attackers from exhausting all connection slots by tarpitting the DID
//!   fetch with slow-responding servers.
//! - **Per-sender rate limiting** — Each peer is rate-limited via a token bucket
//!   with a burst capacity of 500 messages and a steady-state refill of 20
//!   tokens per second. The high burst accommodates WebRTC mesh initialization
//!   (joining a room with N peers generates N SDP offers + multiple ICE
//!   candidates each), while the low refill rate caps sustained throughput.
//!   Peers that exhaust their tokens are immediately disconnected.
//! - **Per-domain DID fetch concurrency limit** — Each `did:web` domain is
//!   limited to 10 concurrent in-flight fetches. Slots are released as soon as
//!   each fetch completes (via RAII guard), so attacker requests that fail
//!   quickly cannot permanently exhaust the budget for legitimate users.
//! - **Global `did:web` fetch concurrency limit** — Total concurrent `did:web`
//!   fetches across all domains are capped at 50. This prevents subdomain
//!   spraying attacks from exhausting the Tokio blocking thread pool with DNS
//!   resolution calls. Like the per-domain limit, slots are freed on
//!   completion, making the limit resistant to unauthenticated DoS.
//!
//! # Usage
//!
//! ```rust,no_run
//! use bevy_symbios_multiuser::relay::{RelayConfig, run_relay};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = RelayConfig {
//!         bind_addr: "0.0.0.0:3536".to_string(),
//!         auth_required: false,
//!         max_peers: 512,
//!         service_did: None,
//!     };
//!     run_relay(config).await.expect("relay crashed");
//! }
//! ```

pub(crate) mod auth;
pub(crate) mod did_resolver;
mod handler;

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

// Re-export protocol types so existing `use relay::SignalEnvelope` still works.
pub use crate::protocol::{SignalEnvelope, SignalPayload};

/// Configuration for the relay server.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// The address to bind the server to (e.g. `"0.0.0.0:3536"`).
    pub bind_addr: String,
    /// If `true`, reject WebSocket connections that do not present a valid
    /// ATProto JWT (via header, subprotocol, or query param). Defaults to `false`.
    pub auth_required: bool,
    /// Maximum number of concurrent peer connections. New connections are
    /// rejected with HTTP 503 once this limit is reached. `0` means unlimited.
    /// Defaults to `512`.
    pub max_peers: usize,
    /// The relay's own service DID (e.g. `did:web:relay.example.com`). When set,
    /// JWT `aud` claims are validated against this value to prevent cross-service
    /// token replay attacks. When `None`, audience validation is skipped.
    pub service_did: Option<String>,
}

/// A connected peer's sender handle paired with a unique connection ID.
///
/// The connection ID distinguishes multiple WebSocket connections from the
/// same user (e.g. reconnects), preventing stale cleanup from clobbering a
/// newer connection.
#[derive(Clone)]
pub struct PeerEntry {
    /// Channel sender for delivering signaling envelopes to this peer's
    /// WebSocket write task.
    pub tx: mpsc::Sender<SignalEnvelope>,
    /// Unique ID for this specific WebSocket connection, used to distinguish
    /// reconnects and prevent stale cleanup from clobbering a newer session.
    pub conn_id: uuid::Uuid,
    /// The room this peer belongs to, derived from the WebSocket URL path.
    /// Peers only see and communicate with other peers in the same room.
    pub room: String,
}

/// Shared server state holding the map of connected peers.
#[derive(Clone)]
pub struct RelayState {
    /// Maps peer session IDs to their WebSocket message senders.
    pub peers: Arc<DashMap<String, PeerEntry>>,
    /// Whether authentication is mandatory for new connections.
    pub auth_required: bool,
    /// Maximum concurrent peers (`0` = unlimited).
    pub max_peers: usize,
    /// DID document resolver for JWT signature verification.
    /// `None` disables cryptographic signature checks.
    pub did_resolver: Option<did_resolver::DidResolver>,
    /// The relay's own service DID for JWT audience validation.
    /// When set, tokens whose `aud` claim does not match are rejected.
    pub service_did: Option<String>,
    /// Atomic counter tracking active + in-handshake connections.
    /// Prevents TOCTOU bypasses where concurrent handshakes all pass the
    /// `max_peers` check before any of them insert into `peers`.
    pub active_connections: Arc<AtomicUsize>,
    /// Atomic counter tracking connections currently in the handshake phase
    /// (identity extraction / DID resolution). Capped at `max_peers / 4` to
    /// prevent attackers from exhausting all connection slots by tarpitting
    /// the DID fetch phase with slow-responding servers.
    pub active_handshakes: Arc<AtomicUsize>,
    /// Maximum concurrent handshakes allowed (derived from `max_peers / 4`).
    pub max_handshakes: usize,
}

impl RelayState {
    fn new(auth_required: bool, max_peers: usize, service_did: Option<String>) -> Self {
        // Always create the DID resolver so that opportunistic authentication
        // works when `auth_required` is false: clients presenting a valid JWT
        // get identified by their DID, while unauthenticated clients fall back
        // to random UUIDs.
        // Reserve at most 25% of slots for in-progress handshakes. This ensures
        // that even if all handshake slots are tarpitted, 75% of capacity
        // remains available for established connections.
        let max_handshakes = if max_peers > 0 {
            (max_peers / 4).max(1)
        } else {
            0
        };
        Self {
            peers: Arc::new(DashMap::new()),
            auth_required,
            max_peers,
            did_resolver: Some(did_resolver::DidResolver::new()),
            service_did,
            active_connections: Arc::new(AtomicUsize::new(0)),
            active_handshakes: Arc::new(AtomicUsize::new(0)),
            max_handshakes,
        }
    }
}

/// Start the relay signaling server.
///
/// Binds to the configured address and serves WebSocket connections.
/// This function runs until the server is shut down.
pub async fn run_relay(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = RelayState::new(config.auth_required, config.max_peers, config.service_did);

    // Accept WebSocket upgrades on any path so clients can use room-based
    // URLs (e.g. `/my_room`) as well as the canonical `/ws` endpoint.
    //
    // The tower-http TimeoutLayer wraps the entire HTTP service so that
    // connections which have not completed the HTTP request (including header
    // parsing and WebSocket upgrade) within 10 seconds are dropped. This
    // mitigates Slowloris-style attacks where an attacker trickles HTTP
    // headers slowly, holding TCP connections without ever reaching the
    // WebSocket handler or its idle timeout logic.
    let app = axum::Router::new()
        .fallback(axum::routing::get(handler::ws_handler))
        .with_state(state)
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            std::time::Duration::from_secs(10),
        ));

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(
        addr = %config.bind_addr,
        auth_required = config.auth_required,
        "relay server listening"
    );

    axum::serve(listener, app).await?;

    Ok(())
}
