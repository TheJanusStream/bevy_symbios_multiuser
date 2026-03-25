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
//! `did:plc`, or `/.well-known/did.json` for `did:web`), extracts the
//! `#atproto` P-256 signing key, and cryptographically verifies the JWT's
//! ES256 signature. Resolved keys are cached in memory with a 5-minute TTL.
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
//! - **Backpressure logging** — When the per-peer relay channel (256 slots)
//!   is full, dropped signals are logged instead of silently discarded.
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
    /// Atomic counter tracking active + in-handshake connections.
    /// Prevents TOCTOU bypasses where concurrent handshakes all pass the
    /// `max_peers` check before any of them insert into `peers`.
    pub active_connections: Arc<AtomicUsize>,
}

impl RelayState {
    fn new(auth_required: bool, max_peers: usize) -> Self {
        // Always create the DID resolver so that opportunistic authentication
        // works when `auth_required` is false: clients presenting a valid JWT
        // get identified by their DID, while unauthenticated clients fall back
        // to random UUIDs.
        Self {
            peers: Arc::new(DashMap::new()),
            auth_required,
            max_peers,
            did_resolver: Some(did_resolver::DidResolver::new()),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Start the relay signaling server.
///
/// Binds to the configured address and serves WebSocket connections.
/// This function runs until the server is shut down.
pub async fn run_relay(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = RelayState::new(config.auth_required, config.max_peers);

    // Accept WebSocket upgrades on any path so clients can use room-based
    // URLs (e.g. `/my_room`) as well as the canonical `/ws` endpoint.
    let app = axum::Router::new()
        .fallback(axum::routing::get(handler::ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(
        addr = %config.bind_addr,
        auth_required = config.auth_required,
        "relay server listening"
    );

    axum::serve(listener, app).await?;

    Ok(())
}
