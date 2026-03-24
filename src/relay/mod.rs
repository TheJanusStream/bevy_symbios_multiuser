//! XRPC Relay — a WebRTC signaling broker built on Axum with optional
//! ATProto JWT authentication.
//!
//! The relay accepts WebSocket connections, optionally verifies ATProto JWT
//! bearer tokens, and routes WebRTC SDP offers/answers and ICE candidates
//! between peers using an in-memory connection map.
//!
//! When [`RelayConfig::auth_required`] is `true`, every connecting client must
//! present a valid ATProto access JWT. The relay accepts the token from three
//! sources, checked in order:
//!
//! 1. `Authorization: Bearer <token>` header (native clients).
//! 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients
//!    using the subprotocol trick).
//! 3. `?token=<token>` query parameter (legacy WASM fallback).
//!
//! The authenticated DID becomes the peer's session identity.
//! When `false` (the default), authentication is opportunistic — valid tokens
//! are used for identity, but unauthenticated clients fall back to random UUIDs.
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
}

impl RelayState {
    fn new(auth_required: bool, max_peers: usize) -> Self {
        // Enable DID resolution (and thus signature verification) whenever
        // authentication is required.
        let did_resolver = if auth_required {
            Some(did_resolver::DidResolver::new())
        } else {
            None
        };

        Self {
            peers: Arc::new(DashMap::new()),
            auth_required,
            max_peers,
            did_resolver,
        }
    }
}

/// Start the relay signaling server.
///
/// Binds to the configured address and serves WebSocket connections.
/// This function runs until the server is shut down.
pub async fn run_relay(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = RelayState::new(config.auth_required, config.max_peers);

    let app = axum::Router::new()
        .route("/ws", axum::routing::get(handler::ws_handler))
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
