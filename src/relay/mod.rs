//! XRPC Relay — a stateless WebRTC signaling broker built on Axum.
//!
//! The relay accepts WebSocket connections from authenticated ATProto users,
//! verifies their JWT bearer tokens, and routes WebRTC SDP offers/answers and
//! ICE candidates between peers using an in-memory connection map.
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
//!     };
//!     run_relay(config).await.expect("relay crashed");
//! }
//! ```

mod handler;

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

pub use handler::SignalEnvelope;

/// Configuration for the relay server.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// The address to bind the server to (e.g. `"0.0.0.0:3536"`).
    pub bind_addr: String,
}

/// A connected peer's sender handle, keyed by their session identifier.
type PeerSender = mpsc::Sender<SignalEnvelope>;

/// Shared server state holding the map of connected peers.
#[derive(Clone)]
pub struct RelayState {
    /// Maps peer session IDs to their WebSocket message senders.
    pub peers: Arc<DashMap<String, PeerSender>>,
}

impl RelayState {
    fn new() -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
        }
    }
}

/// Start the relay signaling server.
///
/// Binds to the configured address and serves WebSocket connections.
/// This function runs until the server is shut down.
pub async fn run_relay(config: RelayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = RelayState::new();

    let app = axum::Router::new()
        .route("/ws", axum::routing::get(handler::ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "relay server listening");

    axum::serve(listener, app).await?;

    Ok(())
}
