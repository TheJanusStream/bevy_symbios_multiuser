//! # bevy_symbios_multiuser
//!
//! A decentralized, low-latency multiplayer plugin for the Bevy engine.
//! Combines [ATProto](https://atproto.com/) for federated identity with
//! WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for
//! peer-to-peer data transfer.
//!
//! ## Architecture
//!
//! The crate provides a generic message bus via [`plugin::SymbiosMultiuserPlugin`]
//! that accepts any serializable domain type `T`. Messages are transported over
//! WebRTC data channels: one **reliable** channel for state mutations and one
//! **unreliable** channel for ephemeral presence data.
//!
//! Authentication flows through a **Sovereign Broker** pattern:
//!
//! 1. The client authenticates with an ATProto PDS via
//!    [`auth::create_session`], obtaining an [`auth::AtprotoSession`]. For
//!    relay authentication with `auth_required = true`, the client must then
//!    call [`auth::get_service_auth`] to obtain a *service auth token* — a
//!    JWT signed by the user's `#atproto` key that third-party relays can
//!    verify via DID document resolution. The `access_jwt` from
//!    `create_session` is signed by the PDS service key and cannot be
//!    verified this way. Wrap the service token in a
//!    [`signaller::TokenSourceRes`] resource so the signaller uses it on
//!    each connection attempt.
//! 2. The [`signaller::SymbiosSignallerBuilder`] passes this token to the
//!    relay during the WebSocket handshake. On native targets, the token is
//!    sent as an `Authorization: Bearer` header. On WASM targets, the token
//!    is sent via the `Sec-WebSocket-Protocol` subprotocol trick (the
//!    browser `WebSocket` API does not support custom headers).
//! 3. The relay (`relay` module, feature-gated) validates the JWT claims and — when
//!    `auth_required` is enabled — resolves the issuer's DID document to
//!    cryptographically verify the signature (ES256/P-256 or ES256K/secp256k1)
//!    against the `#atproto` signing key. When [`RelayConfig::service_did`] is
//!    set, the `aud` claim is also validated to prevent cross-service token
//!    replay. The authenticated DID becomes the peer's session identity.
//! 4. Once signaling completes, data flows directly peer-to-peer over
//!    WebRTC data channels.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bevy::prelude::*;
//! use bevy_symbios_multiuser::prelude::*;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, Debug, Clone)]
//! enum GameMessage {
//!     Move { x: f32, y: f32 },
//!     Chat(String),
//! }
//!
//! fn main() {
//!     App::new()
//!         .add_plugins(DefaultPlugins)
//!         .add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
//!             "wss://matchbox.example.com/my_room",
//!         ))
//!         .add_systems(Update, (handle_incoming, send_movement))
//!         .run();
//! }
//!
//! fn handle_incoming(mut queue: ResMut<NetworkQueue<GameMessage>>) {
//!     for msg in queue.drain() {
//!         info!("From {:?}: {:?}", msg.sender, msg.payload);
//!     }
//! }
//!
//! fn send_movement(mut writer: MessageWriter<Broadcast<GameMessage>>) {
//!     writer.write(Broadcast {
//!         payload: GameMessage::Move { x: 1.0, y: 2.0 },
//!         channel: ChannelKind::Unreliable,
//!     });
//! }
//! ```
//!
//! ## Features
//!
//! - `client` (default) — ATProto authentication, custom signaller for
//!   authenticated relay connections.
//! - `tls` (default) — Enables TLS (via `rustls`) for both `reqwest` HTTPS
//!   and `async-tungstenite` WebSocket (`wss://`) connections.
//! - `relay` — Sovereign Broker relay server with DID-based JWT signature
//!   verification (ES256 + ES256K), room-based peer isolation, atomic
//!   connection limits, SSRF-hardened DID resolution, message size caps,
//!   idle/handshake/write timeouts, HTTP-level Slowloris protection, server-side
//!   pings (WASM keep-alive), per-sender token-bucket rate limiting,
//!   per-target burst limiting, per-domain and global `did:web` fetch
//!   concurrency limiting, request coalescing, negative DID caching, peer ID
//!   length validation, unique target cap, and JWT audience validation
//!   (`service_did`). Built on `axum`.

pub mod error;
pub mod messages;
pub mod plugin;
pub mod protocol;
pub mod systems;

#[cfg(feature = "client")]
pub mod auth;

#[cfg(feature = "client")]
pub mod signaller;

#[cfg(feature = "relay")]
pub mod relay;

/// Re-exports for convenient use.
pub mod prelude {
    pub use crate::error::SymbiosError;
    pub use crate::messages::{
        Broadcast, ChannelKind, NetworkQueue, NetworkReceived, PeerConnectionState,
        PeerStateChanged, PeerStateQueue,
    };
    pub use crate::plugin::{SymbiosMultiuserConfig, SymbiosMultiuserPlugin};
    pub use bevy_matchbox::prelude::{ChannelConfig, PeerId, PeerState};

    #[cfg(feature = "client")]
    pub use crate::auth::{AtprotoCredentials, AtprotoSession};

    #[cfg(feature = "client")]
    pub use crate::signaller::SymbiosSignallerBuilder;
}
