//! # bevy_symbios_multiuser
//!
//! A decentralized, low-latency multiplayer plugin for the Bevy engine.
//! Combines [ATProto](https://atproto.com/) for federated identity with
//! WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for
//! peer-to-peer data transfer.
//!
//! ## Architecture
//!
//! The crate provides a generic message bus via [`SymbiosMultiuserPlugin<T>`]
//! that accepts any serializable domain type `T`. Messages are transported over
//! WebRTC data channels: one **reliable** channel for state mutations and one
//! **unreliable** channel for ephemeral presence data.
//!
//! Authentication flows through a **Sovereign Broker** pattern:
//!
//! 1. The client authenticates with an ATProto PDS via
//!    [`auth::create_session`], obtaining a JWT access token.
//! 2. The [`signaller::SymbiosSignallerBuilder`] passes this JWT in the
//!    `Authorization` header when connecting to the relay.
//! 3. The relay ([`relay`] module) verifies the JWT and uses the
//!    authenticated DID as the peer's session identity.
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
//! App::new()
//!     .add_plugins(DefaultPlugins)
//!     .add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
//!         "wss://matchbox.example.com/my_room",
//!     ))
//!     .run();
//! ```
//!
//! ## Features
//!
//! - `client` (default) — ATProto authentication, custom signaller for
//!   authenticated relay connections.
//! - `relay` — XRPC relay signaling server with optional JWT verification,
//!   built on `axum`.

pub mod error;
pub mod events;
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
    pub use crate::events::{
        BroadcastMessage, ChannelKind, NetworkMessageReceived, PeerConnectionState,
        PeerStateChanged,
    };
    pub use crate::plugin::{SymbiosMultiuserConfig, SymbiosMultiuserPlugin};
    pub use bevy_matchbox::prelude::{ChannelConfig, PeerId, PeerState};

    #[cfg(feature = "client")]
    pub use crate::auth::{AtprotoCredentials, AtprotoSession};

    #[cfg(feature = "client")]
    pub use crate::signaller::SymbiosSignallerBuilder;
}
