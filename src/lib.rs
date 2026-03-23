//! # bevy_symbios_multiuser
//!
//! A decentralized, low-latency multiplayer plugin for the Bevy engine.
//! Combines ATProto for federated identity with WebRTC (via Matchbox) for
//! peer-to-peer data transfer.
//!
//! ## Architecture
//!
//! The crate provides a generic message bus via [`SymbiosMultiuserPlugin<T>`]
//! that accepts any serializable domain type `T`. Messages are transported over
//! WebRTC data channels: one **reliable** channel for state mutations and one
//! **unreliable** channel for ephemeral presence data.
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
//! - `client` (default) — Enables ATProto authentication via `reqwest`.
//! - `relay` — Enables the XRPC relay signaling server built on `axum`.

pub mod error;
pub mod events;
pub mod plugin;
pub mod systems;

#[cfg(feature = "client")]
pub mod auth;

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
}
