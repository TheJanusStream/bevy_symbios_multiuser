use crate::events::{BroadcastMessage, NetworkMessageReceived, PeerStateChanged};
use crate::systems;
use bevy::prelude::*;
use bevy_matchbox::prelude::*;
use matchbox_socket::RtcIceServerConfig;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[cfg(feature = "client")]
use crate::auth::AtprotoSession;

/// Configuration for the symbios multiuser plugin.
#[derive(Resource, Debug, Clone)]
pub struct SymbiosMultiuserConfig {
    /// WebSocket URL for the signaling server room.
    /// Example: `"wss://matchbox.example.com/my_room"`
    pub room_url: String,
    /// Optional ICE server configuration for NAT traversal.
    pub ice_servers: Option<RtcIceServerConfig>,
}

/// A generic multiplayer plugin that transports domain messages of type `T`
/// over WebRTC data channels.
///
/// Sets up two channels:
/// - **Channel 0** (Reliable): ordered, guaranteed delivery for state mutations.
/// - **Channel 1** (Unreliable): unordered, best-effort for ephemeral presence.
///
/// The plugin exposes Bevy messages [`BroadcastMessage<T>`] and
/// [`NetworkMessageReceived<T>`] so the host application can send and receive
/// domain-specific messages without touching the network layer directly.
pub struct SymbiosMultiuserPlugin<T> {
    config: SymbiosMultiuserConfig,
    _marker: PhantomData<T>,
}

impl<T> SymbiosMultiuserPlugin<T> {
    /// Create a new plugin that connects to the given signaling server room URL.
    pub fn new(room_url: impl Into<String>) -> Self {
        Self {
            config: SymbiosMultiuserConfig {
                room_url: room_url.into(),
                ice_servers: None,
            },
            _marker: PhantomData,
        }
    }

    /// Create a new plugin with full configuration control.
    pub fn with_config(config: SymbiosMultiuserConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

impl<T> Plugin for SymbiosMultiuserPlugin<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    fn build(&self, app: &mut App) {
        app.insert_resource(self.config.clone())
            .add_message::<BroadcastMessage<T>>()
            .add_message::<NetworkMessageReceived<T>>()
            .add_message::<PeerStateChanged>()
            .add_systems(Startup, open_socket)
            .add_systems(
                Update,
                (
                    systems::poll_peers,
                    systems::receive_messages::<T>,
                    systems::transmit_messages::<T>,
                )
                    .chain(),
            );
    }
}

fn open_socket(
    mut commands: Commands,
    config: Res<SymbiosMultiuserConfig>,
    #[cfg(feature = "client")] session: Option<Res<AtprotoSession>>,
) {
    let mut builder = WebRtcSocketBuilder::new(&config.room_url)
        .add_channel(ChannelConfig::reliable())
        .add_channel(ChannelConfig::unreliable());

    if let Some(ref ice) = config.ice_servers {
        builder = builder.ice_server(ice.clone());
    }

    // Always use the Symbios signaller so the relay receives SignalEnvelope
    // payloads. When an authenticated ATProto session is available, the JWT
    // is included in the WebSocket handshake; otherwise, the signaller
    // connects without authentication (anonymous mode).
    #[cfg(feature = "client")]
    {
        let signaller = match session {
            Some(s) => crate::signaller::signaller_for_session(&s),
            None => crate::signaller::signaller_anonymous(),
        };
        builder = builder.signaller_builder(signaller);
    }

    commands.open_socket(builder);
}
