use bevy::prelude::*;
use matchbox_socket::PeerId;
use serde::{Deserialize, Serialize};

/// Message sent by the host application to broadcast a payload to all connected peers.
///
/// The payload is serialized via `bincode` and pushed to the appropriate channel
/// based on the [`ChannelKind`] field.
///
/// # Type Parameters
/// * `T` - The domain-specific message type. Must implement `Serialize + Deserialize`.
#[derive(Message, Debug, Clone)]
pub struct BroadcastMessage<T: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static> {
    /// The payload to broadcast to all connected peers.
    pub payload: T,
    /// Which channel to send on: [`ChannelKind::Reliable`] for state mutations,
    /// [`ChannelKind::Unreliable`] for ephemeral presence data.
    pub channel: ChannelKind,
}

/// Message fired when a network payload is received from a remote peer.
///
/// The host application reads these messages to react to incoming network data.
///
/// # Type Parameters
/// * `T` - The domain-specific message type. Must implement `Serialize + Deserialize`.
#[derive(Message, Debug, Clone)]
pub struct NetworkMessageReceived<T: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static>
{
    /// The deserialized payload from the remote peer.
    pub payload: T,
    /// The identity of the peer that sent this message.
    pub sender: PeerId,
    /// Which channel this message arrived on.
    pub channel: ChannelKind,
}

/// Message fired when a peer's connection state changes.
#[derive(Message, Debug, Clone)]
pub struct PeerStateChanged {
    /// The peer whose state changed.
    pub peer: PeerId,
    /// The new connection state.
    pub state: PeerConnectionState,
}

/// The connection state of a remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnectionState {
    /// The peer has connected and data channels are established.
    Connected,
    /// The peer has disconnected.
    Disconnected,
}

/// Selects which WebRTC data channel to use for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelKind {
    /// Ordered, guaranteed delivery. Use for state mutations.
    #[default]
    Reliable,
    /// Unordered, best-effort delivery. Use for ephemeral presence data.
    Unreliable,
}

impl ChannelKind {
    /// Returns the channel index in the matchbox socket.
    /// Channel 0 = Reliable, Channel 1 = Unreliable.
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Reliable => 0,
            Self::Unreliable => 1,
        }
    }
}
