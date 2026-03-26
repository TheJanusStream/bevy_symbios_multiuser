use bevy::prelude::*;
use matchbox_socket::PeerId;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::VecDeque;

/// Broadcast a payload to all connected peers.
///
/// The payload is serialized via `bincode` and pushed to the appropriate channel
/// based on the [`ChannelKind`] field.
///
/// # Type Parameters
/// * `T` - The domain-specific payload type. Must implement `Serialize + Deserialize`.
#[derive(Message, Debug, Clone)]
pub struct Broadcast<T: Serialize + DeserializeOwned + Send + Sync + 'static> {
    /// The payload to broadcast to all connected peers.
    pub payload: T,
    /// Which channel to send on: [`ChannelKind::Reliable`] for state mutations,
    /// [`ChannelKind::Unreliable`] for ephemeral presence data.
    pub channel: ChannelKind,
}

/// A network payload received from a remote peer.
///
/// The host application reads these to react to incoming network data.
///
/// # Type Parameters
/// * `T` - The domain-specific payload type. Must implement `Serialize + Deserialize`.
#[derive(Debug, Clone)]
pub struct NetworkReceived<T: Serialize + DeserializeOwned + Send + Sync + 'static> {
    /// The deserialized payload from the remote peer.
    pub payload: T,
    /// The identity of the peer that sent this message.
    pub sender: PeerId,
    /// Which channel this message arrived on.
    pub channel: ChannelKind,
    /// Size of the raw network packet in bytes (before deserialization).
    /// Used by [`NetworkQueue`] to enforce its byte-size budget.
    pub(crate) packet_size: usize,
}

/// Maximum number of messages buffered in a [`NetworkQueue`] before new
/// arrivals are dropped. Prevents unbounded memory growth if a remote peer
/// floods the WebRTC data channel faster than the application drains it.
const MAX_NETWORK_QUEUE_LEN: usize = 4096;

/// Maximum total estimated byte size of all messages in the queue (64 MiB).
/// This complements the count-based [`MAX_NETWORK_QUEUE_LEN`] limit to prevent
/// a scenario where an attacker sends a small number of maximum-sized (1 MiB)
/// messages that individually pass the count check but collectively exhaust RAM.
const MAX_NETWORK_QUEUE_BYTES: usize = 64 * 1024 * 1024;

/// Bounded queue for incoming network messages.
///
/// Unlike Bevy's double-buffered `Messages`, this resource is **not** cleared
/// automatically each frame. This prevents silent message loss when the
/// consumer runs in `FixedUpdate` at a lower tick rate than the render
/// framerate. The host application must drain the queue manually.
///
/// The queue is capped at [`MAX_NETWORK_QUEUE_LEN`] entries. When full,
/// new messages are dropped and a warning is logged, preventing an
/// out-of-memory condition from a malicious flood.
///
/// # Example
///
/// ```rust,ignore
/// fn handle_incoming(mut queue: ResMut<NetworkQueue<MyMsg>>) {
///     for msg in queue.drain() {
///         // process msg
///     }
/// }
/// ```
#[derive(Resource, Debug)]
pub struct NetworkQueue<T: Serialize + DeserializeOwned + Send + Sync + 'static> {
    incoming: VecDeque<NetworkReceived<T>>,
    /// Running total of `packet_size` for all queued messages.
    total_bytes: usize,
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> Default for NetworkQueue<T> {
    fn default() -> Self {
        Self {
            incoming: VecDeque::new(),
            total_bytes: 0,
        }
    }
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> NetworkQueue<T> {
    /// Push a received message onto the queue, dropping it if at capacity.
    ///
    /// Enforces both a count limit ([`MAX_NETWORK_QUEUE_LEN`]) and a byte-size
    /// budget ([`MAX_NETWORK_QUEUE_BYTES`]) to prevent memory exhaustion from
    /// a flood of large messages.
    pub(crate) fn push(&mut self, msg: NetworkReceived<T>) {
        if self.incoming.len() >= MAX_NETWORK_QUEUE_LEN {
            bevy::log::warn!(
                "NetworkQueue full ({MAX_NETWORK_QUEUE_LEN} messages), dropping incoming message"
            );
            return;
        }
        if self.total_bytes.saturating_add(msg.packet_size) > MAX_NETWORK_QUEUE_BYTES {
            bevy::log::warn!(
                total_bytes = self.total_bytes,
                msg_bytes = msg.packet_size,
                "NetworkQueue byte budget exceeded ({MAX_NETWORK_QUEUE_BYTES} bytes), dropping incoming message"
            );
            return;
        }
        self.total_bytes += msg.packet_size;
        self.incoming.push_back(msg);
    }

    /// Drain all queued messages. The caller owns the returned iterator.
    ///
    /// Uses [`std::mem::take`] to move the entire deque out, so the
    /// `total_bytes` invariant holds even if the iterator is leaked via
    /// `std::mem::forget` (unlike `VecDeque::drain`, which would leave
    /// orphaned elements in the deque with `total_bytes == 0`).
    pub fn drain(&mut self) -> impl Iterator<Item = NetworkReceived<T>> {
        self.total_bytes = 0;
        std::mem::take(&mut self.incoming).into_iter()
    }

    /// Returns `true` if there are no queued messages.
    pub fn is_empty(&self) -> bool {
        self.incoming.is_empty()
    }

    /// Returns the number of queued messages.
    pub fn len(&self) -> usize {
        self.incoming.len()
    }
}

/// A peer connection state change event.
#[derive(Debug, Clone)]
pub struct PeerStateChanged {
    /// The peer whose state changed.
    pub peer: PeerId,
    /// The new connection state.
    pub state: PeerConnectionState,
}

/// Bounded queue for peer state change events.
///
/// Like [`NetworkQueue`], this avoids the double-buffer clearing issue with
/// Bevy `Messages` so that `FixedUpdate` consumers never miss a peer
/// connect/disconnect event. Capped at [`MAX_NETWORK_QUEUE_LEN`].
#[derive(Resource, Debug, Default)]
pub struct PeerStateQueue {
    events: VecDeque<PeerStateChanged>,
}

impl PeerStateQueue {
    /// Push a peer state change onto the queue, dropping it if at capacity.
    pub(crate) fn push(&mut self, event: PeerStateChanged) {
        if self.events.len() >= MAX_NETWORK_QUEUE_LEN {
            bevy::log::warn!(
                "PeerStateQueue full ({MAX_NETWORK_QUEUE_LEN} events), dropping incoming event"
            );
            return;
        }
        self.events.push_back(event);
    }

    /// Drain all queued events.
    pub fn drain(&mut self) -> impl Iterator<Item = PeerStateChanged> + '_ {
        self.events.drain(..)
    }

    /// Returns `true` if there are no queued events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the number of queued events.
    pub fn len(&self) -> usize {
        self.events.len()
    }
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
