use bevy::ecs::system::SystemParam;
use bevy::prelude::*;
use matchbox_socket::PeerId;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::VecDeque;

/// Broadcast a payload to all connected peers.
///
/// The payload is serialized via `bincode` and pushed to the appropriate channel
/// based on the [`ChannelKind`] field.
///
/// Most consumers should reach for the higher-level [`SendMessage`] system
/// parameter instead of writing this message type by hand — it removes the
/// `MessageWriter<Broadcast<T>>` boilerplate and keeps the broadcast and
/// directed-send paths discoverable in one place.
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

/// Send a payload to a single peer.
///
/// Unlike [`Broadcast`], which fans out to every connected peer, `SendTo`
/// addresses one specific [`PeerId`]. WebRTC data channels are already
/// point-to-point — the relay does not see directed traffic — so directing a
/// send is a pure ECS-level abstraction over the existing matchbox channel
/// API. Targeting a peer that is not (or no longer) connected is a no-op:
/// the underlying matchbox channel silently drops the packet.
///
/// As with [`Broadcast`], most consumers should write this message via
/// [`SendMessage`] rather than constructing a `MessageWriter<SendTo<T>>` by
/// hand.
#[derive(Message, Debug, Clone)]
pub struct SendTo<T: Serialize + DeserializeOwned + Send + Sync + 'static> {
    /// The peer that should receive the payload.
    pub target: PeerId,
    /// The payload to send.
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

/// Maximum total estimated byte size of all messages in the queue (16 MiB).
/// This complements the count-based [`MAX_NETWORK_QUEUE_LEN`] limit to prevent
/// a scenario where an attacker sends a small number of maximum-sized (1 MiB)
/// messages that individually pass the count check but collectively exhaust RAM.
///
/// # Wire vs heap accounting
///
/// `packet_size` is the length of the *raw bincode byte slice* off the wire,
/// not the heap footprint of the deserialised `T`. For tightly-packed structs
/// these are very close (bincode skips Rust struct padding and uses varints
/// where applicable), but a `T` that decompresses into many separate heap
/// allocations — large `Vec<Vec<…>>`, `String`-heavy enums, sparse structs
/// with `Vec` capacity slack, etc. — can have a real RAM footprint that is
/// 1.5–2× the wire footprint.
///
/// The 16 MiB cap is therefore deliberately set well below the actual RAM
/// ceiling we are willing to spend, leaving headroom for that amplification
/// factor and for the per-message `NetworkReceived<T>` wrapper overhead.
/// Application authors that build very heap-amplified message types should
/// keep the per-message wire size compact (or shrink the type) so that the
/// wire-budget stays a meaningful proxy for the heap budget; the count limit
/// in [`MAX_NETWORK_QUEUE_LEN`] still bounds the worst-case in either dimension.
const MAX_NETWORK_QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// Bounded queue for incoming network messages.
///
/// Unlike Bevy's double-buffered `Messages`, this resource is **not** cleared
/// automatically each frame. This prevents silent message loss when the
/// consumer runs in `FixedUpdate` at a lower tick rate than the render
/// framerate. The host application must drain the queue manually.
///
/// The queue is bounded by both a count limit ([`MAX_NETWORK_QUEUE_LEN`] = 4,096
/// entries) and a total byte budget ([`MAX_NETWORK_QUEUE_BYTES`] = 16 MiB of
/// raw wire bytes). When either limit is reached, new messages are dropped and
/// a warning is logged, preventing an out-of-memory condition from a malicious
/// flood. See [`MAX_NETWORK_QUEUE_BYTES`] for the wire-vs-heap caveats.
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
    /// Whether a "queue full" warning has already been logged since the last
    /// drain. Prevents an attacker from causing frame drops via synchronous
    /// log I/O by flooding messages that hit the capacity check.
    warned_full: bool,
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> Default for NetworkQueue<T> {
    fn default() -> Self {
        Self {
            incoming: VecDeque::new(),
            total_bytes: 0,
            warned_full: false,
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
            return;
        }
        if self.total_bytes.saturating_add(msg.packet_size) > MAX_NETWORK_QUEUE_BYTES {
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
        self.warned_full = false;
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

    /// Borrow the queued messages without consuming them.
    ///
    /// Useful for read-only inspection (e.g. UI debug overlays). Note that
    /// the queue is **not** drained automatically each frame, so iter-only
    /// consumers will see the same messages on every subsequent call until
    /// some other system calls [`drain`](Self::drain).
    pub fn iter(&self) -> impl Iterator<Item = &NetworkReceived<T>> {
        self.incoming.iter()
    }

    /// Returns `true` if this packet would be dropped by [`push`](Self::push),
    /// and logs a warning the first time the queue is found full (resetting on
    /// the next [`drain`](Self::drain)).
    ///
    /// Call this *before* deserializing to avoid burning CPU on packets that are
    /// guaranteed to be discarded due to the count or byte-budget limits.
    pub(crate) fn would_drop(&mut self, packet_size: usize) -> bool {
        if self.incoming.len() >= MAX_NETWORK_QUEUE_LEN {
            if !self.warned_full {
                bevy::log::warn!(
                    "NetworkQueue full ({MAX_NETWORK_QUEUE_LEN} messages), dropping incoming messages"
                );
                self.warned_full = true;
            }
            return true;
        }
        if self.total_bytes.saturating_add(packet_size) > MAX_NETWORK_QUEUE_BYTES {
            if !self.warned_full {
                bevy::log::warn!(
                    total_bytes = self.total_bytes,
                    msg_bytes = packet_size,
                    "NetworkQueue byte budget exceeded ({MAX_NETWORK_QUEUE_BYTES} bytes), dropping incoming messages"
                );
                self.warned_full = true;
            }
            return true;
        }
        false
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
///
/// The type parameter `T` ties this queue to a specific
/// [`SymbiosMultiuserPlugin<T>`](crate::plugin::SymbiosMultiuserPlugin)
/// instance. Only one plugin instance should be added per app — the underlying
/// `MatchboxSocket` is not generic, so two instances would share the same socket.
#[derive(Resource, Debug)]
pub struct PeerStateQueue<T: Send + Sync + 'static> {
    events: VecDeque<PeerStateChanged>,
    /// Whether a "queue full" warning has already been logged since the last
    /// drain. Mirrors [`NetworkQueue::warned_full`] to prevent an attacker
    /// rapidly toggling connection states from causing a synchronous log-I/O
    /// flood on the game thread.
    warned_full: bool,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Send + Sync + 'static> Default for PeerStateQueue<T> {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            warned_full: false,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: Send + Sync + 'static> PeerStateQueue<T> {
    /// Push a peer state change onto the queue, dropping it if at capacity.
    pub(crate) fn push(&mut self, event: PeerStateChanged) {
        if self.events.len() >= MAX_NETWORK_QUEUE_LEN {
            if !self.warned_full {
                bevy::log::warn!(
                    "PeerStateQueue full ({MAX_NETWORK_QUEUE_LEN} events), dropping incoming event"
                );
                self.warned_full = true;
            }
            return;
        }
        self.events.push_back(event);
    }

    /// Drain all queued events.
    ///
    /// Uses [`std::mem::take`] so the queue is immediately empty and no
    /// lifetime borrow is held on `self`, matching [`NetworkQueue::drain`].
    /// This prevents inconsistent internal state if the caller leaks the
    /// iterator via [`std::mem::forget`].
    pub fn drain(&mut self) -> impl Iterator<Item = PeerStateChanged> {
        self.warned_full = false;
        std::mem::take(&mut self.events).into_iter()
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

/// Fired by the plugin whenever it has opened a fresh
/// [`bevy_matchbox::prelude::MatchboxSocket`] — once on initial connect, and
/// again on every reconnect after a drop.
///
/// Use this to drive UI status indicators ("connecting…" / "connected") or
/// to trigger a fresh authoritative-state pull on resync. Note that the
/// socket has only just been opened: the relay's welcome handshake (the
/// `session_id` + `peer_list` messages that assign the local
/// [`bevy_matchbox::prelude::PeerId`]) has not yet completed. Listen for
/// [`WelcomeHandshakeComplete`] if you need the local PeerId.
#[derive(Message, Debug, Clone, Copy)]
pub struct LocalSocketReopened;

/// Fired once per socket lifetime when the relay's welcome handshake has
/// completed and the local [`bevy_matchbox::prelude::PeerId`] is known.
///
/// Internally this is detected as the first frame on which
/// `MatchboxSocket::id()` returns `Some` after a fresh
/// [`LocalSocketReopened`]: the matchbox signaller buffers the relay's
/// `IdAssigned` event during the welcome handshake (`session_id`/`peer_list`
/// from the Symbios signaller's `read_welcome`) and surfaces it through
/// `socket.id()` once the ECS pulls it.
///
/// Use this when you need the local PeerId before sending peer-targeted
/// messages, or to know that the relay has actually accepted the connection
/// (vs. just having opened the WebSocket).
#[derive(Message, Debug, Clone, Copy)]
pub struct WelcomeHandshakeComplete {
    /// The local peer's id, as assigned by the relay during the welcome
    /// handshake. Stable for the lifetime of this socket; a reconnect will
    /// produce a new id and a new event.
    pub local_peer_id: PeerId,
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

/// Ergonomic [`SystemParam`] wrapper around [`NetworkQueue<T>`] for
/// inbound traffic.
///
/// Replaces the boilerplate of writing `mut queue: ResMut<NetworkQueue<T>>`
/// in every receiving system with a name that documents intent. Forwards
/// [`drain`](Self::drain), [`iter`](Self::iter), [`is_empty`](Self::is_empty),
/// and [`len`](Self::len) onto the underlying queue — the original
/// [`NetworkQueue<T>`] resource is still accessible directly when callers
/// need byte-budget introspection or other low-level operations.
///
/// # Example
///
/// ```rust,no_run
/// # use bevy::prelude::*;
/// # use bevy_symbios_multiuser::prelude::*;
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Serialize, Deserialize, Debug, Clone)]
/// # enum GameMessage { Move { x: f32, y: f32 } }
/// fn handle_incoming(mut messages: MessagesReceived<GameMessage>) {
///     for msg in messages.drain() {
///         info!("from {:?}: {:?}", msg.sender, msg.payload);
///     }
/// }
/// ```
#[derive(SystemParam)]
pub struct MessagesReceived<'w, T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    queue: ResMut<'w, NetworkQueue<T>>,
}

impl<T> MessagesReceived<'_, T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    /// Drain every queued message, leaving the queue empty.
    pub fn drain(&mut self) -> impl Iterator<Item = NetworkReceived<T>> {
        self.queue.drain()
    }

    /// Borrow the queued messages without removing them.
    pub fn iter(&self) -> impl Iterator<Item = &NetworkReceived<T>> {
        self.queue.iter()
    }

    /// `true` if no messages are currently queued.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Number of currently queued messages.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Ergonomic [`SystemParam`] for outbound traffic, covering both
/// [`Broadcast<T>`] (fan-out) and [`SendTo<T>`] (peer-targeted) sends behind
/// a single name.
///
/// Replaces the pair of writers (`MessageWriter<Broadcast<T>>` +
/// `MessageWriter<SendTo<T>>`) that consumers would otherwise enumerate by
/// hand in every system that mixes broadcasts with directed messages.
///
/// # Example
///
/// ```rust,no_run
/// # use bevy::prelude::*;
/// # use bevy_symbios_multiuser::prelude::*;
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Serialize, Deserialize, Debug, Clone)]
/// # enum GameMessage { Pong, Hello }
/// fn replies(
///     mut messages: MessagesReceived<GameMessage>,
///     mut sender: SendMessage<GameMessage>,
/// ) {
///     for msg in messages.drain() {
///         match msg.payload {
///             GameMessage::Hello => sender.broadcast(GameMessage::Hello, ChannelKind::Reliable),
///             GameMessage::Pong  => sender.to(msg.sender, GameMessage::Pong, ChannelKind::Reliable),
///         }
///     }
/// }
/// ```
#[derive(SystemParam)]
pub struct SendMessage<'w, T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    broadcasts: MessageWriter<'w, Broadcast<T>>,
    directed: MessageWriter<'w, SendTo<T>>,
}

impl<T> SendMessage<'_, T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    /// Send `payload` to every connected peer on `channel`.
    pub fn broadcast(&mut self, payload: T, channel: ChannelKind) {
        self.broadcasts.write(Broadcast { payload, channel });
    }

    /// Send `payload` only to the peer identified by `target` on `channel`.
    ///
    /// Targeting a peer that is not (or no longer) connected is a silent
    /// no-op at the matchbox channel layer — there is no error path to
    /// observe and no event is emitted.
    pub fn to(&mut self, target: PeerId, payload: T, channel: ChannelKind) {
        self.directed.write(SendTo {
            target,
            payload,
            channel,
        });
    }
}
