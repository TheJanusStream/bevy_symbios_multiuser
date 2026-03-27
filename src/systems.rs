use crate::messages::{
    Broadcast, ChannelKind, NetworkQueue, NetworkReceived, PeerConnectionState, PeerStateChanged,
    PeerStateQueue,
};
use bevy::prelude::*;
use bevy_matchbox::prelude::*;
use bincode::Options;
use serde::{Serialize, de::DeserializeOwned};

/// Maximum size in bytes for a single deserialized network message.
/// Prevents OOM from malicious length-prefixed payloads.
const MAX_MESSAGE_SIZE: u64 = 1024 * 1024; // 1 MiB

/// Safe upper bound for WebRTC unreliable (SCTP unordered) data channel messages.
/// WebRTC data channels fragment over SCTP, but unreliable messages that exceed
/// the path MTU are silently dropped by many implementations. 1200 bytes is a
/// conservative limit that fits within typical MTUs.
const MAX_UNRELIABLE_MESSAGE_SIZE: usize = 1200;

/// Returns the canonical bincode options used for all network serialization.
/// Both transmit and receive **must** use this to avoid encoding mismatches.
pub fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_MESSAGE_SIZE)
        .with_fixint_encoding()
        .with_little_endian()
}

/// Polls the matchbox socket for peer connection state changes and pushes
/// them to the [`PeerStateQueue`] resource.
pub fn poll_peers<T: Send + Sync + 'static>(
    mut socket: ResMut<MatchboxSocket>,
    mut peer_queue: ResMut<PeerStateQueue<T>>,
) {
    let Ok(changes) = socket.try_update_peers() else {
        return;
    };

    for (peer, state) in changes {
        let connection_state = match state {
            PeerState::Connected => PeerConnectionState::Connected,
            PeerState::Disconnected => PeerConnectionState::Disconnected,
        };
        tracing::info!(peer = %peer, state = ?connection_state, "peer state changed");
        peer_queue.push(PeerStateChanged {
            peer,
            state: connection_state,
        });
    }
}

/// Drains incoming data from all channels, deserializes from `bincode`,
/// and pushes [`NetworkReceived<T>`] entries to the [`NetworkQueue<T>`] resource.
/// Maximum number of deserialization failures logged at `warn` level per
/// invocation of [`receive_messages`]. After this many warnings, further
/// failures are logged at `trace` to prevent an attacker from causing frame
/// drops via synchronous log I/O on the game thread.
const MAX_DESER_WARNS_PER_FRAME: usize = 3;

pub fn receive_messages<T>(mut socket: ResMut<MatchboxSocket>, mut queue: ResMut<NetworkQueue<T>>)
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    let mut deser_warn_count: usize = 0;
    for channel_kind in [ChannelKind::Reliable, ChannelKind::Unreliable] {
        let channel_idx = channel_kind.index();
        let channel = match socket.get_channel_mut(channel_idx) {
            Ok(ch) => ch,
            Err(_) => continue,
        };

        let messages = channel.receive();
        for (peer, packet) in messages {
            match bincode_options().deserialize::<T>(&packet) {
                Ok(payload) => {
                    tracing::trace!(
                        sender = %peer,
                        channel = ?channel_kind,
                        "received message"
                    );
                    queue.push(NetworkReceived {
                        payload,
                        sender: peer,
                        channel: channel_kind,
                        packet_size: packet.len(),
                    });
                }
                Err(err) => {
                    deser_warn_count += 1;
                    if deser_warn_count <= MAX_DESER_WARNS_PER_FRAME {
                        tracing::warn!(
                            sender = %peer,
                            error = %err,
                            "failed to deserialize incoming message"
                        );
                    } else {
                        tracing::trace!(
                            sender = %peer,
                            error = %err,
                            "failed to deserialize incoming message (suppressed)"
                        );
                    }
                }
            }
        }
    }
}

/// Reads [`Broadcast<T>`] messages, serializes them via `bincode`, and
/// sends the bytes to all connected peers on the specified channel.
pub fn transmit_messages<T>(
    mut socket: ResMut<MatchboxSocket>,
    mut broadcasts: MessageReader<Broadcast<T>>,
) where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    let peers: Vec<PeerId> = socket.connected_peers().collect();
    if peers.is_empty() {
        // Advance the reader cursor so stale messages aren't processed
        // if peers connect later this frame.
        broadcasts.read().for_each(drop);
        return;
    }

    for event in broadcasts.read() {
        let bytes = match bincode_options().serialize(&event.payload) {
            Ok(b) => b,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize broadcast message");
                continue;
            }
        };
        let packet: Box<[u8]> = bytes.into_boxed_slice();
        let channel_idx = event.channel.index();

        if event.channel == ChannelKind::Unreliable && packet.len() > MAX_UNRELIABLE_MESSAGE_SIZE {
            tracing::warn!(
                size = packet.len(),
                max = MAX_UNRELIABLE_MESSAGE_SIZE,
                "dropping oversized unreliable message (exceeds WebRTC MTU safe limit)"
            );
            continue;
        }

        let channel = match socket.get_channel_mut(channel_idx) {
            Ok(ch) => ch,
            Err(err) => {
                tracing::error!(channel = channel_idx, error = ?err, "channel unavailable");
                continue;
            }
        };

        // Send to all peers, avoiding one unnecessary clone by sending the
        // original packet to the last peer.
        if let Some((&last, rest)) = peers.split_last() {
            for &peer in rest {
                channel.send(packet.clone(), peer);
            }
            channel.send(packet, last);
        }
    }
}
