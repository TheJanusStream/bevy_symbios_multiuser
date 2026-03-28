//! Shared signaling protocol types used by both the relay server and client signaller.
//!
//! These types define the wire format for WebSocket messages exchanged between
//! peers and the relay during WebRTC signaling.

use serde::{Deserialize, Serialize};

/// A signaling envelope exchanged between peers via the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// The target peer's session ID when sending. When received from the relay,
    /// this is the sender's session ID instead.
    pub peer_id: String,
    /// The signaling payload (SDP offer/answer, ICE candidate, or control).
    pub signal: SignalPayload,
}

/// WebRTC signaling data carried inside a [`SignalEnvelope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SignalPayload {
    /// An SDP offer from the initiating peer.
    Offer(String),
    /// An SDP answer from the responding peer.
    Answer(String),
    /// An ICE candidate for NAT traversal.
    IceCandidate(String),
    /// A new peer has joined the room. The payload is the joining peer's session ID.
    PeerJoined(String),
    /// A peer has left the room. The payload is the leaving peer's session ID.
    PeerLeft(String),
}
