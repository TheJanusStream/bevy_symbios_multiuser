//! Shared signaling protocol types used by both the relay server and client signaller.
//!
//! These types define the wire format for WebSocket messages exchanged between
//! peers and the relay during WebRTC signaling.

use serde::{Deserialize, Serialize};

/// Maximum byte length of the `peer_id` field in a [`SignalEnvelope`].
///
/// DIDs (`did:plc:abc...` is 32 chars) and UUIDs (36 chars) sit comfortably
/// under this cap. The bound is enforced inside the custom deserializer below
/// so that an oversized `peer_id` is rejected during JSON parsing — before any
/// owned `String` is allocated for it on the heap. Without that, an attacker
/// could pipeline 64 KiB frames whose `peer_id` is tens of thousands of bytes
/// of garbage and force the parser to allocate the full duplicate on every
/// frame just to drop it at a post-parse length check.
pub const MAX_PEER_ID_LENGTH: usize = 512;

/// A signaling envelope exchanged between peers via the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// The target peer's session ID when sending. When received from the relay,
    /// this is the sender's session ID instead.
    #[serde(deserialize_with = "deserialize_bounded_peer_id")]
    pub peer_id: String,
    /// The signaling payload (SDP offer/answer, ICE candidate, or control).
    pub signal: SignalPayload,
}

/// Custom string deserializer that errors out as soon as the parser reports a
/// `peer_id` longer than [`MAX_PEER_ID_LENGTH`] bytes.
///
/// `serde_json::from_str` hands borrowed string slices into the source buffer
/// straight to `visit_borrowed_str` (and the unescaped variant to `visit_str`)
/// before any owned `String` is constructed. By rejecting at that point we
/// short-circuit `from_str` itself and never allocate the duplicate buffer
/// for an oversized field.
fn deserialize_bounded_peer_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct PeerIdVisitor;

    impl<'de> Visitor<'de> for PeerIdVisitor {
        type Value = String;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a string of at most {MAX_PEER_ID_LENGTH} bytes")
        }

        fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<String, E> {
            if v.len() > MAX_PEER_ID_LENGTH {
                return Err(E::custom(format!(
                    "peer_id exceeds {MAX_PEER_ID_LENGTH} bytes (got {})",
                    v.len()
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_str<E: Error>(self, v: &str) -> Result<String, E> {
            if v.len() > MAX_PEER_ID_LENGTH {
                return Err(E::custom(format!(
                    "peer_id exceeds {MAX_PEER_ID_LENGTH} bytes (got {})",
                    v.len()
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E: Error>(self, v: String) -> Result<String, E> {
            if v.len() > MAX_PEER_ID_LENGTH {
                return Err(E::custom(format!(
                    "peer_id exceeds {MAX_PEER_ID_LENGTH} bytes (got {})",
                    v.len()
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_string(PeerIdVisitor)
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
