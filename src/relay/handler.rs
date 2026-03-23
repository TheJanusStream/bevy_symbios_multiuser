use super::RelayState;
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Maximum number of queued outbound messages per peer before backpressure.
const RELAY_CHANNEL_CAPACITY: usize = 256;

/// A signaling envelope exchanged between peers via the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalEnvelope {
    /// The target peer's session ID. When received from the relay,
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
    /// A new peer has joined the relay.
    PeerJoined(String),
    /// A peer has left the relay.
    PeerLeft(String),
}

/// Axum handler that upgrades an HTTP request to a WebSocket connection.
///
/// Each connected client is assigned a unique session ID and registered in the
/// relay's peer map. Incoming signal envelopes are routed to the target peer.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: RelayState) {
    let session_id = Uuid::new_v4().to_string();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (relay_tx, mut relay_rx) = mpsc::channel::<SignalEnvelope>(RELAY_CHANNEL_CAPACITY);

    state.peers.insert(session_id.clone(), relay_tx);

    // Announce the assigned session ID to the connecting client.
    let welcome = serde_json::json!({ "type": "session_id", "id": session_id });
    if ws_tx
        .send(Message::Text(welcome.to_string().into()))
        .await
        .is_err()
    {
        state.peers.remove(&session_id);
        return;
    }

    // Broadcast peer list to the new peer.
    let existing_peers: Vec<String> = state
        .peers
        .iter()
        .filter(|entry| *entry.key() != session_id)
        .map(|entry| entry.key().clone())
        .collect();
    let peer_list = serde_json::json!({ "type": "peer_list", "peers": existing_peers });
    let _ = ws_tx
        .send(Message::Text(peer_list.to_string().into()))
        .await;

    // Notify existing peers about the new peer using a proper control variant.
    for entry in state.peers.iter() {
        if *entry.key() != session_id {
            let envelope = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: SignalPayload::PeerJoined(session_id.clone()),
            };
            let _ = entry.value().send(envelope).await;
        }
    }

    let session_id_write = session_id.clone();
    let state_write = state.clone();

    // Forward messages from the relay channel to the WebSocket.
    let write_task = tokio::spawn(async move {
        while let Some(envelope) = relay_rx.recv().await {
            let json = match serde_json::to_string(&envelope) {
                Ok(j) => j,
                Err(_) => continue,
            };
            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Read messages from the WebSocket and route them to the target peer.
    // If the write task dies (e.g. broken connection), stop reading too.
    let read_task = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };

            let envelope: SignalEnvelope = match serde_json::from_str(&text) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(error = %err, "invalid signal envelope from peer");
                    continue;
                }
            };

            // Route to target peer, rewriting peer_id to the sender's ID.
            let target_id = envelope.peer_id.clone();
            let forwarded = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: envelope.signal,
            };

            if let Some(sender) = state_write.peers.get(&target_id) {
                let _ = sender.value().send(forwarded).await;
            } else {
                tracing::debug!(target = %target_id, "target peer not found, dropping signal");
            }
        }
    };

    // Either task finishing causes the other to be cleaned up.
    tokio::select! {
        _ = write_task => {
            tracing::debug!(session = %session_id_write, "write task ended, stopping read");
        }
        _ = read_task => {
            tracing::debug!(session = %session_id_write, "read task ended");
        }
    }

    // Cleanup: remove peer from the map and notify others.
    state.peers.remove(&session_id_write);
    for entry in state.peers.iter() {
        let envelope = SignalEnvelope {
            peer_id: session_id_write.clone(),
            signal: SignalPayload::PeerLeft(session_id_write.clone()),
        };
        let _ = entry.value().send(envelope).await;
    }

    tracing::info!(session = %session_id_write, "peer disconnected");
}
