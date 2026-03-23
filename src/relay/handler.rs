use super::RelayState;
use super::auth;
use crate::protocol::{SignalEnvelope, SignalPayload};
use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Maximum number of queued outbound messages per peer before backpressure.
const RELAY_CHANNEL_CAPACITY: usize = 256;

/// Optional query parameters on the WebSocket upgrade URL.
///
/// WASM clients cannot set custom HTTP headers on the browser `WebSocket`
/// constructor, so they pass the ATProto JWT via `?token=<jwt>` instead.
#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    token: Option<String>,
}

/// Axum handler that upgrades an HTTP request to a WebSocket connection.
///
/// When `auth_required` is enabled on the relay, the handler extracts a
/// `Bearer` token from the `Authorization` header **or** a `token` query
/// parameter (for WASM clients), validates it as an ATProto JWT, and uses the
/// authenticated DID as the peer's session identity. Unauthenticated requests
/// receive HTTP 401.
///
/// When `auth_required` is disabled, authentication is opportunistic: a valid
/// JWT will still be used for identity, but missing or invalid tokens are
/// silently ignored and a random UUID is assigned instead.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(query): Query<WsQueryParams>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    let identity = extract_identity(&headers, query.token.as_deref(), state.auth_required);

    match identity {
        Err(rejection) => rejection.into_response(),
        Ok(id) => ws
            .on_upgrade(move |socket| handle_socket(socket, state, id))
            .into_response(),
    }
}

/// Attempt to extract a [`ValidatedIdentity`](auth::ValidatedIdentity) from
/// the `Authorization: Bearer <token>` header, falling back to a `token`
/// query parameter (used by WASM clients that cannot set custom headers).
///
/// Returns `Err` with a 401 response only when `auth_required` is true and
/// no valid token is found in either location.
fn extract_identity(
    headers: &HeaderMap,
    query_token: Option<&str>,
    auth_required: bool,
) -> Result<Option<auth::ValidatedIdentity>, (StatusCode, &'static str)> {
    // 1. Try the Authorization header first (native clients).
    let header_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    // 2. Fall back to the query parameter (WASM clients).
    let token = header_token.or(query_token);

    let Some(token) = token else {
        if auth_required {
            return Err((StatusCode::UNAUTHORIZED, "Authorization required"));
        }
        return Ok(None);
    };

    match auth::validate_atproto_jwt(token) {
        Ok(identity) => Ok(Some(identity)),
        Err(e) => {
            tracing::warn!(error = %e, "JWT validation failed");
            if auth_required {
                Err((StatusCode::UNAUTHORIZED, "Invalid JWT"))
            } else {
                Ok(None)
            }
        }
    }
}

async fn handle_socket(
    socket: WebSocket,
    state: RelayState,
    identity: Option<auth::ValidatedIdentity>,
) {
    let session_id = match identity {
        Some(ref id) => id.did.clone(),
        None => Uuid::new_v4().to_string(),
    };
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
