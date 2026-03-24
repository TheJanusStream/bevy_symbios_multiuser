use super::auth;
use super::did_resolver::DidResolver;
use super::{PeerEntry, RelayState};
use crate::protocol::{SignalEnvelope, SignalPayload};
use axum::{
    extract::{
        OriginalUri, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;
use uuid::Uuid;

/// RAII guard that decrements the active connection counter on drop.
///
/// Ensures the counter is always decremented even if the `on_upgrade` callback
/// is never executed (e.g. TCP drops during the HTTP upgrade handshake).
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Maximum number of queued outbound messages per peer before backpressure.
const RELAY_CHANNEL_CAPACITY: usize = 256;

/// Maximum size of a single incoming WebSocket message in bytes (64 KiB).
/// SDP offers/answers and ICE candidates are typically a few KiB at most.
const MAX_WS_MESSAGE_SIZE: usize = 64 * 1024;

/// Number of consecutive invalid messages before disconnecting a peer.
/// Prevents log exhaustion from attackers spamming malformed JSON.
const MAX_INVALID_MESSAGES: usize = 10;

/// Optional query parameters on the WebSocket upgrade URL.
///
/// Used as a legacy fallback for WASM clients that pass the ATProto JWT via
/// `?token=<jwt>`. The preferred WASM transport is the `Sec-WebSocket-Protocol`
/// subprotocol trick; this query parameter exists for compatibility.
#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    token: Option<String>,
}

/// Axum handler that upgrades an HTTP request to a WebSocket connection.
///
/// The URL path determines the peer's **room** — e.g. `wss://relay/game_A`
/// joins room `"game_A"`. Connecting to `/` joins the `"default"` room. Peers
/// only see and communicate with other peers in the same room.
///
/// When `auth_required` is enabled on the relay, the handler extracts an
/// ATProto JWT from one of three sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
/// 3. `?token=<token>` query parameter (legacy WASM fallback).
///
/// The token is validated and the authenticated DID becomes the peer's session
/// identity. Unauthenticated requests receive HTTP 401.
///
/// When `auth_required` is disabled, authentication is opportunistic: a valid
/// JWT will still be used for identity, but missing or invalid tokens are
/// silently ignored and a random UUID is assigned instead.
///
/// Connection capacity is enforced atomically *before* the async identity
/// extraction step to prevent concurrent handshakes from bypassing the limit.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(query): Query<WsQueryParams>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    // Extract the room from the URL path. Normalize so "/" and "" both map to
    // the same default room, and strip trailing slashes for consistency.
    let room = uri.path().trim_matches('/').to_string();
    let room = if room.is_empty() {
        "default".to_string()
    } else {
        room
    };
    // Atomically reserve a connection slot *before* the async identity
    // extraction to prevent TOCTOU bypasses where thousands of concurrent
    // handshakes all see `len < max_peers` before any inserts happen.
    let _conn_guard = if state.max_peers > 0 {
        let prev = state
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= state.max_peers {
            state
                .active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return (StatusCode::SERVICE_UNAVAILABLE, "Relay is at capacity").into_response();
        }
        // RAII guard: if the on_upgrade callback is never executed (e.g. TCP
        // drops during the HTTP upgrade handshake), the guard's Drop impl
        // ensures the counter is still decremented.
        Some(ConnectionGuard(Arc::clone(&state.active_connections)))
    } else {
        None
    };

    let identity = extract_identity(
        &headers,
        query.token.as_deref(),
        state.auth_required,
        state.did_resolver.as_ref(),
    )
    .await;

    // If the client used the Sec-WebSocket-Protocol subprotocol trick to pass
    // the JWT, we must echo "access_token" back or the browser will abort.
    let used_subprotocol = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let parts: Vec<&str> = s.split(',').map(str::trim).collect();
            parts.len() == 2 && parts[0] == "access_token"
        })
        .unwrap_or(false);

    match identity {
        Err(rejection) => {
            // _conn_guard drops here, decrementing the counter.
            rejection.into_response()
        }
        Ok(id) => {
            let upgrade = ws.max_message_size(MAX_WS_MESSAGE_SIZE);
            let upgrade = if used_subprotocol {
                upgrade.protocols(["access_token"])
            } else {
                upgrade
            };
            upgrade
                .on_upgrade(move |socket| handle_socket(socket, state, id, room, _conn_guard))
                .into_response()
        }
    }
}

/// Attempt to extract a [`ValidatedIdentity`](auth::ValidatedIdentity) from
/// one of three sources (checked in order):
///
/// 1. `Authorization: Bearer <token>` header (native clients).
/// 2. `Sec-WebSocket-Protocol: access_token, <token>` header (WASM clients).
/// 3. `?token=<token>` query parameter (legacy WASM fallback).
///
/// Returns `Err` with a 401 response only when `auth_required` is true and
/// no valid token is found in any source.
async fn extract_identity(
    headers: &HeaderMap,
    query_token: Option<&str>,
    auth_required: bool,
    resolver: Option<&DidResolver>,
) -> Result<Option<auth::ValidatedIdentity>, (StatusCode, &'static str)> {
    // 1. Try the Authorization header first (native clients).
    let header_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    // 2. Fall back to Sec-WebSocket-Protocol subprotocol (WASM clients).
    //    The browser sends `Sec-WebSocket-Protocol: access_token, <jwt>`.
    let protocol_token = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let parts: Vec<&str> = s.split(',').map(str::trim).collect();
            if parts.len() == 2 && parts[0] == "access_token" {
                Some(parts[1])
            } else {
                None
            }
        });

    // 3. Fall back to query parameter (legacy WASM clients).
    let token = header_token.or(protocol_token).or(query_token);

    let Some(token) = token else {
        if auth_required {
            return Err((StatusCode::UNAUTHORIZED, "Authorization required"));
        }
        return Ok(None);
    };

    match auth::validate_atproto_jwt(token, resolver).await {
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
    room: String,
    _conn_guard: Option<ConnectionGuard>,
) {
    let session_id = match identity {
        Some(ref id) => id.did.clone(),
        None => Uuid::new_v4().to_string(),
    };
    let conn_id = Uuid::new_v4();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (relay_tx, mut relay_rx) = mpsc::channel::<SignalEnvelope>(RELAY_CHANNEL_CAPACITY);

    // If this session ID already exists (reconnect), notify peers in the same
    // room that the old connection is gone before inserting the new one.
    if state.peers.contains_key(&session_id) {
        let leave_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
            .peers
            .iter()
            .filter(|entry| *entry.key() != session_id && entry.value().room == room)
            .map(|entry| entry.value().tx.clone())
            .collect();
        for sender in leave_senders {
            let envelope = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: SignalPayload::PeerLeft(session_id.clone()),
            };
            let _ = sender.try_send(envelope);
        }
    }

    state.peers.insert(
        session_id.clone(),
        PeerEntry {
            tx: relay_tx,
            conn_id,
            room: room.clone(),
        },
    );

    // Announce the assigned session ID to the connecting client.
    let welcome = serde_json::json!({ "type": "session_id", "id": session_id });
    if ws_tx
        .send(Message::Text(welcome.to_string().into()))
        .await
        .is_err()
    {
        state
            .peers
            .remove_if(&session_id, |_, entry| entry.conn_id == conn_id);
        // _conn_guard drops here, decrementing the counter.
        return;
    }

    // Broadcast peer list to the new peer (same room only).
    let existing_peers: Vec<String> = state
        .peers
        .iter()
        .filter(|entry| *entry.key() != session_id && entry.value().room == room)
        .map(|entry| entry.key().clone())
        .collect();
    let peer_list = serde_json::json!({ "type": "peer_list", "peers": existing_peers });
    let _ = ws_tx
        .send(Message::Text(peer_list.to_string().into()))
        .await;

    // Notify existing peers in the same room about the new peer.
    // Collect senders first to avoid holding DashMap read locks across channel sends.
    let peer_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
        .peers
        .iter()
        .filter(|entry| *entry.key() != session_id && entry.value().room == room)
        .map(|entry| entry.value().tx.clone())
        .collect();
    for sender in peer_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id.clone(),
            signal: SignalPayload::PeerJoined(session_id.clone()),
        };
        let _ = sender.try_send(envelope);
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
        let mut invalid_count: usize = 0;
        while let Some(Ok(msg)) = ws_rx.next().await {
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };

            let envelope: SignalEnvelope = match serde_json::from_str(&text) {
                Ok(e) => {
                    invalid_count = 0;
                    e
                }
                Err(err) => {
                    invalid_count += 1;
                    tracing::warn!(
                        error = %err,
                        count = invalid_count,
                        "invalid signal envelope from peer"
                    );
                    if invalid_count >= MAX_INVALID_MESSAGES {
                        tracing::warn!(
                            session = %session_id,
                            "disconnecting peer after {MAX_INVALID_MESSAGES} consecutive invalid messages"
                        );
                        break;
                    }
                    continue;
                }
            };

            // Reject control signals from clients — only the relay may
            // originate PeerJoined/PeerLeft to prevent mesh spoofing.
            if matches!(
                envelope.signal,
                SignalPayload::PeerJoined(_) | SignalPayload::PeerLeft(_)
            ) {
                tracing::warn!(
                    session = %session_id,
                    signal = ?envelope.signal,
                    "dropping forged control signal from client"
                );
                continue;
            }

            // Route to target peer, rewriting peer_id to the sender's ID.
            let target_id = envelope.peer_id.clone();
            let forwarded = SignalEnvelope {
                peer_id: session_id.clone(),
                signal: envelope.signal,
            };

            if let Some(entry) = state_write.peers.get(&target_id) {
                if entry.value().room != room {
                    tracing::warn!(
                        session = %session_id,
                        target = %target_id,
                        "dropping cross-room signal"
                    );
                } else if let Err(mpsc::error::TrySendError::Full(_)) =
                    entry.value().tx.try_send(forwarded)
                {
                    tracing::warn!(
                        target = %target_id,
                        sender = %session_id,
                        "relay channel full, dropping signal (backpressure)"
                    );
                }
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

    // Cleanup: only remove the peer entry if it still belongs to *this*
    // connection. A reconnect may have already replaced it with a new sender.
    let was_removed = state
        .peers
        .remove_if(&session_id_write, |_, entry| entry.conn_id == conn_id);
    if was_removed.is_none() {
        // Another connection owns this session ID now — skip broadcast.
        // _conn_guard drops here, decrementing the counter.
        tracing::debug!(
            session = %session_id_write,
            "stale connection cleanup skipped (session was replaced)"
        );
        return;
    }
    let remaining_senders: Vec<mpsc::Sender<SignalEnvelope>> = state
        .peers
        .iter()
        .filter(|entry| entry.value().room == room)
        .map(|entry| entry.value().tx.clone())
        .collect();
    for sender in remaining_senders {
        let envelope = SignalEnvelope {
            peer_id: session_id_write.clone(),
            signal: SignalPayload::PeerLeft(session_id_write.clone()),
        };
        let _ = sender.try_send(envelope);
    }

    // _conn_guard drops here, decrementing the counter.
    tracing::info!(session = %session_id_write, "peer disconnected");
}
