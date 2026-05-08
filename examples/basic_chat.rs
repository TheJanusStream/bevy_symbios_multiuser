//! A minimal chat example using `bevy_symbios_multiuser`.
//!
//! Run with:
//! ```sh
//! cargo run --example basic_chat
//! ```
//!
//! This example connects to a matchbox signaling server and broadcasts
//! chat messages to all connected peers.

use bevy::prelude::*;
use bevy_symbios_multiuser::prelude::*;
use serde::{Deserialize, Serialize};

/// Domain-specific chat message.
#[derive(Serialize, Deserialize, Debug, Clone)]
enum ChatMessage {
    Text { author: String, body: String },
    Join(String),
    Leave(String),
}

fn main() {
    // 1. Read URL from CLI arguments, fallback to our Scaleway Caddy proxy
    let room_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://<relay ip addr>.nip.io/chat_room".to_string());

    info!("Connecting to signaling server at: {}", room_url);

    App::new()
        .add_plugins(DefaultPlugins)
        // 2. Pass the dynamic URL into the plugin
        .add_plugins(SymbiosMultiuserPlugin::<ChatMessage>::new(room_url))
        .add_systems(Update, (handle_incoming, send_periodic_hello))
        .run();
}

/// Reads incoming chat messages and logs them.
///
/// Uses the high-level [`MessagesReceived<T>`] system parameter; the
/// underlying [`NetworkQueue<T>`] resource is still accessible directly
/// for callers that want byte-budget introspection.
fn handle_incoming(mut messages: MessagesReceived<ChatMessage>) {
    for msg in messages.drain() {
        match &msg.payload {
            ChatMessage::Text { author, body } => {
                info!("[{author}]: {body}");
            }
            ChatMessage::Join(name) => {
                info!("{name} joined the room");
            }
            ChatMessage::Leave(name) => {
                info!("{name} left the room");
            }
        }
    }
}

/// Broadcasts a hello message every 3 seconds as a demonstration.
///
/// Uses the high-level [`SendMessage<T>`] system parameter, which covers
/// both [`SendMessage::broadcast`] (used here) and [`SendMessage::to`] for
/// peer-targeted sends.
fn send_periodic_hello(
    time: Res<Time>,
    mut timer: Local<Option<Timer>>,
    mut sender: SendMessage<ChatMessage>,
) {
    let timer = timer.get_or_insert_with(|| Timer::from_seconds(3.0, TimerMode::Repeating));
    timer.tick(time.delta());
    if timer.just_finished() {
        sender.broadcast(
            ChatMessage::Text {
                author: "local_peer".to_string(),
                body: "Hello from bevy_symbios_multiuser!".to_string(),
            },
            ChannelKind::Reliable,
        );
    }
}
