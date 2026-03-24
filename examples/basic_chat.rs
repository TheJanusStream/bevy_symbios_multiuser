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
    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(SymbiosMultiuserPlugin::<ChatMessage>::new(
            "wss://matchbox.example.com/chat_room",
        ))
        .add_systems(Update, (handle_incoming, send_periodic_hello))
        .run();
}

/// Reads incoming chat messages and logs them.
fn handle_incoming(mut queue: ResMut<NetworkQueue<ChatMessage>>) {
    for msg in queue.drain() {
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
fn send_periodic_hello(
    time: Res<Time>,
    mut timer: Local<Option<Timer>>,
    mut writer: MessageWriter<Broadcast<ChatMessage>>,
) {
    let timer = timer.get_or_insert_with(|| Timer::from_seconds(3.0, TimerMode::Repeating));
    timer.tick(time.delta());
    if timer.just_finished() {
        writer.write(Broadcast {
            payload: ChatMessage::Text {
                author: "local_peer".to_string(),
                body: "Hello from bevy_symbios_multiuser!".to_string(),
            },
            channel: ChannelKind::Reliable,
        });
    }
}
