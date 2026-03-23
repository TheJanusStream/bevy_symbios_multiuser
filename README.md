# bevy_symbios_multiuser

A decentralized, low-latency multiplayer plugin for the [Bevy](https://bevyengine.org/) engine.
Combines [ATProto](https://atproto.com/) for federated identity with WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for peer-to-peer data transfer.

## Overview

`bevy_symbios_multiuser` provides a plug-and-play networking crate that allows any Symbios canvas to support collaborative, real-time multiplayer without requiring a centralized, authoritative game server.

The architecture follows a generic message bus pattern: the plugin accepts any serializable type `T` and exposes Bevy messages for broadcasting and receiving, completely decoupled from specific game logic.

### Key Features

- **Generic Message Bus** — Define your own domain-specific protocol type `T: Serialize + Deserialize`, and the plugin handles serialization (via `bincode`) and transport.
- **Dual Channels** — Reliable (ordered, guaranteed) for state mutations and Unreliable (best-effort) for ephemeral presence data.
- **ATProto Authentication** — Federated identity via `com.atproto.server.createSession` for Bluesky/ATProto-based auth.
- **XRPC Relay Server** — Optional signaling broker built on Axum for routing WebRTC SDP offers/answers between authenticated peers.
- **Bevy-Native** — Uses Bevy's `MessageWriter`/`MessageReader` system for seamless ECS integration.

## Quick Start

```rust
use bevy::prelude::*;
use bevy_symbios_multiuser::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
enum GameMessage {
    Move { x: f32, y: f32 },
    Chat(String),
}

fn main() {
    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
            "wss://matchbox.example.com/my_room",
        ))
        .add_systems(Update, (handle_incoming, send_movement))
        .run();
}

fn handle_incoming(mut reader: MessageReader<NetworkMessageReceived<GameMessage>>) {
    for msg in reader.read() {
        info!("From {:?}: {:?}", msg.sender, msg.payload);
    }
}

fn send_movement(mut writer: MessageWriter<BroadcastMessage<GameMessage>>) {
    writer.write(BroadcastMessage {
        payload: GameMessage::Move { x: 1.0, y: 2.0 },
        channel: ChannelKind::Unreliable,
    });
}
```

## Architecture

```text
                     ┌──────────────┐
                     │  XRPC Relay  │  (optional, feature = "relay")
                     │  (Axum WS)   │
                     └──────┬───────┘
                            │ WebSocket (SDP/ICE)
              ┌─────────────┴─────────────┐
              │                           │
        ┌─────┴─────┐              ┌──────┴────┐
        │  Peer A   │◄────────────►│  Peer B   │
        │ (Bevy App)│   WebRTC     │ (Bevy App)│
        └───────────┘  P2P Data    └───────────┘
```

1. **Signaling** — Peers connect to the relay (or any matchbox-compatible server) to exchange WebRTC SDP offers/answers.
2. **P2P Transport** — Once signaling completes, data flows directly between peers over WebRTC data channels.
3. **Message Bus** — The `SymbiosMultiuserPlugin<T>` serializes/deserializes `T` via bincode and exposes Bevy messages for the host app.

## Features

| Feature  | Default | Description                                         |
|----------|---------|-----------------------------------------------------|
| `client` | Yes     | ATProto authentication via `reqwest`                 |
| `relay`  | No      | XRPC relay signaling server built on `axum`/`tokio`  |

### Running the Relay Server

```sh
cargo run --example relay_server --features relay
```

## ATProto Authentication

The `auth` module provides functions to create and refresh ATProto sessions:

```rust
use bevy_symbios_multiuser::auth::{AtprotoCredentials, create_session};

let credentials = AtprotoCredentials {
    pds_url: "https://bsky.social".to_string(),
    identifier: "alice.bsky.social".to_string(),
    password: "app-password-here".to_string(),
};

let session = create_session(&credentials).await?;
println!("Authenticated as DID: {}", session.did);
```

## Modules

| Module   | Description                                                             |
|----------|-------------------------------------------------------------------------|
| `plugin` | `SymbiosMultiuserPlugin<T>` — the main Bevy plugin                      |
| `events` | `BroadcastMessage<T>`, `NetworkMessageReceived<T>`, `PeerStateChanged`  |
| `systems`| ECS systems for transmit, receive, and peer state polling               |
| `auth`   | ATProto session creation and refresh (feature: `client`)                |
| `relay`  | XRPC relay signaling server (feature: `relay`)                          |
| `error`  | `SymbiosError` error types                                              |

## Compatibility

| Crate              | Version |
|--------------------|---------|
| `bevy`             | 0.18    |
| `bevy_matchbox`    | 0.14    |
| `serde`            | 1.0     |

## License

MIT
