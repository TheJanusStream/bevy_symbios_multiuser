# bevy_symbios_multiuser

A decentralized, low-latency multiplayer plugin for the [Bevy](https://bevyengine.org/) engine.
Combines [ATProto](https://atproto.com/) for federated identity with WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for peer-to-peer data transfer.

## Overview

`bevy_symbios_multiuser` provides a plug-and-play networking crate that allows any Symbios canvas to support collaborative, real-time multiplayer without requiring a centralized, authoritative game server.

The architecture follows a **Sovereign Broker** pattern: clients authenticate with an ATProto PDS to obtain a JWT, present it to the relay during WebSocket signaling, and then communicate peer-to-peer over WebRTC data channels. The plugin accepts any serializable type `T` and exposes Bevy messages for broadcasting and receiving, completely decoupled from specific game logic.

### Key Features

- **Generic Message Bus** — Define your own domain-specific protocol type `T: Serialize + Deserialize`, and the plugin handles serialization (via `bincode`) and transport.
- **Dual Channels** — Reliable (ordered, guaranteed) for state mutations and Unreliable (best-effort) for ephemeral presence data.
- **ATProto Authentication** — Federated identity via `com.atproto.server.createSession` for Bluesky/ATProto-based auth. The JWT is passed to the relay via the `Authorization` header (native) or `Sec-WebSocket-Protocol` subprotocol trick (WASM).
- **Sovereign Broker Relay** — Optional signaling server built on Axum that validates ATProto JWT claims (structure and expiry) and uses the authenticated DID as peer identity. Supports both authenticated and unauthenticated modes.
- **Custom Signaller** — A `matchbox_socket::Signaller` implementation (`SymbiosSignallerBuilder`) that bridges between the matchbox protocol and the relay's wire format, injecting the JWT during WebSocket upgrade.
- **Cross-Platform** — Runs on native targets (via `async-tungstenite`) and in the browser (via `ws_stream_wasm` on WASM).
- **Bevy-Native** — Uses Bevy's `MessageWriter`/`MessageReader` system for seamless ECS integration.
- **Size-Limited Messages** — All network payloads are capped at 1 MiB to prevent OOM from malicious length-prefixed data.

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
  ┌─────────────┐                                     ┌─────────────┐
  │   ATProto   │                                     │   ATProto   │
  │     PDS     │                                     │     PDS     │
  └──────┬──────┘                                     └──────┬──────┘
         │ JWT                                               │ JWT
         │                                                   │
   ┌─────┴─────┐        ┌──────────────────┐          ┌─────┴─────┐
   │  Peer A   │  JWT   │  Sovereign Broker │   JWT   │  Peer B   │
   │ (Bevy App)│───────►│     (Relay)       │◄────────│ (Bevy App)│
   └─────┬─────┘        │  Axum + JWT       │         └─────┬─────┘
         │              │  Validation       │               │
         │              └──────────────────┘                │
         │                                                  │
         └──────────────────────────────────────────────────┘
                         WebRTC P2P Data
```

1. **Authentication** — Each peer authenticates with their ATProto PDS to obtain a JWT access token.
2. **Signaling** — Peers connect to the relay and present the JWT during the WebSocket handshake. On native targets, the token is sent as an `Authorization: Bearer` header. On WASM targets, the token is sent via the `Sec-WebSocket-Protocol` subprotocol trick (the browser `WebSocket` API does not support custom headers). The relay validates JWT claims (structure and expiry) and uses the authenticated DID as the peer's session identity. SDP offers/answers and ICE candidates are exchanged via the relay's `SignalEnvelope` wire format. **Note:** cryptographic signature verification requires DID-document key resolution and is not yet implemented — deploy behind a trusted boundary until this is added.
3. **P2P Transport** — Once signaling completes, data flows directly between peers over WebRTC data channels.
4. **Message Bus** — The `SymbiosMultiuserPlugin<T>` serializes/deserializes `T` via bincode (with a 1 MiB size limit) and exposes Bevy messages for the host app.

## Features

| Feature      | Default | Description                                                                  |
|--------------|---------|------------------------------------------------------------------------------|
| `client`     | Yes     | ATProto authentication, custom signaller for authenticated relay connections  |
| `native-tls` | Yes     | Enables `rustls-tls` for `reqwest` HTTPS connections to the PDS              |
| `relay`      | No      | Sovereign Broker relay server with optional JWT validation (`axum`/`tokio`)   |

### Running the Relay Server

```sh
cargo run --example relay_server --features relay
```

## ATProto Authentication

The `auth` module provides functions to create and refresh ATProto sessions:

```rust
use bevy_symbios_multiuser::auth::{AtprotoCredentials, create_session};

let client = reqwest::Client::new();
let credentials = AtprotoCredentials {
    pds_url: "https://bsky.social".to_string(),
    identifier: "alice.bsky.social".to_string(),
    password: "app-password-here".to_string(),
};

let session = create_session(&client, &credentials).await?;
println!("Authenticated as DID: {}", session.did);
```

Insert the resulting `AtprotoSession` as a Bevy resource **before** adding the plugin, and the custom signaller will automatically use the JWT when connecting to the relay:

```rust
// After authenticating:
app.insert_resource(session);
app.add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
    "wss://relay.example.com/ws",
));
```

## Modules

| Module      | Description                                                                       |
|-------------|-----------------------------------------------------------------------------------|
| `plugin`    | `SymbiosMultiuserPlugin<T>` — the main Bevy plugin                                |
| `events`    | `BroadcastMessage<T>`, `NetworkMessageReceived<T>`, `PeerStateChanged`            |
| `systems`   | ECS systems for transmit, receive, and peer state polling                         |
| `protocol`  | Shared signaling wire format (`SignalEnvelope`, `SignalPayload`)                   |
| `auth`      | ATProto session creation and refresh (feature: `client`)                          |
| `signaller` | Custom `matchbox_socket::Signaller` with JWT injection (feature: `client`)        |
| `relay`     | Sovereign Broker relay server with JWT validation (feature: `relay`)               |
| `error`     | `SymbiosError` error types                                                        |

## Platform Support

The crate supports both **native** and **WASM** targets:

| Platform | WebSocket Transport    | JWT Delivery                                          |
|----------|------------------------|-------------------------------------------------------|
| Native   | `async-tungstenite`    | `Authorization: Bearer <token>` header                |
| WASM     | `ws_stream_wasm`       | `Sec-WebSocket-Protocol` subprotocol trick            |

On WASM targets, the browser `WebSocket` API does not allow custom HTTP headers, so the JWT is sent by requesting subprotocols `["access_token", "<jwt>"]` during the handshake. The relay extracts the token from the second element.

## Compatibility

| Crate              | Version |
|--------------------|---------|
| `bevy`             | 0.18    |
| `bevy_matchbox`    | 0.14    |
| `serde`            | 1.0     |

## License

MIT
