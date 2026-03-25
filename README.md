# bevy_symbios_multiuser

A decentralized, low-latency multiplayer plugin for the [Bevy](https://bevyengine.org/) engine.
Combines [ATProto](https://atproto.com/) for federated identity with WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for peer-to-peer data transfer.

## Overview

`bevy_symbios_multiuser` provides a plug-and-play networking crate that allows any Bevy app to support collaborative, real-time multiplayer without requiring a centralized, authoritative game server.

The architecture follows a **Sovereign Broker** pattern: clients authenticate with an ATProto PDS to obtain a JWT, present it to the relay during WebSocket signaling, and then communicate peer-to-peer over WebRTC data channels. The plugin accepts any serializable type `T` and exposes Bevy messages for broadcasting and receiving, completely decoupled from specific game logic.

### Key Features

- **Generic Message Bus** — Define your own domain-specific protocol type `T: Serialize + Deserialize`, and the plugin handles serialization (via `bincode`) and transport.
- **Dual Channels** — Reliable (ordered, guaranteed) for state mutations and Unreliable (best-effort) for ephemeral presence data.
- **ATProto Authentication** — Federated identity via `com.atproto.server.createSession` for Bluesky/ATProto-based auth. The JWT is passed to the relay via the `Authorization` header (native) or `Sec-WebSocket-Protocol` subprotocol trick (WASM).
- **Sovereign Broker Relay** — Optional signaling server built on Axum with full ATProto JWT verification, room-based peer isolation, and defense-in-depth hardening. When `auth_required` is enabled, the relay resolves the signer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web` — domain-only DIDs use `/.well-known/did.json`, path-based DIDs use `/{path}/did.json`), extracts the `#atproto` P-256 signing key, and cryptographically verifies the JWT signature. Resolved keys are cached in memory (5-minute TTL) with request coalescing to prevent cache stampedes; failed resolutions are negatively cached for 60 seconds to prevent DDoS reflection. The URL path determines the room — peers in different rooms are fully isolated and cannot exchange signals. Hardening includes: atomic connection limits (`max_peers`), a 64 KiB WebSocket message size cap, SSRF protection with DNS-pinning for `did:web` (capped at 100 domain clients), streamed DID document body limits (256 KiB), a 120-second idle timeout with 30-second server-side pings (for WASM keep-alive), a 15-second handshake timeout, self-targeting SDP rejection, control signal filtering, and automatic disconnect after 10 consecutive invalid messages.
- **Custom Signaller** — A `matchbox_socket::Signaller` implementation (`SymbiosSignallerBuilder`) that bridges between the matchbox protocol and the relay's wire format, injecting the JWT during WebSocket upgrade. Supports both static tokens (`signaller_for_session`) and a refreshable `TokenSource` (`signaller_with_token_source`) for long-lived applications where ATProto access tokens expire between reconnects.
- **Cross-Platform** — Runs on native targets (via `async-tungstenite`) and in the browser (via `ws_stream_wasm` on WASM).
- **Bevy-Native** — Outbound messages use Bevy's `MessageWriter<Broadcast<T>>`. Inbound messages are delivered via `NetworkQueue<T>` and `PeerStateQueue` resources, which are safe to drain from any schedule (`Update`, `FixedUpdate`, etc.) without risk of silent message loss.
- **Size-Limited Messages** — All network payloads are capped at 1 MiB to prevent OOM from malicious length-prefixed data. Unreliable-channel messages are additionally capped at 1200 bytes (a conservative WebRTC MTU-safe limit) and silently dropped if oversized.

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

fn handle_incoming(mut queue: ResMut<NetworkQueue<GameMessage>>) {
    for msg in queue.drain() {
        info!("From {:?}: {:?}", msg.sender, msg.payload);
    }
}

fn send_movement(mut writer: MessageWriter<Broadcast<GameMessage>>) {
    writer.write(Broadcast {
        payload: GameMessage::Move { x: 1.0, y: 2.0 },
        channel: ChannelKind::Unreliable,
    });
}
```

## Architecture

```text
   ┌────────────┐                                      ┌────────────┐
   │  ATProto   │                                      │  ATProto   │
   │    PDS     │                                      │    PDS     │
   └─────┬──────┘                                      └─────┬──────┘
         │ JWT                                               │ JWT
         │                ┌──────────────────┐               │
   ┌─────┴──────┐         │  Broker (Relay)  │         ┌─────┴──────┐
   │  Peer A    │   JWT   │                  │   JWT   │  Peer B    │
   │ (Bevy App) │────────►│    Axum + JWT    │◄────────│ (Bevy App) │
   └─────┬──────┘         │    Validation    │         └─────┬──────┘
         │                └──────────────────┘               │
         │                                                   │
         │                                                   │
         └───────────────────────────────────────────────────┘
                            WebRTC P2P Data
```

1. **Authentication** — Each peer authenticates with their ATProto PDS to obtain a JWT access token.
2. **Signaling** — Peers connect to the relay via a room-specific URL (e.g. `wss://relay/my_room`) and present the JWT during the WebSocket handshake. The URL path determines the **room** — peers only see and communicate with other peers in the same room. On native targets, the token is sent as an `Authorization: Bearer` header. On WASM targets, the token is sent via the `Sec-WebSocket-Protocol` subprotocol trick (the browser `WebSocket` API does not support custom headers; the relay echoes the selected subprotocol back per RFC 6455). A legacy `?token=<jwt>` query parameter fallback is also supported. When `auth_required` is enabled, the relay resolves the issuer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web`), extracts the `#atproto` signing key, and cryptographically verifies the JWT's ES256 signature. The authenticated DID becomes the peer's session identity. SDP offers/answers and ICE candidates are exchanged via the relay's `SignalEnvelope` wire format.
3. **P2P Transport** — Once signaling completes, data flows directly between peers over WebRTC data channels.
4. **Message Bus** — The `SymbiosMultiuserPlugin<T>` serializes/deserializes `T` via bincode (with a 1 MiB size limit). Outbound messages are sent via `MessageWriter<Broadcast<T>>`. Inbound messages accumulate in a `NetworkQueue<T>` resource that the host app drains at its own pace.

## Features

| Feature | Default | Description |
| --- | --- | --- |
| `client` | Yes | ATProto authentication, custom signaller for authenticated relay connections |
| `tls` | Yes | Enables TLS (via `rustls`) for both `reqwest` HTTPS (PDS) and `async-tungstenite` WebSocket (`wss://`) connections |
| `relay` | No | Sovereign Broker relay with DID-based JWT signature verification, room isolation, atomic connection limits, SSRF-hardened DID resolution (100-client cap), message size caps, idle/handshake timeouts, server-side pings (WASM keep-alive), request coalescing, and negative DID caching (`axum`/`tokio`/`p256`/`moka`) |

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

| Module | Description |
| --- | --- |
| `plugin` | `SymbiosMultiuserPlugin<T>`, `SymbiosMultiuserConfig` — the main Bevy plugin and its configuration |
| `messages` | `Broadcast<T>`, `NetworkReceived<T>`, `NetworkQueue<T>`, `ChannelKind`, `PeerConnectionState`, `PeerStateChanged`, `PeerStateQueue` |
| `systems` | ECS systems for transmit, receive, and peer state polling; `bincode_options()` for serialization compatibility |
| `protocol` | Shared signaling wire format (`SignalEnvelope`, `SignalPayload`) |
| `auth` | ATProto session creation and refresh (feature: `client`) |
| `signaller` | Custom `matchbox_socket::Signaller` with JWT injection and refreshable `TokenSource` for reconnects (feature: `client`) |
| `relay` | Sovereign Broker relay server with DID-based JWT verification (feature: `relay`) |
| `error` | `SymbiosError` error types |

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
