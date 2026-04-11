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
- **Sovereign Broker Relay** — Optional signaling server (Axum + Tokio) with ATProto JWT verification, room-based peer isolation, and defense-in-depth hardening. When `auth_required` is enabled, the relay resolves the signer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web` — domain-only DIDs use `/.well-known/did.json`, path-based DIDs use `/{path}/did.json`), extracts the `#atproto` signing key (P-256/ES256 or secp256k1/ES256K), and cryptographically verifies the JWT signature. The URL path determines the room — peers in different rooms are fully isolated and cannot exchange signals. See [Relay Hardening](#relay-hardening) for the full security inventory.
- **Custom Signaller** — A `matchbox_socket::Signaller` implementation (`SymbiosSignallerBuilder`) that bridges between the matchbox protocol and the relay's wire format, injecting the JWT during WebSocket upgrade. Supports a refreshable `TokenSource` (`signaller_with_token_source`) for long-lived applications where service auth tokens expire between reconnects, and anonymous mode (`signaller_anonymous`) for unauthenticated connections. The `TokenSource` must wrap a service auth token from `get_service_auth`, not `access_jwt` — the latter is signed by the PDS service key and cannot be verified by a third-party relay that resolves DID documents.
- **Cross-Platform** — Runs on native targets (via `async-tungstenite`) and in the browser (via `ws_stream_wasm` on WASM).
- **Bevy-Native** — Outbound messages use Bevy's `MessageWriter<Broadcast<T>>`. Inbound messages are delivered via `NetworkQueue<T>` and `PeerStateQueue<T>` resources, which are safe to drain from any schedule (`Update`, `FixedUpdate`, etc.) without risk of silent message loss. The queues are bounded (4,096 messages and 64 MiB total byte budget for `NetworkQueue`) to prevent memory exhaustion from a malicious flood — excess messages are dropped with a warning.
- **Single Plugin Per App** — Only one `SymbiosMultiuserPlugin<T>` instance should be added per Bevy app. `SymbiosMultiuserConfig<T>`, `NetworkQueue<T>`, and `PeerStateQueue<T>` are generic over `T`, but the underlying `MatchboxSocket` resource is not — adding two plugin instances would cause them to share and overwrite the same socket, resulting in message theft and connection instability.
- **Deferred Connections** — Use `SymbiosMultiuserPlugin::<T>::deferred()` to register systems without opening a socket. The socket opens automatically on the first frame after a `SymbiosMultiuserConfig<T>` resource is inserted, letting developers connect after login or menu screens instead of at app launch. For full control (e.g. custom ICE servers for NAT traversal), use `SymbiosMultiuserPlugin::<T>::with_config(config)` to pass a complete `SymbiosMultiuserConfig<T>` at plugin registration time.
- **Dynamic Room Switching** — Changing `room_url` in the `SymbiosMultiuserConfig<T>` resource (or removing the resource entirely) automatically tears down the existing socket and opens a new connection to the updated room on the next frame, without restarting the app.
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
            "wss://relay.example.com/my_room",
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
2. **Signaling** — Peers connect to the relay via a room-specific URL (e.g. `wss://relay/my_room`) and present the JWT during the WebSocket handshake. The URL path determines the **room** — peers only see and communicate with other peers in the same room. On native targets, the token is sent as an `Authorization: Bearer` header. On WASM targets, the token is sent via the `Sec-WebSocket-Protocol` subprotocol trick (the browser `WebSocket` API does not support custom headers; the relay echoes the selected subprotocol back per RFC 6455). A legacy `?token=<jwt>` query parameter fallback is also supported. When `auth_required` is enabled, the relay resolves the issuer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web`), extracts the `#atproto` signing key, and cryptographically verifies the JWT signature (ES256/P-256 or ES256K/secp256k1). When `service_did` is configured, the JWT `aud` claim is also validated to prevent cross-service token replay. The authenticated DID becomes the peer's session identity. SDP offers/answers and ICE candidates are exchanged via the relay's `SignalEnvelope` wire format.
3. **P2P Transport** — Once signaling completes, data flows directly between peers over WebRTC data channels.
4. **Message Bus** — The `SymbiosMultiuserPlugin<T>` serializes/deserializes `T` via bincode (with a 1 MiB size limit). Outbound messages are sent via `MessageWriter<Broadcast<T>>`. Inbound messages accumulate in a `NetworkQueue<T>` resource that the host app drains at its own pace.

## Features

| Feature | Default | Description |
| --- | --- | --- |
| `client` | Yes | ATProto authentication, custom signaller for authenticated relay connections |
| `tls` | Yes | Enables TLS (via `rustls`) for both `reqwest` HTTPS (PDS) and `async-tungstenite` WebSocket (`wss://`) connections |
| `relay` | No | Sovereign Broker relay with DID-based JWT signature verification (ES256 + ES256K), room isolation, atomic connection limits, SSRF-hardened DID resolution (100-client cap), message size caps, HTTP-level Slowloris protection, idle/handshake/write timeouts, server-side pings (WASM keep-alive), per-sender token-bucket rate limiting, per-target burst limiting, per-domain and global `did:web` fetch concurrency limiting, request coalescing, negative DID caching, JWT audience validation (`service_did`) (`axum`/`tokio`/`p256`/`k256`/`moka`/`dashmap`) |

### Running the Relay Server

```sh
cargo run --example relay_server --features relay
```

#### Relay Configuration

The `RelayConfig` struct accepts a `service_did` field for JWT audience validation. When set, the relay rejects tokens whose `aud` claim does not match, preventing cross-service token replay attacks:

```rust
let config = RelayConfig {
    bind_addr: "0.0.0.0:3536".to_string(),
    auth_required: true,
    max_peers: 512,
    service_did: Some("did:web:relay.example.com".to_string()),
};
```

#### Relay Hardening

The relay applies multiple independent layers of defense:

- **HTTP timeout (10 s)** — Slowloris protection: connections that do not complete the WebSocket upgrade within 10 seconds are dropped.
- **Atomic connection limits** — `max_peers` slots are reserved before DID resolution to prevent TOCTOU bypasses. New connections receive HTTP 503 when the limit is reached.
- **Handshake slot budget** — At most `max_peers / 4` connections may be in the auth/DID-resolution phase simultaneously, preventing DID tarpit attacks from exhausting all slots.
- **Handshake timeout (15 s)** — The authentication phase is capped at 15 seconds per connection.
- **WebSocket message cap (64 KiB)** — Incoming WebSocket frames are limited to 64 KiB.
- **SSRF protection** — `did:web` domains are resolved and validated against private/loopback IPs; the address is pinned via DNS to prevent rebinding. HTTP redirects are disabled.
- **DID document body limit (256 KiB)** — Responses are streamed with an incremental size check; the fetch aborts before buffering an oversized payload.
- **DID key cache (5-min TTL, 10 000 entries)** — Resolved keys are cached using W-TinyLFU eviction. `moka::future::Cache` coalesces concurrent lookups for the same DID to prevent DDoS amplification.
- **Negative DID cache (60 s)** — Failed resolutions are cached for 60 seconds to prevent DDoS reflection against DID hosting servers.
- **Domain client cap (100)** — Per-domain `reqwest::Client` instances (DNS-pinned for SSRF) are capped at 100, bounding connection-pool and worker overhead.
- **Per-domain `did:web` fetch concurrency (10)** — At most 10 concurrent in-flight fetches per `did:web` domain.
- **Global `did:web` fetch concurrency (50)** — Total concurrent `did:web` fetches across all domains.
- **Idle timeout (120 s) + server-side pings (30 s)** — Idle connections are disconnected after 120 seconds. Server pings keep WASM clients alive (browsers cannot initiate WebSocket pings).
- **WebSocket write timeout (5 s)** — Each outbound write is capped at 5 seconds, preventing an attacker that never drains their TCP receive buffer from holding a connection slot while periodic pings suppress the idle timeout.
- **Self-targeting rejection** — SDP offers/answers addressed to the sender's own session ID are dropped.
- **Control signal filtering** — Clients cannot forge `PeerJoined`/`PeerLeft` events; only the relay originates these.
- **Invalid message disconnect (10 cumulative)** — Peers that send 10 cumulative invalid messages (malformed JSON, binary frames, forged control signals) are disconnected.
- **Peer ID length cap (512 bytes)** — `peer_id` fields in `SignalEnvelope` are validated after deserialization.
- **Per-target backpressure (50 strikes)** — When a target's relay channel (256 slots) is full, delivery silently stops after 50 consecutive channel-full strikes. Successful sends reset the counter; closed channels do not accumulate strikes so reconnected peers recover immediately.
- **Per-target burst limit (64 msg/window)** — Each sender may route at most 64 messages to the same target per rate window, preventing one sender from monopolising a target's relay channel and starving signals from other peers.
- **Per-sender token-bucket rate limit (burst 500, refill 20/s)** — Messages are dropped when the token budget is exhausted; the peer remains connected so that ICE/SDP retry logic can recover.
- **Unique target cap (256/window)** — Each sender may address at most 256 distinct targets per window; senders that exceed this are disconnected.
- **JWT audience validation** — When `service_did` is set, the relay validates the JWT `aud` claim to prevent cross-service token replay.
- **Room isolation** — Cross-room signals are dropped; peers only see events from peers in the same room.

### Running the Basic Chat Example

```sh
cargo run --example basic_chat
```

### Running the Oasis Example

A multiplayer sandbox that demonstrates the full authentication flow: ATProto login, service token acquisition, `TokenSourceRes` setup, deferred plugin connection, and in-game identity display.

```sh
cargo run --example oasis
```

## ATProto Authentication

The `auth` module provides functions to create and refresh ATProto sessions, and to obtain service auth tokens for relay authentication.

```rust
use bevy_symbios_multiuser::auth::{AtprotoCredentials, create_session, get_service_auth};

let client = reqwest::Client::new();
let credentials = AtprotoCredentials {
    pds_url: "https://bsky.social".to_string(),
    identifier: "alice.bsky.social".to_string(),
    password: "app-password-here".to_string(),
};

let session = create_session(&client, &credentials).await?;
println!("Authenticated as DID: {}", session.did);
```

**Important:** The `access_jwt` from `create_session` is signed by the PDS's own service key, which third-party relays cannot verify. When connecting to a relay with `auth_required = true`, use `get_service_auth` to obtain a *service auth token* — this JWT is signed by the user's `#atproto` key (held by the PDS on their behalf) and can be verified by any relay that resolves the user's DID document:

```rust
// Obtain a service auth token for relay authentication.
// `aud` must match the relay's `service_did` if audience validation is enabled.
let service_token = get_service_auth(
    &client,
    &session,
    "https://bsky.social",        // pds_url
    "did:web:relay.example.com",  // aud: the relay's service DID
).await?;
```

Wrap the service token in a `TokenSourceRes` resource. The plugin prefers this over `AtprotoSession` and reads the latest token on each reconnect:

```rust
use std::sync::{Arc, RwLock};
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};

let token_source: TokenSource = Arc::new(RwLock::new(Some(service_token)));
app.insert_resource(session);                          // used for identity (DID, handle)
app.insert_resource(TokenSourceRes(token_source));     // used for relay authentication
app.add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
    "wss://relay.example.com/ws",
));
```

For games with a login screen, use the deferred constructor to register systems without opening a socket. Insert all resources later when ready:

```rust
// Deferred connection (session obtained after login):
app.add_plugins(SymbiosMultiuserPlugin::<GameMessage>::deferred());

// Later, after login completes (e.g. polled from an async task result in an
// Update system — see examples/oasis.rs for a full implementation), insert
// these resources to open the connection:
let source: TokenSource = Arc::new(RwLock::new(Some(service_token)));
commands.insert_resource(session);
commands.insert_resource(TokenSourceRes(source));
commands.insert_resource(SymbiosMultiuserConfig::<GameMessage> {
    room_url: "wss://relay.example.com/ws".to_string(),
    ice_servers: None,
    _marker: std::marker::PhantomData,
});
```

### Token Refresh for Long-Lived Apps

Both ATProto access tokens and service auth tokens are short-lived. For long-lived applications, refresh both when they expire and update the `TokenSource` with a new service auth token:

```rust
use std::sync::{Arc, RwLock};
use bevy_symbios_multiuser::auth::{refresh_session, get_service_auth};
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};

let token_source: TokenSource = Arc::new(RwLock::new(Some(service_token)));
app.insert_resource(TokenSourceRes(token_source.clone()));

// Later, when tokens are near expiry:
let new_session = refresh_session(&client, &session, "https://bsky.social").await?;
let new_service_token = get_service_auth(
    &client,
    &new_session,
    "https://bsky.social",
    "did:web:relay.example.com",
).await?;
*token_source.write().unwrap() = Some(new_service_token);
```

## Modules

| Module | Description |
| --- | --- |
| `plugin` | `SymbiosMultiuserPlugin<T>`, `SymbiosMultiuserConfig<T>` — the main Bevy plugin and its generic configuration |
| `messages` | `Broadcast<T>`, `NetworkReceived<T>`, `NetworkQueue<T>`, `ChannelKind`, `PeerConnectionState`, `PeerStateChanged`, `PeerStateQueue<T>` |
| `systems` | ECS systems for transmit, receive, and peer state polling; `bincode_options()` for serialization compatibility |
| `protocol` | Shared signaling wire format (`SignalEnvelope`, `SignalPayload`) |
| `auth` | ATProto session creation (`create_session`), refresh (`refresh_session`), and service auth token acquisition for relay authentication (`get_service_auth`) (feature: `client`) |
| `signaller` | Custom `matchbox_socket::Signaller` with JWT injection, refreshable `TokenSource`/`TokenSourceRes` for reconnects, and anonymous mode (feature: `client`) |
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
