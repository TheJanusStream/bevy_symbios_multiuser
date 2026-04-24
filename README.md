# bevy_symbios_multiuser

A decentralized, low-latency multiplayer plugin for the [Bevy](https://bevyengine.org/) engine.
Combines [ATProto](https://atproto.com/) for federated identity with WebRTC (via [Matchbox](https://github.com/johanhelsing/matchbox)) for peer-to-peer data transfer.

## Overview

`bevy_symbios_multiuser` provides a plug-and-play networking crate that allows any Bevy app to support collaborative, real-time multiplayer without requiring a centralized, authoritative game server.

The architecture follows a **Sovereign Broker** pattern: clients authenticate with an ATProto PDS to obtain a JWT, present it to the relay during WebSocket signaling, and then communicate peer-to-peer over WebRTC data channels. The plugin accepts any serializable type `T` and exposes Bevy messages for broadcasting and receiving, completely decoupled from specific game logic.

### Key Features

- **Generic Message Bus** — Define your own domain-specific protocol type `T: Serialize + Deserialize`, and the plugin handles serialization (via `bincode`) and transport.
- **Dual Channels** — Reliable (ordered, guaranteed) for state mutations and Unreliable (best-effort) for ephemeral presence data.
- **ATProto Authentication** — Federated identity via OAuth 2.0 + DPoP (using [`proto-blue-oauth`](https://crates.io/crates/proto-blue-oauth)). The host app drives the authorization-code exchange to produce an [`auth::AtprotoSession`] and then calls [`auth::get_service_auth`] to mint a relay-bound service auth token. The token is passed to the relay via the `Authorization` header (native) or `Sec-WebSocket-Protocol` subprotocol trick (WASM).
- **Sovereign Broker Relay** — Optional signaling server (Axum + Tokio) with ATProto JWT verification, room-based peer isolation, and defense-in-depth hardening. When `auth_required` is enabled, the relay resolves the signer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web` — domain-only DIDs use `/.well-known/did.json`, path-based DIDs use `/{path}/did.json`), extracts the `#atproto` signing key (P-256/ES256 or secp256k1/ES256K), and cryptographically verifies the JWT signature. The URL path determines the room — peers in different rooms are fully isolated and cannot exchange signals. See [Relay Hardening](#relay-hardening) for the full security inventory.
- **Custom Signaller** — A `matchbox_socket::Signaller` implementation (`SymbiosSignallerBuilder`) that bridges between the matchbox protocol and the relay's wire format, injecting the JWT during WebSocket upgrade. Supports a refreshable `TokenSource` (`signaller_with_token_source`) for long-lived applications where service auth tokens expire between reconnects, and anonymous mode (`signaller_anonymous`) for unauthenticated connections. The `TokenSource` must wrap a service auth token from `get_service_auth`, not `access_jwt` — the latter is signed by the PDS service key and cannot be verified by a third-party relay that resolves DID documents.
- **Cross-Platform** — Runs on native targets (via `async-tungstenite`) and in the browser (via `ws_stream_wasm` on WASM).
- **Bevy-Native** — Outbound messages use Bevy's `MessageWriter<Broadcast<T>>`. Inbound messages are delivered via `NetworkQueue<T>` and `PeerStateQueue<T>` resources, which are safe to drain from any schedule (`Update`, `FixedUpdate`, etc.) without risk of silent message loss. The queues are bounded (4,096 messages and 16 MiB total wire-byte budget for `NetworkQueue`) to prevent memory exhaustion from a malicious flood — excess messages are dropped with a warning. The byte cap measures raw bincode bytes off the wire, not the deserialised heap footprint of `T`, so it is set well below the actual RAM ceiling to leave headroom for types whose heap layout is larger than their wire layout.
- **Single Plugin Per App** — Only one `SymbiosMultiuserPlugin<T>` instance may be added per Bevy app. `SymbiosMultiuserConfig<T>`, `NetworkQueue<T>`, and `PeerStateQueue<T>` are generic over `T`, but the underlying `MatchboxSocket` resource is not, so a second instance (even with a different `T`) would share and corrupt the same socket. The plugin detects this at `build()` time and **panics** rather than silently allowing two owners of the socket.
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

1. **Authentication** — Each peer authenticates with their ATProto PDS via OAuth 2.0 + DPoP to obtain an [`auth::AtprotoSession`], then calls [`auth::get_service_auth`] to mint a *service auth token* scoped to the relay's DID. The OAuth access token itself is DPoP-bound and cannot be handed to a third-party relay.
2. **Signaling** — Peers connect to the relay via a room-specific URL (e.g. `wss://relay/my_room`) and present the JWT during the WebSocket handshake. The URL path determines the **room** — peers only see and communicate with other peers in the same room. On native targets, the token is sent as an `Authorization: Bearer` header. On WASM targets, the token is sent via the `Sec-WebSocket-Protocol` subprotocol trick (the browser `WebSocket` API does not support custom headers; the relay echoes the selected subprotocol back per RFC 6455). Bearer tokens are intentionally **not** accepted via query string — query parameters are routinely captured in plaintext by reverse proxy and load balancer access logs, which would leak ATProto session credentials into operator-side logs the user never consented to share. When `auth_required` is enabled, the relay resolves the issuer's DID document (via `plc.directory` for `did:plc`, or HTTPS for `did:web`), extracts the `#atproto` signing key, and cryptographically verifies the JWT signature (ES256/P-256 or ES256K/secp256k1). When `service_did` is configured, the JWT `aud` claim is also validated to prevent cross-service token replay. The authenticated DID becomes the peer's session identity. SDP offers/answers and ICE candidates are exchanged via the relay's `SignalEnvelope` wire format.
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
- **Per-target backpressure (log silencer at 50, kick at 256)** — When a target's relay channel (256 slots) is full, the sender's per-target strike counter is incremented and per-sender log emission is silenced after 50 strikes. An **aggregate** counter per target (shared across all senders) also accumulates strikes; once it crosses 256 (matching `RELAY_CHANNEL_CAPACITY`), the target's write task is shut down and the WebSocket is closed with code 1013 ("Try Again Later") so the client's reconnect logic can rebuild the mesh instead of stalling on silently dropped signals.
- **Per-target burst limit (16 msg/window)** — Each sender may route at most 16 messages to the same target per 1-second window. A single sender can therefore contribute at most ~6% of `RELAY_CHANNEL_CAPACITY`, so kicking a target via the aggregate backpressure threshold requires ~16 coordinated attackers.
- **Per-sender token-bucket rate limit (burst scaled to `max_peers`, refill 20/s)** — Burst capacity is `max(1024, max_peers × 16)`, capped at 16,384 (default relay with `max_peers=512` → 8,192). Enough headroom to absorb a full-mesh WebRTC init without dropping legitimate SDP offers or ICE candidates. A peer that still exhausts the budget is **disconnected** — the signaling channel does not retransmit, so surfacing a hard error lets the client's reconnect logic recover instead of leaving the mesh silently stalled.
- **Unique target cap (`clamp(max_peers, 256, 4096)` per window)** — Each sender may address at most this many distinct targets per 1-second window (4,096 when `max_peers = 0`/unlimited). Senders that exceed the cap are disconnected to prevent per-target counter-map bloat from forged random target IDs.
- **JWT audience validation** — When `service_did` is set, the relay validates the JWT `aud` claim to prevent cross-service token replay.
- **Room isolation** — Cross-room signals are dropped; peers only see events from peers in the same room.

### Running the Basic Chat Example

```sh
cargo run --example basic_chat
```

### Running the Oasis Example

> **Note:** the `oasis` example predates the 0.3 OAuth refactor and is disabled by default. It is retained under the `legacy_oasis_example` Cargo feature until it has been ported to the new OAuth-driven flow; do not use it as a reference for the current API. The downstream `symbios-overlands` client carries the canonical OAuth wiring in the meantime.

```sh
cargo run --example oasis --features legacy_oasis_example   # legacy, will not compile against 0.3 API
```

## ATProto Authentication

As of 0.3, this crate no longer offers App-Password login helpers. The host application is responsible for driving the OAuth 2.0 + DPoP authorization-code flow (via [`proto-blue-oauth`](https://crates.io/crates/proto-blue-oauth)) and building an [`AtprotoSession`] from the resulting `OAuthSession`. The `auth` module then exposes one helper — [`get_service_auth`] — that mints a relay-bound service auth token from the authenticated session.

```rust
use bevy_symbios_multiuser::auth::{AtprotoSession, get_service_auth};
use proto_blue_oauth::OAuthSession;
use std::sync::Arc;

// `oauth_session` is produced by the host app's OAuth flow (see
// `proto-blue-oauth` for authorization-code exchange + DPoP setup).
let session = AtprotoSession {
    did: "did:plc:abc123...".to_string(),
    handle: "alice.bsky.social".to_string(),
    pds_url: "https://bsky.social".to_string(),
    session: Arc::new(oauth_session),
};
println!("Authenticated as DID: {}", session.did);
```

**Important:** The OAuth access token inside `AtprotoSession::session` is DPoP-bound to the user's private key and cannot be presented to a third-party relay (the relay has no way to verify the DPoP proof). Use [`get_service_auth`] to obtain a *service auth token* — a JWT signed by the user's `#atproto` key (held by the PDS on their behalf) that any relay can verify by resolving the user's DID document:

```rust
// Obtain a service auth token for relay authentication.
// `aud` must match the relay's `service_did` if audience validation is enabled.
let service_token = get_service_auth(
    &session,
    "did:web:relay.example.com",  // aud: the relay's service DID
).await?;
```

Wrap the service token in a `TokenSourceRes` resource. The plugin reads the current token from this resource on every connection/reconnect attempt, so swapping the inner value via [`TokenSource::set`] is enough to roll over to a fresh token:

```rust
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};

let token_source = TokenSource::new(Some(service_token));
app.insert_resource(session);                                    // optional — for UI-level identity (DID, handle)
app.insert_resource(TokenSourceRes(token_source.clone()));       // required for authenticated relay connection
app.add_plugins(SymbiosMultiuserPlugin::<GameMessage>::new(
    "wss://relay.example.com/ws",
));
```

> **Note:** the plugin never reads `AtprotoSession` for authentication — only `TokenSourceRes`. Inserting `AtprotoSession` is optional and is purely for application-level use (displaying the user's handle in UI, verifying peer identity via `PeerSessionMapRes`, etc.).

For games with a login screen, use the deferred constructor to register systems without opening a socket. Insert the resources later (e.g. from a system that polls the completion of the host's OAuth task) to open the connection:

```rust
// Deferred connection (session obtained after login):
app.add_plugins(SymbiosMultiuserPlugin::<GameMessage>::deferred());

// Later, once the OAuth flow has returned an `AtprotoSession` and a service
// auth token has been issued, insert these resources to open the connection:
let source = TokenSource::new(Some(service_token));
commands.insert_resource(session);
commands.insert_resource(TokenSourceRes(source));
commands.insert_resource(SymbiosMultiuserConfig::<GameMessage> {
    room_url: "wss://relay.example.com/ws".to_string(),
    ice_servers: None,
    _marker: std::marker::PhantomData,
});
```

### Token Refresh for Long-Lived Apps

Service auth tokens are short-lived (minutes). The OAuth access token inside `AtprotoSession::session` is refreshed transparently by `proto-blue-oauth` whenever the inner `OAuthSession` makes a request, so the only thing the host needs to rotate manually is the service auth token handed to the relay. Re-issue it periodically (or on 401 from the relay) and swap the value inside `TokenSource` via [`TokenSource::set`]:

```rust
use bevy_symbios_multiuser::auth::get_service_auth;
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};

let token_source = TokenSource::new(Some(service_token));
app.insert_resource(TokenSourceRes(token_source.clone()));

// Later, when the service auth token is near expiry:
let new_service_token = get_service_auth(&session, "did:web:relay.example.com").await?;
token_source.set(Some(new_service_token));
```

`TokenSource::get` clones the inner value and releases the read guard before returning, and `TokenSource::set` acquires the write guard only for the duration of the swap — the lock is never held across an `.await`, so the signaller's reconnect path cannot deadlock against a host refreshing tokens over the network.

## Modules

| Module | Description |
| --- | --- |
| `plugin` | `SymbiosMultiuserPlugin<T>`, `SymbiosMultiuserConfig<T>` — the main Bevy plugin and its generic configuration |
| `messages` | `Broadcast<T>`, `NetworkReceived<T>`, `NetworkQueue<T>`, `ChannelKind`, `PeerConnectionState`, `PeerStateChanged`, `PeerStateQueue<T>` |
| `systems` | ECS systems for transmit, receive, and peer state polling; `bincode_options()` for serialization compatibility |
| `protocol` | Shared signaling wire format (`SignalEnvelope`, `SignalPayload`) |
| `auth` | OAuth-backed `AtprotoSession` (host-constructed from a `proto_blue_oauth::OAuthSession`) and `get_service_auth` for minting relay-bound service auth tokens (feature: `client`) |
| `signaller` | Custom `matchbox_socket::Signaller` with JWT injection, refreshable `TokenSource`/`TokenSourceRes` for reconnects, anonymous mode, and `PeerSessionMapRes` for DID verification of remote peers (feature: `client`) |
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
