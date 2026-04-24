use crate::messages::{Broadcast, NetworkQueue, PeerStateQueue};
use crate::systems;
use bevy::prelude::*;
use bevy_matchbox::prelude::*;
use matchbox_socket::RtcIceServerConfig;
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::time::Duration;

/// Configuration for the symbios multiuser plugin.
///
/// The type parameter `T` ties this config to a specific
/// [`SymbiosMultiuserPlugin<T>`] instance. Only one plugin instance should be
/// added per app — the underlying `MatchboxSocket` resource is not generic, so
/// two instances would share the same socket and corrupt each other's messages.
#[derive(Resource, Debug, Clone)]
pub struct SymbiosMultiuserConfig<T> {
    /// WebSocket URL for the signaling server room.
    /// Example: `"wss://matchbox.example.com/my_room"`
    pub room_url: String,
    /// Optional ICE server configuration for NAT traversal.
    pub ice_servers: Option<RtcIceServerConfig>,
    #[doc(hidden)]
    pub _marker: PhantomData<T>,
}

/// Marker resource inserted by [`open_socket`] to prevent re-opening the
/// connection every frame. Stores the fields of [`SymbiosMultiuserConfig`]
/// that affect the socket so that any change triggers a teardown and
/// reconnect, allowing config updates without restarting the app.
///
/// Generic over `T` so each plugin instance tracks its own socket independently.
#[cfg(feature = "client")]
#[derive(Resource)]
struct SocketOpened<T> {
    room_url: String,
    /// ICE config stored as-is for change detection. `RtcIceServerConfig`
    /// lacks `PartialEq`, so comparison happens in [`ice_unchanged`] by
    /// comparing individual fields by reference — this avoids cloning the
    /// URL vector on every frame just to answer a boolean equality check.
    ice: Option<RtcIceServerConfig>,
    /// `Time::elapsed()` value captured at the moment this marker was
    /// inserted. Used by the health check to decide when a socket has been
    /// continuously healthy for long enough to count as stable, at which
    /// point any dormant [`ReconnectCooldown`] from an earlier flaky period
    /// is cleared so a later disconnect restarts backoff from
    /// [`INITIAL_RECONNECT_DELAY`] rather than inheriting a stale 60-second
    /// ceiling.
    opened_at: Duration,
    _marker: PhantomData<T>,
}

/// Exponential backoff state for socket respawn after a dead-message-loop
/// teardown. Without this, `open_socket` would spawn a fresh `WebRtcSocket`
/// on the very next frame every time the background task dies — including
/// permanent rejections like HTTP 401, which the signaller fast-fails on
/// before `futures_timer::Delay` can throttle anything. At 60+ FPS that
/// floods the relay with Upgrade requests until the user kills the client.
///
/// The cooldown is only inserted on the dead-socket teardown path; intentional
/// config-change teardowns clear it so the user can reconfigure and reconnect
/// immediately. Delay starts at [`INITIAL_RECONNECT_DELAY`] and doubles on
/// each subsequent dead-socket teardown up to [`MAX_RECONNECT_DELAY`].
#[cfg(feature = "client")]
#[derive(Resource)]
struct ReconnectCooldown<T> {
    /// `Time::elapsed()` value before which no new socket may be opened.
    /// Stored as a duration-from-startup rather than `Instant` so the resource
    /// works identically on native and wasm without pulling in `web_time`.
    next_allowed_at: Duration,
    /// Delay to apply on the next dead-socket teardown. Doubles on each
    /// consecutive failure, capped at [`MAX_RECONNECT_DELAY`].
    next_delay: Duration,
    _marker: PhantomData<T>,
}

/// Initial cooldown between the first dead-socket teardown and the next
/// respawn attempt. Chosen to match the in-signaller retry delay so the
/// retry cadence is consistent between ECS-level respawns and builder-level
/// reconnects.
#[cfg(feature = "client")]
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Cap on the exponential backoff delay. Beyond this point further failures
/// do not slow the retry rate any more, but still bound the respawn rate at
/// one attempt per minute.
#[cfg(feature = "client")]
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// How long a socket must remain continuously healthy after opening before
/// the reconnect cooldown is considered stale and cleared. Set longer than
/// the fast-fail window for HTTP 4xx handshake rejections (sub-second on
/// native, bounded by [`WASM_MAX_BLIND_RETRIES`] × retry delay on wasm) so
/// that a doomed handshake cannot transiently look healthy long enough to
/// zero out accumulated backoff. After this window elapses with the socket
/// still alive, a later disconnect restarts backoff from
/// [`INITIAL_RECONNECT_DELAY`] instead of inheriting a stale 60-second cap.
#[cfg(feature = "client")]
const SOCKET_STABILITY_THRESHOLD: Duration = Duration::from_secs(30);

/// Return `true` if the live [`RtcIceServerConfig`] matches the one recorded
/// in the [`SocketOpened`] marker. Compares field-by-field by reference to
/// avoid the per-frame heap allocations of cloning a comparable key tuple.
#[cfg(feature = "client")]
fn ice_unchanged(
    current: &Option<RtcIceServerConfig>,
    stored: &Option<RtcIceServerConfig>,
) -> bool {
    match (current, stored) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.urls == b.urls && a.username == b.username && a.credential == b.credential
        }
        _ => false,
    }
}

/// A generic multiplayer plugin that transports domain messages of type `T`
/// over WebRTC data channels.
///
/// Sets up two channels:
/// - **Channel 0** (Reliable): ordered, guaranteed delivery for state mutations.
/// - **Channel 1** (Unreliable): unordered, best-effort for ephemeral presence.
///
/// The plugin exposes a Bevy [`Message`] type [`Broadcast<T>`] for outbound
/// traffic and a [`NetworkQueue<T>`] resource for inbound traffic. Peer
/// connection state changes are delivered via [`PeerStateQueue<T>`]. The host
/// application interacts with these to send and receive domain-specific
/// messages without touching the network layer directly.
///
/// The socket connection is **not** opened at startup. Instead, the plugin
/// watches for the insertion of [`SymbiosMultiuserConfig<T>`] and opens the
/// socket on the first frame after the config resource appears. This lets
/// developers insert the config after login/menu screens rather than being
/// forced to connect immediately at app launch.
pub struct SymbiosMultiuserPlugin<T> {
    config: Option<SymbiosMultiuserConfig<T>>,
    _marker: PhantomData<T>,
}

impl<T> SymbiosMultiuserPlugin<T> {
    /// Create a new plugin that connects to the given signaling server room URL.
    ///
    /// The config is inserted immediately, so the socket opens on the first
    /// frame. For deferred connection, use [`Self::deferred`] and insert
    /// [`SymbiosMultiuserConfig<T>`] yourself when ready.
    pub fn new(room_url: impl Into<String>) -> Self {
        Self {
            config: Some(SymbiosMultiuserConfig {
                room_url: room_url.into(),
                ice_servers: None,
                _marker: PhantomData,
            }),
            _marker: PhantomData,
        }
    }

    /// Create a new plugin with full configuration control.
    ///
    /// The config is inserted immediately. For deferred connection, use
    /// [`Self::deferred`].
    pub fn with_config(config: SymbiosMultiuserConfig<T>) -> Self {
        Self {
            config: Some(config),
            _marker: PhantomData,
        }
    }

    /// Create a plugin that registers systems but does **not** insert a config.
    ///
    /// The socket will not open until the application inserts a
    /// [`SymbiosMultiuserConfig<T>`] resource (e.g. after a login screen).
    pub fn deferred() -> Self {
        Self {
            config: None,
            _marker: PhantomData,
        }
    }
}

/// The `Plugin` impl is intentionally gated on the `client` feature.
///
/// Without `client`, the Symbios signaller is absent and the plugin would
/// silently fall back to Matchbox's default signaller, which is wire-incompatible
/// with the Symbios relay's `SignalEnvelope` format. Omitting the impl makes the
/// crate fail to compile with a clear diagnostic:
///
/// ```text
/// error[E0277]: `SymbiosMultiuserPlugin<T>` does not implement `Plugin`
/// ```
///
/// Enable the `client` feature (included in `default`) to resolve this.
/// Non-generic sentinel that structurally enforces single-installation of
/// [`SymbiosMultiuserPlugin`]. `MatchboxSocket` is not generic, so two
/// concurrent instances would share and corrupt the same socket.
#[cfg(feature = "client")]
#[derive(Resource)]
struct SymbiosPluginInstalled;

#[cfg(feature = "client")]
impl<T> Plugin for SymbiosMultiuserPlugin<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static + std::fmt::Debug + Clone,
{
    fn build(&self, app: &mut App) {
        if app.world().contains_resource::<SymbiosPluginInstalled>() {
            panic!(
                "SymbiosMultiuserPlugin can only be added once per App. \
                 MatchboxSocket is a single global resource and cannot be \
                 shared across multiple plugin instances (even with different \
                 message type parameters)."
            );
        }
        app.insert_resource(SymbiosPluginInstalled);

        app.init_resource::<NetworkQueue<T>>()
            .init_resource::<PeerStateQueue<T>>()
            .init_resource::<crate::signaller::PeerSessionMapRes>()
            .add_message::<Broadcast<T>>();

        // On wasm the signaller's blind-retry counter must persist across
        // ECS-level socket respawns, otherwise a permanently-expired token
        // would retry 5 times inside the builder, fail, get respawned by the
        // backoff loop, retry 5 more times, and so on forever. The state is
        // keyed on the plugin instance via a Bevy resource so every future
        // builder the plugin constructs shares the same counter.
        #[cfg(target_arch = "wasm32")]
        app.init_resource::<crate::signaller::WasmBlindRetryStateRes>();

        app.add_systems(
            Update,
            (
                open_socket::<T>,
                (
                    systems::poll_peers::<T>,
                    systems::receive_messages::<T>,
                    systems::transmit_messages::<T>,
                )
                    .chain()
                    .run_if(resource_exists::<MatchboxSocket>),
            )
                .chain(),
        );

        if let Some(ref config) = self.config {
            app.insert_resource(config.clone());
        }
    }
}

#[cfg(feature = "client")]
#[allow(clippy::too_many_arguments)]
fn open_socket<T: Send + Sync + 'static>(
    mut commands: Commands,
    time: Res<Time>,
    config: Option<Res<SymbiosMultiuserConfig<T>>>,
    opened: Option<Res<SocketOpened<T>>>,
    socket: Option<Res<MatchboxSocket>>,
    cooldown: Option<Res<ReconnectCooldown<T>>>,
    #[cfg(feature = "client")] token_source: Option<Res<crate::signaller::TokenSourceRes>>,
    #[cfg(feature = "client")] session_map: Res<crate::signaller::PeerSessionMapRes>,
    #[cfg(all(feature = "client", target_arch = "wasm32"))] wasm_retry: Res<
        crate::signaller::WasmBlindRetryStateRes,
    >,
) {
    // Teardown: if the socket was opened but the config was removed or the
    // room URL changed, close the existing socket so a new one can be opened.
    // This prevents the "soft-locked room" problem where the SocketOpened
    // marker blocks reconnection after a config change.
    if let Some(ref marker) = opened {
        let needs_teardown = match config.as_ref() {
            None => true,
            Some(cfg) => {
                cfg.room_url != marker.room_url || !ice_unchanged(&cfg.ice_servers, &marker.ice)
            }
        };
        if needs_teardown {
            tracing::info!("tearing down socket (config removed or room changed)");
            commands.remove_resource::<SocketOpened<T>>();
            if socket.is_some() {
                commands.remove_resource::<MatchboxSocket>();
            }
            // Intentional reconfigure — clear the reconnect backoff so the
            // user's new config takes effect on the very next frame without
            // waiting out a stale cooldown from a previous failure.
            if cooldown.is_some() {
                commands.remove_resource::<ReconnectCooldown<T>>();
            }
            // Return early — the new socket (if any) will be opened next frame
            // after the deferred commands are applied.
            return;
        }
        // Config exists and URL matches. We have to detect three distinct
        // "the socket is no longer usable" cases here so the next frame can
        // open a fresh one (and pick up any refreshed token along the way):
        //
        // 1. The `MatchboxSocket` resource has been removed entirely (e.g. an
        //    external system called `commands.close_socket()`).
        // 2. The signaling/message-loop task has terminated. `bevy_matchbox`
        //    does *not* automatically remove the `MatchboxSocket` resource on
        //    a signaling drop — the `WebRtcSocket` keeps living in the ECS
        //    world while its background task is dead — so relying on
        //    `socket.is_none()` alone would silently miss every real
        //    disconnect (idle timeout, network flap, server restart) and
        //    leave the plugin in a "permanently broken but resource-present"
        //    state. We detect a dead message loop by checking
        //    `any_channel_closed()`: when the loop terminates it drops the
        //    channel receivers, which closes the channel senders that the
        //    `WebRtcSocket` exposes. Both the reliable and unreliable
        //    channels live or die together with the loop, so this catches
        //    every signaling-side drop without false positives during
        //    healthy steady-state operation.
        // 3. Neither (1) nor (2) — socket is healthy, leave everything alone.
        let socket_dead = socket.as_ref().is_some_and(|s| s.any_channel_closed());
        tracing::trace!(
            socket_present = socket.is_some(),
            socket_dead,
            "open_socket health check",
        );
        if socket.is_none() || socket_dead {
            if socket_dead {
                tracing::info!(
                    "matchbox socket message loop terminated, tearing down for reconnect"
                );
                commands.remove_resource::<MatchboxSocket>();
            } else {
                tracing::info!(
                    "socket was lost while config unchanged, clearing marker for reconnect"
                );
            }
            commands.remove_resource::<SocketOpened<T>>();
            // Arm the reconnect cooldown so the fresh-open path below does
            // not respawn until the backoff window elapses. Without this,
            // a permanent rejection (HTTP 401) causes `open_socket` to spin
            // at framerate: signaller fast-fails → message loop dies →
            // channels close → teardown here → next frame respawns → loop.
            let current_delay = cooldown
                .as_ref()
                .map(|cd| cd.next_delay)
                .unwrap_or(INITIAL_RECONNECT_DELAY);
            let next_allowed_at = time.elapsed() + current_delay;
            let next_delay = (current_delay * 2).min(MAX_RECONNECT_DELAY);
            commands.insert_resource(ReconnectCooldown::<T> {
                next_allowed_at,
                next_delay,
                _marker: PhantomData,
            });
        } else if cooldown.is_some() {
            // Healthy socket that has been alive long enough for any handshake
            // rejection (HTTP 4xx or the wasm blind-retry cap) to have
            // manifested — safe to retire a cooldown carried over from an
            // earlier flaky period so a later disconnect starts backoff from
            // scratch instead of inheriting a stale 60-second ceiling.
            let elapsed_since_opened = time.elapsed().saturating_sub(marker.opened_at);
            if elapsed_since_opened >= SOCKET_STABILITY_THRESHOLD {
                tracing::debug!(
                    elapsed_since_opened_secs = elapsed_since_opened.as_secs(),
                    "socket stable — clearing stale reconnect cooldown"
                );
                commands.remove_resource::<ReconnectCooldown<T>>();
            }
        }
        return;
    }
    let Some(config) = config else {
        return;
    };

    // Respect the exponential backoff cooldown set by the dead-socket
    // teardown branch above. Prevents ECS-level respawn storms when the
    // relay is permanently rejecting the current credential.
    if let Some(cd) = cooldown.as_ref()
        && time.elapsed() < cd.next_allowed_at
    {
        return;
    }

    tracing::debug!(
        room_url = %config.room_url,
        has_ice_servers = config.ice_servers.is_some(),
        "opening WebRTC socket",
    );

    let mut builder = WebRtcSocketBuilder::new(&config.room_url)
        .add_channel(ChannelConfig::reliable())
        .add_channel(ChannelConfig::unreliable());

    if let Some(ref ice) = config.ice_servers {
        tracing::debug!(?ice, "configuring ICE servers");
        builder = builder.ice_server(ice.clone());
    }

    // Always use the Symbios signaller so the relay receives SignalEnvelope
    // payloads. Use the shared TokenSource when present (supports token
    // refresh on reconnect). Fall back to anonymous mode — do not implicitly
    // grab AtprotoSession, as it may be present only for UI purposes and
    // silently transmitting it would cause unexpected 401 rejections.
    #[cfg(feature = "client")]
    {
        // Thread the shared `PeerSessionMap` through whichever signaller
        // variant we pick so the application can resolve peer DIDs via
        // `PeerSessionMapRes` regardless of the auth mode. On wasm, also
        // thread the persistent blind-retry state so a doomed token stays
        // doomed across respawns instead of refreshing its budget every
        // time the plugin spawns a new builder.
        let signaller = crate::signaller::signaller_full(
            token_source.map(|ts| ts.0.clone()),
            Some(session_map.0.clone()),
            #[cfg(target_arch = "wasm32")]
            Some(wasm_retry.0.clone()),
        );
        builder = builder.signaller_builder(signaller);
    }

    commands.open_socket(builder);
    commands.insert_resource(SocketOpened::<T> {
        room_url: config.room_url.clone(),
        ice: config.ice_servers.clone(),
        opened_at: time.elapsed(),
        _marker: PhantomData,
    });
}
