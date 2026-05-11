//! End-to-end OAuth-to-relay flow.
//!
//! Run with:
//! ```sh
//! cargo run --example login_to_relay -- \
//!     --pds https://bsky.social \
//!     --relay wss://relay.example.com/my_room \
//!     --relay-did did:web:relay.example.com
//! ```
//!
//! What this example demonstrates, in one self-contained file:
//!
//! 1. Discover the user's authorization server from a PDS URL via
//!    `.well-known/oauth-protected-resource`.
//! 2. Drive the OAuth 2.0 + DPoP authorization-code flow with
//!    [`proto_blue_oauth`].
//! 3. Catch the redirect on a `tiny_http` loopback listener, exchange the
//!    code for an [`OAuthSession`], and resolve DID + handle from
//!    `com.atproto.server.getSession`.
//! 4. Build a [`bevy_symbios_multiuser::auth::AtprotoSession`] and call
//!    [`get_service_auth`] to mint the relay-bound JWT.
//! 5. Wrap the token in a [`TokenSource`] / [`TokenSourceRes`] resource and
//!    install [`SymbiosMultiuserPlugin::deferred`].
//! 6. Insert the [`SymbiosMultiuserConfig`] from a one-shot system once the
//!    OAuth task finishes — the plugin opens the socket on the next frame.
//! 7. Run a tiny Bevy app that pings the room every 3 s.
//!
//! This is **native-only**. The WASM equivalent uses page redirects and
//! `sessionStorage` instead of a loopback callback; see the README's
//! "Authentication" section for that path.

use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bevy::prelude::*;
use bevy_symbios_multiuser::auth::{AtprotoSession, get_service_auth};
use bevy_symbios_multiuser::prelude::*;
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};
use proto_blue_oauth::client::dpop_key_from_jwk;
use proto_blue_oauth::{
    AuthState, OAuthClient, OAuthClientMetadata, OAuthServerMetadata, OAuthSession,
};
use serde::{Deserialize, Serialize};

const NATIVE_CALLBACK_PORT: u16 = 3456;

// ────────────────────────────────────────────────────────────────────────
// Domain protocol (anything `Serialize + Deserialize + Send + Sync + Clone +
// Debug + 'static` works)
// ────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
enum DemoMessage {
    Ping { from: String },
}

// ────────────────────────────────────────────────────────────────────────
// CLI args
// ────────────────────────────────────────────────────────────────────────

struct Args {
    pds_url: String,
    room_url: String,
    relay_did: String,
}

fn parse_args() -> Args {
    let mut pds_url = None::<String>;
    let mut room_url = None::<String>;
    let mut relay_did = None::<String>;
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--pds" => pds_url = it.next(),
            "--relay" => room_url = it.next(),
            "--relay-did" => relay_did = it.next(),
            other => eprintln!("warning: ignoring unknown argument {other:?}"),
        }
    }
    Args {
        pds_url: pds_url.unwrap_or_else(|| "https://bsky.social".into()),
        room_url: room_url.unwrap_or_else(|| "wss://relay.example.com/login_to_relay_demo".into()),
        relay_did: relay_did.unwrap_or_else(|| "did:web:relay.example.com".into()),
    }
}

// ────────────────────────────────────────────────────────────────────────
// OAuth: client metadata, AS discovery, callback parse, full flow
// ────────────────────────────────────────────────────────────────────────

/// Native loopback `client_id` per the atproto OAuth profile's loopback-client
/// exception. The AS derives client metadata directly from the query
/// parameters; no hosted document required.
fn native_client_metadata() -> OAuthClientMetadata {
    let scope = "atproto transition:generic";
    let redirect = format!("http://127.0.0.1:{NATIVE_CALLBACK_PORT}/callback");
    let client_id = format!(
        "http://localhost?redirect_uri={}&scope={}",
        urlencode(&redirect),
        urlencode(scope),
    );
    OAuthClientMetadata {
        client_id,
        redirect_uris: vec![redirect],
        response_types: Some(vec!["code".into()]),
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scope: Some(scope.into()),
        token_endpoint_auth_method: Some("none".into()),
        token_endpoint_auth_signing_alg: None,
        application_type: Some("native".into()),
        dpop_bound_access_tokens: Some(true),
        client_name: Some("login_to_relay example".into()),
        client_uri: None,
        logo_uri: None,
    }
}

/// Resolve the authorization-server URL from a PDS URL via
/// `.well-known/oauth-protected-resource`. Falls back to treating the input
/// as the AS itself if the document is missing (some PDS deployments serve
/// `oauth-authorization-server` directly).
async fn discover_auth_server(http: &reqwest::Client, pds_url: &str) -> Result<String, String> {
    let url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_url.trim_end_matches('/')
    );
    match http.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("parse oauth-protected-resource: {e}"))?;
            body.get("authorization_servers")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| "no authorization_servers in resource doc".into())
        }
        _ => Ok(pds_url.to_string()),
    }
}

/// Spawn a `tiny_http` listener on the loopback port. It loops until it sees
/// a `/callback?code=&state=...` whose `state` matches the cryptographic
/// random produced by [`OAuthClient::authorize`], then sends the
/// `(code, state)` pair through a channel and shuts down. Mismatched
/// requests get a 404 — a malicious browser tab cannot brick the listener
/// by issuing a forged callback.
fn start_callback_listener(
    expected_state: String,
) -> Result<std::sync::mpsc::Receiver<(String, String)>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let addr = format!("127.0.0.1:{NATIVE_CALLBACK_PORT}");
    let server = tiny_http::Server::http(&addr).map_err(|e| format!("bind {addr}: {e}"))?;

    thread::spawn(move || {
        for req in server.incoming_requests() {
            let url = req.url().to_string();
            let path_ok = url
                .split('?')
                .next()
                .map(|p| p == "/callback" || p.starts_with("/callback/"))
                .unwrap_or(false);
            let (code, state) = parse_callback_query(&url);
            let state_matches = state.as_deref() == Some(expected_state.as_str());
            let authorized = path_ok && code.is_some() && state_matches;

            let body = if authorized {
                "<!doctype html><html><body><h2>Login successful.</h2>\
                 <p>You can close this tab.</p></body></html>"
            } else {
                "Not found"
            };
            let response = tiny_http::Response::from_string(body)
                .with_status_code(if authorized { 200 } else { 404 })
                .with_header(
                    format!(
                        "Content-Type: {}",
                        if authorized {
                            "text/html; charset=utf-8"
                        } else {
                            "text/plain"
                        }
                    )
                    .parse::<tiny_http::Header>()
                    .unwrap(),
                );
            let _ = req.respond(response);

            if authorized && let (Some(code), Some(state)) = (code, state) {
                let _ = tx.send((code, state));
                break;
            }
        }
    });

    Ok(rx)
}

fn parse_callback_query(url: &str) -> (Option<String>, Option<String>) {
    let Some(q_start) = url.find('?') else {
        return (None, None);
    };
    let query = &url[q_start + 1..];
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        match k {
            "code" => code = Some(percent_decode(v)),
            "state" => state = Some(percent_decode(v)),
            _ => {}
        }
    }
    (code, state)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = (bytes[i + 1] as char).to_digit(16);
                let l = (bytes[i + 2] as char).to_digit(16);
                match (h, l) {
                    (Some(h), Some(l)) => {
                        out.push(((h << 4) | l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Run the full OAuth flow synchronously: discover, authorize, wait for
/// callback, exchange code, fetch identity. Returns everything needed to
/// build the multiuser plugin config.
async fn run_oauth_flow(
    pds_url: &str,
    relay_did: &str,
) -> Result<(AtprotoSession, String), String> {
    let oauth_client = OAuthClient::new(native_client_metadata());
    let http = reqwest::Client::new();

    println!("→ discovering authorization server for {pds_url}...");
    let auth_server = discover_auth_server(&http, pds_url).await?;
    let server_metadata: OAuthServerMetadata = oauth_client
        .discover_server(&auth_server)
        .await
        .map_err(|e| format!("discover_server: {e}"))?;

    println!("→ minting authorization URL...");
    let (auth_url, auth_state): (_, AuthState) = oauth_client
        .authorize(&server_metadata)
        .await
        .map_err(|e| format!("authorize: {e}"))?;

    let expected_state = auth_state
        .app_state
        .clone()
        .ok_or_else(|| "authorize() did not produce app_state".to_string())?;
    let listener = start_callback_listener(expected_state)?;

    println!();
    println!("Open this URL in your browser to authorize:");
    println!();
    println!("    {auth_url}");
    println!();
    println!("Waiting for redirect to http://127.0.0.1:{NATIVE_CALLBACK_PORT}/callback ...");

    let (code, _state) = listener
        .recv_timeout(Duration::from_secs(300))
        .map_err(|e| format!("callback: {e}"))?;

    println!("→ exchanging code for tokens...");
    let token_set = oauth_client
        .callback(&code, &auth_state, &server_metadata)
        .await
        .map_err(|e| format!("callback: {e}"))?;
    let did = token_set.sub.clone();
    if did.is_empty() {
        return Err("token response missing `sub` (DID)".into());
    }

    let dpop_key =
        dpop_key_from_jwk(&auth_state.dpop_key).map_err(|e| format!("dpop_key_from_jwk: {e}"))?;
    let session = Arc::new(OAuthSession::new(
        token_set,
        dpop_key,
        oauth_client.dpop_nonces().clone(),
    ));

    // For brevity the example uses the entryway `pds_url` directly. A
    // production client should resolve the user's actual PDS shard from
    // their DID document — see `symbios-overlands::pds::resolve_pds`.
    let pds_for_xrpc = pds_url.to_string();

    println!("→ fetching session identity...");
    let session_resp = session
        .get(&format!(
            "{}/xrpc/com.atproto.server.getSession",
            pds_for_xrpc.trim_end_matches('/')
        ))
        .await
        .map_err(|e| format!("getSession: {e}"))?;
    if !session_resp.status().is_success() {
        let s = session_resp.status();
        let b = session_resp.text().await.unwrap_or_default();
        return Err(format!("getSession returned {s}: {b}"));
    }
    let body: serde_json::Value = session_resp
        .json()
        .await
        .map_err(|e| format!("getSession decode: {e}"))?;
    let handle = body
        .get("handle")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>")
        .to_string();

    let atproto_session = AtprotoSession {
        did: did.clone(),
        handle: handle.clone(),
        pds_url: pds_for_xrpc,
        session,
    };

    println!("→ minting relay service-auth token (aud = {relay_did})...");
    let service_token = get_service_auth(&atproto_session, relay_did)
        .await
        .map_err(|e| format!("get_service_auth: {e}"))?;
    println!("✓ logged in as {handle} ({did}); service token acquired.");

    Ok((atproto_session, service_token))
}

// ────────────────────────────────────────────────────────────────────────
// Bevy app: deferred plugin install, then config insert when ready
// ────────────────────────────────────────────────────────────────────────

/// Pending OAuth task. Polled from a Bevy system; once it completes the
/// system inserts `TokenSourceRes` and `SymbiosMultiuserConfig`, which
/// triggers the plugin's `open_socket` system on the next frame.
#[derive(Resource)]
struct OauthOutcome {
    inner: Arc<Mutex<Option<Result<(AtprotoSession, String), String>>>>,
}

#[derive(Resource)]
struct AppArgs {
    room_url: String,
    relay_did: String,
}

fn main() {
    let args = parse_args();

    // Run the OAuth flow on a Tokio multi-thread runtime in a background
    // thread so the Bevy main thread is free to render/tick.
    let outcome = Arc::new(Mutex::new(None));
    let outcome_thread = outcome.clone();
    let pds_url = args.pds_url.clone();
    let relay_did_thread = args.relay_did.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let result = rt.block_on(run_oauth_flow(&pds_url, &relay_did_thread));
        *outcome_thread.lock().unwrap() = Some(result);
    });

    App::new()
        .add_plugins(MinimalPlugins)
        .add_plugins(bevy::log::LogPlugin::default())
        // Deferred: register systems but do NOT open a socket yet. The
        // plugin watches for `SymbiosMultiuserConfig<DemoMessage>` to be
        // inserted as a resource, then opens the socket on the next frame.
        .add_plugins(SymbiosMultiuserPlugin::<DemoMessage>::deferred())
        .insert_resource(OauthOutcome { inner: outcome })
        .insert_resource(AppArgs {
            room_url: args.room_url,
            relay_did: args.relay_did,
        })
        .add_systems(
            Update,
            (poll_oauth_outcome, send_periodic_ping, log_incoming),
        )
        .run();
}

/// Poll the OAuth task. When it completes successfully, install
/// `TokenSourceRes` (used by the signaller for every reconnect) and
/// `SymbiosMultiuserConfig` (which triggers the deferred socket open).
fn poll_oauth_outcome(
    mut commands: Commands,
    outcome: Res<OauthOutcome>,
    args: Res<AppArgs>,
    mut done: Local<bool>,
) {
    if *done {
        return;
    }
    let mut guard = outcome.inner.lock().unwrap();
    let Some(result) = guard.take() else {
        return;
    };
    *done = true;
    match result {
        Ok((session, service_token)) => {
            info!("OAuth complete; installing TokenSourceRes + plugin config");
            // Optional: insert AtprotoSession so app systems can read the
            // user's identity. The plugin itself does not read it.
            commands.insert_resource(session);

            // TokenSource: the signaller reads from this on every (re)connect,
            // so swapping the inner value via `set` rotates the token without
            // touching the plugin or the socket.
            let token_source = TokenSource::new(Some(service_token));
            commands.insert_resource(TokenSourceRes(token_source));

            // SymbiosMultiuserConfig: the deferred plugin's `open_socket`
            // system watches for this resource. Inserting it here triggers
            // the WebSocket signaling handshake on the next frame.
            commands.insert_resource(SymbiosMultiuserConfig::<DemoMessage> {
                room_url: args.room_url.clone(),
                ice_servers: None,
                _marker: std::marker::PhantomData,
            });
            info!(
                "connecting to relay at {} (aud={})",
                args.room_url, args.relay_did
            );
        }
        Err(e) => error!("OAuth failed: {e}"),
    }
}

/// Broadcast a ping every 3 seconds once the room is connected.
fn send_periodic_ping(
    time: Res<Time>,
    mut timer: Local<Option<Timer>>,
    session: Option<Res<AtprotoSession>>,
    mut sender: SendMessage<DemoMessage>,
) {
    let timer = timer.get_or_insert_with(|| Timer::from_seconds(3.0, TimerMode::Repeating));
    timer.tick(time.delta());
    if !timer.just_finished() {
        return;
    }
    let from = session
        .as_ref()
        .map(|s| s.handle.clone())
        .unwrap_or_else(|| "anonymous".into());
    sender.broadcast(DemoMessage::Ping { from }, ChannelKind::Reliable);
}

fn log_incoming(mut messages: MessagesReceived<DemoMessage>) {
    for msg in messages.drain() {
        match &msg.payload {
            DemoMessage::Ping { from } => info!("ping from {from} via {:?}", msg.sender),
        }
    }
}
