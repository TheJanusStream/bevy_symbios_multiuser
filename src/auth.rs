//! ATProto authentication for federated identity.
//!
//! Provides a minimal auth flow using `reqwest` to call
//! `com.atproto.server.createSession` on a Personal Data Server (PDS),
//! returning a JWT access token and the user's DID.

use crate::error::SymbiosError;
use bevy::prelude::*;
use serde::{Deserialize, Serialize};

/// Credentials used to authenticate with an ATProto PDS.
#[derive(Debug, Clone)]
pub struct AtprotoCredentials {
    /// The PDS base URL (e.g. `"https://bsky.social"`).
    pub pds_url: String,
    /// The user's handle or DID (e.g. `"alice.bsky.social"`).
    pub identifier: String,
    /// The user's password or app password.
    pub password: String,
}

/// An authenticated ATProto session containing tokens and identity.
///
/// Inserted as a Bevy [`Resource`] after successful authentication.
#[derive(Resource, Debug, Clone)]
pub struct AtprotoSession {
    /// The user's Decentralized Identifier.
    pub did: String,
    /// The user's handle.
    pub handle: String,
    /// Short-lived JWT for authenticated XRPC requests.
    pub access_jwt: String,
    /// Long-lived JWT for refreshing the access token.
    pub refresh_jwt: String,
}

#[derive(Serialize)]
struct CreateSessionRequest<'a> {
    identifier: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    did: String,
    handle: String,
    access_jwt: String,
    refresh_jwt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSessionResponse {
    did: String,
    handle: String,
    access_jwt: String,
    refresh_jwt: String,
}

/// Authenticate with an ATProto PDS using `com.atproto.server.createSession`.
///
/// Returns an [`AtprotoSession`] on success containing the access/refresh JWTs
/// and the authenticated DID.
pub async fn create_session(
    credentials: &AtprotoCredentials,
) -> Result<AtprotoSession, SymbiosError> {
    let url = format!(
        "{}/xrpc/com.atproto.server.createSession",
        credentials.pds_url.trim_end_matches('/')
    );

    let client = reqwest::Client::new();
    let response: CreateSessionResponse = client
        .post(&url)
        .json(&CreateSessionRequest {
            identifier: &credentials.identifier,
            password: &credentials.password,
        })
        .send()
        .await?
        .error_for_status()
        .map_err(|e| SymbiosError::AuthFailed(e.to_string()))?
        .json()
        .await?;

    Ok(AtprotoSession {
        did: response.did,
        handle: response.handle,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
    })
}

/// Refresh an existing ATProto session using `com.atproto.server.refreshSession`.
///
/// Returns a new [`AtprotoSession`] with updated tokens.
pub async fn refresh_session(
    session: &AtprotoSession,
    pds_url: &str,
) -> Result<AtprotoSession, SymbiosError> {
    let url = format!(
        "{}/xrpc/com.atproto.server.refreshSession",
        pds_url.trim_end_matches('/')
    );

    let client = reqwest::Client::new();
    let response: RefreshSessionResponse = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.refresh_jwt))
        .send()
        .await?
        .error_for_status()
        .map_err(|e| SymbiosError::AuthFailed(e.to_string()))?
        .json()
        .await?;

    Ok(AtprotoSession {
        did: response.did,
        handle: response.handle,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
    })
}
