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

/// Validate that a PDS URL uses HTTPS to prevent credential leakage.
fn validate_pds_url(url: &str) -> Result<(), SymbiosError> {
    let trimmed = url.trim_end_matches('/');
    if !trimmed.starts_with("https://") {
        return Err(SymbiosError::AuthFailed(format!(
            "PDS URL must use HTTPS to protect credentials, got: {trimmed}"
        )));
    }
    Ok(())
}

/// Authenticate with an ATProto PDS using `com.atproto.server.createSession`.
///
/// Returns an [`AtprotoSession`] on success containing the access/refresh JWTs
/// and the authenticated DID.
pub async fn create_session(
    client: &reqwest::Client,
    credentials: &AtprotoCredentials,
) -> Result<AtprotoSession, SymbiosError> {
    validate_pds_url(&credentials.pds_url)?;

    let url = format!(
        "{}/xrpc/com.atproto.server.createSession",
        credentials.pds_url.trim_end_matches('/')
    );

    let resp = client
        .post(&url)
        .json(&CreateSessionRequest {
            identifier: &credentials.identifier,
            password: &credentials.password,
        })
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SymbiosError::AuthFailed(format!(
            "PDS returned {status}: {body}"
        )));
    }

    let response: CreateSessionResponse = resp.json().await?;

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
    client: &reqwest::Client,
    session: &AtprotoSession,
    pds_url: &str,
) -> Result<AtprotoSession, SymbiosError> {
    validate_pds_url(pds_url)?;

    let url = format!(
        "{}/xrpc/com.atproto.server.refreshSession",
        pds_url.trim_end_matches('/')
    );

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.refresh_jwt))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SymbiosError::AuthFailed(format!(
            "PDS returned {status}: {body}"
        )));
    }

    let response: RefreshSessionResponse = resp.json().await?;

    Ok(AtprotoSession {
        did: response.did,
        handle: response.handle,
        access_jwt: response.access_jwt,
        refresh_jwt: response.refresh_jwt,
    })
}
