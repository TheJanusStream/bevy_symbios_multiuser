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
/// Derives `Serialize`/`Deserialize` so host applications can persist and
/// resume sessions (e.g. save to disk and restore via `refresh_jwt`) without
/// manual mapping boilerplate.
#[derive(Resource, Debug, Clone, Serialize, Deserialize)]
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

/// Response from `com.atproto.server.getServiceAuth`.
#[derive(Deserialize)]
struct GetServiceAuthResponse {
    token: String,
}

/// Request a service auth JWT from an ATProto PDS, targeting a specific audience DID.
///
/// Service auth tokens are signed with the user's `#atproto` signing key
/// (held by the PDS on behalf of the user). Third-party services such as relay
/// servers verify them by resolving the user's DID document and checking
/// the signature against the `#atproto` verification key.
///
/// This is the correct token type for authenticating to relay servers.
/// The access token from [`create_session`] is signed by the PDS's own service
/// key, which third parties cannot verify without resolving the PDS's DID.
///
/// # Arguments
///
/// - `aud` — The DID of the target service (e.g. `"did:web:relay.example.com"`).
///   The relay server's `service_did` must match this value if audience validation
///   is enabled on the relay. Set to any valid DID when `service_did` is `None`.
pub async fn get_service_auth(
    client: &reqwest::Client,
    session: &AtprotoSession,
    pds_url: &str,
    aud: &str,
) -> Result<String, SymbiosError> {
    validate_pds_url(pds_url)?;

    let url = format!(
        "{}/xrpc/com.atproto.server.getServiceAuth",
        pds_url.trim_end_matches('/')
    );

    let resp = client
        .get(&url)
        .query(&[("aud", aud)])
        .header("Authorization", format!("Bearer {}", session.access_jwt))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SymbiosError::AuthFailed(format!(
            "getServiceAuth returned {status}: {body}"
        )));
    }

    let response: GetServiceAuthResponse = resp.json().await?;
    Ok(response.token)
}

/// Validate that a PDS URL is a well-formed HTTPS URL with a host.
///
/// Uses `url::Url::parse` to reject malformed inputs like bare `"https://"`
/// (no host), relative paths, or non-HTTPS schemes.
fn validate_pds_url(raw: &str) -> Result<(), SymbiosError> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| SymbiosError::AuthFailed(format!("invalid PDS URL '{raw}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(SymbiosError::AuthFailed(format!(
            "PDS URL must use HTTPS to protect credentials, got: {raw}"
        )));
    }
    if parsed.host().is_none() {
        return Err(SymbiosError::AuthFailed(format!(
            "PDS URL has no host: {raw}"
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
