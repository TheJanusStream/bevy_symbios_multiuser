//! ATProto authentication via OAuth 2.0 + DPoP.
//!
//! As of 0.3.0 this crate no longer supports legacy App Password auth. All
//! authenticated calls against a user's PDS go through a
//! [`proto_blue_oauth::OAuthSession`], which automatically attaches DPoP
//! proofs and rotates per-origin nonces.
//!
//! # Runtime requirement
//!
//! Every async function in this module uses `reqwest` (via proto-blue-oauth),
//! which **requires a Tokio runtime** on native targets. Calling them from a
//! Bevy system directly will panic with `"must be called from within a Tokio
//! runtime"`. On WASM the browser's `fetch` backend is used and no runtime is
//! required.
//!
//! The recommended pattern is to spawn a detached Tokio task from a Bevy
//! `IoTaskPool` task, or to call them from inside a
//! `tokio::runtime::Runtime::block_on` block.

use std::sync::Arc;

use crate::error::SymbiosError;
use bevy::prelude::*;
use proto_blue_oauth::{OAuthClient, OAuthServerMetadata, OAuthSession};
use serde::Deserialize;

/// Response from `com.atproto.server.getServiceAuth`.
#[derive(Deserialize)]
struct GetServiceAuthResponse {
    token: String,
}

/// An authenticated ATProto session, backed by OAuth 2.0 + DPoP.
///
/// Inserted as a Bevy [`Resource`] after the host app finishes the OAuth
/// authorization-code exchange. Holds the user's identity (DID + handle), the
/// PDS base URL discovered during auth, and a shared [`OAuthSession`] that
/// stamps every outgoing request with a DPoP proof bound to the user's
/// private key.
///
/// Unlike the 0.2 App-Password-backed struct, this type is *not*
/// `Serialize`/`Deserialize`: the DPoP private key lives inside the
/// `OAuthSession` and must not be persisted by naive disk dumps. Host
/// applications that want to persist sessions should use
/// [`proto_blue_oauth::AuthState`] / [`proto_blue_oauth::TokenSet`] directly
/// and rebuild an `OAuthSession` on resume.
#[derive(Resource, Clone)]
pub struct AtprotoSession {
    /// The user's Decentralized Identifier.
    pub did: String,
    /// The user's handle (`alice.bsky.social`).
    pub handle: String,
    /// The PDS base URL (`https://bsky.social`), used to build XRPC URLs.
    pub pds_url: String,
    /// Shared DPoP-signing HTTP session. Cloneable (`Arc`) so multiple
    /// systems can issue concurrent authenticated requests without
    /// passing the resource around by mutable reference.
    pub session: Arc<OAuthSession>,
}

impl AtprotoSession {
    /// Build an authenticated XRPC URL for this session's PDS.
    pub fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.pds_url.trim_end_matches('/'), nsid)
    }
}

/// Request a service auth JWT from the user's PDS, targeting a specific
/// audience DID.
///
/// Service auth tokens are signed with the user's `#atproto` signing key
/// (held by the PDS on behalf of the user). Third-party services such as
/// relay servers verify them by resolving the user's DID document and
/// checking the signature against the `#atproto` verification key.
///
/// This is the correct token type for authenticating to relay servers: the
/// OAuth access token is DPoP-bound and cannot be handed off to a different
/// service.
///
/// # Arguments
///
/// - `aud` — The DID of the target service (e.g. `"did:web:relay.example.com"`).
pub async fn get_service_auth(session: &AtprotoSession, aud: &str) -> Result<String, SymbiosError> {
    let url = format!(
        "{}?aud={}",
        session.xrpc_url("com.atproto.server.getServiceAuth"),
        urlencode(aud),
    );
    let resp = session
        .session
        .get(&url)
        .await
        .map_err(|e| SymbiosError::AuthFailed(format!("getServiceAuth: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SymbiosError::AuthFailed(format!(
            "getServiceAuth returned {status}: {body}"
        )));
    }
    let parsed: GetServiceAuthResponse = resp
        .json()
        .await
        .map_err(|e| SymbiosError::AuthFailed(format!("getServiceAuth decode: {e}")))?;
    Ok(parsed.token)
}

/// Best-effort logout: revoke the session's tokens at the OAuth provider's
/// revocation endpoint (RFC 7009).
///
/// Refresh-then-access ordering is intentional: per RFC 7009 §2.1, revoking a
/// refresh token typically also invalidates every access token derived from
/// it on the same authorization grant, so revoking it first means even if the
/// access-token call fails the refresh token is already dead and the access
/// token will time out on its own short TTL. Both calls are attempted; the
/// first error short-circuits and is returned, leaving any later token still
/// live until expiry — consistent with RFC 7009's "implementation-specific
/// best effort" guidance.
///
/// # Local state
///
/// This function only handles the *server-side* revocation. The host
/// application is still responsible for clearing local state — calling
/// [`crate::signaller::TokenSource::set`]`(None)`, removing the
/// [`AtprotoSession`] resource, and dropping any persisted session blobs.
/// Crucially, **clear local state regardless of whether this returns
/// `Ok` or `Err`**: a failed revocation is a network glitch, not a reason
/// to leave the user partly logged in.
///
/// # Arguments
///
/// - `session` — the active [`AtprotoSession`] whose tokens should be revoked.
/// - `oauth_client` — the [`OAuthClient`] used to acquire `session` (carries
///   the registered client_id required by the revocation request).
/// - `server_metadata` — the OAuth server metadata for the user's PDS,
///   discovered during the original auth flow. Supplies `revocation_endpoint`.
///
/// `oauth_client` and `server_metadata` are taken as parameters rather than
/// pulled off [`AtprotoSession`] to avoid bloating that resource with auth
/// machinery the rest of the crate never reads. Host applications typically
/// keep them together with the session in their own login bundle (see e.g.
/// `symbios-overlands`'s `OauthRefreshCtx`).
///
/// # Runtime
///
/// Like [`get_service_auth`], requires a Tokio runtime on native targets.
///
/// # Example
///
/// ```rust,no_run
/// # use bevy_symbios_multiuser::auth::{AtprotoSession, logout};
/// # use bevy_symbios_multiuser::signaller::TokenSource;
/// # use proto_blue_oauth::{OAuthClient, OAuthServerMetadata};
/// # async fn run(
/// #     session: AtprotoSession,
/// #     oauth_client: OAuthClient,
/// #     server_metadata: OAuthServerMetadata,
/// #     token_source: TokenSource,
/// # ) {
/// // Best-effort revoke. Clear local state whether or not this succeeds.
/// if let Err(e) = logout(&session, &oauth_client, &server_metadata).await {
///     tracing::warn!(%e, "token revocation failed; clearing local state anyway");
/// }
/// token_source.set(None);
/// // …then drop the AtprotoSession resource and any persisted session blob.
/// # }
/// ```
pub async fn logout(
    session: &AtprotoSession,
    oauth_client: &OAuthClient,
    server_metadata: &OAuthServerMetadata,
) -> Result<(), SymbiosError> {
    let token_set = session.session.token_set();

    if let Some(refresh_token) = token_set.refresh_token.as_deref() {
        oauth_client
            .revoke_token(server_metadata, refresh_token)
            .await
            .map_err(|e| SymbiosError::AuthFailed(format!("revoke refresh token: {e}")))?;
    }

    oauth_client
        .revoke_token(server_metadata, &token_set.access_token)
        .await
        .map_err(|e| SymbiosError::AuthFailed(format!("revoke access token: {e}")))?;

    Ok(())
}

/// Minimal percent-encoder for the `aud` query parameter. `did:` identifiers
/// contain `:` which is reserved in a query value (RFC 3986 §3.4); encoding it
/// keeps the URL well-formed.
fn urlencode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}
