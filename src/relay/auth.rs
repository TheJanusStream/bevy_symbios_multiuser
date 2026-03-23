//! ATProto JWT validation for the relay server.
//!
//! Decodes and validates ATProto access JWTs presented during WebSocket
//! upgrade. Checks structural validity and token expiry, and extracts the
//! issuer DID for use as the peer's session identity.
//!
//! # Signature Verification
//!
//! Full cryptographic verification requires resolving the signer's DID
//! document to obtain their public key. This is not yet implemented —
//! the relay currently validates claims (expiry, structure) without
//! checking the signature. Deploy behind a trusted network boundary or
//! add DID-document-based key resolution before exposing to the public
//! internet.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;

/// Claims extracted from an ATProto access JWT.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are read by jsonwebtoken's validation logic
pub struct AtprotoClaims {
    /// The issuer — the user's DID (e.g. `did:plc:abc123`).
    pub iss: String,
    /// Token expiration time (Unix timestamp).
    pub exp: u64,
}

/// A successfully validated peer identity.
#[derive(Debug)]
pub struct ValidatedIdentity {
    /// The user's DID extracted from the JWT `iss` claim.
    pub did: String,
}

/// Decode and validate an ATProto access JWT.
///
/// Performs structural validation and expiry checking. Does **not** verify
/// the cryptographic signature (see module-level docs for rationale).
///
/// # Errors
///
/// Returns a human-readable error string if the token is malformed, expired,
/// or contains an invalid issuer claim.
pub fn validate_atproto_jwt(token: &str) -> Result<ValidatedIdentity, String> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = true;
    // ATProto JWTs typically use ES256 (P-256). Accept common algorithms
    // since signature verification is disabled.
    validation.algorithms = vec![Algorithm::ES256];
    // Audience validation requires knowing the relay's own URL; skip for now
    validation.validate_aud = false;

    let token_data = decode::<AtprotoClaims>(
        token,
        // Dummy key — signature verification is disabled above
        &DecodingKey::from_secret(&[]),
        &validation,
    )
    .map_err(|e| format!("JWT decode failed: {e}"))?;

    let did = &token_data.claims.iss;
    if !did.starts_with("did:") {
        return Err(format!("invalid DID in JWT issuer: {did}"));
    }

    Ok(ValidatedIdentity {
        did: did.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_token() {
        assert!(validate_atproto_jwt("").is_err());
    }

    #[test]
    fn rejects_garbage_token() {
        assert!(validate_atproto_jwt("not.a.jwt").is_err());
    }
}
