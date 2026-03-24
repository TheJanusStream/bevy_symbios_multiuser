//! ATProto JWT validation for the relay server.
//!
//! Decodes and validates ATProto access JWTs presented during WebSocket
//! upgrade. Checks structural validity, token expiry, and — when a
//! [`DidResolver`](super::did_resolver::DidResolver) is available — verifies
//! the cryptographic signature against the signer's DID-document public key.
//!
//! # Signature Verification
//!
//! When a `DidResolver` is supplied, the relay resolves the issuer's DID
//! document (via `plc.directory` for `did:plc`, or `/.well-known/did.json`
//! for `did:web`), extracts the `#atproto` signing key, and verifies the
//! JWT's ES256 signature. Resolved keys are cached in memory.
//!
//! When no resolver is available, only structural validation (expiry,
//! issuer format) is performed and a warning is logged.

use super::did_resolver::DidResolver;
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

/// Decode and validate an ATProto access JWT, verifying the cryptographic
/// signature when a [`DidResolver`] is provided.
///
/// # Verification Flow
///
/// 1. Decode the JWT *without* signature verification to extract the `iss`
///    (DID) claim.
/// 2. Resolve the DID document and extract the signing public key.
/// 3. Re-validate the JWT *with* the resolved key to verify the signature.
///
/// If `resolver` is `None`, step 2–3 are skipped and only structural
/// validation (expiry, issuer format) is performed.
///
/// # Errors
///
/// Returns a human-readable error string if the token is malformed, expired,
/// has an invalid issuer, or fails signature verification.
pub async fn validate_atproto_jwt(
    token: &str,
    resolver: Option<&DidResolver>,
) -> Result<ValidatedIdentity, String> {
    // Step 1: Decode without signature verification to read claims.
    let claims = decode_claims(token)?;
    let did = &claims.iss;

    if !did.starts_with("did:") {
        return Err(format!("invalid DID in JWT issuer: {did}"));
    }

    // Step 2–3: If a resolver is available, verify the signature.
    match resolver {
        Some(resolver) => {
            let key = resolver.resolve_key(did).await?;
            verify_signature(token, &key)?;
            tracing::debug!(did = %did, "JWT signature verified via DID document");
        }
        None => {
            tracing::warn!("JWT signature verification skipped — no DID resolver configured");
        }
    }

    Ok(ValidatedIdentity { did: did.clone() })
}

/// Decode JWT claims without verifying the signature.
fn decode_claims(token: &str) -> Result<AtprotoClaims, String> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = true;
    validation.algorithms = vec![Algorithm::ES256];
    validation.validate_aud = false;

    let token_data = decode::<AtprotoClaims>(token, &DecodingKey::from_secret(&[]), &validation)
        .map_err(|e| format!("JWT decode failed: {e}"))?;

    Ok(token_data.claims)
}

/// Verify the JWT signature against a resolved public key.
fn verify_signature(token: &str, key: &DecodingKey) -> Result<(), String> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.validate_aud = false;

    decode::<AtprotoClaims>(token, key, &validation)
        .map_err(|e| format!("JWT signature verification failed: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use p256::pkcs8::EncodePrivateKey;
    use serde::Serialize;

    /// Build a signed ES256 JWT from a P-256 key pair.
    fn sign_test_jwt(did: &str, secret: &p256::SecretKey) -> String {
        #[derive(Serialize)]
        struct Claims {
            iss: String,
            exp: u64,
        }

        let private_pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encode private key");
        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).expect("parse EC PEM");

        let claims = Claims {
            iss: did.to_string(),
            exp: 9_999_999_999, // far future (Nov 2286)
        };

        encode(&Header::new(Algorithm::ES256), &claims, &encoding_key).expect("sign JWT")
    }

    fn test_key_pair() -> p256::SecretKey {
        p256::SecretKey::from_slice(&[
            0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a,
            0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15,
            0xb0, 0xf0, 0x0a, 0x08,
        ])
        .expect("valid test key")
    }

    #[tokio::test]
    async fn rejects_empty_token() {
        assert!(validate_atproto_jwt("", None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_garbage_token() {
        assert!(validate_atproto_jwt("not.a.jwt", None).await.is_err());
    }

    /// Build a [`DecodingKey`] from a p256 public key using PEM encoding,
    /// matching how `jsonwebtoken` expects EC public keys.
    fn decoding_key_from_p256(public: &p256::PublicKey) -> DecodingKey {
        use p256::pkcs8::EncodePublicKey;
        let pem = public
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encode public key");
        DecodingKey::from_ec_pem(pem.as_bytes()).expect("parse EC PEM")
    }

    #[test]
    fn verify_signature_accepts_valid_jwt() {
        let secret = test_key_pair();
        let token = sign_test_jwt("did:plc:testuser", &secret);
        let decoding_key = decoding_key_from_p256(&secret.public_key());

        let result = verify_signature(&token, &decoding_key);
        assert!(
            result.is_ok(),
            "verify_signature failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        let secret = test_key_pair();
        let token = sign_test_jwt("did:plc:testuser", &secret);

        // Use a different key for verification.
        let wrong_secret = p256::SecretKey::from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
        .expect("valid key");

        let wrong_key = decoding_key_from_p256(&wrong_secret.public_key());

        let result = verify_signature(&token, &wrong_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed"),
            "should report signature failure"
        );
    }

    #[tokio::test]
    async fn validate_without_resolver_skips_signature() {
        let secret = test_key_pair();
        let token = sign_test_jwt("did:plc:testuser", &secret);

        // Without a resolver, validation should pass (signature not checked).
        let identity = validate_atproto_jwt(&token, None).await.unwrap();
        assert_eq!(identity.did, "did:plc:testuser");
    }
}
