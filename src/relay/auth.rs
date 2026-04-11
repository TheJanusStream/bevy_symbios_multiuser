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
//! document (via `plc.directory` for `did:plc`, or HTTPS for `did:web` —
//! domain-only DIDs use `/.well-known/did.json`, path-based DIDs use
//! `/{path}/did.json`), extracts the `#atproto` signing key, and verifies
//! the JWT signature (ES256 for P-256 keys, ES256K for secp256k1 keys).
//! Resolved keys are cached in memory.
//!
//! Callers must ensure a resolver is available before calling
//! [`validate_atproto_jwt`] — unverified JWTs are never trusted for identity.

use super::did_resolver::{DidResolver, ResolvedKey};
use base64::Engine;
use jsonwebtoken::{Algorithm, Validation, decode};
use serde::Deserialize;

/// Error returned by [`validate_atproto_jwt`].
///
/// Distinguishes permanent authentication failures (invalid token, bad
/// signature, expired) from transient infrastructure failures (resolver
/// overloaded, DNS unreachable). Callers map these to different HTTP status
/// codes: 401 for `InvalidToken`, 503 for `Transient`.
#[derive(Debug)]
pub enum AuthError {
    /// JWT is structurally malformed, has an invalid signature, or is expired.
    /// Retrying with the same token will not succeed.
    InvalidToken(String),
    /// Transient infrastructure failure — DID resolver is overloaded or the
    /// DID hosting server is temporarily unreachable. Clients should retry.
    Transient(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidToken(s) | AuthError::Transient(s) => s.fmt(f),
        }
    }
}

/// JWT `aud` claim — can be a single string or an array of strings per RFC 7519 §4.1.3.
///
/// Standard JWT libraries may encode a single audience as either `"did:web:svc"` or
/// `["did:web:svc"]`. We accept both so that PDS implementations using array-style
/// encoding don't cause claim deserialization to fail before DID resolution even starts.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AudClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudClaim {
    /// Returns `true` if `value` is present in the audience claim.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            AudClaim::Single(s) => s == value,
            AudClaim::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

/// Claims extracted from an ATProto access JWT.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are read by jsonwebtoken's validation logic
pub struct AtprotoClaims {
    /// The issuer — the user's DID (e.g. `did:plc:abc123`).
    pub iss: String,
    /// Token expiration time (Unix timestamp).
    pub exp: u64,
    /// Not-before time (Unix timestamp). Optional — tokens without this claim
    /// are valid immediately. When present, the token must not be accepted
    /// before this time (RFC 7519 §4.1.5).
    pub nbf: Option<u64>,
    /// The intended audience (service DID). Optional — older tokens may omit it.
    /// Accepts both a plain string and a JSON array (RFC 7519 §4.1.3).
    pub aud: Option<AudClaim>,
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
/// The caller is responsible for ensuring a resolver is available before
/// calling this function — unverified JWTs must never be trusted for identity.
///
/// # Errors
///
/// Returns a human-readable error string if the token is malformed, expired,
/// has an invalid issuer, or fails signature verification.
pub async fn validate_atproto_jwt(
    token: &str,
    resolver: &DidResolver,
    expected_aud: Option<&str>,
) -> Result<ValidatedIdentity, AuthError> {
    // Step 1: Decode without signature verification to read claims.
    let claims = decode_claims(token).map_err(AuthError::InvalidToken)?;
    let did = &claims.iss;

    if !did.starts_with("did:") {
        return Err(AuthError::InvalidToken(format!(
            "invalid DID in JWT issuer: {did}"
        )));
    }

    // Reject unsupported DID methods before calling the resolver. The resolver
    // returns a generic error string for unknown methods, and blindly mapping
    // that error to AuthError::Transient (HTTP 503) would prompt automated
    // clients to retry a permanently-invalid credential indefinitely.
    if !did.starts_with("did:plc:") && !did.starts_with("did:web:") {
        return Err(AuthError::InvalidToken(format!(
            "unsupported DID method in JWT issuer: {did}"
        )));
    }

    // Validate audience claim when the relay has a service DID configured.
    // Prevents cross-service token replay: a JWT issued for Game A cannot
    // be used to authenticate against Game B's relay.
    if let Some(expected) = expected_aud {
        match &claims.aud {
            Some(aud) if aud.contains(expected) => {}
            Some(aud) => {
                let displayed = match aud {
                    AudClaim::Single(s) => format!("'{s}'"),
                    AudClaim::Multiple(v) => format!("{v:?}"),
                };
                return Err(AuthError::InvalidToken(format!(
                    "JWT audience mismatch: token is for {displayed}, expected '{expected}'"
                )));
            }
            None => {
                return Err(AuthError::InvalidToken(format!(
                    "JWT missing aud claim, expected '{expected}'"
                )));
            }
        }
    }

    // Step 2: Resolve the DID document key. Resolution failures (DNS down,
    // concurrency limit exceeded) are transient — map to AuthError::Transient
    // so callers can return 503 rather than 401.
    let resolved = resolver
        .resolve_key(did)
        .await
        .map_err(AuthError::Transient)?;

    // Step 3: Verify the JWT signature on a blocking thread (ECDSA is CPU-bound;
    // running it on the async executor starves other tasks under connection floods).
    verify_signature(token, &resolved)
        .await
        .map_err(AuthError::InvalidToken)?;
    tracing::debug!(did = %did, "JWT signature verified via DID document");

    Ok(ValidatedIdentity { did: did.clone() })
}

/// Decode JWT claims without verifying the signature.
///
/// Manually splits and base64url-decodes the JWT rather than using
/// `jsonwebtoken::decode`, because `jsonwebtoken`'s `Algorithm` enum does
/// not include `ES256K`. If we relied on `jsonwebtoken` to parse the header,
/// any JWT with `"alg": "ES256K"` would fail deserialization before we could
/// reach our manual `k256` verification path.
fn decode_claims(token: &str) -> Result<AtprotoClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "malformed JWT: expected 3 parts, got {}",
            parts.len()
        ));
    }
    let payload_b64 = parts[1];

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("JWT payload base64 decode failed: {e}"))?;

    let claims: AtprotoClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JWT claims parse failed: {e}"))?;

    Ok(claims)
}

/// Clock-skew leeway for time-based JWT claims (seconds).
///
/// Matches the default leeway applied by `jsonwebtoken` on the P-256 path,
/// ensuring consistent behaviour across both key types. Short-lived ATProto
/// tokens combined with any NTP drift would otherwise cause sporadic failures
/// exclusively for users whose PDS uses secp256k1 keys.
const LEEWAY_SECS: u64 = 60;

/// Verify the JWT signature against a resolved public key.
///
/// Both ECDSA paths are offloaded to [`tokio::task::spawn_blocking`]: a single
/// verification takes ~1–2 ms, but under a connection flood an attacker can
/// saturate the async executor with CPU-bound crypto, starving I/O tasks. The
/// blocking thread pool is the correct place for this work.
///
/// P-256 keys are verified via `jsonwebtoken`'s built-in ES256 support.
/// K-256 (secp256k1) keys are verified manually since `jsonwebtoken` does
/// not support ES256K: the JWT signing input is hashed with SHA-256 and
/// the ECDSA signature is verified using `k256::ecdsa`.
async fn verify_signature(token: &str, resolved: &ResolvedKey) -> Result<(), String> {
    let token_owned = token.to_string();
    let resolved_owned = resolved.clone();
    tokio::task::spawn_blocking(move || match resolved_owned {
        ResolvedKey::P256(key) => {
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_exp = true;
            validation.validate_nbf = true;
            validation.validate_aud = false;
            validation.leeway = LEEWAY_SECS;
            decode::<AtprotoClaims>(&token_owned, &key, &validation)
                .map_err(|e| format!("JWT signature verification failed: {e}"))?;
            Ok(())
        }
        ResolvedKey::K256(public_key) => verify_es256k(&token_owned, &public_key),
    })
    .await
    .map_err(|e| format!("ECDSA verification task panicked: {e}"))
    .and_then(|r| r)
}

/// Manually verify an ES256K JWT signature using the `k256` crate.
///
/// ES256K uses ECDSA with SHA-256 over the secp256k1 curve. The JWT's
/// signing input (`header.payload`) is hashed and the base64url-decoded
/// signature (r || s, 64 bytes) is verified against the public key.
fn verify_es256k(token: &str, public_key: &k256::PublicKey) -> Result<(), String> {
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    // Split into header.payload and signature
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return Err("malformed JWT: expected header.payload.signature".to_string());
    }
    let sig_b64 = parts[0];
    let signing_input = parts[1]; // "header.payload"

    // Verify the JWT header declares ES256K. Without this check, a token
    // with a mismatched `alg` header (e.g. "HS256") would still pass ECDSA
    // verification, violating RFC 7515 §4.1.1 best practices.
    let header_b64 = signing_input
        .split('.')
        .next()
        .ok_or("malformed JWT: missing header")?;
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| format!("JWT header base64 decode failed: {e}"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("JWT header parse failed: {e}"))?;
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("ES256K") => {}
        Some(other) => {
            return Err(format!(
                "JWT alg mismatch: token header says '{other}', but key requires ES256K"
            ));
        }
        None => {
            return Err("JWT header missing 'alg' field".to_string());
        }
    }

    // Decode the signature (base64url, no padding)
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("JWT signature base64 decode failed: {e}"))?;

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| format!("invalid ES256K signature: {e}"))?;

    let verifying_key = VerifyingKey::from(public_key);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("ES256K signature verification failed: {e}"))?;

    // Validate time-based claims (without sig check — signature already verified above).
    let claims = decode_claims(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?
        .as_secs();
    // Apply the same leeway as the P-256 path for consistency.
    if claims.exp.saturating_add(LEEWAY_SECS) < now {
        return Err("JWT has expired".to_string());
    }
    if let Some(nbf) = claims.nbf
        && now + LEEWAY_SECS < nbf
    {
        return Err("JWT not yet valid (nbf)".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
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

    /// A resolver that points nowhere — used for tests that check token
    /// decoding failures before any network call is attempted.
    fn dummy_resolver() -> DidResolver {
        DidResolver::with_plc_directory("http://127.0.0.1:1".to_string())
    }

    #[tokio::test]
    async fn rejects_empty_token() {
        assert!(
            validate_atproto_jwt("", &dummy_resolver(), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_garbage_token() {
        assert!(
            validate_atproto_jwt("not.a.jwt", &dummy_resolver(), None)
                .await
                .is_err()
        );
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

    #[tokio::test]
    async fn verify_signature_accepts_valid_jwt() {
        let secret = test_key_pair();
        let token = sign_test_jwt("did:plc:testuser", &secret);
        let decoding_key = decoding_key_from_p256(&secret.public_key());

        let result = verify_signature(&token, &ResolvedKey::P256(decoding_key)).await;
        assert!(
            result.is_ok(),
            "verify_signature failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn verify_signature_rejects_wrong_key() {
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

        let result = verify_signature(&token, &ResolvedKey::P256(wrong_key)).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed"),
            "should report signature failure"
        );
    }

    #[tokio::test]
    async fn rejects_valid_jwt_with_no_matching_key() {
        // A resolver with no reachable backend should fail resolution,
        // preventing identity spoofing from unverified claims.
        let secret = test_key_pair();
        let token = sign_test_jwt("did:plc:testuser", &secret);
        let resolver = DidResolver::with_plc_directory("http://127.0.0.1:1".to_string());

        let result = validate_atproto_jwt(&token, &resolver, None).await;
        assert!(result.is_err(), "should reject when key resolution fails");
    }
}
