//! Resolves ATProto DID documents to extract signing public keys.
//!
//! Supports `did:plc` (via the PLC directory at `plc.directory`) and `did:web`
//! (via `/.well-known/did.json`). Resolved keys are cached in memory with a
//! configurable TTL to avoid redundant network requests.

use dashmap::DashMap;
use jsonwebtoken::DecodingKey;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default cache TTL for resolved DID signing keys (5 minutes).
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default PLC directory base URL.
const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// HTTP timeout for DID document fetches.
const DID_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A cached signing key with expiration time.
struct CachedKey {
    key: DecodingKey,
    expires_at: Instant,
}

/// Resolves ATProto DIDs to their signing public keys.
///
/// Fetches DID documents over HTTPS, extracts the `#atproto` verification
/// method, decodes the multibase/multicodec public key, and caches the result.
#[derive(Clone)]
pub struct DidResolver {
    client: reqwest::Client,
    cache: Arc<DashMap<String, CachedKey>>,
    plc_directory: String,
    cache_ttl: Duration,
}

impl DidResolver {
    /// Create a new resolver with default settings.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(DID_FETCH_TIMEOUT)
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            cache: Arc::new(DashMap::new()),
            plc_directory: DEFAULT_PLC_DIRECTORY.to_string(),
            cache_ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// Create a resolver pointing at a custom PLC directory URL (for testing).
    #[cfg(test)]
    pub fn with_plc_directory(plc_directory: String) -> Self {
        let mut resolver = Self::new();
        resolver.plc_directory = plc_directory;
        resolver
    }

    /// Resolve the signing [`DecodingKey`] for a DID.
    ///
    /// Returns a cached key if available and not expired, otherwise fetches
    /// the DID document from the network.
    pub async fn resolve_key(&self, did: &str) -> Result<DecodingKey, String> {
        // Check cache first.
        if let Some(entry) = self.cache.get(did) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.key.clone());
            }
            // Expired — drop the reference before removing.
            drop(entry);
            self.cache.remove(did);
        }

        let doc = self.fetch_did_document(did).await?;
        let key = extract_signing_key(&doc)?;

        self.cache.insert(
            did.to_string(),
            CachedKey {
                key: key.clone(),
                expires_at: Instant::now() + self.cache_ttl,
            },
        );

        Ok(key)
    }

    /// Fetch the DID document from the appropriate directory.
    async fn fetch_did_document(&self, did: &str) -> Result<DidDocument, String> {
        let url = if did.starts_with("did:plc:") {
            format!("{}/{did}", self.plc_directory.trim_end_matches('/'))
        } else if did.starts_with("did:web:") {
            let domain = did
                .strip_prefix("did:web:")
                .ok_or("invalid did:web")?
                .replace(':', "/");
            format!("https://{domain}/.well-known/did.json")
        } else {
            return Err(format!("unsupported DID method: {did}"));
        };

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("DID document fetch failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("DID directory returned {status} for {did}"));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| format!("invalid DID document JSON: {e}"))
    }
}

// ── DID Document types ──────────────────────────────────────────────────────

/// Minimal DID document structure — only the fields we need.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidDocument {
    verification_method: Option<Vec<VerificationMethod>>,
}

/// A verification method entry in a DID document.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    public_key_multibase: Option<String>,
}

// ── Key extraction ──────────────────────────────────────────────────────────

/// Multicodec varint prefix for P-256 (secp256r1) public keys.
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// Multicodec varint prefix for secp256k1 public keys.
const K256_MULTICODEC: [u8; 2] = [0xe7, 0x01];

/// Extract the `#atproto` signing key from a DID document and convert it
/// to a [`DecodingKey`] suitable for `jsonwebtoken` ES256 verification.
fn extract_signing_key(doc: &DidDocument) -> Result<DecodingKey, String> {
    let methods = doc
        .verification_method
        .as_ref()
        .ok_or("DID document has no verificationMethod")?;

    // ATProto signing keys use the fragment `#atproto`.
    let method = methods
        .iter()
        .find(|m| m.id.ends_with("#atproto"))
        .ok_or("no #atproto verification method in DID document")?;

    if method.key_type != "Multikey" {
        return Err(format!(
            "unsupported verification method type: {}",
            method.key_type
        ));
    }

    let multibase = method
        .public_key_multibase
        .as_ref()
        .ok_or("verification method missing publicKeyMultibase")?;

    // Multibase `z` prefix = base58btc encoding.
    let encoded = multibase
        .strip_prefix('z')
        .ok_or_else(|| format!("unsupported multibase prefix: {}", &multibase[..1]))?;

    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| format!("base58 decode failed: {e}"))?;

    if bytes.len() < 2 {
        return Err("multicodec key too short".to_string());
    }

    let (prefix, key_bytes) = bytes.split_at(2);

    if prefix == P256_MULTICODEC {
        decode_p256_key(key_bytes)
    } else if prefix == K256_MULTICODEC {
        Err(
            "secp256k1 (K-256) signing keys are not yet supported for JWT verification; \
             only P-256 (ES256) keys are handled"
                .to_string(),
        )
    } else {
        Err(format!(
            "unknown multicodec prefix: [{:#04x}, {:#04x}]",
            prefix[0], prefix[1]
        ))
    }
}

/// Decode a compressed P-256 public key into a [`DecodingKey`].
fn decode_p256_key(compressed: &[u8]) -> Result<DecodingKey, String> {
    let public_key = p256::PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;

    let pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("P-256 PEM encoding failed: {e}"))?;

    DecodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| format!("failed to create DecodingKey from P-256 PEM: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known P-256 compressed public key (33 bytes), wrapped in multicodec
    /// + multibase for round-trip testing.
    fn make_test_multibase_key() -> String {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        // Use a fixed test key (first 32 bytes of SHA-256 of "test").
        let secret = p256::SecretKey::from_slice(&[
            0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a,
            0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15,
            0xb0, 0xf0, 0x0a, 0x08,
        ])
        .expect("valid test key");
        let public = secret.public_key();
        let point = public.to_encoded_point(true); // compressed
        let compressed = point.as_bytes();

        // Wrap in multicodec P-256 prefix + multibase z (base58btc).
        let mut prefixed = Vec::with_capacity(2 + compressed.len());
        prefixed.extend_from_slice(&P256_MULTICODEC);
        prefixed.extend_from_slice(compressed);
        let encoded = bs58::encode(&prefixed).into_string();

        format!("z{encoded}")
    }

    fn assert_err_contains(result: Result<DecodingKey, String>, needle: &str) {
        match result {
            Err(e) => assert!(e.contains(needle), "unexpected error: {e}"),
            Ok(_) => panic!("expected error containing '{needle}', got Ok"),
        }
    }

    #[test]
    fn extract_p256_key_from_did_document() {
        let multibase_key = make_test_multibase_key();

        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some(multibase_key),
            }]),
        };

        let result = extract_signing_key(&doc);
        assert!(result.is_ok(), "failed to extract key: {:?}", result.err());
    }

    #[test]
    fn rejects_missing_atproto_method() {
        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#other".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some("zNotUsed".to_string()),
            }]),
        };

        assert_err_contains(extract_signing_key(&doc), "#atproto");
    }

    #[test]
    fn rejects_k256_key_with_clear_message() {
        // Build a fake K-256 multibase key (wrong codec for our verifier).
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(&K256_MULTICODEC);
        prefixed.extend_from_slice(&[0x02; 33]); // fake compressed point
        let encoded = format!("z{}", bs58::encode(&prefixed).into_string());

        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some(encoded),
            }]),
        };

        assert_err_contains(extract_signing_key(&doc), "secp256k1");
    }

    #[test]
    fn rejects_empty_verification_methods() {
        let doc = DidDocument {
            verification_method: None,
        };

        assert_err_contains(extract_signing_key(&doc), "no verificationMethod");
    }

    #[test]
    fn rejects_unsupported_key_type() {
        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Ed25519VerificationKey2020".to_string(),
                public_key_multibase: Some("zNotUsed".to_string()),
            }]),
        };

        assert_err_contains(
            extract_signing_key(&doc),
            "unsupported verification method type",
        );
    }
}
