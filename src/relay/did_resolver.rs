//! Resolves ATProto DID documents to extract signing public keys.
//!
//! Supports `did:plc` (via the PLC directory at `plc.directory`) and `did:web`
//! (via `/.well-known/did.json`). Resolved keys are cached in memory with a
//! configurable TTL to avoid redundant network requests.
//!
//! # Security
//!
//! - **SSRF protection** — `did:web` domains are resolved and validated against
//!   private/loopback IP ranges before fetching. The validated IP is pinned via
//!   `reqwest::ClientBuilder::resolve` to prevent TOCTOU DNS rebinding attacks.
//!   HTTP redirects are disabled to prevent attackers from bouncing pinned
//!   requests to internal endpoints (e.g. cloud metadata services).
//! - **Streaming body limit** — DID document responses are streamed with an
//!   incremental size check (max 256 KiB), aborting early rather than buffering
//!   an unbounded payload into memory.
//! - **Cache hardening** — The key cache uses a bounded W-TinyLFU cache
//!   ([`moka`]) capped at 10,000 entries with a 5-minute TTL. When full,
//!   the least-frequently/recently-used entries are evicted automatically,
//!   preventing an attacker from filling the cache with garbage DIDs and
//!   starving legitimate users of cached lookups.

use jsonwebtoken::DecodingKey;
use moka::sync::Cache;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde::Deserialize;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// Default cache TTL for resolved DID signing keys (5 minutes).
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Negative cache TTL for failed DID resolutions (60 seconds).
/// Prevents attackers from using the relay as a DDoS reflector by spamming
/// handshakes with the same DID pointing at a victim server.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Default PLC directory base URL.
const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// HTTP timeout for DID document fetches.
const DID_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum response body size for DID document fetches (256 KiB).
/// DID documents are small JSON; anything larger is suspicious.
const MAX_DID_DOCUMENT_SIZE: usize = 256 * 1024;

/// Maximum number of cached DID signing keys.
const MAX_CACHE_ENTRIES: u64 = 10_000;

/// Resolves ATProto DIDs to their signing public keys.
///
/// Fetches DID documents over HTTPS, extracts the `#atproto` verification
/// method, decodes the multibase/multicodec public key, and caches the result.
/// The cache uses moka's W-TinyLFU admission policy, which automatically
/// evicts the least-valuable entries when at capacity.
#[derive(Clone)]
pub struct DidResolver {
    client: reqwest::Client,
    cache: Cache<String, DecodingKey>,
    /// Caches failed DID resolutions to prevent repeated outbound requests
    /// for the same bad DID (DDoS reflection protection).
    negative_cache: Cache<String, String>,
    plc_directory: String,
}

/// Build the URL for fetching a DID document.
///
/// Follows the W3C DID specification:
/// - `did:plc:*` → `{plc_directory}/{did}`
/// - `did:web:example.com` → `https://example.com/.well-known/did.json`
/// - `did:web:example.com:u:alice` → `https://example.com/u/alice/did.json`
///
/// Percent-encoded port separators (`%3A`) in the domain are decoded.
fn did_document_url(did: &str, plc_directory: &str) -> Result<String, String> {
    if did.starts_with("did:plc:") {
        Ok(format!("{}/{did}", plc_directory.trim_end_matches('/')))
    } else if did.starts_with("did:web:") {
        let raw = did.strip_prefix("did:web:").ok_or("invalid did:web")?;
        // Split into domain (first segment) and optional path segments.
        // Percent-decode %3A back to : for port numbers (e.g. example.com%3A8443).
        let parts: Vec<&str> = raw.splitn(2, ':').collect();
        let domain = parts[0].replace("%3A", ":").replace("%3a", ":");

        if parts.len() > 1 {
            // Path-based: did:web:example.com:u:alice → example.com/u/alice/did.json
            let path = parts[1].replace(':', "/");
            Ok(format!("https://{domain}/{path}/did.json"))
        } else {
            // Domain-only: did:web:example.com → example.com/.well-known/did.json
            Ok(format!("https://{domain}/.well-known/did.json"))
        }
    } else {
        Err(format!("unsupported DID method: {did}"))
    }
}

/// Resolve a domain's DNS records, reject private/loopback IPs (SSRF protection),
/// and return the first safe [`std::net::SocketAddr`].
///
/// The caller **must** pin the returned address when issuing the HTTP request
/// (via `reqwest::ClientBuilder::resolve`) to prevent TOCTOU DNS rebinding
/// attacks where the domain resolves to a different (private) IP on the second
/// lookup performed by reqwest.
fn validate_and_resolve_domain(domain: &str) -> Result<std::net::SocketAddr, String> {
    // Add default HTTPS port if no port is present, so ToSocketAddrs works.
    // Bracketed IPv6 addresses like [2001:db8::1] contain colons but have no
    // port — detect them by the leading bracket rather than a naive colon check.
    let host_port = if domain.starts_with('[') {
        // Bracketed IPv6: [addr] or [addr]:port
        if domain.contains("]:") {
            domain.to_string()
        } else {
            format!("{domain}:443")
        }
    } else if domain.contains(':') {
        // IPv4 or hostname with explicit port
        domain.to_string()
    } else {
        format!("{domain}:443")
    };

    let addrs: Vec<std::net::SocketAddr> = host_port
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve domain '{domain}': {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("domain '{domain}' resolved to no addresses"));
    }

    for addr in &addrs {
        // Unmap IPv4-mapped IPv6 (::ffff:a.b.c.d) back to IPv4 before safety
        // checks. Without this, an attacker can bypass loopback/private checks
        // by resolving to e.g. ::ffff:127.0.0.1 (std's is_loopback() returns
        // false for the V6 mapped form).
        let ip = match addr.ip() {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(v6)),
            v4 => v4,
        };
        if ip.is_loopback() || ip.is_unspecified() || is_private_ip(&ip) || is_link_local(&ip) {
            return Err(format!(
                "did:web domain '{domain}' resolves to private/loopback address {ip}, \
                 request blocked (SSRF protection)"
            ));
        }
    }

    Ok(addrs[0])
}

/// Check if an IP address is in a private, reserved, or otherwise non-global range.
///
/// Covers RFC 1918, RFC 4193, carrier-grade NAT, link-local, "this" network
/// (0.0.0.0/8 — routed to loopback on Linux), multicast, broadcast, and other
/// IANA-reserved ranges that should never appear in a did:web domain.
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8 — "This" network (RFC 1122). On Linux, 0.0.0.1–0.255.255.255
            // are routed to the loopback interface, making them an SSRF vector.
            octets[0] == 0
            // 10.0.0.0/8
            || octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 100.64.0.0/10 (carrier-grade NAT, RFC 6598)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
            // 169.254.0.0/16 (link-local, also caught by is_link_local)
            || (octets[0] == 169 && octets[1] == 254)
            // 192.0.0.0/24 (IETF protocol assignments, RFC 6890)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
            // 192.0.2.0/24 (TEST-NET-1, RFC 5737)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            // 198.18.0.0/15 (benchmarking, RFC 2544)
            || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
            // 198.51.100.0/24 (TEST-NET-2, RFC 5737)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            // 203.0.113.0/24 (TEST-NET-3, RFC 5737)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            // 224.0.0.0/4 (multicast, RFC 5771)
            || octets[0] >= 224
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 (unique local)
            (segments[0] & 0xfe00) == 0xfc00
            // ff00::/8 (multicast)
            || (segments[0] & 0xff00) == 0xff00
        }
    }
}

/// Check if an IP is link-local (169.254.0.0/16 or fe80::/10).
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

impl DidResolver {
    /// Create a new resolver with default settings.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(DID_FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");

        let cache = Cache::builder()
            .max_capacity(MAX_CACHE_ENTRIES)
            .time_to_live(DEFAULT_CACHE_TTL)
            .build();

        let negative_cache = Cache::builder()
            .max_capacity(MAX_CACHE_ENTRIES)
            .time_to_live(NEGATIVE_CACHE_TTL)
            .build();

        Self {
            client,
            cache,
            negative_cache,
            plc_directory: DEFAULT_PLC_DIRECTORY.to_string(),
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
    /// the DID document from the network. The moka cache handles TTL expiry
    /// and W-TinyLFU eviction automatically.
    pub async fn resolve_key(&self, did: &str) -> Result<DecodingKey, String> {
        if let Some(key) = self.cache.get(did) {
            return Ok(key);
        }

        // Reject DIDs that recently failed resolution to prevent repeated
        // outbound requests (DDoS reflection / resource exhaustion).
        if let Some(cached_err) = self.negative_cache.get(did) {
            return Err(format!("DID resolution recently failed (cached): {cached_err}"));
        }

        let result = async {
            let doc = self.fetch_did_document(did).await?;
            extract_signing_key(&doc)
        }
        .await;

        match result {
            Ok(key) => {
                self.cache.insert(did.to_string(), key.clone());
                Ok(key)
            }
            Err(e) => {
                self.negative_cache.insert(did.to_string(), e.clone());
                Err(e)
            }
        }
    }

    /// Fetch the DID document from the appropriate directory.
    ///
    /// The response body is **streamed** with an incremental size check against
    /// [`MAX_DID_DOCUMENT_SIZE`] (256 KiB). The stream is aborted as soon as
    /// the accumulated size exceeds the limit, preventing a malicious server
    /// from exhausting memory with an oversized or infinite response.
    ///
    /// For `did:web`, the domain is resolved and validated against private/loopback
    /// IPs, and the validated address is pinned to prevent DNS rebinding (SSRF).
    async fn fetch_did_document(&self, did: &str) -> Result<DidDocument, String> {
        let url = did_document_url(did, &self.plc_directory)?;

        // SSRF protection: for did:web, resolve DNS once, validate IPs, and
        // pin the validated address so reqwest cannot re-resolve to a different
        // (potentially private) IP (prevents TOCTOU DNS rebinding attacks).
        let pinned_client = if did.starts_with("did:web:") {
            let raw = did.strip_prefix("did:web:").ok_or("invalid did:web")?;
            let parts: Vec<&str> = raw.splitn(2, ':').collect();
            let domain = parts[0].replace("%3A", ":").replace("%3a", ":");
            let validated_addr = validate_and_resolve_domain(&domain)?;
            let host_only = domain.split(':').next().unwrap_or(&domain);
            // Build a one-off client that pins DNS resolution to the validated IP.
            let pinned = reqwest::Client::builder()
                .timeout(DID_FETCH_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .resolve(host_only, validated_addr)
                .build()
                .map_err(|e| format!("failed to build pinned HTTP client: {e}"))?;
            Some(pinned)
        } else {
            None
        };

        let client = pinned_client.as_ref().unwrap_or(&self.client);
        let resp = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("DID document fetch failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("DID directory returned {status} for {did}"));
        }

        // Check Content-Length hint if present (not authoritative, but fast).
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_DID_DOCUMENT_SIZE {
                return Err(format!(
                    "DID document response too large ({len} bytes, max {MAX_DID_DOCUMENT_SIZE})"
                ));
            }
        }

        // Stream the body with a hard size limit to prevent memory exhaustion.
        // Unlike `resp.bytes()`, this aborts early without buffering an
        // unbounded payload from a malicious server.
        use futures_util::StreamExt;
        let mut stream = resp.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("failed to read DID document body: {e}"))?;
            if body.len() + chunk.len() > MAX_DID_DOCUMENT_SIZE {
                return Err(format!(
                    "DID document response too large (>{MAX_DID_DOCUMENT_SIZE} bytes), aborting"
                ));
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice::<DidDocument>(&body)
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

/// Maximum length of the base58-encoded portion of `publicKeyMultibase`.
/// A compressed P-256 key is 33 bytes + 2-byte multicodec prefix = 35 bytes,
/// which encodes to ~48 base58 characters. We allow up to 128 to be generous.
/// This cap prevents O(N²) CPU exhaustion from bs58-decoding a ~250 KiB string
/// embedded in a malicious DID document.
const MAX_MULTIBASE_ENCODED_LEN: usize = 128;

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
    let encoded = multibase.strip_prefix('z').ok_or_else(|| {
        let prefix = multibase
            .chars()
            .next()
            .map_or("(empty)", |_| &multibase[..1]);
        format!("unsupported multibase prefix: {prefix}")
    })?;

    if encoded.len() > MAX_MULTIBASE_ENCODED_LEN {
        return Err(format!(
            "publicKeyMultibase too long ({} chars, max {MAX_MULTIBASE_ENCODED_LEN}); \
             valid P-256 keys encode to ~48 characters",
            encoded.len()
        ));
    }

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

    // ── did_document_url tests ──────────────────────────────────────────

    #[test]
    fn did_web_domain_only_resolves_to_well_known() {
        let url = did_document_url("did:web:example.com", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_path_based_resolves_without_well_known() {
        let url = did_document_url("did:web:example.com:u:alice", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://example.com/u/alice/did.json");
    }

    #[test]
    fn did_web_single_path_segment() {
        let url = did_document_url("did:web:example.com:users", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://example.com/users/did.json");
    }

    #[test]
    fn did_web_percent_encoded_port() {
        let url = did_document_url("did:web:example.com%3A8443", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://example.com:8443/.well-known/did.json");
    }

    #[test]
    fn did_web_percent_encoded_port_with_path() {
        let url =
            did_document_url("did:web:example.com%3A8443:u:bob", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://example.com:8443/u/bob/did.json");
    }

    #[test]
    fn did_plc_resolves_to_plc_directory() {
        let url = did_document_url("did:plc:abc123", "https://plc.directory").unwrap();
        assert_eq!(url, "https://plc.directory/did:plc:abc123");
    }

    #[test]
    fn unsupported_did_method_returns_error() {
        let result = did_document_url("did:key:z123", DEFAULT_PLC_DIRECTORY);
        let err = result.unwrap_err();
        assert!(
            err.contains("unsupported DID method"),
            "unexpected error: {err}"
        );
    }

    // ── SSRF protection tests ─────────────────────────────────────────

    #[test]
    fn ssrf_rejects_loopback() {
        let result = validate_and_resolve_domain("localhost");
        assert!(result.is_err(), "expected loopback to be rejected");
        assert!(
            result.unwrap_err().contains("SSRF protection"),
            "error should mention SSRF"
        );
    }

    #[test]
    fn ssrf_rejects_127_0_0_1() {
        let result = validate_and_resolve_domain("127.0.0.1");
        assert!(result.is_err(), "expected 127.0.0.1 to be rejected");
    }

    #[test]
    fn ssrf_rejects_private_10_network() {
        let result = validate_and_resolve_domain("10.0.0.1");
        assert!(result.is_err(), "expected 10.x.x.x to be rejected");
    }

    #[test]
    fn ssrf_rejects_private_172_network() {
        let result = validate_and_resolve_domain("172.16.0.1");
        assert!(result.is_err(), "expected 172.16.x.x to be rejected");
    }

    #[test]
    fn ssrf_rejects_private_192_168_network() {
        let result = validate_and_resolve_domain("192.168.1.1");
        assert!(result.is_err(), "expected 192.168.x.x to be rejected");
    }

    #[test]
    fn ssrf_rejects_link_local() {
        let result = validate_and_resolve_domain("169.254.1.1");
        assert!(result.is_err(), "expected link-local to be rejected");
    }

    #[test]
    fn ssrf_rejects_loopback_with_port() {
        let result = validate_and_resolve_domain("127.0.0.1:10250");
        assert!(result.is_err(), "expected 127.0.0.1:port to be rejected");
    }

    #[test]
    fn ssrf_rejects_this_network_0_0_0_1() {
        let result = validate_and_resolve_domain("0.0.0.1");
        assert!(result.is_err(), "expected 0.0.0.1 (this-network) to be rejected");
    }

    #[test]
    fn ssrf_rejects_multicast() {
        let result = validate_and_resolve_domain("224.0.0.1");
        assert!(result.is_err(), "expected multicast 224.0.0.1 to be rejected");
    }

    #[test]
    fn ssrf_rejects_broadcast() {
        let result = validate_and_resolve_domain("255.255.255.255");
        assert!(result.is_err(), "expected broadcast to be rejected");
    }

    // ── Key length limit tests ───────────────────────────────────────

    #[test]
    fn rejects_oversized_multibase_key() {
        let long_key = format!("z{}", "1".repeat(MAX_MULTIBASE_ENCODED_LEN + 1));
        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some(long_key),
            }]),
        };

        assert_err_contains(extract_signing_key(&doc), "too long");
    }
}
