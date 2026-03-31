//! Resolves ATProto DID documents to extract signing public keys.
//!
//! Supports `did:plc` (via the PLC directory at `plc.directory`) and `did:web`
//! (via HTTPS — domain-only DIDs resolve to `/.well-known/did.json`, while
//! path-based DIDs like `did:web:example.com:u:alice` resolve to
//! `https://example.com/u/alice/did.json`). Resolved keys are cached in memory
//! with a configurable TTL to avoid redundant network requests.
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
//! - **Request coalescing** — The key cache uses [`moka::future::Cache`] with
//!   [`try_get_with`](moka::future::Cache::try_get_with), which deduplicates
//!   concurrent lookups for the same DID. This prevents the relay from acting
//!   as a DDoS amplifier when many connections present the same uncached DID
//!   simultaneously.
//! - **Domain client cap** — Per-domain `reqwest::Client` instances (used for
//!   DNS-pinned SSRF protection) are capped at 100 entries. Each client holds
//!   a connection pool and spawns background workers, so the lower cap prevents
//!   resource exhaustion from an attacker feeding unique `did:web` domains.

use dashmap::DashMap;
use jsonwebtoken::DecodingKey;
use moka::sync::Cache;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde::Deserialize;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Maximum number of cached per-domain `reqwest::Client` instances.
/// Each client holds a connection pool and spawns background workers, so this
/// must be much lower than [`MAX_CACHE_ENTRIES`] to prevent resource exhaustion
/// (memory, file descriptors, tokio tasks) from an attacker systematically
/// feeding unique `did:web` domains.
const MAX_DOMAIN_CLIENTS: u64 = 100;

/// Maximum number of concurrent in-flight DID document fetches for a single
/// `did:web` domain. Prevents attackers from using unique DID paths
/// (e.g. `did:web:victim.com:u:random1`, `did:web:victim.com:u:random2`) to
/// bypass the per-DID negative cache and coalescing, turning the relay into a
/// DDoS amplifier against the target domain. Unlike a cumulative rate limit,
/// a concurrency limit naturally frees slots as requests complete (or fail),
/// so attacker traffic cannot permanently exhaust the budget for legitimate users.
const DOMAIN_FETCH_CONCURRENCY_LIMIT: u64 = 10;

/// Maximum number of concurrent in-flight `did:web` document fetches across
/// ALL domains. Prevents subdomain spraying attacks where an attacker creates
/// thousands of unique subdomains (e.g. `did:web:1.evil.com`,
/// `did:web:2.evil.com`) to exhaust the Tokio blocking thread pool with
/// `getaddrinfo` calls. Slots are released as soon as each fetch completes
/// (success or failure), so transient attacker traffic cannot lock out
/// legitimate users.
const GLOBAL_DIDWEB_FETCH_CONCURRENCY_LIMIT: u64 = 50;

/// A resolved signing key with its verification strategy.
///
/// P-256 keys use `jsonwebtoken`'s built-in ES256 verification.
/// K-256 (secp256k1) keys use manual ECDSA verification via the `k256` crate,
/// since `jsonwebtoken` does not support ES256K.
#[derive(Clone)]
pub enum ResolvedKey {
    /// P-256 (ES256) — verified via `jsonwebtoken`.
    P256(DecodingKey),
    /// secp256k1 (ES256K) — verified manually via `k256::ecdsa`.
    K256(k256::PublicKey),
}

/// Resolves ATProto DIDs to their signing public keys.
///
/// Fetches DID documents over HTTPS, extracts the `#atproto` verification
/// method, decodes the multibase/multicodec public key, and caches the result.
/// The cache uses moka's W-TinyLFU admission policy, which automatically
/// evicts the least-valuable entries when at capacity.
#[derive(Clone)]
pub struct DidResolver {
    client: reqwest::Client,
    /// Async-aware key cache with built-in request coalescing.
    /// [`moka::future::Cache::try_get_with`] deduplicates concurrent lookups
    /// for the same DID — if 500 connections present the same uncached DID
    /// simultaneously, only one outbound fetch is issued and all waiters
    /// share the result. This prevents the relay from acting as a DDoS
    /// amplifier against DID hosting servers.
    cache: moka::future::Cache<String, ResolvedKey>,
    /// Caches failed DID resolutions to prevent repeated outbound requests
    /// for the same bad DID (DDoS reflection protection).
    negative_cache: Cache<String, String>,
    /// Caches `reqwest::Client` instances keyed by did:web domain (host:port).
    /// Each client has DNS pinned to a validated (non-private) IP via
    /// `ClientBuilder::resolve`, which is a builder-level setting requiring a
    /// separate client. Caching avoids the heavy cost of constructing a new
    /// client (connection pool + background workers) on every DID fetch.
    /// Capped at [`MAX_DOMAIN_CLIENTS`] (100) — much lower than the key cache —
    /// because each client holds a connection pool and spawns background tasks.
    domain_clients: Cache<String, reqwest::Client>,
    /// Per-domain in-flight fetch counter. Tracks how many DID document fetches
    /// are currently in progress for each `did:web` domain. The counter is
    /// incremented before and decremented after each fetch (via RAII guard),
    /// so it reflects concurrent load rather than cumulative requests. This
    /// prevents attackers from permanently exhausting a domain's budget with
    /// fake requests that fail quickly.
    ///
    /// Uses an unbounded [`DashMap`] rather than a bounded moka cache to prevent
    /// cache-eviction attacks: a bounded cache allows an attacker to evict a
    /// domain's counter while requests are in-flight, causing a fresh counter
    /// (value 0) to be created on the next access and bypassing the per-domain
    /// concurrency limit. Entries are small (`Arc<AtomicU64>`) so the unbounded
    /// growth is acceptable; the global concurrency limit caps in-flight domains.
    domain_fetch_counts: Arc<DashMap<String, Arc<AtomicU64>>>,
    /// Global in-flight `did:web` fetch counter across all domains. Incremented
    /// before and decremented after each fetch (via RAII guard). Works alongside
    /// the per-domain counter to cap concurrent outbound DNS + HTTP activity,
    /// preventing subdomain spraying from exhausting the blocking thread pool.
    global_didweb_fetch_count: Arc<AtomicU64>,
    plc_directory: String,
}

/// Split a `did:web` method-specific identifier into (domain, optional_path).
///
/// Handles bracketed IPv6 addresses: if `raw` starts with `[`, the domain
/// extends through the closing `]` (and an optional `%3A`-encoded port),
/// and only a colon *after* that bracket group is treated as a path separator.
fn split_did_web_domain_path(raw: &str) -> Result<(&str, Option<&str>), String> {
    if raw.starts_with('[') {
        // Bracketed IPv6: find the closing `]`.
        let bracket_end = raw
            .find(']')
            .ok_or_else(|| "did:web contains opening '[' with no closing ']'".to_string())?;
        // After `]` there may be a percent-encoded port (`%3A8443` or `%3a8443`)
        // before the first path-separator colon.
        let after_bracket = &raw[bracket_end + 1..];
        // Skip an optional percent-encoded port (e.g. `%3A8443`).
        let rest = if let Some(stripped) = after_bracket
            .strip_prefix("%3A")
            .or_else(|| after_bracket.strip_prefix("%3a"))
        {
            // Consume digits (the port number), stop at the next colon or end.
            let port_end = stripped
                .find(':')
                .map(|i| bracket_end + 1 + 3 + i) // 3 = len("%3A")
                .unwrap_or(raw.len());
            let domain = &raw[..port_end];
            let path = if port_end < raw.len() {
                Some(&raw[port_end + 1..]) // skip the ':'
            } else {
                None
            };
            return Ok((domain, path));
        } else if after_bracket.starts_with(':') {
            // Colon immediately after `]` — path separator.
            let domain = &raw[..bracket_end + 1];
            let path = Some(&raw[bracket_end + 2..]); // skip `]:`
            return Ok((domain, path));
        } else {
            // Nothing after `]`, or unexpected characters — domain is the whole thing.
            &raw[bracket_end + 1..]
        };
        if rest.is_empty() {
            Ok((&raw[..], None))
        } else {
            Err(format!(
                "unexpected characters after IPv6 bracket in did:web: '{raw}'"
            ))
        }
    } else {
        // Non-bracketed: first colon is the path separator.
        match raw.find(':') {
            Some(i) => Ok((&raw[..i], Some(&raw[i + 1..]))),
            None => Ok((raw, None)),
        }
    }
}

/// Build the URL for fetching a DID document.
///
/// Follows the W3C DID specification:
/// - `did:plc:*` → `{plc_directory}/{did}`
/// - `did:web:example.com` → `https://example.com/.well-known/did.json`
/// - `did:web:example.com:u:alice` → `https://example.com/u/alice/did.json`
/// - `did:web:[2001:db8::1]` → `https://[2001:db8::1]/.well-known/did.json`
///
/// Percent-encoded port separators (`%3A`) in the domain are decoded.
/// Normalize a DID string for cache keying. For `did:web` DIDs, the domain
/// portion is lowercased because DNS is case-insensitive — `did:web:Example.com`
/// and `did:web:example.com` refer to the same host. Path segments and
/// `did:plc` identifiers are left unchanged (PLC identifiers are already
/// case-sensitive hex).
fn normalize_did(did: &str) -> String {
    if let Some(rest) = did.strip_prefix("did:web:") {
        // Use split_did_web_domain_path to correctly identify the domain
        // boundary for both regular hosts and bracketed IPv6 addresses.
        // A naïve `rest.find(':')` would match a colon *inside* an IPv6
        // bracket group (e.g. `[2001:DB8::1]`) rather than the path separator
        // colon that follows it, causing case permutations of the IPv6 address
        // to bypass the moka cache and the per-DID request coalescing.
        match split_did_web_domain_path(rest) {
            Ok((domain, Some(path))) => {
                format!("did:web:{}:{}", domain.to_ascii_lowercase(), path)
            }
            Ok((domain, None)) => {
                format!("did:web:{}", domain.to_ascii_lowercase())
            }
            // Malformed DID — return as-is; downstream validation will reject it.
            Err(_) => did.to_string(),
        }
    } else {
        did.to_string()
    }
}

fn did_document_url(did: &str, plc_directory: &str) -> Result<String, String> {
    if did.starts_with("did:plc:") {
        Ok(format!("{}/{did}", plc_directory.trim_end_matches('/')))
    } else if did.starts_with("did:web:") {
        let raw = did.strip_prefix("did:web:").ok_or("invalid did:web")?;
        let (domain_raw, path_raw) = split_did_web_domain_path(raw)?;
        // The W3C did:web spec requires only the port-separator colon to be
        // percent-encoded as %3A in the method-specific identifier.  We decode
        // exactly that sequence and nothing else: DNS hostnames do not use
        // RFC 3986 percent-encoding (IDNs are expressed as punycode ACE labels),
        // so any remaining `%XX` in the domain indicates a malformed DID.
        let domain = domain_raw.replace("%3A", ":").replace("%3a", ":");

        if let Some(path_segments) = path_raw {
            // Path-based: did:web:example.com:u:alice → example.com/u/alice/did.json
            let path = path_segments.replace(':', "/");
            Ok(format!("https://{domain}/{path}/did.json"))
        } else {
            // Domain-only: did:web:example.com → example.com/.well-known/did.json
            Ok(format!("https://{domain}/.well-known/did.json"))
        }
    } else {
        Err(format!("unsupported DID method: {did}"))
    }
}

/// RAII guard that decrements an [`AtomicU64`] on drop, ensuring concurrency
/// counters are always released even on early returns or panics.
///
/// Defined at module scope so it can be created inside [`tokio::task::spawn_blocking`]
/// closures and returned to async callers. This is critical: if the guard were
/// created in async code, dropping the async future (e.g. client TCP disconnect)
/// would free the concurrency slot while the blocking DNS thread continues,
/// allowing an attacker to bypass limits and exhaust the blocking pool.
///
/// Domain guards carry an optional back-reference to `domain_fetch_counts` so
/// that the map entry is pruned when the counter reaches zero. Without cleanup
/// the DashMap would accumulate one entry per unique attacker-controlled domain
/// string and grow without bound (OOM DoS). The `Arc::ptr_eq` check prevents
/// removing a replacement entry that a concurrent request may have inserted
/// between our `fetch_sub` and the `remove_if`.
#[derive(Debug)]
struct ConcurrencyGuard {
    counter: Arc<AtomicU64>,
    /// If set, remove the map entry on drop when `counter` reaches zero.
    cleanup: Option<(Arc<DashMap<String, Arc<AtomicU64>>>, String)>,
}

impl ConcurrencyGuard {
    fn new(counter: Arc<AtomicU64>) -> Self {
        Self {
            counter,
            cleanup: None,
        }
    }

    fn new_domain(
        counter: Arc<AtomicU64>,
        map: Arc<DashMap<String, Arc<AtomicU64>>>,
        key: String,
    ) -> Self {
        Self {
            counter,
            cleanup: Some((map, key)),
        }
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
        if let Some((map, key)) = &self.cleanup {
            // Remove the entry only if it still holds *our* Arc and the count
            // is zero.  A concurrent request may have re-used the same Arc
            // (counter now > 0) or replaced it with a new one (ptr_eq fails);
            // in either case we must not evict the live entry.
            let ours = Arc::clone(&self.counter);
            map.remove_if(key, |_, v| {
                Arc::ptr_eq(v, &ours) && v.load(Ordering::Relaxed) == 0
            });
        }
    }
}

/// Resolve a domain's DNS records, reject private/loopback IPs (SSRF protection),
/// and return the first safe [`std::net::SocketAddr`] along with RAII concurrency
/// guards.
///
/// The caller **must** pin the returned address when issuing the HTTP request
/// (via `reqwest::ClientBuilder::resolve`) to prevent TOCTOU DNS rebinding
/// attacks where the domain resolves to a different (private) IP on the second
/// lookup performed by reqwest.
///
/// Concurrency guards are acquired **inside** the [`tokio::task::spawn_blocking`]
/// closure so that if the async caller is dropped (e.g. client disconnects),
/// the slot is not freed until the OS thread finishes `getaddrinfo`. Without
/// this, an attacker could repeatedly connect/disconnect to queue un-cancellable
/// blocking tasks while the concurrency counter stays at zero, exhausting the
/// Tokio blocking thread pool (512 threads by default).
///
/// The per-domain counter is looked up **and incremented** inside `spawn_blocking`
/// while holding the [`DashMap`] entry lock. This closes the TOCTOU race where
/// [`ConcurrencyGuard::drop`] could call `remove_if` between the map lookup and
/// the `fetch_add`, causing a new request to track state on a disconnected `Arc`.
async fn validate_and_resolve_domain(
    domain: &str,
    global_counter: Arc<AtomicU64>,
    domain_fetch_counts: Arc<DashMap<String, Arc<AtomicU64>>>,
) -> Result<(std::net::SocketAddr, ConcurrencyGuard, ConcurrencyGuard), String> {
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

    // Everything below runs inside spawn_blocking: guard acquisition, DNS
    // resolution, and IP validation. This ensures the concurrency guards
    // are held by the OS thread and not freed if the async caller is dropped.
    let domain_owned = domain.to_string();
    tokio::task::spawn_blocking(move || {
        // Acquire the global concurrency guard on the blocking thread.
        let global_prev = global_counter.fetch_add(1, Ordering::Relaxed);
        let global_guard = ConcurrencyGuard::new(global_counter);
        if global_prev >= GLOBAL_DIDWEB_FETCH_CONCURRENCY_LIMIT {
            return Err(format!(
                "global did:web concurrency limit exceeded \
                 ({GLOBAL_DIDWEB_FETCH_CONCURRENCY_LIMIT} concurrent fetches)"
            ));
        }

        // Acquire the per-domain concurrency guard on the blocking thread.
        // The fetch_add is performed while holding the DashMap entry lock so
        // that ConcurrencyGuard::drop cannot call remove_if between the map
        // lookup and the increment (TOCTOU race fix).
        let domain_prev;
        let domain_counter = {
            let entry = domain_fetch_counts
                .entry(domain_owned.clone())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)));
            domain_prev = entry.fetch_add(1, Ordering::Relaxed);
            Arc::clone(&*entry)
        };
        let domain_guard =
            ConcurrencyGuard::new_domain(domain_counter, domain_fetch_counts, domain_owned.clone());
        if domain_prev >= DOMAIN_FETCH_CONCURRENCY_LIMIT {
            return Err(format!(
                "concurrency limit exceeded for did:web domain '{domain_owned}' \
                 ({DOMAIN_FETCH_CONCURRENCY_LIMIT} concurrent fetches)"
            ));
        }

        // std::net::ToSocketAddrs delegates to the OS's blocking getaddrinfo.
        let addrs: Vec<std::net::SocketAddr> = host_port
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
            .map_err(|e| format!("failed to resolve domain '{domain_owned}': {e}"))?;

        if addrs.is_empty() {
            return Err(format!("domain '{domain_owned}' resolved to no addresses"));
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
                    "did:web domain '{domain_owned}' resolves to private/loopback address {ip}, \
                     request blocked (SSRF protection)"
                ));
            }
        }

        Ok((addrs[0], global_guard, domain_guard))
    })
    .await
    .map_err(|e| format!("DNS resolution task panicked: {e}"))?
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
            // fc00::/7 (unique local, RFC 4193)
            (segments[0] & 0xfe00) == 0xfc00
            // ff00::/8 (multicast, RFC 4291)
            || (segments[0] & 0xff00) == 0xff00
            // 100::/64 (discard-only, RFC 6666)
            || (segments[0] == 0x0100
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0)
            // 2001:2::/48 (benchmarking, RFC 5180)
            || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0x0000)
            // 2001:db8::/32 (documentation, RFC 3849)
            || (segments[0] == 0x2001 && segments[1] == 0x0db8)
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

/// Extract the hostname portion of a domain string for DNS pinning.
///
/// Handles three forms:
/// - Plain hostname or IPv4: `example.com` / `example.com:8443` → `example.com`
/// - Bracketed IPv6 with port: `[2001:db8::1]:8443` → `[2001:db8::1]`
/// - Bracketed IPv6 without port: `[2001:db8::1]` → `[2001:db8::1]`
fn extract_hostname(domain: &str) -> String {
    if domain.starts_with('[') {
        // Bracketed IPv6 — take everything up to and including `]`.
        match domain.find(']') {
            Some(idx) => domain[..=idx].to_string(),
            None => domain.to_string(), // malformed, pass through
        }
    } else {
        // IPv4 or hostname — take everything before the first colon (port).
        domain.split(':').next().unwrap_or(domain).to_string()
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

        let cache = moka::future::Cache::builder()
            .max_capacity(MAX_CACHE_ENTRIES)
            .time_to_live(DEFAULT_CACHE_TTL)
            .build();

        let negative_cache = Cache::builder()
            .max_capacity(MAX_CACHE_ENTRIES)
            .time_to_live(NEGATIVE_CACHE_TTL)
            .build();

        let domain_clients = Cache::builder()
            .max_capacity(MAX_DOMAIN_CLIENTS)
            .time_to_live(DEFAULT_CACHE_TTL)
            .build();

        let domain_fetch_counts = Arc::new(DashMap::new());

        let global_didweb_fetch_count = Arc::new(AtomicU64::new(0));

        Self {
            client,
            cache,
            negative_cache,
            domain_clients,
            domain_fetch_counts,
            global_didweb_fetch_count,
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

    /// Resolve the signing key and algorithm for a DID.
    ///
    /// Returns a cached key if available and not expired, otherwise fetches
    /// the DID document from the network. Concurrent requests for the same
    /// DID are coalesced via [`moka::future::Cache::try_get_with`] — only one
    /// outbound fetch is issued and all waiters share the result.
    ///
    /// The moka cache handles TTL expiry and W-TinyLFU eviction automatically.
    pub async fn resolve_key(&self, did: &str) -> Result<ResolvedKey, String> {
        // Normalize the DID for cache keying. DNS is case-insensitive, so
        // did:web:Example.com and did:web:example.com should share a cache
        // entry. Lowercase the domain portion of did:web DIDs to prevent
        // case-permutation cache bypass attacks.
        let normalized = normalize_did(did);
        let did = normalized.as_str();

        // Reject DIDs that recently failed resolution to prevent repeated
        // outbound requests (DDoS reflection / resource exhaustion).
        if let Some(cached_err) = self.negative_cache.get(did) {
            return Err(format!(
                "DID resolution recently failed (cached): {cached_err}"
            ));
        }

        // try_get_with coalesces concurrent lookups for the same key: if
        // multiple tasks call this simultaneously for the same uncached DID,
        // only one runs the async closure and the others await its result.
        let negative_cache = self.negative_cache.clone();
        let did_owned = did.to_string();
        self.cache
            .try_get_with(did.to_string(), async {
                let doc = self.fetch_did_document(&did_owned).await.map_err(|e| {
                    negative_cache.insert(did_owned.clone(), e.clone());
                    e
                })?;
                extract_signing_key(&doc).map_err(|e| {
                    negative_cache.insert(did_owned.clone(), e.clone());
                    e
                })
            })
            .await
            .map_err(|e: Arc<String>| (*e).clone())
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
        //
        // Pinned clients are cached per domain to avoid the cost of
        // constructing a new reqwest::Client (connection pool + background
        // workers) on every cache-miss fetch. The domain_clients cache is
        // bounded and TTL'd so an attacker spamming unique domains can only
        // create a bounded number of clients before eviction kicks in.

        // Concurrency guards must live across the entire HTTP fetch, not just
        // the DNS resolution. They are acquired inside `spawn_blocking` (by
        // `validate_and_resolve_domain`) and returned here so they remain held
        // for the duration of the network call. This prevents a cancelled
        // caller from freeing the slot while the blocking thread still runs.
        let mut _global_guard: Option<ConcurrencyGuard> = None;
        let mut _domain_guard: Option<ConcurrencyGuard> = None;

        let pinned_client = if did.starts_with("did:web:") {
            let raw = did.strip_prefix("did:web:").ok_or("invalid did:web")?;
            let (domain_raw, _) = split_did_web_domain_path(raw)?;
            // Only %3A/%3a (port separator) is decoded — see did_document_url
            // for the rationale on intentionally skipping full RFC 3986 decode.
            let domain = domain_raw.replace("%3A", ":").replace("%3a", ":");

            // Use the full domain (host + port) as the cache key so that
            // `did:web:example.com%3A80` and `did:web:example.com` don't
            // share a pinned client (which would poison TLS on port 80).
            let cache_key = domain.clone();

            // Check the domain client cache BEFORE spawning a blocking DNS
            // resolution task. Many unique DIDs sharing the same domain
            // (e.g. `did:web:victim.com:u:1`, `did:web:victim.com:u:2`) would
            // otherwise each block a Tokio thread on getaddrinfo only to
            // discard the resolved address and reuse the cached client.
            let client = if let Some(cached) = self.domain_clients.get(&cache_key) {
                // Acquire concurrency guards for the HTTP fetch even when DNS
                // is skipped — the guards limit concurrent fetches per domain.
                // Since there is no spawn_blocking here, acquiring in async
                // context is correct (no blocking thread outlives the guard).
                let global_prev = self
                    .global_didweb_fetch_count
                    .fetch_add(1, Ordering::Relaxed);
                _global_guard = Some(ConcurrencyGuard::new(Arc::clone(
                    &self.global_didweb_fetch_count,
                )));
                if global_prev >= GLOBAL_DIDWEB_FETCH_CONCURRENCY_LIMIT {
                    return Err(format!(
                        "global did:web concurrency limit exceeded \
                         ({GLOBAL_DIDWEB_FETCH_CONCURRENCY_LIMIT} concurrent fetches)"
                    ));
                }
                // Increment while holding the entry lock to close the TOCTOU
                // race between fetch_add and remove_if in ConcurrencyGuard::drop.
                let domain_prev;
                let domain_counter = {
                    let entry = self
                        .domain_fetch_counts
                        .entry(domain.clone())
                        .or_insert_with(|| Arc::new(AtomicU64::new(0)));
                    domain_prev = entry.fetch_add(1, Ordering::Relaxed);
                    Arc::clone(&*entry)
                };
                _domain_guard = Some(ConcurrencyGuard::new_domain(
                    domain_counter,
                    Arc::clone(&self.domain_fetch_counts),
                    domain.clone(),
                ));
                if domain_prev >= DOMAIN_FETCH_CONCURRENCY_LIMIT {
                    return Err(format!(
                        "concurrency limit exceeded for did:web domain '{domain}' \
                         ({DOMAIN_FETCH_CONCURRENCY_LIMIT} concurrent fetches)"
                    ));
                }
                cached
            } else {
                // No cached client — resolve DNS, validate the IP, and build a
                // pinned client. Guards (including the domain counter increment)
                // are acquired inside spawn_blocking so they are not freed if
                // the async caller is cancelled mid-DNS.
                let (validated_addr, global_guard, domain_guard) = validate_and_resolve_domain(
                    &domain,
                    Arc::clone(&self.global_didweb_fetch_count),
                    Arc::clone(&self.domain_fetch_counts),
                )
                .await?;
                _global_guard = Some(global_guard);
                _domain_guard = Some(domain_guard);

                // Extract hostname for DNS pinning. Bracketed IPv6 literals like
                // `[2001:db8::1]:8443` must be handled specially — a naive
                // `split(':').next()` would yield `[2001` instead of the full
                // bracket expression.
                let host_only = extract_hostname(&domain);

                let pinned = reqwest::Client::builder()
                    .timeout(DID_FETCH_TIMEOUT)
                    .redirect(reqwest::redirect::Policy::none())
                    .resolve(&host_only, validated_addr)
                    .build()
                    .map_err(|e| format!("failed to build pinned HTTP client: {e}"))?;
                self.domain_clients.insert(cache_key, pinned.clone());
                pinned
            };
            Some(client)
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
/// to a [`ResolvedKey`] suitable for `jsonwebtoken` verification.
///
/// Supports both P-256 (ES256) and secp256k1 (ES256K) keys, as the ATProto
/// specification permits either curve for `did:plc` identities.
fn extract_signing_key(doc: &DidDocument) -> Result<ResolvedKey, String> {
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
            .map_or_else(|| "(empty)".to_string(), |c| c.to_string());
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
        decode_k256_key(key_bytes)
    } else {
        Err(format!(
            "unknown multicodec prefix: [{:#04x}, {:#04x}]",
            prefix[0], prefix[1]
        ))
    }
}

/// Decode a compressed P-256 public key into a [`ResolvedKey`] for ES256.
fn decode_p256_key(compressed: &[u8]) -> Result<ResolvedKey, String> {
    let public_key = p256::PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;

    let pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("P-256 PEM encoding failed: {e}"))?;

    let key = DecodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| format!("failed to create DecodingKey from P-256 PEM: {e}"))?;

    Ok(ResolvedKey::P256(key))
}

/// Decode a compressed secp256k1 public key into a [`ResolvedKey`] for ES256K.
fn decode_k256_key(compressed: &[u8]) -> Result<ResolvedKey, String> {
    let public_key = k256::PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| format!("invalid secp256k1 public key: {e}"))?;

    Ok(ResolvedKey::K256(public_key))
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

    /// A known K-256 (secp256k1) compressed public key, wrapped in multicodec
    /// + multibase for round-trip testing.
    fn make_test_k256_multibase_key() -> String {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = k256::SecretKey::from_slice(&[
            0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a,
            0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15,
            0xb0, 0xf0, 0x0a, 0x08,
        ])
        .expect("valid test key");
        let public = secret.public_key();
        let point = public.to_encoded_point(true);
        let compressed = point.as_bytes();

        let mut prefixed = Vec::with_capacity(2 + compressed.len());
        prefixed.extend_from_slice(&K256_MULTICODEC);
        prefixed.extend_from_slice(compressed);
        let encoded = bs58::encode(&prefixed).into_string();

        format!("z{encoded}")
    }

    fn assert_err_contains(result: Result<ResolvedKey, String>, needle: &str) {
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
        assert!(matches!(result.unwrap(), ResolvedKey::P256(_)));
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
    fn extracts_k256_key_from_did_document() {
        let multibase_key = make_test_k256_multibase_key();

        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some(multibase_key),
            }]),
        };

        let result = extract_signing_key(&doc);
        assert!(
            result.is_ok(),
            "failed to extract K-256 key: {:?}",
            result.err()
        );
        assert!(matches!(result.unwrap(), ResolvedKey::K256(_)));
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

    // ── IPv6 did:web tests ─────────────────────────────────────────────

    #[test]
    fn did_web_ipv6_domain_only() {
        let url = did_document_url("did:web:[2001:db8::1]", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://[2001:db8::1]/.well-known/did.json");
    }

    #[test]
    fn did_web_ipv6_with_path() {
        let url = did_document_url("did:web:[2001:db8::1]:u:alice", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://[2001:db8::1]/u/alice/did.json");
    }

    #[test]
    fn did_web_ipv6_with_port() {
        let url = did_document_url("did:web:[2001:db8::1]%3A8443", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://[2001:db8::1]:8443/.well-known/did.json");
    }

    #[test]
    fn did_web_ipv6_with_port_and_path() {
        let url =
            did_document_url("did:web:[2001:db8::1]%3A8443:u:bob", DEFAULT_PLC_DIRECTORY).unwrap();
        assert_eq!(url, "https://[2001:db8::1]:8443/u/bob/did.json");
    }

    #[test]
    fn did_web_ipv6_unclosed_bracket_errors() {
        let result = did_document_url("did:web:[2001:db8::1", DEFAULT_PLC_DIRECTORY);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no closing ']'"));
    }

    // ── SSRF protection tests ─────────────────────────────────────────

    /// Helper: call `validate_and_resolve_domain` with fresh counters.
    async fn resolve_domain_for_test(
        domain: &str,
    ) -> Result<(std::net::SocketAddr, ConcurrencyGuard, ConcurrencyGuard), String> {
        validate_and_resolve_domain(
            domain,
            Arc::new(AtomicU64::new(0)),
            Arc::new(DashMap::new()),
        )
        .await
    }

    #[tokio::test]
    async fn ssrf_rejects_loopback() {
        let result = resolve_domain_for_test("localhost").await;
        assert!(result.is_err(), "expected loopback to be rejected");
        assert!(
            result.unwrap_err().contains("SSRF protection"),
            "error should mention SSRF"
        );
    }

    #[tokio::test]
    async fn ssrf_rejects_127_0_0_1() {
        let result = resolve_domain_for_test("127.0.0.1").await;
        assert!(result.is_err(), "expected 127.0.0.1 to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_private_10_network() {
        let result = resolve_domain_for_test("10.0.0.1").await;
        assert!(result.is_err(), "expected 10.x.x.x to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_private_172_network() {
        let result = resolve_domain_for_test("172.16.0.1").await;
        assert!(result.is_err(), "expected 172.16.x.x to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_private_192_168_network() {
        let result = resolve_domain_for_test("192.168.1.1").await;
        assert!(result.is_err(), "expected 192.168.x.x to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_link_local() {
        let result = resolve_domain_for_test("169.254.1.1").await;
        assert!(result.is_err(), "expected link-local to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_loopback_with_port() {
        let result = resolve_domain_for_test("127.0.0.1:10250").await;
        assert!(result.is_err(), "expected 127.0.0.1:port to be rejected");
    }

    #[tokio::test]
    async fn ssrf_rejects_this_network_0_0_0_1() {
        let result = resolve_domain_for_test("0.0.0.1").await;
        assert!(
            result.is_err(),
            "expected 0.0.0.1 (this-network) to be rejected"
        );
    }

    #[tokio::test]
    async fn ssrf_rejects_multicast() {
        let result = resolve_domain_for_test("224.0.0.1").await;
        assert!(
            result.is_err(),
            "expected multicast 224.0.0.1 to be rejected"
        );
    }

    #[tokio::test]
    async fn ssrf_rejects_broadcast() {
        let result = resolve_domain_for_test("255.255.255.255").await;
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

    #[test]
    fn multibyte_multibase_prefix_does_not_panic() {
        // A multi-byte UTF-8 character as the multibase prefix must not
        // cause a panic from byte-level string slicing (issue #1).
        let doc = DidDocument {
            verification_method: Some(vec![VerificationMethod {
                id: "did:plc:test#atproto".to_string(),
                key_type: "Multikey".to_string(),
                public_key_multibase: Some("\u{1F680}rest".to_string()), // 🚀
            }]),
        };

        let result = extract_signing_key(&doc);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("should reject non-'z' prefix"),
        };
        assert!(
            err.contains("unsupported multibase prefix"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains('\u{1F680}'),
            "error should include the actual prefix char"
        );
    }
}
