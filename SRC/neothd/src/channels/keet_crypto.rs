//! Keet / Hyperswarm pairing crypto primitives — R-2 Phase 1.
//!
//! Hyperswarm pairs peers via a 32-byte topic key that BOTH sides
//! derive from the same seed material. The first side that drops
//! the topic into the DHT becomes discoverable; the second side
//! looks up the same topic + completes a NOISE handshake using a
//! per-peer ed25519 keypair derived from a SEPARATE branch of the
//! same seed.
//!
//! This module ships the deterministic byte-level derivation
//! Hyperswarm + Keet's identity layer expect. The actual handshake
//! (NOISE/IK + Hypercore replication state machine + DHT bucket
//! protocol) is multi-week Phase 2 work; what's here is the
//! cryptographic anchor every Phase 2 component will reuse.
//!
//! ## Domain separation
//!
//! Three independent 32-byte values fall out of the operator's
//! 24-word seed phrase:
//!
//!   - **Entropy** = SHA-256("keet/entropy/v1\0" || phrase_canonical)
//!     The raw seed bytes the ed25519 keypair is built from.
//!   - **Topic key** = SHA-256("keet/topic/v1\0" || phrase_canonical)
//!     The 32-byte topic the swarm subscribes to. Both sides
//!     compute this identically.
//!   - **Discovery key** = HMAC-SHA256("hypercore", topic_key)
//!     The DHT lookup key. Matches Hyperswarm's reference impl
//!     (`hypercore-crypto::discovery_key`).
//!
//! `phrase_canonical` is the seed phrase with words split on
//! whitespace then re-joined by single spaces — guards against
//! invisible-character paste artifacts (NBSP / tab / multi-space).
//!
//! ## Why not BIP39
//!
//! Keet uses its own wordlist (not BIP39's), and the JS
//! Holepunch stack derives the keypair via a Sodium-style
//! seed-expansion that we can't bit-exact reproduce here
//! without porting the wordlist + algorithm. The wire-protocol
//! contact point IS the 32-byte topic key, NOT the wordlist —
//! so this module computes the topic key from the phrase as
//! the operator typed it, in a domain-separated way that gives
//! deterministic results across both sides AS LONG AS both
//! sides use this same derivation.
//!
//! For Phase 2 (real Holepunch interop) the topic-key derivation
//! will need to switch to whatever Keet's actual algorithm is.
//! The function-level surface here stays stable: callers ask for
//! `topic_key(phrase)`, the implementation can swap algorithms
//! without breaking call sites.

use sha2::{Digest, Sha256};

/// Domain-separation prefix for the entropy branch.
const ENTROPY_DOMAIN: &[u8] = b"keet/entropy/v1\0";

/// Domain-separation prefix for the topic-key branch.
const TOPIC_DOMAIN: &[u8] = b"keet/topic/v1\0";

/// Hypercore's discovery-key HMAC namespace. Pinned to the
/// reference impl's value so a NEOTH operator + a JS-Keet operator
/// on the SAME topic key compute the same DHT lookup key.
const HYPERCORE_DISCOVERY_NAMESPACE: &[u8] = b"hypercore";

/// 32-byte cryptographic value with a typed wrapper so call sites
/// can't mix entropy + topic + discovery keys by accident.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entropy(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TopicKey(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryKey(pub [u8; 32]);

impl std::fmt::Debug for Entropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak the entropy bytes in debug output — protects
        // operators who copy stack traces to a bug report.
        write!(f, "Entropy(<32 bytes redacted>)")
    }
}

impl std::fmt::Debug for TopicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Topic key is less sensitive than entropy but still
        // identifies the swarm; render as hex prefix only.
        write!(f, "TopicKey({})", hex_short(&self.0))
    }
}

impl std::fmt::Debug for DiscoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DiscoveryKey({})", hex_short(&self.0))
    }
}

/// Render the first 8 bytes of `bytes` as lowercase hex — used by
/// the Debug impls to give operators a visual anchor without
/// leaking the whole key.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(17);
    for b in &bytes[..8] {
        out.push_str(&format!("{:02x}", b));
    }
    out.push('…');
    out
}

/// Errors the derivation primitives can produce.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeetCryptoError {
    #[error("empty seed phrase")]
    EmptyPhrase,
}

/// Canonical form of the operator's seed phrase: split on any
/// whitespace + rejoin with single spaces. Guards against NBSP /
/// tab / trailing-whitespace paste artifacts so the same words
/// always produce the same bytes.
pub fn canonicalize(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// 32-byte entropy branch — feeds an ed25519 secret-seed when the
/// Phase 2 handshake lands. Domain-separated from the topic key so
/// a leaked topic doesn't reveal the keypair.
pub fn entropy(phrase: &str) -> Result<Entropy, KeetCryptoError> {
    let canonical = canonicalize(phrase);
    if canonical.is_empty() {
        return Err(KeetCryptoError::EmptyPhrase);
    }
    let mut hasher = Sha256::new();
    hasher.update(ENTROPY_DOMAIN);
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Ok(Entropy(bytes))
}

/// 32-byte topic key — the swarm rendezvous anchor. Both sides
/// derive this identically from the shared phrase.
pub fn topic_key(phrase: &str) -> Result<TopicKey, KeetCryptoError> {
    let canonical = canonicalize(phrase);
    if canonical.is_empty() {
        return Err(KeetCryptoError::EmptyPhrase);
    }
    let mut hasher = Sha256::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Ok(TopicKey(bytes))
}

/// Hyperswarm discovery key — HMAC-SHA256(namespace="hypercore",
/// data=topic_key). Pinned to the reference impl's namespace so a
/// NEOTH operator + a JS-Keet operator on the same topic look up
/// the same DHT bucket.
pub fn discovery_key(topic: TopicKey) -> DiscoveryKey {
    let mut out = [0u8; 32];
    hmac_sha256(HYPERCORE_DISCOVERY_NAMESPACE, &topic.0, &mut out);
    DiscoveryKey(out)
}

/// Tiny HMAC-SHA256 — uses the existing sha2 dep so we don't add
/// `hmac` to the Cargo.toml just for one call. Matches the
/// standard RFC 2104 construction.
///
/// Public so the cluster-discovery layer can reuse it for its own
/// authenticator without re-deriving the construction.
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; 32]) {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = Sha256::new();
        h.update(key);
        let k = h.finalize();
        key_block[..32].copy_from_slice(&k);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let final_hash = outer.finalize();
    out.copy_from_slice(&final_hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PHRASE: &str =
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
         kilo lima mike november oscar papa quebec romeo sierra tango \
         uniform victor whiskey xray";

    #[test]
    fn canonicalize_normalises_whitespace() {
        assert_eq!(canonicalize("  foo  bar\t  baz\n"), "foo bar baz");
        assert_eq!(canonicalize("foo bar baz"), "foo bar baz");
        assert_eq!(canonicalize(""), "");
    }

    #[test]
    fn entropy_deterministic_for_same_phrase() {
        let a = entropy(SAMPLE_PHRASE).unwrap();
        let b = entropy(SAMPLE_PHRASE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn entropy_differs_across_phrases() {
        let a = entropy("foo bar baz").unwrap();
        let b = entropy("foo bar qux").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn entropy_canonicalises_whitespace() {
        // Operator pasted with extra spaces — should match clean phrase.
        let a = entropy(SAMPLE_PHRASE).unwrap();
        let b = entropy(&format!("  {SAMPLE_PHRASE}\t\n")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn entropy_rejects_empty() {
        assert_eq!(entropy(""), Err(KeetCryptoError::EmptyPhrase));
        assert_eq!(entropy("   \t\n  "), Err(KeetCryptoError::EmptyPhrase));
    }

    #[test]
    fn topic_key_differs_from_entropy() {
        let e = entropy(SAMPLE_PHRASE).unwrap();
        let t = topic_key(SAMPLE_PHRASE).unwrap();
        assert_ne!(e.0, t.0, "domain separation: entropy != topic_key");
    }

    #[test]
    fn topic_key_deterministic() {
        let a = topic_key(SAMPLE_PHRASE).unwrap();
        let b = topic_key(SAMPLE_PHRASE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn discovery_key_differs_from_topic() {
        let t = topic_key(SAMPLE_PHRASE).unwrap();
        let d = discovery_key(t);
        assert_ne!(d.0, t.0);
    }

    #[test]
    fn discovery_key_deterministic() {
        let t = topic_key(SAMPLE_PHRASE).unwrap();
        let d1 = discovery_key(t);
        let d2 = discovery_key(t);
        assert_eq!(d1, d2);
    }

    #[test]
    fn hmac_sha256_matches_known_test_vector() {
        // RFC 4231 test vector 1: key = "Jefe" * x20 (len 20),
        // data = "Hi There" (Test Case 1: key=0x0b*20, data="Hi There").
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b\
                           881dc200c9833da726e9376c2e32cff7";
        let mut out = [0u8; 32];
        hmac_sha256(&key, data, &mut out);
        let got_hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got_hex, expected_hex);
    }

    #[test]
    fn debug_redacts_entropy_bytes() {
        let e = entropy(SAMPLE_PHRASE).unwrap();
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("redacted"));
        // The actual byte values should NOT appear in debug output.
        let hex: String = e.0.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex));
    }

    #[test]
    fn debug_topic_shows_hex_prefix() {
        let t = topic_key(SAMPLE_PHRASE).unwrap();
        let dbg = format!("{:?}", t);
        assert!(dbg.contains("TopicKey"));
        assert!(dbg.contains("…"), "should truncate with ellipsis");
        // First 8 bytes should appear in lowercase hex.
        let prefix_hex: String = t.0[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert!(dbg.contains(&prefix_hex));
    }

    #[test]
    fn domain_separation_pinned_constants() {
        // Pin the constants — if a future contributor changes them,
        // every existing pairing breaks (different topic key →
        // different DHT bucket → peers never find each other).
        assert_eq!(ENTROPY_DOMAIN, b"keet/entropy/v1\0");
        assert_eq!(TOPIC_DOMAIN, b"keet/topic/v1\0");
        assert_eq!(HYPERCORE_DISCOVERY_NAMESPACE, b"hypercore");
    }
}
