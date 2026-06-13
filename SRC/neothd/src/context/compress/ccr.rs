//! GOLD-HR-03 — Content-Caching-and-Retrieval: the safety store that makes
//! every lossy compression answer-safe.
//!
//! When a transform drops rows or replaces a span with an opaque summary, the
//! *original* text is stashed here keyed by its content hash, and a retrieval
//! marker ([`marker_for`]) is left inline in the compressed body. The model
//! (via an MCP retrieve tool) or the operator (via `neoth ctx retrieve <key>`)
//! can later pull the exact original back — lossy on the wire, lossless
//! end-to-end. This is the cornerstone the headroom design calls CCR.
//!
//! Ported from headroom's `ccr/` module (chopratejas/headroom, Apache-2.0),
//! stripped to the put/get contract that matters for retrieval. Two NEOTH
//! deltas from upstream, both to stay self-contained:
//!
//! - **Key = SHA-256[:24]** (24 hex chars / 96 bits), not headroom's BLAKE3 —
//!   NEOTH already depends on `sha2`, and adds no `blake3`. The marker shape
//!   (`[0-9a-f]{24}`) is identical, and the store is internally consistent
//!   (NEOTH stashes and NEOTH retrieves), so the hash choice is private.
//! - **Backend = a single `Mutex<HashMap>`**, not a sharded `DashMap` — the
//!   daemon issues one put/get per compressed block per call, nowhere near the
//!   QPS that justified upstream's sharding. The [`CcrStore`] trait keeps the
//!   door open for an on-disk (sqlite) backend later without touching callers.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use sha2::{Digest, Sha256};

/// Default capacity — matches headroom's `CompressionStore` default.
pub const DEFAULT_CAPACITY: usize = 1000;

/// Default TTL — 5 minutes, matching headroom. Long enough that a marker
/// emitted early in a turn is still retrievable when the model asks for it
/// later in the same conversation; short enough to bound memory.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Pluggable CCR storage backend. `Send + Sync` so it can live behind an `Arc`
/// in daemon state and be shared across the dispatch loop's worker threads.
pub trait CcrStore: Send + Sync {
    /// Stash `payload` under `hash`. Re-storing the same hash overwrites and
    /// refreshes the timestamp (idempotent — same hash means same content).
    fn put(&self, hash: &str, payload: &str);

    /// Look up `hash`. Returns `None` if missing or past its TTL.
    fn get(&self, hash: &str) -> Option<String>;

    /// Number of live entries. Informational (tests + telemetry).
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Compute the canonical CCR key for `payload`: SHA-256 → first 24 hex chars
/// (96 bits — collision-resistant for the bounded LRU population the daemon
/// holds). Centralized so every call site hashes identically.
pub fn compute_key(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    // 12 bytes → 24 lowercase hex chars. Matches the `[0-9a-f]{24}` marker
    // grammar without pulling in a hex crate.
    let mut out = String::with_capacity(24);
    for b in &digest[..12] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The inline marker injected where compressed content was dropped, e.g.
/// `<<ccr:1a2b3c…>>`. The format is fixed so the retrieval tool and the
/// `neoth ctx retrieve` CLI parse the same shape.
pub fn marker_for(hash: &str) -> String {
    format!("<<ccr:{hash}>>")
}

/// Matches every `<<ccr:HASH>>` marker, capturing the 24-char key.
static MARKER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<<ccr:([0-9a-f]{24})>>").unwrap());

/// Extract every CCR key referenced by `text`, in order of appearance
/// (duplicates preserved — callers dedupe if they care). Used by the dispatch
/// loop to know which keys a compressed block may ask to retrieve.
pub fn extract_keys(text: &str) -> Vec<String> {
    MARKER_RE
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

/// Stash `original` and return `(key, marker)`. The lossy transform writes
/// `marker` where it dropped `original`; the store now holds the bytes to
/// answer a later retrieval. The key is content-addressed, so stashing the
/// same text twice is a cheap idempotent overwrite.
pub fn stash(store: &dyn CcrStore, original: &str) -> (String, String) {
    let key = compute_key(original.as_bytes());
    store.put(&key, original);
    let marker = marker_for(&key);
    (key, marker)
}

/// Retrieve by raw key or by a full `<<ccr:KEY>>` marker. Returns the exact
/// original bytes, or `None` if the key is unknown / expired.
pub fn retrieve(store: &dyn CcrStore, key_or_marker: &str) -> Option<String> {
    let key = MARKER_RE
        .captures(key_or_marker)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| key_or_marker.trim().to_string());
    store.get(&key)
}

// ─── In-memory backend ─────────────────────────────────────────────────

struct Entry {
    payload: String,
    inserted: Instant,
}

struct Inner {
    map: HashMap<String, Entry>,
    /// FIFO insertion order for capacity eviction. May hold keys already
    /// dropped from `map` (TTL-expired) — eviction tolerates and skips those.
    order: VecDeque<String>,
}

/// Process-local CCR store: capacity-bounded, TTL-expiring, behind one
/// `Mutex`. The daemon mounts a single instance in shared state.
///
/// - **TTL**: entries past their TTL are dropped lazily on the next `get`
///   (no background reaper).
/// - **Capacity**: a fresh `put` past capacity evicts the oldest entry
///   (FIFO / insertion order).
pub struct InMemoryCcrStore {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

impl InMemoryCcrStore {
    /// Default: 1000 entries, 5-minute TTL.
    pub fn new() -> Self {
        Self::with_capacity_and_ttl(DEFAULT_CAPACITY, DEFAULT_TTL)
    }

    pub fn with_capacity_and_ttl(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(capacity.min(1024)),
                order: VecDeque::new(),
            }),
            ttl,
            capacity: capacity.max(1),
        }
    }
}

impl Default for InMemoryCcrStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CcrStore for InMemoryCcrStore {
    fn put(&self, hash: &str, payload: &str) {
        let mut g = self.inner.lock().expect("ccr mutex poisoned");
        // Idempotent re-store: overwrite payload + refresh timestamp, leave
        // the order queue alone.
        if let Some(existing) = g.map.get_mut(hash) {
            existing.payload = payload.to_string();
            existing.inserted = Instant::now();
            return;
        }
        // Fresh key — evict oldest *real* entries until under capacity, then
        // insert + record FIFO order.
        while g.map.len() >= self.capacity {
            let Some(oldest) = g.order.pop_front() else {
                break;
            };
            g.map.remove(&oldest); // no-op if already lazy-expired
        }
        g.map.insert(
            hash.to_string(),
            Entry {
                payload: payload.to_string(),
                inserted: Instant::now(),
            },
        );
        g.order.push_back(hash.to_string());
    }

    fn get(&self, hash: &str) -> Option<String> {
        let mut g = self.inner.lock().expect("ccr mutex poisoned");
        match g.map.get(hash) {
            Some(e) if e.inserted.elapsed() <= self.ttl => Some(e.payload.clone()),
            Some(_) => {
                // Expired — drop it.
                g.map.remove(hash);
                None
            }
            None => None,
        }
    }

    fn len(&self) -> usize {
        self.inner.lock().expect("ccr mutex poisoned").map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_key_is_24_lowercase_hex() {
        let k = compute_key(b"hello world");
        assert_eq!(k.len(), 24);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn compute_key_is_deterministic_and_distinct() {
        assert_eq!(compute_key(b"same"), compute_key(b"same"));
        assert_ne!(compute_key(b"alpha"), compute_key(b"beta"));
    }

    #[test]
    fn marker_format_is_pinned() {
        assert_eq!(marker_for("abc123abc123abc123abc123"), "<<ccr:abc123abc123abc123abc123>>");
    }

    #[test]
    fn put_then_get_round_trips() {
        let store = InMemoryCcrStore::new();
        store.put("abc", r#"[{"id":1}]"#);
        assert_eq!(store.get("abc"), Some(r#"[{"id":1}]"#.to_string()));
        assert_eq!(store.get("missing"), None);
    }

    #[test]
    fn put_overwrites_same_hash_no_dup() {
        let store = InMemoryCcrStore::new();
        store.put("h", "first");
        store.put("h", "second");
        assert_eq!(store.get("h"), Some("second".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = InMemoryCcrStore::with_capacity_and_ttl(2, DEFAULT_TTL);
        store.put("a", "1");
        store.put("b", "2");
        store.put("c", "3");
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("a"), None);
        assert_eq!(store.get("b"), Some("2".to_string()));
        assert_eq!(store.get("c"), Some("3".to_string()));
    }

    #[test]
    fn expired_entries_dropped_on_get() {
        let store = InMemoryCcrStore::with_capacity_and_ttl(10, Duration::from_millis(10));
        store.put("a", "1");
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(store.get("a"), None);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn extract_keys_finds_all_markers() {
        let body = format!(
            "head {} mid {} tail",
            marker_for("0123456789abcdef01234567"),
            marker_for("fedcba9876543210fedcba98")
        );
        let keys = extract_keys(&body);
        assert_eq!(
            keys,
            vec![
                "0123456789abcdef01234567".to_string(),
                "fedcba9876543210fedcba98".to_string()
            ]
        );
        assert!(extract_keys("no markers here").is_empty());
    }

    #[test]
    fn stash_then_retrieve_round_trips_byte_for_byte() {
        // The HR-03 acceptance test: compress → marker → retrieve returns the
        // exact original, byte-for-byte, including newlines and unicode.
        let store = InMemoryCcrStore::new();
        let original = "line1\nÜber\tTAB\n  trailing spaces   \n{\"k\":[1,2,3]}\n";
        let (key, marker) = stash(&store, original);

        // The compressed body would carry the marker in place of the original.
        let compressed = format!("[compressed 3 of 200 rows; rest at {marker}]");
        let referenced = extract_keys(&compressed);
        assert_eq!(referenced, vec![key.clone()]);

        // Retrieval by marker and by raw key both return the original.
        assert_eq!(retrieve(&store, &marker).as_deref(), Some(original));
        assert_eq!(retrieve(&store, &key).as_deref(), Some(original));
    }

    #[test]
    fn retrieve_unknown_key_is_none() {
        let store = InMemoryCcrStore::new();
        assert_eq!(retrieve(&store, "<<ccr:000000000000000000000000>>"), None);
        assert_eq!(retrieve(&store, "deadbeef"), None);
    }

    #[test]
    fn store_is_send_sync_and_trait_object() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryCcrStore>();
        let store: Box<dyn CcrStore> = Box::new(InMemoryCcrStore::new());
        store.put("h", "v");
        assert_eq!(store.get("h"), Some("v".to_string()));
        assert!(!store.is_empty());
    }
}
