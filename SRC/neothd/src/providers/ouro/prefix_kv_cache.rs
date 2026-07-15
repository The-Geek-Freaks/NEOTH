//! GOLD-ADAPT-KV-01 — cross-request prefix-KV reuse cache for the Ouro local
//! model. Caches the per-loop KV snapshot of a shared prompt PREFIX (the system
//! prompt) keyed by a hash of the prefix token ids, so a later request with the
//! same system prompt skips re-prefilling it.
//!
//! Re-implemented in Rust from the IDEAS in LMCache (Apache-2.0; cross-request
//! prefix reuse + chunk-hash key chain — `QUELLEN/LMCache/lmcache/`), adapted to
//! NEOTH's RECURRENT Ouro KV cache (per-loop slots, not a flat transformer
//! cache).
//!
//! ## Correctness
//!
//! A restored prefix snapshot + a suffix forward at `seqlen_offset = prefix_len`
//! produces logits identical (within fp tolerance) to a clean full-prefill: the
//! prefix's per-loop K/V is causally independent of the suffix (causal attention
//! → a prefix position's hidden state at every recurrent loop depends only on
//! `0..=that position`, regardless of the suffix; proven by induction over the
//! loops). The parity oracle `prefix_kv_restore_matches_full_prefill_baseline`
//! in `forward.rs` + `quantized_forward.rs` pins this on deterministic non-zero
//! synthetic weights (the property is algebraic — position encoding + attention
//! math — so synthetic weights are sufficient, like GOLD-COR-36).
//!
//! ## Gating
//!
//! OFF by default. It relies on the COR-36 `per_loop` incremental decode path
//! (the offset>0 KV reuse), so it activates only when BOTH
//! `NEOTH_OURO_KV_CACHE_MODE=per_loop` AND `NEOTH_OURO_PREFIX_KV=1` are set. The
//! default `full_resequence` path is 100% unchanged (it clears the cache every
//! step, so a prefix snapshot would be moot).

use candle_core::Tensor;
use xxhash_rust::xxh3::xxh3_64;

/// A full-model KV snapshot: outer = layers, inner = per-recurrent-loop slots.
/// `Tensor::clone` is an Arc refcount bump, so taking a snapshot copies no
/// tensor data — only the `Option`/`Vec` spine is allocated.
pub type KvSnapshot = Vec<Vec<Option<(Tensor, Tensor)>>>;

/// One cached prefix: its KV snapshot + the token ids that produced it (kept for
/// the hash-collision / tokenizer-drift debug-assert on a cache hit).
pub struct PrefixKvEntry {
    pub snapshot: KvSnapshot,
    pub prefix_ids: Vec<u32>,
}

/// Bounded in-process cache keyed by a hash of the prefix token ids. A single
/// operator typically uses one or a few system prompts, so a tiny cap suffices;
/// eviction is arbitrary (key diversity is low). Lives inside `LoadedOuro`
/// behind the adapter's existing model lock — no extra synchronisation.
pub struct PrefixKvCache {
    entries: std::collections::HashMap<u64, PrefixKvEntry>,
    cap: usize,
}

impl PrefixKvCache {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Deterministic key = xxh3-64 over the little-endian bytes of the prefix
    /// token ids. In-process only (the cache is cleared on daemon restart), so
    /// no cross-host stability is required — endianness is irrelevant.
    pub fn key(prefix_ids: &[u32]) -> u64 {
        let mut bytes = Vec::with_capacity(prefix_ids.len() * 4);
        for id in prefix_ids {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        xxh3_64(&bytes)
    }

    pub fn get(&self, key: u64) -> Option<&PrefixKvEntry> {
        self.entries.get(&key)
    }

    pub fn insert(&mut self, key: u64, entry: PrefixKvEntry) {
        // Evict only when inserting a genuinely new key at capacity (a re-insert
        // of an existing key replaces in place and must not evict a sibling).
        if !self.entries.contains_key(&key)
            && self.entries.len() >= self.cap
            && let Some(victim) = self.entries.keys().next().copied()
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(key, entry);
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_snapshot() -> KvSnapshot {
        vec![vec![None]]
    }

    #[test]
    fn key_is_deterministic_and_order_sensitive() {
        assert_eq!(
            PrefixKvCache::key(&[1, 2, 3]),
            PrefixKvCache::key(&[1, 2, 3])
        );
        assert_ne!(
            PrefixKvCache::key(&[1, 2, 3]),
            PrefixKvCache::key(&[3, 2, 1]),
            "order matters"
        );
        assert_ne!(
            PrefixKvCache::key(&[1, 2, 3]),
            PrefixKvCache::key(&[1, 2]),
            "length matters"
        );
    }

    #[test]
    fn insert_get_roundtrip() {
        let mut c = PrefixKvCache::new(4);
        let k = PrefixKvCache::key(&[1, 2, 3]);
        c.insert(
            k,
            PrefixKvEntry {
                snapshot: stub_snapshot(),
                prefix_ids: vec![1, 2, 3],
            },
        );
        assert_eq!(c.get(k).unwrap().prefix_ids, vec![1, 2, 3]);
        assert!(c.get(PrefixKvCache::key(&[9])).is_none());
    }

    #[test]
    fn evicts_at_cap_on_new_key() {
        let mut c = PrefixKvCache::new(2);
        for i in 0..3u32 {
            let k = PrefixKvCache::key(&[i]);
            c.insert(
                k,
                PrefixKvEntry {
                    snapshot: stub_snapshot(),
                    prefix_ids: vec![i],
                },
            );
        }
        assert_eq!(
            c.entry_count(),
            2,
            "cap holds at 2 after a third distinct insert"
        );
    }

    #[test]
    fn reinsert_same_key_does_not_grow_or_evict() {
        let mut c = PrefixKvCache::new(2);
        let a = PrefixKvCache::key(&[7]);
        let b = PrefixKvCache::key(&[8]);
        c.insert(
            a,
            PrefixKvEntry {
                snapshot: stub_snapshot(),
                prefix_ids: vec![7],
            },
        );
        c.insert(
            b,
            PrefixKvEntry {
                snapshot: stub_snapshot(),
                prefix_ids: vec![8],
            },
        );
        // Re-insert an existing key at cap: must replace in place, not evict the sibling.
        c.insert(
            a,
            PrefixKvEntry {
                snapshot: stub_snapshot(),
                prefix_ids: vec![7],
            },
        );
        assert_eq!(c.entry_count(), 2);
        assert!(c.get(a).is_some() && c.get(b).is_some());
    }
}
