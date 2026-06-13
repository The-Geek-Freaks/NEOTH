//! GOLD-ADAPT-ODY-29 — disk-backed LRU cache for `web_search` results.
//!
//! Kills redundant paid search-API calls: a repeated `{provider, query,
//! count}` inside the TTL window is served from `~/.neoth/cache/search/`
//! instead of re-billing the provider. Mirrors the on-disk-cache idiom of
//! [`crate::tools::web_selector_cache`] (serde_json bodies, atomic tmp-write).
//!
//! - **Key:** `SHA-256(provider | query | count)` hex — collision-resistant +
//!   path-safe, so distinct queries never alias.
//! - **Freshness:** each entry stores its fetch `ts_unix`; [`SearchCache::get`]
//!   returns a hit only while `now - ts_unix < ttl_secs`. An expired entry is
//!   removed on read.
//! - **LRU:** the cache is bounded at `max_entries`. A read-hit rewrites the
//!   entry bytes (bumping the file mtime WITHOUT changing the stored `ts_unix`,
//!   so freshness stays anchored to fetch time) and [`SearchCache::put`] evicts
//!   the oldest-mtime files once the directory exceeds the cap.
//!
//! The policy is clock-injected (`now_secs` is a parameter, never read inside
//! `get`/`put`), so the whole TTL + eviction behaviour is deterministically
//! unit-tested against a `tempfile` dir.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tools::web_search::SearchHit;

/// Default freshness window: 24h. Search results age slowly enough that a
/// day-old cached answer is almost always fine, and the point of the cache is
/// to kill the *redundant same-day* re-queries that dominate paid-API spend.
pub const DEFAULT_TTL_SECS: u64 = 24 * 3600;

/// Default LRU cap. 1000 distinct `{provider,query,count}` keys is generous for
/// an operator workflow while bounding the cache dir to a few MB.
pub const DEFAULT_MAX_ENTRIES: usize = 1000;

/// One cached search response.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    /// Unix-seconds the underlying provider call was made — anchors TTL.
    ts_unix: u64,
    provider: String,
    query: String,
    count: usize,
    hits: Vec<SearchHit>,
}

/// Disk-backed LRU cache for `web_search` results.
pub struct SearchCache {
    dir: PathBuf,
    ttl_secs: u64,
    max_entries: usize,
}

impl SearchCache {
    /// Construct against an explicit directory + policy (used by tests).
    pub fn new(dir: PathBuf, ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            dir,
            ttl_secs,
            max_entries,
        }
    }

    /// Production cache at `~/.neoth/cache/search/` with the default policy.
    pub fn at_default() -> Self {
        let dir = crate::config::FreedomConfig::default_neoth_home()
            .join("cache")
            .join("search");
        Self::new(dir, DEFAULT_TTL_SECS, DEFAULT_MAX_ENTRIES)
    }

    /// `SHA-256(provider | query | count)` as lowercase hex.
    fn cache_key(provider: &str, query: &str, count: usize) -> String {
        let mut h = Sha256::new();
        // 0x1f (unit separator) between fields so `("a","bc")` and `("ab","c")`
        // can never collide.
        h.update(provider.as_bytes());
        h.update([0x1f]);
        h.update(query.as_bytes());
        h.update([0x1f]);
        h.update(count.to_le_bytes());
        let digest = h.finalize();
        let mut s = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Return the cached hits for `{provider, query, count}` if a fresh entry
    /// exists. A corrupt/unparseable file is treated as a miss; an expired
    /// entry is removed. On a fresh hit the entry bytes are rewritten to bump
    /// the file mtime (LRU recency) without touching the stored `ts_unix`.
    pub fn get(
        &self,
        provider: &str,
        query: &str,
        count: usize,
        now_secs: u64,
    ) -> Option<Vec<SearchHit>> {
        let key = Self::cache_key(provider, query, count);
        let path = self.entry_path(&key);
        let bytes = std::fs::read(&path).ok()?;
        let entry: CacheEntry = serde_json::from_slice(&bytes).ok()?;
        if now_secs.saturating_sub(entry.ts_unix) >= self.ttl_secs {
            // Stale — drop it so the dir doesn't accumulate dead entries.
            let _ = std::fs::remove_file(&path);
            return None;
        }
        // LRU touch: rewrite identical bytes → mtime bumps, ts_unix unchanged.
        let _ = std::fs::write(&path, &bytes);
        Some(entry.hits)
    }

    /// Store the provider response for `{provider, query, count}`, then enforce
    /// the LRU cap. Returns an `io::Error` only on a hard write failure (the
    /// caller treats caching as best-effort and ignores it).
    pub fn put(
        &self,
        provider: &str,
        query: &str,
        count: usize,
        hits: &[SearchHit],
        now_secs: u64,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let entry = CacheEntry {
            ts_unix: now_secs,
            provider: provider.to_string(),
            query: query.to_string(),
            count,
            hits: hits.to_vec(),
        };
        let body = serde_json::to_vec(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let key = Self::cache_key(provider, query, count);
        let path = self.entry_path(&key);
        // tmp-then-rename so a concurrent reader never sees a half-written file.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)?;
        // Windows `rename` fails if the destination exists → remove first.
        let _ = std::fs::remove_file(&path);
        std::fs::rename(&tmp, &path)?;
        self.enforce_cap();
        Ok(())
    }

    /// Evict oldest-mtime entries until the directory holds at most
    /// `max_entries` cache files. Best-effort: filesystem errors are ignored
    /// (a slightly-over-cap cache is harmless).
    fn enforce_cap(&self) {
        let mut entries: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for de in rd.flatten() {
            let path = de.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let mtime = de
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            entries.push((path, mtime));
        }
        if entries.len() <= self.max_entries {
            return;
        }
        // Oldest first; remove the overflow.
        entries.sort_by_key(|(_, m)| *m);
        let overflow = entries.len() - self.max_entries;
        for (path, _) in entries.into_iter().take(overflow) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Current Unix time in whole seconds (0 on a pre-epoch clock — impossible in
/// practice). Used by the production `search_cached` wrapper; tests pass an
/// explicit `now_secs` instead.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort mtime read for tests + the cap policy.
#[cfg(test)]
fn mtime_of(path: &std::path::Path) -> std::time::SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(title: &str) -> SearchHit {
        SearchHit {
            title: title.to_string(),
            url: format!("https://example.com/{title}"),
            snippet: format!("snippet for {title}"),
        }
    }

    #[test]
    fn put_then_get_within_ttl_returns_hits() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SearchCache::new(tmp.path().to_path_buf(), 100, 1000);
        let hits = vec![hit("a"), hit("b")];
        cache.put("brave", "rust async", 5, &hits, 1_000).unwrap();
        // 50s later — still inside the 100s TTL.
        let got = cache.get("brave", "rust async", 5, 1_050).unwrap();
        assert_eq!(got, hits);
    }

    #[test]
    fn get_past_ttl_is_a_miss_and_removes_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SearchCache::new(tmp.path().to_path_buf(), 100, 1000);
        cache.put("brave", "q", 3, &[hit("x")], 1_000).unwrap();
        // Exactly at TTL boundary counts as expired (>=).
        assert!(cache.get("brave", "q", 3, 1_100).is_none());
        // Expired entry was deleted on read.
        let key = SearchCache::cache_key("brave", "q", 3);
        assert!(!cache.entry_path(&key).exists());
    }

    #[test]
    fn missing_key_is_a_miss() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SearchCache::new(tmp.path().to_path_buf(), 100, 1000);
        assert!(cache.get("tavily", "never stored", 5, 1).is_none());
    }

    #[test]
    fn key_varies_by_provider_query_and_count() {
        let base = SearchCache::cache_key("brave", "q", 5);
        assert_ne!(base, SearchCache::cache_key("tavily", "q", 5));
        assert_ne!(base, SearchCache::cache_key("brave", "q2", 5));
        assert_ne!(base, SearchCache::cache_key("brave", "q", 6));
        // Deterministic + 64 hex chars (SHA-256).
        assert_eq!(base, SearchCache::cache_key("brave", "q", 5));
        assert_eq!(base.len(), 64);
        assert!(base.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn field_separator_prevents_boundary_collision() {
        // ("ab","c") and ("a","bc") must not collide despite concatenation.
        assert_ne!(
            SearchCache::cache_key("ab", "c", 1),
            SearchCache::cache_key("a", "bc", 1)
        );
    }

    #[test]
    fn enforce_cap_evicts_oldest_mtime_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SearchCache::new(tmp.path().to_path_buf(), 10_000, 3);
        // Write 5 distinct entries; bump mtimes apart so eviction order is
        // deterministic (sleep is fine in a unit test — 5 short ticks).
        for i in 0..5 {
            cache
                .put("brave", &format!("query-{i}"), 5, &[hit("h")], 1_000)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        // Cap is 3 → only 3 json files survive.
        let surviving: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|d| d.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        assert_eq!(surviving.len(), 3, "cap of 3 enforced");
        // The two OLDEST (query-0, query-1) were evicted; query-4 (newest) lives.
        let newest = cache.entry_path(&SearchCache::cache_key("brave", "query-4", 5));
        let oldest = cache.entry_path(&SearchCache::cache_key("brave", "query-0", 5));
        assert!(newest.exists(), "newest entry survives");
        assert!(!oldest.exists(), "oldest entry evicted");
    }

    #[test]
    fn read_hit_bumps_mtime_for_lru_without_extending_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SearchCache::new(tmp.path().to_path_buf(), 100, 1000);
        cache.put("brave", "q", 5, &[hit("h")], 1_000).unwrap();
        let key = SearchCache::cache_key("brave", "q", 5);
        let before = mtime_of(&cache.entry_path(&key));
        std::thread::sleep(std::time::Duration::from_millis(15));
        // A fresh read bumps the mtime (LRU recency)...
        assert!(cache.get("brave", "q", 5, 1_050).is_some());
        let after = mtime_of(&cache.entry_path(&key));
        assert!(after > before, "read-hit rewrites the entry → mtime bumped");
        // ...but the stored ts_unix is unchanged, so freshness still expires
        // relative to the ORIGINAL fetch time, not the read time.
        assert!(
            cache.get("brave", "q", 5, 1_100).is_none(),
            "TTL anchored to fetch ts_unix, not last read"
        );
    }
}
