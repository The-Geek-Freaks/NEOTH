//! GOLD-ADAPT-ODY-30 — lightweight on-disk analytics for `web_search`.
//!
//! Tracks normalized-query frequency + `success` / `fail` / `cache_hit`
//! counters in `~/.neoth/logs/search_analytics.json`, so an operator can see
//! which searches dominate spend and how often the ODY-29 disk-LRU cache is
//! actually saving a paid call. Surfaced via `neoth search --stats`.
//!
//! Recording is best-effort (a failed load/save never breaks a search) and
//! goes through [`SearchAnalytics::record_to`], a load→record→save round-trip
//! keyed off the same `~/.neoth` home as the cache. Pure helpers
//! ([`SearchAnalytics::normalize`], [`record`](SearchAnalytics::record),
//! [`top_patterns`](SearchAnalytics::top_patterns)) are unit-tested without
//! touching the filesystem.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Outcome of a single `web_search` invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Live provider call returned results.
    Success,
    /// Live provider call errored (or the query was rejected).
    Fail,
    /// Served from the ODY-29 disk cache — no provider call billed.
    CacheHit,
}

/// Persisted search-usage counters. `BTreeMap` keeps the JSON key order stable
/// across saves (deterministic file, clean diffs).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchAnalytics {
    /// Normalized query → number of times it was searched (any outcome).
    #[serde(default)]
    pub queries: BTreeMap<String, u64>,
    #[serde(default)]
    pub success: u64,
    #[serde(default)]
    pub fail: u64,
    #[serde(default)]
    pub cache_hit: u64,
}

impl SearchAnalytics {
    /// Canonical form for frequency counting: trim, collapse internal
    /// whitespace to single spaces, lowercase. `"  Rust   Async "` and
    /// `"rust async"` count as the same pattern.
    pub fn normalize(query: &str) -> String {
        query
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Fold one invocation into the counters. An empty/whitespace-only query
    /// does not pollute the pattern map but still moves the outcome counter.
    pub fn record(&mut self, query: &str, outcome: Outcome) {
        let norm = Self::normalize(query);
        if !norm.is_empty() {
            *self.queries.entry(norm).or_insert(0) += 1;
        }
        match outcome {
            Outcome::Success => self.success = self.success.saturating_add(1),
            Outcome::Fail => self.fail = self.fail.saturating_add(1),
            Outcome::CacheHit => self.cache_hit = self.cache_hit.saturating_add(1),
        }
    }

    /// Total invocations recorded (`success + fail + cache_hit`).
    pub fn total(&self) -> u64 {
        self.success
            .saturating_add(self.fail)
            .saturating_add(self.cache_hit)
    }

    /// The `n` most-searched patterns, count-desc then query-asc (stable).
    pub fn top_patterns(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.queries.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Production analytics path: `~/.neoth/logs/search_analytics.json`.
    pub fn default_path() -> PathBuf {
        crate::config::FreedomConfig::default_neoth_home()
            .join("logs")
            .join("search_analytics.json")
    }

    /// Load from disk; a missing or corrupt file yields an empty default.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Persist (pretty JSON) via tmp-then-rename so a concurrent reader never
    /// sees a half-written file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)?;
        let _ = std::fs::remove_file(path);
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Best-effort load→record→save against `path`. Any I/O error is swallowed
    /// (analytics must never break a search).
    pub fn record_to(path: &Path, query: &str, outcome: Outcome) {
        let mut a = Self::load(path);
        a.record(query, outcome);
        let _ = a.save(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_case_and_whitespace() {
        assert_eq!(SearchAnalytics::normalize("  Rust   Async "), "rust async");
        assert_eq!(SearchAnalytics::normalize("RUST"), "rust");
        assert_eq!(SearchAnalytics::normalize("   "), "");
    }

    #[test]
    fn record_increments_query_and_outcome_counters() {
        let mut a = SearchAnalytics::default();
        a.record("Rust async", Outcome::Success);
        a.record("rust   async", Outcome::CacheHit); // same normalized key
        a.record("tokio", Outcome::Fail);
        assert_eq!(a.queries.get("rust async"), Some(&2));
        assert_eq!(a.queries.get("tokio"), Some(&1));
        assert_eq!(a.success, 1);
        assert_eq!(a.cache_hit, 1);
        assert_eq!(a.fail, 1);
        assert_eq!(a.total(), 3);
    }

    #[test]
    fn empty_query_moves_counter_but_not_pattern_map() {
        let mut a = SearchAnalytics::default();
        a.record("   ", Outcome::Fail);
        assert!(a.queries.is_empty());
        assert_eq!(a.fail, 1);
    }

    #[test]
    fn top_patterns_orders_by_count_then_query() {
        let mut a = SearchAnalytics::default();
        for _ in 0..3 {
            a.record("alpha", Outcome::Success);
        }
        a.record("beta", Outcome::Success);
        a.record("gamma", Outcome::Success);
        let top = a.top_patterns(2);
        assert_eq!(top[0], ("alpha".to_string(), 3));
        // beta + gamma tie at 1 → query-asc breaks it → beta first.
        assert_eq!(top[1], ("beta".to_string(), 1));
        assert_eq!(a.top_patterns(10).len(), 3);
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("search_analytics.json");
        let mut a = SearchAnalytics::default();
        a.record("rust", Outcome::Success);
        a.record("rust", Outcome::CacheHit);
        a.save(&path).unwrap();
        let back = SearchAnalytics::load(&path);
        assert_eq!(back, a);
        assert_eq!(back.queries.get("rust"), Some(&2));
    }

    #[test]
    fn record_to_persists_incrementally() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("logs").join("a.json");
        SearchAnalytics::record_to(&path, "rust", Outcome::Success);
        SearchAnalytics::record_to(&path, "rust", Outcome::Fail);
        let a = SearchAnalytics::load(&path);
        assert_eq!(a.queries.get("rust"), Some(&2));
        assert_eq!(a.success, 1);
        assert_eq!(a.fail, 1);
    }

    #[test]
    fn load_missing_file_is_empty_default() {
        let tmp = tempfile::tempdir().unwrap();
        let a = SearchAnalytics::load(&tmp.path().join("nope.json"));
        assert_eq!(a, SearchAnalytics::default());
        assert_eq!(a.total(), 0);
    }
}
