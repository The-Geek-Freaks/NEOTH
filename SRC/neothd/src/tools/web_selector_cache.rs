//! GOLD-ADOPT-04 — persistent CSS-selector cache with adaptive recovery.
//!
//! Wraps [`crate::tools::web_extract`] with a per-`cache_key` memory: the
//! last-known-good selector + an [`ElementFingerprint`]. When the stored
//! selector stops matching (the site changed), the fingerprint drives
//! [`web_extract::refind`] to relocate the element and self-heal the selector —
//! Scrapling's "adaptive" feature, NEOTH-minimal + deterministic.
//!
//! WAL audit: a match emits `0x59 WEB_EXTRACT_HIT` (batchable); a stale selector
//! emits `0x5A WEB_EXTRACT_SELECTOR_STALE` (immediate-sync — a structural-change
//! anchor). The audit stores an `xxh3` URL hash + byte counts, never the URL or
//! the extracted content.
//!
//! The cache LOGIC lives on [`SelectorCache::apply`] (pure of the process
//! singleton, so it's unit-testable on a raw-HTML string + a test WAL writer);
//! the [`extract_with_cache`] entry point owns the fetch + the static singleton
//! + disk persistence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use xxhash_rust::xxh3::xxh3_64;

use crate::tools::web_extract::{self, ElementFingerprint};
use crate::wal::events::{EVENT_TYPE_WEB_EXTRACT_HIT, EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE};
use crate::wal::writer::WalWriterHandle;

/// One cached selector + the fingerprint that re-locates it if it breaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CacheEntry {
    selector: String,
    #[serde(default)]
    fingerprint: Option<ElementFingerprint>,
    last_hit_unix: i64,
}

/// Persisted `cache_key → entry` map.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SelectorCache {
    #[serde(default)]
    entries: HashMap<String, CacheEntry>,
}

/// Result of a cache-backed extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractResult {
    pub hits: Vec<String>,
    /// The selector that actually matched (may differ from the operator's input
    /// after an adaptive recovery).
    pub selector_used: String,
    /// True when the stored selector was stale + the fingerprint re-find healed it.
    pub stale_recovered: bool,
}

static CACHE: OnceLock<RwLock<SelectorCache>> = OnceLock::new();
static CACHE_PATH: OnceLock<PathBuf> = OnceLock::new();

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn total_bytes(hits: &[String]) -> usize {
    hits.iter().map(|s| s.len()).sum()
}

/// Idempotent: loads `<home>/web_selector_cache.json` into the process
/// singleton. Safe to call more than once (later calls are no-ops).
pub async fn init(home: &Path) {
    let path = home.join("web_selector_cache.json");
    let loaded = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<SelectorCache>(&s).ok())
        .unwrap_or_default();
    let _ = CACHE_PATH.set(path);
    let _ = CACHE.set(RwLock::new(loaded));
}

/// Fetch `url` (raw HTML, SSRF-guarded + no-redirect via `web_fetch::fetch_raw`)
/// and extract `selector`, healing a stale selector from the cache when needed.
/// Requires [`init`] to have run.
pub async fn extract_with_cache(
    url: &str,
    cache_key: &str,
    selector: &str,
    wal: Option<&WalWriterHandle>,
) -> Result<ExtractResult> {
    let cache = CACHE
        .get()
        .context("web_selector_cache not initialised — call init() first")?;
    let raw = crate::tools::web_fetch::fetch_raw(url).await?;
    let mut guard = cache.write().await;
    let result = guard
        .apply(&raw.raw_html, url, cache_key, selector, wal)
        .await?;
    if let Some(path) = CACHE_PATH.get() {
        if let Err(e) = guard.save(path) {
            tracing::warn!(error = %e, "web_selector_cache save failed (extract still returned)");
        }
    }
    Ok(result)
}

impl SelectorCache {
    /// The adaptive extract logic. Pure of the singleton + the network: takes the
    /// raw HTML + emits WAL via the supplied handle. Mutates `self` (seeds /
    /// heals the cached entry).
    async fn apply(
        &mut self,
        raw_html: &str,
        url: &str,
        cache_key: &str,
        operator_selector: &str,
        wal: Option<&WalWriterHandle>,
    ) -> Result<ExtractResult> {
        let url_hash = format!("{:016x}", xxh3_64(url.as_bytes()));
        let stored = self.entries.get(cache_key).cloned();
        // Prefer the cached (possibly already-healed) selector; fall back to the
        // operator's input on a cold key.
        let active = stored
            .as_ref()
            .map(|e| e.selector.clone())
            .unwrap_or_else(|| operator_selector.to_string());

        let hits = web_extract::extract_text(raw_html, &active)?;
        if !hits.is_empty() {
            // HIT — (re)seed the entry, capturing a fingerprint if we lack one.
            let fingerprint = stored
                .as_ref()
                .and_then(|e| e.fingerprint.clone())
                .or_else(|| web_extract::fingerprint_first(raw_html, &active).ok().flatten());
            self.entries.insert(
                cache_key.to_string(),
                CacheEntry {
                    selector: active.clone(),
                    fingerprint,
                    last_hit_unix: now_unix(),
                },
            );
            emit_hit(wal, &url_hash, &active, cache_key, total_bytes(&hits)).await;
            return Ok(ExtractResult {
                hits,
                selector_used: active,
                stale_recovered: false,
            });
        }

        // MISS. A cold key with no match has nothing to recover — return empty.
        let Some(entry) = stored else {
            return Ok(ExtractResult {
                hits: Vec::new(),
                selector_used: active,
                stale_recovered: false,
            });
        };

        // A KNOWN key whose selector matched nothing → STALE. Try the fingerprint.
        let Some(fp) = entry.fingerprint.clone() else {
            emit_stale(wal, &url_hash, cache_key, &entry.selector, false, None, None).await;
            return Ok(ExtractResult {
                hits: Vec::new(),
                selector_used: entry.selector,
                stale_recovered: false,
            });
        };
        match web_extract::refind(raw_html, &fp) {
            Some((new_sel, score)) => {
                let new_hits = web_extract::extract_text(raw_html, &new_sel)?;
                let new_fp = web_extract::fingerprint_first(raw_html, &new_sel)
                    .ok()
                    .flatten()
                    .or(Some(fp));
                self.entries.insert(
                    cache_key.to_string(),
                    CacheEntry {
                        selector: new_sel.clone(),
                        fingerprint: new_fp,
                        last_hit_unix: now_unix(),
                    },
                );
                emit_stale(
                    wal,
                    &url_hash,
                    cache_key,
                    &entry.selector,
                    true,
                    Some(&new_sel),
                    Some(score),
                )
                .await;
                if !new_hits.is_empty() {
                    emit_hit(wal, &url_hash, &new_sel, cache_key, total_bytes(&new_hits)).await;
                }
                Ok(ExtractResult {
                    stale_recovered: !new_hits.is_empty(),
                    hits: new_hits,
                    selector_used: new_sel,
                })
            }
            None => {
                emit_stale(wal, &url_hash, cache_key, &entry.selector, false, None, None).await;
                Ok(ExtractResult {
                    hits: Vec::new(),
                    selector_used: entry.selector,
                    stale_recovered: false,
                })
            }
        }
    }

    /// Atomic temp+rename JSON persist.
    fn save(&self, path: &Path) -> Result<()> {
        let body = serde_json::to_string_pretty(self).context("serialize selector cache")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

async fn emit_hit(
    wal: Option<&WalWriterHandle>,
    url_hash: &str,
    selector: &str,
    cache_key: &str,
    extracted_bytes: usize,
) {
    let Some(w) = wal else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "url_hash": url_hash,
        "selector": selector,
        "cache_key": cache_key,
        "extracted_bytes": extracted_bytes,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_WEB_EXTRACT_HIT, &payload).build();
    if let Err(e) = w.append(header, payload).await {
        tracing::warn!(error = %e, "WEB_EXTRACT_HIT append failed");
    }
}

#[allow(clippy::too_many_arguments)]
async fn emit_stale(
    wal: Option<&WalWriterHandle>,
    url_hash: &str,
    cache_key: &str,
    old_selector: &str,
    stale_recovered: bool,
    new_selector: Option<&str>,
    similarity_score: Option<f32>,
) {
    let Some(w) = wal else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "url_hash": url_hash,
        "cache_key": cache_key,
        "old_selector": old_selector,
        "stale_recovered": stale_recovered,
        "new_selector": new_selector,
        "similarity_score": similarity_score,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    let header =
        crate::wal::HeaderBuilder::new(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE, &payload).build();
    if let Err(e) = w.append(header, payload).await {
        tracing::warn!(error = %e, "WEB_EXTRACT_SELECTOR_STALE append failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scan_event_types(wal_path: &Path) -> Vec<u8> {
        let bytes = std::fs::read(wal_path).unwrap();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut out = Vec::new();
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
                break;
            };
            out.push(f.header.event_type);
            let t = f.header.total_len as usize;
            if t == 0 {
                break;
            }
            cur += t;
        }
        out
    }

    #[tokio::test]
    async fn hit_seeds_entry_and_emits_0x59() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();

        let mut cache = SelectorCache::default();
        let html = r#"<div class="card"><span class="price">$9.99</span></div>"#;
        let res = cache
            .apply(html, "https://x.test/p", "x.test:span.price", "span.price", Some(&writer))
            .await
            .unwrap();
        drop(writer);
        join.await.ok();

        assert_eq!(res.hits, vec!["$9.99"]);
        assert!(!res.stale_recovered);
        // Entry seeded with a fingerprint for future recovery.
        let entry = cache.entries.get("x.test:span.price").unwrap();
        assert_eq!(entry.selector, "span.price");
        assert!(entry.fingerprint.is_some());
        // 0x59 emitted, no raw URL in the WAL.
        assert!(scan_event_types(&wal_path).await.contains(&EVENT_TYPE_WEB_EXTRACT_HIT));
    }

    #[tokio::test]
    async fn stale_selector_recovers_via_fingerprint_and_emits_0x5a() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();

        // Pre-seed a cache entry whose OLD selector won't match the new HTML,
        // but whose fingerprint will relocate the element.
        let v1 = r#"<div class="card"><span class="price" id="p1">$9</span></div>"#;
        let fp = web_extract::fingerprint_first(v1, "span#p1").unwrap().unwrap();
        let mut cache = SelectorCache::default();
        cache.entries.insert(
            "x.test:price".to_string(),
            CacheEntry {
                selector: "span#p1".to_string(), // id-based, will break below
                fingerprint: Some(fp),
                last_hit_unix: 0,
            },
        );
        // v2: same element, same id+class, but the operator's stored selector
        // still works here... so to force STALE, drop the id in v2.
        let v2 = r#"<section><div class="card"><span class="price">$9</span></div></section>"#;
        let res = cache
            .apply(v2, "https://x.test/p", "x.test:price", "span#p1", Some(&writer))
            .await
            .unwrap();
        drop(writer);
        join.await.ok();

        assert!(res.stale_recovered, "fingerprint should heal the stale selector");
        assert_eq!(res.hits, vec!["$9"]);
        let types = scan_event_types(&wal_path).await;
        assert!(types.contains(&EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE), "0x5A expected");
        assert!(types.contains(&EVENT_TYPE_WEB_EXTRACT_HIT), "0x59 after recovery");
    }

    #[tokio::test]
    async fn stale_unrecoverable_emits_0x5a_only() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let mut cache = SelectorCache::default();
        cache.entries.insert(
            "x.test:k".to_string(),
            CacheEntry {
                selector: "span.price".to_string(),
                fingerprint: web_extract::fingerprint_first(
                    r#"<span class="price">$9</span>"#,
                    "span.price",
                )
                .unwrap(),
                last_hit_unix: 0,
            },
        );
        // No span anywhere → refind fails.
        let res = cache
            .apply(r#"<p>nothing here</p>"#, "https://x.test", "x.test:k", "span.price", Some(&writer))
            .await
            .unwrap();
        drop(writer);
        join.await.ok();
        assert!(res.hits.is_empty());
        assert!(!res.stale_recovered);
        let types = scan_event_types(&wal_path).await;
        assert!(types.contains(&EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE));
        assert!(!types.contains(&EVENT_TYPE_WEB_EXTRACT_HIT));
    }

    #[tokio::test]
    async fn cold_key_no_match_is_quiet() {
        let mut cache = SelectorCache::default();
        // No stored entry + no match → empty, no stale, no panic, no WAL needed.
        let res = cache
            .apply(r#"<p>x</p>"#, "https://x.test", "cold", "span.price", None)
            .await
            .unwrap();
        assert!(res.hits.is_empty());
        assert!(!res.stale_recovered);
        assert!(cache.entries.is_empty(), "cold miss seeds nothing");
    }

    #[test]
    fn cache_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web_selector_cache.json");
        let mut cache = SelectorCache::default();
        cache.entries.insert(
            "k".to_string(),
            CacheEntry {
                selector: "span.price".to_string(),
                fingerprint: web_extract::fingerprint_first(
                    r#"<span class="price">$9</span>"#,
                    "span.price",
                )
                .unwrap(),
                last_hit_unix: 123,
            },
        );
        cache.save(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let back: SelectorCache = serde_json::from_str(&body).unwrap();
        assert_eq!(back.entries.get("k").unwrap().selector, "span.price");
        assert_eq!(back.entries.get("k").unwrap().last_hit_unix, 123);
    }
}
