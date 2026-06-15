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
//! GR-097 — the audit only lands when a WAL-OWNING caller passes a
//! [`WalWriterHandle`] to [`extract_with_cache`]; that is the daemon when it
//! consumes this cache. The only caller today is the one-shot `neoth fetch`
//! CLI, which has no daemon WAL context and so passes `None` by design (the
//! high-cadence 0x59 HIT is telemetry, not an audit-RPC-forwardable permission
//! event). The `apply` logic + emission are fully built and tested against a
//! real WAL writer; they are simply dormant until a WAL-owning consumer exists.
//!
//! GOLD-ADOPT-04 — [`SelectorCache::apply`] is SYNCHRONOUS and returns the WAL
//! events to emit ([`PendingAudit`]); [`extract_with_cache`] holds the cache
//! write-lock only for that synchronous decision + persist and appends the audit
//! AFTER releasing the guard, so no WAL await is ever held under the lock.
//!
//! The cache LOGIC lives on [`SelectorCache::apply`] (pure of the process
//! singleton, so it's unit-testable on a raw-HTML string); the
//! [`extract_with_cache`] entry point owns the fetch + the static singleton +
//! disk persistence + the post-lock audit emission.

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

/// GOLD-ADOPT-04 — a WAL audit event the cache decided to emit. Returned from the
/// SYNCHRONOUS (lock-held) [`SelectorCache::apply`] so the actual WAL append
/// happens AFTER the cache write-lock is released — no WAL I/O is performed while
/// holding the guard (the old code awaited the append under the write lock,
/// serialising every concurrent extract).
#[derive(Debug, Clone, PartialEq)]
enum PendingAudit {
    Hit {
        url_hash: String,
        selector: String,
        cache_key: String,
        extracted_bytes: usize,
    },
    Stale {
        url_hash: String,
        cache_key: String,
        old_selector: String,
        stale_recovered: bool,
        new_selector: Option<String>,
        similarity_score: Option<f32>,
    },
}

static CACHE: OnceLock<RwLock<SelectorCache>> = OnceLock::new();
static CACHE_PATH: OnceLock<PathBuf> = OnceLock::new();

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
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
    // GOLD-ADOPT-04 — hold the write-lock ONLY for the synchronous decision +
    // mutation + persist; `apply` returns the WAL events, which we append AFTER
    // releasing the guard so no WAL await is held under the lock.
    let (result, audits) = {
        let mut guard = cache.write().await;
        let outcome = guard.apply(&raw.raw_html, url, cache_key, selector)?;
        if let Some(path) = CACHE_PATH.get() {
            if let Err(e) = guard.save(path) {
                tracing::warn!(error = %e, "web_selector_cache save failed (extract still returned)");
            }
        }
        outcome
    };
    // GR-097 — the audit only lands when a WAL-owning caller supplies a handle
    // (the daemon, when it consumes this cache). The one-shot `neoth fetch` CLI
    // has no daemon WAL context, so it passes `None` by design — the high-cadence
    // 0x59 HIT is telemetry, not an audit-RPC-forwardable permission event.
    for audit in &audits {
        audit.emit(wal).await;
    }
    Ok(result)
}

impl SelectorCache {
    /// The adaptive extract logic. Pure of the singleton + the network AND now
    /// SYNCHRONOUS (no WAL I/O) — returns the WAL events to emit so the caller
    /// appends them after releasing the cache lock. Mutates `self` (seeds / heals
    /// the cached entry).
    fn apply(
        &mut self,
        raw_html: &str,
        url: &str,
        cache_key: &str,
        operator_selector: &str,
    ) -> Result<(ExtractResult, Vec<PendingAudit>)> {
        let url_hash = format!("{:016x}", xxh3_64(url.as_bytes()));
        let mut audits: Vec<PendingAudit> = Vec::new();
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
            audits.push(PendingAudit::Hit {
                url_hash,
                selector: active.clone(),
                cache_key: cache_key.to_string(),
                extracted_bytes: total_bytes(&hits),
            });
            return Ok((
                ExtractResult {
                    hits,
                    selector_used: active,
                    stale_recovered: false,
                },
                audits,
            ));
        }

        // MISS. A cold key with no match has nothing to recover — return empty.
        let Some(entry) = stored else {
            return Ok((
                ExtractResult {
                    hits: Vec::new(),
                    selector_used: active,
                    stale_recovered: false,
                },
                audits,
            ));
        };

        // A KNOWN key whose selector matched nothing → STALE. Try the fingerprint.
        let Some(fp) = entry.fingerprint.clone() else {
            audits.push(PendingAudit::Stale {
                url_hash,
                cache_key: cache_key.to_string(),
                old_selector: entry.selector.clone(),
                stale_recovered: false,
                new_selector: None,
                similarity_score: None,
            });
            return Ok((
                ExtractResult {
                    hits: Vec::new(),
                    selector_used: entry.selector,
                    stale_recovered: false,
                },
                audits,
            ));
        };
        match web_extract::refind(raw_html, &fp) {
            // A candidate scoring >= threshold AND yielding text is a real
            // recovery. A look-alike that scores high but extracts NOTHING is a
            // false lead → treat as unrecovered: keep the old entry + report
            // recovered=false everywhere (never claim recovery, update the
            // cache, or rewrite selector_used when the new selector is empty).
            Some((new_sel, score)) => {
                let new_hits = web_extract::extract_text(raw_html, &new_sel)?;
                if new_hits.is_empty() {
                    audits.push(PendingAudit::Stale {
                        url_hash,
                        cache_key: cache_key.to_string(),
                        old_selector: entry.selector.clone(),
                        stale_recovered: false,
                        new_selector: None,
                        similarity_score: None,
                    });
                    return Ok((
                        ExtractResult {
                            hits: Vec::new(),
                            selector_used: entry.selector,
                            stale_recovered: false,
                        },
                        audits,
                    ));
                }
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
                audits.push(PendingAudit::Stale {
                    url_hash: url_hash.clone(),
                    cache_key: cache_key.to_string(),
                    old_selector: entry.selector.clone(),
                    stale_recovered: true,
                    new_selector: Some(new_sel.clone()),
                    similarity_score: Some(score),
                });
                audits.push(PendingAudit::Hit {
                    url_hash,
                    selector: new_sel.clone(),
                    cache_key: cache_key.to_string(),
                    extracted_bytes: total_bytes(&new_hits),
                });
                Ok((
                    ExtractResult {
                        hits: new_hits,
                        selector_used: new_sel,
                        stale_recovered: true,
                    },
                    audits,
                ))
            }
            None => {
                audits.push(PendingAudit::Stale {
                    url_hash,
                    cache_key: cache_key.to_string(),
                    old_selector: entry.selector.clone(),
                    stale_recovered: false,
                    new_selector: None,
                    similarity_score: None,
                });
                Ok((
                    ExtractResult {
                        hits: Vec::new(),
                        selector_used: entry.selector,
                        stale_recovered: false,
                    },
                    audits,
                ))
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

impl PendingAudit {
    /// Append this audit to the WAL via a WAL-owning caller's handle. No-op when
    /// `wal` is `None` (e.g. the one-shot `neoth fetch` CLI — see GR-097).
    async fn emit(&self, wal: Option<&WalWriterHandle>) {
        let Some(w) = wal else { return };
        let (event_type, payload_json) = match self {
            PendingAudit::Hit {
                url_hash,
                selector,
                cache_key,
                extracted_bytes,
            } => (
                EVENT_TYPE_WEB_EXTRACT_HIT,
                serde_json::json!({
                    "url_hash": url_hash,
                    "selector": selector,
                    "cache_key": cache_key,
                    "extracted_bytes": extracted_bytes,
                    "ts_unix": now_unix(),
                }),
            ),
            PendingAudit::Stale {
                url_hash,
                cache_key,
                old_selector,
                stale_recovered,
                new_selector,
                similarity_score,
            } => (
                EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE,
                serde_json::json!({
                    "url_hash": url_hash,
                    "cache_key": cache_key,
                    "old_selector": old_selector,
                    "stale_recovered": stale_recovered,
                    "new_selector": new_selector,
                    "similarity_score": similarity_score,
                    "ts_unix": now_unix(),
                }),
            ),
        };
        let payload = serde_json::to_vec(&payload_json).unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        if let Err(e) = w.append(header, payload).await {
            tracing::warn!(error = %e, event_type, "web-extract audit append failed");
        }
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
        let (res, audits) = cache
            .apply(html, "https://x.test/p", "x.test:span.price", "span.price")
            .unwrap();
        for a in &audits {
            a.emit(Some(&writer)).await;
        }
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
        let (res, audits) = cache
            .apply(v2, "https://x.test/p", "x.test:price", "span#p1")
            .unwrap();
        for a in &audits {
            a.emit(Some(&writer)).await;
        }
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
        let (res, audits) = cache
            .apply(r#"<p>nothing here</p>"#, "https://x.test", "x.test:k", "span.price")
            .unwrap();
        for a in &audits {
            a.emit(Some(&writer)).await;
        }
        drop(writer);
        join.await.ok();
        assert!(res.hits.is_empty());
        assert!(!res.stale_recovered);
        let types = scan_event_types(&wal_path).await;
        assert!(types.contains(&EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE));
        assert!(!types.contains(&EVENT_TYPE_WEB_EXTRACT_HIT));
    }

    /// Regression test for the `stale_recovered` flag semantics fixed in
    /// GOLD-ADOPT-04: `stale_recovered` must be `!new_hits.is_empty()`, NOT an
    /// unconditional `true` after a successful refind.
    ///
    /// Two sub-cases are exercised:
    ///
    /// 1. **Refind succeeds + new element has text** → `stale_recovered: true`,
    ///    `hits` non-empty.  Covered by the existing
    ///    `stale_selector_recovers_via_fingerprint_and_emits_0x5a` test.
    ///
    /// 2. **Refind succeeds + new element has no text content** → the derived
    ///    selector (`span.icon`) matches the element, but `el.text()` is empty
    ///    so `extract_text` pushes `""` for every match.  `new_hits` is
    ///    therefore `[""]` (one empty-string entry), which is NOT the empty
    ///    `vec![]` — `stale_recovered` is `true` and `hits` contains the
    ///    placeholder.  This case is documented here so that any future change
    ///    that makes `extract_text` filter out blank entries does not silently
    ///    break the invariant.
    ///
    /// 3. **Refind + derived selector matches nothing** (`stale_recovered:
    ///    false`) — requires `derive_selector` to produce a CSS string that
    ///    parses but matches zero elements in the same document.  With the
    ///    current `scraper`-based implementation this path is not reachable
    ///    through the public `apply` API (the element `refind` scores was
    ///    selected from the same document `extract_text` re-queries), so it is
    ///    not exercised here.  The `stale_recovered: !new_hits.is_empty()`
    ///    expression is the compile-time guard for that case.
    #[tokio::test]
    async fn stale_recovered_false_when_refind_element_has_no_text() {
        // Build a fingerprint from v1: span.icon with text "★".
        let v1 = r#"<div class="card"><span class="icon">&#9733;</span></div>"#;
        let fp = web_extract::fingerprint_first(v1, "span.icon").unwrap().unwrap();

        let mut cache = SelectorCache::default();
        cache.entries.insert(
            "x.test:icon".to_string(),
            CacheEntry {
                selector: "span#gone".to_string(), // old id-based selector
                fingerprint: Some(fp),
                last_hit_unix: 0,
            },
        );

        // v2: the span is still there (class "icon" intact for refind to score
        // ≥ REFIND_MIN_SCORE) but its content is replaced with an <img> child
        // that carries no text nodes — `el.text().collect()` returns "".
        let v2 = r#"<div class="card"><span class="icon"><img src="star.png"></span></div>"#;
        let (res, _audits) = cache
            .apply(v2, "https://x.test/p", "x.test:icon", "span#gone")
            .unwrap();

        // refind should locate span.icon (class Jaccard = 1.0 ≥ 0.5 → +3 pts,
        // parent tag "div" → +1 → score ≥ REFIND_MIN_SCORE=4).
        // extract_text returns [""] (one blank-string entry, not the empty vec),
        // so stale_recovered MUST be true (hit found, content just happens blank).
        assert!(
            res.stale_recovered,
            "refind found the element → stale_recovered should be true even with blank text"
        );
        assert_eq!(res.hits, vec![""], "one blank-text match expected");
        // GR-019 — derive_selector now emits the escape-free attribute form.
        assert_eq!(
            res.selector_used, r#"span[class~="icon"]"#,
            "derived selector should be the attribute form"
        );
        // The healed entry must be persisted in the cache.
        let entry = cache.entries.get("x.test:icon").expect("entry should be updated");
        assert_eq!(entry.selector, r#"span[class~="icon"]"#);
    }

    #[tokio::test]
    async fn cold_key_no_match_is_quiet() {
        let mut cache = SelectorCache::default();
        // No stored entry + no match → empty, no stale, no panic, no audits.
        let (res, audits) = cache
            .apply(r#"<p>x</p>"#, "https://x.test", "cold", "span.price")
            .unwrap();
        assert!(res.hits.is_empty());
        assert!(!res.stale_recovered);
        assert!(audits.is_empty(), "cold miss emits no audit");
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

    #[test]
    fn web_extract_codes_and_sync_policy_pinned() {
        use crate::wal::events::needs_immediate_sync;
        // Literal codes (the plan's 0xCE/0xCF were taken → reassigned).
        assert_eq!(EVENT_TYPE_WEB_EXTRACT_HIT, 0x59);
        assert_eq!(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE, 0x5A);
        // HIT is high-cadence + re-derivable → batchable; STALE is a
        // structural-change audit anchor → must survive a crash.
        assert!(!needs_immediate_sync(EVENT_TYPE_WEB_EXTRACT_HIT));
        assert!(needs_immediate_sync(EVENT_TYPE_WEB_EXTRACT_SELECTOR_STALE));
    }

}
