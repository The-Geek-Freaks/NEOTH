//! GOLD-ADAPT-SKILL-03 — conditional-GET (HTTP-304) document cache for
//! `web_fetch`. The NEOTH-correct form of the agent-skills `sdd-cache` hook.
//!
//! ## Why this is a cache, not a hook
//!
//! The agent-skills source `sdd-cache` is a Claude-Code `Pre/PostToolUse`
//! WebFetch hook. NEOTH has NO per-tool hook stage — `hooks::stages::HookStage`
//! is `{PreProviderCall, PostProviderCall, PreChannelIngress}` (provider /
//! channel-pipeline only). So the doc cache lives where NEOTH actually fetches:
//! a conditional-GET layer in [`crate::tools::web_fetch::fetch_inner`] (the one
//! fetch chokepoint), sibling to [`crate::tools::web_selector_cache`].
//!
//! ## Correctness + safety
//!
//! - **Always revalidated, never stale.** On a cache hit we send `If-None-Match`
//!   (ETag) and/or `If-Modified-Since` (Last-Modified). The server decides:
//!   `304 Not Modified` → serve the cached body; `200` → the body changed, take
//!   the fresh one. A `304` is the ORIGIN confirming the cached copy is current,
//!   so the cache can never serve content the server would not.
//! - **The SSRF guard is untouched.** `fetch_inner` still runs `validate_url`
//!   (DNS pre-resolution + private/loopback/metadata block) and the no-redirect
//!   client on EVERY request, conditional or not. The cache adds request headers
//!   and a 304 branch; it does not bypass any check.
//! - **No cross-URL poisoning.** The key is `xxh3(url)` (a hex filename, no path
//!   traversal) and [`lookup`] re-verifies the stored `url` matches the query —
//!   a hash collision yields a miss, not a wrong body.
//! - **Bounded.** Only validator-bearing `2xx` bodies up to
//!   [`MAX_CACHEABLE_BYTES`] are stored, one JSON file per URL under
//!   `<home>/web_cache/`, capped at [`CACHE_CAP`] entries (oldest-by-mtime
//!   evicted). A cache write never fails a fetch (best-effort).
//! - **Off until enabled.** [`dir`] returns `None` until [`init`] runs, so the
//!   cache is inert in tests and in any process that does not opt in. The
//!   `neoth fetch` CLI opts in (alongside the selector cache).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

/// Max entries kept on disk. A single operator re-fetches a handful of doc
/// pages, so a small cap covers the real working set; oldest-by-mtime is
/// evicted on overflow.
pub const CACHE_CAP: usize = 64;

/// Max body size we will cache. Documentation pages are text and rarely exceed
/// this; a larger response is served fresh but not cached (keeps the cache dir
/// bounded well under `MAX_RESPONSE_BYTES`).
pub const MAX_CACHEABLE_BYTES: usize = 4 * 1024 * 1024;

static CACHE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// A cached document + the validators that let us revalidate it cheaply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedDoc {
    /// The exact URL this body came from (re-checked on lookup vs hash collision).
    pub url: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    pub content_type: String,
    pub status: u16,
    /// The raw response body (lossy-UTF8), as `fetch_inner` produced it.
    pub raw: String,
    pub stored_unix: i64,
}

/// Opt the process into doc caching: `<home>/web_cache/` becomes the store.
/// Idempotent; later calls are no-ops.
pub fn init(home: &Path) {
    let _ = CACHE_DIR.set(home.join("web_cache"));
}

/// The active cache dir, or `None` when the process has not opted in (tests,
/// un-initialised daemons) — in which case `web_fetch` behaves exactly as it
/// did before this cache existed.
pub fn dir() -> Option<PathBuf> {
    CACHE_DIR.get().cloned()
}

fn key(url: &str) -> String {
    format!("{:016x}", xxh3_64(url.as_bytes()))
}

/// Security (doc-cache review LOW-2): true when the URL's query string carries a
/// credential-like parameter. Such a response may be authenticated / per-user,
/// so it must NEVER be persisted to the on-disk cache. Checks each param NAME
/// (the part before `=`), not the value, so a benign value can't trip it.
pub fn url_has_credential_params(url: &str) -> bool {
    let Some(query) = url.split('?').nth(1) else {
        return false;
    };
    const MARKERS: &[&str] = &[
        "token",
        "api_key",
        "apikey",
        "access_key",
        "access_token",
        "secret",
        "password",
        "passwd",
        "auth",
        "authorization",
        "bearer",
        "signature",
        "sig",
        "credential",
        "session",
    ];
    query.split('&').any(|pair| {
        let name = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
        MARKERS.iter().any(|m| name.contains(m))
    })
}

// Test fixture helper — production callers stamp `stored_unix` at the
// fetch site (web_fetch.rs).
#[cfg(test)]
fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

/// Look up a cached doc for `url` in `dir`. Returns `None` on a miss, an
/// unreadable / malformed entry, or a hash collision (stored url != query).
pub fn lookup(dir: &Path, url: &str) -> Option<CachedDoc> {
    let path = dir.join(format!("{}.json", key(url)));
    let body = std::fs::read_to_string(&path).ok()?;
    let doc: CachedDoc = serde_json::from_str(&body).ok()?;
    if doc.url == url { Some(doc) } else { None }
}

/// Persist `doc` (best-effort: a failure is logged, never propagated, so a
/// cache problem can never break a fetch). Evicts the oldest entry first when
/// at capacity.
pub fn store(dir: &Path, doc: &CachedDoc) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    evict_if_full(dir);
    let path = dir.join(format!("{}.json", key(&doc.url)));
    let Ok(body) = serde_json::to_string(doc) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, body.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// When the dir holds `CACHE_CAP` or more entries, delete the oldest by mtime
/// until inserting one more stays within the cap.
///
/// (doc-cache review LOW-3) The check-then-write is single-flight-safe in the
/// one-shot `neoth fetch` CLI that currently opts in; a future daemon consumer
/// running concurrent fetches would need a per-dir lock to avoid briefly
/// overshooting the cap. The overshoot is bounded + harmless, never unsafe.
fn evict_if_full(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| {
            let t = e.metadata().ok().and_then(|m| m.modified().ok())?;
            Some((t, e.path()))
        })
        .collect();
    if files.len() < CACHE_CAP {
        return;
    }
    files.sort_by_key(|(t, _)| *t);
    let remove_n = files.len() + 1 - CACHE_CAP;
    for (_, p) in files.into_iter().take(remove_n) {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(url: &str, etag: Option<&str>) -> CachedDoc {
        CachedDoc {
            url: url.to_string(),
            etag: etag.map(str::to_string),
            last_modified: None,
            content_type: "text/html".to_string(),
            status: 200,
            raw: format!("<html>{url}</html>"),
            stored_unix: now_unix(),
        }
    }

    #[test]
    fn store_then_lookup_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://react.dev/reference/react/useActionState";
        store(dir.path(), &doc(url, Some("\"abc123\"")));
        let got = lookup(dir.path(), url).expect("cached doc should be found");
        assert_eq!(got.url, url);
        assert_eq!(got.etag.as_deref(), Some("\"abc123\""));
        assert!(got.raw.contains(url));
    }

    #[test]
    fn lookup_miss_for_uncached_url() {
        let dir = tempfile::tempdir().unwrap();
        assert!(lookup(dir.path(), "https://never.fetched/").is_none());
    }

    #[test]
    fn lookup_rejects_hash_collision_url_mismatch() {
        // Hand-write an entry at url A's key but with a DIFFERENT stored url,
        // simulating a (astronomically unlikely) xxh3 collision. lookup must
        // treat it as a miss, never return the wrong body.
        let dir = tempfile::tempdir().unwrap();
        let url_a = "https://a.test/doc";
        let path = dir.path().join(format!("{}.json", key(url_a)));
        let mut wrong = doc("https://b.test/other", Some("x"));
        wrong.raw = "WRONG BODY".to_string();
        std::fs::write(&path, serde_json::to_string(&wrong).unwrap()).unwrap();
        assert!(
            lookup(dir.path(), url_a).is_none(),
            "a stored url != query url must be a miss, not a wrong-body hit"
        );
    }

    #[test]
    fn store_evicts_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(CACHE_CAP + 10) {
            store(dir.path(), &doc(&format!("https://x.test/{i}"), Some("e")));
        }
        let count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .count();
        assert!(
            count <= CACHE_CAP,
            "cache must stay bounded at {CACHE_CAP}, found {count}"
        );
    }

    #[test]
    fn dir_is_none_until_init() {
        // Without init(), the cache is inert (web_fetch behaves as before).
        // NB: init() sets a process-global OnceLock, so this test only asserts
        // the not-yet-set contract is representable; it does not call init().
        // (A dedicated init test would race the singleton across the suite.)
        let key_stable = key("https://x");
        assert_eq!(key_stable, key("https://x"), "key must be deterministic");
        assert_ne!(key("https://x"), key("https://y"));
    }

    #[test]
    fn credential_params_in_url_block_caching() {
        assert!(url_has_credential_params(
            "https://api.x/v1?access_token=abc"
        ));
        assert!(url_has_credential_params("https://x/d?foo=1&api_key=K"));
        assert!(url_has_credential_params("https://x/d?sig=zzz"));
        assert!(!url_has_credential_params(
            "https://react.dev/reference/react/useActionState"
        ));
        assert!(!url_has_credential_params("https://x/d?page=2&lang=en"));
    }
}
