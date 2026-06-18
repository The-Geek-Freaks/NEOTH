//! GOLD-WIRE-07b — daemon-side HNSW snapshot auto-freshness.
//!
//! WIRE-07 made `neoth recall` cold-load the on-disk HNSW snapshot
//! (`<neoth_home>/embeddings.hnsw`) when `memory.vector_index.backend = hnsw`
//! and the corpus is past [`crate::memory::embeddings::hnsw_beneficial_for_corpus`].
//! But that snapshot only refreshed on the manual `neoth memory --rebuild-index`,
//! so a growing corpus left HNSW recall silently missing recent vectors (the
//! `neoth doctor` "vector index snapshot" check warns about exactly this).
//!
//! This module closes that gap WITHOUT an in-memory daemon warm index. The
//! reason an in-memory warm index would be WRONG here: `idx_embedding` is
//! written by BOTH the daemon (channel media attachments, `serve_pipeline.rs`)
//! AND the **separate `neoth ingest` CLI process** (`cli/ingest.rs`, the bulk
//! writer). A daemon that only `add`ed its own upserts to an in-memory index
//! would miss every CLI-ingested vector — and saving that incomplete index
//! would *clobber* a good `neoth memory --rebuild-index` snapshot. So instead
//! the daemon periodically REBUILDS the snapshot FROM SQLite (the shared source
//! of truth across both processes) when it has gone stale. The result is a
//! cross-process-correct, always-reasonably-fresh snapshot for the CLI cold-load.
//!
//! The pass is gated (backend=hnsw + corpus past the brute-force ceiling — below
//! it recall uses brute-force and the snapshot is moot), idempotent (a fresh
//! snapshot is a no-op), best-effort (any error is logged + swallowed — a failed
//! refresh must never crash the daemon), and crash-safe (the underlying
//! [`crate::memory::embeddings::EmbeddingIndex::save`] is a tmp+atomic-rename, so
//! a concurrent CLI cold-load and a mid-rebuild abort both see a consistent file).
//! The deferred extras (an in-memory warm index + daemon-IPC hot-serve to skip
//! the CLI cold-load entirely, per-kind sharding, tunable `M`/`ef`) are tracked
//! separately — this slice delivers the freshness, which is the actual gap.

use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

/// Decide whether the daemon should rebuild the HNSW snapshot right now. PURE +
/// testable — the actual I/O lives in [`refresh_snapshot_once`].
///
/// Rebuild iff:
/// - the configured backend is HNSW (else the snapshot is never read), AND
/// - the corpus is large enough that HNSW beats brute-force (else recall uses
///   the brute-force scan and the snapshot is moot), AND
/// - the snapshot is absent (but vectors exist to index) OR stale (the newest
///   embedding is newer than the snapshot's mtime).
pub(crate) fn should_refresh_snapshot(
    backend_is_hnsw: bool,
    corpus_count: usize,
    snapshot_mtime_unix: Option<i64>,
    newest_embedding_unix: Option<i64>,
) -> bool {
    if !backend_is_hnsw {
        return false;
    }
    if !crate::memory::embeddings::hnsw_beneficial_for_corpus(corpus_count) {
        return false;
    }
    match (snapshot_mtime_unix, newest_embedding_unix) {
        // No snapshot yet but vectors exist → build the first one.
        (None, Some(_)) => true,
        // Snapshot exists → rebuild only if the DB has newer vectors.
        (Some(mtime), Some(latest)) => latest > mtime,
        // No vectors (or unreadable max) → nothing to index.
        _ => false,
    }
}

/// Snapshot file mtime as unix seconds (best-effort; `None` if absent/unreadable).
fn snapshot_mtime_unix(snap: &Path) -> Option<i64> {
    std::fs::metadata(snap)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// Newest `idx_embedding.created_at` (unix seconds), or `None` when the table is
/// empty / unreadable. Mirrors the `neoth doctor` staleness probe.
fn newest_embedding_unix(conn: &Connection) -> Option<i64> {
    conn.query_row("SELECT MAX(created_at) FROM idx_embedding", [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
}

/// Run one daemon snapshot-freshness pass against the views.db + snapshot under
/// `neoth_home`. `backend_is_hnsw` is read from the live config by the caller so
/// this stays a pure-ish function (no freedom.yaml re-read).
///
/// Synchronous (rusqlite + a full index rebuild are blocking) — the daemon
/// caller wraps it in `spawn_blocking`. Returns `Ok(Some(corpus_count))` when a
/// rebuild was performed, `Ok(None)` when the pass was a gated/idempotent no-op.
/// An `Err` is surfaced to the caller, which logs it and continues (best-effort).
pub(crate) fn refresh_snapshot_once(
    neoth_home: &Path,
    backend_is_hnsw: bool,
) -> Result<Option<usize>> {
    if !backend_is_hnsw {
        return Ok(None);
    }
    let db = neoth_home.join("views.db");
    if !db.exists() {
        return Ok(None);
    }
    let conn = crate::memory::store::open(&db)?;
    let corpus = crate::memory::embeddings::count(&conn)? as usize;
    let snap = crate::memory::embeddings::hnsw_snapshot_path(neoth_home);
    if !should_refresh_snapshot(
        backend_is_hnsw,
        corpus,
        snapshot_mtime_unix(&snap),
        newest_embedding_unix(&conn),
    ) {
        return Ok(None);
    }
    let n = crate::memory::embeddings::rebuild_index(&conn, &snap)?;
    tracing::info!(
        vectors = n,
        path = %snap.display(),
        "GOLD-WIRE-07b: daemon rebuilt the stale HNSW snapshot from SQLite",
    );
    Ok(Some(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    // BRUTE_FORCE_CEILING is ~50k; pick values clearly on each side of it.
    const ABOVE: usize = 1_000_000;
    const BELOW: usize = 10;

    #[test]
    fn no_refresh_when_backend_is_not_hnsw() {
        // Even a stale, large corpus must not trigger a rebuild on brute-force.
        assert!(!should_refresh_snapshot(false, ABOVE, Some(1), Some(999)));
    }

    #[test]
    fn no_refresh_below_brute_force_ceiling() {
        // Below the ceiling recall uses brute-force; the snapshot is moot even
        // if it would otherwise look stale.
        assert!(!should_refresh_snapshot(true, BELOW, None, Some(999)));
        assert!(!should_refresh_snapshot(true, BELOW, Some(1), Some(999)));
    }

    #[test]
    fn refresh_when_hnsw_large_corpus_and_no_snapshot_but_vectors_exist() {
        assert!(should_refresh_snapshot(true, ABOVE, None, Some(123)));
    }

    #[test]
    fn refresh_when_snapshot_is_stale() {
        // Newest embedding (200) is newer than the snapshot mtime (100) → stale.
        assert!(should_refresh_snapshot(true, ABOVE, Some(100), Some(200)));
    }

    #[test]
    fn no_refresh_when_snapshot_is_fresh() {
        // Snapshot mtime (200) >= newest embedding (200 / 150) → fresh.
        assert!(!should_refresh_snapshot(true, ABOVE, Some(200), Some(200)));
        assert!(!should_refresh_snapshot(true, ABOVE, Some(200), Some(150)));
    }

    #[test]
    fn no_refresh_when_no_vectors() {
        // No MAX(created_at) → nothing to index, regardless of snapshot state.
        assert!(!should_refresh_snapshot(true, ABOVE, None, None));
        assert!(!should_refresh_snapshot(true, ABOVE, Some(100), None));
    }

    #[test]
    fn refresh_once_is_noop_when_backend_not_hnsw() {
        // backend_is_hnsw=false short-circuits before any DB access — a
        // non-existent home is fine.
        let dir = tempfile::tempdir().unwrap();
        let out = refresh_snapshot_once(dir.path(), false).expect("noop is Ok");
        assert_eq!(out, None);
    }

    #[test]
    fn refresh_once_is_noop_when_views_db_absent() {
        // backend=hnsw but no views.db yet (fresh install) → Ok(None), no error.
        let dir = tempfile::tempdir().unwrap();
        let out = refresh_snapshot_once(dir.path(), true).expect("absent db is Ok(None)");
        assert_eq!(out, None);
    }

    #[test]
    fn refresh_once_is_noop_for_small_corpus() {
        // A real (empty/tiny) views.db below the brute-force ceiling → the
        // ceiling gate fires, no rebuild, no snapshot written.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let _conn = crate::memory::store::open(&db).expect("open views.db");
        let out = refresh_snapshot_once(dir.path(), true).expect("small corpus is Ok(None)");
        assert_eq!(out, None, "below-ceiling corpus must not rebuild");
        assert!(
            !crate::memory::embeddings::hnsw_snapshot_path(dir.path()).exists(),
            "no snapshot should be written for a below-ceiling corpus"
        );
    }
}
