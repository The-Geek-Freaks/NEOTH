//! Sources-table GC — Phase 33c BS-3.
//!
//! Operators index documents via `neoth ctx --index <file>` and arbitrary
//! ad-hoc text via `--index-stdin`. The `sources` row tracking each
//! document grows unbounded if every preview-paste sticks around forever.
//!
//! This module sweeps rows older than a TTL — but only when their
//! `source_category` is in the [`TRANSIENT_CATEGORIES`] set. Operator-
//! tagged sources (`source_category = "operator"` or `"onboarding"`) are
//! kept forever, just like ground-truth rows. Default TTL: 90 days.
//!
//! ## What the sweeper does
//!
//! For every `sources` row matching `category ∈ TRANSIENT_CATEGORIES AND
//! indexed_ts < now - ttl`:
//!   1. Delete linked rows from `chunks` and `chunks_trigram` (the FTS5
//!      virtual tables don't cascade — operator's chunks would orphan
//!      without this).
//!   2. Delete the `sources` row.
//!
//! Logical-document sources and retained logical references are protected:
//! automatic GC does not authorize an explicit logical lifecycle mutation.
//! Eligible sources use the shared vocabulary subtraction before FTS/source
//! deletion, so all derived removals commit or roll back together.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use super::ctx;

/// Default retention for transient sources. 90 days — same boundary as
/// the warm→cold memory tier promotion, so operator mental model stays
/// "stuff older than 90d is either retained explicitly or gone".
pub const DEFAULT_TTL_NS: i64 = 90 * 86_400 * 1_000_000_000;

/// Categories considered transient. Anything not in this list is kept
/// forever regardless of age — the operator marked it as authoritative
/// when indexing.
pub const TRANSIENT_CATEGORIES: &[&str] = &["transient", "session", "scratch"];

/// GOLD-ADOPT-26 — category PREFIXES treated as transient (TTL-bounded) in
/// addition to [`TRANSIENT_CATEGORIES`]. RSS feed entries are indexed under
/// `rss:<label>` (a per-feed dynamic category), so they can't be listed
/// exhaustively; without this they'd be kept FOREVER and an active feed would
/// grow the ctx store unbounded (`max_entries` only caps per-tick). With it,
/// feed entries age out at the same 90-day boundary as other transient sources.
pub const TRANSIENT_PREFIXES: &[&str] = &["rss:"];

/// Keep physical markers, current owners and historical event references.
/// Retention is not permission to delete an explicitly managed document.
const UNOWNED_SOURCE_PREDICATE: &str = "sources.logical_id IS NULL \
     AND sources.id NOT IN (SELECT current_source_id FROM logical_documents) \
     AND sources.id NOT IN (SELECT source_id_at_result FROM logical_document_events)";

/// Result of one sweep pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub sources_dropped: usize,
    pub chunks_dropped: usize,
    pub chunks_trigram_dropped: usize,
}

/// Run a single GC pass. Caller supplies `now_ns` so tests can simulate
/// the clock without sleeping. Transactional — partial failure rolls back.
pub fn run_pass(conn: &mut Connection, now_ns: i64, ttl_ns: i64) -> Result<GcReport> {
    if ttl_ns <= 0 {
        anyhow::bail!("ttl_ns must be positive, got {ttl_ns}");
    }
    let cutoff = now_ns.saturating_sub(ttl_ns);

    let placeholders = TRANSIENT_CATEGORIES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");

    let tx = conn.transaction().context("begin gc tx")?;

    // Materialise the ids first so we can cascade into the FTS5 tables
    // before the `sources` row vanishes.
    // Transient = an exact category in TRANSIENT_CATEGORIES OR a category with a
    // TRANSIENT_PREFIXES prefix (e.g. `rss:hn`). Both age out at the cutoff.
    let like_clause = TRANSIENT_PREFIXES
        .iter()
        .map(|p| format!(" OR source_category LIKE '{p}%'"))
        .collect::<String>();
    let select_sql = format!(
        "SELECT id FROM sources \
         WHERE (source_category IN ({placeholders}){like_clause}) AND indexed_ts < ? \
         AND {UNOWNED_SOURCE_PREDICATE} ORDER BY id",
    );
    let mut stmt = tx.prepare(&select_sql)?;
    // Bind categories first, then the cutoff.
    let mut bindings: Vec<rusqlite::types::Value> = TRANSIENT_CATEGORIES
        .iter()
        .map(|c| rusqlite::types::Value::Text((*c).to_string()))
        .collect();
    bindings.push(rusqlite::types::Value::Integer(cutoff));
    let mut rows = stmt.query(rusqlite::params_from_iter(bindings.iter()))?;

    let mut victim_ids: Vec<i64> = Vec::new();
    while let Some(row) = rows.next()? {
        victim_ids.push(row.get(0)?);
    }
    drop(rows);
    drop(stmt);

    let mut chunks_dropped = 0usize;
    let mut chunks_trigram_dropped = 0usize;
    for id in &victim_ids {
        ctx::remove_source_vocabulary(&tx, *id)
            .with_context(|| format!("remove vocabulary for source {id}"))?;
        chunks_dropped += tx
            .execute("DELETE FROM chunks WHERE source_id = ?1", params![id])
            .with_context(|| format!("delete chunks for source {id}"))?;
        chunks_trigram_dropped += tx
            .execute(
                "DELETE FROM chunks_trigram WHERE source_id = ?1",
                params![id],
            )
            .with_context(|| format!("delete trigram chunks for source {id}"))?;
    }
    let mut sources_dropped = 0;
    for id in &victim_ids {
        let deleted = tx
            .execute("DELETE FROM sources WHERE id = ?1", [id])
            .with_context(|| format!("delete source {id}"))?;
        anyhow::ensure!(deleted == 1, "source {id} deletion was not applied");
        sources_dropped += deleted;
    }

    tx.commit().context("commit gc tx")?;
    Ok(GcReport {
        sources_dropped,
        chunks_dropped,
        chunks_trigram_dropped,
    })
}

/// GOLD-ADAPT-MEM-13 — default soft cap on the ctx `sources` table. The TTL
/// pass ([`run_pass`]) only ages out *transient* rows; a busy operator can
/// still accrete an unbounded archive of non-transient indexed content. This
/// bounds automatic retention of unowned sources. Protected logical sources
/// may keep the total above this soft cap and require explicit lifecycle work.
pub const DEFAULT_MAX_SOURCES: usize = 50_000;

/// MEM-13 — enforce a total-size cap on the ctx `sources` table: when the row
/// count exceeds `max_sources`, delete the **oldest** (`indexed_ts ASC`)
/// overflow rows that have no logical ownership or event reference. Both FTS
/// tables and vocabulary are removed in the same transaction as the source.
/// Returns the actual number dropped. Protected documents may keep the total
/// above the requested cap; that outcome is logged, never reported as erased.
/// Operator episodes and ground truth live in separate tables and are untouched.
pub fn enforce_size_cap(conn: &mut Connection, max_sources: usize) -> Result<usize> {
    let max_sources = i64::try_from(max_sources).unwrap_or(i64::MAX);
    let tx = conn.transaction().context("begin size-cap tx")?;
    let total: i64 = tx
        .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
        .context("count sources for size cap")?;
    if total <= max_sources {
        return Ok(0);
    }
    let overflow = total - max_sources;

    let victim_ids: Vec<i64> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT id FROM sources WHERE {UNOWNED_SOURCE_PREDICATE} \
             ORDER BY indexed_ts ASC, id ASC LIMIT ?1"
        ))?;
        let rows = stmt.query_map(params![overflow], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("collect size-cap source ids")?
    };
    for id in &victim_ids {
        ctx::remove_source_vocabulary(&tx, *id)
            .with_context(|| format!("remove vocabulary for source {id}"))?;
        tx.execute("DELETE FROM chunks WHERE source_id = ?1", params![id])
            .with_context(|| format!("delete chunks for source {id}"))?;
        tx.execute(
            "DELETE FROM chunks_trigram WHERE source_id = ?1",
            params![id],
        )
        .with_context(|| format!("delete trigram chunks for source {id}"))?;
    }
    let mut dropped = 0;
    for id in &victim_ids {
        let deleted = tx
            .execute("DELETE FROM sources WHERE id = ?1", [id])
            .with_context(|| format!("delete source {id}"))?;
        anyhow::ensure!(deleted == 1, "source {id} deletion was not applied");
        dropped += deleted;
    }
    let remaining: i64 = tx.query_row("SELECT count(*) FROM sources", [], |row| row.get(0))?;
    tx.commit().context("commit size-cap tx")?;
    if remaining > max_sources {
        tracing::warn!(
            remaining_sources = remaining,
            requested_cap = max_sources,
            "automatic source cap remains above target; logical references are protected"
        );
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn fresh_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        (dir, conn)
    }

    fn insert_source(conn: &Connection, label: &str, category: &str, indexed_ts: i64) -> i64 {
        conn.execute(
            "INSERT INTO sources \
             (label, content_hash, file_path, content_type, source_category, chunk_count, indexed_ts) \
             VALUES (?1, 'h', NULL, 'text/plain', ?2, 0, ?3)",
            params![label, category, indexed_ts],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn ttl_must_be_positive() {
        let (_dir, mut conn) = fresh_db();
        assert!(run_pass(&mut conn, 1_000, 0).is_err());
        assert!(run_pass(&mut conn, 1_000, -1).is_err());
    }

    #[test]
    fn size_cap_drops_oldest_overflow_and_is_noop_under_cap() {
        let (_dir, mut conn) = fresh_db();
        // 5 sources at increasing indexed_ts (id1 oldest … id5 newest).
        for i in 0..5 {
            insert_source(&conn, &format!("doc-{i}"), "perm", 1_000 + i as i64);
        }
        // Under cap → no-op.
        assert_eq!(enforce_size_cap(&mut conn, 10).unwrap(), 0);
        // Cap at 3 → drop the 2 oldest.
        let dropped = enforce_size_cap(&mut conn, 3).unwrap();
        assert_eq!(dropped, 2);
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 3);
        // The two oldest labels are gone; the three newest survive.
        let gone: i64 = conn
            .query_row(
                "SELECT count(*) FROM sources WHERE label IN ('doc-0','doc-1')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gone, 0, "oldest two evicted");
        // Re-running at the same cap is now a no-op.
        assert_eq!(enforce_size_cap(&mut conn, 3).unwrap(), 0);
    }

    #[test]
    fn empty_table_returns_zero_report() {
        let (_dir, mut conn) = fresh_db();
        let r = run_pass(&mut conn, 1_000_000, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r, GcReport::default());
    }

    #[test]
    fn fresh_transient_rows_survive() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let fresh_ts = now - 1_000_000_000; // 1s old
        insert_source(&conn, "doc-a", "transient", fresh_ts);
        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 0);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn old_transient_rows_dropped() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let old_ts = now - 91 * 86_400 * 1_000_000_000; // 91 days old
        insert_source(&conn, "doc-old", "transient", old_ts);
        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 1);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn old_rss_feed_entries_age_out_via_prefix() {
        // GOLD-ADOPT-26 retention: `rss:<label>` is a TRANSIENT_PREFIXES match,
        // so an old feed entry ages out while a fresh one + a non-transient one
        // survive. Without the prefix rule, rss entries would be kept forever.
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let old_ts = now - 91 * 86_400 * 1_000_000_000; // 91 days
        let fresh_ts = now - 86_400 * 1_000_000_000; // 1 day
        insert_source(&conn, "rss:hn:abc", "rss:hn", old_ts);
        insert_source(&conn, "rss:hn:def", "rss:hn", fresh_ts);
        insert_source(&conn, "rss:rust:xyz", "rss:rust_blog", old_ts);
        insert_source(&conn, "authoritative", "operator", old_ts);
        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 2, "both old rss entries drop");
        // The fresh rss entry + the operator doc survive.
        let mut stmt = conn
            .prepare("SELECT label FROM sources ORDER BY label")
            .unwrap();
        let labels: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        assert_eq!(
            labels,
            vec!["authoritative".to_string(), "rss:hn:def".to_string()]
        );
    }

    #[test]
    fn operator_rows_kept_forever() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let ancient = now - 365 * 86_400 * 1_000_000_000; // 1 year
        // "operator" is NOT in TRANSIENT_CATEGORIES → must be preserved.
        insert_source(&conn, "ground-truth-doc", "operator", ancient);
        insert_source(&conn, "onboarding-doc", "onboarding", ancient);
        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 0);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn cascade_deletes_chunks() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let old_ts = now - 91 * 86_400 * 1_000_000_000;
        let id = insert_source(&conn, "doc", "transient", old_ts);
        // Seed a chunk row pointing at this source. FTS5 columns are
        // UNINDEXED for the dedup fields; we still need the rows present
        // so the GC sweeper has something to delete.
        conn.execute(
            "INSERT INTO chunks (title, content, source_id, content_type, source_category, event_id, file_path, ts_ns) \
             VALUES ('t', 'c', ?1, 'text/plain', 'transient', 0, NULL, ?2)",
            params![id, old_ts],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chunks_trigram (title, content, source_id, content_type, source_category, event_id, file_path, ts_ns) \
             VALUES ('t', 'c', ?1, 'text/plain', 'transient', 0, NULL, ?2)",
            params![id, old_ts],
        )
        .unwrap();

        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 1);
        assert!(r.chunks_dropped >= 1);
        assert!(r.chunks_trigram_dropped >= 1);
    }

    #[test]
    fn cascade_error_is_reported_and_rolls_back_every_delete() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let old_ts = now - 91 * 86_400 * 1_000_000_000;
        let id = insert_source(&conn, "doc", "transient", old_ts);
        conn.execute(
            "INSERT INTO chunks \
             (title, content, source_id, content_type, source_category, event_id, file_path, ts_ns) \
             VALUES ('t', 'c', ?1, 'text/plain', 'transient', 0, NULL, ?2)",
            params![id, old_ts],
        )
        .unwrap();
        conn.execute("DROP TABLE chunks_trigram", []).unwrap();

        let error = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap_err();
        assert!(
            error.to_string().contains("delete trigram chunks"),
            "unexpected error: {error:#}"
        );
        let sources: i64 = conn
            .query_row("SELECT COUNT(*) FROM sources WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        let chunks: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chunks WHERE source_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sources, 1, "source deletion must roll back");
        assert_eq!(chunks, 1, "earlier chunk deletion must roll back");
    }

    #[test]
    fn mixed_set_drops_only_old_transient() {
        let (_dir, mut conn) = fresh_db();
        let now = 1_700_000_000_000_000_000i64;
        let old = now - 200 * 86_400 * 1_000_000_000;
        let fresh = now - 1_000_000;
        insert_source(&conn, "keep-fresh", "transient", fresh);
        insert_source(&conn, "drop-old", "transient", old);
        insert_source(&conn, "keep-op", "operator", old);
        let r = run_pass(&mut conn, now, DEFAULT_TTL_NS).unwrap();
        assert_eq!(r.sources_dropped, 1);
        let labels: Vec<String> = conn
            .prepare("SELECT label FROM sources ORDER BY label")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(
            labels,
            vec!["keep-fresh".to_string(), "keep-op".to_string()]
        );
    }

    fn gc_index_transient(conn: &mut Connection, label: &str, content: &str) -> i64 {
        crate::memory::ctx::index_document(
            conn,
            &crate::memory::ctx::IndexRequest {
                label: label.into(),
                content: content.into(),
                file_path: None,
                content_type: "prose".into(),
                source_category: Some("transient".into()),
                event_id: None,
                document_provenance: None,
            },
        )
        .unwrap()
        .source_id
    }

    fn gc_register_managed(conn: &mut Connection) -> Vec<u8> {
        let request = serde_json::to_vec(&serde_json::json!({
            "action": "register",
            "logical_document_id": "doc",
            "logical_event_id": "registered",
            "authorization_epoch": 0,
            "index": {
                "label": "managed",
                "content": "sharedquartz logicalzircon",
                "file_path": "old/document.md",
                "source_category": "transient"
            }
        }))
        .unwrap();
        crate::memory::ctx::logical::apply(conn, &request).unwrap();
        request
    }

    fn gc_current_source(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT current_source_id FROM logical_documents WHERE logical_id='doc'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn gc_age_sources(conn: &Connection) {
        conn.execute("UPDATE sources SET indexed_ts=0", []).unwrap();
    }

    fn gc_source_exists(conn: &Connection, id: i64) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sources WHERE id=?1)",
            [id],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn gc_fts_count(conn: &Connection, table: &str, word: &str) -> i64 {
        assert!(matches!(table, "chunks" | "chunks_trigram"));
        conn.query_row(
            &format!("SELECT count(*) FROM {table} WHERE {table} MATCH ?1"),
            [word],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn gc_vocabulary_frequency(conn: &Connection, word: &str) -> Option<i64> {
        use rusqlite::OptionalExtension;
        conn.query_row(
            "SELECT frequency FROM vocabulary WHERE term=?1",
            [word],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
    }

    fn gc_snapshot(conn: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        [
            "sources",
            "chunks",
            "chunks_trigram",
            "vocabulary",
            "logical_documents",
            "logical_document_events",
            "ctx_logical_state",
            "sqlite_sequence",
        ]
        .iter()
        .map(|table| {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = stmt.column_count();
            stmt.query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        })
        .collect()
    }

    fn gc_apply_path(conn: &mut Connection, ttl: bool) -> anyhow::Result<usize> {
        if ttl {
            run_pass(conn, 100, 1).map(|report| report.sources_dropped)
        } else {
            enforce_size_cap(conn, 1)
        }
    }

    #[test]
    fn ttl_preserves_managed_document_and_reconciles_vocabulary_and_fts() {
        let (_dir, mut conn) = fresh_db();
        let request = gc_register_managed(&mut conn);
        let managed = gc_current_source(&conn);
        let victim = gc_index_transient(&mut conn, "unowned", "sharedquartz victimamethyst");
        gc_age_sources(&conn);
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(2));

        let report = run_pass(&mut conn, 100, 1).unwrap();
        assert_eq!(report.sources_dropped, 1);
        assert_eq!(report.chunks_dropped, 1);
        assert_eq!(report.chunks_trigram_dropped, 1);
        assert!(gc_source_exists(&conn, managed));
        assert!(!gc_source_exists(&conn, victim));
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "logicalzircon"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        for table in ["chunks", "chunks_trigram"] {
            assert_eq!(gc_fts_count(&conn, table, "sharedquartz"), 1);
            assert_eq!(gc_fts_count(&conn, table, "logicalzircon"), 1);
            assert_eq!(gc_fts_count(&conn, table, "victimamethyst"), 0);
        }
        let replay = crate::memory::ctx::logical::apply(&mut conn, &request).unwrap();
        assert!(replay.replayed && replay.is_current);
        assert_eq!(replay.source_id, managed);
    }

    #[test]
    fn size_cap_skips_oldest_managed_source_and_reports_actual_removals() {
        let (_dir, mut conn) = fresh_db();
        let request = gc_register_managed(&mut conn);
        let managed = gc_current_source(&conn);
        let victim = gc_index_transient(&mut conn, "newer", "sharedquartz victimamethyst");
        conn.execute("UPDATE sources SET indexed_ts=0 WHERE id=?1", [managed])
            .unwrap();
        conn.execute("UPDATE sources SET indexed_ts=1 WHERE id=?1", [victim])
            .unwrap();
        assert_eq!(enforce_size_cap(&mut conn, usize::MAX).unwrap(), 0);
        assert_eq!(enforce_size_cap(&mut conn, 1).unwrap(), 1);
        assert!(gc_source_exists(&conn, managed));
        assert!(!gc_source_exists(&conn, victim));
        assert_eq!(enforce_size_cap(&mut conn, 0).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM sources", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        let replay = crate::memory::ctx::logical::apply(&mut conn, &request).unwrap();
        assert!(replay.replayed && replay.is_current);
        assert_eq!(replay.source_id, managed);
    }

    #[test]
    fn corrupt_vocabulary_rolls_back_both_gc_paths() {
        for ttl in [true, false] {
            let (_dir, mut conn) = fresh_db();
            gc_register_managed(&mut conn);
            gc_index_transient(&mut conn, "victim", "sharedquartz victimamethyst");
            gc_age_sources(&conn);
            assert_eq!(
                conn.execute("DELETE FROM vocabulary WHERE term='victimamethyst'", [])
                    .unwrap(),
                1
            );
            let before = gc_snapshot(&conn);
            assert!(gc_apply_path(&mut conn, ttl).is_err(), "ttl={ttl}");
            assert_eq!(gc_snapshot(&conn), before, "ttl={ttl}");
        }
    }

    #[test]
    fn source_delete_failure_rolls_back_both_gc_paths_and_retry_succeeds() {
        for ttl in [true, false] {
            let (_dir, mut conn) = fresh_db();
            gc_register_managed(&mut conn);
            let victim = gc_index_transient(&mut conn, "victim", "sharedquartz victimamethyst");
            gc_age_sources(&conn);
            conn.execute_batch(
                "CREATE TRIGGER gc_test_reject_source_delete BEFORE DELETE ON sources
                 BEGIN SELECT RAISE(ABORT,'injected source delete failure'); END;",
            )
            .unwrap();
            let before = gc_snapshot(&conn);
            assert!(gc_apply_path(&mut conn, ttl).is_err(), "ttl={ttl}");
            assert_eq!(gc_snapshot(&conn), before, "ttl={ttl}");
            conn.execute_batch("DROP TRIGGER gc_test_reject_source_delete")
                .unwrap();
            assert_eq!(gc_apply_path(&mut conn, ttl).unwrap(), 1, "ttl={ttl}");
            assert!(!gc_source_exists(&conn, victim));
            assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
            assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        }
    }

    #[test]
    fn both_gc_paths_protect_current_and_event_references_without_source_markers() {
        for ttl in [true, false] {
            let (_dir, mut conn) = fresh_db();
            gc_register_managed(&mut conn);
            let event_source = gc_current_source(&conn);
            conn.execute(
                "UPDATE sources SET logical_id=NULL,logical_revision=NULL WHERE id=?1",
                [event_source],
            )
            .unwrap();
            let current_source = gc_index_transient(&mut conn, "current", "currenttopaz");
            conn.execute(
                "UPDATE logical_documents SET current_source_id=?1 WHERE logical_id='doc'",
                [current_source],
            )
            .unwrap();
            let victim = gc_index_transient(&mut conn, "victim", "victimamethyst");
            gc_age_sources(&conn);
            let removed = if ttl {
                run_pass(&mut conn, 100, 1).unwrap().sources_dropped
            } else {
                enforce_size_cap(&mut conn, 0).unwrap()
            };
            assert_eq!(removed, 1, "ttl={ttl}");
            assert!(gc_source_exists(&conn, event_source), "ttl={ttl}");
            assert!(gc_source_exists(&conn, current_source), "ttl={ttl}");
            assert!(!gc_source_exists(&conn, victim), "ttl={ttl}");
            assert_eq!(gc_current_source(&conn), current_source);
            let retained_event: i64 = conn.query_row(
                "SELECT source_id_at_result FROM logical_document_events WHERE event_id='registered'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(retained_event, event_source);
        }
    }

    fn gc_emulate_legacy_deletion(conn: &mut Connection, victim: i64) {
        let tx = conn.transaction().unwrap();
        crate::memory::code_range::remove_schema_for_legacy_fixture(&tx).unwrap();
        tx.execute("DELETE FROM chunks WHERE source_id = ?1", [victim])
            .unwrap();
        tx.execute("DELETE FROM chunks_trigram WHERE source_id = ?1", [victim])
            .unwrap();
        assert_eq!(
            tx.execute("DELETE FROM sources WHERE id = ?1", [victim])
                .unwrap(),
            1
        );
        assert_eq!(
            tx.execute(
                "UPDATE meta SET value = '50' WHERE key = 'schema_version'",
                [],
            )
            .unwrap(),
            1
        );
        tx.commit().unwrap();
    }

    fn gc_schema_version(conn: &Connection) -> String {
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn v50_gc_vocabulary_drift_is_repaired_on_open_and_not_rebuilt_again() {
        let (dir, mut conn) = fresh_db();
        let request = gc_register_managed(&mut conn);
        let managed = gc_current_source(&conn);
        let victim = gc_index_transient(&mut conn, "victim", "sharedquartz victimamethyst");
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(2));
        gc_emulate_legacy_deletion(&mut conn, victim);
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(2));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), Some(1));
        drop(conn);

        let mut conn = store::open(&dir.path().join("v.db")).unwrap();
        assert_eq!(gc_schema_version(&conn), store::SCHEMA_VERSION.to_string());
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "logicalzircon"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        assert!(gc_source_exists(&conn, managed));
        assert!(!gc_source_exists(&conn, victim));
        for table in ["chunks", "chunks_trigram"] {
            assert_eq!(gc_fts_count(&conn, table, "sharedquartz"), 1);
            assert_eq!(gc_fts_count(&conn, table, "logicalzircon"), 1);
            assert_eq!(gc_fts_count(&conn, table, "victimamethyst"), 0);
        }
        let replay = crate::memory::ctx::logical::apply(&mut conn, &request).unwrap();
        assert!(replay.replayed && replay.is_current);
        assert_eq!(replay.source_id, managed);

        conn.execute_batch(
            "CREATE TRIGGER gc_test_reject_vocabulary_insert
             BEFORE INSERT ON vocabulary
             BEGIN SELECT RAISE(ABORT, 'unexpected vocabulary rebuild'); END;",
        )
        .unwrap();
        drop(conn);
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        assert_eq!(gc_schema_version(&conn), store::SCHEMA_VERSION.to_string());
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "logicalzircon"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        conn.execute_batch("DROP TRIGGER gc_test_reject_vocabulary_insert;")
            .unwrap();
    }

    #[test]
    fn v50_to_v51_failed_rebuild_rolls_back_vocabulary_and_version_then_retries() {
        let (_dir, mut conn) = fresh_db();
        let request = gc_register_managed(&mut conn);
        let victim = gc_index_transient(&mut conn, "victim", "sharedquartz victimamethyst");
        gc_emulate_legacy_deletion(&mut conn, victim);
        conn.execute_batch(
            "CREATE TRIGGER gc_test_reject_logical_term
             BEFORE INSERT ON vocabulary WHEN NEW.term = 'logicalzircon'
             BEGIN SELECT RAISE(ABORT, 'injected vocabulary rebuild failure'); END;",
        )
        .unwrap();
        let before = gc_snapshot(&conn);
        assert!(crate::memory::migrations::migrate(&mut conn, 50, 51).is_err());
        assert_eq!(gc_snapshot(&conn), before);
        assert_eq!(gc_schema_version(&conn), "50");

        conn.execute_batch("DROP TRIGGER gc_test_reject_logical_term;")
            .unwrap();
        assert_eq!(
            crate::memory::migrations::migrate(&mut conn, 50, 51).unwrap(),
            51
        );
        assert_eq!(gc_schema_version(&conn), "51");
        assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "logicalzircon"), Some(1));
        assert_eq!(gc_vocabulary_frequency(&conn, "victimamethyst"), None);
        let replay = crate::memory::ctx::logical::apply(&mut conn, &request).unwrap();
        assert!(replay.replayed && replay.is_current);
    }

    #[test]
    fn ignored_source_delete_rolls_back_entire_gc_batch() {
        for ttl in [true, false] {
            let (_dir, mut conn) = fresh_db();
            gc_register_managed(&mut conn);
            let first = gc_index_transient(&mut conn, "first", "sharedquartz firstamethyst");
            let ignored = gc_index_transient(&mut conn, "ignored", "sharedquartz ignoredamethyst");
            gc_age_sources(&conn);
            conn.execute_batch(&format!(
                "CREATE TRIGGER gc_test_ignore_source_delete BEFORE DELETE ON sources
                 WHEN OLD.id = {ignored} BEGIN SELECT RAISE(IGNORE); END;"
            ))
            .unwrap();
            let before = gc_snapshot(&conn);
            let error = gc_apply_path(&mut conn, ttl).unwrap_err();
            assert!(error.to_string().contains("deletion was not applied"));
            assert_eq!(gc_snapshot(&conn), before, "ttl={ttl}");
            assert!(gc_source_exists(&conn, first));
            assert!(gc_source_exists(&conn, ignored));
            conn.execute_batch("DROP TRIGGER gc_test_ignore_source_delete;")
                .unwrap();
            assert_eq!(gc_apply_path(&mut conn, ttl).unwrap(), 2, "ttl={ttl}");
            assert_eq!(gc_vocabulary_frequency(&conn, "sharedquartz"), Some(1));
            assert_eq!(gc_vocabulary_frequency(&conn, "firstamethyst"), None);
            assert_eq!(gc_vocabulary_frequency(&conn, "ignoredamethyst"), None);
        }
    }
}
