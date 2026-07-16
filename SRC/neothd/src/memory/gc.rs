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
//! Vocabulary terms are NOT deleted here — they're append-only, idempotent,
//! and cheap to keep around. A separate `vocabulary` GC could run if the
//! table ever blows up, but the corpus growth rate doesn't warrant one.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

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
         WHERE (source_category IN ({placeholders}){like_clause}) AND indexed_ts < ?",
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
    let sources_dropped = if victim_ids.is_empty() {
        0
    } else {
        let placeholders = victim_ids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("DELETE FROM sources WHERE id IN ({placeholders})");
        tx.execute(&sql, rusqlite::params_from_iter(victim_ids.iter().copied()))?
    };

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
/// caps the total at a generous bound so the store can't grow without limit.
pub const DEFAULT_MAX_SOURCES: usize = 50_000;

/// MEM-13 — enforce a total-size cap on the ctx `sources` table: when the row
/// count exceeds `max_sources`, delete the **oldest** (`indexed_ts ASC`)
/// overflow rows, cascading into the `chunks` + `chunks_trigram` FTS tables
/// exactly like [`run_pass`]. Returns the number of source rows dropped.
/// Transactional — partial failure rolls back. (Operator episodes + ground
/// truth live in separate tables and are untouched.)
pub fn enforce_size_cap(conn: &mut Connection, max_sources: usize) -> Result<usize> {
    let total: i64 = conn
        .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
        .context("count sources for size cap")?;
    if total <= max_sources as i64 {
        return Ok(0);
    }
    let overflow = total - max_sources as i64;

    let tx = conn.transaction().context("begin size-cap tx")?;
    let victim_ids: Vec<i64> = {
        let mut stmt =
            tx.prepare("SELECT id FROM sources ORDER BY indexed_ts ASC, id ASC LIMIT ?1")?;
        let rows = stmt.query_map(params![overflow], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("collect size-cap source ids")?
    };
    for id in &victim_ids {
        tx.execute("DELETE FROM chunks WHERE source_id = ?1", params![id])
            .with_context(|| format!("delete chunks for source {id}"))?;
        tx.execute(
            "DELETE FROM chunks_trigram WHERE source_id = ?1",
            params![id],
        )
        .with_context(|| format!("delete trigram chunks for source {id}"))?;
    }
    let dropped = if victim_ids.is_empty() {
        0
    } else {
        let placeholders = victim_ids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        tx.execute(
            &format!("DELETE FROM sources WHERE id IN ({placeholders})"),
            rusqlite::params_from_iter(victim_ids.iter().copied()),
        )?
    };
    tx.commit().context("commit size-cap tx")?;
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
}
