//! Daily consolidation + decay pass — Phase 28a R-22 MT-2 + R-24 GT-3.
//!
//! Run once per day (cron-triggered). Three phases inside one DB transaction:
//!
//! 1. **Decay** — multiply `idx_episode.importance` by the hot-tier decay
//!    factor; the warm/cold tier rows in `idx_consolidated` / `idx_longterm`
//!    get their tier-specific factors.
//! 2. **Hot → Warm migration** — events older than 7 days move from
//!    `idx_episode` into `idx_consolidated`. Each event lands as a
//!    `kind='retained'` row; the simple v1 leaves the summary-rollup for
//!    Phase 28c when the LLM extractor is real. The retained-row carries
//!    the importance + text verbatim so recall still works.
//! 3. **Warm → Cold / archive** — `idx_consolidated` rows older than 90
//!    days promote into `idx_longterm` if importance ≥ `PROMOTION_THRESHOLD`;
//!    otherwise they drop from views (archive MD file untouched).
//!
//! Returns a [`PassReport`] for the audit-trail WAL event. Caller emits
//! the WAL frame.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use tracing::debug;

use super::tiers::{FORGET_FLOOR, PROMOTION_THRESHOLD, Tier};

const DAY_NS: i64 = 86_400 * 1_000_000_000;

/// Summary of one consolidation pass for the audit log.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PassReport {
    /// Total `idx_episode` rows whose `importance` was decayed.
    pub hot_decayed: usize,
    /// Rows that moved `idx_episode` → `idx_consolidated` (kind='retained').
    pub consolidated: usize,
    /// Rows that fell below FORGET_FLOOR during decay and were removed
    /// from `idx_episode` without being promoted.
    pub hot_archived: usize,
    /// Rows that moved `idx_consolidated` → `idx_longterm`.
    pub promoted: usize,
    /// Rows that exceeded 90 days but fell below PROMOTION_THRESHOLD;
    /// dropped from `idx_consolidated`.
    pub warm_archived: usize,
    /// `idx_consolidated` rows whose importance was decayed.
    pub warm_decayed: usize,
    /// `idx_longterm` rows whose importance was decayed.
    pub cold_decayed: usize,
}

/// Run one consolidation pass against `conn`. All work happens in a single
/// transaction so a partial failure leaves the views unchanged.
///
/// `now_ns` is injected (rather than read inside) so tests can simulate
/// arbitrary clock positions without sleeping.
pub fn run_consolidation_pass(conn: &mut Connection, now_ns: i64) -> Result<PassReport> {
    let tx = conn.transaction().context("begin consolidation tx")?;
    let mut report = PassReport::default();

    // ── Phase 1: decay every importance column in every tier ──────────────
    //
    // SQLite handles the math via an UPDATE with a constant factor. The
    // `Tier::decay_factor` constants are duplicated inline so the SQL
    // remains a single statement — the alternative (per-row procedural
    // multiply) is ~3× slower at 100K rows and offers no clarity gain.
    let hot_decay = Tier::Hot.decay_factor();
    let warm_decay = Tier::Warm.decay_factor();
    let cold_decay = Tier::Cold.decay_factor();

    report.hot_decayed = tx
        .execute(
            "UPDATE idx_episode SET importance = importance * ?1",
            params![hot_decay],
        )
        .context("decay idx_episode")?;
    report.warm_decayed = tx
        .execute(
            "UPDATE idx_consolidated SET importance = importance * ?1",
            params![warm_decay],
        )
        .context("decay idx_consolidated")?;
    report.cold_decayed = tx
        .execute(
            "UPDATE idx_longterm SET importance = importance * ?1",
            params![cold_decay],
        )
        .context("decay idx_longterm")?;

    // ── Phase 2: hot → warm consolidation ─────────────────────────────────
    //
    // Events older than 7 days leave `idx_episode`. v1 keeps the original
    // text verbatim under `kind='retained'`; per-day LLM summary rollups
    // land when Phase 28a MT-2b adds the extraction prompt.
    let seven_days_ago = now_ns - 7 * DAY_NS;

    let mut select = tx.prepare(
        "SELECT event_id, ts_ns, text, text_hash, importance \
         FROM idx_episode \
         WHERE ts_ns < ?1",
    )?;
    let rows: Vec<(i64, i64, String, String, f64)> = select
        .query_map(params![seven_days_ago], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, f64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(select);

    for (event_id, ts_ns, text, text_hash, importance) in rows {
        if importance < FORGET_FLOOR {
            // Below floor → drop without consolidating. Archive MD remains.
            tx.execute(
                "DELETE FROM idx_episode WHERE event_id = ?1",
                params![event_id],
            )?;
            report.hot_archived += 1;
            continue;
        }

        let day = ts_to_day_string(ts_ns);
        tx.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![day, event_id, text, text_hash, importance, now_ns],
        )?;
        tx.execute(
            "DELETE FROM idx_episode WHERE event_id = ?1",
            params![event_id],
        )?;
        report.consolidated += 1;
    }

    // ── Phase 3: warm → cold promotion / archive ──────────────────────────
    //
    // Rows in `idx_consolidated` whose source day is > 90 days old leave
    // the warm tier. ≥ PROMOTION_THRESHOLD → idx_longterm. Else dropped.
    let ninety_days_ago = now_ns - 90 * DAY_NS;
    let ninety_days_ago_day = ts_to_day_string(ninety_days_ago);

    let mut select_warm = tx.prepare(
        "SELECT id, event_id, text, text_hash, importance \
         FROM idx_consolidated \
         WHERE day < ?1",
    )?;
    let warm_rows: Vec<(i64, Option<i64>, String, String, f64)> = select_warm
        .query_map(params![ninety_days_ago_day], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, f64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(select_warm);

    for (row_id, maybe_event_id, text, text_hash, importance) in warm_rows {
        if importance >= PROMOTION_THRESHOLD {
            // Promote to long-term. Use the original event_id if we have one,
            // otherwise synthesise from the warm row id (offset to avoid
            // collision with real hot event ids).
            let event_id = maybe_event_id.unwrap_or(-row_id - 1);
            tx.execute(
                "INSERT OR REPLACE INTO idx_longterm \
                 (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
                params![event_id, text, text_hash, importance, now_ns],
            )?;
            report.promoted += 1;
        } else {
            report.warm_archived += 1;
        }
        tx.execute(
            "DELETE FROM idx_consolidated WHERE id = ?1",
            params![row_id],
        )?;
    }

    // ── Phase 4: cold-tier floor sweep ────────────────────────────────────
    //
    // Long-term rows can decay below FORGET_FLOOR over years. Drop them
    // from the queryable view; archive file remains.
    let cold_swept = tx
        .execute(
            "DELETE FROM idx_longterm WHERE importance < ?1",
            params![FORGET_FLOOR],
        )
        .context("sweep cold-tier floor")?;
    if cold_swept > 0 {
        debug!(
            rows = cold_swept,
            "cold-tier rows below FORGET_FLOOR dropped"
        );
    }

    tx.commit().context("commit consolidation tx")?;
    Ok(report)
}

fn ts_to_day_string(ts_ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ts_ns / 1_000_000_000;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".into())
}

/// Helper for tier-bucket counts. Used by `neoth memory --tier <t>` (MT-5).
pub fn count_in_tier(conn: &Connection, tier: Tier) -> Result<i64> {
    let sql = match tier {
        Tier::Hot => "SELECT count(*) FROM idx_episode",
        Tier::Warm => "SELECT count(*) FROM idx_consolidated",
        Tier::Cold => "SELECT count(*) FROM idx_longterm",
    };
    Ok(conn.query_row(sql, [], |r| r.get(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        (dir, conn)
    }

    fn insert_episode(
        conn: &Connection,
        event_id: i64,
        age_days: i64,
        importance: f64,
        now_ns: i64,
    ) {
        let ts_ns = now_ns - age_days * DAY_NS;
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event_id,
                ts_ns,
                format!("event-{event_id}"),
                format!("hash-{event_id}"),
                importance,
                ts_ns,
            ],
        )
        .unwrap();
    }

    fn insert_consolidated(
        conn: &Connection,
        kind: &str,
        day_ago: i64,
        importance: f64,
        now_ns: i64,
    ) -> i64 {
        let ts_ns = now_ns - day_ago * DAY_NS;
        let day = ts_to_day_string(ts_ns);
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES (?1, ?2, NULL, 'text', 'hash', ?3, ?4, ?4)",
            params![kind, day, importance, ts_ns],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn pass_decays_every_tier() {
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 1, 0.50, now);
        insert_consolidated(&conn, "retained", 30, 0.50, now);
        let report = run_consolidation_pass(&mut conn, now).unwrap();
        assert_eq!(report.hot_decayed, 1);
        assert_eq!(report.warm_decayed, 1);

        let hot_imp: f64 = conn
            .query_row("SELECT importance FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert!((hot_imp - 0.50 * 0.97).abs() < 1e-6, "got {hot_imp}");
        let warm_imp: f64 = conn
            .query_row("SELECT importance FROM idx_consolidated", [], |r| r.get(0))
            .unwrap();
        assert!((warm_imp - 0.50 * 0.99).abs() < 1e-6, "got {warm_imp}");
    }

    #[test]
    fn pass_consolidates_old_hot_events_above_floor() {
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        // 10-day-old event well above floor — must consolidate.
        insert_episode(&conn, 1, 10, 0.5, now);
        // 10-day-old event below floor (post-decay) — must archive without
        // consolidating. importance pre-decay = 0.05; post-decay = 0.0485,
        // still below FORGET_FLOOR (0.10).
        insert_episode(&conn, 2, 10, 0.05, now);
        // 3-day-old event — stays hot.
        insert_episode(&conn, 3, 3, 0.5, now);

        let report = run_consolidation_pass(&mut conn, now).unwrap();
        assert_eq!(report.consolidated, 1, "event 1 should move warm");
        assert_eq!(report.hot_archived, 1, "event 2 should archive");
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "only event 3 should stay hot");

        let warm: i64 = conn
            .query_row("SELECT count(*) FROM idx_consolidated", [], |r| r.get(0))
            .unwrap();
        assert_eq!(warm, 1);
    }

    #[test]
    fn pass_promotes_above_threshold_and_archives_below() {
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        // Warm rows older than 90 days. One above threshold (0.80), one below (0.30).
        insert_consolidated(&conn, "retained", 95, 0.80, now);
        insert_consolidated(&conn, "retained", 95, 0.30, now);

        let report = run_consolidation_pass(&mut conn, now).unwrap();
        // Decay pulls 0.80 → 0.792 (still ≥ 0.65 threshold).
        assert_eq!(report.promoted, 1);
        // 0.30 → 0.297 (below 0.65) → archive (drop from views).
        assert_eq!(report.warm_archived, 1);

        let long: i64 = conn
            .query_row("SELECT count(*) FROM idx_longterm", [], |r| r.get(0))
            .unwrap();
        assert_eq!(long, 1);
        let warm: i64 = conn
            .query_row("SELECT count(*) FROM idx_consolidated", [], |r| r.get(0))
            .unwrap();
        assert_eq!(warm, 0);
    }

    #[test]
    fn pass_is_idempotent_with_no_events() {
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        let report = run_consolidation_pass(&mut conn, now).unwrap();
        assert_eq!(report, PassReport::default());
    }

    #[test]
    fn count_in_tier_returns_zero_on_empty() {
        let (_dir, conn) = open();
        assert_eq!(count_in_tier(&conn, Tier::Hot).unwrap(), 0);
        assert_eq!(count_in_tier(&conn, Tier::Warm).unwrap(), 0);
        assert_eq!(count_in_tier(&conn, Tier::Cold).unwrap(), 0);
    }
}
