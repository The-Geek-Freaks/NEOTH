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
    /// JV-MEM-04: `idx_episode` rows AUTO-PINNED this pass — a `trust=2`
    /// (operator-confirmed) episode at `importance >= 0.9` is promoted to
    /// `pinned=1` so the decay step (which skips pinned rows, NN-MEM-01)
    /// leaves it permanent instead of slowly eroding below FORGET_FLOOR.
    pub auto_pinned: usize,
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
    /// M-06 (Session 24): cold-tier rows DELETED for falling below
    /// `FORGET_FLOOR` after long-term decay. Pre-fix this count
    /// only lived in a `tracing::debug!` line — operators reading
    /// `PassReport` via `neoth memory --decay --json` or the
    /// consolidation cron audit frame could not see the cold sweep
    /// at all. Surface it here so the report-shape matches the
    /// other tier-archive fields.
    pub cold_swept: usize,
    /// KF-10 (Session 30): hot rows drafted to the Obsidian `PreDecay/`
    /// vault before being forgotten (only non-zero when the operator
    /// configured `obsidian_vault` AND rows fell below FORGET_FLOOR this
    /// pass). Equals `hot_archived` when a vault is set and every draft
    /// wrote cleanly.
    pub pre_decay_drafted: usize,
    /// JV-MEM-12: structural-integrity issues found by the pre-flight
    /// circuit-breaker. Empty on a healthy store. When NON-empty the pass
    /// REFUSED to run (every count above stays 0) so the corruption is not
    /// amplified; see [`PassReport::integrity_ok`].
    pub integrity_issues: Vec<String>,
}

impl PassReport {
    /// JV-MEM-12: true iff the integrity circuit-breaker found no structural
    /// corruption. When false the consolidation pass refused to run this cycle.
    pub fn integrity_ok(&self) -> bool {
        self.integrity_issues.is_empty()
    }
}

/// Run one consolidation pass against `conn`. All work happens in a single
/// transaction so a partial failure leaves the views unchanged.
///
/// `now_ns` is injected (rather than read inside) so tests can simulate
/// arbitrary clock positions without sleeping.
pub fn run_consolidation_pass(
    conn: &mut Connection,
    now_ns: i64,
    vault_path: Option<&std::path::Path>,
) -> Result<PassReport> {
    let mut report = PassReport::default();
    // JV-MEM-12 circuit-breaker: refuse to consolidate a structurally corrupt
    // store — consolidating inconsistent tiers would amplify the damage. The
    // checks are exact-corruption (cross-tier id collision / duplicate retained
    // id) so a healthy store never trips this and consolidation never stalls.
    let integrity = crate::memory::integrity::check_integrity(conn)
        .context("consolidation integrity pre-flight")?;
    if !integrity.ok {
        tracing::error!(
            issues = ?integrity.issues,
            "consolidation REFUSED: memory store failed the integrity circuit-breaker — \
             skipping this pass so the inconsistency is not amplified. Inspect the tiers; \
             consolidation resumes automatically once the store is consistent again."
        );
        report.integrity_issues = integrity.issues;
        return Ok(report);
    }
    let tx = conn.transaction().context("begin consolidation tx")?;
    // KF-10: hot rows captured at the FORGET_FLOOR delete site (Phase 2)
    // so the EXACT set being forgotten is drafted to Obsidian after the tx
    // commits. Stays empty (zero overhead) when no `vault_path` is set.
    let mut forgotten: Vec<crate::memory::pre_decay_export::PreDecayRow> = Vec::new();

    // ── Phase 1: decay every importance column in every tier ──────────────
    //
    // SQLite handles the math via an UPDATE with a constant factor. The
    // `Tier::decay_factor` constants are duplicated inline so the SQL
    // remains a single statement — the alternative (per-row procedural
    // multiply) is ~3× slower at 100K rows and offers no clarity gain.
    let hot_decay = Tier::Hot.decay_factor();
    let warm_decay = Tier::Warm.decay_factor();
    let cold_decay = Tier::Cold.decay_factor();

    // JV-MEM-04: auto-pin BEFORE decaying. A `trust=2` (operator-confirmed)
    // episode at `importance >= 0.9` is promoted to `pinned=1` so the very next
    // decay step (which skips pinned rows) leaves it untouched — a high-trust,
    // high-importance memory becomes permanent instead of eroding. Idempotent:
    // already-pinned rows are excluded, so a steady store auto-pins nothing.
    report.auto_pinned = tx
        .execute(
            "UPDATE idx_episode SET pinned = 1 \
             WHERE trust = 2 AND importance >= 0.9 AND pinned = 0",
            [],
        )
        .context("auto-pin high-trust high-importance episodes")?;

    // NN-MEM-01: `pinned` episodes are decay-immune — skip them so a critical
    // memory can never decay below FORGET_FLOOR and be forgotten.
    report.hot_decayed = tx
        .execute(
            "UPDATE idx_episode SET importance = importance * ?1 WHERE pinned = 0",
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
        "SELECT event_id, ts_ns, text, text_hash, importance, access_count \
         FROM idx_episode \
         WHERE ts_ns < ?1",
    )?;
    let rows: Vec<(i64, i64, String, String, f64, i64)> = select
        .query_map(params![seven_days_ago], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, f64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(select);

    for (event_id, ts_ns, text, text_hash, importance, access_count) in rows {
        if importance < FORGET_FLOOR {
            // Below floor → drop without consolidating. Archive MD remains.
            // KF-10: capture the row BEFORE the DELETE for pre-decay export
            // (only when a vault is configured) — `text` is unused on this
            // branch otherwise, so move it in rather than clone.
            if vault_path.is_some() {
                forgotten.push(crate::memory::pre_decay_export::PreDecayRow {
                    event_id,
                    ts_ns,
                    text,
                    importance,
                });
            }
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
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts, access_count) \
             VALUES ('retained', ?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
            params![day, event_id, text, text_hash, importance, now_ns, access_count],
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
        "SELECT id, event_id, text, text_hash, importance, access_count \
         FROM idx_consolidated \
         WHERE day < ?1",
    )?;
    let warm_rows: Vec<(i64, Option<i64>, String, String, f64, i64)> = select_warm
        .query_map(params![ninety_days_ago_day], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, f64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(select_warm);

    for (row_id, maybe_event_id, text, text_hash, importance, access_count) in warm_rows {
        if importance >= PROMOTION_THRESHOLD {
            // Promote to long-term. Use the original event_id if we have one,
            // otherwise synthesise from the warm row id (offset to avoid
            // collision with real hot event ids).
            let event_id = maybe_event_id.unwrap_or(-row_id - 1);
            tx.execute(
                "INSERT OR REPLACE INTO idx_longterm \
                 (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path, access_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL, ?6)",
                params![event_id, text, text_hash, importance, now_ns, access_count],
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
    report.cold_swept = cold_swept;

    tx.commit().context("commit consolidation tx")?;

    // KF-10: AFTER the tx commits (never holding the DB lock during file
    // IO), draft the forgotten hot rows into the Obsidian vault. Best-
    // effort — `write_pre_decay_drafts` logs + skips individual failures
    // and never errors, so a full/read-only vault can't fail a decay pass.
    if let Some(vault) = vault_path {
        if !forgotten.is_empty() {
            report.pre_decay_drafted =
                crate::memory::pre_decay_export::write_pre_decay_drafts(vault, &forgotten);
        }
    }
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
    fn access_count_carries_through_hot_warm_cold_consolidation() {
        // JV-MEM-09: a frequently-recalled row must keep its access_count as it
        // ages out of the hot tier, so it can re-promote in ranking later.
        let (_dir, mut conn) = open();
        let now_ns: i64 = 400 * DAY_NS;
        // A hot row, 10 days old (→ warm), well above FORGET_FLOOR, recalled 7×.
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts, access_count) \
             VALUES (42, 1, ?1, 'hot', 'h', 0.9, ?1, 7)",
            params![now_ns - 10 * DAY_NS],
        )
        .unwrap();

        run_consolidation_pass(&mut conn, now_ns, None).unwrap();

        // hot → warm carried the count.
        let warm: i64 = conn
            .query_row(
                "SELECT access_count FROM idx_consolidated WHERE event_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(warm, 7, "access_count must survive hot→warm consolidation");

        // Age the warm row past 90 days + restore importance above the promotion
        // threshold so the next pass promotes it to cold.
        conn.execute(
            "UPDATE idx_consolidated SET day = ?1, importance = 0.9 WHERE event_id = 42",
            params![ts_to_day_string(now_ns - 120 * DAY_NS)],
        )
        .unwrap();
        run_consolidation_pass(&mut conn, now_ns, None).unwrap();

        let cold: i64 = conn
            .query_row(
                "SELECT access_count FROM idx_longterm WHERE event_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cold, 7, "access_count must survive warm→cold promotion");
    }

    #[test]
    fn consolidation_refuses_on_integrity_corruption() {
        // JV-MEM-12: a cross-tier event_id collision trips the circuit-breaker,
        // so the pass refuses to run rather than amplify the inconsistency.
        let (_dir, mut conn) = open();
        let now_ns: i64 = 400 * DAY_NS;
        // Same positive event_id in hot AND warm — a corrupt state consolidation
        // could never produce on its own. The hot row is aged so a HEALTHY pass
        // would otherwise consolidate it.
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (9, 1, ?1, 'hot', 'h', 0.9, 0)",
            params![now_ns - 30 * DAY_NS],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-01-01', 9, 'warm', 'h', 0.9, 0, 0)",
            [],
        )
        .unwrap();

        let report = run_consolidation_pass(&mut conn, now_ns, None).unwrap();
        assert!(
            !report.integrity_ok(),
            "the breaker must trip on a cross-tier collision"
        );
        assert!(!report.integrity_issues.is_empty());
        // Refused ⇒ no work done: the aged hot row was NOT consolidated.
        assert_eq!(report.consolidated, 0, "no consolidation work on a refused pass");
        assert_eq!(report.hot_decayed, 0, "no decay work on a refused pass");
        let hot_still_there: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE event_id = 9",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hot_still_there, 1, "the hot row is untouched by a refused pass");
    }

    #[test]
    fn pinned_episodes_are_decay_immune() {
        // NN-MEM-01: a pinned hot episode skips the Phase-1 importance decay;
        // an unpinned one decays by the hot-tier factor. Both are recent
        // (age 0) so they stay in idx_episode (no hot→warm consolidation).
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 0, 0.8, now); // unpinned → decays
        insert_episode(&conn, 2, 0, 0.8, now); // pinned   → immune
        assert_eq!(store::set_episode_pinned(&conn, 2, true).unwrap(), 1);

        run_consolidation_pass(&mut conn, now, None).unwrap();

        let importance = |id: i64| -> f64 {
            conn.query_row(
                "SELECT importance FROM idx_episode WHERE event_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        let pinned = importance(2);
        let unpinned = importance(1);
        assert!(
            (pinned - 0.8).abs() < 1e-9,
            "pinned importance must be unchanged, got {pinned}"
        );
        assert!(
            (unpinned - 0.8 * Tier::Hot.decay_factor()).abs() < 1e-9,
            "unpinned importance must decay by the hot factor, got {unpinned}"
        );
        assert!(pinned > unpinned, "the pinned event now outranks the decayed one");
    }

    #[test]
    fn auto_pins_high_trust_high_importance_then_decay_skips_it() {
        // JV-MEM-04: a trust=2 episode at importance>=0.9 is auto-pinned BEFORE
        // the decay step, so its importance stays put (decay skips pinned rows).
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 0, 0.95, now);
        conn.execute("UPDATE idx_episode SET trust = 2 WHERE event_id = 1", [])
            .unwrap();

        let report = run_consolidation_pass(&mut conn, now, None).unwrap();

        assert_eq!(report.auto_pinned, 1, "the high-trust high-importance row is auto-pinned");
        let (pinned, importance): (i64, f64) = conn
            .query_row(
                "SELECT pinned, importance FROM idx_episode WHERE event_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(pinned, 1, "row must be promoted to pinned=1");
        assert!(
            (importance - 0.95).abs() < 1e-9,
            "auto-pinned importance must NOT decay this pass, got {importance}"
        );
    }

    #[test]
    fn does_not_auto_pin_low_trust_or_low_importance() {
        // JV-MEM-04: the auto-pin needs BOTH trust=2 AND importance>=0.9.
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 0, 0.95, now); // trust=1 (default), high imp → no pin
        insert_episode(&conn, 2, 0, 0.50, now); // low imp
        conn.execute("UPDATE idx_episode SET trust = 2 WHERE event_id = 2", [])
            .unwrap();

        let report = run_consolidation_pass(&mut conn, now, None).unwrap();

        assert_eq!(report.auto_pinned, 0, "neither row qualifies for auto-pin");
        let pinned = |id: i64| -> i64 {
            conn.query_row(
                "SELECT pinned FROM idx_episode WHERE event_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(pinned(1), 0, "high-importance but low-trust must stay unpinned");
        assert_eq!(pinned(2), 0, "high-trust but low-importance must stay unpinned");
        // Both decayed normally (not pinned).
        let importance = |id: i64| -> f64 {
            conn.query_row(
                "SELECT importance FROM idx_episode WHERE event_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert!((importance(1) - 0.95 * Tier::Hot.decay_factor()).abs() < 1e-9);
    }

    #[test]
    fn forgotten_hot_rows_are_drafted_to_vault_when_configured() {
        // KF-10: a below-floor, >7d-old row is FORGOTTEN this pass → it must
        // be drafted to the vault. A row that gets CONSOLIDATED (above floor)
        // must NOT be drafted. Proves the draft set equals the deleted set
        // exactly — captured at the delete site, not a re-derived criterion.
        let (_dir, mut conn) = open();
        let vault = tempdir().unwrap();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 10, 0.05, now); // below floor + old → forgotten
        insert_episode(&conn, 2, 10, 0.50, now); // above floor + old → consolidated

        let report = run_consolidation_pass(&mut conn, now, Some(vault.path())).unwrap();

        assert_eq!(report.hot_archived, 1, "event 1 forgotten");
        assert_eq!(report.consolidated, 1, "event 2 consolidated");
        assert_eq!(
            report.pre_decay_drafted, 1,
            "exactly the forgotten row is drafted"
        );
        let files: Vec<String> = std::fs::read_dir(vault.path().join("PreDecay"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            files.len(),
            1,
            "only the forgotten row drafted, got {files:?}"
        );
        assert!(
            files[0].ends_with("-1.md"),
            "draft is for event_id 1, got {files:?}"
        );
        // Tier outcomes unchanged by the export: hot emptied, warm gained one.
        assert_eq!(count_in_tier(&conn, Tier::Hot).unwrap(), 0);
        assert_eq!(count_in_tier(&conn, Tier::Warm).unwrap(), 1);
    }

    #[test]
    fn no_vault_means_no_drafts_and_unchanged_forget_behaviour() {
        // The default daemon path (no obsidian_vault) is byte-for-byte the
        // pre-KF-10 behaviour: the row is still forgotten, just not drafted.
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 10, 0.05, now);
        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
        assert_eq!(report.hot_archived, 1);
        assert_eq!(report.pre_decay_drafted, 0, "no vault → no drafts");
    }

    #[test]
    fn pass_decays_every_tier() {
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        insert_episode(&conn, 1, 1, 0.50, now);
        insert_consolidated(&conn, "retained", 30, 0.50, now);
        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
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

        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
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

        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
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
        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
        assert_eq!(report, PassReport::default());
    }

    #[test]
    fn pass_surfaces_cold_swept_count() {
        // M-06 regression guard. Before the fix `cold_swept` lived only in
        // a `debug!` line; operators reading `PassReport` could not see how
        // many long-term rows fell below FORGET_FLOOR during the sweep.
        let (_dir, mut conn) = open();
        let now: i64 = 1_700_000_000_000_000_000;
        // Three long-term rows: two below floor (0.05 + 0.04), one above (0.50).
        conn.execute(
            "INSERT INTO idx_longterm \
             (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
             VALUES (?1, 'a', 'h1', 0.05, ?2, ?2, NULL), \
                    (?3, 'b', 'h2', 0.04, ?2, ?2, NULL), \
                    (?4, 'c', 'h3', 0.50, ?2, ?2, NULL)",
            params![1_i64, now, 2_i64, 3_i64],
        )
        .unwrap();

        let report = run_consolidation_pass(&mut conn, now, None).unwrap();
        // Decay multiplier 0.999 keeps the 0.50 row above floor; the 0.05
        // and 0.04 rows both fall below 0.10 → swept.
        assert_eq!(report.cold_swept, 2, "report must surface the sweep count");
        assert_eq!(report.cold_decayed, 3, "all three rows decayed first");

        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_longterm", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "only the 0.50 row survives the sweep");
    }

    #[test]
    fn count_in_tier_returns_zero_on_empty() {
        let (_dir, conn) = open();
        assert_eq!(count_in_tier(&conn, Tier::Hot).unwrap(), 0);
        assert_eq!(count_in_tier(&conn, Tier::Warm).unwrap(), 0);
        assert_eq!(count_in_tier(&conn, Tier::Cold).unwrap(), 0);
    }
}
