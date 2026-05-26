//! KF-07 (Session 24) — Hebbian drift report.
//!
//! Operator-facing diagnostic: "which beliefs are FADING from
//! the ground-truth tier toward the forget floor?" The Hebbian
//! decay schedule (0.997/day for cold, 0.99/day for warm, 0.97/
//! day for hot) means importance silently drops without recall
//! reinforcement. A claim that mattered 3 months ago + never
//! got recalled is on a glide path to FORGET_FLOOR (0.10) where
//! the consolidation pass deletes it from queryable views.
//!
//! Drift report surfaces:
//! - **Imminent forgets** — rows already below `IMMINENT_THRESHOLD`
//!   (0.20) that the next consolidation pass will sweep.
//! - **At-risk rows** — between `AT_RISK_THRESHOLD` (0.40) and
//!   `IMMINENT_THRESHOLD`. Reinforcing now (one recall hit) bumps
//!   importance back above 0.5 via the Hebbian formula.
//! - **Stable rows** — above `AT_RISK_THRESHOLD`. Operator-visible
//!   count only; not listed individually.
//!
//! ## Tier scope
//!
//! The report queries `idx_episode` (hot tier) since that's where
//! the operator's recent work lives + the operator can still
//! reinforce by recalling. Cold-tier rows below FORGET_FLOOR are
//! already gone — too late to drift-report on them.
//!
//! ## Why not a cron
//!
//! Drift detection is operator-on-demand. A scheduled drift report
//! would create notification noise (G-01a's `ProactiveQueue` is
//! capped at 3/day for good reason). Operators run `neoth memory
//! drift` when they want to triage stale knowledge — typically
//! before a deep work session or weekly review.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::memory::tiers::FORGET_FLOOR;

/// Rows below this importance will be swept by the next
/// consolidation pass if they age past 7 days. Operator should
/// reinforce IMMEDIATELY to keep.
pub const IMMINENT_THRESHOLD: f64 = 0.20;

/// Rows between this and IMMINENT_THRESHOLD. Operator has time
/// to act but the trajectory is downward.
pub const AT_RISK_THRESHOLD: f64 = 0.40;

/// One drifting row surfaced by [`drift_report`]. Sorted in the
/// report by importance ASC (most-imminent first) so the operator
/// sees the most-urgent triage candidates at the top.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DriftingRow {
    pub event_id: i64,
    pub text: String,
    pub importance: f64,
    pub ts_ns: i64,
    /// Operator-facing severity tag. Pinned by [`severity_for`]
    /// + the drift-guard test.
    pub severity: DriftSeverity,
}

/// Severity bucket. Pinned via `serde(rename_all = "snake_case")`
/// for stable wire form across CLI/GUI/JSON consumers.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// importance < IMMINENT_THRESHOLD — next consolidation may sweep.
    Imminent,
    /// IMMINENT_THRESHOLD ≤ importance < AT_RISK_THRESHOLD — fading.
    AtRisk,
}

impl DriftSeverity {
    /// Stable wire form. Drift-guard pinned.
    pub fn as_str(self) -> &'static str {
        match self {
            DriftSeverity::Imminent => "imminent",
            DriftSeverity::AtRisk => "at_risk",
        }
    }
}

/// Classify an importance value into a drift severity, or `None`
/// when the row is stable (importance ≥ AT_RISK_THRESHOLD) or
/// already below FORGET_FLOOR (consolidation will delete it).
pub fn severity_for(importance: f64) -> Option<DriftSeverity> {
    if importance < FORGET_FLOOR {
        // Already dead — out of the operator's recovery window.
        // Returning None is intentional: drift_report shouldn't
        // surface unrecoverable rows.
        None
    } else if importance < IMMINENT_THRESHOLD {
        Some(DriftSeverity::Imminent)
    } else if importance < AT_RISK_THRESHOLD {
        Some(DriftSeverity::AtRisk)
    } else {
        None
    }
}

/// Aggregate report. Carries the buckets + summary counts that
/// the CLI renders. Pure read over `idx_episode`; no mutations.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DriftReport {
    /// Most-imminent first (importance ASC, then ts_ns DESC).
    /// Capped at `limit` (caller-supplied) so the operator's
    /// terminal isn't flooded.
    pub drifting: Vec<DriftingRow>,
    pub imminent_count: i64,
    pub at_risk_count: i64,
    pub stable_count: i64,
}

/// Build the drift report. Pure-read over idx_episode.
///
/// `limit` caps the `drifting` vec (sorted most-imminent first).
/// Summary counts are always exact regardless of limit.
pub fn drift_report(conn: &Connection, limit: usize) -> Result<DriftReport> {
    let imminent_count: i64 = conn.query_row(
        "SELECT count(*) FROM idx_episode \
         WHERE importance >= ?1 AND importance < ?2",
        params![FORGET_FLOOR, IMMINENT_THRESHOLD],
        |r| r.get(0),
    )?;
    let at_risk_count: i64 = conn.query_row(
        "SELECT count(*) FROM idx_episode \
         WHERE importance >= ?1 AND importance < ?2",
        params![IMMINENT_THRESHOLD, AT_RISK_THRESHOLD],
        |r| r.get(0),
    )?;
    let stable_count: i64 = conn.query_row(
        "SELECT count(*) FROM idx_episode WHERE importance >= ?1",
        params![AT_RISK_THRESHOLD],
        |r| r.get(0),
    )?;

    let mut stmt = conn.prepare(
        "SELECT event_id, text, importance, ts_ns FROM idx_episode \
         WHERE importance >= ?1 AND importance < ?2 \
         ORDER BY importance ASC, ts_ns DESC \
         LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(
            params![FORGET_FLOOR, AT_RISK_THRESHOLD, limit as i64],
            |r| {
                let event_id: i64 = r.get(0)?;
                let text: String = r.get(1)?;
                let importance: f64 = r.get(2)?;
                let ts_ns: i64 = r.get(3)?;
                let severity = severity_for(importance).unwrap_or(DriftSeverity::AtRisk);
                Ok(DriftingRow {
                    event_id,
                    text,
                    importance,
                    ts_ns,
                    severity,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(DriftReport {
        drifting: rows,
        imminent_count,
        at_risk_count,
        stable_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        (dir, conn)
    }

    fn seed(conn: &Connection, event_id: i64, text: &str, importance: f64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, ?3, ?4, ?5, ?2)",
            params![event_id, event_id, text, format!("h{event_id}"), importance],
        )
        .unwrap();
    }

    // ── Severity classifier ───────────────────────────────────────────

    #[test]
    fn severity_for_pins_each_band() {
        // < FORGET_FLOOR → None (already dead)
        assert_eq!(severity_for(0.05), None);
        // FORGET_FLOOR ≤ x < IMMINENT_THRESHOLD → Imminent
        assert_eq!(severity_for(0.10), Some(DriftSeverity::Imminent));
        assert_eq!(severity_for(0.15), Some(DriftSeverity::Imminent));
        // IMMINENT_THRESHOLD ≤ x < AT_RISK_THRESHOLD → AtRisk
        assert_eq!(severity_for(0.20), Some(DriftSeverity::AtRisk));
        assert_eq!(severity_for(0.35), Some(DriftSeverity::AtRisk));
        // ≥ AT_RISK_THRESHOLD → None (stable)
        assert_eq!(severity_for(0.40), None);
        assert_eq!(severity_for(0.95), None);
    }

    #[test]
    fn severity_as_str_pinned_for_audit() {
        assert_eq!(DriftSeverity::Imminent.as_str(), "imminent");
        assert_eq!(DriftSeverity::AtRisk.as_str(), "at_risk");
    }

    // ── drift_report integration ──────────────────────────────────────

    #[test]
    fn report_empty_db_returns_zeros() {
        let (_dir, conn) = open();
        let r = drift_report(&conn, 100).unwrap();
        assert!(r.drifting.is_empty());
        assert_eq!(r.imminent_count, 0);
        assert_eq!(r.at_risk_count, 0);
        assert_eq!(r.stable_count, 0);
    }

    #[test]
    fn report_buckets_rows_correctly() {
        let (_dir, conn) = open();
        // Already-dead (below FORGET_FLOOR) — excluded from report.
        seed(&conn, 1, "dead", 0.05);
        // Imminent (FORGET_FLOOR..IMMINENT_THRESHOLD = 0.10..0.20).
        seed(&conn, 2, "imminent-a", 0.12);
        seed(&conn, 3, "imminent-b", 0.18);
        // At-risk (0.20..0.40).
        seed(&conn, 4, "at-risk-a", 0.25);
        seed(&conn, 5, "at-risk-b", 0.39);
        // Stable (≥ 0.40).
        seed(&conn, 6, "stable", 0.50);
        seed(&conn, 7, "stable-top", 0.95);

        let r = drift_report(&conn, 100).unwrap();
        assert_eq!(r.imminent_count, 2);
        assert_eq!(r.at_risk_count, 2);
        assert_eq!(r.stable_count, 2);
        // drifting vec contains imminent + at-risk (4 rows total).
        assert_eq!(r.drifting.len(), 4);
        // Sorted by importance ASC (most-imminent first).
        let imps: Vec<f64> = r.drifting.iter().map(|d| d.importance).collect();
        for w in imps.windows(2) {
            assert!(
                w[0] <= w[1],
                "drifting must sort importance ASC, got {imps:?}"
            );
        }
        // First row is imminent severity.
        assert_eq!(r.drifting[0].severity, DriftSeverity::Imminent);
        // Last row is at-risk severity.
        assert_eq!(r.drifting[3].severity, DriftSeverity::AtRisk);
    }

    #[test]
    fn report_respects_limit_on_drifting_vec_but_not_counts() {
        let (_dir, conn) = open();
        for i in 1..=10 {
            // All imminent (0.12 .. 0.19).
            seed(&conn, i, &format!("imm-{i}"), 0.12 + (i as f64) * 0.005);
        }
        let r = drift_report(&conn, 3).unwrap();
        // drifting vec capped.
        assert_eq!(r.drifting.len(), 3);
        // Count is the full population (not the limit).
        assert_eq!(r.imminent_count, 10);
    }

    #[test]
    fn report_excludes_already_dead_rows_below_forget_floor() {
        // Operator-recovery contract: rows already below
        // FORGET_FLOOR are unrecoverable + the next consolidation
        // pass deletes them. The drift report MUST NOT include
        // them — surfacing dead rows would mislead the operator
        // about what's still triagable.
        let (_dir, conn) = open();
        seed(&conn, 1, "dead-1", 0.01);
        seed(&conn, 2, "dead-2", 0.09);
        seed(&conn, 3, "imminent", 0.15);

        let r = drift_report(&conn, 100).unwrap();
        assert_eq!(r.drifting.len(), 1, "only the imminent row surfaces");
        assert_eq!(r.drifting[0].event_id, 3);
        assert_eq!(r.imminent_count, 1);
    }

    #[test]
    fn report_severity_field_matches_classifier() {
        // Drift guard: the severity attached to each DriftingRow
        // MUST equal what severity_for() returns. Catches a future
        // refactor that diverges the classifier from the SQL
        // bucket boundaries.
        let (_dir, conn) = open();
        seed(&conn, 1, "imm", 0.15);
        seed(&conn, 2, "risk", 0.30);

        let r = drift_report(&conn, 100).unwrap();
        for row in &r.drifting {
            let expected = severity_for(row.importance).expect("must classify");
            assert_eq!(
                row.severity, expected,
                "row {} imp={} severity mismatch (got {:?} expected {:?})",
                row.event_id, row.importance, row.severity, expected,
            );
        }
    }

    #[test]
    fn threshold_constants_are_monotonic() {
        // FORGET_FLOOR < IMMINENT_THRESHOLD < AT_RISK_THRESHOLD.
        // Pinned so a future tier-tuning doesn't invert the bands
        // without also reviewing the report semantics.
        assert!(FORGET_FLOOR < IMMINENT_THRESHOLD);
        assert!(IMMINENT_THRESHOLD < AT_RISK_THRESHOLD);
    }
}
