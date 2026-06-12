//! GOLD-ADAPT-JV-MEM-12 — cross-tier structural integrity circuit-breaker.
//!
//! A conservative, EXACT-corruption check across the memory tier tables. The
//! consolidation pass runs it as a pre-flight and refuses to run when the store
//! is structurally inconsistent — consolidating corrupt tiers would amplify the
//! damage (a duplicated row would be decayed/promoted twice, drift further out
//! of sync, and never self-heal). Every check flags only states that cannot
//! arise in healthy operation (consolidation always moves a row between tiers
//! via INSERT-then-DELETE inside ONE transaction), so a healthy store never
//! trips the breaker and consolidation never stalls on a false positive.
//!
//! Scope is deliberately the WRITE path (consolidation). Recall is read-only and
//! cannot amplify corruption, so it is intentionally NOT gated — the operator
//! can always read memory even while the store is being repaired.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Result of an integrity sweep. `ok` is true iff `issues` is empty.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IntegrityReport {
    pub ok: bool,
    pub issues: Vec<String>,
}

/// Run the cross-tier integrity checks. Read-only; never mutates the store.
///
/// Checks (all exact-corruption — never false-positive on a healthy store):
///  1. A positive `event_id` present in MORE THAN ONE tier table
///     (`idx_episode` hot / `idx_consolidated` warm / `idx_longterm` cold).
///     Consolidation moves a row between tiers via INSERT-then-DELETE in one
///     transaction, so a *committed* cross-tier collision means the row was
///     duplicated, not moved.
///  2. A duplicate non-null `event_id` WITHIN `idx_consolidated` — the only tier
///     table without a `UNIQUE`/`PRIMARY KEY` on `event_id`. One hot row
///     consolidates to exactly one retained row, so a duplicate means a
///     double-consolidation bug.
///
/// Summary rows carry a NULL `event_id` (and recall surfaces them with a
/// synthetic negative id); the `event_id > 0` / `IS NOT NULL` filters exclude
/// them so a legitimately-NULL summary never registers as a collision.
pub fn check_integrity(conn: &Connection) -> Result<IntegrityReport> {
    let mut issues = Vec::new();

    // Check 1: cross-tier positive event_id collisions, one pair at a time so
    // the operator-facing message names exactly which tiers disagree.
    let intersect_count = |a: &str, b: &str| -> Result<i64> {
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM (
                     SELECT event_id FROM {a} WHERE event_id > 0
                     INTERSECT
                     SELECT event_id FROM {b} WHERE event_id > 0
                 )"
            ),
            [],
            |r| r.get(0),
        )
        .with_context(|| format!("integrity: {a} ∩ {b} event_id check"))
    };

    let hot_warm = intersect_count("idx_episode", "idx_consolidated")?;
    if hot_warm > 0 {
        issues.push(format!(
            "{hot_warm} event_id(s) live in BOTH idx_episode and idx_consolidated \
             (hot→warm consolidation should have deleted the hot row)"
        ));
    }
    let hot_cold = intersect_count("idx_episode", "idx_longterm")?;
    if hot_cold > 0 {
        issues.push(format!(
            "{hot_cold} event_id(s) live in BOTH idx_episode and idx_longterm"
        ));
    }
    let warm_cold = intersect_count("idx_consolidated", "idx_longterm")?;
    if warm_cold > 0 {
        issues.push(format!(
            "{warm_cold} event_id(s) live in BOTH idx_consolidated and idx_longterm \
             (warm→cold promotion should have deleted the warm row)"
        ));
    }

    // Check 2: duplicate retained event_id within idx_consolidated.
    let dup_warm: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT event_id FROM idx_consolidated
                 WHERE event_id IS NOT NULL
                 GROUP BY event_id HAVING COUNT(*) > 1
             )",
            [],
            |r| r.get(0),
        )
        .context("integrity: duplicate warm event_id check")?;
    if dup_warm > 0 {
        issues.push(format!(
            "{dup_warm} event_id(s) appear MORE THAN ONCE in idx_consolidated \
             (double-consolidation)"
        ));
    }

    Ok(IntegrityReport {
        ok: issues.is_empty(),
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use rusqlite::params;
    use tempfile::tempdir;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        (dir, conn)
    }

    fn insert_hot(conn: &Connection, event_id: i64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, 1000, 'hot', 'h', 0.5, 0)",
            params![event_id],
        )
        .unwrap();
    }

    fn insert_warm(conn: &Connection, event_id: Option<i64>) {
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-01-01', ?1, 'warm', 'h', 0.5, 0, 0)",
            params![event_id],
        )
        .unwrap();
    }

    fn insert_cold(conn: &Connection, event_id: i64) {
        conn.execute(
            "INSERT INTO idx_longterm \
             (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
             VALUES (?1, 'cold', 'h', 0.5, 0, 0, NULL)",
            params![event_id],
        )
        .unwrap();
    }

    #[test]
    fn healthy_store_passes() {
        let (_d, conn) = open();
        insert_hot(&conn, 1);
        insert_warm(&conn, Some(2));
        insert_warm(&conn, None); // summary row, NULL event_id — must not collide
        insert_cold(&conn, 3);
        let report = check_integrity(&conn).unwrap();
        assert!(report.ok, "clean store must pass: {:?}", report.issues);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn cross_tier_event_id_collision_trips_the_breaker() {
        // Same positive event_id in hot AND warm — consolidation should have
        // deleted the hot row.
        let (_d, conn) = open();
        insert_hot(&conn, 42);
        insert_warm(&conn, Some(42));
        let report = check_integrity(&conn).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.contains("idx_episode") && i.contains("idx_consolidated")),
            "issue must name the colliding tiers: {:?}",
            report.issues
        );
    }

    #[test]
    fn duplicate_retained_warm_event_id_trips_the_breaker() {
        let (_d, conn) = open();
        insert_warm(&conn, Some(7));
        insert_warm(&conn, Some(7));
        let report = check_integrity(&conn).unwrap();
        assert!(!report.ok);
        assert!(
            report.issues.iter().any(|i| i.contains("MORE THAN ONCE")),
            "issue must flag the duplicate: {:?}",
            report.issues
        );
    }

    #[test]
    fn null_summary_event_ids_never_collide() {
        // Two summary rows (NULL event_id) in warm + a NULL-equivalent absence
        // elsewhere must NOT be read as a collision or a duplicate.
        let (_d, conn) = open();
        insert_warm(&conn, None);
        insert_warm(&conn, None);
        let report = check_integrity(&conn).unwrap();
        assert!(report.ok, "NULL summary ids must not collide: {:?}", report.issues);
    }
}
