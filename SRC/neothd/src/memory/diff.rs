//! KF-02 (Session 24) — region-scoped memory diff.
//!
//! Operator-facing diagnostic: "what changed in the Amygdala
//! between 7d ago and now?" The answer comes back as 3 buckets:
//!
//! - **Added** — rows whose `ts_ns` falls inside the window
//!   `(from, to]`. New episodic content the region picked up.
//! - **Reinforced** — rows that existed BEFORE the window but
//!   whose `last_access_ts` falls inside it. Operator (or the
//!   recall path) touched them, bumping importance.
//! - **Forgot** — rows whose importance dropped BELOW
//!   `FORGET_FLOOR` during the window. Pulled from a
//!   forensic-replay-snapshot heuristic: we treat the current
//!   importance as the END state + classify rows that ended
//!   below the floor as "forgot in window" if their ts_ns is
//!   ≤ from (i.e. they pre-existed) AND their importance < floor.
//!
//! ## Why a snapshot-pair heuristic instead of full time-series
//!
//! Storing per-row importance history would require either a
//! second table or per-frame WAL audit at every reinforce hit
//! (M-02 ships the 0x93 frame but doesn't accumulate). The
//! snapshot-pair approach reads the CURRENT state of
//! `idx_episode` + classifies rows by their `ts_ns` +
//! `last_access_ts` + `importance` against the window edges.
//! Operator gets a useful approximation today; full time-series
//! diff lands when a separate "memory journal" surface ships
//! (post-v0.9 PROGRESS placeholder).

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::memory::regions::{AMYGDALA_THRESHOLD, MemoryRegion};
use crate::memory::tiers::FORGET_FLOOR;

/// One row in the diff. Variants distinguish the operator-visible
/// category. `current_importance` + `ts_ns` carry enough metadata
/// for the CLI renderer to format a useful one-line summary.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiffRow {
    pub event_id: i64,
    pub text: String,
    pub current_importance: f64,
    pub ts_ns: i64,
    pub last_access_ts: i64,
    pub category: DiffCategory,
}

/// Three-bucket classification. Pinned `serde(rename_all = "snake_case")`
/// for stable wire form across CLI / GUI / JSON consumers.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DiffCategory {
    /// Row's `ts_ns` falls strictly inside `(from, to]`.
    Added,
    /// Row pre-existed (`ts_ns <= from`) but `last_access_ts`
    /// falls inside `(from, to]` — reinforced during the window.
    Reinforced,
    /// Row pre-existed but current importance is below
    /// `FORGET_FLOOR` — the consolidation pass has it queued for
    /// sweep (or already swept).
    Forgot,
}

impl DiffCategory {
    /// Stable wire form. Drift-guard pinned.
    pub fn as_str(self) -> &'static str {
        match self {
            DiffCategory::Added => "added",
            DiffCategory::Reinforced => "reinforced",
            DiffCategory::Forgot => "forgot",
        }
    }
}

/// Aggregate diff result. Each bucket sorted by `(importance DESC,
/// ts_ns DESC)` so the most-salient + most-recent rows lead within
/// each section. Summary counts always exact (independent of
/// `limit` parameter).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiffReport {
    pub added: Vec<DiffRow>,
    pub reinforced: Vec<DiffRow>,
    pub forgot: Vec<DiffRow>,
    pub added_count: i64,
    pub reinforced_count: i64,
    pub forgot_count: i64,
}

/// Build the diff. `region` scopes by `event_type IN (...)` (for
/// the 5 primary regions) or `importance >= AMYGDALA_THRESHOLD`
/// (for Amygdala overlay). `from_ns` + `to_ns` are inclusive-low,
/// inclusive-high (`from_ns ≤ ts_ns ≤ to_ns` for "added"). `limit`
/// caps each bucket's vec independently; summary counts always
/// exact.
///
/// Pre-rule: `from_ns < to_ns` — caller-side responsibility, but
/// the function returns Ok(empty buckets) gracefully when reversed
/// rather than erroring.
pub fn diff_report(
    conn: &Connection,
    region: MemoryRegion,
    from_ns: i64,
    to_ns: i64,
    limit: usize,
) -> Result<DiffReport> {
    // Build the region predicate fragment. Amygdala uses
    // importance overlay; others use event_type IN list.
    let (region_sql, region_binds): (String, Vec<rusqlite::types::Value>) = match region {
        MemoryRegion::Amygdala => (
            "importance >= ?".to_string(),
            vec![AMYGDALA_THRESHOLD.into()],
        ),
        primary => {
            let types: Vec<u8> = (0u8..=255u8)
                .filter(|et| crate::memory::regions::classify_region(*et) == primary)
                .collect();
            let placeholders = vec!["?"; types.len()].join(",");
            (
                format!("event_type IN ({placeholders})"),
                types.iter().map(|et| (*et as i64).into()).collect(),
            )
        }
    };

    // ── ADDED bucket — rows ts_ns ∈ [from, to] ────────────────────
    let added = query_bucket(
        conn,
        &format!(
            "SELECT event_id, text, importance, ts_ns, last_access_ts \
             FROM idx_episode WHERE {region_sql} AND ts_ns >= ? AND ts_ns <= ? \
             ORDER BY importance DESC, ts_ns DESC LIMIT ?",
        ),
        &region_binds,
        from_ns,
        to_ns,
        limit,
        DiffCategory::Added,
    )?;
    let added_count = query_count(
        conn,
        &format!(
            "SELECT count(*) FROM idx_episode WHERE {region_sql} \
             AND ts_ns >= ? AND ts_ns <= ?",
        ),
        &region_binds,
        from_ns,
        to_ns,
    )?;

    // ── REINFORCED bucket — pre-existed + last_access in window ───
    //
    // Bind shape differs from `query_bucket`'s (from, to) template
    // (we need ts_ns < ?, last>=?, last<=?, limit), so inline the
    // build to keep the placeholders + binds aligned.
    let reinforced = {
        let mut sql = String::from(
            "SELECT event_id, text, importance, ts_ns, last_access_ts \
             FROM idx_episode WHERE ",
        );
        sql.push_str(&region_sql);
        sql.push_str(
            " AND ts_ns < ? AND last_access_ts >= ? AND last_access_ts <= ? \
             ORDER BY importance DESC, ts_ns DESC LIMIT ?",
        );
        let mut binds: Vec<rusqlite::types::Value> = region_binds.clone();
        binds.push(from_ns.into());
        binds.push(from_ns.into());
        binds.push(to_ns.into());
        binds.push((limit as i64).into());
        let bind_refs: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_refs.iter().copied()), |r| {
                Ok(DiffRow {
                    event_id: r.get(0)?,
                    text: r.get(1)?,
                    current_importance: r.get(2)?,
                    ts_ns: r.get(3)?,
                    last_access_ts: r.get(4)?,
                    category: DiffCategory::Reinforced,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let reinforced_count = {
        let mut sql = String::from("SELECT count(*) FROM idx_episode WHERE ");
        sql.push_str(&region_sql);
        sql.push_str(" AND ts_ns < ? AND last_access_ts >= ? AND last_access_ts <= ?");
        let mut binds: Vec<rusqlite::types::Value> = region_binds.clone();
        binds.push(from_ns.into());
        binds.push(from_ns.into());
        binds.push(to_ns.into());
        let bind_refs: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        conn.query_row(
            &sql,
            rusqlite::params_from_iter(bind_refs.iter().copied()),
            |r| r.get::<_, i64>(0),
        )?
    };

    // ── FORGOT bucket — pre-existed + current importance < floor ──
    let forgot = {
        let mut sql = String::from(
            "SELECT event_id, text, importance, ts_ns, last_access_ts \
             FROM idx_episode WHERE ",
        );
        sql.push_str(&region_sql);
        sql.push_str(
            " AND ts_ns < ? AND importance < ? \
             ORDER BY importance ASC, ts_ns DESC LIMIT ?",
        );
        let mut binds: Vec<rusqlite::types::Value> = region_binds.clone();
        binds.push(from_ns.into());
        binds.push(FORGET_FLOOR.into());
        binds.push((limit as i64).into());
        let bind_refs: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(rusqlite::params_from_iter(bind_refs.iter().copied()), |r| {
            Ok(DiffRow {
                event_id: r.get(0)?,
                text: r.get(1)?,
                current_importance: r.get(2)?,
                ts_ns: r.get(3)?,
                last_access_ts: r.get(4)?,
                category: DiffCategory::Forgot,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let forgot_count = {
        let mut sql = String::from("SELECT count(*) FROM idx_episode WHERE ");
        sql.push_str(&region_sql);
        sql.push_str(" AND ts_ns < ? AND importance < ?");
        let mut binds: Vec<rusqlite::types::Value> = region_binds.clone();
        binds.push(from_ns.into());
        binds.push(FORGET_FLOOR.into());
        let bind_refs: Vec<&dyn rusqlite::ToSql> =
            binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        conn.query_row(
            &sql,
            rusqlite::params_from_iter(bind_refs.iter().copied()),
            |r| r.get::<_, i64>(0),
        )?
    };

    Ok(DiffReport {
        added,
        reinforced,
        forgot,
        added_count,
        reinforced_count,
        forgot_count,
    })
}

/// Helper for the simple `from + to + limit + category` shaped queries.
/// Added bucket uses this directly. Reinforced + Forgot inline their
/// SQL because their bind shape differs.
fn query_bucket(
    conn: &Connection,
    sql: &str,
    region_binds: &[rusqlite::types::Value],
    from_ns: i64,
    to_ns: i64,
    limit: usize,
    category: DiffCategory,
) -> Result<Vec<DiffRow>> {
    let mut binds: Vec<rusqlite::types::Value> = region_binds.to_vec();
    binds.push(from_ns.into());
    binds.push(to_ns.into());
    binds.push((limit as i64).into());
    let bind_refs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bind_refs.iter().copied()), |r| {
            Ok(DiffRow {
                event_id: r.get(0)?,
                text: r.get(1)?,
                current_importance: r.get(2)?,
                ts_ns: r.get(3)?,
                last_access_ts: r.get(4)?,
                category,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn query_count(
    conn: &Connection,
    sql: &str,
    region_binds: &[rusqlite::types::Value],
    from_ns: i64,
    to_ns: i64,
) -> Result<i64> {
    let mut binds: Vec<rusqlite::types::Value> = region_binds.to_vec();
    binds.push(from_ns.into());
    binds.push(to_ns.into());
    let bind_refs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    Ok(conn.query_row(
        sql,
        rusqlite::params_from_iter(bind_refs.iter().copied()),
        |r| r.get::<_, i64>(0),
    )?)
}

/// Parse a `--from` / `--to` operator-typed string into nanoseconds.
/// Supports:
/// - `now` → current wall clock
/// - `<N>d` / `<N>h` / `<N>m` / `<N>s` (relative-to-now subtractive)
/// - bare integer → interpreted as `ts_ns` directly
///
/// Operator-facing helper for the CLI side; pure-fn so the parser
/// is testable.
pub fn parse_window_arg(s: &str, now_ns: i64) -> Result<i64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("window arg must be non-empty (e.g. `7d`, `now`, or ns)");
    }
    if trimmed.eq_ignore_ascii_case("now") {
        return Ok(now_ns);
    }
    // Relative-to-now shape: trailing s/m/h/d
    let last = trimmed.chars().last().unwrap();
    if matches!(last, 's' | 'm' | 'h' | 'd' | 'S' | 'M' | 'H' | 'D') {
        let n: i64 = trimmed[..trimmed.len() - 1]
            .parse()
            .map_err(|_| anyhow::anyhow!("bad number in window arg `{trimmed}`"))?;
        let mult: i64 = match last.to_ascii_lowercase() {
            's' => 1_000_000_000,
            'm' => 60 * 1_000_000_000,
            'h' => 3_600 * 1_000_000_000,
            'd' => 86_400 * 1_000_000_000,
            _ => unreachable!(),
        };
        let delta = n
            .checked_mul(mult)
            .ok_or_else(|| anyhow::anyhow!("window arg overflows i64 nanoseconds"))?;
        return Ok(now_ns.saturating_sub(delta));
    }
    // Bare integer = ts_ns.
    trimmed
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("unrecognised window arg `{trimmed}`"))
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

    fn seed(
        conn: &Connection,
        event_id: i64,
        event_type: u8,
        text: &str,
        importance: f64,
        ts_ns: i64,
        last_access_ts: i64,
    ) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id,
                event_type as i64,
                ts_ns,
                text,
                format!("h{event_id}"),
                importance,
                last_access_ts,
            ],
        )
        .unwrap();
    }

    // ── parse_window_arg ──────────────────────────────────────────────

    #[test]
    fn parse_window_now_returns_current() {
        let now = 1_700_000_000_000_000_000;
        assert_eq!(parse_window_arg("now", now).unwrap(), now);
        assert_eq!(parse_window_arg("NOW", now).unwrap(), now);
    }

    #[test]
    fn parse_window_relative_subtracts() {
        let now = 1_700_000_000_000_000_000;
        let day_ns = 86_400 * 1_000_000_000;
        assert_eq!(parse_window_arg("7d", now).unwrap(), now - 7 * day_ns);
        assert_eq!(
            parse_window_arg("2h", now).unwrap(),
            now - 2 * 3_600 * 1_000_000_000
        );
        assert_eq!(
            parse_window_arg("30m", now).unwrap(),
            now - 30 * 60 * 1_000_000_000
        );
        assert_eq!(
            parse_window_arg("45s", now).unwrap(),
            now - 45 * 1_000_000_000
        );
    }

    #[test]
    fn parse_window_bare_integer_used_as_ts_ns() {
        assert_eq!(
            parse_window_arg("1700000000000000000", 0).unwrap(),
            1_700_000_000_000_000_000
        );
    }

    #[test]
    fn parse_window_rejects_garbage() {
        for bad in ["", "  ", "abc", "7x", "d", "-"] {
            assert!(parse_window_arg(bad, 0).is_err(), "must reject `{bad}`");
        }
    }

    // ── DiffCategory + diff_report ────────────────────────────────────

    #[test]
    fn category_as_str_pinned_for_audit() {
        assert_eq!(DiffCategory::Added.as_str(), "added");
        assert_eq!(DiffCategory::Reinforced.as_str(), "reinforced");
        assert_eq!(DiffCategory::Forgot.as_str(), "forgot");
    }

    #[test]
    fn report_empty_db_returns_zeros() {
        let (_dir, conn) = open();
        let r = diff_report(&conn, MemoryRegion::Hippocampus, 0, 1_000_000, 50).unwrap();
        assert_eq!(r.added_count, 0);
        assert_eq!(r.reinforced_count, 0);
        assert_eq!(r.forgot_count, 0);
        assert!(r.added.is_empty());
    }

    #[test]
    fn added_bucket_contains_rows_with_ts_in_window() {
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 2_000;
        // Inside window — added.
        seed(&conn, 1, 0x01, "new-a", 0.5, 1_500, 1_500);
        seed(&conn, 2, 0x01, "new-b", 0.5, 1_900, 1_900);
        // Outside window (before) — NOT added.
        seed(&conn, 3, 0x01, "before", 0.5, 500, 500);
        // Outside window (after) — NOT added.
        seed(&conn, 4, 0x01, "after", 0.5, 5_000, 5_000);

        let r = diff_report(&conn, MemoryRegion::Hippocampus, from, to, 100).unwrap();
        assert_eq!(r.added_count, 2);
        let ids: Vec<i64> = r.added.iter().map(|d| d.event_id).collect();
        assert!(ids.contains(&1) && ids.contains(&2));
        assert!(!ids.contains(&3) && !ids.contains(&4));
    }

    #[test]
    fn reinforced_bucket_contains_pre_existing_with_access_in_window() {
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 2_000;
        // Pre-existed + accessed inside window → reinforced.
        seed(&conn, 1, 0x01, "touched", 0.7, 500, 1_500);
        // Pre-existed + NOT accessed in window → not reinforced.
        seed(&conn, 2, 0x01, "stale", 0.7, 500, 800);
        // Created inside window → added, not reinforced.
        seed(&conn, 3, 0x01, "new", 0.5, 1_500, 1_500);

        let r = diff_report(&conn, MemoryRegion::Hippocampus, from, to, 100).unwrap();
        assert_eq!(r.reinforced_count, 1);
        assert_eq!(r.reinforced[0].event_id, 1);
    }

    #[test]
    fn forgot_bucket_contains_pre_existing_below_floor() {
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 2_000;
        // Pre-existed + importance < FORGET_FLOOR → forgot.
        seed(&conn, 1, 0x01, "forgotten", 0.05, 500, 500);
        // Pre-existed + healthy importance → not forgot.
        seed(&conn, 2, 0x01, "alive", 0.7, 500, 500);
        // Created inside window — not forgot (was never alive long enough).
        seed(&conn, 3, 0x01, "new-low", 0.05, 1_500, 1_500);

        let r = diff_report(&conn, MemoryRegion::Hippocampus, from, to, 100).unwrap();
        assert_eq!(r.forgot_count, 1);
        assert_eq!(r.forgot[0].event_id, 1);
    }

    #[test]
    fn region_scope_filters_correctly() {
        // Hippocampus diff must NOT include Insula rows + vice versa.
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 2_000;
        seed(&conn, 1, 0x01, "hippo-new", 0.5, 1_500, 1_500); // Hippocampus
        seed(&conn, 2, 0x32, "insula-new", 0.5, 1_500, 1_500); // Insula

        let hippo = diff_report(&conn, MemoryRegion::Hippocampus, from, to, 100).unwrap();
        assert_eq!(hippo.added_count, 1);
        assert_eq!(hippo.added[0].event_id, 1);

        let insula = diff_report(&conn, MemoryRegion::Insula, from, to, 100).unwrap();
        assert_eq!(insula.added_count, 1);
        assert_eq!(insula.added[0].event_id, 2);
    }

    #[test]
    fn amygdala_region_scopes_by_importance_overlay() {
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 2_000;
        // High-importance Cerebellum row + low-importance Cerebellum row,
        // both inside the time window.
        seed(&conn, 1, 0x65, "low-cere", 0.5, 1_500, 1_500);
        seed(&conn, 2, 0x65, "salient-cere", 0.95, 1_500, 1_500);

        let r = diff_report(&conn, MemoryRegion::Amygdala, from, to, 100).unwrap();
        // Amygdala overlay catches only the high-importance one.
        assert_eq!(r.added_count, 1);
        assert_eq!(r.added[0].event_id, 2);
    }

    #[test]
    fn limit_caps_each_bucket_independently() {
        let (_dir, conn) = open();
        let from = 1_000;
        let to = 10_000;
        // 5 rows in each bucket.
        for i in 0..5 {
            seed(&conn, 100 + i, 0x01, "added", 0.5, 1_500 + i, 1_500 + i);
            seed(&conn, 200 + i, 0x01, "reinforced", 0.7, 500, 1_500 + i);
            seed(&conn, 300 + i, 0x01, "forgot", 0.05, 500, 500 + i);
        }

        let r = diff_report(&conn, MemoryRegion::Hippocampus, from, to, 2).unwrap();
        // vec caps at 2; counts are exact.
        assert_eq!(r.added.len(), 2);
        assert_eq!(r.reinforced.len(), 2);
        assert_eq!(r.forgot.len(), 2);
        assert_eq!(r.added_count, 5);
        assert_eq!(r.reinforced_count, 5);
        assert_eq!(r.forgot_count, 5);
    }

    #[test]
    fn reversed_window_returns_empty_buckets_gracefully() {
        // from > to → no rows match the BETWEEN. Caller-side
        // mistake; function returns Ok(empty) rather than erroring.
        let (_dir, conn) = open();
        seed(&conn, 1, 0x01, "x", 0.5, 1_500, 1_500);
        let r = diff_report(&conn, MemoryRegion::Hippocampus, 2_000, 1_000, 100).unwrap();
        assert_eq!(r.added_count, 0);
        assert_eq!(r.reinforced_count, 0);
    }
}
