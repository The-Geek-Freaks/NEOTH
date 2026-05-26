//! Memory-tier mechanics — Phase 28a R-22.
//!
//! Three tiers anchored on age of the underlying event:
//!   - **Hot** (≤ 7d): live in `idx_episode`, full text, full FTS.
//!   - **Warm** (7-90d): consolidated in `idx_consolidated`. Per-day summary
//!     rows + retained high-importance individual events.
//!   - **Cold** (> 90d): only `idx_longterm` survivors (importance crossed
//!     `PROMOTION_THRESHOLD` at the 90-day boundary). Everything else is
//!     dropped from views but preserved in the immutable archive.
//!
//! Decay schedule (math-validated by Round-3 research agent, 2026-05-14):
//!
//! | tier | decay/day | reinforce |
//! |------|-----------|-----------|
//! | hot  |   0.97    | 0.15·(1−old) |
//! | warm |   0.99    | 0.10·(1−old) |
//! | cold |   0.997   | 0.05·(1−old) |
//!
//! `FORGET_FLOOR = 0.10`. Events below the floor are archived (removed from
//! queryable views, MD file kept).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

/// Days in nanoseconds — used by `tier_for` to bucket events without
/// pulling in chrono on the hot path.
const DAY_NS: u64 = 86_400 * 1_000_000_000;

/// Anything below this importance is dropped from the queryable layer.
pub const FORGET_FLOOR: f64 = 0.10;

/// Importance threshold that promotes warm → cold (kept) versus warm → archived.
pub const PROMOTION_THRESHOLD: f64 = 0.65;

/// Memory tier of an event, derived purely from age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Hot,
    Warm,
    Cold,
}

impl Tier {
    /// Per-tier weight applied to importance during retrieval ranking.
    pub fn weight(self) -> f64 {
        match self {
            Tier::Hot => 1.0,
            Tier::Warm => 0.85,
            Tier::Cold => 0.60,
        }
    }
    /// Per-tier daily recency penalty (subtracted from score).
    pub fn recency_penalty_per_day(self) -> f64 {
        match self {
            Tier::Hot => 0.010,
            Tier::Warm => 0.004,
            Tier::Cold => 0.001,
        }
    }
    /// Per-tier decay factor applied per daily consolidation pass.
    pub fn decay_factor(self) -> f64 {
        match self {
            Tier::Hot => 0.97,
            Tier::Warm => 0.99,
            Tier::Cold => 0.997,
        }
    }
    /// Per-tier reinforcement coefficient. `new = old + k·(1 − old)`.
    pub fn reinforce_coefficient(self) -> f64 {
        match self {
            Tier::Hot => 0.15,
            Tier::Warm => 0.10,
            Tier::Cold => 0.05,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Hot => "hot",
            Tier::Warm => "warm",
            Tier::Cold => "cold",
        }
    }
}

/// Bucket an event into a tier based on its age in nanoseconds.
pub fn tier_for(now_ns: u64, event_ts_ns: u64) -> Tier {
    let age_ns = now_ns.saturating_sub(event_ts_ns);
    if age_ns < 7 * DAY_NS {
        Tier::Hot
    } else if age_ns < 90 * DAY_NS {
        Tier::Warm
    } else {
        Tier::Cold
    }
}

/// Hebbian reinforce: `new = old + k·(1 − old)`, clamped to [0, 1].
///
/// `k` comes from `tier.reinforce_coefficient()`. The formula gives diminishing
/// returns near 1.0 — repeated recalls of an already-high-importance event
/// crawl toward 1.0 rather than overshoot, which keeps the recall ranker stable.
pub fn hebbian_reinforce_value(old: f64, tier: Tier) -> f64 {
    let k = tier.reinforce_coefficient();
    let v = old + k * (1.0 - old);
    v.clamp(0.0, 1.0)
}

/// Hebbian decay: `new = old · decay_factor`. Floor at 0.
pub fn hebbian_decay_value(old: f64, tier: Tier) -> f64 {
    (old * tier.decay_factor()).max(0.0)
}

/// Retrieval ranking score combining importance, tier, and recency.
/// Hard floor at 0 — archive-tier events never score negative.
pub fn ranking_score(importance: f64, tier: Tier, days_since_access: f64) -> f64 {
    (importance * tier.weight() - days_since_access * tier.recency_penalty_per_day()).max(0.0)
}

/// Result of one recall-hit reinforce. Both fields clamped to [0, 1].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReinforceOutcome {
    pub old: f64,
    pub new: f64,
    pub tier: Tier,
}

// `consolidate_pass` lives in `memory::consolidate::run_consolidation_pass`.
// This module owns only the math primitives (decay/reinforce/ranking/tier_for)
// and per-event helpers (`hebbian_reinforce_event`).

/// Apply Hebbian reinforce to one event in `idx_episode` (hot tier). Reads
/// the current importance + ts_ns, computes the new value, writes both
/// `importance` and `last_access_ts` back. Caller is responsible for emitting
/// the audit WAL event (`IMPORTANCE_REINFORCED`) when a writer is available.
///
/// Returns `Ok(None)` if the event_id is unknown (e.g. operator passed a
/// stale id from an archived row). The caller should treat that as a
/// soft-fail, not a panic.
///
/// M-01 (Session 24): this hot-only entry point is kept as a thin wrapper
/// around the tier-aware [`hebbian_reinforce_at_tier`] so existing daemon
/// callsites do not need to change. New code that knows the hit's tier
/// (e.g. `cli/recall.rs`) should call `hebbian_reinforce_at_tier` directly
/// so warm + cold rows also get reinforced on recall hits — pre-fix only
/// the hot-tier branch reinforced, leaving warm/cold importance frozen
/// against active access and violating SPEC `PLAN/SPEC_memory_tiers.md`
/// MT-3 ("Hebbian reinforce on every recall hit, all tiers").
pub fn hebbian_reinforce_event(
    conn: &Connection,
    event_id: i64,
    now_ns: u64,
) -> Result<Option<ReinforceOutcome>> {
    hebbian_reinforce_at_tier(conn, Tier::Hot, event_id, now_ns)
}

/// Apply Hebbian reinforce to one event in the tier's backing table —
/// `idx_episode` for Hot, `idx_consolidated` for Warm, `idx_longterm` for
/// Cold. Returns the old + new importance + tier in a [`ReinforceOutcome`].
///
/// Warm-tier lookup uses `COALESCE(event_id, -id) = ?` so it matches both
/// (a) retained events whose original `idx_episode.event_id` survived the
/// hot→warm migration, and (b) synthesised per-day summary rows where
/// `event_id IS NULL`. The matching pattern mirrors how [`crate::cli::recall`]
/// surfaces warm hits, so any id returned by recall round-trips here.
///
/// Cold-tier rows always have a non-null `event_id` (set by
/// [`crate::memory::consolidate::run_consolidation_pass`]'s warm→cold
/// promotion path — original id when available, synthetic `-row_id - 1`
/// otherwise) and the lookup is the simple `event_id = ?` predicate.
///
/// Returns `Ok(None)` if the row is unknown — soft-fail per `Pick #32`.
pub fn hebbian_reinforce_at_tier(
    conn: &Connection,
    tier: Tier,
    event_id: i64,
    now_ns: u64,
) -> Result<Option<ReinforceOutcome>> {
    use rusqlite::OptionalExtension;
    // SQL is hard-pinned to one table per tier; the table-name is a
    // compile-time literal so this is NOT runtime-format SQL.
    let (select_sql, update_sql) = match tier {
        Tier::Hot => (
            "SELECT importance FROM idx_episode WHERE event_id = ?1",
            "UPDATE idx_episode SET importance = ?1, last_access_ts = ?2 \
             WHERE event_id = ?3",
        ),
        Tier::Warm => (
            "SELECT importance FROM idx_consolidated \
             WHERE COALESCE(event_id, -id) = ?1",
            "UPDATE idx_consolidated SET importance = ?1, last_access_ts = ?2 \
             WHERE COALESCE(event_id, -id) = ?3",
        ),
        Tier::Cold => (
            "SELECT importance FROM idx_longterm WHERE event_id = ?1",
            "UPDATE idx_longterm SET importance = ?1, last_access_ts = ?2 \
             WHERE event_id = ?3",
        ),
    };
    let old: Option<f64> = conn
        .query_row(select_sql, params![event_id], |r| r.get::<_, f64>(0))
        .optional()
        .with_context(|| {
            format!(
                "lookup {tier} row for hebbian reinforce, event_id={event_id}",
                tier = tier.as_str(),
            )
        })?;
    let Some(old) = old else {
        return Ok(None);
    };
    let new = hebbian_reinforce_value(old, tier);
    conn.execute(update_sql, params![new, now_ns as i64, event_id])
        .with_context(|| {
            format!(
                "update {tier} importance after recall hit, event_id={event_id}",
                tier = tier.as_str(),
            )
        })?;
    Ok(Some(ReinforceOutcome { old, new, tier }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn insert_row(conn: &Connection, event_id: i64, ts_ns: i64, importance: f64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, 'x', 'h', ?3, 0)",
            params![event_id, ts_ns, importance],
        )
        .unwrap();
    }

    #[test]
    fn tier_buckets_by_age() {
        let now: u64 = 400 * DAY_NS;
        assert_eq!(tier_for(now, now), Tier::Hot);
        assert_eq!(tier_for(now, now - 3 * DAY_NS), Tier::Hot);
        assert_eq!(tier_for(now, now - 30 * DAY_NS), Tier::Warm);
        assert_eq!(tier_for(now, now - 200 * DAY_NS), Tier::Cold);
    }

    #[test]
    fn hebbian_reinforce_value_diminishing_returns() {
        // From 0.5 in hot: jumps to 0.5 + 0.15 * 0.5 = 0.575.
        let v = hebbian_reinforce_value(0.5, Tier::Hot);
        assert!((v - 0.575).abs() < 1e-6, "got {v}");
        // From 0.95: only goes to 0.95 + 0.15 * 0.05 = 0.9575 (diminishing).
        let v2 = hebbian_reinforce_value(0.95, Tier::Hot);
        assert!((v2 - 0.9575).abs() < 1e-6, "got {v2}");
        // Clamped at 1.0.
        let v3 = hebbian_reinforce_value(1.0, Tier::Hot);
        assert!((v3 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn hebbian_decay_value_is_multiplicative() {
        // Hot 0.97: 0.5 → 0.485.
        let v = hebbian_decay_value(0.5, Tier::Hot);
        assert!((v - 0.485).abs() < 1e-6, "got {v}");
        // Cold 0.997: barely moves.
        let v2 = hebbian_decay_value(0.5, Tier::Cold);
        assert!((v2 - 0.4985).abs() < 1e-6, "got {v2}");
    }

    #[test]
    fn ranking_score_penalises_old_cold_events() {
        // Hot event with importance 0.8, accessed today: 0.8 · 1.0 − 0 = 0.8
        let hot_today = ranking_score(0.8, Tier::Hot, 0.0);
        assert!((hot_today - 0.8).abs() < 1e-6);
        // Cold event with importance 0.5, accessed 100 days ago: 0.5·0.6 − 100·0.001 = 0.2
        let cold_old = ranking_score(0.5, Tier::Cold, 100.0);
        assert!((cold_old - 0.2).abs() < 1e-6, "got {cold_old}");
        // Negative results floor at 0.
        let zero = ranking_score(0.05, Tier::Cold, 1000.0);
        assert_eq!(zero, 0.0);
    }

    #[test]
    fn hebbian_reinforce_event_bumps_importance_and_returns_old_new() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        let now: u64 = 1_700_000_000 * 1_000_000_000;
        insert_row(&conn, 42, now as i64 - (DAY_NS as i64), 0.5);

        let outcome = hebbian_reinforce_event(&conn, 42, now).unwrap().unwrap();
        assert_eq!(outcome.tier, Tier::Hot);
        assert!((outcome.old - 0.5).abs() < 1e-6);
        assert!((outcome.new - 0.575).abs() < 1e-6, "new={}", outcome.new);

        // Re-read from DB to confirm persistence.
        let (imp, last_access): (f64, i64) = conn
            .query_row(
                "SELECT importance, last_access_ts FROM idx_episode WHERE event_id = 42",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!((imp - 0.575).abs() < 1e-6);
        assert_eq!(last_access, now as i64);
    }

    #[test]
    fn hebbian_reinforce_event_returns_none_for_unknown_id() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        let out = hebbian_reinforce_event(&conn, 99_999, 0).unwrap();
        assert!(out.is_none());
    }

    // ── M-01 (Session 24) tier-aware reinforce ────────────────────────
    //
    // Pre-fix `hebbian_reinforce_event` only touched `idx_episode`; the
    // recall path explicitly skipped warm + cold hits, so frequently-
    // recalled consolidated/long-term memories decayed against active
    // access. These tests pin the new tier-dispatch contract: each
    // tier writes to its own backing table, and the warm-tier COALESCE
    // trick handles both retained-event + synthesised summary rows.

    fn insert_consolidated(conn: &Connection, event_id: Option<i64>, importance: f64) -> i64 {
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-01-01', ?1, 'warm', 'h', ?2, 0, 0)",
            params![event_id, importance],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn insert_longterm(conn: &Connection, event_id: i64, importance: f64) {
        conn.execute(
            "INSERT INTO idx_longterm \
             (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
             VALUES (?1, 'cold', 'h', ?2, 0, 0, NULL)",
            params![event_id, importance],
        )
        .unwrap();
    }

    #[test]
    fn hebbian_reinforce_at_tier_warm_retained_row_uses_event_id() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        let _row_id = insert_consolidated(&conn, Some(123), 0.5);
        let now: u64 = 1_700_000_000 * 1_000_000_000;
        let out = hebbian_reinforce_at_tier(&conn, Tier::Warm, 123, now)
            .unwrap()
            .unwrap();
        assert_eq!(out.tier, Tier::Warm);
        // Warm k=0.10: 0.5 → 0.55
        assert!((out.new - 0.55).abs() < 1e-6, "new={}", out.new);
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_consolidated WHERE event_id = 123",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((imp - 0.55).abs() < 1e-6);
    }

    #[test]
    fn hebbian_reinforce_at_tier_warm_summary_row_uses_negative_id() {
        // Summary rows have NULL event_id; recall surfaces them with
        // synthetic event_id = -id. The reinforce path must route the
        // negative id back to the same row via COALESCE.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        let row_id = insert_consolidated(&conn, None, 0.4);
        let now: u64 = 1_700_000_000 * 1_000_000_000;
        let synthetic_id = -row_id;
        let out = hebbian_reinforce_at_tier(&conn, Tier::Warm, synthetic_id, now)
            .unwrap()
            .unwrap();
        // 0.4 + 0.10 * 0.6 = 0.46
        assert!((out.new - 0.46).abs() < 1e-6, "new={}", out.new);
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_consolidated WHERE id = ?1",
                params![row_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!((imp - 0.46).abs() < 1e-6);
    }

    #[test]
    fn hebbian_reinforce_at_tier_cold_updates_longterm() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        insert_longterm(&conn, 555, 0.7);
        let now: u64 = 1_700_000_000 * 1_000_000_000;
        let out = hebbian_reinforce_at_tier(&conn, Tier::Cold, 555, now)
            .unwrap()
            .unwrap();
        assert_eq!(out.tier, Tier::Cold);
        // Cold k=0.05: 0.7 + 0.05 * 0.3 = 0.715
        assert!((out.new - 0.715).abs() < 1e-6, "new={}", out.new);
        let (imp, last): (f64, i64) = conn
            .query_row(
                "SELECT importance, last_access_ts FROM idx_longterm WHERE event_id = 555",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!((imp - 0.715).abs() < 1e-6);
        assert_eq!(last, now as i64);
    }

    #[test]
    fn hebbian_reinforce_at_tier_unknown_id_returns_none_per_tier() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        let now: u64 = 1;
        assert!(
            hebbian_reinforce_at_tier(&conn, Tier::Hot, 1, now)
                .unwrap()
                .is_none()
        );
        assert!(
            hebbian_reinforce_at_tier(&conn, Tier::Warm, 1, now)
                .unwrap()
                .is_none()
        );
        assert!(
            hebbian_reinforce_at_tier(&conn, Tier::Cold, 1, now)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn hebbian_reinforce_event_still_targets_hot_only() {
        // Back-compat: the old hot-only entry point must keep its
        // pre-M-01 behaviour so daemon callsites that don't carry a
        // tier label still reinforce idx_episode rows.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        let now: u64 = 1_700_000_000 * 1_000_000_000;
        insert_row(&conn, 7, now as i64 - (DAY_NS as i64), 0.3);
        // Warm row with the same event_id must NOT be touched.
        insert_consolidated(&conn, Some(7), 0.3);
        let out = hebbian_reinforce_event(&conn, 7, now).unwrap().unwrap();
        assert_eq!(out.tier, Tier::Hot);
        let warm_imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_consolidated WHERE event_id = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (warm_imp - 0.3).abs() < 1e-9,
            "warm row must be untouched, got {warm_imp}",
        );
    }

    // Consolidation-pass tests moved to memory::consolidate alongside the
    // implementation. This module's tests stay focused on the math + the
    // single-event reinforce helper.

    // ── V03-05 (Session 13) Hebbian invariant grid sweep ──────────────
    //
    // Project policy is deterministic-iter instead of adding the
    // proptest crate (see V02-04 backfill 2026-05-16). Each sweep
    // walks a fixed grid of (importance, tier) combinations and pins
    // the math invariants that the recall ranker depends on. Any
    // future refactor of `hebbian_*` or `ranking_score` that breaks
    // a documented bound fails the build deterministically.

    const IMPORTANCE_GRID: &[f64] = &[0.0, 0.05, 0.1, 0.25, 0.5, 0.6, 0.75, 0.9, 0.95, 1.0];
    const TIER_GRID: &[Tier] = &[Tier::Hot, Tier::Warm, Tier::Cold];

    #[test]
    fn hebbian_decay_never_increases_value() {
        // Invariant 1: decay is monotonic non-increasing — the new
        // value is always ≤ the old. Multiplicative formula with
        // factors ≤ 1.0; floor at 0 enforced by `.max(0.0)`.
        for &old in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                let new = hebbian_decay_value(old, tier);
                assert!(
                    new <= old + 1e-12,
                    "decay must not increase: old={old} tier={tier:?} new={new}",
                );
            }
        }
    }

    #[test]
    fn hebbian_decay_stays_non_negative() {
        // Invariant 2: decay never produces negative values even at
        // the lower end of importance + any tier.
        for &old in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                let new = hebbian_decay_value(old, tier);
                assert!(
                    new >= 0.0,
                    "decay must be ≥ 0: old={old} tier={tier:?} new={new}",
                );
            }
        }
    }

    #[test]
    fn hebbian_decay_zero_stays_zero() {
        // Invariant 3: the zero importance is a fixed point — no
        // amount of decay can lift it. Pins the floor semantics.
        for &tier in TIER_GRID {
            assert_eq!(hebbian_decay_value(0.0, tier), 0.0, "tier={tier:?}");
        }
    }

    #[test]
    fn hebbian_decay_iterated_converges_to_zero() {
        // Invariant 4: under repeated decay every importance value
        // approaches zero (no fixed point above 0 for any tier with
        // decay_factor < 1.0). Pins the "stale memories fade away"
        // contract the consolidation pass relies on.
        for &start in &[0.5, 1.0] {
            for &tier in TIER_GRID {
                let mut v = start;
                for _ in 0..1000 {
                    v = hebbian_decay_value(v, tier);
                }
                // After 1000 iterations of decay-factor < 1.0 the
                // value must be vanishingly small. Archive tier has
                // the closest-to-1 decay factor, so its 1000th iter
                // is the worst case. Bound generously at 0.1.
                assert!(
                    v < 0.1,
                    "1000-iter decay must approach 0: tier={tier:?} v={v}",
                );
            }
        }
    }

    #[test]
    fn hebbian_reinforce_never_decreases_value() {
        // Invariant 5: reinforce is monotonic non-decreasing — the
        // new value is always ≥ the old. Formula `new = old + k·(1 −
        // old)` with k ∈ (0, 1) yields a value between old and 1.
        for &old in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                let new = hebbian_reinforce_value(old, tier);
                assert!(
                    new >= old - 1e-12,
                    "reinforce must not decrease: old={old} tier={tier:?} new={new}",
                );
            }
        }
    }

    #[test]
    fn hebbian_reinforce_stays_within_unit_interval() {
        // Invariant 6: reinforce always produces a value in [0, 1].
        // Clamp at 1.0 prevents overshoot at the top of the range.
        for &old in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                let new = hebbian_reinforce_value(old, tier);
                assert!(
                    (0.0..=1.0).contains(&new),
                    "reinforce out of unit interval: old={old} tier={tier:?} new={new}",
                );
            }
        }
    }

    #[test]
    fn hebbian_reinforce_one_stays_one() {
        // Invariant 7: 1.0 is a fixed point under reinforce. Pins
        // the "max importance can't overflow" contract.
        for &tier in TIER_GRID {
            assert!(
                (hebbian_reinforce_value(1.0, tier) - 1.0).abs() < 1e-12,
                "tier={tier:?}",
            );
        }
    }

    #[test]
    fn ranking_score_stays_non_negative_across_grid() {
        // Invariant 8: `ranking_score` has a hard floor at 0 via the
        // `.max(0.0)` cap, so even extremely old/cold events never
        // score negative. Sweep importance × tier × days_since_access.
        const DAY_GRID: &[f64] = &[0.0, 0.5, 1.0, 7.0, 30.0, 100.0, 365.0, 10000.0];
        for &imp in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                for &days in DAY_GRID {
                    let score = ranking_score(imp, tier, days);
                    assert!(
                        score >= 0.0,
                        "ranking_score must be ≥ 0: imp={imp} tier={tier:?} days={days} score={score}",
                    );
                    assert!(
                        score.is_finite(),
                        "ranking_score must be finite: imp={imp} tier={tier:?} days={days}",
                    );
                }
            }
        }
    }

    #[test]
    fn ranking_score_monotonic_in_days_since_access() {
        // Invariant 9: for the same importance + tier, increasing
        // `days_since_access` never INCREASES the ranking score (it
        // may stay at the 0-floor once the penalty exceeds the base).
        for &imp in IMPORTANCE_GRID {
            for &tier in TIER_GRID {
                let mut prev = f64::INFINITY;
                for days in 0..200 {
                    let score = ranking_score(imp, tier, days as f64);
                    assert!(
                        score <= prev + 1e-12,
                        "ranking_score must be monotonic non-increasing in days: imp={imp} tier={tier:?} days={days} score={score} prev={prev}",
                    );
                    prev = score;
                }
            }
        }
    }
}
