//! GOLD-ADAPT-JV-MEM-15 — Memory quality scorecard (5-dim, A-F grade).
//!
//! Computes a composite quality score over five independent dimensions derived
//! from signals already persisted in the memory SQLite store:
//!
//!   1. **accuracy**    — Hebbian reinforcement rate: fraction of surfaced
//!      memories that the operator re-reinforced (co-access / manual confirm).
//!      High reinforcement = memories are accurate / useful.
//!   2. **completeness** — Recall hit rate: fraction of non-skip recall
//!      queries that returned at least one result. Low hit rate = gaps.
//!   3. **consistency** — Inverse of pending contradiction density: pending
//!      contradiction pairs vs total active verified facts. Zero pending = 1.0.
//!   4. **freshness**   — Fraction of hot-tier episodes accessed within the
//!      last 7 days (last_access_ts > now-7d). Stale hot rows drag this down.
//!   5. **attribution** — Fraction of active groundtruth facts that carry a
//!      non-empty source tag (i.e. the operator knows where the fact came from).
//!
//! Weighted composite (weights sum to 1.0):
//!   accuracy 0.30 + completeness 0.25 + consistency 0.20 +
//!   freshness 0.15 + attribution 0.10
//!
//! Grade mapping:
//!   composite ≥ 0.90 → A
//!              ≥ 0.80 → B
//!              ≥ 0.70 → C   (HEALTHY threshold)
//!              ≥ 0.60 → D
//!              ≥ 0.50 → E
//!              < 0.50  → F
//!
//! HEALTHY_THRESHOLD = 0.70 (grade C and above).
//!
//! ## Usage
//!
//! The daemon's `monitor_cron` calls [`compute_quality_scorecard`] every tick
//! (when the feature is enabled) and appends the result to a
//! [`ScorecardHistory`] ring buffer (7 days / `HISTORY_CAP` entries).
//!
//! All store access is read-only. No WAL writes happen here.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants

/// Composite score at or above which memory quality is considered healthy.
pub const HEALTHY_THRESHOLD: f64 = 0.70;

/// Maximum number of history entries kept in [`ScorecardHistory`] (~7 days of
/// hourly ticks, or any other cadence — the cap is time-agnostic).
pub const HISTORY_CAP: usize = 168; // 7 * 24 hourly snapshots

/// Dimension weights. Must sum to 1.0.
const W_ACCURACY: f64 = 0.30;
const W_COMPLETENESS: f64 = 0.25;
const W_CONSISTENCY: f64 = 0.20;
const W_FRESHNESS: f64 = 0.15;
const W_ATTRIBUTION: f64 = 0.10;

/// Minimum non-skip recall count before accuracy / completeness are considered
/// trustworthy (cold-start guard — returns 0.5 below this).
const MIN_RECALL_SAMPLES: u32 = 5;

// ---------------------------------------------------------------------------
// Public types

/// A-F letter grade derived from the composite score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    E,
    F,
}

impl Grade {
    /// Compute grade from a composite score in `[0, 1]`.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.90 {
            Grade::A
        } else if score >= 0.80 {
            Grade::B
        } else if score >= 0.70 {
            Grade::C
        } else if score >= 0.60 {
            Grade::D
        } else if score >= 0.50 {
            Grade::E
        } else {
            Grade::F
        }
    }

    /// String label ("A" … "F").
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::E => "E",
            Grade::F => "F",
        }
    }

    /// True when the grade indicates a healthy store (C or above).
    pub fn is_healthy(self) -> bool {
        matches!(self, Grade::A | Grade::B | Grade::C)
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Raw input signals read from the memory store.
///
/// Separated so `compute_quality_scorecard_from_stats` is fully pure and
/// unit-testable without a real SQLite connection.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryStats {
    // ── accuracy / completeness (from idx_recall_events) ─────────────────────
    /// Total non-skip recall events in the recent window.
    pub non_skip_recall_count: u32,
    /// Non-skip recalls that returned ≥ 1 result.
    pub recall_hits: u32,
    /// Sum of `reinforced_count / result_count` over non-empty, non-skip rows.
    /// The caller computes this sum; we divide by `non_empty_count` here.
    pub reinforcement_ratio_sum: f64,
    /// Number of non-empty, non-skip rows (denominator for reinforcement_rate).
    pub non_empty_count: u32,

    // ── consistency (from idx_contradictions + idx_groundtruth) ──────────────
    /// Active verified facts (revoked_at IS NULL, fact_state = 'verified').
    pub verified_fact_count: u64,
    /// Pending contradiction pairs (decision = 'pending').
    pub pending_contradiction_count: u64,

    // ── freshness (from idx_episode) ─────────────────────────────────────────
    /// Hot-tier episodes (all of idx_episode).
    pub hot_episode_count: u64,
    /// Hot-tier episodes with last_access_ts > (now_unix - 7*86400)*1_000_000_000.
    /// Zero means none accessed recently — but we treat an empty store as
    /// freshness 1.0 (no data = nothing stale).
    pub recently_accessed_count: u64,

    // ── attribution (from idx_groundtruth) ───────────────────────────────────
    /// Active facts (revoked_at IS NULL, any fact_state).
    pub active_fact_count: u64,
    /// Active facts with a non-empty source column.
    pub attributed_fact_count: u64,
}

/// Per-dimension scores (each in `[0, 1]`) + the weighted composite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityScorecard {
    /// Unix timestamp when this scorecard was computed.
    pub ts_unix: i64,
    /// Raw accuracy score (Hebbian reinforcement rate).
    pub accuracy: f64,
    /// Raw completeness score (recall hit rate).
    pub completeness: f64,
    /// Raw consistency score (1 - pending_contradiction_density).
    pub consistency: f64,
    /// Raw freshness score (recently-accessed hot-row fraction).
    pub freshness: f64,
    /// Raw attribution score (attributed-fact fraction).
    pub attribution: f64,
    /// Weighted composite of all five dimensions.
    pub composite: f64,
    /// Letter grade derived from the composite score.
    pub grade: Grade,
    /// True when composite ≥ HEALTHY_THRESHOLD.
    pub is_healthy: bool,
    /// Number of non-skip recall samples used for accuracy/completeness.
    pub sample_count: u32,
    /// True when sample_count ≥ MIN_RECALL_SAMPLES (cold-start guard).
    pub data_sufficient: bool,
}

/// A rolling history of recent scorecards (ring buffer, capped at
/// `HISTORY_CAP`). Lives in the monitor-cron loop state.
#[derive(Debug, Default, Clone)]
pub struct ScorecardHistory {
    entries: Vec<QualityScorecard>,
}

impl ScorecardHistory {
    /// Push a new entry, dropping the oldest when over capacity.
    pub fn push(&mut self, sc: QualityScorecard) {
        if self.entries.len() >= HISTORY_CAP {
            self.entries.remove(0);
        }
        self.entries.push(sc);
    }

    /// Most-recent entry, if any.
    pub fn latest(&self) -> Option<&QualityScorecard> {
        self.entries.last()
    }

    /// All entries (oldest-first).
    pub fn entries(&self) -> &[QualityScorecard] {
        &self.entries
    }

    /// Number of entries stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Minimum composite in the window (or 0.0 when empty).
    pub fn min_composite(&self) -> f64 {
        self.entries
            .iter()
            .map(|e| e.composite)
            .fold(f64::INFINITY, f64::min)
            // INFINITY when empty (fold over empty iter) → clamp to [0, 1]
            .clamp(0.0, 1.0)
    }

    /// True when all entries in the window are unhealthy (grade D/E/F).
    /// A single healthy entry in the window counts as "not persistently bad".
    pub fn is_persistently_unhealthy(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|e| !e.is_healthy)
    }
}

// ---------------------------------------------------------------------------
// Pure computation

/// Compute all five dimension scores from `stats` and return the
/// [`QualityScorecard`]. This is a pure function — no I/O.
pub fn compute_quality_scorecard_from_stats(stats: &MemoryStats, ts_unix: i64) -> QualityScorecard {
    let data_sufficient = stats.non_skip_recall_count >= MIN_RECALL_SAMPLES;
    let cold_start_fallback = 0.5; // neutral when we can't measure yet

    // 1. Accuracy — Hebbian reinforcement rate over non-empty non-skip recalls.
    let accuracy = if !data_sufficient || stats.non_empty_count == 0 {
        cold_start_fallback
    } else {
        (stats.reinforcement_ratio_sum / stats.non_empty_count as f64).clamp(0.0, 1.0)
    };

    // 2. Completeness — hit rate over non-skip recalls.
    let completeness = if !data_sufficient || stats.non_skip_recall_count == 0 {
        cold_start_fallback
    } else {
        (stats.recall_hits as f64 / stats.non_skip_recall_count as f64).clamp(0.0, 1.0)
    };

    // 3. Consistency — 1 - pending_contradiction_density.
    // density = pending / max(1, verified_facts)  so an empty store → density=0 → score=1.0
    let consistency = {
        let denom = stats.verified_fact_count.max(1) as f64;
        let density = (stats.pending_contradiction_count as f64 / denom).min(1.0);
        (1.0 - density).clamp(0.0, 1.0)
    };

    // 4. Freshness — recently-accessed hot rows fraction.
    let freshness = if stats.hot_episode_count == 0 {
        1.0 // empty store — nothing is stale
    } else {
        (stats.recently_accessed_count as f64 / stats.hot_episode_count as f64).clamp(0.0, 1.0)
    };

    // 5. Attribution — attributed-fact fraction.
    let attribution = if stats.active_fact_count == 0 {
        1.0 // no facts yet — nothing is unattributed
    } else {
        (stats.attributed_fact_count as f64 / stats.active_fact_count as f64).clamp(0.0, 1.0)
    };

    let composite = (W_ACCURACY * accuracy
        + W_COMPLETENESS * completeness
        + W_CONSISTENCY * consistency
        + W_FRESHNESS * freshness
        + W_ATTRIBUTION * attribution)
        .clamp(0.0, 1.0);

    let grade = Grade::from_score(composite);
    let is_healthy = composite >= HEALTHY_THRESHOLD;

    QualityScorecard {
        ts_unix,
        accuracy,
        completeness,
        consistency,
        freshness,
        attribution,
        composite,
        grade,
        is_healthy,
        sample_count: stats.non_skip_recall_count,
        data_sufficient,
    }
}

// ---------------------------------------------------------------------------
// Store queries (read-only)

/// Read the [`MemoryStats`] snapshot from a live SQLite connection.
///
/// All queries are read-only SELECT statements — no writes, no schema changes.
/// Errors from individual sub-queries are treated as 0-count (best-effort
/// monitor — a missing table doesn't break the scorecard).
pub fn read_memory_stats(
    conn: &Connection,
    now_unix: i64,
    recall_window: usize,
) -> rusqlite::Result<MemoryStats> {
    // ── accuracy / completeness — recent recall events ────────────────────────
    let events = crate::memory::store::recent_recall_events(conn, recall_window)?;
    let non_skip: Vec<_> = events.iter().filter(|e| e.tier != "skip").collect();
    let recall_hits = non_skip.iter().filter(|e| e.result_count >= 1).count() as u32;
    let non_empty: Vec<_> = non_skip.iter().filter(|e| e.result_count >= 1).collect();
    let reinforcement_ratio_sum: f64 = non_empty
        .iter()
        .map(|e| e.reinforced_count as f64 / e.result_count as f64)
        .sum();

    // ── consistency — pending contradictions vs verified facts ────────────────
    let verified_fact_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND fact_state = 'verified'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;
    let pending_contradiction_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_contradictions WHERE decision = 'pending'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;

    // ── freshness — hot-tier rows accessed within last 7 days ────────────────
    let seven_days_ago_ns = (now_unix - 7 * 86_400) * 1_000_000_000i64;
    let hot_episode_count: u64 = conn
        .query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get::<_, i64>(0))
        .unwrap_or(0) as u64;
    let recently_accessed_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_episode WHERE last_access_ts > ?1",
            rusqlite::params![seven_days_ago_ns],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;

    // ── attribution — active facts with a non-empty source tag ───────────────
    let active_fact_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;
    let attributed_fact_count: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND source IS NOT NULL AND source != ''",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64;

    Ok(MemoryStats {
        non_skip_recall_count: non_skip.len() as u32,
        recall_hits,
        reinforcement_ratio_sum,
        non_empty_count: non_empty.len() as u32,
        verified_fact_count,
        pending_contradiction_count,
        hot_episode_count,
        recently_accessed_count,
        active_fact_count,
        attributed_fact_count,
    })
}

/// Convenience wrapper: read stats from the store and compute the scorecard.
pub fn compute_quality_scorecard(
    conn: &Connection,
    now_unix: i64,
    recall_window: usize,
) -> rusqlite::Result<QualityScorecard> {
    let stats = read_memory_stats(conn, now_unix, recall_window)?;
    Ok(compute_quality_scorecard_from_stats(&stats, now_unix))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn stats_with_good_recall() -> MemoryStats {
        MemoryStats {
            // 20 non-skip recalls, 18 hits, reinforcement rate 0.80
            non_skip_recall_count: 20,
            recall_hits: 18,
            reinforcement_ratio_sum: 0.80 * 18.0,
            non_empty_count: 18,
            // zero contradictions, 10 verified facts → consistency = 1.0
            verified_fact_count: 10,
            pending_contradiction_count: 0,
            // all 100 hot rows accessed recently → freshness = 1.0
            hot_episode_count: 100,
            recently_accessed_count: 100,
            // 10/10 facts have sources → attribution = 1.0
            active_fact_count: 10,
            attributed_fact_count: 10,
        }
    }

    fn stats_failing() -> MemoryStats {
        MemoryStats {
            // 20 non-skip, 0 hits, 0 reinforcements
            non_skip_recall_count: 20,
            recall_hits: 0,
            reinforcement_ratio_sum: 0.0,
            non_empty_count: 0,
            // all facts contradicted
            verified_fact_count: 10,
            pending_contradiction_count: 10,
            // no fresh accesses
            hot_episode_count: 100,
            recently_accessed_count: 0,
            // no attribution
            active_fact_count: 10,
            attributed_fact_count: 0,
        }
    }

    // ── 1. high-quality stats → grade A or B ─────────────────────────────────

    #[test]
    fn high_quality_stats_produce_healthy_grade() {
        let sc = compute_quality_scorecard_from_stats(&stats_with_good_recall(), 0);
        // accuracy = 0.80, completeness = 18/20 = 0.90, consistency = 1.0,
        // freshness = 1.0, attribution = 1.0
        // composite = 0.30*0.80 + 0.25*0.90 + 0.20*1.0 + 0.15*1.0 + 0.10*1.0
        //           = 0.24 + 0.225 + 0.20 + 0.15 + 0.10 = 0.915
        assert!(sc.composite > 0.90, "composite={}", sc.composite);
        assert_eq!(sc.grade, Grade::A);
        assert!(sc.is_healthy);
        assert!(sc.data_sufficient, "20 samples ≥ MIN_RECALL_SAMPLES");
    }

    // ── 2. failing stats → grade F ────────────────────────────────────────────

    #[test]
    fn failing_stats_produce_grade_f() {
        let sc = compute_quality_scorecard_from_stats(&stats_failing(), 0);
        // accuracy cold-start (non_empty_count=0) → 0.5
        // completeness = 0/20 = 0.0
        // consistency = 1 - 10/10 = 0.0
        // freshness = 0/100 = 0.0
        // attribution = 0/10 = 0.0
        // composite = 0.30*0.5 + 0.25*0.0 + 0.20*0.0 + 0.15*0.0 + 0.10*0.0 = 0.15
        assert!(sc.composite < 0.50, "composite={}", sc.composite);
        assert_eq!(sc.grade, Grade::F);
        assert!(!sc.is_healthy);
    }

    // ── 3. HEALTHY_THRESHOLD boundary ────────────────────────────────────────

    #[test]
    fn grade_c_is_exactly_at_threshold() {
        // Build a stat set that produces composite ≈ 0.70
        // composite = 0.30*A + 0.25*C + 0.20*Cn + 0.15*F + 0.10*At = 0.70
        // Use: accuracy=0.50 (cold), completeness=0.60, consistency=0.90, freshness=0.80, attribution=1.0
        // = 0.30*0.5 + 0.25*0.6 + 0.20*0.9 + 0.15*0.8 + 0.10*1.0
        // = 0.15 + 0.15 + 0.18 + 0.12 + 0.10 = 0.70
        let stats = MemoryStats {
            non_skip_recall_count: 20,
            recall_hits: 12, // 12/20 = 0.60
            reinforcement_ratio_sum: 0.0,
            non_empty_count: 0, // → accuracy cold-start = 0.50
            verified_fact_count: 10,
            pending_contradiction_count: 1, // 1-1/10 = 0.90
            hot_episode_count: 100,
            recently_accessed_count: 80, // 80/100 = 0.80
            active_fact_count: 10,
            attributed_fact_count: 10, // 10/10 = 1.0
        };
        let sc = compute_quality_scorecard_from_stats(&stats, 0);
        assert!(
            (sc.composite - 0.70).abs() < 1e-9,
            "composite={:.6}",
            sc.composite
        );
        assert_eq!(sc.grade, Grade::C);
        assert!(sc.is_healthy, "grade C is at the HEALTHY_THRESHOLD");
    }

    // ── 4. cold-start guard ───────────────────────────────────────────────────

    #[test]
    fn cold_start_below_min_samples_uses_fallback() {
        let stats = MemoryStats {
            // only 4 samples — below MIN_RECALL_SAMPLES
            non_skip_recall_count: 4,
            recall_hits: 4,
            reinforcement_ratio_sum: 1.0 * 4.0,
            non_empty_count: 4,
            verified_fact_count: 0,
            pending_contradiction_count: 0,
            hot_episode_count: 0,
            recently_accessed_count: 0,
            active_fact_count: 0,
            attributed_fact_count: 0,
        };
        let sc = compute_quality_scorecard_from_stats(&stats, 0);
        assert!(!sc.data_sufficient);
        // accuracy and completeness both use cold-start fallback 0.5
        assert!((sc.accuracy - 0.5).abs() < 1e-9, "accuracy={}", sc.accuracy);
        assert!(
            (sc.completeness - 0.5).abs() < 1e-9,
            "completeness={}",
            sc.completeness
        );
    }

    // ── 5. empty store produces healthy fallback values ───────────────────────

    #[test]
    fn empty_store_stats_produce_non_zero_scorecard() {
        let stats = MemoryStats {
            non_skip_recall_count: 0,
            recall_hits: 0,
            reinforcement_ratio_sum: 0.0,
            non_empty_count: 0,
            verified_fact_count: 0,
            pending_contradiction_count: 0,
            hot_episode_count: 0,
            recently_accessed_count: 0,
            active_fact_count: 0,
            attributed_fact_count: 0,
        };
        let sc = compute_quality_scorecard_from_stats(&stats, 0);
        // freshness=1.0 (empty store), attribution=1.0, consistency=1.0,
        // accuracy/completeness=0.5 cold-start
        // composite = 0.30*0.5 + 0.25*0.5 + 0.20*1.0 + 0.15*1.0 + 0.10*1.0 = 0.625
        let expected = W_ACCURACY * 0.5
            + W_COMPLETENESS * 0.5
            + W_CONSISTENCY * 1.0
            + W_FRESHNESS * 1.0
            + W_ATTRIBUTION * 1.0;
        assert!(
            (sc.composite - expected).abs() < 1e-9,
            "composite={} expected={}",
            sc.composite,
            expected
        );
        assert!(sc.is_healthy, "empty store should not alarm");
    }

    // ── 6. history ring buffer caps at HISTORY_CAP ───────────────────────────

    #[test]
    fn history_ring_buffer_caps_and_preserves_latest() {
        let mut hist = ScorecardHistory::default();
        for i in 0..=(HISTORY_CAP + 5) {
            let sc = compute_quality_scorecard_from_stats(&stats_with_good_recall(), i as i64);
            hist.push(sc);
        }
        assert_eq!(hist.len(), HISTORY_CAP);
        // The oldest entry should have been evicted; latest = highest ts_unix
        assert_eq!(hist.latest().unwrap().ts_unix as usize, HISTORY_CAP + 5);
    }

    // ── 7. grade boundary values ──────────────────────────────────────────────

    #[test]
    fn grade_from_score_boundaries() {
        assert_eq!(Grade::from_score(1.00), Grade::A);
        assert_eq!(Grade::from_score(0.90), Grade::A);
        assert_eq!(Grade::from_score(0.89), Grade::B);
        assert_eq!(Grade::from_score(0.80), Grade::B);
        assert_eq!(Grade::from_score(0.79), Grade::C);
        assert_eq!(Grade::from_score(0.70), Grade::C);
        assert_eq!(Grade::from_score(0.69), Grade::D);
        assert_eq!(Grade::from_score(0.60), Grade::D);
        assert_eq!(Grade::from_score(0.59), Grade::E);
        assert_eq!(Grade::from_score(0.50), Grade::E);
        assert_eq!(Grade::from_score(0.49), Grade::F);
        assert_eq!(Grade::from_score(0.00), Grade::F);
    }

    // ── 8. grade helpers ──────────────────────────────────────────────────────

    #[test]
    fn grade_is_healthy_for_a_b_c_only() {
        assert!(Grade::A.is_healthy());
        assert!(Grade::B.is_healthy());
        assert!(Grade::C.is_healthy());
        assert!(!Grade::D.is_healthy());
        assert!(!Grade::E.is_healthy());
        assert!(!Grade::F.is_healthy());
    }

    // ── 9. persistently_unhealthy flag ────────────────────────────────────────

    #[test]
    fn persistently_unhealthy_when_all_entries_fail() {
        let mut hist = ScorecardHistory::default();
        // push 3 failing scorecards
        for i in 0..3 {
            let sc = compute_quality_scorecard_from_stats(&stats_failing(), i);
            hist.push(sc);
        }
        assert!(hist.is_persistently_unhealthy());

        // one healthy entry breaks the run
        let good = compute_quality_scorecard_from_stats(&stats_with_good_recall(), 3);
        hist.push(good);
        assert!(!hist.is_persistently_unhealthy());
    }

    // ── 10. consistency score with contradictions ─────────────────────────────

    #[test]
    fn consistency_penalises_pending_contradictions() {
        let stats = MemoryStats {
            non_skip_recall_count: 20,
            recall_hits: 18,
            reinforcement_ratio_sum: 0.80 * 18.0,
            non_empty_count: 18,
            verified_fact_count: 10,
            pending_contradiction_count: 5, // 50% pending → consistency = 0.50
            hot_episode_count: 100,
            recently_accessed_count: 100,
            active_fact_count: 10,
            attributed_fact_count: 10,
        };
        let sc = compute_quality_scorecard_from_stats(&stats, 0);
        assert!(
            (sc.consistency - 0.50).abs() < 1e-9,
            "consistency={}",
            sc.consistency
        );
        // composite degrades from the ideal by the consistency shortfall
        let sc_ideal = compute_quality_scorecard_from_stats(&stats_with_good_recall(), 0);
        assert!(
            sc.composite < sc_ideal.composite,
            "contradictions lower the composite"
        );
    }

    // ── 11. DB integration — compute_quality_scorecard round-trip ────────────

    #[test]
    fn db_integration_round_trip_on_empty_store() {
        let conn = crate::memory::store::open(std::path::Path::new(":memory:")).unwrap();
        let now = 1_700_000_000i64;
        let sc = compute_quality_scorecard(&conn, now, 200).unwrap();
        // empty store → all fallback values → should be healthy
        assert!(sc.is_healthy, "empty store should not trigger alarm: {:?}", sc.grade);
        assert_eq!(sc.ts_unix, now);
    }
}
