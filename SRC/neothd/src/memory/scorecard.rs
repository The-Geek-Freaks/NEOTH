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
        .query_row("SELECT COUNT(*) FROM idx_episode", [], |r| {
            r.get::<_, i64>(0)
        })
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
// MEM-11: Per-subsystem 15-point pipeline scorecard

/// One subsystem's score in the pipeline scorecard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemScore {
    /// Human-readable subsystem name (matches the 15 names in the research plan).
    pub name: String,
    /// Score in `[0.0, 1.0]`. 1.0 = fully healthy, 0.0 = completely failing.
    pub score: f64,
    /// Letter grade derived from the score.
    pub grade: Grade,
}

/// 15-point per-subsystem memory pipeline scorecard.
///
/// Subsystems (in order):
///  1. indexer — WAL-tail ingest (episode row count / embedding coverage proxy)
///  2. episodic_store — hot-tier row count + embedding coverage
///  3. recall_hit_rate — recall completeness (non-skip hit fraction)
///  4. recall_latency — p95 latency health (from idx_recall_latency)
///  5. groundtruth — verified-fact count + attribution health
///  6. contradictions — pending vs resolved ratio
///  7. gc_pressure — source-count vs max cap
///  8. decay_freshness — recently-accessed hot-row fraction
///  9. consolidation — warm-tier ratio relative to hot
/// 10. ingress — cold-tier headroom (longterm row count)
/// 11. knowledge_graph — entity + relation presence (MEM-06)
/// 12. assoc_graph — memory link presence (MEM-07)
/// 13. embedding_coverage — fraction of hot episodes with an embedding
/// 14. contradiction_resolution — resolved vs total contradiction pairs
/// 15. people_staleness — people.json staleness proxy (attribution coverage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineScorecard {
    /// Unix timestamp when this scorecard was computed.
    pub ts_unix: i64,
    /// Per-subsystem breakdown (15 entries, stable order).
    pub subsystems: Vec<SubsystemScore>,
    /// Mean of all 15 subsystem scores.
    pub overall_composite: f64,
    /// Grade derived from `overall_composite`.
    pub overall_grade: Grade,
    /// True when `overall_composite >= HEALTHY_THRESHOLD`.
    pub is_healthy: bool,
}

/// Rolling history of [`PipelineScorecard`] entries — same API as
/// [`ScorecardHistory`], capped at [`HISTORY_CAP`].
#[derive(Debug, Default, Clone)]
pub struct PipelineHistory {
    entries: Vec<PipelineScorecard>,
}

impl PipelineHistory {
    /// Push a new entry, dropping the oldest when over capacity.
    pub fn push(&mut self, sc: PipelineScorecard) {
        if self.entries.len() >= HISTORY_CAP {
            self.entries.remove(0);
        }
        self.entries.push(sc);
    }

    /// Most-recent entry, if any.
    pub fn latest(&self) -> Option<&PipelineScorecard> {
        self.entries.last()
    }

    /// All entries (oldest-first).
    pub fn entries(&self) -> &[PipelineScorecard] {
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

    /// True when all entries in the window have an unhealthy overall grade.
    pub fn is_persistently_unhealthy(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|e| !e.is_healthy)
    }
}

/// Pure function: given a slice of `(name, score)` pairs, build a
/// [`PipelineScorecard`]. The `score` values must already be in `[0.0, 1.0]`.
/// The `name` values are static string slices that are copied into owned
/// `String` fields on [`SubsystemScore`].
pub fn compute_pipeline_scorecard_from_raw(
    scores: &[(&str, f64)],
    ts_unix: i64,
) -> PipelineScorecard {
    let subsystems: Vec<SubsystemScore> = scores
        .iter()
        .map(|&(name, raw)| {
            let score = raw.clamp(0.0, 1.0);
            SubsystemScore {
                name: name.to_owned(),
                score,
                grade: Grade::from_score(score),
            }
        })
        .collect();

    let overall_composite = if subsystems.is_empty() {
        0.0
    } else {
        let sum: f64 = subsystems.iter().map(|s| s.score).sum();
        (sum / subsystems.len() as f64).clamp(0.0, 1.0)
    };
    let overall_grade = Grade::from_score(overall_composite);
    let is_healthy = overall_composite >= HEALTHY_THRESHOLD;

    PipelineScorecard {
        ts_unix,
        subsystems,
        overall_composite,
        overall_grade,
        is_healthy,
    }
}

/// Read the memory store and compute the 15-point pipeline scorecard.
///
/// All SQL probes are best-effort (`unwrap_or(0)`): a missing table on a
/// pre-migration install scores that subsystem as 0 counts → neutral/healthy
/// default. The connection must already be open by the caller; it is consumed
/// within a synchronous scope (no `.await` inside this function) so it is safe
/// to call from a `!Send` context or before any `.await` in an async fn.
pub fn read_and_compute_pipeline_scorecard(
    conn: &Connection,
    now_unix: i64,
) -> rusqlite::Result<PipelineScorecard> {
    // ── 1. indexer — ingest coverage proxy (embedding coverage of hot episodes)
    let hot_total: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap_or(0);
    // Indexed in last 24 hours = recently indexed episodes
    let recently_indexed_ns = (now_unix - 86_400) * 1_000_000_000i64;
    let recently_indexed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_episode WHERE ts_ns >= ?1",
            rusqlite::params![recently_indexed_ns],
            |r| r.get(0),
        )
        .unwrap_or(0);
    // Score: if store is empty → neutral 0.5; else fraction recently indexed
    // (clamp: an idle system with old memories scores 0.5, not 0)
    let indexer_score = if hot_total == 0 {
        0.5 // empty store, nothing to index
    } else {
        let fraction = recently_indexed as f64 / hot_total as f64;
        // Cold store (nothing indexed today) gets 0.3 floor — it may simply be
        // quiet, not broken. Scale from [0,1] to [0.3,1.0].
        0.3 + fraction * 0.7
    };

    // ── 2. episodic_store — hot-tier row count health
    // Score: use a soft cap. 0 rows = cold start (0.5). More rows = healthier
    // up to a ceiling of 1000 rows at which point it fully scores.
    let episodic_score = if hot_total == 0 {
        0.5
    } else {
        (hot_total as f64 / 1000.0_f64).min(1.0)
    };

    // ── 3. recall_hit_rate — non-skip recall completeness (same as JV-MEM-15)
    let non_skip_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_recall_events WHERE tier != 'skip'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let hit_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_recall_events WHERE tier != 'skip' AND result_count >= 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let recall_hit_score = if non_skip_count < 5 {
        0.5 // cold-start guard
    } else {
        hit_count as f64 / non_skip_count as f64
    };

    // ── 4. recall_latency — p95 latency health (lower is better)
    // idx_recall_latency stores latency_ms values. p95 < 200ms = perfect.
    // p95 >= 2000ms = 0. Linear interpolation between.
    let p95_latency_ms: f64 = conn
        .query_row(
            "SELECT latency_ms FROM idx_recall_latency \
             ORDER BY latency_ms \
             LIMIT 1 OFFSET CAST(0.95 * (SELECT COUNT(*) FROM idx_recall_latency) AS INTEGER)",
            [],
            |r| r.get::<_, f64>(0),
        )
        .unwrap_or(0.0); // 0 = table absent or empty → neutral (score will be 1.0)
    let latency_score = if p95_latency_ms <= 0.0 {
        1.0 // no data → neutral healthy
    } else if p95_latency_ms >= 2000.0 {
        0.0
    } else if p95_latency_ms <= 200.0 {
        1.0
    } else {
        // Linear from 200ms (1.0) to 2000ms (0.0)
        1.0 - (p95_latency_ms - 200.0) / 1800.0
    };

    // ── 5. groundtruth — verified fact + attribution (composite of two sub-signals)
    let verified_facts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND fact_state = 'verified'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let active_facts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let attributed_facts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND source IS NOT NULL AND source != ''",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    // Verified fraction + attribution fraction averaged
    let verified_frac = if active_facts == 0 {
        1.0
    } else {
        verified_facts as f64 / active_facts as f64
    };
    let attrib_frac = if active_facts == 0 {
        1.0
    } else {
        attributed_facts as f64 / active_facts as f64
    };
    let groundtruth_score = (verified_frac * 0.6 + attrib_frac * 0.4).clamp(0.0, 1.0);

    // ── 6. contradictions — pending vs total contradiction pairs
    let pending_contradictions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_contradictions WHERE decision = 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total_contradictions: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_contradictions", [], |r| r.get(0))
        .unwrap_or(0);
    let contradiction_score = if total_contradictions == 0 {
        1.0 // no contradictions → healthy
    } else {
        let density = pending_contradictions as f64 / total_contradictions.max(1) as f64;
        (1.0 - density).clamp(0.0, 1.0)
    };

    // ── 7. gc_pressure — source-count vs DEFAULT_MAX_SOURCES cap
    // A full source table means GC hasn't run or is overloaded.
    const DEFAULT_MAX_SOURCES: i64 = 10_000;
    let source_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_sources", [], |r| r.get(0))
        .unwrap_or(0);
    let gc_pressure_score = if source_count == 0 {
        1.0
    } else {
        let pressure = source_count as f64 / DEFAULT_MAX_SOURCES as f64;
        (1.0 - pressure).clamp(0.0, 1.0)
    };

    // ── 8. decay_freshness — recently-accessed hot episodes fraction (7-day window)
    let seven_days_ago_ns = (now_unix - 7 * 86_400) * 1_000_000_000i64;
    let recently_accessed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_episode WHERE last_access_ts > ?1",
            rusqlite::params![seven_days_ago_ns],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let freshness_score = if hot_total == 0 {
        1.0
    } else {
        (recently_accessed as f64 / hot_total as f64).clamp(0.0, 1.0)
    };

    // ── 9. consolidation — warm-tier ratio relative to hot (healthy consolidation)
    // A non-empty warm tier with a reasonable ratio to hot is healthy.
    let warm_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_consolidated", [], |r| r.get(0))
        .unwrap_or(0);
    let consolidation_score = if hot_total == 0 && warm_count == 0 {
        0.5 // empty system — neutral
    } else if warm_count == 0 {
        // No warm consolidation yet (very new system or consolidation broken)
        0.4
    } else {
        // Healthy: warm_count > 0. Score relative to how populated warm is.
        // Clamp at 1.0 once warm hits 100 rows.
        (warm_count as f64 / 100.0).min(1.0)
    };

    // ── 10. ingress — cold-tier (longterm) headroom
    // A fully-populated cold tier with large counts is healthy.
    let cold_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_longterm", [], |r| r.get(0))
        .unwrap_or(0);
    // Score: presence of cold-tier rows is positive. Cap at 500 for full score.
    let ingress_score = if hot_total == 0 && warm_count == 0 && cold_count == 0 {
        0.5 // empty system
    } else {
        (cold_count as f64 / 500.0).clamp(0.3, 1.0)
        // 0.3 floor even with 0 cold rows if there are hot/warm rows — cold
        // tier fills over time, absence on a new system is not a failure.
    };

    // ── 11. knowledge_graph — entity + relation presence (MEM-06, schema v13+)
    let entity_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_entities", [], |r| r.get(0))
        .unwrap_or(0);
    let relation_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_relations", [], |r| r.get(0))
        .unwrap_or(0);
    let kg_score = if entity_count == 0 && relation_count == 0 {
        0.5 // empty or missing table (pre-MEM-06 install) — neutral
    } else {
        // Presence of entities + relations is healthy. Cap at 200 entities.
        ((entity_count as f64 / 200.0).min(1.0) * 0.6
            + (relation_count as f64 / 400.0).min(1.0) * 0.4)
            .clamp(0.0, 1.0)
    };

    // ── 12. assoc_graph — memory link presence (MEM-07, schema v16+)
    let link_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get(0))
        .unwrap_or(0);
    let assoc_score = if link_count == 0 {
        0.5 // absent or empty — neutral (pre-MEM-07 or no links yet)
    } else {
        (link_count as f64 / 1000.0).clamp(0.5, 1.0)
    };

    // ── 13. embedding_coverage — fraction of hot episodes with an idx_embedding row
    let embedded_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_embedding WHERE source_kind = 'episode'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let embedding_score = if hot_total == 0 {
        1.0 // nothing to embed
    } else {
        (embedded_count as f64 / hot_total as f64).clamp(0.0, 1.0)
    };

    // ── 14. contradiction_resolution — resolved vs total contradiction pairs
    let resolved_contradictions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_contradictions WHERE decision != 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let contradiction_resolution_score = if total_contradictions == 0 {
        1.0 // no contradictions at all → perfect
    } else {
        (resolved_contradictions as f64 / total_contradictions as f64).clamp(0.0, 1.0)
    };

    // ── 15. people_staleness — attribution coverage proxy from people.json
    // We proxy this via the groundtruth attribution fraction (same as subsystem 5,
    // but focused on the attribution dimension only). A separate people.json check
    // would require filesystem I/O; the SQLite-based attribution fraction is the
    // canonical in-store signal.
    let people_score = attrib_frac; // same as attribution fraction in subsystem 5

    let raw: &[(&str, f64)] = &[
        ("indexer", indexer_score),
        ("episodic_store", episodic_score),
        ("recall_hit_rate", recall_hit_score),
        ("recall_latency", latency_score),
        ("groundtruth", groundtruth_score),
        ("contradictions", contradiction_score),
        ("gc_pressure", gc_pressure_score),
        ("decay_freshness", freshness_score),
        ("consolidation", consolidation_score),
        ("ingress", ingress_score),
        ("knowledge_graph", kg_score),
        ("assoc_graph", assoc_score),
        ("embedding_coverage", embedding_score),
        ("contradiction_resolution", contradiction_resolution_score),
        ("people_staleness", people_score),
    ];

    Ok(compute_pipeline_scorecard_from_raw(raw, now_unix))
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
        assert!(
            sc.is_healthy,
            "empty store should not trigger alarm: {:?}",
            sc.grade
        );
        assert_eq!(sc.ts_unix, now);
    }

    // =========================================================================
    // MEM-11: PipelineScorecard unit tests
    // =========================================================================

    // ── MEM-11-1. All-healthy raw scores → composite near 1.0, grade A/B ─────

    #[test]
    fn pipeline_scorecard_all_healthy_produces_high_grade() {
        let scores: &[(&str, f64)] = &[
            ("indexer", 1.0),
            ("episodic_store", 1.0),
            ("recall_hit_rate", 1.0),
            ("recall_latency", 1.0),
            ("groundtruth", 1.0),
            ("contradictions", 1.0),
            ("gc_pressure", 1.0),
            ("decay_freshness", 1.0),
            ("consolidation", 1.0),
            ("ingress", 1.0),
            ("knowledge_graph", 1.0),
            ("assoc_graph", 1.0),
            ("embedding_coverage", 1.0),
            ("contradiction_resolution", 1.0),
            ("people_staleness", 1.0),
        ];
        let sc = compute_pipeline_scorecard_from_raw(scores, 0);
        assert_eq!(sc.subsystems.len(), 15, "exactly 15 subsystems");
        assert!(
            (sc.overall_composite - 1.0).abs() < 1e-9,
            "all-1.0 scores → composite = 1.0"
        );
        assert_eq!(sc.overall_grade, Grade::A);
        assert!(sc.is_healthy);
    }

    // ── MEM-11-2. All-failing raw scores → composite = 0.0, grade F ──────────

    #[test]
    fn pipeline_scorecard_all_failing_produces_grade_f() {
        let scores: Vec<(&'static str, f64)> = vec![
            ("indexer", 0.0),
            ("episodic_store", 0.0),
            ("recall_hit_rate", 0.0),
            ("recall_latency", 0.0),
            ("groundtruth", 0.0),
            ("contradictions", 0.0),
            ("gc_pressure", 0.0),
            ("decay_freshness", 0.0),
            ("consolidation", 0.0),
            ("ingress", 0.0),
            ("knowledge_graph", 0.0),
            ("assoc_graph", 0.0),
            ("embedding_coverage", 0.0),
            ("contradiction_resolution", 0.0),
            ("people_staleness", 0.0),
        ];
        let sc = compute_pipeline_scorecard_from_raw(&scores, 0);
        assert!(
            sc.overall_composite < 1e-9,
            "all-0.0 scores → composite near 0"
        );
        assert_eq!(sc.overall_grade, Grade::F);
        assert!(!sc.is_healthy);
    }

    // ── MEM-11-3. Single unhealthy subsystem lowers composite but overall may still be healthy

    #[test]
    fn pipeline_scorecard_single_bad_subsystem_lowers_composite() {
        // 14 perfect + 1 failing → composite = 14/15 ≈ 0.933
        let mut scores: Vec<(&'static str, f64)> = (0..14)
            .map(|i| {
                let names: &[&'static str] = &[
                    "indexer",
                    "episodic_store",
                    "recall_hit_rate",
                    "recall_latency",
                    "groundtruth",
                    "contradictions",
                    "gc_pressure",
                    "decay_freshness",
                    "consolidation",
                    "ingress",
                    "knowledge_graph",
                    "assoc_graph",
                    "embedding_coverage",
                    "contradiction_resolution",
                ];
                (names[i], 1.0f64)
            })
            .collect();
        scores.push(("people_staleness", 0.0));
        let sc = compute_pipeline_scorecard_from_raw(&scores, 0);
        assert_eq!(sc.subsystems.len(), 15);
        let expected = 14.0 / 15.0;
        assert!(
            (sc.overall_composite - expected).abs() < 1e-9,
            "composite={} expected={}",
            sc.overall_composite,
            expected
        );
        // 14/15 ≈ 0.933 → grade A, still healthy
        assert!(
            sc.is_healthy,
            "14/15 healthy subsystems → still overall healthy"
        );
        // The bad subsystem must have grade F
        let bad = sc
            .subsystems
            .iter()
            .find(|s| s.name == "people_staleness")
            .unwrap();
        assert_eq!(bad.grade, Grade::F);
    }

    // ── MEM-11-4. DB round-trip on empty store → 15 subsystems, not panicking ─

    #[test]
    fn pipeline_scorecard_db_round_trip_empty_store() {
        let conn = crate::memory::store::open(std::path::Path::new(":memory:")).unwrap();
        let now = 1_700_000_000i64;
        let sc = read_and_compute_pipeline_scorecard(&conn, now).unwrap();
        assert_eq!(
            sc.subsystems.len(),
            15,
            "must produce exactly 15 subsystems on empty store"
        );
        assert_eq!(sc.ts_unix, now);
        // Empty store with fallback values should be neutral/healthy (not alarm)
        assert!(
            sc.is_healthy,
            "empty store must not trigger alarm — is_healthy=false grade={:?}",
            sc.overall_grade
        );
    }

    // ── MEM-11-5. PipelineHistory ring-buffer caps at HISTORY_CAP ─────────────

    #[test]
    fn pipeline_history_ring_buffer_caps() {
        let mut hist = PipelineHistory::default();
        let scores: &[(&str, f64)] = &[("s", 1.0)];
        for i in 0..=(HISTORY_CAP + 3) {
            let sc = compute_pipeline_scorecard_from_raw(scores, i as i64);
            hist.push(sc);
        }
        assert_eq!(
            hist.len(),
            HISTORY_CAP,
            "ring buffer must cap at HISTORY_CAP"
        );
        assert_eq!(
            hist.latest().unwrap().ts_unix as usize,
            HISTORY_CAP + 3,
            "latest entry has the highest ts_unix"
        );
    }

    // ── MEM-11-6. is_persistently_unhealthy reflects all-bad window ───────────

    #[test]
    fn pipeline_history_persistently_unhealthy_flag() {
        let mut hist = PipelineHistory::default();
        let bad_scores: Vec<(&'static str, f64)> = vec![("s", 0.0)];
        for i in 0..3 {
            hist.push(compute_pipeline_scorecard_from_raw(&bad_scores, i));
        }
        assert!(
            hist.is_persistently_unhealthy(),
            "all-bad entries → persistently unhealthy"
        );

        let good_scores: &[(&str, f64)] = &[("s", 1.0)];
        hist.push(compute_pipeline_scorecard_from_raw(good_scores, 3));
        assert!(
            !hist.is_persistently_unhealthy(),
            "one healthy entry breaks the run"
        );
    }
}
