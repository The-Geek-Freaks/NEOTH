//! NN-MEM-02 — 5-dimensional synthesis pattern-recognition weekly cron.
//!
//! Performs a weekly pass over `idx_episode`, `idx_groundtruth`, and
//! `idx_contradictions` to produce a structured synthesis meta-note. The note
//! captures the five dimensions of understanding gathered across all operator
//! memory:
//!
//! 1. **Frequency** — topics most mentioned in the look-back window (which
//!    subjects dominate the operator's recent attention).
//! 2. **Temporal clustering** — dense time windows for those topics (when
//!    does the operator focus on specific subjects).
//! 3. **Domain correlation** — overlap between high-frequency episode topics
//!    and ground-truth facts already in `idx_groundtruth` (Jaccard shingles,
//!    same engine as `memory::contradiction`).
//! 4. **Contradiction flags** — pending contradiction ledger rows whose
//!    subject overlaps a top topic (signals operator attention on a contested
//!    fact).
//! 5. **Cross-cutting meta** — topics that appear across multiple domain
//!    partitions (technical + personal), suggesting cross-domain synthesis
//!    opportunities.
//!
//! ## Output
//!
//! The synthesis note is a JSON blob written as a new `idx_groundtruth` row
//! (`source = "synthesis-cron"`, `scope = "meta"`, `fact_state = "candidate"`)
//! together with the contributing episode ids. An empty/unresolved source
//! window is not persisted, preventing orphan synthesis.
//! When `freedom.yaml::obsidian_vault` is set, an atomic `YYYY-WW.md` file is
//! also written to `~/.neoth/synthesis/` via tempfile-rename (race-safe with
//! JV-IMP-05 vault writer).
//!
//! ## Design
//!
//! - **WAL-free**: no WAL event needed for this cron. Tracing logs only.
//! - **Opt-in**: default `enabled: false`. Operators enable via
//!   `freedom.yaml::synthesis_cron.enabled: true`.
//! - **spawn_blocking**: the rusqlite `Connection` is `!Send`; all SQLite work
//!   runs in `spawn_blocking` via a one-shot local runtime — same pattern as
//!   `daemon::contradiction_resolve_cron`.
//! - **Atomic vault write**: tmp → rename, eliminating any mutex with
//!   JV-IMP-05. Same approach as `daemon::guidance_cron`'s snapshot write.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::automation::SynthesisCronConfig;

// ---------------------------------------------------------------------------
// Public report type

/// Summary returned by one synthesis cron tick. Used for tracing + tests.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SynthesisReport {
    /// Number of distinct topics analyzed from the episode window.
    pub topics_analyzed: usize,
    /// Number of groundtruth correlations found (dimension 3).
    pub correlations_found: usize,
    /// Number of pending contradiction rows flagged (dimension 4).
    pub contradictions_flagged: usize,
    /// Whether a groundtruth row was written this tick.
    pub note_written: bool,
    /// NN-MEM-05: number of skill-prompt suggestions written this tick.
    pub skill_suggestions_written: usize,
    /// HERMES-06 GAP-B: number of `SkillPerfSuggestion` proposals newly staged
    /// in the OB-03 queue this tick (0 when `propose_skills_from_perf = false`).
    pub skill_proposals_staged: usize,
}

// ---------------------------------------------------------------------------
// Structured synthesis note (serialised into the groundtruth statement field)

/// The synthesis note stored in `idx_groundtruth.statement` as JSON.
///
/// `statement` is a JSON blob so the entire structured synthesis note
/// survives the untyped TEXT column in SQLite while remaining human-readable
/// via `neoth groundtruth list --scope meta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisNote {
    /// ISO week label, e.g. `"2026-W25"`.
    pub week_iso: String,
    /// Top-N topics by mention frequency.
    pub frequency_peaks: Vec<FrequencyPeak>,
    /// Dense temporal clusters found in the window.
    pub temporal_clusters: Vec<TemporalCluster>,
    /// Groundtruth rows whose statement overlaps high-frequency topics.
    pub domain_correlations: Vec<DomainCorrelation>,
    /// Pending contradiction ledger entries overlapping top topics.
    pub contradiction_flags: Vec<ContradictionFlag>,
    /// Topics that appear across multiple domain partitions.
    pub cross_cutting: Vec<CrossCuttingTopic>,
    /// NN-MEM-05: SWIRL-style skill-prompt improvement suggestions.
    /// Empty when `enable_skill_perf_pass = false` or the ledger has no data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skill_perf_suggestions: Vec<SkillPerfSuggestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyPeak {
    pub topic: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCluster {
    /// Start of the dense window as a UTC day label (`YYYY-MM-DD` approx).
    pub window_start_day: i64,
    /// Number of days in the cluster.
    pub window_days: u32,
    /// Topics that appeared densely in this window.
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCorrelation {
    /// `idx_groundtruth.id` of the correlating fact.
    pub gt_id: i64,
    /// Matched topic from the frequency pass.
    pub topic: String,
    /// Jaccard overlap score (0.0–1.0).
    pub overlap: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionFlag {
    /// `idx_contradictions.id`.
    pub id: i64,
    /// First fact's statement (truncated to 120 chars).
    pub statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCuttingTopic {
    pub topic: String,
    /// Domain labels in which this topic appears (e.g. `["technical", "personal"]`).
    pub domains: Vec<String>,
}

/// NN-MEM-05 — one skill-prompt improvement suggestion from the SWIRL-style pass.
///
/// The synthesis cron reads the SkillOpt ledger (`~/.neoth/self_improve_log.json`)
/// to compute per-skill accepted/rejected ratios and mean score deltas, then flags
/// skills with low improvement signals and generates a natural-language suggestion
/// grounded in the operator's top work topics from dimensions 1–4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPerfSuggestion {
    /// The skill id (matches `ImproveRecord.skill`).
    pub skill_id: String,
    /// Why this skill was flagged: `"low_score_delta"` | `"high_rejection_rate"`.
    pub signal_kind: String,
    /// Mean `score_after - score_before` across accepted proposals in the window.
    pub score_delta_mean: f64,
    /// Fraction of all proposals (accepted + rejected) that were rejected (0.0–1.0).
    pub rejection_rate: f64,
    /// Natural-language suggestion text referencing top frequency topics.
    pub suggestion: String,
}

// ---------------------------------------------------------------------------
// Constants

/// Minimum Jaccard overlap to call a groundtruth fact "correlated" with a topic.
const DOMAIN_CORRELATION_THRESHOLD: f32 = 0.12;

/// Top-N frequency topics to surface.
const TOP_N_TOPICS: usize = 15;

/// Maximum correlations per tick (prevents very long JSON blobs).
const MAX_CORRELATIONS: usize = 20;

/// Maximum contradiction flags per tick.
const MAX_CONTRADICTION_FLAGS: usize = 10;

/// Maximum cross-cutting topics per tick.
const MAX_CROSS_CUTTING: usize = 10;

/// RAW_TEXT event_type in `idx_episode` (0x01).
const RAW_TEXT_EVENT_TYPE: i64 = crate::wal::events::EVENT_TYPE_RAW_TEXT as i64;

// ── NN-MEM-05 constants ──────────────────────────────────────────────────────

/// SkillOpt score delta below which a skill is considered under-performing.
const SKILL_PERF_MIN_SCORE_DELTA: f64 = 0.05;

/// Rejection rate above which a skill is flagged (majority of proposals rejected).
const SKILL_PERF_MAX_REJECTION_RATE: f64 = 0.5;

/// Maximum skill suggestions per tick (prevents very long JSON blobs).
const MAX_SKILL_SUGGESTIONS: usize = 5;

/// Number of top frequency topics to mention in each suggestion text.
const SUGGESTION_CONTEXT_TOPICS: usize = 3;

// ---------------------------------------------------------------------------
// Dimension helpers

/// Bigram-shingle tokeniser identical to the one used in `memory::contradiction`
/// (Jaccard over 2-char character shingles of lowercased, whitespace-normalised text).
/// Re-implemented here to avoid a cross-module dependency on private helpers.
fn shingle_set(text: &str) -> std::collections::HashSet<String> {
    let normalised: String = text
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalised.chars().count() < 2 {
        return std::collections::HashSet::new();
    }
    let chars: Vec<char> = normalised.chars().collect();
    chars.windows(2).map(|w| w.iter().collect()).collect()
}

/// Jaccard similarity between two shingle sets (0.0 when both empty).
fn jaccard_shingles(
    a: &std::collections::HashSet<String>,
    b: &std::collections::HashSet<String>,
) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f32 / union as f32
}

/// Dimension 1+2 — frequency peaks + temporal clusters.
///
/// Reads `idx_episode` for RAW_TEXT rows in the look-back window, runs the
/// shared `reflection::topic_counts` tokeniser, and detects 3-day dense
/// clusters (UTC-day buckets with ≥3 episodes sharing a top topic).
fn compute_frequency_and_temporal(
    conn: &rusqlite::Connection,
    window_start_ns: i64,
    now_ns: i64,
) -> (Vec<FrequencyPeak>, Vec<TemporalCluster>, Vec<i64>) {
    // ── Dimension 1: frequency ───────────────────────────────────────────────
    let texts: Vec<String> = {
        let mut stmt = match conn.prepare(
            "SELECT text FROM idx_episode \
             WHERE ts_ns >= ?1 AND ts_ns <= ?2 AND event_type = ?3",
        ) {
            Ok(s) => s,
            Err(_) => return (vec![], vec![], vec![]),
        };
        match stmt
            .query_map(
                rusqlite::params![window_start_ns, now_ns, RAW_TEXT_EVENT_TYPE],
                |r| r.get::<_, String>(0),
            )
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(_) => return (vec![], vec![], vec![]),
        }
    };

    let counts = crate::reflection::topic_counts(&texts);
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_topics: Vec<FrequencyPeak> = sorted
        .iter()
        .take(TOP_N_TOPICS)
        .map(|(t, c)| FrequencyPeak {
            topic: t.clone(),
            count: *c,
        })
        .collect();

    // ── Dimension 2: temporal clustering ────────────────────────────────────
    // Fetch (ts_ns, text) rows for the window; bucket by UTC day;
    // find consecutive day-buckets where ≥2 top topics appear in ≥3 episodes.
    let top_set: std::collections::HashSet<&str> = sorted
        .iter()
        .take(TOP_N_TOPICS)
        .map(|(t, _)| t.as_str())
        .collect();

    let day_episodes: Vec<(i64, i64, String)> = {
        let mut stmt = match conn.prepare(
            "SELECT ts_ns, event_id, text FROM idx_episode \
             WHERE ts_ns >= ?1 AND ts_ns <= ?2 AND event_type = ?3 \
             ORDER BY ts_ns ASC, event_id ASC",
        ) {
            Ok(s) => s,
            Err(_) => return (top_topics, vec![], vec![]),
        };
        match stmt
            .query_map(
                rusqlite::params![window_start_ns, now_ns, RAW_TEXT_EVENT_TYPE],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(_) => return (top_topics, vec![], vec![]),
        }
    };

    // Group episodes by UTC day (ts_ns / 86_400_000_000_000).
    let mut day_map: HashMap<i64, Vec<String>> = HashMap::new();
    for (ts, _event_id, text) in &day_episodes {
        let day = ts / (86_400 * 1_000_000_000);
        day_map.entry(day).or_default().push(text.clone());
    }

    let mut clusters: Vec<TemporalCluster> = Vec::new();
    let mut days_sorted: Vec<i64> = day_map.keys().copied().collect();
    days_sorted.sort_unstable();

    // Sliding window: look for 3+ consecutive days with dense top-topic content.
    let mut i = 0;
    while i < days_sorted.len() {
        let window_start = days_sorted[i];
        let mut j = i;
        // Find consecutive-day run (gap ≤ 1 day).
        while j + 1 < days_sorted.len() && days_sorted[j + 1] - days_sorted[j] <= 1 {
            j += 1;
        }
        let run_len = (j - i + 1) as u32;
        if run_len >= 2 {
            // Collect all texts in this run.
            let run_texts: Vec<String> = (i..=j)
                .flat_map(|k| {
                    day_map
                        .get(&days_sorted[k])
                        .map(|v| v.to_vec())
                        .unwrap_or_default()
                })
                .collect();
            let run_counts = crate::reflection::topic_counts(&run_texts);
            let cluster_topics: Vec<String> = run_counts
                .iter()
                .filter(|(t, c)| top_set.contains(t.as_str()) && **c >= 2)
                .map(|(t, _)| t.clone())
                .collect();
            if !cluster_topics.is_empty() {
                clusters.push(TemporalCluster {
                    window_start_day: window_start,
                    window_days: run_len,
                    topics: cluster_topics,
                });
            }
        }
        i = j + 1;
    }

    let evidence_start = day_episodes
        .len()
        .saturating_sub(crate::memory::groundtruth::MAX_EVIDENCE_BACKLINKS);
    let evidence_ids = day_episodes[evidence_start..]
        .iter()
        .map(|(_, event_id, _)| *event_id)
        .collect();

    (top_topics, clusters, evidence_ids)
}

/// Dimension 3 — domain correlations between top topics and groundtruth facts.
///
/// For each active, non-revoked groundtruth row, compute Jaccard shingle
/// overlap with each top topic. Return the top correlating pairs.
fn compute_domain_correlations(
    conn: &rusqlite::Connection,
    top_topics: &[FrequencyPeak],
) -> Vec<DomainCorrelation> {
    if top_topics.is_empty() {
        return vec![];
    }

    let gt_rows: Vec<(i64, String)> = {
        let mut stmt = match conn.prepare(
            "SELECT id, statement FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND fact_state = 'verified' \
             ORDER BY asserted_at DESC LIMIT 200",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        match stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(_) => return vec![],
        }
    };

    let mut correlations: Vec<DomainCorrelation> = Vec::new();
    let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();

    for peak in top_topics.iter().take(10) {
        let topic_shingles = shingle_set(&peak.topic);
        if topic_shingles.is_empty() {
            continue;
        }
        for (gt_id, statement) in &gt_rows {
            if seen.contains(gt_id) {
                continue;
            }
            let gt_shingles = shingle_set(statement);
            let overlap = jaccard_shingles(&topic_shingles, &gt_shingles);
            if overlap >= DOMAIN_CORRELATION_THRESHOLD {
                seen.insert(*gt_id);
                correlations.push(DomainCorrelation {
                    gt_id: *gt_id,
                    topic: peak.topic.clone(),
                    overlap,
                });
                if correlations.len() >= MAX_CORRELATIONS {
                    return correlations;
                }
            }
        }
    }

    correlations
}

/// Dimension 4 — contradiction flags: pending ledger rows whose statement
/// overlaps with the top topics.
fn compute_contradiction_flags(
    conn: &rusqlite::Connection,
    top_topics: &[FrequencyPeak],
) -> Vec<ContradictionFlag> {
    if top_topics.is_empty() {
        return vec![];
    }

    // Fetch pending contradictions (decision = 'pending').
    let ledger_rows: Vec<(i64, i64, i64)> = {
        let mut stmt = match conn.prepare(
            "SELECT id, fact_a_id, fact_b_id FROM idx_contradictions \
             WHERE decision = 'pending' ORDER BY detected_at DESC LIMIT 100",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        match stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(_) => return vec![],
        }
    };

    let top_set: std::collections::HashSet<&str> = top_topics
        .iter()
        .take(10)
        .map(|p| p.topic.as_str())
        .collect();

    let mut flags: Vec<ContradictionFlag> = Vec::new();

    for (ledger_id, fact_a_id, _fact_b_id) in ledger_rows {
        let statement: Option<String> = conn
            .query_row(
                "SELECT statement FROM idx_groundtruth WHERE id = ?1",
                rusqlite::params![fact_a_id],
                |r| r.get(0),
            )
            .ok();
        let Some(stmt_text) = statement else { continue };

        // Check if any top topic appears in the statement.
        let lower_stmt = stmt_text.to_lowercase();
        let overlaps = top_set.iter().any(|t| lower_stmt.contains(*t));
        if overlaps {
            let truncated = if stmt_text.chars().count() > 120 {
                stmt_text.chars().take(120).collect::<String>() + "…"
            } else {
                stmt_text.clone()
            };
            flags.push(ContradictionFlag {
                id: ledger_id,
                statement: truncated,
            });
            if flags.len() >= MAX_CONTRADICTION_FLAGS {
                break;
            }
        }
    }

    flags
}

/// Dimension 5 — cross-cutting meta: topics appearing in both "technical"
/// and "personal" domain partitions.
///
/// Domain classification is heuristic: episodes whose text contains terms
/// from a technical-keyword list land in "technical"; all others go to
/// "personal". Topics appearing in both sets are cross-cutting.
fn compute_cross_cutting(
    conn: &rusqlite::Connection,
    window_start_ns: i64,
    now_ns: i64,
    top_topics: &[FrequencyPeak],
) -> Vec<CrossCuttingTopic> {
    if top_topics.is_empty() {
        return vec![];
    }

    // Heuristic technical keywords (any match → "technical" domain).
    const TECH_KEYWORDS: &[&str] = &[
        "rust",
        "cargo",
        "tokio",
        "async",
        "server",
        "daemon",
        "build",
        "docker",
        "deploy",
        "github",
        "git",
        "code",
        "compile",
        "debug",
        "kubernetes",
        "pipeline",
        "database",
        "sqlite",
        "http",
        "tcp",
        "memory",
        "config",
        "yaml",
        "json",
        "api",
        "test",
        "error",
    ];

    let domain_episodes: Vec<(i64, String)> = {
        let mut stmt = match conn.prepare(
            "SELECT ts_ns, text FROM idx_episode \
             WHERE ts_ns >= ?1 AND ts_ns <= ?2 AND event_type = ?3",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        match stmt
            .query_map(
                rusqlite::params![window_start_ns, now_ns, RAW_TEXT_EVENT_TYPE],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        {
            Ok(v) => v,
            Err(_) => return vec![],
        }
    };

    let mut tech_texts: Vec<String> = Vec::new();
    let mut personal_texts: Vec<String> = Vec::new();

    for (_ts, text) in &domain_episodes {
        let lower = text.to_lowercase();
        let is_tech = TECH_KEYWORDS.iter().any(|kw| lower.contains(kw));
        if is_tech {
            tech_texts.push(text.clone());
        } else {
            personal_texts.push(text.clone());
        }
    }

    let tech_counts = crate::reflection::topic_counts(&tech_texts);
    let personal_counts = crate::reflection::topic_counts(&personal_texts);

    let top_set: std::collections::HashSet<&str> =
        top_topics.iter().map(|p| p.topic.as_str()).collect();

    let mut cross: Vec<CrossCuttingTopic> = Vec::new();
    for topic in top_set {
        let in_tech = tech_counts.contains_key(topic);
        let in_personal = personal_counts.contains_key(topic);
        if in_tech && in_personal {
            let mut domains = Vec::new();
            if in_tech {
                domains.push("technical".to_string());
            }
            if in_personal {
                domains.push("personal".to_string());
            }
            cross.push(CrossCuttingTopic {
                topic: topic.to_string(),
                domains,
            });
            if cross.len() >= MAX_CROSS_CUTTING {
                break;
            }
        }
    }
    // Sort for determinism.
    cross.sort_by(|a, b| a.topic.cmp(&b.topic));
    cross
}

/// ISO week label for a Unix second timestamp: `"YYYY-Www"`.
fn iso_week_label(unix_secs: i64) -> String {
    // Days since Unix epoch → weekday offset + week number.
    // Simplified ISO 8601 week: week 1 contains the first Thursday.
    let days = unix_secs / 86_400;
    // Jan 1 1970 was a Thursday (ISO weekday 4). Days since Monday of week 1:
    // The ISO week number can be approximated as:
    //   week = (days + 3) / 7 + 1   — close enough for labelling purposes.
    // For a label we use: year derived from days + ISO week.
    // Since this is just a label (not scheduling logic), we keep it simple.
    let approx_year = 1970 + (days / 365);
    let day_of_year = days % 365;
    let week_num = (day_of_year / 7) + 1;
    format!("{:04}-W{:02}", approx_year, week_num.clamp(1, 53))
}

// ---------------------------------------------------------------------------
// Dimension 6 — NN-MEM-05 SWIRL-style skill-performance pass

/// Per-skill aggregated stats computed from the SkillOpt ledger.
struct SkillStats {
    total: usize,
    rejected: usize,
    /// Deltas from accepted proposals only (`score_after - score_before`).
    accepted_deltas: Vec<f64>,
}

/// Dimension 6 — SWIRL-style skill-performance pass (NN-MEM-05).
///
/// Reads `~/.neoth/self_improve_log.json` (the SkillOpt ledger), groups
/// records by skill id, and flags skills whose SkillOpt proposals consistently
/// show low improvement (mean `score_after - score_before < 0.05`) or high
/// rejection rate (`rejected / total > 0.5`).
///
/// For each flagged skill (capped at `MAX_SKILL_SUGGESTIONS`), a natural-language
/// suggestion string is generated that references the operator's top frequency
/// topics from dimension 1, grounding the hint in current work context —
/// the SWIRL "what the operator is doing right now should inform how skills are
/// tuned" principle.
///
/// Pure and synchronous — runs inside `spawn_blocking` alongside dimensions 1–5.
/// Failure-tolerant: an absent or malformed ledger yields an empty vec.
pub(crate) fn compute_skill_perf_pass(
    home: &Path,
    window_start_unix: i64,
    top_topics: &[FrequencyPeak],
) -> Vec<SkillPerfSuggestion> {
    let records = crate::self_improve::load_ledger(home);
    if records.is_empty() {
        return vec![];
    }

    // Group into per-skill stats, filtering to the synthesis window.
    let mut by_skill: HashMap<String, SkillStats> = HashMap::new();
    for rec in &records {
        if rec.at_unix < window_start_unix {
            continue;
        }
        let entry = by_skill.entry(rec.skill.clone()).or_insert(SkillStats {
            total: 0,
            rejected: 0,
            accepted_deltas: Vec::new(),
        });
        entry.total += 1;
        if rec.accepted {
            entry
                .accepted_deltas
                .push(rec.score_after - rec.score_before);
        } else {
            entry.rejected += 1;
        }
    }

    if by_skill.is_empty() {
        return vec![];
    }

    // Build context string from top frequency topics.
    let topic_ctx: String = top_topics
        .iter()
        .take(SUGGESTION_CONTEXT_TOPICS)
        .map(|p| p.topic.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let topic_phrase = if topic_ctx.is_empty() {
        "recent operator work".to_string()
    } else {
        format!("recent focus on {topic_ctx}")
    };

    // Flag skills below thresholds; deterministic order by skill id.
    let mut skill_ids: Vec<&String> = by_skill.keys().collect();
    skill_ids.sort_unstable();

    let mut suggestions: Vec<SkillPerfSuggestion> = Vec::new();

    for skill_id in skill_ids {
        if suggestions.len() >= MAX_SKILL_SUGGESTIONS {
            break;
        }
        let stats = &by_skill[skill_id];
        if stats.total == 0 {
            continue;
        }

        let rejection_rate = stats.rejected as f64 / stats.total as f64;
        let score_delta_mean = if stats.accepted_deltas.is_empty() {
            0.0
        } else {
            stats.accepted_deltas.iter().sum::<f64>() / stats.accepted_deltas.len() as f64
        };

        let low_delta =
            !stats.accepted_deltas.is_empty() && score_delta_mean < SKILL_PERF_MIN_SCORE_DELTA;
        let high_rejection = rejection_rate > SKILL_PERF_MAX_REJECTION_RATE;

        if !low_delta && !high_rejection {
            continue;
        }

        let signal_kind = if low_delta && high_rejection {
            "low_score_delta+high_rejection_rate".to_string()
        } else if low_delta {
            "low_score_delta".to_string()
        } else {
            "high_rejection_rate".to_string()
        };

        let suggestion = if high_rejection && !low_delta {
            format!(
                "Skill `{skill_id}` had {:.0}% of SkillOpt proposals rejected in this synthesis \
                 window. Given {topic_phrase}, review whether the skill's system prompt \
                 accurately reflects the operator's current priorities and task patterns. \
                 Consider broadening its framing or clarifying its scope.",
                rejection_rate * 100.0,
            )
        } else {
            format!(
                "Skill `{skill_id}` accepted proposals show a mean score improvement of only \
                 {score_delta_mean:.3} (threshold {SKILL_PERF_MIN_SCORE_DELTA}). Given \
                 {topic_phrase}, the skill prompt may not be aligned with current work patterns. \
                 Consider refining its system prompt to better match these topics.",
            )
        };

        suggestions.push(SkillPerfSuggestion {
            skill_id: skill_id.clone(),
            signal_kind,
            score_delta_mean,
            rejection_rate,
            suggestion,
        });
    }

    suggestions
}

// ---------------------------------------------------------------------------
// Main tick function

/// One synthesis tick. Opens `db_path`, runs all 5 dimensions, writes the
/// result as an evidence-bound `idx_groundtruth` row (`source =
/// "synthesis-cron"`, `scope = "meta"`), and optionally writes
/// `home/synthesis/YYYY-WW.md` via atomic tempfile rename. With no contributing
/// episode the tick still reports its analysis but persists neither output.
///
/// Returns `Ok(SynthesisReport)` on success. A missing `db_path` (fresh
/// install with no views.db yet) is treated as a graceful no-op → `Ok` with
/// all-zero counts, `note_written = false`. Any other error is returned as
/// `Err(String)`.
///
/// Pure + synchronous — intended to be called inside `tokio::task::spawn_blocking`.
pub fn run_synthesis_tick_once(
    db_path: &Path,
    home: &Path,
    config: &SynthesisCronConfig,
) -> Result<SynthesisReport, String> {
    // Fresh install: no views.db yet → graceful no-op.
    if !db_path.exists() {
        tracing::debug!(
            path = %db_path.display(),
            "synthesis cron: views.db absent — skipping tick (NN-MEM-02)"
        );
        return Ok(SynthesisReport::default());
    }

    let conn =
        crate::memory::store::open(db_path).map_err(|e| format!("synthesis cron: open db: {e}"))?;

    let now_ns = crate::time::now_unix_ns_i64();
    let now_unix = now_ns / 1_000_000_000;
    // Look-back window in nanoseconds.
    let window_ns = (config.window_days as i64)
        .saturating_mul(86_400)
        .saturating_mul(1_000_000_000);
    let window_start_ns = now_ns.saturating_sub(window_ns);

    // ── Dimension 1+2: frequency peaks + temporal clusters ──────────────────
    let (frequency_peaks, temporal_clusters, evidence_ids) =
        compute_frequency_and_temporal(&conn, window_start_ns, now_ns);

    // ── Dimension 3: domain correlations ────────────────────────────────────
    let domain_correlations = compute_domain_correlations(&conn, &frequency_peaks);

    // ── Dimension 4: contradiction flags ────────────────────────────────────
    let contradiction_flags = compute_contradiction_flags(&conn, &frequency_peaks);

    // ── Dimension 5: cross-cutting topics ───────────────────────────────────
    let cross_cutting = compute_cross_cutting(&conn, window_start_ns, now_ns, &frequency_peaks);

    // ── Dimension 6 (NN-MEM-05): SWIRL-style skill-perf pass ────────────────
    let window_start_unix = window_start_ns / 1_000_000_000;
    let skill_perf_suggestions = if config.enable_skill_perf_pass {
        compute_skill_perf_pass(home, window_start_unix, &frequency_peaks)
    } else {
        vec![]
    };
    let skill_suggestions_written = skill_perf_suggestions.len();

    // ── HERMES-06 GAP-B: SkillPerfSuggestion → staged ConfigTweak proposals ──
    // Runs after the perf pass so `skill_perf_suggestions` is fully populated.
    // Best-effort: staging errors are logged at warn level, never propagated.
    let skill_proposals_staged = if config.propose_skills_from_perf {
        stage_skill_perf_proposals(home, &skill_perf_suggestions, now_unix)
    } else {
        0
    };
    if skill_proposals_staged > 0 {
        tracing::info!(
            skill_proposals_staged,
            "HERMES-06 GAP-B: staged SkillPerfSuggestion proposal(s) for operator review"
        );
    }

    let topics_analyzed = frequency_peaks.len();
    let correlations_found = domain_correlations.len();
    let contradictions_flagged = contradiction_flags.len();

    // ── Build the synthesis note ─────────────────────────────────────────────
    let week_iso = iso_week_label(now_unix);
    let note = SynthesisNote {
        week_iso: week_iso.clone(),
        frequency_peaks,
        temporal_clusters,
        domain_correlations,
        contradiction_flags,
        cross_cutting,
        skill_perf_suggestions,
    };

    let statement =
        serde_json::to_string(&note).map_err(|e| format!("synthesis cron: serialise note: {e}"))?;

    // ── Write to idx_groundtruth ─────────────────────────────────────────────
    // Use the `Synthesis` source variant (→ as_str() = "synthesis-cron").
    // scope = "meta" so operators can query with `neoth groundtruth list --scope meta`.
    let note_written = if evidence_ids.is_empty() {
        tracing::debug!(
            week = %week_iso,
            "synthesis cron: no contributing episodes; refusing to write orphan synthesis"
        );
        false
    } else {
        match crate::memory::groundtruth::insert_with_evidence(
            &conn,
            &statement,
            &crate::memory::groundtruth::Source::Synthesis,
            "meta",
            now_ns,
            &evidence_ids,
        ) {
            Ok(id) => {
                tracing::info!(
                    id,
                    week = %week_iso,
                    topics = topics_analyzed,
                    correlations = correlations_found,
                    contradictions = contradictions_flagged,
                    evidence_episodes = evidence_ids.len(),
                    skill_suggestions = skill_suggestions_written,
                    "NN-MEM-02/NN-MEM-03/NN-MEM-05: synthesis note written to idx_groundtruth"
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "synthesis cron: evidence-bound groundtruth insert failed (non-fatal)"
                );
                false
            }
        }
    };

    // ── Optional vault write (~/.neoth/synthesis/YYYY-WW.md) ────────────────
    // Atomic tmp→rename to avoid race with JV-IMP-05 vault writer.
    let synthesis_dir = home.join("synthesis");
    let vault_path = synthesis_dir.join(format!("{week_iso}.md"));
    let tmp_path = synthesis_dir.join(format!(".{week_iso}.md.tmp"));

    if !note_written {
        tracing::debug!(
            evidence_episodes = evidence_ids.len(),
            "synthesis cron: vault note skipped because no evidence-bound groundtruth row committed"
        );
    } else if let Err(e) = std::fs::create_dir_all(&synthesis_dir) {
        tracing::debug!(error = %e, "synthesis cron: could not create synthesis dir (non-fatal)");
    } else {
        let md = build_synthesis_markdown(&note, now_unix);
        match std::fs::write(&tmp_path, md.as_bytes()) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp_path, &vault_path) {
                    tracing::debug!(
                        error = %e,
                        "synthesis cron: vault file rename failed (non-fatal)"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "synthesis cron: vault file write failed (non-fatal)"
                );
            }
        }
    }

    Ok(SynthesisReport {
        topics_analyzed,
        correlations_found,
        contradictions_flagged,
        note_written,
        skill_suggestions_written,
        skill_proposals_staged,
    })
}

// ── HERMES-06 GAP-B: SkillPerfSuggestion → staged proposal ─────────────────

/// For each [`SkillPerfSuggestion`] from the SWIRL pass, forge a
/// `ProposalKind::ConfigTweak` candidate and stage it in the OB-03 proactive
/// review queue.
///
/// Called synchronously from within `spawn_blocking` (already off the async
/// executor) so blocking FS ops are correct here. Best-effort — every error is
/// logged at `warn` level; staging continues for the remaining suggestions.
///
/// Returns the count of newly enqueued proposals.
fn stage_skill_perf_proposals(
    home: &Path,
    suggestions: &[SkillPerfSuggestion],
    tick_ts_unix: i64,
) -> usize {
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::{
        ProposalKind, ProposalStatus, ProposedAction, make_proposal_id, stage_and_enqueue,
    };

    if suggestions.is_empty() {
        return 0;
    }

    let queue_path = home.join("proactive_queue.json");
    // Locked load→mutate→save; tolerates a corrupt file (same as the old
    // `unwrap_or_default()`) by logging + returning 0.
    match ProactiveQueue::modify(&queue_path, |queue| {
        let mut staged = 0usize;

        for s in suggestions {
            // Produce a minimal YAML block describing what the operator should
            // review. The `ConfigTweak` kind signals "this is about a config or
            // skill prompt change", not a new skill file.
            let draft_yaml = format!(
                "# HERMES-06 SkillPerfSuggestion\nskill_id: {skill_id}\nsignal_kind: {signal_kind}\n\
                 score_delta_mean: {score_delta_mean:.4}\nrejection_rate: {rejection_rate:.4}\n\
                 suggestion: |\n  {suggestion}\n",
                skill_id = s.skill_id,
                signal_kind = s.signal_kind,
                score_delta_mean = s.score_delta_mean,
                rejection_rate = s.rejection_rate,
                suggestion = s.suggestion.replace('\n', "\n  "),
            );
            let title = format!("Skill prompt review: {}", s.skill_id);
            let rationale = format!(
                "The weekly synthesis SWIRL pass detected a performance concern for skill `{}`.\n\n\
                 Signal: **{}** (score delta mean: {:.3}, rejection rate: {:.1}%).\n\n\
                 Suggestion: {}\n\n\
                 Review the YAML draft; `accept` acknowledges the suggestion and logs it, \
                 `reject` discards it. No files are modified automatically.",
                s.skill_id,
                s.signal_kind,
                s.score_delta_mean,
                s.rejection_rate * 100.0,
                s.suggestion,
            );
            let proposal_id =
                make_proposal_id(ProposalKind::ConfigTweak, &title, &draft_yaml, tick_ts_unix);
            let proposal = ProposedAction {
                id: proposal_id,
                kind: ProposalKind::ConfigTweak,
                title,
                rationale,
                draft_yaml,
                generated_ts_unix: tick_ts_unix,
                status: ProposalStatus::Pending,
                operator_note: String::new(),
            };
            match stage_and_enqueue(home, proposal, queue) {
                Ok((_, true)) => staged += 1,
                Ok((_, false)) => {} // dedup: already in queue from a prior tick
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        skill_id = %s.skill_id,
                        "synthesis cron: SkillPerfSuggestion proposal staging failed"
                    );
                }
            }
        }

        // Persist only when at least one new proposal was staged.
        (staged > 0, staged)
    }) {
        Ok(staged) => staged,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "synthesis cron: queue load/save failed, HERMES-06 GAP-B staging skipped"
            );
            0
        }
    }
}

/// Render the synthesis note as a human-readable Obsidian markdown file.
fn build_synthesis_markdown(note: &SynthesisNote, now_unix: i64) -> String {
    let mut md = format!(
        "---\nweek: {}\ngenerated_unix: {}\nsource: synthesis-cron\n---\n\n\
         # Weekly Synthesis — {}\n\n",
        note.week_iso, now_unix, note.week_iso
    );

    md.push_str("## Frequency Peaks\n\n");
    if note.frequency_peaks.is_empty() {
        md.push_str("_(no topics this week)_\n");
    } else {
        for p in &note.frequency_peaks {
            md.push_str(&format!("- **{}**: {} mention(s)\n", p.topic, p.count));
        }
    }

    md.push_str("\n## Temporal Clusters\n\n");
    if note.temporal_clusters.is_empty() {
        md.push_str("_(no dense clusters detected)_\n");
    } else {
        for c in &note.temporal_clusters {
            md.push_str(&format!(
                "- Day +{}, {} day(s): {}\n",
                c.window_start_day,
                c.window_days,
                c.topics.join(", ")
            ));
        }
    }

    md.push_str("\n## Domain Correlations\n\n");
    if note.domain_correlations.is_empty() {
        md.push_str("_(no groundtruth correlations)_\n");
    } else {
        for dc in &note.domain_correlations {
            md.push_str(&format!(
                "- gt#{}: `{}` (overlap: {:.2})\n",
                dc.gt_id, dc.topic, dc.overlap
            ));
        }
    }

    md.push_str("\n## Contradiction Flags\n\n");
    if note.contradiction_flags.is_empty() {
        md.push_str("_(no pending contradictions overlap top topics)_\n");
    } else {
        for f in &note.contradiction_flags {
            md.push_str(&format!("- ledger#{}: {}\n", f.id, f.statement));
        }
    }

    md.push_str("\n## Cross-Cutting Topics\n\n");
    if note.cross_cutting.is_empty() {
        md.push_str("_(no cross-cutting topics detected)_\n");
    } else {
        for cc in &note.cross_cutting {
            md.push_str(&format!("- **{}**: {}\n", cc.topic, cc.domains.join(" + ")));
        }
    }

    md
}

// ---------------------------------------------------------------------------
// Spawn helper

/// Spawn the synthesis pattern-recognition cron loop as a background tokio task.
///
/// Returns `None` when `config.enabled == false` — opt-out operators carry no
/// idle task. Mirrors [`super::contradiction_resolve_cron::spawn_contradiction_resolve_cron_loop`].
///
/// `db_path` is typically `~/.neoth/views.db` (use `memory::store::default_path()`).
/// `home` is `~/.neoth/` (use `FreedomConfig::default_neoth_home()`).
pub fn spawn_synthesis_cron_loop(
    config: SynthesisCronConfig,
    db_path: PathBuf,
    home: PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            window_days = config.window_days,
            "synthesis pattern-recognition cron online (NN-MEM-02)",
        );
        loop {
            ticker.tick().await;
            let db2 = db_path.clone();
            let home2 = home.clone();
            let cfg2 = config;
            let _ = tokio::task::spawn_blocking(move || {
                match run_synthesis_tick_once(&db2, &home2, &cfg2) {
                    Ok(report) => tracing::info!(
                        topics_analyzed = report.topics_analyzed,
                        correlations_found = report.correlations_found,
                        contradictions_flagged = report.contradictions_flagged,
                        note_written = report.note_written,
                        skill_suggestions_written = report.skill_suggestions_written,
                        skill_proposals_staged = report.skill_proposals_staged,
                        "NN-MEM-02/NN-MEM-05/HERMES-06: synthesis cron tick complete",
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        "synthesis cron tick failed (NN-MEM-02)",
                    ),
                }
            })
            .await;
        }
    }))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use std::time::Duration;

    // ── Test 1: disabled → spawn returns None ────────────────────────────────

    #[test]
    fn spawn_synthesis_cron_loop_returns_none_when_disabled() {
        let cfg = SynthesisCronConfig::default();
        assert!(!cfg.enabled, "must be off by default");
        let handle = spawn_synthesis_cron_loop(cfg, "/nonexistent".into(), "/nonexistent".into());
        assert!(handle.is_none(), "disabled config must return None");
    }

    // ── Test 2: enabled → spawn returns Some ─────────────────────────────────

    #[tokio::test]
    async fn spawn_synthesis_cron_loop_returns_some_when_enabled() {
        let cfg = SynthesisCronConfig {
            enabled: true,
            interval_secs: 604_800,
            window_days: 30,
            enable_skill_perf_pass: false,
            propose_skills_from_perf: false,
        };
        let handle = spawn_synthesis_cron_loop(cfg, "/nonexistent".into(), "/nonexistent".into())
            .expect("handle when enabled");
        handle.abort();
        let _ = handle.await; // JoinError on abort expected
    }

    // ── Test 3: no views.db → graceful no-op ─────────────────────────────────

    #[test]
    fn run_synthesis_tick_once_no_db_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = SynthesisCronConfig::default();
        let result = run_synthesis_tick_once(&dir.path().join("views.db"), dir.path(), &cfg);
        assert!(result.is_ok(), "must not error when views.db absent");
        let report = result.unwrap();
        assert!(!report.note_written, "no note when db absent");
    }

    // ── Test 4: seeded db → writes groundtruth row (consumer proof) ──────────

    #[test]
    fn run_synthesis_tick_writes_groundtruth_row() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = store::open(&db_path).unwrap();

        // Seed 6 RAW_TEXT episodes within the 30-day look-back window.
        // Use real current time minus small offsets so they fall inside the window.
        let now_ns = crate::time::now_unix_ns_i64();
        for i in 0i64..6 {
            // Space episodes 1 day apart, all within the last 6 days (well inside 30d window).
            let ts = now_ns - i * 86_400 * 1_000_000_000_i64;
            conn.execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (?1, 1, ?2, 'kubernetes deployment pipeline rust cargo build', ?3, 0.7, ?2)",
                rusqlite::params![
                    i,
                    ts,
                    format!("hash{i}"),
                ],
            )
            .unwrap();
        }
        drop(conn);

        let cfg = SynthesisCronConfig {
            enabled: true,
            interval_secs: 604_800,
            window_days: 30,
            enable_skill_perf_pass: false,
            propose_skills_from_perf: false,
        };
        let report =
            run_synthesis_tick_once(&db_path, dir.path(), &cfg).expect("tick must succeed");

        // Must have analyzed some topics.
        assert!(
            report.topics_analyzed > 0,
            "must analyze topics from seeded episodes"
        );

        // Consumer proof: exactly one synthesis-cron row in idx_groundtruth.
        let conn2 = store::open(&db_path).unwrap();
        let count: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM idx_groundtruth WHERE source = 'synthesis-cron'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "synthesis cron must write exactly one groundtruth row per tick"
        );

        // The row must have scope = 'meta'.
        let (scope, evidence): (String, String) = conn2
            .query_row(
                "SELECT scope, evidence FROM idx_groundtruth WHERE source = 'synthesis-cron'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(scope, "meta");
        assert_eq!(
            serde_json::from_str::<Vec<i64>>(&evidence).unwrap(),
            vec![5, 4, 3, 2, 1, 0],
            "the synthesis note must retain every contributing episode in chronological order"
        );
    }

    #[test]
    fn run_synthesis_tick_refuses_orphan_note_without_episodes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        store::open(&db_path).unwrap();

        let cfg = SynthesisCronConfig {
            enabled: true,
            interval_secs: 604_800,
            window_days: 30,
            enable_skill_perf_pass: false,
            propose_skills_from_perf: false,
        };
        let report = run_synthesis_tick_once(&db_path, dir.path(), &cfg).unwrap();
        assert!(!report.note_written);

        let conn = store::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_groundtruth WHERE source = 'synthesis-cron'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "empty synthesis must not become orphan wisdom");
        assert!(
            !dir.path().join("synthesis").exists(),
            "vault synthesis is skipped when it has no episode provenance"
        );
    }

    #[test]
    fn run_synthesis_tick_does_not_write_vault_when_evidence_insert_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = store::open(&db_path).unwrap();
        let now_ns = crate::time::now_unix_ns_i64();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (91, 1, ?1, 'rust deployment synthesis evidence', 'synth-evidence', 0.7, ?1)",
            rusqlite::params![now_ns],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_synthesis_groundtruth \
             BEFORE INSERT ON idx_groundtruth \
             WHEN NEW.source = 'synthesis-cron' \
             BEGIN SELECT RAISE(FAIL, 'test insert failure'); END;",
        )
        .unwrap();
        drop(conn);

        let report = run_synthesis_tick_once(
            &db_path,
            dir.path(),
            &SynthesisCronConfig {
                enabled: true,
                interval_secs: 604_800,
                window_days: 30,
                enable_skill_perf_pass: false,
                propose_skills_from_perf: false,
            },
        )
        .unwrap();
        assert!(!report.note_written);
        assert!(
            !dir.path().join("synthesis").exists(),
            "a vault file must never outlive a failed evidence-bound DB insert"
        );
    }

    // ── Test 5: config defaults ───────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = SynthesisCronConfig::default();
        assert!(!cfg.enabled, "off by default");
        assert_eq!(
            cfg.interval_secs,
            super::super::super::config::automation::DEFAULT_SYNTHESIS_CRON_INTERVAL_SECS
        );
        assert_eq!(
            cfg.window_days,
            super::super::super::config::automation::DEFAULT_SYNTHESIS_WINDOW_DAYS
        );
        assert_eq!(
            cfg.interval_duration(),
            Duration::from_secs(
                super::super::super::config::automation::DEFAULT_SYNTHESIS_CRON_INTERVAL_SECS
            )
        );
    }

    // ── Test 6: interval floor clamps zero ───────────────────────────────────

    #[test]
    fn interval_floor_clamps_zero() {
        let cfg = SynthesisCronConfig {
            enabled: true,
            interval_secs: 0,
            window_days: 30,
            enable_skill_perf_pass: false,
            propose_skills_from_perf: false,
        };
        assert_eq!(cfg.interval_duration(), Duration::from_secs(60));
    }

    // ── Test 7: Source::Synthesis round-trips correctly ──────────────────────

    #[test]
    fn synthesis_source_as_str() {
        use crate::memory::groundtruth::Source;
        assert_eq!(Source::Synthesis.as_str(), "synthesis-cron");
        assert!(!Source::Synthesis.is_operator_attested());
    }

    // ── Test 8: iso_week_label sanity ────────────────────────────────────────

    #[test]
    fn iso_week_label_format() {
        // Unix epoch 0 = 1970-01-01 (Thursday). Week 1.
        let label = iso_week_label(0);
        assert!(
            label.starts_with("1970-W"),
            "label must start with year-W: {label}"
        );
        // A known timestamp: 2026-06-22 ≈ Unix 1750550400.
        let label2 = iso_week_label(1_750_550_400);
        assert!(label2.starts_with("202"), "year 2026 label: {label2}");
    }

    // ── Test 9: markdown generation smoke test ────────────────────────────────

    #[test]
    fn build_synthesis_markdown_contains_week_label() {
        let note = SynthesisNote {
            week_iso: "2026-W25".to_string(),
            frequency_peaks: vec![FrequencyPeak {
                topic: "kubernetes".to_string(),
                count: 5,
            }],
            temporal_clusters: vec![],
            domain_correlations: vec![],
            contradiction_flags: vec![],
            cross_cutting: vec![],
            skill_perf_suggestions: vec![],
        };
        let md = build_synthesis_markdown(&note, 1_750_000_000);
        assert!(md.contains("2026-W25"), "must contain week label");
        assert!(md.contains("kubernetes"), "must contain topic");
        assert!(
            md.contains("synthesis-cron"),
            "must have source in frontmatter"
        );
    }
}
