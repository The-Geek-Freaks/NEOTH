//! NN-MEM-02 â€” 5-dimensional synthesis pattern-recognition weekly cron.
//!
//! Performs a weekly pass over `idx_episode`, `idx_groundtruth`, and
//! `idx_contradictions` to produce a structured synthesis meta-note. The note
//! captures the five dimensions of understanding gathered across all operator
//! memory:
//!
//! 1. **Frequency** â€” topics most mentioned in the look-back window (which
//!    subjects dominate the operator's recent attention).
//! 2. **Temporal clustering** â€” dense time windows for those topics (when
//!    does the operator focus on specific subjects).
//! 3. **Domain correlation** â€” overlap between high-frequency episode topics
//!    and ground-truth facts already in `idx_groundtruth` (Jaccard shingles,
//!    same engine as `memory::contradiction`).
//! 4. **Contradiction flags** â€” pending contradiction ledger rows whose
//!    subject overlaps a top topic (signals operator attention on a contested
//!    fact).
//! 5. **Cross-cutting meta** â€” topics that appear across multiple domain
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
//!   runs in `spawn_blocking` via a one-shot local runtime â€” same pattern as
//!   `daemon::contradiction_resolve_cron`.
//! - **Atomic vault write**: tmp â†’ rename, eliminating any mutex with
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
    /// Jaccard overlap score (0.0â€“1.0).
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

/// NN-MEM-05 â€” one skill-prompt improvement suggestion from the SWIRL-style pass.
///
/// The synthesis cron reads the SkillOpt ledger (`~/.neoth/self_improve_log.json`)
/// to compute per-skill accepted/rejected ratios and mean score deltas, then flags
/// skills with low improvement signals and generates a natural-language suggestion
/// grounded in the operator's top work topics from dimensions 1â€“4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPerfSuggestion {
    /// The skill id (matches `ImproveRecord.skill`).
    pub skill_id: String,
    /// Why this skill was flagged: `"low_score_delta"` | `"high_rejection_rate"`.
    pub signal_kind: String,
    /// Mean `score_after - score_before` across accepted proposals in the window.
    pub score_delta_mean: f64,
    /// Fraction of all proposals (accepted + rejected) that were rejected (0.0â€“1.0).
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

// â”€â”€ NN-MEM-05 constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

/// Dimension 1+2 â€” frequency peaks + temporal clusters.
///
/// Reads `idx_episode` for RAW_TEXT rows in the look-back window, runs the
/// shared `reflection::topic_counts` tokeniser, and detects 3-day dense
/// clusters (UTC-day buckets with â‰¥3 episodes sharing a top topic).
fn compute_frequency_and_temporal(
    conn: &rusqlite::Connection,
    window_start_ns: i64,
    now_ns: i64,
) -> (Vec<FrequencyPeak>, Vec<TemporalCluster>, Vec<i64>) {
    // â”€â”€ Dimension 1: frequency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // â”€â”€ Dimension 2: temporal clustering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Fetch (ts_ns, text) rows for the window; bucket by UTC day;
    // find consecutive day-buckets where â‰¥2 top topics appear in â‰¥3 episodes.
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
        // Find consecutive-day run (gap â‰¤ 1 day).
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

/// Dimension 3 â€” domain correlations between top topics and groundtruth facts.
///
/// For each active, non-revoked groundtruth row, compute Jaccard shingle
/// overlap with each top topic. Return the top correlating pairs.
fn compute_domain_correlations(
    conn: &rusqlite::Connectioó4¶‰ËkºwµçQ”…Ì„¡Õµ…¸µÉ•…‘…‰±”=‰Í¥‘¥…¸µ…É­‘½İ¸™¥±”¸)™¸‰Õ¥±‘}Íå¹Ñ¡•Í¥Í}µ…É­‘½İ¸¡¹½Ñ”è€™Må¹Ñ¡•Í¥Í9½Ñ”°¹½İ}Õ¹¥àè¤ØĞ¤€´øMÑÉ¥¹œì(€€€±•ĞµÕĞµ€ô™½Éµ…Ğ„ (€€€€€€€€ˆ´´µq¹İ••¬èíõq¹•¹•É…Ñ•‘}Õ¹¥àèíõq¹Í½ÕÉ”èÍå¹Ñ¡•Í¥ÌµÉ½¹q¸´´µq¹q¹p(€€€€€€€€€Œ]••­±äMå¹Ñ¡•Í¥ÌƒŠPíõq¹q¸ˆ°(€€€€€€€¹½Ñ”¹İ••­}¥Í¼°¹½İ}Õ¹¥à°¹½Ñ”¹İ••­}¥Í¼(€€€€¤ì((€€€µ¹ÁÕÍ¡}ÍÑÈ ˆŒŒÉ•ÅÕ•¹äA•…­Íq¹q¸ˆ¤ì(€€€¥˜¹½Ñ”¹™É•ÅÕ•¹å}Á•…­Ì¹¥Í}•µÁÑä ¤ì(€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ‰|¡¹¼Ñ½Á¥ÌÑ¡¥Ìİ••¬¥}q¸ˆ¤ì(€€€ô•±Í”ì(€€€€€€€™½ÈÀ¥¸€™¹½Ñ”¹™É•ÅÕ•¹å}Á•…­Ìì(€€€€€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ™™½Éµ…Ğ„ ˆ´€¨©íô¨¨èíôµ•¹Ñ¥½¸¡Ì¥q¸ˆ°À¹Ñ½Á¥Œ°À¹½Õ¹Ğ¤¤ì(€€€€€€€ô(€€€ô((€€€µ¹ÁÕÍ¡}ÍÑÈ ‰q¸ŒŒQ•µÁ½É…°±ÕÍÑ•ÉÍq¹q¸ˆ¤ì(€€€¥˜¹½Ñ”¹Ñ•µÁ½É…±}±ÕÍÑ•ÉÌ¹¥Í}•µÁÑä ¤ì(€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ‰|¡¹¼‘•¹Í”±ÕÍÑ•ÉÌ‘•Ñ•Ñ•¥}q¸ˆ¤ì(€€€ô•±Í”ì(€€€€€€€™½ÈŒ¥¸€™¹½Ñ”¹Ñ•µÁ½É…±}±ÕÍÑ•ÉÌì(€€€€€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ™™½Éµ…Ğ„ (€€€€€€€€€€€€€€€€ˆ´…ä€­íô°íô‘…ä¡Ì¤èíõq¸ˆ°(€€€€€€€€€€€€€€€Œ¹İ¥¹‘½İ}ÍÑ…ÉÑ}‘…ä°(€€€€€€€€€€€€€€€Œ¹İ¥¹‘½İ}‘…åÌ°(€€€€€€€€€€€€€€€Œ¹Ñ½Á¥Ì¹©½¥¸ ˆ°€ˆ¤(€€€€€€€€€€€€¤¤ì(€€€€€€€ô(€€€ô((€€€µ¹ÁÕÍ¡}ÍÑÈ ‰q¸ŒŒ½µ…¥¸½ÉÉ•±…Ñ¥½¹Íq¹q¸ˆ¤ì(€€€¥˜¹½Ñ”¹‘½µ…¥¹}½ÉÉ•±…Ñ¥½¹Ì¹¥Í}•µÁÑä ¤ì(€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ‰|¡¹¼É½Õ¹‘ÑÉÕÑ ½ÉÉ•±…Ñ¥½¹Ì¥}q¸ˆ¤ì(€€€ô•±Í”ì(€€€€€€€™½È‘Œ¥¸€™¹½Ñ”¹‘½µ…¥¹}½ÉÉ•±…Ñ¥½¹Ìì(€€€€€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ™™½Éµ…Ğ„ (€€€€€€€€€€€€€€€€ˆ´Ğíôèíõ€€¡½Ù•É±…Àèìè¸Éô¥q¸ˆ°(€€€€€€€€€€€€€€€‘Œ¹Ñ}¥°‘Œ¹Ñ½Á¥Œ°‘Œ¹½Ù•É±…À(€€€€€€€€€€€€¤¤ì(€€€€€€€ô(€€€ô((€€€µ¹ÁÕÍ¡}ÍÑÈ ‰q¸ŒŒ½¹ÑÉ…‘¥Ñ¥½¸±…Íq¹q¸ˆ¤ì(€€€¥˜¹½Ñ”¹½¹ÑÉ…‘¥Ñ¥½¹}™±…Ì¹¥Í}•µÁÑä ¤ì(€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ‰|¡¹¼Á•¹‘¥¹œ½¹ÑÉ…‘¥Ñ¥½¹Ì½Ù•É±…ÀÑ½ÀÑ½Á¥Ì¥}q¸ˆ¤ì(€€€ô•±Í”ì(€€€€€€€™½È˜¥¸€™¹½Ñ”¹½¹ÑÉ…‘¥Ñ¥½¹}™±…Ìì(€€€€€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ™™½Éµ…Ğ„ ˆ´±•‘•Èíôèíõq¸ˆ°˜¹¥°˜¹ÍÑ…Ñ•µ•¹Ğ¤¤ì(€€€€€€€ô(€€€ô((€€€µ¹ÁÕÍ¡}ÍÑÈ ‰q¸ŒŒÉ½ÍÌµÕÑÑ¥¹œQ½Á¥Íq¹q¸ˆ¤ì(€€€¥˜¹½Ñ”¹É½ÍÍ}ÕÑÑ¥¹œ¹¥Í}•µÁÑä ¤ì(€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ‰|¡¹¼É½ÍÌµÕÑÑ¥¹œÑ½Á¥Ì‘•Ñ•Ñ•¥}q¸ˆ¤ì(€€€ô•±Í”ì(€€€€€€€™½ÈŒ¥¸€™¹½Ñ”¹É½ÍÍ}ÕÑÑ¥¹œì(€€€€€€€€€€€µ¹ÁÕÍ¡}ÍÑÈ ™™½Éµ…Ğ„ ˆ´€¨©íô¨¨èíõq¸ˆ°Œ¹Ñ½Á¥Œ°Œ¹‘½µ…¥¹Ì¹©½¥¸ ˆ€¬€ˆ¤¤¤ì(€€€€€€€ô(€€€ô((€€€µ)ô((¼¼€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´(¼¼MÁ…İ¸¡•±Á•È((¼¼¼MÁ…İ¸Ñ¡”Íå¹Ñ¡•Í¥ÌÁ…ÑÑ•É¸µÉ•½¹¥Ñ¥½¸É½¸±½½À…Ì„‰…­É½Õ¹Ñ½­¥¼Ñ…Í¬¸(¼¼¼(¼¼¼I•ÑÕÉ¹Ì9½¹•€İ¡•¸½¹™¥œ¹•¹…‰±•€ôô™…±Í•€ƒŠP½ÁĞµ½ÕĞ½Á•É…Ñ½ÉÌ…ÉÉä¹¼(¼¼¼¥‘±”Ñ…Í¬¸5¥ÉÉ½ÉÌmÍÕÁ•Èèé½¹ÑÉ…‘¥Ñ¥½¹}É•Í½±Ù•}É½¸èéÍÁ…İ¹}½¹ÑÉ…‘¥Ñ¥½¹}É•Í½±Ù•}É½¹}±½½Át¸(¼¼¼(¼¼¼‘‰}Á…Ñ¡€¥ÌÑåÁ¥…±±äø¼¹¹•½Ñ ½Ù¥•İÌ¹‘‰€€¡ÕÍ”µ•µ½ÉäèéÍÑ½É”èé‘•™…Õ±Ñ}Á…Ñ  ¥€¤¸(¼¼¼¡½µ•€¥Ìø¼¹¹•½Ñ ½€€¡ÕÍ”É••‘½µ½¹™¥œèé‘•™…Õ±Ñ}¹•½Ñ¡}¡½µ” ¥€¤¸)ÁÕˆ™¸ÍÁ…İ¹}Íå¹Ñ¡•Í¥Í}É½¹}±½½À (€€€½¹™¥œèMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œ°(€€€‘‰}Á…Ñ èA…Ñ¡	Õ˜°(€€€¡½µ”èA…Ñ¡	Õ˜°(¤€´ø=ÁÑ¥½¸ñÑ½­¥¼èéÑ…Í¬èé)½¥¹!…¹‘±”ğ ¤øøì(€€€¥˜€…½¹™¥œ¹•¹…‰±•ì(€€€€€€€É•ÑÕÉ¸9½¹”ì(€€€ô(€€€±•Ğ¥¹Ñ•ÉÙ…°€ô½¹™¥œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤ì(€€€M½µ”¡Ñ½­¥¼èéÍÁ…İ¸¡…Íå¹Œµ½Ù”ì(€€€€€€€±•ĞµÕĞÑ¥­•È€ôÑ½­¥¼èéÑ¥µ”èé¥¹Ñ•ÉÙ…°¡¥¹Ñ•ÉÙ…°¤ì(€€€€€€€Ñ¥­•È¹Í•Ñ}µ¥ÍÍ•‘}Ñ¥­}‰•¡…Ù¥½È¡Ñ½­¥¼èéÑ¥µ”èé5¥ÍÍ•‘Q¥­	•¡…Ù¥½ÈèéM­¥À¤ì(€€€€€€€ÑÉ…¥¹œèé¥¹™¼„ (€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ì€ô¥¹Ñ•ÉÙ…°¹…Í}Í•Ì ¤°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌ€ô½¹™¥œ¹İ¥¹‘½İ}‘…åÌ°(€€€€€€€€€€€€‰Íå¹Ñ¡•Í¥ÌÁ…ÑÑ•É¸µÉ•½¹¥Ñ¥½¸É½¸½¹±¥¹”€¡98µ54´ÀÈ¤ˆ°(€€€€€€€€¤ì(€€€€€€€±½½Àì(€€€€€€€€€€€Ñ¥­•È¹Ñ¥¬ ¤¹…İ…¥Ğì(€€€€€€€€€€€±•Ğ‘ˆÈ€ô‘‰}Á…Ñ ¹±½¹” ¤ì(€€€€€€€€€€€±•Ğ¡½µ”È€ô¡½µ”¹±½¹” ¤ì(€€€€€€€€€€€±•Ğ™œÈ€ô½¹™¥œì(€€€€€€€€€€€±•Ğ|€ôÑ½­¥¼èéÑ…Í¬èéÍÁ…İ¹}‰±½­¥¹œ¡µ½Ù”ñğì(€€€€€€€€€€€€€€€µ…Ñ ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹” ™‘ˆÈ°€™¡½µ”È°€™™œÈ¤ì(€€€€€€€€€€€€€€€€€€€=¬¡É•Á½ÉĞ¤€ôøÑÉ…¥¹œèé¥¹™¼„ (€€€€€€€€€€€€€€€€€€€€€€€Ñ½Á¥Í}…¹…±åé•€ôÉ•Á½ÉĞ¹Ñ½Á¥Í}…¹…±åé•°(€€€€€€€€€€€€€€€€€€€€€€€½ÉÉ•±…Ñ¥½¹Í}™½Õ¹€ôÉ•Á½ÉĞ¹½ÉÉ•±…Ñ¥½¹Í}™½Õ¹°(€€€€€€€€€€€€€€€€€€€€€€€½¹ÑÉ…‘¥Ñ¥½¹Í}™±…•€ôÉ•Á½ÉĞ¹½¹ÑÉ…‘¥Ñ¥½¹Í}™±…•°(€€€€€€€€€€€€€€€€€€€€€€€¹½Ñ•}İÉ¥ÑÑ•¸€ôÉ•Á½ÉĞ¹¹½Ñ•}İÉ¥ÑÑ•¸°(€€€€€€€€€€€€€€€€€€€€€€€Í­¥±±}ÍÕ•ÍÑ¥½¹Í}İÉ¥ÑÑ•¸€ôÉ•Á½ÉĞ¹Í­¥±±}ÍÕ•ÍÑ¥½¹Í}İÉ¥ÑÑ•¸°(€€€€€€€€€€€€€€€€€€€€€€€Í­¥±±}ÁÉ½Á½Í…±Í}ÍÑ…•€ôÉ•Á½ÉĞ¹Í­¥±±}ÁÉ½Á½Í…±Í}ÍÑ…•°(€€€€€€€€€€€€€€€€€€€€€€€€‰98µ54´ÀÈ½98µ54´ÀÔ½!I5L´ÀØèÍå¹Ñ¡•Í¥ÌÉ½¸Ñ¥¬½µÁ±•Ñ”ˆ°(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€€€€€ÉÈ¡”¤€ôøÑÉ…¥¹œèé•ÉÉ½È„ (€€€€€€€€€€€€€€€€€€€€€€€•ÉÉ½È€ô€•”°(€€€€€€€€€€€€€€€€€€€€€€€€‰Íå¹Ñ¡•Í¥ÌÉ½¸Ñ¥¬™…¥±•€¡98µ54´ÀÈ¤ˆ°(€€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€ô(€€€€€€€€€€€ô¤(€€€€€€€€€€€€¹…İ…¥Ğì(€€€€€€€ô(€€€ô¤¤)ô((¼¼€´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´´(¼¼Q•ÍÑÌ((m™œ¡Ñ•ÍĞ¥t)µ½Ñ•ÍÑÌì(€€€ÕÍ”ÍÕÁ•Èèè¨ì(€€€ÕÍ”É…Ñ”èéµ•µ½ÉäèéÍÑ½É”ì(€€€ÕÍ”ÍÑèéÑ¥µ”èéÕÉ…Ñ¥½¸ì((€€€€¼¼ƒŠRŠR Q•ÍĞ€Äè‘¥Í…‰±•ƒŠHÍÁ…İ¸É•ÑÕÉ¹Ì9½¹”ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸ÍÁ…İ¹}Íå¹Ñ¡•Í¥Í}É½¹}±½½Á}É•ÑÕÉ¹Í}¹½¹•}İ¡•¹}‘¥Í…‰±• ¤ì(€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …™œ¹•¹…‰±•°€‰µÕÍĞ‰”½™˜‰ä‘•™…Õ±Ğˆ¤ì(€€€€€€€±•Ğ¡…¹‘±”€ôÍÁ…İ¹}Íå¹Ñ¡•Í¥Í}É½¹}±½½À¡™œ°€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤¤ì(€€€€€€€…ÍÍ•ÉĞ„¡¡…¹‘±”¹¥Í}¹½¹” ¤°€‰‘¥Í…‰±•½¹™¥œµÕÍĞÉ•ÑÕÉ¸9½¹”ˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€Èè•¹…‰±•ƒŠHÍÁ…İ¸É•ÑÕÉ¹ÌM½µ”ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ½­¥¼èéÑ•ÍÑt(€€€…Íå¹Œ™¸ÍÁ…İ¹}Íå¹Ñ¡•Í¥Í}É½¹}±½½Á}É•ÑÕÉ¹Í}Í½µ•}İ¡•¹}•¹…‰±• ¤ì(€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€ØÀÑ|àÀÀ°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌè€ÌÀ°(€€€€€€€€€€€•¹…‰±•}Í­¥±±}Á•É™}Á…ÍÌè™…±Í”°(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Í}™É½µ}Á•É˜è™…±Í”°(€€€€€€€ôì(€€€€€€€±•Ğ¡…¹‘±”€ôÍÁ…İ¹}Íå¹Ñ¡•Í¥Í}É½¹}±½½À¡™œ°€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤°€ˆ½¹½¹•á¥ÍÑ•¹Ğˆ¹¥¹Ñ¼ ¤¤(€€€€€€€€€€€€¹•áÁ•Ğ ‰¡…¹‘±”İ¡•¸•¹…‰±•ˆ¤ì(€€€€€€€¡…¹‘±”¹…‰½ÉĞ ¤ì(€€€€€€€±•Ğ|€ô¡…¹‘±”¹…İ…¥Ğì€¼¼)½¥¹ÉÉ½È½¸…‰½ÉĞ•áÁ•Ñ•(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€Ìè¹¼Ù¥•İÌ¹‘ˆƒŠHÉ…•™Õ°¹¼µ½ÀƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹•}¹½}‘‰}É•ÑÕÉ¹Í}½¬ ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€±•ĞÉ•ÍÕ±Ğ€ôÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹” ™‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤°‘¥È¹Á…Ñ  ¤°€™™œ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡É•ÍÕ±Ğ¹¥Í}½¬ ¤°€‰µÕÍĞ¹½Ğ•ÉÉ½Èİ¡•¸Ù¥•İÌ¹‘ˆ…‰Í•¹Ğˆ¤ì(€€€€€€€±•ĞÉ•Á½ÉĞ€ôÉ•ÍÕ±Ğ¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …É•Á½ÉĞ¹¹½Ñ•}İÉ¥ÑÑ•¸°€‰¹¼¹½Ñ”İ¡•¸‘ˆ…‰Í•¹Ğˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€ĞèÍ••‘•‘ˆƒŠHİÉ¥Ñ•ÌÉ½Õ¹‘ÑÉÕÑ É½Ü€¡½¹ÍÕµ•ÈÁÉ½½˜¤ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}İÉ¥Ñ•Í}É½Õ¹‘ÑÉÕÑ¡}É½Ü ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€±•Ğ½¹¸€ôÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤ì((€€€€€€€€¼¼M••€ØI]}QaP•Á¥Í½‘•Ìİ¥Ñ¡¥¸Ñ¡”€ÌÀµ‘…ä±½½¬µ‰…¬İ¥¹‘½Ü¸(€€€€€€€€¼¼UÍ”É•…°ÕÉÉ•¹ĞÑ¥µ”µ¥¹ÕÌÍµ…±°½™™Í•ÑÌÍ¼Ñ¡•ä™…±°¥¹Í¥‘”Ñ¡”İ¥¹‘½Ü¸(€€€€€€€±•Ğ¹½İ}¹Ì€ôÉ…Ñ”èéÑ¥µ”èé¹½İ}Õ¹¥á}¹Í}¤ØĞ ¤ì(€€€€€€€™½È¤¥¸€Á¤ØĞ¸¸Øì(€€€€€€€€€€€€¼¼MÁ…”•Á¥Í½‘•Ì€Ä‘…ä…Á…ÉĞ°…±°İ¥Ñ¡¥¸Ñ¡”±…ÍĞ€Ø‘…åÌ€¡İ•±°¥¹Í¥‘”€ÌÁİ¥¹‘½Ü¤¸(€€€€€€€€€€€±•ĞÑÌ€ô¹½İ}¹Ì€´¤€¨€àÙ|ĞÀÀ€¨€Å|ÀÀÁ|ÀÀÁ|ÀÀÁ}¤ØĞì(€€€€€€€€€€€½¹¸¹•á•ÕÑ” (€€€€€€€€€€€€€€€€‰%9MIP%9Q<¥‘á}•Á¥Í½‘”p(€€€€€€€€€€€€€€€€€¡•Ù•¹Ñ}¥°•Ù•¹Ñ}ÑåÁ”°ÑÍ}¹Ì°Ñ•áĞ°Ñ•áÑ}¡…Í °¥µÁ½ÉÑ…¹”°±…ÍÑ}…•ÍÍ}ÑÌ¤p(€€€€€€€€€€€€€€€€Y1UL€ üÄ°€Ä°€üÈ°€­Õ‰•É¹•Ñ•Ì‘•Á±½åµ•¹ĞÁ¥Á•±¥¹”ÉÕÍĞ…É¼‰Õ¥±œ°€üÌ°€À¸Ü°€üÈ¤ˆ°(€€€€€€€€€€€€€€€ÉÕÍÅ±¥Ñ”èéÁ…É…µÌ…l(€€€€€€€€€€€€€€€€€€€¤°(€€€€€€€€€€€€€€€€€€€ÑÌ°(€€€€€€€€€€€€€€€€€€€™½Éµ…Ğ„ ‰¡…Í¡í¥ôˆ¤°(€€€€€€€€€€€€€€€t°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€ô(€€€€€€€‘É½À¡½¹¸¤ì((€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€ØÀÑ|àÀÀ°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌè€ÌÀ°(€€€€€€€€€€€•¹…‰±•}Í­¥±±}Á•É™}Á…ÍÌè™…±Í”°(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Í}™É½µ}Á•É˜è™…±Í”°(€€€€€€€ôì(€€€€€€€±•ĞÉ•Á½ÉĞ€ô(€€€€€€€€€€€ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹” ™‘‰}Á…Ñ °‘¥È¹Á…Ñ  ¤°€™™œ¤¹•áÁ•Ğ ‰Ñ¥¬µÕÍĞÍÕ••ˆ¤ì((€€€€€€€€¼¼5ÕÍĞ¡…Ù”…¹…±åé•Í½µ”Ñ½Á¥Ì¸(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€É•Á½ÉĞ¹Ñ½Á¥Í}…¹…±åé•€ø€À°(€€€€€€€€€€€€‰µÕÍĞ…¹…±åé”Ñ½Á¥Ì™É½´Í••‘••Á¥Í½‘•Ìˆ(€€€€€€€€¤ì((€€€€€€€€¼¼½¹ÍÕµ•ÈÁÉ½½˜è•á…Ñ±ä½¹”Íå¹Ñ¡•Í¥ÌµÉ½¸É½Ü¥¸¥‘á}É½Õ¹‘ÑÉÕÑ ¸(€€€€€€€±•Ğ½¹¸È€ôÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ½Õ¹Ğè¤ØĞ€ô½¹¸È(€€€€€€€€€€€€¹ÅÕ•Éå}É½Ü (€€€€€€€€€€€€€€€€‰M1P=U9P ¨¤I=4¥‘á}É½Õ¹‘ÑÉÕÑ ]!IÍ½ÕÉ”€ô€Íå¹Ñ¡•Í¥ÌµÉ½¸œˆ°(€€€€€€€€€€€€€€€mt°(€€€€€€€€€€€€€€€ñÉğÈ¹•Ğ À¤°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€½Õ¹Ğ°€Ä°(€€€€€€€€€€€€‰Íå¹Ñ¡•Í¥ÌÉ½¸µÕÍĞİÉ¥Ñ”•á…Ñ±ä½¹”É½Õ¹‘ÑÉÕÑ É½ÜÁ•ÈÑ¥¬ˆ(€€€€€€€€¤ì((€€€€€€€€¼¼Q¡”É½ÜµÕÍĞ¡…Ù”Í½Á”€ô€µ•Ñ„œ¸(€€€€€€€±•Ğ€¡Í½Á”°•Ù¥‘•¹”¤è€¡MÑÉ¥¹œ°MÑÉ¥¹œ¤€ô½¹¸È(€€€€€€€€€€€€¹ÅÕ•Éå}É½Ü (€€€€€€€€€€€€€€€€‰M1PÍ½Á”°•Ù¥‘•¹”I=4¥‘á}É½Õ¹‘ÑÉÕÑ ]!IÍ½ÕÉ”€ô€Íå¹Ñ¡•Í¥ÌµÉ½¸œˆ°(€€€€€€€€€€€€€€€mt°(€€€€€€€€€€€€€€€ñÉğ=¬ ¡È¹•Ğ À¤ü°È¹•Ğ Ä¤ü¤¤°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Í½Á”°€‰µ•Ñ„ˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€Í•É‘•}©Í½¸èé™É½µ}ÍÑÈèèñY•Œñ¤ØĞøø ™•Ù¥‘•¹”¤¹Õ¹İÉ…À ¤°(€€€€€€€€€€€Ù•Œ…lÔ°€Ğ°€Ì°€È°€Ä°€Át°(€€€€€€€€€€€€‰Ñ¡”Íå¹Ñ¡•Í¥Ì¹½Ñ”µÕÍĞÉ•Ñ…¥¸•Ù•Éä½¹ÑÉ¥‰ÕÑ¥¹œ•Á¥Í½‘”¥¸¡É½¹½±½¥…°½É‘•Èˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}É•™ÕÍ•Í}½ÉÁ¡…¹}¹½Ñ•}İ¥Ñ¡½ÕÑ}•Á¥Í½‘•Ì ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€ÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤ì((€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€ØÀÑ|àÀÀ°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌè€ÌÀ°(€€€€€€€€€€€•¹…‰±•}Í­¥±±}Á•É™}Á…ÍÌè™…±Í”°(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Í}™É½µ}Á•É˜è™…±Í”°(€€€€€€€ôì(€€€€€€€±•ĞÉ•Á½ÉĞ€ôÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹” ™‘‰}Á…Ñ °‘¥È¹Á…Ñ  ¤°€™™œ¤¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …É•Á½ÉĞ¹¹½Ñ•}İÉ¥ÑÑ•¸¤ì((€€€€€€€±•Ğ½¹¸€ôÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ½Õ¹Ğè¤ØĞ€ô½¹¸(€€€€€€€€€€€€¹ÅÕ•Éå}É½Ü (€€€€€€€€€€€€€€€€‰M1P=U9P ¨¤I=4¥‘á}É½Õ¹‘ÑÉÕÑ ]!IÍ½ÕÉ”€ô€Íå¹Ñ¡•Í¥ÌµÉ½¸œˆ°(€€€€€€€€€€€€€€€mt°(€€€€€€€€€€€€€€€ñÉğÈ¹•Ğ À¤°(€€€€€€€€€€€€¤(€€€€€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡½Õ¹Ğ°€À°€‰•µÁÑäÍå¹Ñ¡•Í¥ÌµÕÍĞ¹½Ğ‰•½µ”½ÉÁ¡…¸İ¥Í‘½´ˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€€…‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Íå¹Ñ¡•Í¥Ìˆ¤¹•á¥ÍÑÌ ¤°(€€€€€€€€€€€€‰Ù…Õ±ĞÍå¹Ñ¡•Í¥Ì¥ÌÍ­¥ÁÁ•İ¡•¸¥Ğ¡…Ì¹¼•Á¥Í½‘”ÁÉ½Ù•¹…¹”ˆ(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}‘½•Í}¹½Ñ}İÉ¥Ñ•}Ù…Õ±Ñ}İ¡•¹}•Ù¥‘•¹•}¥¹Í•ÉÑ}™…¥±Ì ¤ì(€€€€€€€±•Ğ‘¥È€ôÑ•µÁ™¥±”èéÑ•µÁ‘¥È ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ‘‰}Á…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Ù¥•İÌ¹‘ˆˆ¤ì(€€€€€€€±•Ğ½¹¸€ôÍÑ½É”èé½Á•¸ ™‘‰}Á…Ñ ¤¹Õ¹İÉ…À ¤ì(€€€€€€€±•Ğ¹½İ}¹Ì€ôÉ…Ñ”èéÑ¥µ”èé¹½İ}Õ¹¥á}¹Í}¤ØĞ ¤ì(€€€€€€€½¹¸¹•á•ÕÑ” (€€€€€€€€€€€€‰%9MIP%9Q<¥‘á}•Á¥Í½‘”p(€€€€€€€€€€€€€¡•Ù•¹Ñ}¥°•Ù•¹Ñ}ÑåÁ”°ÑÍ}¹Ì°Ñ•áĞ°Ñ•áÑ}¡…Í °¥µÁ½ÉÑ…¹”°±…ÍÑ}…•ÍÍ}ÑÌ¤p(€€€€€€€€€€€€Y1UL€ äÄ°€Ä°€üÄ°€ÉÕÍĞ‘•Á±½åµ•¹ĞÍå¹Ñ¡•Í¥Ì•Ù¥‘•¹”œ°€Íå¹Ñ µ•Ù¥‘•¹”œ°€À¸Ü°€üÄ¤ˆ°(€€€€€€€€€€€ÉÕÍÅ±¥Ñ”èéÁ…É…µÌ…m¹½İ}¹Ít°(€€€€€€€€¤(€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€½¹¸¹•á•ÕÑ•}‰…Ñ  (€€€€€€€€€€€€‰IQQI%HÉ•©•Ñ}Íå¹Ñ¡•Í¥Í}É½Õ¹‘ÑÉÕÑ p(€€€€€€€€€€€€	=I%9MIP=8¥‘á}É½Õ¹‘ÑÉÕÑ p(€€€€€€€€€€€€]!89\¹Í½ÕÉ”€ô€Íå¹Ñ¡•Í¥ÌµÉ½¸œp(€€€€€€€€€€€€	%8M1PI%M¡%0°€Ñ•ÍĞ¥¹Í•ÉĞ™…¥±ÕÉ”œ¤ì9ìˆ°(€€€€€€€€¤(€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€‘É½À¡½¹¸¤ì((€€€€€€€±•ĞÉ•Á½ÉĞ€ôÉÕ¹}Íå¹Ñ¡•Í¥Í}Ñ¥­}½¹” (€€€€€€€€€€€€™‘‰}Á…Ñ °(€€€€€€€€€€€‘¥È¹Á…Ñ  ¤°(€€€€€€€€€€€€™Må¹Ñ¡•Í¥ÍÉ½¹½¹™¥œì(€€€€€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€ØÀÑ|àÀÀ°(€€€€€€€€€€€€€€€İ¥¹‘½İ}‘…åÌè€ÌÀ°(€€€€€€€€€€€€€€€•¹…‰±•}Í­¥±±}Á•É™}Á…ÍÌè™…±Í”°(€€€€€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Í}™É½µ}Á•É˜è™…±Í”°(€€€€€€€€€€€ô°(€€€€€€€€¤(€€€€€€€€¹Õ¹İÉ…À ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …É•Á½ÉĞ¹¹½Ñ•}İÉ¥ÑÑ•¸¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€€…‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰Íå¹Ñ¡•Í¥Ìˆ¤¹•á¥ÍÑÌ ¤°(€€€€€€€€€€€€‰„Ù…Õ±Ğ™¥±”µÕÍĞ¹•Ù•È½ÕÑ±¥Ù”„™…¥±••Ù¥‘•¹”µ‰½Õ¹¥¹Í•ÉĞˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€Ôè½¹™¥œ‘•™…Õ±ÑÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸½¹™¥}‘•™…Õ±ÑÌ ¤ì(€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œèé‘•™…Õ±Ğ ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …™œ¹•¹…‰±•°€‰½™˜‰ä‘•™…Õ±Ğˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€™œ¹¥¹Ñ•ÉÙ…±}Í•Ì°(€€€€€€€€€€€ÍÕÁ•ÈèéÍÕÁ•ÈèéÍÕÁ•Èèé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéU1Q}Me9Q!M%M}I=9}%9QIY1}ML(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€™œ¹İ¥¹‘½İ}‘…åÌ°(€€€€€€€€€€€ÍÕÁ•ÈèéÍÕÁ•ÈèéÍÕÁ•Èèé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéU1Q}Me9Q!M%M}]%9=]}eL(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ (€€€€€€€€€€€™œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤°(€€€€€€€€€€€ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì (€€€€€€€€€€€€€€€ÍÕÁ•ÈèéÍÕÁ•ÈèéÍÕÁ•Èèé½¹™¥œèé…ÕÑ½µ…Ñ¥½¸èéU1Q}Me9Q!M%M}I=9}%9QIY1}ML(€€€€€€€€€€€€¤(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€Øè¥¹Ñ•ÉÙ…°™±½½È±…µÁÌé•É¼ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸¥¹Ñ•ÉÙ…±}™±½½É}±…µÁÍ}é•É¼ ¤ì(€€€€€€€±•Ğ™œ€ôMå¹Ñ¡•Í¥ÍÉ½¹½¹™¥œì(€€€€€€€€€€€•¹…‰±•èÑÉÕ”°(€€€€€€€€€€€¥¹Ñ•ÉÙ…±}Í•Ìè€À°(€€€€€€€€€€€İ¥¹‘½İ}‘…åÌè€ÌÀ°(€€€€€€€€€€€•¹…‰±•}Í­¥±±}Á•É™}Á…ÍÌè™…±Í”°(€€€€€€€€€€€ÁÉ½Á½Í•}Í­¥±±Í}™É½µ}Á•É˜è™…±Í”°(€€€€€€€ôì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡™œ¹¥¹Ñ•ÉÙ…±}‘ÕÉ…Ñ¥½¸ ¤°ÕÉ…Ñ¥½¸èé™É½µ}Í•Ì ØÀ¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€ÜèM½ÕÉ”èéMå¹Ñ¡•Í¥ÌÉ½Õ¹µÑÉ¥ÁÌ½ÉÉ•Ñ±äƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸Íå¹Ñ¡•Í¥Í}Í½ÕÉ•}…Í}ÍÑÈ ¤ì(€€€€€€€ÕÍ”É…Ñ”èéµ•µ½ÉäèéÉ½Õ¹‘ÑÉÕÑ èéM½ÕÉ”ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡M½ÕÉ”èéMå¹Ñ¡•Í¥Ì¹…Í}ÍÑÈ ¤°€‰Íå¹Ñ¡•Í¥ÌµÉ½¸ˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„ …M½ÕÉ”èéMå¹Ñ¡•Í¥Ì¹¥Í}½Á•É…Ñ½É}…ÑÑ•ÍÑ• ¤¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€àè¥Í½}İ••­}±…‰•°Í…¹¥ÑäƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸¥Í½}İ••­}±…‰•±}™½Éµ…Ğ ¤ì(€€€€€€€€¼¼U¹¥à•Á½ €À€ô€ÄäÜÀ´ÀÄ´ÀÄ€¡Q¡ÕÉÍ‘…ä¤¸]••¬€Ä¸(€€€€€€€±•Ğ±…‰•°€ô¥Í½}İ••­}±…‰•° À¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€±…‰•°¹ÍÑ…ÉÑÍ}İ¥Ñ  ˆÄäÜÀµ\ˆ¤°(€€€€€€€€€€€€‰±…‰•°µÕÍĞÍÑ…ÉĞİ¥Ñ å•…Èµ\èí±…‰•±ôˆ(€€€€€€€€¤ì(€€€€€€€€¼¼­¹½İ¸Ñ¥µ•ÍÑ…µÀè€ÈÀÈØ´ÀØ´ÈÈƒŠ& U¹¥à€ÄÜÔÀÔÔÀĞÀÀ¸(€€€€€€€±•Ğ±…‰•°È€ô¥Í½}İ••­}±…‰•° Å|ÜÔÁ|ÔÔÁ|ĞÀÀ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡±…‰•°È¹ÍÑ…ÉÑÍ}İ¥Ñ  ˆÈÀÈˆ¤°€‰å•…È€ÈÀÈØ±…‰•°èí±…‰•°Éôˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR Q•ÍĞ€äèµ…É­‘½İ¸•¹•É…Ñ¥½¸Íµ½­”Ñ•ÍĞƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€mÑ•ÍÑt(€€€™¸‰Õ¥±‘}Íå¹Ñ¡•Í¥Í}µ…É­‘½İ¹}½¹Ñ…¥¹Í}İ••­}±…‰•° ¤ì(€€€€€€€±•Ğ¹½Ñ”€ôMå¹Ñ¡•Í¥Í9½Ñ”ì(€€€€€€€€€€€İ••­}¥Í¼è€ˆÈÀÈØµ\ÈÔˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€™É•ÅÕ•¹å}Á•…­ÌèÙ•Œ…mÉ•ÅÕ•¹åA•…¬ì(€€€€€€€€€€€€€€€Ñ½Á¥Œè€‰­Õ‰•É¹•Ñ•Ìˆ¹Ñ½}ÍÑÉ¥¹œ ¤°(€€€€€€€€€€€€€€€½Õ¹Ğè€Ô°(€€€€€€€€€€€õt°(€€€€€€€€€€€Ñ•µÁ½É…±}±ÕÍÑ•ÉÌèÙ•Œ…mt°(€€€€€€€€€€€‘½µ…¥¹}½ÉÉ•±…Ñ¥½¹ÌèÙ•Œ…mt°(€€€€€€€€€€€½¹ÑÉ…‘¥Ñ¥½¹}™±…ÌèÙ•Œ…mt°(€€€€€€€€€€€É½ÍÍ}ÕÑÑ¥¹œèÙ•Œ…mt°(€€€€€€€€€€€Í­¥±±}Á•É™}ÍÕ•ÍÑ¥½¹ÌèÙ•Œ…mt°(€€€€€€€ôì(€€€€€€€±•Ğµ€ô‰Õ¥±‘}Íå¹Ñ¡•Í¥Í}µ…É­‘½İ¸ ™¹½Ñ”°€Å|ÜÔÁ|ÀÀÁ|ÀÀÀ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡µ¹½¹Ñ…¥¹Ì ˆÈÀÈØµ\ÈÔˆ¤°€‰µÕÍĞ½¹Ñ…¥¸İ••¬±…‰•°ˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„¡µ¹½¹Ñ…¥¹Ì ‰­Õ‰•É¹•Ñ•Ìˆ¤°€‰µÕÍĞ½¹Ñ…¥¸Ñ½Á¥Œˆ¤ì(€€€€€€€…ÍÍ•ÉĞ„ (€€€€€€€€€€€µ¹½¹Ñ…¥¹Ì ‰Íå¹Ñ¡•Í¥ÌµÉ½¸ˆ¤°(€€€€€€€€€€€€‰µÕÍĞ¡…Ù”Í½ÕÉ”¥¸™É½¹Ñµ…ÑÑ•Èˆ(€€€€€€€€¤ì(€€€ô)ô