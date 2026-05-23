//! P-01 — behaviour-pattern estimators (5 dimensions).
//!
//! Per the user-adaptation specs, NEOTH derives five behavioural
//! signals from the WAL replay so the proactive self-dev loop
//! (P-04) can propose profile adjustments + the briefing emitter
//! (P-08) can time outputs against the operator's actual rhythm:
//!
//!   - **Temporal** — what hour-of-day buckets does the operator use?
//!   - **Cadence** — average / median time between operator turns
//!   - **Length** — distribution of operator message lengths
//!   - **Topic** — top-N topic tags inferred from prompt text
//!   - **Tone** — formality / register signal from word choice
//!
//! Each estimator is a pure-fn over a slice of `ObservedTurn`
//! samples. Caller (the aggregation cron) reads the WAL replay +
//! materialises samples + calls every estimator. Outputs are
//! typed `*Estimate` structs that downstream code (P-04 / P-08)
//! consumes without re-deriving anything.
//!
//! No model dependency — these are deterministic statistics, not
//! ML inference. Future enhancement (Phase 4 Hebbian tuning per
//! P-12) layers learned weights on top of the raw signals.

use serde::{Deserialize, Serialize};

/// One observed operator turn the estimators consume. Caller maps
/// from WAL RAW_TEXT events into this shape.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservedTurn {
    /// Unix-epoch seconds the operator's message landed.
    pub ts_unix: i64,
    /// Operator-side text (sanitised, no provider responses).
    pub text: String,
}

// ────────────────────────────────────────────────────────────────
//  Temporal estimator
// ────────────────────────────────────────────────────────────────

/// Hour-of-day usage distribution (24 buckets). Caller picks a
/// timezone before feeding `ts_unix` values in — estimator stays
/// timezone-naive to avoid mis-attributing late-night activity to
/// the wrong day boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalEstimate {
    /// Hits per hour 0..=23. Sum equals the input sample count.
    pub hour_buckets: [u32; 24],
    /// Hour-of-day with the most hits. None when no samples.
    pub peak_hour: Option<u8>,
}

pub fn estimate_temporal(samples: &[ObservedTurn]) -> TemporalEstimate {
    let mut buckets = [0u32; 24];
    for t in samples {
        let secs_in_day = t.ts_unix.rem_euclid(86_400);
        let hour = (secs_in_day / 3600) as usize;
        if hour < 24 {
            buckets[hour] = buckets[hour].saturating_add(1);
        }
    }
    let peak = buckets
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| **c)
        .filter(|(_, c)| **c > 0)
        .map(|(i, _)| i as u8);
    TemporalEstimate {
        hour_buckets: buckets,
        peak_hour: peak,
    }
}

// ────────────────────────────────────────────────────────────────
//  Cadence estimator
// ────────────────────────────────────────────────────────────────

/// Inter-turn timing distribution. `mean_gap_secs` answers "how
/// frequently does the operator engage?" The median + p90 give the
/// outlier-resistant view for briefings that shouldn't fire during
/// a long-silence stretch.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CadenceEstimate {
    pub sample_count: u32,
    pub mean_gap_secs: f64,
    pub median_gap_secs: f64,
    pub p90_gap_secs: f64,
}

pub fn estimate_cadence(samples: &[ObservedTurn]) -> CadenceEstimate {
    if samples.len() < 2 {
        return CadenceEstimate::default();
    }
    let mut sorted_ts: Vec<i64> = samples.iter().map(|t| t.ts_unix).collect();
    sorted_ts.sort_unstable();
    let mut gaps: Vec<i64> = sorted_ts
        .windows(2)
        .map(|w| (w[1] - w[0]).max(0))
        .collect();
    if gaps.is_empty() {
        return CadenceEstimate::default();
    }
    let mean = gaps.iter().copied().sum::<i64>() as f64 / gaps.len() as f64;
    gaps.sort_unstable();
    let median_idx = gaps.len() / 2;
    let median = gaps[median_idx] as f64;
    let p90_idx = ((gaps.len() as f64 * 0.9) as usize).min(gaps.len() - 1);
    let p90 = gaps[p90_idx] as f64;
    CadenceEstimate {
        sample_count: samples.len() as u32,
        mean_gap_secs: mean,
        median_gap_secs: median,
        p90_gap_secs: p90,
    }
}

// ────────────────────────────────────────────────────────────────
//  Length estimator
// ────────────────────────────────────────────────────────────────

/// Operator message length distribution (UTF-8 char count, not byte
/// count). Drives verbosity tuning — operator who writes 5-char
/// prompts wants 30-char replies, operator writing 500-char prompts
/// expects 500-char essays.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LengthEstimate {
    pub sample_count: u32,
    pub mean_chars: f64,
    pub median_chars: u32,
    pub p10_chars: u32,
    pub p90_chars: u32,
}

pub fn estimate_length(samples: &[ObservedTurn]) -> LengthEstimate {
    if samples.is_empty() {
        return LengthEstimate::default();
    }
    let mut lens: Vec<u32> = samples
        .iter()
        .map(|t| t.text.chars().count() as u32)
        .collect();
    lens.sort_unstable();
    let n = lens.len();
    let mean = lens.iter().copied().sum::<u32>() as f64 / n as f64;
    let median = lens[n / 2];
    let p10 = lens[((n as f64 * 0.1) as usize).min(n - 1)];
    let p90 = lens[((n as f64 * 0.9) as usize).min(n - 1)];
    LengthEstimate {
        sample_count: n as u32,
        mean_chars: mean,
        median_chars: median,
        p10_chars: p10,
        p90_chars: p90,
    }
}

// ────────────────────────────────────────────────────────────────
//  Topic estimator
// ────────────────────────────────────────────────────────────────

/// Top-N topic tags inferred from operator text. v0.1 uses simple
/// keyword bucketing against a pinned topic taxonomy — substantive
/// LSA / embedding-based topic modelling is Phase 4 work (P-12).
/// Pinned taxonomy keeps the surface deterministic + testable now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicEstimate {
    /// (topic, hit_count) sorted by hit_count descending.
    pub top_topics: Vec<(String, u32)>,
}

/// Pinned v0.1 topic taxonomy. Each entry is (canonical name,
/// keyword fragments — case-insensitive substring match). Adding
/// a topic needs an entry here + a test pin.
pub const TOPIC_TAXONOMY: &[(&str, &[&str])] = &[
    ("code", &["function", "rust", "python", "fn ", "def ", "class ", "import ", "// ", "pub fn"]),
    ("research", &["paper", "study", "explain", "what is", "how does", "history of"]),
    ("planning", &["roadmap", "milestone", "next steps", "deadline", "schedule"]),
    ("security", &["vulnerability", "exploit", "pentest", "cve", "owasp", "attack"]),
    ("writing", &["draft", "rewrite", "summarise", "summarize", "polish"]),
    ("personal", &["i feel", "i think", "my day", "should i", "i'm"]),
];

pub fn estimate_topic(samples: &[ObservedTurn]) -> TopicEstimate {
    let mut counts: std::collections::HashMap<&'static str, u32> =
        std::collections::HashMap::new();
    for t in samples {
        let lower = t.text.to_lowercase();
        for (topic, fragments) in TOPIC_TAXONOMY {
            if fragments.iter().any(|f| lower.contains(f)) {
                *counts.entry(topic).or_insert(0) += 1;
            }
        }
    }
    let mut sorted: Vec<(String, u32)> = counts
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    TopicEstimate { top_topics: sorted }
}

// ────────────────────────────────────────────────────────────────
//  Tone estimator
// ────────────────────────────────────────────────────────────────

/// Formality signal from word choice. Counts contractions (`don't`,
/// `it's`, `i'm`) as casual signal, and full-sentence connectors
/// (`however`, `therefore`, `furthermore`) as formal signal. Ratio
/// drives the profile preset recommendation (Lowkey vs Formal).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToneEstimate {
    pub sample_count: u32,
    pub casual_hits: u32,
    pub formal_hits: u32,
    /// (casual_hits − formal_hits) / total_hits, clamped to [-1, 1].
    /// Positive = casual; negative = formal; ~0 = neutral.
    pub casual_score: f64,
}

const CASUAL_FRAGMENTS: &[&str] = &[
    "don't", "it's", "i'm", "you're", "we're", "can't", "won't", "gonna", "wanna",
    "lol", "btw", "tbh", "imo", "fwiw", "ish",
];

const FORMAL_FRAGMENTS: &[&str] = &[
    "however", "therefore", "furthermore", "moreover", "nevertheless",
    "consequently", "notwithstanding", "hereby", "thereof", "thusly",
];

pub fn estimate_tone(samples: &[ObservedTurn]) -> ToneEstimate {
    if samples.is_empty() {
        return ToneEstimate::default();
    }
    let mut casual = 0u32;
    let mut formal = 0u32;
    for t in samples {
        let lower = t.text.to_lowercase();
        for f in CASUAL_FRAGMENTS {
            if lower.contains(f) {
                casual = casual.saturating_add(1);
            }
        }
        for f in FORMAL_FRAGMENTS {
            if lower.contains(f) {
                formal = formal.saturating_add(1);
            }
        }
    }
    let total = casual + formal;
    let score = if total == 0 {
        0.0
    } else {
        ((casual as f64 - formal as f64) / total as f64).clamp(-1.0, 1.0)
    };
    ToneEstimate {
        sample_count: samples.len() as u32,
        casual_hits: casual,
        formal_hits: formal,
        casual_score: score,
    }
}

// ────────────────────────────────────────────────────────────────
//  Aggregate
// ────────────────────────────────────────────────────────────────

/// Single struct carrying all 5 estimates. The cron aggregation
/// task (P-01.b — multi-day follow-up) builds this from a WAL
/// scan + writes it into `views.db::idx_behavioural_profile`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BehaviouralProfile {
    pub temporal: TemporalEstimate,
    pub cadence: CadenceEstimate,
    pub length: LengthEstimate,
    pub topic: TopicEstimate,
    pub tone: ToneEstimate,
}

pub fn estimate_all(samples: &[ObservedTurn]) -> BehaviouralProfile {
    BehaviouralProfile {
        temporal: estimate_temporal(samples),
        cadence: estimate_cadence(samples),
        length: estimate_length(samples),
        topic: estimate_topic(samples),
        tone: estimate_tone(samples),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(ts: i64, text: &str) -> ObservedTurn {
        ObservedTurn {
            ts_unix: ts,
            text: text.to_string(),
        }
    }

    // ── Temporal ────────────────────────────────────────────────

    #[test]
    fn temporal_empty_input_returns_zeroed() {
        let e = estimate_temporal(&[]);
        assert_eq!(e.hour_buckets, [0u32; 24]);
        assert_eq!(e.peak_hour, None);
    }

    #[test]
    fn temporal_buckets_match_hour_of_day() {
        // 1700000000 UTC = 2023-11-14 22:13:20 UTC → hour 22.
        let e = estimate_temporal(&[turn(1_700_000_000, "x")]);
        assert_eq!(e.hour_buckets[22], 1);
        assert_eq!(e.peak_hour, Some(22));
    }

    #[test]
    fn temporal_peak_picks_max_bucket() {
        let samples = vec![
            turn(1_700_000_000, "x"), // hour 22
            turn(1_700_000_000, "y"), // hour 22
            turn(1_700_000_000 + 7200, "z"), // hour 0 (next day)
        ];
        let e = estimate_temporal(&samples);
        assert_eq!(e.peak_hour, Some(22));
        assert_eq!(e.hour_buckets[22], 2);
        assert_eq!(e.hour_buckets[0], 1);
    }

    // ── Cadence ─────────────────────────────────────────────────

    #[test]
    fn cadence_returns_default_on_fewer_than_two_samples() {
        let e = estimate_cadence(&[]);
        assert_eq!(e, CadenceEstimate::default());
        let e1 = estimate_cadence(&[turn(0, "x")]);
        assert_eq!(e1, CadenceEstimate::default());
    }

    #[test]
    fn cadence_mean_matches_uniform_gaps() {
        let samples = vec![
            turn(0, "a"),
            turn(60, "b"),
            turn(120, "c"),
            turn(180, "d"),
        ];
        let e = estimate_cadence(&samples);
        assert!((e.mean_gap_secs - 60.0).abs() < f64::EPSILON);
        assert_eq!(e.median_gap_secs, 60.0);
        assert_eq!(e.sample_count, 4);
    }

    #[test]
    fn cadence_p90_captures_outlier_gap() {
        // Mostly 1-minute gaps with one 1-hour spike.
        let samples = vec![
            turn(0, "a"),
            turn(60, "b"),
            turn(120, "c"),
            turn(180, "d"),
            turn(180 + 3600, "e"),
        ];
        let e = estimate_cadence(&samples);
        assert!(e.p90_gap_secs >= 60.0);
    }

    // ── Length ──────────────────────────────────────────────────

    #[test]
    fn length_empty_input_returns_default() {
        assert_eq!(estimate_length(&[]), LengthEstimate::default());
    }

    #[test]
    fn length_counts_utf8_chars_not_bytes() {
        // "café" = 4 chars, 5 bytes.
        let e = estimate_length(&[turn(0, "café")]);
        assert_eq!(e.median_chars, 4);
    }

    #[test]
    fn length_percentiles_pick_distribution_tails() {
        // 10 samples with lengths 1..=10. Index math:
        // p10 = lens[(10 * 0.1) as usize] = lens[1] = 2 (sorted asc)
        // p90 = lens[(10 * 0.9) as usize] = lens[9] = 10
        let samples: Vec<ObservedTurn> = (1..=10)
            .map(|n| turn(0, &"a".repeat(n)))
            .collect();
        let e = estimate_length(&samples);
        assert_eq!(e.p10_chars, 2);
        assert_eq!(e.p90_chars, 10);
        assert_eq!(e.sample_count, 10);
    }

    // ── Topic ───────────────────────────────────────────────────

    #[test]
    fn topic_empty_input_returns_empty_top_list() {
        assert!(estimate_topic(&[]).top_topics.is_empty());
    }

    #[test]
    fn topic_classifies_code_text() {
        let e = estimate_topic(&[
            turn(0, "Can you explain this rust function?"),
            turn(0, "Write me a python def for fibonacci"),
        ]);
        let names: Vec<&str> = e.top_topics.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"code"));
    }

    #[test]
    fn topic_taxonomy_has_required_entries() {
        let names: Vec<&str> = TOPIC_TAXONOMY.iter().map(|(n, _)| *n).collect();
        for required in ["code", "research", "planning", "security", "writing", "personal"] {
            assert!(names.contains(&required), "missing taxonomy topic: {required}");
        }
    }

    #[test]
    fn topic_sorts_by_hit_count_descending() {
        // 3 code prompts, 1 research prompt.
        let samples = vec![
            turn(0, "rust function example"),
            turn(0, "python def fib"),
            turn(0, "explain this fn"),
            turn(0, "what is photosynthesis"),
        ];
        let e = estimate_topic(&samples);
        // First entry must be `code` (3 hits) before `research` (1 hit).
        assert_eq!(e.top_topics[0].0, "code");
    }

    // ── Tone ────────────────────────────────────────────────────

    #[test]
    fn tone_empty_input_returns_default() {
        assert_eq!(estimate_tone(&[]), ToneEstimate::default());
    }

    #[test]
    fn tone_casual_text_scores_positive() {
        let e = estimate_tone(&[
            turn(0, "don't worry it's fine, i'm just chillin"),
            turn(0, "btw, can't say tbh"),
        ]);
        assert!(e.casual_hits > 0);
        assert!(e.casual_score > 0.0);
    }

    #[test]
    fn tone_formal_text_scores_negative() {
        let e = estimate_tone(&[turn(
            0,
            "However, the analysis demonstrates that, therefore, we should proceed. Furthermore, nevertheless, this is sound.",
        )]);
        assert!(e.formal_hits > 0);
        assert!(e.casual_score < 0.0);
    }

    #[test]
    fn tone_score_clamps_to_unit_range() {
        let e = estimate_tone(&[
            turn(0, "don't won't can't lol btw tbh imo"),
            turn(0, "however therefore furthermore"),
        ]);
        assert!(e.casual_score >= -1.0);
        assert!(e.casual_score <= 1.0);
    }

    // ── Aggregate ───────────────────────────────────────────────

    #[test]
    fn estimate_all_runs_every_estimator() {
        let samples = vec![
            turn(1_700_000_000, "rust function explain"),
            turn(1_700_000_060, "don't worry it's fine"),
        ];
        let p = estimate_all(&samples);
        assert!(p.temporal.peak_hour.is_some());
        assert!(p.cadence.sample_count > 0);
        assert!(p.length.sample_count > 0);
        assert!(!p.topic.top_topics.is_empty());
        assert!(p.tone.sample_count > 0);
    }

    #[test]
    fn behavioural_profile_serde_round_trips() {
        let p = BehaviouralProfile::default();
        let s = serde_json::to_string(&p).unwrap();
        let back: BehaviouralProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }
}
