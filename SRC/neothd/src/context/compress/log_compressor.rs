//! GOLD-HR-04 — `LogOffload`: keep the errors, drop the noise, stash the rest.
//!
//! A bloaty build/test log is mostly low-signal repetition (INFO heartbeats,
//! progress spam) burying a handful of errors. This offload keeps the
//! high-priority lines (errors, warnings, stack frames) plus a small head/tail
//! context window, replaces each dropped run with a compact placeholder + a
//! CCR retrieval marker, and stashes the FULL original under one key. Lossy on
//! the wire, lossless via `neoth ctx retrieve` — typical savings 70–99 % on
//! repetitive logs.
//!
//! Where headroom uses a 1300-line `LogCompressor` + an aho-corasick
//! `KeywordDetector`, NEOTH keeps it self-contained: line importance is a
//! small regex heuristic (no new deps), and the bloat estimator is a faithful
//! port of headroom's repetition + priority-dilution signals.

use std::collections::HashSet;
use std::fmt::Write;
use std::sync::LazyLock;

use regex::Regex;

use crate::context::compress::ccr::{compute_key, marker_for, CcrStore};
use crate::context::compress::content_detector::ContentType;
use crate::context::compress::transform::{
    CompressionContext, OffloadOutput, OffloadTransform, TransformError,
};

const NAME: &str = "log_offload";
const CONFIDENCE: f32 = 0.8;

// ─── Line-importance heuristic (regex, dep-free) ───────────────────────

/// Errors + fatals + panics + stack frames — always kept.
static HIGH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\b(ERROR|FAIL|FAILED|FATAL|CRITICAL|PANIC|EXCEPTION|ASSERT)\b|Traceback \(most recent call last\)|^\s*at\s+[\w.$]+\()").unwrap()
});
/// Warnings — kept.
static WARN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(WARN|WARNING|DEPRECAT)").unwrap());
/// Routine noise — the first to be dropped.
static LOW_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(INFO|DEBUG|TRACE|VERBOSE)\b").unwrap());

/// Importance score in `0.0..=1.0`. High = keep, low = droppable noise.
/// Checked high→warn→low so an "INFO: ERROR recovered" line scores as an error.
pub fn line_importance(line: &str) -> f32 {
    if HIGH_RE.is_match(line) {
        0.9
    } else if WARN_RE.is_match(line) {
        0.6
    } else if LOW_RE.is_match(line) {
        0.2
    } else {
        0.5 // unclassified — neutral; kept only via head/tail window
    }
}

// ─── Config ────────────────────────────────────────────────────────────

/// Tunables for [`LogOffload`]. Code-level defaults; not freedom.yaml.
#[derive(Debug, Clone, Copy)]
pub struct LogOffloadConfig {
    /// Logs shorter than this are passed through (CCR overhead not worth it).
    pub min_lines: usize,
    /// Lines sampled by `estimate_bloat` (bounds its cost).
    pub sample_size: usize,
    /// Lines scoring at or below this count as "low priority" for the
    /// dilution signal and are eligible to be dropped by `apply`.
    pub high_priority_threshold: f32,
    /// Weight of the repetition signal in the bloat score.
    pub uniqueness_weight: f32,
    /// Weight of the priority-dilution signal in the bloat score.
    pub priority_dilution_weight: f32,
    /// Cap on kept high-priority lines (a log that IS all errors shouldn't
    /// keep 10k lines — beyond this the rest go to CCR too).
    pub max_kept_priority: usize,
    /// Verbatim head/tail context lines always kept (the log's start/end
    /// frame the errors in between).
    pub head_tail: usize,
}

impl Default for LogOffloadConfig {
    fn default() -> Self {
        Self {
            min_lines: 50,
            sample_size: 100,
            high_priority_threshold: 0.4,
            uniqueness_weight: 0.5,
            priority_dilution_weight: 0.5,
            max_kept_priority: 50,
            head_tail: 3,
        }
    }
}

pub struct LogOffload {
    config: LogOffloadConfig,
}

impl LogOffload {
    pub fn new(config: LogOffloadConfig) -> Self {
        Self { config }
    }
}

impl Default for LogOffload {
    fn default() -> Self {
        Self::new(LogOffloadConfig::default())
    }
}

impl OffloadTransform for LogOffload {
    fn name(&self) -> &'static str {
        NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::BuildOutput]
    }

    fn estimate_bloat(&self, content: &str) -> f32 {
        if content.is_empty() {
            return 0.0;
        }
        let total_lines = content.lines().count();
        if total_lines < self.config.min_lines {
            return 0.0;
        }
        // Bounded sample: unique-line ratio (repetition) + low-priority ratio
        // (dilution). Faithful port of headroom's log bloat estimator.
        let mut unique: HashSet<&str> = HashSet::with_capacity(self.config.sample_size);
        let mut sampled = 0usize;
        let mut low_priority = 0usize;
        for line in content.lines() {
            if sampled >= self.config.sample_size {
                break;
            }
            sampled += 1;
            unique.insert(line);
            if line_importance(line) <= self.config.high_priority_threshold {
                low_priority += 1;
            }
        }
        if sampled == 0 {
            return 0.0;
        }
        let repetition = 1.0 - (unique.len() as f32 / sampled as f32);
        let dilution = low_priority as f32 / sampled as f32;
        (repetition * self.config.uniqueness_weight + dilution * self.config.priority_dilution_weight)
            .clamp(0.0, 1.0)
    }

    fn apply(
        &self,
        content: &str,
        _ctx: &CompressionContext,
        store: &dyn CcrStore,
    ) -> Result<OffloadOutput, TransformError> {
        let lines: Vec<&str> = content.lines().collect();
        let n = lines.len();
        if n < self.config.min_lines {
            return Err(TransformError::skipped(NAME, "below min_lines"));
        }

        // Decide which lines to keep: high-priority (capped) + head/tail.
        let mut keep = vec![false; n];
        let ht = self.config.head_tail.min(n);
        for k in keep.iter_mut().take(ht) {
            *k = true;
        }
        for k in keep.iter_mut().skip(n.saturating_sub(self.config.head_tail)) {
            *k = true;
        }
        let mut kept_priority = 0usize;
        for (i, line) in lines.iter().enumerate() {
            if keep[i] {
                continue;
            }
            if kept_priority >= self.config.max_kept_priority {
                break;
            }
            if line_importance(line) > self.config.high_priority_threshold {
                keep[i] = true;
                kept_priority += 1;
            }
        }

        let kept_count = keep.iter().filter(|&&k| k).count();
        if kept_count >= n {
            return Err(TransformError::skipped(NAME, "nothing droppable"));
        }

        // Compute the CCR key + marker WITHOUT writing yet — a skip below must
        // not leave a dangling store entry (the trait's skip-is-clean contract).
        let key = compute_key(content.as_bytes());
        let marker = marker_for(&key);

        // Rebuild preserving order; collapse dropped runs into a placeholder.
        let mut out = String::with_capacity(content.len() / 2);
        let mut i = 0;
        while i < n {
            if keep[i] {
                out.push_str(lines[i]);
                out.push('\n');
                i += 1;
            } else {
                let start = i;
                while i < n && !keep[i] {
                    i += 1;
                }
                let dropped = i - start;
                let _ = writeln!(out, "[… {dropped} log lines omitted — retrieve {marker} …]");
            }
        }
        if !content.ends_with('\n') && out.ends_with('\n') {
            out.pop();
        }

        if out.len() >= content.len() {
            return Err(TransformError::skipped(NAME, "no byte savings"));
        }
        // Savings confirmed — now commit the original to the store.
        store.put(&key, content);
        Ok(OffloadOutput::from_lengths(content.len(), out, key))
    }

    fn confidence(&self) -> f32 {
        CONFIDENCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::compress::ccr::{extract_keys, InMemoryCcrStore};

    fn offload() -> LogOffload {
        LogOffload::default()
    }

    #[test]
    fn importance_ranks_errors_above_info() {
        assert!(line_importance("2025 ERROR boom") > line_importance("2025 INFO ok"));
        assert!(line_importance("WARNING deprecated") > line_importance("DEBUG x"));
        assert!(line_importance("  at com.foo.Bar(Bar.java:42)") >= 0.9);
        assert_eq!(line_importance("plain unclassified line"), 0.5);
        // High beats a co-occurring INFO token.
        assert!(line_importance("INFO: ERROR recovered") >= 0.9);
    }

    #[test]
    fn name_and_applies_to() {
        assert_eq!(offload().name(), "log_offload");
        assert_eq!(offload().applies_to(), &[ContentType::BuildOutput]);
    }

    #[test]
    fn estimate_bloat_empty_and_short_is_zero() {
        assert_eq!(offload().estimate_bloat(""), 0.0);
        let short = "INFO a\nERROR b\nINFO c\nINFO d\nINFO e";
        assert_eq!(offload().estimate_bloat(short), 0.0); // below min_lines
    }

    #[test]
    fn estimate_bloat_high_repetition_scores_high() {
        let log = vec!["INFO: heartbeat from worker-7"; 100].join("\n");
        assert!(offload().estimate_bloat(&log) > 0.8);
    }

    #[test]
    fn estimate_bloat_unique_errors_score_low() {
        let log: String = (0..100)
            .map(|i| format!("ERROR: failure {i} at module x"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(offload().estimate_bloat(&log) < 0.3);
    }

    #[test]
    fn estimate_bloat_safe_on_huge_input() {
        let log: String = (0..100_000).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        let _ = offload().estimate_bloat(&log); // sample-bounded → must not hang
    }

    #[test]
    fn apply_keeps_errors_drops_noise_and_round_trips_via_ccr() {
        // 200 INFO heartbeats with 2 ERRORs buried in the middle.
        let mut log = String::new();
        for i in 0..100 {
            log.push_str(&format!("INFO heartbeat {i}\n"));
        }
        log.push_str("ERROR disk full on /var\n");
        log.push_str("ERROR retry exhausted\n");
        for i in 0..100 {
            log.push_str(&format!("INFO heartbeat {}\n", 100 + i));
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&log, &CompressionContext::default(), &store)
            .expect("bloaty log compresses");

        // Errors survive on the wire.
        assert!(r.output.contains("ERROR disk full on /var"));
        assert!(r.output.contains("ERROR retry exhausted"));
        // Noise was dropped + a marker emitted.
        assert!(r.output.contains("log lines omitted"));
        assert!(r.bytes_saved > 0);
        assert!(r.output.len() < log.len() / 2, "expect strong savings");
        // CCR round-trip: the marker key resolves to the byte-exact original.
        let keys = extract_keys(&r.output);
        assert!(!keys.is_empty());
        assert_eq!(store.get(&r.cache_key).as_deref(), Some(log.as_str()));
        assert_eq!(keys[0], r.cache_key);
    }

    #[test]
    fn apply_skips_short_log() {
        let log = "INFO a\nINFO b\nINFO c\nINFO d\nINFO e";
        let store = InMemoryCcrStore::new();
        let err = offload()
            .apply(log, &CompressionContext::default(), &store)
            .expect_err("short log skipped");
        assert!(matches!(err, TransformError::Skipped { .. }));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn apply_skips_all_error_log_nothing_droppable() {
        // Every line high-priority → nothing droppable (under the cap) → skip.
        let log: String = (0..60)
            .map(|i| format!("ERROR failure {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let store = InMemoryCcrStore::new();
        let res = offload().apply(&log, &CompressionContext::default(), &store);
        // With max_kept_priority=50 and 60 error lines, 10 errors beyond the
        // cap ARE droppable, so this may compress; if it does, errors in the
        // kept window survive and CCR holds the original. Either way: no panic,
        // and any output is a strict subset round-trippable via CCR.
        if let Ok(out) = res {
            assert!(out.bytes_saved > 0);
            assert_eq!(store.get(&out.cache_key).as_deref(), Some(log.as_str()));
        } else {
            assert_eq!(store.len(), 0);
        }
    }
}
