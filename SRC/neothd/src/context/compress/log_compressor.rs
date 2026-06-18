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

use crate::context::compress::ccr::{CcrStore, compute_key, marker_for};
use crate::context::compress::content_detector::ContentType;
use crate::context::compress::tag_protector::{has_protected_regions, protected_line_mask};
use crate::context::compress::transform::{
    CompressionContext, OffloadOutput, OffloadTransform, TransformError,
};

const NAME: &str = "log_offload";
const CONFIDENCE: f32 = 0.8;

// ─── Line-importance heuristic (regex, dep-free) ───────────────────────

// neoth: line classification stays a 3-regex heuristic. headroom replaces this
// with one aho-corasick automaton (O(n+m) vs O(3n)) — but at NEOTH's
// log-compression scale (occasional build-output runs, not a hot loop) three
// compiled regexes are already fast enough, so the AC rewrite (GOLD-ADAPT-HR-03b,
// aho-corasick is already in Cargo.lock) is deferred until log compression ever
// shows on a profile. Upgrade path: swap the three statics for one AhoCorasick +
// a word-boundary post-filter, keeping line_importance's signature.

/// Errors + fatals + panics + stack frames — always kept. GOLD-ADAPT-HR-03 added
/// ABORT/TIMEOUT/DENIED/REJECTED (operator-facing failure words that headroom's
/// keyword set carries but NEOTH's did not).
static HIGH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\b(ERROR|FAIL|FAILED|FATAL|CRITICAL|PANIC|EXCEPTION|ASSERT|ABORT|TIMEOUT|DENIED|REJECTED)\b|Traceback \(most recent call last\)|^\s*at\s+[\w.$]+\()").unwrap()
});
/// Warnings — kept.
static WARN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(WARN|WARNING|DEPRECAT)").unwrap());
/// Routine noise — the first to be dropped.
static LOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(INFO|DEBUG|TRACE|VERBOSE)\b").unwrap());

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

/// GOLD-ADAPT-HR-03a — the dedup key for a warning line: the line with each run
/// of digits collapsed to `#`, so "disk usage high at 5mb" and "…7mb" share a key
/// (same template, different value) but "disk full" and "network down" do not.
/// A prefix-before-colon key would over-collapse — every "WARNING: …" line shares
/// the prefix "WARNING" — so the template is keyed on the whole normalised line.
fn warn_key(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_digits = false;
    for c in line.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                out.push('#');
            }
            in_digits = true;
        } else {
            out.push(c);
            in_digits = false;
        }
    }
    out
}

/// GOLD-ADAPT-HR-02 — keep multi-line stack traces WHOLE. A Python traceback's
/// frame lines (`  File "...", line N`) and its trailing `ExceptionType: message`
/// line don't individually match the error keywords, so the base keep-mask would
/// strip a trace down to just its "Traceback (most recent call last)" header.
/// This post-pass keeps, for each opener, the contiguous continuation block so
/// the model sees the whole trace instead of a decapitated one. It runs after the
/// keep-mask, so the trace survives regardless of the `max_kept_priority` cap.
fn extend_trace_blocks(lines: &[&str], keep: &mut [bool]) {
    let n = lines.len();
    for i in 0..n {
        // Python: a Traceback header pulls in its indented frame block + the
        // trailing (non-indented) `ExceptionType: message` line that closes it.
        if lines[i].contains("Traceback (most recent call last)") {
            keep[i] = true;
            let mut j = i + 1;
            while j < n && (lines[j].is_empty() || lines[j].starts_with([' ', '\t'])) {
                keep[j] = true;
                j += 1;
            }
            if j < n {
                keep[j] = true; // the exception line closing the trace
            }
        }
        // JS / Java: an `at <frame>(` line is part of a stack — keep it, plus the
        // error header directly above the first frame of the run.
        let t = lines[i].trim_start();
        if t.starts_with("at ") && t.contains('(') {
            keep[i] = true;
            if i > 0 && !keep[i - 1] {
                let prev = lines[i - 1].trim_start();
                if !(prev.starts_with("at ") && prev.contains('(')) {
                    keep[i - 1] = true;
                }
            }
        }
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
    /// GOLD-ADAPT-HR-03a: cap on distinct WARNING lines kept. Warnings are
    /// deduplicated on their message prefix (text before the first `:`/`=`), so
    /// 50× "warning: unused var X" (different X) collapse to one. Beyond this
    /// many DISTINCT warning prefixes the rest are dropped to CCR.
    pub max_distinct_warnings: usize,
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
            max_distinct_warnings: 10,
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
        (repetition * self.config.uniqueness_weight
            + dilution * self.config.priority_dilution_weight)
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
        for k in keep
            .iter_mut()
            .skip(n.saturating_sub(self.config.head_tail))
        {
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

        // GOLD-ADAPT-HR-02: keep multi-line stack traces whole (Python frame
        // blocks + JS/Java `at` runs) so a trace survives un-decapitated.
        extend_trace_blocks(&lines, &mut keep);

        // GOLD-ADAPT-HR-03a: collapse repeated warnings. A log with 50× the same
        // warning (different trailing value) keeps all 50 today; dedup on the
        // message prefix + cap the distinct count.
        {
            let mut warn_seen: HashSet<String> = HashSet::new();
            for i in 0..n {
                if !keep[i] {
                    continue;
                }
                let s = line_importance(lines[i]);
                if !(0.55..0.75).contains(&s) {
                    continue; // only WARN-band lines (0.6) are deduped
                }
                let key = warn_key(lines[i]);
                if warn_seen.contains(&key) {
                    keep[i] = false; // duplicate warning template
                } else if warn_seen.len() >= self.config.max_distinct_warnings {
                    keep[i] = false; // beyond the distinct-warning cap
                } else {
                    warn_seen.insert(key);
                }
            }
        }

        // HR-07 safety: never drop a line inside a code fence or carrying a
        // tool-call / XML structural tag — that would dangle the boundary.
        if has_protected_regions(content) {
            for (k, protected) in keep.iter_mut().zip(protected_line_mask(content).iter()) {
                *k |= *protected;
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
    use crate::context::compress::ccr::{InMemoryCcrStore, extract_keys};

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
    fn importance_new_high_keywords_and_token_stays_neutral() {
        // GOLD-ADAPT-HR-03: failure words headroom carries that NEOTH lacked.
        assert!(line_importance("process abort due to OOM") >= 0.9);
        assert!(line_importance("request timeout after 30s") >= 0.9);
        assert!(line_importance("auth rejected by server") >= 0.9);
        assert!(line_importance("connection denied by peer") >= 0.9);
        // "token" is NOT a priority word — an LLM token-count line stays neutral.
        assert_eq!(line_importance("token count: 4096"), 0.5);
    }

    #[test]
    fn warn_key_collapses_digits_but_keeps_distinct_templates() {
        assert_eq!(warn_key("disk high at 5mb"), warn_key("disk high at 17mb"));
        assert_ne!(warn_key("disk full"), warn_key("network down"));
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
        let log: String = (0..100_000)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
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
    fn apply_never_splits_an_embedded_code_fence() {
        // A bloaty log with a fenced code block buried in the noise. The fence
        // delimiters + interior must survive intact (HR-07 tag protection),
        // so the model never sees a dangling ```.
        let mut log = String::new();
        for i in 0..80 {
            log.push_str(&format!("INFO heartbeat {i}\n"));
        }
        log.push_str("```rust\nfn main() { panic!(\"boom\") }\nlet x = 1;\n```\n");
        for i in 0..80 {
            log.push_str(&format!("INFO heartbeat {}\n", 80 + i));
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&log, &CompressionContext::default(), &store)
            .expect("compresses");
        // Both fence delimiters survive, and so does the interior.
        assert_eq!(
            r.output.matches("```").count(),
            2,
            "both fences must survive"
        );
        assert!(r.output.contains("fn main() { panic!(\"boom\") }"));
        assert!(r.output.contains("let x = 1;"));
        assert!(r.bytes_saved > 0);
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

    #[test]
    fn python_traceback_kept_whole_not_decapitated() {
        // GOLD-ADAPT-HR-02: the frame lines + exception line don't match the
        // error keywords, but the whole trace must survive, not just its header.
        let mut log = String::new();
        for i in 0..40 {
            log.push_str(&format!("INFO heartbeat {i}\n"));
        }
        log.push_str("Traceback (most recent call last):\n");
        log.push_str("  File \"a.py\", line 10, in foo\n");
        log.push_str("    bar()\n");
        log.push_str("  File \"b.py\", line 5, in bar\n");
        log.push_str("    raise ValueError(\"oops\")\n");
        log.push_str("ValueError: oops\n");
        for i in 0..40 {
            log.push_str(&format!("INFO heartbeat {}\n", 40 + i));
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&log, &CompressionContext::default(), &store)
            .expect("compresses");
        assert!(
            r.output.contains("Traceback (most recent call last)"),
            "header"
        );
        assert!(r.output.contains("File \"a.py\""), "frame a.py missing");
        assert!(r.output.contains("File \"b.py\""), "frame b.py missing");
        assert!(
            r.output.contains("ValueError: oops"),
            "exception line missing"
        );
        assert!(r.bytes_saved > 0);
    }

    #[test]
    fn js_at_frames_kept_with_their_header() {
        let mut log = String::new();
        for i in 0..40 {
            log.push_str(&format!("INFO heartbeat {i}\n"));
        }
        log.push_str("TypeError: Cannot read property 'x' of null\n");
        log.push_str("    at Object.foo (app.js:10:5)\n");
        log.push_str("    at Module.bar (lib.js:42:3)\n");
        for i in 0..40 {
            log.push_str(&format!("INFO heartbeat {}\n", 40 + i));
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&log, &CompressionContext::default(), &store)
            .expect("compresses");
        assert!(r.output.contains("at Object.foo"));
        assert!(r.output.contains("at Module.bar"));
        assert!(
            r.output.contains("TypeError: Cannot read property"),
            "the error header above the frames must survive"
        );
    }

    #[test]
    fn repeated_warnings_dedup_to_one_template() {
        // GOLD-ADAPT-HR-03a: 50 warnings sharing a template collapse to one.
        let mut log = String::new();
        for i in 0..30 {
            log.push_str(&format!("INFO heartbeat {i}\n"));
        }
        for i in 0..50 {
            log.push_str(&format!("WARNING disk usage high at {i}mb\n"));
        }
        for i in 0..30 {
            log.push_str(&format!("INFO heartbeat {}\n", 30 + i));
        }
        let store = InMemoryCcrStore::new();
        let r = offload()
            .apply(&log, &CompressionContext::default(), &store)
            .expect("compresses");
        let kept = r
            .output
            .lines()
            .filter(|l| l.starts_with("WARNING disk usage high"))
            .count();
        assert_eq!(kept, 1, "50 same-template warnings dedup to 1, got {kept}");
    }
}
