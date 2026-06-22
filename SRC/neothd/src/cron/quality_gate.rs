//! JV-PRO-07 — Briefing/proactive output quality gate.
//!
//! Pure functions. No I/O. No async. Scores a cron job's generated output so
//! the caller can decide whether to deliver or discard it. (V1: regeneration/
//! retry is not yet implemented — the score is operator diagnostics + a
//! deliver/skip signal, not a regen trigger.)
//!
//! ## What is scored
//!
//! | Signal            | Weight in score |
//! |-------------------|-----------------|
//! | Word count ≥ floor| pass/fail gate  |
//! | Has title/heading | +0.20 bonus     |
//! | Citation density  | up to +0.15     |
//! | Filler ratio      | penalty up to −0.30 |
//!
//! Final score ∈ `[0.0, 1.0]`. `passed` is true when `score ≥ PASS_THRESHOLD`.
//!
//! ## Filler detection
//!
//! Reuses the nspace anti-pattern catalog from `council::nspace` (LOWKEY-02/03)
//! — the same phrases that penalise council hemisphere responses are checked
//! here. This is a word-level ratio: `filler_words / total_words`.
//!
//! ## Note on naming
//!
//! `council::quality_score` already defines a `QualityScore` type for
//! hemisphere scoring. This module uses `BriefingScore` to avoid a name
//! collision in the `cron` namespace.

// neoth tunable — minimum acceptable score to pass the gate.
const PASS_THRESHOLD: f64 = 0.55;

// neoth tunable — bonus for having at least one heading line.
const TITLE_BONUS: f64 = 0.20;

// neoth tunable — maximum citation bonus (reached at CITATION_SATURATION hits).
const CITATION_BONUS_CAP: f64 = 0.15;
const CITATION_SATURATION: usize = 5; // saturates at 5 citations

// neoth tunable — filler penalty cap (applied as fraction of filler_ratio).
const FILLER_PENALTY_CAP: f64 = 0.30;

// neoth tunable — filler ratio above which the penalty is maxed.
const FILLER_RATIO_MAX: f64 = 0.20; // 20 % filler → full penalty cap

/// Composite quality score for one cron job output.
///
/// All fields are public so callers can surface per-signal diagnostics in the
/// WAL frame or CLI output (`neoth cron logs --quality`).
#[derive(Debug, Clone, PartialEq)]
pub struct BriefingScore {
    /// Total word count in the output.
    pub word_count: usize,
    /// True when at least one heading/title line was detected.
    pub has_title: bool,
    /// Number of citation-style patterns found (URLs, `[N]`, `(source)`, etc.).
    pub citation_count: usize,
    /// Fraction of words that are filler phrases `[0.0, 1.0]`.
    pub filler_ratio: f64,
    /// Composite score `[0.0, 1.0]`.
    pub score: f64,
    /// Whether the score meets `PASS_THRESHOLD`.
    pub passed: bool,
}

impl BriefingScore {
    /// True when the score is below threshold and a regeneration attempt is
    /// warranted. Alias for `!self.passed` — exists so callers read as intent.
    pub fn should_regenerate(&self) -> bool {
        !self.passed
    }
}

// ── Filler catalog ────────────────────────────────────────────────────────────

/// Flat list of filler phrases reused from `council::nspace` groups
/// (LOWKEY-02/03). Kept as a local const slice so `quality_gate` stays
/// independent of the council crate path at call sites. Any additions to
/// `nspace.rs` should be mirrored here.
///
/// Phrases are lowercased; matching is case-insensitive via
/// `to_ascii_lowercase`.
const FILLER_PHRASES: &[&str] = &[
    // performative_apology group
    "i apologize",
    "i'm sorry",
    "i am sorry",
    "forgive me",
    "pardon me",
    "i regret",
    "my apologies",
    "sorry for",
    // hedging group
    "please note that",
    "it's worth noting",
    "it is worth noting",
    "i should mention",
    "keep in mind",
    "bear in mind",
    "as you may know",
    "as you might know",
    "feel free to",
    "don't hesitate to",
    // assistant_theater group
    "as an ai",
    "as a language model",
    "i'm an ai",
    "i am an ai",
    "i don't have the ability",
    "my training data",
    "my knowledge cutoff",
    "certainly!",
    "certainly,",
    "absolutely!",
    "absolutely,",
    "of course!",
    "of course,",
    "great question",
    "excellent question",
    // fake_empathy group
    "i understand your",
    "i hear you",
    "that's understandable",
    "that is understandable",
    "i can imagine",
    "i'm here to help",
    "i am here to help",
    // tone_policing group
    "i encourage you to",
    "you might want to consider",
    "perhaps you could",
    "it might be helpful",
    // safety_moralizing group
    "i must decline",
    "i cannot and will not",
    "violates my",
    "against my guidelines",
    "i'm not able to",
    "i am not able to",
];

// ── Scoring helpers ───────────────────────────────────────────────────────────

/// Count whitespace-delimited words. Used consistently for word_count and
/// filler_ratio denominator.
fn count_words(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Detect a title / heading line. Criteria (any one suffices):
/// - Line starts with `#` (Markdown heading).
/// - Line is ALL-CAPS and ≥ 3 words (a shouting summary title).
/// - Line ends with `:` and has no whitespace before the colon (section label).
fn detect_title(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Markdown heading
        if trimmed.starts_with('#') {
            return true;
        }
        // ALL-CAPS heading (≥ 3 words)
        let upper = trimmed.to_ascii_uppercase();
        if upper == trimmed && count_words(trimmed) >= 3 {
            return true;
        }
        // Section label: one or two words followed by `:` at line end
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() <= 3 {
            if let Some(last) = words.last() {
                if last.ends_with(':') {
                    return true;
                }
            }
        }
    }
    false
}

/// Count citation-style patterns:
/// - URLs: contains `http://` or `https://`
/// - Numeric references: `[1]`, `[12]`, etc.
/// - Source parentheticals: `(source`, `(via`
fn count_citations(text: &str) -> usize {
    let lower = text.to_ascii_lowercase();
    let mut count = 0usize;

    // URLs — count per occurrence
    count += lower.matches("https://").count();
    count += lower.matches("http://").count();

    // Numeric refs [N] or [NN]
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b']' {
                count += 1;
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }

    // (source / (via
    count += lower.matches("(source").count();
    count += lower.matches("(via").count();

    count
}

/// Compute filler ratio: proportion of text tokens that are filler phrases.
///
/// We scan the full lowercased text for each phrase and count non-overlapping
/// hits. The word count of each matched phrase is accumulated as
/// `filler_words`; dividing by `total_words` gives the ratio.
fn filler_ratio(text: &str, total_words: usize) -> f64 {
    if total_words == 0 {
        return 0.0;
    }
    let lower = text.to_ascii_lowercase();
    let mut filler_words = 0usize;
    for phrase in FILLER_PHRASES {
        // Count non-overlapping occurrences; each adds phrase word count.
        let phrase_word_count = phrase.split_whitespace().count();
        let mut start = 0usize;
        while let Some(pos) = lower[start..].find(phrase) {
            filler_words += phrase_word_count;
            start += pos + phrase.len();
        }
    }
    (filler_words as f64 / total_words as f64).min(1.0)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Score a cron job's generated briefing/proactive output.
///
/// `output` — the raw text returned by the provider.
/// `min_words` — minimum word count for a valid briefing. Outputs below this
///   threshold score 0.0 and fail regardless of other signals.
///
/// Returns a [`BriefingScore`] with per-signal breakdown and a `passed` flag.
/// Use `score.should_regenerate()` to decide whether to retry the job.
pub fn score_briefing(output: &str, min_words: usize) -> BriefingScore {
    let trimmed = output.trim();
    let word_count = count_words(trimmed);

    // Hard gate: below the word floor → instant fail, no further scoring.
    if word_count < min_words {
        return BriefingScore {
            word_count,
            has_title: false,
            citation_count: 0,
            filler_ratio: 0.0,
            score: 0.0,
            passed: false,
        };
    }

    let has_title = detect_title(trimmed);
    let citation_count = count_citations(trimmed);
    let fr = filler_ratio(trimmed, word_count);

    // Build score from bonuses and penalties.
    let mut score: f64 = 0.50; // neutral base for a word-count-passing output

    if has_title {
        score += TITLE_BONUS;
    }

    // Citation bonus: linear ramp to cap.
    let citation_fraction = (citation_count as f64 / CITATION_SATURATION as f64).min(1.0);
    score += citation_fraction * CITATION_BONUS_CAP;

    // Filler penalty: linear ramp to cap.
    let filler_fraction = (fr / FILLER_RATIO_MAX).min(1.0);
    score -= filler_fraction * FILLER_PENALTY_CAP;

    let score = score.clamp(0.0, 1.0);
    let passed = score >= PASS_THRESHOLD;

    BriefingScore {
        word_count,
        has_title,
        citation_count,
        filler_ratio: fr,
        score,
        passed,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A 5-word filler-heavy output must fail the word-count gate.
    #[test]
    fn fails_word_count_gate() {
        let output = "Certainly! Of course absolutely feel";
        let s = score_briefing(output, 50);
        assert!(!s.passed, "output below min_words must fail");
        assert_eq!(s.score, 0.0);
        assert_eq!(s.word_count, 5);
    }

    /// A substantive briefing with a title and citations should pass.
    #[test]
    fn passes_substantive_briefing() {
        let output = "\
# Morning Tech Brief

Rust 2024 edition shipped with 15 new lints. See https://blog.rust-lang.org/2024/01/01/Rust.html \
for the full changelog. The team also released cargo-vet [1] as a supply chain auditing tool. \
According to the announcement (source: rust-lang.org), adoption is already above 3000 crates. \
New async features include better support for structured concurrency and improved diagnostics \
for lifetime errors in async contexts. Tokio 2.0 beta dropped the same week with a revamped \
task scheduler that reduces p99 latency by roughly 30 percent on IO-heavy workloads. The Bevy \
game engine reached 0.13 with GPU-driven rendering enabled by default on Vulkan targets.";
        let s = score_briefing(output, 50);
        assert!(s.passed, "substantive briefing should pass; score={}", s.score);
        assert!(s.has_title);
        assert!(s.citation_count >= 2);
    }

    /// A filler-heavy output of sufficient word count should fail due to penalty.
    #[test]
    fn fails_filler_heavy_output() {
        // 80+ words, but full of filler
        let output = "Certainly! Of course! I apologize for any confusion. I'm sorry. \
            As an AI I don't have the ability to browse the web. My apologies. \
            I am here to help you though! Certainly certainly certainly. Please note that \
            I understand your concern and I can imagine how frustrating this might be. \
            Of course of course feel free to ask me anything. I must decline to speculate. \
            Absolutely! Great question! I am an AI language model. Forgive me. \
            I am not able to provide real-time data. My training data has a cutoff.";
        let s = score_briefing(output, 50);
        assert!(
            !s.passed,
            "filler-heavy output should fail; score={} filler_ratio={}",
            s.score,
            s.filler_ratio
        );
        assert!(s.filler_ratio > 0.10, "filler_ratio should be significant");
    }

    /// Word count boundary: exactly min_words should proceed to scoring.
    #[test]
    fn exactly_min_words_proceeds_to_scoring() {
        // 10 distinct non-filler words — should not hard-fail.
        let output = "The quick brown fox jumps over the lazy sleeping dog";
        let s = score_briefing(output, 10);
        // May or may not pass, but must NOT be stuck at score 0.0.
        assert!(s.score > 0.0, "at-boundary output must not hard-fail with score=0");
    }

    /// Markdown heading is detected as title.
    #[test]
    fn detects_markdown_heading() {
        let output = "# Daily Summary\nToday was uneventful. Some text here. \
            More words to reach the minimum count of twenty words total here.";
        let s = score_briefing(output, 20);
        assert!(s.has_title);
    }

    /// No title detected for body-only text.
    #[test]
    fn no_title_for_body_only() {
        let output = "today was uneventful some text here more words to reach minimum \
            count of twenty words total in this plain paragraph no heading at all";
        let s = score_briefing(output, 20);
        assert!(!s.has_title);
    }

    /// Citation counting covers URLs and numeric refs.
    #[test]
    fn counts_citations() {
        let output = "See https://example.com and https://other.org for refs [1] and [2]. \
            Additional context (source: internal). More text needed for word count \
            threshold to be satisfied in this test case here.";
        let s = score_briefing(output, 20);
        assert!(s.citation_count >= 4, "should count 2 URLs + 2 numeric refs, got {}", s.citation_count);
    }

    /// should_regenerate mirrors !passed.
    #[test]
    fn should_regenerate_mirrors_not_passed() {
        let short = score_briefing("hi", 50);
        assert!(short.should_regenerate());

        let long = score_briefing(
            "# Brief\nLong enough text with real content about Rust 2024 edition \
             and many new features shipped this year in the ecosystem.",
            10,
        );
        assert_eq!(long.should_regenerate(), !long.passed);
    }
}
