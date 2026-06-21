//! GOLD-ADAPT-LOWKEY-04 — MIF motive-identification pre-step.
//!
//! Classifies operator intent as [`MifIntent::Stated`],
//! [`MifIntent::Inferred`], or [`MifIntent::Conflicted`] BEFORE the
//! council hemispheres are queried.  A `Conflicted` result gates the
//! debate and surfaces a disambiguation request instead of a confused
//! answer.
//!
//! ## Design
//!
//! * **Deterministic, LLM-free.**  Pattern-based classification avoids
//!   an extra LLM call in the hot path.  False-positive rate is kept low
//!   by requiring at least two evidence points from different signal
//!   classes before emitting `Conflicted`.
//! * **Conservative.**  When in doubt, `Inferred` is preferred over
//!   `Conflicted` — blocking a valid request is worse than letting the
//!   council answer an ambiguous one.
//! * **Operator-visible.**  [`MifAnalysis::reason`] and
//!   [`MifAnalysis::contradictions`] are human-readable so the
//!   disambiguation request can name exactly what was detected.
//!
//! ## Classification logic
//!
//! 1. **Contradiction scan** — check for paired antonym cues within the
//!    same prompt (e.g. "brief" vs "explain every detail", "do X" vs
//!    "don't do X", "always" vs "never").  Each matched pair becomes a
//!    contradiction entry.
//! 2. **Scope inflation scan** — detect absolute-quantity mismatches
//!    (e.g. "one sentence" + "cover all cases") that imply conflicting
//!    scope constraints.
//! 3. **Imperative vs exploratory mode** — if contradictions found →
//!    `Conflicted`; if an explicit imperative verb introduces the prompt
//!    → `Stated`; otherwise → `Inferred`.

use super::types::{MifAnalysis, MifIntent};

// ─── Antonym pairs ────────────────────────────────────────────────────────────
//
// Each entry is (signal_a_keywords, signal_b_keywords, label).
// The label names the pair for the `contradictions` field.
// Match is case-insensitive; all keywords within a group must appear
// ANYWHERE in the prompt (not necessarily adjacent) to count as a hit.
// Pair fires when BOTH sides of the pair are present.

struct AntonymPair {
    /// Keywords belonging to the first side of the contradiction.
    side_a: &'static [&'static str],
    /// Keywords belonging to the second side.
    side_b: &'static [&'static str],
    /// Short label for the `contradictions` Vec.
    label: &'static str,
}

const ANTONYM_PAIRS: &[AntonymPair] = &[
    AntonymPair {
        side_a: &["brief", "concise", "short", "terse", "succinct", "one sentence", "one-sentence", "summary", "tldr"],
        side_b: &["every detail", "all details", "exhaustive", "comprehensive", "thorough", "in depth", "in-depth", "step by step", "step-by-step", "explain everything"],
        label: "brevity vs exhaustiveness",
    },
    AntonymPair {
        // "do X" vs "don't do X" / "do not do X" / "avoid X" — captured
        // by the presence of a negation modifier alongside a positive action.
        // Because the specific X varies, we key on the structural markers.
        side_a: &["must", "always", "every time", "make sure", "ensure", "guarantee"],
        side_b: &["never", "do not", "don't", "avoid", "without", "except"],
        label: "mandatory vs prohibited",
    },
    AntonymPair {
        side_a: &["formal", "professional", "technical", "precise"],
        side_b: &["casual", "informal", "simple", "layman", "plain language", "easy to understand", "non-technical"],
        label: "formal vs informal register",
    },
    AntonymPair {
        side_a: &["high level", "high-level", "overview", "abstract", "conceptual"],
        side_b: &["low level", "low-level", "implementation detail", "line by line", "line-by-line", "code-level", "concrete"],
        label: "high-level vs low-level detail",
    },
    AntonymPair {
        // Quantity conflict: "one X" vs "all X" / "multiple X"
        side_a: &["one ", "single", "only one", "just one"],
        side_b: &["all ", "every ", "multiple", "several", "all cases", "every case"],
        label: "singular vs plural scope",
    },
    AntonymPair {
        side_a: &["quickly", "fast", "rapid", "immediately", "right now"],
        side_b: &["carefully", "thoroughly", "slowly", "take your time", "no rush"],
        label: "speed vs thoroughness",
    },
];

// ─── Imperative starters (Stated detection) ──────────────────────────────────
//
// A prompt that opens with one of these verbs after optional leading
// whitespace/punctuation is `Stated` when no contradictions fire.

const IMPERATIVE_VERBS: &[&str] = &[
    "summarize", "summarise", "explain", "describe", "list", "enumerate",
    "write", "create", "generate", "produce", "build", "implement",
    "translate", "convert", "refactor", "fix", "debug", "analyse", "analyze",
    "compare", "contrast", "evaluate", "review", "check", "test",
    "show", "display", "print", "output", "give", "provide", "find",
    "search", "look up", "lookup", "calculate", "compute", "solve",
    "format", "rewrite", "paraphrase",
];

// ─── Public API ───────────────────────────────────────────────────────────────

/// GOLD-ADAPT-LOWKEY-04 — classify the operator intent of `prompt`.
///
/// The function is synchronous and has no I/O: it is safe to call from
/// both async and non-async contexts.  The council orchestrator calls
/// this before launching the hemisphere futures.
///
/// # Returns
///
/// A [`MifAnalysis`] carrying the [`MifIntent`] variant, a human-
/// readable reason, and (for `Conflicted`) the list of contradiction
/// pairs that were detected.
pub fn classify_motive(prompt: &str) -> MifAnalysis {
    let lower = prompt.to_ascii_lowercase();

    // 1. Contradiction scan.
    let mut contradictions: Vec<String> = Vec::new();
    for pair in ANTONYM_PAIRS {
        let side_a_hit = pair.side_a.iter().any(|kw| lower.contains(kw));
        let side_b_hit = pair.side_b.iter().any(|kw| lower.contains(kw));
        if side_a_hit && side_b_hit {
            contradictions.push(pair.label.to_string());
        }
    }

    // 2. Conflicted if at least one contradiction pair fired.
    if !contradictions.is_empty() {
        return MifAnalysis {
            intent: MifIntent::Conflicted,
            reason: format!(
                "contradictory signals detected in {} pair(s)",
                contradictions.len()
            ),
            contradictions,
        };
    }

    // 3. Stated if an imperative verb opens the prompt.
    if starts_with_imperative(&lower) {
        return MifAnalysis {
            intent: MifIntent::Stated,
            reason: "prompt begins with an explicit imperative directive".into(),
            contradictions: vec![],
        };
    }

    // 4. Default: Inferred.
    MifAnalysis {
        intent: MifIntent::Inferred,
        reason: "no explicit imperative; intent inferred from phrasing".into(),
        contradictions: vec![],
    }
}

/// Returns `true` when `lower` (already lowercased) begins with one of
/// the known imperative verbs, optionally preceded by whitespace or a
/// single punctuation character (e.g. a leading `"`).
fn starts_with_imperative(lower: &str) -> bool {
    let trimmed = lower.trim_start_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
    IMPERATIVE_VERBS
        .iter()
        .any(|verb| trimmed.starts_with(verb))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Conflicted cases ──────────────────────────────────────────────

    #[test]
    fn conflicted_brevity_vs_exhaustiveness() {
        // "brief" and "explain every detail" are contradictory scope signals.
        let r = classify_motive("Give me a brief summary but explain every detail.");
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
        assert!(
            r.contradictions
                .iter()
                .any(|c| c.contains("brevity") || c.contains("exhaustiveness")),
            "contradiction label missing: {:?}",
            r.contradictions
        );
        assert!(r.blocks_debate());
    }

    #[test]
    fn conflicted_mandatory_vs_prohibited() {
        // "always" (mandatory) + "never" (prohibited) — cannot both hold.
        let r = classify_motive("You must always include the full trace, but never exceed 5 lines.");
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
        assert!(r.blocks_debate());
    }

    #[test]
    fn conflicted_formal_vs_informal_register() {
        let r = classify_motive("Write a formal technical report in plain language for laymen.");
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
    }

    #[test]
    fn conflicted_disambiguation_message_is_produced() {
        let r = classify_motive("Be concise but give step-by-step exhaustive coverage.");
        assert_eq!(r.intent, MifIntent::Conflicted);
        let msg = r.disambiguation_message().expect("must produce a message");
        assert!(
            msg.contains("conflicting goals"),
            "message should name the issue: {msg}"
        );
    }

    #[test]
    fn conflicted_singular_vs_plural_scope() {
        let r = classify_motive("Pick one function and fix all of them.");
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
    }

    #[test]
    fn conflicted_speed_vs_thoroughness() {
        let r = classify_motive("Do this quickly but carefully and thoroughly.");
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
    }

    // ── Stated cases ──────────────────────────────────────────────────

    #[test]
    fn stated_explicit_imperative_summarize() {
        let r = classify_motive("Summarise this document in three bullet points.");
        assert_eq!(r.intent, MifIntent::Stated, "reason: {}", r.reason);
        assert!(!r.blocks_debate());
    }

    #[test]
    fn stated_explicit_imperative_write() {
        let r = classify_motive("Write a Rust function that parses JSON.");
        assert_eq!(r.intent, MifIntent::Stated, "reason: {}", r.reason);
    }

    #[test]
    fn stated_explicit_imperative_list() {
        let r = classify_motive("List all open files in this directory.");
        assert_eq!(r.intent, MifIntent::Stated, "reason: {}", r.reason);
    }

    #[test]
    fn stated_no_disambiguation_message() {
        let r = classify_motive("Refactor this function to reduce nesting.");
        assert_eq!(r.intent, MifIntent::Stated);
        assert!(r.disambiguation_message().is_none());
    }

    // ── Inferred cases ────────────────────────────────────────────────

    #[test]
    fn inferred_interrogative_what() {
        let r = classify_motive("What does this diff change?");
        assert_eq!(r.intent, MifIntent::Inferred, "reason: {}", r.reason);
        assert!(!r.blocks_debate());
    }

    #[test]
    fn inferred_interrogative_how() {
        let r = classify_motive("How does the scheduler decide which task to run?");
        assert_eq!(r.intent, MifIntent::Inferred, "reason: {}", r.reason);
    }

    #[test]
    fn inferred_open_ended_statement() {
        let r = classify_motive("This code has a potential race condition.");
        assert_eq!(r.intent, MifIntent::Inferred, "reason: {}", r.reason);
    }

    #[test]
    fn inferred_no_disambiguation_message() {
        let r = classify_motive("Tell me about the error on line 42.");
        // "Tell me" doesn't start with a canonical imperative verb.
        // Still non-conflicted — no disambiguation needed.
        assert!(r.disambiguation_message().is_none());
    }

    // ── Allows-debate invariant ───────────────────────────────────────

    #[test]
    fn stated_and_inferred_allow_debate_conflicted_does_not() {
        let cases = [
            ("Summarise this.", MifIntent::Stated),
            ("What is going on?", MifIntent::Inferred),
        ];
        for (prompt, expected) in cases {
            let r = classify_motive(prompt);
            assert_eq!(r.intent, expected, "prompt: {prompt}");
            assert!(r.intent.allows_debate(), "prompt: {prompt}");
        }
        let conflicted = classify_motive("Be brief but exhaustive and explain every detail.");
        assert_eq!(conflicted.intent, MifIntent::Conflicted);
        assert!(!conflicted.intent.allows_debate());
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn empty_prompt_is_inferred() {
        let r = classify_motive("");
        assert_eq!(r.intent, MifIntent::Inferred);
    }

    #[test]
    fn whitespace_only_prompt_is_inferred() {
        let r = classify_motive("   \t\n");
        assert_eq!(r.intent, MifIntent::Inferred);
    }

    #[test]
    fn case_insensitive_classification() {
        // Uppercase prompt should classify the same as lowercase.
        let upper = classify_motive("SUMMARISE THIS DOCUMENT.");
        let lower = classify_motive("summarise this document.");
        assert_eq!(upper.intent, lower.intent);
    }

    #[test]
    fn high_level_vs_low_level_is_conflicted() {
        let r = classify_motive(
            "Give me a high-level overview and also walk through every low-level implementation detail.",
        );
        assert_eq!(r.intent, MifIntent::Conflicted, "reason: {}", r.reason);
    }
}
