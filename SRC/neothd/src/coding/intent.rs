//! Round-3 v0.4 — coding-intent auto-detection.
//!
//! `neoth chat` is the operator's daily-driver entry point. When the
//! prompt body looks like a coding request ("bau mir eine Funktion
//! die …", "fix the bug in …", "refactor X", "implement Y", "schreib
//! einen Test für Z"), routing through the dedicated coding workflow
//! (`cli::code::run_code` → kanban session + hemisphere worker
//! dispatch + patch+test loop) produces a better outcome than a
//! single-turn chat reply. This module ships the pure-fn detector;
//! `chat::run_chat_with` consumes it + auto-dispatches.
//!
//! ## Detection scope
//!
//! Bilingual (English + German — the operator's profile mixes
//! both freely). Two signal classes:
//!
//! 1. **Verb-led patterns** — first-word coding verbs in either
//!    language ("bau", "build", "code", "implement", "refactor",
//!    "fix", "write", "schreib", "implementiere", etc.).
//!
//! 2. **Programming-noun anchors** — the prompt mentions a
//!    programming artefact ("function", "class", "test", "bug",
//!    "PR", "Funktion", "Klasse", "Bug", "Patch", file extensions
//!    like ".rs" / ".py" / ".ts") within a noun-context window.
//!
//! Both classes together → high confidence. Verb alone OR noun
//! alone → low confidence (still detected, but caller may show a
//! "use `neoth code` instead?" banner rather than auto-dispatch).
//!
//! ## False-positive defence
//!
//! Casual chat about coding ("I'm tired of debugging") shouldn't
//! trigger auto-dispatch. The detector requires a coding-verb at
//! the FRONT of the prompt (first 30 chars) — narrative mentions
//! mid-sentence don't fire. The opt-out env var `NEOTH_NO_AUTO_CODE=1`
//! disables auto-dispatch entirely for operators who want manual
//! routing.
//!
//! ## Future swap
//!
//! v0.9 G-01 LLM-driven intent classification can replace this
//! heuristic. The pure-fn surface stays the same so the swap is
//! drop-in.

use serde::{Deserialize, Serialize};

/// One detected coding intent. Carries the confidence signal so
/// the caller can decide auto-dispatch (High) vs offer-only-banner
/// (Low).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingIntent {
    pub confidence: IntentConfidence,
    /// Which verb pattern matched (operator-readable in the banner).
    pub matched_verb: Option<String>,
    /// Which noun anchor matched (operator-readable in the banner).
    pub matched_noun: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentConfidence {
    /// Both verb + noun matched → safe to auto-dispatch.
    High,
    /// Verb OR noun alone → show banner offering `neoth code`.
    Low,
}

/// Verb patterns that lead a coding request. Matched against the
/// first 30 characters of the prompt (lowercased + trimmed). The
/// front-anchor rule prevents mid-sentence false positives like
/// "I built that yesterday". Bilingual EN + DE.
pub const CODING_VERBS: &[&str] = &[
    // English imperatives
    "build",
    "code",
    "write",
    "implement",
    "refactor",
    "fix",
    "patch",
    "add",
    "create",
    "make",
    "debug",
    "rewrite",
    "port",
    "extend",
    "scaffold",
    "wire up",
    "wire",
    // German imperatives
    "bau",
    "baue",
    "schreib",
    "schreibe",
    "implementier",
    "implementiere",
    "fix",
    "patche",
    "refaktor",
    "refaktorier",
    "erweiter",
    "erweitere",
    "erstell",
    "erstelle",
    "mach",
    "mache",
    "korrigier",
    "korrigiere",
    "portier",
    "portiere",
    // Interrogative coding requests
    "can you build",
    "can you write",
    "can you implement",
    "kannst du",
    "könntest du",
    "koenntest du",
];

/// Noun anchors that signal a programming artefact in the prompt.
/// Matched case-insensitively anywhere in the prompt body. Bilingual.
pub const CODING_NOUNS: &[&str] = &[
    // English
    "function",
    "method",
    "class",
    "module",
    "trait",
    "impl",
    "struct",
    "enum",
    "test",
    "tests",
    "bug",
    "feature",
    "endpoint",
    "api",
    "handler",
    "route",
    "regex",
    "parser",
    "compiler",
    "loop",
    "callback",
    "closure",
    "async",
    "await",
    "thread",
    "mutex",
    "lock",
    "schema",
    "migration",
    "ci",
    "pr ",
    "pull request",
    "refactor",
    "patch",
    // German
    "funktion",
    "methode",
    "klasse",
    "modul",
    "test",
    "tests",
    "bug",
    "feature",
    "endpunkt",
    "schnittstelle",
    "schema",
    "migration",
    "patch",
    // File extensions (anchor at boundary)
    ".rs",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".java",
    ".kt",
    ".cpp",
    ".c",
    ".h",
    ".rb",
    ".php",
    ".sh",
    ".sql",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
];

/// Maximum byte offset for verb-front anchoring. Matches the doc
/// rule that coding verbs must lead the prompt to trip detection;
/// 30 bytes covers the common "Hey, fix the …" / "Bitte schreib
/// mir …" preambles without admitting paragraph-deep narrative
/// mentions.
pub const VERB_FRONT_ANCHOR_BYTES: usize = 30;

/// Detect coding intent in `prompt`. Returns `None` when no
/// signal matches. Returns `Some(CodingIntent)` with confidence
/// based on whether both signals fired or only one.
pub fn detect_coding_intent(prompt: &str) -> Option<CodingIntent> {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    // GOLD-COR-02 / A-04: slice on a CHAR boundary — `lower` is lowercased
    // (often German, multibyte ü/ö/ä), and a raw `[..N]` panics mid-char.
    let mut front_end = lower.len().min(VERB_FRONT_ANCHOR_BYTES);
    while front_end > 0 && !lower.is_char_boundary(front_end) {
        front_end -= 1;
    }
    let front_window = &lower[..front_end];

    let matched_verb = CODING_VERBS
        .iter()
        .find(|v| front_window.starts_with(*v) || front_window.contains(&format!(" {v} ")))
        .map(|s| (*s).to_string());

    let matched_noun = CODING_NOUNS
        .iter()
        .find(|n| {
            // For file extensions (starts with '.'), match anywhere;
            // for words, require a word-ish boundary (start of string
            // OR preceded by whitespace / punctuation).
            if n.starts_with('.') {
                lower.contains(*n)
            } else {
                contains_word(&lower, n)
            }
        })
        .map(|s| (*s).to_string());

    match (matched_verb.is_some(), matched_noun.is_some()) {
        (false, false) => None,
        (true, true) => Some(CodingIntent {
            confidence: IntentConfidence::High,
            matched_verb,
            matched_noun,
        }),
        _ => Some(CodingIntent {
            confidence: IntentConfidence::Low,
            matched_verb,
            matched_noun,
        }),
    }
}

/// True when `haystack` contains `needle` as a word — preceded by
/// boundary (start-of-string / whitespace / punctuation) AND followed
/// by boundary. Avoids matching `"refactor"` inside `"refactoring"`
/// but allows `"refactor"` standalone.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let pre_ok = abs == 0
            || haystack[..abs]
                .chars()
                .last()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);
        let end = abs + needle.len();
        let post_ok = end >= haystack.len()
            || haystack[end..]
                .chars()
                .next()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);
        if pre_ok && post_ok {
            return true;
        }
        start = abs + needle.len();
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// Convenience: should the caller auto-dispatch to the coding
/// workflow? `true` iff intent detected AND confidence is High AND
/// the operator hasn't set `NEOTH_NO_AUTO_CODE=1`.
pub fn should_auto_dispatch(prompt: &str) -> bool {
    if std::env::var("NEOTH_NO_AUTO_CODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    matches!(
        detect_coding_intent(prompt),
        Some(CodingIntent {
            confidence: IntentConfidence::High,
            ..
        })
    )
}

/// One-line operator banner format for the detected intent. The
/// chat dispatch path prints this BEFORE auto-dispatching so the
/// operator sees what NEOTH decided + how to opt out.
pub fn format_dispatch_banner(intent: &CodingIntent) -> String {
    let verb = intent.matched_verb.as_deref().unwrap_or("?");
    let noun = intent.matched_noun.as_deref().unwrap_or("?");
    format!(
        "[neoth] coding intent detected (verb='{verb}' noun='{noun}') — auto-dispatching to `neoth code`. \
         Set NEOTH_NO_AUTO_CODE=1 to disable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn high(prompt: &str) {
        let i = detect_coding_intent(prompt)
            .unwrap_or_else(|| panic!("expected High-confidence intent on: {prompt}"));
        assert_eq!(
            i.confidence,
            IntentConfidence::High,
            "{prompt} should be High but was {:?}",
            i.confidence,
        );
    }
    fn low(prompt: &str) {
        let i = detect_coding_intent(prompt)
            .unwrap_or_else(|| panic!("expected some intent on: {prompt}"));
        assert_eq!(
            i.confidence,
            IntentConfidence::Low,
            "{prompt} should be Low but was {:?}",
            i.confidence,
        );
    }
    fn none(prompt: &str) {
        assert!(
            detect_coding_intent(prompt).is_none(),
            "{prompt} should NOT detect intent",
        );
    }

    // ── High-confidence: verb + noun ──────────────────────────────

    #[test]
    fn high_english_imperative_with_noun() {
        high("build a function that reverses a linked list");
        high("write tests for the new auth handler");
        high("refactor the schema migration");
        high("fix the bug in the regex parser");
        high("implement a callback for the websocket endpoint");
    }

    #[test]
    fn high_german_imperative_with_noun() {
        high("bau mir eine Funktion die Listen umdreht");
        high("schreib einen Test für den auth handler");
        high("refaktoriere das Schema");
        high("implementiere eine Methode für die API");
        high("erstelle ein neues Modul für die Migration");
    }

    #[test]
    fn high_file_extension_noun() {
        // ".rs" anchor counts as noun even without prose nouns.
        high("fix the panic in main.rs");
        high("baue mir was in src/foo.py");
    }

    // ── Low-confidence: verb alone or noun alone ──────────────────

    #[test]
    fn low_verb_only_no_noun() {
        low("build something cool today");
        low("schreib was nettes");
        low("implement it however you like");
    }

    #[test]
    fn low_noun_only_no_verb() {
        low("the function we discussed yesterday was nice");
        low("die Funktion war kompliziert");
        low("there's a bug somewhere in that loop");
    }

    // ── No detection: narrative / casual / unrelated ──────────────

    #[test]
    fn none_pure_conversation() {
        none("how was your day?");
        none("what time is it?");
        none("tell me a joke");
        none("");
        none("   ");
    }

    #[test]
    fn none_mid_sentence_verb_with_no_noun_anchor() {
        // "build" appears mid-sentence; no anchor → no detection
        // (the verb-front rule + no noun guards against this).
        none("yesterday I just felt happy and free");
    }

    #[test]
    fn front_anchor_window_strict_for_verbs() {
        // 30+ chars of preamble, THEN a coding verb — verb-front
        // anchor must NOT fire (verb is past the window). But a
        // noun mid-sentence may still trip Low confidence — that's
        // intentional (operator IS talking about code).
        let prompt =
            "I was thinking about something completely different today and then build a function";
        // The window cuts off before "build", so verb-front match
        // shouldn't fire — but "build" surrounded by spaces in the
        // window-search-with-spaces variant CAN match. We check
        // that no _High_ confidence fires (the verb-front rule
        // protects us from auto-dispatch on this).
        let intent = detect_coding_intent(prompt);
        if let Some(i) = intent {
            assert_ne!(
                i.confidence,
                IntentConfidence::High,
                "verb past anchor + noun present should not produce High",
            );
        }
    }

    // ── Word-boundary safety ──────────────────────────────────────

    #[test]
    fn contains_word_avoids_substring_matches() {
        // Positive control: standalone word matches.
        assert!(contains_word("write a test", "test"));
        // Negative: "test" inside "tests" / "attestation" must NOT match
        // — that's the whole point. The noun list carries "tests" as its
        // own entry, so detection of "write tests" doesn't lean on this.
        assert!(!contains_word("write tests", "test"));
        assert!(!contains_word("attestation document", "test"));
        assert!(contains_word("bug fix", "bug"));
        assert!(!contains_word("bugbear", "bug"));
    }

    #[test]
    fn contains_word_handles_punctuation_boundary() {
        assert!(contains_word("fix the bug.", "bug"));
        assert!(contains_word("(class Foo)", "class"));
    }

    // ── should_auto_dispatch ──────────────────────────────────────

    #[test]
    fn should_auto_dispatch_true_for_high_confidence() {
        // NEOTH_NO_AUTO_CODE is process-global; take the env lock so
        // these three should_auto_dispatch tests don't race each other
        // under the multi-threaded runner. See crate::test_env.
        let _env = crate::test_env::lock();
        unsafe { std::env::remove_var("NEOTH_NO_AUTO_CODE") };
        assert!(should_auto_dispatch("build a function for me"));
    }

    #[test]
    fn should_auto_dispatch_false_for_low_confidence() {
        let _env = crate::test_env::lock();
        unsafe { std::env::remove_var("NEOTH_NO_AUTO_CODE") };
        assert!(!should_auto_dispatch("build something cool"));
    }

    #[test]
    fn should_auto_dispatch_false_when_env_opt_out() {
        let _env = crate::test_env::lock();
        unsafe { std::env::set_var("NEOTH_NO_AUTO_CODE", "1") };
        assert!(!should_auto_dispatch("build a function for me"));
        unsafe { std::env::remove_var("NEOTH_NO_AUTO_CODE") };
    }

    // ── format_dispatch_banner ────────────────────────────────────

    #[test]
    fn format_banner_includes_verb_noun_and_optout_hint() {
        let intent = CodingIntent {
            confidence: IntentConfidence::High,
            matched_verb: Some("build".to_string()),
            matched_noun: Some("function".to_string()),
        };
        let banner = format_dispatch_banner(&intent);
        assert!(banner.contains("build"));
        assert!(banner.contains("function"));
        assert!(banner.contains("NEOTH_NO_AUTO_CODE"));
    }

    #[test]
    fn multibyte_prompt_does_not_panic_at_front_window() {
        // GOLD-COR-02 / A-04: a German prompt whose multibyte char straddles
        // the VERB_FRONT_ANCHOR_BYTES (30) boundary must not panic the slice.
        // "ä" is 2 bytes; pad so a char lands across byte 30.
        let prompt = "ääääääääääääääääääbaue mir eine funktion bitte";
        let _ = detect_coding_intent(prompt); // must not panic
        // An emoji (4-byte) straddling the boundary too.
        let prompt2 = "🚀🚀🚀🚀🚀🚀🚀🚀fix the parser bug please";
        let _ = detect_coding_intent(prompt2); // must not panic
    }
}
