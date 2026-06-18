//! Round-3 v0.4 ADV-12 — Council factual-contradiction check using
//! `[GROUND_TRUTH]` tags + ground-truth-based scoring (NOT hemisphere
//! agreement).
//!
//! ## The bug ADV-12 closes
//!
//! Pre-ADV-12 the council adversarial check `test_all_three_agree_
//! and_wrong` was structurally unimplementable. The dissent + diversity
//! scoring (`council::dissent`, `council::diversity`) measure
//! **agreement among the three hemispheres** — when all three agree
//! the dissent score is 0 (high confidence). But three hemispheres
//! converging on a wrong fact (operator's profile claims their
//! birthday is March; all three hemispheres echo "March" because the
//! profile context biased them) ALSO produces a 0 dissent score. The
//! council's quality metric was indistinguishable from genuine
//! factual correctness.
//!
//! The structural fix: inject a typed `[GROUND_TRUTH]…[/GROUND_TRUTH]`
//! block into the council prompt with assertions known to be true
//! (sourced from `idx_groundtruth`); after the hemispheres respond,
//! check each response against the ground-truth assertions
//! independently of inter-hemisphere agreement. A response that
//! contradicts an assertion flags as `Contradicts`, regardless of
//! whether the OTHER hemispheres agree with it.
//!
//! ## Scope of this primitive
//!
//! This module ships:
//!
//! - `GROUND_TRUTH_TAG_OPEN` + `GROUND_TRUTH_TAG_CLOSE` canonical
//!   wrapper strings.
//! - `embed_ground_truth_tag(prompt, assertions)` — pure-fn injector
//!   that wraps the assertions block + appends to the supplied
//!   prompt.
//! - `FactualAssertion { subject, expected_keyword }` — minimal typed
//!   shape for an assertion. Caller (council-orchestrator
//!   integration) pulls these from `idx_groundtruth` rows.
//! - `FactualCheckOutcome { agrees, missing_keywords,
//!   contradicting_phrases }`.
//! - `factual_contradiction_check(response, assertions, negation_markers)`
//!   — pure-fn coarse-NLP check: for each assertion, if the response
//!   mentions the subject, verify the expected_keyword appears AND
//!   no negation-marker precedes it within a small window.
//!
//! The ARCH-02 `test_all_three_agree_and_wrong` adversarial test
//! (different PROGRESS item, currently gated on ARCH-07 +
//! ARCH-04 + this primitive) will use these helpers to build the
//! fixture-based test once shipped.
//!
//! ## Why coarse heuristics not full NLP
//!
//! Full contradiction detection is an open NLP problem (NLI / RTE).
//! Ground-truth-tag injection is a **structural** fix — it gives the
//! council pipeline a typed surface to compare against, regardless
//! of how sophisticated the comparison is. The coarse keyword + no-
//! negation-in-window check catches the high-impact failure mode
//! (response mentions subject AND nearby negation/contradiction
//! marker) without dragging in a heavyweight NLP dependency. The
//! L follow-on can swap the comparator for a Qwen3-Q8 entailment
//! check once Day-14b lands (matches the SPEC-04 dependency edge).

use serde::{Deserialize, Serialize};

/// Opening tag wrapped around the ground-truth assertions block in
/// the council prompt. Tags are paired so hemisphere responses can
/// be inspected for "did the model see + understand the tag block".
pub const GROUND_TRUTH_TAG_OPEN: &str = "[GROUND_TRUTH]";

/// Closing tag. Operator-readable + LLM-readable (no special tokens)
/// so dumping the prompt to a log preserves the structure.
pub const GROUND_TRUTH_TAG_CLOSE: &str = "[/GROUND_TRUTH]";

/// Default negation markers — words within
/// [`DEFAULT_NEGATION_WINDOW_CHARS`] of a subject-mention that
/// indicate a contradiction. Bilingual (German + English) per the
/// operator's profile mixing both freely.
pub const DEFAULT_NEGATION_MARKERS: &[&str] = &[
    // English
    "not",
    "no",
    "never",
    "isn't",
    "aren't",
    "wasn't",
    "weren't",
    "doesn't",
    "don't",
    "didn't",
    "incorrect",
    "wrong",
    "false",
    // German
    "nicht",
    "kein",
    "keine",
    "keinen",
    "nie",
    "niemals",
    "falsch",
    "stimmt nicht",
    "unrichtig",
];

/// Character window around a subject mention searched for negation
/// markers. 80 chars ≈ one sentence at typical English/German prose
/// density.
pub const DEFAULT_NEGATION_WINDOW_CHARS: usize = 80;

/// One ground-truth assertion. `subject` is a noun-phrase the
/// response is likely to reference (e.g. `"Sam's birthday"`);
/// `expected_keyword` is the canonical fact (`"March"`). Both are
/// case-insensitively matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactualAssertion {
    pub subject: String,
    pub expected_keyword: String,
}

/// Outcome of a [`factual_contradiction_check`] against one hemisphere
/// response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactualCheckOutcome {
    /// `true` iff every assertion's `expected_keyword` was found
    /// near the corresponding subject AND no negation-marker was
    /// found in the window.
    pub agrees: bool,
    /// Subjects whose expected_keyword was NOT found in the response
    /// at all (response didn't address them or used a different word).
    pub missing_keywords: Vec<String>,
    /// Concrete (subject, snippet) pairs where a negation marker
    /// fired inside the window around the subject mention.
    pub contradicting_phrases: Vec<(String, String)>,
}

impl FactualCheckOutcome {
    /// Convenience: did this response contradict ANY assertion?
    /// Distinct from `!agrees` because `!agrees` also fires when a
    /// keyword was simply missing (no contradiction, just absence).
    pub fn contradicts(&self) -> bool {
        !self.contradicting_phrases.is_empty()
    }
}

/// Wrap `assertions` in `[GROUND_TRUTH]…[/GROUND_TRUTH]` and append
/// to `prompt`. Empty assertions list returns the prompt unchanged.
/// The block is appended (not prepended) so the operator's intent
/// stays at the top — the ground-truth block reads as a sidebar.
pub fn embed_ground_truth_tag(prompt: &str, assertions: &[FactualAssertion]) -> String {
    if assertions.is_empty() {
        return prompt.to_string();
    }
    let body: Vec<String> = assertions
        .iter()
        .map(|a| format!("- {}: {}", a.subject, a.expected_keyword))
        .collect();
    format!(
        "{prompt}\n\n{open}\n{body}\n{close}",
        open = GROUND_TRUTH_TAG_OPEN,
        body = body.join("\n"),
        close = GROUND_TRUTH_TAG_CLOSE,
    )
}

/// Extract the body bytes between the opening + closing tags, if
/// present. Used by the council orchestrator to verify hemispheres
/// received the tag block (a response that strips it suggests
/// prompt-leak through transport sanitisation).
pub fn extract_ground_truth_block(text: &str) -> Option<&str> {
    let start = text.find(GROUND_TRUTH_TAG_OPEN)?;
    let after_open = start + GROUND_TRUTH_TAG_OPEN.len();
    let close_rel = text[after_open..].find(GROUND_TRUTH_TAG_CLOSE)?;
    Some(text[after_open..after_open + close_rel].trim())
}

/// Pure-fn coarse contradiction check.
///
/// For each assertion in `assertions`:
///   1. Find the FIRST case-insensitive occurrence of `subject` in
///      `response`. If absent, append the subject to `missing_keywords`
///      + continue.
///   2. Inside a ±`window_chars/2` window around the subject mention,
///      search for `expected_keyword` (case-insensitive).
///   3. If `expected_keyword` is absent → also push to
///      `missing_keywords` (response talks about the subject but
///      not the fact).
///   4. Search the same window for any [`negation_markers`] word
///      adjacent (within the window) to the subject mention. If
///      found, push `(subject, window-snippet)` to
///      `contradicting_phrases`.
///
/// `agrees = missing_keywords.is_empty() AND contradicting_phrases.is_empty()`.
pub fn factual_contradiction_check(
    response: &str,
    assertions: &[FactualAssertion],
    negation_markers: &[&str],
    window_chars: usize,
) -> FactualCheckOutcome {
    let lower = response.to_lowercase();
    let mut missing_keywords = Vec::new();
    let mut contradicting_phrases = Vec::new();

    for assertion in assertions {
        let subject_lower = assertion.subject.to_lowercase();
        let keyword_lower = assertion.expected_keyword.to_lowercase();

        let Some(subject_pos) = lower.find(&subject_lower) else {
            missing_keywords.push(assertion.subject.clone());
            continue;
        };

        // ±window_chars/2 around the subject mention (char-boundary
        // safe via byte arithmetic on the lowercased clone — the
        // ASCII-tolerant compare doesn't need char-precise slicing).
        let half = window_chars / 2;
        let win_start = subject_pos.saturating_sub(half);
        let win_end = (subject_pos + subject_lower.len() + half).min(lower.len());
        let window = &lower[win_start..win_end];

        let keyword_in_window = window.contains(&keyword_lower);
        if !keyword_in_window {
            missing_keywords.push(assertion.subject.clone());
            // No keyword present → nothing to negate. Skip the
            // negation check so a negation belonging to a *different*
            // clause can't flag a subject whose keyword is simply
            // absent.
            continue;
        }

        // A negation contradicts the assertion only when it sits in the
        // connective span BETWEEN the subject and its keyword ("X is
        // not Y") — per the module contract ("no negation-marker
        // precedes the keyword within a small window"). Searching the
        // whole ±window let a negation in a neighbouring clause about a
        // *different* subject ("… city is not Berlin") leak into this
        // subject's verdict, breaking the per-subject independence the
        // council depends on. Bound the search to the subject↔keyword
        // span (covers both textual orders). All four offsets land on
        // substring-match boundaries, so the slice is UTF-8 safe.
        let kw_abs = win_start + window.find(&keyword_lower).expect("contains ⇒ find");
        let subj_end = subject_pos + subject_lower.len();
        let span_start = subj_end.min(kw_abs);
        let span_end = (subject_pos.max(kw_abs + keyword_lower.len())).min(lower.len());
        let connective = &lower[span_start..span_end.max(span_start)];

        for marker in negation_markers {
            let marker_lower = marker.to_lowercase();
            if connective.contains(&marker_lower) {
                // Snippet from the ORIGINAL response (not lowercased)
                // so the audit log preserves casing.
                let snippet = safe_slice(
                    response,
                    span_start.min(response.len()),
                    span_end.min(response.len()),
                );
                contradicting_phrases.push((assertion.subject.clone(), snippet));
                break; // one negation marker per assertion is enough
            }
        }
    }

    FactualCheckOutcome {
        agrees: missing_keywords.is_empty() && contradicting_phrases.is_empty(),
        missing_keywords,
        contradicting_phrases,
    }
}

fn safe_slice(s: &str, start: usize, end: usize) -> String {
    if start >= end || s.is_empty() {
        return String::new();
    }
    let mut a = start.min(s.len());
    while a > 0 && !s.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = end.min(s.len());
    while b > a && !s.is_char_boundary(b) {
        b -= 1;
    }
    s[a..b].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion(subject: &str, keyword: &str) -> FactualAssertion {
        FactualAssertion {
            subject: subject.to_string(),
            expected_keyword: keyword.to_string(),
        }
    }

    // ── embed_ground_truth_tag ────────────────────────────────────

    #[test]
    fn embed_empty_assertions_returns_unchanged() {
        let prompt = "What is Sam's birthday?";
        assert_eq!(embed_ground_truth_tag(prompt, &[]), prompt);
    }

    #[test]
    fn embed_appends_block_with_open_close_tags() {
        let prompt = "What is Sam's birthday?";
        let a = vec![assertion("Sam's birthday", "March")];
        let out = embed_ground_truth_tag(prompt, &a);
        assert!(out.contains(GROUND_TRUTH_TAG_OPEN));
        assert!(out.contains(GROUND_TRUTH_TAG_CLOSE));
        assert!(out.starts_with(prompt));
        assert!(out.contains("Sam's birthday: March"));
    }

    #[test]
    fn embed_multi_assertions_each_on_own_line() {
        let a = vec![
            assertion("Sam's birthday", "March"),
            assertion("Sam's city", "Berlin"),
        ];
        let out = embed_ground_truth_tag("Q?", &a);
        let inside = extract_ground_truth_block(&out).unwrap();
        assert!(inside.contains("Sam's birthday: March"));
        assert!(inside.contains("Sam's city: Berlin"));
    }

    // ── extract_ground_truth_block ────────────────────────────────

    #[test]
    fn extract_returns_trimmed_inner_body() {
        let text = format!(
            "preamble {}  body content  {} trailer",
            GROUND_TRUTH_TAG_OPEN, GROUND_TRUTH_TAG_CLOSE,
        );
        let inner = extract_ground_truth_block(&text).unwrap();
        assert_eq!(inner, "body content");
    }

    #[test]
    fn extract_none_when_missing() {
        assert!(extract_ground_truth_block("no tags here").is_none());
    }

    #[test]
    fn extract_none_when_only_open_tag() {
        let text = format!("preamble {} body without close", GROUND_TRUTH_TAG_OPEN);
        assert!(extract_ground_truth_block(&text).is_none());
    }

    // ── factual_contradiction_check ───────────────────────────────

    #[test]
    fn check_agrees_when_subject_keyword_present_no_negation() {
        let a = vec![assertion("Sam's birthday", "March")];
        let resp = "Sam's birthday is in March, I remember well.";
        let out = factual_contradiction_check(
            resp,
            &a,
            DEFAULT_NEGATION_MARKERS,
            DEFAULT_NEGATION_WINDOW_CHARS,
        );
        assert!(out.agrees);
        assert!(out.missing_keywords.is_empty());
        assert!(out.contradicting_phrases.is_empty());
        assert!(!out.contradicts());
    }

    #[test]
    fn check_flags_missing_subject() {
        let a = vec![assertion("Sam's birthday", "March")];
        let resp = "I have no information about that.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(!out.agrees);
        assert_eq!(out.missing_keywords, vec!["Sam's birthday"]);
        assert!(out.contradicting_phrases.is_empty());
    }

    #[test]
    fn check_flags_missing_keyword_when_subject_present() {
        let a = vec![assertion("Sam's birthday", "March")];
        let resp = "Sam's birthday is a wonderful day filled with cake.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(!out.agrees);
        assert!(out.missing_keywords.contains(&"Sam's birthday".to_string()));
    }

    #[test]
    fn check_flags_negation_near_subject() {
        let a = vec![assertion("Sam's birthday", "March")];
        let resp = "Sam's birthday is not in March, you are mistaken.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        // Subject present, keyword present (March), but negation
        // ("not") is in the window → contradiction.
        assert!(out.contradicts());
        let (subj, snippet) = &out.contradicting_phrases[0];
        assert_eq!(subj, "Sam's birthday");
        assert!(snippet.to_lowercase().contains("not"));
    }

    #[test]
    fn check_german_negation_marker_caught() {
        let a = vec![assertion("Sam's Geburtstag", "März")];
        let resp = "Sam's Geburtstag ist nicht im März, das ist falsch.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(out.contradicts());
    }

    #[test]
    fn check_case_insensitive_subject_and_keyword() {
        let a = vec![assertion("Sam's Birthday", "MARCH")];
        let resp = "sam's birthday is in march.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(out.agrees, "case-insensitive matching MUST pass");
    }

    #[test]
    fn check_negation_far_from_subject_doesnt_trip() {
        // "not" appears but FAR from the subject mention — outside
        // the window — so it shouldn't flag.
        let a = vec![assertion("birthday", "March")];
        let mut resp = String::from("birthday is in March. ");
        resp.push_str(&"x ".repeat(200));
        resp.push_str(" and that is not what you asked.");
        let out = factual_contradiction_check(&resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(
            out.contradicting_phrases.is_empty(),
            "negation outside window must NOT flag"
        );
        assert!(out.agrees);
    }

    #[test]
    fn check_multi_assertion_independent_per_subject() {
        let a = vec![assertion("birthday", "March"), assertion("city", "Berlin")];
        // First assertion: correct. Second: contradicted.
        let resp = "birthday is in March. city is not Berlin.";
        let out = factual_contradiction_check(resp, &a, DEFAULT_NEGATION_MARKERS, 80);
        assert_eq!(out.contradicting_phrases.len(), 1);
        assert_eq!(out.contradicting_phrases[0].0, "city");
    }

    #[test]
    fn check_no_assertions_trivially_agrees() {
        let out =
            factual_contradiction_check("any response at all", &[], DEFAULT_NEGATION_MARKERS, 80);
        assert!(out.agrees);
    }

    #[test]
    fn check_empty_response_flags_all_missing() {
        let a = vec![assertion("subj1", "kw1"), assertion("subj2", "kw2")];
        let out = factual_contradiction_check("", &a, DEFAULT_NEGATION_MARKERS, 80);
        assert!(!out.agrees);
        assert_eq!(out.missing_keywords.len(), 2);
    }

    // ── Constants pin ─────────────────────────────────────────────

    #[test]
    fn tag_constants_canonical() {
        assert_eq!(GROUND_TRUTH_TAG_OPEN, "[GROUND_TRUTH]");
        assert_eq!(GROUND_TRUTH_TAG_CLOSE, "[/GROUND_TRUTH]");
        assert_eq!(DEFAULT_NEGATION_WINDOW_CHARS, 80);
    }

    #[test]
    fn negation_markers_bilingual_coverage() {
        // Drift guard: ensure both EN + DE high-frequency markers
        // are in the list so a future trim doesn't accidentally drop
        // one language's coverage.
        let all: Vec<&str> = DEFAULT_NEGATION_MARKERS.to_vec();
        assert!(all.contains(&"not"), "EN: 'not' missing");
        assert!(all.contains(&"never"), "EN: 'never' missing");
        assert!(all.contains(&"nicht"), "DE: 'nicht' missing");
        assert!(all.contains(&"falsch"), "DE: 'falsch' missing");
    }
}
