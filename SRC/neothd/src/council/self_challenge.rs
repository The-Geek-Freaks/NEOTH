//! GOLD-ADAPT-LOWKEY-05 + LOWKEY-02 — post-answer answer-quality self-challenge.
//!
//! A post-answer epistemic pass over a final reply, surfacing TWO classes of
//! weakness so the operator doesn't take the answer at face value. Both are
//! pure + LLM-free; the consumer (`cli::chat`) runs [`challenge_answer`] on the
//! final answer and prints a single non-intrusive STDERR note (never stdout, so
//! it can't corrupt the piped reply) when anything fires.
//!
//! 1. **ONTOLOGY adversarial self-challenge (LOWKEY-05)** — speculative claims:
//!    decompose the answer with [`crate::profile::fact_check::assess`] (the same
//!    no-LLM classifier behind `neoth fact-check`) and flag the **suspect**
//!    propositions (absolutisms / unsupported assertions — "guaranteed",
//!    "everyone always", "never fails"). Opinion/plausible/verifiable are NOT
//!    flagged (they'd be noise on a normal answer).
//!
//! 2. **IMBA anti-smoothing omission scan (LOWKEY-02)** — Information Voids:
//!    a success/completion claim ("it works", "fixed", "should work") made with
//!    NO evidence anchor anywhere in the answer (no test / ran / verified /
//!    output / build). "Answers 'it works' without citing a test" — the exact
//!    LOWKEY-8 IMBA failure mode. Heuristic + coarse-by-design (any evidence
//!    anchor in the answer suppresses the flag → under-flags rather than spams).
//!
//! Home is `council/` (per the plan); the consumer is the chat post-reply, so
//! it challenges EVERY final answer (council AND single-provider). The omission
//! scan lives here (not the named `factual_check.rs`, which is ground-truth
//! *contradiction*, a different mechanism) so BOTH scans share ONE surface +
//! one chat hook.

use crate::profile::fact_check::{Confidence, assess};

/// Completion/success claims that, made WITHOUT evidence, are Information Voids.
/// Multi-word phrases (not bare "work"/"fix") to keep false positives low.
const SUCCESS_CLAIMS: &[&str] = &[
    "it works",
    "works now",
    "now works",
    "that works",
    "this works",
    "works fine",
    "it's fixed",
    "is fixed",
    "now fixed",
    "it's done",
    "all done",
    "should work",
    "should be fine",
    "problem solved",
    "issue resolved",
];

/// Evidence anchors — if ANY appears in the answer, the success claim is treated
/// as supported (no void). Coarse on purpose: presence anywhere suppresses the
/// flag, so the scan under-flags (no spam) rather than over-flags.
const EVIDENCE_ANCHORS: &[&str] = &[
    "test", "tested", "ran ", "verified", "confirm", "passing", "passes", "passed", "cargo",
    "compiled", "build", "output", "result", "checked", "0 failed", "exit 0", "green",
];

/// The weaknesses a self-challenge found in an answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelfChallenge {
    /// LOWKEY-05 — text of each `suspect` proposition (absolutism / unsupported
    /// assertion). Empty when the answer made no speculative claim.
    pub speculative: Vec<String>,
    /// LOWKEY-02 — success/completion claims made with no evidence anchor
    /// anywhere in the answer (Information Voids).
    pub information_voids: Vec<String>,
}

impl SelfChallenge {
    /// True when the answer carried at least one speculative claim.
    pub fn has_speculative(&self) -> bool {
        !self.speculative.is_empty()
    }

    /// True when the answer made an unsupported success claim.
    pub fn has_voids(&self) -> bool {
        !self.information_voids.is_empty()
    }

    /// True when either scan flagged something.
    pub fn has_findings(&self) -> bool {
        self.has_speculative() || self.has_voids()
    }

    /// A one-line operator-facing summary, or `None` when nothing to flag.
    /// Goes to STDERR (never stdout) so it can't corrupt the piped answer.
    pub fn note(&self) -> Option<String> {
        if !self.has_findings() {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if let Some(first) = self.speculative.first() {
            parts.push(format!(
                "{} speculative claim(s) (e.g. \"{}\")",
                self.speculative.len(),
                truncate(first)
            ));
        }
        if let Some(first) = self.information_voids.first() {
            parts.push(format!(
                "{} unsupported success-claim(s) without evidence (e.g. \"{}\")",
                self.information_voids.len(),
                truncate(first)
            ));
        }
        Some(format!("⚠ self-challenge: {}", parts.join("; ")))
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

/// Run the post-answer self-challenge over `answer`: the LOWKEY-05 speculative
/// scan + the LOWKEY-02 information-void scan. Pure + deterministic.
pub fn challenge_answer(answer: &str) -> SelfChallenge {
    let report = assess(answer);
    let speculative = report
        .propositions
        .iter()
        .filter(|p| p.confidence == Confidence::Suspect)
        .map(|p| p.text.clone())
        .collect();
    SelfChallenge {
        speculative,
        information_voids: scan_information_voids(answer),
    }
}

/// LOWKEY-02 — collect success/completion claims the answer made with NO
/// evidence anchor anywhere. Returns the matched claim phrases; empty when the
/// answer cited evidence OR made no success claim.
pub fn scan_information_voids(answer: &str) -> Vec<String> {
    let lower = answer.to_lowercase();
    // Any evidence anchor in the whole answer ⇒ the claim is supported.
    if EVIDENCE_ANCHORS
        .iter()
        .any(|a| contains_word(&lower, a.trim()))
    {
        return Vec::new();
    }
    SUCCESS_CLAIMS
        .iter()
        .filter(|m| lower.contains(*m))
        .map(|m| (*m).to_string())
        .collect()
}

/// Whole-word / bounded-phrase containment (caller lowercases). A bare
/// `str::contains` wrongly treated an evidence anchor as present when it was only
/// a SUBSTRING of a larger word — e.g. `"test"` inside `"latest"`/`"contest"`,
/// `"build"` inside `"rebuild"` — which falsely suppressed the information-void
/// flag. The match must be bounded by a non-alphanumeric char (or a string edge)
/// on each alphanumeric side. Multi-word anchors (`"0 failed"`, `"exit 0"`) match
/// when the whole phrase appears at word boundaries. ASCII-only boundary check;
/// a multibyte neighbour reads as a boundary (errs toward suppression, matching
/// the module's deliberate under-flag posture).
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let nlen = needle.len();
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + nlen;
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = start + 1; // needle is ASCII → start+1 is a valid char boundary
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_an_absolutist_unsupported_claim() {
        let c = challenge_answer("Everyone always agrees with this approach.");
        assert!(c.has_speculative(), "absolutism must be flagged: {c:?}");
        assert!(c.note().unwrap().contains("self-challenge"));
    }

    #[test]
    fn does_not_flag_a_grounded_verifiable_answer() {
        let c = challenge_answer("NEOTH shipped in 2026. It may help with recall.");
        assert!(
            !c.has_speculative(),
            "grounded/hedged claims must NOT be flagged: {c:?}"
        );
        assert!(!c.has_voids());
        assert!(c.note().is_none());
    }

    #[test]
    fn empty_answer_has_no_challenge() {
        let c = challenge_answer("");
        assert!(!c.has_findings());
        assert!(c.note().is_none());
    }

    // ── LOWKEY-02 information-void scan ────────────────────────────────

    #[test]
    fn flags_success_claim_without_evidence() {
        // "it works" with no test / ran / verified anywhere → Information Void.
        let voids = scan_information_voids("I changed the config. It works now.");
        assert!(voids.iter().any(|v| v.contains("works")), "got: {voids:?}");
        let c = challenge_answer("I changed the config. It works now.");
        assert!(c.has_voids());
        assert!(c.note().unwrap().contains("unsupported success-claim"));
    }

    #[test]
    fn success_claim_with_a_test_anchor_is_not_a_void() {
        // Same success claim BUT it cites a test → supported, not flagged.
        let voids = scan_information_voids("It works now — the test suite passes, 0 failed.");
        assert!(
            voids.is_empty(),
            "evidence anchor must suppress the void: {voids:?}"
        );
    }

    #[test]
    fn anchor_substring_inside_a_larger_word_does_not_suppress() {
        // "test" is a substring of "latest" / "rebuild" contains "build" — a bare
        // str::contains wrongly treated these as evidence and suppressed the void.
        // Word-boundary matching must still flag the unsupported success claim.
        let voids = scan_information_voids("It works now in the latest rebuild.");
        assert!(
            voids.iter().any(|v| v.contains("works")),
            "substring-only anchor must NOT suppress the void: {voids:?}"
        );
        // A genuine whole-word anchor still suppresses.
        assert!(
            scan_information_voids("It works now; ran the suite.").is_empty(),
            "'ran' as a whole word must still count as evidence"
        );
    }

    #[test]
    fn no_success_claim_no_void() {
        let voids = scan_information_voids("Here is the analysis of the tradeoffs.");
        assert!(voids.is_empty());
    }

    #[test]
    fn note_combines_both_scans() {
        let c = SelfChallenge {
            speculative: vec!["this is guaranteed to work".into()],
            information_voids: vec!["it works".into()],
        };
        let note = c.note().unwrap();
        assert!(note.contains("1 speculative claim"), "got: {note}");
        assert!(note.contains("1 unsupported success-claim"), "got: {note}");
    }
}
