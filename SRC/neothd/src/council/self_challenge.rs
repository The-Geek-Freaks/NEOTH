//! GOLD-ADAPT-LOWKEY-05 — ONTOLOGY adversarial self-challenge.
//!
//! A post-answer epistemic pass: after a reply is produced, decompose it into
//! atomic claims and flag the SPECULATIVE / unsupported ones, so the operator
//! sees which parts of an answer are assertion-without-evidence rather than
//! taking the whole reply at face value. Adapted from LOWKEY-9.3 §Phase3.
//!
//! ## Reuses the shipped fact-check engine
//!
//! The claim classifier is [`crate::profile::fact_check::assess`] (the same
//! deterministic, no-LLM proposition classifier behind `neoth fact-check`).
//! `assess` already labels each proposition `verifiable / plausible / opinion /
//! suspect`. This pass extracts the **suspect** propositions — absolutisms and
//! unsupported assertions ("guaranteed", "everyone always", "never fails") —
//! which are the genuinely speculative claims worth challenging. Opinion /
//! plausible / verifiable propositions are NOT flagged (they would be noise on
//! every normal answer).
//!
//! Pure + LLM-free; the consumer (`cli::chat`) runs it on the final answer and
//! surfaces a non-intrusive STDERR note when speculative claims are present.

use crate::profile::fact_check::{assess, Confidence};

/// The speculative claims an answer made without support.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelfChallenge {
    /// The text of each `suspect` proposition (absolutism / unsupported
    /// assertion). Empty when the answer made no speculative claim.
    pub speculative: Vec<String>,
}

impl SelfChallenge {
    /// True when the answer carried at least one speculative claim worth
    /// surfacing to the operator.
    pub fn has_speculative(&self) -> bool {
        !self.speculative.is_empty()
    }

    /// A one-line operator-facing summary, or `None` when nothing to flag.
    /// Goes to STDERR (never stdout) so it can't corrupt the piped answer.
    pub fn note(&self) -> Option<String> {
        let n = self.speculative.len();
        if n == 0 {
            return None;
        }
        // Show the count + the first claim (truncated) as the concrete example.
        let first = self.speculative[0].chars().take(120).collect::<String>();
        Some(format!(
            "⚠ self-challenge: {n} speculative/unsupported claim(s) in this answer — e.g. \"{first}\""
        ))
    }
}

/// Run the adversarial self-challenge over `answer`: classify its claims and
/// collect the speculative (suspect) ones. Pure + deterministic.
pub fn challenge_answer(answer: &str) -> SelfChallenge {
    let report = assess(answer);
    let speculative = report
        .propositions
        .iter()
        .filter(|p| p.confidence == Confidence::Suspect)
        .map(|p| p.text.clone())
        .collect();
    SelfChallenge { speculative }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_an_absolutist_unsupported_claim() {
        // "Everyone always" is a suspect absolutism → fact_check marks it suspect.
        let c = challenge_answer("Everyone always agrees with this approach.");
        assert!(c.has_speculative(), "absolutism must be flagged: {c:?}");
        assert!(c.note().is_some());
        assert!(c.note().unwrap().contains("self-challenge"));
    }

    #[test]
    fn does_not_flag_a_grounded_verifiable_answer() {
        // A concrete, dated, hedged statement carries no suspect propositions.
        let c = challenge_answer("NEOTH shipped in 2026. It may help with recall.");
        assert!(
            !c.has_speculative(),
            "grounded/hedged claims must NOT be flagged: {c:?}"
        );
        assert!(c.note().is_none());
    }

    #[test]
    fn empty_answer_has_no_challenge() {
        let c = challenge_answer("");
        assert!(!c.has_speculative());
        assert!(c.note().is_none());
    }

    #[test]
    fn note_carries_count_and_first_example() {
        let c = SelfChallenge {
            speculative: vec!["this is guaranteed to work".into(), "it never fails".into()],
        };
        let note = c.note().unwrap();
        assert!(note.contains("2 speculative"), "got: {note}");
        assert!(note.contains("guaranteed to work"), "got: {note}");
    }
}
