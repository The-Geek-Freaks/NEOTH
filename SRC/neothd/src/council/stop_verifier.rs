//! GOLD-ADAPT-KB-02 — independent judge for autonomous-loop stop conditions.
//!
//! **Problem (MiMo-Code origin):** When an autonomous agent loop self-reports
//! completion ("I'm done, all tasks are resolved") and the loop immediately
//! exits, there is no independent check between "agent says done" and loop
//! exit. A premature or hallucinated completion claim causes the loop to
//! terminate early, leaving work undone — the exact gap MiMo-Code's
//! judge-gated stop addresses.
//!
//! **Solution:** Route every proposed agent-stop through a [`StopConditionVerifier`]
//! when autonomy is `Elevated` or `Full`. The verifier is an INDEPENDENT,
//! LLM-free judge in the `council/` clean lane. It inspects the agent's
//! claimed completion evidence against the loop's declared exit criteria
//! and produces a [`StopJudgement`]: either `Approved` (stop is genuine,
//! loop may exit) or `Rejected` (stop is premature, loop must continue).
//!
//! **Design choices:**
//! - **Pure + deterministic.** No I/O, no LLM, no async. The judge is a
//!   structural signal over the *shape* of the evidence: does every declared
//!   `done_criterion` have at least one matching evidence token? A fuzzy
//!   semantic match would need an LLM; a structural match is fast, free,
//!   and reproducible in WAL audit.
//! - **Gate at `Elevated / Full` only.** Below `Elevated` the loop is not
//!   supposed to run unattended; the operator is supervising, so the extra
//!   independent pass adds friction without value. At `Standard` and below
//!   the verifier returns `Approved` unconditionally (bypass).
//! - **Fail-open on empty criteria.** When no `done_criteria` were declared
//!   the agent's completion claim is unchecked — the caller opted out of the
//!   structured exit gate. The result is `Approved` with a diagnostic note
//!   so the operator's WAL audit can surface "unchecked stop".
//! - **Reject partial matches.** Every criterion must be satisfied; a
//!   partial match (some covered, some not) is a `Rejected` stop. The
//!   unsatisfied criteria are surfaced so the loop can reframe the next
//!   iteration.
//!
//! ## Integration point
//!
//! The caller (the autonomous-loop dispatcher, not yet wired — tracked
//! separately) calls [`StopConditionVerifier::judge`] when the agent emits
//! `Action::AgentStop` and the current autonomy is `Elevated` or `Full`:
//!
//! ```rust,ignore
//! use crate::council::stop_verifier::{StopConditionVerifier, StopProposal};
//! use crate::permissions::AutonomyLevel;
//!
//! let verifier = StopConditionVerifier::new(done_criteria);
//! let judgement = verifier.judge(&proposal, autonomy_level);
//! if !judgement.is_approved() {
//!     // loop continues — feed judgement.rejection_reason() back to agent
//! }
//! ```

use crate::permissions::AutonomyLevel;

// ─── Public surface ─────────────────────────────────────────────────────────

/// A proposed agent-stop: the agent's claim that all work is done.
///
/// `claimed_evidence` is the list of evidence tokens the agent supplied in
/// its completion claim — e.g. `["tests pass", "build green", "deployed"]`.
/// These are compared structurally against the loop's declared
/// `done_criteria` by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopProposal {
    /// Human-readable completion message from the agent (e.g.
    /// "All 5 tasks are resolved and tests pass."). Used for WAL audit +
    /// rejection-reason assembly; not parsed by the judge.
    pub agent_message: String,
    /// Evidence tokens the agent cited. Each is a short lowercase phrase or
    /// keyword (normalised by the caller before passing; the judge compares
    /// case-insensitively so plain-English is fine).
    pub claimed_evidence: Vec<String>,
}

/// The verifier's verdict on a proposed stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopJudgement {
    /// The stop is genuine — every declared criterion is satisfied.
    /// `note` carries an optional diagnostic (e.g. "no criteria declared,
    /// stop unchecked") so the WAL audit can distinguish a verified stop
    /// from an unchecked one.
    Approved { note: Option<String> },
    /// The stop is premature — at least one declared criterion is NOT
    /// satisfied by the claimed evidence. `unsatisfied` names every
    /// unmet criterion so the loop can reframe.
    Rejected { unsatisfied: Vec<String> },
}

impl StopJudgement {
    /// `true` iff the loop may exit.
    pub fn is_approved(&self) -> bool {
        matches!(self, StopJudgement::Approved { .. })
    }

    /// Operator-facing reason string. For `Approved` with a note, returns
    /// the note; for `Rejected`, lists the unsatisfied criteria.
    pub fn reason(&self) -> String {
        match self {
            StopJudgement::Approved { note: Some(n) } => n.clone(),
            StopJudgement::Approved { note: None } => "all criteria satisfied".to_string(),
            StopJudgement::Rejected { unsatisfied } => format!(
                "premature stop: {} criterion/criteria unmet: [{}]",
                unsatisfied.len(),
                unsatisfied.join(", ")
            ),
        }
    }
}

/// Independent judge for autonomous-loop stop conditions.
///
/// Constructed once per loop run with the declared `done_criteria` — the
/// structural exit conditions the loop operator registered up-front (e.g.
/// `["all tests pass", "no open tasks", "build green"]`). The same
/// verifier instance can judge multiple stop proposals across retries.
pub struct StopConditionVerifier {
    /// Normalised (trimmed, lowercased) done criteria. Each must be matched
    /// by at least one evidence token in a `StopProposal` for the stop to
    /// be approved.
    criteria: Vec<String>,
}

impl StopConditionVerifier {
    /// Create a verifier for the given done criteria. Each criterion is
    /// normalised (trimmed + lowercased) so matching is case-insensitive.
    /// An empty `criteria` list means "no structured gate" — the verifier
    /// will approve any stop with an `Approved { note: Some(...) }`.
    pub fn new(criteria: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            criteria: criteria
                .into_iter()
                .map(|c| c.into().trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty())
                .collect(),
        }
    }

    /// Judge whether the proposed stop is genuine.
    ///
    /// Gate: at `Standard` or below (i.e. below `Elevated`) the operator is
    /// supervising the loop; the independent pass adds friction without value
    /// and is bypassed — returns `Approved { note: None }` immediately.
    ///
    /// At `Elevated` or `Full`, every declared criterion is tested against
    /// the proposal's `claimed_evidence` using a case-insensitive substring
    /// match: a criterion is *satisfied* iff at least one evidence token
    /// contains the criterion string (or vice versa — token ⊆ criterion is
    /// also accepted so short keywords like "green" match "build green"). If
    /// every criterion is satisfied, the stop is approved. If any are unmet,
    /// the stop is rejected and the unsatisfied list is returned.
    pub fn judge(&self, proposal: &StopProposal, autonomy: AutonomyLevel) -> StopJudgement {
        // Below the elevated threshold — bypass the independent check.
        if !is_elevated_or_full(autonomy) {
            return StopJudgement::Approved { note: None };
        }

        // No declared criteria → unchecked stop; approve with a note.
        if self.criteria.is_empty() {
            return StopJudgement::Approved {
                note: Some(
                    "no done_criteria declared; stop accepted unchecked — \
                     add criteria for a verified gate"
                        .to_string(),
                ),
            };
        }

        // Normalise the claimed evidence once.
        let evidence: Vec<String> = proposal
            .claimed_evidence
            .iter()
            .map(|e| e.trim().to_ascii_lowercase())
            .collect();

        let unsatisfied: Vec<String> = self
            .criteria
            .iter()
            .filter(|crit| !criterion_is_met(crit, &evidence))
            .cloned()
            .collect();

        if unsatisfied.is_empty() {
            StopJudgement::Approved { note: None }
        } else {
            StopJudgement::Rejected { unsatisfied }
        }
    }

    /// The normalised criteria this verifier checks. Exposed for audit
    /// logging and tests; callers should not mutate the list.
    pub fn criteria(&self) -> &[String] {
        &self.criteria
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// True iff `autonomy` is `Elevated` or `Full`.
fn is_elevated_or_full(autonomy: AutonomyLevel) -> bool {
    matches!(autonomy, AutonomyLevel::Elevated | AutonomyLevel::Full)
}

/// True iff at least one evidence token *covers* the criterion.
///
/// "Coverage" is bidirectional containment (case-insensitive):
/// - `evidence_token.contains(criterion)` — evidence is more specific than
///   the criterion (e.g. criterion="tests pass", token="unit tests pass").
/// - `criterion.contains(evidence_token)` — criterion is more specific than
///   the token (e.g. criterion="all unit tests pass", token="tests pass").
///
/// This avoids requiring exact-string equality while staying LLM-free and
/// deterministic. A criterion is satisfied when ANY evidence token matches.
fn criterion_is_met(criterion: &str, evidence: &[String]) -> bool {
    evidence
        .iter()
        .any(|tok| tok.contains(criterion) || criterion.contains(tok.as_str()))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(evidence: &[&str]) -> StopProposal {
        StopProposal {
            agent_message: "All tasks complete.".to_string(),
            claimed_evidence: evidence.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    // ── Gate: autonomy below Elevated bypasses the check ────────────────

    #[test]
    fn stop_always_approved_at_standard_regardless_of_evidence() {
        let v = StopConditionVerifier::new(["all tests pass", "no open tasks"]);
        let p = proposal(&[]); // no evidence at all
        let j = v.judge(&p, AutonomyLevel::Standard);
        assert!(j.is_approved(), "Standard must bypass the independent check");
        // note is None on bypass path
        assert_eq!(j, StopJudgement::Approved { note: None });
    }

    #[test]
    fn stop_always_approved_at_strict_regardless_of_evidence() {
        let v = StopConditionVerifier::new(["build green"]);
        let p = proposal(&[]);
        let j = v.judge(&p, AutonomyLevel::Strict);
        assert!(j.is_approved());
    }

    // ── Gate: Elevated/Full — premature stop is rejected ────────────────

    #[test]
    fn premature_stop_is_rejected_at_elevated() {
        let v = StopConditionVerifier::new(["all tests pass", "no open tasks", "build green"]);
        // Agent only claims "tests pass" — "no open tasks" and "build green" are unmet.
        let p = proposal(&["tests pass"]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(!j.is_approved(), "premature stop must be rejected");
        match &j {
            StopJudgement::Rejected { unsatisfied } => {
                // both unmet criteria must appear
                assert!(
                    unsatisfied.iter().any(|u| u.contains("no open tasks")),
                    "expected 'no open tasks' in unsatisfied: {unsatisfied:?}"
                );
                assert!(
                    unsatisfied.iter().any(|u| u.contains("build green")),
                    "expected 'build green' in unsatisfied: {unsatisfied:?}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn premature_stop_is_rejected_at_full() {
        let v = StopConditionVerifier::new(["deploy complete"]);
        let p = proposal(&["tests pass", "build green"]); // "deploy complete" missing
        let j = v.judge(&p, AutonomyLevel::Full);
        assert!(!j.is_approved());
        match &j {
            StopJudgement::Rejected { unsatisfied } => {
                assert_eq!(unsatisfied, &["deploy complete"]);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // ── Gate: Elevated/Full — genuine completion passes ──────────────────

    #[test]
    fn genuine_stop_is_approved_at_elevated() {
        let v = StopConditionVerifier::new(["tests pass", "build green"]);
        let p = proposal(&["unit tests pass", "cargo build green"]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(j.is_approved(), "genuine stop must be approved: {j:?}");
        assert_eq!(j, StopJudgement::Approved { note: None });
    }

    #[test]
    fn genuine_stop_is_approved_at_full() {
        let v = StopConditionVerifier::new(["all tests pass", "no open tasks"]);
        let p = proposal(&["all tests pass", "no open tasks remaining"]);
        let j = v.judge(&p, AutonomyLevel::Full);
        assert!(j.is_approved());
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn no_criteria_gives_unchecked_approved_at_elevated() {
        let v = StopConditionVerifier::new(Vec::<String>::new());
        let p = proposal(&[]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(j.is_approved());
        match &j {
            StopJudgement::Approved { note: Some(n) } => {
                assert!(n.contains("unchecked"), "note must say unchecked: {n}");
            }
            other => panic!("expected Approved with unchecked note, got {other:?}"),
        }
    }

    #[test]
    fn single_criterion_all_evidence_unrelated_is_rejected() {
        let v = StopConditionVerifier::new(["deploy complete"]);
        let p = proposal(&["refactored the parser", "added docs"]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(!j.is_approved());
    }

    #[test]
    fn criteria_are_case_insensitively_normalised() {
        // Criterion registered with mixed case; evidence in different case.
        let v = StopConditionVerifier::new(["Build Green"]);
        let p = proposal(&["CARGO BUILD GREEN"]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(j.is_approved(), "case normalisation must work: {j:?}");
    }

    #[test]
    fn empty_criteria_strings_are_filtered_out() {
        // Whitespace-only entries must be ignored (not treated as trivially
        // unsatisfied criteria).
        let v = StopConditionVerifier::new(["", "   ", "tests pass"]);
        assert_eq!(v.criteria().len(), 1, "empty criteria must be filtered");
        let p = proposal(&["tests pass"]);
        let j = v.judge(&p, AutonomyLevel::Elevated);
        assert!(j.is_approved());
    }

    #[test]
    fn reason_on_approved_without_note_is_generic() {
        let j = StopJudgement::Approved { note: None };
        assert_eq!(j.reason(), "all criteria satisfied");
    }

    #[test]
    fn reason_on_approved_with_note_returns_note() {
        let j = StopJudgement::Approved {
            note: Some("no criteria; unchecked".to_string()),
        };
        assert!(j.reason().contains("unchecked"));
    }

    #[test]
    fn reason_on_rejected_lists_unsatisfied_criteria() {
        let j = StopJudgement::Rejected {
            unsatisfied: vec!["build green".to_string(), "deploy done".to_string()],
        };
        let r = j.reason();
        assert!(r.contains("build green"), "got: {r}");
        assert!(r.contains("deploy done"), "got: {r}");
        assert!(r.contains("premature stop"), "got: {r}");
    }

    #[test]
    fn partial_match_only_satisfied_criteria_not_all() {
        // 3 criteria, only 1 covered → rejected, 2 unsatisfied reported.
        let v = StopConditionVerifier::new([
            "tests pass",
            "lint clean",
            "integration verified",
        ]);
        let p = proposal(&["all tests pass"]);
        let j = v.judge(&p, AutonomyLevel::Full);
        assert!(!j.is_approved());
        match &j {
            StopJudgement::Rejected { unsatisfied } => {
                assert_eq!(unsatisfied.len(), 2, "exactly 2 unmet: {unsatisfied:?}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
