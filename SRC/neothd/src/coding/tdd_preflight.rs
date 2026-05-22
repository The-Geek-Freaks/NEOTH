//! QM-7 — TDD pre-flight checklist for `neoth code`.
//!
//! Per `PLAN/QUELLEN_ADOPT_mattpocock_2026-05-21.md` §2 `tdd` ADOPT-
//! AS-CORE: the vertical-slice tracer-bullet loop + "never refactor
//! while RED" + behavior-through-public-interface doctrine are
//! unconditional quality gates that belong in `neoth code`, not as
//! an opt-in skill. This module ships the deterministic pre-flight
//! checker that classifies the operator's prompt and surfaces the
//! checklist before decomposition starts.
//!
//! ## What this module does
//!
//! `evaluate(prompt) -> TddPreflight` — pure function, no I/O.
//! Classifies the prompt into a [`WorkKind`] (Feature / BugFix /
//! Refactor / Question / TrivialChange) and produces a
//! [`TddPreflight`] report carrying the recommended checklist + a
//! `skip_tdd` flag for prompts where TDD doesn't apply (questions,
//! pure renames, throwaway exploration).
//!
//! ## Where this is wired
//!
//! `cli::code::run_code` invokes `evaluate` BEFORE decomposition and
//! prints the report so the operator sees the discipline expectation
//! up front. The check is non-blocking — operator can ignore it and
//! still proceed; the goal is education, not gatekeeping. Skill-
//! router-installed `test_driven_development` (QM-21) carries the
//! enforcement-via-prompt path; this module is the CORE Rust
//! complement for the explicit `neoth code` entry point.
//!
//! ## What it does NOT do
//!
//! - Block dispatch. The operator's authority is final; the
//!   pre-flight prints + moves on.
//! - Run actual tests. That's the worker's job during dispatch.
//! - LLM-classify the prompt. Pattern matching is deterministic +
//!   testable + free.

use serde::{Deserialize, Serialize};

/// QM-7: classified work-kind the operator's prompt represents.
/// Drives the pre-flight branching — Feature gets the full RED-
/// GREEN-REFACTOR checklist; BugFix gets a regression-test-first
/// reminder; Refactor gets a behavior-preservation pin; Question /
/// TrivialChange skip entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    Feature,
    BugFix,
    Refactor,
    Question,
    TrivialChange,
}

impl WorkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkKind::Feature => "feature",
            WorkKind::BugFix => "bug_fix",
            WorkKind::Refactor => "refactor",
            WorkKind::Question => "question",
            WorkKind::TrivialChange => "trivial_change",
        }
    }
}

/// QM-7 pre-flight report. Operator sees this rendered as a short
/// markdown block before decomposition starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TddPreflight {
    /// Classifier output.
    pub kind: WorkKind,
    /// True when TDD doesn't meaningfully apply (questions, trivial
    /// renames, throwaway exploration). The CLI suppresses the
    /// checklist render in this case.
    pub skip_tdd: bool,
    /// Multi-line checklist text. Empty when `skip_tdd`.
    pub checklist: String,
    /// One-line summary that fits in a single terminal row.
    pub headline: String,
}

/// QM-7 entry point. Pure function — pattern-based classification
/// + checklist generation. Operator-readable output is the headline
/// + checklist; downstream tooling consumes the typed kind.
pub fn evaluate(prompt: &str) -> TddPreflight {
    let kind = classify(prompt);
    let (skip_tdd, checklist, headline) = match kind {
        WorkKind::Feature => (
            false,
            FEATURE_CHECKLIST.to_string(),
            "TDD pre-flight (feature): RED → GREEN → REFACTOR. Test FIRST.".to_string(),
        ),
        WorkKind::BugFix => (
            false,
            BUGFIX_CHECKLIST.to_string(),
            "TDD pre-flight (bug fix): write the regression test FIRST, watch it fail.".to_string(),
        ),
        WorkKind::Refactor => (
            false,
            REFACTOR_CHECKLIST.to_string(),
            "TDD pre-flight (refactor): tests stay GREEN throughout. No new behaviour."
                .to_string(),
        ),
        WorkKind::Question => (
            true,
            String::new(),
            "Question-only request — no code to test; TDD skipped.".to_string(),
        ),
        WorkKind::TrivialChange => (
            true,
            String::new(),
            "Trivial change (rename / typo / format) — TDD skipped.".to_string(),
        ),
    };
    TddPreflight {
        kind,
        skip_tdd,
        checklist,
        headline,
    }
}

/// QM-7 pattern-based classifier. Order matters — TrivialChange +
/// Question short-circuit FIRST so a prompt like "rename foo to bar"
/// doesn't get misclassified as Feature for containing the word
/// "implement". Refactor + BugFix come before Feature for the same
/// reason. Feature is the residual.
fn classify(prompt: &str) -> WorkKind {
    let lower = prompt.to_lowercase();

    // Question markers — operator asking for explanation / analysis,
    // not requesting code change.
    let question_markers = [
        "explain",
        "what is",
        "what does",
        "how does",
        "why does",
        "warum",
        "erklär",
        "was macht",
        "?",
    ];
    let is_question = question_markers.iter().any(|m| lower.contains(m));
    let has_implementation_verb = ["implement", "add", "build", "write", "create", "fix"]
        .iter()
        .any(|v| lower.contains(v));
    if is_question && !has_implementation_verb {
        return WorkKind::Question;
    }

    // Trivial-change markers — pure renames / typo / format.
    let trivial_markers = [
        "rename ",
        "typo",
        "format only",
        "reformat",
        "whitespace",
        "comment only",
        "fix spelling",
        "umbenennen",
    ];
    if trivial_markers.iter().any(|m| lower.contains(m)) {
        return WorkKind::TrivialChange;
    }

    // Refactor markers — operator wants restructure, NOT new
    // behaviour. Order before BugFix because "refactor to fix
    // readability" is refactor not bugfix.
    let refactor_markers = [
        "refactor",
        "restructure",
        "extract",
        "consolidate",
        "deduplicate",
        "rearrange",
        "umstrukturieren",
    ];
    if refactor_markers.iter().any(|m| lower.contains(m)) {
        return WorkKind::Refactor;
    }

    // Bug-fix markers — operator names a failure to repair.
    let bugfix_markers = [
        "fix ",
        "bug",
        "broken",
        "fails",
        "failing",
        "regression",
        "panic",
        "crash",
        "kaputt",
        "reparieren",
    ];
    if bugfix_markers.iter().any(|m| lower.contains(m)) {
        return WorkKind::BugFix;
    }

    // Residual = Feature.
    WorkKind::Feature
}

const FEATURE_CHECKLIST: &str = "\
1. RED — write the failing test FIRST. Name the public-interface
   behaviour the test pins. Run it; quote the failure line.
2. GREEN — write the smallest implementation that makes the test
   pass. Resist adjacent features.
3. REFACTOR — clean up while the test stays GREEN. Stop when the
   code is as clean as the test demands.
4. Vertical slice — the test exercises the END-TO-END public
   surface, not the helper internals. Behavior-through-public-
   interface doctrine.
5. NEVER refactor while RED — fix the failing test first; refactor
   only when GREEN.";

const BUGFIX_CHECKLIST: &str = "\
1. Reproduce — write a test that exhibits the bug today. Watch it
   FAIL. Quote the failure line.
2. Fix — minimum change that makes the regression test pass.
3. Verify — re-run the suite. Bug-test GREEN + no regressions.
4. Keep the test — it earned a permanent regression-suite seat.";

const REFACTOR_CHECKLIST: &str = "\
1. Tests GREEN BEFORE you start. Refactor on a red suite is a
   debugging session, not a refactor.
2. No behaviour change — the same tests pass after as before.
   New tests don't belong in this commit.
3. Each refactor step keeps the suite GREEN. Multi-step rewrites
   commit at the green checkpoints.
4. Stop when the structure is as clean as the existing tests
   demand. Speculative depth waits for the next feature.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_feature_request() {
        let r = classify("Implement a new dashboard for cost tracking");
        assert_eq!(r, WorkKind::Feature);
    }

    #[test]
    fn classifies_bug_fix_request() {
        let r = classify("Fix the panic when the WAL segment is empty");
        assert_eq!(r, WorkKind::BugFix);
    }

    #[test]
    fn classifies_refactor_request() {
        let r = classify("Refactor channels/discord.rs into smaller files");
        assert_eq!(r, WorkKind::Refactor);
    }

    #[test]
    fn classifies_question_request() {
        let r = classify("What does the K-Wire-2 council trigger do?");
        assert_eq!(r, WorkKind::Question);
    }

    #[test]
    fn classifies_trivial_rename() {
        let r = classify("Rename `foo_bar` to `baz_qux` across the codebase");
        assert_eq!(r, WorkKind::TrivialChange);
    }

    #[test]
    fn refactor_takes_precedence_over_bugfix() {
        // "Refactor to fix readability" — operator wants
        // restructuring, NOT a behaviour change. Refactor must win
        // even though the word "fix" appears.
        let r = classify("Refactor the recall module to fix readability");
        assert_eq!(r, WorkKind::Refactor);
    }

    #[test]
    fn trivial_takes_precedence_over_feature() {
        // Pure rename even with "implement" wouldn't really happen,
        // but defensively ensure trivial markers win when present.
        let r = classify("Rename the test fixture");
        assert_eq!(r, WorkKind::TrivialChange);
    }

    #[test]
    fn question_skip_does_not_override_implementation_verb() {
        // "How does X work AND can you implement Y" — the
        // implementation verb overrides the question short-circuit.
        // Operator wants both an explanation AND a code change;
        // route to the code-change classifier.
        let r = classify("How does X work and can you implement a fix for it?");
        assert_ne!(r, WorkKind::Question);
    }

    #[test]
    fn evaluate_feature_produces_full_checklist() {
        let r = evaluate("Build a new export command for kanban tasks");
        assert_eq!(r.kind, WorkKind::Feature);
        assert!(!r.skip_tdd);
        assert!(r.checklist.contains("RED"));
        assert!(r.checklist.contains("GREEN"));
        assert!(r.checklist.contains("REFACTOR"));
        assert!(r.checklist.contains("Vertical slice"));
        assert!(r.headline.contains("feature"));
    }

    #[test]
    fn evaluate_bugfix_produces_regression_checklist() {
        let r = evaluate("Fix the OOM panic in webhook listener");
        assert_eq!(r.kind, WorkKind::BugFix);
        assert!(!r.skip_tdd);
        assert!(r.checklist.contains("Reproduce"));
        assert!(r.checklist.contains("regression"));
    }

    #[test]
    fn evaluate_refactor_produces_behavior_preservation_checklist() {
        let r = evaluate("Refactor the recall module");
        assert_eq!(r.kind, WorkKind::Refactor);
        assert!(!r.skip_tdd);
        assert!(r.checklist.contains("No behaviour change"));
        assert!(r.checklist.contains("GREEN"));
    }

    #[test]
    fn evaluate_question_skips_tdd() {
        let r = evaluate("What does the K-Wire-2 council trigger do?");
        assert_eq!(r.kind, WorkKind::Question);
        assert!(r.skip_tdd);
        assert!(r.checklist.is_empty());
        assert!(r.headline.contains("Question"));
    }

    #[test]
    fn evaluate_trivial_skips_tdd() {
        let r = evaluate("Rename foo to bar");
        assert_eq!(r.kind, WorkKind::TrivialChange);
        assert!(r.skip_tdd);
        assert!(r.checklist.is_empty());
        assert!(r.headline.contains("Trivial"));
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = evaluate("Implement export command");
        let json = serde_json::to_string(&r).unwrap();
        let back: TddPreflight = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(json.contains("\"kind\":\"feature\""));
    }

    #[test]
    fn workkind_round_trips_serde() {
        for k in [
            WorkKind::Feature,
            WorkKind::BugFix,
            WorkKind::Refactor,
            WorkKind::Question,
            WorkKind::TrivialChange,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            let back: WorkKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
            assert_eq!(k.as_str(), s.trim_matches('"'));
        }
    }

    #[test]
    fn checklists_are_distinct() {
        // Pin that each work kind gets a DISTINCT checklist body —
        // a future refactor that accidentally aliases two kinds to
        // the same string surfaces here.
        let f = evaluate("Implement X").checklist;
        let b = evaluate("Fix bug X").checklist;
        let r = evaluate("Refactor X").checklist;
        assert_ne!(f, b);
        assert_ne!(b, r);
        assert_ne!(f, r);
    }
}
