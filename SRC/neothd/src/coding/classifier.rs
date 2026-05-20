//! Heuristic complexity classifier — Pick #3 per
//! `PLAN/SPEC_coding_workflow.md` build order.
//!
//! Routes a kanban task to either the Left hemisphere (Fast worker —
//! well-scoped UI/CRUD/test stubs) or the Right hemisphere (Deep
//! worker — architecture / design / review / ambiguous specs).
//!
//! The classifier is heuristic-first by design: a string-match
//! against two operator-curated word lists. When neither signal
//! fires, the result is [`Complexity::Ambiguous`] — the dispatcher
//! then escalates to the Cerebellum hemisphere for an LLM
//! second-opinion (Pick #9 per the SPEC build order).
//!
//! Why no LLM call in the heuristic: a classifier that takes 2-5 s
//! per task adds latency to the decomposer's hot path. The two
//! lists encode the operator's intuition — they're tunable without
//! recompiling logic and cover ~80% of real coding tasks.

use super::types::{Hemisphere, KanbanTask};

/// Result of running a task through the heuristic classifier. The
/// dispatcher (Pick #6) maps `Fast → Left`, `Deep → Right`, and
/// escalates `Ambiguous` to a Cerebellum LLM second-opinion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Complexity {
    /// Well-scoped change — UI scaffold, simple CRUD, test stub,
    /// rename, typo fix. Routes to Left hemisphere (fast worker).
    Fast,
    /// Architecture / design / review / ambiguous requirement.
    /// Routes to Right hemisphere (deep worker).
    Deep,
    /// Neither heuristic signal fired — operator intent is unclear.
    /// Dispatcher escalates to Cerebellum LLM classify (Pick #9).
    Ambiguous,
}

impl Complexity {
    /// Stable wire form for WAL payloads + operator-facing logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Complexity::Fast => "fast",
            Complexity::Deep => "deep",
            Complexity::Ambiguous => "ambiguous",
        }
    }

    /// Map a heuristic verdict to the hemisphere the dispatcher
    /// SHOULD assign. `Ambiguous` returns `Unassigned` so the
    /// caller knows to escalate instead of guessing.
    pub const fn to_hemisphere(self) -> Hemisphere {
        match self {
            Complexity::Fast => Hemisphere::Left,
            Complexity::Deep => Hemisphere::Right,
            Complexity::Ambiguous => Hemisphere::Unassigned,
        }
    }
}

/// Words that push a task toward Deep when present anywhere in the
/// title or description. These are CHOSEN — they encode the operator's
/// intuition that any task touching architecture / design / review /
/// migration / security is too risky to hand to a fast worker without
/// a deep model pass.
///
/// All entries are lowercase; the matcher normalises input via
/// `to_lowercase` before scanning.
const DEEP_SIGNALS: &[&str] = &[
    "architecture",
    "design decision",
    "design choice",
    "design considerations",
    "refactor",
    "review",
    "consider",
    "evaluate",
    "trade-off",
    "tradeoff",
    "should we",
    "edge case",
    "edge-case",
    "security",
    "race condition",
    "deadlock",
    "migration",
    "schema change",
    "breaking change",
    "rollback",
    "rfc",
    "spec",
    "specification",
];

/// Words that push a task toward Fast when present. Tuned for
/// well-scoped, single-file, single-concept work that a local fast
/// worker can ship in one pass without architectural judgment.
const FAST_SIGNALS: &[&str] = &[
    "add toggle",
    "add button",
    "add input",
    "add field",
    "add label",
    "add icon",
    "add link",
    "save preference",
    "store value",
    "store setting",
    "load setting",
    "load value",
    "write test",
    "add test",
    "add tests",
    "fix typo",
    "rename",
    "add validation",
    "add error message",
    "add tooltip",
    "add placeholder",
    "increment counter",
    "decrement counter",
];

/// Run the heuristic. Title + description are lowercased + concatenated;
/// then we scan DEEP_SIGNALS first (Deep wins ties), FAST_SIGNALS next.
///
/// Title is REQUIRED — a task without one is treated as `Ambiguous`
/// regardless of description content (the dispatcher refuses to assign
/// any task missing a title anyway, so this is defensive).
pub fn classify_heuristic(task: &KanbanTask) -> Complexity {
    if task.title.trim().is_empty() {
        return Complexity::Ambiguous;
    }
    let title_lower = task.title.to_lowercase();
    let desc_lower = task.description.as_deref().unwrap_or("").to_lowercase();
    // Avoid allocating a third string — scan both lowercased halves
    // independently. Catches signals that span the title/description
    // boundary at worst by missing them, never by false-matching.
    if DEEP_SIGNALS
        .iter()
        .any(|kw| title_lower.contains(kw) || desc_lower.contains(kw))
    {
        return Complexity::Deep;
    }
    if FAST_SIGNALS
        .iter()
        .any(|kw| title_lower.contains(kw) || desc_lower.contains(kw))
    {
        return Complexity::Fast;
    }
    Complexity::Ambiguous
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTaskId, TaskStatus};

    /// Minimal task builder for classifier inputs. Other fields use
    /// defaults the classifier ignores anyway (status, timestamps,
    /// worker). Keep this in the tests module — production code
    /// constructs tasks via `coding::store::insert_task`.
    fn task(title: &str, description: Option<&str>) -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(1),
            session_id: KanbanSessionId(1),
            status: TaskStatus::Backlog,
            title: title.to_string(),
            description: description.map(String::from),
            task_type: "ui".to_string(),
            hemisphere: Hemisphere::Unassigned,
            worker: None,
            parent_task_id: None,
            created_ns: 0,
            started_ns: None,
            eta_ns: None,
            completed_ns: None,
            patch_path: None,
            test_summary: None,
        }
    }

    #[test]
    fn complexity_wire_form_is_snake_case() {
        // Wire form pinning — WAL payloads + operator-facing logs
        // grep on these strings.
        assert_eq!(Complexity::Fast.as_str(), "fast");
        assert_eq!(Complexity::Deep.as_str(), "deep");
        assert_eq!(Complexity::Ambiguous.as_str(), "ambiguous");
    }

    #[test]
    fn complexity_to_hemisphere_maps_per_spec() {
        assert_eq!(Complexity::Fast.to_hemisphere(), Hemisphere::Left);
        assert_eq!(Complexity::Deep.to_hemisphere(), Hemisphere::Right);
        assert_eq!(
            Complexity::Ambiguous.to_hemisphere(),
            Hemisphere::Unassigned,
            "Ambiguous must NOT auto-assign — caller escalates to LLM classify"
        );
    }

    #[test]
    fn fast_signals_yield_fast() {
        // The image's example tasks should all hit the Fast lane.
        assert_eq!(
            classify_heuristic(&task("Add toggle UI in settings", None)),
            Complexity::Fast
        );
        assert_eq!(
            classify_heuristic(&task("Save preference to storage", None)),
            Complexity::Fast
        );
        assert_eq!(
            classify_heuristic(&task("Add tests", None)),
            Complexity::Fast
        );
        assert_eq!(
            classify_heuristic(&task("Fix typo in error message", None)),
            Complexity::Fast
        );
    }

    #[test]
    fn deep_signals_yield_deep() {
        // The image's REVIEW + PLANNING column tasks should all hit
        // the Deep lane.
        assert_eq!(
            classify_heuristic(&task("Code review & edge cases", None)),
            Complexity::Deep
        );
        assert_eq!(
            classify_heuristic(&task("Dark mode design considerations", None)),
            Complexity::Deep
        );
        assert_eq!(
            classify_heuristic(&task("Refactor the auth middleware", None)),
            Complexity::Deep
        );
        assert_eq!(
            classify_heuristic(&task(
                "Add migration for the new column",
                Some("Schema change requires backfill"),
            )),
            Complexity::Deep,
            "migration + schema change BOTH hit Deep"
        );
    }

    #[test]
    fn deep_wins_when_both_signals_present() {
        // "Add tests" is FAST. "Edge case" is DEEP. A task that
        // mentions both MUST hit Deep — Deep wins ties because the
        // cost of a fast worker getting an edge-case wrong is high.
        assert_eq!(
            classify_heuristic(&task("Add tests for the auth edge case", None,)),
            Complexity::Deep,
        );
    }

    #[test]
    fn neither_signal_yields_ambiguous() {
        // Tasks the operator's word lists don't cover end up here.
        // The dispatcher then escalates to Cerebellum LLM classify.
        assert_eq!(
            classify_heuristic(&task("Implement the foo widget", None)),
            Complexity::Ambiguous
        );
        assert_eq!(
            classify_heuristic(&task("Wire the bar to the baz", Some("Standard plumbing"))),
            Complexity::Ambiguous
        );
    }

    #[test]
    fn empty_title_yields_ambiguous() {
        // Defensive — the dispatcher refuses to assign titleless
        // tasks anyway, but the classifier must not panic + must
        // return a defensible verdict.
        assert_eq!(
            classify_heuristic(&task("", Some("Lots of description content"))),
            Complexity::Ambiguous
        );
        assert_eq!(
            classify_heuristic(&task("   ", None)),
            Complexity::Ambiguous,
            "whitespace-only title is empty for our purposes"
        );
    }

    #[test]
    fn case_insensitivity_via_lowercase_normalise() {
        // Operators type with mixed case. The classifier MUST
        // normalise — otherwise "ADD TOGGLE" silently misses Fast.
        assert_eq!(
            classify_heuristic(&task("ADD TOGGLE UI IN SETTINGS", None)),
            Complexity::Fast
        );
        assert_eq!(
            classify_heuristic(&task("Refactor THE Foo Module", None)),
            Complexity::Deep
        );
    }

    #[test]
    fn description_alone_can_trigger_deep() {
        // A bland title with a deep-signal in the description
        // (operator wrote "Cleanup", described it as "refactor the
        // auth flow + migration") MUST hit Deep — the description is
        // where most of the spec lives.
        assert_eq!(
            classify_heuristic(&task(
                "Cleanup",
                Some("Refactor the auth flow and add a migration"),
            )),
            Complexity::Deep
        );
    }

    #[test]
    fn description_alone_can_trigger_fast() {
        // Heuristic is substring-match — operator-typed phrases that
        // include articles ("add A toggle") would NOT match the "add
        // toggle" signal. Pin a description that uses the exact signal
        // phrase, which is the contract: operators using the documented
        // verbs hit Fast, prose that wraps them hits Ambiguous +
        // escalates to the LLM classifier (Pick #9).
        assert_eq!(
            classify_heuristic(&task(
                "Settings work",
                Some("Add tests for dark-mode toggle persistence"),
            )),
            Complexity::Fast,
            "description carrying 'add tests' signal must hit Fast"
        );
    }

    #[test]
    fn signal_lists_are_lowercase_for_matcher_correctness() {
        // The matcher relies on `to_lowercase` normalising the input
        // before scanning. If a signal entry has uppercase letters,
        // it would never match. Pin that constraint at the const-list
        // level so future additions stay consistent.
        for kw in DEEP_SIGNALS.iter().chain(FAST_SIGNALS.iter()) {
            assert!(
                kw.chars()
                    .all(|c| c.is_ascii_lowercase() || !c.is_ascii_alphabetic()),
                "signal {kw:?} must be all-lowercase for the matcher to find it"
            );
        }
    }

    #[test]
    fn signal_lists_have_no_duplicates() {
        // Duplicates don't break correctness but they inflate the
        // matcher's runtime + suggest operator intent drift across
        // commits. Catch them early.
        for (i, kw1) in DEEP_SIGNALS.iter().enumerate() {
            for kw2 in DEEP_SIGNALS.iter().skip(i + 1) {
                assert_ne!(kw1, kw2, "duplicate in DEEP_SIGNALS: {kw1:?}");
            }
        }
        for (i, kw1) in FAST_SIGNALS.iter().enumerate() {
            for kw2 in FAST_SIGNALS.iter().skip(i + 1) {
                assert_ne!(kw1, kw2, "duplicate in FAST_SIGNALS: {kw1:?}");
            }
        }
    }

    #[test]
    fn signal_lists_have_no_cross_overlap() {
        // A word in BOTH lists would mean Deep wins (per the
        // ordering) but the operator's intent was unclear. Flag at
        // the const-list level instead of letting a silent
        // misclassification ship.
        for fast_kw in FAST_SIGNALS {
            assert!(
                !DEEP_SIGNALS.contains(fast_kw),
                "signal {fast_kw:?} appears in BOTH FAST and DEEP lists — \
                 pick one or rename"
            );
        }
    }
}
