//! QM-4 part 1 — Brainstorm gate (SP-C1 from QUELLEN superpowers).
//!
//! Per `PLAN/QUELLEN_ADOPT_superpowers_2026-05-22.md` SP-C1
//! `brainstorming` ADOPT-AS-CORE. The operator-facing
//! `brainstorming` skill (QM-24) is the prompt-side discipline;
//! this module is the CORE Rust gate that classifies whether a
//! request NEEDS brainstorming and produces a structured
//! [`BrainstormSpec`] when an operator (or another sub-agent)
//! drives the gate to completion.
//!
//! ## Iron Law
//!
//! No implementation tasks before a reviewed spec exists. The gate
//! enforces this by returning `Decision::NeedsBrainstorm` for
//! FeatureRequest-shaped prompts that don't carry a pre-existing
//! spec marker. Composes with QM-7 TDD pre-flight: brainstorm
//! determines WHAT to build, TDD pre-flight determines HOW.
//!
//! ## What this module ships
//!
//! - [`evaluate`] — classifies the prompt + returns a
//!   [`Decision`] (Skip / NeedsBrainstorm / SpecReady).
//! - [`BrainstormSpec`] — 6-section PRD shape mirroring the
//!   `to_prd` skill (QM-22 batch B): Problem / Solution /
//!   UserStories / ImplementationDecisions / TestingDecisions /
//!   OutOfScope.
//! - [`parse_spec`] — extract a `BrainstormSpec` from a markdown
//!   document that uses the six section headers. Operators paste
//!   their spec text + downstream code consumes typed fields.
//!
//! ## What this is NOT (yet)
//!
//! - The Socratic Q&A loop. That lives in the
//!   `brainstorming` skill's system_prompt — when activated the
//!   model drives the operator through the questions. This
//!   module is the post-skill processing step that turns the
//!   operator-approved spec back into typed data.
//! - The kanban write. [`super::plan_writer`] owns that surface
//!   once a `BrainstormSpec` is in hand.

use serde::{Deserialize, Serialize};

/// GRILL-04 — maximum brainstorm rounds before a [`Decision::Deadlock`]
/// is returned. Prevents infinite Q&A loops when operator and model
/// cannot converge on a spec within a bounded session.
pub const MAX_BRAINSTORM_ROUNDS: u32 = 6;

/// QM-4: gate decision. The coding workflow (`cli::code`) consults
/// this BEFORE decomposition so the operator either:
///   - skips brainstorming entirely (bug fix / refactor /
///     question / trivial change — no spec needed)
///   - brainstorms first (feature request without a pre-existing
///     spec marker)
///   - proceeds to decomposition (spec already attached via the
///     SpecReady path)
///   - receives a Deadlock after [`MAX_BRAINSTORM_ROUNDS`] rounds
///     without convergence (GRILL-04)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    /// Operator's prompt is bug-fix / refactor / question / trivial
    /// — no spec needed. Decomposition proceeds immediately.
    Skip { reason: String },
    /// Feature-shaped request without a pre-existing spec marker.
    /// Operator should brainstorm via the `brainstorming` skill OR
    /// paste an existing spec into the prompt with the section
    /// headers `parse_spec` recognises.
    NeedsBrainstorm { rationale: String },
    /// Operator's prompt already carries a parseable spec (six
    /// section headers detected). The gate hands the typed spec
    /// off to downstream.
    SpecReady { spec: Box<BrainstormSpec> },
    /// GRILL-04 — brainstorm loop exhausted [`MAX_BRAINSTORM_ROUNDS`]
    /// without reaching a `SpecReady` decision. The `unresolved`
    /// list names the open issues that blocked convergence.
    /// Downstream code (e.g. `cli::code`) MUST surface these to
    /// the operator and halt — do NOT proceed to decomposition.
    Deadlock { unresolved: Vec<String> },
}

impl Decision {
    pub fn is_skip(&self) -> bool {
        matches!(self, Decision::Skip { .. })
    }
    pub fn needs_brainstorm(&self) -> bool {
        matches!(self, Decision::NeedsBrainstorm { .. })
    }
    pub fn is_spec_ready(&self) -> bool {
        matches!(self, Decision::SpecReady { .. })
    }
    /// GRILL-04: true when the brainstorm loop hit its round ceiling.
    pub fn is_deadlock(&self) -> bool {
        matches!(self, Decision::Deadlock { .. })
    }
}

/// GRILL-04 — brainstorm-loop evaluator with a round ceiling.
///
/// Drives a stateless classification loop: on each round it evaluates
/// the current `prompt` and returns either a final decision or
/// `NeedsBrainstorm` (meaning the caller should present the rationale
/// to the operator, collect a revised prompt, and call again).
///
/// When `round` reaches [`MAX_BRAINSTORM_ROUNDS`] without returning
/// [`Decision::SpecReady`] or [`Decision::Skip`], this function returns
/// [`Decision::Deadlock`] with the `unresolved` list populated from the
/// last `NeedsBrainstorm` rationale.
///
/// # Arguments
///
/// * `prompt`  — the current operator prompt (may be revised each round)
/// * `round`   — 1-based round number (caller increments between calls)
/// * `unresolved` — open issues accumulated so far (append rationale on
///                  each `NeedsBrainstorm` round, pass the vec through)
///
/// # Returns
///
/// The [`Decision`] for this round. When `Deadlock` is returned the
/// caller MUST stop the loop.
pub fn evaluate_with_rounds(
    prompt: &str,
    round: u32,
    unresolved: Vec<String>,
) -> Decision {
    let decision = evaluate(prompt);
    match decision {
        // Terminal decisions — return immediately.
        Decision::Skip { .. } | Decision::SpecReady { .. } => decision,
        // Not yet approved — check the ceiling.
        Decision::NeedsBrainstorm { ref rationale } => {
            if round >= MAX_BRAINSTORM_ROUNDS {
                let mut issues = unresolved;
                issues.push(rationale.clone());
                Decision::Deadlock { unresolved: issues }
            } else {
                decision
            }
        }
        // Already a Deadlock — pass through (shouldn't happen in
        // normal usage, but be safe).
        Decision::Deadlock { .. } => decision,
    }
}

/// QM-4 6-section PRD shape. Mirrors the `to_prd` skill's
/// authoring contract from QM-22 batch B. Every field is mandatory
/// at the type level; `parse_spec` enforces non-empty content per
/// section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrainstormSpec {
    /// Problem statement (one paragraph).
    pub problem: String,
    /// Solution shape (one paragraph).
    pub solution: String,
    /// User stories (1+ "as X, I want Y, so that Z" entries).
    pub user_stories: Vec<String>,
    /// Implementation decisions (non-trivial technical choices).
    pub implementation_decisions: Vec<String>,
    /// Testing decisions per tier.
    pub testing_decisions: Vec<String>,
    /// Out-of-scope items (intentionally NOT in this spec).
    pub out_of_scope: Vec<String>,
}

impl BrainstormSpec {
    /// True when every section has non-empty content. The
    /// `parse_spec` path returns an Err for incomplete specs so
    /// downstream code can rely on `is_complete() == true`.
    pub fn is_complete(&self) -> bool {
        !self.problem.trim().is_empty()
            && !self.solution.trim().is_empty()
            && !self.user_stories.is_empty()
            && !self.implementation_decisions.is_empty()
            && !self.testing_decisions.is_empty()
            && !self.out_of_scope.is_empty()
    }
}

/// QM-4 entry point. Classifies the prompt + returns the gate
/// decision. Pure function; no I/O.
///
/// Classification rules (mirror QM-7 TDD pre-flight but in this
/// module the focus is brainstorm-vs-skip, not TDD shape):
///
/// - **Skip** when the prompt contains bugfix markers (`fix `,
///   `bug`, `broken`, `panic`), refactor markers (`refactor`,
///   `restructure`), question markers (`explain`, `what is`,
///   `?`), or trivial-change markers (`rename `, `typo`).
/// - **SpecReady** when the prompt contains all six required
///   section headers — operator pasted a pre-prepared spec.
/// - **NeedsBrainstorm** otherwise (Feature-shaped request
///   without a spec).
pub fn evaluate(prompt: &str) -> Decision {
    let lower = prompt.to_lowercase();

    // Skip-class markers checked first (same order as TDD
    // pre-flight). Question short-circuit only without
    // implementation verb so "implement X" beats "what is X".
    let has_impl_verb = ["implement", "add", "build", "write", "create", "fix "]
        .iter()
        .any(|v| lower.contains(v));
    let is_question = [
        "explain ",
        "what is",
        "what does",
        "how does",
        "why does",
        "?",
    ]
    .iter()
    .any(|m| lower.contains(m))
        && !has_impl_verb;
    if is_question {
        return Decision::Skip {
            reason: "question-only request — no implementation, no spec needed".into(),
        };
    }
    let trivial_markers = ["rename ", "typo", "format only", "reformat", "whitespace"];
    if trivial_markers.iter().any(|m| lower.contains(m)) {
        return Decision::Skip {
            reason: "trivial change (rename / typo / format) — no spec needed".into(),
        };
    }
    let refactor_markers = ["refactor", "restructure", "extract ", "deduplicate"];
    if refactor_markers.iter().any(|m| lower.contains(m)) {
        return Decision::Skip {
            reason: "refactor — no new behaviour, no spec needed (verify tests stay green)".into(),
        };
    }
    let bugfix_markers = [
        "fix ", "bug", "broken", "fails", "failing", "panic", "crash", "kaputt",
    ];
    if bugfix_markers.iter().any(|m| lower.contains(m)) {
        return Decision::Skip {
            reason: "bug fix — no spec needed; write the regression test first".into(),
        };
    }

    // Try to parse as already-prepared spec. If every section
    // header is present + content is non-empty, hand the typed
    // spec off.
    if let Ok(spec) = parse_spec(prompt) {
        return Decision::SpecReady {
            spec: Box::new(spec),
        };
    }

    Decision::NeedsBrainstorm {
        rationale: "Feature-shaped request without an attached spec. Run the brainstorming skill \
             (`/skill brainstorming`) or paste a spec with the six section headers: \
             ## Problem, ## Solution, ## User Stories, ## Implementation Decisions, \
             ## Testing Decisions, ## Out-of-Scope."
            .into(),
    }
}

/// QM-4 parser. Extracts a [`BrainstormSpec`] from markdown that
/// uses the six section headers. Case-insensitive. Returns Err
/// when any section is missing OR has empty content.
///
/// Section format expected:
///
/// ```markdown
/// ## Problem
/// One paragraph...
///
/// ## Solution
/// One paragraph...
///
/// ## User Stories
/// - As <role>, I want <action> so that <outcome>.
/// - As ...
///
/// ## Implementation Decisions
/// - Decision 1 + rationale
/// - Decision 2 + rationale
///
/// ## Testing Decisions
/// - Unit: ...
/// - Integration: ...
///
/// ## Out-of-Scope
/// - Item 1
/// - Item 2
/// ```
pub fn parse_spec(text: &str) -> anyhow::Result<BrainstormSpec> {
    // Find each section header (case-insensitive substring match
    // on the canonical title) + extract content up to the next
    // header.
    let headers = [
        "problem",
        "solution",
        "user stories",
        "implementation decisions",
        "testing decisions",
        "out-of-scope",
    ];
    // Walk through the lines, collect content per header.
    let mut sections: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    let mut current_header: Option<&'static str> = None;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        // Header detection — `## <title>` or `# <title>` shapes.
        let header_start = trimmed.starts_with('#');
        if header_start {
            let stripped = trimmed.trim_start_matches('#').trim().to_lowercase();
            // Match the most-specific header first so "user
            // stories" doesn't get shadowed by "stories" etc.
            let matched = headers
                .iter()
                .find(|h| stripped == **h || stripped.starts_with(*h));
            current_header = matched.copied();
            continue;
        }
        if let Some(h) = current_header {
            sections.entry(h).or_default().push_str(raw_line);
            sections.get_mut(h).unwrap().push('\n');
        }
    }

    let take = |name: &str| {
        sections
            .get(name)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("spec missing or empty section: ## {name}"))
    };
    let problem = take("problem")?;
    let solution = take("solution")?;
    let user_stories = parse_bullets(&take("user stories")?, "user stories")?;
    let implementation_decisions = parse_bullets(
        &take("implementation decisions")?,
        "implementation decisions",
    )?;
    let testing_decisions = parse_bullets(&take("testing decisions")?, "testing decisions")?;
    let out_of_scope = parse_bullets(&take("out-of-scope")?, "out-of-scope")?;
    Ok(BrainstormSpec {
        problem,
        solution,
        user_stories,
        implementation_decisions,
        testing_decisions,
        out_of_scope,
    })
}

/// Helper for parse_spec — split a section body into bulleted
/// items. Accepts `-` / `*` / `1.` style; falls back to lines
/// when no bullet markers are present (operator wrote prose).
/// Returns Err if zero items.
fn parse_bullets(body: &str, section_name: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // Strip bullet/number prefix.
        let cleaned = if let Some(rest) = t.strip_prefix("- ") {
            rest
        } else if let Some(rest) = t.strip_prefix("* ") {
            rest
        } else if let Some(rest) = t.strip_prefix("• ") {
            rest
        } else if let Some(pos) = t.find(". ") {
            // Numbered list "1. foo" — strip prefix.
            if t[..pos].chars().all(|c| c.is_ascii_digit()) {
                &t[pos + 2..]
            } else {
                t
            }
        } else {
            t
        };
        if !cleaned.trim().is_empty() {
            out.push(cleaned.trim().to_string());
        }
    }
    if out.is_empty() {
        anyhow::bail!("spec section `## {section_name}` parsed to zero items");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_on_bug_fix_marker() {
        let d = evaluate("Fix the panic when WAL segment is empty");
        assert!(d.is_skip(), "bug fix must skip brainstorm, got {d:?}");
    }

    #[test]
    fn skip_on_refactor_marker() {
        let d = evaluate("Refactor the recall module");
        assert!(d.is_skip());
    }

    #[test]
    fn skip_on_question_marker() {
        let d = evaluate("What does the K-Wire-2 trigger do?");
        assert!(d.is_skip());
    }

    #[test]
    fn skip_on_trivial_rename() {
        let d = evaluate("Rename foo_bar to baz_qux");
        assert!(d.is_skip());
    }

    #[test]
    fn needs_brainstorm_on_bare_feature_request() {
        let d = evaluate("Build a new dashboard for cost tracking");
        assert!(d.needs_brainstorm());
        if let Decision::NeedsBrainstorm { rationale } = d {
            assert!(rationale.contains("Problem"));
            assert!(rationale.contains("Out-of-Scope"));
        }
    }

    #[test]
    fn question_with_implementation_verb_does_not_skip() {
        // "How does X work AND can you implement Y" — has both
        // markers; implementation verb wins → NeedsBrainstorm.
        let d = evaluate("How does the WAL writer work and can you implement a usage dashboard?");
        assert!(
            !d.is_skip(),
            "implementation verb must override question-skip"
        );
    }

    #[test]
    fn parse_spec_extracts_six_sections() {
        let text = "\
## Problem
Operators have no cost visibility today.

## Solution
Add a usage dashboard that surfaces per-provider cost.

## User Stories
- As an operator running NEOTH with paid providers, I want a daily cost summary so that I can spot runaway spend.
- As an operator on free tier, I want to verify zero spend so that I trust the meter.

## Implementation Decisions
- Use the existing meter::cost rolling-window data; no new schema.
- Render in CLI table format first; Slint panel is follow-up.

## Testing Decisions
- Unit: cost rollup math via fixture meter snapshots.
- Integration: `neoth cost --since 24h` smoke test.

## Out-of-Scope
- Cross-provider price normalisation.
- Historical >30d view.
";
        let spec = parse_spec(text).unwrap();
        assert!(spec.is_complete());
        assert!(spec.problem.contains("cost visibility"));
        assert!(spec.solution.contains("usage dashboard"));
        assert_eq!(spec.user_stories.len(), 2);
        assert_eq!(spec.implementation_decisions.len(), 2);
        assert_eq!(spec.testing_decisions.len(), 2);
        assert_eq!(spec.out_of_scope.len(), 2);
    }

    #[test]
    fn parse_spec_errors_on_missing_section() {
        let text = "\
## Problem
just one section
";
        let r = parse_spec(text);
        assert!(r.is_err());
        let err = r.unwrap_err().to_string();
        assert!(
            err.contains("solution"),
            "error must name first missing: {err}"
        );
    }

    #[test]
    fn parse_spec_errors_on_empty_section() {
        // Header present but content empty → reject.
        let text = "\
## Problem


## Solution
fine

## User Stories
- A

## Implementation Decisions
- B

## Testing Decisions
- C

## Out-of-Scope
- D
";
        let r = parse_spec(text);
        assert!(r.is_err());
        let err = r.unwrap_err().to_string();
        assert!(err.contains("problem"));
    }

    #[test]
    fn spec_ready_when_prompt_contains_full_spec() {
        // Operator pasted a complete spec; gate hands it off
        // typed.
        let text = "\
Please proceed with this spec:

## Problem
Operators have no cost visibility.

## Solution
Add a usage dashboard.

## User Stories
- As an operator I want a daily cost summary.

## Implementation Decisions
- Reuse meter::cost.

## Testing Decisions
- Unit: cost rollup math.

## Out-of-Scope
- >30d view.
";
        let d = evaluate(text);
        assert!(
            d.is_spec_ready(),
            "complete spec must produce SpecReady; got {d:?}"
        );
    }

    #[test]
    fn parse_bullets_handles_numbered_list() {
        let body = "\
1. First item
2. Second item
3. Third
";
        let out = parse_bullets(body, "test").unwrap();
        assert_eq!(out, vec!["First item", "Second item", "Third"]);
    }

    #[test]
    fn parse_bullets_falls_back_to_lines_without_markers() {
        let body = "\
Plain line one.
Plain line two.
";
        let out = parse_bullets(body, "test").unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn decision_round_trips_through_json() {
        let d = evaluate("Fix the OOM bug");
        let json = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(json.contains("\"kind\":\"skip\""));
    }

    // ── GRILL-04 ──────────────────────────────────────────────────────────

    #[test]
    fn deadlock_variant_is_not_skip_or_spec_ready() {
        let d = Decision::Deadlock {
            unresolved: vec!["Scope unclear".into()],
        };
        assert!(!d.is_skip());
        assert!(!d.needs_brainstorm());
        assert!(!d.is_spec_ready());
        assert!(d.is_deadlock());
    }

    #[test]
    fn deadlock_round_trips_through_json() {
        let d = Decision::Deadlock {
            unresolved: vec!["a".into(), "b".into()],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(json.contains("\"kind\":\"deadlock\""));
    }

    /// Calling `evaluate_with_rounds` on a feature prompt MAX times
    /// without an approved spec must return Deadlock.
    #[test]
    fn evaluate_with_rounds_returns_deadlock_at_max_without_approval() {
        // A plain feature request will always produce NeedsBrainstorm
        // from the pure `evaluate` path.
        let prompt = "Build a new dashboard for cost tracking";
        let mut unresolved: Vec<String> = Vec::new();

        let mut final_decision = Decision::Skip {
            reason: "sentinel".into(),
        };
        for round in 1..=MAX_BRAINSTORM_ROUNDS {
            let d = evaluate_with_rounds(prompt, round, unresolved.clone());
            match &d {
                Decision::NeedsBrainstorm { rationale } => {
                    // Still within budget — accumulate.
                    unresolved.push(rationale.clone());
                }
                Decision::Deadlock { .. } => {
                    final_decision = d;
                    break;
                }
                other => panic!("unexpected decision mid-loop: {other:?}"),
            }
        }
        assert!(
            final_decision.is_deadlock(),
            "loop must end in Deadlock; got {final_decision:?}"
        );
        if let Decision::Deadlock { unresolved } = &final_decision {
            assert!(
                !unresolved.is_empty(),
                "Deadlock unresolved list must be populated"
            );
        }
    }

    /// Below MAX_ROUNDS a feature prompt returns NeedsBrainstorm (not Deadlock).
    #[test]
    fn evaluate_with_rounds_no_deadlock_before_max() {
        let prompt = "Build a new dashboard for cost tracking";
        for round in 1..MAX_BRAINSTORM_ROUNDS {
            let d = evaluate_with_rounds(prompt, round, vec![]);
            assert!(
                !d.is_deadlock(),
                "round {round} must not deadlock before MAX_BRAINSTORM_ROUNDS"
            );
        }
    }

    /// A Skip prompt resolves immediately even at round 1.
    #[test]
    fn evaluate_with_rounds_skip_resolves_immediately() {
        let d = evaluate_with_rounds("Fix the panic when WAL is empty", 1, vec![]);
        assert!(d.is_skip());
    }
}
