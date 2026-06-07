//! QM-4 part 2 — Plan-writer with no-placeholders Iron Law (SP-C2).
//!
//! Per `PLAN/QUELLEN_ADOPT_superpowers_2026-05-22.md` SP-C2
//! `writing-plans` ADOPT-AS-CORE. Companion to
//! [`super::brainstorm::BrainstormGate`]: after a [`BrainstormSpec`]
//! is approved, this module enforces the plan-writing contract:
//! no placeholder text, no TBD, no "TODO: implement X" pseudo-tasks.
//!
//! ## Iron Law
//!
//! Plans never carry placeholder text. A plan with `TBD` looks like
//! progress but ISN'T — implementers spend more time decoding the
//! placeholder than executing the real task. [`validate_plan`] is the
//! pure check that enforces this — but note it is **not yet wired into
//! the kanban write path**: it has no production caller today (only
//! tests exercise it), so nothing currently runs it before a plan lands
//! in SQLite. It is ready to gate `store::insert_tasks` the moment that
//! chain lands (see "What this is NOT" below).
//!
//! ## What this module ships
//!
//! - [`PlanTask`] — one row in the operator's plan
//! - [`Plan`] — the top-level plan + tasks + metadata
//! - [`validate_plan`] — checks the no-placeholders Iron Law +
//!   the task-shape invariants (every task has acceptance criteria,
//!   every task has evidence requirement, size is S/M/L)
//! - [`PlanValidationError`] — typed errors so the operator sees
//!   WHICH placeholder fired the rejection
//!
//! ## What this is NOT
//!
//! - The kanban DB write. That lives in `coding::store` today; this
//!   module is the pure validation primitive. A future commit
//!   chains `validate_plan(plan)` → `store::insert_tasks(plan)` so
//!   broken plans never reach SQLite.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// QM-4: one row in a plan. Operator emits N of these from a
/// `BrainstormSpec` decomposition (mirrors the `to_issues` skill's
/// tracer-bullet doctrine — each row a vertical slice through the
/// stack).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTask {
    /// Stable id within the plan (T-01, T-02, ...). Operator-
    /// readable; the DB write reassigns to a real kanban id.
    pub id: String,
    /// Imperative-verb title. Rejected if it starts with a
    /// placeholder marker.
    pub title: String,
    /// Acceptance criteria. Empty list → reject (vertical-slice
    /// rule: every task ships with at least one pass condition).
    pub acceptance: Vec<String>,
    /// Evidence requirement (test name / output line / file:line
    /// citation). Empty → reject (TDD compose with QM-21
    /// verification_before_completion + QM-7 TDD pre-flight).
    pub evidence: Vec<String>,
    /// Size bucket: `S` (1-3h), `M` (half-day), `L` (full day).
    /// Anything else → reject; if the operator wrote `>L` the
    /// task needs splitting first.
    pub size: PlanSize,
}

/// QM-4 plan size bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PlanSize {
    S,
    M,
    L,
}

impl PlanSize {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanSize::S => "S",
            PlanSize::M => "M",
            PlanSize::L => "L",
        }
    }
}

/// QM-4 plan envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Source spec id / link / hash that this plan decomposes.
    pub source: String,
    /// Owner — operator name or sub-agent id. "TBD" / "TBA" /
    /// "?" reject.
    pub owner: String,
    /// One-line scope.
    pub scope: String,
    /// One-line out-of-scope.
    pub out_of_scope: String,
    /// Tasks.
    pub tasks: Vec<PlanTask>,
}

/// QM-4 typed validation errors. Operator-readable string surfaces
/// in the `neoth code plan validate` CLI output.
#[derive(Debug, Error)]
pub enum PlanValidationError {
    #[error("placeholder text in {field}: {token}")]
    Placeholder { field: String, token: String },
    #[error(
        "task {task_id}: acceptance criteria list is empty — every task needs at least one pass condition"
    )]
    EmptyAcceptance { task_id: String },
    #[error(
        "task {task_id}: evidence requirement list is empty — every task needs at least one verifiable artefact"
    )]
    EmptyEvidence { task_id: String },
    #[error("task {task_id} title is empty — every task needs an imperative-verb title")]
    EmptyTitle { task_id: String },
    #[error("plan has zero tasks — at least one task required")]
    EmptyPlan,
    #[error("plan source is empty — spec id / link / hash required for provenance")]
    EmptySource,
    #[error("plan owner is empty — name the operator OR sub-agent")]
    EmptyOwner,
}

/// QM-4 placeholder tokens that the no-placeholders Iron Law
/// rejects. Operator-readable (case-insensitive substring match).
const PLACEHOLDER_TOKENS: &[&str] = &[
    "tbd",
    "tba",
    "todo:",
    "todo ",
    "fixme",
    "xxx",
    "...",
    "placeholder",
    "[redacted]",
    "[fill in",
    "[unknown",
    "(later)",
    "see issue #",
    "see #",
    "?",
];

/// QM-4 validate the plan against the no-placeholders Iron Law +
/// task-shape invariants. Returns Ok(()) when every check passes,
/// or Err with the FIRST violation (operator fixes that, re-runs).
///
/// Pure function; no I/O.
pub fn validate_plan(plan: &Plan) -> Result<(), PlanValidationError> {
    if plan.source.trim().is_empty() {
        return Err(PlanValidationError::EmptySource);
    }
    if plan.owner.trim().is_empty() {
        return Err(PlanValidationError::EmptyOwner);
    }
    if plan.tasks.is_empty() {
        return Err(PlanValidationError::EmptyPlan);
    }

    // Plan-level placeholders.
    check_placeholder("source", &plan.source)?;
    check_placeholder("owner", &plan.owner)?;
    check_placeholder("scope", &plan.scope)?;
    check_placeholder("out_of_scope", &plan.out_of_scope)?;

    for task in &plan.tasks {
        if task.title.trim().is_empty() {
            return Err(PlanValidationError::EmptyTitle {
                task_id: task.id.clone(),
            });
        }
        if task.acceptance.is_empty() {
            return Err(PlanValidationError::EmptyAcceptance {
                task_id: task.id.clone(),
            });
        }
        if task.evidence.is_empty() {
            return Err(PlanValidationError::EmptyEvidence {
                task_id: task.id.clone(),
            });
        }
        // Per-task placeholder check across every text field.
        check_placeholder(&format!("task {}.title", task.id), &task.title)?;
        for (i, c) in task.acceptance.iter().enumerate() {
            check_placeholder(&format!("task {}.acceptance[{i}]", task.id), c)?;
        }
        for (i, e) in task.evidence.iter().enumerate() {
            check_placeholder(&format!("task {}.evidence[{i}]", task.id), e)?;
        }
    }
    Ok(())
}

fn check_placeholder(field: &str, text: &str) -> Result<(), PlanValidationError> {
    let lower = text.to_lowercase();
    for token in PLACEHOLDER_TOKENS {
        if lower.contains(token) {
            return Err(PlanValidationError::Placeholder {
                field: field.to_string(),
                token: (*token).to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_task(id: &str) -> PlanTask {
        PlanTask {
            id: id.into(),
            title: format!("Implement feature {id}"),
            acceptance: vec!["test x passes".into()],
            evidence: vec!["cargo test output line".into()],
            size: PlanSize::M,
        }
    }

    fn good_plan() -> Plan {
        Plan {
            source: "spec-2026-05-22".into(),
            owner: "sam".into(),
            scope: "build the cost dashboard".into(),
            out_of_scope: "cross-provider price normalisation".into(),
            tasks: vec![good_task("T-01"), good_task("T-02")],
        }
    }

    #[test]
    fn validate_accepts_well_formed_plan() {
        let plan = good_plan();
        assert!(validate_plan(&plan).is_ok());
    }

    #[test]
    fn validate_rejects_empty_source() {
        let mut plan = good_plan();
        plan.source = "".into();
        let e = validate_plan(&plan).unwrap_err();
        assert!(matches!(e, PlanValidationError::EmptySource));
    }

    #[test]
    fn validate_rejects_empty_owner() {
        let mut plan = good_plan();
        plan.owner = "  ".into();
        let e = validate_plan(&plan).unwrap_err();
        assert!(matches!(e, PlanValidationError::EmptyOwner));
    }

    #[test]
    fn validate_rejects_zero_tasks() {
        let mut plan = good_plan();
        plan.tasks.clear();
        let e = validate_plan(&plan).unwrap_err();
        assert!(matches!(e, PlanValidationError::EmptyPlan));
    }

    #[test]
    fn validate_rejects_placeholder_tbd_in_owner() {
        let mut plan = good_plan();
        plan.owner = "TBD".into();
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::Placeholder { field, token } => {
                assert_eq!(field, "owner");
                assert_eq!(token, "tbd");
            }
            other => panic!("expected Placeholder, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_placeholder_todo_in_task_title() {
        let mut plan = good_plan();
        plan.tasks[0].title = "TODO: implement the thing".into();
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::Placeholder { field, token } => {
                assert!(field.contains("T-01.title"));
                assert!(token.contains("todo"));
            }
            other => panic!("expected Placeholder, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_ellipsis_placeholder() {
        let mut plan = good_plan();
        plan.tasks[0].acceptance = vec!["test ... passes".into()];
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::Placeholder { field, token } => {
                assert!(field.contains("acceptance"));
                assert_eq!(token, "...");
            }
            other => panic!("expected Placeholder, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_see_issue_unlinked() {
        // "see issue #..." with no real issue number is a
        // placeholder per the writing_plans skill rule.
        let mut plan = good_plan();
        plan.tasks[0].evidence = vec!["see issue #...".into()];
        let e = validate_plan(&plan).unwrap_err();
        assert!(matches!(e, PlanValidationError::Placeholder { .. }));
    }

    #[test]
    fn validate_rejects_empty_acceptance_list() {
        let mut plan = good_plan();
        plan.tasks[0].acceptance.clear();
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::EmptyAcceptance { task_id } => {
                assert_eq!(task_id, "T-01");
            }
            other => panic!("expected EmptyAcceptance, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_evidence_list() {
        let mut plan = good_plan();
        plan.tasks[1].evidence.clear();
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::EmptyEvidence { task_id } => {
                assert_eq!(task_id, "T-02");
            }
            other => panic!("expected EmptyEvidence, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_title() {
        let mut plan = good_plan();
        plan.tasks[0].title = "   ".into();
        let e = validate_plan(&plan).unwrap_err();
        match e {
            PlanValidationError::EmptyTitle { task_id } => {
                assert_eq!(task_id, "T-01");
            }
            other => panic!("expected EmptyTitle, got {other:?}"),
        }
    }

    #[test]
    fn plan_size_serialises_uppercase() {
        // Pin the wire form — S/M/L not s/m/l.
        assert_eq!(serde_json::to_string(&PlanSize::S).unwrap(), "\"S\"");
        assert_eq!(serde_json::to_string(&PlanSize::M).unwrap(), "\"M\"");
        assert_eq!(serde_json::to_string(&PlanSize::L).unwrap(), "\"L\"");
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = good_plan();
        let json = serde_json::to_string(&plan).unwrap();
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn placeholder_detection_is_case_insensitive() {
        let mut plan = good_plan();
        plan.scope = "Build the FIXME cleanup pass".into();
        let e = validate_plan(&plan).unwrap_err();
        assert!(matches!(e, PlanValidationError::Placeholder { .. }));
    }

    #[test]
    fn placeholder_tokens_are_pinned_at_known_count() {
        // Pin so a future contributor adding a token surfaces the
        // change in this test — the list is the operator-visible
        // contract.
        assert_eq!(PLACEHOLDER_TOKENS.len(), 15);
    }
}
