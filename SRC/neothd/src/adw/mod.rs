//! Agentic Developer Workflow (ADW) typed artifacts.
//!
//! This module is intentionally staged. W1 defines the Wayfinder handoff
//! contract only; it does not parse maps, start work, dispatch an agent, or
//! claim that a goal has been proven.

pub mod goal;

pub use goal::{
    AcceptanceCriterion, CommandSpec, Constraint, CouncilThreshold, CriterionId, EvidenceKind,
    Goal, GoalError, GoalId, GoalIntentClassification, GoalStatus,
};
