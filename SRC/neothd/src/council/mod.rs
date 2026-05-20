//! Council debate primitive — Phase 2 architecture foundation.
//!
//! NEOTH's "Council" is the multi-hemisphere debate pattern: a prompt
//! gets routed to all three configured hemispheres in parallel (Left
//! analytic / Right creative / Cerebellum router), their responses are
//! collected, dissent is scored, and a verdict is produced. The
//! design rationale is `SPEC_council_governance.md`; this module
//! ships the orchestrator + scoring primitives so the chat dispatch
//! (CH-04 follow-up) can opt into council mode on a per-call basis.
//!
//! What's here today:
//!   - [`HemisphereResponse`] — one provider's reply with timing + tokens
//!   - [`CouncilDebate`] — the aggregate: three responses + dissent + verdict
//!   - [`DissentScore`] — operator-readable disagreement metric (0.0-1.0)
//!   - [`run_debate`] — fires the three providers in parallel, builds the
//!     debate record. Pure logic; no WAL emission (caller's job).
//!
//! Deferred (explicit follow-ups, not shipped today):
//!   - Council adversarial test suite `test_all_three_agree_and_wrong`
//!     (CH-03 GROUND_TRUTH_TAG injection).
//!   - Council adaptive thresholds (CH-12).
//!   - Council smart-trigger logic (CH-14: complexity + dissent + rate
//!     + budget gates that decide WHEN to convene the council vs use
//!       single-hemisphere chat).
//!   - Block-B profile injection / Block-C recall ranking integration
//!     (CH-09/10/11) — those layer on top of `run_debate` once the
//!     dispatch path consumes it.

pub mod budget;
pub mod callosum;
pub mod dissent;
pub mod diversity;
pub mod eval;
pub mod last_ts;
pub mod orchestrator;
pub mod quality_score;
pub mod self_reflect;
pub mod trigger;
pub mod types;

#[allow(unused_imports)]
pub use budget::{BudgetExhausted, BudgetToken};
#[allow(unused_imports)]
pub use callosum::{CorticalVerdict, resolve};
#[allow(unused_imports)]
pub use dissent::{DissentScore, score_dissent};
#[allow(unused_imports)]
pub use diversity::{DiversityVerdict, classify_council_diversity};
#[allow(unused_imports)]
pub use eval::{EvalOutcome, FIXTURES, FixtureCategory, GroundTruthFixture, verify};
#[allow(unused_imports)]
pub use orchestrator::{run_debate, run_debate_with_depth, run_debate_with_depth_budget};
#[allow(unused_imports)]
pub use trigger::{TriggerContext, TriggerDecision, TriggerPolicy, should_convene};
#[allow(unused_imports)]
pub use types::{CouncilDebate, HemisphereResponse, Verdict};
