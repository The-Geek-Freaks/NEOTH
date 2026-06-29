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

pub mod adaptive_thresholds;
pub mod budget;
pub mod callosum;
pub mod day_counter;
pub mod dissent;
pub mod diversity;
pub mod eval;
/// GOLD-ADAPT-LOWKEY-08 — Dynamic-persona MDS tone modifier.
/// Classifies per-turn input intensity (Low/Medium/High/Urgent) from the
/// raw prompt string and maps it to a tone-hint string appended to the
/// active `persona_override`. Pure-fn over `&str`; no I/O; no WAL event
/// (STDERR-only observability following LOWKEY-05/07 precedent).
pub mod mds_tone;
/// GOLD-ADAPT-LOWKEY-04 — MIF motive-identification pre-step.
/// Classifies operator intent as Stated / Inferred / Conflicted before
/// the hemisphere debate runs.  `Conflicted` gates the debate and
/// surfaces a disambiguation request instead of a confused answer.
pub mod motive_ident;
/// Round-3 v0.4 ADV-12 — Council factual-contradiction check using
/// `[GROUND_TRUTH]…[/GROUND_TRUTH]` tags + ground-truth-based
/// scoring (not hemisphere agreement). Structural fix that closes
/// the `test_all_three_agree_and_wrong` adversarial gap — three
/// hemispheres echoing the same wrong fact previously read as
/// "high confidence" (0 dissent); now the ground-truth check
/// catches it independently.
pub mod factual_check;
pub mod last_ts;
pub mod nspace;
pub mod orchestrator;
pub mod qa_verdict;
pub mod quality_score;
pub mod self_challenge;
pub mod self_reflect;
pub mod transparent;
/// GOLD-ADAPT-KB-02 — independent judge for autonomous-loop stop conditions.
/// Gates `Action::AgentStop` at autonomy ≥ Elevated through a deterministic,
/// LLM-free structural check: every declared `done_criterion` must be covered
/// by the agent's `claimed_evidence` for the stop to be approved.
pub mod stop_verifier;
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
pub use motive_ident::classify_motive;
#[allow(unused_imports)]
pub use orchestrator::{run_debate, run_debate_with_depth, run_debate_with_depth_budget};
#[allow(unused_imports)]
pub use trigger::{TriggerContext, TriggerDecision, TriggerPolicy, should_convene};
#[allow(unused_imports)]
pub use types::{CouncilDebate, HemisphereResponse, MifAnalysis, MifIntent, Verdict};
