//! Live multi-hemisphere Council runtime.
//!
//! Both local chat and channel dispatch use the smart trigger before routing
//! eligible prompts to Left, Right, and Cerebellum in parallel. The shared
//! orchestrator enforces call/depth budgets, scores dissent and response
//! quality, checks verified ground truth, supports bounded fractal depth, and
//! produces the typed debate consumed by winner selection, callosum recovery,
//! self-reflection, transparent diagnostics, and WAL audit emission at the
//! dispatch boundary.
//!
//! Trigger thresholds, extra dissent markers, topology, budget caps, factual
//! injection, reflection, and debug surfaces are operator-configurable. Pure
//! helpers remain deterministic; provider calls and durable audit writes stay
//! in their explicit runtime callers.

pub mod budget;
pub mod callosum;
pub(crate) mod daily_budget;
pub mod day_counter;
pub mod dissent;
pub mod diversity;
pub mod eval;
/// Round-3 v0.4 ADV-12 — Council factual-contradiction check using
/// `[GROUND_TRUTH]…[/GROUND_TRUTH]` tags + ground-truth-based
/// scoring (not hemisphere agreement). Structural fix that closes
/// the `test_all_three_agree_and_wrong` adversarial gap — three
/// hemispheres echoing the same wrong fact previously read as
/// "high confidence" (0 dissent); now the ground-truth check
/// catches it independently.
pub mod factual_check;
pub mod last_ts;
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
pub mod nspace;
pub mod orchestrator;
pub mod qa_verdict;
pub mod quality_score;
pub mod self_challenge;
pub mod self_reflect;
/// GOLD-ADAPT-KB-02 — independent judge for autonomous-loop stop conditions.
/// Gates `Action::AgentStop` at autonomy ≥ Elevated through a deterministic,
/// LLM-free structural check: every declared `done_criterion` must be covered
/// by the agent's `claimed_evidence` for the stop to be approved.
pub mod stop_verifier;
pub mod transparent;
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
