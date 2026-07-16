//! User-profile pipeline — Phase 2 SPEC_proactive_learning.md.
//!
//! Schicht-0 deterministic stages live here. Stage 3 (`profile.extract`)
//! is an LLM call and stays out of this module until the local-inference
//! runtime (D14b) closes its forward-pass + sampling-loop. Stage 6
//! (`profile.apply`) is a Schicht-1 Effect Adapter that emits WAL events
//! into the Hypothalamus band — also Phase-2 work, deferred until the
//! band invariants land in the WAL ingress gate.
//!
//! What ships today:
//!   - `window_extract` — given a trigger event id + turns-back count,
//!     slice prior episodic rows into a [`ConversationWindow`]. Pure
//!     read against `idx_episode`. Used by stage 1 of `profile_learn.yaml`.
//!   - `window_attribute` — given a [`ConversationWindow`], classify
//!     each segment as `UserSpeech` / `QuotedExternal` / `ToolOutput` /
//!     `Ambiguous`. Pure heuristic (regex + first-person ratio + quote
//!     markers). H1 fix: drops quoted/forwarded content before it reaches
//!     the extractor LLM.
//!
//! Both stages are pure functions over typed structs — no WAL writes,
//! no provider calls, no LLM, no I/O outside the SQLite reader.

pub mod apply;
/// ADV-03 item 4 (Session 24): Stage-5b operator-confirmation gate
/// between `claim_guard` (Stage 5) and `apply_delta` (Stage 6). When
/// `profile.require_approval = true` AND `AutonomyLevel != Full`,
/// the extracted `ProfileDelta` either prompts the operator
/// interactively (tty present) or parks in `idx_profile_pending` for
/// `neoth profile approve/decline` (daemon mode).
pub mod approval_gate;
pub mod baseline_diff;
pub mod baseline_snapshot;
pub mod briefing_gate;
pub mod briefing_policy;
pub mod claim_guard;
pub mod communication;
pub mod delta;
pub mod estimators;
pub mod extension_registry;
pub mod extract;
pub mod fact_check;
pub mod injection;
pub mod inline_extract_trigger;
pub mod lookup;
pub mod presets;
pub mod redaction;
pub mod relative_time;
pub mod runner;
pub mod self_dev;
pub mod snapshot;
/// Round-3 v0.4 G-02 — "Knows things about you you don't know"
/// proactive surfacing. Finds active high-confidence claims newer
/// than the cron window + turns them into ProactiveItems that flow
/// through the G-01 consumer drain → JSONL sidecar → channel
/// adapters chain shipped earlier this session.
pub mod surfacing;
pub mod temporal_guard;
pub mod timestamp_check;
pub mod types;
pub mod validate;
pub mod window_attribute;
pub mod window_extract;

#[allow(unused_imports)]
pub use runner::{PipelineConn, PipelineRun, PipelineSkip, run_pipeline};

#[allow(unused_imports)]
pub use timestamp_check::TimestampPolicy;

#[allow(unused_imports)]
pub use extension_registry::TypedExtensionRegistry;

#[allow(unused_imports)]
pub use redaction::{
    Redaction, add as add_redaction, lookup_active as lookup_redaction, revoke as revoke_redaction,
};

#[allow(unused_imports)]
pub use apply::{ApplyOutcome, apply_delta, record_blocked};
#[allow(unused_imports)]
pub use claim_guard::{DailyLlmCounter, GuardConfig, GuardOutcome, GuardReason, ProfileClaimGuard};
#[allow(unused_imports)]
pub use delta::{Contradiction, ProfileDelta, RawClaim};
#[allow(unused_imports)]
pub use extract::extract as extract_delta;
#[allow(unused_imports)]
pub use types::{
    AttributedSegment, AttributedWindow, Attribution, ConversationSegment, ConversationWindow,
    SegmentOrigin,
};
#[allow(unused_imports)]
pub use validate::{DroppedClaim, ValidateError, ValidatedDelta, validate};
#[allow(unused_imports)]
pub use window_attribute::attribute_segments;
#[allow(unused_imports)]
pub use window_extract::extract_window;
