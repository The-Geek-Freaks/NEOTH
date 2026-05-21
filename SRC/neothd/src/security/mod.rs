//! Security gates that run before any inbound channel message touches the
//! WAL, the LLM provider, or any pipeline stage downstream of the channel
//! adapter.
//!
//! Per `memory/neoth-research-synthesis.md` (Phase 11a): the ingress sanitizer
//! is the highest-risk shortcut to skip — every operator-facing message goes
//! through it first. Skipping = memory-poisoning surface wide open.

pub mod ingress_sanitizer;
pub mod redact;
pub mod refusal_cause;
pub mod refusal_detect;
pub mod refusal_recovery;
pub mod refusal_reframings;
