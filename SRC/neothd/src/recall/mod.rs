//! Recall-side helpers separate from the `cli::recall` CLI surface.
//!
//! Today: `citation_check` (QM-18). Future: live citation lookup
//! against Crossref/OpenAlex/Semantic Scholar once the outbound HTTP
//! allowlist extends; cross-reference against `idx_groundtruth`.

pub mod citation_check;
pub mod conversational;
/// ARCH-05 / SPEC-08 — Jarvis→NEOTH recall-parity migration gate. `goldset`
/// (file formats), `parity` (pure kappa/parity/divergence math), `parity_run`
/// (the grade→report aggregator). Consumed by `neoth recall score`.
pub mod goldset;
pub mod parity;
pub mod parity_run;
/// Round-3 v0.4 QU-11 / ARS-6 — multi-session pipeline recovery via
/// the `MODE_CHECKPOINT` WAL frame. Operator-facing entry point is
/// `cli/chat.rs` `resume from <hash>` (small wrapper around
/// [`reconstruct::reconstruct_from_checkpoint`]).
pub mod reconstruct;
