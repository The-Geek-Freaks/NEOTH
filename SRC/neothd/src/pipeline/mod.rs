//! Pipeline composition primitives shared by CLI + channel paths.
//!
//! Workstream K (K-Wire-3 main, Session 23 — 2026-05-24) factored the
//! enrichment composition out of `cli/chat.rs::run_chat_with` so the
//! channel-side `cli/serve.rs::build_pipeline_handler` can reach the
//! same operator-context layering as `neoth chat` without duplicating
//! the 200-line layering logic.
//!
//! ## What lives here
//!
//! - [`enriched_request::build_enriched_request`] — deterministic
//!   composition of operator_md + typed communication preferences +
//!   repo_context + skill + MCP + persona blocks into a single
//!   `EnrichedRequest`. Pure sync; the
//!   caller is responsible for any async I/O (FS reads, MCP server
//!   `tools/list`, embedding provider invocation) and hands the
//!   already-assembled string blocks to the helper.
//!
//! ## What does NOT live here
//!
//! - Slash command dispatch (CLI-only built-in actions; channel-side
//!   uses the same slash registry but its action surface differs).
//! - Karpathy metacognitive preamble injection (CLI-only Q1 ship —
//!   channel adoption is a separate operator decision).
//! - Provider call execution + WAL audit framing. That stays in the
//!   call-site files because the audit envelopes carry path-specific
//!   metadata (channel vs CLI).

pub mod enriched_request;
/// GOLD-ADAPT-ODY-18 — untrusted-source-data sandbox (`<<<UNTRUSTED_SOURCE_DATA>>>`
/// guard + policy preamble + marker-injection defang) applied to external tool
/// output before it re-enters the LLM prompt.
pub mod untrusted_wrap;

pub use enriched_request::{
    CommunicationProfilePrompt, EnrichedRequest, EnrichmentInputs, build_enriched_request,
};
pub use untrusted_wrap::wrap_untrusted;
