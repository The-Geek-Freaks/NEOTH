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

pub mod attachment_context;
pub mod enriched_request;
/// GOLD-R3-14 — typed, canonical, length-bound untrusted prompt data.
pub mod untrusted_context;
/// Deprecated pre-v1 string API; delegates to [`untrusted_context`].
pub mod untrusted_wrap;

pub use attachment_context::{
    AttachmentContentKind, AttachmentContextBatch, AttachmentContextError, AttachmentContextInput,
    AttachmentContextLimits, AttachmentOrigin, build_attachment_contexts,
};
pub use enriched_request::{
    CommunicationProfilePrompt, EnrichedRequest, EnrichmentInputs, build_enriched_request,
};
pub use untrusted_context::{
    RenderedUntrustedContext, StableSourceId, UntrustedContext, UntrustedContextClass,
};
#[allow(deprecated)]
pub use untrusted_wrap::wrap_untrusted;
