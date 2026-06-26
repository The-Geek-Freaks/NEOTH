//! Conversation/agent-loop context management.
//!
//! GOLD-ADOPT-19 — [`compaction`] is threshold-triggered LLM summarization of
//! the MCP tool-dispatch loop's accumulated prompt. The loop accumulates every
//! prior turn (assistant replies + tool-result blocks + hints) into one growing
//! `String` (`mcp::dispatch_loop::build_next_prompt`); past a fraction of the
//! token cap that string is replaced by a dense `[CONTEXT SUMMARY]` so a long
//! tool chain doesn't blow the model's context window.

pub mod compaction;
pub mod compactor;
pub mod compress;

pub use compaction::{
    CompactionPolicy, SUMMARY_MARKER, build_compaction_prompt, needs_compaction, wrap_summary,
};
