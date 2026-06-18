//! GOLD-ADOPT-20 — tool-repetition / stuck-loop guard.
//!
//! Port of goose's `RepetitionInspector` (`crates/goose/src/tool_monitor.rs`):
//! a stuck agent loop tends to re-issue the SAME tool call over and over, or
//! hammer one tool far past any plausible need. This guard, threaded through the
//! [`crate::mcp::dispatch_loop`], blocks two failure modes BEFORE the call runs:
//!
//!   1. **Consecutive repetition** — the identical `(server, tool, arguments)`
//!      issued more than `max_consecutive` times in a row.
//!   2. **Per-tool ceiling** — a single `(server, tool)` called more than
//!      `max_per_tool` times across the whole loop, regardless of arguments.
//!
//! A block doesn't execute the tool; the loop feeds the LLM an operator-visible
//! notice so it changes approach (and if every call in a round is blocked, the
//! loop's existing all-failed termination breaks it cleanly).

use std::collections::HashMap;

use crate::mcp::tool_call_parser::ParsedToolCall;

/// Default consecutive-identical ceiling: a 4th identical call in a row blocks.
pub const DEFAULT_MAX_CONSECUTIVE: u32 = 3;

/// Default per-tool total-call ceiling within one loop.
pub const DEFAULT_MAX_PER_TOOL: u32 = 25;

/// The guard's decision for one prospective tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Run the call.
    Allow,
    /// Identical call repeated `count` times in a row (> `max_consecutive`).
    BlockedConsecutive { tool: String, count: u32 },
    /// `tool` exceeded `max_per_tool` total calls this loop (now at `count`).
    BlockedCeiling { tool: String, count: u32 },
}

impl GuardVerdict {
    pub fn is_blocked(&self) -> bool {
        !matches!(self, GuardVerdict::Allow)
    }
}

/// Stateful guard for one [`crate::mcp::dispatch_loop`] invocation. `None` for a
/// limit disables that check.
#[derive(Debug)]
pub struct ToolRepetitionGuard {
    max_consecutive: Option<u32>,
    max_per_tool: Option<u32>,
    /// Last call identity `server::tool::args` (consecutive tracking).
    last_identity: Option<String>,
    repeat_count: u32,
    /// Total calls per `server::tool` (ceiling tracking).
    call_counts: HashMap<String, u32>,
}

impl ToolRepetitionGuard {
    pub fn new(max_consecutive: Option<u32>, max_per_tool: Option<u32>) -> Self {
        Self {
            max_consecutive,
            max_per_tool,
            last_identity: None,
            repeat_count: 0,
            call_counts: HashMap::new(),
        }
    }

    /// The shipped defaults.
    pub fn with_defaults() -> Self {
        Self::new(Some(DEFAULT_MAX_CONSECUTIVE), Some(DEFAULT_MAX_PER_TOOL))
    }

    /// Record + judge a prospective call. Call EXACTLY once per dispatch
    /// attempt (a blocked call still counts toward the per-tool total, so a
    /// model that keeps retrying a ceiling-hit tool stays blocked).
    pub fn check(&mut self, call: &ParsedToolCall) -> GuardVerdict {
        let tool_key = format!("{}::{}", call.server, call.tool);
        let identity = format!("{tool_key}::{}", call.arguments);

        // Per-tool ceiling (counts every attempt, blocked or not).
        let total = {
            let c = self.call_counts.entry(tool_key.clone()).or_insert(0);
            *c += 1;
            *c
        };

        // Consecutive-identical tracking.
        if self.last_identity.as_deref() == Some(identity.as_str()) {
            self.repeat_count += 1;
        } else {
            self.repeat_count = 1;
            self.last_identity = Some(identity);
        }

        if let Some(max) = self.max_per_tool {
            if total > max {
                return GuardVerdict::BlockedCeiling {
                    tool: tool_key,
                    count: total,
                };
            }
        }
        if let Some(max) = self.max_consecutive {
            if self.repeat_count > max {
                return GuardVerdict::BlockedConsecutive {
                    tool: tool_key,
                    count: self.repeat_count,
                };
            }
        }
        GuardVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(server: &str, tool: &str, args: serde_json::Value) -> ParsedToolCall {
        ParsedToolCall {
            server: server.into(),
            tool: tool.into(),
            arguments: args,
        }
    }

    #[test]
    fn allows_up_to_max_consecutive_then_blocks() {
        let mut g = ToolRepetitionGuard::new(Some(3), None);
        let c = call("fs", "read", serde_json::json!({"path": "a"}));
        // 3 identical allowed, the 4th blocks.
        assert_eq!(g.check(&c), GuardVerdict::Allow);
        assert_eq!(g.check(&c), GuardVerdict::Allow);
        assert_eq!(g.check(&c), GuardVerdict::Allow);
        assert!(matches!(
            g.check(&c),
            GuardVerdict::BlockedConsecutive { count: 4, .. }
        ));
    }

    #[test]
    fn differing_args_reset_the_consecutive_run() {
        let mut g = ToolRepetitionGuard::new(Some(2), None);
        let a = call("fs", "read", serde_json::json!({"path": "a"}));
        let b = call("fs", "read", serde_json::json!({"path": "b"}));
        assert_eq!(g.check(&a), GuardVerdict::Allow);
        assert_eq!(g.check(&a), GuardVerdict::Allow);
        // Switching args resets the run, so it doesn't block here.
        assert_eq!(g.check(&b), GuardVerdict::Allow);
        assert_eq!(g.check(&b), GuardVerdict::Allow);
        // Third identical b blocks (> 2).
        assert!(g.check(&b).is_blocked());
    }

    #[test]
    fn per_tool_ceiling_blocks_regardless_of_args() {
        let mut g = ToolRepetitionGuard::new(None, Some(3));
        // Same tool, all DIFFERENT args — consecutive guard never fires, but the
        // per-tool ceiling does.
        for i in 0..3 {
            let c = call("sh", "exec", serde_json::json!({ "cmd": i }));
            assert_eq!(g.check(&c), GuardVerdict::Allow, "call {i}");
        }
        let c = call("sh", "exec", serde_json::json!({ "cmd": 99 }));
        assert!(matches!(
            g.check(&c),
            GuardVerdict::BlockedCeiling { count: 4, .. }
        ));
    }

    #[test]
    fn per_tool_counts_are_independent() {
        let mut g = ToolRepetitionGuard::new(None, Some(2));
        assert_eq!(
            g.check(&call("a", "x", serde_json::json!({}))),
            GuardVerdict::Allow
        );
        assert_eq!(
            g.check(&call("a", "x", serde_json::json!({}))),
            GuardVerdict::Allow
        );
        // Different tool starts its own count.
        assert_eq!(
            g.check(&call("b", "y", serde_json::json!({}))),
            GuardVerdict::Allow
        );
        // 3rd call to a::x trips its ceiling.
        assert!(g.check(&call("a", "x", serde_json::json!({}))).is_blocked());
    }

    #[test]
    fn none_limits_never_block() {
        let mut g = ToolRepetitionGuard::new(None, None);
        let c = call("fs", "read", serde_json::json!({"path": "a"}));
        for _ in 0..1000 {
            assert_eq!(g.check(&c), GuardVerdict::Allow);
        }
    }
}
