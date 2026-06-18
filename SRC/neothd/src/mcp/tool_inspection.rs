//! GOLD-ADAPT-GOOSE-02 — pluggable tool-inspection chain.
//!
//! Port of goose's `ToolInspector` trait + inspector vector
//! (`crates/goose/src/agents/tool_inspection.rs`): the pre-dispatch safety
//! checks run as an ordered chain of [`ToolInspector`]s instead of a
//! hand-wired sequence inside [`crate::mcp::dispatch_loop`]. Each inspector
//! returns a typed [`InspectorVerdict`]; the chain returns the FIRST block,
//! preserving the historical order (repetition guard, then risk policy).
//!
//! ## Scope (deliberate, security-reviewed)
//!
//! The chain DECIDES "is this call blocked, and why" — it computes the
//! repetition verdict (GOLD-ADOPT-20) and the dangerous-command/egress risk
//! verdict (GOLD-ADOPT-23). It does NOT perform the NEOTH-specific
//! risk-confirm LEASE lift or the distinct WAL audit emits: those are async +
//! stateful authorization side-effects (filesystem leases, the WAL writer),
//! not a pure inspection, so they stay in the dispatch loop, driven by the
//! [`BlockKind::Risk`] payload the chain hands back. The allowlist / autonomy
//! / SmartApprove checks likewise stay in [`crate::mcp::gate::invoke_with_audit`]
//! (they need the live `McpClient`). A new PURE safety check bolts on by
//! implementing [`ToolInspector`] and pushing it into the chain.

use crate::config::SecurityPolicy;
use crate::mcp::repetition_guard::{GuardVerdict, ToolRepetitionGuard};
use crate::mcp::tool_call_parser::ParsedToolCall;
use crate::security::risk_gate::{RiskGate, evaluate_tool_risk};
use crate::security::{ToolCallRisk, inspect_tool_args};

/// One inspector's decision for a prospective tool call.
pub enum InspectorVerdict {
    /// No objection from this inspector.
    Allow,
    /// Block the call. `inspector` names the source for logging/audit.
    Block {
        inspector: &'static str,
        kind: BlockKind,
    },
}

/// The typed payload behind a block, so the dispatch loop can act with the
/// full context the original inline code had.
pub enum BlockKind {
    /// Stuck-loop guard tripped — carries the verdict for the LLM notice.
    Repetition(GuardVerdict),
    /// Dangerous-command / egress risk gate tripped — carries the findings +
    /// the base gate so the loop can run the lease-lift + distinct WAL emit.
    Risk { risk: ToolCallRisk, gate: RiskGate },
}

/// A pre-dispatch safety check. `Send` so the chain can be held across the
/// dispatch loop's `.await` points.
pub trait ToolInspector: Send {
    /// Stable name for logs/audit.
    fn name(&self) -> &'static str;
    /// Judge ONE prospective call. Called exactly once per dispatch attempt
    /// (a stateful inspector, e.g. the repetition guard, records the attempt).
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict;
}

/// Stuck-loop guard as an inspector (GOLD-ADOPT-20).
pub struct RepetitionInspector(pub ToolRepetitionGuard);

impl ToolInspector for RepetitionInspector {
    fn name(&self) -> &'static str {
        "repetition"
    }
    fn inspect(&mut self, call: &ParsedToolCall, _policy: &SecurityPolicy) -> InspectorVerdict {
        let v = self.0.check(call);
        if v.is_blocked() {
            InspectorVerdict::Block {
                inspector: "repetition",
                kind: BlockKind::Repetition(v),
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Dangerous-command + egress risk policy as an inspector (GOLD-ADOPT-23).
/// Computes the verdict + surfaces every finding (tracing warn) exactly as the
/// pre-chain loop did; the lease-lift + WAL emits stay in the loop.
pub struct RiskPolicyInspector;

impl ToolInspector for RiskPolicyInspector {
    fn name(&self) -> &'static str {
        "risk_policy"
    }
    fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        let risk = inspect_tool_args(&call.arguments);
        if risk.is_empty() {
            return InspectorVerdict::Allow;
        }
        // GOLD-ADOPT-23 P0 — ALWAYS surface dangerous + egress findings, even
        // when the policy is warn-only and the gate ends up Allow.
        for d in &risk.dangerous {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                rule = d.id, severity = d.severity.as_str(),
                "dangerous-command pattern in tool call: {}", d.reason
            );
        }
        for e in &risk.egress {
            tracing::warn!(
                server = %call.server, tool = %call.tool,
                kind = %e.kind, domain = %e.domain,
                "outbound egress destination in tool call"
            );
        }
        let gate = evaluate_tool_risk(&risk, policy);
        if gate.is_blocked() {
            InspectorVerdict::Block {
                inspector: "risk_policy",
                kind: BlockKind::Risk { risk, gate },
            }
        } else {
            InspectorVerdict::Allow
        }
    }
}

/// Ordered chain of inspectors. The FIRST block wins (historical order:
/// repetition guard, then risk policy — so a repeated call is never also
/// risk-inspected, matching the pre-chain `continue`).
pub struct ToolInspectorChain {
    inspectors: Vec<Box<dyn ToolInspector>>,
}

impl ToolInspectorChain {
    /// The shipped chain: repetition guard (defaults) + risk policy.
    pub fn with_defaults() -> Self {
        Self {
            inspectors: vec![
                Box::new(RepetitionInspector(ToolRepetitionGuard::with_defaults())),
                Box::new(RiskPolicyInspector),
            ],
        }
    }

    /// Build from an explicit inspector list (tests / future custom chains).
    pub fn new(inspectors: Vec<Box<dyn ToolInspector>>) -> Self {
        Self { inspectors }
    }

    /// Run inspectors in order; return the FIRST block, else `Allow`. Every
    /// inspector up to (and including) the first blocker is run, so stateful
    /// inspectors before the blocker still record the attempt.
    pub fn inspect(&mut self, call: &ParsedToolCall, policy: &SecurityPolicy) -> InspectorVerdict {
        for insp in self.inspectors.iter_mut() {
            match insp.inspect(call, policy) {
                InspectorVerdict::Allow => continue,
                block => return block,
            }
        }
        InspectorVerdict::Allow
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

    fn policy() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    #[test]
    fn clean_call_passes_the_whole_chain() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "notes.md" }));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Allow
        ));
    }

    #[test]
    fn repetition_inspector_blocks_a_repeated_call() {
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("fs", "read", serde_json::json!({ "path": "a" }));
        // Defaults: a 4th identical call in a row blocks.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Allow
            ));
        }
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Repetition(_),
            } => {
                assert_eq!(inspector, "repetition")
            }
            _ => panic!("expected a repetition block on the 4th identical call"),
        }
    }

    #[test]
    fn risk_inspector_blocks_a_dangerous_command_under_default_deny() {
        let mut chain = ToolInspectorChain::with_defaults();
        // The default dangerous-command policy is Deny.
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        match chain.inspect(&c, &policy()) {
            InspectorVerdict::Block {
                inspector,
                kind: BlockKind::Risk { gate, .. },
            } => {
                assert_eq!(inspector, "risk_policy");
                assert!(gate.is_blocked());
            }
            _ => panic!("expected a risk block for a dangerous command"),
        }
    }

    #[test]
    fn repetition_is_checked_before_risk() {
        // A call that is BOTH repeated past the threshold AND dangerous must
        // surface as a Repetition block (repetition runs first), never Risk.
        let mut chain = ToolInspectorChain::with_defaults();
        let c = call("sh", "exec", serde_json::json!({ "command": "rm -rf /" }));
        // First three are risk-blocks (dangerous), but they also tick the
        // repetition counter; the 4th identical call trips repetition first.
        for _ in 0..3 {
            assert!(matches!(
                chain.inspect(&c, &policy()),
                InspectorVerdict::Block {
                    kind: BlockKind::Risk { .. },
                    ..
                }
            ));
        }
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                kind: BlockKind::Repetition(_),
                ..
            }
        ));
    }

    #[test]
    fn custom_pure_inspector_bolts_on_without_a_loop_edit() {
        // Demonstrates the extensibility seam: a new inspector just implements
        // the trait + joins the chain; the dispatch loop never changes.
        struct DenyAll;
        impl ToolInspector for DenyAll {
            fn name(&self) -> &'static str {
                "deny_all"
            }
            fn inspect(&mut self, _c: &ParsedToolCall, _p: &SecurityPolicy) -> InspectorVerdict {
                InspectorVerdict::Block {
                    inspector: "deny_all",
                    kind: BlockKind::Repetition(GuardVerdict::Allow),
                }
            }
        }
        let mut chain = ToolInspectorChain::new(vec![Box::new(DenyAll)]);
        let c = call("fs", "read", serde_json::json!({}));
        assert!(matches!(
            chain.inspect(&c, &policy()),
            InspectorVerdict::Block {
                inspector: "deny_all",
                ..
            }
        ));
    }
}
