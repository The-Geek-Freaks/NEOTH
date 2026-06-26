//! Sub-agent TOML schema — Phase 30 R-18 SA-1.
//!
//! ## QM-5 NEXUS handoff schema (2026-05-22)
//!
//! In addition to the static `SubAgent` config shape, this module now
//! also ships [`SubAgentRequest`] + [`SubAgentResult`] — the runtime
//! payload that flows between Cerebellum → Left/Right hemispheres and
//! between successive sub-agents in a coding-workflow chain. Adopted
//! verbatim from the NEXUS handoff pattern documented in
//! `PLAN/QUELLEN_ADOPT_agency_2026-05-21.md` §4: every transfer carries
//! `from / to / phase / task_id / priority / context / success_criteria /
//! deliverable / evidence_required`. Returns carry `verdict` (typed via
//! [`crate::council::qa_verdict::QaVerdict`] from QM-6) + `evidence` +
//! `next_agent` so the dispatcher loop has structured pass/fail/blocked
//! semantics instead of free-form prose.
//!
//! ```toml
//! # ~/.neoth/agents/code-reviewer.toml
//! name        = "code-reviewer"
//! description = "Review code for bugs, style, and security"
//! model       = "claude-opus-4-7"           # optional — falls back to default
//! system      = """
//! You are a senior software engineer. Review the supplied code for:
//! ...
//! """
//! tools       = ["recall", "ctx_search"]    # tool allowlist
//! enabled     = true
//! ```
//!
//! Tools listed in `tools` must match the names the daemon's tool registry
//! exposes. Unknown tool names log + skip at dispatch time, they don't
//! fail validation — operator-typo recovery without daemon restart.

use serde::{Deserialize, Serialize};

use crate::council::qa_verdict::QaVerdict;

/// GOLD-ADAPT-OH-13 — per-agent context-layer omission flags.
///
/// Each flag controls whether the corresponding enrichment layer is OMITTED
/// when the agent fires (true = omit, false = keep). Defaults mirror OH's
/// intent: everything except the moral core is omitted by default (the agent
/// supplies its own system prompt and doesn't need the operator's profile /
/// recall / MCP catalogue), but the moral-core safety layer stays injected
/// so agents can't silently drop the operator's position-0 directives.
///
/// Operators override these in their agent TOML:
/// ```toml
/// omit_moral_core = true        # opts the agent out of the moral-core layer
/// omit_operator_context = false # keeps the operator context for this agent
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentOmitFlags {
    /// Omit the `operator_context` enrichment layer (identity + memory context).
    pub operator_context: bool,
    /// Omit the `mcp_catalogue` enrichment layer.
    pub mcp_catalogue: bool,
    /// Omit the `moral_core` enrichment layer (position-0 directives).
    /// Defaults to `false` — moral core stays injected for safety.
    pub moral_core: bool,
    /// Omit the `preset_addendum` enrichment layer (profile preset delta).
    pub preset: bool,
    /// Omit the recall block (Block::D memory episodes).
    pub recall: bool,
    /// Omit the `repo_context_block` enrichment layer.
    pub repo_context: bool,
}

/// One sub-agent definition. Either operator-defined (TOML) or built-in
/// (returned by [`super::builtins::built_in_agents`]).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SubAgent {
    /// Stable identifier. Used by `/agent <name>` dispatch + `delegate_to`
    /// in skill manifests. Override resolution: same-name operator entry
    /// wins over a built-in.
    pub name: String,
    /// One-line description shown by `/agent list`.
    pub description: String,
    /// Model preference for this sub-agent. `None` → daemon falls back to
    /// `freedom.yaml::provider_model`.
    #[serde(default)]
    pub model: Option<String>,
    /// System prompt replaces the operator's per-turn system block when
    /// the sub-agent activates. Multi-line. No `{args}` substitution
    /// (sub-agents see the user message as the prompt body, not via the
    /// system prompt).
    pub system: String,
    /// Names of host tools this sub-agent is allowed to call. Empty list
    /// or `None` means "no tools" (provider-only). Phase 30 wires this
    /// into the tool dispatcher when host tools land.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Names of host tools this sub-agent is explicitly FORBIDDEN from
    /// calling, even if the server-level `allow_tools` list permits them.
    /// Takes priority over `tools` allow-list — if a tool appears in both,
    /// the denylist wins. Operators use this to harden a sub-agent's blast
    /// radius without rewriting the server-level gate.
    ///
    /// ```toml
    /// disallowedTools = ["shell_exec", "file_write"]
    /// ```
    #[serde(default, rename = "disallowedTools")]
    pub disallowed_tools: Vec<String>,
    /// Disable an override without deleting the file.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    // ── GOLD-ADAPT-OH-13: per-agent context-layer omission flags ────────────
    /// Omit the `operator_context` enrichment layer for this agent.
    /// Default: true (agents get their own system; operator context excluded).
    #[serde(default = "default_true")]
    pub omit_operator_context: bool,
    /// Omit the `mcp_catalogue` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_mcp_catalogue: bool,
    /// Omit the `moral_core` enrichment layer for this agent.
    /// Default: false — moral core stays injected for safety by default.
    #[serde(default)]
    pub omit_moral_core: bool,
    /// Omit the `preset_addendum` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_preset: bool,
    /// Omit the recall block (Block::D memory episodes) for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_recall: bool,
    /// Omit the `repo_context_block` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_repo_context: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

impl SubAgent {
    /// True if this agent is allowed to call `tool_name`.
    pub fn allows_tool(&self, tool_name: &str) -> bool {
        self.tools.iter().any(|t| t == tool_name)
    }

    /// True if this agent's denylist forbids `tool_name`.
    /// The denylist WINS over the allow-list: a tool in both is denied.
    pub fn denies_tool(&self, tool_name: &str) -> bool {
        self.disallowed_tools.iter().any(|t| t == tool_name)
    }

    /// GOLD-ADAPT-OH-13 — convert this agent's `omit_*` TOML fields into
    /// the typed [`AgentOmitFlags`] struct used by the enrichment rebuild.
    pub fn to_omit_flags(&self) -> AgentOmitFlags {
        AgentOmitFlags {
            operator_context: self.omit_operator_context,
            mcp_catalogue: self.omit_mcp_catalogue,
            moral_core: self.omit_moral_core,
            preset: self.omit_preset,
            recall: self.omit_recall,
            repo_context: self.omit_repo_context,
        }
    }
}

// ─── QM-5 NEXUS handoff types ───────────────────────────────────────────────

/// Handoff priority. NEXUS spec uses Low/Normal/High/Critical; ports
/// verbatim so operators familiar with the NEXUS taxonomy don't have
/// to relearn it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffPriority {
    Low,
    Normal,
    High,
    Critical,
}

impl Default for HandoffPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// One-shot work item flowing FROM one agent TO another. Replaces the
/// pre-QM-5 implicit handoff (just task text + WAL frame) with a
/// structured contract.
///
/// Wire serialised as JSON for two reasons:
///   1. WAL frames live in `0x7X` event band (coding workflow) and
///      already carry JSON payloads.
///   2. The `neoth code show <task>` operator surface renders the
///      request structure for grep-friendly diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentRequest {
    /// Sender agent id — `"cerebellum"`, `"left"`, `"right"`, or any
    /// operator-defined sub-agent name from [`SubAgent::name`].
    pub from: String,
    /// Recipient agent id.
    pub to: String,
    /// Workflow phase — `"plan"` / `"implementation"` / `"verify"` /
    /// `"merge"`. Operator-readable; the dispatcher doesn't enforce a
    /// fixed enum so future phases don't need a schema bump.
    pub phase: String,
    /// Stable task identifier — typically `idx_kanban_*.task_id`.
    pub task_id: String,
    /// Urgency — drives dispatcher scheduling (`Critical` preempts
    /// in-flight Low/Normal work; default `Normal`).
    #[serde(default)]
    pub priority: HandoffPriority,
    /// Free-form context for the recipient — current state, relevant
    /// files, dependencies. NEXUS calls this `current_state`.
    pub context: String,
    /// What the recipient must produce — patch, test plan, verdict,
    /// summary. NEXUS calls this `deliverable`.
    pub deliverable: String,
    /// Acceptance criteria the deliverable must satisfy. Recipient's
    /// QA verdict (`SubAgentResult::verdict`) checks these. Empty
    /// list means "no formal criteria" — recipient applies its own
    /// judgment.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// What evidence the recipient must include in its response.
    /// `cargo test` output, `file:line` citations, etc. Drives the
    /// EvidenceCollector sub-agent's verification pass.
    #[serde(default)]
    pub evidence_required: Vec<String>,
    /// Wall-clock seconds when the handoff was created. Used for
    /// stale-handoff detection (a 24h-old Critical request that
    /// hasn't been picked up flags an operator alert).
    pub ts_unix: i64,
}

/// Response from a sub-agent back to its caller (typically Cerebellum)
/// or forward to the next sub-agent in the chain. The verdict field
/// carries the structured PASS/FAIL/BLOCKED outcome from QM-6
/// (`QaVerdict`) so the dispatcher's retry path has typed routing
/// instead of free-form text parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentResult {
    /// The sub-agent that produced this result.
    pub from: String,
    /// Intended recipient — usually `"cerebellum"`, sometimes a peer.
    pub to: String,
    /// Mirrors the originating `SubAgentRequest::task_id` so the
    /// dispatcher can correlate handoffs across the chain.
    pub task_id: String,
    /// Structured pass/fail/blocked. Pass → merge, Fail → retry path
    /// consumes the failure items, Blocked → escalate to operator.
    pub verdict: QaVerdict,
    /// Free-form evidence the sub-agent collected — `cargo test`
    /// excerpts, screenshots, log lines, citations. Operators see
    /// this in `neoth code show <task>`.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// Optional pointer to the next sub-agent in the chain. `Some`
    /// for Dev → QA handoffs; `None` for terminal results that close
    /// the kanban row.
    #[serde(default)]
    pub next_agent: Option<String>,
    /// Wall-clock seconds when the result was emitted.
    pub ts_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_agent() {
        let toml_src = r#"
            name = "planner"
            description = "Plan complex changes"
            system = "You are a planner."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.name, "planner");
        assert!(a.enabled);
        assert!(a.model.is_none());
        assert!(a.tools.is_empty());
    }

    #[test]
    fn parses_full_agent_with_tools() {
        let toml_src = r#"
            name = "reviewer"
            description = "Review"
            model = "claude-opus-4-7"
            system = "Be thorough."
            tools = ["recall", "ctx_search", "groundtruth_list"]
            enabled = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(a.tools.len(), 3);
        assert!(a.allows_tool("recall"));
        assert!(!a.allows_tool("nope"));
    }

    #[test]
    fn disabled_round_trips() {
        let toml_src = r#"
            name = "off"
            description = "Disabled"
            system = "noop"
            enabled = false
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(!a.enabled);
    }

    #[test]
    fn empty_tools_means_no_tools() {
        let a = SubAgent {
            name: "n".into(),
            description: "d".into(),
            model: None,
            system: "s".into(),
            tools: vec![],
            disallowed_tools: vec![],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        };
        assert!(!a.allows_tool("anything"));
    }

    #[test]
    fn denies_tool_returns_true_for_listed_tool() {
        let a = SubAgent {
            name: "n".into(),
            description: "d".into(),
            model: None,
            system: "s".into(),
            tools: vec!["safe_tool".into(), "dangerous_tool".into()],
            disallowed_tools: vec!["dangerous_tool".into()],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        };
        assert!(a.denies_tool("dangerous_tool"), "listed tool must be denied");
        assert!(!a.denies_tool("safe_tool"), "non-listed tool must not be denied");
    }

    #[test]
    fn disallowed_tools_parsed_from_toml() {
        let toml_src = r#"
            name = "hardened"
            description = "Hardened agent"
            system = "Be careful."
            tools = ["shell_exec", "file_read", "file_write"]
            disallowedTools = ["shell_exec", "file_write"]
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.disallowed_tools, vec!["shell_exec", "file_write"]);
        assert!(a.denies_tool("shell_exec"));
        assert!(a.denies_tool("file_write"));
        assert!(!a.denies_tool("file_read"));
    }

    #[test]
    fn disallowed_tools_defaults_empty_when_absent() {
        let toml_src = r#"
            name = "plain"
            description = "No denylist"
            system = "Normal agent."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(a.disallowed_tools.is_empty());
        assert!(!a.denies_tool("anything"));
    }

    // ── GOLD-ADAPT-OH-13: omit_ flag tests ─────────────────────────────

    #[test]
    fn omit_flags_default_to_true_for_all_but_moral_core() {
        // A minimal TOML with no omit_ fields must produce omit=true for all
        // context layers EXCEPT moral_core, which defaults to false.
        let toml_src = r#"
            name = "planner2"
            description = "Plan"
            system = "Be a planner."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(a.omit_operator_context, "omit_operator_context must default true");
        assert!(a.omit_mcp_catalogue, "omit_mcp_catalogue must default true");
        assert!(a.omit_preset, "omit_preset must default true");
        assert!(a.omit_recall, "omit_recall must default true");
        assert!(a.omit_repo_context, "omit_repo_context must default true");
        assert!(!a.omit_moral_core, "omit_moral_core must default false (safety layer stays in)");
    }

    #[test]
    fn omit_moral_core_can_be_set_true_in_toml() {
        let toml_src = r#"
            name = "bare-agent"
            description = "No moral core"
            system = "raw system"
            omit_moral_core = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(flags.moral_core, "to_omit_flags must propagate omit_moral_core=true");
    }

    #[test]
    fn omit_operator_context_false_in_toml() {
        let toml_src = r#"
            name = "context-agent"
            description = "Wants operator context"
            system = "use context"
            omit_operator_context = false
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(!flags.operator_context);
        assert!(!flags.moral_core, "moral_core still false by default");
    }

    #[test]
    fn to_omit_flags_round_trips_all_fields() {
        let toml_src = r#"
            name = "full-omit"
            description = "Everything omitted"
            system = "agent"
            omit_operator_context = true
            omit_mcp_catalogue = true
            omit_moral_core = true
            omit_preset = true
            omit_recall = true
            omit_repo_context = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(flags.operator_context);
        assert!(flags.mcp_catalogue);
        assert!(flags.moral_core);
        assert!(flags.preset);
        assert!(flags.recall);
        assert!(flags.repo_context);
    }

    // ── QM-5 NEXUS handoff tests ────────────────────────────────────────

    #[test]
    fn nexus_request_round_trips_through_json() {
        let r = SubAgentRequest {
            from: "cerebellum".into(),
            to: "right".into(),
            phase: "implementation".into(),
            task_id: "T-42".into(),
            priority: HandoffPriority::High,
            context: "refactor the WAL writer to use io_uring".into(),
            deliverable: "diff against main + cargo test green".into(),
            success_criteria: vec![
                "no clippy warnings".into(),
                "writer_recovers_torn_tail still passes".into(),
            ],
            evidence_required: vec!["paste cargo test output".into()],
            ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"priority\":\"high\""));
        let back: SubAgentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn nexus_result_with_pass_verdict_round_trips() {
        let res = SubAgentResult {
            from: "right".into(),
            to: "cerebellum".into(),
            task_id: "T-42".into(),
            verdict: QaVerdict::pass_with_evidence(vec!["1450 tests pass".into()]),
            evidence: vec!["cargo test output: 1450 / 0".into()],
            next_agent: Some("evidence_collector".into()),
            ts_unix: 1_700_000_500,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"kind\":\"pass\""));
        let back: SubAgentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, back);
        assert!(back.verdict.is_pass());
    }

    #[test]
    fn nexus_result_with_fail_verdict_round_trips() {
        use crate::council::qa_verdict::FailureItem;
        let res = SubAgentResult {
            from: "left".into(),
            to: "cerebellum".into(),
            task_id: "T-99".into(),
            verdict: QaVerdict::fail(vec![FailureItem {
                kind: "test_failure".into(),
                message: "ArithmeticError in line 88".into(),
                citation: Some("src/math.rs:88".into()),
            }]),
            evidence: vec!["cargo test failed".into()],
            next_agent: None,
            ts_unix: 1_700_001_000,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert!(json.contains("\"kind\":\"fail\""));
        let back: SubAgentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, back);
        assert!(back.verdict.is_retriable());
    }

    #[test]
    fn handoff_priority_round_trips_serde() {
        for p in [
            HandoffPriority::Low,
            HandoffPriority::Normal,
            HandoffPriority::High,
            HandoffPriority::Critical,
        ] {
            let s = serde_json::to_string(&p).unwrap();
            let back: HandoffPriority = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn handoff_priority_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&HandoffPriority::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffPriority::Normal).unwrap(),
            "\"normal\""
        );
    }

    #[test]
    fn nexus_request_defaults_keep_optional_lists_empty() {
        let minimal = r#"{
            "from": "ce",
            "to": "left",
            "phase": "plan",
            "task_id": "T-1",
            "priority": "normal",
            "context": "x",
            "deliverable": "y",
            "ts_unix": 1
        }"#;
        let r: SubAgentRequest = serde_json::from_str(minimal).unwrap();
        assert!(r.success_criteria.is_empty());
        assert!(r.evidence_required.is_empty());
    }
}
