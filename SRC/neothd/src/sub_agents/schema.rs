//! Sub-agent TOML schema — Phase 30 R-18 SA-1.
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

use serde::Deserialize;

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
    /// Disable an override without deleting the file.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl SubAgent {
    /// True if this agent is allowed to call `tool_name`.
    pub fn allows_tool(&self, tool_name: &str) -> bool {
        self.tools.iter().any(|t| t == tool_name)
    }
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
            enabled: true,
        };
        assert!(!a.allows_tool("anything"));
    }
}
