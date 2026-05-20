//! Sub-agents — Phase 30 R-18.
//!
//! A sub-agent is a named system prompt + model preference + tool allowlist.
//! Operators (or skills, or slash commands) can route a turn to a sub-agent
//! instead of the default provider call: the sub-agent's system prompt
//! replaces the operator's, and only its allowlisted tools are reachable
//! from the call.
//!
//! Sub-agents are declarative TOML; no Rust code per sub-agent. Built-ins
//! (`code-reviewer`, `security-reviewer`, `planner`) ship in the binary
//! and can be overridden by `~/.neoth/agents/<name>.toml` of the same name.
//!
//! ## Dispatch
//!
//! A sub-agent activates when:
//!   - the operator writes `/agent <name> <message>` (slash dispatch)
//!   - a skill manifest references it via `delegate_to: <name>`
//!   - the daemon programmatically calls `sub_agents::dispatch_to(name, ...)`
//!
//! For v0.1 only the first path is wired; skill delegation lands when the
//! Skills Stage-2 router gets a real embedding re-rank (Day-14b).

pub mod builtins;
pub mod loader;
pub mod review;
pub mod schema;

pub use loader::load_all;
pub use schema::SubAgent;

/// Resolved dispatch — the caller swaps these in for the per-turn system
/// prompt + model preference, and consults `allowed_tools` before letting
/// any host tool call go through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub agent_name: String,
    pub system: String,
    pub model: Option<String>,
    pub allowed_tools: Vec<String>,
    /// The user-facing prompt body — `/agent <name> <body>` strips the
    /// `/agent <name>` prefix and forwards `<body>` here.
    pub prompt: String,
}

/// Parse `/agent <name> <body>` invocations against the loaded set and
/// return the matched `Dispatch` if any. The caller is expected to:
///   1. call this on the raw operator text
///   2. if `Some`, swap `req.system` with `dispatch.system` and `req.prompt`
///      with `dispatch.prompt`
///   3. enforce `dispatch.allowed_tools` if/when host tools land
///
/// Returns `None` when the prefix doesn't match or the named agent
/// doesn't exist — caller passes the original text through unchanged.
pub fn parse_agent_invocation(text: &str, agents: &[SubAgent]) -> Option<Dispatch> {
    let trimmed = text.trim_start();
    let rest = trimmed.strip_prefix("/agent ")?;
    let rest = rest.trim_start();
    let (name, body) = match rest.split_once(char::is_whitespace) {
        Some((n, b)) => (n, b.trim()),
        None => (rest, ""),
    };
    if name.is_empty() {
        return None;
    }
    let agent = agents.iter().find(|a| a.name == name)?;
    Some(Dispatch {
        agent_name: agent.name.clone(),
        system: agent.system.clone(),
        model: agent.model.clone(),
        allowed_tools: agent.tools.clone(),
        prompt: body.to_string(),
    })
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    fn fixture() -> Vec<SubAgent> {
        vec![SubAgent {
            name: "planner".into(),
            description: "d".into(),
            model: Some("opus".into()),
            system: "be a planner".into(),
            tools: vec!["recall".into()],
            enabled: true,
        }]
    }

    #[test]
    fn dispatches_to_named_agent() {
        let agents = fixture();
        let d = parse_agent_invocation("/agent planner build a feature", &agents).unwrap();
        assert_eq!(d.agent_name, "planner");
        assert_eq!(d.system, "be a planner");
        assert_eq!(d.model.as_deref(), Some("opus"));
        assert_eq!(d.allowed_tools, vec!["recall"]);
        assert_eq!(d.prompt, "build a feature");
    }

    #[test]
    fn dispatch_without_body_returns_empty_prompt() {
        let agents = fixture();
        let d = parse_agent_invocation("/agent planner", &agents).unwrap();
        assert_eq!(d.prompt, "");
    }

    #[test]
    fn unknown_agent_returns_none() {
        let agents = fixture();
        assert!(parse_agent_invocation("/agent ghost hello", &agents).is_none());
    }

    #[test]
    fn missing_prefix_returns_none() {
        let agents = fixture();
        assert!(parse_agent_invocation("hello world", &agents).is_none());
        assert!(parse_agent_invocation("/planner hello", &agents).is_none());
    }

    #[test]
    fn leading_whitespace_tolerated() {
        let agents = fixture();
        assert!(parse_agent_invocation("   /agent planner work", &agents).is_some());
    }
}
