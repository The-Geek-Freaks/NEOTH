//! C_d (tool/agent coupling density) computation.
//!
//! ## Algorithm (C_d_v0)
//!
//! Build a bipartite graph G = (agents ∪ tools, edges) from co-occurrence
//! within 500 ms windows of WAL events:
//!   - `0xC0 MCP_TOOL_CALLED` → tool node
//!   - `0xFC AGENT_DISPATCHED` → agent node
//!   - An edge (agent, tool) is added when a tool call appears within 500 ms
//!     after an agent dispatch of the same session.
//!
//! C_d = |edges| / (|agents| * |tools|)   — bipartite density, range [0,1].
//!
//! When only one agent is active: C_d = |distinct tools called| / total_tools_available.
//!
//! ## WAL event sources
//!
//! Both event types already exist in `wal/events.rs`:
//!   - `EVENT_TYPE_MCP_TOOL_CALLED = 0xC0`
//!   - `EVENT_TYPE_AGENT_DISPATCHED = 0xFC`

/// Co-occurrence window for edge detection (milliseconds).
pub const COOCCURRENCE_WINDOW_MS: i64 = 500;

/// One observed (agent_id, tool_name) co-occurrence.
#[derive(Clone, Debug)]
pub struct CouplingEdge {
    pub agent_id: String,
    pub tool_name: String,
    pub ts_unix_ms: i64,
}

/// Compute bipartite coupling density from a list of edges observed in a window.
///
/// `total_tools_available`: the count of distinct tools exposed by all active MCP
/// servers — used when only one agent is present.
pub fn coupling_density(
    edges: &[CouplingEdge],
    total_tools_available: usize,
) -> f64 {
    let agents: std::collections::HashSet<&str> =
        edges.iter().map(|e| e.agent_id.as_str()).collect();
    let tools: std::collections::HashSet<&str> =
        edges.iter().map(|e| e.tool_name.as_str()).collect();

    let n_agents = agents.len();
    let n_tools = tools.len();

    if n_agents == 0 || n_tools == 0 {
        return 0.0;
    }

    if n_agents == 1 {
        // Single-agent mode: fraction of available tools called
        let denom = total_tools_available.max(1);
        return (n_tools as f64 / denom as f64).clamp(0.0, 1.0);
    }

    // Multi-agent: bipartite edge density
    let distinct_edges: std::collections::HashSet<(&str, &str)> = edges
        .iter()
        .map(|e| (e.agent_id.as_str(), e.tool_name.as_str()))
        .collect();
    let max_edges = (n_agents * n_tools) as f64;
    (distinct_edges.len() as f64 / max_edges).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(agent: &str, tool: &str) -> CouplingEdge {
        CouplingEdge { agent_id: agent.into(), tool_name: tool.into(), ts_unix_ms: 0 }
    }

    #[test]
    fn empty_edges_gives_zero_density() {
        assert_eq!(coupling_density(&[], 10), 0.0);
    }

    #[test]
    fn single_agent_uses_tool_fraction() {
        let edges = vec![edge("a1", "bash"), edge("a1", "read")];
        // 2 tools used of 10 available
        let c = coupling_density(&edges, 10);
        assert!((c - 0.2).abs() < 1e-9);
    }

    #[test]
    fn multi_agent_full_bipartite_gives_one() {
        let edges = vec![
            edge("a1", "t1"), edge("a1", "t2"),
            edge("a2", "t1"), edge("a2", "t2"),
        ];
        // 2 agents × 2 tools = 4 max edges, 4 distinct → 1.0
        let c = coupling_density(&edges, 10);
        assert!((c - 1.0).abs() < 1e-9);
    }

    #[test]
    fn multi_agent_partial_gives_correct_density() {
        let edges = vec![
            edge("a1", "t1"),
            edge("a2", "t2"),
        ];
        // 2 agents × 2 tools = 4 max, 2 distinct edges → 0.5
        let c = coupling_density(&edges, 10);
        assert!((c - 0.5).abs() < 1e-9);
    }
}
