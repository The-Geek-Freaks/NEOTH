//! ADOPT-22 — SmartApprove: session-scoped read-only tool cache.
//!
//! [`ReadOnlyCache`] maps `(server_id, tool_name) → is_readonly`,
//!    populated from the server's DECLARED tool annotations
//!    ([`classify_from_annotations`]). Session-scoped: constructed per
//!    `run_tool_loop_with_cap` invocation and discarded afterwards.
//!
//! ## Integration in the gate (as wired in ADOPT-22)
//!
//! `invoke_with_audit` (mcp/gate.rs) receives an `Option<&mut ReadOnlyCache>`
//! (`Some` only when `security.smart_approve` is set). When the autonomy gate
//! returns `Decision::Confirm`, it consults the cache keyed by
//! `(server_id, tool_name)`:
//!
//! ```text
//! is_readonly(server, tool) == Some(true)  → auto-approve, emit
//!                                            RISK_GATE_ALLOWED_BY_READONLY_CACHE
//! is_readonly(server, tool) == Some(false) → normal confirm path
//! is_readonly(server, tool) == None        → fetch the server's tool
//!                                            annotations (sanitised) + seed,
//!                                            then re-check (fail-closed)
//! ```
//!
//! **The auto-approve decision is EFFECT-driven, not name-driven** (operator
//! point 1 — trust-creep guard): the cache is populated ONLY from the server's
//! declared tool annotations ([`classify_from_annotations`]). The earlier
//! name-based LLM judge was removed: it had no production consumer and wiring
//! it would let an adversarial session model influence an authorization gate.
//!
//! ## Security contract
//!
//! - A `true` (read-only) cache entry only upgrades `Decision::Confirm →
//!   Allow`. It NEVER touches `Decision::Deny` — the operator's hard floor
//!   is final. The server-level allowlist (gate Layer 1) runs FIRST.
//! - Auto-approve is driven by the server's `readOnlyHint` (and blocked by
//!   `destructiveHint`); a `tools/list` failure leaves the tool uncached → the
//!   normal confirm path runs (fail-closed). No silent Allow on fetch failure.
//! - The cache is keyed by `(server_id, tool_name)` so two servers can't share
//!   a verdict for a same-named tool.
//! - The cache is NOT persisted to disk. A fresh session always re-reads the
//!   live annotations, so a tool that changes its declared effect (server
//!   update) isn't permanently grandfathered as read-only.
//! - Trust assumption: SmartApprove trusts the configured server's
//!   self-declared annotations for the session. Enable only for servers under
//!   your operational control, ideally with a minimal `allow_tools` list.

use std::collections::HashMap;

use crate::mcp::client::McpTool;

/// GOLD-ADOPT-22 (operator point 1 — trust-creep guard). Classify a tool's
/// read-only status from its server-DECLARED EFFECT metadata
/// ([`crate::mcp::client::ToolAnnotations`]), **NOT its name**. This is the
/// authoritative SmartApprove signal: a renamed or repurposed tool carries its
/// own (current) annotations, so it can't be grandfathered read-only by a
/// familiar name.
///
/// - `destructiveHint == true` → `Some(false)` (NEVER auto-approve, even if a
///   `readOnlyHint` is also set — destructive wins).
/// - else `readOnlyHint == true` → `Some(true)` (read-only, auto-approvable).
/// - `readOnlyHint == false` → `Some(false)`.
/// - no decisive hint → `None` (unknown — the normal confirm path runs;
///   SmartApprove never auto-approves on a guess).
pub fn classify_from_annotations(tool: &McpTool) -> Option<bool> {
    let ann = tool.annotations.as_ref()?;
    if ann.destructive_hint == Some(true) {
        return Some(false);
    }
    ann.read_only_hint
}

/// Session-scoped read-only tool classification cache, keyed by
/// `(server_id, tool_name)` — a tool name is only meaningful within its server
/// (review F5: two servers can expose the same tool name with OPPOSITE effects,
/// so the name alone must never decide auto-approval).
///
/// `Some(true)` = tool declared read-only (safe to auto-allow).
/// `Some(false)` = tool declared write / destructive (normal gate path).
/// `None` = not yet classified this session.
#[derive(Debug, Default, Clone)]
pub struct ReadOnlyCache {
    inner: HashMap<(String, String), bool>,
}

impl ReadOnlyCache {
    /// New empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `(server, tool)` has been classified as read-only this session.
    /// `None` when no entry exists yet.
    pub fn is_readonly(&self, server: &str, tool: &str) -> Option<bool> {
        self.inner
            .get(&(server.to_string(), tool.to_string()))
            .copied()
    }

    /// Record the verdict for `(server, tool)`.
    pub fn insert(&mut self, server: impl Into<String>, tool: impl Into<String>, readonly: bool) {
        self.inner.insert((server.into(), tool.into()), readonly);
    }

    /// GOLD-ADOPT-22 — populate from a SERVER's declared tool annotations (the
    /// authoritative EFFECT signal via [`classify_from_annotations`]). Only
    /// tools with a decisive hint are recorded under `(server, name)`; unhinted
    /// tools stay uncached so the normal confirm path runs. Idempotent
    /// re-seeding is fine (the live catalogue is re-read each session, so a
    /// changed annotation overwrites a stale verdict).
    pub fn seed_from_tools(&mut self, server: &str, tools: &[McpTool]) {
        for t in tools {
            if let Some(readonly) = classify_from_annotations(t) {
                self.inner
                    .insert((server.to_string(), t.name.clone()), readonly);
            }
        }
    }

    /// TEST-ONLY name-based seeding. Deliberately NOT a production API: seeding
    /// read-only by NAME is the trust-creep vector ADOPT-22 guards against —
    /// production auto-approve goes through [`Self::seed_from_tools`] (EFFECT).
    #[cfg(test)]
    pub fn seed_static(&mut self, server: &str, read_only_tools: &[&str]) {
        for name in read_only_tools {
            self.inner
                .insert((server.to_string(), (*name).to_string()), true);
        }
    }

    /// TEST-ONLY: tool names with no entry for `server`.
    #[cfg(test)]
    pub fn uncached<'a>(&self, server: &str, tools: &[&'a str]) -> Vec<&'a str> {
        tools
            .iter()
            .copied()
            .filter(|t| {
                !self
                    .inner
                    .contains_key(&(server.to_string(), (*t).to_string()))
            })
            .collect()
    }
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ReadOnlyCache -------------------------------------------------------

    #[test]
    fn new_cache_is_empty() {
        let c = ReadOnlyCache::new();
        assert_eq!(c.is_readonly("srv", "read_file"), None);
    }

    #[test]
    fn insert_and_hit_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "read_file", true);
        assert_eq!(c.is_readonly("srv", "read_file"), Some(true));
    }

    #[test]
    fn insert_and_hit_not_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "write_file", false);
        assert_eq!(c.is_readonly("srv", "write_file"), Some(false));
    }

    #[test]
    fn miss_returns_none() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "something", true);
        assert_eq!(c.is_readonly("srv", "other_tool"), None);
    }

    #[test]
    fn cache_is_scoped_per_server_no_cross_server_collision() {
        // Review F5: two servers expose the same tool name with OPPOSITE
        // effects — the read-only verdict must NOT leak across servers.
        let mut c = ReadOnlyCache::new();
        c.insert("server_a", "search", true);
        c.insert("server_b", "search", false);
        assert_eq!(c.is_readonly("server_a", "search"), Some(true));
        assert_eq!(c.is_readonly("server_b", "search"), Some(false));
        // A third server's same-named tool is still unknown.
        assert_eq!(c.is_readonly("server_c", "search"), None);
    }

    #[test]
    fn seed_static_marks_tools_as_readonly() {
        let mut c = ReadOnlyCache::new();
        c.seed_static("srv", &["list_dir", "search_web"]);
        assert_eq!(c.is_readonly("srv", "list_dir"), Some(true));
        assert_eq!(c.is_readonly("srv", "search_web"), Some(true));
        assert_eq!(c.is_readonly("srv", "write_file"), None);
    }

    #[test]
    fn uncached_returns_tools_with_no_entry() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "known_tool", true);
        let all = ["known_tool", "unknown_a", "unknown_b"];
        let uncached = c.uncached("srv", &all);
        assert_eq!(uncached.len(), 2);
        assert!(uncached.contains(&"unknown_a"));
        assert!(uncached.contains(&"unknown_b"));
        assert!(!uncached.contains(&"known_tool"));
    }

    #[test]
    fn uncached_empty_when_all_known() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "a", true);
        c.insert("srv", "b", false);
        assert!(c.uncached("srv", &["a", "b"]).is_empty());
    }

    // ---- classify_from_annotations / seed_from_tools (effect metadata) ------

    use crate::mcp::client::{McpTool, ToolAnnotations};

    fn tool(name: &str, ann: Option<ToolAnnotations>) -> McpTool {
        McpTool {
            name: name.into(),
            description: None,
            input_schema: serde_json::json!({}),
            annotations: ann,
        }
    }

    #[test]
    fn classify_read_only_hint_marks_readonly() {
        let t = tool(
            "search",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        assert_eq!(classify_from_annotations(&t), Some(true));
    }

    #[test]
    fn classify_destructive_hint_always_wins_over_readonly() {
        // A server that (incoherently) marks a tool BOTH read-only AND
        // destructive must NOT be auto-approved — destructive wins.
        let t = tool(
            "wipe",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(true),
            }),
        );
        assert_eq!(classify_from_annotations(&t), Some(false));
    }

    #[test]
    fn classify_no_annotations_is_unknown() {
        // No declared effect metadata → unknown → never auto-approved on a name.
        assert_eq!(classify_from_annotations(&tool("mystery", None)), None);
        // Annotations present but no decisive hint → still unknown.
        let t = tool("partial", Some(ToolAnnotations::default()));
        assert_eq!(classify_from_annotations(&t), None);
    }

    #[test]
    fn seed_from_tools_records_only_decisive_hints() {
        let tools = vec![
            tool(
                "read_graph",
                Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: Some(false),
                }),
            ),
            tool(
                "delete_node",
                Some(ToolAnnotations {
                    read_only_hint: Some(false),
                    destructive_hint: Some(true),
                }),
            ),
            tool("unknown", None),
        ];
        let mut c = ReadOnlyCache::new();
        c.seed_from_tools("graph_srv", &tools);
        assert_eq!(c.is_readonly("graph_srv", "read_graph"), Some(true));
        assert_eq!(c.is_readonly("graph_srv", "delete_node"), Some(false));
        // Unhinted tool stays uncached — falls through to the confirm path.
        assert_eq!(c.is_readonly("graph_srv", "unknown"), None);
    }
}
