//! ADOPT-22 — SmartApprove: session-scoped read-only tool cache + LLM judge.
//!
//! Mirrors goose's `permission_judge.rs` + `permission_inspector.rs` pattern:
//!
//! 1. **Cache** (`ReadOnlyCache`) — maps `(server_id, tool_name) → is_readonly`,
//!    populated from the server's DECLARED tool annotations
//!    ([`classify_from_annotations`]). Session-scoped: constructed per
//!    `run_tool_loop_with_cap` invocation and discarded afterwards.
//!
//! 2. **LLM judge** (`build_judge_prompt` / `parse_judge_response`) — an
//!    ADVISORY name-based classifier kept as a `pub(crate)` primitive. It is
//!    deliberately NOT wired into the auto-approve path (see the gate-integration
//!    note below) — auto-approve is EFFECT-driven only.
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
//! declared tool annotations ([`classify_from_annotations`]). The LLM judge
//! below is implemented but **deliberately NOT wired into the auto-approve
//! path** — name-based LLM classification is the exact trust-creep risk the
//! operator flagged, and the judge prompt is itself answered by the (possibly
//! adversarial) session LLM. It stays `pub(crate)` + test-covered as an
//! advisory primitive only.
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

// ── LLM judge (ADVISORY ONLY — NOT wired into the auto-approve path) ─────────
//
// ⚠ These functions are `pub(crate)` + test-covered but are deliberately NOT
// called from `smart_approve_is_readonly` or any path reaching
// `invoke_with_audit`. Auto-approval is EFFECT-driven (server annotations), not
// name-driven (this LLM judge). Do NOT wire these into the gate — name-based
// LLM classification is the trust-creep risk ADOPT-22 guards against, and the
// judge prompt is answered by the (possibly adversarial) session LLM.

/// Prompt sent to the provider asking it to classify a batch of tool names.
/// Mirrors goose's `create_check_messages` / `create_read_only_tool` pattern
/// but uses a simpler plain-JSON response (no synthetic tool definition needed)
/// so any provider can answer, not just those with structured tool_use.
///
/// The response is expected to be a JSON object:
/// ```json
/// {"read_only_tools": ["tool_a", "tool_c"]}
/// ```
/// Any tool NOT listed in the array is treated as write / side-effecting.
pub(crate) fn build_judge_prompt(tool_names: &[&str]) -> String {
    let names_list = tool_names
        .iter()
        .map(|n| format!("  - {n}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "You are a tool-classification assistant. Given the following MCP tool names, \
         identify which ones perform ONLY read-only operations (no mutations, no side effects).\n\n\
         Read-only examples: reading a file, listing a directory, SELECT SQL queries, \
         fetching a URL without POST/PUT/DELETE.\n\
         Write examples: writing a file, INSERT/UPDATE/DELETE SQL, sending a message, \
         modifying system state.\n\n\
         Tool names to classify:\n{names_list}\n\n\
         Respond with ONLY valid JSON in this exact shape (no markdown, no explanation):\n\
         {{\"read_only_tools\": [\"<tool_name>\", ...]}}\n\
         List only the tool names that are STRICTLY read-only. \
         When in doubt, omit — it is safer to require confirmation than to auto-allow."
    )
}

/// Parse the LLM judge's plain-text response into a `HashMap<name, is_readonly>`.
///
/// Tries to extract `{"read_only_tools": [...]}` from the response. Anything
/// that fails to parse cleanly is treated as "no read-only tools found" (safe
/// fail-closed: the normal confirm path runs).
///
/// The `known_tools` slice is the full list of tools the judge was asked about.
/// Every tool NOT in the returned read-only list is recorded as `false`
/// (write-or-unknown) so the cache is fully populated in one pass.
pub(crate) fn parse_judge_response(response: &str, known_tools: &[&str]) -> HashMap<String, bool> {
    let mut result: HashMap<String, bool> =
        known_tools.iter().map(|t| (t.to_string(), false)).collect();

    // Strip optional markdown code fences the LLM may add.
    let trimmed = response.trim();
    let json_str = trimmed
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(arr) = v.get("read_only_tools").and_then(|a| a.as_array()) {
            for item in arr {
                if let Some(name) = item.as_str() {
                    // Only record names we actually asked about to prevent prompt
                    // injection from the judge response adding unexpected entries.
                    if known_tools.contains(&name) {
                        result.insert(name.to_string(), true);
                    }
                }
            }
        }
    }
    // On any parse failure `result` already has all tools set to `false` (safe).
    result
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

    // ---- build_judge_prompt -------------------------------------------------

    #[test]
    fn judge_prompt_contains_all_tool_names() {
        let names = ["read_file", "list_dir", "write_file"];
        let prompt = build_judge_prompt(&names);
        for n in &names {
            assert!(prompt.contains(n), "prompt must mention {n}");
        }
    }

    #[test]
    fn judge_prompt_instructs_json_response() {
        let prompt = build_judge_prompt(&["t1"]);
        assert!(
            prompt.contains("read_only_tools"),
            "must request read_only_tools key"
        );
        assert!(
            prompt.contains("valid JSON"),
            "must instruct JSON-only response"
        );
    }

    // ---- parse_judge_response -----------------------------------------------

    #[test]
    fn parse_valid_json_marks_listed_tools_readonly() {
        let known = ["read_file", "list_dir", "write_file"];
        let resp = r#"{"read_only_tools": ["read_file", "list_dir"]}"#;
        let result = parse_judge_response(resp, &known);
        assert_eq!(result.get("read_file"), Some(&true));
        assert_eq!(result.get("list_dir"), Some(&true));
        assert_eq!(result.get("write_file"), Some(&false));
    }

    #[test]
    fn parse_empty_array_marks_all_as_write() {
        let known = ["a", "b"];
        let resp = r#"{"read_only_tools": []}"#;
        let result = parse_judge_response(resp, &known);
        assert_eq!(result.get("a"), Some(&false));
        assert_eq!(result.get("b"), Some(&false));
    }

    #[test]
    fn parse_garbage_response_fails_closed() {
        let known = ["a", "b"];
        let resp = "I cannot answer that request.";
        let result = parse_judge_response(resp, &known);
        // Safe fail-closed: all tools treated as non-readonly.
        assert_eq!(result.get("a"), Some(&false));
        assert_eq!(result.get("b"), Some(&false));
    }

    #[test]
    fn parse_strips_markdown_code_fences() {
        let known = ["tool_x"];
        let resp = "```json\n{\"read_only_tools\": [\"tool_x\"]}\n```";
        let result = parse_judge_response(resp, &known);
        assert_eq!(result.get("tool_x"), Some(&true));
    }

    #[test]
    fn parse_ignores_injected_tool_names_not_in_known() {
        // Security: prompt injection in judge response must not insert unknown
        // tool names into the cache as read-only.
        let known = ["safe_tool"];
        let resp = r#"{"read_only_tools": ["safe_tool", "injected_evil_tool"]}"#;
        let result = parse_judge_response(resp, &known);
        assert_eq!(result.get("safe_tool"), Some(&true));
        // injected_evil_tool must NOT appear in result (not in known_tools).
        assert!(!result.contains_key("injected_evil_tool"));
    }

    #[test]
    fn parse_all_tools_readonly() {
        let known = ["a", "b", "c"];
        let resp = r#"{"read_only_tools": ["a", "b", "c"]}"#;
        let result = parse_judge_response(resp, &known);
        for t in &known {
            assert_eq!(result.get(*t), Some(&true), "{t} must be readonly");
        }
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
