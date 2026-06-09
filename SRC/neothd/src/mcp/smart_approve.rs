//! ADOPT-22 — SmartApprove: session-scoped read-only tool cache + LLM judge.
//!
//! Mirrors goose's `permission_judge.rs` + `permission_inspector.rs` pattern:
//!
//! 1. **Cache** (`ReadOnlyCache`) — maps `tool_name → is_readonly`. Populated
//!    either from per-call `insert()` (after an LLM-judge verdict) or from a
//!    static well-known list. Session-scoped: constructed per
//!    `run_tool_loop_with_cap` invocation and discarded afterwards.
//!
//! 2. **LLM judge** (`detect_read_only_via_llm`) — when the cache has no
//!    entry for a tool that is about to require `Decision::Confirm`, ask the
//!    currently-active provider whether the tool is read-only. Uses a
//!    structured JSON response so no extra provider round-trip or tool-use is
//!    needed. Returns a `HashMap<tool_name, is_readonly>`.
//!
//! ## Integration in the gate
//!
//! `invoke_with_audit` (mcp/gate.rs) receives an `Option<&mut ReadOnlyCache>`.
//! Before escalating a `McpToolInvocation` to `Decision::Confirm`, it checks
//! the cache:
//!
//! ```text
//! if cache.is_readonly(tool) == Some(true)  → skip confirm, emit 0xCF WAL
//! if cache.is_readonly(tool) == Some(false) → proceed to normal confirm path
//! if cache.is_readonly(tool) == None        → caller must run LLM judge first
//! ```
//!
//! The gate never calls the LLM judge itself; the dispatch loop calls it for
//! the full batch of uncached tools before dispatching any of them. This
//! batches the single judge call over all tools in one loop iteration.
//!
//! ## Security contract
//!
//! - A `true` (read-only) cache entry only upgrades `Decision::Confirm →
//!   Allow`. It NEVER touches `Decision::Deny` — the operator's hard floor
//!   is final.
//! - The LLM judge is advisory: if the judge call fails or times out, the
//!   cache stays empty for that tool and the normal confirm/fail-closed path
//!   runs. No silent Allow on judge failure.
//! - The cache is NOT persisted to disk. A fresh session always re-judges
//!   unknown tools. This ensures a tool that changes behaviour (server update,
//!   permission change) isn't permanently grandfathered as read-only.

use std::collections::HashMap;

/// Session-scoped read-only tool classification cache.
///
/// `Some(true)` = tool judged as read-only (safe to auto-allow).
/// `Some(false)` = tool judged as write / side-effecting (normal gate path).
/// `None` = not yet judged this session.
#[derive(Debug, Default, Clone)]
pub struct ReadOnlyCache {
    inner: HashMap<String, bool>,
}

impl ReadOnlyCache {
    /// New empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `tool` has been classified as read-only this session.
    /// Returns `None` when no entry exists (judge has not been called yet).
    pub fn is_readonly(&self, tool: &str) -> Option<bool> {
        self.inner.get(tool).copied()
    }

    /// Record the judge's verdict for `tool`.
    pub fn insert(&mut self, tool: impl Into<String>, readonly: bool) {
        self.inner.insert(tool.into(), readonly);
    }

    /// Pre-populate with a static slice of known-read-only tool names.
    /// Avoids an LLM round-trip for common patterns like `read_file`,
    /// `list_dir`, `search_web`.
    pub fn seed_static(&mut self, read_only_tools: &[&str]) {
        for name in read_only_tools {
            self.inner.insert((*name).to_string(), true);
        }
    }

    /// Returns all tool names whose read-only status is not yet known.
    pub fn uncached<'a>(&self, tools: &[&'a str]) -> Vec<&'a str> {
        tools.iter().copied().filter(|t| !self.inner.contains_key(*t)).collect()
    }
}

// ── LLM judge ───────────────────────────────────────────────────────────────

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
pub fn build_judge_prompt(tool_names: &[&str]) -> String {
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
pub fn parse_judge_response(response: &str, known_tools: &[&str]) -> HashMap<String, bool> {
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
        assert_eq!(c.is_readonly("read_file"), None);
    }

    #[test]
    fn insert_and_hit_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("read_file", true);
        assert_eq!(c.is_readonly("read_file"), Some(true));
    }

    #[test]
    fn insert_and_hit_not_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("write_file", false);
        assert_eq!(c.is_readonly("write_file"), Some(false));
    }

    #[test]
    fn miss_returns_none() {
        let mut c = ReadOnlyCache::new();
        c.insert("something", true);
        assert_eq!(c.is_readonly("other_tool"), None);
    }

    #[test]
    fn seed_static_marks_tools_as_readonly() {
        let mut c = ReadOnlyCache::new();
        c.seed_static(&["list_dir", "search_web"]);
        assert_eq!(c.is_readonly("list_dir"), Some(true));
        assert_eq!(c.is_readonly("search_web"), Some(true));
        assert_eq!(c.is_readonly("write_file"), None);
    }

    #[test]
    fn uncached_returns_tools_with_no_entry() {
        let mut c = ReadOnlyCache::new();
        c.insert("known_tool", true);
        let all = ["known_tool", "unknown_a", "unknown_b"];
        let uncached = c.uncached(&all);
        assert_eq!(uncached.len(), 2);
        assert!(uncached.contains(&"unknown_a"));
        assert!(uncached.contains(&"unknown_b"));
        assert!(!uncached.contains(&"known_tool"));
    }

    #[test]
    fn uncached_empty_when_all_known() {
        let mut c = ReadOnlyCache::new();
        c.insert("a", true);
        c.insert("b", false);
        assert!(c.uncached(&["a", "b"]).is_empty());
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
        assert!(prompt.contains("read_only_tools"), "must request read_only_tools key");
        assert!(prompt.contains("valid JSON"), "must instruct JSON-only response");
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
}
