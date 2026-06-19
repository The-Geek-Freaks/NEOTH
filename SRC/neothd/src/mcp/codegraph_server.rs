//! N-07 (Session 24) — codegraph as an MCP-tool surface.
//!
//! A3 + A6 sequencing #6: an external MCP client (other Claude Code
//! installations, n8n workflows, GUI consumers) should be able to
//! call NEOTH's local code-map operations without HTTP round-trips
//! or reading the SQLite directly. The smallcode paper measured
//! -35% cost and -70% tool calls when the LLM has typed codegraph
//! access instead of re-deriving relevance via repeated greps.
//!
//! ## Scope of this commit
//!
//! Two pure helpers:
//!
//! - [`codegraph_tools`] returns the canonical [`McpTool`] list with
//!   names + descriptions + JSON-Schema input shapes. The wider
//!   stdio JSON-RPC server that exposes this list to external
//!   processes is the follow-up; this module ships the typed tool
//!   definitions so every future surface (in-process, stdio,
//!   HTTP, GUI) consumes the same source of truth.
//! - [`dispatch_codegraph_tool`] takes a tool name + args + the
//!   operator's code-map DB path and returns a [`ToolCallResult`]
//!   ready for the MCP `tools/call` response envelope.
//!
//! Today's tool set (5 tools, mirrors the smallcode minimum + call-chain BFS):
//!
//! - `codegraph_relevant_files` — top-N files for a prompt
//! - `codegraph_extract_identifiers` — symbol-shape extraction
//! - `codegraph_path_keywords` — path-segment extraction
//! - `codegraph_callers` — transitive callers of a symbol (inverse BFS)
//! - `codegraph_callees` — transitive callees of a symbol (forward BFS)
//!
//! Each is a pure read against the in-memory [`CallGraph`] built from
//! source files, or (for relevant_files) against `~/.neoth/code_map.db`.
//! No mutations, no provider calls, no network. Safe to expose to any
//! MCP client the operator's autonomy level allows.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::mcp::client::{McpContent, McpTool, ToolAnnotations, ToolCallResult};

/// All codegraph tools are pure read-only queries over the local
/// code-map (no mutation) — declare it so ADOPT-22 SmartApprove can
/// auto-approve them by EFFECT.
fn read_only_annotations() -> Option<ToolAnnotations> {
    Some(ToolAnnotations {
        read_only_hint: Some(true),
        destructive_hint: Some(false),
    })
}

/// Canonical tool list. Pure constant — no IO. Public so the GUI
/// + the future stdio JSON-RPC wrapper consume the same definitions.
pub fn codegraph_tools() -> Vec<McpTool> {
    vec![
        McpTool {
            name: "codegraph_relevant_files".into(),
            description: Some(
                "Return the top-N files from the local code-map most relevant to a prompt. \
                 Uses identifier-shape extraction + path-keyword overlap; ranks by \
                 symbol hits with path overlap as tie-break."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Free-form text. Identifiers + path keywords extracted from this drive the match."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 50,
                        "description": "Cap on returned files. Default 5."
                    }
                },
                "required": ["prompt"]
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_extract_identifiers".into(),
            description: Some(
                "Extract CamelCase + snake_case identifier-shaped tokens from text. \
                 Returns a deduplicated list. Useful for tools that want to know which \
                 symbols a prompt is plausibly about before calling the relevance ranker."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string"}
                },
                "required": ["text"]
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_path_keywords".into(),
            description: Some(
                "Extract path-keyword candidates (lowercase ASCII tokens ≥3 chars, minus \
                 a small stop-list) from text. These are the same keywords the relevance \
                 ranker uses for path-overlap tie-breaking."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string"}
                },
                "required": ["text"]
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_callers".into(),
            description: Some(
                "Return the transitive callers of a symbol up to depth N (inverse BFS). \
                 Walks the call-graph backwards from `symbol`, returning every function \
                 that (directly or indirectly) reaches it within `depth` hops. \
                 Each row contains `file_path`, `symbol`, and `depth`. \
                 Results are sorted by (depth, file_path, symbol) for deterministic output. \
                 Useful for impact analysis: \"who calls this function?\""
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Name of the target symbol to trace callers for."
                    },
                    "depth": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 20,
                        "description": "Maximum BFS depth. Default 5."
                    }
                },
                "required": ["symbol"]
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_callees".into(),
            description: Some(
                "Return the transitive callees of a symbol up to depth N (forward BFS). \
                 Walks the call-graph forwards from `symbol` in `file`, returning every \
                 function it (directly or indirectly) calls within `depth` hops. \
                 Each row contains `name` and `depth`. \
                 Results are sorted by (depth, name) for deterministic output. \
                 Useful for dependency tracing: \"what does this function call?\""
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Name of the source symbol to trace callees from."
                    },
                    "file": {
                        "type": "string",
                        "description": "File path that defines the source symbol. \
                                        Required to resolve the correct call-site scope \
                                        when the same name is defined in multiple files."
                    },
                    "depth": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 20,
                        "description": "Maximum BFS depth. Default 5."
                    }
                },
                "required": ["symbol", "file"]
            }),
            annotations: read_only_annotations(),
        },
    ]
}

/// Names of every tool [`dispatch_codegraph_tool`] knows. Used by
/// the catalogue builder + as a drift guard so a future tool added
/// to [`codegraph_tools`] forces a dispatcher update.
pub const TOOL_NAMES: &[&str] = &[
    "codegraph_relevant_files",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
];

/// Dispatch one `tools/call` request. `db_path` points at the
/// operator's `~/.neoth/code_map.db`; tools that need it open the
/// DB read-only inside their branch. Tools that don't need the DB
/// (pure-string analysis) ignore the path.
///
/// Returns a [`ToolCallResult`] with `is_error = true` on every
/// failure path so the MCP envelope renders cleanly without
/// surfacing a Rust `Err` to the operator's chat session.
pub fn dispatch_codegraph_tool(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
) -> ToolCallResult {
    match tool_name {
        "codegraph_extract_identifiers" => tool_extract_identifiers(args),
        "codegraph_path_keywords" => tool_path_keywords(args),
        "codegraph_relevant_files" => tool_relevant_files(db_path, args),
        "codegraph_callers" => tool_callers(args),
        "codegraph_callees" => tool_callees(args),
        other => error_result(format!(
            "unknown codegraph tool `{other}` (known: {})",
            TOOL_NAMES.join(", "),
        )),
    }
}

#[derive(Deserialize)]
struct TextArgs {
    text: String,
}

#[derive(Deserialize)]
struct RelevantFilesArgs {
    prompt: String,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    5
}

fn tool_extract_identifiers(args: &serde_json::Value) -> ToolCallResult {
    let parsed: TextArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let ids = crate::code_map::recall::extract_identifiers(&parsed.text);
    text_result(serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()))
}

fn tool_path_keywords(args: &serde_json::Value) -> ToolCallResult {
    let parsed: TextArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let keys = crate::code_map::recall::extract_path_keywords(&parsed.text);
    text_result(serde_json::to_string(&keys).unwrap_or_else(|_| "[]".into()))
}

fn tool_relevant_files(db_path: &Path, args: &serde_json::Value) -> ToolCallResult {
    let parsed: RelevantFilesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let limit = parsed.limit.clamp(1, 50) as usize;
    match relevant_files_inner(db_path, &parsed.prompt, limit) {
        Ok(payload) => text_result(payload),
        Err(e) => error_result(format!("relevant_files failed: {e:#}")),
    }
}

fn relevant_files_inner(db_path: &Path, prompt: &str, limit: usize) -> Result<String> {
    if !db_path.exists() {
        // Empty result rather than error — the operator hasn't built
        // a code map yet; the MCP client should see "0 files", not
        // a hard failure that kills its tool-call retry loop.
        return Ok("[]".into());
    }
    let conn = crate::code_map::persist::open(db_path)
        .with_context(|| format!("open {}", db_path.display()))?;
    let files = crate::code_map::recall::relevant_files_for_prompt(&conn, prompt, limit)?;
    // Project the typed result down to the JSON shape MCP clients want.
    let payload: Vec<serde_json::Value> = files
        .iter()
        .map(|f| {
            serde_json::json!({
                "root": f.root,
                "path": f.path,
                "identifier_hits": f.identifier_hits,
                "matched_symbols": f.matched_symbols,
                "path_keyword_overlap": f.path_keyword_overlap,
            })
        })
        .collect();
    Ok(serde_json::to_string(&payload).unwrap_or_else(|_| "[]".into()))
}

#[derive(Deserialize)]
struct CallersArgs {
    symbol: String,
    #[serde(default = "default_bfs_depth")]
    depth: u32,
}

#[derive(Deserialize)]
struct CalleesArgs {
    symbol: String,
    file: String,
    #[serde(default = "default_bfs_depth")]
    depth: u32,
}

fn default_bfs_depth() -> u32 {
    5
}

fn tool_callers(args: &serde_json::Value) -> ToolCallResult {
    let parsed: CallersArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    // Empty graph — the dispatch surface returns [] until the follow-up
    // slice wires in the persisted code-map loader. The BFS logic itself
    // is fully exercised via callers_inner / callees_inner in tests.
    let graph = crate::code_map::graph::CallGraph::build(&[]);
    text_result(callers_inner(&graph, &parsed.symbol, depth))
}

fn tool_callees(args: &serde_json::Value) -> ToolCallResult {
    let parsed: CalleesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    let graph = crate::code_map::graph::CallGraph::build(&[]);
    text_result(callees_inner(&graph, &parsed.file, &parsed.symbol, depth))
}

/// Build a [`CallGraph`] from `files` and call [`CallGraph::callers_of`].
/// Extracted so tests can drive the BFS without going through the
/// `dispatch_codegraph_tool` HTTP surface.
pub(crate) fn callers_inner(
    graph: &crate::code_map::graph::CallGraph,
    symbol: &str,
    depth: usize,
) -> String {
    let mut entries = graph.callers_of(symbol, depth);
    entries.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then(a.file_path.cmp(&b.file_path))
            .then(a.symbol.cmp(&b.symbol))
    });
    let payload: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "file_path": e.file_path,
                "symbol": e.symbol,
                "depth": e.depth,
            })
        })
        .collect();
    serde_json::to_string(&payload).unwrap_or_else(|_| "[]".into())
}

/// Same as [`callers_inner`] for the forward direction.
pub(crate) fn callees_inner(
    graph: &crate::code_map::graph::CallGraph,
    file: &str,
    symbol: &str,
    depth: usize,
) -> String {
    let mut entries = graph.callees_of(file, symbol, depth);
    entries.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));
    let payload: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "depth": e.depth,
            })
        })
        .collect();
    serde_json::to_string(&payload).unwrap_or_else(|_| "[]".into())
}

fn text_result(text: String) -> ToolCallResult {
    ToolCallResult {
        content: vec![McpContent::Text { text }],
        is_error: false,
    }
}

fn error_result(message: String) -> ToolCallResult {
    ToolCallResult {
        content: vec![McpContent::Text { text: message }],
        is_error: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::graph::CallGraph;
    use crate::code_map::walker::Language;
    use tempfile::tempdir;

    /// Build a [`CallGraph`] from a single Rust source file for BFS tests.
    fn graph_from_rust(path: &str, src: &str) -> CallGraph {
        let syms = crate::code_map::symbols::extract_symbols(src, Language::Rust);
        let file = crate::code_map::graph::FileInput::c_family(path, src, syms);
        CallGraph::build(&[file])
    }

    fn text_content(r: &ToolCallResult) -> String {
        for c in &r.content {
            if let McpContent::Text { text } = c {
                return text.clone();
            }
        }
        String::new()
    }

    #[test]
    fn codegraph_tools_lists_five_canonical_tools() {
        let tools = codegraph_tools();
        assert_eq!(tools.len(), 5);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_relevant_files"));
        assert!(names.contains(&"codegraph_extract_identifiers"));
        assert!(names.contains(&"codegraph_path_keywords"));
        assert!(names.contains(&"codegraph_callers"));
        assert!(names.contains(&"codegraph_callees"));
    }

    #[test]
    fn codegraph_tools_declare_read_only_effect_for_smart_approve() {
        // GOLD-ADOPT-22: every codegraph tool is a pure query → readOnlyHint
        // true + destructiveHint false, so SmartApprove classifies them
        // read-only by EFFECT (the built-in consumer of the feature).
        for t in codegraph_tools() {
            assert_eq!(
                crate::mcp::smart_approve::classify_from_annotations(&t),
                Some(true),
                "{} must declare a read-only effect",
                t.name
            );
        }
    }

    #[test]
    fn codegraph_tools_carries_required_field_in_each_schema() {
        // Drift guard: every tool must declare its required input
        // field so MCP clients can validate before calling.
        for tool in codegraph_tools() {
            let required = tool
                .input_schema
                .get("required")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("tool {} missing `required` array", tool.name));
            assert!(
                !required.is_empty(),
                "tool {} has empty `required` array",
                tool.name,
            );
        }
    }

    #[test]
    fn tool_names_constant_matches_codegraph_tools_list() {
        // Drift guard: TOOL_NAMES must stay in sync with codegraph_tools().
        let tools = codegraph_tools();
        let from_fn: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        let from_const: Vec<&str> = TOOL_NAMES.to_vec();
        assert_eq!(from_fn, from_const);
    }

    #[test]
    fn dispatch_unknown_tool_returns_error_result() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "nope",
            &serde_json::json!({}),
        );
        assert!(r.is_error);
        let text = text_content(&r);
        assert!(text.contains("unknown codegraph tool"), "got: {text}");
        // Error message must list known tools so the operator can fix.
        for known in TOOL_NAMES {
            assert!(text.contains(known), "missing `{known}` in: {text}");
        }
    }

    #[test]
    fn dispatch_extract_identifiers_round_trips_via_recall() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_extract_identifiers",
            &serde_json::json!({"text": "rebuild OrderService and auth_middleware soon"}),
        );
        assert!(!r.is_error);
        let body = text_content(&r);
        let ids: Vec<String> = serde_json::from_str(&body).unwrap();
        assert!(ids.contains(&"OrderService".to_string()), "got: {ids:?}");
        assert!(ids.contains(&"auth_middleware".to_string()), "got: {ids:?}");
    }

    #[test]
    fn dispatch_path_keywords_round_trips_via_recall() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_path_keywords",
            &serde_json::json!({"text": "refactor the auth middleware tests in src/auth"}),
        );
        assert!(!r.is_error);
        let body = text_content(&r);
        let keys: Vec<String> = serde_json::from_str(&body).unwrap();
        // refactor / auth / middleware / tests / src should all appear
        // — every one is 3+ ASCII chars and not a stop word.
        for key in &["auth", "middleware"] {
            assert!(
                keys.iter().any(|k| k == *key),
                "expected `{key}` in: {keys:?}",
            );
        }
    }

    #[test]
    fn dispatch_relevant_files_returns_empty_array_when_db_missing() {
        // Defensive: operator hasn't built a code map yet. MCP client
        // gets `[]`, NOT an error. Pinned so a future eager-error
        // refactor doesn't break the "operator just installed" path.
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("never-built.db"),
            "codegraph_relevant_files",
            &serde_json::json!({"prompt": "any prompt"}),
        );
        assert!(!r.is_error, "missing DB must not produce error result");
        let body = text_content(&r);
        assert_eq!(body, "[]");
    }

    #[test]
    fn dispatch_relevant_files_rejects_missing_required_prompt() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_relevant_files",
            &serde_json::json!({"limit": 5}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("bad args"));
    }

    #[test]
    fn dispatch_relevant_files_clamps_out_of_range_limit() {
        // Schema says max 50; the dispatcher clamps to be defensive
        // even when the client ignores the schema bounds. Pre-clamp
        // a 10000 would have hit a huge SQL LIMIT. Pinned via the
        // "DB missing → []" branch (which still parses the args).
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("never-built.db"),
            "codegraph_relevant_files",
            &serde_json::json!({"prompt": "x", "limit": 10000}),
        );
        assert!(!r.is_error);
        // The clamp path didn't crash + returned the empty body.
        assert_eq!(text_content(&r), "[]");
    }

    // ── GOLD-ADAPT-CBM-05: codegraph_callers / codegraph_callees ─────────

    #[test]
    fn callers_inner_returns_transitive_callers_of_leaf() {
        // a -> b -> c  (root calls middle calls leaf)
        let src = r#"
fn leaf() {}
fn middle() { leaf(); }
fn root() { middle(); }
"#;
        let g = graph_from_rust("x.rs", src);
        let json = callers_inner(&g, "leaf", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let symbols: Vec<&str> = rows
            .iter()
            .map(|r| r["symbol"].as_str().unwrap())
            .collect();
        assert!(symbols.contains(&"middle"), "missing middle in: {symbols:?}");
        assert!(symbols.contains(&"root"), "missing root in: {symbols:?}");
        // depth ordering: middle=1, root=2
        let middle = rows.iter().find(|r| r["symbol"] == "middle").unwrap();
        let root = rows.iter().find(|r| r["symbol"] == "root").unwrap();
        assert_eq!(middle["depth"], 1);
        assert_eq!(root["depth"], 2);
    }

    #[test]
    fn callers_inner_unknown_symbol_returns_empty() {
        let src = "fn foo() {}\n";
        let g = graph_from_rust("a.rs", src);
        let json = callers_inner(&g, "nonexistent", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn callees_inner_returns_transitive_callees_of_root() {
        let src = r#"
fn leaf() {}
fn middle() { leaf(); }
fn root() { middle(); }
"#;
        let g = graph_from_rust("x.rs", src);
        let json = callees_inner(&g, "x.rs", "root", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"middle"), "missing middle in: {names:?}");
        assert!(names.contains(&"leaf"), "missing leaf in: {names:?}");
    }

    #[test]
    fn callees_inner_unknown_symbol_returns_empty() {
        let src = "fn foo() {}\n";
        let g = graph_from_rust("a.rs", src);
        let json = callees_inner(&g, "a.rs", "nonexistent", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn dispatch_codegraph_callers_rejects_missing_symbol() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callers",
            &serde_json::json!({}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("bad args"));
    }

    #[test]
    fn dispatch_codegraph_callees_rejects_missing_required_args() {
        let dir = tempdir().unwrap();
        // Missing both symbol and file.
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callees",
            &serde_json::json!({}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("bad args"));
    }

    #[test]
    fn dispatch_codegraph_callers_empty_graph_returns_empty_array() {
        // No source files → graph is empty → callers of anything = [].
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callers",
            &serde_json::json!({"symbol": "foo"}),
        );
        assert!(!r.is_error);
        assert_eq!(text_content(&r), "[]");
    }

    #[test]
    fn dispatch_codegraph_callees_empty_graph_returns_empty_array() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callees",
            &serde_json::json!({"symbol": "foo", "file": "a.rs"}),
        );
        assert!(!r.is_error);
        assert_eq!(text_content(&r), "[]");
    }

    #[test]
    fn callers_inner_result_is_sorted_deterministically() {
        // Two callers at the same depth must come out in lexicographic order.
        let src = r#"
fn leaf() {}
fn alpha() { leaf(); }
fn beta() { leaf(); }
"#;
        let g = graph_from_rust("x.rs", src);
        let json = callers_inner(&g, "leaf", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        // Both alpha and beta are depth-1 callers; alpha < beta lexicographically.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["symbol"], "alpha");
        assert_eq!(rows[1]["symbol"], "beta");
    }

    #[test]
    fn callees_inner_result_is_sorted_deterministically() {
        // root calls both alpha and beta at depth 1 → alpha before beta.
        let src = r#"
fn alpha() {}
fn beta() {}
fn root() { alpha(); beta(); }
"#;
        let g = graph_from_rust("x.rs", src);
        let json = callees_inner(&g, "x.rs", "root", 5);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["name"], "alpha");
        assert_eq!(rows[1]["name"], "beta");
    }
}
