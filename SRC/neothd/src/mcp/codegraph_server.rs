//! N-07 (Session 24) — codegraph as an MCP-tool surface.
//!
//! A3 + A6 sequencing #6: an external MCP client (other Claude Code
//! installations, n8n workflows, GUI consumers) should be able to
//! call NEOTH's local code-map operations without HTTP round-trips
//! or reading the SQLite directly. The smallcode paper measured
//! -35% cost and -70% tool calls when the LLM has typed codegraph
//! access instead of re-deriving relevance via repeated greps.
//!
//! ## Surface
//!
//! The canonical tool definitions and dispatcher are exposed through a real
//! newline-delimited JSON-RPC stdio server (`neoth mcp codegraph-serve`).
//! External clients therefore consume the same typed source of truth as NEOTH's
//! in-process catalogue. The outline tool is restricted to files present in the
//! persisted code-map; the MCP client cannot turn it into an arbitrary local
//! file reader.
//!
//! - [`codegraph_tools`] returns the canonical [`McpTool`] list with names,
//!   descriptions, and JSON-Schema input shapes.
//! - [`dispatch_codegraph_tool`] takes a tool name + args + the
//!   operator's code-map DB path and returns a [`ToolCallResult`]
//!   ready for the MCP `tools/call` response envelope.
//!
//! Today's tool set (6 tools, mirrors the smallcode minimum + call-chain BFS):
//!
//! - `codegraph_relevant_files` — top-N files for a prompt
//! - `codegraph_extract_identifiers` — symbol-shape extraction
//! - `codegraph_path_keywords` — path-segment extraction
//! - `codegraph_callers` — transitive callers of a symbol (inverse BFS)
//! - `codegraph_callees` — transitive callees of a symbol (forward BFS)
//! - `codegraph_outline` — structural outline for a file already indexed in
//!   the persisted code map
//!
//! Each is a pure read against the operator's persisted code map
//! (`~/.neoth/code_map.db`): relevant_files ranks stored file rows;
//! callers/callees reconstruct the [`CallGraph`] from the stored
//! `code_map_edges` table (no source rescan). No mutations, no provider
//! calls, no network. Safe to expose to any MCP client the operator's
//! autonomy level allows.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        // GOLD-ADAPT-CCS-04: native AST outline — per-file structural overview
        // (symbols + line ranges) without any Node.js or tree-sitter dep.
        McpTool {
            name: "codegraph_outline".into(),
            description: Some(
                "Return a structural outline of an indexed source file: every top-level \
                 declaration (function, struct, trait, class, …) with its name, \
                 kind, start line, and estimated end line. \
                 Replaces reading the whole file to understand its shape — \
                 typical output is ~95% smaller than the raw source. \
                 Language is inferred from the file extension. \
                 Returns `[]` if the file cannot be read or the language has \
                 no symbol patterns."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or unambiguous repo-relative path already present in the persisted code map."
                    }
                },
                "required": ["path"]
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
    "codegraph_outline",
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
        "codegraph_callers" => tool_callers(db_path, args),
        "codegraph_callees" => tool_callees(db_path, args),
        "codegraph_outline" => tool_outline(db_path, args),
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
    text_result(
        serde_json::to_string(&ids)
            .expect("identifier strings and vectors are always JSON-serializable"),
    )
}

fn tool_path_keywords(args: &serde_json::Value) -> ToolCallResult {
    let parsed: TextArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let keys = crate::code_map::recall::extract_path_keywords(&parsed.text);
    text_result(
        serde_json::to_string(&keys)
            .expect("path-keyword strings and vectors are always JSON-serializable"),
    )
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
    // GOLD-R3-13: scope to the persisted root that contains the server's
    // working directory. An unmapped CWD returns an empty result rather than a
    // cross-repo mix — the MCP client sees "0 files", never another repo's.
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let Some(active_root) = crate::code_map::recall::resolve_active_root(&conn, &cwd) else {
        return Ok("[]".into());
    };
    let files =
        crate::code_map::recall::relevant_files_for_prompt(&conn, prompt, &active_root, limit)?;
    // GOLD-R3-13: surface the active root's index generation so an MCP client can
    // detect a re-index under it and invalidate a cached result. Carried per file
    // (the array shape is preserved so existing clients keep parsing) — every row
    // shares the one active root's generation.
    let index_generation =
        crate::code_map::persist::root_index_generation(&conn, &active_root).unwrap_or(None);
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
                "index_generation": index_generation,
            })
        })
        .collect();
    Ok(serde_json::to_string(&payload)
        .expect("serde_json::Value arrays are always JSON-serializable"))
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

/// Load the call graph from the operator's persisted code-map DB. A
/// missing DB yields an EMPTY graph (the operator hasn't built a code map
/// yet → callers/callees return `[]`, never a hard error — same posture
/// as `relevant_files`). Reconstructs the graph from the stored
/// `code_map_edges` table via [`CallGraph::from_edges`] — no source rescan.
fn graph_from_db(db_path: &Path) -> Result<crate::code_map::graph::CallGraph> {
    if !db_path.exists() {
        return Ok(crate::code_map::graph::CallGraph::default());
    }
    let conn = crate::code_map::persist::open(db_path)
        .with_context(|| format!("open {}", db_path.display()))?;
    let edges = crate::code_map::persist::load_all_edges(&conn)?;
    Ok(crate::code_map::graph::CallGraph::from_edges(edges))
}

fn tool_callers(db_path: &Path, args: &serde_json::Value) -> ToolCallResult {
    let parsed: CallersArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    let graph = match graph_from_db(db_path) {
        Ok(g) => g,
        Err(e) => return error_result(format!("codegraph_callers failed: {e:#}")),
    };
    text_result(callers_inner(&graph, &parsed.symbol, depth))
}

fn tool_callees(db_path: &Path, args: &serde_json::Value) -> ToolCallResult {
    let parsed: CalleesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    let graph = match graph_from_db(db_path) {
        Ok(g) => g,
        Err(e) => return error_result(format!("codegraph_callees failed: {e:#}")),
    };
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
    serde_json::to_string(&payload).expect("serde_json::Value arrays are always JSON-serializable")
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
    serde_json::to_string(&payload).expect("serde_json::Value arrays are always JSON-serializable")
}

// ── GOLD-ADAPT-CCS-04: codegraph_outline ─────────────────────────────────

#[derive(Deserialize)]
struct OutlineArgs {
    path: String,
}

fn tool_outline(db_path: &Path, args: &serde_json::Value) -> ToolCallResult {
    let parsed: OutlineArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let path = match resolve_indexed_outline_path(db_path, &parsed.path) {
        Ok(path) => path,
        Err(error) => return error_result(format!("outline access denied: {error:#}")),
    };
    let entries = crate::code_map::outline::outline_file(&path);
    match serde_json::to_string(&entries) {
        Ok(payload) => text_result(payload),
        Err(e) => error_result(format!("outline serialisation failed: {e}")),
    }
}

/// Resolve an outline request only when the canonical file is part of the
/// persisted code-map. Relative paths must identify exactly one indexed root;
/// callers can disambiguate duplicate repo-relative paths with an absolute path.
/// Canonical root containment also rejects indexed symlinks/junctions that now
/// escape their original repository.
fn resolve_indexed_outline_path(db_path: &Path, requested: &str) -> Result<PathBuf> {
    let requested = requested.trim();
    if requested.is_empty() {
        anyhow::bail!("path is empty");
    }
    if !db_path.exists() {
        anyhow::bail!("code-map database is missing; build it before requesting file outlines");
    }
    let requested_path = Path::new(requested);
    let requested_absolute = if requested_path.is_absolute() {
        Some(
            requested_path
                .canonicalize()
                .with_context(|| format!("canonicalize requested path `{requested}`"))?,
        )
    } else {
        None
    };

    let conn = crate::code_map::persist::open(db_path)
        .with_context(|| format!("open {}", db_path.display()))?;
    let mut stmt = conn
        .prepare("SELECT root, path FROM code_map_files ORDER BY root, path")
        .context("prepare indexed-outline membership query")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("query indexed-outline membership")?;

    let mut matches = Vec::new();
    for row in rows {
        let (root, relative) = row.context("read indexed-outline membership row")?;
        if requested_absolute.is_none() && Path::new(&relative) != requested_path {
            continue;
        }
        let canonical_root = match Path::new(&root).canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        let canonical_file = match canonical_root.join(&relative).canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        if canonical_file.strip_prefix(&canonical_root).is_err() {
            continue;
        }
        if requested_absolute
            .as_ref()
            .is_some_and(|absolute| absolute != &canonical_file)
        {
            continue;
        }
        matches.push(canonical_file);
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => anyhow::bail!("`{requested}` is not an indexed code-map file"),
        _ => anyhow::bail!(
            "relative path `{requested}` exists in multiple indexed roots; use an absolute path"
        ),
    }
}

#[derive(Default)]
struct StdioSession {
    initialize_seen: bool,
    ready: bool,
}

/// Run the production codegraph MCP server on stdin/stdout. Stdout is reserved
/// exclusively for compact JSON-RPC messages; diagnostics belong on stderr via
/// the process tracing subscriber.
pub async fn serve_stdio(db_path: PathBuf) -> Result<()> {
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    let mut session = StdioSession::default();

    loop {
        while let Some((body, consumed)) = crate::mcp::transport::parse_frame(&buffer)
            .map_err(|error| anyhow::anyhow!("invalid MCP stdio message: {error}"))?
        {
            buffer.drain(..consumed);
            if let Some(response) = handle_stdio_message(&db_path, &body, &mut session) {
                let encoded = serde_json::to_vec(&response).context("encode MCP response")?;
                let message = crate::mcp::transport::frame(&encoded);
                output
                    .write_all(&message)
                    .await
                    .context("write MCP response")?;
                output.flush().await.context("flush MCP response")?;
            }
        }

        let read = input.read(&mut chunk).await.context("read MCP stdin")?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(());
            }
            anyhow::bail!("MCP stdin closed with an incomplete JSON message");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if !buffer.contains(&b'\n') && buffer.len() > crate::mcp::transport::MAX_MCP_FRAME_BYTES {
            anyhow::bail!(
                "MCP stdin message exceeds {} bytes",
                crate::mcp::transport::MAX_MCP_FRAME_BYTES
            );
        }
    }
}

/// Pure JSON-RPC request handler used by the stdio loop and protocol tests.
/// Notifications return `None` as required by JSON-RPC.
fn handle_stdio_message(
    db_path: &Path,
    body: &[u8],
    session: &mut StdioSession,
) -> Option<serde_json::Value> {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return Some(rpc_error(
                serde_json::Value::Null,
                -32700,
                "Parse error",
                Some(serde_json::json!({"detail": error.to_string()})),
            ));
        }
    };
    let id = value.get("id").cloned();
    let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
        return Some(rpc_error(
            id.unwrap_or(serde_json::Value::Null),
            -32600,
            "Invalid Request",
            None,
        ));
    };
    if value.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
        return Some(rpc_error(
            id.unwrap_or(serde_json::Value::Null),
            -32600,
            "Invalid Request",
            None,
        ));
    }

    // Notifications never receive a response.
    if id.is_none() {
        if method == "notifications/initialized" && session.initialize_seen {
            session.ready = true;
        }
        return None;
    }
    let id = id.expect("checked above");

    if method == "initialize" {
        if session.initialize_seen {
            return Some(rpc_error(
                id,
                -32600,
                "initialize may only be sent once",
                None,
            ));
        }
        let Some(requested) = value
            .pointer("/params/protocolVersion")
            .and_then(serde_json::Value::as_str)
        else {
            return Some(rpc_error(id, -32602, "Invalid params", None));
        };
        let negotiated = if crate::mcp::client::SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
            requested
        } else {
            crate::mcp::client::MCP_PROTOCOL_VERSION
        };
        session.initialize_seen = true;
        return Some(rpc_result(
            id,
            serde_json::json!({
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "neoth-codegraph",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Read-only queries over NEOTH's persisted local code map"
                },
                "instructions": "Only files already indexed in the local code map can be outlined."
            }),
        ));
    }

    if method == "ping" {
        return Some(rpc_result(id, serde_json::json!({})));
    }
    if !session.ready {
        return Some(rpc_error(id, -32002, "Server not initialized", None));
    }

    match method {
        "tools/list" => Some(rpc_result(
            id,
            serde_json::json!({"tools": codegraph_tools()}),
        )),
        "tools/call" => {
            let Some(name) = value
                .pointer("/params/name")
                .and_then(serde_json::Value::as_str)
            else {
                return Some(rpc_error(id, -32602, "Invalid params", None));
            };
            let arguments = value
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            Some(rpc_result(
                id,
                serde_json::to_value(dispatch_codegraph_tool(db_path, name, &arguments))
                    .unwrap_or_else(|error| {
                        serde_json::json!({
                            "content": [{"type": "text", "text": format!("result serialisation failed: {error}")}],
                            "isError": true
                        })
                    }),
            ))
        }
        _ => Some(rpc_error(id, -32601, "Method not found", None)),
    }
}

fn rpc_result(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(
    id: serde_json::Value,
    code: i64,
    message: &str,
    data: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut error = serde_json::json!({"code": code, "message": message});
    if let Some(data) = data {
        error["data"] = data;
    }
    serde_json::json!({"jsonrpc": "2.0", "id": id, "error": error})
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
    fn codegraph_tools_lists_six_canonical_tools() {
        // GOLD-ADAPT-CCS-04: codegraph_outline is the 6th tool.
        let tools = codegraph_tools();
        assert_eq!(tools.len(), 6);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_relevant_files"));
        assert!(names.contains(&"codegraph_extract_identifiers"));
        assert!(names.contains(&"codegraph_path_keywords"));
        assert!(names.contains(&"codegraph_callers"));
        assert!(names.contains(&"codegraph_callees"));
        assert!(names.contains(&"codegraph_outline"));
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
        let symbols: Vec<&str> = rows.iter().map(|r| r["symbol"].as_str().unwrap()).collect();
        assert!(
            symbols.contains(&"middle"),
            "missing middle in: {symbols:?}"
        );
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

    /// Seed a real `code_map.db` (root row + persisted edges) for the
    /// dispatch wiring tests below.
    fn seed_code_map_db(db: &Path) {
        let mut conn = crate::code_map::persist::open(db).unwrap();
        // Edges FK into code_map_roots — seed the root row first.
        conn.execute(
            "INSERT INTO code_map_roots \
             (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped) \
             VALUES ('x.rs', 0, 1, 0, 3, 0)",
            [],
        )
        .unwrap();
        let g = graph_from_rust(
            "x.rs",
            "fn leaf() {}\nfn middle() { leaf(); }\nfn root() { middle(); }\n",
        );
        crate::code_map::persist::persist_edges(&mut conn, "x.rs", g.edges()).unwrap();
    }

    #[test]
    fn dispatch_codegraph_callers_reads_persisted_edges() {
        // The wiring this slice closes: with a real code_map.db that has
        // stored edges, the dispatch surface returns the ACTUAL transitive
        // callers — not `[]` (the empty-graph stub the follow-up replaced).
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        seed_code_map_db(&db);
        let r = dispatch_codegraph_tool(
            &db,
            "codegraph_callers",
            &serde_json::json!({"symbol": "leaf"}),
        );
        assert!(!r.is_error, "got: {}", text_content(&r));
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text_content(&r)).unwrap();
        let syms: Vec<&str> = rows.iter().map(|x| x["symbol"].as_str().unwrap()).collect();
        assert!(syms.contains(&"middle"), "wiring broken — got: {syms:?}");
        assert!(syms.contains(&"root"), "wiring broken — got: {syms:?}");
    }

    #[test]
    fn dispatch_codegraph_callees_reads_persisted_edges() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        seed_code_map_db(&db);
        let r = dispatch_codegraph_tool(
            &db,
            "codegraph_callees",
            &serde_json::json!({"symbol": "root", "file": "x.rs"}),
        );
        assert!(!r.is_error, "got: {}", text_content(&r));
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text_content(&r)).unwrap();
        let names: Vec<&str> = rows.iter().map(|x| x["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"middle"), "wiring broken — got: {names:?}");
        assert!(names.contains(&"leaf"), "wiring broken — got: {names:?}");
    }

    // ── GOLD-ADAPT-CCS-04: codegraph_outline dispatch tests ───────────────

    fn seed_indexed_file(db: &Path, root: &Path, relative: &str) {
        let conn = crate::code_map::persist::open(db).unwrap();
        let root = root.canonicalize().unwrap().display().to_string();
        conn.execute(
            "INSERT INTO code_map_roots \
             (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped) \
             VALUES (?1, 0, 1, 0, 1, 0)",
            rusqlite::params![root],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_map_files \
             (root, path, language, bytes, loc, sha256, mtime_ns) \
             VALUES (?1, ?2, 'rust', 0, 1, '', 0)",
            rusqlite::params![root, relative],
        )
        .unwrap();
    }

    #[test]
    fn dispatch_codegraph_outline_rejects_missing_path() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_outline",
            &serde_json::json!({}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("bad args"));
    }

    #[test]
    fn dispatch_codegraph_outline_rejects_unindexed_file() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_outline",
            &serde_json::json!({"path": "/this/does/not/exist.rs"}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("access denied"));
    }

    #[test]
    fn dispatch_codegraph_outline_fixture_lists_fns_with_line_ranges() {
        // Write a small Rust fixture, run the outline tool, verify the
        // structural result (names + line numbers).
        let dir = tempdir().unwrap();
        let fixture = dir.path().join("fixture.rs");
        std::fs::write(
            &fixture,
            "pub struct Config {}\npub fn init() {}\npub fn run() {\n    // body\n}\n",
        )
        .unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, dir.path(), "fixture.rs");

        let r = dispatch_codegraph_tool(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": "fixture.rs"}),
        );
        assert!(!r.is_error, "got: {}", text_content(&r));

        let entries: Vec<serde_json::Value> = serde_json::from_str(&text_content(&r)).unwrap();
        assert_eq!(entries.len(), 3, "expected 3 outline entries: {entries:?}");

        // Config at line 1
        let cfg = entries.iter().find(|e| e["name"] == "Config").unwrap();
        assert_eq!(cfg["kind"], "struct");
        assert_eq!(cfg["line_start"], 1);

        // init at line 2
        let init = entries.iter().find(|e| e["name"] == "init").unwrap();
        assert_eq!(init["kind"], "function");
        assert_eq!(init["line_start"], 2);

        // run at line 3 — last symbol, line_end == total lines (5)
        let run = entries.iter().find(|e| e["name"] == "run").unwrap();
        assert_eq!(run["kind"], "function");
        assert_eq!(run["line_start"], 3);
        assert_eq!(run["line_end"], 5);
    }

    #[test]
    fn dispatch_codegraph_outline_result_has_all_required_json_keys() {
        let dir = tempdir().unwrap();
        let fixture = dir.path().join("keys.rs");
        std::fs::write(&fixture, "fn one() {}\nfn two() {}\n").unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, dir.path(), "keys.rs");

        let r = dispatch_codegraph_tool(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": fixture.to_str().unwrap()}),
        );
        assert!(!r.is_error);
        let entries: Vec<serde_json::Value> = serde_json::from_str(&text_content(&r)).unwrap();
        for e in &entries {
            assert!(e.get("name").is_some(), "name missing in {e}");
            assert!(e.get("kind").is_some(), "kind missing in {e}");
            assert!(e.get("line_start").is_some(), "line_start missing in {e}");
            assert!(e.get("line_end").is_some(), "line_end missing in {e}");
        }
    }

    #[test]
    fn dispatch_codegraph_outline_cannot_read_unindexed_neighbor() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("indexed.rs"), "fn allowed() {}\n").unwrap();
        let secret = dir.path().join("secret.rs");
        std::fs::write(&secret, "fn must_not_leak() {}\n").unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, dir.path(), "indexed.rs");

        let denied = dispatch_codegraph_tool(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": secret}),
        );
        assert!(denied.is_error);
        assert!(!text_content(&denied).contains("must_not_leak"));
    }

    // ── Production stdio JSON-RPC wiring ─────────────────────────────────

    fn message(
        db: &Path,
        session: &mut StdioSession,
        value: serde_json::Value,
    ) -> Option<serde_json::Value> {
        handle_stdio_message(db, &serde_json::to_vec(&value).unwrap(), session)
    }

    #[test]
    fn stdio_server_negotiates_and_requires_initialized_notification() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut session = StdioSession::default();
        let initialized = message(
            &db,
            &mut session,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}
            }),
        )
        .unwrap();
        assert_eq!(initialized["id"], "init-1");
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            initialized["result"]["capabilities"]["tools"]["listChanged"],
            false
        );

        let early = message(
            &db,
            &mut session,
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .unwrap();
        assert_eq!(early["error"]["code"], -32002);

        assert!(
            message(
                &db,
                &mut session,
                serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            )
            .is_none(),
            "notifications must never receive a response"
        );
        let listed = message(
            &db,
            &mut session,
            serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        )
        .unwrap();
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn stdio_server_calls_real_dispatcher_and_preserves_string_id() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut session = StdioSession {
            initialize_seen: true,
            ready: true,
        };
        let response = message(
            &db,
            &mut session,
            serde_json::json!({
                "jsonrpc":"2.0",
                "id":"call-7",
                "method":"tools/call",
                "params":{"name":"codegraph_extract_identifiers","arguments":{"text":"OrderService auth_middleware"}}
            }),
        )
        .unwrap();
        assert_eq!(response["id"], "call-7");
        assert_eq!(response["result"]["isError"], false);
        let payload = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(payload.contains("OrderService"));
        assert!(payload.contains("auth_middleware"));
    }

    #[test]
    fn stdio_server_returns_json_rpc_errors_for_parse_and_unknown_method() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut session = StdioSession {
            initialize_seen: true,
            ready: true,
        };
        let parse = handle_stdio_message(&db, b"not json", &mut session).unwrap();
        assert_eq!(parse["error"]["code"], -32700);
        let unknown = message(
            &db,
            &mut session,
            serde_json::json!({"jsonrpc":"2.0","id":9,"method":"resources/list","params":{}}),
        )
        .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
    }
}
