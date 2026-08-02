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
//! Today's tool set (8 tools, including a versioned recall receipt):
//!
//! - `codegraph_relevant_files` — top-N files for a prompt
//! - `codegraph_recall_v1` — identity/generation-bound recall envelope
//! - `codegraph_extract_identifiers` — symbol-shape extraction
//! - `codegraph_path_keywords` — path-segment extraction
//! - `codegraph_callers` — transitive callers of a symbol (inverse BFS)
//! - `codegraph_callees` — transitive callees of a symbol (forward BFS)
//! - `codegraph_impact_radius` — generation-bound, concrete-node blast radius
//! - `codegraph_outline` — structural outline for a file already indexed in
//!   the persisted code map
//!
//! Each is a pure read against the operator's persisted code map
//! (`~/.neoth/code_map.db`): relevant_files ranks stored file rows;
//! callers/callees reconstruct the [`CallGraph`] from the stored
//! `code_map_edges` table. Impact analysis additionally re-hashes the indexed
//! root to enforce its default fail-closed staleness contract. No source is
//! returned, no provider calls or network access occur, and no project files
//! are mutated. Safe to expose to any MCP client the operator's autonomy level
//! allows.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::mcp::client::{McpContent, McpTool, ToolAnnotations, ToolCallResult};

fn open_code_map_read_only(path: &Path) -> Result<rusqlite::Connection> {
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    rusqlite::Connection::open_with_flags(path, flags)
        .with_context(|| format!("open code-map DB read-only at {}", path.display()))
}

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
                 symbol hits with path overlap as tie-break. Legacy response: JSON array. \
                 Only fresh, complete receipts can be represented safely; use \
                 codegraph_recall_v1 for stale/truncated states and the full \
                 identity/generation receipt envelope."
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
            name: "codegraph_recall_v1".into(),
            description: Some(
                "Return a versioned repository-local recall receipt containing canonical root \
                 identity, index/graph generations, freshness, truncation truth and ranked files."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Free-form text used for identifier and path ranking."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 50
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
                 Refuses stale, partial, generation-mismatched or over-budget snapshots. \
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
                 Refuses stale, partial, generation-mismatched or over-budget snapshots. \
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
        McpTool {
            name: "codegraph_impact_radius".into(),
            description: Some(
                "Compute a deterministic structural blast radius from changed files or exact \
                 declarations in the active persisted repository. Every traversed endpoint is \
                 resolved to one concrete root/file/symbol/line identity; missing or ambiguous \
                 name-only edges remain explicit unresolved evidence. Refuses mismatched graph \
                 generations and stale indexes by default, and marks node-cap versus bounded \
                 evidence truncation separately."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "seeds": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": crate::code_map::impact::MAX_REQUESTED_SEEDS,
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "Repo-relative indexed file path."
                                },
                                "symbol": {
                                    "type": "string",
                                    "description": "Optional exact declaration name. Omit to seed every declaration in the file."
                                }
                            },
                            "required": ["file"],
                            "additionalProperties": false
                        }
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["callers", "callees", "both"],
                        "default": "callers",
                        "description": "Dependents, dependencies, or both neighborhoods."
                    },
                    "max_depth": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": crate::code_map::impact::MAX_IMPACT_DEPTH,
                        "default": crate::code_map::impact::DEFAULT_MAX_DEPTH
                    },
                    "max_nodes": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": crate::code_map::impact::MAX_IMPACT_NODES,
                        "default": crate::code_map::impact::DEFAULT_MAX_NODES
                    },
                    "allow_stale": {
                        "type": "boolean",
                        "default": false,
                        "description": "Explicitly permit a stale index; the result still records stale=true."
                    }
                },
                "required": ["seeds"],
                "additionalProperties": false
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
                 Language is inferred from the file extension. The file must belong \
                 to the fresh, complete active code-map generation; reads are \
                 hash-bound, size-bounded and refuse symlink/reparse traversal. \
                 Missing, stale and unreadable files are explicit errors."
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
    "codegraph_recall_v1",
    "codegraph_extract_identifiers",
    "codegraph_path_keywords",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_impact_radius",
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
    // The server runs as a stdio child and inherits the client's working
    // directory; that directory is what decides WHICH indexed repository may
    // answer. Resolved once here and threaded down, so every tool on this
    // surface applies the same containment and tests can state the location
    // explicitly instead of depending on the test runner's cwd.
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    dispatch_codegraph_tool_at(db_path, tool_name, args, &cwd)
}

pub(crate) fn dispatch_codegraph_tool_at(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
) -> ToolCallResult {
    match tool_name {
        "codegraph_extract_identifiers" => tool_extract_identifiers(args),
        "codegraph_path_keywords" => tool_path_keywords(args),
        "codegraph_relevant_files" => tool_relevant_files(db_path, args, cwd, false),
        "codegraph_recall_v1" => tool_relevant_files(db_path, args, cwd, true),
        "codegraph_callers" => tool_callers(db_path, args, cwd),
        "codegraph_callees" => tool_callees(db_path, args, cwd),
        "codegraph_impact_radius" => tool_impact_radius(db_path, args, cwd),
        "codegraph_outline" => tool_outline(db_path, args, cwd),
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

fn tool_relevant_files(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    versioned: bool,
) -> ToolCallResult {
    let parsed: RelevantFilesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let limit = parsed.limit.clamp(1, 50) as usize;
    match recall_v1_inner(db_path, &parsed.prompt, limit, cwd) {
        Ok(envelope) => {
            let payload: Result<String> = if versioned {
                serde_json::to_string(&envelope).map_err(Into::into)
            } else {
                legacy_relevant_files_json(&envelope)
            };
            match payload {
                Ok(payload) => text_result(payload),
                Err(error) if versioned => {
                    error_result(format!("serialize codegraph_recall_v1 result: {error:#}"))
                }
                Err(error) => error_result(format!(
                    "codegraph_relevant_files refused unsafe legacy result: {error:#}"
                )),
            }
        }
        Err(e) => error_result(format!("relevant_files failed: {e:#}")),
    }
}

fn recall_v1_inner(
    db_path: &Path,
    prompt: &str,
    limit: usize,
    cwd: &Path,
) -> Result<crate::code_map::recall_wire::RecallWireEnvelope> {
    if !db_path
        .try_exists()
        .with_context(|| format!("inspect code-map DB path {}", db_path.display()))?
    {
        // Missing setup is a valid zero-result state, but it still uses the
        // same versioned envelope as a successful recall so clients never
        // have to infer whether an empty array carried a generation receipt.
        return crate::code_map::recall_wire::RecallWireEnvelope::empty(
            crate::code_map::recall_wire::RecallWireStatus::Unavailable,
            prompt,
            limit,
            "code-map index is not built",
        );
    }
    let conn = open_code_map_read_only(db_path)?;
    let Some(receipt) = crate::code_map::recall::recall_receipt_for_prompt(
        &conn,
        cwd,
        prompt,
        limit,
        crate::code_map::recall::RecallStaleness::Check,
    )?
    else {
        return crate::code_map::recall_wire::RecallWireEnvelope::empty(
            crate::code_map::recall_wire::RecallWireStatus::Unmapped,
            prompt,
            limit,
            "server working directory is not inside a persisted code-map root",
        );
    };
    anyhow::ensure!(
        receipt.snapshot.index_generation > 0 && receipt.snapshot.graph_generation > 0,
        "code-map recall has no published positive generation; rebuild the code map"
    );
    anyhow::ensure!(
        receipt.snapshot.index_generation == receipt.snapshot.graph_generation,
        "code-map recall index generation {} does not match graph generation {}; rebuild the code map",
        receipt.snapshot.index_generation,
        receipt.snapshot.graph_generation
    );
    crate::code_map::recall_wire::RecallWireEnvelope::success(prompt, limit, &receipt)
}

fn legacy_relevant_files_json(
    envelope: &crate::code_map::recall_wire::RecallWireEnvelope,
) -> Result<String> {
    let Some(receipt) = envelope.receipt.as_ref() else {
        return Ok("[]".into());
    };
    match receipt.stale {
        Some(false) => {}
        Some(true) => anyhow::bail!(
            "legacy codegraph_relevant_files refuses stale recall evidence; use \
             codegraph_recall_v1 and inspect its receipt"
        ),
        None => anyhow::bail!(
            "legacy codegraph_relevant_files refuses recall evidence with unknown freshness; use \
             codegraph_recall_v1 and inspect its receipt"
        ),
    }
    if receipt.truncated {
        anyhow::bail!(
            "legacy codegraph_relevant_files refuses truncated recall evidence; use \
             codegraph_recall_v1 and inspect its receipt"
        );
    }
    if receipt.index_generation <= 0
        || receipt.graph_generation <= 0
        || receipt.index_generation != receipt.graph_generation
    {
        anyhow::bail!(
            "legacy codegraph_relevant_files refuses unpublished or mismatched generations; use \
             codegraph_recall_v1 and inspect its receipt"
        );
    }
    let rows: Vec<serde_json::Value> = receipt
        .hits
        .iter()
        .map(|hit| {
            serde_json::json!({
                "root": hit.root,
                "path": hit.path,
                "identifier_hits": hit.identifier_hits,
                "matched_symbols": hit.matched_symbols,
                "path_keyword_overlap": hit.path_keyword_overlap,
                "index_generation": receipt.index_generation,
            })
        })
        .collect();
    Ok(serde_json::to_string(&rows)?)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImpactArgs {
    seeds: Vec<crate::code_map::impact::ImpactSeed>,
    #[serde(default)]
    direction: crate::code_map::impact::ImpactDirection,
    #[serde(default = "default_impact_depth")]
    max_depth: usize,
    #[serde(default = "default_impact_nodes")]
    max_nodes: usize,
    #[serde(default)]
    allow_stale: bool,
}

fn default_impact_depth() -> usize {
    crate::code_map::impact::DEFAULT_MAX_DEPTH
}

fn default_impact_nodes() -> usize {
    crate::code_map::impact::DEFAULT_MAX_NODES
}

fn tool_impact_radius(db_path: &Path, args: &serde_json::Value, cwd: &Path) -> ToolCallResult {
    let parsed: ImpactArgs = match serde_json::from_value(args.clone()) {
        Ok(parsed) => parsed,
        Err(error) => return error_result(format!("bad args: {error}")),
    };
    let db_exists = match db_path.try_exists() {
        Ok(exists) => exists,
        Err(error) => {
            return error_result(format!(
                "codegraph_impact_radius failed to inspect code-map DB {}: {error}",
                db_path.display()
            ));
        }
    };
    if !db_exists {
        return error_result(format!(
            "codegraph_impact_radius failed: code-map DB {} does not exist; \
             run `neoth code-map persist` first",
            db_path.display()
        ));
    }
    let conn = match open_code_map_read_only(db_path) {
        Ok(conn) => conn,
        Err(error) => {
            return error_result(format!(
                "codegraph_impact_radius failed to open {}: {error:#}",
                db_path.display()
            ));
        }
    };
    let result = match crate::code_map::impact::impact_radius_for_path(
        &conn,
        cwd,
        &parsed.seeds,
        crate::code_map::impact::ImpactOptions {
            direction: parsed.direction,
            max_depth: parsed.max_depth,
            max_nodes: parsed.max_nodes,
            allow_stale: parsed.allow_stale,
        },
    ) {
        Ok(result) => result,
        Err(error) => {
            return error_result(format!("codegraph_impact_radius failed: {error:#}"));
        }
    };
    match serde_json::to_string(&result) {
        Ok(payload) => text_result(payload),
        Err(error) => error_result(format!(
            "codegraph_impact_radius result serialisation failed: {error}"
        )),
    }
}

const CALL_GRAPH_EDGE_LIMIT: usize = 250_000;
const CALL_GRAPH_EDGE_TEXT_BYTE_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct StoredGraphSnapshot {
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
    complete: bool,
}

fn stored_graph_snapshot(conn: &rusqlite::Connection, root: &str) -> Result<StoredGraphSnapshot> {
    conn.query_row(
        "SELECT root_identity, index_generation, graph_generation, \
                oversize_skipped = 0 AND truncated_at IS NULL \
         FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| {
            Ok(StoredGraphSnapshot {
                root_identity: row.get(0)?,
                index_generation: row.get(1)?,
                graph_generation: row.get(2)?,
                complete: row.get(3)?,
            })
        },
    )
    .with_context(|| format!("read call-graph snapshot metadata for {root:?}"))
}

fn validate_stored_graph_snapshot(
    expected: &crate::code_map::recall::RootGenerationSnapshot,
    stored: &StoredGraphSnapshot,
) -> Result<()> {
    anyhow::ensure!(
        stored.root_identity == expected.root.identity().as_str(),
        "code-map root identity changed before call-graph materialization; retry after rebuilding"
    );
    anyhow::ensure!(
        stored.index_generation == expected.index_generation
            && stored.graph_generation == expected.graph_generation,
        "code-map generations changed before call-graph materialization; retry"
    );
    anyhow::ensure!(
        stored.index_generation > 0 && stored.graph_generation > 0,
        "code-map call graph has no published positive generation; rebuild the code map"
    );
    anyhow::ensure!(
        stored.index_generation == stored.graph_generation,
        "code-map index generation {} does not match graph generation {}; rebuild the code map",
        stored.index_generation,
        stored.graph_generation
    );
    anyhow::ensure!(
        stored.complete,
        "code-map root was published from a partial scan; rebuild without explicit limits before querying the call graph"
    );
    Ok(())
}

/// Load the call graph from one identity- and generation-bound code-map root.
/// Missing or unmapped state is an explicit error, distinct from a certified
/// snapshot that legitimately contains zero edges. Corrupt, partial, stale or
/// over-budget snapshots also fail closed.
fn graph_from_db(db_path: &Path, cwd: &Path) -> Result<crate::code_map::graph::CallGraph> {
    graph_from_db_with_limits(
        db_path,
        cwd,
        CALL_GRAPH_EDGE_LIMIT,
        CALL_GRAPH_EDGE_TEXT_BYTE_LIMIT,
    )
}

fn graph_from_db_with_limits(
    db_path: &Path,
    cwd: &Path,
    edge_limit: usize,
    edge_text_byte_limit: usize,
) -> Result<crate::code_map::graph::CallGraph> {
    if !db_path
        .try_exists()
        .with_context(|| format!("inspect code-map DB path {}", db_path.display()))?
    {
        anyhow::bail!(
            "code-map DB does not exist at {}; run `neoth code-map persist` first",
            db_path.display()
        );
    }
    let conn = open_code_map_read_only(db_path)?;
    // Typed resolution preserves canonicalization, SQLite and physical-identity
    // failures. A genuine no-match is unavailable evidence, not an empty graph.
    let Some(expected) = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)? else {
        anyhow::bail!(
            "working directory {} is not inside a persisted code-map root",
            cwd.display()
        );
    };
    anyhow::ensure!(
        expected.index_generation > 0 && expected.graph_generation > 0,
        "code-map call graph has no published positive generation; rebuild the code map"
    );
    anyhow::ensure!(
        expected.index_generation == expected.graph_generation,
        "code-map index generation {} does not match graph generation {}; rebuild the code map",
        expected.index_generation,
        expected.graph_generation
    );

    // Root metadata, completeness and edges are read from one stable SQLite
    // snapshot. The filesystem is observed on both sides of edge loading so a
    // mid-query edit cannot be reported as fresh.
    let tx = conn
        .unchecked_transaction()
        .context("begin atomic call-graph read transaction")?;
    let initial_stored = stored_graph_snapshot(&tx, expected.root.display())?;
    validate_stored_graph_snapshot(&expected, &initial_stored)?;
    let initial_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !initial_freshness.stale,
        "code-map call graph is stale; rebuild the code map before querying it"
    );
    let (edges, truncated, _) =
        crate::code_map::persist::load_edges_for_root_bounded_with_text_limit(
            &tx,
            expected.root.display(),
            edge_limit,
            edge_text_byte_limit,
        )?;
    anyhow::ensure!(
        !truncated,
        "code-map call graph exceeds the per-root edge ceiling of {edge_limit}; narrow or rebuild the index"
    );
    let final_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !final_freshness.stale
            && initial_freshness.filesystem_fingerprint == final_freshness.filesystem_fingerprint,
        "code-map root changed during call-graph materialization; rebuild and retry"
    );
    let final_stored = stored_graph_snapshot(&tx, expected.root.display())?;
    validate_stored_graph_snapshot(&expected, &final_stored)?;
    anyhow::ensure!(
        final_stored == initial_stored,
        "code-map snapshot changed during call-graph materialization; retry"
    );
    tx.commit()
        .context("commit atomic call-graph read transaction")?;

    // Close the window between the original active-root resolution and the
    // completed read. A renamed/replaced root or a newer writer generation is
    // never allowed to inherit this graph's answer.
    let final_active = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)?;
    anyhow::ensure!(
        final_active.as_ref() == Some(&expected),
        "active code-map root or generation changed during call-graph materialization; retry"
    );
    Ok(crate::code_map::graph::CallGraph::from_edges(edges))
}

fn tool_callers(db_path: &Path, args: &serde_json::Value, cwd: &Path) -> ToolCallResult {
    let parsed: CallersArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    let graph = match graph_from_db(db_path, cwd) {
        Ok(g) => g,
        Err(e) => return error_result(format!("codegraph_callers failed: {e:#}")),
    };
    text_result(callers_inner(&graph, &parsed.symbol, depth))
}

fn tool_callees(db_path: &Path, args: &serde_json::Value, cwd: &Path) -> ToolCallResult {
    let parsed: CalleesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let depth = parsed.depth.clamp(1, 20) as usize;
    let graph = match graph_from_db(db_path, cwd) {
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

fn tool_outline(db_path: &Path, args: &serde_json::Value, cwd: &Path) -> ToolCallResult {
    let parsed: OutlineArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return error_result(format!("bad args: {e}")),
    };
    let entries = match outline_from_db(db_path, &parsed.path, cwd) {
        Ok(entries) => entries,
        Err(error) => return error_result(format!("codegraph_outline failed: {error:#}")),
    };
    match serde_json::to_string(&entries) {
        Ok(payload) => text_result(payload),
        Err(e) => error_result(format!("outline serialisation failed: {e}")),
    }
}

const OUTLINE_MAX_FILE_BYTES: u64 = crate::code_map::walker::DEFAULT_MAX_FILE_BYTES;

#[derive(Debug)]
struct IndexedOutlineFile {
    relative_path: String,
    bytes: u64,
    sha256: String,
}

fn outline_from_db(
    db_path: &Path,
    requested: &str,
    cwd: &Path,
) -> Result<Vec<crate::code_map::outline::OutlineEntry>> {
    outline_from_db_with_hooks(db_path, requested, cwd, |_| {}, |_| {})
}

fn outline_from_db_with_hooks<BeforeRead, AfterRead>(
    db_path: &Path,
    requested: &str,
    cwd: &Path,
    before_read: BeforeRead,
    after_read: AfterRead,
) -> Result<Vec<crate::code_map::outline::OutlineEntry>>
where
    BeforeRead: FnOnce(&Path),
    AfterRead: FnOnce(&Path),
{
    let requested = requested.trim();
    if requested.is_empty() {
        anyhow::bail!("path is empty");
    }
    if !db_path
        .try_exists()
        .with_context(|| format!("inspect code-map DB path {}", db_path.display()))?
    {
        anyhow::bail!("code-map database is missing; build it before requesting file outlines");
    }

    let conn = open_code_map_read_only(db_path)?;
    let Some(expected) = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)? else {
        anyhow::bail!(
            "working directory is not inside an indexed repository; build a code map before requesting outlines"
        );
    };
    anyhow::ensure!(
        expected.index_generation > 0 && expected.graph_generation > 0,
        "code-map outline has no published positive generation; rebuild the code map"
    );
    anyhow::ensure!(
        expected.index_generation == expected.graph_generation,
        "code-map outline index generation {} does not match graph generation {}; rebuild the code map",
        expected.index_generation,
        expected.graph_generation
    );
    let relative = requested_outline_relative_path(expected.root.path(), Path::new(requested))?;

    let tx = conn
        .unchecked_transaction()
        .context("begin atomic codegraph-outline read transaction")?;
    let initial_stored = stored_graph_snapshot(&tx, expected.root.display())?;
    validate_stored_graph_snapshot(&expected, &initial_stored)?;
    let initial_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !initial_freshness.stale,
        "code-map outline snapshot is stale; rebuild the code map before requesting outlines"
    );
    let indexed = indexed_outline_file(&tx, expected.root.display(), &relative)?;
    let path = checked_outline_path(expected.root.path(), &indexed.relative_path)?;
    before_read(&path);
    let source = read_indexed_outline_source(expected.root.path(), &indexed)?;
    after_read(&path);
    let final_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !final_freshness.stale
            && initial_freshness.filesystem_fingerprint == final_freshness.filesystem_fingerprint,
        "code-map root changed during outline read; rebuild and retry"
    );
    let final_stored = stored_graph_snapshot(&tx, expected.root.display())?;
    validate_stored_graph_snapshot(&expected, &final_stored)?;
    anyhow::ensure!(
        final_stored == initial_stored,
        "code-map snapshot changed during outline read; retry"
    );
    tx.commit()
        .context("commit atomic codegraph-outline read transaction")?;

    let final_active = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)?;
    anyhow::ensure!(
        final_active.as_ref() == Some(&expected),
        "active code-map root or generation changed during outline read; retry"
    );
    Ok(crate::code_map::outline::outline_source(
        &source,
        crate::code_map::walker::Language::from_path(&path),
    ))
}

fn requested_outline_relative_path(root: &Path, requested: &Path) -> Result<String> {
    let relative = if requested.is_absolute() {
        match requested.strip_prefix(root) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => {
                // Windows canonical roots commonly use an extended-length
                // prefix while client arguments use the ordinary drive form.
                // Canonicalisation is used only to map that spelling to the
                // persisted relative key; the actual read is rebuilt from the
                // trusted root and opened with no-follow semantics below.
                let canonical = requested.canonicalize().with_context(|| {
                    format!("canonicalize absolute outline path {}", requested.display())
                })?;
                canonical
                    .strip_prefix(root)
                    .with_context(|| {
                        format!(
                            "absolute outline path {} is outside active root {}",
                            requested.display(),
                            root.display()
                        )
                    })?
                    .to_path_buf()
            }
        }
    } else {
        requested.to_path_buf()
    };
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().context("outline path is not valid UTF-8")?;
                anyhow::ensure!(
                    !part.is_empty() && !part.contains('\\'),
                    "outline path contains an ambiguous separator"
                );
                parts.push(part);
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                anyhow::bail!("outline path must be a normalized repository-relative file path")
            }
        }
    }
    anyhow::ensure!(!parts.is_empty(), "outline path is empty");
    Ok(parts.join("/"))
}

fn indexed_outline_file(
    conn: &rusqlite::Connection,
    root: &str,
    relative: &str,
) -> Result<IndexedOutlineFile> {
    let mut stmt = conn
        .prepare(
            "SELECT path, bytes, sha256 FROM code_map_files \
             WHERE root = ?1 AND path = ?2 LIMIT 2",
        )
        .context("prepare indexed-outline file query")?;
    let rows = stmt
        .query_map(rusqlite::params![root, relative], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .context("query indexed-outline file")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect indexed-outline file")?;
    let [(relative_path, bytes, sha256)] = rows.as_slice() else {
        anyhow::bail!("`{relative}` is not exactly one indexed code-map file");
    };
    let bytes = u64::try_from(*bytes).context("indexed outline file has a negative byte length")?;
    anyhow::ensure!(
        bytes <= OUTLINE_MAX_FILE_BYTES,
        "indexed outline file exceeds the {OUTLINE_MAX_FILE_BYTES}-byte read ceiling"
    );
    anyhow::ensure!(
        sha256.len() == 64 && sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "indexed outline file has no valid SHA-256 binding; rebuild the code map"
    );
    Ok(IndexedOutlineFile {
        relative_path: relative_path.clone(),
        bytes,
        sha256: sha256.clone(),
    })
}

fn checked_outline_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    let components: Vec<&str> = relative.split('/').collect();
    anyhow::ensure!(
        !components.is_empty()
            && components
                .iter()
                .all(|component| !component.is_empty() && *component != "." && *component != ".."),
        "persisted outline path is not a normalized relative path"
    );
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!("inspect indexed outline path component {}", path.display())
        })?;
        anyhow::ensure!(
            !metadata_is_link_or_reparse(&metadata),
            "indexed outline path contains a symlink or reparse point: {}",
            path.display()
        );
        if index + 1 == components.len() {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "indexed outline path is not a regular file: {}",
                path.display()
            );
        } else {
            anyhow::ensure!(
                metadata.file_type().is_dir(),
                "indexed outline parent is not a directory: {}",
                path.display()
            );
        }
    }
    Ok(path)
}

fn metadata_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn read_indexed_outline_source(root: &Path, indexed: &IndexedOutlineFile) -> Result<String> {
    let path = checked_outline_path(root, &indexed.relative_path)?;
    let before = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect indexed outline file {}", path.display()))?;
    anyhow::ensure!(
        before.file_type().is_file() && !metadata_is_link_or_reparse(&before),
        "indexed outline path is not a regular non-reparse file: {}",
        path.display()
    );
    let mut file = open_outline_file_no_follow(&path)?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened outline file {}", path.display()))?;
    anyhow::ensure!(
        opened.file_type().is_file() && !metadata_is_link_or_reparse(&opened),
        "opened outline path is not a regular non-reparse file: {}",
        path.display()
    );
    let path_probe = open_outline_file_no_follow(&path)?;
    anyhow::ensure!(
        same_outline_file_identity(&file, &path_probe)?,
        "indexed outline file changed identity while it was opened"
    );
    drop(path_probe);
    anyhow::ensure!(
        opened.len() == indexed.bytes && opened.len() <= OUTLINE_MAX_FILE_BYTES,
        "indexed outline file length no longer matches its persisted snapshot"
    );
    let capacity = usize::try_from(indexed.bytes).context("convert outline allocation bound")?;
    let mut raw = Vec::with_capacity(capacity);
    file.by_ref()
        .take(OUTLINE_MAX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .with_context(|| format!("read bounded indexed outline file {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(raw.len()).context("convert outline read length")? <= OUTLINE_MAX_FILE_BYTES,
        "indexed outline file exceeded the {OUTLINE_MAX_FILE_BYTES}-byte read ceiling"
    );
    anyhow::ensure!(
        u64::try_from(raw.len()).context("convert outline content length")? == indexed.bytes,
        "indexed outline file changed length while it was read"
    );
    let actual_sha256 = format!("{:x}", Sha256::digest(&raw));
    anyhow::ensure!(
        actual_sha256 == indexed.sha256,
        "indexed outline file content no longer matches its persisted SHA-256"
    );
    let after_path = checked_outline_path(root, &indexed.relative_path)?;
    anyhow::ensure!(
        after_path == path,
        "indexed outline path changed while it was read"
    );
    let after_probe = open_outline_file_no_follow(&after_path)?;
    anyhow::ensure!(
        same_outline_file_identity(&file, &after_probe)?,
        "indexed outline file changed identity while it was read"
    );
    String::from_utf8(raw).context("indexed outline file is not valid UTF-8")
}

fn open_outline_file_no_follow(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).with_context(|| {
        format!(
            "open indexed outline file without following links {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn same_outline_file_identity(left: &std::fs::File, right: &std::fs::File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let left = left.metadata().context("inspect first outline handle")?;
    let right = right.metadata().context("inspect second outline handle")?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_outline_file_identity(left: &std::fs::File, right: &std::fs::File) -> Result<bool> {
    Ok(windows_outline_file_identity(left)? == windows_outline_file_identity(right)?)
}

#[cfg(windows)]
fn windows_outline_file_identity(file: &std::fs::File) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let handle: HANDLE = file.as_raw_handle().cast();
    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `handle` comes from a live `std::fs::File`; `information` is
    // correctly sized/aligned writable storage and is observed only after the
    // Win32 call reports success.
    if unsafe { GetFileInformationByHandle(handle, information.as_mut_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("identify opened outline file by Win32 handle");
    }
    // SAFETY: the successful Win32 call initialized the entire structure.
    let information = unsafe { information.assume_init() };
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, file_index))
}

#[cfg(not(any(unix, windows)))]
fn same_outline_file_identity(left: &std::fs::File, right: &std::fs::File) -> Result<bool> {
    let left = left.metadata().context("inspect first outline handle")?;
    let right = right.metadata().context("inspect second outline handle")?;
    Ok(left.len() == right.len() && left.modified().ok() == right.modified().ok())
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
                let message = encode_bounded_stdio_response(&response)?;
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

fn encode_bounded_stdio_response(response: &serde_json::Value) -> Result<Vec<u8>> {
    encode_bounded_stdio_response_with_limit(response, crate::mcp::transport::MAX_MCP_FRAME_BYTES)
}

fn encode_bounded_stdio_response_with_limit(
    response: &serde_json::Value,
    body_limit: usize,
) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(response).context("encode MCP response")?;
    if encoded.len() <= body_limit {
        return Ok(crate::mcp::transport::frame(&encoded));
    }

    let id = response
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let fallback = rpc_error(
        id,
        -32003,
        "Response exceeds MCP frame limit",
        Some(serde_json::json!({
            "encoded_bytes": encoded.len(),
            "limit_bytes": body_limit,
        })),
    );
    let mut fallback =
        serde_json::to_vec(&fallback).context("encode bounded MCP error response")?;
    if fallback.len() > body_limit {
        // A request ID is client-controlled JSON and can itself be larger than
        // the response cap. JSON-RPC permits `null` when an ID cannot be
        // represented safely; never let an oversized ID turn the bounded
        // fallback into a second oversized frame or terminate the server.
        fallback = serde_json::to_vec(&rpc_error(
            serde_json::Value::Null,
            -32003,
            "Response exceeds MCP frame limit",
            Some(serde_json::json!({"limit_bytes": body_limit})),
        ))
        .context("encode minimal bounded MCP error response")?;
    }
    if fallback.len() > body_limit {
        anyhow::bail!(
            "MCP response limit {body_limit} bytes is too small for the bounded error envelope"
        );
    }
    Ok(crate::mcp::transport::frame(&fallback))
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
    fn codegraph_tools_lists_eight_canonical_tools() {
        let tools = codegraph_tools();
        assert_eq!(tools.len(), 8);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_relevant_files"));
        assert!(names.contains(&"codegraph_recall_v1"));
        assert!(names.contains(&"codegraph_extract_identifiers"));
        assert!(names.contains(&"codegraph_path_keywords"));
        assert!(names.contains(&"codegraph_callers"));
        assert!(names.contains(&"codegraph_callees"));
        assert!(names.contains(&"codegraph_impact_radius"));
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
        // Backward-compatible legacy tool contract: an operator who has not
        // built a map receives the same empty array existing MCP clients parse.
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("never-built.db"),
            "codegraph_relevant_files",
            &serde_json::json!({"prompt": "any prompt"}),
        );
        assert!(!r.is_error, "missing DB must not produce error result");
        assert_eq!(text_content(&r), "[]");
    }

    #[test]
    fn dispatch_recall_v1_returns_typed_unavailable_receipt_when_db_missing() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("never-built.db"),
            "codegraph_recall_v1",
            &serde_json::json!({"prompt": "any prompt"}),
        );
        assert!(!r.is_error);
        let body = crate::code_map::RecallWireEnvelope::parse_json(&text_content(&r)).unwrap();
        assert_eq!(body.status, crate::code_map::RecallWireStatus::Unavailable);
        assert!(body.receipt.is_none());
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
        assert_eq!(text_content(&r), "[]");
    }

    fn legacy_recall_envelope(
        stale: Option<bool>,
        truncated: bool,
    ) -> crate::code_map::recall_wire::RecallWireEnvelope {
        crate::code_map::recall_wire::RecallWireEnvelope {
            schema: crate::code_map::recall_wire::RECALL_WIRE_SCHEMA.to_owned(),
            status: crate::code_map::recall_wire::RecallWireStatus::Ok,
            prompt: "find AuthService".into(),
            max: 5,
            receipt: Some(crate::code_map::recall_wire::RecallWireReceipt {
                root: "/repo".into(),
                root_identity: "test-root".into(),
                index_generation: 1,
                graph_generation: 1,
                stale,
                truncated,
                hits: vec![crate::code_map::recall_wire::RecallWireHit {
                    root: "/repo".into(),
                    path: "src/auth.rs".into(),
                    identifier_hits: 1,
                    matched_symbols: vec!["AuthService".into()],
                    path_keyword_overlap: 1,
                }],
            }),
            note: None,
        }
    }

    #[test]
    fn legacy_relevant_files_refuses_unverifiable_receipts() {
        let mut zero_generation = legacy_recall_envelope(Some(false), false);
        zero_generation.receipt.as_mut().unwrap().index_generation = 0;
        let mut mismatched_generation = legacy_recall_envelope(Some(false), false);
        mismatched_generation
            .receipt
            .as_mut()
            .unwrap()
            .graph_generation = 2;
        for envelope in [
            legacy_recall_envelope(Some(true), false),
            legacy_recall_envelope(None, false),
            legacy_recall_envelope(Some(false), true),
            zero_generation,
            mismatched_generation,
        ] {
            let error = legacy_relevant_files_json(&envelope).unwrap_err();
            assert!(
                error.to_string().contains("codegraph_recall_v1"),
                "legacy rejection must direct the client to the receipt surface: {error:#}"
            );
        }
    }

    #[test]
    fn legacy_relevant_files_keeps_fresh_complete_compatibility_shape() {
        let json = legacy_relevant_files_json(&legacy_recall_envelope(Some(false), false)).unwrap();
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["path"], "src/auth.rs");
        assert_eq!(rows[0]["index_generation"], 1);
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
    fn dispatch_codegraph_callers_rejects_missing_snapshot() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callers",
            &serde_json::json!({"symbol": "foo"}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("code-map DB does not exist"));
    }

    #[test]
    fn dispatch_codegraph_callees_rejects_missing_snapshot() {
        let dir = tempdir().unwrap();
        let r = dispatch_codegraph_tool(
            &dir.path().join("code_map.db"),
            "codegraph_callees",
            &serde_json::json!({"symbol": "foo", "file": "a.rs"}),
        );
        assert!(r.is_error);
        assert!(text_content(&r).contains("code-map DB does not exist"));
    }

    #[test]
    fn dispatch_call_graph_distinguishes_certified_zero_edges_from_unavailable() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db = dir.path().join("code_map.db");
        let map = crate::code_map::walker::RepoMapBuilder::new(&repo)
            .with_symbols(true)
            .scan()
            .unwrap();
        let mut conn = crate::code_map::persist::open(&db).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut conn, &map, &[]).unwrap();
        drop(conn);

        for (tool, args) in [
            ("codegraph_callers", serde_json::json!({"symbol": "foo"})),
            (
                "codegraph_callees",
                serde_json::json!({"symbol": "foo", "file": "a.rs"}),
            ),
        ] {
            let result = dispatch_codegraph_tool_at(&db, tool, &args, &repo);
            assert!(!result.is_error, "{tool} rejected certified empty graph");
            assert_eq!(text_content(&result), "[]");
        }
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
    /// Seed a call graph under a REAL root directory. The root matters: the
    /// tools answer only from the root that contains the server's working
    /// directory, so a test has to say where the server is running.
    fn seed_code_map_db(db: &Path, root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        let source = "fn leaf() {}\nfn middle() { leaf(); }\nfn root() { middle(); }\n";
        std::fs::write(root.join("x.rs"), source).unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(root)
            .with_symbols(true)
            .scan()
            .unwrap();
        let g = graph_from_rust("x.rs", source);
        let mut conn = crate::code_map::persist::open(db).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut conn, &map, g.edges()).unwrap();
    }

    #[test]
    fn dispatch_codegraph_callers_reads_persisted_edges() {
        // The wiring this slice closes: with a real code_map.db that has
        // stored edges, the dispatch surface returns the ACTUAL transitive
        // callers — not `[]` (the empty-graph stub the follow-up replaced).
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_code_map_db(&db, &repo);
        let r = dispatch_codegraph_tool_at(
            &db,
            "codegraph_callers",
            &serde_json::json!({"symbol": "leaf"}),
            &repo,
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
        let repo = dir.path().join("repo");
        seed_code_map_db(&db, &repo);
        let r = dispatch_codegraph_tool_at(
            &db,
            "codegraph_callees",
            &serde_json::json!({"symbol": "root", "file": "x.rs"}),
            &repo,
        );
        assert!(!r.is_error, "got: {}", text_content(&r));
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text_content(&r)).unwrap();
        let names: Vec<&str> = rows.iter().map(|x| x["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"middle"), "wiring broken — got: {names:?}");
        assert!(names.contains(&"leaf"), "wiring broken — got: {names:?}");
    }

    #[test]
    fn call_graph_refuses_stale_or_over_budget_root_snapshots() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_code_map_db(&db, &repo);

        let edge_error = graph_from_db_with_limits(&db, &repo, 1, usize::MAX).unwrap_err();
        assert!(edge_error.to_string().contains("edge ceiling"));
        let byte_error =
            graph_from_db_with_limits(&db, &repo, CALL_GRAPH_EDGE_LIMIT, 1).unwrap_err();
        assert!(byte_error.to_string().contains("text bytes"));

        std::fs::write(repo.join("x.rs"), "fn leaf() { changed(); }\n").unwrap();
        let stale_error = graph_from_db(&db, &repo).unwrap_err();
        assert!(stale_error.to_string().contains("stale"));
    }

    #[test]
    fn call_graph_refuses_non_positive_mismatched_or_partial_generations() {
        for mutation in [
            "UPDATE code_map_roots SET graph_generation = 0",
            "UPDATE code_map_roots SET graph_generation = index_generation + 1",
            "UPDATE code_map_roots SET oversize_skipped = 1",
        ] {
            let dir = tempdir().unwrap();
            let db = dir.path().join("code_map.db");
            let repo = dir.path().join("repo");
            seed_code_map_db(&db, &repo);
            let conn = crate::code_map::persist::open(&db).unwrap();
            conn.execute(mutation, []).unwrap();

            assert!(
                graph_from_db(&db, &repo).is_err(),
                "invalid graph snapshot was accepted after {mutation}"
            );
        }
    }

    #[test]
    fn impact_dispatch_matches_the_canonical_typed_service() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("changed.rs"), "fn changed() {}\n").unwrap();
        std::fs::write(repo.path().join("caller.rs"), "fn caller() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        let mut conn = crate::code_map::persist::open(&db).unwrap();
        crate::code_map::persist::persist_map(&mut conn, &map).unwrap();
        crate::code_map::persist::persist_edges(
            &mut conn,
            &map.root,
            &[crate::code_map::graph::CodeEdge {
                from_file: "caller.rs".into(),
                from_symbol: "caller".into(),
                to_name: "changed".into(),
                kind: crate::code_map::graph::EdgeKind::Calls,
            }],
        )
        .unwrap();
        let seeds = vec![crate::code_map::impact::ImpactSeed::symbol(
            "changed.rs",
            "changed",
        )];
        let options = crate::code_map::impact::ImpactOptions {
            direction: crate::code_map::impact::ImpactDirection::Callers,
            max_depth: 3,
            max_nodes: 25,
            allow_stale: false,
        };
        let canonical =
            crate::code_map::impact::impact_radius_for_path(&conn, repo.path(), &seeds, options)
                .unwrap();

        let dispatched = dispatch_codegraph_tool_at(
            &db,
            "codegraph_impact_radius",
            &serde_json::json!({
                "seeds": [{"file": "changed.rs", "symbol": "changed"}],
                "direction": "callers",
                "max_depth": 3,
                "max_nodes": 25
            }),
            repo.path(),
        );
        assert!(!dispatched.is_error, "got: {}", text_content(&dispatched));
        let from_mcp: crate::code_map::impact::ImpactResult =
            serde_json::from_str(&text_content(&dispatched)).unwrap();
        assert_eq!(from_mcp, canonical);
        assert_eq!(from_mcp.impacted_nodes[0].node.symbol, "caller");
    }

    #[test]
    fn impact_dispatch_fails_closed_without_index_or_active_root() {
        let missing = tempdir().unwrap();
        let missing_result = dispatch_codegraph_tool_at(
            &missing.path().join("absent.db"),
            "codegraph_impact_radius",
            &serde_json::json!({"seeds": [{"file": "a.rs"}]}),
            missing.path(),
        );
        assert!(missing_result.is_error);
        assert!(text_content(&missing_result).contains("does not exist"));

        let indexed = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        std::fs::write(indexed.path().join("a.rs"), "fn a() {}\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(indexed.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        let mut conn = crate::code_map::persist::open(&db).unwrap();
        crate::code_map::persist::persist_map(&mut conn, &map).unwrap();
        crate::code_map::persist::persist_edges(&mut conn, &map.root, &[]).unwrap();

        let outside = dispatch_codegraph_tool_at(
            &db,
            "codegraph_impact_radius",
            &serde_json::json!({"seeds": [{"file": "a.rs", "symbol": "a"}]}),
            elsewhere.path(),
        );
        assert!(outside.is_error);
        assert!(text_content(&outside).contains("not inside a persisted code-map root"));
    }

    /// PR5-016: the call graph must honour the same containment as
    /// `relevant_files`. A client working outside the indexed root must never
    /// see another repository's symbols.
    #[test]
    fn call_graph_answers_only_from_the_active_root() {
        let indexed = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        let db = indexed.path().join("code_map.db");
        let repo = indexed.path().join("repo");
        seed_code_map_db(&db, &repo);

        let inside = dispatch_codegraph_tool_at(
            &db,
            "codegraph_callers",
            &serde_json::json!({"symbol": "leaf"}),
            &repo,
        );
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text_content(&inside)).unwrap();
        assert!(!rows.is_empty(), "inside the indexed root it must answer");

        let outside = dispatch_codegraph_tool_at(
            &db,
            "codegraph_callers",
            &serde_json::json!({"symbol": "leaf"}),
            elsewhere.path(),
        );
        assert!(outside.is_error);
        assert!(
            text_content(&outside).contains("not inside a persisted code-map root"),
            "unmapped state must remain distinct from a certified empty graph: {}",
            text_content(&outside)
        );
    }

    // ── GOLD-ADAPT-CCS-04: codegraph_outline dispatch tests ───────────────

    fn seed_indexed_file(db: &Path, root: &Path, relative: &str) {
        let map = crate::code_map::walker::RepoMapBuilder::new(root)
            .with_symbols(true)
            .scan()
            .unwrap();
        assert!(
            map.files.iter().any(|file| file.path == relative),
            "outline fixture {relative:?} was not scanned"
        );
        let mut conn = crate::code_map::persist::open(db).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut conn, &map, &[]).unwrap();
    }

    fn seeded_outline_fixture(source: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("outline.rs"), source).unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, &repo, "outline.rs");
        (dir, repo, db)
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
        assert!(text_content(&r).contains("codegraph_outline failed"));
    }

    #[test]
    fn dispatch_codegraph_outline_fixture_lists_fns_with_line_ranges() {
        // Write a small Rust fixture, run the outline tool, verify the
        // structural result (names + line numbers).
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let fixture = repo.join("fixture.rs");
        std::fs::write(
            &fixture,
            "pub struct Config {}\npub fn init() {}\npub fn run() {\n    // body\n}\n",
        )
        .unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, &repo, "fixture.rs");

        let r = dispatch_codegraph_tool_at(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": "fixture.rs"}),
            &repo,
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
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let fixture = repo.join("keys.rs");
        std::fs::write(&fixture, "fn one() {}\nfn two() {}\n").unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, &repo, "keys.rs");

        let r = dispatch_codegraph_tool_at(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": fixture.to_str().unwrap()}),
            &repo,
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
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("indexed.rs"), "fn allowed() {}\n").unwrap();
        let db = dir.path().join("code_map.db");
        seed_indexed_file(&db, &repo, "indexed.rs");
        let secret = repo.join("secret.rs");
        std::fs::write(&secret, "fn must_not_leak() {}\n").unwrap();

        let denied = dispatch_codegraph_tool_at(
            &db,
            "codegraph_outline",
            &serde_json::json!({"path": secret}),
            &repo,
        );
        assert!(denied.is_error);
        assert!(text_content(&denied).contains("stale"));
        assert!(!text_content(&denied).contains("must_not_leak"));
    }

    #[test]
    fn outline_read_is_bound_to_persisted_hash_and_post_read_freshness() {
        let (_dir, repo, db) = seeded_outline_fixture(b"fn old() {}\n");
        let changed_before_read = outline_from_db_with_hooks(
            &db,
            "outline.rs",
            &repo,
            |path| std::fs::write(path, "fn new() {}\n").unwrap(),
            |_| {},
        )
        .unwrap_err();
        assert!(changed_before_read.to_string().contains("SHA-256"));

        let (_dir, repo, db) = seeded_outline_fixture(b"fn old() {}\n");
        let changed_after_read = outline_from_db_with_hooks(
            &db,
            "outline.rs",
            &repo,
            |_| {},
            |path| std::fs::write(path, "fn new() {}\n").unwrap(),
        )
        .unwrap_err();
        assert!(
            changed_after_read
                .to_string()
                .contains("changed during outline read")
        );
    }

    #[test]
    fn outline_refuses_invalid_snapshot_metadata_and_oversized_rows() {
        for mutation in [
            "UPDATE code_map_roots SET graph_generation = 0",
            "UPDATE code_map_roots SET graph_generation = index_generation + 1",
            "UPDATE code_map_roots SET oversize_skipped = 1",
            "UPDATE code_map_files SET bytes = 2097153",
        ] {
            let (_dir, repo, db) = seeded_outline_fixture(b"fn outlined() {}\n");
            let conn = crate::code_map::persist::open(&db).unwrap();
            conn.execute(mutation, []).unwrap();
            assert!(
                outline_from_db(&db, "outline.rs", &repo).is_err(),
                "invalid outline snapshot was accepted after {mutation}"
            );
        }
    }

    #[test]
    fn outline_reports_invalid_utf8_and_rejects_path_aliases() {
        let (_dir, repo, db) = seeded_outline_fixture(&[0xff, 0xfe, 0xfd]);
        let invalid_utf8 = outline_from_db(&db, "outline.rs", &repo).unwrap_err();
        assert!(invalid_utf8.to_string().contains("not valid UTF-8"));

        let missing = outline_from_db(&db, "missing.rs", &repo).unwrap_err();
        assert!(missing.to_string().contains("not exactly one indexed"));

        let traversal = outline_from_db(&db, "../outline.rs", &repo).unwrap_err();
        assert!(
            traversal
                .to_string()
                .contains("normalized repository-relative")
        );
    }

    #[cfg(unix)]
    #[test]
    fn outline_reader_refuses_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let source = b"fn target() {}\n";
        std::fs::write(dir.path().join("target.rs"), source).unwrap();
        symlink("target.rs", dir.path().join("outline.rs")).unwrap();
        let indexed = IndexedOutlineFile {
            relative_path: "outline.rs".into(),
            bytes: source.len() as u64,
            sha256: format!("{:x}", Sha256::digest(source)),
        };

        let error = read_indexed_outline_source(dir.path(), &indexed).unwrap_err();
        assert!(error.to_string().contains("symlink or reparse point"));
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
        assert_eq!(
            listed["result"]["tools"].as_array().unwrap().len(),
            TOOL_NAMES.len()
        );
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
    fn stdio_outbound_guard_replaces_oversized_result_with_small_rpc_error() {
        let response = rpc_result(
            serde_json::json!("oversized-7"),
            serde_json::json!({"payload": "x".repeat(2_048)}),
        );
        let framed = encode_bounded_stdio_response_with_limit(&response, 512).unwrap();
        let (body, consumed) = crate::mcp::transport::parse_frame(&framed)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, framed.len());
        assert!(body.len() <= 512);
        let bounded: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(bounded["id"], "oversized-7");
        assert_eq!(bounded["error"]["code"], -32003);
        assert_eq!(
            bounded["error"]["message"],
            "Response exceeds MCP frame limit"
        );
        assert!(bounded["error"]["data"]["encoded_bytes"].as_u64().unwrap() > 512);
        assert_eq!(bounded["error"]["data"]["limit_bytes"], 512);
    }

    #[test]
    fn stdio_outbound_guard_drops_client_id_when_id_breaks_fallback_cap() {
        let response = rpc_result(serde_json::json!("i".repeat(2_048)), serde_json::json!({}));
        let framed = encode_bounded_stdio_response_with_limit(&response, 512).unwrap();
        let (body, _) = crate::mcp::transport::parse_frame(&framed)
            .unwrap()
            .unwrap();
        assert!(body.len() <= 512);
        let bounded: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(bounded["id"].is_null());
        assert_eq!(bounded["error"]["code"], -32003);
        assert_eq!(bounded["error"]["data"]["limit_bytes"], 512);
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
