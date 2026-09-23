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
//! Today's tool set (11 tools, including a generation-bound import graph, recall receipt, diff impact,
//! and its bounded observed-test projection):
//!
//! - `codegraph_relevant_files` — top-N files for a prompt
//! - `codegraph_recall_v1` — identity/generation-bound recall envelope
//! - `codegraph_extract_identifiers` — symbol-shape extraction
//! - `codegraph_path_keywords` — path-segment extraction
//! - `codegraph_callers` — transitive callers of a symbol (inverse BFS)
//! - `codegraph_callees` — transitive callees of a symbol (forward BFS)
//! - `codegraph_imports` — root-local resolved import dependents or dependencies
//! - `codegraph_impact_radius` — generation-bound, concrete-node blast radius
//! - `codegraph_diff_impact` — explicit Git diff acquisition into that radius
//! - `codegraph_diff_test_gaps` — bounded observed-test evidence for that exact impact
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
use crate::mcp::config::{McpServerConfig, McpServers};

pub(crate) const CODEGRAPH_CONTEXT_BINDING_META_KEY: &str = "io.neoth.codegraph.context_binding.v1";

#[derive(Clone, Debug)]
struct ContextBindingWitness {
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
}

struct CodegraphToolResponse {
    result: ToolCallResult,
    witness: Option<ContextBindingWitness>,
}

impl CodegraphToolResponse {
    fn plain(result: ToolCallResult) -> Self {
        Self {
            result,
            witness: None,
        }
    }
}

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
            name: "codegraph_imports".into(),
            description: Some(
                "Return a bounded root-local import neighborhood for an indexed file. \
                 Forward returns unambiguously resolved local imports; reverse returns \
                 local files that import it. Rust and Python syntax is resolved only \
                 when one scanned destination is proven; aliases, globs, re-exports, \
                 macros and ambiguous or external modules are omitted as unknown. \
                 Refuses stale, partial, schema-legacy or generation-mismatched snapshots."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "Repo-relative indexed source file."},
                    "direction": {"type": "string", "enum": ["forward", "reverse"], "default": "forward"},
                    "depth": {"type": "integer", "default": 5, "minimum": 1, "maximum": 20}
                },
                "required": ["file"],
                "additionalProperties": false
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_types".into(),
            description: Some("Return a bounded ancestor or descendant type hierarchy from the active complete current code-map snapshot.".into()),
            input_schema: serde_json::json!({"type":"object","properties":{"file":{"type":"string"},"symbol":{"type":"string"},"direction":{"type":"string","enum":["ancestors","descendants"],"default":"ancestors"},"depth":{"type":"integer","default":5,"minimum":1,"maximum":20}},"required":["file","symbol"],"additionalProperties":false}),
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
        McpTool {
            name: "codegraph_diff_impact".into(),
            description: Some(
                "Acquire one explicit bounded Git diff under the active repository, map only \
                 hunk-intersecting parser declaration lines to exact symbol seeds, then run \
                 the canonical generation-bound impact analysis. Source reads, Git failures, \
                 malformed diffs, and stale indexes are returned as errors."
                    .into(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "root": {
                        "type": "string",
                        "description": "Explicit repository root used for Git, source containment, and active code-map selection."
                    },
                    "source": {
                        "type": "string",
                        "enum": ["working_tree", "staged", "committed", "stdin"],
                        "default": "working_tree"
                    },
                    "base": {"type": "string", "description": "Required only for source=committed."},
                    "target": {"type": "string", "description": "Required only for source=committed."},
                    "unified_diff": {"type": "string", "maxLength": crate::code_map::diff::MAX_DIFF_BYTES, "description": "Required only for source=stdin. Character limit is advisory; the authoritative UTF-8 byte limit is enforced before parsing."},
                    "direction": {"type": "string", "enum": ["callers", "callees", "both"], "default": "callers"},
                    "max_depth": {"type": "integer", "minimum": 0, "maximum": crate::code_map::impact::MAX_IMPACT_DEPTH, "default": crate::code_map::impact::DEFAULT_MAX_DEPTH},
                    "max_nodes": {"type": "integer", "minimum": 0, "maximum": crate::code_map::impact::MAX_IMPACT_NODES, "default": crate::code_map::impact::DEFAULT_MAX_NODES},
                    "allow_stale": {"type": "boolean", "default": false}
                },
                "required": ["root"],
                "additionalProperties": false
            }),
            annotations: read_only_annotations(),
        },
        McpTool {
            name: "codegraph_diff_test_gaps".into(),
            description: Some("Run one explicit bounded diff-impact analysis, then project only typed, generation-bound observed test evidence. Empty observed evidence is never an absence claim; raw unified diff is never returned or persisted.".into()),
            input_schema: serde_json::json!({
                "type":"object", "properties": {
                    "root":{"type":"string"}, "source":{"type":"string","enum":["working_tree","staged","committed","stdin"],"default":"working_tree"},
                    "base":{"type":"string"}, "target":{"type":"string"}, "unified_diff":{"type":"string","maxLength":crate::code_map::diff::MAX_DIFF_BYTES,"description":"Character limit is advisory; the authoritative UTF-8 byte limit is enforced before parsing."},
                    "direction":{"type":"string","enum":["callers","callees","both"],"default":"callers"},
                    "max_depth":{"type":"integer","minimum":0,"maximum":crate::code_map::impact::MAX_IMPACT_DEPTH,"default":crate::code_map::impact::DEFAULT_MAX_DEPTH},
                    "max_nodes":{"type":"integer","minimum":0,"maximum":crate::code_map::impact::MAX_IMPACT_NODES,"default":crate::code_map::impact::DEFAULT_MAX_NODES},
                    "allow_stale":{"type":"boolean","default":false}
                }, "required":["root"], "additionalProperties":false
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
                "required": ["path"],
                "additionalProperties": false
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
    "codegraph_imports",
    "codegraph_types",
    "codegraph_impact_radius",
    "codegraph_diff_impact",
    "codegraph_diff_test_gaps",
    "codegraph_outline",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CodegraphImpactRuntime {
    max_depth: usize,
    max_nodes: usize,
    reject_stale: bool,
}

/// Runtime-only descriptor data for explicit requested context. `None` is the
/// generic stdio server's legacy static mode; only the exact generated child
/// receives `Some` from an accepted config snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestedContextRuntime(Option<crate::config::RequestedContextPolicy>);

impl RequestedContextRuntime {
    pub(crate) fn static_defaults() -> Self {
        Self(None)
    }
    pub(crate) fn from_policy(policy: crate::config::RequestedContextPolicy) -> Self {
        Self(Some(policy))
    }

    fn is_generated_requested_context(self) -> bool {
        self.0.is_some()
    }

    fn recall_limit(self, requested: u32) -> Result<usize> {
        if let Some(policy) = self.0 {
            anyhow::ensure!(
                requested <= 50,
                "limit {requested} exceeds codegraph hard ceiling 50"
            );
            anyhow::ensure!(
                requested <= policy.recall_max_files,
                "limit {requested} exceeds accepted requested-context recall ceiling {}",
                policy.recall_max_files
            );
            return Ok(requested.max(1) as usize);
        }
        Ok(requested.clamp(1, 50) as usize)
    }

    fn bfs_depth(self, requested: u32) -> Result<usize> {
        if let Some(policy) = self.0 {
            anyhow::ensure!(
                requested <= 20,
                "depth {requested} exceeds codegraph hard ceiling 20"
            );
            anyhow::ensure!(
                requested <= u32::from(policy.max_bfs_depth),
                "depth {requested} exceeds accepted requested-context BFS ceiling {}",
                policy.max_bfs_depth
            );
            return Ok(requested.max(1) as usize);
        }
        Ok(requested.clamp(1, 20) as usize)
    }

    fn bound_result(self, result: ToolCallResult) -> ToolCallResult {
        let Some(policy) = self.0 else {
            return result;
        };
        let bytes: usize = result
            .content
            .iter()
            .map(|content| match content {
                McpContent::Text { text } => text.len(),
                _ => 0,
            })
            .sum();
        if !result.is_error && bytes > policy.max_rendered_bytes() {
            return error_result(format!(
                "requested-context result is {} bytes, exceeding accepted rendered ceiling {} bytes",
                bytes,
                policy.max_rendered_bytes()
            ));
        }
        result
    }
}
impl CodegraphImpactRuntime {
    pub(crate) fn static_defaults() -> Self {
        Self {
            max_depth: crate::code_map::impact::DEFAULT_MAX_DEPTH,
            max_nodes: crate::code_map::impact::DEFAULT_MAX_NODES,
            reject_stale: false,
        }
    }
    pub(crate) fn from_policy(policy: crate::config::CodeMapImpactPolicy) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            max_depth: policy.max_depth as usize,
            max_nodes: policy.max_nodes as usize,
            reject_stale: true,
        })
    }
    fn resolve(
        self,
        depth: Option<usize>,
        nodes: Option<usize>,
        stale: bool,
    ) -> Result<(usize, usize, bool)> {
        anyhow::ensure!(
            !self.reject_stale || !stale,
            "allow_stale=true is denied by the accepted impact policy"
        );
        let depth = depth.unwrap_or(self.max_depth);
        let nodes = nodes.unwrap_or(self.max_nodes);
        anyhow::ensure!(
            depth <= self.max_depth,
            "max_depth {depth} exceeds accepted impact-policy ceiling {}",
            self.max_depth
        );
        anyhow::ensure!(
            nodes <= self.max_nodes,
            "max_nodes {nodes} exceeds accepted impact-policy ceiling {}",
            self.max_nodes
        );
        Ok((depth, nodes, stale))
    }
}
pub(crate) fn startup_impact_runtime(
    depth: Option<u32>,
    nodes: Option<u32>,
    stale: Option<bool>,
) -> Result<CodegraphImpactRuntime> {
    match (depth, nodes, stale) {
        (None, None, None) => Ok(CodegraphImpactRuntime::static_defaults()),
        (Some(max_depth), Some(max_nodes), Some(false)) => {
            CodegraphImpactRuntime::from_policy(crate::config::CodeMapImpactPolicy {
                max_depth,
                max_nodes,
                allow_stale: false,
            })
        }
        _ => anyhow::bail!(
            "codegraph impact startup policy requires --impact-max-depth, --impact-max-nodes, and --impact-allow-stale false together"
        ),
    }
}

pub(crate) fn startup_requested_context_runtime(
    recall_max_files: Option<u32>,
    callers_per_symbol: Option<u32>,
    summary_token_budget: Option<u32>,
    max_bfs_depth: Option<u8>,
) -> Result<RequestedContextRuntime> {
    match (
        recall_max_files,
        callers_per_symbol,
        summary_token_budget,
        max_bfs_depth,
    ) {
        (None, None, None, None) => Ok(RequestedContextRuntime::static_defaults()),
        (
            Some(recall_max_files),
            Some(callers_per_symbol),
            Some(summary_token_budget),
            Some(max_bfs_depth),
        ) => {
            let config = crate::config::CodeMapConfig {
                coding_recall_max_files: recall_max_files,
                coding_callers_per_symbol: callers_per_symbol,
                coding_summary_token_budget: summary_token_budget,
                requested_context_max_bfs_depth: max_bfs_depth,
                ..Default::default()
            };
            Ok(RequestedContextRuntime::from_policy(
                config.requested_context_policy()?,
            ))
        }
        _ => anyhow::bail!(
            "codegraph requested-context startup policy requires --requested-recall-max-files, --requested-callers-per-symbol, --requested-summary-token-budget, and --requested-max-bfs-depth together"
        ),
    }
}
pub(crate) fn effective_builtin_codegraph_server(
    base: &McpServerConfig,
    policy: crate::config::CodeMapImpactPolicy,
) -> Result<McpServerConfig> {
    policy.validate()?;
    if !is_exact_generated_codegraph_base(base) {
        return Ok(base.clone());
    }
    let mut effective = base.clone();
    effective.args.extend([
        "--impact-max-depth".into(),
        policy.max_depth.to_string(),
        "--impact-max-nodes".into(),
        policy.max_nodes.to_string(),
        "--impact-allow-stale".into(),
        "false".into(),
    ]);
    Ok(effective)
}

/// Compose W56 and W59 trailers only for the exact generated descriptor.
/// The original tool JSON and authorization binding remain untouched; the
/// immutable values become child startup arguments after PreToolUse admits the
/// call.
pub(crate) fn effective_builtin_codegraph_server_with_requested_policy(
    base: &McpServerConfig,
    impact_policy: crate::config::CodeMapImpactPolicy,
    requested_policy: crate::config::RequestedContextPolicy,
) -> Result<McpServerConfig> {
    let mut effective = effective_builtin_codegraph_server(base, impact_policy)?;
    if !is_exact_generated_codegraph_base(base) {
        return Ok(effective);
    }
    effective.args.extend([
        "--requested-recall-max-files".into(),
        requested_policy.recall_max_files.to_string(),
        "--requested-callers-per-symbol".into(),
        requested_policy.callers_per_symbol.to_string(),
        "--requested-summary-token-budget".into(),
        requested_policy.summary_token_budget.to_string(),
        "--requested-max-bfs-depth".into(),
        requested_policy.max_bfs_depth.to_string(),
    ]);
    Ok(effective)
}
fn generated_codegraph_database_candidate(args: &[String]) -> Option<PathBuf> {
    match args {
        [mcp, serve] if mcp == "mcp" && serve == "codegraph-serve" => {
            Some(crate::code_map::persist::default_path())
        }
        [mcp, serve, flag, db]
            if mcp == "mcp"
                && serve == "codegraph-serve"
                && flag == "--db"
                && !db.is_empty()
                && !db.contains('\0') =>
        {
            Some(PathBuf::from(db))
        }
        _ => None,
    }
}
fn parse_generated_codegraph_database(args: &[String]) -> Option<PathBuf> {
    generated_codegraph_database_candidate(args)?
        .canonicalize()
        .ok()
}
fn has_generated_codegraph_descriptor(cfg: &McpServerConfig) -> bool {
    if cfg.id != "neoth-codegraph"
        || !cfg.enabled
        || !cfg.env.is_empty()
        || cfg.validate_launcher().is_err()
        || cfg.trust_all_tools
        || !cfg.smart_approve
        || cfg.autonomy_gate.is_some()
        || !cfg.allow_tools.as_ref().is_some_and(|tools| {
            tools.len() == TOOL_NAMES.len()
                && TOOL_NAMES.iter().all(|required| {
                    tools
                        .iter()
                        .filter(|tool| tool.as_str() == *required)
                        .count()
                        == 1
                })
        })
        || generated_codegraph_database_candidate(&cfg.args).is_none()
    {
        return false;
    }
    true
}

fn is_generated_codegraph_identity_for_expected_executable(
    cfg: &McpServerConfig,
    expected_executable: &Path,
) -> bool {
    if !has_generated_codegraph_descriptor(cfg) {
        return false;
    }
    let Ok(expected) = expected_executable.canonicalize() else {
        return false;
    };
    PathBuf::from(&cfg.command).canonicalize().ok().as_ref() == Some(&expected)
}

fn is_generated_codegraph_identity(cfg: &McpServerConfig) -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    is_generated_codegraph_identity_for_expected_executable(cfg, &executable)
}
fn is_exact_generated_codegraph_base(cfg: &McpServerConfig) -> bool {
    is_generated_codegraph_identity(cfg) && parse_generated_codegraph_database(&cfg.args).is_some()
}

pub(crate) fn is_exact_generated_codegraph_base_for_direct_cli(cfg: &McpServerConfig) -> bool {
    is_exact_generated_codegraph_base(cfg)
}

/// Read-only classification shared by Doctor and the W53 admission path. It
/// never starts a child or opens SQLite; canonicalising an existing configured
/// database only establishes whether W53 could select that exact descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinOutlineRegistrationReadiness {
    NotExactGenerated,
    DatabaseUnavailable,
    Exact { database_path: PathBuf },
}

/// Diagnostic-only generated-registration inspection for another local NEOTH
/// executable, such as the GUI's resolved CLI sibling. Runtime admission keeps
/// using the current-process identity wrapper above.
pub(crate) fn inspect_builtin_outline_registration_for_expected_executable(
    cfg: Option<&McpServerConfig>,
    expected_executable: &Path,
) -> BuiltinOutlineRegistrationReadiness {
    let Some(cfg) = cfg else {
        return BuiltinOutlineRegistrationReadiness::NotExactGenerated;
    };
    if !is_generated_codegraph_identity_for_expected_executable(cfg, expected_executable) {
        return BuiltinOutlineRegistrationReadiness::NotExactGenerated;
    }
    match parse_generated_codegraph_database(&cfg.args) {
        Some(database_path) => BuiltinOutlineRegistrationReadiness::Exact { database_path },
        None => BuiltinOutlineRegistrationReadiness::DatabaseUnavailable,
    }
}

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
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    dispatch_codegraph_tool_at_with_runtime(
        db_path,
        tool_name,
        args,
        &cwd,
        CodegraphImpactRuntime::static_defaults(),
    )
}
fn dispatch_codegraph_tool_at_with_runtime(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: CodegraphImpactRuntime,
) -> ToolCallResult {
    dispatch_codegraph_tool_at_with_runtimes(
        db_path,
        tool_name,
        args,
        cwd,
        runtime,
        RequestedContextRuntime::static_defaults(),
    )
}
fn dispatch_codegraph_tool_at_with_runtimes(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: CodegraphImpactRuntime,
    requested_runtime: RequestedContextRuntime,
) -> ToolCallResult {
    // The server runs as a stdio child and inherits the client's working
    // directory; that directory is what decides WHICH indexed repository may
    // answer. Resolved once here and threaded down, so every tool on this
    // surface applies the same containment and tests can state the location
    // explicitly instead of depending on the test runner's cwd.
    dispatch_codegraph_tool_at_runtime(db_path, tool_name, args, cwd, runtime, requested_runtime)
}

#[cfg(test)]
pub(crate) fn dispatch_codegraph_tool_at(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
) -> ToolCallResult {
    dispatch_codegraph_tool_at_runtime(
        db_path,
        tool_name,
        args,
        cwd,
        CodegraphImpactRuntime::static_defaults(),
        RequestedContextRuntime::static_defaults(),
    )
}

fn dispatch_codegraph_tool_at_runtime(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: CodegraphImpactRuntime,
    requested_runtime: RequestedContextRuntime,
) -> ToolCallResult {
    dispatch_codegraph_tool_at_runtime_with_binding(
        db_path,
        tool_name,
        args,
        cwd,
        runtime,
        requested_runtime,
    )
    .result
}

fn dispatch_codegraph_tool_at_runtime_with_binding(
    db_path: &Path,
    tool_name: &str,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: CodegraphImpactRuntime,
    requested_runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let result = match tool_name {
        "codegraph_extract_identifiers" => {
            CodegraphToolResponse::plain(tool_extract_identifiers(args))
        }
        "codegraph_path_keywords" => CodegraphToolResponse::plain(tool_path_keywords(args)),
        "codegraph_relevant_files" => {
            tool_relevant_files_with_binding(db_path, args, cwd, false, requested_runtime)
        }
        "codegraph_recall_v1" => {
            tool_relevant_files_with_binding(db_path, args, cwd, true, requested_runtime)
        }
        "codegraph_callers" => tool_callers_with_binding(db_path, args, cwd, requested_runtime),
        "codegraph_callees" => tool_callees_with_binding(db_path, args, cwd, requested_runtime),
        "codegraph_imports" => tool_imports_with_binding(db_path, args, cwd, requested_runtime),
        "codegraph_types" => tool_types_with_binding(db_path, args, cwd, requested_runtime),
        "codegraph_impact_radius" => {
            CodegraphToolResponse::plain(tool_impact_radius(db_path, args, cwd, runtime))
        }
        "codegraph_diff_impact" => {
            CodegraphToolResponse::plain(tool_diff_impact(db_path, args, cwd, runtime))
        }
        "codegraph_diff_test_gaps" => {
            CodegraphToolResponse::plain(tool_diff_test_gaps(db_path, args, cwd, runtime))
        }
        "codegraph_outline" => CodegraphToolResponse::plain(tool_outline(db_path, args, cwd)),
        other => CodegraphToolResponse::plain(error_result(format!(
            "unknown codegraph tool `{other}` (known: {})",
            TOOL_NAMES.join(", "),
        ))),
    };
    let result = match tool_name {
        "codegraph_relevant_files"
        | "codegraph_recall_v1"
        | "codegraph_callers"
        | "codegraph_callees"
        | "codegraph_imports"
        | "codegraph_types" => {
            let CodegraphToolResponse { result, witness } = result;
            CodegraphToolResponse {
                result: requested_runtime.bound_result(result),
                witness,
            }
        }
        _ => result,
    };
    if !requested_runtime.is_generated_requested_context() || result.result.is_error {
        return CodegraphToolResponse::plain(result.result);
    }
    result
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

fn tool_relevant_files_with_binding(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    versioned: bool,
    runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let parsed: RelevantFilesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return CodegraphToolResponse::plain(error_result(format!("bad args: {e}"))),
    };
    let limit = match runtime.recall_limit(parsed.limit) {
        Ok(limit) => limit,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph recall rejected before DB access: {error:#}"
            )));
        }
    };
    match recall_v1_inner(db_path, &parsed.prompt, limit, cwd) {
        Ok(envelope) => {
            let payload: Result<String> = if versioned {
                serde_json::to_string(&envelope).map_err(Into::into)
            } else {
                legacy_relevant_files_json(&envelope)
            };
            match payload {
                Ok(payload) => CodegraphToolResponse {
                    result: text_result(payload),
                    witness: envelope
                        .receipt
                        .as_ref()
                        .map(|receipt| ContextBindingWitness {
                            root_identity: receipt.root_identity.clone(),
                            index_generation: receipt.index_generation,
                            graph_generation: receipt.graph_generation,
                        }),
                },
                Err(error) if versioned => CodegraphToolResponse::plain(error_result(format!(
                    "serialize codegraph_recall_v1 result: {error:#}"
                ))),
                Err(error) => CodegraphToolResponse::plain(error_result(format!(
                    "codegraph_relevant_files refused unsafe legacy result: {error:#}"
                ))),
            }
        }
        Err(e) => {
            CodegraphToolResponse::plain(error_result(format!("relevant_files failed: {e:#}")))
        }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportsArgs {
    file: String,
    #[serde(default)]
    direction: crate::code_map::imports::ImportDirection,
    #[serde(default = "default_bfs_depth")]
    depth: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TypesArgs {
    file: String,
    symbol: String,
    #[serde(default)]
    direction: crate::code_map::type_hierarchy::TypeHierarchyDirection,
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
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    allow_stale: bool,
}

fn tool_impact_radius(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: CodegraphImpactRuntime,
) -> ToolCallResult {
    let parsed: ImpactArgs = match serde_json::from_value(args.clone()) {
        Ok(parsed) => parsed,
        Err(error) => return error_result(format!("bad args: {error}")),
    };
    let (max_depth, max_nodes, allow_stale) =
        match runtime.resolve(parsed.max_depth, parsed.max_nodes, parsed.allow_stale) {
            Ok(value) => value,
            Err(error) => {
                return error_result(format!("codegraph_impact_radius failed: {error:#}"));
            }
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
            max_depth,
            max_nodes,
            allow_stale,
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

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DiffImpactSource {
    #[default]
    WorkingTree,
    Staged,
    Committed,
    Stdin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiffImpactArgs {
    root: String,
    #[serde(default)]
    source: DiffImpactSource,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    unified_diff: Option<String>,
    #[serde(default)]
    direction: crate::code_map::impact::ImpactDirection,
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    allow_stale: bool,
}

/// Acquire, validate, map, and analyze one explicit diff as a typed value.
/// Both MCP consumers call this shared path before either renders a response.
fn resolve_diff_impact(
    db_path: &Path,
    args: &serde_json::Value,
    runtime: CodegraphImpactRuntime,
) -> Result<crate::code_map::impact::ImpactResult> {
    // This check intentionally borrows the JSON string before `from_value`
    // clones it. JSON Schema's maxLength is character-based; this byte cap is
    // the authoritative bound for multibyte UTF-8 and runs before parsing/IO.
    if let Some(input) = args.get("unified_diff").and_then(serde_json::Value::as_str) {
        anyhow::ensure!(
            input.len() <= crate::code_map::diff::MAX_DIFF_BYTES,
            "unified_diff exceeds {} UTF-8 byte limit",
            crate::code_map::diff::MAX_DIFF_BYTES
        );
    }
    let parsed: DiffImpactArgs = serde_json::from_value(args.clone()).context("bad args")?;
    let DiffImpactArgs {
        root,
        source,
        base,
        target,
        unified_diff,
        direction,
        max_depth,
        max_nodes,
        allow_stale,
    } = parsed;
    let (max_depth, max_nodes, allow_stale) = runtime.resolve(max_depth, max_nodes, allow_stale)?;
    let root = std::path::PathBuf::from(root);
    let acquired = match (&source, base, target, unified_diff) {
        (DiffImpactSource::WorkingTree, None, None, None) => {
            crate::code_map::diff_git::acquire_git_diff(
                &root,
                crate::code_map::diff_git::GitDiffSource::WorkingTree,
            )
        }
        (DiffImpactSource::Staged, None, None, None) => {
            crate::code_map::diff_git::acquire_git_diff(
                &root,
                crate::code_map::diff_git::GitDiffSource::Staged,
            )
        }
        (DiffImpactSource::Committed, Some(base), Some(target), None) => {
            crate::code_map::diff_git::acquire_git_diff(
                &root,
                crate::code_map::diff_git::GitDiffSource::Committed { base, target },
            )
        }
        (DiffImpactSource::Stdin, None, None, Some(input)) => {
            crate::code_map::diff_git::parse_stdin_diff(&input)
        }
        _ => anyhow::bail!(
            "source requires exactly its matching fields: working_tree/staged have none, committed has base and target, stdin has unified_diff"
        ),
    };
    let acquired = acquired.context("acquire explicit diff")?;
    let exists = db_path
        .try_exists()
        .with_context(|| format!("inspect code-map DB {}", db_path.display()))?;
    if !exists {
        anyhow::bail!(
            "code-map DB {} does not exist; run `neoth code-map persist` first",
            db_path.display()
        );
    }
    let conn = open_code_map_read_only(db_path)?;
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize root {}", root.display()))?;
    if !canonical_root.is_dir() {
        anyhow::bail!("root is not a directory: {}", canonical_root.display());
    }
    let canonical_root_text = canonical_root.to_str().context("root is not valid UTF-8")?;
    let indexed = crate::code_map::persist::load_map(&conn, canonical_root_text)?
        .context("root is not indexed; run `neoth code-map persist` first")?;
    let seeds = crate::code_map::diff_git::map_acquired_diff_to_indexed_impact_seeds(
        &canonical_root,
        &acquired,
        &indexed,
    )?;
    crate::code_map::impact::impact_radius_for_diff_seeds(
        &conn,
        &canonical_root,
        &seeds,
        crate::code_map::impact::ImpactOptions {
            direction,
            max_depth,
            max_nodes,
            allow_stale,
        },
    )
}

fn tool_diff_impact(
    db_path: &Path,
    args: &serde_json::Value,
    _cwd: &Path,
    runtime: CodegraphImpactRuntime,
) -> ToolCallResult {
    match resolve_diff_impact(db_path, args, runtime) {
        Ok(result) => match serde_json::to_string(&result) {
            Ok(payload) => text_result(payload),
            Err(error) => error_result(format!(
                "codegraph_diff_impact result serialisation failed: {error}"
            )),
        },
        Err(error) => error_result(format!("codegraph_diff_impact failed: {error:#}")),
    }
}

/// W48 composes the existing explicit diff selector with the canonical typed
/// test-gap service. The intermediate impact value is local and transient;
/// callers never provide or receive a detached impact receipt as input.
fn tool_diff_test_gaps(
    db_path: &Path,
    args: &serde_json::Value,
    _cwd: &Path,
    runtime: CodegraphImpactRuntime,
) -> ToolCallResult {
    let impact = match resolve_diff_impact(db_path, args, runtime) {
        Ok(impact) => impact,
        Err(error) => return error_result(format!("codegraph_diff_test_gaps failed: {error:#}")),
    };
    let conn = match open_code_map_read_only(db_path) {
        Ok(conn) => conn,
        Err(error) => {
            return error_result(format!(
                "codegraph_diff_test_gaps failed to open {}: {error:#}",
                db_path.display()
            ));
        }
    };
    match crate::code_map::test_coverage::test_gap_for_impact(
        &conn,
        &impact,
        crate::code_map::test_coverage::TestCoverageOptions::default(),
    ) {
        Ok(result) => match serde_json::to_string(&result) {
            Ok(payload) => text_result(payload),
            Err(error) => error_result(format!(
                "codegraph_diff_test_gaps result serialisation failed: {error}"
            )),
        },
        Err(error) => error_result(format!("codegraph_diff_test_gaps failed: {error:#}")),
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
#[cfg(test)]
fn graph_from_db(db_path: &Path, cwd: &Path) -> Result<crate::code_map::graph::CallGraph> {
    Ok(graph_from_db_with_snapshot(db_path, cwd)?.0)
}

fn graph_from_db_with_snapshot(
    db_path: &Path,
    cwd: &Path,
) -> Result<(crate::code_map::graph::CallGraph, ContextBindingWitness)> {
    graph_from_db_with_limits_and_snapshot(
        db_path,
        cwd,
        CALL_GRAPH_EDGE_LIMIT,
        CALL_GRAPH_EDGE_TEXT_BYTE_LIMIT,
    )
}

#[cfg(test)]
fn graph_from_db_with_limits(
    db_path: &Path,
    cwd: &Path,
    edge_limit: usize,
    edge_text_byte_limit: usize,
) -> Result<crate::code_map::graph::CallGraph> {
    Ok(graph_from_db_with_limits_and_snapshot(db_path, cwd, edge_limit, edge_text_byte_limit)?.0)
}

fn graph_from_db_with_limits_and_snapshot(
    db_path: &Path,
    cwd: &Path,
    edge_limit: usize,
    edge_text_byte_limit: usize,
) -> Result<(crate::code_map::graph::CallGraph, ContextBindingWitness)> {
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
    Ok((
        crate::code_map::graph::CallGraph::from_edges(edges),
        ContextBindingWitness {
            root_identity: expected.root.identity().as_str().to_owned(),
            index_generation: expected.index_generation,
            graph_generation: expected.graph_generation,
        },
    ))
}

const IMPORT_GRAPH_EDGE_LIMIT: usize = crate::code_map::imports::DEFAULT_MAX_IMPORT_EDGES;
const IMPORT_GRAPH_EDGE_TEXT_BYTE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct StoredImportSnapshot {
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
    import_generation: i64,
    complete: bool,
}

fn stored_import_snapshot(conn: &rusqlite::Connection, root: &str) -> Result<StoredImportSnapshot> {
    conn.query_row(
        "SELECT root_identity, index_generation, graph_generation, import_generation, \
                oversize_skipped = 0 AND truncated_at IS NULL \
         FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| {
            Ok(StoredImportSnapshot {
                root_identity: row.get(0)?,
                index_generation: row.get(1)?,
                graph_generation: row.get(2)?,
                import_generation: row.get(3)?,
                complete: row.get(4)?,
            })
        },
    )
    .with_context(|| format!("read import-graph snapshot metadata for {root:?}"))
}

fn validate_stored_import_snapshot(
    expected: &crate::code_map::recall::RootGenerationSnapshot,
    stored: &StoredImportSnapshot,
) -> Result<()> {
    anyhow::ensure!(
        stored.root_identity == expected.root.identity().as_str()
            && stored.index_generation == expected.index_generation
            && stored.graph_generation == expected.graph_generation,
        "code-map root or current generation changed before import-graph materialization; retry"
    );
    anyhow::ensure!(
        stored.index_generation > 0
            && stored.index_generation == stored.graph_generation
            && stored.index_generation == stored.import_generation,
        "code-map import graph has no current generation; rebuild the code map"
    );
    anyhow::ensure!(
        stored.complete,
        "code-map root was published from a partial scan; rebuild without explicit limits before querying the import graph"
    );
    Ok(())
}

fn import_graph_from_db_with_snapshot(
    db_path: &Path,
    cwd: &Path,
    requested_file: &str,
) -> Result<(crate::code_map::imports::ImportGraph, ContextBindingWitness)> {
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
    let Some(expected) = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)? else {
        anyhow::bail!(
            "working directory {} is not inside a persisted code-map root",
            cwd.display()
        );
    };
    let tx = conn
        .unchecked_transaction()
        .context("begin atomic import-graph read transaction")?;
    let initial = stored_import_snapshot(&tx, expected.root.display())?;
    validate_stored_import_snapshot(&expected, &initial)?;
    let initial_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !initial_freshness.stale,
        "code-map import graph is stale; rebuild the code map before querying it"
    );
    crate::code_map::persist::ensure_current_import_file(
        &tx,
        expected.root.display(),
        requested_file,
    )?;
    let (edges, truncated) = crate::code_map::persist::load_import_edges_for_root_bounded(
        &tx,
        expected.root.display(),
        IMPORT_GRAPH_EDGE_LIMIT,
        IMPORT_GRAPH_EDGE_TEXT_BYTE_LIMIT,
    )?;
    anyhow::ensure!(
        !truncated,
        "code-map import graph exceeds the per-root edge ceiling of {IMPORT_GRAPH_EDGE_LIMIT}; narrow or rebuild the index"
    );
    let final_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !final_freshness.stale
            && initial_freshness.filesystem_fingerprint == final_freshness.filesystem_fingerprint,
        "code-map root changed during import-graph materialization; rebuild and retry"
    );
    let final_stored = stored_import_snapshot(&tx, expected.root.display())?;
    validate_stored_import_snapshot(&expected, &final_stored)?;
    anyhow::ensure!(
        final_stored == initial,
        "code-map import snapshot changed during materialization; retry"
    );
    tx.commit()
        .context("commit atomic import-graph read transaction")?;
    let final_active = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)?;
    anyhow::ensure!(
        final_active.as_ref() == Some(&expected),
        "active code-map root or generation changed during import-graph materialization; retry"
    );
    Ok((
        crate::code_map::imports::ImportGraph::from_edges(edges),
        ContextBindingWitness {
            root_identity: expected.root.identity().as_str().to_owned(),
            index_generation: expected.index_generation,
            graph_generation: expected.graph_generation,
        },
    ))
}

fn tool_imports_with_binding(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let parsed: ImportsArgs = match serde_json::from_value(args.clone()) {
        Ok(parsed) => parsed,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!("bad args: {error}")));
        }
    };
    let depth = match runtime.bfs_depth(parsed.depth) {
        Ok(depth) => depth,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph imports rejected before DB access: {error:#}"
            )));
        }
    };
    let (graph, witness) = match import_graph_from_db_with_snapshot(db_path, cwd, &parsed.file) {
        Ok(graph) => graph,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph_imports failed: {error:#}"
            )));
        }
    };
    let node_limit = runtime.0.map_or(
        crate::code_map::imports::DEFAULT_MAX_IMPORT_QUERY_NODES,
        |policy| {
            policy
                .max_rendered_bytes()
                .min(crate::code_map::imports::DEFAULT_MAX_IMPORT_QUERY_NODES)
        },
    );
    let text_limit = runtime.0.map_or(
        crate::code_map::imports::DEFAULT_MAX_IMPORT_QUERY_TEXT_BYTES,
        |policy| {
            policy
                .max_rendered_bytes()
                .min(crate::code_map::imports::DEFAULT_MAX_IMPORT_QUERY_TEXT_BYTES)
        },
    );
    match graph.query_bounded(
        &parsed.file,
        parsed.direction,
        depth,
        node_limit,
        text_limit,
    ) {
        Ok(entries) => match bounded_json_array(
            entries
                .into_iter()
                .map(|entry| serde_json::json!({"file": entry.file, "depth": entry.depth})),
            runtime.0.map(|policy| policy.max_rendered_bytes()),
        ) {
            Ok(payload) => CodegraphToolResponse {
                result: text_result(payload),
                witness: Some(witness),
            },
            Err(error) => CodegraphToolResponse::plain(error_result(format!(
                "codegraph imports bounded result: {error:#}"
            ))),
        },
        Err(error) => CodegraphToolResponse::plain(error_result(format!(
            "codegraph imports bounded result: {error:#}"
        ))),
    }
}

const TYPE_HIERARCHY_EDGE_LIMIT: usize = crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_EDGES;
const TYPE_HIERARCHY_ENDPOINT_LIMIT: usize =
    crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_DECLARATIONS;
const TYPE_HIERARCHY_TEXT_BYTE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct StoredTypeHierarchySnapshot {
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
    import_generation: i64,
    type_generation: i64,
    complete: bool,
}

fn stored_type_hierarchy_snapshot(
    conn: &rusqlite::Connection,
    root: &str,
) -> Result<StoredTypeHierarchySnapshot> {
    conn.query_row(
        "SELECT root_identity, index_generation, graph_generation, import_generation, type_generation, \
                oversize_skipped = 0 AND truncated_at IS NULL \
         FROM code_map_roots WHERE root = ?1",
        rusqlite::params![root],
        |row| {
            Ok(StoredTypeHierarchySnapshot {
                root_identity: row.get(0)?,
                index_generation: row.get(1)?,
                graph_generation: row.get(2)?,
                import_generation: row.get(3)?,
                type_generation: row.get(4)?,
                complete: row.get(5)?,
            })
        },
    )
    .with_context(|| format!("read type-hierarchy snapshot metadata for {root:?}"))
}

fn validate_stored_type_hierarchy_snapshot(
    expected: &crate::code_map::recall::RootGenerationSnapshot,
    stored: &StoredTypeHierarchySnapshot,
) -> Result<()> {
    anyhow::ensure!(
        stored.root_identity == expected.root.identity().as_str()
            && stored.index_generation == expected.index_generation
            && stored.graph_generation == expected.graph_generation,
        "code-map root or current generation changed before type-hierarchy materialization; retry"
    );
    anyhow::ensure!(
        stored.index_generation > 0
            && stored.index_generation == stored.graph_generation
            && stored.index_generation == stored.import_generation
            && stored.index_generation == stored.type_generation,
        "code-map type hierarchy has no current generation; rebuild the code map"
    );
    anyhow::ensure!(
        stored.complete,
        "code-map root was published from a partial scan; rebuild without explicit limits before querying the type hierarchy"
    );
    Ok(())
}

fn type_hierarchy_from_db_with_snapshot(
    db_path: &Path,
    cwd: &Path,
    requested_endpoint: &crate::code_map::type_hierarchy::TypeEndpoint,
) -> Result<(
    crate::code_map::type_hierarchy::TypeHierarchy,
    ContextBindingWitness,
)> {
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
    let Some(expected) = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)? else {
        anyhow::bail!(
            "working directory {} is not inside a persisted code-map root",
            cwd.display()
        );
    };
    let tx = conn
        .unchecked_transaction()
        .context("begin atomic type-hierarchy read transaction")?;
    let initial = stored_type_hierarchy_snapshot(&tx, expected.root.display())?;
    validate_stored_type_hierarchy_snapshot(&expected, &initial)?;
    let initial_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !initial_freshness.stale,
        "code-map type hierarchy is stale; rebuild the code map before querying it"
    );
    let (hierarchy, truncated) = crate::code_map::persist::load_type_hierarchy_for_root_bounded(
        &tx,
        expected.root.display(),
        TYPE_HIERARCHY_EDGE_LIMIT,
        TYPE_HIERARCHY_ENDPOINT_LIMIT,
        TYPE_HIERARCHY_TEXT_BYTE_LIMIT,
    )?;
    anyhow::ensure!(
        !truncated,
        "code-map type hierarchy exceeds its bounded persisted load ceiling; narrow or rebuild the index"
    );
    // A non-edge declaration is a valid known leaf.  The hierarchy's endpoint
    // table makes it distinct from an unknown file/symbol pair.
    anyhow::ensure!(
        hierarchy.endpoints().contains(requested_endpoint),
        "type hierarchy endpoint is not an exact declaration in this root generation"
    );
    let final_freshness =
        crate::code_map::persist::index_freshness_receipt(&tx, expected.root.display())?;
    anyhow::ensure!(
        !final_freshness.stale
            && initial_freshness.filesystem_fingerprint == final_freshness.filesystem_fingerprint,
        "code-map root changed during type-hierarchy materialization; rebuild and retry"
    );
    let final_stored = stored_type_hierarchy_snapshot(&tx, expected.root.display())?;
    validate_stored_type_hierarchy_snapshot(&expected, &final_stored)?;
    anyhow::ensure!(
        final_stored == initial,
        "code-map type-hierarchy snapshot changed during materialization; retry"
    );
    tx.commit()
        .context("commit atomic type-hierarchy read transaction")?;
    let final_active = crate::code_map::recall::resolve_active_root_snapshot(&conn, cwd)?;
    anyhow::ensure!(
        final_active.as_ref() == Some(&expected),
        "active code-map root or generation changed during type-hierarchy materialization; retry"
    );
    Ok((
        hierarchy,
        ContextBindingWitness {
            root_identity: expected.root.identity().as_str().to_owned(),
            index_generation: expected.index_generation,
            graph_generation: expected.graph_generation,
        },
    ))
}

fn tool_types_with_binding(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let parsed: TypesArgs = match serde_json::from_value(args.clone()) {
        Ok(parsed) => parsed,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!("bad args: {error}")));
        }
    };
    let requested_endpoint =
        match crate::code_map::type_hierarchy::TypeEndpoint::new(parsed.file, parsed.symbol) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                return CodegraphToolResponse::plain(error_result(format!(
                    "codegraph types rejected before DB access: {error:#}"
                )));
            }
        };
    let depth = match runtime.bfs_depth(parsed.depth) {
        Ok(depth) => depth.min(crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_QUERY_DEPTH),
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph types rejected before DB access: {error:#}"
            )));
        }
    };
    let defaults = crate::code_map::type_hierarchy::TypeTraversalBudget::default();
    let budget = crate::code_map::type_hierarchy::TypeTraversalBudget {
        max_depth: depth,
        max_nodes: runtime.0.map_or(defaults.max_nodes, |policy| {
            policy
                .max_rendered_bytes()
                .min(crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_QUERY_NODES)
        }),
        max_text_bytes: runtime.0.map_or(defaults.max_text_bytes, |policy| {
            policy
                .max_rendered_bytes()
                .min(crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_QUERY_TEXT_BYTES)
        }),
        max_work_steps: runtime.0.map_or(defaults.max_work_steps, |policy| {
            policy
                .max_rendered_bytes()
                .min(crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_QUERY_WORK_STEPS)
        }),
    };
    let (hierarchy, witness) =
        match type_hierarchy_from_db_with_snapshot(db_path, cwd, &requested_endpoint) {
            Ok(value) => value,
            Err(error) => {
                return CodegraphToolResponse::plain(error_result(format!(
                    "codegraph_types failed: {error:#}"
                )));
            }
        };
    match hierarchy.query_bounded(&requested_endpoint, parsed.direction, budget) {
        Ok(entries) => match bounded_json_array(
            entries.into_iter().map(|entry| {
                serde_json::json!({
                    "file": entry.endpoint.file_path,
                    "symbol": entry.endpoint.symbol,
                    "depth": entry.depth,
                })
            }),
            runtime.0.map(|policy| policy.max_rendered_bytes()),
        ) {
            Ok(payload) => CodegraphToolResponse {
                result: text_result(payload),
                witness: Some(witness),
            },
            Err(error) => CodegraphToolResponse::plain(error_result(format!(
                "codegraph_types bounded result: {error:#}"
            ))),
        },
        Err(error) => CodegraphToolResponse::plain(error_result(format!(
            "codegraph_types bounded result: {error:#}"
        ))),
    }
}
fn tool_callers_with_binding(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let parsed: CallersArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return CodegraphToolResponse::plain(error_result(format!("bad args: {e}"))),
    };
    let depth = match runtime.bfs_depth(parsed.depth) {
        Ok(depth) => depth,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph callers rejected before DB access: {error:#}"
            )));
        }
    };
    let (graph, witness) = match graph_from_db_with_snapshot(db_path, cwd) {
        Ok(g) => g,
        Err(e) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph_callers failed: {e:#}"
            )));
        }
    };
    match callers_inner_with_requested_budget(&graph, &parsed.symbol, depth, runtime) {
        Ok(payload) => CodegraphToolResponse {
            result: text_result(payload),
            witness: Some(witness),
        },
        Err(error) => CodegraphToolResponse::plain(error_result(format!(
            "codegraph callers bounded result: {error:#}"
        ))),
    }
}

fn tool_callees_with_binding(
    db_path: &Path,
    args: &serde_json::Value,
    cwd: &Path,
    runtime: RequestedContextRuntime,
) -> CodegraphToolResponse {
    let parsed: CalleesArgs = match serde_json::from_value(args.clone()) {
        Ok(p) => p,
        Err(e) => return CodegraphToolResponse::plain(error_result(format!("bad args: {e}"))),
    };
    let depth = match runtime.bfs_depth(parsed.depth) {
        Ok(depth) => depth,
        Err(error) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph callees rejected before DB access: {error:#}"
            )));
        }
    };
    let (graph, witness) = match graph_from_db_with_snapshot(db_path, cwd) {
        Ok(g) => g,
        Err(e) => {
            return CodegraphToolResponse::plain(error_result(format!(
                "codegraph_callees failed: {e:#}"
            )));
        }
    };
    match callees_inner_with_requested_budget(&graph, &parsed.file, &parsed.symbol, depth, runtime)
    {
        Ok(payload) => CodegraphToolResponse {
            result: text_result(payload),
            witness: Some(witness),
        },
        Err(error) => CodegraphToolResponse::plain(error_result(format!(
            "codegraph callees bounded result: {error:#}"
        ))),
    }
}

/// Serialize an existing public JSON-array shape without accepting a partial
/// array. The item is encoded before it enters the final buffer, making the
/// configured ceiling observable before the outer response serialization.
fn bounded_json_array<I>(items: I, byte_ceiling: Option<usize>) -> Result<String>
where
    I: IntoIterator<Item = serde_json::Value>,
{
    let mut payload = String::from("[");
    for (index, item) in items.into_iter().enumerate() {
        let encoded = serde_json::to_string(&item)?;
        let separator = usize::from(index != 0);
        if let Some(limit) = byte_ceiling
            && payload
                .len()
                .saturating_add(separator)
                .saturating_add(encoded.len())
                .saturating_add(1)
                > limit
        {
            anyhow::bail!(
                "result exceeds accepted rendered ceiling {limit} bytes before JSON-array materialization"
            );
        }
        if index != 0 {
            payload.push(',');
        }
        payload.push_str(&encoded);
    }
    payload.push(']');
    Ok(payload)
}

fn callers_inner_with_requested_budget(
    graph: &crate::code_map::graph::CallGraph,
    symbol: &str,
    depth: usize,
    runtime: RequestedContextRuntime,
) -> Result<String> {
    let mut entries = match runtime.0 {
        Some(policy) => graph.callers_of_bounded(
            symbol,
            depth,
            policy.max_rendered_bytes(),
            policy.max_rendered_bytes(),
        )?,
        None => graph.callers_of(symbol, depth),
    };
    entries.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then(a.file_path.cmp(&b.file_path))
            .then(a.symbol.cmp(&b.symbol))
    });
    bounded_json_array(
        entries.iter().map(|entry| {
            serde_json::json!({
                "file_path": entry.file_path,
                "symbol": entry.symbol,
                "depth": entry.depth,
            })
        }),
        runtime.0.map(|policy| policy.max_rendered_bytes()),
    )
}

fn callees_inner_with_requested_budget(
    graph: &crate::code_map::graph::CallGraph,
    file: &str,
    symbol: &str,
    depth: usize,
    runtime: RequestedContextRuntime,
) -> Result<String> {
    let mut entries = match runtime.0 {
        Some(policy) => graph.callees_of_bounded(
            file,
            symbol,
            depth,
            policy.max_rendered_bytes(),
            policy.max_rendered_bytes(),
        )?,
        None => graph.callees_of(file, symbol, depth),
    };
    entries.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.name.cmp(&b.name)));
    bounded_json_array(
        entries.iter().map(|entry| {
            serde_json::json!({
                "name": entry.name,
                "depth": entry.depth,
            })
        }),
        runtime.0.map(|policy| policy.max_rendered_bytes()),
    )
}

/// Build a [`CallGraph`] from `files` and call [`CallGraph::callers_of`].
/// Extracted so tests can drive the BFS without going through the
/// `dispatch_codegraph_tool` HTTP surface.
#[cfg(test)]
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
#[cfg(test)]
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
#[serde(deny_unknown_fields)]
pub(crate) struct OutlineArgs {
    pub(crate) path: String,
}

pub(crate) fn parse_outline_args(args: &serde_json::Value) -> Result<OutlineArgs> {
    serde_json::from_value(args.clone())
        .context("codegraph_outline requires exactly { path: string }")
}

fn tool_outline(db_path: &Path, args: &serde_json::Value, cwd: &Path) -> ToolCallResult {
    let parsed: OutlineArgs = match parse_outline_args(args) {
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

pub(crate) fn is_trusted_generated_codegraph_identity(
    server: &McpServerConfig,
    desired: &McpServerConfig,
) -> bool {
    server.id == desired.id
        && server.command == desired.command
        && server.args == desired.args
        && server.env.is_empty()
        && server.enabled
        && !server.trust_all_tools
        && server.smart_approve
        && server.autonomy_gate.is_none()
}
const OUTLINE_ENRICHMENT_MAX_DEPTH: usize = 1;
const OUTLINE_ENRICHMENT_MAX_NODES: usize = 24;

#[derive(Clone)]
pub(crate) struct ConfiguredMcpPathReadEnrichmentPlan {
    context: crate::hooks::PreToolUseContext,
    database_path: PathBuf,
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
    sidecar: String,
}

impl std::fmt::Debug for ConfiguredMcpPathReadEnrichmentPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfiguredMcpPathReadEnrichmentPlan")
            .field("database_path", &"<redacted>")
            .field("root_identity", &self.root_identity)
            .field("index_generation", &self.index_generation)
            .field("graph_generation", &self.graph_generation)
            .field("sidecar_bytes", &self.sidecar.len())
            .finish_non_exhaustive()
    }
}
/// Builds the W53 retrieval plan for its existing built-in outline route or
/// one operator-pinned `path` projection. The selector does not grant an MCP
/// permission and it never maps a remote path: the exact generated local
/// codegraph descriptor remains a separate mandatory condition before its
/// database is opened.
pub(crate) fn prepare_configured_mcp_path_read_enrichment(
    trusted_codegraph_cfg: Option<&McpServerConfig>,
    arguments: &serde_json::Value,
    context: &crate::hooks::PreToolUseContext,
    enabled: bool,
    selectors: &[crate::config::ConfiguredMcpPathRead],
) -> Result<Option<ConfiguredMcpPathReadEnrichmentPlan>> {
    if !enabled {
        return Ok(None);
    }
    // W53 stays intact: its exact generated built-in outline is still selected
    // by the existing master switch. W95 only adds an operator-pinned external
    // pair; it cannot replace the built-in path or turn selectors into grants.
    let builtin_outline = context.server() == "neoth-codegraph"
        && context.tool() == "codegraph_outline"
        && trusted_codegraph_cfg
            .and_then(trusted_generated_codegraph_database)
            .is_some();
    let selector = selectors
        .iter()
        .find(|selector| selector.server_id == context.server() && selector.tool == context.tool());
    if !builtin_outline && selector.is_none() {
        return Ok(None);
    }
    if let Some(selector) = selector {
        anyhow::ensure!(
            matches!(
                selector.kind,
                crate::config::ConfiguredMcpPathReadKind::ReadPath
            ) && selector.path_field == "path",
            "configured MCP ReadPath selector failed exact validated projection"
        );
    }
    let Some(database_path) = trusted_codegraph_cfg.and_then(trusted_generated_codegraph_database)
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        !context.is_cancelled() && !context.deadline_elapsed(),
        "outline enrichment cancelled or deadline elapsed"
    );
    let parsed = parse_outline_args(arguments)?;
    let conn = open_code_map_read_only(&database_path)?;
    let Some(active) =
        crate::code_map::recall::resolve_active_root_snapshot(&conn, context.canonical_cwd())?
    else {
        anyhow::bail!("outline enrichment cwd has no indexed root");
    };
    anyhow::ensure!(
        active.index_generation > 0
            && active.index_generation == active.graph_generation
            && crate::code_map::persist::root_snapshot_complete(&conn, active.root.display())?
            && !crate::code_map::persist::index_freshness_receipt(&conn, active.root.display())?
                .stale,
        "outline enrichment requires a fresh complete snapshot"
    );
    let relative =
        requested_outline_relative_path(active.root.path(), Path::new(parsed.path.trim()))?;
    let indexed = indexed_outline_file(&conn, active.root.display(), &relative)?;
    let _ = checked_outline_path(active.root.path(), &indexed.relative_path)?;
    let impact = crate::code_map::impact::impact_radius_for_path(
        &conn,
        context.canonical_cwd(),
        &[crate::code_map::impact::ImpactSeed::file(&relative)],
        crate::code_map::impact::ImpactOptions {
            direction: crate::code_map::impact::ImpactDirection::Both,
            max_depth: OUTLINE_ENRICHMENT_MAX_DEPTH,
            max_nodes: OUTLINE_ENRICHMENT_MAX_NODES,
            allow_stale: false,
        },
    )?;
    let gaps = crate::code_map::test_coverage::test_gap_for_impact(
        &conn,
        &impact,
        crate::code_map::test_coverage::TestCoverageOptions {
            max_depth: OUTLINE_ENRICHMENT_MAX_DEPTH,
            max_nodes: OUTLINE_ENRICHMENT_MAX_NODES,
        },
    )?;
    Ok(Some(ConfiguredMcpPathReadEnrichmentPlan {
        context: context.clone(),
        database_path,
        root_identity: active.root.identity().as_str().to_owned(),
        index_generation: active.index_generation,
        graph_generation: active.graph_generation,
        sidecar: render_outline_enrichment(
            active.root.identity().as_str(),
            &relative,
            &impact,
            &gaps,
            context.call_id(),
            selector.map(|selector| (selector.server_id.as_str(), selector.tool.as_str())),
        ),
    }))
}

impl ConfiguredMcpPathReadEnrichmentPlan {
    pub(crate) fn still_fresh(&self) -> Option<crate::hooks::PreToolUseEnrichment> {
        if self.context.is_cancelled() || self.context.deadline_elapsed() {
            return None;
        }
        let conn = open_code_map_read_only(&self.database_path).ok()?;
        let active = crate::code_map::recall::resolve_active_root_snapshot(
            &conn,
            self.context.canonical_cwd(),
        )
        .ok()??;
        let complete =
            crate::code_map::persist::root_snapshot_complete(&conn, active.root.display()).ok()?;
        let freshness =
            crate::code_map::persist::index_freshness_receipt(&conn, active.root.display()).ok()?;
        if active.root.identity().as_str() != self.root_identity
            || active.index_generation != self.index_generation
            || active.graph_generation != self.graph_generation
            || !complete
            || freshness.stale
        {
            return None;
        }
        crate::hooks::PreToolUseEnrichment::new(self.sidecar.clone()).ok()
    }
}

/// W239's direct-CLI counterpart to the existing configured-MCP plan.  It is
/// intentionally a distinct type and render shape: a local `fs read` never
/// claims provider or MCP-call provenance merely because it consults the
/// operator-pinned generated descriptor as read-only evidence.
#[derive(Clone)]
pub(crate) struct NativeFsReadEnrichmentPlan {
    context: crate::hooks::PreToolUseContext,
    database_path: PathBuf,
    root_identity: String,
    index_generation: i64,
    graph_generation: i64,
    sidecar: String,
}

impl std::fmt::Debug for NativeFsReadEnrichmentPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeFsReadEnrichmentPlan")
            .field("database_path", &"<redacted>")
            .field("root_identity", &self.root_identity)
            .field("index_generation", &self.index_generation)
            .field("graph_generation", &self.graph_generation)
            .field("sidecar_bytes", &self.sidecar.len())
            .finish_non_exhaustive()
    }
}

/// Prepare bounded native `fs read` sidecar evidence.  The caller must have
/// already passed the OS allowlist/autonomy preflight and delivered the one
/// typed direct-CLI OS-file read or literal-search context to PreToolUse.  A missing, lookalike,
/// stale, incomplete, or non-containing descriptor is simply ineligible; it
/// neither authorizes the read nor changes the original file result.
pub(crate) fn prepare_native_fs_read_enrichment(
    home: &Path,
    repository_root: &Path,
    admitted_target: &Path,
    context: &crate::hooks::PreToolUseContext,
    enabled: bool,
) -> Result<Option<NativeFsReadEnrichmentPlan>> {
    if !enabled {
        return Ok(None);
    }
    anyhow::ensure!(
        matches!(
            context.origin(),
            crate::hooks::PreToolUseOrigin::DirectCliOsFileRead
                | crate::hooks::PreToolUseOrigin::DirectCliOsFileSearch
        ),
        "native fs enrichment requires a direct CLI OS-file read or search origin"
    );
    anyhow::ensure!(
        !context.is_cancelled() && !context.deadline_elapsed(),
        "native fs enrichment cancelled or deadline elapsed"
    );
    let root = repository_root
        .canonicalize()
        .with_context(|| format!("canonicalize repository root {}", repository_root.display()))?;
    anyhow::ensure!(
        root.is_dir(),
        "repository root {} is not a directory",
        root.display()
    );
    anyhow::ensure!(
        context.canonical_root() == root && context.canonical_cwd() == root,
        "native fs enrichment context is not bound to the requested repository root"
    );
    let servers = McpServers::load_from(&home.join("mcp_servers.yaml"))?;
    let Some(database_path) = servers
        .get_enabled("neoth-codegraph")
        .and_then(trusted_generated_codegraph_database)
    else {
        return Ok(None);
    };
    let relative = requested_outline_relative_path(&root, admitted_target)?;
    let conn = open_code_map_read_only(&database_path)?;
    let Some(active) = crate::code_map::recall::resolve_active_root_snapshot(&conn, &root)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        active.root.path() == root,
        "native fs enrichment active root differs from requested repository root"
    );
    anyhow::ensure!(
        active.index_generation > 0
            && active.index_generation == active.graph_generation
            && crate::code_map::persist::root_snapshot_complete(&conn, active.root.display())?
            && !crate::code_map::persist::index_freshness_receipt(&conn, active.root.display())?
                .stale,
        "native fs enrichment requires a fresh complete snapshot"
    );
    let indexed = indexed_outline_file(&conn, active.root.display(), &relative)?;
    let checked = checked_outline_path(active.root.path(), &indexed.relative_path)?;
    anyhow::ensure!(
        checked == admitted_target,
        "native fs enrichment target does not match the indexed contained file"
    );
    let impact = crate::code_map::impact::impact_radius_for_path(
        &conn,
        &root,
        &[crate::code_map::impact::ImpactSeed::file(&relative)],
        crate::code_map::impact::ImpactOptions {
            direction: crate::code_map::impact::ImpactDirection::Both,
            max_depth: OUTLINE_ENRICHMENT_MAX_DEPTH,
            max_nodes: OUTLINE_ENRICHMENT_MAX_NODES,
            allow_stale: false,
        },
    )?;
    let gaps = crate::code_map::test_coverage::test_gap_for_impact(
        &conn,
        &impact,
        crate::code_map::test_coverage::TestCoverageOptions {
            max_depth: OUTLINE_ENRICHMENT_MAX_DEPTH,
            max_nodes: OUTLINE_ENRICHMENT_MAX_NODES,
        },
    )?;
    Ok(Some(NativeFsReadEnrichmentPlan {
        context: context.clone(),
        database_path,
        root_identity: active.root.identity().as_str().to_owned(),
        index_generation: active.index_generation,
        graph_generation: active.graph_generation,
        sidecar: render_native_fs_read_enrichment(
            active.root.identity().as_str(),
            &relative,
            &impact,
            &gaps,
            context.call_id(),
            context.origin(),
        ),
    }))
}

pub(crate) enum NativeFsReadFreshness {
    Fresh(crate::hooks::PreToolUseEnrichment),
    Stale,
    Unavailable,
}

impl NativeFsReadEnrichmentPlan {
    /// Recheck freshness only after the actual same-fd file read has
    /// succeeded.  The sidecar is untrusted, bounded supplemental output and
    /// is dropped rather than attached if the snapshot changed meanwhile.
    pub(crate) fn freshness_after_read(&self) -> NativeFsReadFreshness {
        if self.context.is_cancelled() || self.context.deadline_elapsed() {
            return NativeFsReadFreshness::Unavailable;
        }
        let Ok(conn) = open_code_map_read_only(&self.database_path) else {
            return NativeFsReadFreshness::Unavailable;
        };
        let Ok(Some(active)) = crate::code_map::recall::resolve_active_root_snapshot(
            &conn,
            self.context.canonical_root(),
        ) else {
            return NativeFsReadFreshness::Unavailable;
        };
        let Ok(complete) =
            crate::code_map::persist::root_snapshot_complete(&conn, active.root.display())
        else {
            return NativeFsReadFreshness::Unavailable;
        };
        let Ok(freshness) =
            crate::code_map::persist::index_freshness_receipt(&conn, active.root.display())
        else {
            return NativeFsReadFreshness::Unavailable;
        };
        if active.root.identity().as_str() != self.root_identity
            || active.index_generation != self.index_generation
            || active.graph_generation != self.graph_generation
            || !complete
            || freshness.stale
        {
            return NativeFsReadFreshness::Stale;
        }
        match crate::hooks::PreToolUseEnrichment::new(self.sidecar.clone()) {
            Ok(sidecar) => NativeFsReadFreshness::Fresh(sidecar),
            Err(_) => NativeFsReadFreshness::Unavailable,
        }
    }
}

fn render_native_fs_read_enrichment(
    root_identity: &str,
    relative: &str,
    impact: &crate::code_map::impact::ImpactResult,
    gaps: &crate::code_map::test_coverage::ImpactTestGapResult,
    call_id: crate::hooks::PreToolUseCallId,
    origin: crate::hooks::PreToolUseOrigin,
) -> String {
    let mut rendered =
        render_outline_enrichment(root_identity, relative, impact, gaps, call_id, None);
    rendered = rendered.replacen(
        "[untrusted built-in codegraph_outline sidecar]",
        match origin {
            crate::hooks::PreToolUseOrigin::DirectCliOsFileSearch => {
                "[untrusted native fs-grep codegraph sidecar]"
            }
            _ => "[untrusted native fs-read codegraph sidecar]",
        },
        1,
    );
    rendered = rendered.replacen(
        "configured_mcp: built_in=neoth-codegraph/codegraph_outline",
        match origin {
            crate::hooks::PreToolUseOrigin::DirectCliOsFileSearch => {
                "native_origin: direct_cli_os_file_search"
            }
            _ => "native_origin: direct_cli_os_file_read",
        },
        1,
    );
    rendered
}

fn trusted_generated_codegraph_database(cfg: &McpServerConfig) -> Option<PathBuf> {
    if cfg.id != "neoth-codegraph"
        || !cfg.enabled
        || !cfg.env.is_empty()
        || cfg.validate_launcher().is_err()
        || cfg.trust_all_tools
        || !cfg.smart_approve
        || cfg.autonomy_gate.is_some()
        || !cfg.allow_tools.as_ref().is_some_and(|tools| {
            tools.len() == TOOL_NAMES.len()
                && TOOL_NAMES.iter().all(|required| {
                    tools
                        .iter()
                        .filter(|tool| tool.as_str() == *required)
                        .count()
                        == 1
                })
        })
    {
        return None;
    }
    let database = parse_generated_codegraph_database(&cfg.args)?;
    let executable = std::env::current_exe().ok()?.canonicalize().ok()?;
    let configured = PathBuf::from(&cfg.command).canonicalize().ok()?;
    (configured == executable).then_some(database)
}

fn render_outline_enrichment(
    root_identity: &str,
    relative: &str,
    impact: &crate::code_map::impact::ImpactResult,
    gaps: &crate::code_map::test_coverage::ImpactTestGapResult,
    call_id: crate::hooks::PreToolUseCallId,
    configured_selector: Option<(&str, &str)>,
) -> String {
    const LIMIT: usize = crate::hooks::pre_tool_use::MAX_PRE_TOOL_USE_ENRICHMENT_BYTES;
    const MARKER: &str = "sidecar_truncated: ";
    let body_limit = LIMIT.saturating_sub(MARKER.len() + "true\n".len());
    let mut out = match configured_selector {
        Some(_) => String::from("[untrusted configured MCP ReadPath sidecar]\n"),
        None => String::from("[untrusted built-in codegraph_outline sidecar]\n"),
    };
    let mut truncated = false;
    for line in [
        format!("call_id: {:?}", call_id),
        configured_selector
            .map(|(server_id, tool)| format!("configured_mcp: server_id={server_id} tool={tool}"))
            .unwrap_or_else(|| {
                "configured_mcp: built_in=neoth-codegraph/codegraph_outline".to_owned()
            }),
        format!("root_identity: {root_identity}"),
        format!("file: {relative}"),
        "snapshot: fresh_complete=true stale=false".to_owned(),
        format!(
            "generations: index={} graph={}",
            impact.index_generation, impact.graph_generation
        ),
        format!(
            "impact: truncated={} budget_truncated={} evidence_truncated={} unmapped_seeds={} unmapped_edges={}",
            impact.truncated,
            impact.budget_truncated,
            impact.evidence_truncated,
            impact.unresolved_seeds.len(),
            impact.unresolved_edges.len()
        ),
    ] {
        truncated |= !append_outline_sidecar(&mut out, body_limit, &line);
    }
    for edge in &impact.traversed_edges {
        let line = match edge.traversal {
            crate::code_map::impact::ImpactDirection::Callers => format!(
                "direct_caller: {} :: {} @{} ({}) confidence={}",
                edge.caller.file,
                edge.caller.symbol,
                edge.caller.line,
                edge.caller.kind,
                edge.confidence
            ),
            crate::code_map::impact::ImpactDirection::Callees => format!(
                "direct_callee: {} :: {} @{} ({}) confidence={}",
                edge.callee.file,
                edge.callee.symbol,
                edge.callee.line,
                edge.callee.kind,
                edge.confidence
            ),
            crate::code_map::impact::ImpactDirection::Both => continue,
        };
        truncated |= !append_outline_sidecar(&mut out, body_limit, &line);
    }
    truncated |= !append_outline_sidecar(
        &mut out,
        body_limit,
        &format!(
            "test_gap: partial={} capped={} no_observed_test_is_not_absence={}",
            gaps.impact_partial, gaps.work_budget.capped, gaps.no_observed_test_is_not_absence
        ),
    );
    let mut observed = 0usize;
    for node in &gaps.per_node {
        if let Some(coverage) = &node.coverage {
            for test in &coverage.observed_tests {
                observed += 1;
                truncated |= !append_outline_sidecar(
                    &mut out,
                    body_limit,
                    &format!(
                        "observed_test: {} :: {} confidence={} distance={}",
                        test.test.file, test.test.symbol, test.confidence, test.distance
                    ),
                );
            }
        }
    }
    if observed == 0 {
        truncated |= !append_outline_sidecar(
            &mut out,
            body_limit,
            "observed_test: no observed test evidence",
        );
    }
    out.push_str(MARKER);
    out.push_str(if truncated { "true\n" } else { "false\n" });
    out
}

fn append_outline_sidecar(out: &mut String, limit: usize, line: &str) -> bool {
    if out.len().saturating_add(line.len()).saturating_add(1) <= limit {
        out.push_str(line);
        out.push('\n');
        true
    } else {
        false
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
    serve_stdio_with_runtime(db_path, CodegraphImpactRuntime::static_defaults()).await
}
pub(crate) async fn serve_stdio_with_runtime(
    db_path: PathBuf,
    runtime: CodegraphImpactRuntime,
) -> Result<()> {
    serve_stdio_with_runtimes(db_path, runtime, RequestedContextRuntime::static_defaults()).await
}
pub(crate) async fn serve_stdio_with_runtimes(
    db_path: PathBuf,
    runtime: CodegraphImpactRuntime,
    requested_runtime: RequestedContextRuntime,
) -> Result<()> {
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
            if let Some(response) = handle_stdio_message_with_runtimes(
                &db_path,
                &body,
                &mut session,
                runtime,
                requested_runtime,
            ) {
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
#[cfg(test)]
fn handle_stdio_message(
    db_path: &Path,
    body: &[u8],
    session: &mut StdioSession,
) -> Option<serde_json::Value> {
    handle_stdio_message_with_runtimes(
        db_path,
        body,
        session,
        CodegraphImpactRuntime::static_defaults(),
        RequestedContextRuntime::static_defaults(),
    )
}
fn handle_stdio_message_with_runtimes(
    db_path: &Path,
    body: &[u8],
    session: &mut StdioSession,
    runtime: CodegraphImpactRuntime,
    requested_runtime: RequestedContextRuntime,
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
            #[cfg(test)]
            record_w56_child_event(serde_json::json!({
                "event": "tools/call",
                "name": name,
                "arguments": arguments.clone(),
            }));
            let response = dispatch_codegraph_tool_at_runtime_with_binding(
                db_path,
                name,
                &arguments,
                &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                runtime,
                requested_runtime,
            );
            Some(rpc_result(
                id,
                codegraph_response_with_context_meta(name, response)
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

fn codegraph_response_with_context_meta(
    tool: &str,
    response: CodegraphToolResponse,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(&response.result)?;
    let Some(witness) = response.witness else {
        return Ok(value);
    };
    anyhow::ensure!(
        !response.result.is_error
            && witness.index_generation > 0
            && witness.index_generation == witness.graph_generation,
        "refuse codegraph provenance for an uncertified result"
    );
    let projection = crate::mcp::client::tool_call_result_projection(&response.result);
    let projection = serde_json::to_vec(&projection)?;
    let root_identity_sha256 = hex::encode(Sha256::digest(witness.root_identity.as_bytes()));
    value["_meta"] = serde_json::json!({
        CODEGRAPH_CONTEXT_BINDING_META_KEY: {
            "schema": "io.neoth.codegraph.context_binding.v1",
            "tool": tool,
            "root_identity_sha256": root_identity_sha256,
            "index_generation": witness.index_generation,
            "graph_generation": witness.graph_generation,
            "public_result_sha256": hex::encode(Sha256::digest(&projection)),
            "public_result_bytes": projection.len(),
        }
    });
    Ok(value)
}

pub(crate) fn validate_codegraph_context_binding_metadata(
    tool: &str,
    result: &ToolCallResult,
    meta: Option<&serde_json::Value>,
) -> Result<()> {
    let binding = meta
        .and_then(|meta| meta.get(CODEGRAPH_CONTEXT_BINDING_META_KEY))
        .and_then(serde_json::Value::as_object)
        .context("missing codegraph context-binding metadata")?;
    const BINDING_KEYS: &[&str] = &[
        "schema",
        "tool",
        "root_identity_sha256",
        "index_generation",
        "graph_generation",
        "public_result_sha256",
        "public_result_bytes",
    ];
    anyhow::ensure!(
        binding.len() == BINDING_KEYS.len()
            && BINDING_KEYS.iter().all(|key| binding.contains_key(*key)),
        "unexpected codegraph context-binding metadata fields"
    );
    let string = |key: &str| binding.get(key).and_then(serde_json::Value::as_str);
    anyhow::ensure!(
        string("schema") == Some("io.neoth.codegraph.context_binding.v1"),
        "invalid codegraph context-binding schema"
    );
    anyhow::ensure!(
        string("tool") == Some(tool),
        "codegraph context-binding tool mismatch"
    );
    let root = string("root_identity_sha256").context("missing root identity commitment")?;
    anyhow::ensure!(
        root.len() == 64
            && root
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid root identity commitment"
    );
    let index = binding
        .get("index_generation")
        .and_then(serde_json::Value::as_i64)
        .context("missing index generation")?;
    let graph = binding
        .get("graph_generation")
        .and_then(serde_json::Value::as_i64)
        .context("missing graph generation")?;
    anyhow::ensure!(index > 0 && index == graph, "invalid codegraph generations");
    let projection = serde_json::to_vec(&crate::mcp::client::tool_call_result_projection(result))?;
    anyhow::ensure!(
        binding
            .get("public_result_bytes")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|bytes| {
                bytes <= crate::mcp::transport::MAX_MCP_FRAME_BYTES as u64
                    && bytes == projection.len() as u64
            }),
        "codegraph public-result byte count mismatch"
    );
    let expected_digest = hex::encode(Sha256::digest(&projection));
    anyhow::ensure!(
        string("public_result_sha256") == Some(expected_digest.as_str()),
        "codegraph public-result digest mismatch"
    );
    Ok(())
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

/// Test-executable entrypoint for W53's real concrete-child transport.
#[cfg(test)]
#[test]
fn w53_serve_stdio_marker_child() {
    let Ok(raw_db) = std::env::var("NEOTH_W53_SERVE_STDIO_DB") else {
        return;
    };
    if let Some(cwd) = std::env::var_os("NEOTH_W59_CHILD_CWD") {
        std::env::set_current_dir(cwd)
            .expect("W59 marker child receives an existing isolated active root");
    }
    let db = std::path::PathBuf::from(raw_db);
    let (runtime, requested_runtime) =
        if let Ok(descriptor) = std::env::var("NEOTH_W56_DERIVED_DESCRIPTOR") {
            let descriptor = serde_json::from_str::<serde_json::Value>(&descriptor)
                .expect("W56 marker receives a serializable descriptor");
            let args = descriptor["args"].as_array().expect("W56 descriptor args");
            let depth = args[5]
                .as_str()
                .expect("W56 impact depth")
                .parse()
                .expect("numeric W56 impact depth");
            let nodes = args[7]
                .as_str()
                .expect("W56 impact nodes")
                .parse()
                .expect("numeric W56 impact nodes");
            let stale = args[9]
                .as_str()
                .expect("W56 impact stale")
                .parse()
                .expect("boolean W56 impact stale");
            record_w56_child_event(serde_json::json!({
                "event": "startup",
                "descriptor": descriptor,
                "request_binding": std::env::var("NEOTH_W56_REQUEST_BINDING")
                    .expect("W56 marker receives the bound request commitment"),
            }));
            let requested_runtime = match args.get(10..) {
                None => RequestedContextRuntime::static_defaults(),
                Some(trailer)
                    if trailer.len() == 8
                        && trailer[0].as_str() == Some("--requested-recall-max-files")
                        && trailer[2].as_str() == Some("--requested-callers-per-symbol")
                        && trailer[4].as_str() == Some("--requested-summary-token-budget")
                        && trailer[6].as_str() == Some("--requested-max-bfs-depth") =>
                {
                    startup_requested_context_runtime(
                        Some(
                            trailer[1]
                                .as_str()
                                .expect("W59 recall value")
                                .parse()
                                .expect("numeric W59 recall"),
                        ),
                        Some(
                            trailer[3]
                                .as_str()
                                .expect("W59 callers value")
                                .parse()
                                .expect("numeric W59 callers"),
                        ),
                        Some(
                            trailer[5]
                                .as_str()
                                .expect("W59 token value")
                                .parse()
                                .expect("numeric W59 token budget"),
                        ),
                        Some(
                            trailer[7]
                                .as_str()
                                .expect("W59 depth value")
                                .parse()
                                .expect("numeric W59 BFS depth"),
                        ),
                    )
                    .expect("W59 marker starts with the complete canonical requested policy")
                }
                Some(_) => panic!(
                    "W59 marker rejects partial, reordered, or duplicate requested-policy trailer"
                ),
            };
            (
                startup_impact_runtime(Some(depth), Some(nodes), Some(stale))
                    .expect("W56 marker starts with the derived impact policy"),
                requested_runtime,
            )
        } else {
            (
                CodegraphImpactRuntime::static_defaults(),
                RequestedContextRuntime::static_defaults(),
            )
        };
    use std::io::Write as _;
    println!();
    println!("NEOTH_W53_STDIO_READY");
    std::io::stdout().flush().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve_stdio_with_runtimes(db, runtime, requested_runtime))
        .unwrap();
}

/// The W56 marker child writes evidence to a file, never stdout, so its real
/// JSON-RPC transport remains byte-for-byte the production server path.
#[cfg(test)]
fn record_w56_child_event(event: serde_json::Value) {
    use std::io::Write as _;

    let Ok(path) = std::env::var("NEOTH_W56_CHILD_RECORD") else {
        return;
    };
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open W56 marker evidence");
    serde_json::to_writer(&mut file, &event).expect("serialize W56 marker evidence");
    file.write_all(b"\n")
        .expect("terminate W56 marker evidence");
    file.flush().expect("flush W56 marker evidence");
}

/// Seed one real persisted root for the W59 process-isolated dispatcher
/// acceptance fixture. The unique suffix makes a cross-root response visible.
#[cfg(test)]
pub(crate) fn w59_seed_real_sqlite_root(db: &Path, root: &Path, suffix: &str) {
    std::fs::create_dir_all(root).expect("create W59 fixture root");
    let source = format!(
        "fn leaf_{suffix}() {{}}\nfn middle_{suffix}() {{ leaf_{suffix}(); }}\nfn root_{suffix}() {{ middle_{suffix}(); }}\n"
    );
    std::fs::write(root.join("x.rs"), &source).expect("write W59 fixture source");
    let map = crate::code_map::walker::RepoMapBuilder::new(root)
        .with_symbols(true)
        .scan()
        .expect("scan W59 fixture root");
    let symbols =
        crate::code_map::symbols::extract_symbols(&source, crate::code_map::walker::Language::Rust);
    let graph =
        crate::code_map::graph::CallGraph::build(&[crate::code_map::graph::FileInput::c_family(
            "x.rs", &source, symbols,
        )]);
    let mut conn = crate::code_map::persist::open(db).expect("open W59 fixture DB");
    crate::code_map::persist::persist_map_and_edges(&mut conn, &map, graph.edges())
        .expect("persist W59 fixture graph");
}

/// Persist a result deliberately larger than W59's accepted rendered ceiling.
#[cfg(test)]
pub(crate) fn w59_seed_oversized_callers_root(db: &Path, root: &Path) {
    std::fs::create_dir_all(root).expect("create W59 oversized fixture root");
    let mut source = String::from("fn leaf_big() {}\n");
    for index in 0..48 {
        source.push_str(&format!("fn caller_{index:02}() {{ leaf_big(); }}\n"));
    }
    std::fs::write(root.join("x.rs"), &source).expect("write W59 oversized fixture source");
    let map = crate::code_map::walker::RepoMapBuilder::new(root)
        .with_symbols(true)
        .scan()
        .expect("scan W59 oversized fixture root");
    let symbols =
        crate::code_map::symbols::extract_symbols(&source, crate::code_map::walker::Language::Rust);
    let graph =
        crate::code_map::graph::CallGraph::build(&[crate::code_map::graph::FileInput::c_family(
            "x.rs", &source, symbols,
        )]);
    let mut conn = crate::code_map::persist::open(db).expect("open W59 oversized fixture DB");
    crate::code_map::persist::persist_map_and_edges(&mut conn, &map, graph.edges())
        .expect("persist W59 oversized fixture graph");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::graph::{CallGraph, EdgeKind};
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

    fn w56_generated_base(database: &std::path::Path) -> McpServerConfig {
        McpServerConfig {
            id: "neoth-codegraph".into(),
            description: None,
            command: std::env::current_exe()
                .unwrap()
                .canonicalize()
                .unwrap()
                .display()
                .to_string(),
            args: vec![
                "mcp".into(),
                "codegraph-serve".into(),
                "--db".into(),
                database.display().to_string(),
            ],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: Some(TOOL_NAMES.iter().map(|tool| (*tool).to_owned()).collect()),
            trust_all_tools: false,
            smart_approve: true,
            autonomy_gate: None,
        }
    }

    #[test]
    fn w100_diagnostic_identity_accepts_expected_cli_and_rejects_gui_lookalike() {
        let temp = tempdir().expect("temporary diagnostic identity fixture");
        let database = temp.path().join("code_map.db");
        std::fs::write(&database, b"fixture database").expect("write fixture database");
        let cli = std::env::current_exe()
            .expect("current CLI fixture executable")
            .canonicalize()
            .expect("canonical CLI fixture executable");
        let gui_lookalike = temp.path().join("neothd-gui-lookalike");
        std::fs::write(&gui_lookalike, b"distinct GUI diagnostic marker")
            .expect("write distinct GUI lookalike fixture");
        let registration =
            w56_generated_base(&database.canonicalize().expect("canonical database"));

        assert!(matches!(
            inspect_builtin_outline_registration_for_expected_executable(Some(&registration), &cli,),
            BuiltinOutlineRegistrationReadiness::Exact { .. }
        ));
        assert!(matches!(
            inspect_builtin_outline_registration_for_expected_executable(
                Some(&registration),
                &gui_lookalike,
            ),
            BuiltinOutlineRegistrationReadiness::NotExactGenerated
        ));
        assert!(
            is_generated_codegraph_identity(&registration),
            "runtime current-executable identity remains the existing W53/W95 gate"
        );
    }

    #[test]
    fn w56_derived_launch_binds_policy_without_rewriting_tool_json_and_requires_canonical_db() {
        let temp = tempdir().unwrap();
        let database = temp.path().join("code_map.db");
        std::fs::write(&database, b"fixture").unwrap();
        let base = w56_generated_base(&database.canonicalize().unwrap());
        let policy_n = crate::config::CodeMapImpactPolicy {
            max_depth: 2,
            max_nodes: 40,
            allow_stale: false,
        };
        let policy_n1 = crate::config::CodeMapImpactPolicy {
            max_depth: 3,
            max_nodes: 80,
            allow_stale: false,
        };
        let args = serde_json::json!({"seeds":[{"file":"src/lib.rs"}],"nested":{"z":1,"a":2}});
        let n = effective_builtin_codegraph_server(&base, policy_n).unwrap();
        let n1 = effective_builtin_codegraph_server(&base, policy_n1).unwrap();
        assert_eq!(
            args,
            serde_json::json!({"seeds":[{"file":"src/lib.rs"}],"nested":{"z":1,"a":2}})
        );
        assert_ne!(
            n.args, n1.args,
            "accepted N+1 must bind a new child descriptor"
        );
        assert_ne!(
            crate::mcp::gate::mcp_request_binding(&n, "codegraph_impact_radius", &args).unwrap(),
            crate::mcp::gate::mcp_request_binding(&n1, "codegraph_impact_radius", &args).unwrap()
        );
        assert!(trusted_generated_codegraph_database(&base).is_some());
        let mut relative = base.clone();
        relative.args[3] = "relative.db".into();
        assert_eq!(
            effective_builtin_codegraph_server(&relative, policy_n).unwrap(),
            relative
        );
        let mut missing = base.clone();
        missing.args[3] = temp.path().join("missing.db").display().to_string();
        assert_eq!(
            effective_builtin_codegraph_server(&missing, policy_n).unwrap(),
            missing
        );
        let mut trailer_lookalike = base.clone();
        trailer_lookalike.args.extend([
            "--impact-max-depth".into(),
            "2".into(),
            "--impact-max-nodes".into(),
            "40".into(),
            "--impact-allow-stale".into(),
            "false".into(),
        ]);
        assert!(
            trusted_generated_codegraph_database(&trailer_lookalike).is_none(),
            "a persisted trailer lookalike cannot gain W53 provenance"
        );
    }

    #[test]
    fn codegraph_tools_lists_twelve_canonical_tools() {
        let tools = codegraph_tools();
        assert_eq!(tools.len(), 12);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "codegraph_relevant_files",
                "codegraph_recall_v1",
                "codegraph_extract_identifiers",
                "codegraph_path_keywords",
                "codegraph_callers",
                "codegraph_callees",
                "codegraph_imports",
                "codegraph_types",
                "codegraph_impact_radius",
                "codegraph_diff_impact",
                "codegraph_diff_test_gaps",
                "codegraph_outline",
            ]
        );
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

    fn seed_import_graph_db(db: &Path, root: &Path) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "mod api;\n").unwrap();
        std::fs::write(root.join("src/api.rs"), "pub struct Api;\n").unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(root)
            .with_symbols(true)
            .scan()
            .unwrap();
        let canonical = crate::code_map::root_identity::CanonicalRepoRoot::discover(root).unwrap();
        let imports = crate::code_map::imports::ImportGraph::from_edges(vec![
            crate::code_map::imports::ImportEdge {
                from_file: "src/lib.rs".into(),
                to_file: "src/api.rs".into(),
                language: "rust".into(),
            },
        ]);
        let hierarchy = crate::code_map::type_hierarchy::TypeHierarchy::build_bounded(
            &[(
                "src/api.rs".to_string(),
                crate::code_map::walker::Language::Rust,
                "pub struct Api;".to_string(),
            )],
            crate::code_map::type_hierarchy::DEFAULT_MAX_TYPE_EDGES,
        )
        .unwrap();
        let mut conn = crate::code_map::persist::open(db).unwrap();
        crate::code_map::persist::persist_map_and_edges_bound(
            &mut conn,
            &map,
            &[],
            imports.edges(),
            &hierarchy,
            &canonical,
        )
        .unwrap();
    }

    fn seed_type_hierarchy_db(db: &Path, root: &Path) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/types.rs"),
            "trait Parent {}\nstruct Child;\nimpl Parent for Child {}\n",
        )
        .unwrap();
        let map = crate::code_map::walker::RepoMapBuilder::new(root)
            .with_symbols(true)
            .scan()
            .unwrap();
        let canonical = crate::code_map::root_identity::CanonicalRepoRoot::discover(root).unwrap();
        let child =
            crate::code_map::type_hierarchy::TypeEndpoint::new("src/types.rs", "Child").unwrap();
        let parent =
            crate::code_map::type_hierarchy::TypeEndpoint::new("src/types.rs", "Parent").unwrap();
        let hierarchy = crate::code_map::type_hierarchy::TypeHierarchy::from_parts(
            vec![crate::code_map::type_hierarchy::TypeHierarchyEdge {
                child: child.clone(),
                parent: parent.clone(),
                language: "rust".into(),
            }],
            std::collections::BTreeSet::from([child, parent]),
        )
        .unwrap();
        let mut conn = crate::code_map::persist::open(db).unwrap();
        crate::code_map::persist::persist_map_and_edges_bound(
            &mut conn,
            &map,
            &[],
            &[],
            &hierarchy,
            &canonical,
        )
        .unwrap();
    }
    #[test]
    fn dispatch_codegraph_imports_reads_current_root_local_snapshot() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_import_graph_db(&db, &repo);
        let result = dispatch_codegraph_tool_at(
            &db,
            "codegraph_imports",
            &serde_json::json!({"file":"src/lib.rs"}),
            &repo,
        );
        assert!(!result.is_error, "got: {}", text_content(&result));
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text_content(&result)).unwrap();
        assert_eq!(
            rows,
            vec![serde_json::json!({"file":"src/api.rs", "depth":1})]
        );
        let empty = dispatch_codegraph_tool_at(
            &db,
            "codegraph_imports",
            &serde_json::json!({"file":"src/api.rs"}),
            &repo,
        );
        assert!(
            !empty.is_error,
            "known leaf must return a certified empty result"
        );
        assert_eq!(text_content(&empty), "[]");
        let unknown = dispatch_codegraph_tool_at(
            &db,
            "codegraph_imports",
            &serde_json::json!({"file":"../../outside.rs"}),
            &repo,
        );
        assert!(unknown.is_error);
        assert!(text_content(&unknown).contains("normalized repository-relative"));
    }

    #[test]
    fn dispatch_codegraph_types_distinguishes_known_leaf_from_unknown_endpoint() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_import_graph_db(&db, &repo);
        let leaf = dispatch_codegraph_tool_at(
            &db,
            "codegraph_types",
            &serde_json::json!({"file":"src/api.rs","symbol":"Api"}),
            &repo,
        );
        assert!(!leaf.is_error, "known declaration leaf must be queryable");
        assert_eq!(text_content(&leaf), "[]");
        let unknown = dispatch_codegraph_tool_at(
            &db,
            "codegraph_types",
            &serde_json::json!({"file":"src/api.rs","symbol":"Missing"}),
            &repo,
        );
        assert!(unknown.is_error, "unknown declaration must fail closed");
    }

    #[test]
    fn dispatch_codegraph_types_rejects_source_mutation_and_bounded_query_overflow() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_type_hierarchy_db(&db, &repo);
        let bounded = tool_types_with_binding(
            &db,
            &serde_json::json!({"file":"src/types.rs","symbol":"Child"}),
            &repo,
            RequestedContextRuntime::from_policy(crate::config::RequestedContextPolicy {
                recall_max_files: 1,
                callers_per_symbol: 0,
                summary_token_budget: 1,
                max_bfs_depth: 2,
            }),
        );
        assert!(
            bounded.result.is_error,
            "requested context cap must reject a non-partial type traversal"
        );
        std::fs::write(
            repo.join("src/types.rs"),
            "trait Parent {}\nstruct Child;\n// changed\n",
        )
        .unwrap();
        let stale = dispatch_codegraph_tool_at(
            &db,
            "codegraph_types",
            &serde_json::json!({"file":"src/types.rs","symbol":"Child"}),
            &repo,
        );
        assert!(
            stale.is_error,
            "source mutation must refuse a stale type hierarchy"
        );
        assert!(text_content(&stale).contains("stale"));
    }

    #[test]
    fn stdio_types_call_has_bound_receipt_and_rejects_stale_type_generation() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_type_hierarchy_db(&db, &repo);
        let prior_cwd = std::env::current_dir().unwrap();
        struct RestoreCwd(std::path::PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                std::env::set_current_dir(&self.0).expect("restore type stdio CWD");
            }
        }
        std::env::set_current_dir(&repo).unwrap();
        let _restore = RestoreCwd(prior_cwd);
        let request = serde_json::json!({
            "jsonrpc":"2.0", "id":"types-1", "method":"tools/call",
            "params":{"name":"codegraph_types", "arguments":{"file":"src/types.rs","symbol":"Child","depth":2}}
        });
        let mut session = StdioSession {
            initialize_seen: true,
            ready: true,
            ..Default::default()
        };
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());
        let response = handle_stdio_message_with_runtimes(
            &db,
            &serde_json::to_vec(&request).unwrap(),
            &mut session,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        )
        .unwrap();
        assert_eq!(
            response["result"]["isError"], false,
            "initial stdio type response: {response}"
        );
        assert_eq!(
            response["result"]["_meta"][CODEGRAPH_CONTEXT_BINDING_META_KEY]["tool"],
            "codegraph_types"
        );
        let conn = crate::code_map::persist::open(&db).unwrap();
        conn.execute("UPDATE code_map_roots SET type_generation = 0", [])
            .unwrap();
        let stale = handle_stdio_message_with_runtimes(
            &db,
            &serde_json::to_vec(&request).unwrap(),
            &mut session,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        )
        .unwrap();
        assert_eq!(stale["result"]["isError"], true);
        assert!(
            stale["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("no current generation")
        );
    }
    #[test]
    fn stdio_imports_call_has_bound_receipt_and_rejects_stale_generation() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_import_graph_db(&db, &repo);
        let prior_cwd = std::env::current_dir().unwrap();
        struct RestoreCwd(std::path::PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                std::env::set_current_dir(&self.0).expect("restore import stdio CWD");
            }
        }
        std::env::set_current_dir(&repo).unwrap();
        let _restore = RestoreCwd(prior_cwd);
        let request = serde_json::json!({
            "jsonrpc":"2.0", "id":"imports-1", "method":"tools/call",
            "params":{"name":"codegraph_imports", "arguments":{"file":"src/lib.rs","depth":2}}
        });
        let mut session = StdioSession {
            initialize_seen: true,
            ready: true,
            ..Default::default()
        };
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());
        let response = handle_stdio_message_with_runtimes(
            &db,
            &serde_json::to_vec(&request).unwrap(),
            &mut session,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        )
        .unwrap();
        assert_eq!(
            response["result"]["isError"], false,
            "initial stdio import response: {response}"
        );
        assert_eq!(
            response["result"]["_meta"][CODEGRAPH_CONTEXT_BINDING_META_KEY]["tool"],
            "codegraph_imports"
        );
        let conn = crate::code_map::persist::open(&db).unwrap();
        conn.execute("UPDATE code_map_roots SET import_generation = 0", [])
            .unwrap();
        let stale = handle_stdio_message_with_runtimes(
            &db,
            &serde_json::to_vec(&request).unwrap(),
            &mut session,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        )
        .unwrap();
        assert_eq!(stale["result"]["isError"], true);
        assert!(
            stale["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("no current generation")
        );
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
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: crate::code_map::graph::EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: crate::code_map::graph::EdgeConfidenceTier::Inferred,
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
    fn diff_impact_dispatch_uses_parser_backed_symbol_seed() {
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
                target_file: None,
                kind: EdgeKind::Calls,
                confidence: crate::code_map::graph::EdgeConfidenceTier::INFERRED_CONFIDENCE,
                confidence_tier: crate::code_map::graph::EdgeConfidenceTier::Inferred,
            }],
        )
        .unwrap();
        let dispatched = dispatch_codegraph_tool_at(
            &db,
            "codegraph_diff_impact",
            &serde_json::json!({
                "root": repo.path(),
                "source": "stdin",
                "unified_diff": concat!(
                    "diff --git a/changed.rs b/changed.rs\n",
                    "--- a/changed.rs\n",
                    "+++ b/changed.rs\n",
                    "@@ -1 +1 @@\n",
                    "-fn changed() {}\n",
                    "+fn changed() {}\n"
                ),
                "direction": "callers",
                "max_depth": 3,
                "max_nodes": 25
            }),
            repo.path(),
        );
        assert!(!dispatched.is_error, "got: {}", text_content(&dispatched));
        let from_mcp: crate::code_map::impact::ImpactResult =
            serde_json::from_str(&text_content(&dispatched)).unwrap();
        assert_eq!(
            from_mcp.requested_seeds,
            vec![crate::code_map::impact::ImpactSeed::symbol(
                "changed.rs",
                "changed"
            )]
        );
        assert_eq!(from_mcp.impacted_nodes[0].node.symbol, "caller");

        let gaps = dispatch_codegraph_tool_at(
            &db,
            "codegraph_diff_test_gaps",
            &serde_json::json!({
                "root": repo.path(), "source": "stdin",
                "unified_diff": "diff --git a/changed.rs b/changed.rs\n--- a/changed.rs\n+++ b/changed.rs\n@@ -1 +1 @@\n-fn changed() {}\n+fn changed() { caller(); }\n"
            }),
            repo.path(),
        );
        assert!(!gaps.is_error, "got: {}", text_content(&gaps));
        let gaps: crate::code_map::test_coverage::ImpactTestGapResult =
            serde_json::from_str(&text_content(&gaps)).unwrap();
        assert!(gaps.no_observed_test_is_not_absence);
    }

    #[test]
    fn diff_test_gaps_rejects_multibyte_overlimit_stdin_before_db_or_diff_parse() {
        let repo = tempdir().unwrap();
        let missing_db = repo.path().join("absent-code-map.db");
        // Fewer characters than the schema maxLength, but more UTF-8 bytes:
        // proves the runtime byte check is authoritative at the public MCP
        // dispatch boundary and fires before either DB access or diff parsing.
        let oversized = "é".repeat(crate::code_map::diff::MAX_DIFF_BYTES / 2 + 1);
        let result = dispatch_codegraph_tool_at(
            &missing_db,
            "codegraph_diff_test_gaps",
            &serde_json::json!({
                "root": repo.path(),
                "source": "stdin",
                "unified_diff": oversized,
            }),
            repo.path(),
        );
        assert!(result.is_error);
        let text = text_content(&result);
        assert!(text.contains("UTF-8 byte limit"), "got: {text}");
        assert!(
            !text.contains("does not exist"),
            "byte cap must precede DB access: {text}"
        );
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
    fn outline_parser_agrees_with_advertised_live_schema() {
        let outline = codegraph_tools()
            .into_iter()
            .find(|tool| tool.name == "codegraph_outline")
            .expect("live catalogue contains codegraph_outline");
        assert_eq!(outline.input_schema["type"], "object");
        assert_eq!(
            outline.input_schema["required"],
            serde_json::json!(["path"])
        );
        assert_eq!(outline.input_schema["additionalProperties"], false);
        assert_eq!(outline.input_schema["properties"]["path"]["type"], "string");
        assert!(parse_outline_args(&serde_json::json!({"path": "src/a.rs"})).is_ok());
        assert!(
            parse_outline_args(&serde_json::json!({"path": "src/a.rs", "symbol": "a"})).is_err()
        );
        assert!(parse_outline_args(&serde_json::json!({"path": 7})).is_err());
        assert!(parse_outline_args(&serde_json::json!({})).is_err());
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
        assert!(
            listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| { tool["name"] == "codegraph_imports" })
        );
        assert!(
            listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| { tool["name"] == "codegraph_types" })
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

    fn w59_requested_policy() -> crate::config::RequestedContextPolicy {
        crate::config::RequestedContextPolicy {
            recall_max_files: 1,
            callers_per_symbol: 0,
            summary_token_budget: 128,
            max_bfs_depth: 2,
        }
    }

    #[test]
    fn w59_requested_runtime_keeps_four_public_success_shapes_with_real_sqlite_graph() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_code_map_db(&db, &repo);
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());

        let recall = dispatch_codegraph_tool_at_runtime(
            &db,
            "codegraph_recall_v1",
            &serde_json::json!({"prompt":"leaf","limit":1}),
            &repo,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        );
        assert!(!recall.is_error, "{}", text_content(&recall));
        assert!(
            serde_json::from_str::<serde_json::Value>(&text_content(&recall))
                .unwrap()
                .is_object()
        );
        let legacy = dispatch_codegraph_tool_at_runtime(
            &db,
            "codegraph_relevant_files",
            &serde_json::json!({"prompt":"leaf","limit":1}),
            &repo,
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        );
        assert!(!legacy.is_error, "{}", text_content(&legacy));
        assert!(
            serde_json::from_str::<serde_json::Value>(&text_content(&legacy))
                .unwrap()
                .is_array()
        );
        for (tool, arguments) in [
            (
                "codegraph_callers",
                serde_json::json!({"symbol":"leaf","depth":2}),
            ),
            (
                "codegraph_callees",
                serde_json::json!({"file":"x.rs","symbol":"root","depth":2}),
            ),
        ] {
            let result = dispatch_codegraph_tool_at_runtime(
                &db,
                tool,
                &arguments,
                &repo,
                CodegraphImpactRuntime::static_defaults(),
                runtime,
            );
            assert!(!result.is_error, "{tool}: {}", text_content(&result));
            assert!(
                serde_json::from_str::<serde_json::Value>(&text_content(&result))
                    .unwrap()
                    .is_array()
            );
        }
    }

    #[test]
    fn w59_requested_runtime_rejects_raw_limit_depth_and_overflow_before_db_access() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("never-opened.db");
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());
        for (tool, arguments, expected) in [
            (
                "codegraph_recall_v1",
                serde_json::json!({"prompt":"x","limit":2}),
                "recall rejected before DB access",
            ),
            (
                "codegraph_callers",
                serde_json::json!({"symbol":"x","depth":3}),
                "callers rejected before DB access",
            ),
            (
                "codegraph_callees",
                serde_json::json!({"file":"x.rs","symbol":"x","depth":21}),
                "callees rejected before DB access",
            ),
        ] {
            let result = dispatch_codegraph_tool_at_runtime(
                &missing,
                tool,
                &arguments,
                dir.path(),
                CodegraphImpactRuntime::static_defaults(),
                runtime,
            );
            let text = text_content(&result);
            assert!(result.is_error && text.contains(expected), "{tool}: {text}");
            assert!(
                !text.contains("does not exist"),
                "{tool} opened the DB: {text}"
            );
        }
        let overflow = dispatch_codegraph_tool_at_runtime(
            &missing,
            "codegraph_recall_v1",
            &serde_json::json!({"prompt":"x","limit":4294967296u64}),
            dir.path(),
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        );
        assert!(overflow.is_error);
        assert!(text_content(&overflow).contains("bad args"));
    }

    #[test]
    fn w59_descriptor_is_exact_atomic_and_raw_mode_stays_static() {
        let dir = tempdir().unwrap();
        let database = dir.path().join("code_map.db");
        std::fs::write(&database, b"fixture").unwrap();
        let base = w56_generated_base(&database.canonicalize().unwrap());
        let impact = crate::config::CodeMapImpactPolicy {
            max_depth: 2,
            max_nodes: 40,
            allow_stale: false,
        };
        let effective = effective_builtin_codegraph_server_with_requested_policy(
            &base,
            impact,
            w59_requested_policy(),
        )
        .unwrap();
        assert_eq!(
            effective.args[4..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "--impact-max-depth",
                "2",
                "--impact-max-nodes",
                "40",
                "--impact-allow-stale",
                "false",
                "--requested-recall-max-files",
                "1",
                "--requested-callers-per-symbol",
                "0",
                "--requested-summary-token-budget",
                "128",
                "--requested-max-bfs-depth",
                "2",
            ]
        );
        let mut lookalike = base.clone();
        lookalike
            .args
            .extend(["--requested-recall-max-files".into(), "1".into()]);
        assert_eq!(
            effective_builtin_codegraph_server_with_requested_policy(
                &lookalike,
                impact,
                w59_requested_policy()
            )
            .unwrap(),
            lookalike
        );
        assert_eq!(
            RequestedContextRuntime::static_defaults()
                .recall_limit(100)
                .unwrap(),
            50
        );
    }

    #[test]
    fn w59_requested_result_cap_is_typed_and_does_not_change_other_tools() {
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());
        let oversized = runtime.bound_result(text_result("x".repeat(513)));
        assert!(oversized.is_error);
        assert!(text_content(&oversized).contains("exceeding accepted rendered ceiling 512"));
        let mut source = String::from("fn leaf() {}\n");
        for index in 0..32 {
            source.push_str(&format!("fn caller_{index:02}() {{ leaf(); }}\n"));
        }
        let graph = graph_from_rust("fixture.rs", &source);
        let bounded = callers_inner_with_requested_budget(&graph, "leaf", 1, runtime);
        assert!(
            bounded.is_err(),
            "a public JSON array must be refused whole, never partially rendered"
        );
        let unrequested = dispatch_codegraph_tool_at_runtime(
            &tempdir().unwrap().path().join("missing.db"),
            "codegraph_extract_identifiers",
            &serde_json::json!({"text":"OrderService"}),
            std::path::Path::new("."),
            CodegraphImpactRuntime::static_defaults(),
            runtime,
        );
        assert!(
            !unrequested.is_error,
            "requested policy must not cap extract-identifiers"
        );
    }

    #[test]
    fn w61_generated_stdio_binds_all_four_tools_from_one_real_snapshot_including_empty_results() {
        // The stdio handler deliberately resolves its repository from the
        // process CWD. Keep this scoped process-global mutation serialized and
        // restore it before the temporary repository is dropped.
        let _environment = crate::test_env::lock();
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let repo = dir.path().join("repo");
        seed_code_map_db(&db, &repo);
        let prior_cwd = std::env::current_dir().unwrap();
        struct RestoreCwd(std::path::PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                std::env::set_current_dir(&self.0).expect("restore W61 fixture CWD");
            }
        }
        std::env::set_current_dir(&repo).unwrap();
        let _restore_cwd = RestoreCwd(prior_cwd);
        let runtime = RequestedContextRuntime::from_policy(w59_requested_policy());
        let calls = [
            (
                "codegraph_recall_v1",
                serde_json::json!({"prompt":"absent_symbol","limit":1}),
            ),
            (
                "codegraph_relevant_files",
                serde_json::json!({"prompt":"absent_symbol","limit":1}),
            ),
            (
                "codegraph_callers",
                serde_json::json!({"symbol":"root","depth":1}),
            ),
            (
                "codegraph_callees",
                serde_json::json!({"file":"x.rs","symbol":"leaf","depth":1}),
            ),
        ];
        for (index, (tool, arguments)) in calls.into_iter().enumerate() {
            let mut session = StdioSession {
                initialize_seen: true,
                ready: true,
            };
            let request = serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0", "id":index, "method":"tools/call",
                "params":{"name":tool,"arguments":arguments}
            }))
            .unwrap();
            let response = handle_stdio_message_with_runtimes(
                &db,
                &request,
                &mut session,
                CodegraphImpactRuntime::static_defaults(),
                runtime,
            )
            .unwrap();
            let result: ToolCallResult =
                serde_json::from_value(response["result"].clone()).unwrap();
            assert!(!result.is_error, "{tool}: {result:?}");
            let inner: serde_json::Value = serde_json::from_str(&text_content(&result))
                .expect("the established public text payload remains JSON");
            match tool {
                "codegraph_recall_v1" => assert!(
                    inner.is_object(),
                    "recall remains its versioned object envelope"
                ),
                "codegraph_relevant_files" | "codegraph_callers" | "codegraph_callees" => {
                    assert!(
                        inner.is_array(),
                        "{tool} remains its legacy JSON array shape"
                    );
                }
                _ => unreachable!("the fixture is intentionally limited to the four bound tools"),
            }
            let meta = response["result"].get("_meta").cloned();
            validate_codegraph_context_binding_metadata(tool, &result, meta.as_ref()).unwrap();
            let binding = meta.unwrap()[CODEGRAPH_CONTEXT_BINDING_META_KEY].clone();
            assert_eq!(binding["index_generation"], binding["graph_generation"]);
            assert!(binding["index_generation"].as_i64().unwrap() > 0);
        }
    }

    #[test]
    fn w61_context_binding_rejects_unknown_own_fields_but_does_not_constrain_other_meta_namespaces()
    {
        let result = text_result("[]".into());
        let projection =
            serde_json::to_vec(&crate::mcp::client::tool_call_result_projection(&result)).unwrap();
        let own = serde_json::json!({
            "schema":"io.neoth.codegraph.context_binding.v1", "tool":"codegraph_callers",
            "root_identity_sha256":"a".repeat(64), "index_generation":1, "graph_generation":1,
            "public_result_sha256":hex::encode(Sha256::digest(&projection)), "public_result_bytes":projection.len(),
        });
        let meta = serde_json::json!({CODEGRAPH_CONTEXT_BINDING_META_KEY: own, "com.example.other": {"opaque": true}});
        validate_codegraph_context_binding_metadata("codegraph_callers", &result, Some(&meta))
            .unwrap();
        let mut malformed = meta;
        malformed[CODEGRAPH_CONTEXT_BINDING_META_KEY]["root"] = serde_json::json!("C:/private");
        assert!(
            validate_codegraph_context_binding_metadata(
                "codegraph_callers",
                &result,
                Some(&malformed)
            )
            .is_err()
        );
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

    #[test]
    fn w239_native_fs_read_plan_uses_real_descriptor_and_drops_stale_sidecar() {
        let home = tempdir().unwrap();
        let repository = home.path().join("repository");
        let database = home.path().join("code_map.db");
        seed_code_map_db(&database, &repository);
        let descriptor = w56_generated_base(&database.canonicalize().unwrap());
        std::fs::write(
            home.path().join("mcp_servers.yaml"),
            serde_yaml::to_string(&McpServers {
                servers: vec![descriptor],
                smart_loading: false,
            })
            .unwrap(),
        )
        .unwrap();
        let root = repository.canonicalize().unwrap();
        let target = root.join("x.rs");
        let context = crate::hooks::PreToolUseContext::admitted(
            crate::hooks::PreToolUseOrigin::DirectCliOsFileRead,
            "native-os-file-read",
            "fs-read",
            &serde_json::json!({"path": target.display().to_string()}),
            &root,
            &root,
            std::time::Duration::from_secs(1),
            crate::hooks::PreToolUseCancellation::unbound(),
            crate::hooks::PreToolUseReplay::direct_request(),
        )
        .unwrap();

        let plan = prepare_native_fs_read_enrichment(home.path(), &root, &target, &context, true)
            .unwrap()
            .expect("the actual generated descriptor and fresh indexed target are eligible");
        let NativeFsReadFreshness::Fresh(sidecar) = plan.freshness_after_read() else {
            panic!("fresh sidecar after the successful read boundary")
        };
        assert!(
            sidecar
                .as_str()
                .contains("native_origin: direct_cli_os_file_read")
        );
        assert!(!sidecar.as_str().contains("configured_mcp:"));

        std::fs::write(&target, "fn changed_after_plan() {}\n").unwrap();
        assert!(matches!(
            plan.freshness_after_read(),
            NativeFsReadFreshness::Stale
        ));
        assert!(
            !matches!(plan.freshness_after_read(), NativeFsReadFreshness::Fresh(_)),
            "a changed root cannot append native sidecar evidence after the file read"
        );
    }
}
