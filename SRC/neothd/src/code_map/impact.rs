//! Root-scoped structural blast-radius analysis over persisted code-map data.
//!
//! The persisted call graph stores heuristic name references. This service
//! resolves every endpoint back to one concrete declaration before traversal:
//! `(root, file, symbol, line, kind)`. Missing or ambiguous endpoints are
//! reported as unresolved evidence and are never traversed. That conservative
//! boundary prevents same-name declarations in different files from being
//! silently conflated.
//!
//! An impact query is also generation-bound. Production rebuilds atomically
//! publish the map, edge set, `index_generation`, and `graph_generation` in one
//! transaction. Queries refuse non-positive or mismatched generations and,
//! unless explicitly overridden, an index that no longer matches the files on
//! disk.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::graph::{CodeEdge, EdgeKind};
use super::persist::{
    index_freshness_receipt, load_edges_for_root_bounded_with_text_limit, root_graph_generation,
    root_index_generation,
};
use super::recall::resolve_active_root;

pub const DEFAULT_MAX_DEPTH: usize = 3;
pub const DEFAULT_MAX_NODES: usize = 250;
pub const MAX_IMPACT_DEPTH: usize = 32;
pub const MAX_IMPACT_NODES: usize = 10_000;
pub const MAX_REQUESTED_SEEDS: usize = 256;
pub const MAX_RESOLVED_SEED_NODES: usize = 4_096;
const MAX_PREPROCESSING_FILES: usize = 250_000;
const MAX_PREPROCESSING_SYMBOLS: usize = 250_000;
const MAX_PREPROCESSING_EDGES: usize = 250_000;
const MAX_PREPROCESSING_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SINGLE_IDENTITY_TEXT_BYTES: usize = 64 * 1024;
const MAX_IDENTITY_ALLOCATION_BYTES: usize = 32 * 1024 * 1024;
const MAX_RESOLVED_EDGE_ALLOCATION_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENDPOINT_CANDIDATES: usize = 16;
const MAX_UNRESOLVED_EVIDENCE_BYTES: usize = 512 * 1024;
const MAX_PATH_EVIDENCE_RECORDS: usize = 8_192;
const MAX_IMPACTED_NODE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
/// Canonical impact-result ceiling. The generic MCP outbound encoder remains
/// the final authority after this JSON is escaped into a `tools/call` envelope.
pub const MAX_SERIALIZED_IMPACT_RESULT_BYTES: usize = 6 * 1024 * 1024;
const CALL_DEPTH_DECAY: f64 = 0.6;

/// One file or exact declaration selected as a changed-set seed.
///
/// `symbol = None` expands to every persisted declaration in `file`.
/// `symbol = Some(..)` must resolve to exactly one declaration in that file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactSeed {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

impl ImpactSeed {
    pub fn file(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            symbol: None,
        }
    }

    pub fn symbol(file: impl Into<String>, symbol: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            symbol: Some(symbol.into()),
        }
    }
}

/// Which side of a call relationship is affected by a changed declaration.
///
/// - `callers`: dependents that call the changed declaration (blast radius).
/// - `callees`: dependencies called by the changed declaration.
/// - `both`: the union of both neighborhoods at each hop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactDirection {
    #[default]
    Callers,
    Callees,
    Both,
}

impl ImpactDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Callers => "callers",
            Self::Callees => "callees",
            Self::Both => "both",
        }
    }
}

impl FromStr for ImpactDirection {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "callers" => Ok(Self::Callers),
            "callees" => Ok(Self::Callees),
            "both" => Ok(Self::Both),
            other => {
                bail!("invalid impact direction {other:?}; expected callers, callees, or both")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactOptions {
    pub direction: ImpactDirection,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub allow_stale: bool,
}

impl Default for ImpactOptions {
    fn default() -> Self {
        Self {
            direction: ImpactDirection::Callers,
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            allow_stale: false,
        }
    }
}

/// Canonical declaration identity used throughout the result.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ImpactNodeId {
    pub root: String,
    pub file: String,
    pub symbol: String,
    pub line: u32,
    pub kind: String,
}

/// One concrete call edge used as traversal evidence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImpactEdgeEvidence {
    pub caller: ImpactNodeId,
    pub callee: ImpactNodeId,
    /// The direction in which this edge was traversed from the prior node.
    /// Always `callers` or `callees`; `both` is a query mode, not an edge.
    pub traversal: ImpactDirection,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactedNode {
    #[serde(flatten)]
    pub node: ImpactNodeId,
    pub distance: usize,
    pub score: f64,
    /// Deterministic shortest evidence path from one seed to this node.
    pub path: Vec<ImpactEdgeEvidence>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactedFile {
    pub root: String,
    pub file: String,
    pub nearest_distance: usize,
    pub max_score: f64,
    pub impacted_symbols: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedSeedReason {
    InvalidPath,
    InvalidSymbol,
    UnindexedFile,
    FileHasNoSymbols,
    MissingSymbol,
    AmbiguousSymbol,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnresolvedSeed {
    pub seed: ImpactSeed,
    pub reason: UnresolvedSeedReason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ImpactNodeId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub candidates_truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedEdgeEndpoint {
    Edge,
    Source,
    Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedEdgeReason {
    UnsupportedReferenceEdge,
    InvalidSourcePath,
    MissingSource,
    AmbiguousSource,
    MissingTarget,
    AmbiguousTarget,
}

/// An edge that could not be tied to one concrete source and target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnresolvedEdge {
    pub from_file: String,
    pub from_symbol: String,
    pub to_name: String,
    pub kind: String,
    pub endpoint: UnresolvedEdgeEndpoint,
    pub reason: UnresolvedEdgeReason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ImpactNodeId>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub candidates_truncated: bool,
}

/// Canonical result shared by CLI and MCP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactResult {
    pub root: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub stale: bool,
    pub direction: ImpactDirection,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub requested_seeds: Vec<ImpactSeed>,
    pub seed_nodes: Vec<ImpactNodeId>,
    pub impacted_nodes: Vec<ImpactedNode>,
    pub impacted_files: Vec<ImpactedFile>,
    pub traversed_edges: Vec<ImpactEdgeEvidence>,
    pub unresolved_seeds: Vec<UnresolvedSeed>,
    pub unresolved_edges: Vec<UnresolvedEdge>,
    /// True only when the `max_nodes` ceiling omitted reachable nodes.
    pub truncated: bool,
    /// True when the explicit path-evidence record/byte budget omitted
    /// reachable nodes. This is separate from `truncated` so a caller never
    /// mistakes a resource-bounded partial result for a complete traversal.
    #[serde(default)]
    pub budget_truncated: bool,
    /// True when unresolved-edge evidence exceeded its bounded output ceiling.
    pub evidence_truncated: bool,
    /// SHA-256 over the canonical JSON result with this field set to `""`.
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ResolvedEdge {
    caller: ImpactNodeId,
    callee: ImpactNodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TraversalStep {
    neighbor: ImpactNodeId,
    evidence: ImpactEdgeEvidence,
}

#[derive(Clone, Debug)]
struct BestPath {
    distance: usize,
    path: Vec<ImpactEdgeEvidence>,
    path_wire_bytes: usize,
    output_wire_bytes: usize,
}

#[derive(Clone, Copy)]
struct TraversalBudget {
    max_path_records: usize,
    max_output_bytes: usize,
}

impl Default for TraversalBudget {
    fn default() -> Self {
        Self {
            max_path_records: MAX_PATH_EVIDENCE_RECORDS,
            max_output_bytes: MAX_IMPACTED_NODE_OUTPUT_BYTES,
        }
    }
}

type SymbolRows = (
    BTreeSet<String>,
    BTreeMap<String, Vec<ImpactNodeId>>,
    BTreeMap<(String, String), Vec<ImpactNodeId>>,
    BTreeMap<String, Vec<ImpactNodeId>>,
);

/// Compute a deterministic, bounded impact radius for one persisted root.
///
/// Callers must pass the root selected by the same containment authority as
/// their surface (normally `resolve_active_root(cwd)`). This function never
/// searches another root and never falls back to a same-name declaration.
pub fn impact_radius(
    conn: &Connection,
    root: &str,
    seeds: &[ImpactSeed],
    options: ImpactOptions,
) -> Result<ImpactResult> {
    impact_radius_with_final_check(conn, root, seeds, options, || {})
}

fn impact_radius_with_final_check<F>(
    conn: &Connection,
    root: &str,
    seeds: &[ImpactSeed],
    options: ImpactOptions,
    before_final_check: F,
) -> Result<ImpactResult>
where
    F: FnOnce(),
{
    validate_request(seeds, options)?;

    let Some(index_generation) = root_index_generation(conn, root)? else {
        bail!("code-map root {root:?} is not indexed; run `neoth code-map persist` there first");
    };
    let Some(graph_generation) = root_graph_generation(conn, root)? else {
        bail!("code-map root {root:?} has no graph-generation metadata; rebuild its code map");
    };
    if index_generation <= 0 || graph_generation <= 0 {
        bail!(
            "code-map graph for root {root:?} is not a certified rebuilt snapshot: \
             index generation {index_generation}, graph generation {graph_generation}; \
             rerun `neoth code-map persist`"
        );
    }
    if index_generation != graph_generation {
        bail!(
            "code-map graph is not current for root {root:?}: index generation \
             {index_generation}, graph generation {graph_generation}; rerun `neoth code-map persist`"
        );
    }

    let initial_freshness = index_freshness_receipt(conn, root)
        .with_context(|| format!("verify code-map freshness for root {root:?}"))?;
    let stale = initial_freshness.stale;
    if stale && !options.allow_stale {
        bail!(
            "code-map index for root {root:?} is stale; rerun `neoth code-map persist` \
             or explicitly pass allow_stale=true"
        );
    }

    enforce_preprocessing_limits(conn, root)?;
    let ((indexed_files, by_file, by_file_symbol, by_name), symbol_text_bytes) =
        load_symbol_rows(conn, root)?;
    if indexed_files.is_empty() {
        bail!("code-map root {root:?} contains no indexed files; persist a non-empty repository");
    }

    let mut requested_seeds: Vec<ImpactSeed> = seeds.to_vec();
    requested_seeds.sort();
    requested_seeds.dedup();
    let (seed_nodes, unresolved_seeds) =
        resolve_seeds(&requested_seeds, &indexed_files, &by_file, &by_file_symbol);
    if seed_nodes.is_empty() {
        let detail =
            serde_json::to_string(&unresolved_seeds).unwrap_or_else(|_| "unresolved".into());
        bail!("no impact seed resolved in root {root:?}: {detail}");
    }
    if seed_nodes.len() > MAX_RESOLVED_SEED_NODES {
        bail!(
            "impact seed expansion resolved {} declarations; maximum is \
             {MAX_RESOLVED_SEED_NODES}. Select exact file::symbol seeds",
            seed_nodes.len()
        );
    }

    let evidence_limit = options.max_nodes.max(1).min(MAX_IMPACT_NODES);
    let remaining_text_bytes = MAX_PREPROCESSING_TEXT_BYTES.saturating_sub(symbol_text_bytes);
    let (raw_edges, edge_limit_exceeded, _) = load_edges_for_root_bounded_with_text_limit(
        conn,
        root,
        MAX_PREPROCESSING_EDGES,
        remaining_text_bytes,
    )?;
    if edge_limit_exceeded {
        bail!(
            "impact preprocessing refused more than {MAX_PREPROCESSING_EDGES} edge rows; \
             persist a narrower repository or select a smaller code-map root"
        );
    }
    let (resolved_edges, unresolved_edges, evidence_truncated) = resolve_edges(
        raw_edges,
        &by_file_symbol,
        &by_name,
        evidence_limit,
        MAX_UNRESOLVED_EVIDENCE_BYTES,
        MAX_RESOLVED_EDGE_ALLOCATION_BYTES,
    )?;

    let (forward, reverse) = build_adjacency(&resolved_edges);
    let (mut impacted_nodes, truncated, budget_truncated) = traverse(
        &seed_nodes,
        &forward,
        &reverse,
        options.direction,
        options.max_depth,
        options.max_nodes,
    );
    impacted_nodes.sort_by(compare_impacted_nodes);

    let impacted_files = aggregate_files(&impacted_nodes);
    let traversed_edges = impacted_nodes
        .iter()
        .flat_map(|node| node.path.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    before_final_check();

    // Concurrent DB and filesystem changes are both receipts: a generation
    // mismatch invalidates the rows traversed, while a different filesystem
    // fingerprint invalidates the initial `stale` observation.
    let final_index_generation = root_index_generation(conn, root)?;
    let final_graph_generation = root_graph_generation(conn, root)?;
    if final_index_generation != Some(index_generation)
        || final_graph_generation != Some(graph_generation)
    {
        bail!(
            "code-map root {root:?} changed while impact analysis was running; retry against the new generation"
        );
    }
    let final_freshness = index_freshness_receipt(conn, root)
        .with_context(|| format!("recheck code-map freshness for root {root:?}"))?;
    if final_freshness.filesystem_fingerprint != initial_freshness.filesystem_fingerprint {
        bail!(
            "code-map files for root {root:?} changed while impact analysis was running; \
             retry against a stable filesystem snapshot"
        );
    }
    let stale = stale || final_freshness.stale;
    if stale && !options.allow_stale {
        bail!(
            "code-map index for root {root:?} became stale while impact analysis was running; \
             rerun `neoth code-map persist`"
        );
    }

    let result = ImpactResult {
        root: root.to_string(),
        index_generation,
        graph_generation,
        stale,
        direction: options.direction,
        max_depth: options.max_depth,
        max_nodes: options.max_nodes,
        requested_seeds,
        seed_nodes: seed_nodes.into_iter().collect(),
        impacted_nodes,
        impacted_files,
        traversed_edges,
        unresolved_seeds,
        unresolved_edges,
        truncated,
        budget_truncated,
        evidence_truncated,
        digest: String::new(),
    };
    finalize_impact_result(result, MAX_SERIALIZED_IMPACT_RESULT_BYTES)
}

fn finalize_impact_result(mut result: ImpactResult, byte_limit: usize) -> Result<ImpactResult> {
    result.digest.clear();
    let canonical =
        serde_json::to_vec(&result).context("serialize canonical impact result for digest")?;
    result.digest = hex::encode(Sha256::digest(canonical));
    let serialized =
        serde_json::to_vec(&result).context("serialize final bounded impact result")?;
    if serialized.len() > byte_limit {
        bail!(
            "impact result requires {} serialized bytes; hard ceiling is {byte_limit}. \
             Reduce max_nodes/max_depth or select narrower exact seeds",
            serialized.len()
        );
    }
    Ok(result)
}

/// Resolve the active persisted root from `current_path` and run the canonical
/// impact service. CLI and MCP both use this entry point so containment,
/// freshness, ordering, and digest semantics cannot drift between surfaces.
pub fn impact_radius_for_path(
    conn: &Connection,
    current_path: &Path,
    seeds: &[ImpactSeed],
    options: ImpactOptions,
) -> Result<ImpactResult> {
    let active_root = resolve_active_root(conn, current_path).ok_or_else(|| {
        anyhow::anyhow!(
            "current path {} is not inside a persisted code-map root; run `neoth code-map persist` there first",
            current_path.display()
        )
    })?;
    impact_radius(conn, &active_root, seeds, options)
}

fn validate_request(seeds: &[ImpactSeed], options: ImpactOptions) -> Result<()> {
    if seeds.is_empty() {
        bail!("impact analysis requires at least one --file or --symbol seed");
    }
    if seeds.len() > MAX_REQUESTED_SEEDS {
        bail!(
            "impact request contains {} seeds; maximum is {MAX_REQUESTED_SEEDS}",
            seeds.len()
        );
    }
    if options.max_depth > MAX_IMPACT_DEPTH {
        bail!(
            "impact max_depth {} exceeds hard ceiling {MAX_IMPACT_DEPTH}",
            options.max_depth
        );
    }
    if options.max_nodes > MAX_IMPACT_NODES {
        bail!(
            "impact max_nodes {} exceeds hard ceiling {MAX_IMPACT_NODES}",
            options.max_nodes
        );
    }
    Ok(())
}

fn enforce_preprocessing_limits(conn: &Connection, root: &str) -> Result<()> {
    let file_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM code_map_files WHERE root = ?1",
            rusqlite::params![root],
            |row| row.get(0),
        )
        .context("count impact files before preprocessing")?;
    let symbol_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) \
             FROM code_map_symbols s \
             JOIN code_map_files f ON f.id = s.file_id \
             WHERE f.root = ?1",
            rusqlite::params![root],
            |row| row.get(0),
        )
        .context("count impact symbols before preprocessing")?;
    let edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM code_map_edges WHERE root = ?1",
            rusqlite::params![root],
            |row| row.get(0),
        )
        .context("count impact edges before preprocessing")?;
    enforce_preprocessing_count("file", file_count, MAX_PREPROCESSING_FILES)?;
    enforce_preprocessing_count("symbol", symbol_count, MAX_PREPROCESSING_SYMBOLS)?;
    enforce_preprocessing_count("edge", edge_count, MAX_PREPROCESSING_EDGES)?;
    enforce_preprocessing_text_bytes(conn, root, MAX_PREPROCESSING_TEXT_BYTES)
}

fn enforce_preprocessing_count(kind: &str, count: i64, ceiling: usize) -> Result<()> {
    let count = usize::try_from(count)
        .with_context(|| format!("invalid negative code-map {kind} count {count}"))?;
    if count > ceiling {
        bail!(
            "impact preprocessing refused {count} {kind} rows; hard ceiling is {ceiling}. \
             Persist a narrower repository or select a smaller code-map root"
        );
    }
    Ok(())
}

/// Count UTF-8 bytes in SQLite before any path/symbol/edge text is copied into
/// Rust allocations. Row-count caps alone do not protect an untrusted
/// repository from storing a few enormous identifiers.
fn enforce_preprocessing_text_bytes(conn: &Connection, root: &str, ceiling: usize) -> Result<()> {
    let bytes: i64 = conn
        .query_row(
            "SELECT \
                 COALESCE((SELECT SUM(length(CAST(path AS BLOB))) \
                           FROM code_map_files WHERE root = ?1), 0) + \
                 COALESCE((SELECT SUM(length(CAST(s.name AS BLOB)) + \
                                      length(CAST(s.kind AS BLOB))) \
                           FROM code_map_symbols s \
                           JOIN code_map_files f ON f.id = s.file_id \
                           WHERE f.root = ?1), 0) + \
                 COALESCE((SELECT SUM(length(CAST(from_file AS BLOB)) + \
                                      length(CAST(from_symbol AS BLOB)) + \
                                      length(CAST(to_name AS BLOB)) + \
                                      length(CAST(kind AS BLOB))) \
                           FROM code_map_edges WHERE root = ?1), 0)",
            rusqlite::params![root],
            |row| row.get(0),
        )
        .context("count impact preprocessing text bytes")?;
    let bytes = usize::try_from(bytes)
        .with_context(|| format!("invalid negative impact text-byte count {bytes}"))?;
    if bytes > ceiling {
        bail!(
            "impact preprocessing refused {bytes} path/symbol/edge text bytes; \
             hard ceiling is {ceiling}. Persist a narrower repository or \
             shorten generated identifiers"
        );
    }
    Ok(())
}

fn load_symbol_rows(conn: &Connection, root: &str) -> Result<(SymbolRows, usize)> {
    let mut text_bytes = 0usize;
    let mut identity_allocation_bytes = 0usize;
    let file_limit = i64::try_from(MAX_PREPROCESSING_FILES.saturating_add(1))
        .context("convert impact file-query limit")?;
    let indexed_file_rows: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT path, length(CAST(path AS BLOB)) \
                 FROM code_map_files WHERE root = ?1 ORDER BY path LIMIT ?2",
            )
            .context("prepare impact indexed-files query")?;
        let mut rows = stmt
            .query(rusqlite::params![root, file_limit])
            .context("query impact indexed files")?;
        let mut output = Vec::with_capacity(MAX_PREPROCESSING_FILES.min(4_096));
        while let Some(row) = rows.next().context("advance impact indexed-file row")? {
            reserve_text_bytes(
                &mut text_bytes,
                row.get(1).context("read indexed-file text-byte count")?,
                MAX_PREPROCESSING_TEXT_BYTES,
                "indexed-file",
            )?;
            output.push(row.get(0).context("read impact indexed-file path")?);
        }
        output
    };
    if indexed_file_rows.len() > MAX_PREPROCESSING_FILES {
        bail!(
            "impact preprocessing refused more than {MAX_PREPROCESSING_FILES} file rows; \
             persist a narrower repository or select a smaller code-map root"
        );
    }
    let indexed_files = indexed_file_rows.into_iter().collect();

    let symbol_limit = i64::try_from(MAX_PREPROCESSING_SYMBOLS.saturating_add(1))
        .context("convert impact symbol-query limit")?;
    let rows: Vec<(String, String, String, i64)> = {
        let mut stmt = conn
            .prepare(
                "SELECT f.path, s.name, s.kind, s.line, \
                        length(CAST(s.name AS BLOB)) + length(CAST(s.kind AS BLOB)), \
                        length(CAST(f.path AS BLOB)) + \
                        length(CAST(s.name AS BLOB)) + length(CAST(s.kind AS BLOB)) \
                 FROM code_map_symbols s \
                 JOIN code_map_files f ON f.id = s.file_id \
                 WHERE f.root = ?1 \
                 ORDER BY f.path, s.name, s.line, s.kind \
                 LIMIT ?2",
            )
            .context("prepare impact symbol query")?;
        let mut rows = stmt
            .query(rusqlite::params![root, symbol_limit])
            .context("query impact symbols")?;
        let mut output = Vec::with_capacity(MAX_PREPROCESSING_SYMBOLS.min(4_096));
        while let Some(row) = rows.next().context("advance impact symbol row")? {
            reserve_text_bytes(
                &mut text_bytes,
                row.get(4).context("read symbol text-byte count")?,
                MAX_PREPROCESSING_TEXT_BYTES,
                "symbol",
            )?;
            let identity_text_bytes: i64 = row
                .get(5)
                .context("read declaration identity text-byte count")?;
            let identity_text_bytes = usize::try_from(identity_text_bytes).with_context(|| {
                format!("invalid negative declaration identity byte count {identity_text_bytes}")
            })?;
            let identity_text_bytes = identity_text_bytes
                .checked_add(root.len())
                .context("declaration identity byte count overflow")?;
            if identity_text_bytes > MAX_SINGLE_IDENTITY_TEXT_BYTES {
                bail!(
                    "impact declaration identity requires {identity_text_bytes} text bytes; \
                     per-identity ceiling is {MAX_SINGLE_IDENTITY_TEXT_BYTES}"
                );
            }
            // Each concrete identity is retained in three indexes (`by_file`,
            // `by_file_symbol`, and `by_name`). Account for those clones before
            // materialising any of the row's strings.
            let retained_bytes = identity_text_bytes
                .checked_mul(3)
                .context("declaration identity allocation estimate overflow")?;
            identity_allocation_bytes = identity_allocation_bytes
                .checked_add(retained_bytes)
                .context("declaration identity allocation budget overflow")?;
            if identity_allocation_bytes > MAX_IDENTITY_ALLOCATION_BYTES {
                bail!(
                    "impact declaration indexes require more than \
                     {MAX_IDENTITY_ALLOCATION_BYTES} retained text bytes"
                );
            }
            output.push((
                row.get(0).context("read symbol file path")?,
                row.get(1).context("read symbol name")?,
                row.get(2).context("read symbol kind")?,
                row.get(3).context("read symbol line")?,
            ));
        }
        output
    };
    if rows.len() > MAX_PREPROCESSING_SYMBOLS {
        bail!(
            "impact preprocessing refused more than {MAX_PREPROCESSING_SYMBOLS} symbol rows; \
             persist a narrower repository or select a smaller code-map root"
        );
    }

    let mut by_file: BTreeMap<String, Vec<ImpactNodeId>> = BTreeMap::new();
    let mut by_file_symbol: BTreeMap<(String, String), Vec<ImpactNodeId>> = BTreeMap::new();
    let mut by_name: BTreeMap<String, Vec<ImpactNodeId>> = BTreeMap::new();
    for (file, symbol, kind, line) in rows {
        let line = u32::try_from(line)
            .with_context(|| format!("invalid declaration line {line} for {file}::{symbol}"))?;
        if line == 0 {
            bail!("invalid declaration line 0 for {file}::{symbol}; rebuild the code map");
        }
        let node = ImpactNodeId {
            root: root.to_string(),
            file: file.clone(),
            symbol: symbol.clone(),
            line,
            kind,
        };
        by_file.entry(file.clone()).or_default().push(node.clone());
        by_file_symbol
            .entry((file, symbol.clone()))
            .or_default()
            .push(node.clone());
        by_name.entry(symbol).or_default().push(node);
    }
    Ok((
        (indexed_files, by_file, by_file_symbol, by_name),
        text_bytes,
    ))
}

fn reserve_text_bytes(used: &mut usize, row_bytes: i64, ceiling: usize, kind: &str) -> Result<()> {
    let row_bytes = usize::try_from(row_bytes)
        .with_context(|| format!("invalid negative {kind} text-byte count {row_bytes}"))?;
    if row_bytes > MAX_SINGLE_IDENTITY_TEXT_BYTES {
        bail!(
            "impact {kind} row requires {row_bytes} text bytes; per-row ceiling is \
             {MAX_SINGLE_IDENTITY_TEXT_BYTES}"
        );
    }
    *used = (*used)
        .checked_add(row_bytes)
        .with_context(|| format!("{kind} text-byte count overflow"))?;
    if *used > ceiling {
        bail!("impact {kind} materialization refused more than {ceiling} cumulative text bytes");
    }
    Ok(())
}

fn resolve_seeds(
    requested: &[ImpactSeed],
    indexed_files: &BTreeSet<String>,
    by_file: &BTreeMap<String, Vec<ImpactNodeId>>,
    by_file_symbol: &BTreeMap<(String, String), Vec<ImpactNodeId>>,
) -> (BTreeSet<ImpactNodeId>, Vec<UnresolvedSeed>) {
    let mut resolved = BTreeSet::new();
    let mut unresolved = BTreeSet::new();

    for seed in requested {
        let Some(file) = normalize_repo_relative_path(&seed.file) else {
            unresolved.insert(seed_issue(seed, UnresolvedSeedReason::InvalidPath, &[]));
            continue;
        };
        if !indexed_files.contains(&file) {
            unresolved.insert(seed_issue(seed, UnresolvedSeedReason::UnindexedFile, &[]));
            continue;
        }

        match seed.symbol.as_deref() {
            None => match by_file.get(&file) {
                Some(nodes) if !nodes.is_empty() => resolved.extend(nodes.iter().cloned()),
                _ => {
                    unresolved.insert(seed_issue(
                        seed,
                        UnresolvedSeedReason::FileHasNoSymbols,
                        &[],
                    ));
                }
            },
            Some(symbol) if symbol.trim().is_empty() => {
                unresolved.insert(seed_issue(seed, UnresolvedSeedReason::InvalidSymbol, &[]));
            }
            Some(symbol) => {
                let candidates = by_file_symbol
                    .get(&(file, symbol.trim().to_string()))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                match candidates {
                    [only] => {
                        resolved.insert(only.clone());
                    }
                    [] => {
                        unresolved.insert(seed_issue(
                            seed,
                            UnresolvedSeedReason::MissingSymbol,
                            candidates,
                        ));
                    }
                    _ => {
                        unresolved.insert(seed_issue(
                            seed,
                            UnresolvedSeedReason::AmbiguousSymbol,
                            candidates,
                        ));
                    }
                }
            }
        }
    }

    (resolved, unresolved.into_iter().collect())
}

fn seed_issue(
    seed: &ImpactSeed,
    reason: UnresolvedSeedReason,
    candidates: &[ImpactNodeId],
) -> UnresolvedSeed {
    let candidates_truncated = candidates.len() > MAX_ENDPOINT_CANDIDATES;
    UnresolvedSeed {
        seed: seed.clone(),
        reason,
        candidates: candidates
            .iter()
            .take(MAX_ENDPOINT_CANDIDATES)
            .cloned()
            .collect(),
        candidates_truncated,
    }
}

fn resolve_edges(
    raw_edges: Vec<CodeEdge>,
    by_file_symbol: &BTreeMap<(String, String), Vec<ImpactNodeId>>,
    by_name: &BTreeMap<String, Vec<ImpactNodeId>>,
    evidence_limit: usize,
    evidence_byte_limit: usize,
    resolved_allocation_limit: usize,
) -> Result<(BTreeSet<ResolvedEdge>, Vec<UnresolvedEdge>, bool)> {
    let mut resolved = BTreeSet::new();
    let mut resolved_allocation_bytes = 0usize;
    let mut unresolved = BTreeSet::new();
    let mut unresolved_bytes = 0usize;
    let mut evidence_truncated = false;

    for edge in raw_edges {
        if edge.kind == EdgeKind::References {
            evidence_truncated |= insert_unresolved_bounded(
                &mut unresolved,
                &mut unresolved_bytes,
                edge_issue(
                    &edge,
                    UnresolvedEdgeEndpoint::Edge,
                    UnresolvedEdgeReason::UnsupportedReferenceEdge,
                    &[],
                ),
                evidence_limit,
                evidence_byte_limit,
            );
            continue;
        }
        let Some(from_file) = normalize_repo_relative_path(&edge.from_file) else {
            evidence_truncated |= insert_unresolved_bounded(
                &mut unresolved,
                &mut unresolved_bytes,
                edge_issue(
                    &edge,
                    UnresolvedEdgeEndpoint::Source,
                    UnresolvedEdgeReason::InvalidSourcePath,
                    &[],
                ),
                evidence_limit,
                evidence_byte_limit,
            );
            continue;
        };
        let source_candidates = by_file_symbol
            .get(&(from_file, edge.from_symbol.clone()))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let target_candidates = by_name.get(&edge.to_name).map(Vec::as_slice).unwrap_or(&[]);

        let source = match source_candidates {
            [only] => Some(only),
            [] => {
                evidence_truncated |= insert_unresolved_bounded(
                    &mut unresolved,
                    &mut unresolved_bytes,
                    edge_issue(
                        &edge,
                        UnresolvedEdgeEndpoint::Source,
                        UnresolvedEdgeReason::MissingSource,
                        source_candidates,
                    ),
                    evidence_limit,
                    evidence_byte_limit,
                );
                None
            }
            _ => {
                evidence_truncated |= insert_unresolved_bounded(
                    &mut unresolved,
                    &mut unresolved_bytes,
                    edge_issue(
                        &edge,
                        UnresolvedEdgeEndpoint::Source,
                        UnresolvedEdgeReason::AmbiguousSource,
                        source_candidates,
                    ),
                    evidence_limit,
                    evidence_byte_limit,
                );
                None
            }
        };
        let target = match target_candidates {
            [only] => Some(only),
            [] => {
                evidence_truncated |= insert_unresolved_bounded(
                    &mut unresolved,
                    &mut unresolved_bytes,
                    edge_issue(
                        &edge,
                        UnresolvedEdgeEndpoint::Target,
                        UnresolvedEdgeReason::MissingTarget,
                        target_candidates,
                    ),
                    evidence_limit,
                    evidence_byte_limit,
                );
                None
            }
            _ => {
                evidence_truncated |= insert_unresolved_bounded(
                    &mut unresolved,
                    &mut unresolved_bytes,
                    edge_issue(
                        &edge,
                        UnresolvedEdgeEndpoint::Target,
                        UnresolvedEdgeReason::AmbiguousTarget,
                        target_candidates,
                    ),
                    evidence_limit,
                    evidence_byte_limit,
                );
                None
            }
        };

        if let (Some(caller), Some(callee)) = (source, target) {
            let candidate = ResolvedEdge {
                caller: caller.clone(),
                callee: callee.clone(),
            };
            if !resolved.contains(&candidate) {
                resolved_allocation_bytes = resolved_allocation_bytes
                    .checked_add(resolved_edge_allocation_upper_bound(&candidate))
                    .context("resolved-edge allocation budget overflow")?;
                if resolved_allocation_bytes > resolved_allocation_limit {
                    bail!(
                        "impact resolved-edge graph requires more than \
                         {resolved_allocation_limit} retained identity bytes; \
                         persist a narrower repository"
                    );
                }
                resolved.insert(candidate);
            }
        }
    }

    Ok((
        resolved,
        unresolved.into_iter().collect(),
        evidence_truncated,
    ))
}

fn edge_issue(
    edge: &CodeEdge,
    endpoint: UnresolvedEdgeEndpoint,
    reason: UnresolvedEdgeReason,
    candidates: &[ImpactNodeId],
) -> UnresolvedEdge {
    let candidates_truncated = candidates.len() > MAX_ENDPOINT_CANDIDATES;
    UnresolvedEdge {
        from_file: edge.from_file.clone(),
        from_symbol: edge.from_symbol.clone(),
        to_name: edge.to_name.clone(),
        kind: edge.kind.as_str().to_string(),
        endpoint,
        reason,
        candidates: candidates
            .iter()
            .take(MAX_ENDPOINT_CANDIDATES)
            .cloned()
            .collect(),
        candidates_truncated,
    }
}

fn json_string_wire_upper_bound(value: &str) -> usize {
    // A JSON control byte can expand to a six-byte `\u00XX` escape. UTF-8
    // bytes that do not need escaping remain one byte, so 6x plus quotes is a
    // conservative allocation-free ceiling.
    value.len().saturating_mul(6).saturating_add(2)
}

fn impact_node_wire_upper_bound(node: &ImpactNodeId) -> usize {
    96usize
        .saturating_add(json_string_wire_upper_bound(&node.root))
        .saturating_add(json_string_wire_upper_bound(&node.file))
        .saturating_add(json_string_wire_upper_bound(&node.symbol))
        .saturating_add(json_string_wire_upper_bound(&node.kind))
}

fn impact_node_text_bytes(node: &ImpactNodeId) -> usize {
    node.root
        .len()
        .saturating_add(node.file.len())
        .saturating_add(node.symbol.len())
        .saturating_add(node.kind.len())
}

fn resolved_edge_allocation_upper_bound(edge: &ResolvedEdge) -> usize {
    // The resolved set and forward/reverse adjacency retain several concrete
    // node/evidence clones per edge. Twelve copies is deliberately
    // conservative and keeps their cumulative text allocation bounded before
    // adjacency construction starts.
    impact_node_text_bytes(&edge.caller)
        .saturating_add(impact_node_text_bytes(&edge.callee))
        .saturating_add(256)
        .saturating_mul(12)
}

fn impact_edge_wire_upper_bound(edge: &ImpactEdgeEvidence) -> usize {
    96usize
        .saturating_add(impact_node_wire_upper_bound(&edge.caller))
        .saturating_add(impact_node_wire_upper_bound(&edge.callee))
}

fn unresolved_edge_wire_upper_bound(edge: &UnresolvedEdge) -> usize {
    edge.candidates
        .iter()
        .map(impact_node_wire_upper_bound)
        .fold(
            192usize
                .saturating_add(json_string_wire_upper_bound(&edge.from_file))
                .saturating_add(json_string_wire_upper_bound(&edge.from_symbol))
                .saturating_add(json_string_wire_upper_bound(&edge.to_name))
                .saturating_add(json_string_wire_upper_bound(&edge.kind)),
            usize::saturating_add,
        )
}

fn insert_unresolved_bounded(
    values: &mut BTreeSet<UnresolvedEdge>,
    current_bytes: &mut usize,
    value: UnresolvedEdge,
    record_limit: usize,
    byte_limit: usize,
) -> bool {
    let value_bytes = unresolved_edge_wire_upper_bound(&value);
    if !values.insert(value) {
        return false;
    }
    *current_bytes = (*current_bytes).saturating_add(value_bytes);
    let mut truncated = false;
    while values.len() > record_limit || *current_bytes > byte_limit {
        let Some(largest) = values.iter().next_back().cloned() else {
            break;
        };
        *current_bytes =
            (*current_bytes).saturating_sub(unresolved_edge_wire_upper_bound(&largest));
        values.remove(&largest);
        truncated = true;
    }
    truncated
}

fn build_adjacency(
    edges: &BTreeSet<ResolvedEdge>,
) -> (
    BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
    BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
) {
    let mut forward: BTreeMap<ImpactNodeId, BTreeSet<TraversalStep>> = BTreeMap::new();
    let mut reverse: BTreeMap<ImpactNodeId, BTreeSet<TraversalStep>> = BTreeMap::new();
    for edge in edges {
        forward
            .entry(edge.caller.clone())
            .or_default()
            .insert(TraversalStep {
                neighbor: edge.callee.clone(),
                evidence: ImpactEdgeEvidence {
                    caller: edge.caller.clone(),
                    callee: edge.callee.clone(),
                    traversal: ImpactDirection::Callees,
                },
            });
        reverse
            .entry(edge.callee.clone())
            .or_default()
            .insert(TraversalStep {
                neighbor: edge.caller.clone(),
                evidence: ImpactEdgeEvidence {
                    caller: edge.caller.clone(),
                    callee: edge.callee.clone(),
                    traversal: ImpactDirection::Callers,
                },
            });
    }
    (
        forward
            .into_iter()
            .map(|(node, steps)| (node, steps.into_iter().collect()))
            .collect(),
        reverse
            .into_iter()
            .map(|(node, steps)| (node, steps.into_iter().collect()))
            .collect(),
    )
}

fn traverse(
    seed_nodes: &BTreeSet<ImpactNodeId>,
    forward: &BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
    reverse: &BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
    direction: ImpactDirection,
    max_depth: usize,
    max_nodes: usize,
) -> (Vec<ImpactedNode>, bool, bool) {
    traverse_with_budget(
        seed_nodes,
        forward,
        reverse,
        direction,
        max_depth,
        max_nodes,
        TraversalBudget::default(),
    )
}

fn traverse_with_budget(
    seed_nodes: &BTreeSet<ImpactNodeId>,
    forward: &BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
    reverse: &BTreeMap<ImpactNodeId, Vec<TraversalStep>>,
    direction: ImpactDirection,
    max_depth: usize,
    max_nodes: usize,
    budget: TraversalBudget,
) -> (Vec<ImpactedNode>, bool, bool) {
    if max_depth == 0 {
        return (Vec::new(), false, false);
    }

    let mut visited = seed_nodes.clone();
    let mut frontier: BTreeMap<ImpactNodeId, BestPath> = seed_nodes
        .iter()
        .cloned()
        .map(|node| {
            (
                node,
                BestPath {
                    distance: 0,
                    path: Vec::new(),
                    path_wire_bytes: 0,
                    output_wire_bytes: 0,
                },
            )
        })
        .collect();
    let mut impacted = Vec::new();
    let mut truncated = false;
    let mut budget_truncated = false;
    let mut output_path_records = 0usize;
    let mut output_wire_bytes = 0usize;

    for distance in 1..=max_depth {
        let mut candidates: BTreeMap<ImpactNodeId, BestPath> = BTreeMap::new();
        let mut candidate_path_records = 0usize;
        let mut candidate_wire_bytes = 0usize;
        let remaining_nodes = max_nodes.saturating_sub(impacted.len());
        let remaining_records = budget.max_path_records.saturating_sub(output_path_records);
        let remaining_bytes = budget.max_output_bytes.saturating_sub(output_wire_bytes);

        for (node, state) in &frontier {
            let mut steps = Vec::new();
            if matches!(direction, ImpactDirection::Callees | ImpactDirection::Both)
                && let Some(found) = forward.get(node)
            {
                steps.extend(found.iter().cloned());
            }
            if matches!(direction, ImpactDirection::Callers | ImpactDirection::Both)
                && let Some(found) = reverse.get(node)
            {
                steps.extend(found.iter().cloned());
            }
            steps.sort();
            steps.dedup();

            for step in steps {
                if visited.contains(&step.neighbor) {
                    continue;
                }
                let mut path = state.path.clone();
                let path_wire_bytes = state
                    .path_wire_bytes
                    .saturating_add(impact_edge_wire_upper_bound(&step.evidence));
                path.push(step.evidence);
                let candidate = BestPath {
                    distance,
                    output_wire_bytes: 128usize
                        .saturating_add(impact_node_wire_upper_bound(&step.neighbor))
                        .saturating_add(path_wire_bytes),
                    path,
                    path_wire_bytes,
                };
                let candidate_node = step.neighbor;
                match candidates.get_mut(&candidate_node) {
                    Some(existing) if candidate.path < existing.path => {
                        candidate_path_records =
                            candidate_path_records.saturating_sub(existing.path.len());
                        candidate_wire_bytes =
                            candidate_wire_bytes.saturating_sub(existing.output_wire_bytes);
                        candidate_path_records =
                            candidate_path_records.saturating_add(candidate.path.len());
                        candidate_wire_bytes =
                            candidate_wire_bytes.saturating_add(candidate.output_wire_bytes);
                        *existing = candidate;
                    }
                    Some(_) => {}
                    None => {
                        candidate_path_records =
                            candidate_path_records.saturating_add(candidate.path.len());
                        candidate_wire_bytes =
                            candidate_wire_bytes.saturating_add(candidate.output_wire_bytes);
                        candidates.insert(candidate_node, candidate);
                    }
                }

                while candidates.len() > remaining_nodes {
                    remove_largest_candidate(
                        &mut candidates,
                        &mut candidate_path_records,
                        &mut candidate_wire_bytes,
                    );
                    truncated = true;
                }
                while candidate_path_records > remaining_records
                    || candidate_wire_bytes > remaining_bytes
                {
                    if !remove_largest_candidate(
                        &mut candidates,
                        &mut candidate_path_records,
                        &mut candidate_wire_bytes,
                    ) {
                        break;
                    }
                    budget_truncated = true;
                }
            }
        }

        if candidates.is_empty() {
            break;
        }

        output_path_records = output_path_records.saturating_add(candidate_path_records);
        output_wire_bytes = output_wire_bytes.saturating_add(candidate_wire_bytes);
        frontier.clear();
        for (node, state) in candidates {
            visited.insert(node.clone());
            frontier.insert(node.clone(), state.clone());
            impacted.push(ImpactedNode {
                node,
                distance: state.distance,
                score: CALL_DEPTH_DECAY.powi(state.distance as i32),
                path: state.path,
            });
        }
        if truncated || budget_truncated {
            break;
        }
    }

    (impacted, truncated, budget_truncated)
}

fn remove_largest_candidate(
    candidates: &mut BTreeMap<ImpactNodeId, BestPath>,
    path_records: &mut usize,
    wire_bytes: &mut usize,
) -> bool {
    let Some(largest) = candidates.keys().next_back().cloned() else {
        return false;
    };
    let Some(removed) = candidates.remove(&largest) else {
        return false;
    };
    *path_records = (*path_records).saturating_sub(removed.path.len());
    *wire_bytes = (*wire_bytes).saturating_sub(removed.output_wire_bytes);
    true
}

fn compare_impacted_nodes(left: &ImpactedNode, right: &ImpactedNode) -> Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.distance.cmp(&right.distance))
        .then_with(|| left.node.cmp(&right.node))
        .then_with(|| left.path.cmp(&right.path))
}

fn aggregate_files(nodes: &[ImpactedNode]) -> Vec<ImpactedFile> {
    let mut files: BTreeMap<(String, String), (usize, f64, BTreeSet<(String, u32)>)> =
        BTreeMap::new();
    for impacted in nodes {
        let entry = files
            .entry((impacted.node.root.clone(), impacted.node.file.clone()))
            .or_insert_with(|| (impacted.distance, impacted.score, BTreeSet::new()));
        entry.0 = entry.0.min(impacted.distance);
        entry.1 = entry.1.max(impacted.score);
        entry
            .2
            .insert((impacted.node.symbol.clone(), impacted.node.line));
    }
    let mut output: Vec<ImpactedFile> = files
        .into_iter()
        .map(
            |((root, file), (nearest_distance, max_score, symbols))| ImpactedFile {
                root,
                file,
                nearest_distance,
                max_score,
                impacted_symbols: symbols.len(),
            },
        )
        .collect();
    output.sort_by(|left, right| {
        right
            .max_score
            .total_cmp(&left.max_score)
            .then_with(|| left.nearest_distance.cmp(&right.nearest_distance))
            .then_with(|| left.file.cmp(&right.file))
    });
    output
}

fn normalize_repo_relative_path(input: &str) -> Option<String> {
    let value = input.trim().replace('\\', "/");
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with("//")
        || value.as_bytes().get(1) == Some(&b':')
    {
        return None;
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::graph::CodeEdge;
    use crate::code_map::persist::{open, persist_edges, persist_map};
    use crate::code_map::walker::RepoMapBuilder;
    use tempfile::{TempDir, tempdir};

    struct Fixture {
        _repo: TempDir,
        _db: TempDir,
        conn: Connection,
        root: String,
    }

    fn fixture(files: &[(&str, &str)], edges: Vec<CodeEdge>) -> Fixture {
        let repo = tempdir().unwrap();
        for (path, source) in files {
            let absolute = repo.path().join(path);
            if let Some(parent) = absolute.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(absolute, source).unwrap();
        }
        let map = RepoMapBuilder::new(repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let root = map.root.clone();
        let db = tempdir().unwrap();
        let mut conn = open(&db.path().join("code_map.db")).unwrap();
        persist_map(&mut conn, &map).unwrap();
        persist_edges(&mut conn, &root, &edges).unwrap();
        Fixture {
            _repo: repo,
            _db: db,
            conn,
            root,
        }
    }

    fn calls(file: &str, from: &str, to: &str) -> CodeEdge {
        CodeEdge {
            from_file: file.into(),
            from_symbol: from.into(),
            to_name: to.into(),
            kind: EdgeKind::Calls,
        }
    }

    fn node(file: impl Into<String>, symbol: impl Into<String>, line: u32) -> ImpactNodeId {
        ImpactNodeId {
            root: "/repo".into(),
            file: file.into(),
            symbol: symbol.into(),
            line,
            kind: "function".into(),
        }
    }

    #[test]
    fn cycles_and_diamonds_are_deterministic_without_duplicate_nodes() {
        let fixture = fixture(
            &[
                ("a.rs", "fn a() {}\n"),
                ("b.rs", "fn b() {}\n"),
                ("c.rs", "fn c() {}\n"),
                ("d.rs", "fn d() {}\n"),
            ],
            vec![
                calls("a.rs", "a", "b"),
                calls("a.rs", "a", "c"),
                calls("b.rs", "b", "d"),
                calls("c.rs", "c", "d"),
                calls("d.rs", "d", "a"),
            ],
        );
        let options = ImpactOptions {
            direction: ImpactDirection::Callers,
            max_depth: 8,
            max_nodes: 50,
            allow_stale: false,
        };

        let first = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("d.rs", "d")],
            options,
        )
        .unwrap();
        let second = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("d.rs", "d")],
            options,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.digest, second.digest);
        let mut digest_payload = first.clone();
        digest_payload.digest.clear();
        assert_eq!(
            first.digest,
            hex::encode(Sha256::digest(serde_json::to_vec(&digest_payload).unwrap()))
        );
        assert_eq!(
            first
                .impacted_nodes
                .iter()
                .map(|node| node.node.symbol.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c", "a"]
        );
        assert_eq!(
            first
                .impacted_nodes
                .iter()
                .map(|node| node.node.symbol.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            first.impacted_nodes.len()
        );
        assert!(!first.truncated);
        assert!(!first.budget_truncated);

        let mut bounded = first.clone();
        bounded.digest.clear();
        let error = finalize_impact_result(bounded, 128).unwrap_err();
        assert!(error.to_string().contains("serialized bytes"));
    }

    #[test]
    fn duplicate_target_names_are_explicit_and_never_traversed() {
        let fixture = fixture(
            &[
                ("a.rs", "fn a() {}\n"),
                ("left.rs", "fn duplicate() {}\n"),
                ("right.rs", "fn duplicate() {}\n"),
            ],
            vec![calls("a.rs", "a", "duplicate")],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions {
                direction: ImpactDirection::Callees,
                ..ImpactOptions::default()
            },
        )
        .unwrap();

        assert!(result.impacted_nodes.is_empty());
        assert_eq!(result.unresolved_edges.len(), 1);
        assert_eq!(
            result.unresolved_edges[0].reason,
            UnresolvedEdgeReason::AmbiguousTarget
        );
        assert_eq!(result.unresolved_edges[0].candidates.len(), 2);
    }

    #[test]
    fn duplicate_source_names_in_one_file_are_explicit_and_never_traversed() {
        let fixture = fixture(
            &[
                ("duplicate.rs", "fn duplicate() {}\nfn duplicate() {}\n"),
                ("target.rs", "fn target() {}\n"),
            ],
            vec![calls("duplicate.rs", "duplicate", "target")],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("target.rs", "target")],
            ImpactOptions::default(),
        )
        .unwrap();

        assert!(result.impacted_nodes.is_empty());
        assert_eq!(result.unresolved_edges.len(), 1);
        assert_eq!(
            result.unresolved_edges[0].reason,
            UnresolvedEdgeReason::AmbiguousSource
        );
        assert_eq!(result.unresolved_edges[0].candidates.len(), 2);
    }

    #[test]
    fn large_duplicate_endpoint_clones_only_bounded_evidence() {
        let source = node("source.rs", "source", 1);
        let by_file_symbol = BTreeMap::from([(
            ("source.rs".to_string(), "source".to_string()),
            vec![source],
        )]);
        let duplicate_candidates = (0..4_096)
            .map(|index| node(format!("duplicates/{index:04}.rs"), "duplicate", 1))
            .collect();
        let by_name = BTreeMap::from([("duplicate".to_string(), duplicate_candidates)]);

        let (resolved, unresolved, evidence_truncated) = resolve_edges(
            vec![calls("source.rs", "source", "duplicate")],
            &by_file_symbol,
            &by_name,
            10,
            MAX_UNRESOLVED_EVIDENCE_BYTES,
            MAX_RESOLVED_EDGE_ALLOCATION_BYTES,
        )
        .unwrap();

        assert!(resolved.is_empty());
        assert!(!evidence_truncated);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].reason, UnresolvedEdgeReason::AmbiguousTarget);
        assert!(unresolved[0].candidates_truncated);
        assert_eq!(unresolved[0].candidates.len(), MAX_ENDPOINT_CANDIDATES);
        assert_eq!(unresolved[0].candidates[0].file, "duplicates/0000.rs");
        assert_eq!(unresolved[0].candidates[15].file, "duplicates/0015.rs");
    }

    #[test]
    fn unresolved_edge_evidence_is_bounded_during_resolution() {
        let source = node("source.rs", "source", 1);
        let by_file_symbol = BTreeMap::from([(
            ("source.rs".to_string(), "source".to_string()),
            vec![source],
        )]);
        let edges = (0..100)
            .map(|index| calls("source.rs", "source", &format!("missing_{index:03}")))
            .collect();

        let (resolved, unresolved, evidence_truncated) = resolve_edges(
            edges,
            &by_file_symbol,
            &BTreeMap::new(),
            3,
            MAX_UNRESOLVED_EVIDENCE_BYTES,
            MAX_RESOLVED_EDGE_ALLOCATION_BYTES,
        )
        .unwrap();

        assert!(resolved.is_empty());
        assert!(evidence_truncated);
        assert_eq!(unresolved.len(), 3);
        assert_eq!(unresolved[0].to_name, "missing_000");
        assert_eq!(unresolved[2].to_name, "missing_002");
    }

    #[test]
    fn preprocessing_counts_fail_closed_before_unbounded_allocation() {
        assert!(
            enforce_preprocessing_count(
                "edge",
                MAX_PREPROCESSING_EDGES as i64,
                MAX_PREPROCESSING_EDGES,
            )
            .is_ok()
        );
        let error = enforce_preprocessing_count(
            "edge",
            MAX_PREPROCESSING_EDGES as i64 + 1,
            MAX_PREPROCESSING_EDGES,
        )
        .unwrap_err();
        assert!(error.to_string().contains("hard ceiling"));
        assert!(enforce_preprocessing_count("symbol", -1, 10).is_err());
    }

    #[test]
    fn preprocessing_text_and_per_row_guards_reject_long_edge_strings() {
        let fixture = fixture(
            &[("a.rs", "fn a() {}\n"), ("b.rs", "fn b() {}\n")],
            vec![calls("a.rs", "a", "b")],
        );
        let long_target = "x".repeat(MAX_SINGLE_IDENTITY_TEXT_BYTES + 1);
        fixture
            .conn
            .execute(
                "UPDATE code_map_edges SET to_name = ?1 WHERE root = ?2",
                rusqlite::params![long_target, &fixture.root],
            )
            .unwrap();

        let aggregate_error =
            enforce_preprocessing_text_bytes(&fixture.conn, &fixture.root, 1_024).unwrap_err();
        assert!(aggregate_error.to_string().contains("text bytes"));

        let row_error = load_edges_for_root_bounded_with_text_limit(
            &fixture.conn,
            &fixture.root,
            10,
            MAX_PREPROCESSING_TEXT_BYTES,
        )
        .unwrap_err();
        assert!(row_error.to_string().contains("per-row ceiling"));
    }

    #[test]
    fn resolved_edge_retention_budget_fails_before_adjacency_amplification() {
        let source = node("source.rs", "source", 1);
        let target = node("target.rs", "target", 1);
        let by_file_symbol = BTreeMap::from([(
            ("source.rs".to_string(), "source".to_string()),
            vec![source.clone()],
        )]);
        let by_name = BTreeMap::from([("target".to_string(), vec![target.clone()])]);
        let edge = ResolvedEdge {
            caller: source,
            callee: target,
        };
        let required = resolved_edge_allocation_upper_bound(&edge);

        let error = resolve_edges(
            vec![calls("source.rs", "source", "target")],
            &by_file_symbol,
            &by_name,
            10,
            MAX_UNRESOLVED_EVIDENCE_BYTES,
            required.saturating_sub(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("resolved-edge graph requires"));
    }

    #[test]
    fn unresolved_evidence_byte_budget_is_typed_and_deterministic() {
        let source = node("source.rs", "source", 1);
        let by_file_symbol = BTreeMap::from([(
            ("source.rs".to_string(), "source".to_string()),
            vec![source],
        )]);
        let edges = (0..4)
            .map(|index| {
                calls(
                    "source.rs",
                    "source",
                    &format!("missing_{index}_{}", "x".repeat(128)),
                )
            })
            .collect();

        let (resolved, unresolved, truncated) = resolve_edges(
            edges,
            &by_file_symbol,
            &BTreeMap::new(),
            10,
            1_024,
            MAX_RESOLVED_EDGE_ALLOCATION_BYTES,
        )
        .unwrap();
        assert!(resolved.is_empty());
        assert!(truncated);
        assert!(unresolved.len() < 4);
        let retained_bytes = unresolved
            .iter()
            .map(unresolved_edge_wire_upper_bound)
            .fold(0usize, usize::saturating_add);
        assert!(retained_bytes <= 1_024);
    }

    #[test]
    fn traversal_path_budget_bounds_candidates_during_construction() {
        let a = node("a.rs", "a", 1);
        let b = node("b.rs", "b", 1);
        let c = node("c.rs", "c", 1);
        let d = node("d.rs", "d", 1);
        let e = node("e.rs", "e", 1);
        let resolved = BTreeSet::from([
            ResolvedEdge {
                caller: a.clone(),
                callee: b,
            },
            ResolvedEdge {
                caller: node("b.rs", "b", 1),
                callee: c,
            },
            ResolvedEdge {
                caller: node("c.rs", "c", 1),
                callee: d,
            },
            ResolvedEdge {
                caller: node("d.rs", "d", 1),
                callee: e,
            },
        ]);
        let (forward, reverse) = build_adjacency(&resolved);
        let (impacted, node_truncated, budget_truncated) = traverse_with_budget(
            &BTreeSet::from([a]),
            &forward,
            &reverse,
            ImpactDirection::Callees,
            10,
            10,
            TraversalBudget {
                max_path_records: 3,
                max_output_bytes: usize::MAX,
            },
        );

        assert!(!node_truncated);
        assert!(budget_truncated);
        assert_eq!(impacted.len(), 2);
        assert_eq!(
            impacted.iter().map(|item| item.path.len()).sum::<usize>(),
            3
        );

        let source = node("source.rs", "source", 1);
        let target = node("target.rs", "target", 1);
        let one_edge = ResolvedEdge {
            caller: source.clone(),
            callee: target.clone(),
        };
        let (forward, reverse) = build_adjacency(&BTreeSet::from([one_edge.clone()]));
        let one_step_bytes = 128usize
            .saturating_add(impact_node_wire_upper_bound(&target))
            .saturating_add(impact_edge_wire_upper_bound(&ImpactEdgeEvidence {
                caller: one_edge.caller,
                callee: one_edge.callee,
                traversal: ImpactDirection::Callees,
            }));
        let (impacted, node_truncated, budget_truncated) = traverse_with_budget(
            &BTreeSet::from([source]),
            &forward,
            &reverse,
            ImpactDirection::Callees,
            1,
            10,
            TraversalBudget {
                max_path_records: 10,
                max_output_bytes: one_step_bytes.saturating_sub(1),
            },
        );
        assert!(impacted.is_empty());
        assert!(!node_truncated);
        assert!(budget_truncated);
    }

    #[test]
    fn unresolved_sources_targets_and_reference_edges_remain_visible() {
        let fixture = fixture(
            &[("a.rs", "fn a() {}\n")],
            vec![
                calls("gone.rs", "gone", "a"),
                calls("a.rs", "a", "missing"),
                CodeEdge {
                    from_file: "a.rs".into(),
                    from_symbol: "a".into(),
                    to_name: "a".into(),
                    kind: EdgeKind::References,
                },
            ],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions::default(),
        )
        .unwrap();

        let reasons = result
            .unresolved_edges
            .iter()
            .map(|edge| edge.reason)
            .collect::<BTreeSet<_>>();
        assert!(reasons.contains(&UnresolvedEdgeReason::MissingSource));
        assert!(reasons.contains(&UnresolvedEdgeReason::MissingTarget));
        assert!(reasons.contains(&UnresolvedEdgeReason::UnsupportedReferenceEdge));
    }

    #[test]
    fn public_result_reports_deterministically_truncated_unresolved_evidence() {
        let fixture = fixture(
            &[("a.rs", "fn a() {}\n")],
            (0..4)
                .map(|index| calls("a.rs", "a", &format!("missing_{index}")))
                .collect(),
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions {
                direction: ImpactDirection::Callees,
                max_nodes: 2,
                ..ImpactOptions::default()
            },
        )
        .unwrap();

        assert!(result.evidence_truncated);
        assert_eq!(result.unresolved_edges.len(), 2);
        assert_eq!(result.unresolved_edges[0].to_name, "missing_0");
        assert_eq!(result.unresolved_edges[1].to_name, "missing_1");
    }

    #[test]
    fn file_seed_expands_declarations_and_mixed_missing_seeds_are_reported() {
        let fixture = fixture(
            &[
                ("changed.rs", "fn first() {}\nfn second() {}\n"),
                ("caller.rs", "fn caller() {}\n"),
            ],
            vec![calls("caller.rs", "caller", "first")],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[
                ImpactSeed::file("./changed.rs"),
                ImpactSeed::symbol("../outside.rs", "nope"),
                ImpactSeed::symbol("missing.rs", "nope"),
            ],
            ImpactOptions::default(),
        )
        .unwrap();

        assert_eq!(result.seed_nodes.len(), 2);
        assert_eq!(result.unresolved_seeds.len(), 2);
        assert_eq!(result.impacted_nodes.len(), 1);
        assert_eq!(result.impacted_nodes[0].node.symbol, "caller");
    }

    #[test]
    fn all_invalid_seeds_fail_closed() {
        let fixture = fixture(&[("a.rs", "fn a() {}\n")], Vec::new());
        let error = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("../outside.rs", "a")],
            ImpactOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no impact seed resolved"));
    }

    #[test]
    fn depth_zero_returns_only_seed_metadata() {
        let fixture = fixture(
            &[("a.rs", "fn a() {}\n"), ("b.rs", "fn b() {}\n")],
            vec![calls("a.rs", "a", "b")],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("b.rs", "b")],
            ImpactOptions {
                max_depth: 0,
                ..ImpactOptions::default()
            },
        )
        .unwrap();
        assert_eq!(result.seed_nodes.len(), 1);
        assert!(result.impacted_nodes.is_empty());
        assert!(!result.truncated);
    }

    #[test]
    fn fanout_respects_hard_node_cap_and_marks_truncation() {
        let fixture = fixture(
            &[
                ("seed.rs", "fn seed() {}\n"),
                ("a.rs", "fn a() {}\n"),
                ("b.rs", "fn b() {}\n"),
                ("c.rs", "fn c() {}\n"),
            ],
            vec![
                calls("a.rs", "a", "seed"),
                calls("b.rs", "b", "seed"),
                calls("c.rs", "c", "seed"),
            ],
        );
        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("seed.rs", "seed")],
            ImpactOptions {
                max_nodes: 2,
                ..ImpactOptions::default()
            },
        )
        .unwrap();
        assert_eq!(result.impacted_nodes.len(), 2);
        assert_eq!(
            result
                .impacted_nodes
                .iter()
                .map(|node| node.node.symbol.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(result.truncated);
    }

    #[test]
    fn stale_index_requires_explicit_override() {
        let fixture = fixture(&[("a.rs", "fn a() {}\n")], Vec::new());
        std::fs::write(fixture._repo.path().join("a.rs"), "fn changed() {}\n").unwrap();

        let error = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("is stale"));

        let result = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions {
                allow_stale: true,
                ..ImpactOptions::default()
            },
        )
        .unwrap();
        assert!(result.stale);
    }

    #[test]
    fn concurrent_disk_edit_cannot_return_stale_false() {
        let fixture = fixture(&[("a.rs", "fn a() {}\n")], Vec::new());
        let source_path = fixture._repo.path().join("a.rs");

        let error = impact_radius_with_final_check(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions::default(),
            move || {
                std::fs::write(source_path, "fn changed_during_analysis() {}\n").unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("files for root"));
        assert!(
            error
                .to_string()
                .contains("changed while impact analysis was running")
        );
    }

    #[test]
    fn reindex_without_edge_rebuild_fails_generation_check() {
        let mut fixture = fixture(&[("a.rs", "fn a() {}\n")], Vec::new());
        let map = RepoMapBuilder::new(fixture._repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        persist_map(&mut fixture.conn, &map).unwrap();

        let error = impact_radius(
            &fixture.conn,
            &fixture.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("graph is not current"));
    }

    #[test]
    fn same_name_in_another_root_never_enters_result() {
        let first = fixture(
            &[("a.rs", "fn a() {}\n"), ("target.rs", "fn target() {}\n")],
            vec![calls("a.rs", "a", "target")],
        );
        let other_repo = tempdir().unwrap();
        std::fs::write(other_repo.path().join("other.rs"), "fn target() {}\n").unwrap();
        let other_map = RepoMapBuilder::new(other_repo.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let mut conn = first.conn;
        persist_map(&mut conn, &other_map).unwrap();
        persist_edges(&mut conn, &other_map.root, &[]).unwrap();

        let result = impact_radius(
            &conn,
            &first.root,
            &[ImpactSeed::symbol("a.rs", "a")],
            ImpactOptions {
                direction: ImpactDirection::Callees,
                ..ImpactOptions::default()
            },
        )
        .unwrap();
        assert_eq!(result.impacted_nodes.len(), 1);
        assert_eq!(result.impacted_nodes[0].node.root, first.root);
        assert_eq!(result.impacted_nodes[0].node.file, "target.rs");
    }
}
