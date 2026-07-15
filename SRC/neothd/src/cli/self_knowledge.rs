//! Native, read-only access to NEOTH's verified release self-knowledge.
//!
//! The command never invokes Graphify or Python. It only reads an installed
//! snapshot after [`VerifiedReleaseSnapshot`] has verified the closed manifest,
//! every payload hash, and the release identity. Operator overlays remain a
//! separate, explicitly labelled corpus and are never executed or applied.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::OutputFormat;
use crate::wiki::release_snapshot::{
    OPERATOR_NOTES_DIR, RELEASE_KNOWLEDGE_DIR, REVIEWED_SELF_IMPROVE_DIR,
    SELF_IMPROVE_PROPOSALS_DIR, USER_OVERLAYS_DIR, VerifiedReleaseSnapshot,
};

const GRAPH_FILE: &str = "graph.json";
const MAX_GRAPH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_GRAPH_NODES: usize = 500_000;
const MAX_GRAPH_EDGES: usize = 2_000_000;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_QUERY_BYTES: usize = 512;
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 50;
const MAX_NEIGHBORS_PER_HIT: usize = 20;
const MAX_OVERLAY_ENTRIES: usize = 10_000;
const MAX_OVERLAY_FILES: usize = 1_000;
const MAX_OVERLAY_FILE_BYTES: u64 = 1024 * 1024;
const MAX_OVERLAY_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OVERLAY_DEPTH: usize = 16;

#[derive(Args, Debug)]
pub struct SelfKnowledgeArgs {
    #[command(subcommand)]
    pub action: SelfKnowledgeAction,
}

#[derive(Subcommand, Debug)]
pub enum SelfKnowledgeAction {
    /// Verify and describe the installed release self-knowledge snapshot.
    Status,
    /// Verify an archive snapshot without materializing it or opening NEOTH_HOME.
    Verify {
        /// Exact self-knowledge directory extracted from a release archive.
        #[arg(long, value_name = "PATH")]
        snapshot: PathBuf,
    },
    /// Search the verified release graph and persistent Markdown overlays.
    Query {
        /// Plain-text search. Ranking is deterministic and local-only.
        #[arg(value_name = "TEXT")]
        text: String,
        /// Maximum combined graph/overlay results (1..=50).
        #[arg(long, default_value_t = DEFAULT_LIMIT, value_parser = parse_limit)]
        limit: usize,
    },
}

#[derive(Debug, Serialize)]
struct StatusReport {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graphify_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graphify_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graphify_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wiki_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obsidian_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overlays_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    materialized_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    materialized_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    self_wiki_enabled: Option<bool>,
}

#[derive(Debug)]
struct SnapshotPaths {
    wiki: PathBuf,
    obsidian: PathBuf,
    overlays: PathBuf,
    self_wiki_enabled: bool,
    materialized_state: &'static str,
    materialized_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphDocument {
    #[serde(default)]
    directed: bool,
    nodes: Vec<GraphNode>,
    #[serde(alias = "edges")]
    links: Vec<GraphEdge>,
}

#[derive(Debug, Deserialize)]
struct GraphNode {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    file_type: Option<String>,
    #[serde(default)]
    source_file: Option<String>,
    #[serde(default)]
    source_location: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GraphEdge {
    source: String,
    target: String,
    #[serde(default = "default_relation")]
    relation: String,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    source_file: Option<String>,
    #[serde(default)]
    source_location: Option<String>,
}

#[derive(Debug)]
struct GraphData {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    node_by_id: HashMap<String, usize>,
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes = self.bytes.saturating_add(read as u64);
        Ok(read)
    }
}

#[derive(Debug)]
struct OverlayDocument {
    relative_path: String,
    text: String,
    kind: OverlayKind,
    review_state: OverlayReviewState,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OverlayKind {
    OperatorNote,
    SelfImprove,
    Other,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OverlayReviewState {
    Attested,
    Reviewed,
    Proposed,
    Unclassified,
}

impl OverlayReviewState {
    const fn provenance(self) -> &'static str {
        match self {
            Self::Attested => "operator_overlay",
            Self::Reviewed => "reviewed_self_improve",
            Self::Proposed => "self_improve_proposal",
            Self::Unclassified => "unclassified_overlay",
        }
    }
}

#[derive(Debug)]
enum CandidateKind {
    Graph(usize),
    Overlay(usize),
}

#[derive(Debug)]
struct Candidate {
    score: u32,
    stable_key: String,
    kind: CandidateKind,
}

#[derive(Debug, Serialize)]
struct QueryReport {
    state: &'static str,
    version: String,
    source_head: String,
    query: String,
    limit: usize,
    total_matches: usize,
    graph_matches: usize,
    overlay_matches: usize,
    graph_nodes_scanned: usize,
    graph_edges_scanned: usize,
    overlay_files_scanned: usize,
    overlays_path: String,
    results: Vec<QueryHit>,
}

#[derive(Debug, Serialize)]
struct QueryHit {
    provenance: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay_kind: Option<OverlayKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_state: Option<OverlayReviewState>,
    score: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excerpt: Option<String>,
    neighbors_total: usize,
    neighbors_truncated: bool,
    neighbors: Vec<QueryNeighbor>,
}

#[derive(Clone, Debug, Serialize)]
struct QueryNeighbor {
    direction: &'static str,
    relation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_source_location: Option<String>,
}

pub fn run_self_knowledge(args: SelfKnowledgeArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        SelfKnowledgeAction::Status => run_status(output),
        SelfKnowledgeAction::Verify { snapshot } => run_verify(&snapshot, output),
        SelfKnowledgeAction::Query { text, limit } => run_query(&text, limit, output),
    }
}

fn run_verify(path: &Path, output: OutputFormat) -> Result<()> {
    let snapshot = match VerifiedReleaseSnapshot::open(path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            render_status(&invalid_status(&error), output)?;
            return Err(error).with_context(|| {
                format!(
                    "release self-knowledge preflight failed: {}",
                    path.display()
                )
            });
        }
    };
    if let Err(error) = load_graph(&snapshot)
        .context("preflight native self-knowledge query")
        .and_then(|_| {
            snapshot
                .validate_recall_payload()
                .context("preflight native self-knowledge recall ingest")
        })
    {
        render_status(&invalid_status(&error), output)?;
        return Err(error).with_context(|| {
            format!(
                "release self-knowledge runtime preflight failed: {}",
                path.display()
            )
        });
    }
    render_status(&verified_status(&snapshot, None), output)
}

fn run_status(output: OutputFormat) -> Result<()> {
    let snapshot = match VerifiedReleaseSnapshot::discover() {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            render_status(
                &StatusReport {
                    state: "absent",
                    error: Some(
                        "no installed release self-knowledge snapshot was found".to_string(),
                    ),
                    version: None,
                    source_head: None,
                    graphify_version: None,
                    graphify_backend: None,
                    graphify_model: None,
                    nodes: None,
                    edges: None,
                    installed_root: None,
                    wiki_path: None,
                    obsidian_path: None,
                    overlays_path: None,
                    materialized_state: None,
                    materialized_error: None,
                    self_wiki_enabled: None,
                },
                output,
            )?;
            return Ok(());
        }
        Err(error) => {
            let report = invalid_status(&error);
            render_status(&report, output)?;
            return Err(error).context("installed release self-knowledge is invalid");
        }
    };

    let paths = match resolve_snapshot_paths(&snapshot) {
        Ok(paths) => paths,
        Err(error) => {
            let mut report = verified_status(&snapshot, None);
            report.materialized_state = Some("invalid");
            report.materialized_error = Some(error.to_string());
            render_status(&report, output)?;
            return Err(error).context("resolve self-knowledge materialization paths");
        }
    };
    let report = verified_status(&snapshot, Some(&paths));
    let materialized_error = paths.materialized_error.clone();
    render_status(&report, output)?;
    if let Some(error) = materialized_error {
        anyhow::bail!("materialized release self-knowledge is invalid: {error}");
    }
    Ok(())
}

fn run_query(text: &str, limit: usize, output: OutputFormat) -> Result<()> {
    let query = QueryTerms::new(text)?;
    if !(1..=MAX_LIMIT).contains(&limit) {
        anyhow::bail!("--limit must be between 1 and {MAX_LIMIT}");
    }
    let snapshot = VerifiedReleaseSnapshot::discover()?
        .ok_or_else(|| anyhow::anyhow!("no installed release self-knowledge snapshot was found"))?;
    let paths = resolve_snapshot_paths(&snapshot)?;
    if let Some(error) = &paths.materialized_error {
        anyhow::bail!("materialized release self-knowledge is invalid: {error}");
    }
    let graph = load_graph(&snapshot)?;
    let overlays = load_overlays(&paths.overlays)?;
    let report = query_graph_and_overlays(&snapshot, &paths, &graph, &overlays, &query, limit);
    render_query(&report, output)
}

fn invalid_status(error: &anyhow::Error) -> StatusReport {
    StatusReport {
        state: "invalid",
        error: Some(error.to_string()),
        version: None,
        source_head: None,
        graphify_version: None,
        graphify_backend: None,
        graphify_model: None,
        nodes: None,
        edges: None,
        installed_root: None,
        wiki_path: None,
        obsidian_path: None,
        overlays_path: None,
        materialized_state: None,
        materialized_error: None,
        self_wiki_enabled: None,
    }
}

fn verified_status(
    snapshot: &VerifiedReleaseSnapshot,
    paths: Option<&SnapshotPaths>,
) -> StatusReport {
    let manifest = snapshot.manifest();
    StatusReport {
        state: "verified",
        error: None,
        version: Some(manifest.release_version.clone()),
        source_head: Some(manifest.source_head.clone()),
        graphify_version: Some(manifest.graphify_version.clone()),
        graphify_backend: Some(manifest.graphify_backend.clone()),
        graphify_model: Some(manifest.graphify_model.clone()),
        nodes: Some(manifest.node_count),
        edges: Some(manifest.edge_count),
        installed_root: Some(path_text(snapshot.root())),
        wiki_path: paths.map(|paths| path_text(&paths.wiki)),
        obsidian_path: paths.map(|paths| path_text(&paths.obsidian)),
        overlays_path: paths.map(|paths| path_text(&paths.overlays)),
        materialized_state: paths.map(|paths| paths.materialized_state),
        materialized_error: paths.and_then(|paths| paths.materialized_error.clone()),
        self_wiki_enabled: paths.map(|paths| paths.self_wiki_enabled),
    }
}

fn resolve_snapshot_paths(snapshot: &VerifiedReleaseSnapshot) -> Result<SnapshotPaths> {
    let config = crate::config::FreedomConfig::load_from_default_path_or_default()
        .context("load freedom.yaml for self-wiki paths")?;
    let subdir = PathBuf::from(&config.self_wiki.subdir);
    crate::cli::obsidian::validate_subdir(&subdir).context("validate self-wiki subdirectory")?;
    let vault = config
        .self_wiki
        .vault
        .clone()
        .unwrap_or_else(crate::cli::obsidian::default_vault_path);
    let wiki_root = vault.join(subdir);
    let manifest = snapshot.manifest();
    if !manifest
        .release_version
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+'))
    {
        anyhow::bail!("release version is unsafe for a materialization path");
    }
    let baseline = wiki_root.join(RELEASE_KNOWLEDGE_DIR).join(format!(
        "{}-{}",
        manifest.release_version,
        &manifest.source_head[..12]
    ));
    let overlays = wiki_root.join(USER_OVERLAYS_DIR);
    let wiki = baseline.join("wiki");
    let obsidian = baseline.join("obsidian");
    let (materialized_state, materialized_error) = match baseline.try_exists() {
        Ok(false) => ("absent", None),
        Ok(true) => match VerifiedReleaseSnapshot::open(&baseline) {
            Ok(installed) if installed.manifest().payload_sha256 == manifest.payload_sha256 => {
                ("verified", None)
            }
            Ok(_) => (
                "invalid",
                Some("materialized baseline identity collides with different bytes".to_string()),
            ),
            Err(error) => ("invalid", Some(error.to_string())),
        },
        Err(error) => ("invalid", Some(error.to_string())),
    };
    Ok(SnapshotPaths {
        wiki,
        obsidian,
        overlays,
        self_wiki_enabled: config.self_wiki.enabled,
        materialized_state,
        materialized_error,
    })
}

fn load_graph(snapshot: &VerifiedReleaseSnapshot) -> Result<GraphData> {
    let manifest = snapshot.manifest();
    let entry = manifest
        .files
        .iter()
        .find(|entry| entry.path == GRAPH_FILE)
        .ok_or_else(|| anyhow::anyhow!("verified snapshot has no graph.json"))?;
    if entry.bytes == 0 || entry.bytes > MAX_GRAPH_BYTES {
        anyhow::bail!(
            "graph.json is {} bytes; native query accepts 1..={MAX_GRAPH_BYTES} bytes",
            entry.bytes
        );
    }
    let mut reader = HashingReader {
        inner: File::open(snapshot.root().join(GRAPH_FILE))
            .context("open verified graph.json")?
            .take(entry.bytes + 1),
        hasher: Sha256::new(),
        bytes: 0,
    };
    let document: GraphDocument = serde_json::from_reader(BufReader::new(&mut reader))
        .context("parse verified graph.json within the 256 MiB byte ceiling")?;
    if reader.bytes != entry.bytes || hex::encode(reader.hasher.finalize()) != entry.sha256 {
        anyhow::bail!("graph.json changed after snapshot verification");
    }
    validate_graph(document, manifest.node_count, manifest.edge_count)
}

fn validate_graph(
    document: GraphDocument,
    expected_nodes: u64,
    expected_edges: u64,
) -> Result<GraphData> {
    if !document.directed {
        anyhow::bail!("release graph is not marked directed");
    }
    if document.nodes.is_empty() || document.nodes.len() > MAX_GRAPH_NODES {
        anyhow::bail!("release graph node count is outside 1..={MAX_GRAPH_NODES}");
    }
    if document.links.is_empty() || document.links.len() > MAX_GRAPH_EDGES {
        anyhow::bail!("release graph edge count is outside 1..={MAX_GRAPH_EDGES}");
    }
    if u64::try_from(document.nodes.len())? != expected_nodes
        || u64::try_from(document.links.len())? != expected_edges
    {
        anyhow::bail!("manifest graph counters disagree with graph.json");
    }

    let mut node_by_id = HashMap::with_capacity(document.nodes.len());
    for (index, node) in document.nodes.iter().enumerate() {
        validate_field("node id", &node.id)?;
        if node.id.trim().is_empty() || node_by_id.insert(node.id.clone(), index).is_some() {
            anyhow::bail!("release graph contains an empty or duplicate node id");
        }
        for (name, value) in [
            ("node label", node.label.as_deref()),
            ("node file_type", node.file_type.as_deref()),
            ("node source_file", node.source_file.as_deref()),
            ("node source_location", node.source_location.as_deref()),
            ("node description", node.description.as_deref()),
            ("node summary", node.summary.as_deref()),
        ] {
            if let Some(value) = value {
                validate_field(name, value)?;
            }
        }
        for (key, value) in &node.metadata {
            validate_field("node metadata key", key)?;
            if let Some(value) = value.as_str() {
                validate_field("node metadata value", value)?;
            }
        }
    }
    for edge in &document.links {
        for (name, value) in [
            ("edge source", Some(edge.source.as_str())),
            ("edge target", Some(edge.target.as_str())),
            ("edge relation", Some(edge.relation.as_str())),
            ("edge confidence", edge.confidence.as_deref()),
            ("edge source_file", edge.source_file.as_deref()),
            ("edge source_location", edge.source_location.as_deref()),
        ] {
            if let Some(value) = value {
                validate_field(name, value)?;
            }
        }
        if !node_by_id.contains_key(&edge.source) || !node_by_id.contains_key(&edge.target) {
            anyhow::bail!("release graph contains an edge with a missing endpoint");
        }
    }
    Ok(GraphData {
        nodes: document.nodes,
        edges: document.links,
        node_by_id,
    })
}

fn load_overlays(root: &Path) -> Result<Vec<OverlayDocument>> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("inspect self-knowledge overlays"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("self-knowledge overlays root is not a regular directory");
    }
    let canonical_root = fs::canonicalize(root).context("canonicalize self-knowledge overlays")?;
    let mut scan = OverlayScan {
        root,
        canonical_root,
        visited: 0,
        total_bytes: 0,
        documents: Vec::new(),
    };
    scan.visit(root, 0)?;
    scan.documents
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(scan.documents)
}

struct OverlayScan<'a> {
    root: &'a Path,
    canonical_root: PathBuf,
    visited: usize,
    total_bytes: u64,
    documents: Vec<OverlayDocument>,
}

impl OverlayScan<'_> {
    fn visit(&mut self, current: &Path, depth: usize) -> Result<()> {
        if depth > MAX_OVERLAY_DEPTH {
            anyhow::bail!("self-knowledge overlays exceed the {MAX_OVERLAY_DEPTH}-level depth cap");
        }
        let mut entries = fs::read_dir(current)
            .with_context(|| {
                format!(
                    "read self-knowledge overlay directory {}",
                    current.display()
                )
            })?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            self.visited += 1;
            if self.visited > MAX_OVERLAY_ENTRIES {
                anyhow::bail!("self-knowledge overlays exceed the {MAX_OVERLAY_ENTRIES}-entry cap");
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "symlink is forbidden in self-knowledge overlays: {}",
                    path.display()
                );
            }
            let canonical = fs::canonicalize(&path)?;
            if !canonical.starts_with(&self.canonical_root) {
                anyhow::bail!(
                    "self-knowledge overlay path escapes its root: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                self.visit(&path, depth + 1)?;
                continue;
            }
            if !metadata.is_file() {
                anyhow::bail!(
                    "non-regular entry in self-knowledge overlays: {}",
                    path.display()
                );
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_none_or(|ext| !ext.eq_ignore_ascii_case("md"))
            {
                continue;
            }
            if self.documents.len() >= MAX_OVERLAY_FILES {
                anyhow::bail!(
                    "self-knowledge overlays exceed the {MAX_OVERLAY_FILES}-Markdown-file cap"
                );
            }
            if metadata.len() > MAX_OVERLAY_FILE_BYTES {
                anyhow::bail!(
                    "self-knowledge overlay exceeds the 1 MiB file cap: {}",
                    path.display()
                );
            }
            let (text, actual_bytes) = read_utf8_bounded(&path, MAX_OVERLAY_FILE_BYTES)?;
            self.total_bytes = self
                .total_bytes
                .checked_add(actual_bytes)
                .ok_or_else(|| anyhow::anyhow!("self-knowledge overlay byte count overflow"))?;
            if self.total_bytes > MAX_OVERLAY_TOTAL_BYTES {
                anyhow::bail!("self-knowledge overlays exceed the 16 MiB total cap");
            }
            let relative_path = path
                .strip_prefix(self.root)
                .context("self-knowledge overlay escaped its root")?
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let (kind, review_state) = classify_overlay(&relative_path);
            self.documents.push(OverlayDocument {
                relative_path,
                text,
                kind,
                review_state,
            });
        }
        Ok(())
    }
}

fn classify_overlay(relative_path: &str) -> (OverlayKind, OverlayReviewState) {
    match relative_path.split('/').next().unwrap_or_default() {
        OPERATOR_NOTES_DIR => (OverlayKind::OperatorNote, OverlayReviewState::Attested),
        REVIEWED_SELF_IMPROVE_DIR => (OverlayKind::SelfImprove, OverlayReviewState::Reviewed),
        SELF_IMPROVE_PROPOSALS_DIR => (OverlayKind::SelfImprove, OverlayReviewState::Proposed),
        _ => (OverlayKind::Other, OverlayReviewState::Unclassified),
    }
}

fn read_utf8_bounded(path: &Path, max_bytes: u64) -> Result<(String, u64)> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open self-knowledge overlay {}", path.display()))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read self-knowledge overlay {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!(
            "self-knowledge overlay exceeds the {max_bytes}-byte cap: {}",
            path.display()
        );
    }
    let length = bytes.len() as u64;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("overlay is not UTF-8 Markdown: {}", path.display()))?;
    Ok((text, length))
}

struct QueryTerms {
    original: String,
    normalized: String,
    tokens: Vec<String>,
}

impl QueryTerms {
    fn new(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_QUERY_BYTES {
            anyhow::bail!("query must contain 1..={MAX_QUERY_BYTES} UTF-8 bytes");
        }
        let normalized = trimmed.to_lowercase();
        let tokens = normalized
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            anyhow::bail!("query must contain at least one letter or number");
        }
        Ok(Self {
            original: trimmed.to_string(),
            normalized,
            tokens,
        })
    }
}

fn query_graph_and_overlays(
    snapshot: &VerifiedReleaseSnapshot,
    paths: &SnapshotPaths,
    graph: &GraphData,
    overlays: &[OverlayDocument],
    query: &QueryTerms,
    limit: usize,
) -> QueryReport {
    let mut candidates = Vec::new();
    let mut graph_matches = 0_usize;
    for (index, node) in graph.nodes.iter().enumerate() {
        let score = score_node(node, query);
        if score > 0 {
            graph_matches += 1;
            candidates.push(Candidate {
                score,
                stable_key: format!("0:{}", node.id.to_lowercase()),
                kind: CandidateKind::Graph(index),
            });
        }
    }
    let mut overlay_matches = 0_usize;
    for (index, document) in overlays.iter().enumerate() {
        let score = score_overlay(document, query);
        if score > 0 {
            overlay_matches += 1;
            candidates.push(Candidate {
                score,
                stable_key: format!("1:{}", document.relative_path.to_lowercase()),
                kind: CandidateKind::Overlay(index),
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.stable_key.cmp(&right.stable_key))
    });
    candidates.truncate(limit);

    let selected_ids = candidates
        .iter()
        .filter_map(|candidate| match &candidate.kind {
            CandidateKind::Graph(index) => Some(graph.nodes[*index].id.clone()),
            CandidateKind::Overlay(_) => None,
        })
        .collect::<BTreeSet<_>>();
    let neighbors = collect_neighbors(graph, &selected_ids);
    let results = candidates
        .into_iter()
        .map(|candidate| match candidate.kind {
            CandidateKind::Graph(index) => {
                let node = &graph.nodes[index];
                let (total, rows) = neighbors.get(&node.id).cloned().unwrap_or_default();
                QueryHit {
                    provenance: "release_graph",
                    overlay_kind: None,
                    review_state: None,
                    score: candidate.score,
                    id: Some(node.id.clone()),
                    label: node.label.clone().unwrap_or_else(|| node.id.clone()),
                    file_type: node.file_type.clone(),
                    source_file: node.source_file.clone(),
                    source_location: node.source_location.clone(),
                    excerpt: node.description.clone().or_else(|| node.summary.clone()),
                    neighbors_total: total,
                    neighbors_truncated: total > rows.len(),
                    neighbors: rows,
                }
            }
            CandidateKind::Overlay(index) => {
                let document = &overlays[index];
                QueryHit {
                    provenance: document.review_state.provenance(),
                    overlay_kind: Some(document.kind),
                    review_state: Some(document.review_state),
                    score: candidate.score,
                    id: None,
                    label: document.relative_path.clone(),
                    file_type: Some("markdown".to_string()),
                    source_file: Some(path_text(&paths.overlays.join(&document.relative_path))),
                    source_location: None,
                    excerpt: Some(overlay_excerpt(&document.text, query)),
                    neighbors_total: 0,
                    neighbors_truncated: false,
                    neighbors: Vec::new(),
                }
            }
        })
        .collect();
    QueryReport {
        state: "verified",
        version: snapshot.manifest().release_version.clone(),
        source_head: snapshot.manifest().source_head.clone(),
        query: query.original.clone(),
        limit,
        total_matches: graph_matches + overlay_matches,
        graph_matches,
        overlay_matches,
        graph_nodes_scanned: graph.nodes.len(),
        graph_edges_scanned: graph.edges.len(),
        overlay_files_scanned: overlays.len(),
        overlays_path: path_text(&paths.overlays),
        results,
    }
}

fn score_node(node: &GraphNode, query: &QueryTerms) -> u32 {
    let mut score = 0_u32;
    score = score.saturating_add(score_text(
        node.label.as_deref().unwrap_or(&node.id),
        query,
        1_200,
        500,
        80,
    ));
    score = score.saturating_add(score_text(&node.id, query, 900, 300, 45));
    for value in [
        node.source_file.as_deref(),
        node.source_location.as_deref(),
        node.file_type.as_deref(),
        node.description.as_deref(),
        node.summary.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        score = score.saturating_add(score_text(value, query, 300, 120, 18));
    }
    for value in node.metadata.values().filter_map(serde_json::Value::as_str) {
        score = score.saturating_add(score_text(value, query, 100, 40, 8));
    }
    score
}

fn score_overlay(document: &OverlayDocument, query: &QueryTerms) -> u32 {
    score_text(&document.relative_path, query, 1_100, 450, 70).saturating_add(score_text(
        &document.text,
        query,
        350,
        180,
        16,
    ))
}

fn score_text(value: &str, query: &QueryTerms, exact: u32, phrase: u32, per_token: u32) -> u32 {
    let normalized = value.to_lowercase();
    let mut score = 0_u32;
    if normalized == query.normalized {
        score = score.saturating_add(exact);
    } else if normalized.contains(&query.normalized) {
        score = score.saturating_add(phrase);
    }
    for token in &query.tokens {
        if normalized.contains(token) {
            score = score.saturating_add(per_token);
        }
    }
    score
}

fn collect_neighbors(
    graph: &GraphData,
    selected_ids: &BTreeSet<String>,
) -> BTreeMap<String, (usize, Vec<QueryNeighbor>)> {
    let mut all = BTreeMap::<String, Vec<QueryNeighbor>>::new();
    for id in selected_ids {
        all.insert(id.clone(), Vec::new());
    }
    for edge in &graph.edges {
        if selected_ids.contains(&edge.source) {
            let node = &graph.nodes[graph.node_by_id[&edge.target]];
            all.get_mut(&edge.source)
                .expect("selected id exists")
                .push(neighbor(
                    edge,
                    node,
                    if edge.source == edge.target {
                        "self"
                    } else {
                        "outgoing"
                    },
                ));
        }
        if edge.target != edge.source && selected_ids.contains(&edge.target) {
            let node = &graph.nodes[graph.node_by_id[&edge.source]];
            all.get_mut(&edge.target)
                .expect("selected id exists")
                .push(neighbor(edge, node, "incoming"));
        }
    }
    all.into_iter()
        .map(|(id, mut rows)| {
            rows.sort_by(|left, right| {
                left.direction
                    .cmp(right.direction)
                    .then_with(|| left.relation.cmp(&right.relation))
                    .then_with(|| left.label.to_lowercase().cmp(&right.label.to_lowercase()))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let total = rows.len();
            rows.truncate(MAX_NEIGHBORS_PER_HIT);
            (id, (total, rows))
        })
        .collect()
}

fn neighbor(edge: &GraphEdge, node: &GraphNode, direction: &'static str) -> QueryNeighbor {
    QueryNeighbor {
        direction,
        relation: edge.relation.clone(),
        confidence: edge.confidence.clone(),
        id: node.id.clone(),
        label: node.label.clone().unwrap_or_else(|| node.id.clone()),
        source_file: node.source_file.clone(),
        source_location: node.source_location.clone(),
        edge_source_file: edge.source_file.clone(),
        edge_source_location: edge.source_location.clone(),
    }
}

fn overlay_excerpt(text: &str, query: &QueryTerms) -> String {
    let line = text
        .lines()
        .find(|line| {
            let normalized = line.to_lowercase();
            normalized.contains(&query.normalized)
                || query.tokens.iter().any(|token| normalized.contains(token))
        })
        .or_else(|| text.lines().find(|line| !line.trim().is_empty()))
        .unwrap_or("")
        .trim();
    truncate_chars(line, 280)
}

fn truncate_chars(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(limit).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn render_status(report: &StatusReport, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(report)?);
        }
        OutputFormat::Table => {
            println!("State               {}", report.state);
            if let Some(error) = &report.error {
                println!("Error               {error}");
            }
            for (label, value) in [
                ("Version", report.version.as_deref()),
                ("Source HEAD", report.source_head.as_deref()),
                ("Graphify", report.graphify_version.as_deref()),
                ("Graphify backend", report.graphify_backend.as_deref()),
                ("Graphify model", report.graphify_model.as_deref()),
                ("Installed root", report.installed_root.as_deref()),
                ("Wiki path", report.wiki_path.as_deref()),
                ("Obsidian path", report.obsidian_path.as_deref()),
                ("User overlays", report.overlays_path.as_deref()),
                ("Materialized", report.materialized_state),
            ] {
                if let Some(value) = value {
                    println!("{label:<19} {value}");
                }
            }
            if let Some(nodes) = report.nodes {
                println!("Nodes               {nodes}");
            }
            if let Some(edges) = report.edges {
                println!("Edges               {edges}");
            }
            if let Some(enabled) = report.self_wiki_enabled {
                println!("Self-wiki enabled   {enabled}");
            }
            if let Some(error) = &report.materialized_error {
                println!("Materialized error  {error}");
            }
        }
    }
    Ok(())
}

fn render_query(report: &QueryReport, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Jsonl => {
            for hit in &report.results {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "self_knowledge_hit",
                        "version": &report.version,
                        "source_head": &report.source_head,
                        "query": &report.query,
                        "result": hit,
                    })
                );
            }
            println!(
                "{}",
                serde_json::json!({
                    "type": "self_knowledge_summary",
                    "state": report.state,
                    "total_matches": report.total_matches,
                    "returned": report.results.len(),
                    "graph_matches": report.graph_matches,
                    "overlay_matches": report.overlay_matches,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "Verified NEOTH {} self-knowledge ({}, {} nodes / {} edges)",
                report.version,
                report.source_head,
                report.graph_nodes_scanned,
                report.graph_edges_scanned
            );
            println!(
                "{} matches ({} graph, {} user overlay); returning {}",
                report.total_matches,
                report.graph_matches,
                report.overlay_matches,
                report.results.len()
            );
            for (index, hit) in report.results.iter().enumerate() {
                println!(
                    "{}. [{} · score {}] {}",
                    index + 1,
                    hit.provenance,
                    hit.score,
                    hit.label
                );
                if let Some(source) = &hit.source_file {
                    let location = hit
                        .source_location
                        .as_deref()
                        .map(|location| format!(":{location}"))
                        .unwrap_or_default();
                    println!("   source: {source}{location}");
                }
                if let Some(excerpt) = &hit.excerpt {
                    println!("   {excerpt}");
                }
                for neighbor in &hit.neighbors {
                    println!(
                        "   -> [{} · {}] {} ({})",
                        neighbor.direction, neighbor.relation, neighbor.label, neighbor.id
                    );
                }
                if hit.neighbors_truncated {
                    println!(
                        "   ... {} more direct neighbors",
                        hit.neighbors_total - hit.neighbors.len()
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_field(name: &str, value: &str) -> Result<()> {
    if value.len() > MAX_FIELD_BYTES {
        anyhow::bail!("{name} exceeds the {MAX_FIELD_BYTES}-byte field cap");
    }
    Ok(())
}

fn default_relation() -> String {
    "related".to_string()
}

fn parse_limit(raw: &str) -> std::result::Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("limit must be an integer between 1 and {MAX_LIMIT}"))?;
    if (1..=MAX_LIMIT).contains(&value) {
        Ok(value)
    } else {
        Err(format!("limit must be between 1 and {MAX_LIMIT}"))
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn graph_fixture() -> GraphData {
        validate_graph(
            serde_json::from_value(serde_json::json!({
                "directed": true,
                "nodes": [
                    {
                        "id": "dispatch_loop",
                        "label": "dispatch_loop()",
                        "file_type": "code",
                        "source_file": "SRC/neothd/src/mcp/dispatch_loop.rs",
                        "source_location": "L42"
                    },
                    {
                        "id": "provider_call",
                        "label": "ProviderCallAuthorizer",
                        "file_type": "code",
                        "source_file": "SRC/neothd/src/providers/authorization.rs",
                        "source_location": "L10"
                    }
                ],
                "links": [{
                    "source": "dispatch_loop",
                    "target": "provider_call",
                    "relation": "calls",
                    "confidence": "EXTRACTED",
                    "source_file": "SRC/neothd/src/mcp/dispatch_loop.rs",
                    "source_location": "L55"
                }]
            }))
            .unwrap(),
            2,
            1,
        )
        .unwrap()
    }

    #[test]
    fn cli_parses_status_and_bounded_query() {
        let cli = crate::cli::Cli::try_parse_from(["neoth", "self-knowledge", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::SelfKnowledge(SelfKnowledgeArgs {
                action: SelfKnowledgeAction::Status
            })
        ));
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "self-knowledge",
            "verify",
            "--snapshot",
            "release/self-knowledge",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::SelfKnowledge(SelfKnowledgeArgs {
                action: SelfKnowledgeAction::Verify { .. }
            })
        ));
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "self-knowledge",
            "query",
            "provider",
            "--limit",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            crate::cli::Commands::SelfKnowledge(SelfKnowledgeArgs {
                action: SelfKnowledgeAction::Query { limit: 3, .. }
            })
        ));
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "self-knowledge",
                "query",
                "x",
                "--limit",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn ranking_and_directed_neighbors_are_deterministic() {
        let graph = graph_fixture();
        let query = QueryTerms::new("provider").unwrap();
        assert!(score_node(&graph.nodes[1], &query) > score_node(&graph.nodes[0], &query));
        let ids = BTreeSet::from(["provider_call".to_string()]);
        let neighbors = collect_neighbors(&graph, &ids);
        let rows = &neighbors["provider_call"].1;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].direction, "incoming");
        assert_eq!(rows[0].id, "dispatch_loop");
        assert_eq!(rows[0].edge_source_location.as_deref(), Some("L55"));
    }

    #[test]
    fn graph_validation_rejects_counter_drift_and_dangling_edges() {
        let value = serde_json::json!({
            "directed": true,
            "nodes": [{"id":"a"}],
            "links": [{"source":"a","target":"missing","relation":"calls"}]
        });
        let document: GraphDocument = serde_json::from_value(value.clone()).unwrap();
        assert!(validate_graph(document, 1, 1).is_err());
        let document: GraphDocument = serde_json::from_value(value).unwrap();
        assert!(validate_graph(document, 2, 1).is_err());
    }

    #[test]
    fn overlays_are_bounded_read_only_and_labelled() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Architecture.md"),
            "# Architecture\nProvider authorization happens before dispatch.\n",
        )
        .unwrap();
        fs::write(dir.path().join("ignored.png"), b"not markdown").unwrap();
        let documents = load_overlays(dir.path()).unwrap();
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0].relative_path, "Architecture.md");
        let query = QueryTerms::new("authorization").unwrap();
        assert!(score_overlay(&documents[0], &query) > 0);
        assert!(overlay_excerpt(&documents[0].text, &query).contains("authorization"));

        for directory in [
            OPERATOR_NOTES_DIR,
            REVIEWED_SELF_IMPROVE_DIR,
            SELF_IMPROVE_PROPOSALS_DIR,
        ] {
            fs::create_dir(dir.path().join(directory)).unwrap();
            fs::write(
                dir.path().join(directory).join("State.md"),
                "# State\nProvider authorization stays explicit.\n",
            )
            .unwrap();
        }
        let documents = load_overlays(dir.path()).unwrap();
        for (directory, expected_state) in [
            (OPERATOR_NOTES_DIR, OverlayReviewState::Attested),
            (REVIEWED_SELF_IMPROVE_DIR, OverlayReviewState::Reviewed),
            (SELF_IMPROVE_PROPOSALS_DIR, OverlayReviewState::Proposed),
        ] {
            let document = documents
                .iter()
                .find(|document| document.relative_path.starts_with(directory))
                .unwrap();
            assert_eq!(document.review_state, expected_state);
            assert_ne!(document.review_state.provenance(), "user_overlay");
        }
        assert_eq!(documents[0].review_state, OverlayReviewState::Unclassified);
    }
}
