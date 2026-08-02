//! Live repository code-map and repo-context subsystem.
//!
//! The ignore-aware, bounded walker records file metadata and optionally
//! extracts declarations with language-specific regexes. A heuristic call
//! graph, git ownership/co-change/risk analysis, and an atomic SQLite snapshot
//! at `~/.neoth/code_map.db` build on that map.
//!
//! Production consumers are operator-visible: `neoth code-map` scans,
//! persists, loads, searches, ranks relevant files, and computes a
//! generation-bound structural impact radius; `neoth chat` can inject a bounded
//! `<repo-context>` block; `neoth code` supplies a compact symbol map to the
//! decomposer; and the in-process codegraph MCP server reads the same persisted
//! data.
//!
//! Current symbol and call-edge extraction is deliberately heuristic, not a
//! tree-sitter AST or a fully resolved cross-language graph. Callers must treat
//! missing edges as unknown, never as proof that no relationship exists.

pub mod co_change;
pub mod graph;
pub mod impact;
pub mod outline;
pub mod ownership;
pub mod persist;
pub mod recall;
pub mod recall_wire;
pub mod repo_map;
pub mod risk;
pub mod root_identity;
pub mod symbols;
pub mod walker;

// Re-exports kept under `allow(unused_imports)` because the CLI
// subcommand currently uses only a subset — future Phase 2/3 picks
// will consume `RepoFile` + `ScanReport` directly.
#[allow(unused_imports)]
pub use impact::{
    ImpactDirection, ImpactEdgeEvidence, ImpactNodeId, ImpactOptions, ImpactResult, ImpactSeed,
    ImpactedFile, ImpactedNode, UnresolvedEdge, UnresolvedEdgeEndpoint, UnresolvedEdgeReason,
    UnresolvedSeed, UnresolvedSeedReason, impact_radius, impact_radius_for_path,
};
#[allow(unused_imports)]
pub use outline::{OutlineEntry, outline_file, outline_source};
#[allow(unused_imports)]
pub use persist::{
    CODE_MAP_SCHEMA_VERSION, PersistStats, SymbolHit, load_map, persist_map, persist_map_and_edges,
    search_symbol,
};
#[allow(unused_imports)]
pub use recall::{
    RecallReceipt, RecallStaleness, RelevantFile, RootGenerationSnapshot,
    recall_receipt_for_prompt, relevant_files_for_prompt, render_context_block,
    resolve_active_root, resolve_active_root_snapshot, sole_persisted_root_snapshot,
};
#[allow(unused_imports)]
pub use recall_wire::{
    RECALL_WIRE_SCHEMA, RecallWireEnvelope, RecallWireHit, RecallWireReceipt, RecallWireStatus,
};
#[allow(unused_imports)]
pub use repo_map::{DEFAULT_TOKEN_BUDGET, RepoMapSummary, build_summary};
#[allow(unused_imports)]
pub use root_identity::{CanonicalRepoRoot, RootIdentity};
#[allow(unused_imports)]
pub use symbols::{Symbol, SymbolKind, extract_symbols};
#[allow(unused_imports)]
pub use walker::{Language, RepoFile, RepoMap, RepoMapBuilder, ScanReport};
