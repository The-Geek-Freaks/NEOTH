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
pub mod diff;
pub mod diff_git;
// Compose with W43's proposal; that mirror supplies the module source.
pub mod diff_impact;
pub mod enrichment_readiness;
pub mod graph;
pub mod impact;
pub mod imports;
mod incremental;
pub mod lifecycle;
pub mod lifecycle_config;
pub(crate) mod lifecycle_repair;
pub mod lifecycle_watcher;
#[cfg(test)]
mod lifecycle_watcher_tests;
pub mod outline;
pub mod ownership;
pub mod persist;
pub mod recall;
pub mod recall_wire;
pub mod repo_map;
pub mod risk;
pub mod root_identity;
pub mod snapshot;
pub mod symbols;
pub mod test_coverage;
pub mod type_hierarchy;
pub mod walker;

// Re-exports kept under `allow(unused_imports)` because the CLI
// subcommand currently uses only a subset — future Phase 2/3 picks
// will consume `RepoFile` + `ScanReport` directly.
#[allow(unused_imports)]
pub use diff_impact::{
    DiffImpactInput, DiffImpactReceipt, DiffImpactRequest, DiffImpactSeedReceipt,
    DiffImpactSourceDescriptor, analyze_diff_impact,
};
pub use enrichment_readiness::{
    EnrichmentReadiness, inspect as inspect_enrichment_readiness,
    inspect_for_expected_executable as inspect_enrichment_readiness_for_expected_executable,
};
#[allow(unused_imports)]
pub use impact::{
    ImpactDirection, ImpactEdgeEvidence, ImpactNodeId, ImpactOptions, ImpactResult, ImpactSeed,
    ImpactedFile, ImpactedNode, UnresolvedEdge, UnresolvedEdgeEndpoint, UnresolvedEdgeReason,
    UnresolvedSeed, UnresolvedSeedReason, impact_radius, impact_radius_for_diff_seeds,
    impact_radius_for_path,
};
#[allow(unused_imports)]
pub use imports::{
    DEFAULT_MAX_IMPORT_EDGES, DEFAULT_MAX_IMPORT_QUERY_NODES, DEFAULT_MAX_IMPORT_QUERY_TEXT_BYTES,
    ImportDirection, ImportEdge, ImportEntry, ImportGraph,
};
#[allow(unused_imports)]
pub use lifecycle::{
    CodeMapLifecycleReceipt, CodeMapLifecycleState, CodeMapLifecycleStatus, LifecycleCancellation,
    LifecycleGeneration, LifecycleRefreshOptions, RefreshCause, RefreshOutcome, inspect, reconcile,
    refresh, root_identity_sha256,
};
pub use lifecycle_config::{
    CodeMapLifecycleConfigApplyReceipt, CodeMapLifecycleConfigPatch,
    CodeMapLifecycleManagedRootObservation, apply_code_map_lifecycle_config,
    apply_code_map_lifecycle_config_patch,
};
pub use lifecycle_watcher::{
    CodeMapLifecycleRuntimeState, CodeMapLifecycleRuntimeStatus,
    read_active_code_map_lifecycle_status,
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
    AutomaticContextReadiness, RECALL_WIRE_SCHEMA, RecallWireEnvelope, RecallWireHit,
    RecallWireReceipt, RecallWireStatus, RepositoryContextUnavailable,
    inspect_automatic_context_readiness,
};
#[allow(unused_imports)]
pub use repo_map::{DEFAULT_TOKEN_BUDGET, RepoMapSummary, build_summary};
#[allow(unused_imports)]
pub use root_identity::{CanonicalRepoRoot, RootIdentity};
#[allow(unused_imports)]
pub use snapshot::{
    RebuildOptions, RebuildSnapshot, rebuild_snapshot, rebuild_snapshot_excluding,
    stable_source_fingerprint, stable_source_fingerprint_excluding,
};
#[allow(unused_imports)]
pub use symbols::{Symbol, SymbolKind, extract_symbols};
#[allow(unused_imports)]
pub use test_coverage::{
    ImpactTestGapIdentity, ImpactTestGapInputProvenance, ImpactTestGapNodeResult,
    ImpactTestGapOutcome, ImpactTestGapRejection, ImpactTestGapResult, ImpactTestGapWorkBudget,
    ObservedTest, TestCoverageNode, TestCoverageOptions, TestCoverageProvenance,
    TestCoverageResult, TestCoverageUncertainty, test_coverage_for, test_gap_for_impact,
};
#[allow(unused_imports)]
pub use type_hierarchy::{
    TypeEndpoint, TypeHierarchy, TypeHierarchyDirection, TypeHierarchyEdge, TypeHierarchyEntry,
    TypeTraversalBudget,
};
#[allow(unused_imports)]
pub use walker::{Language, RepoFile, RepoMap, RepoMapBuilder, ScanReport};
