//! K-Repo-Map (Session 14 Pick #13) — repository code-map for the
//! agent context.
//!
//! NEOTH's biggest competitive gap vs Aider / Cursor / Plandex is a
//! structured map of the codebase the operator is working in. Without
//! it, every prompt has to re-discover file structure + symbol
//! positions by stuffing the prompt with raw file dumps. With a
//! pre-computed map, the dispatcher can synthesise a tight
//! "operator's repo: 412 files, 89k LOC, key symbols X/Y/Z in module
//! M" context block + steer the LLM to the relevant files in advance.
//!
//! ## Phase 1 (this pick) — file walker
//!
//! - Walk the operator's project root respecting `.gitignore` /
//!   `.ignore` / `.neothignore` semantics
//! - Classify each file by language (extension-based + shebang fallback)
//! - Count LOC + bytes per file
//! - Emit a structured `RepoMap` the daemon can serialise into JSON
//!   for the operator + ingest into recall for the agent context
//!
//! ## Phase 2 (follow-up) — tree-sitter symbol extraction
//!
//! - Parse each file with a language-specific tree-sitter grammar
//! - Extract function/class/module/method/trait declarations + spans
//! - Resolve cross-file `import` / `use` / `from` references
//! - Build a directed graph (`Symbol → Caller`) for jump-to-definition
//!
//! ## Phase 3 (follow-up) — semantic recall integration
//!
//! - Persist the graph into `~/.neoth/code_map.db` (separate SQLite)
//! - Embed symbol-context blocks into the existing `memory::tiers`
//!   recall path so the LLM auto-pulls relevant files
//! - Incremental refresh on PreEgress / PostProviderCall hooks

pub mod co_change;
pub mod graph;
pub mod ownership;
pub mod persist;
pub mod recall;
pub mod repo_map;
pub mod risk;
pub mod symbols;
pub mod walker;

// Re-exports kept under `allow(unused_imports)` because the CLI
// subcommand currently uses only a subset — future Phase 2/3 picks
// will consume `RepoFile` + `ScanReport` directly.
#[allow(unused_imports)]
pub use persist::{
    CODE_MAP_SCHEMA_VERSION, PersistStats, SymbolHit, load_map, persist_map, search_symbol,
};
#[allow(unused_imports)]
pub use recall::{RelevantFile, relevant_files_for_prompt, render_context_block};
#[allow(unused_imports)]
pub use repo_map::{DEFAULT_TOKEN_BUDGET, RepoMapSummary, build_summary};
#[allow(unused_imports)]
pub use symbols::{Symbol, SymbolKind, extract_symbols};
#[allow(unused_imports)]
pub use walker::{Language, RepoFile, RepoMap, RepoMapBuilder, ScanReport};
