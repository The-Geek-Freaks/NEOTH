//! Operator-md context loader — Phase 25 R-14.
//!
//! Loads the operator's persistent rules + memory from disk and assembles a
//! single context block that goes at the top of every provider call. Mirrors
//! Claude Code's `CLAUDE.md` hierarchy:
//!
//! ```
//! ~/.neoth/NEOTH.md                — global operator rules (always loaded)
//! <cwd>/NEOTH.md                   — project-specific overrides (if exists)
//! ~/.neoth/rules/index.md          — modular rules index (lists *.md to include)
//! ~/.neoth/rules/*.md              — included via index
//! ~/.neoth/memory/MEMORY.md        — typed memories index (auto-memory pattern)
//! ~/.neoth/memory/<note>.md        — referenced from MEMORY.md
//! ```
//!
//! Assembly order matches the read order above. Missing files are silently
//! skipped — first-time operators have no `NEOTH.md` yet and the daemon must
//! still start.
//!
//! Output: a `Vec<MemoryBlock>` the pipeline turns into a single string for
//! system-prompt injection. Blocks carry source-path metadata so the channel
//! adapter / debug tooling can show provenance.

pub mod loader;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One assembled block of operator context. Sources are kept separate (not
/// pre-joined) so the channel adapter can:
///   - elide redundant blocks at length limits,
///   - print a debug breakdown of "what the model saw",
///   - tag WAL events with the exact rule files that influenced a call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlock {
    /// Source category — used for ordering + length-budget priority.
    pub source: BlockSource,
    /// Path relative to `~/.neoth/` (or the operator's cwd for project blocks).
    pub path: PathBuf,
    /// Raw markdown content. Trimmed but otherwise unprocessed.
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    /// `~/.neoth/NEOTH.md` — global, highest priority.
    Global,
    /// `<cwd>/NEOTH.md` — project-scoped overrides.
    Project,
    /// `~/.neoth/rules/*.md` — modular rules, ordered as listed in `rules/index.md`.
    Rule,
    /// `~/.neoth/memory/*.md` — typed memories, referenced from `memory/MEMORY.md`.
    Memory,
}

/// Total length of all assembled blocks in bytes. Cheap helper for the
/// pipeline's length-budget logic.
pub fn total_bytes(blocks: &[MemoryBlock]) -> usize {
    blocks.iter().map(|b| b.content.len()).sum()
}

/// Render all blocks into a single string ready for system-prompt injection.
/// Each block gets a `## <source>: <path>` header so the model can attribute.
pub fn render(blocks: &[MemoryBlock]) -> String {
    let mut out = String::new();
    for b in blocks {
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        let label = match b.source {
            BlockSource::Global => "global",
            BlockSource::Project => "project",
            BlockSource::Rule => "rule",
            BlockSource::Memory => "memory",
        };
        out.push_str(&format!("## {label}: {}\n", b.path.display()));
        out.push_str(b.content.trim());
    }
    out
}

pub use loader::assemble;
