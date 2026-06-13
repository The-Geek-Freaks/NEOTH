//! GOLD-FEAT-03 — NEOTH self-wiki.
//!
//! Renders NEOTH's own design corpus (the `PLAN/` SPEC + design + Chorus docs)
//! into an interlinked Obsidian vault, so the operator can browse the system's
//! architecture as a navigable wiki instead of a flat folder of markdown.
//!
//! Slice 1 (this module): [`sources`] discovery + [`renderer`] page/index
//! layout + [`writer`] plan/dry-run/write, surfaced via
//! `neoth obsidian wiki-build [--dry-run]`. Later slices add the
//! groundtruth ingest pass + the background rebuild cron (those need a WAL
//! event byte + `SelfWikiConfig`, deferred to keep slice 1 disjoint).

pub mod ingest;
pub mod renderer;
pub mod sources;
pub mod writer;

pub use ingest::{ingest_sources, IngestStats, WIKI_SCOPE};
pub use renderer::{render_index, render_page, INDEX_SLUG};
pub use sources::{discover_sources, SourceCategory, WikiSource};
pub use writer::{build_wiki, plan_wiki, write_plan, WikiBuildPlan, WikiBuildStats};
