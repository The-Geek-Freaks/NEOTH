//! GOLD-FEAT-03 — NEOTH self-wiki.
//!
//! Renders NEOTH's own design corpus (the `PLAN/` SPEC + design + Chorus docs)
//! into an interlinked Obsidian vault, so the operator can browse the system's
//! architecture as a navigable wiki instead of a flat folder of markdown.
//!
//! Slice 1 (this module): [`sources`] discovery + [`renderer`] page/index
//! layout + [`writer`] plan/dry-run/write, surfaced via
//! `neoth obsidian wiki-build [--dry-run] [--ingest]`. The groundtruth ingest
//! pass IS shipped (`ingest_sources`, wired live via `--ingest`); only the
//! background rebuild cron + `SelfWikiConfig` remain deferred (those need a
//! WAL event byte).

pub mod ingest;
pub mod renderer;
pub mod sources;
pub mod writer;

pub use ingest::{IngestStats, WIKI_SCOPE, ingest_sources};
pub use renderer::{INDEX_SLUG, render_index, render_page};
pub use sources::{SourceCategory, WikiSource, discover_sources};
pub use writer::{WikiBuildPlan, WikiBuildStats, build_wiki, plan_wiki, write_plan};
