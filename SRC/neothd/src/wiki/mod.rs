//! GOLD-FEAT-03 — NEOTH self-wiki.
//!
//! Renders NEOTH's own design corpus (the `PLAN/` SPEC + design + Chorus docs)
//! into an interlinked Obsidian vault, so the operator can browse the system's
//! architecture as a navigable wiki instead of a flat folder of markdown.
//!
//! Slice 1 (this module): [`sources`] discovery + [`renderer`] page/index
//! layout + [`writer`] plan/dry-run/write, surfaced via
//! `neoth obsidian wiki-build [--dry-run] [--ingest]`. The groundtruth ingest
//! pass IS shipped (`ingest_sources`, wired live via `--ingest`).
//! Slice 3 (GOLD-FEAT-03b): [`capabilities`] renders the in-binary
//! capability map (the release-binary corpus) and
//! `daemon::wiki_build_cron` rebuilds the whole wiki on a schedule
//! (`freedom.yaml::self_wiki`). No WAL frame — the event-type byte space
//! is exhausted; the cron is tracing-audited instead.

pub mod capabilities;
pub mod ingest;
pub mod release_snapshot;
pub mod renderer;
pub mod sources;
pub mod writer;

pub use ingest::{
    GraphifyIngestRevocation, GraphifyIngestScope, IngestStats, WIKI_SCOPE,
    ingest_graphify_generation_for_scope, ingest_sources, revoke_graphify_scope_for_no_ingest,
};
pub(crate) use ingest::{
    ingest_graphify_generation_for_scope_guarded, revoke_graphify_scope_for_no_ingest_guarded,
};
pub use renderer::{INDEX_SLUG, render_index, render_page};
pub use sources::{SourceCategory, WikiSource, discover_sources};
pub use writer::{WikiBuildPlan, WikiBuildStats, build_wiki, plan_wiki, write_plan};
