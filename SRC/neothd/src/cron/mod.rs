//! Cron scheduler — Phase 11b per `memory/neoth-research-synthesis.md`.
//!
//! Operator defines recurring jobs in `~/.neoth/jobs.yaml`. The daemon
//! (`neoth serve`) spawns a scheduler task on startup that ticks every 30s,
//! finds jobs whose next-run-time has arrived, and dispatches them to the
//! runner. Each fire writes WAL events 0x40 (FIRED) → 0x41 (SUCCESS) or 0x42
//! (FAILED). No system cron daemon involved — NEOTH is self-contained.
//!
//! YAML schema (operator-owned v1 contract):
//!
//! ```yaml
//! version: 1
//! jobs:
//!   - id: morning-tech-news
//!     name: Morning Tech News
//!     enabled: true
//!     schedule:
//!       cron: "0 7 * * *"        # 5-field cron
//!       tz: Europe/Berlin        # optional, defaults to UTC
//!     prompt: |
//!       You are NEOTH's morning news agent. ...
//!     timeout_seconds: 1800
//!     execution:
//!       provider: anthropic_api
//!       model: claude-sonnet-4-5
//!       capabilities: [research]
//!       tools: [web.search]
//!     delivery:
//!       mode: announce
//!       channel: telegram         # destination comes from channel_routing.yaml
//! ```
//!
//! A schedule selects exactly one of `cron`, `every_seconds`, or `at`.
//! Per-job provider/model/profile/thinking/fallback controls and exact MCP
//! server/tool allow-lists cross the same cost, WAL, and permission boundaries
//! as interactive calls. Delivery is tracked separately as queued, delivered,
//! failed, or skipped; a provider result alone never proves channel delivery.

pub mod briefing_prompt;
pub mod error_retrospective;
pub mod guidance;
pub mod quality_gate;
pub mod runner;
pub mod scheduler;
pub mod schema;
pub mod state;

pub use schema::JobsFile;
