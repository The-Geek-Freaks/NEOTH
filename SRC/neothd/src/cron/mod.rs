//! Cron scheduler — Phase 11b per `memory/neoth-research-synthesis.md`.
//!
//! Operator defines recurring jobs in `~/.neoth/jobs.yaml`. The daemon
//! (`neoth serve`) spawns a scheduler task on startup that ticks every 30s,
//! finds jobs whose next-run-time has arrived, and dispatches them to the
//! runner. Each fire writes WAL events 0x40 (FIRED) → 0x41 (SUCCESS) or 0x42
//! (FAILED). No system cron daemon involved — NEOTH is self-contained.
//!
//! YAML schema (kept deliberately small for v1):
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
//!     delivery:
//!       channel: telegram         # destination comes from channel_routing.yaml
//! ```
//!
//! Out of scope for v1 (deferred to 11c / later):
//! - `interval:` schedule (e.g. every 30 min) — only `cron:` for now.
//! - Per-job model overrides — uses freedom.yaml's configured provider.
//! - Capability scoping like Jarvis (`exec`, `read`, `write`) — that comes
//!   with the plugin SDK in Phase 17+.

pub mod briefing_prompt;
pub mod error_retrospective;
pub mod guidance;
pub mod quality_gate;
pub mod runner;
pub mod scheduler;
pub mod schema;

pub use schema::JobsFile;
