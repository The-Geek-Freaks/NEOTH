//! `wal::views` — derived read-only views over the SQLite tables the
//! WAL indexer maintains (`idx_episode`, `idx_provider`, etc.). The
//! views are pure-SQL projections + grouping helpers — no schema
//! migrations, no writes; safe to call concurrent with the WAL
//! writer + indexer.
//!
//! ## Current views
//!
//! - [`episode`] — 60-min temporal-window grouping over `idx_episode`,
//!   surfaces Hippocampus episode summaries (start/end ts, event
//!   count, dominant event type, mean importance) per
//!   Round-3 v0.4 QU-08.

pub mod episode;

// WAL-VIEWS-SCALE-01 — synthetic long-run scalability bench (test-only).
#[cfg(test)]
mod scale_bench;
