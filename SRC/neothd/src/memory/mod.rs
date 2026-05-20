//! Memory layer — queryable views over the WAL.
//!
//! The WAL is the source of truth (append-only, durable, tamper-evident).
//! This module materialises it into SQLite views that NEOTH can SELECT
//! against, turning "Neoth knows" from marketing copy into an actual
//! `neoth recall "..."` query.
//!
//! Architecture:
//! - `store.rs` — SQLite connection + schema init + mode-0600/DACL hardening
//! - `indexer.rs` — async task that tails the WAL and INSERTs new frames
//! - `views.rs` — typed row structs for query results
//!
//! Self-contained per hard rule: bundled rusqlite, no system libsqlite3,
//! no external indexer service. Operator gets recall by virtue of running
//! `neoth serve`.

pub mod archive;
pub mod bulk_text;
pub mod consolidate;
pub mod ctx;
pub mod decay_task;
pub mod dimension;
pub mod embeddings;
pub mod foreign_import;
pub mod forget;
pub mod gc;
pub mod gc_task;
pub mod groundtruth;
pub mod indexer;
pub mod infra_scan;
pub mod migrations;
pub mod operator_md;
pub mod routing_weights;
pub mod store;
pub mod tiers;
pub mod vector_index;
pub mod views;
