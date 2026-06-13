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
pub mod diff;
pub mod dimension;
pub mod drift;
pub mod embeddings;
pub mod foreign_import;
pub mod forget;
pub mod gc;
pub mod gc_task;
pub mod groundtruth;
pub mod hindsight;
pub mod indexer;
/// GOLD-ADAPT-MEM-06 — knowledge-graph layer (typed entities + weighted
/// relations + bounded BFS neighbour expansion). `neoth recall --graph`.
pub mod entities;
/// GOLD-ADAPT-MEM-06 — `[RELEVANT FACTS]` block builder from graph neighbours.
pub mod context_inject;
/// GOLD-ADAPT-MEM-07 — Hebbian co-access association graph between memory rows
/// (episodes). Co-recalled memories reinforce a symmetric weighted link;
/// `neoth recall --assoc <event_id>` queries the 1-hop neighbourhood.
pub mod assoc_graph;
/// GOLD-FEAT-07 — LOWKEY moral-core loader (operator behavioural directives
/// injected at enrichment position 0). `neoth moral-core {list,preview,doctor}`.
pub mod moral_core;
pub mod infra_scan;
pub mod ingress;
pub mod integrity;
pub mod migrations;
pub mod operator_md;
pub mod pre_decay_export;
/// GOLD-ADAPT-MEM-09 — recall decision gating (skip / single / multi tier).
pub mod recall_gate;
pub mod region_router;
pub mod channel_weights;
pub mod regions;
pub mod routing_weights;
pub mod session_search;
pub mod snapshot_refresh;
pub mod store;
pub mod tiers;
pub mod transfer_bundle;
pub mod views;

/// Escape SQLite `LIKE` wildcards (`\`, `%`, `_`) in an untrusted string
/// so they match literally. ALWAYS pair the bound value with
/// `... LIKE ?n ESCAPE '\'`. Without this, an operator-supplied topic of
/// `%` matches every row — e.g. `neoth memory forget "%"` would wipe the
/// entire memory store, and a `_` would over-match (GOLD-SEC-04 / A-08).
pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod escape_like_tests {
    use super::escape_like;

    #[test]
    fn escapes_wildcards_literally() {
        assert_eq!(escape_like("50%"), "50\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c:\\path"), "c:\\\\path");
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("%"), "\\%");
    }
}
