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
/// GOLD-ADAPT-MEM-07 — Hebbian co-access association graph between memory rows
/// (episodes). Co-recalled memories reinforce a symmetric weighted link;
/// `neoth recall --assoc <event_id>` queries the 1-hop neighbourhood.
pub mod assoc_graph;
pub mod bulk_text;
pub mod change_bus;
pub mod channel_weights;
/// GOLD-ADAPT-MEM-05 — Pre-compaction backup + persisted counter.
/// Snapshots session state + bumps a counter before any compaction so a
/// bad compaction is recoverable. Wire as a pre-compact hook in the
/// dispatch loop (follow-up — caller is parallel-hot). Standalone +
/// headless-tested.
pub mod compaction_guard;
pub mod consolidate;
/// JV-SELF-02 — AMEM4Rec consolidation sweep. Clusters hot-tier episode
/// embeddings by cosine similarity ≥ threshold (Union-Find), boosts
/// member importance (cap 0.85), and merges mature clusters into
/// `idx_groundtruth`. Pure sync, no WAL; cron wrapper in
/// `daemon::consolidation_sweep_cron` emits `0x9D`/`0x9E`.
pub mod consolidation_sweep;
/// GOLD-ADAPT-MEM-06 — `[RELEVANT FACTS]` block builder from graph neighbours.
pub mod context_inject;
/// GOLD-ADAPT-MEM-02 — contradiction detection + ledger over ground-truth facts.
pub mod contradiction;
pub mod ctx;
pub mod decay_task;
pub mod diff;
pub mod dimension;
pub mod drift;
pub mod embeddings;
/// GOLD-ADAPT-MEM-06 — knowledge-graph layer (typed entities + weighted
/// relations + bounded BFS neighbour expansion). `neoth recall --graph`.
pub mod entities;
/// GOLD-ADAPT-MEMGRAPH-02 — LongMemEval-style memory eval harness.
/// `neoth memory-eval` runs a synthetic recall benchmark against a fresh
/// temp DB and reports precision so CI can detect memory-tuning regressions.
pub mod eval_harness;
pub mod foreign_import;
pub mod forget;
pub mod gc;
pub mod gc_task;
pub mod groundtruth;
pub mod hindsight;
/// GOLD History Onboarding v1: private review journal for historical exports.
/// It is intentionally disconnected from recall and profile learning.
pub mod history_onboarding;
pub mod indexer;
pub mod infra_scan;
pub mod ingress;
pub mod integrity;
pub mod migrations;
/// GOLD-FEAT-07 — LOWKEY moral-core loader (operator behavioural directives
/// injected at enrichment position 0). `neoth moral-core {list,preview,doctor}`.
pub mod moral_core;
/// Open Knowledge Format (OKF) renderer — export knowledge as Obsidian-native
/// markdown concept docs (see `cli::okf`).
pub mod okf;
/// OMI-MULTIMODAL-01 — idempotent, transactional projection of official OMI
/// conversation revisions, aligned segments, media metadata, and action/fact
/// mappings. Raw transcript retention is explicit; purge leaves a tombstone.
pub mod omi;
pub mod operator_md;
/// GOLD-ADAPT-OH-10 — per-person relationship scorer (recency × frequency ×
/// reciprocity × depth, clamped) → proactive surfacing priority. Surfaced via
/// `neoth memory --people`; recorded on every in-scope channel interaction.
pub mod pending_clarifications;
pub mod people;
pub mod pre_decay_export;
/// GOLD-ADAPT-MEM-09 — recall decision gating (skip / single / multi tier).
pub mod recall_gate;
/// GOLD-ADAPT-MEM-03 — parallel recall lanes + RRF late fusion.
pub mod recall_lanes;
pub mod region_router;
pub mod regions;
pub mod routing_weights;
pub mod scorecard;
/// GOLD-ADAPT-JV-MODE-03 — Self-capability awareness map. Indexes every
/// bundled skill, daemon cron, CLI command, and slash command into a
/// structured [`self_wiki::SelfWiki`] the agent can query to reason about
/// and select its own capabilities. Read-only; no I/O.
pub mod self_wiki;
/// GOLD-ADAPT-VIEW-04 — cross-agent session-transcript import (claude-code /
/// codex / gemini → ground-truth candidates). `neoth import session`.
pub mod session_import;
pub mod session_search;
pub mod snapshot_refresh;
pub mod source_weight;
pub mod store;
/// GOLD-ADAPT-SPEAKR-01 — 5-layer prompt composition for summarization
/// (override/append/tag/folder/user/admin/hardcoded) + `{{var}}` substitution.
/// Standalone, no I/O; wired to `freedom.yaml::skills.meeting_summary.prompt_layers`
/// as a follow-up once the ingress summarise path consumes it.
pub mod summarize_prompt;
pub mod tiers;
/// GOLD-LF-P1-08 stages 1–2: the sealed metadata-only payload contract is
/// unit-test compiled until later work deliberately wires an authenticated
/// production producer and reader.
#[cfg(test)]
pub(crate) mod transcript_mining_provenance;
/// GOLD-ADAPT-ODY-26 — raw-turn persistence + FTS5 search with before/after
/// context rows. `neoth recall --transcript <query>` surface.
pub mod transcript_store;
pub mod transfer_bundle;
pub mod views;
pub mod warm_summarize;

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
