//! Phase-3 migration registry — V10-06 GA blocker foundation.
//!
//! Per `PLAN/RUNBOOK_phase3_cutover.md`, the Phase-3 cutover (Day 61-90)
//! migrates 12 named Jarvis memory stores into the NEOTH WAL + tier
//! views. The migration ships as a separate `neoth-migrate` binary
//! (see `PLAN/RUNBOOK_phase3_cutover.md` Day 63) so a release build of
//! `neothd` doesn't carry the LanceDB / pulldown-cmark / git2 weight.
//!
//! This module is the **registry** the migrator + the dry-run reader +
//! `neoth doctor --explain migrate` all consult. It encodes the 12
//! store names + paths + expected row counts as a single static table
//! so:
//!
//!   1. The migrator can iterate stores in a known order.
//!   2. `neoth doctor` can warn when a store path exists but is empty
//!      (operator forgot to point `~/.openclaw` at the right home).
//!   3. The Phase-3 goldset eval harness can assert "every store was
//!      consulted at least once" by name.
//!
//! Reservation only — the actual migrator (`neoth-migrate` bin) is the
//! Phase-3 deliverable. Today this module exposes the schema; future
//! work adds the readers + writers.

use serde::{Deserialize, Serialize};

/// One row in the Jarvis-store registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JarvisStore {
    /// Operator-readable name. Matches the column in the runbook table.
    pub name: &'static str,
    /// Path template — `~` expands to the operator's home at runtime.
    /// May contain `**/*.md` glob patterns; the migrator resolves them
    /// with the `walkdir` crate (added in Phase-3 dep block).
    pub path_template: &'static str,
    /// One-line operator-readable description of the store's content.
    pub kind: StoreKind,
    /// Best-effort row-count expectation from the runbook ("~1k files",
    /// "1014 files", ...). Used by the dry-run reporter to flag
    /// "operator pointed us at the wrong home" before the migrator
    /// commits anything to the WAL.
    pub expected_hint: &'static str,
}

/// Backing format for a Jarvis store. Drives which reader the
/// Phase-3 migrator dispatches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StoreKind {
    /// Markdown files on disk. Reader: `pulldown_cmark`.
    Markdown,
    /// JSON / NDJSON files. Reader: `serde_json` streaming.
    Json,
    /// Apache Arrow / LanceDB table. Reader: `lance` (Phase-3 dep).
    LanceArrow,
    /// SQLite database file. Reader: `rusqlite` (already in tree).
    Sqlite,
    /// Git working tree. Reader: `git2` (Phase-3 dep).
    GitTree,
    /// FAISS-style flat-vector binary. Reader: hand-rolled (qmd format).
    FaissFlat,
}

/// The 12 stores per `RUNBOOK_phase3_cutover.md` Day 62 table.
///
/// Order matches the runbook so a Day-62 dry-run report renders in the
/// same sequence the operator reads the spec. The migrator iterates
/// this list, hands each entry to the kind-keyed reader, and writes
/// the extracted events into the WAL.
pub const JARVIS_STORES: &[JarvisStore] = &[
    JarvisStore {
        name: "obsidian_vault",
        path_template: "/mnt/obsidian/Jarvis/**/*.md",
        kind: StoreKind::Markdown,
        expected_hint: "~1k files",
    },
    JarvisStore {
        name: "smart_connections",
        path_template: ".smart-env/multi/*.ajson",
        kind: StoreKind::Json,
        expected_hint: "1014 files",
    },
    JarvisStore {
        name: "hippocampus_core_md",
        path_template: "~/.openclaw/workspace/HIPPOCAMPUS_CORE.md",
        kind: StoreKind::Markdown,
        expected_hint: "1 file",
    },
    JarvisStore {
        name: "hippocampus_index_json",
        path_template: "~/.openclaw/workspace/memory/index.json",
        kind: StoreKind::Json,
        expected_hint: "rows",
    },
    JarvisStore {
        name: "hippo_turbo_vectors",
        path_template: "~/.openclaw/workspace/memory/hippo-turbo-vectors.json",
        kind: StoreKind::Json,
        expected_hint: "JSON array",
    },
    JarvisStore {
        name: "lancedb_pro",
        path_template: "~/.openclaw/memory/lancedb-pro",
        kind: StoreKind::LanceArrow,
        expected_hint: "Arrow table",
    },
    JarvisStore {
        name: "lancedb_pro_plugin",
        path_template: "~/.openclaw/plugins/memory-lancedb-pro",
        kind: StoreKind::LanceArrow,
        expected_hint: "Arrow table",
    },
    JarvisStore {
        name: "qmd",
        path_template: "~/.config/qmd/",
        kind: StoreKind::FaissFlat,
        expected_hint: "FAISS-style + bun-bin",
    },
    JarvisStore {
        name: "openclaw_session_md",
        path_template: "~/.openclaw/workspace/memory/*.md",
        kind: StoreKind::Markdown,
        expected_hint: "session files",
    },
    JarvisStore {
        name: "context_mode_fts5",
        path_template: "~/.context-mode/",
        kind: StoreKind::Sqlite,
        expected_hint: "SQLite",
    },
    JarvisStore {
        name: "cq_commons",
        path_template: "~/.cq/local.db",
        kind: StoreKind::Sqlite,
        expected_hint: "SQLite",
    },
    JarvisStore {
        name: "github_backup",
        path_template: "~/github-backup/",
        kind: StoreKind::GitTree,
        expected_hint: "git working tree",
    },
];

/// Lookup helper for `neoth doctor --explain migrate-<name>` style
/// surfaces. Linear scan; the table has 12 entries so the overhead is
/// invisible vs. parsing the runbook.
pub fn store_by_name(name: &str) -> Option<&'static JarvisStore> {
    JARVIS_STORES.iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_exactly_twelve_stores() {
        // The runbook says 12. Pin the count so a future "let's just
        // add one more" lands as a deliberate spec amendment, not as a
        // silent drift.
        assert_eq!(JARVIS_STORES.len(), 12);
    }

    #[test]
    fn every_store_has_a_unique_name() {
        let mut names: Vec<&str> = JARVIS_STORES.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let unique_len = {
            let mut dedup = names.clone();
            dedup.dedup();
            dedup.len()
        };
        assert_eq!(
            names.len(),
            unique_len,
            "duplicate store names break the migrator's idempotency"
        );
    }

    #[test]
    fn every_store_kind_is_reachable_by_name_lookup() {
        // Every entry must round-trip through `store_by_name`. If the
        // helper drifts off the underlying iterator we want to know.
        for s in JARVIS_STORES {
            let back = store_by_name(s.name).expect("store_by_name miss");
            assert_eq!(back, s);
        }
    }

    #[test]
    fn store_by_name_returns_none_for_unknown() {
        assert!(store_by_name("not_a_real_store").is_none());
    }

    #[test]
    fn store_kinds_cover_every_reader_the_runbook_calls_out() {
        // The runbook names six readers (Markdown / Json / LanceArrow
        // / Sqlite / GitTree / FaissFlat). Every reader must have at
        // least one store using it — otherwise the Phase-3 dep block
        // pulls in a crate (lance / git2) we never invoke.
        let kinds: std::collections::HashSet<StoreKind> =
            JARVIS_STORES.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&StoreKind::Markdown));
        assert!(kinds.contains(&StoreKind::Json));
        assert!(kinds.contains(&StoreKind::LanceArrow));
        assert!(kinds.contains(&StoreKind::Sqlite));
        assert!(kinds.contains(&StoreKind::GitTree));
        assert!(kinds.contains(&StoreKind::FaissFlat));
    }

    #[test]
    fn store_serialises_to_json_with_expected_keys() {
        // JarvisStore holds `&'static str` fields so it serialises but
        // doesn't round-trip directly into itself (the deserialized
        // strings would need to outlive `'static`). The migrator
        // serializes for the dry-run report; verify the wire shape
        // names the four operator-facing keys.
        let s = &JARVIS_STORES[0];
        let json = serde_json::to_string(s).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"path_template\""));
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"expected_hint\""));
    }
}
