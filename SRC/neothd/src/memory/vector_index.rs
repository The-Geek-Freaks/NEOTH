//! Vector-index abstraction — V10-08 Pick #36 foundation.
//!
//! `memory::embeddings::find_similar` walks `idx_embedding` brute-
//! force today (O(N) cosine dot product). Past ~50k vectors that gets
//! slow enough to surface a once-WARN (Pick #12 telemetry).
//!
//! This module introduces the `VectorIndex` trait so the brute-force
//! walker and a future indexed implementation share one operator-
//! visible API. The trait + brute-force impl ship in Pick #36; the
//! indexed impl (sqlite-vec or hnsw_rs — design decision flagged for
//! Chorus gremium per handoff §7) lands in a follow-up sprint behind
//! the `vector-index` Cargo feature.
//!
//! ## Design decision deferred to Chorus gremium
//!
//! - **sqlite-vec** — C-dep, sqlite-extension-loaded, requires
//!   bundled rusqlite. Pro: zero rewrite of the storage layer.
//!   Contra: NEOTH self-contained rule says no C-deps. Bundling
//!   sqlite-vec means a forked rusqlite or a custom static link.
//! - **hnsw_rs** — pure-Rust HNSW implementation. Pro: matches
//!   self-contained rule. Contra: needs a sidecar index file +
//!   rebuild trigger logic.
//!
//! Foundation is pure-Rust path-friendly: the `IndexedVectorIndex`
//! impl below is a stub that returns `None` for the search call so
//! callers transparently fall back to brute-force until the real
//! indexed engine wires in.

use serde::{Deserialize, Serialize};

/// One hit returned by [`VectorIndex::find_top_k`]. Shape mirrors
/// `memory::embeddings::SimilarHit` so the existing callers don't
/// need to translate field names.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexHit {
    pub id: i64,
    pub source_kind: String,
    pub source_ref: String,
    pub similarity: f32,
    pub created_at: i64,
}

/// What kind of backing engine an index uses. Operator-visible via
/// `neoth doctor --explain vector-index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IndexBackend {
    /// Linear scan of `idx_embedding`. O(N) dot product per query.
    /// Acceptable up to `BRUTE_FORCE_CEILING` (~50k vectors).
    BruteForce,
    /// Future: sqlite-vec virtual-table backed search. Operator
    /// enables via the `vector-index` Cargo feature. Index lives
    /// at `~/.neoth/views.db` alongside the source table.
    SqliteVec,
    /// Future: hnsw_rs pure-Rust HNSW index. Operator enables via
    /// the `vector-index` Cargo feature. Index lives at
    /// `~/.neoth/hnsw.idx` as a sidecar file.
    HnswRs,
}

impl IndexBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BruteForce => "brute_force",
            Self::SqliteVec => "sqlite_vec",
            Self::HnswRs => "hnsw_rs",
        }
    }
}

/// The active backend at runtime. Compile-time choice today; future
/// `freedom.yaml::memory.vector_index.backend` field flips this.
pub const fn active_backend() -> IndexBackend {
    // Pick #36 ships the trait + brute-force only. Indexed
    // backends arrive in the follow-up. The runtime field will
    // override this when the implementation lands.
    IndexBackend::BruteForce
}

/// The contract every backend implements. Stays small in Pick #36 —
/// search is the only operator-hot path; insert + remove come when
/// the indexed impl arrives (today's brute-force walker just rescans
/// the SQL table per query, no separate index state to mutate).
pub trait VectorIndex {
    /// Backend identifier. Used by doctor + WAL audit lines.
    fn backend(&self) -> IndexBackend;

    /// Approximate nearest-neighbour search. `query` MUST be
    /// L2-normalised (the same precondition the brute-force walker
    /// enforces). Returns `top_k` hits sorted descending by cosine
    /// similarity. `None` signals the backend isn't fully wired yet
    /// and the caller should fall back to brute-force.
    fn find_top_k(&self, query: &[f32], top_k: usize) -> Option<Vec<IndexHit>>;
}

/// Brute-force implementation that mirrors `memory::embeddings::find_similar`.
/// Pick #36 ships this as a marker type — the actual scan continues
/// to live in `embeddings.rs` so we don't fork the codepath. Future
/// refactor merges the two when the indexed impl arrives + a
/// "switch backend at runtime" config lands.
#[derive(Clone, Copy, Debug, Default)]
pub struct BruteForceIndex;

impl VectorIndex for BruteForceIndex {
    fn backend(&self) -> IndexBackend {
        IndexBackend::BruteForce
    }

    fn find_top_k(&self, _query: &[f32], _top_k: usize) -> Option<Vec<IndexHit>> {
        // Caller falls back to the existing
        // `memory::embeddings::find_similar` path. Returning `None`
        // here keeps the trait contract honest without duplicating
        // the SQL walk.
        None
    }
}

/// Stub for the future indexed backend. Pick #36 ships the type so
/// downstream consumers can write the match arms today; the actual
/// search impl arrives in the follow-up sprint.
#[derive(Clone, Copy, Debug)]
pub struct IndexedVectorIndex {
    pub backend: IndexBackend,
}

impl IndexedVectorIndex {
    pub const fn new(backend: IndexBackend) -> Self {
        Self { backend }
    }
}

impl VectorIndex for IndexedVectorIndex {
    fn backend(&self) -> IndexBackend {
        self.backend
    }

    fn find_top_k(&self, _query: &[f32], _top_k: usize) -> Option<Vec<IndexHit>> {
        // Not implemented. Caller falls back to brute-force.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_strings_are_stable_snake_case() {
        // Pin every variant — WAL payloads + doctor JSON read these.
        assert_eq!(IndexBackend::BruteForce.as_str(), "brute_force");
        assert_eq!(IndexBackend::SqliteVec.as_str(), "sqlite_vec");
        assert_eq!(IndexBackend::HnswRs.as_str(), "hnsw_rs");
    }

    #[test]
    fn active_backend_is_brute_force_in_pick_36() {
        // The follow-up sprint flips this; for Pick #36 the contract
        // is "trait shipped, brute-force still authoritative".
        assert_eq!(active_backend(), IndexBackend::BruteForce);
    }

    #[test]
    fn brute_force_returns_none_so_caller_falls_back() {
        let idx = BruteForceIndex;
        let hits = idx.find_top_k(&[1.0, 0.0, 0.0], 5);
        assert!(hits.is_none());
    }

    #[test]
    fn indexed_stub_returns_none_until_real_impl_lands() {
        let idx = IndexedVectorIndex::new(IndexBackend::SqliteVec);
        let hits = idx.find_top_k(&[1.0, 0.0, 0.0], 5);
        assert!(hits.is_none());
        assert_eq!(idx.backend(), IndexBackend::SqliteVec);
    }

    #[test]
    fn brute_force_backend_id_matches_active() {
        let idx = BruteForceIndex;
        assert_eq!(idx.backend(), active_backend());
    }

    #[test]
    fn backend_serialises_to_snake_case_via_serde() {
        let json = serde_json::to_string(&IndexBackend::HnswRs).unwrap();
        assert!(json.contains("hnsw_rs"));
    }
}
