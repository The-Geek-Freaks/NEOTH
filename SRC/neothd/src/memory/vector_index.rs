//! Vector-index abstraction — V10-08 Pick #36 foundation. **SUPERSEDED +
//! UNUSED skeleton — do not build on this.** (GOLD-WIRE-08 honesty pass.)
//!
//! This module shipped a `VectorIndex` trait + stub impls as scaffolding for
//! a future indexed search. That search was then built somewhere else and in
//! a different shape, leaving everything here dead. The production similarity
//! search lives ENTIRELY in [`crate::memory::embeddings`]:
//!   * brute-force [`find_similar`](crate::memory::embeddings::find_similar)
//!     — O(N) cosine scan over `idx_embedding`; and
//!   * the real HNSW index
//!     [`EmbeddingIndex`](crate::memory::embeddings::EmbeddingIndex) — genuine
//!     `hnsw_rs` (`add` / `find_similar_hnsw` / `save` / `load` /
//!     `build_from_sqlite`),
//! dispatched by
//! [`find_similar_dispatch`](crate::memory::embeddings::find_similar_dispatch)
//! and gated on `freedom.yaml::memory.vector_index.backend`
//! (`brute_force` | `hnsw`, GOLD-WIRE-07). The `sqlite-vec` vs `hnsw_rs`
//! design question this module flagged for a gremium was RESOLVED in favour
//! of pure-Rust `hnsw_rs` and implemented there — not here.
//!
//! Nothing constructs or calls the types below — `grep` finds no consumer of
//! `VectorIndex`, `IndexBackend`, `BruteForceIndex`, or `IndexedVectorIndex`
//! outside this file (the runtime backend selector is
//! [`crate::config::VectorBackend`], a separate enum). Both `find_top_k`
//! impls return `None` unconditionally — they were never implemented. The
//! module is retained as a documented dead skeleton; its removal is a
//! deliberate decision tracked under the WS-D dead-code sweep
//! (GOLD-WIRE-12), not this honesty pass.

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

/// Backend tag for this (dead) skeleton's index types. NOT the runtime
/// selector — that is [`crate::config::VectorBackend`]. Nothing reads this
/// enum at runtime (no WAL / doctor / dispatch consumer); it exists only so
/// the unused types below compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IndexBackend {
    /// Linear scan tag. The real O(N) scan is
    /// [`crate::memory::embeddings::find_similar`] (this variant tags the
    /// unused [`BruteForceIndex`] marker only).
    BruteForce,
    /// UNIMPLEMENTED placeholder — there is no sqlite-vec backend anywhere.
    /// The `sqlite-vec`-vs-`hnsw_rs` decision went to `hnsw_rs`, built in
    /// [`crate::memory::embeddings::EmbeddingIndex`]. Nothing constructs this.
    SqliteVec,
    /// UNIMPLEMENTED placeholder IN THIS MODULE. The real HNSW index is
    /// [`crate::memory::embeddings::EmbeddingIndex`] (`hnsw_rs`), reached via
    /// `embeddings::find_similar_dispatch` — not this enum. Nothing
    /// constructs this variant.
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

/// Always returns `BruteForce`. **NOT consulted by the live recall path** —
/// `neoth recall` reads `freedom.yaml::memory.vector_index.backend` into
/// [`crate::config::VectorBackend`] and dispatches through
/// `embeddings::find_similar_dispatch` (GOLD-WIRE-07). This `const fn` exists
/// only so the dead skeleton compiles; no caller exists.
pub const fn active_backend() -> IndexBackend {
    IndexBackend::BruteForce
}

/// The (unused) contract the skeleton's backends implement. No production
/// code depends on this trait — see the module banner.
pub trait VectorIndex {
    /// Backend identifier. (Not read by doctor or WAL — that claim was stale;
    /// nothing consumes this.)
    fn backend(&self) -> IndexBackend;

    /// Approximate nearest-neighbour search. **Both shipped impls return
    /// `None` unconditionally** — neither was ever implemented, and there is
    /// no production caller. The live equivalent is
    /// [`crate::memory::embeddings::find_similar_dispatch`].
    fn find_top_k(&self, query: &[f32], top_k: usize) -> Option<Vec<IndexHit>>;
}

/// Marker type for the brute-force backend. UNUSED — nothing constructs it.
/// The actual O(N) scan is [`crate::memory::embeddings::find_similar`].
#[derive(Clone, Copy, Debug, Default)]
pub struct BruteForceIndex;

impl VectorIndex for BruteForceIndex {
    fn backend(&self) -> IndexBackend {
        IndexBackend::BruteForce
    }

    fn find_top_k(&self, _query: &[f32], _top_k: usize) -> Option<Vec<IndexHit>> {
        // Returns None unconditionally: this marker never carried a search
        // impl. The real scan is `embeddings::find_similar`. No caller exists,
        // so there is no "fallback" — this is simply dead.
        None
    }
}

/// UNIMPLEMENTED stub for an indexed backend. Never wired; superseded by
/// [`crate::memory::embeddings::EmbeddingIndex`] (the real `hnsw_rs` index).
/// Nothing constructs this type.
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
        // Returns None unconditionally — this backend was never implemented.
        // The real HNSW search is
        // `embeddings::EmbeddingIndex::find_similar_hnsw`.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_strings_are_stable_snake_case() {
        // Pin the snake_case tokens for serde stability of the (dead) enum.
        // NOTE: no live WAL/doctor consumer reads these — this only guards
        // the serde wire form if the skeleton is ever revived.
        assert_eq!(IndexBackend::BruteForce.as_str(), "brute_force");
        assert_eq!(IndexBackend::SqliteVec.as_str(), "sqlite_vec");
        assert_eq!(IndexBackend::HnswRs.as_str(), "hnsw_rs");
    }

    #[test]
    fn active_backend_is_always_brute_force() {
        // This is permanent, not a Pick-#36-temporary: `active_backend` is
        // dead (the live selector is `config::VectorBackend`), so it stays
        // pinned to BruteForce.
        assert_eq!(active_backend(), IndexBackend::BruteForce);
    }

    #[test]
    fn brute_force_index_find_top_k_returns_none_unconditionally() {
        // Doc contract: the marker carries no search impl — None for any input.
        let idx = BruteForceIndex;
        assert!(idx.find_top_k(&[1.0, 0.0, 0.0], 5).is_none());
        assert!(idx.find_top_k(&[], 0).is_none());
    }

    #[test]
    fn indexed_stub_find_top_k_returns_none_because_unimplemented() {
        // Doc contract: this stub was never implemented (the real HNSW search
        // is embeddings::EmbeddingIndex) — None for every backend tag + input.
        for backend in [
            IndexBackend::BruteForce,
            IndexBackend::SqliteVec,
            IndexBackend::HnswRs,
        ] {
            let idx = IndexedVectorIndex::new(backend);
            assert!(idx.find_top_k(&[1.0, 0.0, 0.0], 5).is_none());
            assert!(idx.find_top_k(&[0.5; 8], 10).is_none());
            assert_eq!(idx.backend(), backend);
        }
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
