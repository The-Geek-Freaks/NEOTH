//! Embedding store — schema v6.
//!
//! Persists fixed-size dense vectors (CLIP image embeddings today,
//! potentially audio + text projections later) so recall can do
//! similarity search across modalities.
//!
//! ## Search backends
//!
//! Two complementary search paths are provided:
//!
//! 1. **Brute-force** ([`find_similar`]) — O(N) cosine scan directly over
//!    `idx_embedding`. Acceptable up to [`BRUTE_FORCE_CEILING`] (~50k vectors).
//!    Always available, zero setup, used as fallback.
//!
//! 2. **HNSW** ([`EmbeddingIndex`]) — approximate nearest-neighbour index via
//!    `hnsw_rs`. Built in-memory, persisted via `bincode` to
//!    `<neoth_home>/embeddings.hnsw`. On first boot the index is populated from
//!    existing `idx_embedding` rows ([`EmbeddingIndex::build_from_sqlite`]). Add
//!    vectors after each upsert with [`EmbeddingIndex::add`] then call
//!    [`EmbeddingIndex::save`] on graceful shutdown.
//!
//! Storage layout:
//!   * `embedding BLOB` — `dim × 4` bytes, little-endian f32. L2-norm
//!     **expected** at insert time so similarity is one dot product per
//!     candidate, no division on the hot path.
//!   * `(source_kind, source_ref)` is the natural key — an `(image, path)`
//!     can only ever have one current embedding. New inserts UPSERT,
//!     bumping `created_at`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hnsw_rs::anndists::dist::distances::DistCosine;
use hnsw_rs::hnsw::Hnsw;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Insert (or replace) one embedding row. `embedding` MUST already be
/// L2-normalised — `find_similar` relies on that to skip per-candidate
/// division. Inserting a non-normalised vector silently breaks the
/// distance math, so we validate the norm on debug builds.
pub fn upsert(
    conn: &Connection,
    source_kind: &str,
    source_ref: &str,
    model: &str,
    embedding: &[f32],
) -> Result<i64> {
    debug_assert!(
        is_unit_norm(embedding),
        "embedding must be L2-normalised before upsert"
    );
    let blob = floats_to_blob(embedding);
    let dim = embedding.len() as i64;
    let now = unix_seconds_now();
    conn.execute(
        "INSERT INTO idx_embedding \
            (source_kind, source_ref, model, embedding, dim, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(source_kind, source_ref) DO UPDATE SET \
            model      = excluded.model, \
            embedding  = excluded.embedding, \
            dim        = excluded.dim, \
            created_at = excluded.created_at",
        rusqlite::params![source_kind, source_ref, model, blob, dim, now],
    )
    .context("insert embedding row")?;
    Ok(conn.last_insert_rowid())
}

/// One hit returned by `find_similar`.
#[derive(Clone, Debug, PartialEq)]
pub struct SimilarHit {
    pub id: i64,
    pub source_kind: String,
    pub source_ref: String,
    pub model: String,
    /// Cosine similarity in `[-1.0, 1.0]`. Both query and candidate are
    /// L2-normalised, so the value is a plain dot product.
    pub similarity: f32,
    pub created_at: i64,
}

/// Maximum corpus size at which brute-force cosine remains operator-
/// acceptable on commodity hardware. At ~50k rows × dim=512 the scan
/// stays under 50ms on a 2026-class laptop (one pass through ~100 MiB
/// of f32 + a sort). Beyond this the daemon emits a once-per-process
/// WARN pointing operators at the GA blocker V10-08 (HNSW / sqlite-vec
/// replacement). The brute-force path keeps working — the warn is
/// strictly informational, never a refusal — because the alternative
/// (silently returning slow recall) makes the regression invisible to
/// the operator.
pub const BRUTE_FORCE_CEILING: usize = 50_000;

/// Process-wide once-flag for the BRUTE_FORCE_CEILING WARN. AcqRel
/// compare-and-swap keeps the message at most once per daemon run; a
/// busy recall loop polling 100 queries against a 60k-row corpus
/// surfaces the operator action exactly once, not 100 times.
static BRUTE_FORCE_CEILING_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Brute-force cosine-similarity scan. `query` must be L2-normalised.
/// Walks every row whose `source_kind` matches `kind_filter`
/// (`Some("image")` or `None` for "any kind"), computes the dot
/// product, returns the `top_k` highest. Ties broken by `created_at
/// DESC` so recent material wins.
///
/// Returned hits are sorted by similarity descending. Empty result is
/// valid — the caller decides whether that's a miss or a no-op. Row-
/// level decode errors propagate up (DB corruption / locked WAL)
/// rather than silently producing an empty result set.
///
/// Audit 2026-05-19 (V10-08 GA-blocker prep): when the matched-dim
/// corpus exceeds [`BRUTE_FORCE_CEILING`], emit a one-shot WARN that
/// points the operator at the HNSW / sqlite-vec migration. The scan
/// continues — silent slowness is worse than a noisy hint, and most
/// solo operators stay well under the ceiling for the lifetime of v0.1.
pub fn find_similar(
    conn: &Connection,
    query: &[f32],
    kind_filter: Option<&str>,
    top_k: usize,
) -> Result<Vec<SimilarHit>> {
    debug_assert!(is_unit_norm(query), "query embedding must be L2-normalised");
    if top_k == 0 {
        return Ok(Vec::new());
    }
    let dim = query.len() as i64;
    warn_if_brute_force_ceiling_exceeded(conn, dim, kind_filter);
    let mut stmt = if kind_filter.is_some() {
        conn.prepare(
            "SELECT id, source_kind, source_ref, model, embedding, dim, created_at \
             FROM idx_embedding \
             WHERE dim = ?1 AND source_kind = ?2",
        )?
    } else {
        conn.prepare(
            "SELECT id, source_kind, source_ref, model, embedding, dim, created_at \
             FROM idx_embedding \
             WHERE dim = ?1",
        )?
    };
    let raw_rows: Vec<RawEmbeddingRow> = match kind_filter {
        Some(kind) => stmt
            .query_map(rusqlite::params![dim, kind], decode_raw_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("scan idx_embedding rows (kind-filtered)")?,
        None => stmt
            .query_map(rusqlite::params![dim], decode_raw_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("scan idx_embedding rows")?,
    };
    let rows: Vec<SimilarHit> = raw_rows
        .into_iter()
        .filter_map(|raw| {
            let RawEmbeddingRow {
                id,
                source_kind,
                source_ref,
                model,
                blob,
                created_at,
            } = raw;
            let Some(vec) = blob_to_floats(&blob, query.len()) else {
                // Dim mismatch shouldn't reach here because the SQL
                // already filtered on `dim = ?1`, but log loudly if it
                // ever does — silent skip lost hours of debugging in
                // the past.
                tracing::warn!(
                    id,
                    expected_dim = query.len(),
                    blob_bytes = blob.len(),
                    "idx_embedding row size mismatch; skipped"
                );
                return None;
            };
            Some(SimilarHit {
                id,
                source_kind,
                source_ref,
                model,
                similarity: dot(query, &vec),
                created_at,
            })
        })
        .collect();
    let mut sorted = rows;
    sorted.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.created_at.cmp(&a.created_at))
    });
    sorted.truncate(top_k);
    Ok(sorted)
}

/// GOLD-WIRE-07 — the canonical on-disk path for the HNSW snapshot,
/// `<neoth_home>/embeddings.hnsw`. One source of truth so the recall
/// dispatch, `neoth memory --rebuild-index`, and a future boot-load all
/// resolve the same file.
pub fn hnsw_snapshot_path(neoth_home: &Path) -> PathBuf {
    neoth_home.join("embeddings.hnsw")
}

/// GOLD-WIRE-07 — similarity search with backend dispatch. When `hnsw_path`
/// is `Some` (operator set `memory.vector_index.backend: hnsw`) AND the query
/// is NOT kind-scoped, cold-load the HNSW snapshot and use approximate
/// nearest-neighbour search. Every other case — kind-filtered query, no
/// snapshot, empty/unreadable snapshot, or an empty HNSW result — falls back
/// to the always-correct brute-force [`find_similar`].
///
/// Kind-filtered recall stays on brute-force on purpose: [`EmbeddingIndex::
/// find_similar_hnsw`] searches the whole index with no `source_kind` filter,
/// so returning its hits for a `--similar-kind`-scoped query would leak
/// wrong-kind results. The brute-force SQL path is both correct AND already
/// narrower (it scans only the matching `source_kind` rows).
pub fn find_similar_dispatch(
    conn: &Connection,
    query: &[f32],
    kind_filter: Option<&str>,
    top_k: usize,
    hnsw_path: Option<&Path>,
) -> Result<Vec<SimilarHit>> {
    if let Some(path) = hnsw_path {
        if kind_filter.is_some() {
            tracing::debug!(
                "GOLD-WIRE-07: kind-filtered recall uses brute-force \
                 (the HNSW index is not kind-scoped)"
            );
        } else {
            // Cold load: O(N log N) deserialize + HNSW graph rebuild, paid per
            // CLI query until the WIRE-07b warm daemon index lands. The caller
            // (recall) only passes `Some(path)` once the corpus exceeds the
            // brute-force ceiling, so this cost is only borne where brute-force
            // would itself be slow.
            match EmbeddingIndex::load(path) {
                Ok(Some(idx)) if !idx.is_empty() => {
                    let hits = idx.find_similar_hnsw(query, top_k);
                    if !hits.is_empty() {
                        return Ok(hits);
                    }
                    tracing::debug!("GOLD-WIRE-07: HNSW returned 0 hits; brute-force fallback");
                }
                Ok(None) => {
                    tracing::warn!(
                        path = %path.display(),
                        "GOLD-WIRE-07: backend=hnsw but no snapshot exists — \
                         run `neoth memory --rebuild-index`. Using brute-force for this query."
                    );
                }
                Ok(Some(_)) => {
                    tracing::warn!(
                        path = %path.display(),
                        "GOLD-WIRE-07: the HNSW snapshot is empty (0 vectors) — rebuild it AFTER \
                         embeddings exist via `neoth memory --rebuild-index`. Using brute-force."
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "GOLD-WIRE-07: HNSW snapshot load failed; brute-force fallback"
                    );
                }
            }
        }
    }
    find_similar(conn, query, kind_filter, top_k)
}

/// GOLD-WIRE-07 — true when the corpus is large enough that a per-query cold
/// HNSW load+rebuild is worth it. Below [`BRUTE_FORCE_CEILING`] the O(N) cosine
/// scan is FASTER than deserializing + rebuilding the graph, so recall stays on
/// brute-force. (The WIRE-07b warm daemon index removes the cold-load cost and
/// makes HNSW worthwhile at any size; until then this gate prevents a latency
/// regression for mid-size corpora.)
pub fn hnsw_beneficial_for_corpus(corpus: usize) -> bool {
    corpus > BRUTE_FORCE_CEILING
}

/// Wire-shape tuple shared between the two `query_map` call sites in
/// `find_similar`. Keeps the row-decode closure short + lets the post-
/// query scoring loop run over a single typed `Vec`.
struct RawEmbeddingRow {
    id: i64,
    source_kind: String,
    source_ref: String,
    model: String,
    blob: Vec<u8>,
    created_at: i64,
}

fn decode_raw_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEmbeddingRow> {
    Ok(RawEmbeddingRow {
        id: row.get(0)?,
        source_kind: row.get(1)?,
        source_ref: row.get(2)?,
        model: row.get(3)?,
        blob: row.get(4)?,
        created_at: row.get(6)?,
    })
}

/// Remove an embedding by `(source_kind, source_ref)`. Returns the
/// number of rows actually removed (0 when nothing matched).
pub fn delete(conn: &Connection, source_kind: &str, source_ref: &str) -> Result<usize> {
    let n = conn
        .execute(
            "DELETE FROM idx_embedding WHERE source_kind = ?1 AND source_ref = ?2",
            rusqlite::params![source_kind, source_ref],
        )
        .context("delete embedding")?;
    Ok(n)
}

/// Wipe every embedding whose `source_ref` matches `pattern` (SQL LIKE
/// pattern with `%` wildcards). Returns the row count deleted. Used
/// by `memory::forget` for the GDPR cascade; callers pass the same
/// `%topic%` pattern they'd LIKE-query other tiers with.
pub fn wipe_by_source_ref_pattern(conn: &Connection, pattern: &str) -> Result<i64> {
    let n = conn
        .execute(
            // Caller passes an already-`escape_like`d pattern; honour the
            // ESCAPE char so `%`/`_` match literally (GOLD-SEC-04).
            "DELETE FROM idx_embedding WHERE source_ref COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("wipe idx_embedding by source_ref pattern")?;
    Ok(n as i64)
}

/// Total row count — exposed for `neoth status` and similar diagnostics.
pub fn count(conn: &Connection) -> Result<i64> {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_embedding", [], |r| r.get(0))
        .context("count idx_embedding")?;
    Ok(n)
}

/// Count matching rows + emit a once-per-process WARN when the corpus
/// has crossed the brute-force ceiling. Best-effort: the count query
/// failing should never block recall (the actual scan handles its
/// own errors). Used by [`find_similar`].
fn warn_if_brute_force_ceiling_exceeded(conn: &Connection, dim: i64, kind_filter: Option<&str>) {
    use std::sync::atomic::Ordering;
    // Cheap pre-check: if we already warned, skip the count query
    // entirely. SQLite `SELECT COUNT(*)` over 60k rows still costs a
    // few hundred microseconds — the early-return is worth it for the
    // 99%-case "no warn pending".
    if BRUTE_FORCE_CEILING_WARNED.load(Ordering::Acquire) {
        return;
    }
    let count_res: rusqlite::Result<i64> = match kind_filter {
        Some(kind) => conn.query_row(
            "SELECT COUNT(*) FROM idx_embedding WHERE dim = ?1 AND source_kind = ?2",
            rusqlite::params![dim, kind],
            |r| r.get(0),
        ),
        None => conn.query_row(
            "SELECT COUNT(*) FROM idx_embedding WHERE dim = ?1",
            rusqlite::params![dim],
            |r| r.get(0),
        ),
    };
    let Ok(count) = count_res else {
        // Count failure isn't operator-actionable here — recall path
        // will surface the real error through its own query. Don't
        // pollute the log with a redundant warn.
        return;
    };
    if count as usize > BRUTE_FORCE_CEILING
        && BRUTE_FORCE_CEILING_WARNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        tracing::warn!(
            target: "embeddings",
            corpus_size = count,
            ceiling = BRUTE_FORCE_CEILING,
            dim,
            kind_filter,
            "idx_embedding corpus exceeded brute-force ceiling — recall latency \
             will degrade linearly with corpus size. V10-08 (HNSW / sqlite-vec) \
             ships the indexed alternative; track the issue at \
             https://github.com/<repo>/neoth/issues for V10-08 progress. \
             Brute-force scan continues — no functional regression, only speed."
        );
    }
}

/// Test-only reset helper. The brute-force-ceiling warn fires at most
/// once per process; tests that exercise the warn behaviour need to
/// reset between cases.
#[cfg(test)]
pub(crate) fn reset_brute_force_ceiling_flag_for_test() {
    BRUTE_FORCE_CEILING_WARNED.store(false, std::sync::atomic::Ordering::Release);
}

#[cfg(test)]
pub(crate) fn brute_force_ceiling_flag_for_test() -> bool {
    BRUTE_FORCE_CEILING_WARNED.load(std::sync::atomic::Ordering::Acquire)
}

// ─────────────────────────────────────────────────────────────────────────────
// HNSW embedding index — V10-08
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata stored per indexed vector so search results can be
/// reconstructed as [`SimilarHit`] without a round-trip to SQLite.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VectorMeta {
    id: i64,
    source_kind: String,
    source_ref: String,
    model: String,
    created_at: i64,
}

/// The bincode snapshot written to `<neoth_home>/embeddings.hnsw`.
///
/// Layout: every indexed vector is stored in insertion order; the HNSW
/// graph is rebuilt from these raw vectors on load. Rebuilding takes
/// O(N log N) time — fast enough for ≤500k vectors on commodity
/// hardware (< 1 min). The alternative (serialising the internal graph
/// links) would require unsafe access to hnsw_rs internals.
#[derive(Serialize, Deserialize)]
struct IndexSnapshot {
    /// HNSW construction parameters — must be consistent across save/load.
    max_nb_connection: usize,
    ef_construction: usize,
    /// One entry per indexed vector, in insertion order.
    entries: Vec<(VectorMeta, Vec<f32>)>,
}

/// In-process HNSW index over the embedding corpus.
///
/// Call [`EmbeddingIndex::build_from_sqlite`] on first boot (or after
/// `neoth memory rebuild-index`) to populate from `idx_embedding`.
/// Call [`EmbeddingIndex::add`] after each successful [`upsert`].
/// Call [`EmbeddingIndex::save`] on graceful daemon shutdown.
/// Call [`EmbeddingIndex::load`] on boot before the first search.
///
/// The `'static` lifetime bound on the inner `Hnsw` is required because
/// hnsw_rs stores data internally and the struct must be `Send + 'static`
/// to cross tokio task boundaries.
pub struct EmbeddingIndex {
    // SAFETY: 'static here because hnsw_rs copies inserted data into its
    // own heap allocations; no external data reference escapes the struct.
    hnsw: Hnsw<'static, f32, DistCosine>,
    /// Maps the hnsw data-id (a sequential `usize`) back to row metadata.
    meta: HashMap<usize, VectorMeta>,
    /// Raw vectors kept for snapshot persistence (rebuild on load).
    raw: Vec<(usize, VectorMeta, Vec<f32>)>,
    /// Next data-id to assign on insert.
    next_id: usize,
    /// HNSW max-nb-connection (M) used during construction.
    max_nb_connection: usize,
    /// ef_construction parameter used during construction.
    ef_construction: usize,
}

/// HNSW construction constants. M=16 / ef=200 is a well-balanced
/// operating point: recall ≥ 0.95 @ top-10 on cosine-similarity
/// workloads with dim 256–768. Operators who need higher recall at the
/// cost of build time can tune via `freedom.yaml` in a future release.
const HNSW_M: usize = 16;
const HNSW_EF_CONSTRUCTION: usize = 200;
/// ef_search — number of entry-point candidates explored per query.
/// 64 gives recall ≥ 0.98 at top-10 for M=16 / ef_c=200 on
/// typical embedding workloads.
const HNSW_EF_SEARCH: usize = 64;
/// Initial capacity hint. The HNSW graph grows dynamically; this just
/// avoids repeated reallocations for small corpora.
const HNSW_INITIAL_CAPACITY: usize = 10_000;
/// Max layers in the HNSW graph. 8 layers is sufficient for ≤10M
/// vectors.
const HNSW_NB_LAYER: usize = 8;

impl EmbeddingIndex {
    /// Create a new, empty HNSW index.
    pub fn new() -> Self {
        let hnsw = Hnsw::<f32, DistCosine>::new(
            HNSW_M,
            HNSW_INITIAL_CAPACITY,
            HNSW_NB_LAYER,
            HNSW_EF_CONSTRUCTION,
            DistCosine,
        );
        Self {
            hnsw,
            meta: HashMap::new(),
            raw: Vec::new(),
            next_id: 0,
            max_nb_connection: HNSW_M,
            ef_construction: HNSW_EF_CONSTRUCTION,
        }
    }

    /// Insert one L2-normalised vector with its row metadata into the index.
    /// `id` is the SQLite `idx_embedding.id` (rowid). `source_kind`,
    /// `source_ref`, `model`, `created_at` mirror the DB columns.
    pub fn add(
        &mut self,
        id: i64,
        source_kind: &str,
        source_ref: &str,
        model: &str,
        vector: &[f32],
        created_at: i64,
    ) {
        let data_id = self.next_id;
        self.next_id += 1;
        let meta = VectorMeta {
            id,
            source_kind: source_kind.to_owned(),
            source_ref: source_ref.to_owned(),
            model: model.to_owned(),
            created_at,
        };
        self.hnsw.insert((vector, data_id));
        self.meta.insert(data_id, meta.clone());
        self.raw.push((data_id, meta, vector.to_vec()));
    }

    /// Approximate top-k nearest-neighbour search. `query` must be
    /// L2-normalised. Returns up to `top_k` hits sorted by cosine
    /// similarity descending. Returns an empty `Vec` when the index is
    /// empty — never panics.
    ///
    /// Note: `hnsw_rs` with `DistCosine` returns *cosine distance*
    /// (1 − dot_product). We convert back to similarity here.
    pub fn find_similar_hnsw(&self, query: &[f32], top_k: usize) -> Vec<SimilarHit> {
        if top_k == 0 || self.meta.is_empty() {
            return Vec::new();
        }
        // HNSW's recall depends on graph connectivity. With ≤ HNSW_M
        // (16) indexed vectors the graph is degenerate — random
        // layer-assignment can leave one or more nodes unreachable
        // from the entry point, so an `hnsw.search` for k>indexed-1
        // returns fewer than expected. Fall back to brute-force over
        // `self.raw` while the corpus is below the threshold, which
        // is also where brute-force is fastest anyway.
        if self.meta.len() <= HNSW_M {
            return self.find_similar_brute_force(query, top_k);
        }

        let ef = HNSW_EF_SEARCH.max(top_k);
        let neighbours = self.hnsw.search(query, top_k, ef);
        let mut hits: Vec<SimilarHit> = neighbours
            .into_iter()
            .filter_map(|n| {
                let m = self.meta.get(&n.d_id)?;
                // hnsw_rs DistCosine returns 1 - dot_product (cosine
                // distance). Clamp to [0, 2] before negation so a
                // degenerate distance (NaN / negative) doesn't escape.
                let dist = n.distance.clamp(0.0, 2.0);
                Some(SimilarHit {
                    id: m.id,
                    source_kind: m.source_kind.clone(),
                    source_ref: m.source_ref.clone(),
                    model: m.model.clone(),
                    similarity: 1.0 - dist,
                    created_at: m.created_at,
                })
            })
            .collect();
        // Sort descending by similarity, break ties by created_at DESC.
        hits.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.created_at.cmp(&a.created_at))
        });
        hits.truncate(top_k);
        hits
    }

    /// Exact cosine-similarity scan over `self.raw`. Used by
    /// [`find_similar_hnsw`] when the corpus is small enough that
    /// HNSW's approximate recall drops below 100% — see the
    /// `find_similar_hnsw` body for the threshold rationale.
    fn find_similar_brute_force(&self, query: &[f32], top_k: usize) -> Vec<SimilarHit> {
        // Caller invariant: vectors are L2-normalised at insert time,
        // so dot product equals cosine similarity. We accept the
        // caller's contract here rather than re-normalising on every
        // search.
        let dot = |a: &[f32], b: &[f32]| -> f32 {
            a.iter()
                .zip(b.iter())
                .map(|(x, y)| x * y)
                .sum::<f32>()
                .clamp(-1.0, 1.0)
        };
        let mut scored: Vec<(f32, &VectorMeta)> = self
            .raw
            .iter()
            .map(|(_, meta, vec)| (dot(query, vec), meta))
            .collect();
        // Descending by similarity, ties broken by created_at DESC
        // to match find_similar_hnsw.
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.1.created_at.cmp(&a.1.created_at))
        });
        scored
            .into_iter()
            .take(top_k)
            .map(|(sim, m)| SimilarHit {
                id: m.id,
                source_kind: m.source_kind.clone(),
                source_ref: m.source_ref.clone(),
                model: m.model.clone(),
                similarity: sim,
                created_at: m.created_at,
            })
            .collect()
    }

    /// Number of indexed vectors.
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    /// `true` when no vectors have been inserted yet.
    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// Persist the index snapshot to `path` using an atomic write
    /// (write to `path.tmp`, then rename). Uses `bincode` 1.x encoding.
    ///
    /// The snapshot stores raw vectors + metadata. On [`load`] the
    /// HNSW graph is rebuilt from those vectors, which is faster than
    /// serialising the internal link structure.
    pub fn save(&self, path: &Path) -> Result<()> {
        let snapshot = IndexSnapshot {
            max_nb_connection: self.max_nb_connection,
            ef_construction: self.ef_construction,
            entries: self
                .raw
                .iter()
                .map(|(_, meta, vec)| (meta.clone(), vec.clone()))
                .collect(),
        };
        let bytes =
            bincode::serialize(&snapshot).context("bincode-encode embedding index snapshot")?;

        // Atomic write: write to a sibling .tmp file then rename.
        let tmp = path.with_extension("hnsw.tmp");
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir for embedding index: {}", parent.display()))?;
        }
        std::fs::write(&tmp, &bytes)
            .with_context(|| format!("write embedding index tmp file: {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("atomic rename {} → {}", tmp.display(), path.display()))?;
        tracing::debug!(
            path = %path.display(),
            vectors = self.meta.len(),
            bytes = bytes.len(),
            "embedding index snapshot written"
        );
        Ok(())
    }

    /// Load an index snapshot from `path`. Returns `Ok(None)` when the
    /// file does not yet exist (first boot before any snapshot is written).
    /// Returns `Err` on I/O or decode failure (corrupted snapshot).
    ///
    /// The HNSW graph is rebuilt from the stored raw vectors on load;
    /// this takes O(N log N) time proportional to the corpus size.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("read embedding index snapshot: {}", path.display()))?;
        let snapshot: IndexSnapshot = bincode::deserialize(&bytes)
            .with_context(|| format!("decode embedding index snapshot: {}", path.display()))?;

        let mut idx = Self::new_with_params(snapshot.max_nb_connection, snapshot.ef_construction);
        for (meta, vec) in snapshot.entries {
            idx.add(
                meta.id,
                &meta.source_kind,
                &meta.source_ref,
                &meta.model,
                &vec,
                meta.created_at,
            );
        }
        tracing::info!(
            path = %path.display(),
            vectors = idx.meta.len(),
            "embedding index loaded from snapshot"
        );
        Ok(Some(idx))
    }

    /// Construct the index from all rows in `idx_embedding`, filtered
    /// by optional `kind_filter`. Dimension is inferred from the first
    /// row; rows with mismatched dimension are logged and skipped.
    ///
    /// Used for first-boot migration (no snapshot exists yet) and for
    /// `neoth memory rebuild-index`.
    pub fn build_from_sqlite(conn: &Connection, kind_filter: Option<&str>) -> Result<Self> {
        // Row shape for the build_from_sqlite SELECT: `(id, source_kind,
        // source_ref, model, embedding, dim, created_at)`. Aliased so the
        // type doesn't trip clippy::type_complexity at the Vec call site.
        type BuildRow = (i64, String, String, String, Vec<u8>, i64, i64);

        let mut idx = Self::new();

        let sql_base = "SELECT id, source_kind, source_ref, model, embedding, dim, created_at \
                        FROM idx_embedding";
        let sql_filtered = format!("{sql_base} WHERE source_kind = ?1");
        let sql = if kind_filter.is_some() {
            sql_filtered.as_str()
        } else {
            sql_base
        };

        let mut stmt = conn
            .prepare(sql)
            .context("prepare build_from_sqlite query")?;

        let rows: Vec<BuildRow> = match kind_filter {
            Some(kind) => stmt
                .query_map(rusqlite::params![kind], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("scan idx_embedding for build_from_sqlite (filtered)")?,
            None => stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("scan idx_embedding for build_from_sqlite")?,
        };

        let mut inferred_dim: Option<usize> = None;
        let mut skipped = 0usize;

        for (id, source_kind, source_ref, model, blob, dim_col, created_at) in rows {
            let dim = dim_col as usize;
            // Infer dimension from first row; skip mismatches.
            match inferred_dim {
                None => inferred_dim = Some(dim),
                Some(d) if d != dim => {
                    tracing::warn!(
                        id,
                        expected_dim = d,
                        got_dim = dim,
                        "build_from_sqlite: dim mismatch, row skipped"
                    );
                    skipped += 1;
                    continue;
                }
                Some(_) => {}
            }
            let Some(vec) = blob_to_floats(&blob, dim) else {
                tracing::warn!(id, "build_from_sqlite: blob/dim mismatch, row skipped");
                skipped += 1;
                continue;
            };
            idx.add(id, &source_kind, &source_ref, &model, &vec, created_at);
        }

        tracing::info!(
            indexed = idx.meta.len(),
            skipped,
            "embedding index built from idx_embedding"
        );
        Ok(idx)
    }

    /// Constructor with explicit tuning parameters. Used internally by
    /// [`load`] to reconstruct with the same params used at build time.
    fn new_with_params(max_nb_connection: usize, ef_construction: usize) -> Self {
        let hnsw = Hnsw::<f32, DistCosine>::new(
            max_nb_connection,
            HNSW_INITIAL_CAPACITY,
            HNSW_NB_LAYER,
            ef_construction,
            DistCosine,
        );
        Self {
            hnsw,
            meta: HashMap::new(),
            raw: Vec::new(),
            next_id: 0,
            max_nb_connection,
            ef_construction,
        }
    }
}

impl Default for EmbeddingIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuild the HNSW index from `idx_embedding` and persist to `path`.
/// Called by `neoth memory rebuild-index`. Returns the number of
/// vectors indexed.
pub fn rebuild_index(conn: &Connection, path: &Path) -> Result<usize> {
    let idx = EmbeddingIndex::build_from_sqlite(conn, None)?;
    let n = idx.len();
    idx.save(path)?;
    Ok(n)
}

/// GR-005: after a GDPR `forget` deletes `idx_embedding` rows, the on-disk HNSW
/// snapshot still holds the forgotten vectors (it is rebuilt only on demand), so
/// they remain searchable via the cold-load path. Rebuild the snapshot FROM the
/// now-current SQLite so the searchable index no longer returns forgotten
/// vectors. No-op (`Ok(None)`) when no snapshot exists (recall then cold-loads
/// from the already-wiped SQLite / brute-forces). Returns the rebuilt vector
/// count on success.
pub fn rebuild_snapshot_if_present(conn: &Connection, neoth_home: &Path) -> Result<Option<usize>> {
    let path = hnsw_snapshot_path(neoth_home);
    if !path.exists() {
        return Ok(None);
    }
    let n = rebuild_index(conn, &path)?;
    Ok(Some(n))
}

fn floats_to_blob(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for f in v {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

fn blob_to_floats(blob: &[u8], expected_len: usize) -> Option<Vec<f32>> {
    if blob.len() != expected_len * 4 {
        return None;
    }
    let mut out = Vec::with_capacity(expected_len);
    for chunk in blob.chunks_exact(4) {
        out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Some(out)
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn is_unit_norm(v: &[f32]) -> bool {
    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    // Loose tolerance: lossy preprocessing + f32 round-off can drift
    // a fraction of a percent. Tighten only if a downstream lookup
    // misses turn out to be norm-related.
    (n - 1.0).abs() < 0.05 || n.abs() < 1e-6
}

fn unix_seconds_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_with_schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE idx_embedding (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source_kind TEXT NOT NULL,
                source_ref  TEXT NOT NULL,
                model       TEXT NOT NULL,
                embedding   BLOB NOT NULL,
                dim         INTEGER NOT NULL,
                created_at  INTEGER NOT NULL,
                UNIQUE (source_kind, source_ref)
            );
            "#,
        )
        .unwrap();
        conn
    }

    fn unit(v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.into_iter().map(|x| x / n).collect()
    }

    // ── GOLD-WIRE-07: find_similar_dispatch backend routing ───────────────

    fn seed_vectors(conn: &Connection, kind: &str, n: usize) {
        for i in 0..n {
            let mut v = vec![0.0f32; 8];
            v[i % 8] = 1.0;
            v[(i + 1) % 8] = 0.5;
            let v = unit(v);
            upsert(conn, kind, &format!("{kind}-{i}.png"), "clip", &v).unwrap();
        }
    }

    fn q8(a: f32, b: f32) -> Vec<f32> {
        let mut v = vec![0.0f32; 8];
        v[0] = a;
        v[1] = b;
        unit(v)
    }

    #[test]
    fn rebuild_snapshot_if_present_purges_forgotten_vectors() {
        // GR-005: a GDPR forget deletes idx_embedding rows in SQLite, but the
        // on-disk HNSW snapshot keeps the forgotten vectors searchable until a
        // rebuild. Prove rebuild_snapshot_if_present purges them.
        let conn = open_with_schema();
        upsert(&conn, "image", "secret-doc.png", "clip", &q8(1.0, 0.0)).unwrap();
        upsert(&conn, "image", "secret-note.png", "clip", &q8(0.0, 1.0)).unwrap();
        upsert(&conn, "image", "public-doc.png", "clip", &q8(0.5, 0.5)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // Initial snapshot holds all three.
        rebuild_index(&conn, &hnsw_snapshot_path(home)).unwrap();
        assert_eq!(
            EmbeddingIndex::load(&hnsw_snapshot_path(home)).unwrap().unwrap().len(),
            3
        );
        // GDPR forget wipes the two "secret" embedding rows from SQLite.
        let wiped = wipe_by_source_ref_pattern(&conn, "%secret%").unwrap();
        assert_eq!(wiped, 2);
        // Snapshot is now STALE (still 3) until we purge it.
        assert_eq!(
            EmbeddingIndex::load(&hnsw_snapshot_path(home)).unwrap().unwrap().len(),
            3,
            "snapshot still holds forgotten vectors before the rebuild"
        );
        let rebuilt = rebuild_snapshot_if_present(&conn, home).unwrap();
        assert_eq!(rebuilt, Some(1), "snapshot rebuilt with only the surviving vector");
        assert_eq!(
            EmbeddingIndex::load(&hnsw_snapshot_path(home)).unwrap().unwrap().len(),
            1,
            "forgotten vectors purged from the searchable snapshot"
        );
    }

    #[test]
    fn rebuild_snapshot_if_present_is_noop_without_a_snapshot() {
        let conn = open_with_schema();
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(rebuild_snapshot_if_present(&conn, dir.path()).unwrap(), None);
    }

    #[test]
    fn find_similar_dispatch_brute_force_when_hnsw_path_none() {
        let conn = open_with_schema();
        seed_vectors(&conn, "image", 5);
        let q = q8(1.0, 0.0);
        let direct = find_similar(&conn, &q, None, 3).unwrap();
        let dispatched = find_similar_dispatch(&conn, &q, None, 3, None).unwrap();
        assert_eq!(
            direct.iter().map(|h| h.id).collect::<Vec<_>>(),
            dispatched.iter().map(|h| h.id).collect::<Vec<_>>(),
            "hnsw_path=None must be identical to brute-force find_similar"
        );
    }

    #[test]
    fn find_similar_dispatch_uses_hnsw_snapshot_not_the_conn() {
        // Build a snapshot from a populated DB, then dispatch against an EMPTY
        // conn: a non-empty result PROVES the HNSW snapshot was searched (a
        // brute-force scan of the empty conn would return nothing).
        let src = open_with_schema();
        seed_vectors(&src, "image", 20);
        let idx = EmbeddingIndex::build_from_sqlite(&src, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");
        idx.save(&path).unwrap();

        let empty = open_with_schema();
        let q = q8(1.0, 0.5);
        let hits = find_similar_dispatch(&empty, &q, None, 5, Some(path.as_path())).unwrap();
        assert!(
            !hits.is_empty(),
            "HNSW snapshot must be searched even when the conn is empty"
        );
        for w in hits.windows(2) {
            assert!(
                w[0].similarity >= w[1].similarity,
                "hits must be similarity-ordered descending"
            );
        }
    }

    #[test]
    fn find_similar_dispatch_kind_filter_skips_hnsw() {
        // A kind-scoped query must use brute-force (HNSW is not kind-filterable).
        // Snapshot has vectors; the conn is empty → a kind-filtered dispatch
        // returns empty (brute-force on empty conn), proving HNSW was skipped.
        let src = open_with_schema();
        seed_vectors(&src, "image", 20);
        let idx = EmbeddingIndex::build_from_sqlite(&src, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");
        idx.save(&path).unwrap();

        let empty = open_with_schema();
        let q = q8(1.0, 0.5);
        let hits =
            find_similar_dispatch(&empty, &q, Some("image"), 5, Some(path.as_path())).unwrap();
        assert!(
            hits.is_empty(),
            "kind-filtered dispatch must brute-force the (empty) conn, NOT the HNSW snapshot"
        );
    }

    #[test]
    fn find_similar_dispatch_missing_snapshot_falls_back_to_brute_force() {
        let conn = open_with_schema();
        seed_vectors(&conn, "image", 5);
        let q = q8(1.0, 0.0);
        let missing = std::path::Path::new("definitely/no/such/embeddings.hnsw");
        let hits = find_similar_dispatch(&conn, &q, None, 3, Some(missing)).unwrap();
        let direct = find_similar(&conn, &q, None, 3).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.id).collect::<Vec<_>>(),
            direct.iter().map(|h| h.id).collect::<Vec<_>>(),
            "missing snapshot must transparently brute-force the conn"
        );
    }

    #[test]
    fn find_similar_dispatch_corrupt_snapshot_falls_back_without_error() {
        let conn = open_with_schema();
        seed_vectors(&conn, "image", 5);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");
        std::fs::write(&path, b"not a valid bincode snapshot").unwrap();
        let q = q8(1.0, 0.0);
        // Corrupt snapshot must degrade to brute-force, NOT return Err.
        let hits = find_similar_dispatch(&conn, &q, None, 3, Some(path.as_path())).unwrap();
        let direct = find_similar(&conn, &q, None, 3).unwrap();
        assert_eq!(hits.len(), direct.len());
    }

    #[test]
    fn hnsw_snapshot_path_is_canonical() {
        let home = std::path::Path::new("/tmp/neoth-home");
        assert_eq!(
            hnsw_snapshot_path(home),
            std::path::Path::new("/tmp/neoth-home/embeddings.hnsw")
        );
    }

    #[test]
    fn hnsw_beneficial_only_above_brute_force_ceiling() {
        assert!(!hnsw_beneficial_for_corpus(0));
        assert!(!hnsw_beneficial_for_corpus(BRUTE_FORCE_CEILING));
        assert!(hnsw_beneficial_for_corpus(BRUTE_FORCE_CEILING + 1));
    }

    /// Varied (non-degenerate) unit vectors so the HNSW graph has real
    /// connectivity — unlike `seed_vectors`' 8 repeating directions.
    fn seed_varied(conn: &Connection, kind: &str, n: usize) {
        for i in 0..n {
            let v: Vec<f32> = (0..16)
                .map(|j| (((i * 31 + j * 7 + 1) % 17) as f32) + 0.1)
                .collect();
            let v = unit(v);
            upsert(conn, kind, &format!("{kind}-{i}.png"), "clip", &v).unwrap();
        }
    }

    #[test]
    fn find_similar_dispatch_real_hnsw_graph_above_hnsw_m() {
        // 200 varied vectors is well above HNSW_M=16, so find_similar_hnsw
        // exercises the REAL graph search (not its small-corpus brute-force
        // fallback). Empty conn ⇒ a non-empty result proves the snapshot path.
        let src = open_with_schema();
        seed_varied(&src, "image", 200);
        let idx = EmbeddingIndex::build_from_sqlite(&src, None).unwrap();
        assert!(idx.len() > 16, "must exceed HNSW_M to hit the graph path");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");
        idx.save(&path).unwrap();

        let empty = open_with_schema();
        let query = unit((0..16).map(|j| ((j * 7 + 1) % 17) as f32 + 0.1).collect());
        let hits = find_similar_dispatch(&empty, &query, None, 10, Some(path.as_path())).unwrap();
        assert!(!hits.is_empty(), "real HNSW graph search must return hits");
        for w in hits.windows(2) {
            assert!(w[0].similarity >= w[1].similarity);
        }
    }

    #[test]
    fn find_similar_dispatch_kind_filter_returns_conn_rows_via_brute_force() {
        // Positive discriminator: with a populated conn + a present snapshot,
        // a kind-filtered dispatch returns the CONN's matching rows (brute-
        // force), proving the kind path bypasses HNSW rather than both paths
        // being trivially empty.
        let src = open_with_schema();
        seed_vectors(&src, "image", 20);
        let idx = EmbeddingIndex::build_from_sqlite(&src, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");
        idx.save(&path).unwrap();

        // A DIFFERENT conn with image rows of its own.
        let conn = open_with_schema();
        seed_vectors(&conn, "image", 4);
        seed_vectors(&conn, "audio", 4);
        let q = q8(1.0, 0.5);
        let hits =
            find_similar_dispatch(&conn, &q, Some("image"), 10, Some(path.as_path())).unwrap();
        assert!(!hits.is_empty(), "kind-filtered brute-force must find conn rows");
        assert!(
            hits.iter().all(|h| h.source_kind == "image"),
            "kind-filtered result must contain ONLY image hits (brute-force on conn), \
             never the snapshot's unfiltered HNSW results"
        );
        assert_eq!(
            hits.iter().map(|h| h.id).collect::<Vec<_>>(),
            find_similar(&conn, &q, Some("image"), 10)
                .unwrap()
                .iter()
                .map(|h| h.id)
                .collect::<Vec<_>>(),
            "kind-filtered dispatch must equal direct brute-force find_similar"
        );
    }

    #[test]
    fn upsert_returns_rowid() {
        let conn = open_with_schema();
        let v = unit(vec![1.0, 0.0, 0.0]);
        let id = upsert(&conn, "image", "a.png", "clip-test", &v).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn upsert_replaces_existing_pair() {
        let conn = open_with_schema();
        let v1 = unit(vec![1.0, 0.0, 0.0]);
        let v2 = unit(vec![0.0, 1.0, 0.0]);
        upsert(&conn, "image", "x.png", "m1", &v1).unwrap();
        upsert(&conn, "image", "x.png", "m2", &v2).unwrap();
        let c = count(&conn).unwrap();
        assert_eq!(c, 1, "second upsert must replace, not duplicate");
        let row: (String, Vec<u8>) = conn
            .query_row(
                "SELECT model, embedding FROM idx_embedding WHERE source_ref='x.png'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row.0, "m2");
        let read = blob_to_floats(&row.1, 3).unwrap();
        assert!((read[1] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn find_similar_orders_by_dot_product_descending() {
        let conn = open_with_schema();
        let a = unit(vec![1.0, 0.0, 0.0]);
        let b = unit(vec![0.9, 0.1, 0.0]); // close to a
        let c = unit(vec![0.0, 1.0, 0.0]); // orthogonal to a
        upsert(&conn, "image", "a.png", "clip", &a).unwrap();
        upsert(&conn, "image", "b.png", "clip", &b).unwrap();
        upsert(&conn, "image", "c.png", "clip", &c).unwrap();
        let hits = find_similar(&conn, &a, Some("image"), 3).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].source_ref, "a.png");
        assert_eq!(hits[1].source_ref, "b.png");
        assert_eq!(hits[2].source_ref, "c.png");
        assert!(hits[0].similarity > hits[1].similarity);
        assert!(hits[1].similarity > hits[2].similarity);
    }

    #[test]
    fn find_similar_filters_by_kind() {
        let conn = open_with_schema();
        let v = unit(vec![1.0, 0.0, 0.0]);
        upsert(&conn, "image", "img.png", "clip", &v).unwrap();
        upsert(&conn, "audio_segment", "wav#0", "whisper-mel", &v).unwrap();
        let hits = find_similar(&conn, &v, Some("image"), 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source_kind, "image");
        let all = find_similar(&conn, &v, None, 10).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn find_similar_skips_rows_with_wrong_dim() {
        let conn = open_with_schema();
        let v3 = unit(vec![1.0, 0.0, 0.0]);
        let v4 = unit(vec![1.0, 0.0, 0.0, 0.0]);
        upsert(&conn, "image", "small.png", "m3", &v3).unwrap();
        upsert(&conn, "image", "big.png", "m4", &v4).unwrap();
        let hits = find_similar(&conn, &v3, Some("image"), 10).unwrap();
        assert_eq!(hits.len(), 1, "dim mismatch must be skipped");
        assert_eq!(hits[0].source_ref, "small.png");
    }

    #[test]
    fn find_similar_top_k_truncates() {
        let conn = open_with_schema();
        for i in 0..5 {
            let mut v = vec![0f32; 4];
            v[i % 4] = 1.0;
            upsert(&conn, "image", &format!("x{i}.png"), "m", &v).unwrap();
        }
        let q = unit(vec![1.0, 0.0, 0.0, 0.0]);
        let hits = find_similar(&conn, &q, Some("image"), 2).unwrap();
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn find_similar_top_k_zero_returns_empty() {
        let conn = open_with_schema();
        let v = unit(vec![1.0, 0.0]);
        upsert(&conn, "image", "a", "m", &v).unwrap();
        let hits = find_similar(&conn, &v, Some("image"), 0).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn delete_removes_only_matching_row() {
        let conn = open_with_schema();
        let v = unit(vec![1.0, 0.0]);
        upsert(&conn, "image", "a", "m", &v).unwrap();
        upsert(&conn, "image", "b", "m", &v).unwrap();
        let n = delete(&conn, "image", "a").unwrap();
        assert_eq!(n, 1);
        assert_eq!(count(&conn).unwrap(), 1);
    }

    #[test]
    fn delete_missing_returns_zero() {
        let conn = open_with_schema();
        let n = delete(&conn, "image", "nope").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn blob_roundtrip_preserves_floats() {
        let v = vec![0.1, -0.5, 1.0, -1.0, f32::EPSILON];
        let blob = floats_to_blob(&v);
        let back = blob_to_floats(&blob, v.len()).unwrap();
        for (a, b) in v.iter().zip(back.iter()) {
            assert!((a - b).abs() < 1e-9, "{a} != {b}");
        }
    }

    #[test]
    fn blob_to_floats_rejects_size_mismatch() {
        assert!(blob_to_floats(&[0u8; 10], 3).is_none());
    }

    #[test]
    fn is_unit_norm_accepts_zero_vector() {
        // Zero vectors can appear when an upstream extractor degenerates;
        // we'd rather store the placeholder than panic.
        assert!(is_unit_norm(&[0.0, 0.0, 0.0]));
    }

    #[test]
    fn is_unit_norm_accepts_within_tolerance() {
        assert!(is_unit_norm(&[1.0, 0.001]));
        assert!(!is_unit_norm(&[1.0, 1.0]));
    }

    // ── Brute-force ceiling (V10-08 GA-blocker prep) ──────────────────

    #[test]
    fn brute_force_ceiling_is_pinned_at_50k() {
        // Pin the threshold so a future cleanup doesn't silently rotate
        // operator expectations downward. 50k matches the documented
        // commodity-laptop ~50ms budget at dim=512.
        assert_eq!(BRUTE_FORCE_CEILING, 50_000);
    }

    #[test]
    fn warn_does_not_fire_for_small_corpus() {
        reset_brute_force_ceiling_flag_for_test();
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("v.db")).unwrap();
        // Insert a single tiny embedding; corpus size = 1 << 50_000.
        let _ = upsert(&conn, "image", "tiny.png", "clip-vit-b32", &[1.0, 0.0])
            .expect("upsert succeeds");
        warn_if_brute_force_ceiling_exceeded(&conn, 2, None);
        assert!(
            !brute_force_ceiling_flag_for_test(),
            "warn must NOT fire under the ceiling"
        );
    }

    #[test]
    fn warn_does_not_double_fire_when_already_flagged() {
        reset_brute_force_ceiling_flag_for_test();
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("v.db")).unwrap();
        // Force the flag true; ensure the count query short-circuits
        // without contacting the DB (we can't easily insert 50k rows
        // in a unit test — the early-return path is the contract we
        // care about).
        BRUTE_FORCE_CEILING_WARNED.store(true, std::sync::atomic::Ordering::Release);
        warn_if_brute_force_ceiling_exceeded(&conn, 2, None);
        assert!(
            brute_force_ceiling_flag_for_test(),
            "flag stays true — once-set, never reset by the production path"
        );
        reset_brute_force_ceiling_flag_for_test();
    }

    // ── HNSW index tests (V10-08 Workstream E) ───────────────────────

    /// T1: add + search round-trip — verify that an inserted vector can be
    /// found by HNSW search with similarity close to 1.0.
    #[test]
    fn hnsw_add_and_search_round_trip() {
        let mut idx = EmbeddingIndex::new();
        let v = unit(vec![1.0, 0.0, 0.0]);
        idx.add(1, "image", "a.png", "clip", &v, 1000);
        let hits = idx.find_similar_hnsw(&v, 1);
        assert_eq!(hits.len(), 1, "expected one hit");
        assert_eq!(hits[0].source_ref, "a.png");
        // Cosine similarity of identical unit vectors = 1.0 (within f32
        // tolerance after hnsw_rs distance conversion).
        assert!(
            hits[0].similarity > 0.99,
            "similarity of identical vectors must be ~1.0, got {}",
            hits[0].similarity
        );
    }

    /// T2: persist + load round-trip — save the index, load it back, verify
    /// that search still works after deserialization.
    #[test]
    fn hnsw_persist_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("embeddings.hnsw");

        let v_a = unit(vec![1.0, 0.0, 0.0]);
        let v_b = unit(vec![0.0, 1.0, 0.0]);

        {
            let mut idx = EmbeddingIndex::new();
            idx.add(1, "image", "a.png", "clip", &v_a, 1000);
            idx.add(2, "image", "b.png", "clip", &v_b, 1001);
            idx.save(&path).expect("save must succeed");
        }

        let loaded = EmbeddingIndex::load(&path)
            .expect("load must succeed")
            .expect("snapshot must exist after save");

        assert_eq!(loaded.len(), 2, "loaded index must have 2 vectors");
        let hits = loaded.find_similar_hnsw(&v_a, 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source_ref, "a.png");
        assert!(hits[0].similarity > 0.99);
    }

    /// T3: migration from idx_embedding — build index from a synthetic
    /// SQLite table with 100 rows and verify all are indexed.
    #[test]
    fn hnsw_build_from_sqlite_100_rows() {
        let conn = open_with_schema();
        // Insert 100 orthogonal unit vectors (dim=8, cycling across basis).
        for i in 0u64..100 {
            let mut v = vec![0.0f32; 8];
            v[(i % 8) as usize] = 1.0;
            upsert(&conn, "text", &format!("doc{i}"), "model", &v).unwrap();
        }
        let idx =
            EmbeddingIndex::build_from_sqlite(&conn, None).expect("build from sqlite must succeed");
        assert_eq!(idx.len(), 100, "all 100 rows must be indexed");
    }

    /// T4: empty-index search returns empty Vec, no panic.
    #[test]
    fn hnsw_empty_index_search_returns_empty() {
        let idx = EmbeddingIndex::new();
        let q = unit(vec![1.0, 0.0, 0.0]);
        let hits = idx.find_similar_hnsw(&q, 10);
        assert!(hits.is_empty(), "empty index must return empty Vec");
    }

    /// T5: search when no snapshot exists yet falls back gracefully
    /// (load returns Ok(None), caller can use brute-force without crashing).
    #[test]
    fn hnsw_load_returns_none_when_no_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.hnsw");
        let result = EmbeddingIndex::load(&path).expect("load must not error when file absent");
        assert!(
            result.is_none(),
            "must return None when snapshot not present"
        );
    }

    /// T6: ranking — after inserting three vectors, HNSW search returns
    /// them in descending similarity order (same as brute-force).
    #[test]
    fn hnsw_search_ranks_by_similarity_descending() {
        let mut idx = EmbeddingIndex::new();
        let query = unit(vec![1.0, 0.0, 0.0]);
        // a: identical to query → similarity ~1.0
        let a = unit(vec![1.0, 0.0, 0.0]);
        // b: close to query
        let b = unit(vec![0.9, 0.1, 0.0]);
        // c: orthogonal to query → similarity ~0.0
        let c = unit(vec![0.0, 1.0, 0.0]);

        idx.add(1, "image", "a.png", "clip", &a, 1000);
        idx.add(2, "image", "b.png", "clip", &b, 1001);
        idx.add(3, "image", "c.png", "clip", &c, 1002);

        let hits = idx.find_similar_hnsw(&query, 3);
        assert_eq!(hits.len(), 3);
        // Similarity must be non-increasing.
        for w in hits.windows(2) {
            assert!(
                w[0].similarity >= w[1].similarity,
                "hits must be sorted descending by similarity: {} < {}",
                w[0].similarity,
                w[1].similarity
            );
        }
        // Closest hit must be the identical vector.
        assert_eq!(hits[0].source_ref, "a.png");
        // Tightened per Session 24 flake investigation: assert the
        // spread between best and worst hit is large enough that
        // floating-point rounding can't reorder the ranking. With
        // a (1.0), b (~0.995), c (~0.0) the best-to-worst spread
        // is >0.9 — well above any plausible rounding window. If
        // this fires, either HNSW returned a bogus ordering (real
        // bug) or the input vectors were silently mutated upstream.
        assert!(
            hits[0].similarity - hits[2].similarity > 0.5,
            "best-to-worst similarity spread too narrow ({} -> {}); \
             HNSW ordering may be nondeterministic for this input",
            hits[0].similarity,
            hits[2].similarity
        );
    }

    /// T7: rebuild_index helper writes a valid snapshot that load can read.
    #[test]
    fn hnsw_rebuild_index_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v.db");
        let idx_path = dir.path().join("embeddings.hnsw");
        let conn = crate::memory::store::open(&db_path).unwrap();

        let v = unit(vec![1.0, 0.0, 0.0]);
        upsert(&conn, "image", "x.png", "clip", &v).unwrap();

        let n = rebuild_index(&conn, &idx_path).expect("rebuild_index must succeed");
        assert_eq!(n, 1, "one vector must be indexed");
        assert!(idx_path.exists(), "snapshot file must be created");

        let loaded = EmbeddingIndex::load(&idx_path)
            .expect("load must succeed after rebuild")
            .expect("snapshot must exist");
        assert_eq!(loaded.len(), 1);
    }
}
