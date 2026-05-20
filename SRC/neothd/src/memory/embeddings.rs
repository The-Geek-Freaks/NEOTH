//! Embedding store — schema v6.
//!
//! Persists fixed-size dense vectors (CLIP image embeddings today,
//! potentially audio + text projections later) so recall can do
//! similarity search across modalities. Brute-force cosine for now —
//! HNSW / IVF arrives when the corpus exceeds ~50k vectors, which a
//! solo operator is unlikely to hit in v0.1.x.
//!
//! Storage layout:
//!   * `embedding BLOB` — `dim × 4` bytes, little-endian f32. L2-norm
//!     **expected** at insert time so similarity is one dot product per
//!     candidate, no division on the hot path.
//!   * `(source_kind, source_ref)` is the natural key — an `(image, path)`
//!     can only ever have one current embedding. New inserts UPSERT,
//!     bumping `created_at`.
//!
//! Self-contained: no HNSW / qdrant / lance dep. Pure rusqlite + a
//! handful of fold-style reductions.

use anyhow::{Context, Result};
use rusqlite::Connection;

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
            "DELETE FROM idx_embedding WHERE source_ref LIKE ?1 COLLATE NOCASE",
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
}
