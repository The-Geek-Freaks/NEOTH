//! JV-SELF-02 — AMEM4Rec consolidation sweep (pure, sync, no WAL).
//!
//! Runs as a second scheduled memory pass on a longer cadence than the
//! Hebbian decay (default 6 h vs 2 h). It is ADDITIVE on the same SQLite
//! store — it does not replace the decay/tier migration path.
//!
//! ## Algorithm
//!
//! 1. Load all `(event_id, embedding_vec)` pairs from `idx_embedding` whose
//!    `source_kind = 'episode'` — these are the hot-tier cosine inputs.
//! 2. **Union-Find cluster** — for each pair `(i, j)` compute
//!    `dot(v_i, v_j)` (both are L2-normalised, so this equals cosine
//!    similarity) and union them when the result ≥ `cfg.cosine_threshold`.
//!    O(N²) over hot-tier sizes; guarded by a 50k-row cap.
//! 3. For each cluster of size ≥ `cfg.min_cluster_size`:
//!    a. Boost all members: `UPDATE idx_episode SET importance =
//!       MIN(importance * 1.05, cap) WHERE event_id IN (…)`.
//!    b. If the cluster is "mature" (member time-span ≥ 7 days AND
//!       avg_importance ≥ 0.5), pick the highest-importance member as
//!       canonical and INSERT into `idx_groundtruth`
//!       (`source = "consolidation-sweep"`, `scope = "meta"`,
//!       `fact_state = "candidate"`).
//! 4. Returns [`SweepReport`] — counts for WAL audit frames emitted by the
//!    cron wrapper; NO WAL writes happen inside this function.
//!
//! ## Safety
//!
//! - All SQLite writes run inside a single `BEGIN … COMMIT` transaction so
//!   a partial failure leaves the store unchanged.
//! - If the hot-tier embedding count exceeds 50 000 (`embeddings::
//!   BRUTE_FORCE_CEILING`) the sweep is skipped — an empty report is
//!   returned and a `tracing::warn!` is emitted.
//! - The importance UPDATE uses `MIN(…, cap)` to prevent runaway importance
//!   above 1.0 (which breaks the Hebbian decay math).

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use tracing::{debug, warn};

use crate::config::automation::ConsolidationSweepConfig;
use crate::memory::groundtruth::{self, Source};

/// Time-span threshold for a cluster to be considered "mature": 7 days.
const MATURE_SPAN_NS: i64 = 7 * 86_400 * 1_000_000_000;

/// Minimum average importance for a cluster before it is merged into
/// `idx_groundtruth`. Keeps low-quality clusters from polluting ground-truth.
const MATURE_MIN_AVG_IMPORTANCE: f64 = 0.5;

/// Boost factor applied to each cluster member's importance per sweep.
const IMPORTANCE_BOOST_FACTOR: f64 = 1.05;

/// Cap on corpus size before the O(N²) scan is skipped. Matches
/// `embeddings::BRUTE_FORCE_CEILING`.
const BRUTE_FORCE_CEILING: usize = 50_000;

/// Result of one consolidation sweep pass.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SweepReport {
    /// Total clusters found (size ≥ `min_cluster_size`).
    pub clusters_found: usize,
    /// Total episode rows whose importance was boosted this pass.
    pub members_boosted: usize,
    /// Mature clusters merged into `idx_groundtruth` this pass.
    pub merged_to_groundtruth: usize,
}

// ── Union-Find (path-compressed) ─────────────────────────────────────────────

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
        match self.rank[rx].cmp(&self.rank[ry]) {
            std::cmp::Ordering::Less => self.parent[rx] = ry,
            std::cmp::Ordering::Greater => self.parent[ry] = rx,
            std::cmp::Ordering::Equal => {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
    }
}

// ── Row loaded from idx_embedding ────────────────────────────────────────────

struct EmbRow {
    /// event_id string stored in `source_ref` for `source_kind='episode'`.
    event_id_str: String,
    /// L2-normalised f32 embedding. May be None if the blob is corrupt.
    vec: Vec<f32>,
    /// Channel (domain) this episode belongs to, from `idx_episode.channel`.
    /// `None` means the episode has no channel tag (e.g. RAW_TEXT events).
    /// Two episodes with `None` channels are treated as the **same** domain
    /// (conservative: unclassified episodes cluster together).
    channel: Option<String>,
}

/// Dot product of two L2-normalised vectors (= cosine similarity).
#[inline]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Decode a little-endian f32 blob. Returns empty Vec on length mismatch.
fn blob_to_floats(blob: &[u8]) -> Vec<f32> {
    if blob.len() % 4 != 0 {
        return Vec::new();
    }
    blob.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

// ── Episode metadata loaded for boost / merge ─────────────────────────────────

struct EpMeta {
    event_id: i64,
    text: String,
    importance: f64,
    ts_ns: i64,
}

/// Run one AMEM4Rec consolidation sweep against `conn`.
///
/// `now_ns` is the current wall-clock in nanoseconds (injected for testability).
/// Returns an empty [`SweepReport`] when there are no embeddings or when the
/// corpus exceeds `BRUTE_FORCE_CEILING`.
pub fn run_sweep(
    conn: &Connection,
    now_ns: i64,
    cfg: &ConsolidationSweepConfig,
) -> Result<SweepReport> {
    // ── 1. Load embeddings (with channel for same-domain guard) ────────────
    let rows: Vec<EmbRow> = {
        let mut stmt = conn.prepare(
            "SELECT ie.source_ref, ie.embedding, ep.channel \
             FROM idx_embedding ie \
             LEFT JOIN idx_episode ep \
                 ON ep.event_id = CAST(ie.source_ref AS INTEGER) \
             WHERE ie.source_kind = 'episode'",
        )?;
        stmt.query_map([], |r| {
            let source_ref: String = r.get(0)?;
            let blob: Vec<u8> = r.get(1)?;
            let channel: Option<String> = r.get(2)?;
            Ok((source_ref, blob, channel))
        })?
        .filter_map(|res| {
            res.ok().and_then(|(source_ref, blob, channel)| {
                let vec = blob_to_floats(&blob);
                if vec.is_empty() {
                    warn!(source_ref, "consolidation_sweep: skipping embedding with bad blob");
                    return None;
                }
                Some(EmbRow { event_id_str: source_ref, vec, channel })
            })
        })
        .collect()
    };

    if rows.is_empty() {
        debug!("consolidation_sweep: no episode embeddings found — skip");
        return Ok(SweepReport::default());
    }

    if rows.len() > BRUTE_FORCE_CEILING {
        warn!(
            count = rows.len(),
            ceiling = BRUTE_FORCE_CEILING,
            "consolidation_sweep: corpus exceeds brute-force ceiling — skipping this pass"
        );
        return Ok(SweepReport::default());
    }

    // ── 2. Union-Find cluster by cosine ≥ threshold ─────────────────────────
    let n = rows.len();
    let mut uf = UnionFind::new(n);
    let threshold = cfg.cosine_threshold as f32;

    for i in 0..n {
        for j in (i + 1)..n {
            // Same-domain guard: only cluster episodes on the same channel.
            // `None == None` → both unclassified → treated as same domain
            // (conservative: preserves existing behaviour for RAW_TEXT events
            // which have no channel tag).
            // `Some(a) == Some(b)` only when the channel strings match.
            // `Some(_) vs None` → different domains → skip.
            if rows[i].channel != rows[j].channel {
                continue;
            }
            if dot(&rows[i].vec, &rows[j].vec) >= threshold {
                uf.union(i, j);
            }
        }
    }

    // Group indices by root.
    let mut clusters: std::collections::HashMap<usize, Vec<usize>> = Default::default();
    for i in 0..n {
        clusters.entry(uf.find(i)).or_default().push(i);
    }

    // Filter to clusters meeting min_cluster_size.
    let qualifying: Vec<Vec<usize>> = clusters
        .into_values()
        .filter(|members| members.len() >= cfg.min_cluster_size)
        .collect();

    if qualifying.is_empty() {
        debug!("consolidation_sweep: no qualifying clusters — nothing to boost");
        return Ok(SweepReport { clusters_found: 0, members_boosted: 0, merged_to_groundtruth: 0 });
    }

    // ── 3. Load episode metadata for qualifying cluster members ─────────────
    // Build a set of all event_id strings we need metadata for.
    let needed: Vec<&str> = qualifying
        .iter()
        .flatten()
        .map(|&i| rows[i].event_id_str.as_str())
        .collect();

    // Load idx_episode metadata via a loop (rusqlite doesn't support IN with
    // dynamic bind params easily — use repeated queries with caching).
    let mut ep_cache: std::collections::HashMap<String, EpMeta> = Default::default();
    for id_str in &needed {
        if ep_cache.contains_key(*id_str) {
            continue;
        }
        // event_id in idx_episode is stored as INTEGER; source_ref is its
        // string representation.
        let event_id: i64 = match id_str.parse() {
            Ok(v) => v,
            Err(_) => {
                warn!(source_ref = id_str, "consolidation_sweep: bad event_id string — skip");
                continue;
            }
        };
        let meta: Option<(String, f64, i64)> = conn
            .query_row(
                "SELECT text, importance, ts_ns FROM idx_episode WHERE event_id = ?1",
                params![event_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .context("query idx_episode for sweep member")?;

        if let Some((text, importance, ts_ns)) = meta {
            ep_cache.insert(id_str.to_string(), EpMeta { event_id, text, importance, ts_ns });
        }
    }

    // ── 4. Apply boosts and groundtruth merges inside a transaction ──────────
    let tx = conn.unchecked_transaction()?;

    let mut report = SweepReport {
        clusters_found: qualifying.len(),
        ..Default::default()
    };

    for members in &qualifying {
        // Collect metadata for members that have it.
        let metas: Vec<&EpMeta> = members
            .iter()
            .filter_map(|&i| ep_cache.get(&rows[i].event_id_str))
            .collect();

        if metas.is_empty() {
            continue; // all members missing from idx_episode (already migrated to warm/cold)
        }

        // 4a. Boost importance for all members present in idx_episode.
        for meta in &metas {
            let new_importance = (meta.importance * IMPORTANCE_BOOST_FACTOR)
                .min(cfg.importance_boost_cap);
            tx.execute(
                "UPDATE idx_episode SET importance = ?1 WHERE event_id = ?2",
                params![new_importance, meta.event_id],
            )
            .context("boost importance")?;
            report.members_boosted += 1;
        }

        // 4b. Check maturity for groundtruth merge.
        let ts_min = metas.iter().map(|m| m.ts_ns).min().unwrap_or(0);
        let ts_max = metas.iter().map(|m| m.ts_ns).max().unwrap_or(0);
        let span_ns = ts_max.saturating_sub(ts_min);
        let avg_importance: f64 =
            metas.iter().map(|m| m.importance).sum::<f64>() / metas.len() as f64;

        if span_ns >= MATURE_SPAN_NS && avg_importance >= MATURE_MIN_AVG_IMPORTANCE {
            // Pick highest-importance member as canonical.
            if let Some(canonical) = metas.iter().max_by(|a, b| {
                a.importance
                    .partial_cmp(&b.importance)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                let now_unix_secs = now_ns / 1_000_000_000;
                match groundtruth::insert(
                    &tx,
                    &canonical.text,
                    &Source::Synthesis, // closest existing automated-cron source
                    "meta",
                    now_unix_secs,
                ) {
                    Ok(_) => report.merged_to_groundtruth += 1,
                    Err(e) => {
                        // Non-fatal — log and continue. A duplicate statement
                        // is handled by groundtruth::insert corroboration path.
                        debug!(error = %e, "consolidation_sweep: groundtruth insert skipped");
                    }
                }
            }
        }
    }

    tx.commit().context("commit consolidation sweep transaction")?;
    Ok(report)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn default_cfg() -> ConsolidationSweepConfig {
        ConsolidationSweepConfig::default()
    }

    /// Insert a minimal L2-normalised embedding for an episode event_id.
    fn insert_embedding(conn: &Connection, event_id: i64, vec: &[f32]) {
        let blob: Vec<u8> = vec
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let dim = vec.len() as i64;
        let now = 1_000_000i64;
        conn.execute(
            "INSERT OR REPLACE INTO idx_embedding \
             (source_kind, source_ref, model, embedding, dim, created_at) \
             VALUES ('episode', ?1, 'test', ?2, ?3, ?4)",
            params![event_id.to_string(), blob, dim, now],
        )
        .unwrap();
    }

    /// Insert a minimal idx_episode row (no channel tag — e.g. RAW_TEXT).
    fn insert_episode(conn: &Connection, event_id: i64, text: &str, importance: f64, ts_ns: i64) {
        insert_episode_with_channel(conn, event_id, text, importance, ts_ns, None);
    }

    /// Insert a minimal idx_episode row with an optional channel tag.
    fn insert_episode_with_channel(
        conn: &Connection,
        event_id: i64,
        text: &str,
        importance: f64,
        ts_ns: i64,
        channel: Option<&str>,
    ) {
        // event_type=1 (RAW_TEXT), text_hash derived from event_id for uniqueness.
        let text_hash = format!("hash-{event_id}");
        conn.execute(
            "INSERT OR REPLACE INTO idx_episode \
             (event_id, event_type, text, text_hash, importance, trust, ts_ns, pinned, channel) \
             VALUES (?1, 1, ?2, ?3, ?4, 1, ?5, 0, ?6)",
            params![event_id, text, text_hash, importance, ts_ns, channel],
        )
        .unwrap();
    }

    #[test]
    fn empty_db_returns_default_report() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let report = run_sweep(&conn, 1_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(report, SweepReport::default());
    }

    #[test]
    fn single_episode_no_cluster_formed() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // One episode + embedding — no peer → no cluster.
        insert_episode(&conn, 1, "hello world", 0.5, 1_000_000_000_000);
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);

        let report = run_sweep(&conn, 2_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(report.clusters_found, 0);
        assert_eq!(report.members_boosted, 0);
        assert_eq!(report.merged_to_groundtruth, 0);
    }

    #[test]
    fn two_similar_episodes_cluster_and_boost() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Two identical unit vectors → cosine = 1.0 ≥ 0.75 threshold.
        insert_episode(&conn, 1, "rust is fast", 0.4, 1_000_000_000);
        insert_episode(&conn, 2, "rust is fast too", 0.4, 2_000_000_000);
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(report.clusters_found, 1);
        assert_eq!(report.members_boosted, 2);

        // Verify importance was boosted and capped.
        let imp: f64 = conn
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 1", [], |r| r.get(0))
            .unwrap();
        assert!(imp > 0.4, "importance must be boosted");
        assert!(imp <= 0.85, "importance must not exceed cap");
    }

    #[test]
    fn importance_cap_respected() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Start at the cap — boost must not push above it.
        insert_episode(&conn, 1, "capped", 0.85, 1_000_000_000);
        insert_episode(&conn, 2, "capped too", 0.85, 2_000_000_000);
        insert_embedding(&conn, 1, &[0.0f32, 1.0, 0.0]);
        insert_embedding(&conn, 2, &[0.0f32, 1.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(report.members_boosted, 2);

        let imp: f64 = conn
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 1", [], |r| r.get(0))
            .unwrap();
        assert!(
            (imp - 0.85).abs() < 1e-9,
            "importance at cap must not exceed cap: got {imp}"
        );
    }

    #[test]
    fn dissimilar_episodes_no_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Orthogonal vectors → cosine = 0.0 < 0.75 threshold.
        insert_episode(&conn, 1, "apples", 0.5, 1_000_000_000);
        insert_episode(&conn, 2, "oranges", 0.5, 2_000_000_000);
        insert_embedding(&conn, 1, &[1.0f32, 0.0]);
        insert_embedding(&conn, 2, &[0.0f32, 1.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(report.clusters_found, 0);
        assert_eq!(report.members_boosted, 0);
    }

    #[test]
    fn mature_cluster_writes_groundtruth() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Two similar episodes, high importance, 8 days apart → mature.
        const DAY_NS: i64 = 86_400_000_000_000;
        let ts0: i64 = DAY_NS;
        let ts1: i64 = 9 * DAY_NS; // 8-day span

        insert_episode(&conn, 1, "neoth is powerful", 0.7, ts0);
        insert_episode(&conn, 2, "neoth is very powerful", 0.7, ts1);
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0, 0.0]);

        let now_ns = 10 * DAY_NS;
        let report = run_sweep(&conn, now_ns, &default_cfg()).unwrap();

        assert_eq!(report.clusters_found, 1);
        assert_eq!(report.merged_to_groundtruth, 1);

        // Verify a groundtruth row was created.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth WHERE scope = 'meta'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "one groundtruth row should exist after mature merge");
    }

    #[test]
    fn immature_cluster_does_not_write_groundtruth() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Two similar episodes, same timestamp → span < 7d → not mature.
        let ts: i64 = 1_000_000_000;
        insert_episode(&conn, 1, "immature a", 0.7, ts);
        insert_episode(&conn, 2, "immature b", 0.7, ts);
        insert_embedding(&conn, 1, &[1.0f32, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0]);

        let report = run_sweep(&conn, ts + 1_000_000, &default_cfg()).unwrap();
        assert_eq!(report.merged_to_groundtruth, 0);
    }

    // ── DELTA 2: same-domain guard tests ─────────────────────────────────────

    /// Two identical vectors on DIFFERENT channels must NOT cluster.
    /// This proves the same-domain guard is enforced in the union step.
    #[test]
    fn cross_channel_episodes_do_not_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // Cosine = 1.0 (identical unit vectors) — would cluster without the
        // same-domain guard; channel mismatch must prevent it.
        insert_episode_with_channel(&conn, 1, "rust is fast", 0.5, 1_000_000_000, Some("telegram"));
        insert_episode_with_channel(
            &conn,
            2,
            "rust is fast too",
            0.5,
            2_000_000_000,
            Some("discord"),
        );
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(
            report.clusters_found, 0,
            "cross-channel episodes must not form a cluster even with cosine=1.0"
        );
        assert_eq!(report.members_boosted, 0);
    }

    /// Two identical vectors on the SAME named channel must still cluster.
    #[test]
    fn same_channel_episodes_do_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        insert_episode_with_channel(
            &conn,
            1,
            "neoth rocks",
            0.4,
            1_000_000_000,
            Some("telegram"),
        );
        insert_episode_with_channel(
            &conn,
            2,
            "neoth rocks indeed",
            0.4,
            2_000_000_000,
            Some("telegram"),
        );
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(
            report.clusters_found, 1,
            "same-channel episodes with cosine=1.0 must cluster"
        );
        assert_eq!(report.members_boosted, 2);
    }

    /// Two identical vectors with NULL channel (unclassified / RAW_TEXT)
    /// must cluster together — None==None same-domain conservative rule.
    #[test]
    fn null_channel_episodes_cluster_as_same_domain() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        // No channel — both None → treated as same domain.
        insert_episode(&conn, 1, "anon a", 0.4, 1_000_000_000);
        insert_episode(&conn, 2, "anon b", 0.4, 2_000_000_000);
        insert_embedding(&conn, 1, &[0.0f32, 1.0, 0.0]);
        insert_embedding(&conn, 2, &[0.0f32, 1.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(
            report.clusters_found, 1,
            "NULL-channel episodes must cluster (None==None same-domain)"
        );
        assert_eq!(report.members_boosted, 2);
    }

    /// An episode with a named channel must NOT cluster with a NULL-channel
    /// episode (None != Some("telegram")).
    #[test]
    fn named_channel_vs_null_channel_does_not_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();

        insert_episode_with_channel(
            &conn,
            1,
            "tagged",
            0.5,
            1_000_000_000,
            Some("telegram"),
        );
        insert_episode(&conn, 2, "untagged", 0.5, 2_000_000_000); // channel=None
        insert_embedding(&conn, 1, &[1.0f32, 0.0, 0.0]);
        insert_embedding(&conn, 2, &[1.0f32, 0.0, 0.0]);

        let report = run_sweep(&conn, 3_000_000_000_000, &default_cfg()).unwrap();
        assert_eq!(
            report.clusters_found, 0,
            "named-channel vs NULL-channel must not cluster"
        );
    }
}
