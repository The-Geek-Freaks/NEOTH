//! GOLD-ADAPT-MEM-03 — parallel recall lanes + late fusion.
//!
//! NEOTH's text recall already reads several corpora (hot `idx_episode` via
//! FTS5/bm25, warm `idx_consolidated` + cold `idx_longterm` via LIKE, and the
//! operator-asserted `idx_groundtruth`). Before MEM-03 those were merged into a
//! single `Vec` and re-sorted **entirely** by `composite_score` — which means
//! the FTS bm25 keyword-relevance ordering was fetched and then **discarded**,
//! and a hot hit could appear twice if the same content was also summarised into
//! a warm/cold row.
//!
//! This module turns those corpora into explicit named **lanes** that are fused
//! with **reciprocal-rank fusion (RRF)**:
//!   - each lane retrieves independently and keeps its own native ranking
//!     (Semantic = bm25 relevance; Episodic = full `composite_score` order),
//!   - a row's fused score is the sum over lanes of `weight / (RRF_K + rank)`,
//!   - rows are deduped by `text_hash` (a hot hit and a warm summary of the
//!     *same* content collapse to one; corroboration across lanes adds score),
//!   - groundtruth is **never** fused (operator truth is prepended by the
//!     caller, not scored against decaying candidates).
//!
//! RRF is chosen over weighted-score-sum because the per-lane signals live on
//! incompatible scales (FTS `bm25()` is negative, `composite_score` is ~0..1):
//! RRF works purely on rank position, needs no normalisation pass, and degrades
//! gracefully when a lane returns zero hits.
//!
//! Lane execution is **budget-adaptive** via [`crate::memory::recall_gate`]:
//! a genuinely-no-recall query (status/identity/greeting) runs only the cheap
//! Semantic lane and skips the warm+cold scans; ordinary and historical queries
//! cover all available text tiers. (Per-tier lanes mean an ordinary query must
//! still search the aged tiers — dropping them would *regress* recall — so the
//! reduced budget applies only to the Skip tier. The `Multi` tier reserves the
//! deferred Reflex/HNSW vector lane and assoc fan-out for when they exist.)
//!
//! The cross-modal HNSW/vector "Reflex" lane in the original MEM-03 spec is
//! deliberately **deferred**: `idx_embedding` holds only CLIP media/document
//! projections (image/audio/pdf/document `source_kind`s keyed by file path), not
//! per-episode text embeddings, so it shares no id namespace with `idx_episode`
//! and cannot be fused by `text_hash`/`event_id` today. It remains its own
//! `neoth recall --similar-to-text` mode. A text-embedding lane slots into the
//! `Multi` budget once per-episode text vectors are stored.
//!
//! All functions here are pure (no DB, no async) and unit-tested directly.

use std::collections::HashMap;

use crate::memory::recall_gate::RecallTier;
use crate::memory::views::EpisodeHit;

/// Standard RRF damping constant (Cormack et al. 2009). Larger ⇒ flatter
/// contribution curve across ranks; 60 is the widely-used default.
pub const RRF_K: f64 = 60.0;

/// Weight of the Semantic (hot / FTS5 keyword-match) lane. Highest: a direct
/// text match is the strongest relevance signal NEOTH has.
pub const SEMANTIC_WEIGHT: f64 = 1.0;

/// Weight of the Episodic (warm + cold tier-utility) lane. Lower than Semantic:
/// importance/recency without a direct text-match signal.
pub const EPISODIC_WEIGHT: f64 = 0.75;

/// Which lanes a query's [`RecallTier`] budget permits. The Semantic lane always
/// runs (an explicit `neoth recall <query>` should never come back empty); the
/// Episodic lane is shed only for the Skip tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneBudget {
    /// Hot tier (FTS5/bm25 + LIKE fallback over `idx_episode`).
    pub semantic: bool,
    /// Warm (`idx_consolidated`) + cold (`idx_longterm`) tier-utility lane.
    pub episodic: bool,
}

/// Map a recall tier to its lane budget.
///
/// - `Skip` (status/identity/greeting): Semantic only — skip the warm+cold LIKE
///   scans. Still returns hot matches so an explicit search isn't empty.
/// - `Single` / `Multi`: both text lanes. Per-tier lanes mean an ordinary query
///   must keep the aged tiers to avoid a recall regression; `Multi` additionally
///   reserves the deferred vector/assoc fan-out lanes for when they land.
pub fn budget_for(tier: RecallTier) -> LaneBudget {
    match tier {
        RecallTier::Skip => LaneBudget {
            semantic: true,
            episodic: false,
        },
        RecallTier::Single | RecallTier::Multi => LaneBudget {
            semantic: true,
            episodic: true,
        },
    }
}

/// One recall lane's output: its fusion weight and its hits in the lane's own
/// native rank order (index 0 = best in that lane).
pub struct LaneResult {
    pub weight: f64,
    pub hits: Vec<EpisodeHit>,
}

/// Reciprocal-rank-fuse the lanes into a single ranked, deduped list.
///
/// Dedup key is `text_hash`: identical content surfacing from more than one lane
/// collapses to a single row whose fused score is the **sum** of each lane's
/// `weight / (RRF_K + rank + 1)` contribution (so multi-lane corroboration ranks
/// a row higher). The retained `EpisodeHit` is the **first** occurrence — the
/// caller orders `lanes` by priority (Semantic before Episodic), so the
/// higher-weight lane's tier/importance fields win on a collision.
///
/// Ties in fused score keep first-seen order (a stable sort over a first-seen
/// build order), and the result is truncated to `limit`. Pure: no DB, no async.
pub fn fuse_lanes(lanes: &[LaneResult], limit: usize) -> Vec<EpisodeHit> {
    // Preserve first-seen order so the final stable sort breaks score ties by
    // lane priority + within-lane rank rather than HashMap iteration order.
    let mut order: Vec<String> = Vec::new();
    let mut acc: HashMap<String, (EpisodeHit, f64)> = HashMap::new();

    for lane in lanes {
        for (rank, hit) in lane.hits.iter().enumerate() {
            let contribution = lane.weight / (RRF_K + (rank as f64) + 1.0);
            acc.entry(hit.text_hash.clone())
                .and_modify(|entry| entry.1 += contribution)
                .or_insert_with(|| {
                    order.push(hit.text_hash.clone());
                    (hit.clone(), contribution)
                });
        }
    }

    let mut scored: Vec<(EpisodeHit, f64)> =
        order.into_iter().filter_map(|k| acc.remove(&k)).collect();
    // Stable sort: equal fused scores stay in first-seen (lane-priority) order.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(limit);
    scored.into_iter().map(|(hit, _)| hit).collect()
}

/// GOLD-ADAPT-GRAPH-03 — community-based re-ranking pass (Stage-3).
///
/// Given a map of `event_id → community_id` loaded by the caller from
/// `idx_memory_communities`, floats hits that share the plurality community to
/// the front via a stable sort. Hits with no community entry keep their RRF
/// position. Returns the input unchanged when no community has ≥ 2
/// representatives among the hits (prevents noise from singletons).
///
/// Pure: no DB, no async. The caller loads the community map before calling.
pub fn boost_by_community(
    mut hits: Vec<EpisodeHit>,
    community_map: &HashMap<i64, i64>,
) -> Vec<EpisodeHit> {
    let mut counts: HashMap<i64, usize> = HashMap::new();
    for h in &hits {
        if let Some(&cid) = community_map.get(&h.event_id) {
            *counts.entry(cid).or_insert(0) += 1;
        }
    }
    // Only boost when the plurality community has ≥ 2 members among the hits.
    let Some(plurality_cid) = counts
        .iter()
        .filter(|(_, n)| **n >= 2)
        .max_by_key(|(_, n)| **n)
        .map(|(cid, _)| *cid)
    else {
        return hits;
    };
    // Stable sort: plurality-community hits first; RRF order within each group.
    hits.sort_by_key(|h| u8::from(community_map.get(&h.event_id) != Some(&plurality_cid)));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(text_hash: &str, tier: &str, importance: f64) -> EpisodeHit {
        EpisodeHit {
            event_id: 1,
            event_type: 0,
            ts_ns: 0,
            text: text_hash.to_string(),
            text_hash: text_hash.to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: tier.to_string(),
            importance: Some(importance),
            access_count: 0,
            trust: 1,
        }
    }

    #[test]
    fn budget_skip_drops_episodic_keeps_semantic() {
        let b = budget_for(RecallTier::Skip);
        assert!(b.semantic, "an explicit recall always runs the hot lane");
        assert!(!b.episodic, "Skip tier sheds the warm+cold scans");
    }

    #[test]
    fn budget_single_and_multi_cover_all_text_tiers() {
        for t in [RecallTier::Single, RecallTier::Multi] {
            let b = budget_for(t);
            assert!(
                b.semantic && b.episodic,
                "{t:?} keeps both text lanes (no recall regression)"
            );
        }
    }

    #[test]
    fn dedup_by_text_hash_collapses_cross_lane_duplicate() {
        // Same content "abc" appears in both lanes; warm tag in lane B.
        let lane_a = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![hit("abc", "hot", 0.5)],
        };
        let lane_b = LaneResult {
            weight: EPISODIC_WEIGHT,
            hits: vec![hit("abc", "warm", 0.9)],
        };
        let out = fuse_lanes(&[lane_a, lane_b], 10);
        assert_eq!(out.len(), 1, "the duplicate content collapses to one row");
        assert_eq!(
            out[0].tier, "hot",
            "the higher-priority (first) lane's row is kept"
        );
    }

    #[test]
    fn rrf_ordering_rewards_cross_lane_corroboration() {
        // Lane A (w=1.0): [X@0, Y@1]   Lane B (w=0.75): [Y@0, Z@1]
        //   X: 1.0/(60+1)                    = 0.016393
        //   Y: 1.0/(60+2) + 0.75/(60+1)      = 0.016129 + 0.012295 = 0.028424
        //   Z: 0.75/(60+2)                   = 0.012097
        // Expected: Y (corroborated) > X > Z.
        let lane_a = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![hit("X", "hot", 0.5), hit("Y", "hot", 0.5)],
        };
        let lane_b = LaneResult {
            weight: EPISODIC_WEIGHT,
            hits: vec![hit("Y", "warm", 0.5), hit("Z", "warm", 0.5)],
        };
        let out = fuse_lanes(&[lane_a, lane_b], 10);
        let order: Vec<&str> = out.iter().map(|h| h.text_hash.as_str()).collect();
        assert_eq!(
            order,
            vec!["Y", "X", "Z"],
            "corroborated Y leads, then X, then Z"
        );
    }

    #[test]
    fn single_lane_preserves_native_order() {
        // RRF with one lane is monotonic in rank → input order is preserved.
        let lane = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![
                hit("a", "hot", 0.1),
                hit("b", "hot", 0.9),
                hit("c", "hot", 0.5),
            ],
        };
        let out = fuse_lanes(&[lane], 10);
        let order: Vec<&str> = out.iter().map(|h| h.text_hash.as_str()).collect();
        assert_eq!(
            order,
            vec!["a", "b", "c"],
            "single-lane fusion keeps the lane's order"
        );
    }

    #[test]
    fn empty_lane_does_not_panic_and_contributes_nothing() {
        let lane_a = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![],
        };
        let lane_b = LaneResult {
            weight: EPISODIC_WEIGHT,
            hits: vec![hit("a", "warm", 0.5), hit("b", "warm", 0.5)],
        };
        let out = fuse_lanes(&[lane_a, lane_b], 10);
        assert_eq!(
            out.len(),
            2,
            "an empty lane is a no-op, the other lane still surfaces"
        );
    }

    #[test]
    fn limit_truncates_after_fusion() {
        let many: Vec<EpisodeHit> = (0..10).map(|i| hit(&format!("h{i}"), "hot", 0.5)).collect();
        let lane = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: many,
        };
        let out = fuse_lanes(&[lane], 3);
        assert_eq!(out.len(), 3, "fused result is truncated to the limit");
    }

    #[test]
    fn no_lanes_yields_empty() {
        assert!(fuse_lanes(&[], 10).is_empty());
    }

    // ── GOLD-ADAPT-GRAPH-03: community boost ─────────────────────────────────

    fn hit_with_id(text_hash: &str, event_id: i64) -> EpisodeHit {
        EpisodeHit {
            event_id,
            event_type: 0,
            ts_ns: 0,
            text: text_hash.to_string(),
            text_hash: text_hash.to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".to_string(),
            importance: Some(0.5),
            access_count: 0,
            trust: 1,
        }
    }

    #[test]
    fn community_boost_floats_plurality_community() {
        // A(comm=10), B(no comm), C(comm=10), D(comm=20) — community 10 is plurality.
        let community_map: HashMap<i64, i64> =
            HashMap::from([(1i64, 10i64), (3i64, 10i64), (4i64, 20i64)]);
        let hits = vec![
            hit_with_id("A", 1),
            hit_with_id("B", 2),
            hit_with_id("C", 3),
            hit_with_id("D", 4),
        ];
        let result = boost_by_community(hits, &community_map);
        assert_eq!(result[0].text_hash, "A", "community-10 hit A should be first");
        assert_eq!(result[1].text_hash, "C", "community-10 hit C should be second");
    }

    #[test]
    fn community_boost_noop_when_no_plurality() {
        // Each community has only 1 member — order must be unchanged.
        let community_map: HashMap<i64, i64> = HashMap::from([(1i64, 10i64), (2i64, 20i64)]);
        let hits = vec![hit_with_id("A", 1), hit_with_id("B", 2), hit_with_id("C", 99)];
        let result = boost_by_community(hits, &community_map);
        let order: Vec<&str> = result.iter().map(|h| h.text_hash.as_str()).collect();
        assert_eq!(order, vec!["A", "B", "C"], "order unchanged when no plurality");
    }
}
