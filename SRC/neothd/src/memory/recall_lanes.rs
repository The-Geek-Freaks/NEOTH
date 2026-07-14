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

/// GRAPH-03 — additive score applied to members of the selected Louvain
/// community. This is intentionally larger than a single RRF contribution:
/// community membership is the Stage-3 signal that may promote a related
/// memory which did not text-match the query itself.
pub const COMMUNITY_SCORE_BOOST: f64 = 0.10;

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

/// One fused recall row together with the score that produced its rank.
/// Kept crate-private so Stage-3 can add its documented community score
/// without exposing an unstable scoring representation as public API.
pub(crate) struct ScoredHit {
    pub(crate) hit: EpisodeHit,
    pub(crate) score: f64,
    original_rank: usize,
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
    fuse_lanes_scored(lanes, limit)
        .into_iter()
        .map(|scored| scored.hit)
        .collect()
}

/// Scored twin of [`fuse_lanes`], used by GRAPH-03's Stage-3 community pass.
/// The public wrapper deliberately continues to return the historical
/// `Vec<EpisodeHit>` API.
pub(crate) fn fuse_lanes_scored(lanes: &[LaneResult], limit: usize) -> Vec<ScoredHit> {
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
    scored
        .into_iter()
        .enumerate()
        .map(|(original_rank, (hit, score))| ScoredHit {
            hit,
            score,
            original_rank,
        })
        .collect()
}

/// Convert an already-ranked recall result into the same scored representation
/// used by Stage-3. This is the production seam for routed Chat/Channel recall,
/// whose upstream rank is importance/recency rather than RRF. The monotonically
/// decreasing baseline preserves that order until the explicit community boost
/// is applied.
pub(crate) fn score_ranked_hits(hits: Vec<EpisodeHit>) -> Vec<ScoredHit> {
    hits.into_iter()
        .enumerate()
        .map(|(original_rank, hit)| ScoredHit {
            hit,
            score: 1.0 / (RRF_K + original_rank as f64 + 1.0),
            original_rank,
        })
        .collect()
}

/// GOLD-ADAPT-GRAPH-03 — community-based re-ranking pass (Stage-3).
///
/// Compatibility wrapper for callers which do not retain RRF scores. Given a
/// map of `event_id → community_id`, adds [`COMMUNITY_SCORE_BOOST`] to hits
/// in the plurality community. Returns the input unchanged when no community
/// has ≥ 2 representatives (prevents noise from singletons).
///
/// Pure: no DB, no async. The caller loads the community map before calling.
pub fn boost_by_community(
    hits: Vec<EpisodeHit>,
    community_map: &HashMap<i64, i64>,
) -> Vec<EpisodeHit> {
    let limit = hits.len();
    let scored = score_ranked_hits(hits);
    expand_and_boost_by_community(scored, Vec::new(), community_map, limit)
}

/// Pick the plurality community represented by at least two fused hits.
/// Equal-size communities deterministically prefer the smallest id.
pub(crate) fn plurality_community_id(
    hits: &[ScoredHit],
    community_map: &HashMap<i64, i64>,
) -> Option<i64> {
    let mut counts: HashMap<i64, usize> = HashMap::new();
    for scored in hits {
        if let Some(&cid) = community_map.get(&scored.hit.event_id) {
            *counts.entry(cid).or_insert(0) += 1;
        }
    }
    counts
        .iter()
        .filter(|(_, n)| **n >= 2)
        .min_by_key(|(cid, n)| (std::cmp::Reverse(**n), **cid))
        .map(|(cid, _)| *cid)
}

/// GRAPH-03 Stage-3: expand the selected community with DB-loaded members and
/// add [`COMMUNITY_SCORE_BOOST`] to every member's score. Expansion candidates
/// start at score zero, so they enter only through the explicit community
/// signal. Event-id/text-hash dedup and total ordering make the result stable
/// across processes and SQLite row orders.
pub(crate) fn expand_and_boost_by_community(
    mut hits: Vec<ScoredHit>,
    mut community_candidates: Vec<EpisodeHit>,
    community_map: &HashMap<i64, i64>,
    limit: usize,
) -> Vec<EpisodeHit> {
    if limit == 0 {
        return Vec::new();
    }
    let Some(plurality_cid) = plurality_community_id(&hits, community_map) else {
        return hits
            .into_iter()
            .take(limit)
            .map(|scored| scored.hit)
            .collect();
    };

    let mut seen_ids: std::collections::HashSet<i64> =
        hits.iter().map(|scored| scored.hit.event_id).collect();
    let mut seen_hashes: std::collections::HashSet<String> = hits
        .iter()
        .map(|scored| scored.hit.text_hash.clone())
        .collect();

    for scored in &mut hits {
        if community_map.get(&scored.hit.event_id) == Some(&plurality_cid) {
            scored.score += COMMUNITY_SCORE_BOOST;
        }
    }

    community_candidates.sort_by(|a, b| {
        a.event_id
            .cmp(&b.event_id)
            .then(a.text_hash.cmp(&b.text_hash))
            .then(a.tier.cmp(&b.tier))
    });
    for candidate in community_candidates {
        if community_map.get(&candidate.event_id) != Some(&plurality_cid)
            || !seen_ids.insert(candidate.event_id)
            || !seen_hashes.insert(candidate.text_hash.clone())
        {
            continue;
        }
        let original_rank = hits.len();
        hits.push(ScoredHit {
            hit: candidate,
            score: COMMUNITY_SCORE_BOOST,
            original_rank,
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.original_rank.cmp(&b.original_rank))
            .then(a.hit.event_id.cmp(&b.hit.event_id))
            .then(a.hit.text_hash.cmp(&b.hit.text_hash))
    });
    hits.truncate(limit);
    hits.into_iter().map(|scored| scored.hit).collect()
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
        assert_eq!(
            result[0].text_hash, "A",
            "community-10 hit A should be first"
        );
        assert_eq!(
            result[1].text_hash, "C",
            "community-10 hit C should be second"
        );
    }

    #[test]
    fn community_boost_noop_when_no_plurality() {
        // Each community has only 1 member — order must be unchanged.
        let community_map: HashMap<i64, i64> = HashMap::from([(1i64, 10i64), (2i64, 20i64)]);
        let hits = vec![
            hit_with_id("A", 1),
            hit_with_id("B", 2),
            hit_with_id("C", 99),
        ];
        let result = boost_by_community(hits, &community_map);
        let order: Vec<&str> = result.iter().map(|h| h.text_hash.as_str()).collect();
        assert_eq!(
            order,
            vec!["A", "B", "C"],
            "order unchanged when no plurality"
        );
    }

    #[test]
    fn community_boost_tie_breaks_on_smallest_community_id() {
        let community_map: HashMap<i64, i64> = HashMap::from([(1, 20), (2, 10), (3, 20), (4, 10)]);
        let hits = vec![
            hit_with_id("community-20-a", 1),
            hit_with_id("community-10-a", 2),
            hit_with_id("community-20-b", 3),
            hit_with_id("community-10-b", 4),
        ];

        let result = boost_by_community(hits, &community_map);
        let order: Vec<&str> = result.iter().map(|h| h.text_hash.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "community-10-a",
                "community-10-b",
                "community-20-a",
                "community-20-b",
            ],
            "equal-size pluralities must deterministically prefer the smallest community id"
        );
    }

    #[test]
    fn community_stage_expands_missing_members_and_applies_point_one_boost() {
        let lane = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![
                hit_with_id("community-a", 1),
                hit_with_id("unrelated", 2),
                hit_with_id("community-b", 3),
            ],
        };
        let community_map = HashMap::from([(1, 10), (3, 10), (4, 10), (5, 20)]);
        let candidates = vec![
            hit_with_id("missing-community-member", 4),
            hit_with_id("other-community-member", 5),
        ];

        let result = expand_and_boost_by_community(
            fuse_lanes_scored(&[lane], 10),
            candidates,
            &community_map,
            10,
        );
        let order: Vec<&str> = result.iter().map(|h| h.text_hash.as_str()).collect();

        assert_eq!(
            order,
            vec![
                "community-a",
                "community-b",
                "missing-community-member",
                "unrelated",
            ],
            "same-community members receive +0.1, missing members expand recall, and other communities stay out"
        );
    }

    #[test]
    fn community_expansion_deduplicates_and_obeys_limit() {
        let lane = LaneResult {
            weight: SEMANTIC_WEIGHT,
            hits: vec![
                hit_with_id("community-a", 1),
                hit_with_id("unrelated", 2),
                hit_with_id("community-b", 3),
            ],
        };
        let community_map = HashMap::from([(1, 10), (3, 10), (4, 10), (5, 10), (99, 10)]);
        let candidates = vec![
            hit_with_id("community-a", 99),
            hit_with_id("missing-z", 5),
            hit_with_id("missing-a", 4),
        ];

        let result = expand_and_boost_by_community(
            fuse_lanes_scored(&[lane], 10),
            candidates,
            &community_map,
            4,
        );
        let ids: Vec<i64> = result.iter().map(|h| h.event_id).collect();

        assert_eq!(ids, vec![1, 3, 4, 5]);
        assert_eq!(
            result
                .iter()
                .filter(|h| h.text_hash == "community-a")
                .count(),
            1,
            "duplicate content must not be reintroduced by community expansion"
        );
    }
}
