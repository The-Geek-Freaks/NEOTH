//! Dissent score — measures how much the hemispheres disagreed.
//!
//! v0.1 ships a simple text-overlap heuristic: Jaccard similarity over
//! lowercased word sets. 0.0 = identical responses, 1.0 = no shared
//! words. Cheap, deterministic, no LLM call required.
//!
//! Future iterations (CH-12 adaptive thresholds, CH-09 profile-aware
//! re-rank) can replace this Jaccard heuristic with embedding cosine
//! distance via [`crate::providers::embed::cosine`] now that the
//! local-Qwen embedding path shipped in Day-14b Phase 1b (Session 21,
//! 2026-05-23). The score type itself is stable; only the scoring
//! function changes. Phase 3 of the embed-wire plan switches the
//! default path to cosine when an `EmbedProvider` is wired into the
//! council orchestrator, falling back to Jaccard when no provider
//! is configured (matches the L-07 `allow_cloud_fallback: false`
//! safe-default).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Operator-visible disagreement metric.
///
/// `0.0` → all hemispheres said essentially the same thing.
/// `1.0` → no shared content. Sub-thresholds:
///   - `< 0.25` → near-consensus; verdict picks the median-length response.
///   - `0.25..0.6` → mild dissent; consensus possible if 2/3 agree.
///   - `> 0.6` → strong dissent; Split verdict, operator picks.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct DissentScore(pub f32);

impl DissentScore {
    /// Threshold below which the verdict is Consensus. Operators with
    /// stricter agreement requirements lower this; v0.1 ships at 0.25
    /// based on the [CH-12] design table.
    pub const CONSENSUS_THRESHOLD: f32 = 0.25;

    /// Threshold above which the verdict is unambiguously Split.
    pub const STRONG_DISSENT: f32 = 0.6;

    pub fn is_consensus(&self) -> bool {
        self.0 <= Self::CONSENSUS_THRESHOLD
    }

    pub fn is_strong_dissent(&self) -> bool {
        self.0 >= Self::STRONG_DISSENT
    }
}

impl Eq for DissentScore {}

/// Compute dissent across N response texts. Returns 0.0 for fewer than
/// 2 texts (nothing to compare). Each text is lowercased + tokenised
/// on whitespace + punctuation; the Jaccard distance is averaged
/// pairwise across all 2-combinations.
pub fn score_dissent(texts: &[&str]) -> DissentScore {
    if texts.len() < 2 {
        return DissentScore(0.0);
    }
    let tokenised: Vec<HashSet<String>> = texts.iter().map(|t| tokenise(t)).collect();
    let mut sum = 0.0_f32;
    let mut pairs = 0u32;
    for i in 0..tokenised.len() {
        for j in (i + 1)..tokenised.len() {
            sum += jaccard_distance(&tokenised[i], &tokenised[j]);
            pairs += 1;
        }
    }
    let avg = if pairs > 0 { sum / pairs as f32 } else { 0.0 };
    DissentScore(avg.clamp(0.0, 1.0))
}

/// Lowercase + strip punctuation + split on whitespace. Punctuation
/// stripping keeps "yes!" and "yes" tokenising the same way so
/// near-identical responses don't artificially inflate dissent.
fn tokenise(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

/// Jaccard distance = 1 - (|A ∩ B| / |A ∪ B|). 0.0 = identical, 1.0
/// = no overlap. Both sets empty → 0.0 (vacuously identical).
fn jaccard_distance(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    let intersection = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    if union == 0.0 {
        return 0.0;
    }
    1.0 - (intersection / union)
}

/// Day-14b Phase 3 — semantic dissent via embedding cosine distance.
/// Drop-in replacement for [`score_dissent`] when an `EmbedProvider`
/// is available. Catches "agreement in different words" — two
/// responses that share zero word tokens but mean the same thing
/// (e.g. "yes, confirmed" vs "affirmative, that's right") score
/// near-zero dissent under cosine but ~1.0 under Jaccard.
///
/// Algorithm: embed each text, compute pairwise `1 - cos(a, b)`
/// distance, average across all 2-combinations, clamp to `[0, 1]`.
/// Cosine of L2-normalised embeddings is bounded `[-1, 1]`; for
/// natural-language texts it's almost always `[0, 1]` so the clamp
/// only catches pathological inputs (negative-cosine vectors).
///
/// Returns `Err` when any embed call fails — callers (council
/// orchestrator) should fall back to [`score_dissent`] in that case
/// per the L-07 `allow_cloud_fallback: false` safe-default
/// pattern. Empty / single-text inputs return `Ok(DissentScore(0.0))`
/// without calling the provider.
pub async fn score_dissent_via_embedding(
    texts: &[&str],
    provider: &dyn crate::providers::embed::EmbedProvider,
) -> anyhow::Result<DissentScore> {
    use crate::providers::embed::{EmbedRequest, cosine};
    if texts.len() < 2 {
        return Ok(DissentScore(0.0));
    }
    let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(texts.len());
    for text in texts {
        let resp = provider.embed(EmbedRequest::new(text.to_string())).await?;
        vectors.push(resp.vector);
    }
    let mut sum = 0.0_f32;
    let mut pairs = 0u32;
    for i in 0..vectors.len() {
        for j in (i + 1)..vectors.len() {
            // 1 - cos = distance. Clamp to [0, 1] so the DissentScore
            // semantic invariant holds even if cos drops below 0 for
            // pathological embedding inputs.
            let distance = (1.0 - cosine(&vectors[i], &vectors[j])).clamp(0.0, 1.0);
            sum += distance;
            pairs += 1;
        }
    }
    let avg = if pairs > 0 { sum / pairs as f32 } else { 0.0 };
    Ok(DissentScore(avg.clamp(0.0, 1.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_texts_score_zero() {
        let texts = ["yes that is correct", "yes that is correct"];
        let s = score_dissent(&texts);
        assert_eq!(s.0, 0.0);
        assert!(s.is_consensus());
    }

    #[test]
    fn completely_disjoint_texts_score_one() {
        let texts = ["alpha beta gamma", "delta epsilon zeta"];
        let s = score_dissent(&texts);
        assert!((s.0 - 1.0).abs() < f32::EPSILON);
        assert!(s.is_strong_dissent());
    }

    #[test]
    fn partial_overlap_scores_between() {
        // Two texts share 2 of 4 unique words → Jaccard = 2/6 → distance ≈ 0.67
        let texts = ["a b c d", "a b e f"];
        let s = score_dissent(&texts);
        assert!(s.0 > 0.5 && s.0 < 0.8, "got {}", s.0);
    }

    #[test]
    fn punctuation_does_not_inflate_dissent() {
        // "yes!" and "yes" should tokenise the same way.
        let texts = ["yes!", "yes"];
        let s = score_dissent(&texts);
        assert_eq!(s.0, 0.0);
    }

    #[test]
    fn case_insensitive_matching() {
        let texts = ["The Answer Is Yes", "the answer is yes"];
        let s = score_dissent(&texts);
        assert_eq!(s.0, 0.0);
    }

    #[test]
    fn pairwise_average_with_three_texts() {
        // A, B identical; C disjoint from both. Pairs: (A,B)=0,
        // (A,C)=1, (B,C)=1. Average = 2/3.
        let texts = ["alpha beta", "alpha beta", "gamma delta"];
        let s = score_dissent(&texts);
        let expected = 2.0 / 3.0;
        assert!((s.0 - expected).abs() < 0.01, "got {}", s.0);
    }

    #[test]
    fn fewer_than_two_texts_returns_zero() {
        assert_eq!(score_dissent(&[]).0, 0.0);
        assert_eq!(score_dissent(&["solo"]).0, 0.0);
    }

    #[test]
    fn consensus_threshold_pinned_at_quarter() {
        // CH-12 design table baseline — pin so a refactor doesn't
        // silently shift the consensus boundary.
        assert_eq!(DissentScore::CONSENSUS_THRESHOLD, 0.25);
    }

    #[test]
    fn strong_dissent_threshold_pinned_at_sixty_percent() {
        assert_eq!(DissentScore::STRONG_DISSENT, 0.6);
    }

    #[test]
    fn empty_texts_produce_zero_distance() {
        // Two empty strings — both produce empty token sets. Vacuous
        // identical → 0.0 dissent. The defensive branch in
        // jaccard_distance ensures no divide-by-zero panic.
        let texts = ["", ""];
        let s = score_dissent(&texts);
        assert_eq!(s.0, 0.0);
    }

    // ── Phase 3 — score_dissent_via_embedding ───────────────────────

    /// Toy provider for embedding-dissent tests. Each input text maps
    /// to a canonical unit vector at slot `keyword_to_slot(text)` →
    /// cosine becomes deterministic + we can construct identical-text /
    /// orthogonal-text / opposite-axis scenarios without real weights.
    struct SlotMockEmbed {
        dim: usize,
    }

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for SlotMockEmbed {
        fn name(&self) -> &'static str {
            "slot_mock"
        }
        fn default_dim(&self) -> usize {
            self.dim
        }
        async fn embed(
            &self,
            req: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            // Slot mapping: first word of input → slot index.
            // "yes" → 0, "affirmative" → 0 (semantic agreement),
            // "no" → 1, "negative" → 1, default → last slot.
            let slot = match req.text.split_whitespace().next().unwrap_or("") {
                "yes" | "affirmative" => 0,
                "no" | "negative" => 1,
                _ => self.dim - 1,
            };
            let mut v = vec![0.0f32; self.dim];
            v[slot] = 1.0;
            Ok(crate::providers::embed::EmbedResponse {
                vector: v,
                model: "slot_mock".into(),
                latency: std::time::Duration::from_micros(1),
            })
        }
    }

    #[tokio::test]
    async fn embedding_dissent_zero_for_identical_texts() {
        let provider = SlotMockEmbed { dim: 4 };
        let texts = ["yes confirmed", "yes confirmed"];
        let s = score_dissent_via_embedding(&texts, &provider)
            .await
            .unwrap();
        assert!(
            (s.0).abs() < 1e-6,
            "identical texts: dissent ≈ 0.0, got {}",
            s.0
        );
        assert!(s.is_consensus());
    }

    #[tokio::test]
    async fn embedding_dissent_catches_semantic_agreement_jaccard_misses() {
        // "yes" and "affirmative" share zero word tokens — Jaccard
        // would score this 1.0 (max dissent). Cosine via the slot
        // mock maps both to slot 0 → dissent 0.0. This is the
        // headline win of Phase 3.
        let provider = SlotMockEmbed { dim: 4 };
        let texts = ["yes that is right", "affirmative correct"];
        let cosine_score = score_dissent_via_embedding(&texts, &provider)
            .await
            .unwrap();
        let jaccard_score = score_dissent(&texts);
        assert!(
            cosine_score.0 < 0.01,
            "embedding catches semantic agreement: dissent ≈ 0.0, got {}",
            cosine_score.0
        );
        assert!(
            jaccard_score.0 > 0.9,
            "jaccard misses semantic agreement: dissent ≈ 1.0, got {}",
            jaccard_score.0
        );
    }

    #[tokio::test]
    async fn embedding_dissent_one_for_orthogonal_texts() {
        let provider = SlotMockEmbed { dim: 4 };
        let texts = ["yes confirmed", "no rejected"];
        let s = score_dissent_via_embedding(&texts, &provider)
            .await
            .unwrap();
        // Slot 0 vs slot 1 are orthogonal → cos = 0 → distance = 1.
        assert!(
            (s.0 - 1.0).abs() < 1e-6,
            "orthogonal: dissent ≈ 1.0, got {}",
            s.0
        );
        assert!(s.is_strong_dissent());
    }

    #[tokio::test]
    async fn embedding_dissent_short_circuits_for_fewer_than_two_texts() {
        let provider = SlotMockEmbed { dim: 4 };
        let zero = score_dissent_via_embedding(&[], &provider).await.unwrap();
        assert_eq!(zero.0, 0.0);
        let one = score_dissent_via_embedding(&["solo"], &provider)
            .await
            .unwrap();
        assert_eq!(one.0, 0.0);
    }

    #[tokio::test]
    async fn embedding_dissent_pairwise_average_with_three_texts() {
        // A, B identical (both slot 0); C orthogonal (slot 1). Pairs:
        // (A,B) = 0.0, (A,C) = 1.0, (B,C) = 1.0. Average = 2/3.
        let provider = SlotMockEmbed { dim: 4 };
        let texts = ["yes one", "yes two", "no three"];
        let s = score_dissent_via_embedding(&texts, &provider)
            .await
            .unwrap();
        let expected = 2.0 / 3.0;
        assert!(
            (s.0 - expected).abs() < 1e-5,
            "got {} expected {}",
            s.0,
            expected
        );
    }

    #[tokio::test]
    async fn embedding_dissent_propagates_provider_errors() {
        // Provider that always fails — ensures the caller's fallback
        // path (use Jaccard) gets the error rather than a silent 0.0.
        struct FailingEmbed;
        #[async_trait::async_trait]
        impl crate::providers::embed::EmbedProvider for FailingEmbed {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn default_dim(&self) -> usize {
                4
            }
            async fn embed(
                &self,
                _req: crate::providers::embed::EmbedRequest,
            ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
                anyhow::bail!("provider unavailable")
            }
        }
        let provider = FailingEmbed;
        let texts = ["a", "b"];
        let err = score_dissent_via_embedding(&texts, &provider).await;
        assert!(err.is_err());
    }
}
