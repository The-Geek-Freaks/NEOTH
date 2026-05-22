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
}
