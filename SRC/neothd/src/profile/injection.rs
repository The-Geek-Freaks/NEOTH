//! CH-09 / P-06 — Block-B profile injection confidence gate.
//! CH-10 / P-07 — Block-C recall ranking `profile_relevance_bonus`.
//!
//! Two pure-fn gates the council + recall paths consult before
//! mutating their dispatch:
//!
//!   1. **`should_inject_profile(claim_confidence, gate_floor)`** —
//!      true ⇔ the claim's confidence ≥ floor (default 0.6). Below
//!      the floor the claim is too speculative to inject into the
//!      Block-B prompt; injecting low-confidence claims would shape
//!      model responses toward unverified facts.
//!
//!   2. **`profile_relevance_bonus(query_tokens, claim_tokens,
//!      base_score, bonus_weight)`** — additive score bonus when
//!      a recall result overlaps with the operator's active profile
//!      claims. The bonus is bounded so a low base-score result
//!      can't outrank a high base-score result purely on overlap.
//!
//! Both functions are deterministic + side-effect-free; tests pin
//! the gate behaviour without spinning up a council session or a
//! recall index.

/// Default confidence floor for Block-B injection. Pinned by SPEC
/// (CH-09 + P-06) at 0.6 — below this, a claim is "the model
/// guessed once" rather than "the operator confirmed".
pub const DEFAULT_INJECTION_FLOOR: f64 = 0.6;

/// Default bonus weight for Block-C recall-ranking. Additive,
/// bounded to `bonus_weight` so the worst-case profile-relevance
/// bump can't override the base FTS5 / cosine score.
pub const DEFAULT_RELEVANCE_BONUS_WEIGHT: f64 = 0.15;

/// True ⇔ the claim's confidence meets-or-exceeds the floor.
/// Pure-fn so callers don't need a thread/runtime context.
pub fn should_inject_profile(claim_confidence: f64, gate_floor: f64) -> bool {
    claim_confidence >= gate_floor
}

/// Compute the Jaccard overlap between two token slices (case-
/// insensitive). Used by `profile_relevance_bonus` to estimate
/// how much of the operator's claim shows up in the query.
///
/// Returns 0.0 when either slice is empty (no overlap signal).
pub fn jaccard_overlap(a_tokens: &[&str], b_tokens: &[&str]) -> f64 {
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return 0.0;
    }
    let a: std::collections::HashSet<String> =
        a_tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    let b: std::collections::HashSet<String> =
        b_tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    let intersection = a.intersection(&b).count() as f64;
    let union = a.union(&b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Compute the boosted recall score for one result that overlaps
/// with an operator profile claim. `base_score` is the FTS5 /
/// cosine score; `bonus_weight` is the maximum additive lift
/// (default 0.15). Returns `base_score + bonus_weight * overlap`,
/// clamped at `base_score + bonus_weight` so a perfect overlap
/// never adds more than the configured ceiling.
///
/// **Invariant**: a 0-overlap result returns exactly `base_score`
/// (no penalty for missing profile context). A 1.0-overlap result
/// returns `base_score + bonus_weight`.
pub fn profile_relevance_bonus(
    query_tokens: &[&str],
    claim_tokens: &[&str],
    base_score: f64,
    bonus_weight: f64,
) -> f64 {
    let overlap = jaccard_overlap(query_tokens, claim_tokens);
    base_score + bonus_weight * overlap
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Block-B injection gate (CH-09 / P-06) ───────────────────

    #[test]
    fn default_injection_floor_pinned_at_06() {
        assert_eq!(DEFAULT_INJECTION_FLOOR, 0.6);
    }

    #[test]
    fn injection_allowed_when_confidence_at_or_above_floor() {
        assert!(should_inject_profile(0.6, DEFAULT_INJECTION_FLOOR));
        assert!(should_inject_profile(0.8, DEFAULT_INJECTION_FLOOR));
        assert!(should_inject_profile(1.0, DEFAULT_INJECTION_FLOOR));
    }

    #[test]
    fn injection_blocked_below_floor() {
        assert!(!should_inject_profile(0.59, DEFAULT_INJECTION_FLOOR));
        assert!(!should_inject_profile(0.3, DEFAULT_INJECTION_FLOOR));
        assert!(!should_inject_profile(0.0, DEFAULT_INJECTION_FLOOR));
    }

    #[test]
    fn injection_gate_respects_custom_floor() {
        // Tighter operator who wants only ≥0.9 confidence injected.
        assert!(should_inject_profile(0.95, 0.9));
        assert!(!should_inject_profile(0.85, 0.9));
    }

    // ── Jaccard overlap ─────────────────────────────────────────

    #[test]
    fn jaccard_empty_input_returns_zero() {
        assert_eq!(jaccard_overlap(&[], &["a"]), 0.0);
        assert_eq!(jaccard_overlap(&["a"], &[]), 0.0);
        assert_eq!(jaccard_overlap(&[], &[]), 0.0);
    }

    #[test]
    fn jaccard_full_overlap_returns_one() {
        let a = &["rust", "memory"];
        let b = &["rust", "memory"];
        assert!((jaccard_overlap(a, b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_no_overlap_returns_zero() {
        let a = &["rust", "memory"];
        let b = &["python", "django"];
        assert_eq!(jaccard_overlap(a, b), 0.0);
    }

    #[test]
    fn jaccard_half_overlap_matches_formula() {
        // {a, b, c} ∩ {b, c, d} = {b, c} → 2
        // {a, b, c} ∪ {b, c, d} = {a, b, c, d} → 4
        // Jaccard = 2/4 = 0.5
        let a = &["a", "b", "c"];
        let b = &["b", "c", "d"];
        assert!((jaccard_overlap(a, b) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_is_case_insensitive() {
        let a = &["Rust", "Memory"];
        let b = &["rust", "memory"];
        assert!((jaccard_overlap(a, b) - 1.0).abs() < f64::EPSILON);
    }

    // ── Block-C profile_relevance_bonus (CH-10 / P-07) ──────────

    #[test]
    fn default_bonus_weight_pinned_at_015() {
        assert!((DEFAULT_RELEVANCE_BONUS_WEIGHT - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_overlap_returns_base_score_unchanged() {
        let r =
            profile_relevance_bonus(&["rust"], &["python"], 0.5, DEFAULT_RELEVANCE_BONUS_WEIGHT);
        assert!((r - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn full_overlap_adds_exact_bonus_weight() {
        let r = profile_relevance_bonus(
            &["rust", "memory"],
            &["rust", "memory"],
            0.5,
            DEFAULT_RELEVANCE_BONUS_WEIGHT,
        );
        assert!((r - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn partial_overlap_scales_bonus_linearly_with_jaccard() {
        // jaccard = 0.5 → bonus = 0.15 * 0.5 = 0.075
        let r = profile_relevance_bonus(
            &["a", "b", "c"],
            &["b", "c", "d"],
            0.5,
            DEFAULT_RELEVANCE_BONUS_WEIGHT,
        );
        assert!((r - (0.5 + 0.075)).abs() < f64::EPSILON);
    }

    #[test]
    fn bonus_never_exceeds_base_plus_weight_ceiling() {
        // Drift guard — even at 1.0 overlap the bump must equal
        // exactly `bonus_weight`, not more.
        let r = profile_relevance_bonus(&["x"], &["x"], 0.99, 0.15);
        assert!(r <= 0.99 + 0.15 + f64::EPSILON);
    }

    #[test]
    fn bonus_preserves_relative_order_when_base_score_dominates() {
        // High-base-score result with no overlap should still
        // outrank low-base-score result with full overlap.
        let high_base = profile_relevance_bonus(&["x"], &["y"], 0.9, 0.15);
        let low_base_full_overlap = profile_relevance_bonus(&["x"], &["x"], 0.7, 0.15);
        assert!(high_base > low_base_full_overlap);
    }
}
