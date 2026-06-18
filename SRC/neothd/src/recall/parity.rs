//! ARCH-05 / SPEC-08 — recall-parity scoring math.
//!
//! The deterministic, side-effect-free core of the Jarvis→NEOTH migration gate
//! (`PLAN/SPEC_recall_parity_methodology.md`). These pure functions are what
//! make the gate REAL + `cargo test`-verifiable: given grader sheets (NEOTH vs
//! a reference system, scored 0–5 Likert across 5 dimensions), they compute the
//! inter-rater Cohen's kappa, the kappa-adjusted weighted-harmonic parity
//! score, and CRITICAL-divergence classification.
//!
//! What is DELIBERATELY out of scope here (genuinely operator-operational, not
//! theater): the live 14-day shadow-run against the real Jarvis, the human
//! grading itself, and identity cross-contamination detection (needs the live
//! human_uuid). Those produce the grade files this module SCORES — the file
//! format ([`super::goldset`]) is the contract, and these functions are the
//! trusted scorer that already exists when the grades land.

/// The 5 grading dimensions + their parity weights (SPEC §3/§6). Higher weight
/// = a harder failure (a wrong fact is unacceptable; verbosity is merely
/// annoying).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    Factual,
    Completeness,
    OnTone,
    Usefulness,
    Brevity,
}

impl Dimension {
    pub const ALL: [Dimension; 5] = [
        Dimension::Factual,
        Dimension::Completeness,
        Dimension::OnTone,
        Dimension::Usefulness,
        Dimension::Brevity,
    ];

    pub fn weight(self) -> f64 {
        match self {
            Dimension::Factual | Dimension::Completeness | Dimension::Usefulness => 1.5,
            Dimension::OnTone | Dimension::Brevity => 1.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Factual => "factual",
            Dimension::Completeness => "completeness",
            Dimension::OnTone => "on_tone",
            Dimension::Usefulness => "usefulness",
            Dimension::Brevity => "brevity",
        }
    }

    /// SPEC §7.1 absolute-quality floor — the mean NEOTH score (0–5) this
    /// dimension must clear REGARDLESS of parity. Parity alone is
    /// NEOTH-relative-to-Jarvis; if Jarvis itself is bad, 85% parity of a 2/5
    /// Jarvis is still useless. This is the gate's defence against passing on a
    /// low-quality baseline.
    pub fn absolute_floor(self) -> f64 {
        match self {
            Dimension::Factual | Dimension::Usefulness => 3.5,
            Dimension::Completeness | Dimension::OnTone | Dimension::Brevity => 3.0,
        }
    }
}

/// Pass threshold for the aggregate parity score (SPEC §6): NEOTH must reach
/// ≥ 0.85 of Jarvis's graded quality, kappa-reliability-weighted.
pub const PARITY_PASS_THRESHOLD: f64 = 0.85;

/// Per-query CRITICAL floor (SPEC §7): a factual/usefulness kappa-parity below
/// this aborts the migration regardless of the aggregate.
pub const CRITICAL_FLOOR: f64 = 0.50;

/// SPEC §5 inter-rater reliability floor: the mean kappa must clear this or the
/// rubric is too under-specified to trust the grades (re-grade required). The
/// gate fails when unmet — distinct from a low-quality FAIL.
pub const KAPPA_RELIABILITY_FLOOR: f64 = 0.60;

/// Maximum valid Likert score (0..=5).
pub const LIKERT_MAX: u8 = 5;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParityError {
    #[error("grader score slices differ in length ({a} vs {b})")]
    LengthMismatch { a: usize, b: usize },
    #[error("empty grader score slice")]
    Empty,
    #[error("Likert score {0} out of range (0..={LIKERT_MAX})")]
    LikertOutOfRange(u8),
    #[error("dimension parity/weight slices mismatch ({p} parities vs {w} weights)")]
    DimMismatch { p: usize, w: usize },
}

/// Pairwise Cohen's kappa with the SPEC §5 "within 1 Likert point = agreement"
/// definition. `a`/`b` are the two graders' scores (0..=5) for the SAME ordered
/// set of (query, dimension) observations.
///
/// `p_o` = fraction of observations where `|a_i − b_i| ≤ 1`. `p_e` = the
/// expected within-1 agreement under independence, computed from each grader's
/// marginal score distribution: `Σ_{|i−j|≤1} P_a(i)·P_b(j)`. `kappa = (p_o −
/// p_e)/(1 − p_e)`, clamped so a degenerate `p_e ≥ 1` (both graders constant +
/// within 1) yields perfect agreement `1.0`.
pub fn cohen_kappa_within1(a: &[u8], b: &[u8]) -> Result<f64, ParityError> {
    if a.len() != b.len() {
        return Err(ParityError::LengthMismatch {
            a: a.len(),
            b: b.len(),
        });
    }
    if a.is_empty() {
        return Err(ParityError::Empty);
    }
    for &s in a.iter().chain(b.iter()) {
        if s > LIKERT_MAX {
            return Err(ParityError::LikertOutOfRange(s));
        }
    }
    let n = a.len() as f64;
    let agreements = a
        .iter()
        .zip(b.iter())
        .filter(|(x, y)| x.abs_diff(**y) <= 1)
        .count() as f64;
    let p_o = agreements / n;

    // Marginal distributions over 0..=5.
    let mut pa = [0.0f64; 6];
    let mut pb = [0.0f64; 6];
    for &s in a {
        pa[s as usize] += 1.0 / n;
    }
    for &s in b {
        pb[s as usize] += 1.0 / n;
    }
    let mut p_e = 0.0;
    for (i, &pai) in pa.iter().enumerate() {
        for (j, &pbj) in pb.iter().enumerate() {
            if i.abs_diff(j) <= 1 {
                p_e += pai * pbj;
            }
        }
    }
    if p_e >= 1.0 {
        // Chance agreement is already total — graders cannot do "better than
        // chance"; treat as perfect (the SPEC's poor/strong bands never reach
        // here in practice).
        return Ok(1.0);
    }
    Ok((p_o - p_e) / (1.0 - p_e))
}

/// Per-query per-dimension raw parity (SPEC §6): `neoth / jarvis`, clamped to
/// `[0,1]`. A `jarvis == 0` baseline yields `1.0` (NEOTH meets-or-exceeds a
/// zero baseline), matching the SPEC's edge-case rule.
pub fn parity_raw(neoth: f64, jarvis: f64) -> f64 {
    // Fail-closed on invalid (negative / NaN) inputs — Likert is 0..=5, so a
    // negative score is corrupt data and must not produce a misleading 1.0.
    if !neoth.is_finite() || !jarvis.is_finite() || neoth < 0.0 || jarvis < 0.0 {
        return 0.0;
    }
    if jarvis == 0.0 {
        // SPEC §6: a zero Jarvis baseline ⇒ NEOTH meets-or-exceeds it. (The
        // absolute-quality floor — not parity — guards the "both bad" case.)
        return 1.0;
    }
    (neoth / jarvis).clamp(0.0, 1.0)
}

/// Kappa-adjusted per-dimension parity (SPEC §6): the mean of the per-query raw
/// parities, scaled by that dimension's inter-rater reliability `kappa`.
pub fn parity_kappa_dim(per_query_parities: &[f64], kappa: f64) -> Result<f64, ParityError> {
    if per_query_parities.is_empty() {
        return Err(ParityError::Empty);
    }
    let mean = per_query_parities.iter().sum::<f64>() / per_query_parities.len() as f64;
    Ok(mean * kappa)
}

/// Weighted harmonic mean of the per-dimension kappa-parities (SPEC §6):
/// `Σw / Σ(w/parity)`. A zero parity (an infinite harmonic term ⇒ the system
/// totally failed a dimension) yields `0.0` — the gate fails, which is correct.
pub fn parity_aggregate(dim_parity_kappa: &[(f64, f64)]) -> Result<f64, ParityError> {
    if dim_parity_kappa.is_empty() {
        return Err(ParityError::Empty);
    }
    let sum_w: f64 = dim_parity_kappa.iter().map(|(_, w)| w).sum();
    let mut denom = 0.0;
    for &(parity, w) in dim_parity_kappa {
        if parity <= 0.0 {
            // Total failure on a weighted dimension ⇒ aggregate is 0 (fail).
            return Ok(0.0);
        }
        denom += w / parity;
    }
    if denom <= 0.0 {
        return Ok(0.0);
    }
    Ok(sum_w / denom)
}

/// The reason a per-query response is CRITICAL (SPEC §7). Identity
/// cross-contamination is intentionally absent — it needs the live human_uuid
/// and is checked operator-side, not in this pure scorer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriticalReason {
    FactualBelow50,
    UsefulnessBelow50,
    EmptyResponse,
    ErrorText,
}

/// Per-query divergence class (SPEC §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DivergenceClass {
    Clean,
    Critical(CriticalReason),
}

impl DivergenceClass {
    pub fn is_critical(&self) -> bool {
        matches!(self, DivergenceClass::Critical(_))
    }
}

/// Classify one query's NEOTH response (SPEC §7). CRITICAL if the factual or
/// usefulness kappa-parity for the query is below [`CRITICAL_FLOOR`], or the
/// response is empty / carries error text. Checked in priority order so the
/// most severe reason is reported.
pub fn classify_divergence(
    factual_parity_kappa: f64,
    usefulness_parity_kappa: f64,
    neoth_text: &str,
) -> DivergenceClass {
    let trimmed = neoth_text.trim();
    if trimmed.is_empty() {
        return DivergenceClass::Critical(CriticalReason::EmptyResponse);
    }
    if looks_like_error_text(trimmed) {
        return DivergenceClass::Critical(CriticalReason::ErrorText);
    }
    if factual_parity_kappa < CRITICAL_FLOOR {
        return DivergenceClass::Critical(CriticalReason::FactualBelow50);
    }
    if usefulness_parity_kappa < CRITICAL_FLOOR {
        return DivergenceClass::Critical(CriticalReason::UsefulnessBelow50);
    }
    DivergenceClass::Clean
}

/// Per-query divergence from the kappa-parity scores ALONE (no response text).
/// Used by the grade-based gate scorer ([`super::parity_run`]): an empty/error
/// NEOTH response is graded factual≈0 by the graders, so the factual floor
/// already catches it — the explicit text check is for a live-response monitor
/// (the [`classify_divergence`] variant), not the graded path.
pub fn classify_divergence_scores(
    factual_parity_kappa: f64,
    usefulness_parity_kappa: f64,
) -> DivergenceClass {
    if factual_parity_kappa < CRITICAL_FLOOR {
        return DivergenceClass::Critical(CriticalReason::FactualBelow50);
    }
    if usefulness_parity_kappa < CRITICAL_FLOOR {
        return DivergenceClass::Critical(CriticalReason::UsefulnessBelow50);
    }
    DivergenceClass::Clean
}

/// Heuristic: does the NEOTH response read as an error/refusal rather than an
/// answer? Conservative — only fires on unambiguous error markers so a real
/// answer that merely mentions "error" isn't misflagged.
fn looks_like_error_text(text: &str) -> bool {
    let head: String = text.chars().take(64).collect::<String>().to_lowercase();
    head.starts_with("error:")
        || head.starts_with("error ")
        || head.starts_with("[error")
        || head.starts_with("traceback")
        || head.starts_with("panic")
        || head.contains("internal server error")
}

/// Full gate verdict (SPEC §10): `passed` ⇒ ALL of — aggregate ≥ 0.85
/// (parity), every dimension's absolute-quality floor met (§7.1), zero CRITICAL
/// divergences (§7), AND mean inter-rater kappa ≥ 0.60 (§5 reliability). Any one
/// failing fails the gate (fail-closed — a wrong PASS authorises an
/// irreversible memory cutover).
#[derive(Debug, Clone, PartialEq)]
pub struct ParityVerdict {
    pub aggregate: f64,
    pub threshold: f64,
    pub critical_count: usize,
    pub absolute_floors_met: bool,
    pub kappa_gate_met: bool,
    pub passed: bool,
}

/// Compose the final verdict. `absolute_floors_met` comes from comparing each
/// dimension's mean NEOTH score to [`Dimension::absolute_floor`]; `mean_kappa`
/// is the mean inter-rater agreement.
pub fn parity_verdict(
    aggregate: f64,
    divergences: &[DivergenceClass],
    absolute_floors_met: bool,
    mean_kappa: f64,
) -> ParityVerdict {
    let critical_count = divergences.iter().filter(|d| d.is_critical()).count();
    let kappa_gate_met = mean_kappa >= KAPPA_RELIABILITY_FLOOR;
    ParityVerdict {
        aggregate,
        threshold: PARITY_PASS_THRESHOLD,
        critical_count,
        absolute_floors_met,
        kappa_gate_met,
        passed: aggregate >= PARITY_PASS_THRESHOLD
            && critical_count == 0
            && absolute_floors_met
            && kappa_gate_met,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kappa_length_and_empty_guards() {
        assert_eq!(
            cohen_kappa_within1(&[1, 2], &[1]),
            Err(ParityError::LengthMismatch { a: 2, b: 1 })
        );
        assert_eq!(cohen_kappa_within1(&[], &[]), Err(ParityError::Empty));
        assert_eq!(
            cohen_kappa_within1(&[6], &[1]),
            Err(ParityError::LikertOutOfRange(6))
        );
    }

    #[test]
    fn kappa_perfect_within1_agreement_is_high() {
        // Spread scores so chance agreement isn't total; graders always within 1.
        let a = [0u8, 1, 2, 3, 4, 5, 0, 2, 4, 1];
        let b = [1u8, 1, 3, 3, 5, 5, 0, 3, 4, 2];
        let k = cohen_kappa_within1(&a, &b).unwrap();
        assert!(
            k > 0.0 && k <= 1.0,
            "within-1 agreement ⇒ positive kappa: {k}"
        );
    }

    #[test]
    fn kappa_systematic_disagreement_is_low_or_negative() {
        // One grader low, the other high, never within 1.
        let a = [0u8, 0, 1, 0, 1, 0];
        let b = [5u8, 4, 5, 5, 4, 5];
        let k = cohen_kappa_within1(&a, &b).unwrap();
        assert!(k <= 0.0, "no within-1 agreement ⇒ kappa <= 0: {k}");
    }

    #[test]
    fn parity_raw_edge_cases() {
        assert_eq!(parity_raw(0.0, 0.0), 1.0);
        assert_eq!(parity_raw(3.0, 0.0), 1.0, "zero baseline ⇒ NEOTH meets it");
        assert_eq!(parity_raw(4.0, 4.0), 1.0);
        assert_eq!(parity_raw(2.0, 4.0), 0.5);
        assert_eq!(parity_raw(8.0, 4.0), 1.0, "clamped to 1.0");
    }

    #[test]
    fn parity_aggregate_matches_spec_worked_example() {
        // SPEC §6 example: parity_kappa values + weights ⇒ 0.611 (FAIL).
        let dims = [
            (0.655, 1.5), // factual
            (0.598, 1.5), // completeness
            (0.512, 1.0), // on_tone
            (0.668, 1.5), // usefulness
            (0.607, 1.0), // brevity
        ];
        let agg = parity_aggregate(&dims).unwrap();
        assert!(
            (agg - 0.611).abs() < 0.005,
            "SPEC example ⇒ ~0.611, got {agg}"
        );
        assert!(
            agg < PARITY_PASS_THRESHOLD,
            "the SPEC example FAILS the gate"
        );
    }

    #[test]
    fn parity_aggregate_zero_dimension_fails_closed() {
        let dims = [(0.9, 1.5), (0.0, 1.5), (0.9, 1.0)];
        assert_eq!(parity_aggregate(&dims).unwrap(), 0.0);
    }

    #[test]
    fn parity_kappa_dim_is_mean_times_kappa() {
        let pk = parity_kappa_dim(&[0.8, 0.9, 1.0], 0.5).unwrap();
        assert!(
            (pk - 0.45).abs() < 1e-9,
            "mean 0.9 * kappa 0.5 = 0.45, got {pk}"
        );
    }

    #[test]
    fn divergence_empty_and_error_are_critical() {
        assert_eq!(
            classify_divergence(0.9, 0.9, "   "),
            DivergenceClass::Critical(CriticalReason::EmptyResponse)
        );
        assert_eq!(
            classify_divergence(0.9, 0.9, "Error: provider timed out"),
            DivergenceClass::Critical(CriticalReason::ErrorText)
        );
        assert_eq!(
            classify_divergence(0.9, 0.9, "Traceback (most recent call last)"),
            DivergenceClass::Critical(CriticalReason::ErrorText)
        );
    }

    #[test]
    fn divergence_factual_and_usefulness_floors() {
        assert_eq!(
            classify_divergence(0.49, 0.9, "a fine answer"),
            DivergenceClass::Critical(CriticalReason::FactualBelow50)
        );
        assert_eq!(
            classify_divergence(0.9, 0.4, "a fine answer"),
            DivergenceClass::Critical(CriticalReason::UsefulnessBelow50)
        );
        assert_eq!(
            classify_divergence(0.9, 0.9, "a fine answer"),
            DivergenceClass::Clean
        );
        // A real answer that merely mentions the word error is NOT critical.
        assert_eq!(
            classify_divergence(0.9, 0.9, "The error budget for the SLO is 0.1%"),
            DivergenceClass::Clean
        );
    }

    #[test]
    fn verdict_requires_all_four_gates() {
        let clean = [DivergenceClass::Clean, DivergenceClass::Clean];
        // All four gates met ⇒ PASS.
        assert!(parity_verdict(0.90, &clean, true, 0.70).passed);
        // One CRITICAL ⇒ FAIL (a single CRITICAL aborts, SPEC §7).
        let v = parity_verdict(
            0.95,
            &[
                DivergenceClass::Clean,
                DivergenceClass::Critical(CriticalReason::FactualBelow50),
            ],
            true,
            0.70,
        );
        assert!(!v.passed);
        assert_eq!(v.critical_count, 1);
        // Below parity threshold ⇒ FAIL even if everything else is fine.
        assert!(!parity_verdict(0.84, &clean, true, 0.70).passed);
        // Absolute floor NOT met ⇒ FAIL even at high parity (the §7.1
        // "parity against an unvalidated Jarvis" gap — the false-PASS the
        // review found).
        let v = parity_verdict(1.0, &clean, false, 0.90);
        assert!(!v.passed, "high parity but floors unmet must FAIL");
        assert!(!v.absolute_floors_met);
        // Kappa below the §5 reliability floor ⇒ FAIL (rubric untrustworthy).
        let v = parity_verdict(0.95, &clean, true, 0.45);
        assert!(!v.passed, "low inter-rater kappa must FAIL");
        assert!(!v.kappa_gate_met);
    }

    #[test]
    fn parity_raw_rejects_negative_and_nan() {
        assert_eq!(parity_raw(-1.0, 4.0), 0.0, "negative neoth ⇒ fail-closed");
        assert_eq!(parity_raw(3.0, -2.0), 0.0, "negative jarvis ⇒ fail-closed");
        assert_eq!(parity_raw(f64::NAN, 4.0), 0.0);
    }

    #[test]
    fn absolute_floors_are_the_spec_values() {
        assert_eq!(Dimension::Factual.absolute_floor(), 3.5);
        assert_eq!(Dimension::Usefulness.absolute_floor(), 3.5);
        assert_eq!(Dimension::Completeness.absolute_floor(), 3.0);
        assert_eq!(Dimension::OnTone.absolute_floor(), 3.0);
        assert_eq!(Dimension::Brevity.absolute_floor(), 3.0);
    }
}
