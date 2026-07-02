//! Babel score computation — all candidate forms.
//!
//! ## Epsilon governance (from review brief HIGH/falsifiability)
//!
//! Primary form: **log form** — no epsilon, mathematically identical to
//! B_mult up to a constant when D,H > 0.  Used for all cross-instance
//! pooled analysis.
//!
//! Multiplicative form (simplified ratio form, upstream fix `a4bd367`):
//! `B_mult = norm((C*K*M) / ((D/A)*(H/V) + epsilon))` — A and V enter as
//! load/capacity ratios, never as bare numerator terms. Epsilon =
//! `0.01 * median((D/A)*(H/V))` over the first 10% of the instance's data
//! (frozen as `epsilon_calibrated` in `BabelConfig` after calibration).
//! The epsilon value AND the rule string
//! ("0.01_median_buffer_ratio_calibration") are included in every
//! federated record.
//!
//! B_bottleneck: min(C,K,M,A,V) / max(D,H) — captures the weakest amplifier
//! over the strongest buffer.  No epsilon needed.
//!
//! All three forms are computed and stored in `candidate_scores`; the log form
//! is the primary discriminator for pooled falsification.

use serde::{Deserialize, Serialize};

use super::feature::BabelFeatures;
use super::norm::Normaliser;

/// All candidate B_d score forms for one window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BabelScores {
    /// Primary form for cross-instance pooled analysis (no epsilon needed).
    /// log(C) + log(K) + log(M) + log(A) + log(V) - log(D) - log(H).
    /// None when any numerator variable is 0.0 (log undefined).
    pub b_log: Option<f64>,
    /// Multiplicative form, normalised by the per-instance Normaliser.
    /// Requires epsilon > 0 (governed by epsilon_value + epsilon_rule).
    pub b_mult: Option<f64>,
    /// Epsilon value used for b_mult (pre-registered, not post-hoc).
    pub b_mult_epsilon: Option<f64>,
    /// Epsilon governance rule string (pinned in protocol spec).
    pub b_mult_epsilon_rule: String,
    /// Bottleneck form: min(C,K,M,A,V) / max(D,H).
    pub b_bottleneck: f64,
}

impl BabelScores {
    /// Compute all candidate scores from validated features.
    ///
    /// `epsilon`: when Some, used for the multiplicative form.
    ///           When None, b_mult is also None (not emitted).
    pub fn compute(f: &BabelFeatures, normaliser: &Normaliser, epsilon: Option<f64>) -> Self {
        let b_log = compute_log_form(f);
        let b_bottleneck = compute_bottleneck(f);
        // Simplified ratio form: (C*K*M) / ((D/A)*(H/V) + eps). A or V at
        // zero would make the buffer ratios undefined (0/0 when D or H is
        // also zero) — treat like the log form and emit no score.
        let (b_mult, b_mult_epsilon) = match epsilon {
            Some(eps) if eps > 0.0 && f.a > 0.0 && f.v > 0.0 => {
                let raw = (f.c * f.k * f.m)
                    / ((f.d / f.a) * (f.h / f.v) + eps);
                let normed = normaliser.normalise(raw);
                (Some(normed), Some(eps))
            }
            _ => (None, None),
        };
        Self {
            b_log,
            b_mult,
            b_mult_epsilon,
            b_mult_epsilon_rule: "0.01_median_buffer_ratio_calibration".into(),
            b_bottleneck,
        }
    }
}

/// log(C) + log(K) + log(M) + log(A/D) + log(V/H) — expanded below as
/// individual ln() terms (algebraically identical for positive inputs).
/// Returns None if any numerator variable is <= 0 (log undefined).
fn compute_log_form(f: &BabelFeatures) -> Option<f64> {
    if f.c <= 0.0 || f.k <= 0.0 || f.m <= 0.0 || f.a <= 0.0 || f.v <= 0.0 {
        return None;
    }
    Some(
        f.c.ln() + f.k.ln() + f.m.ln() + f.a.ln() + f.v.ln()
        - f.d.ln() - f.h.ln()
    )
}

/// min(C,K,M,A,V) / max(D,H).
fn compute_bottleneck(f: &BabelFeatures) -> f64 {
    let numerator_min = f.c.min(f.k).min(f.m).min(f.a).min(f.v);
    let denominator_max = f.d.max(f.h);
    if denominator_max <= 0.0 { return 0.0; }
    numerator_min / denominator_max
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::feature::FeatureAlgorithmVersions;
    use super::super::norm::Normaliser;

    fn sample_features() -> BabelFeatures {
        BabelFeatures {
            c: 0.62, k: 0.71, m: 0.56, a: 0.48, v: 0.68,
            d: 0.44, h: 0.39,
            algorithm_versions: FeatureAlgorithmVersions::default(),
        }
    }

    #[test]
    fn log_form_is_finite_for_positive_features() {
        let f = sample_features();
        let s = compute_log_form(&f);
        assert!(s.is_some(), "should compute when all > 0");
        assert!(s.unwrap().is_finite());
    }

    #[test]
    fn log_form_is_none_when_c_is_zero() {
        let mut f = sample_features();
        f.c = 0.0;
        assert!(compute_log_form(&f).is_none());
    }

    #[test]
    fn bottleneck_is_ratio_of_min_over_max() {
        let f = sample_features();
        // min(0.62,0.71,0.56,0.48,0.68) = 0.48; max(0.44,0.39) = 0.44
        let expected = 0.48 / 0.44;
        let got = compute_bottleneck(&f);
        assert!((got - expected).abs() < 1e-9);
    }

    #[test]
    fn scores_emit_no_b_mult_when_epsilon_none() {
        let f = sample_features();
        let norm = Normaliser::cold_start();
        let s = BabelScores::compute(&f, &norm, None);
        assert!(s.b_mult.is_none());
        assert!(s.b_mult_epsilon.is_none());
    }

    #[test]
    fn scores_emit_b_mult_when_epsilon_provided() {
        let f = sample_features();
        let norm = Normaliser::cold_start();
        let s = BabelScores::compute(&f, &norm, Some(0.01));
        assert!(s.b_mult.is_some());
        assert_eq!(s.b_mult_epsilon, Some(0.01));
        assert_eq!(
            s.b_mult_epsilon_rule.as_str(),
            "0.01_median_buffer_ratio_calibration"
        );
    }

    #[test]
    fn scores_emit_no_b_mult_when_agent_density_is_zero() {
        // a = 0 makes the D/A buffer ratio undefined — the ratio form must
        // decline to score, exactly like the log form does.
        let mut f = sample_features();
        f.a = 0.0;
        let norm = Normaliser::cold_start();
        let s = BabelScores::compute(&f, &norm, Some(0.01));
        assert!(s.b_mult.is_none());
        assert!(s.b_mult_epsilon.is_none());
    }
}
