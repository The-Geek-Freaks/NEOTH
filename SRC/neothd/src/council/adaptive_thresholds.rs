//! CH-12 — council adaptive thresholds.
//!
//! The static CH-14 trigger thresholds (complexity ≥ 120 chars,
//! rate cooldown 60s, budget multiplier 3×, 15 dissent markers)
//! work for the typical operator but drift wrong for the extremes:
//!
//!   - **Heavy power user** writing 500-char prompts every 30s
//!     hits the rate-cooldown gate constantly + complains the
//!     council "never fires when I need it".
//!   - **Casual operator** writing 20-char prompts twice a week
//!     never hits the complexity gate + complains the council
//!     "doesn't help on the only prompts that matter".
//!
//! This module ships the **per-operator adaptive layer** that
//! adjusts the static thresholds based on the operator's
//! BehaviouralProfile (from P-01 estimators). Pure-fn surface:
//! `compute_adaptive_thresholds(&BehaviouralProfile, &BaseThresholds)`
//! returns the operator-tuned thresholds the trigger gate should
//! actually consult.
//!
//! Adaptive rules (all gated on sample_count ≥ 30 — below this
//! we don't have enough data to tune confidently):
//!   - **Complexity floor** scales with operator's median prompt
//!     length: median ≥ 200 chars → floor bumps to 250 (heavy
//!     writer needs MORE signal to convene council); median ≤ 30
//!     chars → floor drops to 40 (casual operator's "what now?"
//!     should still trigger when paired with dissent).
//!   - **Rate cooldown** scales inversely with cadence: mean-gap
//!     < 60s → cooldown drops to 20s (power user); mean-gap > 1h
//!     → cooldown bumps to 300s (casual user; council is rare so
//!     each fire matters more — don't burn the next one).

use serde::{Deserialize, Serialize};

use crate::profile::estimators::BehaviouralProfile;

/// Static baseline thresholds the trigger gate uses when adaptive
/// tuning has insufficient data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseThresholds {
    pub complexity_min_chars: u32,
    pub rate_cooldown_secs: u32,
}

impl Default for BaseThresholds {
    fn default() -> Self {
        Self {
            complexity_min_chars: 120,
            rate_cooldown_secs: 60,
        }
    }
}

/// Output of [`compute_adaptive_thresholds`] — operator-tuned
/// thresholds the trigger gate consults at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveThresholds {
    pub complexity_min_chars: u32,
    pub rate_cooldown_secs: u32,
    /// Reason the adaptive layer applied this tuning. Operator-
    /// visible in WAL trace + `neoth council status`. Owned
    /// String so the type is serde-round-trippable.
    pub reason: String,
}

/// Minimum samples before adaptive tuning kicks in. Below this we
/// return the base thresholds verbatim — adaptive on 5 samples
/// would be noise-driven.
pub const MIN_SAMPLES_FOR_ADAPTIVE: u32 = 30;

/// Heavy-writer threshold: median prompt length above this →
/// bump complexity floor.
const HEAVY_WRITER_MEDIAN: u32 = 200;
const HEAVY_WRITER_COMPLEXITY_FLOOR: u32 = 250;

/// Casual-writer threshold: median prompt length below this →
/// drop complexity floor.
const CASUAL_WRITER_MEDIAN: u32 = 30;
const CASUAL_WRITER_COMPLEXITY_FLOOR: u32 = 40;

/// Power-user cadence threshold: mean inter-turn gap below this →
/// shrink cooldown so council fires more often.
const POWER_USER_GAP_SECS: f64 = 60.0;
const POWER_USER_COOLDOWN_SECS: u32 = 20;

/// Casual-cadence threshold: mean inter-turn gap above this →
/// extend cooldown so the few council fires get max impact.
const CASUAL_USER_GAP_SECS: f64 = 3_600.0;
const CASUAL_USER_COOLDOWN_SECS: u32 = 300;

/// Compute the operator-tuned thresholds. Pure-fn — caller can
/// memoise per-operator + invalidate on next P-01 cron tick.
pub fn compute_adaptive_thresholds(
    profile: &BehaviouralProfile,
    base: &BaseThresholds,
) -> AdaptiveThresholds {
    let length_samples = profile.length.sample_count;
    let cadence_samples = profile.cadence.sample_count;

    let (complexity_min_chars, complexity_reason) = if length_samples >= MIN_SAMPLES_FOR_ADAPTIVE {
        if profile.length.median_chars >= HEAVY_WRITER_MEDIAN {
            (
                HEAVY_WRITER_COMPLEXITY_FLOOR,
                "heavy-writer complexity bump",
            )
        } else if profile.length.median_chars <= CASUAL_WRITER_MEDIAN {
            (
                CASUAL_WRITER_COMPLEXITY_FLOOR,
                "casual-writer complexity drop",
            )
        } else {
            (base.complexity_min_chars, "")
        }
    } else {
        (base.complexity_min_chars, "")
    };

    let (rate_cooldown_secs, cadence_reason) = if cadence_samples >= MIN_SAMPLES_FOR_ADAPTIVE {
        if profile.cadence.mean_gap_secs < POWER_USER_GAP_SECS {
            (POWER_USER_COOLDOWN_SECS, "power-user cooldown shrink")
        } else if profile.cadence.mean_gap_secs > CASUAL_USER_GAP_SECS {
            (CASUAL_USER_COOLDOWN_SECS, "casual-user cooldown extend")
        } else {
            (base.rate_cooldown_secs, "")
        }
    } else {
        (base.rate_cooldown_secs, "")
    };

    let reason = match (complexity_reason, cadence_reason) {
        ("", "") => "insufficient samples — base thresholds",
        ("", c) => c,
        (l, "") => l,
        _ => "heavy-writer + cadence adaptive",
    };

    AdaptiveThresholds {
        complexity_min_chars,
        rate_cooldown_secs,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::estimators::{CadenceEstimate, LengthEstimate};

    fn profile_with(
        length_samples: u32,
        median: u32,
        gap_secs: f64,
        cadence_samples: u32,
    ) -> BehaviouralProfile {
        BehaviouralProfile {
            length: LengthEstimate {
                sample_count: length_samples,
                mean_chars: median as f64,
                median_chars: median,
                p10_chars: median,
                p90_chars: median,
            },
            cadence: CadenceEstimate {
                sample_count: cadence_samples,
                mean_gap_secs: gap_secs,
                median_gap_secs: gap_secs,
                p90_gap_secs: gap_secs,
            },
            ..Default::default()
        }
    }

    #[test]
    fn base_thresholds_default_pinned() {
        let b = BaseThresholds::default();
        assert_eq!(b.complexity_min_chars, 120);
        assert_eq!(b.rate_cooldown_secs, 60);
    }

    #[test]
    fn min_samples_for_adaptive_pinned() {
        assert_eq!(MIN_SAMPLES_FOR_ADAPTIVE, 30);
    }

    #[test]
    fn insufficient_samples_returns_base_thresholds() {
        let profile = profile_with(5, 100, 90.0, 5);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.complexity_min_chars, 120);
        assert_eq!(a.rate_cooldown_secs, 60);
        assert!(a.reason.contains("base"));
    }

    #[test]
    fn heavy_writer_bumps_complexity_floor() {
        let profile = profile_with(100, 250, 90.0, 5);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.complexity_min_chars, HEAVY_WRITER_COMPLEXITY_FLOOR);
    }

    #[test]
    fn casual_writer_drops_complexity_floor() {
        let profile = profile_with(100, 20, 90.0, 5);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.complexity_min_chars, CASUAL_WRITER_COMPLEXITY_FLOOR);
    }

    #[test]
    fn medium_writer_keeps_base_complexity_floor() {
        let profile = profile_with(100, 100, 90.0, 5);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.complexity_min_chars, 120);
    }

    #[test]
    fn power_user_shrinks_cooldown() {
        let profile = profile_with(5, 100, 30.0, 100);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.rate_cooldown_secs, POWER_USER_COOLDOWN_SECS);
    }

    #[test]
    fn casual_user_extends_cooldown() {
        let profile = profile_with(5, 100, 7200.0, 100);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.rate_cooldown_secs, CASUAL_USER_COOLDOWN_SECS);
    }

    #[test]
    fn medium_cadence_keeps_base_cooldown() {
        let profile = profile_with(5, 100, 300.0, 100);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.rate_cooldown_secs, 60);
    }

    #[test]
    fn both_adaptive_reasons_combine_in_explanation() {
        // Heavy writer + power-user cadence → both tunings apply.
        let profile = profile_with(100, 250, 30.0, 100);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        assert_eq!(a.complexity_min_chars, HEAVY_WRITER_COMPLEXITY_FLOOR);
        assert_eq!(a.rate_cooldown_secs, POWER_USER_COOLDOWN_SECS);
        assert!(a.reason.contains("adaptive"));
    }

    #[test]
    fn adaptive_thresholds_serde_round_trips() {
        let profile = profile_with(100, 250, 30.0, 100);
        let a = compute_adaptive_thresholds(&profile, &BaseThresholds::default());
        let s = serde_json::to_string(&a).unwrap();
        let back: AdaptiveThresholds = serde_json::from_str(&s).unwrap();
        assert_eq!(back, a);
    }
}
