//! GOLD-DELTA-01 — `BabelConfig`, the `babel:` block in `freedom.yaml`.
//!
//! Design rules (see `analytics/babel/mod.rs` + the WS-DELTA tracker section):
//! the observer itself is default-ON (it never blocks inference and never
//! leaves the machine), while `federate` — the ONLY egress path — is
//! default-OFF and additionally consent-gated at runtime by
//! `federation::ConsentGate` (AutonomyLevel >= Elevated + calibration
//! maturity). Every field carries a serde default so existing
//! `freedom.yaml` files parse unchanged.

use serde::{Deserialize, Serialize};

/// The `babel:` configuration block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BabelConfig {
    /// Master switch for the Babel-Index observer (window accumulation,
    /// scoring, SQLite persistence). Local-only; no egress.
    pub enabled: bool,
    /// Cron tick cadence in seconds. Window boundaries are independent of
    /// the tick; a slower tick only delays window close detection.
    pub tick_interval_secs: u64,
    /// Normalized `B_d` warning threshold on the 15-minute window. Crossing
    /// it emits a `tracing::warn!` (no WAL event — byte space exhausted).
    /// Operator-tunable; 0.8 is a pre-calibration placebo default and is
    /// expected to be revisited once `epsilon_calibrated` freezes.
    pub threshold: f64,
    /// Cold-start `V_MAX` (tokens/sec p99 stand-in) used until the norm
    /// table has real p99 data. Mirrors `feature.rs` cold-start default.
    pub v_max_default: f64,
    /// Frozen epsilon for the multiplicative form, written back exactly once
    /// by `norm::compute_calibration_epsilon` (pre-hoc rule:
    /// `0.01 x median((D/A) x (H/V))` over the first 10% of windows).
    /// `None` = not yet calibrated.
    pub epsilon_calibrated: Option<f64>,
    /// Feed memory-subsystem signals (contradiction ledger, recall misses)
    /// into feature extraction.
    pub memory_signals: bool,
    /// Feed skill-router signals (routing misses, low-weight dispatches)
    /// into feature extraction.
    pub skill_signals: bool,
    /// Federation opt-in. Default FALSE — sharing anonymized window records
    /// with other NEOTH instances only happens when the operator explicitly
    /// enables this AND the runtime consent gate passes.
    pub federate: bool,
    /// iroh endpoint id (hex) of the delta-kosmologie aggregation node.
    /// `None` = no live transport — queued batches stay in
    /// `~/.neoth/babel/pending/` for a later drain or manual upload.
    pub federation_endpoint: Option<String>,
    /// GOLD-DELTA panel decision Q1 (2026-07-02, unanimous): optional named
    /// sentence-embedding checkpoint for K_d. The NAME lives here in config
    /// (model-version-agnostic rule — never in code). `None` = the shipped
    /// K_d_v0 token-frequency histogram (khist feed). NOTE: the embedding
    /// implementation is a post-GOLD item; v1.0 reads but does not yet act
    /// on this field, and `algorithm_versions.k` stratifies the two methods
    /// per-row so mixed-method pools stay analyzable.
    pub k_d_embedding_model: Option<String>,
    /// Export serialization for `neoth babel export`. Currently `jsonl`.
    pub export_format: String,
}

impl Default for BabelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tick_interval_secs: 60,
            threshold: 0.8,
            v_max_default: 150.0,
            epsilon_calibrated: None,
            memory_signals: true,
            skill_signals: true,
            federate: false,
            federation_endpoint: None,
            k_d_embedding_model: None,
            export_format: "jsonl".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled_but_never_federates() {
        let c = BabelConfig::default();
        assert!(c.enabled, "observer is default-ON (local-only)");
        assert!(!c.federate, "egress is default-OFF (consent-first)");
        assert!(c.epsilon_calibrated.is_none());
    }

    #[test]
    fn empty_yaml_mapping_parses_to_defaults() {
        let c: BabelConfig = serde_yaml::from_str("{}").expect("empty mapping parses");
        assert_eq!(c, BabelConfig::default());
    }

    #[test]
    fn partial_yaml_keeps_other_defaults() {
        let c: BabelConfig =
            serde_yaml::from_str("federate: true\ntick_interval_secs: 30\n").expect("parses");
        assert!(c.federate);
        assert_eq!(c.tick_interval_secs, 30);
        assert!(c.enabled, "unspecified fields keep defaults");
        assert_eq!(c.export_format, "jsonl");
    }

    #[test]
    fn yaml_roundtrip_is_lossless() {
        let mut c = BabelConfig::default();
        c.epsilon_calibrated = Some(0.0123);
        let y = serde_yaml::to_string(&c).expect("serializes");
        let back: BabelConfig = serde_yaml::from_str(&y).expect("parses back");
        assert_eq!(c, back);
    }
}
