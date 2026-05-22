//! Ouro LoopLM model — config + forward-pass scaffolding (O-1).
//!
//! v0.1 scope: `OuroConfig` deserialiser for the published HF
//! `config.json` shape, plus the `Ouro` model struct shell that
//! holds the 24 shared layers + total_ut_steps loop count + the
//! sub-modules (`OuroLayer`, `OuroAttention`, `OuroMLP`).
//!
//! Forward pass + sampling lands in O-1b once the candle nn
//! plumbing is in place. This commit pins the data shape so the
//! Provider impl (O-2) compiles against a stable surface.

use serde::Deserialize;

/// Default loop-step count when `config.json` doesn't pin one.
/// Matches the published Ouro paper's training-time default.
pub const DEFAULT_TOTAL_UT_STEPS: usize = 4;

/// Hard ceiling on `total_ut_steps` regardless of operator override.
/// Above 8 the cost per token grows faster than any measurable
/// reasoning gain; values >8 are wasted compute. Validation in
/// `OuroConfig::validate` clamps + warns.
pub const MAX_TOTAL_UT_STEPS: usize = 8;

/// On-disk Ouro config (matches HF `ByteDance/Ouro-*` `config.json`).
///
/// Fields without `#[serde(default)]` are required — a missing field
/// surfaces as a deserialise error so the operator gets a clear
/// "your Ouro config.json is broken" message rather than a silent
/// inference bug downstream.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct OuroConfig {
    pub vocab_size: usize,
    pub hidden_size: usize,
    pub intermediate_size: usize,
    /// "num_hidden_layers" in HF parlance — the count of *unique*
    /// layers. Ouro applies these `total_ut_steps` times.
    pub num_hidden_layers: usize,
    pub num_attention_heads: usize,
    pub max_position_embeddings: usize,
    pub rope_theta: f64,
    pub rms_norm_eps: f64,
    /// Loop count — the headline LoopLM hyperparameter. Same layer
    /// stack runs N times before producing each output token. The
    /// shipped Ouro checkpoints train with `total_ut_steps = 4`.
    #[serde(default = "default_total_ut_steps")]
    pub total_ut_steps: usize,
    /// Optional early-exit threshold — when hidden-state entropy
    /// falls below this on loop N<total_ut_steps, stop early. None
    /// = always run all loops (safe default; deterministic latency).
    #[serde(default)]
    pub early_exit_threshold: Option<f32>,
    /// `model_type` from HF — pinned to `"ouro"` for validation.
    /// Other values reject in `validate`.
    #[serde(default)]
    pub model_type: Option<String>,
    /// Tokeniser type, when present. Operator-readable diagnostic
    /// only; the candle tokenizer crate handles the actual parse
    /// from `tokenizer.json`.
    #[serde(default)]
    pub tokenizer_class: Option<String>,
}

fn default_total_ut_steps() -> usize {
    DEFAULT_TOTAL_UT_STEPS
}

impl OuroConfig {
    /// Clamp `total_ut_steps` to `[1, MAX_TOTAL_UT_STEPS]` + verify
    /// the basic shape invariants candle's tensor math depends on.
    /// Returns `Err` on impossible shapes (zero heads, hidden not
    /// divisible by heads, etc).
    pub fn validate(&self) -> anyhow::Result<OuroConfig> {
        if self.num_attention_heads == 0 {
            anyhow::bail!("Ouro config: num_attention_heads must be > 0");
        }
        if self.hidden_size % self.num_attention_heads != 0 {
            anyhow::bail!(
                "Ouro config: hidden_size ({}) must be divisible by num_attention_heads ({})",
                self.hidden_size,
                self.num_attention_heads
            );
        }
        if self.num_hidden_layers == 0 {
            anyhow::bail!("Ouro config: num_hidden_layers must be > 0");
        }
        if self.vocab_size == 0 {
            anyhow::bail!("Ouro config: vocab_size must be > 0");
        }
        if let Some(model_type) = &self.model_type {
            if !model_type.eq_ignore_ascii_case("ouro") {
                anyhow::bail!(
                    "Ouro config: model_type `{model_type}` is not `ouro` — operator pointed the Ouro provider at a non-Ouro checkpoint"
                );
            }
        }
        let mut clamped = self.clone();
        if clamped.total_ut_steps == 0 {
            tracing::warn!(
                "Ouro config: total_ut_steps=0 is meaningless; clamping to default {DEFAULT_TOTAL_UT_STEPS}"
            );
            clamped.total_ut_steps = DEFAULT_TOTAL_UT_STEPS;
        }
        if clamped.total_ut_steps > MAX_TOTAL_UT_STEPS {
            tracing::warn!(
                requested = clamped.total_ut_steps,
                ceiling = MAX_TOTAL_UT_STEPS,
                "Ouro config: total_ut_steps above ceiling; clamping"
            );
            clamped.total_ut_steps = MAX_TOTAL_UT_STEPS;
        }
        if let Some(t) = clamped.early_exit_threshold {
            if !(0.0..=1.0).contains(&t) {
                anyhow::bail!(
                    "Ouro config: early_exit_threshold must be in [0.0, 1.0], got {t}"
                );
            }
        }
        Ok(clamped)
    }

    /// Hidden dimension per attention head — derived. Some candle
    /// helpers expect this directly.
    pub fn head_dim(&self) -> usize {
        self.hidden_size / self.num_attention_heads
    }
}

/// One Ouro decoder layer. Same weight tensor is applied
/// `total_ut_steps` times per forward pass; we hold ONE copy
/// here + the `Ouro::forward` impl loops over it.
///
/// Sandwich-norm topology: `norm_pre → attn → norm_mid → mlp →
/// norm_post`. Three RMSNorm modules per layer (vs Qwen2's two).
#[allow(dead_code)]
pub struct OuroLayer {
    // Field handles populated by O-1b — left typed as unit for
    // the scaffolding commit so the struct shape pins without
    // requiring the full candle nn weight-loading code yet.
    _placeholder: (),
}

impl OuroLayer {
    /// O-1b will wire this up to load attention + MLP + 3 RMSNorms
    /// per layer from the `VarBuilder` path.
    pub fn from_config(_cfg: &OuroConfig) -> anyhow::Result<Self> {
        Ok(Self { _placeholder: () })
    }
}

/// Top-level Ouro model. Holds the 24 shared layers + the loop
/// count + a hidden_size cache. Operator-tweakable per-call
/// loop count via `OuroForward::with_loop_steps(n)` (O-1b).
#[allow(dead_code)]
pub struct Ouro {
    config: OuroConfig,
    layers: Vec<OuroLayer>,
}

impl Ouro {
    /// Build a scaffolded Ouro from a validated config. Weight
    /// loading (embed_tokens + per-layer params + lm_head + norm)
    /// is the next-bite step — this constructor takes only the
    /// config so the surface compiles for O-2 (Provider impl).
    pub fn new(config: OuroConfig) -> anyhow::Result<Self> {
        let config = config.validate()?;
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for _ in 0..config.num_hidden_layers {
            layers.push(OuroLayer::from_config(&config)?);
        }
        Ok(Self { config, layers })
    }

    /// Read-only view of the validated config — operator tooling
    /// (`neoth providers --output table`) reads via this.
    pub fn config(&self) -> &OuroConfig {
        &self.config
    }

    /// Number of unique layers (not loop-steps). Each layer runs
    /// `total_ut_steps` times per token.
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Effective compute multiplier — `total_ut_steps`. Operator
    /// status surface uses this for "Ouro runs 4× compute per
    /// token" cost-warning copy.
    pub fn loop_steps(&self) -> usize {
        self.config.total_ut_steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config(json_total_ut: Option<&str>) -> String {
        let total_ut_line = match json_total_ut {
            Some(s) => format!("\"total_ut_steps\": {s},"),
            None => String::new(),
        };
        format!(
            r#"{{
            "vocab_size": 49152,
            "hidden_size": 2048,
            "intermediate_size": 8192,
            "num_hidden_layers": 24,
            "num_attention_heads": 16,
            "max_position_embeddings": 32768,
            "rope_theta": 10000.0,
            "rms_norm_eps": 1e-5,
            {total_ut_line}
            "model_type": "ouro"
        }}"#
        )
    }

    #[test]
    fn parses_full_config_with_total_ut_steps() {
        let cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).expect("parse config");
        assert_eq!(cfg.vocab_size, 49152);
        assert_eq!(cfg.hidden_size, 2048);
        assert_eq!(cfg.num_hidden_layers, 24);
        assert_eq!(cfg.num_attention_heads, 16);
        assert_eq!(cfg.total_ut_steps, 4);
        assert_eq!(cfg.model_type.as_deref(), Some("ouro"));
    }

    #[test]
    fn parses_config_without_total_ut_uses_default() {
        let cfg: OuroConfig =
            serde_json::from_str(&fixture_config(None)).expect("parse config");
        assert_eq!(cfg.total_ut_steps, DEFAULT_TOTAL_UT_STEPS);
    }

    #[test]
    fn head_dim_derived_from_hidden_size_and_heads() {
        let cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        // 2048 / 16 = 128
        assert_eq!(cfg.head_dim(), 128);
    }

    #[test]
    fn validate_rejects_zero_heads() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.num_attention_heads = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_indivisible_hidden_size() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.num_attention_heads = 17; // 2048 % 17 != 0
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("divisible"));
    }

    #[test]
    fn validate_rejects_zero_layers() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.num_hidden_layers = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_vocab() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.vocab_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_ouro_model_type() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.model_type = Some("qwen2".to_string());
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("not `ouro`"));
    }

    #[test]
    fn validate_accepts_absent_model_type() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.model_type = None;
        // Older HF dumps lack model_type — don't punish that.
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_clamps_zero_total_ut_to_default() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.total_ut_steps = 0;
        let v = cfg.validate().unwrap();
        assert_eq!(v.total_ut_steps, DEFAULT_TOTAL_UT_STEPS);
    }

    #[test]
    fn validate_clamps_excessive_total_ut_to_ceiling() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.total_ut_steps = 99;
        let v = cfg.validate().unwrap();
        assert_eq!(v.total_ut_steps, MAX_TOTAL_UT_STEPS);
    }

    #[test]
    fn validate_rejects_early_exit_threshold_out_of_range() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.early_exit_threshold = Some(1.5);
        assert!(cfg.validate().is_err());
        cfg.early_exit_threshold = Some(-0.1);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ouro_construct_holds_validated_config_and_layer_count() {
        let cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        let model = Ouro::new(cfg).unwrap();
        assert_eq!(model.num_layers(), 24);
        assert_eq!(model.loop_steps(), 4);
        assert_eq!(model.config().hidden_size, 2048);
    }

    #[test]
    fn ouro_construct_propagates_validation_failure() {
        let mut cfg: OuroConfig =
            serde_json::from_str(&fixture_config(Some("4"))).unwrap();
        cfg.vocab_size = 0;
        assert!(Ouro::new(cfg).is_err());
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(DEFAULT_TOTAL_UT_STEPS, 4);
        assert_eq!(MAX_TOTAL_UT_STEPS, 8);
    }
}
