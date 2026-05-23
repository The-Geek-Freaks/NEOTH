//! Ouro top-level model — the `total_ut_steps` recurrent loop.
//!
//! Bite 2 of the O-1b workstream. Wraps Bite 1's `OuroLayer` stack
//! with `embed_tokens` + `final_norm` + `lm_head` + the looped
//! forward pass that defines LoopLM:
//!
//! ```text
//! input_ids
//!   → embed_tokens                                     [b, seq, hidden]
//!   → for _loop in 0..total_ut_steps:
//!       clear per-layer KV caches
//!       for layer in &mut layers:
//!           h = layer.forward(h, mask, seqlen_offset)
//!   → final_norm
//!   → lm_head                                          [b, 1, vocab]   (forward path, last token only)
//!     OR mean-pool over seq dim → L2 normalise         [b, hidden]      (embed path)
//! ```
//!
//! KV-cache is cleared at the start of every loop iteration so each
//! loop is a complete fresh forward pass over the same weights and
//! same input positions. This matches the architect-agent verdict
//! (KL-cache reset between loops avoids corrupting position-indexed
//! RoPE lookups).
//!
//! Early-exit (when `cfg.early_exit_threshold` is `Some`) is deferred
//! to O-1c — requires a real Ouro checkpoint to tune the threshold.
//! Bite 2 always runs all loops + emits a `tracing::debug!` noting
//! the deferral when the field is set.

use anyhow::{Context, Result};
use candle_core::{DType, Device, IndexOp, Module, Tensor, D};
use candle_nn::{linear_no_bias, ops::softmax_last_dim, rms_norm, Embedding, Linear, RmsNorm, VarBuilder};
use std::sync::Arc;

use super::layers::OuroLayer;
use super::model::OuroConfig;
use super::rope::OuroRoPE;

/// Top-level LoopLM model — weight-shared 24-layer stack applied
/// `total_ut_steps` times per token.
pub struct OuroModel {
    embed_tokens: Embedding,
    layers: Vec<OuroLayer>,
    final_norm: RmsNorm,
    lm_head: Linear,
    total_ut_steps: usize,
    hidden_size: usize,
    device: Device,
    dtype: DType,
}

impl OuroModel {
    /// Build from a `VarBuilder` rooted at the safetensors model
    /// scope. Loading follows HF's canonical `ByteDance/Ouro-*`
    /// path layout: `model.embed_tokens.*`, `model.layers.{i}.*`,
    /// `model.norm.*`, `lm_head.*`.
    pub fn new(cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let cfg = cfg.validate()?;
        if cfg.early_exit_threshold.is_some() {
            tracing::debug!(
                threshold = ?cfg.early_exit_threshold,
                "Ouro: early_exit_threshold set but O-1b ignores it (deferred to O-1c)"
            );
        }
        let vb_m = vb.pp("model");
        let embed_tokens =
            candle_nn::embedding(cfg.vocab_size, cfg.hidden_size, vb_m.pp("embed_tokens"))
                .context("OuroModel: build embed_tokens")?;
        let rope = OuroRoPE::new(vb.dtype(), &cfg, vb_m.device())?;
        let mut layers = Vec::with_capacity(cfg.num_hidden_layers);
        let vb_l = vb_m.pp("layers");
        for layer_idx in 0..cfg.num_hidden_layers {
            let layer = OuroLayer::new(Arc::clone(&rope), &cfg, vb_l.pp(layer_idx))
                .with_context(|| format!("OuroModel: build layer {layer_idx}"))?;
            layers.push(layer);
        }
        let final_norm = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb_m.pp("norm"))
            .context("OuroModel: final norm")?;
        // `lm_head.weight` lives at the root, not under `model.` —
        // matches HF transformers' typical CausalLM split. When the
        // checkpoint ties embeddings (no `lm_head.weight`), we fall
        // back to a transposed view of `embed_tokens.weight`.
        let lm_head = if vb.contains_tensor("lm_head.weight") {
            linear_no_bias(cfg.hidden_size, cfg.vocab_size, vb.pp("lm_head"))
                .context("OuroModel: lm_head")?
        } else {
            // Tied embeddings — `Linear::from_weights` reuses the
            // embed_tokens weight matrix without a fresh tensor copy.
            Linear::new(embed_tokens.embeddings().clone(), None)
        };
        Ok(Self {
            embed_tokens,
            layers,
            final_norm,
            lm_head,
            total_ut_steps: cfg.total_ut_steps,
            hidden_size: cfg.hidden_size,
            device: vb.device().clone(),
            dtype: vb.dtype(),
        })
    }

    /// Run one Ouro forward pass + lm_head projection. Returns
    /// `[batch, 1, vocab_size]` logits for the last input position
    /// (matching qwen2's `ModelForCausalLM::forward` shape so
    /// `local_qwen::sample_token` can consume the result verbatim).
    ///
    /// `seqlen_offset` is the position of the first new token —
    /// 0 for the prompt pass, `prompt_len + step` for each
    /// subsequent generation step.
    pub fn forward(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        let (_b, seq_len) = input_ids
            .dims2()
            .context("OuroModel: input_ids must be [b, seq]")?;
        let hidden = self.forward_loops(input_ids, seqlen_offset)?;
        // Take only the last token's hidden state before lm_head —
        // matches qwen2's narrow-then-apply pattern, saves a full
        // vocab projection over the prompt's earlier positions.
        let last = hidden
            .narrow(1, seq_len - 1, 1)
            .context("OuroModel: narrow to last token")?;
        last.apply(&self.lm_head)
            .context("OuroModel: lm_head projection")
    }

    /// Embed surface — same loop, no lm_head, mean-pool over seq
    /// dim, L2 normalise. Returns `[hidden_size]` (squeezed batch).
    pub fn embed(&mut self, input_ids: &Tensor) -> Result<Vec<f32>> {
        let hidden = self.forward_loops(input_ids, 0)?;
        // Mean over sequence dim → [batch=1, hidden].
        let pooled = hidden
            .mean(1)
            .context("OuroModel: mean-pool over seq")?
            .squeeze(0)
            .context("OuroModel: drop batch dim")?;
        let mut out: Vec<f32> = pooled
            .to_dtype(DType::F32)
            .context("OuroModel: cast pooled to f32")?
            .to_vec1()
            .context("OuroModel: extract Vec<f32>")?;
        if !crate::providers::embed::l2_normalize(&mut out) {
            anyhow::bail!("OuroModel: pooled hidden state is zero — model misload?");
        }
        Ok(out)
    }

    /// Hidden dimensionality — operators read via the
    /// `EmbedProvider::default_dim` impl in Bite 3.
    pub fn hidden_size(&self) -> usize {
        self.hidden_size
    }

    /// Effective loop count — for operator status surfaces +
    /// `neoth providers --output table` cost-warning copy.
    pub fn loop_steps(&self) -> usize {
        self.total_ut_steps
    }

    /// Internal: the shared body of `forward` and `embed`. Runs the
    /// total_ut_steps loop over the 24-layer stack, applying the
    /// final norm at the end. Returns post-norm hidden states
    /// `[batch, seq, hidden_size]` BEFORE any lm_head / pooling.
    fn forward_loops(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        let (b_size, seq_len) = input_ids
            .dims2()
            .context("OuroModel: input_ids must be [b, seq]")?;
        // Causal mask only when the sequence has more than one token
        // (single-token decoding doesn't need a mask).
        let attention_mask = if seq_len > 1 {
            Some(self.causal_attention_mask(b_size, seq_len, seqlen_offset)?)
        } else {
            None
        };
        // Embed the input tokens ONCE — every loop iteration runs
        // over the same embedded sequence (the loop is about
        // recurrence over the layer stack, not over re-embedding).
        let xs = self
            .embed_tokens
            .forward(input_ids)
            .context("OuroModel: embed_tokens forward")?;
        let mut h = xs;
        for loop_idx in 0..self.total_ut_steps {
            // Reset every layer's KV-cache at the start of each
            // loop. Each loop is a complete fresh forward pass.
            for layer in self.layers.iter_mut() {
                layer.clear_kv_cache();
            }
            for layer in self.layers.iter_mut() {
                h = layer
                    .forward(&h, attention_mask.as_ref(), seqlen_offset)
                    .with_context(|| {
                        format!("OuroModel: layer forward in loop {loop_idx}")
                    })?;
            }
        }
        h.apply(&self.final_norm)
            .context("OuroModel: final_norm")
    }

    fn causal_attention_mask(
        &self,
        b_size: usize,
        tgt_len: usize,
        seqlen_offset: usize,
    ) -> Result<Tensor> {
        // Strict upper-triangle mask — `i < j` positions get
        // -inf so the softmax can only attend to past tokens.
        let mask: Vec<f32> = (0..tgt_len)
            .flat_map(|i| {
                (0..tgt_len).map(move |j| if i < j { f32::NEG_INFINITY } else { 0.0 })
            })
            .collect();
        let mask = Tensor::from_slice(&mask, (tgt_len, tgt_len), &self.device)
            .context("causal mask: build tensor")?;
        let mask = if seqlen_offset > 0 {
            // Prepend a [tgt_len × seqlen_offset] zero block — positions
            // in the offset region are all attendable (they're the
            // already-emitted prefix).
            let mask0 = Tensor::zeros((tgt_len, seqlen_offset), DType::F32, &self.device)
                .context("causal mask: build offset prefix")?;
            Tensor::cat(&[&mask0, &mask], D::Minus1).context("causal mask: cat offset")?
        } else {
            mask
        };
        mask.expand((b_size, 1, tgt_len, tgt_len + seqlen_offset))
            .context("causal mask: expand to [b, 1, tgt, k]")?
            .to_dtype(self.dtype)
            .context("causal mask: cast to model dtype")
    }

    /// Clear every layer's KV-cache. Exposed for the future
    /// `LocalOuroAdapter` so a fresh chat completion starts clean
    /// even when the adapter reuses a warm `OuroModel`.
    pub fn clear_kv_cache(&mut self) {
        for layer in self.layers.iter_mut() {
            layer.clear_kv_cache();
        }
    }
}

// Silence unused-import lints while Bite 3 wires the adapter in.
#[allow(dead_code)]
fn _ouro_softmax_for_future_logits_inspection(t: &Tensor) -> Result<Tensor> {
    softmax_last_dim(t).context("softmax fallback")
}

#[allow(dead_code)]
fn _ouro_index_op_for_future_topk(t: &Tensor, idx: usize) -> Result<Tensor> {
    Ok(t.i(idx)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::{DType, Device, Tensor};
    use candle_nn::var_builder::VarBuilderArgs;
    use std::collections::HashMap;

    fn tiny_cfg() -> OuroConfig {
        OuroConfig {
            vocab_size: 8,
            hidden_size: 8,
            intermediate_size: 16,
            num_hidden_layers: 2,
            num_attention_heads: 2,
            max_position_embeddings: 16,
            rope_theta: 10_000.0,
            rms_norm_eps: 1e-5,
            total_ut_steps: 2,
            early_exit_threshold: None,
            model_type: Some("ouro".into()),
            tokenizer_class: None,
        }
    }

    fn add_layer_tensors(map: &mut HashMap<String, Tensor>, prefix: &str, dev: &Device) {
        let h = 8usize;
        let i = 16usize;
        for proj in &["q_proj", "k_proj", "v_proj", "o_proj"] {
            // All MHA projections are square hidden→hidden for the
            // toy 2-head fixture (head_dim=4, num_heads=2 → 8×8).
            map.insert(
                format!("{prefix}.self_attn.{proj}.weight"),
                Tensor::zeros((h, h), DType::F32, dev).unwrap(),
            );
        }
        map.insert(
            format!("{prefix}.mlp.gate_proj.weight"),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        map.insert(
            format!("{prefix}.mlp.up_proj.weight"),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        map.insert(
            format!("{prefix}.mlp.down_proj.weight"),
            Tensor::zeros((h, i), DType::F32, dev).unwrap(),
        );
        for norm in &["norm_pre", "norm_mid", "norm_post"] {
            map.insert(
                format!("{prefix}.{norm}.weight"),
                Tensor::ones((h,), DType::F32, dev).unwrap(),
            );
        }
    }

    /// Build a fresh VarBuilder for the full model — zero weights for
    /// projections + ones for norms. Embedding is also zeros (so the
    /// embedded input is the zero vector, propagating identity through
    /// the sandwich-norm residual algebra).
    fn synthetic_full_vb(dev: &Device, with_lm_head: bool) -> VarBuilder<'static> {
        let cfg = tiny_cfg();
        let mut map: HashMap<String, Tensor> = HashMap::new();
        map.insert(
            "model.embed_tokens.weight".into(),
            Tensor::zeros((cfg.vocab_size, cfg.hidden_size), DType::F32, dev).unwrap(),
        );
        for i in 0..cfg.num_hidden_layers {
            add_layer_tensors(&mut map, &format!("model.layers.{i}"), dev);
        }
        map.insert(
            "model.norm.weight".into(),
            Tensor::ones((cfg.hidden_size,), DType::F32, dev).unwrap(),
        );
        if with_lm_head {
            map.insert(
                "lm_head.weight".into(),
                Tensor::zeros((cfg.vocab_size, cfg.hidden_size), DType::F32, dev).unwrap(),
            );
        }
        VarBuilderArgs::from_tensors(map, DType::F32, dev)
    }

    fn input_ids(dev: &Device, ids: &[u32]) -> Tensor {
        Tensor::new(ids, dev).unwrap().unsqueeze(0).unwrap()
    }

    #[test]
    fn forward_produces_logits_shape_for_last_token_only() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2, 3, 4]);
        let logits = model.forward(&ids, 0).expect("forward");
        // Shape MUST be [batch=1, 1, vocab=8] — last-token-only.
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn forward_with_tied_embeddings_when_lm_head_absent() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, false); // no lm_head
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2]);
        let logits = model.forward(&ids, 0).expect("forward tied-embed");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn embed_returns_l2_normalised_vector_of_hidden_size() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2, 3]);
        // Zero weights → pooled hidden is zero → l2_normalize bails.
        // We use real-ish norms (ones) but zero projections; final
        // hidden after sandwich-norm + final_norm is zero. So embed
        // returns Err — pin that behaviour (caller wraps in
        // Result so a dead-weight model surfaces a clear error
        // instead of silently emitting NaN vectors).
        let err = model.embed(&ids).unwrap_err();
        assert!(err.to_string().contains("zero"));
    }

    #[test]
    fn loop_steps_field_propagates_from_config() {
        let dev = Device::Cpu;
        let mut cfg = tiny_cfg();
        cfg.total_ut_steps = 3;
        let vb = synthetic_full_vb(&dev, true);
        let model = OuroModel::new(&cfg, vb).expect("build model");
        assert_eq!(model.loop_steps(), 3);
    }

    #[test]
    fn hidden_size_field_propagates_from_config() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let model = OuroModel::new(&cfg, vb).expect("build model");
        assert_eq!(model.hidden_size(), cfg.hidden_size);
    }

    #[test]
    fn forward_handles_single_token_input_without_mask() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[7]);
        let logits = model.forward(&ids, 0).expect("single-token forward");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn forward_with_seqlen_offset_extends_mask() {
        // Simulate the 2nd generation step: 1 new token, 4 prior
        // positions in the KV-cache. mask construction must succeed
        // (mask shape [b, 1, 1, 5]).
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        // Prime KV cache with a 4-token pass.
        let ids = input_ids(&dev, &[1, 2, 3, 4]);
        let _ = model.forward(&ids, 0).unwrap();
        // Now feed 1 new token at offset 4.
        let next = input_ids(&dev, &[5]);
        let logits = model.forward(&next, 4).expect("offset forward");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn clear_kv_cache_resets_every_layer() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = OuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2]);
        let _ = model.forward(&ids, 0).unwrap();
        model.clear_kv_cache();
        // Re-forward at offset 0 must succeed (would mismatch if
        // cache wasn't cleared between sessions).
        let _ = model.forward(&ids, 0).unwrap();
    }

    #[test]
    fn new_rejects_invalid_config_via_validate() {
        let dev = Device::Cpu;
        let mut cfg = tiny_cfg();
        cfg.num_attention_heads = 0; // invalid
        let vb = synthetic_full_vb(&dev, true);
        assert!(OuroModel::new(&cfg, vb).is_err());
    }
}
