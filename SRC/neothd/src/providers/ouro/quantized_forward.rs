//! Ouro O-5c — parallel quantized top-level model.
//!
//! Mirrors `providers/ouro/forward.rs::OuroModel` but uses
//! `QuantizedOuroLayer` (Q8 matmuls inside attention + MLP) and a
//! `QuantizedLinear` `lm_head` (the biggest single tensor after
//! `embed_tokens`). Embeddings stay native (`candle_nn::Embedding`)
//! since the lookup-then-output path doesn't go through matmul.
//!
//! Same `total_ut_steps` loop semantics + KV-cache reset between
//! loops + sandwich-norm topology. Operator-visible forward shape
//! identical to native — logits `[batch, 1, vocab]` for last
//! position only, embeddings `[hidden_size]` L2-normalised. Caller
//! (`LocalOuroAdapter`) dispatches based on `OuroQuantMode` at
//! load.

use std::sync::Arc;

use anyhow::{Context, Result};
use candle_core::{D, DType, Device, Module, Tensor};
use candle_nn::{Embedding, RmsNorm, VarBuilder, rms_norm};
use candle_transformers::quantized_nn::Linear as QuantizedLinear;

use super::model::OuroConfig;
use super::quantized_layers::{QuantizedOuroLayer, load_quantized_linear_no_bias};
use super::rope::OuroRoPE;

/// Top-level Ouro LoopLM with Q8-quantized layer stack.
pub struct QuantizedOuroModel {
    embed_tokens: Embedding,
    layers: Vec<QuantizedOuroLayer>,
    final_norm: RmsNorm,
    lm_head: QuantizedLinear,
    total_ut_steps: usize,
    hidden_size: usize,
    device: Device,
    dtype: DType,
}

impl QuantizedOuroModel {
    /// Build from a regular BF16/F32 `VarBuilder` rooted at the
    /// safetensors model scope. Walks each Linear's weight, quantizes
    /// to Q8, wraps via `QuantizedLinear`. Embeddings + RMSNorms
    /// stay native — those structures are small enough that
    /// quantizing them adds no meaningful saving.
    pub fn new(cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let cfg = cfg.validate()?;
        if cfg.early_exit_threshold.is_some() {
            tracing::debug!(
                threshold = ?cfg.early_exit_threshold,
                "QuantizedOuroModel: early_exit_threshold set but O-5c ignores it (defer to O-5d)"
            );
        }
        let vb_m = vb.pp("model");
        let embed_tokens =
            candle_nn::embedding(cfg.vocab_size, cfg.hidden_size, vb_m.pp("embed_tokens"))
                .context("QuantizedOuroModel: build embed_tokens")?;
        let rope = OuroRoPE::new(vb.dtype(), &cfg, vb_m.device())?;
        let mut layers = Vec::with_capacity(cfg.num_hidden_layers);
        let vb_l = vb_m.pp("layers");
        for layer_idx in 0..cfg.num_hidden_layers {
            let layer = QuantizedOuroLayer::new(Arc::clone(&rope), &cfg, vb_l.pp(layer_idx))
                .with_context(|| format!("QuantizedOuroModel: build layer {layer_idx}"))?;
            layers.push(layer);
        }
        let final_norm = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb_m.pp("norm"))
            .context("QuantizedOuroModel: final norm")?;
        // lm_head: load native then quantize. Tied-embeddings path
        // (no separate lm_head.weight in safetensors) takes the
        // embed_tokens weight, transposes mentally via the same
        // (vocab_size, hidden_size) shape, quantizes.
        let lm_head = if vb.contains_tensor("lm_head.weight") {
            load_quantized_linear_no_bias(&vb, "lm_head", cfg.vocab_size, cfg.hidden_size)
                .context("QuantizedOuroModel: lm_head")?
        } else {
            // Tied embeddings — quantize the embed_tokens weight
            // matrix as the lm_head weight (same shape per BEP-ouro).
            let weight = embed_tokens.embeddings().clone();
            let qweight = super::quantize::quantize_tensor_q8(&weight)
                .context("QuantizedOuroModel: quantize tied lm_head from embed_tokens")?;
            super::quantize::quantized_linear_from_tensor(qweight, None)
                .context("QuantizedOuroModel: wrap tied lm_head as QuantizedLinear")?
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

    /// Run one forward pass + lm_head projection. Returns `[batch,
    /// 1, vocab_size]` logits for the last input position (matches
    /// native `OuroModel::forward` shape so `local_qwen::sample_token`
    /// consumes verbatim).
    pub fn forward(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        let (_b, seq_len) = input_ids
            .dims2()
            .context("QuantizedOuroModel: input_ids must be [b, seq]")?;
        let hidden = self.forward_loops(input_ids, seqlen_offset)?;
        let last = hidden
            .narrow(1, seq_len - 1, 1)
            .context("QuantizedOuroModel: narrow to last token")?;
        last.apply(&self.lm_head)
            .context("QuantizedOuroModel: lm_head projection")
    }

    /// Embed surface — same loop, no lm_head, mean-pool over seq dim,
    /// L2-normalise. Returns `[hidden_size]` (squeezed batch).
    pub fn embed(&mut self, input_ids: &Tensor) -> Result<Vec<f32>> {
        let hidden = self.forward_loops(input_ids, 0)?;
        let pooled = hidden
            .mean(1)
            .context("QuantizedOuroModel: mean-pool over seq")?
            .squeeze(0)
            .context("QuantizedOuroModel: drop batch dim")?;
        let mut out: Vec<f32> = pooled
            .to_dtype(DType::F32)
            .context("QuantizedOuroModel: cast pooled to f32")?
            .to_vec1()
            .context("QuantizedOuroModel: extract Vec<f32>")?;
        if !crate::providers::embed::l2_normalize(&mut out) {
            anyhow::bail!(
                "QuantizedOuroModel: pooled hidden state is zero — model misload (quantize normalize)"
            );
        }
        Ok(out)
    }

    pub fn hidden_size(&self) -> usize {
        self.hidden_size
    }

    pub fn loop_steps(&self) -> usize {
        self.total_ut_steps
    }

    /// Shared body of `forward` + `embed`. Runs the total_ut_steps
    /// loop over the 24-layer stack, applies final norm.
    fn forward_loops(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        let (b_size, seq_len) = input_ids
            .dims2()
            .context("QuantizedOuroModel: input_ids must be [b, seq]")?;
        let attention_mask = if seq_len > 1 {
            Some(self.causal_attention_mask(b_size, seq_len, seqlen_offset)?)
        } else {
            None
        };
        let xs = self
            .embed_tokens
            .forward(input_ids)
            .context("QuantizedOuroModel: embed_tokens forward")?;
        let mut h = xs;
        for loop_idx in 0..self.total_ut_steps {
            for layer in self.layers.iter_mut() {
                layer.clear_kv_cache();
            }
            for layer in self.layers.iter_mut() {
                h = layer
                    .forward(&h, attention_mask.as_ref(), seqlen_offset)
                    .with_context(|| {
                        format!("QuantizedOuroModel: layer forward in loop {loop_idx}")
                    })?;
            }
        }
        h.apply(&self.final_norm)
            .context("QuantizedOuroModel: final_norm")
    }

    fn causal_attention_mask(
        &self,
        b_size: usize,
        tgt_len: usize,
        seqlen_offset: usize,
    ) -> Result<Tensor> {
        let mask: Vec<f32> = (0..tgt_len)
            .flat_map(|i| (0..tgt_len).map(move |j| if i < j { f32::NEG_INFINITY } else { 0.0 }))
            .collect();
        let mask = Tensor::from_slice(&mask, (tgt_len, tgt_len), &self.device)
            .context("causal mask: build tensor")?;
        let mask = if seqlen_offset > 0 {
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

    pub fn clear_kv_cache(&mut self) {
        for layer in self.layers.iter_mut() {
            layer.clear_kv_cache();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::{DType, Device, Tensor};
    use candle_nn::var_builder::VarBuilderArgs;
    use std::collections::HashMap;

    fn tiny_cfg() -> OuroConfig {
        OuroConfig {
            vocab_size: 32, // divisible by Q8_BLOCK_SIZE=32 for lm_head
            hidden_size: 32,
            intermediate_size: 64,
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

    fn add_layer_weights(map: &mut HashMap<String, Tensor>, prefix: &str, dev: &Device) {
        let h = 32usize;
        let i = 64usize;
        for proj in &["q_proj", "k_proj", "v_proj", "o_proj"] {
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

    fn synthetic_full_vb(dev: &Device, with_lm_head: bool) -> VarBuilder<'static> {
        let cfg = tiny_cfg();
        let mut map: HashMap<String, Tensor> = HashMap::new();
        map.insert(
            "model.embed_tokens.weight".into(),
            Tensor::zeros((cfg.vocab_size, cfg.hidden_size), DType::F32, dev).unwrap(),
        );
        for i in 0..cfg.num_hidden_layers {
            add_layer_weights(&mut map, &format!("model.layers.{i}"), dev);
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
    fn forward_produces_last_token_logits_shape() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2, 3, 4]);
        let logits = model.forward(&ids, 0).expect("forward");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn forward_with_tied_embeddings_when_lm_head_absent() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, false);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build tied-embed model");
        let ids = input_ids(&dev, &[1, 2]);
        let logits = model.forward(&ids, 0).expect("forward tied");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn embed_returns_err_on_zero_pooled() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build model");
        let ids = input_ids(&dev, &[1, 2, 3]);
        // Zero-weight projections → zero pooled hidden → l2_normalize
        // bails with operator-readable error.
        let err = model.embed(&ids).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("zero") || msg.contains("normalize"));
    }

    #[test]
    fn loop_steps_propagates_from_config() {
        let dev = Device::Cpu;
        let mut cfg = tiny_cfg();
        cfg.total_ut_steps = 3;
        let vb = synthetic_full_vb(&dev, true);
        let model = QuantizedOuroModel::new(&cfg, vb).expect("build");
        assert_eq!(model.loop_steps(), 3);
    }

    #[test]
    fn hidden_size_propagates_from_config() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let model = QuantizedOuroModel::new(&cfg, vb).expect("build");
        assert_eq!(model.hidden_size(), cfg.hidden_size);
    }

    #[test]
    fn forward_handles_single_token_without_mask() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build");
        let ids = input_ids(&dev, &[7]);
        let logits = model.forward(&ids, 0).expect("forward single");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn forward_with_seqlen_offset_extends_mask() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build");
        let ids = input_ids(&dev, &[1, 2, 3, 4]);
        let _ = model.forward(&ids, 0).unwrap();
        let next = input_ids(&dev, &[5]);
        let logits = model.forward(&next, 4).expect("forward offset");
        assert_eq!(logits.dims(), &[1, 1, cfg.vocab_size]);
    }

    #[test]
    fn clear_kv_cache_resets_every_layer() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_full_vb(&dev, true);
        let mut model = QuantizedOuroModel::new(&cfg, vb).expect("build");
        let ids = input_ids(&dev, &[1, 2]);
        let _ = model.forward(&ids, 0).unwrap();
        model.clear_kv_cache();
        let _ = model.forward(&ids, 0).unwrap();
    }

    #[test]
    fn new_rejects_invalid_config_via_validate() {
        let dev = Device::Cpu;
        let mut cfg = tiny_cfg();
        cfg.num_attention_heads = 0;
        let vb = synthetic_full_vb(&dev, true);
        assert!(QuantizedOuroModel::new(&cfg, vb).is_err());
    }
}
