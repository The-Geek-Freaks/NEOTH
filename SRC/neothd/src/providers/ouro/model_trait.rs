//! GOLD-ARCH-11 — shared inference surface over the native and quantized
//! Ouro models.
//!
//! `OuroModel` (F16/F32 safetensors) and `QuantizedOuroModel` (Q8) grew as
//! parallel structs with byte-identical public APIs. The [`OuroForward`]
//! trait pins that API at compile time so the two impls cannot silently
//! drift, and [`build_causal_mask`] deduplicates the one genuinely shared
//! body. `forward_loops` deliberately stays per-struct: deduplicating it
//! would force either dyn-dispatch on the inference hot path or a generic
//! layer trait across `layers.rs`/`quantized_layers.rs`; the cross-model
//! parity oracle below makes divergence detectable instead.
//!
//! The adapter's `LoadedOuroModel` enum keeps its zero-cost match dispatch —
//! this trait is the drift guard, not a vtable replacement.

use anyhow::{Context, Result};
use candle_core::{D, DType, Device, Tensor};

use super::forward::OuroModel;
use super::quantized_forward::QuantizedOuroModel;

/// The shared model surface. `forward` and `embed` take `&mut self`
/// because the per-loop KV caches (GOLD-COR-36) mutate during the
/// recurrent loop.
pub(crate) trait OuroForward {
    /// Full forward pass: `[b, seq]` token ids at `seqlen_offset` →
    /// last-position logits.
    fn forward(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor>;
    /// L2-normalised mean-pooled hidden state for embeddings.
    fn embed(&mut self, input_ids: &Tensor) -> Result<Vec<f32>>;
    fn hidden_size(&self) -> usize;
    fn loop_steps(&self) -> usize;
    fn clear_kv_cache(&mut self);
}

impl OuroForward for OuroModel {
    fn forward(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        OuroModel::forward(self, input_ids, seqlen_offset)
    }
    fn embed(&mut self, input_ids: &Tensor) -> Result<Vec<f32>> {
        OuroModel::embed(self, input_ids)
    }
    fn hidden_size(&self) -> usize {
        OuroModel::hidden_size(self)
    }
    fn loop_steps(&self) -> usize {
        OuroModel::loop_steps(self)
    }
    fn clear_kv_cache(&mut self) {
        OuroModel::clear_kv_cache(self)
    }
}

impl OuroForward for QuantizedOuroModel {
    fn forward(&mut self, input_ids: &Tensor, seqlen_offset: usize) -> Result<Tensor> {
        QuantizedOuroModel::forward(self, input_ids, seqlen_offset)
    }
    fn embed(&mut self, input_ids: &Tensor) -> Result<Vec<f32>> {
        QuantizedOuroModel::embed(self, input_ids)
    }
    fn hidden_size(&self) -> usize {
        QuantizedOuroModel::hidden_size(self)
    }
    fn loop_steps(&self) -> usize {
        QuantizedOuroModel::loop_steps(self)
    }
    fn clear_kv_cache(&mut self) {
        QuantizedOuroModel::clear_kv_cache(self)
    }
}

/// Strict causal attention mask, shared by both model impls.
///
/// Upper-triangle `i < j` positions get -inf so the softmax can only
/// attend to past tokens. When `seqlen_offset > 0` a
/// `[tgt_len × seqlen_offset]` zero block is prepended — positions in the
/// offset region are all attendable (they're the already-emitted prefix).
/// Returns `[b, 1, tgt_len, tgt_len + seqlen_offset]` in the model dtype.
pub(super) fn build_causal_mask(
    b_size: usize,
    tgt_len: usize,
    seqlen_offset: usize,
    device: &Device,
    dtype: DType,
) -> Result<Tensor> {
    let mask: Vec<f32> = (0..tgt_len)
        .flat_map(|i| (0..tgt_len).map(move |j| if i < j { f32::NEG_INFINITY } else { 0.0 }))
        .collect();
    let mask = Tensor::from_slice(&mask, (tgt_len, tgt_len), device)
        .context("causal mask: build tensor")?;
    let mask = if seqlen_offset > 0 {
        let mask0 = Tensor::zeros((tgt_len, seqlen_offset), DType::F32, device)
            .context("causal mask: build offset prefix")?;
        Tensor::cat(&[&mask0, &mask], D::Minus1).context("causal mask: cat offset")?
    } else {
        mask
    };
    mask.expand((b_size, 1, tgt_len, tgt_len + seqlen_offset))
        .context("causal mask: expand to [b, 1, tgt, k]")?
        .to_dtype(dtype)
        .context("causal mask: cast to model dtype")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use candle_nn::VarBuilder;
    use candle_nn::var_builder::VarBuilderArgs;

    use super::super::model::OuroConfig;
    use super::*;

    /// Q8-compatible tiny config: every Linear dim divisible by
    /// Q8_BLOCK_SIZE=32 so the SAME weights build both models.
    fn tiny_cfg_q8() -> OuroConfig {
        OuroConfig {
            vocab_size: 32,
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

    fn det_tensor(rows: usize, cols: usize, dev: &Device, salt: usize) -> Tensor {
        let data: Vec<f32> = (0..rows * cols)
            .map(|k| (((k + salt) % 13) as f32 - 6.0) * 0.03)
            .collect();
        Tensor::from_vec(data, (rows, cols), dev).unwrap()
    }

    /// One deterministic non-zero weight map feeding BOTH model
    /// constructors (the quantized one quantizes it to Q8 internally).
    fn shared_nonzero_vb(dev: &Device) -> VarBuilder<'static> {
        let cfg = tiny_cfg_q8();
        let (h, i) = (cfg.hidden_size, cfg.intermediate_size);
        let mut map: HashMap<String, Tensor> = HashMap::new();
        map.insert(
            "model.embed_tokens.weight".into(),
            det_tensor(cfg.vocab_size, h, dev, 1),
        );
        for l in 0..cfg.num_hidden_layers {
            let p = format!("model.layers.{l}");
            let mut salt = 2 + l * 10;
            for proj in ["q_proj", "k_proj", "v_proj", "o_proj"] {
                map.insert(
                    format!("{p}.self_attn.{proj}.weight"),
                    det_tensor(h, h, dev, salt),
                );
                salt += 1;
            }
            map.insert(
                format!("{p}.mlp.gate_proj.weight"),
                det_tensor(i, h, dev, salt),
            );
            map.insert(
                format!("{p}.mlp.up_proj.weight"),
                det_tensor(i, h, dev, salt + 1),
            );
            map.insert(
                format!("{p}.mlp.down_proj.weight"),
                det_tensor(h, i, dev, salt + 2),
            );
            for norm in ["norm_pre", "norm_mid", "norm_post"] {
                map.insert(
                    format!("{p}.{norm}.weight"),
                    Tensor::ones((h,), DType::F32, dev).unwrap(),
                );
            }
        }
        map.insert(
            "model.norm.weight".into(),
            Tensor::ones((h,), DType::F32, dev).unwrap(),
        );
        map.insert(
            "lm_head.weight".into(),
            det_tensor(cfg.vocab_size, h, dev, 99),
        );
        VarBuilderArgs::from_tensors(map, DType::F32, dev)
    }

    fn input_ids(dev: &Device, ids: &[u32]) -> Tensor {
        Tensor::from_vec(ids.to_vec(), (1, ids.len()), dev).unwrap()
    }

    fn logits_vec(t: &Tensor) -> Vec<f32> {
        t.flatten_all().unwrap().to_vec1().unwrap()
    }

    /// Both impls satisfy the trait (compile-time drift guard).
    #[test]
    fn both_models_are_trait_objects() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg_q8();
        let mut native = OuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("native");
        let mut q8 = QuantizedOuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("q8");
        let _: &mut dyn OuroForward = &mut native;
        let _: &mut dyn OuroForward = &mut q8;
    }

    /// GOLD-ARCH-11 ORACLE: the native and quantized forward paths must
    /// produce matching logits from the SAME weights. Q8 quantization adds
    /// ~0.5% relative error, so the bound is loose enough to absorb
    /// quantization noise but tight enough that any mask / RoPE /
    /// forward_loops divergence between the two impls fails loudly.
    #[test]
    fn native_and_quantized_forward_agree_on_same_weights() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg_q8();
        let mut native = OuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("native");
        let mut q8 = QuantizedOuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("q8");

        let ids = input_ids(&dev, &[1, 2, 3, 4]);
        let l_native = logits_vec(&OuroForward::forward(&mut native, &ids, 0).unwrap());
        let l_q8 = logits_vec(&OuroForward::forward(&mut q8, &ids, 0).unwrap());
        assert_eq!(l_native.len(), l_q8.len(), "same logit width");

        // Context-sensitivity guard: degenerate weights would make this
        // parity vacuous.
        native.clear_kv_cache();
        let l_other = logits_vec(
            &OuroForward::forward(&mut native, &input_ids(&dev, &[4, 3, 2, 1]), 0).unwrap(),
        );
        assert!(
            l_native
                .iter()
                .zip(&l_other)
                .any(|(a, b)| (a - b).abs() > 1e-3),
            "non-zero weights must be context-sensitive"
        );

        // Structural divergence (mask / RoPE / forward_loops bugs) scrambles
        // the logit DIRECTION and the argmax; Q8 quantization noise (which
        // also quantizes activations per GGML Q8_0) only perturbs magnitudes.
        let dot: f32 = l_native.iter().zip(&l_q8).map(|(a, b)| a * b).sum();
        let na: f32 = l_native.iter().map(|a| a * a).sum::<f32>().sqrt();
        let nq: f32 = l_q8.iter().map(|b| b * b).sum::<f32>().sqrt();
        let cosine = dot / (na * nq);
        let argmax = |v: &[f32]| {
            v.iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .map(|(i, _)| i)
        };
        let max_diff = l_native
            .iter()
            .zip(&l_q8)
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f32, f32::max);
        // Measured baseline on these weights: cosine ~0.9944, max_diff ~0.24
        // (pure Q8 noise — the forward bodies are diff-verified identical).
        // A structural bug (mask shape, RoPE offset, loop wiring) scrambles
        // the direction to cosine << 0.9.
        assert!(
            cosine > 0.99,
            "native vs Q8 logit direction diverged (structural bug, not noise):              cosine={cosine} max_diff={max_diff}"
        );
        assert_eq!(
            argmax(&l_native),
            argmax(&l_q8),
            "native vs Q8 disagree on the greedy token (cosine={cosine} max_diff={max_diff})"
        );
        assert!(
            max_diff < 0.5,
            "native vs Q8 absolute drift beyond the measured Q8 noise ceiling              (~0.24 on these weights): max_diff={max_diff}"
        );
    }

    /// Incremental decode parity across BOTH impls via the trait surface:
    /// prompt [1,2,3] then single token [4]@3 must match the full pass on
    /// each model (exercises build_causal_mask's offset path uniformly).
    #[test]
    fn trait_surface_incremental_decode_matches_full_pass_on_both_impls() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg_q8();
        let native = OuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("native");
        let q8 = QuantizedOuroModel::new(&cfg, shared_nonzero_vb(&dev)).expect("q8");
        let models: Vec<Box<dyn OuroForward>> = vec![Box::new(native), Box::new(q8)];
        for (idx, mut m) in models.into_iter().enumerate() {
            let full = logits_vec(&m.forward(&input_ids(&dev, &[1, 2, 3, 4]), 0).unwrap());
            m.clear_kv_cache();
            let _ = m.forward(&input_ids(&dev, &[1, 2, 3]), 0).unwrap();
            let inc = logits_vec(&m.forward(&input_ids(&dev, &[4]), 3).unwrap());
            for (k, (f, i)) in full.iter().zip(&inc).enumerate() {
                assert!(
                    (f - i).abs() < 1e-4,
                    "impl #{idx}: incremental decode diverged at logit {k}: {f} vs {i}"
                );
            }
        }
    }
}
