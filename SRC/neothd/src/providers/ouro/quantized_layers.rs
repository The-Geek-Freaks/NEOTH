//! Ouro O-5c — parallel quantized decoder layer stack.
//!
//! Mirrors `providers/ouro/layers.rs` but uses
//! `candle_transformers::quantized_nn::Linear` instead of
//! `candle_nn::Linear`. Constructed by walking a regular
//! BF16/F32 `VarBuilder`, manually extracting each Linear's weight
//! tensor, calling `quantize::quantize_tensor_q8`, then wrapping
//! via `quantize::quantized_linear_from_tensor`.
//!
//! Memory trade-off: each Linear's weight goes from BF16
//! (2 bytes/weight) to Q8_0 (~1.0625 bytes/weight) → ~47% storage
//! reduction per projection. RMSNorms stay native F32 (they're
//! tiny — `hidden_size` floats per norm).
//!
//! v0.1 ships `QuantizedOuroMLP` (SwiGLU). Attention + sandwich-
//! norm layer + top-level model follow in O-5c-2/3/4 bites so the
//! shipping unit stays small + each bite is independently
//! reviewable. Wiring into `LoadedOuro` (adapter dispatch on
//! `OuroQuantMode::Q8 → quantized model`) is the final bite that
//! flips `is_quant_active()` to true.

use anyhow::{Context, Result};
use candle_core::{Module, Tensor};
use candle_nn::{Activation, VarBuilder};
use candle_transformers::quantized_nn::Linear as QuantizedLinear;

use super::model::OuroConfig;
use super::quantize::{quantize_tensor_q8, quantized_linear_from_tensor};

/// SwiGLU FFN with Q8-quantized projections.
///
/// Walks the input `VarBuilder` (BF16/F32 weights from safetensors)
/// for `gate_proj.weight`, `up_proj.weight`, `down_proj.weight`,
/// quantizes each in place, wraps in `QuantizedLinear`. Same
/// `forward()` semantics as `OuroMLP` — the difference is purely
/// storage (Q8 matmul vs F32 matmul inside the Linear).
#[derive(Debug)]
pub struct QuantizedOuroMLP {
    gate_proj: QuantizedLinear,
    up_proj: QuantizedLinear,
    down_proj: QuantizedLinear,
    act_fn: Activation,
}

impl QuantizedOuroMLP {
    pub fn new(cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let hidden_sz = cfg.hidden_size;
        let intermediate_sz = cfg.intermediate_size;

        let gate = load_quantized_linear_no_bias(&vb, "gate_proj", intermediate_sz, hidden_sz)
            .context("QuantizedOuroMLP: gate_proj")?;
        let up = load_quantized_linear_no_bias(&vb, "up_proj", intermediate_sz, hidden_sz)
            .context("QuantizedOuroMLP: up_proj")?;
        let down = load_quantized_linear_no_bias(&vb, "down_proj", hidden_sz, intermediate_sz)
            .context("QuantizedOuroMLP: down_proj")?;
        Ok(Self {
            gate_proj: gate,
            up_proj: up,
            down_proj: down,
            act_fn: Activation::Silu,
        })
    }

    pub fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let lhs = xs
            .apply(&self.gate_proj)
            .context("QuantizedOuroMLP: gate forward")?
            .apply(&self.act_fn)
            .context("QuantizedOuroMLP: activation")?;
        let rhs = xs
            .apply(&self.up_proj)
            .context("QuantizedOuroMLP: up forward")?;
        let prod = (lhs * rhs).context("QuantizedOuroMLP: gate*up")?;
        prod.apply(&self.down_proj)
            .context("QuantizedOuroMLP: down forward")
    }
}

/// Walk a VarBuilder for a single Linear's `weight` tensor, quantize
/// it to Q8, wrap in `QuantizedLinear` (no bias — Ouro's MLP
/// projections are all bias-free). Shape: `(out_dim, in_dim)`
/// matches candle's row-major Linear convention.
///
/// Extracted so future modules (`QuantizedOuroAttention`, future
/// quantized variants of other models) reuse one path.
pub fn load_quantized_linear_no_bias(
    vb: &VarBuilder,
    name: &str,
    out_dim: usize,
    in_dim: usize,
) -> Result<QuantizedLinear> {
    let weight = vb
        .pp(name)
        .get((out_dim, in_dim), "weight")
        .with_context(|| format!("load weight `{name}.weight` shape ({out_dim}, {in_dim})"))?;
    let qweight =
        quantize_tensor_q8(&weight).with_context(|| format!("quantize `{name}.weight` to Q8"))?;
    quantized_linear_from_tensor(qweight, None)
        .with_context(|| format!("wrap `{name}` as QuantizedLinear"))
}

// ── QuantizedOuroAttention ─────────────────────────────────────────
//
// MHA with Q8-quantized q/k/v/o projections. RoPE + KV cache match
// the native `OuroAttention` semantics; only the matmul math runs
// in Q8 space. Shares the `OuroRoPE` sin/cos tables via Arc so
// both native + quantized layer stacks reuse one rotary embedding
// construction in `QuantizedOuroModel` (O-5c-3 follow-up).

use candle_nn::ops::softmax_last_dim;
use std::sync::Arc;

use super::rope::OuroRoPE;

/// Multi-head attention with Q8-quantized projections.
#[derive(Debug)]
pub struct QuantizedOuroAttention {
    q_proj: QuantizedLinear,
    k_proj: QuantizedLinear,
    v_proj: QuantizedLinear,
    o_proj: QuantizedLinear,
    num_heads: usize,
    head_dim: usize,
    hidden_size: usize,
    rotary_emb: Arc<OuroRoPE>,
    kv_cache: Option<(Tensor, Tensor)>,
}

impl QuantizedOuroAttention {
    pub fn new(rotary_emb: Arc<OuroRoPE>, cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let hidden_sz = cfg.hidden_size;
        let num_heads = cfg.num_attention_heads;
        let head_dim = cfg.head_dim();
        let proj_out = num_heads * head_dim;
        let q_proj = load_quantized_linear_no_bias(&vb, "q_proj", proj_out, hidden_sz)
            .context("QuantizedOuroAttention: q_proj")?;
        let k_proj = load_quantized_linear_no_bias(&vb, "k_proj", proj_out, hidden_sz)
            .context("QuantizedOuroAttention: k_proj")?;
        let v_proj = load_quantized_linear_no_bias(&vb, "v_proj", proj_out, hidden_sz)
            .context("QuantizedOuroAttention: v_proj")?;
        let o_proj = load_quantized_linear_no_bias(&vb, "o_proj", hidden_sz, proj_out)
            .context("QuantizedOuroAttention: o_proj")?;
        Ok(Self {
            q_proj,
            k_proj,
            v_proj,
            o_proj,
            num_heads,
            head_dim,
            hidden_size: hidden_sz,
            rotary_emb,
            kv_cache: None,
        })
    }

    pub fn forward(
        &mut self,
        xs: &Tensor,
        attention_mask: Option<&Tensor>,
        seqlen_offset: usize,
    ) -> Result<Tensor> {
        let (b_sz, q_len, _) = xs
            .dims3()
            .context("QuantizedOuroAttention: input must be [b, seq, hidden]")?;

        let q = xs.apply(&self.q_proj).context("Attention: q_proj")?;
        let k = xs.apply(&self.k_proj).context("Attention: k_proj")?;
        let v = xs.apply(&self.v_proj).context("Attention: v_proj")?;

        let q = q
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape q")?
            .transpose(1, 2)
            .context("Attention: transpose q")?;
        let k = k
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape k")?
            .transpose(1, 2)
            .context("Attention: transpose k")?;
        let v = v
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape v")?
            .transpose(1, 2)
            .context("Attention: transpose v")?;

        let (q, k) = self
            .rotary_emb
            .apply_rotary_emb_qkv(&q, &k, seqlen_offset)?;

        let (k, v) = match &self.kv_cache {
            None => (k, v),
            Some((prev_k, prev_v)) => {
                let k = Tensor::cat(&[prev_k, &k], 2).context("Attention: cat K")?;
                let v = Tensor::cat(&[prev_v, &v], 2).context("Attention: cat V")?;
                (k, v)
            }
        };
        self.kv_cache = Some((k.clone(), v.clone()));

        let k = k.contiguous().context("Attention: K contiguous")?;
        let v = v.contiguous().context("Attention: V contiguous")?;

        let scale = 1f64 / f64::sqrt(self.head_dim as f64);
        let kt = k.transpose(2, 3).context("Attention: K^T")?;
        let attn =
            (q.matmul(&kt).context("Attention: QK^T")? * scale).context("Attention: scale QK^T")?;
        let attn = match attention_mask {
            None => attn,
            Some(mask) => attn.broadcast_add(mask).context("Attention: add mask")?,
        };
        let attn = softmax_last_dim(&attn).context("Attention: softmax")?;
        let out = attn.matmul(&v).context("Attention: attn @ V")?;
        out.transpose(1, 2)
            .context("Attention: transpose back")?
            .reshape((b_sz, q_len, self.hidden_size))
            .context("Attention: reshape to [b, seq, hidden]")?
            .apply(&self.o_proj)
            .context("Attention: o_proj")
    }

    pub fn clear_kv_cache(&mut self) {
        self.kv_cache = None;
    }
}

// ── QuantizedOuroLayer ─────────────────────────────────────────────
//
// Sandwich-norm topology mirroring `OuroLayer`. RMSNorms stay
// native F32 (tiny: `hidden_size` floats per norm), only the
// Linear projections inside attention + MLP go Q8.

use candle_nn::{RmsNorm, rms_norm};

/// One Ouro decoder layer with Q8-quantized attention + MLP, native
/// RMSNorms.
#[derive(Debug)]
pub struct QuantizedOuroLayer {
    self_attn: QuantizedOuroAttention,
    mlp: QuantizedOuroMLP,
    norm_pre: RmsNorm,
    norm_mid: RmsNorm,
    norm_post: RmsNorm,
}

impl QuantizedOuroLayer {
    pub fn new(rotary_emb: Arc<OuroRoPE>, cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let self_attn = QuantizedOuroAttention::new(rotary_emb, cfg, vb.pp("self_attn"))?;
        let mlp = QuantizedOuroMLP::new(cfg, vb.pp("mlp"))?;
        let norm_pre = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_pre"))
            .context("QuantizedOuroLayer: norm_pre")?;
        let norm_mid = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_mid"))
            .context("QuantizedOuroLayer: norm_mid")?;
        let norm_post = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_post"))
            .context("QuantizedOuroLayer: norm_post")?;
        Ok(Self {
            self_attn,
            mlp,
            norm_pre,
            norm_mid,
            norm_post,
        })
    }

    /// Same sandwich-norm residual topology as `OuroLayer::forward`:
    /// ```text
    ///   r2 = xs + attn(norm_pre(xs))
    ///   out = r2 + norm_post(mlp(norm_mid(r2)))
    /// ```
    pub fn forward(
        &mut self,
        xs: &Tensor,
        attention_mask: Option<&Tensor>,
        seqlen_offset: usize,
    ) -> Result<Tensor> {
        let r1 = xs;
        let h1 = self.norm_pre.forward(xs).context("Layer: norm_pre")?;
        let attn = self
            .self_attn
            .forward(&h1, attention_mask, seqlen_offset)
            .context("Layer: attn")?;
        let r2 = (r1 + attn).context("Layer: residual_1")?;
        let h2 = self.norm_mid.forward(&r2).context("Layer: norm_mid")?;
        let mlp = self.mlp.forward(&h2).context("Layer: mlp")?;
        let mlp_out = self.norm_post.forward(&mlp).context("Layer: norm_post")?;
        (&r2 + mlp_out).context("Layer: residual_2")
    }

    pub fn clear_kv_cache(&mut self) {
        self.self_attn.clear_kv_cache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::{DType, Device};
    use candle_nn::var_builder::VarBuilderArgs;
    use std::collections::HashMap;

    fn tiny_cfg() -> OuroConfig {
        OuroConfig {
            vocab_size: 4,
            hidden_size: 32, // divisible by Q8_BLOCK_SIZE=32
            intermediate_size: 64,
            num_hidden_layers: 1,
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

    fn synthetic_mlp_vb(dev: &Device) -> VarBuilder<'static> {
        let cfg = tiny_cfg();
        let h = cfg.hidden_size;
        let i = cfg.intermediate_size;
        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        // SwiGLU projections — all hidden → intermediate (gate, up)
        // and intermediate → hidden (down).
        tensors.insert(
            "gate_proj.weight".into(),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "up_proj.weight".into(),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "down_proj.weight".into(),
            Tensor::zeros((h, i), DType::F32, dev).unwrap(),
        );
        VarBuilderArgs::from_tensors(tensors, DType::F32, dev)
    }

    #[test]
    fn quantized_mlp_constructs_from_zero_weights() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_mlp_vb(&dev);
        let _mlp = QuantizedOuroMLP::new(&cfg, vb).expect("build quantized MLP");
    }

    #[test]
    fn quantized_mlp_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_mlp_vb(&dev);
        let mlp = QuantizedOuroMLP::new(&cfg, vb).expect("build mlp");
        // Input [batch=1, seq=4, hidden=32]; output preserves shape.
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = mlp.forward(&xs).expect("forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn quantized_mlp_forward_with_nonzero_input_produces_zero_output_on_zero_weights() {
        // Sanity — zero weights collapse to zero output regardless
        // of input. Pins the quantize-then-matmul path doesn't
        // introduce spurious bias.
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_mlp_vb(&dev);
        let mlp = QuantizedOuroMLP::new(&cfg, vb).expect("build mlp");
        let xs = Tensor::ones((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = mlp.forward(&xs).expect("forward");
        let out_vec: Vec<f32> = out.flatten_all().unwrap().to_vec1().unwrap();
        for (i, v) in out_vec.iter().enumerate() {
            assert!(
                v.abs() < 1e-5,
                "element {i}: zero-weight quantized matmul must produce ~0, got {v}"
            );
        }
    }

    #[test]
    fn load_quantized_linear_no_bias_round_trips_basic_shape() {
        let dev = Device::Cpu;
        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        tensors.insert(
            "proj.weight".into(),
            Tensor::zeros((64, 32), DType::F32, &dev).unwrap(),
        );
        let vb = VarBuilderArgs::from_tensors(tensors, DType::F32, &dev);
        let _linear =
            load_quantized_linear_no_bias(&vb, "proj", 64, 32).expect("build quantized linear");
    }

    #[test]
    fn load_quantized_linear_no_bias_errors_on_missing_weight() {
        let dev = Device::Cpu;
        let tensors: HashMap<String, Tensor> = HashMap::new();
        let vb = VarBuilderArgs::from_tensors(tensors, DType::F32, &dev);
        // No `missing.weight` in the VarBuilder → load fails with
        // an actionable context-wrapped error.
        let err = load_quantized_linear_no_bias(&vb, "missing", 64, 32).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing.weight") || msg.contains("load weight"),
            "expected actionable missing-weight error, got: {msg}"
        );
    }

    // ── QuantizedOuroAttention + QuantizedOuroLayer tests ────────────

    fn synthetic_layer_vb(dev: &Device) -> VarBuilder<'static> {
        let cfg = tiny_cfg();
        let h = cfg.hidden_size;
        let i = cfg.intermediate_size;
        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        // Attention: q/k/v/o all hidden→hidden for MHA with
        // hidden=32, heads=2, head_dim=16 → proj_out = 32.
        for proj in &["q_proj", "k_proj", "v_proj", "o_proj"] {
            tensors.insert(
                format!("self_attn.{proj}.weight"),
                Tensor::zeros((h, h), DType::F32, dev).unwrap(),
            );
        }
        // MLP SwiGLU projections.
        tensors.insert(
            "mlp.gate_proj.weight".into(),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "mlp.up_proj.weight".into(),
            Tensor::zeros((i, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "mlp.down_proj.weight".into(),
            Tensor::zeros((h, i), DType::F32, dev).unwrap(),
        );
        // Three sandwich RMSNorms.
        for norm in &["norm_pre", "norm_mid", "norm_post"] {
            tensors.insert(
                format!("{norm}.weight"),
                Tensor::ones((h,), DType::F32, dev).unwrap(),
            );
        }
        VarBuilderArgs::from_tensors(tensors, DType::F32, dev)
    }

    #[test]
    fn quantized_attention_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_layer_vb(&dev);
        let mut attn = QuantizedOuroAttention::new(rope, &cfg, vb.pp("self_attn"))
            .expect("build quantized attention");
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = attn.forward(&xs, None, 0).expect("attention forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn quantized_attention_kv_cache_clears() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_layer_vb(&dev);
        let mut attn = QuantizedOuroAttention::new(rope, &cfg, vb.pp("self_attn"))
            .expect("build quantized attention");
        let xs = Tensor::zeros((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let _ = attn.forward(&xs, None, 0).unwrap();
        assert!(attn.kv_cache.is_some(), "cache populated by forward");
        attn.clear_kv_cache();
        assert!(attn.kv_cache.is_none(), "clear resets cache");
    }

    #[test]
    fn quantized_layer_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_layer_vb(&dev);
        let mut layer = QuantizedOuroLayer::new(rope, &cfg, vb).expect("build layer");
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = layer.forward(&xs, None, 0).expect("layer forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn quantized_layer_residual_topology_preserves_input_on_zero_weights() {
        // Same headline pin as the native OuroLayer test — sandwich
        // norm residual algebra must surface input verbatim when
        // every projection is zero. Pins the parallel-model wiring
        // doesn't break the residual contract.
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_layer_vb(&dev);
        let mut layer = QuantizedOuroLayer::new(rope, &cfg, vb).expect("build layer");
        let xs = Tensor::ones((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = layer.forward(&xs, None, 0).expect("forward");
        let inp: Vec<f32> = xs.flatten_all().unwrap().to_vec1().unwrap();
        let got: Vec<f32> = out.flatten_all().unwrap().to_vec1().unwrap();
        for (i, (a, b)) in inp.iter().zip(got.iter()).enumerate() {
            assert!(
                (a - b).abs() < 1e-3,
                "element {i}: residual topology broken (in={a} out={b})"
            );
        }
    }

    #[test]
    fn quantized_layer_clear_propagates_to_attention_cache() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_layer_vb(&dev);
        let mut layer = QuantizedOuroLayer::new(rope, &cfg, vb).expect("build layer");
        let xs = Tensor::zeros((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let _ = layer.forward(&xs, None, 0).unwrap();
        assert!(layer.self_attn.kv_cache.is_some());
        layer.clear_kv_cache();
        assert!(layer.self_attn.kv_cache.is_none());
    }
}
