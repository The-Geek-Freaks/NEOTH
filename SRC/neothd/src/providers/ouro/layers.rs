//! Ouro decoder layer — MHA + SwiGLU + Sandwich RMSNorm.
//!
//! Adapted from `candle_transformers::models::qwen2::DecoderLayer`
//! with two structural changes:
//!   1. **MHA, not GQA**: `num_kv_heads == num_attention_heads` →
//!      `num_kv_groups = 1` → the `repeat_kv` call short-circuits
//!      to the identity (we skip it entirely to save the no-op
//!      tensor materialisation cost; see Risk 3 in the O-1b
//!      architecture plan).
//!   2. **Sandwich RMSNorm**: three norms per layer instead of two.
//!      Topology per Ouro paper Figure 2:
//!        r1   = xs
//!        h1   = norm_pre(xs)
//!        attn = self_attn(h1)
//!        r2   = r1 + attn
//!        h2   = norm_mid(r2)
//!        mlp  = mlp(h2)
//!        out  = r2 + norm_post(mlp)
//!
//! The same `OuroLayer` instance is applied `total_ut_steps` times
//! per token by the `OuroModel::forward` loop in `forward.rs` (next
//! bite). KV-cache is cleared between loops.

use std::sync::Arc;

use anyhow::{Context, Result};
use candle_core::{Module, Tensor};
use candle_nn::{
    Activation, Linear, RmsNorm, VarBuilder, linear_no_bias, ops::softmax_last_dim, rms_norm,
};

use super::model::OuroConfig;
use super::rope::OuroRoPE;

/// SwiGLU feed-forward — `silu(W_gate(x)) * W_up(x)) @ W_down`.
/// Identical wire shape to qwen2's MLP; broken out here so the Ouro
/// stack stays self-contained.
#[derive(Debug)]
pub struct OuroMLP {
    gate_proj: Linear,
    up_proj: Linear,
    down_proj: Linear,
    act_fn: Activation,
}

impl OuroMLP {
    pub fn new(cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let hidden_sz = cfg.hidden_size;
        let intermediate_sz = cfg.intermediate_size;
        let gate_proj = linear_no_bias(hidden_sz, intermediate_sz, vb.pp("gate_proj"))
            .context("MLP: gate_proj")?;
        let up_proj =
            linear_no_bias(hidden_sz, intermediate_sz, vb.pp("up_proj")).context("MLP: up_proj")?;
        let down_proj = linear_no_bias(intermediate_sz, hidden_sz, vb.pp("down_proj"))
            .context("MLP: down_proj")?;
        Ok(Self {
            gate_proj,
            up_proj,
            down_proj,
            act_fn: Activation::Silu,
        })
    }

    pub fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let lhs = xs
            .apply(&self.gate_proj)
            .context("MLP: gate forward")?
            .apply(&self.act_fn)
            .context("MLP: activation")?;
        let rhs = xs.apply(&self.up_proj).context("MLP: up forward")?;
        let prod = (lhs * rhs).context("MLP: gate*up")?;
        prod.apply(&self.down_proj).context("MLP: down forward")
    }
}

/// Multi-head attention (MHA — Ouro has no GQA). KV-cache is cleared
/// between every recurrent loop iteration in `OuroModel::forward`.
#[derive(Debug)]
pub struct OuroAttention {
    q_proj: Linear,
    k_proj: Linear,
    v_proj: Linear,
    o_proj: Linear,
    num_heads: usize,
    head_dim: usize,
    hidden_size: usize,
    rotary_emb: Arc<OuroRoPE>,
    /// GOLD-COR-36: one KV-cache slot PER recurrent loop (length
    /// `total_ut_steps`), indexed by `loop_idx`. The Universal-Transformer
    /// recurrence refines a hidden state across loops; a past token's loop-`L`
    /// K/V is causally independent of any later token, so caching it per-loop
    /// lets incremental decode (feed one new token at a growing `seqlen_offset`)
    /// produce BIT-IDENTICAL logits to the full-resequence baseline in O(n)
    /// forward passes instead of O(n²). Each loop reads + appends ONLY its own
    /// slot; a new sequence (`seqlen_offset == 0`) resets all slots.
    kv_caches: Vec<Option<(Tensor, Tensor)>>,
}

impl OuroAttention {
    pub fn new(rotary_emb: Arc<OuroRoPE>, cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let hidden_sz = cfg.hidden_size;
        let num_heads = cfg.num_attention_heads;
        let head_dim = cfg.head_dim();
        // MHA: no separate kv-head projection sizes. All projections
        // map hidden_sz → num_heads * head_dim = hidden_sz.
        let q_proj = linear_no_bias(hidden_sz, num_heads * head_dim, vb.pp("q_proj"))
            .context("Attention: q_proj")?;
        let k_proj = linear_no_bias(hidden_sz, num_heads * head_dim, vb.pp("k_proj"))
            .context("Attention: k_proj")?;
        let v_proj = linear_no_bias(hidden_sz, num_heads * head_dim, vb.pp("v_proj"))
            .context("Attention: v_proj")?;
        let o_proj = linear_no_bias(num_heads * head_dim, hidden_sz, vb.pp("o_proj"))
            .context("Attention: o_proj")?;
        Ok(Self {
            q_proj,
            k_proj,
            v_proj,
            o_proj,
            num_heads,
            head_dim,
            hidden_size: hidden_sz,
            rotary_emb,
            kv_caches: vec![None; cfg.total_ut_steps],
        })
    }

    pub fn forward(
        &mut self,
        xs: &Tensor,
        attention_mask: Option<&Tensor>,
        seqlen_offset: usize,
        loop_idx: usize,
    ) -> Result<Tensor> {
        let (b_sz, q_len, _) = xs
            .dims3()
            .context("Attention: input must be [b, seq, hidden]")?;

        let query_states = self
            .q_proj
            .forward(xs)
            .context("Attention: q_proj forward")?;
        let key_states = self
            .k_proj
            .forward(xs)
            .context("Attention: k_proj forward")?;
        let value_states = self
            .v_proj
            .forward(xs)
            .context("Attention: v_proj forward")?;

        // Reshape into [b, heads, seq, head_dim] for attention math.
        let query_states = query_states
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape q")?
            .transpose(1, 2)
            .context("Attention: transpose q")?;
        let key_states = key_states
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape k")?
            .transpose(1, 2)
            .context("Attention: transpose k")?;
        let value_states = value_states
            .reshape((b_sz, q_len, self.num_heads, self.head_dim))
            .context("Attention: reshape v")?
            .transpose(1, 2)
            .context("Attention: transpose v")?;

        let (query_states, key_states) =
            self.rotary_emb
                .apply_rotary_emb_qkv(&query_states, &key_states, seqlen_offset)?;

        // GOLD-COR-36: KV-cache append into THIS loop's slot. For the prompt /
        // full-resequence pass (`seqlen_offset == 0`) `forward_loops` resets all
        // slots first, so the slot starts empty and holds the whole sequence.
        // For incremental decode (`seqlen_offset > 0`) the slot already holds the
        // prefix's loop-`loop_idx` K/V (causally identical across decode steps),
        // and we append the new token's K/V — yielding the same attention inputs
        // the full-resequence baseline would compute at this (loop, position).
        let (key_states, value_states) = match &self.kv_caches[loop_idx] {
            None => (key_states, value_states),
            Some((prev_k, prev_v)) => {
                let k = Tensor::cat(&[prev_k, &key_states], 2)
                    .context("Attention: cat prev K + new K on seq dim")?;
                let v = Tensor::cat(&[prev_v, &value_states], 2)
                    .context("Attention: cat prev V + new V on seq dim")?;
                (k, v)
            }
        };
        self.kv_caches[loop_idx] = Some((key_states.clone(), value_states.clone()));

        // MHA: num_kv_groups == 1, so we skip the qwen2 `repeat_kv`
        // step entirely (it would be the identity for groups == 1
        // but candle materialises the expanded tensor anyway —
        // pure waste, see Risk 3 in O-1b architecture plan).
        let key_states = key_states.contiguous().context("Attention: K contiguous")?;
        let value_states = value_states
            .contiguous()
            .context("Attention: V contiguous")?;

        let attn_output = {
            let scale = 1f64 / f64::sqrt(self.head_dim as f64);
            let kt = key_states.transpose(2, 3).context("Attention: K^T")?;
            let attn_weights = (query_states.matmul(&kt).context("Attention: QK^T")? * scale)
                .context("Attention: scale QK^T")?;
            let attn_weights = match attention_mask {
                None => attn_weights,
                Some(mask) => attn_weights
                    .broadcast_add(mask)
                    .context("Attention: add causal mask")?,
            };
            let attn_weights = softmax_last_dim(&attn_weights).context("Attention: softmax")?;
            attn_weights
                .matmul(&value_states)
                .context("Attention: attn @ V")?
        };
        attn_output
            .transpose(1, 2)
            .context("Attention: transpose back")?
            .reshape((b_sz, q_len, self.hidden_size))
            .context("Attention: reshape to [b, seq, hidden]")?
            .apply(&self.o_proj)
            .context("Attention: o_proj")
    }

    /// Reset EVERY loop's KV-cache slot — a fresh sequence / completion.
    pub fn clear_kv_cache(&mut self) {
        for slot in self.kv_caches.iter_mut() {
            *slot = None;
        }
    }

    /// GOLD-ADAPT-KV-01 — clone every loop's KV slot. `Tensor::clone` is an Arc
    /// refcount bump, so this copies no tensor data (only the `Vec`/`Option`
    /// spine). Used by the cross-request prefix-KV cache to snapshot a shared
    /// prompt prefix's per-loop K/V.
    pub fn snapshot_kv_caches(&self) -> Vec<Option<(Tensor, Tensor)>> {
        self.kv_caches
            .iter()
            .map(|slot| slot.as_ref().map(|(k, v)| (k.clone(), v.clone())))
            .collect()
    }

    /// GOLD-ADAPT-KV-01 — overwrite every loop slot from a snapshot produced by
    /// [`Self::snapshot_kv_caches`] (same `total_ut_steps` length).
    pub fn restore_kv_caches(&mut self, snap: Vec<Option<(Tensor, Tensor)>>) {
        debug_assert_eq!(snap.len(), self.kv_caches.len());
        self.kv_caches = snap;
    }
}

/// One Ouro decoder layer — sandwich RMSNorm topology.
///
/// Three RMSNorms per layer (vs qwen2's two): `norm_pre` before
/// attention, `norm_mid` before MLP, `norm_post` on the MLP output
/// before the final residual add.
#[derive(Debug)]
pub struct OuroLayer {
    self_attn: OuroAttention,
    mlp: OuroMLP,
    norm_pre: RmsNorm,
    norm_mid: RmsNorm,
    norm_post: RmsNorm,
}

impl OuroLayer {
    pub fn new(rotary_emb: Arc<OuroRoPE>, cfg: &OuroConfig, vb: VarBuilder) -> Result<Self> {
        let self_attn = OuroAttention::new(rotary_emb, cfg, vb.pp("self_attn"))?;
        let mlp = OuroMLP::new(cfg, vb.pp("mlp"))?;
        let norm_pre = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_pre"))
            .context("Layer: norm_pre")?;
        let norm_mid = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_mid"))
            .context("Layer: norm_mid")?;
        let norm_post = rms_norm(cfg.hidden_size, cfg.rms_norm_eps, vb.pp("norm_post"))
            .context("Layer: norm_post")?;
        Ok(Self {
            self_attn,
            mlp,
            norm_pre,
            norm_mid,
            norm_post,
        })
    }

    /// Sandwich-norm forward pass.
    /// ```text
    ///   r1   = xs
    ///   h1   = norm_pre(xs)
    ///   attn = self_attn(h1)
    ///   r2   = r1 + attn
    ///   h2   = norm_mid(r2)
    ///   mlp  = mlp(h2)
    ///   out  = r2 + norm_post(mlp)
    /// ```
    pub fn forward(
        &mut self,
        xs: &Tensor,
        attention_mask: Option<&Tensor>,
        seqlen_offset: usize,
        loop_idx: usize,
    ) -> Result<Tensor> {
        let r1 = xs;
        let h1 = self
            .norm_pre
            .forward(xs)
            .context("Layer: norm_pre forward")?;
        let attn = self
            .self_attn
            .forward(&h1, attention_mask, seqlen_offset, loop_idx)
            .context("Layer: attn forward")?;
        let r2 = (r1 + attn).context("Layer: residual_1 add")?;
        let h2 = self
            .norm_mid
            .forward(&r2)
            .context("Layer: norm_mid forward")?;
        let mlp = self.mlp.forward(&h2).context("Layer: mlp forward")?;
        let mlp_out = self
            .norm_post
            .forward(&mlp)
            .context("Layer: norm_post forward")?;
        (&r2 + mlp_out).context("Layer: residual_2 add")
    }

    pub fn clear_kv_cache(&mut self) {
        self.self_attn.clear_kv_cache()
    }

    /// GOLD-ADAPT-KV-01 — snapshot/restore this layer's per-loop KV (delegates
    /// to the self-attention block).
    pub fn snapshot_kv(&self) -> Vec<Option<(Tensor, Tensor)>> {
        self.self_attn.snapshot_kv_caches()
    }
    pub fn restore_kv(&mut self, snap: Vec<Option<(Tensor, Tensor)>>) {
        self.self_attn.restore_kv_caches(snap);
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
            vocab_size: 4,
            hidden_size: 8,
            intermediate_size: 16,
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

    /// Build a synthetic VarBuilder populated with zero-weights for
    /// every parameter the OuroLayer + sub-modules consume. Enables
    /// shape-only unit tests without real safetensors.
    fn synthetic_vb(dev: &Device) -> VarBuilder<'static> {
        let cfg = tiny_cfg();
        let h = cfg.hidden_size;
        let i = cfg.intermediate_size;
        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        // Attention projections.
        tensors.insert(
            "self_attn.q_proj.weight".into(),
            Tensor::zeros((h, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "self_attn.k_proj.weight".into(),
            Tensor::zeros((h, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "self_attn.v_proj.weight".into(),
            Tensor::zeros((h, h), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "self_attn.o_proj.weight".into(),
            Tensor::zeros((h, h), DType::F32, dev).unwrap(),
        );
        // MLP projections.
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
        // Three RMSNorm weights — sandwich topology.
        tensors.insert(
            "norm_pre.weight".into(),
            Tensor::ones((h,), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "norm_mid.weight".into(),
            Tensor::ones((h,), DType::F32, dev).unwrap(),
        );
        tensors.insert(
            "norm_post.weight".into(),
            Tensor::ones((h,), DType::F32, dev).unwrap(),
        );
        VarBuilderArgs::from_tensors(tensors, DType::F32, dev)
    }

    #[test]
    fn ouro_mlp_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let vb = synthetic_vb(&dev);
        let mlp = OuroMLP::new(&cfg, vb.pp("mlp")).expect("build MLP");
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = mlp.forward(&xs).expect("MLP forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn ouro_attention_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_vb(&dev);
        let mut attn = OuroAttention::new(rope, &cfg, vb.pp("self_attn")).expect("build attention");
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = attn.forward(&xs, None, 0, 0).expect("attention forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn ouro_attention_kv_cache_clears() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_vb(&dev);
        let mut attn = OuroAttention::new(rope, &cfg, vb.pp("self_attn")).expect("build attention");
        let xs = Tensor::zeros((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let _ = attn.forward(&xs, None, 0, 0).unwrap();
        assert!(attn.kv_caches[0].is_some(), "first forward must populate loop-0 cache");
        attn.clear_kv_cache();
        assert!(attn.kv_caches[0].is_none(), "clear must reset to None");
    }

    #[test]
    fn ouro_layer_forward_shape_preserved() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_vb(&dev);
        let mut layer = OuroLayer::new(rope, &cfg, vb).expect("build layer");
        let xs = Tensor::zeros((1, 4, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = layer.forward(&xs, None, 0, 0).expect("layer forward");
        assert_eq!(out.dims(), &[1, 4, cfg.hidden_size]);
    }

    #[test]
    fn ouro_layer_clear_propagates_to_attention_cache() {
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_vb(&dev);
        let mut layer = OuroLayer::new(rope, &cfg, vb).expect("build layer");
        let xs = Tensor::zeros((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let _ = layer.forward(&xs, None, 0, 0).unwrap();
        assert!(layer.self_attn.kv_caches[0].is_some());
        layer.clear_kv_cache();
        assert!(layer.self_attn.kv_caches[0].is_none());
    }

    #[test]
    fn ouro_layer_residual_topology_pinned() {
        // Smoke: with all-ones norms + zero weights, every forward
        // path collapses to identity-plus-zero. Output MUST equal
        // input. Validates that the sandwich-norm residual algebra
        // wires the two `+` operations to the right tensors.
        let dev = Device::Cpu;
        let cfg = tiny_cfg();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("rope");
        let vb = synthetic_vb(&dev);
        let mut layer = OuroLayer::new(rope, &cfg, vb).expect("build layer");
        // Non-zero input — a constant +1.0 in every element.
        let xs = Tensor::ones((1, 2, cfg.hidden_size), DType::F32, &dev).unwrap();
        let out = layer.forward(&xs, None, 0, 0).expect("layer forward");
        let inp_vec: Vec<f32> = xs.flatten_all().unwrap().to_vec1().unwrap();
        let out_vec: Vec<f32> = out.flatten_all().unwrap().to_vec1().unwrap();
        // Zero-weight projections collapse attn + mlp to zero; the
        // two residual adds should preserve xs verbatim.
        for (i, (a, b)) in inp_vec.iter().zip(out_vec.iter()).enumerate() {
            assert!(
                (a - b).abs() < 1e-4,
                "element {i}: expected {a}, got {b} (residual topology broken)"
            );
        }
    }
}
