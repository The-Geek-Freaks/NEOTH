//! Ouro RoPE — rotary positional embedding.
//!
//! Adapted from `candle_transformers::models::qwen2::RotaryEmbedding`
//! and parameterised against `OuroConfig::head_dim()` + `rope_theta`
//! instead of the qwen2 `Config`. The math is identical (Su et al.
//! 2021 RoPE) — Ouro's paper uses the same standard rotary formulation,
//! just driven from a different config struct.
//!
//! Held as `Arc<OuroRoPE>` inside `OuroAttention` so the sin/cos tables
//! are shared across all 24 layers + across all `total_ut_steps` loop
//! iterations (the tables are pure functions of head_dim, rope_theta,
//! max_position_embeddings — they never change at inference time).

use std::sync::Arc;

use anyhow::{Context, Result};
use candle_core::{DType, Device, Tensor};

use super::model::OuroConfig;

#[derive(Debug)]
pub struct OuroRoPE {
    sin: Tensor,
    cos: Tensor,
}

impl OuroRoPE {
    /// Build the rotary sin/cos tables up to `cfg.max_position_embeddings`.
    /// Tables stored on `dev` so all attention forward passes can
    /// `narrow` into them without a host-device copy.
    pub fn new(dtype: DType, cfg: &OuroConfig, dev: &Device) -> Result<Arc<Self>> {
        let dim = cfg.head_dim();
        let max_seq_len = cfg.max_position_embeddings;
        let inv_freq: Vec<f32> = (0..dim)
            .step_by(2)
            .map(|i| 1f32 / cfg.rope_theta.powf(i as f64 / dim as f64) as f32)
            .collect();
        let inv_freq_len = inv_freq.len();
        let inv_freq = Tensor::from_vec(inv_freq, (1, inv_freq_len), dev)
            .context("RoPE: build inv_freq tensor")?
            .to_dtype(dtype)
            .context("RoPE: cast inv_freq to model dtype")?;
        let t = Tensor::arange(0u32, max_seq_len as u32, dev)
            .context("RoPE: build position range")?
            .to_dtype(dtype)
            .context("RoPE: cast positions to model dtype")?
            .reshape((max_seq_len, 1))
            .context("RoPE: reshape positions to column")?;
        let freqs = t.matmul(&inv_freq).context("RoPE: outer-product freqs")?;
        Ok(Arc::new(Self {
            sin: freqs.sin().context("RoPE: sin table")?,
            cos: freqs.cos().context("RoPE: cos table")?,
        }))
    }

    /// Apply rotary embedding to query + key projections at
    /// `seqlen_offset`. Returns the rotated `(q, k)`. Same wire
    /// shape as candle_transformers qwen2 — we delegate to the
    /// candle_nn::rotary_emb::rope helper so future numerical
    /// fixes upstream land for Ouro automatically.
    pub fn apply_rotary_emb_qkv(
        &self,
        q: &Tensor,
        k: &Tensor,
        seqlen_offset: usize,
    ) -> Result<(Tensor, Tensor)> {
        let (_b_sz, _h, seq_len, _n_embd) =
            q.dims4().context("RoPE: q must be rank-4 [b, h, seq, head_dim]")?;
        let cos = self
            .cos
            .narrow(0, seqlen_offset, seq_len)
            .context("RoPE: narrow cos table")?;
        let sin = self
            .sin
            .narrow(0, seqlen_offset, seq_len)
            .context("RoPE: narrow sin table")?;
        let q_contig = q.contiguous().context("RoPE: q.contiguous()")?;
        let k_contig = k.contiguous().context("RoPE: k.contiguous()")?;
        let q_embed = candle_nn::rotary_emb::rope(&q_contig, &cos, &sin)
            .context("RoPE: apply to q")?;
        let k_embed = candle_nn::rotary_emb::rope(&k_contig, &cos, &sin)
            .context("RoPE: apply to k")?;
        Ok((q_embed, k_embed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::Device;

    fn cfg_from_fixture() -> OuroConfig {
        OuroConfig {
            vocab_size: 4,
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

    #[test]
    fn build_rope_tables_have_expected_shape() {
        let dev = Device::Cpu;
        let cfg = cfg_from_fixture();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("build rope");
        // head_dim = 4, dim/2 = 2, max_seq = 16 → (16, 2) each.
        let (sin_rows, sin_cols) = rope.sin.dims2().unwrap();
        assert_eq!(sin_rows, 16);
        assert_eq!(sin_cols, 2);
        let (cos_rows, cos_cols) = rope.cos.dims2().unwrap();
        assert_eq!(cos_rows, 16);
        assert_eq!(cos_cols, 2);
    }

    #[test]
    fn apply_rotary_emb_preserves_qk_shape() {
        let dev = Device::Cpu;
        let cfg = cfg_from_fixture();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("build rope");
        // q + k both shape [batch=1, heads=2, seq=4, head_dim=4]
        let q = Tensor::zeros((1, 2, 4, 4), DType::F32, &dev).unwrap();
        let k = Tensor::zeros((1, 2, 4, 4), DType::F32, &dev).unwrap();
        let (q_rot, k_rot) = rope.apply_rotary_emb_qkv(&q, &k, 0).unwrap();
        assert_eq!(q_rot.dims(), &[1, 2, 4, 4]);
        assert_eq!(k_rot.dims(), &[1, 2, 4, 4]);
    }

    #[test]
    fn apply_rotary_emb_respects_seqlen_offset() {
        let dev = Device::Cpu;
        let cfg = cfg_from_fixture();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("build rope");
        // seq=2 at offset=14 → needs positions 14, 15 (within max_seq=16)
        let q = Tensor::zeros((1, 2, 2, 4), DType::F32, &dev).unwrap();
        let k = Tensor::zeros((1, 2, 2, 4), DType::F32, &dev).unwrap();
        let (q_rot, _k_rot) = rope.apply_rotary_emb_qkv(&q, &k, 14).unwrap();
        assert_eq!(q_rot.dims(), &[1, 2, 2, 4]);
    }

    #[test]
    fn apply_rotary_emb_rejects_out_of_range_seqlen_offset() {
        let dev = Device::Cpu;
        let cfg = cfg_from_fixture();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("build rope");
        // max_seq=16; offset 15 + seq 2 = 17 → narrow fails cleanly.
        let q = Tensor::zeros((1, 2, 2, 4), DType::F32, &dev).unwrap();
        let k = Tensor::zeros((1, 2, 2, 4), DType::F32, &dev).unwrap();
        assert!(rope.apply_rotary_emb_qkv(&q, &k, 15).is_err());
    }

    #[test]
    fn rope_tables_differ_at_different_positions() {
        // Sanity — sin(0) != sin(1) for non-zero inv_freq.
        let dev = Device::Cpu;
        let cfg = cfg_from_fixture();
        let rope = OuroRoPE::new(DType::F32, &cfg, &dev).expect("build rope");
        let row0: Vec<f32> = rope.sin.get(0).unwrap().to_vec1().unwrap();
        let row1: Vec<f32> = rope.sin.get(1).unwrap().to_vec1().unwrap();
        // At least one element must differ — RoPE has positional info.
        assert!(row0.iter().zip(&row1).any(|(a, b)| (a - b).abs() > 1e-6));
    }
}
