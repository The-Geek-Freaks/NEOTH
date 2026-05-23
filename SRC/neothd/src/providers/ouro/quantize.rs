//! Ouro O-5b — in-process Q8 weight quantization helpers.
//!
//! Bridges the operator-facing `OuroQuantMode` knob (shipped O-5a)
//! with candle 0.8's `quantized::QTensor` storage. The actual
//! parallel-model swap (`QuantizedOuroLayer` + `QuantizedOuroModel`)
//! defers to O-5c — this module ships the **tensor-level
//! quantization primitive + Linear wrapper construction helper +
//! tests** so the swap lands without re-debugging the candle API
//! plumbing.
//!
//! ## Math + memory trade-off
//!
//! Q8 (GGUF `Q8_0` block format) stores weights as 8-bit ints +
//! one f16 scale per 32-element block. Memory ≈ 9.0625 bits/weight
//! vs 16 bits/weight for BF16 — about 44% reduction. Numerical
//! error is bounded; for Ouro's 1.4B-Thinking checkpoint that's
//! 2.8 GB BF16 → ~1.6 GB Q8.
//!
//! Matmul cost is roughly equal (Q8 dequantizes on-the-fly inside
//! `QMatMul`) but cold-start grows by the per-tensor quantize-cost
//! (linear in weight count). For Ouro's 24 layers × 4 projections
//! + 3 norms each, that's ~100 tensors total — ~30-60 s extra on
//! first boot.
//!
//! ## What this module does NOT do (yet)
//!
//! - Build a parallel `OuroQuantizedLayer` (O-5c follow-up)
//! - Build a parallel `OuroQuantizedModel` forward (O-5c follow-up)
//! - Read pre-quantized GGUF safetensors (different code path —
//!   `candle_core::quantized::gguf_file::Content::tensors`)
//!
//! O-5c will compose `quantize_tensor_q8` + `quantized_linear_from_tensor`
//! against each Linear's loaded weight to build the parallel model.

use anyhow::{Context, Result};
use candle_core::Tensor;
use candle_core::quantized::{GgmlDType, QTensor};
use candle_transformers::quantized_nn::Linear as QuantizedLinear;

/// The shipping Q8 format — `Q8_0` is the standard GGUF block
/// format (32-element blocks, one f16 scale). Pinned here so a
/// future swap to e.g. `Q8_1` (per-block min) lands in one place.
pub const SHIPPING_Q8_DTYPE: GgmlDType = GgmlDType::Q8_0;

/// Block size for `Q8_0` — exposed as a const so callers can
/// pre-check tensor element counts before paying the quantize
/// cost. `QTensor::quantize` errors when `elem_count % block_size
/// != 0`; we let it surface that error rather than gate
/// upstream (every Linear projection in Ouro is divisible by 32
/// by checkpoint construction).
pub const Q8_BLOCK_SIZE: usize = 32;

/// Quantize one `Tensor` (typically a Linear's `.weight` matrix
/// loaded BF16/F32) into the shipping Q8 storage format. Returns a
/// `QTensor` ready for `QMatMul::from_weights` /
/// `quantized_nn::Linear::from_arc`.
///
/// The input is cast to F32 inside `QTensor::quantize` so callers
/// passing BF16 / F16 tensors don't need to pre-cast. Output
/// device matches input device — operators with a CUDA-resident
/// model stay on CUDA after quantize.
pub fn quantize_tensor_q8(tensor: &Tensor) -> Result<QTensor> {
    QTensor::quantize(tensor, SHIPPING_Q8_DTYPE).context("quantize_tensor_q8: QTensor::quantize")
}

/// Construct a `quantized_nn::Linear` from a manually-quantized
/// weight + optional bias. The bias stays at the input tensor's
/// native dtype (typically F32 after `dequantize`) since Linear's
/// bias path uses `broadcast_add` against the Q8 matmul output.
///
/// Wrap the QTensor in `Arc` so multiple Linears can share weights
/// (not used by Ouro today since each layer owns its own
/// projections, but the wire shape stays compatible with future
/// shared-embedding tied-input paths).
pub fn quantized_linear_from_tensor(
    weight: QTensor,
    bias: Option<Tensor>,
) -> Result<QuantizedLinear> {
    QuantizedLinear::from_arc(std::sync::Arc::new(weight), bias)
        .context("quantized_linear_from_tensor: Linear::from_arc")
}

/// Bytes per `Q8_0` block in candle's storage layout: 1 f16 scale
/// (2 bytes) + 32 int8 values (32 bytes) = 34 bytes per 32-element
/// block ≈ 1.0625 bytes / weight = 8.5 bits / weight.
pub const Q8_BLOCK_BYTES: usize = 34;

/// Memory-saving estimate — returns bytes saved when converting a
/// BF16-stored tensor of `elem_count` weights to Q8. Operator
/// status surface (`neoth ouro status` once O-5c lands) reads
/// this to show "Q8 saving: ~14 MB on Ouro-1.4B-Thinking
/// gate_proj".
///
/// Math:
///   BF16 = 2.00 bytes / weight (= 16 bits / weight)
///   Q8_0 = 34 bytes per 32-element block = 1.0625 bytes / weight
///   savings = 2 - 1.0625 = 0.9375 bytes / weight ≈ 47% reduction
///
/// Reports an integer byte count. Rounds Q8 cost UP via block
/// count so we never claim more savings than reality (block
/// headers + alignment eat a tiny bit on partial-block inputs).
pub fn q8_bytes_saved_vs_bf16(elem_count: usize) -> u64 {
    let bf16_bytes = elem_count as u64 * 2;
    let blocks = elem_count.div_ceil(Q8_BLOCK_SIZE);
    let q8_bytes = blocks as u64 * Q8_BLOCK_BYTES as u64;
    bf16_bytes.saturating_sub(q8_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::{DType, Device, Tensor};

    fn tiny_f32_tensor(rows: usize, cols: usize) -> Tensor {
        let v: Vec<f32> = (0..(rows * cols))
            .map(|i| (i as f32) * 0.01 - 0.5)
            .collect();
        Tensor::from_vec(v, (rows, cols), &Device::Cpu).unwrap()
    }

    #[test]
    fn shipping_dtype_pinned_to_q8_0() {
        assert_eq!(SHIPPING_Q8_DTYPE, GgmlDType::Q8_0);
    }

    #[test]
    fn block_size_constant_matches_candle_runtime() {
        // candle's GgmlDType::Q8_0.block_size() returns 32 — pin
        // here so a candle upgrade that changes the block size
        // can't sneak past without us noticing the constant.
        assert_eq!(SHIPPING_Q8_DTYPE.block_size(), Q8_BLOCK_SIZE);
    }

    #[test]
    fn quantize_tensor_q8_preserves_shape() {
        // 64 cols = 2 Q8 blocks; 8 rows = 8 sub-matrices.
        let t = tiny_f32_tensor(8, 64);
        let q = quantize_tensor_q8(&t).expect("quantize");
        assert_eq!(q.shape().dims(), &[8, 64]);
        assert_eq!(q.dtype(), GgmlDType::Q8_0);
    }

    #[test]
    fn quantize_tensor_q8_round_trip_within_block_quant_error() {
        // Q8 has ~1/127 relative error per block. Encode → decode
        // (dequantize) and check the L_inf error stays bounded.
        let t = tiny_f32_tensor(4, 32); // 1 row of blocks
        let q = quantize_tensor_q8(&t).expect("quantize");
        let back = q.dequantize(&Device::Cpu).expect("dequantize");
        let a: Vec<f32> = t.flatten_all().unwrap().to_vec1().unwrap();
        let b: Vec<f32> = back.flatten_all().unwrap().to_vec1().unwrap();
        // Element-wise abs error bounded by per-block scale / 127.
        // For tiny_f32_tensor's [-0.5, ...] range, the scale is
        // ~max/127 ≈ 0.5/127 ≈ 0.004 → tolerance 0.01 is safe.
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (x - y).abs() < 0.01,
                "element {i}: input {x}, decoded {y} (delta {})",
                (x - y).abs()
            );
        }
    }

    #[test]
    fn quantize_tensor_q8_handles_bf16_input_via_internal_cast() {
        // Input cast to F32 inside QTensor::quantize — caller can
        // pass BF16 without pre-cast.
        let f32_t = tiny_f32_tensor(4, 32);
        let bf16_t = f32_t.to_dtype(DType::BF16).expect("cast bf16");
        let q = quantize_tensor_q8(&bf16_t).expect("quantize bf16");
        assert_eq!(q.shape().dims(), &[4, 32]);
    }

    #[test]
    fn quantize_tensor_q8_errors_on_non_divisible_size() {
        // 31 elements — not divisible by 32-element block size.
        // Q8 quantize bails with shape error.
        let t = Tensor::from_vec(vec![0.0f32; 31], 31, &Device::Cpu).unwrap();
        assert!(quantize_tensor_q8(&t).is_err());
    }

    #[test]
    fn quantized_linear_from_tensor_constructs_via_arc_wrap() {
        // Smoke — manual quantize → wrap → Linear builds without
        // panic. We don't exercise forward here (separate test
        // module — O-5c integration), just the construction path.
        let weight_f32 = tiny_f32_tensor(8, 64);
        let qweight = quantize_tensor_q8(&weight_f32).expect("quantize");
        let _linear = quantized_linear_from_tensor(qweight, None).expect("Linear from arc");
    }

    #[test]
    fn q8_bytes_saved_zero_for_empty_tensor() {
        assert_eq!(q8_bytes_saved_vs_bf16(0), 0);
    }

    #[test]
    fn q8_bytes_saved_positive_for_typical_layer() {
        // Single MLP gate_proj for Ouro-1.4B-Thinking: roughly
        // hidden_size × intermediate_size = 2048 × 8192 ≈ 16.78M
        // weights. BF16 = ~33.55 MB; Q8 ≈ 17.83 MB → save ~14.72 MB.
        let n = 2048 * 8192;
        let saved = q8_bytes_saved_vs_bf16(n);
        let saved_mb = saved / (1024 * 1024);
        assert!(
            (13..=16).contains(&saved_mb),
            "expected ~14 MB saved on a 16.78M-weight matrix, got {saved_mb} MB"
        );
    }

    #[test]
    fn q8_bytes_saved_uses_div_ceil_for_block_count() {
        // 33 weights → 2 blocks (div_ceil), even though only the
        // first is fully populated. Pin the rounding behaviour so
        // savings stay honest (claim less, not more).
        let n = 33;
        // BF16 = 66 bytes; Q8 = 2 blocks × 34 = 68 bytes; saturating
        // saved = 0 (Q8 cost slightly exceeds BF16 cost for tiny
        // partial-block inputs — the function MUST NOT underflow).
        assert_eq!(q8_bytes_saved_vs_bf16(n), 0);
    }

    #[test]
    fn q8_bytes_saved_clean_full_block_savings() {
        // 32 weights = exactly 1 block. BF16 = 64 bytes; Q8 = 34
        // bytes; savings = 30 bytes. Pin the per-full-block savings
        // arithmetic so changing Q8_BLOCK_BYTES later forces a
        // test update.
        assert_eq!(q8_bytes_saved_vs_bf16(32), 30);
        // 64 weights = 2 blocks. BF16 = 128; Q8 = 68; saved = 60.
        assert_eq!(q8_bytes_saved_vs_bf16(64), 60);
    }

    #[test]
    fn q8_block_bytes_constant_pinned() {
        assert_eq!(Q8_BLOCK_BYTES, 34);
    }

    #[test]
    fn q8_bytes_saved_never_overflows_or_underflows() {
        // Huge tensor — must not panic, must return ≤ BF16 cost.
        let n = usize::MAX / 32; // avoid overflow in elem_count * 2
        let saved = q8_bytes_saved_vs_bf16(n);
        assert!(saved < (n as u64) * 2);
    }
}
