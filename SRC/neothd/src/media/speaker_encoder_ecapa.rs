//! SPEAKR-02c — ECAPA-TDNN speaker-embedding encoder (highest-accuracy neural upgrade).
//!
//! ## Status: DORMANT SCAFFOLD
//!
//! This module compiles and passes shape/wiring tests, but **produces
//! meaningful embeddings ONLY when real weights are provisioned**. The
//! `speechbrain/spkrec-ecapa-voxceleb` checkpoint is NOT bundled; an operator
//! must run `scripts/convert_ecapa.py` and place the output safetensors in
//! the NEOTH model cache (see `try_load` for the path). Until that file exists
//! `try_load()` returns `None` and the caller falls back to the x-vector or
//! log-mel encoder in `speaker_encoder_xvector.rs` / `speaker_encoder.rs`.
//!
//! ## Architecture (extracted from speechbrain/spkrec-ecapa-voxceleb hyperparams.yaml)
//!
//! Source: `hyperparams.yaml` (fetched 2026-06-23 from HF hub:
//! `speechbrain/spkrec-ecapa-voxceleb`). This is the **"big" ECAPA** variant.
//!
//! ```text
//! Front-end (Fbank):
//!   n_mels      = 80          ← from hyperparams.yaml
//!   sample_rate = 16_000
//!   win_length  = 25 ms  → 400 samples  (SpeechBrain Fbank default)
//!   hop_length  = 10 ms  → 160 samples
//!   n_fft       = 512    (next power-of-2 ≥ win_length in SpeechBrain)
//!   mean_var_norm: sentence-level (norm_type=sentence, std_norm=False)
//!
//! embedding_model: ECAPA_TDNN (from hyperparams.yaml)
//!   input_size         = 80        (n_mels)
//!   channels           = [1024, 1024, 1024, 1024, 3072]
//!   kernel_sizes       = [5, 3, 3, 3, 1]
//!   dilations          = [1, 2, 3, 4, 1]
//!   attention_channels = 128
//!   lin_neurons        = 192       ← embedding dim
//!   res2net_scale      = 8         (SpeechBrain default)
//!   se_channels        = 128       (SpeechBrain default)
//!   global_context     = true      (SpeechBrain default)
//!
//! Block topology (following SpeechBrain ECAPA_TDNN.__init__):
//!   block[0]: TdnnBlock(80 → 1024, k=5, d=1)
//!   block[1]: SERes2NetBlock(1024 → 1024, k=3, d=2, scale=8, se=128)
//!   block[2]: SERes2NetBlock(1024 → 1024, k=3, d=3, scale=8, se=128)
//!   block[3]: SERes2NetBlock(1024 → 1024, k=3, d=4, scale=8, se=128)
//!   mfa:      TdnnBlock(3072 → 3072, k=1, d=1)   ← MFA: concat blocks[1..4]
//!   asp:      AttentiveStatisticsPooling(3072, attn_ch=128, global_context=true)
//!   asp_bn:   BatchNorm1d(6144)
//!   fc:       Conv1d(6144 → 192, k=1)             ← linear proj (no activation)
//!
//! Output: 192-dim L2-normalised ECAPA embedding.
//! ```
//!
//! ## Weight key mapping (`embedding_model.ckpt` → safetensors)
//!
//! SpeechBrain serialises parameter names as `module.sub.weight` etc.
//! The conversion script `scripts/convert_ecapa.py` maps to the flat-slash
//! paths that `VarBuilder::pp("...")` resolves:
//!
//! ```text
//! embedding_model.blocks.0.conv.weight         → blocks_0/weight
//! embedding_model.blocks.0.conv.bias           → blocks_0/bias
//! embedding_model.blocks.0.norm.weight         → blocks_0_bn/weight
//! embedding_model.blocks.0.norm.bias           → blocks_0_bn/bias
//! embedding_model.blocks.0.norm.running_mean   → blocks_0_bn/running_mean
//! embedding_model.blocks.0.norm.running_var    → blocks_0_bn/running_var
//! embedding_model.blocks.N.tdnn1.conv.weight   → blocks_N_tdnn1/weight   (SERes2Net)
//! embedding_model.blocks.N.tdnn1.norm.weight   → blocks_N_tdnn1_bn/weight
//! … (see convert_ecapa.py for full mapping)
//! embedding_model.mfa.conv.weight              → mfa/weight
//! embedding_model.mfa.norm.weight              → mfa_bn/weight
//! embedding_model.asp.tdnn.conv.weight         → asp_tdnn/weight
//! embedding_model.asp.tdnn.norm.weight         → asp_tdnn_bn/weight
//! embedding_model.asp.conv.weight              → asp_conv/weight
//! embedding_model.asp_bn.weight                → asp_bn/weight
//! embedding_model.fc.weight                    → fc/weight
//! embedding_model.fc.bias                      → fc/bias
//! ```
//!
//! ## Validation status
//!
//! Wiring (shape propagation) is validated by unit tests with synthetic
//! weights (zeros for weights/bias, ones for BN running_var so BatchNorm
//! doesn't NaN). Identity accuracy has NOT been validated in-session — no
//! reference weights are present. Accuracy validation is the operator's
//! responsibility after running `scripts/convert_ecapa.py`.
//!
//! ## No auto-download
//!
//! The model is never fetched automatically. The operator provisions it via:
//! ```text
//! python scripts/convert_ecapa.py \
//!     --ckpt  ~/.cache/huggingface/hub/models--speechbrain--spkrec-ecapa-voxceleb/\
//!             snapshots/<hash>/embedding_model.ckpt \
//!     --out   ~/.neoth/models/speechbrain-spkrec-ecapa-voxceleb/model.safetensors
//! ```

use anyhow::{Context, Result};
use candle_core::{DType, Device, Module, ModuleT, Tensor};
use candle_nn::{
    BatchNormConfig, Conv1dConfig, VarBuilder, batch_norm, conv1d,
};

use crate::media::speaker_profile::unit_normalise;
use crate::providers::clip_engine::default_cache_dir;
use realfft::RealFftPlanner;

// ── architecture constants (from hyperparams.yaml) ───────────────────────────

/// HuggingFace repo id for the SpeechBrain ECAPA model.
const ECAPA_REPO: &str = "speechbrain/spkrec-ecapa-voxceleb";
/// Expected safetensors file name in the NEOTH model cache dir.
const SAFETENSORS_FILE: &str = "model.safetensors";

/// Number of Fbank mel bins (from hyperparams.yaml: n_mels: 80).
const N_MELS: usize = 80;
/// FFT size. SpeechBrain Fbank defaults to `n_fft = win_length = 400` (it does
/// NOT round up to a power of two), so 257-bin (512) framing fed the checkpoint
/// the wrong frequency resolution. realfft handles non-power-of-two sizes.
const N_FFT: usize = 400;
/// Analysis frame length: 25 ms @ 16 kHz.
const FRAME_LEN: usize = 400;
/// Hop length: 10 ms @ 16 kHz.
const HOP_LEN: usize = 160;
/// Working sample rate.
const SAMPLE_RATE: u32 = 16_000;
/// Minimum samples before encoding is attempted (~0.5 s @ 16 kHz).
const MIN_SAMPLES: usize = 8_000;
/// Minimum frames before pooling is meaningful.
const MIN_FRAMES: usize = 4;

/// Mel frequency lower bound (Hz) — SpeechBrain Fbank default.
const MEL_FMIN: f32 = 0.0;
/// Mel frequency upper bound (Hz) — SpeechBrain Fbank default (Nyquist for 16 kHz).
const MEL_FMAX: f32 = 8_000.0;

// ECAPA architecture parameters (from hyperparams.yaml).
/// channels[0]: initial TdnnBlock output channels.
const C0: usize = 1024;
/// channels[1..4]: SERes2NetBlock channels (same in and out for blocks 1-3).
const C1: usize = 1024;
// channels[4] = 3072 — MFA output (and ASP input).
const C_MFA: usize = 3072;
/// Attention channels for AttentiveStatisticsPooling.
const ATTN_CH: usize = 128;
/// Res2Net scale: number of groups the channels are split into.
const RES2NET_SCALE: usize = 8;
/// SE bottleneck channels.
const SE_CH: usize = 128;

/// Output embedding dimensionality.
/// Matches `lin_neurons` in hyperparams.yaml (= 192).
pub const ECAPA_EMBEDDING_DIM: usize = 192;

// ── shared helpers ────────────────────────────────────────────────────────────

fn relu(x: &Tensor) -> candle_core::Result<Tensor> {
    x.relu()
}

// ── TdnnBlock: Conv1d("same" padding) → ReLU → BatchNorm ─────────────────────

/// A single TDNN layer following SpeechBrain's TDNNBlock (ReLU activation,
/// "same" padding).  Used both as block[0] and as the MFA block.
struct TdnnBlock {
    conv: candle_nn::Conv1d,
    bn: candle_nn::BatchNorm,
}

impl TdnnBlock {
    fn new(
        in_ch: usize,
        out_ch: usize,
        kernel: usize,
        dilation: usize,
        conv_vb: VarBuilder,
        bn_vb: VarBuilder,
    ) -> Result<Self> {
        let cfg = Conv1dConfig {
            // SpeechBrain Conv1d uses "same" padding — symmetric for stride=1.
            padding: (kernel - 1) * dilation / 2,
            stride: 1,
            dilation,
            groups: 1,
        };
        let conv = conv1d(in_ch, out_ch, kernel, cfg, conv_vb)
            .context("TdnnBlock: conv1d")?;
        let bn = batch_norm(out_ch, BatchNormConfig::default(), bn_vb)
            .context("TdnnBlock: batch_norm")?;
        Ok(Self { conv, bn })
    }

    /// Forward in inference mode (BatchNorm uses running stats).
    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        // x: [batch, channels, time]
        let x = self.conv.forward(x)?;
        let x = relu(&x)?;
        self.bn.forward_t(&x, false)
    }
}

// ── Res2NetBlock ──────────────────────────────────────────────────────────────

/// Hierarchical dilated multi-scale block.
///
/// Splits channels into `scale` groups of `C/scale` each, then applies
/// a chain of TDNN sub-blocks where group i adds the previous group's output
/// before its conv. Groups [0] passes through; groups [1..scale-1] have a
/// TdnnBlock each (scale-1 total sub-blocks). Concatenates all group outputs.
///
/// Input/output: [batch, in_ch, time] — same channel count.
struct Res2NetBlock {
    /// scale-1 sub-TdnnBlocks (conv only — each is Conv1d+ReLU+BN).
    blocks: Vec<TdnnBlock>,
    scale: usize,
    group_ch: usize,
}

impl Res2NetBlock {
    fn new(
        channels: usize,
        kernel: usize,
        dilation: usize,
        scale: usize,
        vb: VarBuilder,
    ) -> Result<Self> {
        assert_eq!(
            channels % scale,
            0,
            "Res2Net: channels ({channels}) must be divisible by scale ({scale})"
        );
        let group_ch = channels / scale;
        let mut blocks = Vec::with_capacity(scale - 1);
        // scale-1 sub-blocks (SpeechBrain `self.blocks` is a ModuleList of
        // TDNNBlock for range(scale-1) indexed by i).
        for i in 0..(scale - 1) {
            let sub_vb = vb.pp(format!("blocks_{i}"));
            let sub_bn_vb = vb.pp(format!("blocks_{i}_bn"));
            blocks.push(TdnnBlock::new(
                group_ch, group_ch, kernel, dilation,
                sub_vb, sub_bn_vb,
            )?);
        }
        Ok(Self { blocks, scale, group_ch })
    }

    /// Forward pass matching SpeechBrain `Res2NetBlock.forward`.
    ///
    /// ```text
    /// i=0: y_0 = x_0          (pass-through)
    /// i=1: y_1 = block[0](x_1)
    /// i>1: y_i = block[i-1](x_i + y_{i-1})
    /// output: cat(y_0 … y_{scale-1}, dim=1)
    /// ```
    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        // Split along channel dim (dim=1) into `scale` equal pieces.
        let n_time = x.dim(2)?;
        let batch = x.dim(0)?;
        let mut ys: Vec<Tensor> = Vec::with_capacity(self.scale);

        for i in 0..self.scale {
            // Slice channels [i*group_ch .. (i+1)*group_ch].
            let x_i = x.narrow(1, i * self.group_ch, self.group_ch)?;
            let y_i = if i == 0 {
                // Group 0: pass-through.
                x_i
            } else if i == 1 {
                // Group 1: first sub-block, no accumulation.
                self.blocks[i - 1].forward(&x_i)?
            } else {
                // Group i>1: add previous group output before conv.
                let prev = &ys[i - 1];
                // prev has shape [batch, group_ch, time]; x_i same.
                debug_assert_eq!(prev.dims(), &[batch, self.group_ch, n_time]);
                let x_i_sum = (x_i + prev)?;
                self.blocks[i - 1].forward(&x_i_sum)?
            };
            ys.push(y_i);
        }

        // Concatenate all group outputs along channel dim.
        let refs: Vec<&Tensor> = ys.iter().collect();
        Tensor::cat(&refs, 1)
    }
}

// ── SEBlock ───────────────────────────────────────────────────────────────────

/// Squeeze-and-Excitation block (channel attention).
///
/// Global avg-pool over time → Linear(C→se_ch) → ReLU →
/// Linear(se_ch→out_ch) → Sigmoid → channel-wise scale.
///
/// Input:  [batch, in_ch, time]
/// Output: [batch, out_ch, time]
struct SeBlock {
    conv1: candle_nn::Conv1d,
    conv2: candle_nn::Conv1d,
}

impl SeBlock {
    fn new(
        in_ch: usize,
        se_ch: usize,
        out_ch: usize,
        vb: VarBuilder,
    ) -> Result<Self> {
        // Both convolutions use kernel=1 (pointwise, no padding needed).
        let k1_cfg = Conv1dConfig { padding: 0, stride: 1, dilation: 1, groups: 1 };
        let conv1 = conv1d(in_ch, se_ch, 1, k1_cfg, vb.pp("conv1"))
            .context("SEBlock: conv1")?;
        let conv2 = conv1d(se_ch, out_ch, 1, k1_cfg, vb.pp("conv2"))
            .context("SEBlock: conv2")?;
        Ok(Self { conv1, conv2 })
    }

    /// Forward (no length masking — full-sequence mean pooling).
    ///
    /// SpeechBrain uses a length mask in training; for inference without
    /// variable-length batching we use simple mean over the time axis.
    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        // x: [batch, in_ch, time]
        // Squeeze: global avg-pool over time → [batch, in_ch, 1].
        let s = x.mean_keepdim(2)?;
        // Linear + ReLU.
        let s = relu(&self.conv1.forward(&s)?)?;
        // Linear + Sigmoid.
        let s = candle_nn::ops::sigmoid(&self.conv2.forward(&s)?)?;
        // Channel-wise scale: broadcast over time.
        x.broadcast_mul(&s)
    }
}

// ── SERes2NetBlock ─────────────────────────────────────────────────────────────

/// One building block of ECAPA-TDNN:
/// TdnnBlock(1×1) → Res2NetBlock → TdnnBlock(1×1) → SEBlock + residual.
///
/// Mirrors SpeechBrain `SERes2NetBlock`. When in_ch ≠ out_ch a pointwise
/// conv shortcut is added; for ECAPA all blocks have equal channel counts
/// so no shortcut is needed — but we carry the field for completeness.
struct SeRes2NetBlock {
    tdnn1: TdnnBlock,
    res2net: Res2NetBlock,
    tdnn2: TdnnBlock,
    se: SeBlock,
    // Optional pointwise shortcut when in_ch ≠ out_ch.
    shortcut: Option<candle_nn::Conv1d>,
}

impl SeRes2NetBlock {
    fn new(
        in_ch: usize,
        out_ch: usize,
        kernel: usize,
        dilation: usize,
        scale: usize,
        se_ch: usize,
        vb: VarBuilder,
    ) -> Result<Self> {
        // tdnn1: 1×1 pointwise Conv.
        let tdnn1 = TdnnBlock::new(in_ch, out_ch, 1, 1,
            vb.pp("tdnn1"), vb.pp("tdnn1_bn"))?;
        // Res2Net body.
        let res2net = Res2NetBlock::new(out_ch, kernel, dilation, scale,
            vb.pp("res2net"))?;
        // tdnn2: 1×1 pointwise Conv.
        let tdnn2 = TdnnBlock::new(out_ch, out_ch, 1, 1,
            vb.pp("tdnn2"), vb.pp("tdnn2_bn"))?;
        // SE block.
        let se = SeBlock::new(out_ch, se_ch, out_ch, vb.pp("se"))?;
        // Shortcut only when dimensions differ (not needed for ECAPA's equal-ch blocks).
        let shortcut = if in_ch != out_ch {
            let cfg = Conv1dConfig { padding: 0, stride: 1, dilation: 1, groups: 1 };
            Some(conv1d(in_ch, out_ch, 1, cfg, vb.pp("shortcut"))
                .context("SERes2NetBlock: shortcut conv")?)
        } else {
            None
        };
        Ok(Self { tdnn1, res2net, tdnn2, se, shortcut })
    }

    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        // Residual path (with optional shortcut projection).
        let residual = if let Some(sc) = &self.shortcut {
            sc.forward(x)?
        } else {
            x.clone()
        };

        let x = self.tdnn1.forward(x)?;
        let x = self.res2net.forward(&x)?;
        let x = self.tdnn2.forward(&x)?;
        let x = self.se.forward(&x)?;

        // Residual add.
        x + residual
    }
}

// ── AttentiveStatisticsPooling ─────────────────────────────────────────────────

/// Attentive Statistics Pooling (ASP).
///
/// Computes attention-weighted mean and std over the time axis and
/// concatenates them, yielding [batch, 2*channels].
///
/// With `global_context=true` (ECAPA default) the attention input is the
/// concatenation of [x, broadcast_mean, broadcast_std] → 3×channels wide.
/// A TdnnBlock reduces this to `attn_ch`, followed by a pointwise conv to
/// `channels`; softmax over time produces per-channel attention weights.
///
/// Reference: SpeechBrain `AttentiveStatisticsPooling.forward`.
struct AttentiveStatisticsPooling {
    /// TdnnBlock: (3*C → attn_ch, k=1, d=1) when global_context=true.
    attn_tdnn: TdnnBlock,
    /// Pointwise conv: (attn_ch → C, k=1).
    attn_conv: candle_nn::Conv1d,
    channels: usize,
}

impl AttentiveStatisticsPooling {
    fn new(channels: usize, attn_ch: usize, vb: VarBuilder) -> Result<Self> {
        // global_context=true → input channels = channels * 3.
        let attn_tdnn = TdnnBlock::new(
            channels * 3, attn_ch, 1, 1,
            vb.pp("tdnn"), vb.pp("tdnn_bn"),
        )?;
        let cfg = Conv1dConfig { padding: 0, stride: 1, dilation: 1, groups: 1 };
        let attn_conv = conv1d(attn_ch, channels, 1, cfg, vb.pp("conv"))
            .context("ASP: attn_conv")?;
        Ok(Self { attn_tdnn, attn_conv, channels })
    }

    /// Forward.
    ///
    /// Input:  [batch, C, T]
    /// Output: [batch, 2*C]   (mean ‖ std, flattened)
    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        let (batch, _c, t) = x.dims3()?;

        // ── global context: compute utterance-level mean + std for broadcast ──
        // SpeechBrain uses a uniform mask (all ones) when lengths are absent.
        // (uniform weight = 1/T — mean_keepdim already divides by T)
        // Weighted mean: same as simple mean.
        let mean = x.mean_keepdim(2)?; // [batch, C, 1]
        // Weighted std (biased, SpeechBrain style):
        //   std = sqrt( E[(x - mean)²] + eps )
        let diff = x.broadcast_sub(&mean)?;          // [batch, C, T]
        let var = diff.sqr()?.mean_keepdim(2)?;       // [batch, C, 1]
        let std = (var + 1e-12f64)?.sqrt()?;         // [batch, C, 1]

        // Broadcast mean and std over time, then concatenate with x.
        let mean_t = mean.expand(&[batch, self.channels, t])?;
        let std_t  = std.expand(&[batch, self.channels, t])?;
        let attn   = Tensor::cat(&[x, &mean_t, &std_t], 1)?; // [batch, 3C, T]

        // Attention weights: TdnnBlock → Tanh not needed because SpeechBrain
        // wraps the TdnnBlock output (which already has ReLU) in a Tanh, then
        // a conv. We skip the Tanh here because the TdnnBlock already ends with
        // BN and the attention score is relative (softmax normalises it).
        // Note: SpeechBrain actually applies:
        //   attn = self.conv(self.tanh(self.tdnn(attn)))
        // The TdnnBlock includes ReLU+BN; tanh is an extra activation.
        // We apply tanh after the TdnnBlock's output, before the attn_conv.
        let attn = self.attn_tdnn.forward(&attn)?;   // [batch, attn_ch, T]
        let attn = attn.tanh()?;                      // tanh on top of BN output
        let attn = self.attn_conv.forward(&attn)?;    // [batch, C, T]

        // Softmax over time axis (dim=2).
        let attn = candle_nn::ops::softmax(&attn, 2)?; // [batch, C, T]

        // Attentive mean: sum_t( attn_t * x_t ) per channel.
        let w_mean = (attn.clone() * x)?.sum(2)?;                 // [batch, C]
        // Attentive std:
        //   std = sqrt( sum_t( attn_t * (x_t - mean)² ) + eps )
        let mean2 = w_mean.unsqueeze(2)?;                          // [batch, C, 1]
        let diff2 = x.broadcast_sub(&mean2)?;                      // [batch, C, T]
        let w_var = (attn * diff2.sqr()?)?.sum(2)?;                // [batch, C]
        let w_std = (w_var + 1e-12f64)?.sqrt()?;                  // [batch, C]

        // Concatenate mean ‖ std.
        Tensor::cat(&[&w_mean, &w_std], 1)  // [batch, 2*C]
    }

}

// ── EcapaTdnn ─────────────────────────────────────────────────────────────────

/// ECAPA-TDNN speaker-embedding encoder (dormant until weights are provisioned).
///
/// Construct via [`EcapaTdnn::try_load`]. Returns `None` if the safetensors
/// file is not in the NEOTH model cache — the caller falls back to the
/// x-vector or log-mel encoder.
pub struct EcapaTdnn {
    /// block[0]: initial TdnnBlock (80 → 1024, k=5, d=1).
    block0: TdnnBlock,
    /// blocks[1..3]: three SERes2NetBlocks with dilations 2, 3, 4.
    se_blocks: [SeRes2NetBlock; 3],
    /// MFA TdnnBlock: (3*1024=3072 → 3072, k=1, d=1).
    mfa: TdnnBlock,
    /// Attentive Statistics Pooling (3072 channels, 128 attn).
    asp: AttentiveStatisticsPooling,
    /// BatchNorm after ASP: input 6144.
    asp_bn: candle_nn::BatchNorm,
    /// Final pointwise conv: 6144 → 192.
    fc: candle_nn::Conv1d,
    device: Device,
    /// Pre-computed mel filterbank [N_MELS][N_FFT/2+1].
    filterbank: Vec<Vec<f32>>,
}

impl EcapaTdnn {
    /// Try to load the encoder from the NEOTH model cache.
    ///
    /// Returns `None` (no error) if the safetensors file does not exist.
    /// Returns `Err` only on a genuine load failure (corrupt file, wrong
    /// tensor shape, etc.) so the caller can log a warning and fall back.
    pub fn try_load() -> Option<Self> {
        match Self::load_inner() {
            Ok(enc) => Some(enc),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such file") || msg.contains("os error 2") {
                    tracing::debug!(
                        "ecapa: weights not cached ({}), trying x-vector fallback",
                        default_cache_dir(ECAPA_REPO)
                            .join(SAFETENSORS_FILE)
                            .display()
                    );
                } else {
                    tracing::warn!(error = %e, "ecapa: load failed, trying x-vector fallback");
                }
                None
            }
        }
    }

    fn load_inner() -> Result<Self> {
        let weights_path = default_cache_dir(ECAPA_REPO).join(SAFETENSORS_FILE);
        if !weights_path.exists() {
            anyhow::bail!("No such file: {}", weights_path.display());
        }
        let device = Device::Cpu;
        // SAFETY: from_mmaped_safetensors requires the mapped file to remain
        // unmodified for the lifetime of the VarBuilder. Weights are
        // operator-provisioned read-only artifacts written once by the
        // convert_ecapa.py script; the same safety contract is used in
        // clip_engine.rs (search: "SAFETY: `from_mmaped_safetensors`").
        let vb = unsafe {
            candle_nn::VarBuilder::from_mmaped_safetensors(
                &[&weights_path], DType::F32, &device,
            )
            .with_context(|| format!("mmap safetensors {}", weights_path.display()))?
        };

        Self::build_from_vb(vb, device)
    }

    fn build_from_vb(vb: VarBuilder, device: Device) -> Result<Self> {
        // block[0]: TdnnBlock(80 → 1024, k=5, d=1).
        let block0 = TdnnBlock::new(N_MELS, C0, 5, 1,
            vb.pp("blocks_0"), vb.pp("blocks_0_bn"))?;

        // blocks[1..3]: SERes2NetBlocks with dilations 2, 3, 4.
        // From hyperparams.yaml: channels[1]=channels[2]=channels[3]=1024,
        // kernel_sizes[1]=kernel_sizes[2]=kernel_sizes[3]=3,
        // dilations[1]=2, dilations[2]=3, dilations[3]=4.
        let dilations = [2usize, 3, 4];
        let mut se_block_vec = Vec::with_capacity(3);
        for (i, &dil) in dilations.iter().enumerate() {
            let block_idx = i + 1; // SpeechBrain block indices 1, 2, 3
            se_block_vec.push(SeRes2NetBlock::new(
                C1, C1, 3, dil,
                RES2NET_SCALE, SE_CH,
                vb.pp(format!("blocks_{block_idx}")),
            )?);
        }
        let se_blocks: [SeRes2NetBlock; 3] = se_block_vec
            .try_into()
            .unwrap_or_else(|_| unreachable!("pushed exactly 3 SERes2NetBlocks"));

        // MFA TdnnBlock: concat of blocks[1..4] → 3*C1=3072 channels, then
        // project to C_MFA=3072 with k=1, d=1.
        let mfa = TdnnBlock::new(C1 * 3, C_MFA, 1, 1,
            vb.pp("mfa"), vb.pp("mfa_bn"))?;

        // ASP: 3072 input channels, 128 attention channels.
        let asp = AttentiveStatisticsPooling::new(C_MFA, ATTN_CH, vb.pp("asp"))?;

        // BatchNorm after ASP: input 2 * C_MFA = 6144.
        let asp_bn = batch_norm(C_MFA * 2, BatchNormConfig::default(), vb.pp("asp_bn"))
            .context("ecapa: asp_bn")?;

        // Final conv (fc): 6144 → 192, k=1 (no bias in SpeechBrain's Conv1d wrapper).
        // SpeechBrain Conv1d default has bias=True.
        let fc_cfg = Conv1dConfig { padding: 0, stride: 1, dilation: 1, groups: 1 };
        let fc = conv1d(C_MFA * 2, ECAPA_EMBEDDING_DIM, 1, fc_cfg, vb.pp("fc"))
            .context("ecapa: fc")?;

        let filterbank = ecapa_fbank_filterbank();
        Ok(Self { block0, se_blocks, mfa, asp, asp_bn, fc, device, filterbank })
    }

    /// Encode 16 kHz mono f32 samples into a unit-norm ECAPA embedding.
    ///
    /// Returns `None` if the clip is too short or the forward pass fails.
    /// Embedding failures are logged and do not abort transcription.
    pub fn embed(&self, samples_16k: &[f32]) -> Option<Vec<f32>> {
        if samples_16k.len() < MIN_SAMPLES {
            return None;
        }
        match self.embed_inner(samples_16k) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "ecapa: forward pass failed");
                None
            }
        }
    }

    fn embed_inner(&self, samples: &[f32]) -> Result<Vec<f32>> {
        // 1. Fbank front-end → [n_frames, N_MELS].
        let frames = ecapa_fbank_frames(samples, &self.filterbank);
        if frames.len() < MIN_FRAMES {
            anyhow::bail!("too few frames ({})", frames.len());
        }
        let n_frames = frames.len();

        // 2. Sentence-level mean subtraction
        //    (mean_var_norm: norm_type=sentence, std_norm=False).
        let frames = mean_subtract_frames(frames);

        // 3. Convert to tensor [1, N_MELS, n_frames] (batch=1, channels, time).
        // Channel-major layout: all frames for mel-bin 0, then bin 1, …
        let mut flat = Vec::with_capacity(N_MELS * n_frames);
        for m in 0..N_MELS {
            for t in 0..n_frames {
                flat.push(frames[t][m]);
            }
        }
        // x: [1, 80, T]
        let x = Tensor::from_vec(flat, (1, N_MELS, n_frames), &self.device)?;

        // 4. block[0]: TdnnBlock(80 → 1024, k=5, d=1).
        let x0 = self.block0.forward(&x)?;  // [1, 1024, T]

        // 5. SE-Res2Net blocks with dilations 2, 3, 4.
        //    Collect outputs for MFA (multi-feature aggregation).
        let x1 = self.se_blocks[0].forward(&x0)?; // [1, 1024, T]
        let x2 = self.se_blocks[1].forward(&x1)?; // [1, 1024, T]
        let x3 = self.se_blocks[2].forward(&x2)?; // [1, 1024, T]

        // 6. MFA: concatenate blocks[1..4] outputs along channel dim.
        //    SpeechBrain: `x = torch.cat(xl[1:], dim=1)` where xl includes
        //    block[0] and the 3 SERes2Net outputs — so xl[1:] = [x1, x2, x3].
        //    Result: [1, 3072, T].
        let x_cat = Tensor::cat(&[&x1, &x2, &x3], 1)?; // [1, 3072, T]

        // 7. MFA TdnnBlock: 3072 → 3072, k=1, d=1.
        let x_mfa = self.mfa.forward(&x_cat)?; // [1, 3072, T]

        // 8. Attentive Statistics Pooling → [1, 6144].
        let x_asp = self.asp.forward(&x_mfa)?; // [1, 6144]

        // 9. BatchNorm after ASP (treat as [1, 6144, 1] for conv-friendly BN).
        //    SpeechBrain BatchNorm1d with skip_transpose=True expects [B, C, T].
        //    Unsqueeze time dim, apply BN in inference mode, squeeze back.
        let x_asp3 = x_asp.unsqueeze(2)?;              // [1, 6144, 1]
        let x_bn   = self.asp_bn.forward_t(&x_asp3, false)?; // [1, 6144, 1]

        // 10. Final fc Conv1d(6144 → 192, k=1).
        let x_fc = self.fc.forward(&x_bn)?;             // [1, 192, 1]

        // 11. Flatten to Vec<f32> and L2-normalise.
        let vec: Vec<f32> = x_fc.flatten_all()?.to_vec1()?;
        debug_assert_eq!(vec.len(), ECAPA_EMBEDDING_DIM);
        Ok(unit_normalise(&vec))
    }
}

// ── Fbank front-end (SpeechBrain Fbank with n_mels=80) ───────────────────────

fn hz_to_mel(hz: f32) -> f32 {
    2595.0 * (1.0 + hz / 700.0).log10()
}

fn mel_to_hz(mel: f32) -> f32 {
    700.0 * (10.0_f32.powf(mel / 2595.0) - 1.0)
}

/// Build a triangular mel filterbank for ECAPA's 80-band front-end.
fn ecapa_fbank_filterbank() -> Vec<Vec<f32>> {
    let n_bins = N_FFT / 2 + 1;
    let mel_min = hz_to_mel(MEL_FMIN);
    let mel_max = hz_to_mel(MEL_FMAX);
    let pts: Vec<f32> = (0..N_MELS + 2)
        .map(|i| {
            let mel = mel_min + (mel_max - mel_min) * i as f32 / (N_MELS + 1) as f32;
            mel_to_hz(mel)
        })
        .collect();
    let bin = |hz: f32| hz * N_FFT as f32 / SAMPLE_RATE as f32;
    let mut fb = vec![vec![0.0f32; n_bins]; N_MELS];
    for (m, filt) in fb.iter_mut().enumerate() {
        let left   = bin(pts[m]);
        let center = bin(pts[m + 1]);
        let right  = bin(pts[m + 2]);
        for (k, w) in filt.iter_mut().enumerate() {
            let kf = k as f32;
            *w = if kf >= left && kf <= center && center > left {
                (kf - left) / (center - left)
            } else if kf > center && kf <= right && right > center {
                (right - kf) / (right - center)
            } else {
                0.0
            };
        }
    }
    fb
}

/// Compute log-mel filterbank energies (Fbank, NOT MFCC — no DCT).
fn ecapa_fbank_frames(samples: &[f32], fb: &[Vec<f32>]) -> Vec<Vec<f32>> {
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let mut indata   = r2c.make_input_vec();
    let mut spectrum = r2c.make_output_vec();

    // PERIODIC HAMMING window — SpeechBrain STFT defaults to
    // `torch.hamming_window(win_length)` (periodic=True): `0.54 - 0.46·cos(2πn/N)`
    // with denominator N (= FRAME_LEN). The earlier symmetric-Hann (0.5/0.5,
    // denom N-1) fed the checkpoint up to ~8% per-sample amplitude error.
    let window: Vec<f32> = (0..FRAME_LEN)
        .map(|n| 0.54 - 0.46 * (2.0 * std::f32::consts::PI * n as f32 / FRAME_LEN as f32).cos())
        .collect();

    // center=True (SpeechBrain/torchaudio STFT default): pad N_FFT/2 on both
    // sides so frame t is centred at t·HOP. torch pads with 'reflect'; we
    // zero-pad — the difference only touches the first/last frame and is
    // negligible after utterance-level mean/std pooling.
    let pad = N_FFT / 2;
    let mut padded = Vec::with_capacity(samples.len() + 2 * pad);
    padded.resize(pad, 0.0f32);
    padded.extend_from_slice(samples);
    padded.resize(padded.len() + pad, 0.0f32);
    let samples = padded.as_slice();

    let mut frames = Vec::new();
    let mut start = 0usize;
    while start + FRAME_LEN <= samples.len() {
        for v in indata.iter_mut() {
            *v = 0.0;
        }
        for (n, w) in window.iter().enumerate() {
            indata[n] = samples[start + n] * w;
        }
        if r2c.process(&mut indata, &mut spectrum).is_err() {
            break;
        }
        let mut mel = vec![0.0f32; N_MELS];
        for (m, filt) in fb.iter().enumerate() {
            let mut e = 0.0f32;
            for (k, c) in spectrum.iter().enumerate() {
                e += filt[k] * c.norm_sqr();
            }
            mel[m] = (e + 1e-10).ln();
        }
        frames.push(mel);
        start += HOP_LEN;
    }
    frames
}

/// Sentence-level mean subtraction (std_norm=False).
fn mean_subtract_frames(mut frames: Vec<Vec<f32>>) -> Vec<Vec<f32>> {
    if frames.is_empty() {
        return frames;
    }
    let n = frames.len() as f32;
    let mut mean = vec![0.0f32; N_MELS];
    for f in &frames {
        for (m, v) in f.iter().enumerate() {
            mean[m] += v;
        }
    }
    for v in &mut mean {
        *v /= n;
    }
    for frame in &mut frames {
        for (m, v) in frame.iter_mut().enumerate() {
            *v -= mean[m];
        }
    }
    frames
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use candle_core::{DType, Device, Tensor};
    use candle_nn::VarBuilder;
    use std::collections::HashMap;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn sine_1s(freq_hz: f32) -> Vec<f32> {
        (0..SAMPLE_RATE as usize)
            .map(|i| {
                (2.0 * std::f32::consts::PI * freq_hz * i as f32 / SAMPLE_RATE as f32).sin()
            })
            .collect()
    }

    /// Build a VarBuilder with all-zero weights and running_var=1 so BatchNorm
    /// doesn't produce NaN in the sqrt.  running_var=1 → BN normalises to identity.
    fn proper_vb(dev: &Device) -> VarBuilder<'static> {
        let mut t: HashMap<String, Tensor> = HashMap::new();

        // ── free helper fns (avoid multiple closure borrows of `t`) ──────────
        fn zz(dev: &Device, shape: &[usize]) -> Tensor {
            Tensor::zeros(shape, DType::F32, dev).unwrap()
        }
        fn oo(dev: &Device, shape: &[usize]) -> Tensor {
            Tensor::ones(shape, DType::F32, dev).unwrap()
        }
        // Insert Conv1d weight [out, in, k] + bias [out].
        fn ins_conv(t: &mut HashMap<String, Tensor>, dev: &Device,
                    prefix: &str, out_ch: usize, in_ch: usize, k: usize) {
            t.insert(format!("{prefix}.weight"), zz(dev, &[out_ch, in_ch, k]));
            t.insert(format!("{prefix}.bias"),   zz(dev, &[out_ch]));
        }
        // Insert BatchNorm γ/β/running_mean/running_var (var=1 to avoid NaN).
        fn ins_bn(t: &mut HashMap<String, Tensor>, dev: &Device,
                  prefix: &str, ch: usize) {
            t.insert(format!("{prefix}.weight"),       oo(dev, &[ch]));
            t.insert(format!("{prefix}.bias"),         zz(dev, &[ch]));
            t.insert(format!("{prefix}.running_mean"), zz(dev, &[ch]));
            t.insert(format!("{prefix}.running_var"),  oo(dev, &[ch]));
        }

        // block[0]: TdnnBlock(80 → 1024, k=5).
        ins_conv(&mut t, dev, "blocks_0", C0, N_MELS, 5);
        ins_bn(&mut t, dev, "blocks_0_bn", C0);

        // blocks[1..3]: SERes2NetBlocks.
        for i in 1..=3usize {
            let p = format!("blocks_{i}");
            // tdnn1 (1×1, C1 → C1).
            ins_conv(&mut t, dev, &format!("{p}.tdnn1"),    C1, C1, 1);
            ins_bn(&mut t, dev, &format!("{p}.tdnn1_bn"), C1);
            // Res2Net sub-blocks (scale-1 = 7 sub-blocks, each group_ch=128).
            let gc = C1 / RES2NET_SCALE; // 1024/8 = 128
            for j in 0..(RES2NET_SCALE - 1) {
                ins_conv(&mut t, dev, &format!("{p}.res2net.blocks_{j}"),    gc, gc, 3);
                ins_bn(&mut t, dev, &format!("{p}.res2net.blocks_{j}_bn"), gc);
            }
            // tdnn2 (1×1, C1 → C1).
            ins_conv(&mut t, dev, &format!("{p}.tdnn2"),    C1, C1, 1);
            ins_bn(&mut t, dev, &format!("{p}.tdnn2_bn"), C1);
            // SE block (pointwise convs — no BN; conv1: C1 → SE_CH, conv2: SE_CH → C1).
            t.insert(format!("{p}.se.conv1.weight"), zz(dev, &[SE_CH, C1, 1]));
            t.insert(format!("{p}.se.conv1.bias"),   zz(dev, &[SE_CH]));
            t.insert(format!("{p}.se.conv2.weight"), zz(dev, &[C1, SE_CH, 1]));
            t.insert(format!("{p}.se.conv2.bias"),   zz(dev, &[C1]));
        }

        // MFA TdnnBlock (3072 → 3072, k=1).
        ins_conv(&mut t, dev, "mfa",    C_MFA, C1 * 3, 1);
        ins_bn(&mut t, dev, "mfa_bn", C_MFA);

        // ASP tdnn (3*3072 → ATTN_CH, k=1) + conv (ATTN_CH → 3072, k=1).
        ins_conv(&mut t, dev, "asp.tdnn",    ATTN_CH, C_MFA * 3, 1);
        ins_bn(&mut t, dev, "asp.tdnn_bn", ATTN_CH);
        t.insert("asp.conv.weight".into(), zz(dev, &[C_MFA, ATTN_CH, 1]));
        t.insert("asp.conv.bias".into(),   zz(dev, &[C_MFA]));

        // asp_bn (6144).
        ins_bn(&mut t, dev, "asp_bn", C_MFA * 2);

        // fc Conv1d(6144 → 192, k=1).
        t.insert("fc.weight".into(), zz(dev, &[ECAPA_EMBEDDING_DIM, C_MFA * 2, 1]));
        t.insert("fc.bias".into(),   zz(dev, &[ECAPA_EMBEDDING_DIM]));

        VarBuilder::from_tensors(t, DType::F32, dev)
    }

    fn make_encoder_with_proper_weights() -> EcapaTdnn {
        let device = Device::Cpu;
        let vb = proper_vb(&device);
        EcapaTdnn::build_from_vb(vb, device).expect("build EcapaTdnn with synthetic weights")
    }

    // ── unit tests ───────────────────────────────────────────────────────────

    #[test]
    fn ecapa_embedding_dim_constant_is_192() {
        assert_eq!(ECAPA_EMBEDDING_DIM, 192);
    }

    #[test]
    fn filterbank_has_correct_dimensions() {
        let fb = ecapa_fbank_filterbank();
        assert_eq!(fb.len(), N_MELS, "filterbank row count must be N_MELS=80");
        assert_eq!(fb[0].len(), N_FFT / 2 + 1, "filterbank column count");
    }

    #[test]
    fn fbank_frames_returns_mel_frames() {
        let samples = sine_1s(440.0);
        let fb = ecapa_fbank_filterbank();
        let frames = ecapa_fbank_frames(&samples, &fb);
        // At HOP_LEN=160, 16000 samples → ~99 frames.
        assert!(frames.len() >= 90, "expected ~99 frames, got {}", frames.len());
        assert_eq!(frames[0].len(), N_MELS);
    }

    #[test]
    fn mean_subtract_is_zero_mean() {
        let samples = sine_1s(300.0);
        let fb = ecapa_fbank_filterbank();
        let frames = ecapa_fbank_frames(&samples, &fb);
        let norm = mean_subtract_frames(frames);
        let n = norm.len() as f32;
        for m in 0..N_MELS {
            let col_mean: f32 = norm.iter().map(|f| f[m]).sum::<f32>() / n;
            assert!(
                col_mean.abs() < 1e-4,
                "mel bin {m} mean after subtraction = {col_mean}"
            );
        }
    }

    #[test]
    fn res2net_block_shape() {
        // Validates that Res2NetBlock preserves shape: [1, 1024, 50] → [1, 1024, 50].
        let dev = Device::Cpu;
        let mut t: HashMap<String, Tensor> = HashMap::new();
        let zeros = |shape: &[usize]| Tensor::zeros(shape, DType::F32, &dev).unwrap();
        let ones  = |shape: &[usize]| Tensor::ones(shape, DType::F32, &dev).unwrap();
        let gc = C1 / RES2NET_SCALE; // 128
        for j in 0..(RES2NET_SCALE - 1) {
            t.insert(format!("blocks_{j}.weight"), zeros(&[gc, gc, 3]));
            t.insert(format!("blocks_{j}.bias"),   zeros(&[gc]));
            t.insert(format!("blocks_{j}_bn.weight"),       ones(&[gc]));
            t.insert(format!("blocks_{j}_bn.bias"),         zeros(&[gc]));
            t.insert(format!("blocks_{j}_bn.running_mean"), zeros(&[gc]));
            t.insert(format!("blocks_{j}_bn.running_var"),  ones(&[gc]));
        }
        let vb = VarBuilder::from_tensors(t, DType::F32, &dev);
        let block = Res2NetBlock::new(C1, 3, 2, RES2NET_SCALE, vb).unwrap();
        let x = Tensor::zeros(&[1usize, C1, 50], DType::F32, &dev).unwrap();
        let y = block.forward(&x).unwrap();
        assert_eq!(y.dims(), &[1, C1, 50], "Res2NetBlock must preserve [batch, C, T]");
    }

    #[test]
    fn se_block_shape() {
        // Validates that SEBlock preserves [1, 1024, 50] → [1, 1024, 50].
        let dev = Device::Cpu;
        let mut t: HashMap<String, Tensor> = HashMap::new();
        let zeros = |shape: &[usize]| Tensor::zeros(shape, DType::F32, &dev).unwrap();
        t.insert("conv1.weight".into(), zeros(&[SE_CH, C1, 1]));
        t.insert("conv1.bias".into(),   zeros(&[SE_CH]));
        t.insert("conv2.weight".into(), zeros(&[C1, SE_CH, 1]));
        t.insert("conv2.bias".into(),   zeros(&[C1]));
        let vb  = VarBuilder::from_tensors(t, DType::F32, &dev);
        let se  = SeBlock::new(C1, SE_CH, C1, vb).unwrap();
        let x   = Tensor::zeros(&[1usize, C1, 50], DType::F32, &dev).unwrap();
        let y   = se.forward(&x).unwrap();
        assert_eq!(y.dims(), &[1, C1, 50], "SEBlock must preserve shape");
    }

    #[test]
    fn asp_output_shape() {
        // Validates AttentiveStatisticsPooling: [1, 3072, T] → [1, 6144].
        let dev = Device::Cpu;
        let mut t: HashMap<String, Tensor> = HashMap::new();
        let zeros = |shape: &[usize]| Tensor::zeros(shape, DType::F32, &dev).unwrap();
        let ones  = |shape: &[usize]| Tensor::ones(shape, DType::F32, &dev).unwrap();
        t.insert("tdnn.weight".into(),       zeros(&[ATTN_CH, C_MFA * 3, 1]));
        t.insert("tdnn.bias".into(),         zeros(&[ATTN_CH]));
        t.insert("tdnn_bn.weight".into(),    ones(&[ATTN_CH]));
        t.insert("tdnn_bn.bias".into(),      zeros(&[ATTN_CH]));
        t.insert("tdnn_bn.running_mean".into(), zeros(&[ATTN_CH]));
        t.insert("tdnn_bn.running_var".into(),  ones(&[ATTN_CH]));
        t.insert("conv.weight".into(), zeros(&[C_MFA, ATTN_CH, 1]));
        t.insert("conv.bias".into(),   zeros(&[C_MFA]));
        let vb  = VarBuilder::from_tensors(t, DType::F32, &dev);
        let asp = AttentiveStatisticsPooling::new(C_MFA, ATTN_CH, vb).unwrap();
        let x   = Tensor::zeros(&[1usize, C_MFA, 30], DType::F32, &dev).unwrap();
        let y   = asp.forward(&x).unwrap();
        assert_eq!(y.dims(), &[1, C_MFA * 2], "ASP output must be [batch, 2*channels]");
    }

    #[test]
    fn ecapa_forward_yields_192_dim() {
        // Full end-to-end forward with synthetic weights.
        // Validates wiring: zero-weight network must produce finite 192-dim output.
        let enc = make_encoder_with_proper_weights();
        let samples = sine_1s(300.0);
        let result = enc.embed_inner(&samples);
        match result {
            Ok(v) => {
                assert_eq!(v.len(), ECAPA_EMBEDDING_DIM, "embedding dim must be 192");
                assert!(
                    v.iter().all(|x| x.is_finite()),
                    "all embedding values must be finite"
                );
                assert!(
                    v.iter().all(|x| !x.is_nan()),
                    "no NaN in embedding output"
                );
            }
            Err(e) => {
                // Known: zero weights → all-zero output after BN; unit_normalise
                // on a zero vector returns zero (no panic, no NaN).
                panic!("forward pass failed unexpectedly with proper BN init: {e}");
            }
        }
    }

    #[test]
    fn too_short_clip_returns_none() {
        let enc = make_encoder_with_proper_weights();
        let short = vec![0.0f32; MIN_SAMPLES - 1];
        assert!(enc.embed(&short).is_none(), "sub-MIN_SAMPLES must return None");
    }
}
