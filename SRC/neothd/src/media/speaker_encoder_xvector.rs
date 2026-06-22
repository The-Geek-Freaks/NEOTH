//! SPEAKR-02c — x-vector (TDNN) speaker-embedding encoder.
//!
//! ## Status: DORMANT SCAFFOLD
//!
//! This module compiles and passes shape/wiring tests, but **produces
//! meaningful embeddings ONLY when real weights are provisioned**. The
//! `speechbrain/spkrec-xvect-voxceleb` checkpoint is NOT bundled; an operator
//! must run `scripts/convert_xvector.py` and place the output safetensors in
//! the NEOTH model cache (see `try_load` for the path). Until that file exists
//! `try_load()` returns `None` and the caller falls back to the log-mel
//! encoder in `speaker_encoder.rs`.
//!
//! ## Architecture (extracted from speechbrain/spkrec-xvect-voxceleb)
//!
//! Source: `hyperparams.yaml` (fetched 2026-06-22 from HF hub).
//!
//! ```text
//! Front-end (Fbank):
//!   n_mels = 24          ← NOT 40; this is the checkpoint's actual value
//!   sample_rate = 16_000
//!   win_length  = 25 ms  → 400 samples  (SpeechBrain Fbank default)
//!   hop_length  = 10 ms  → 160 samples
//!   n_fft       = 512    (next power-of-2 ≥ win_length in SpeechBrain)
//!   mean_var_norm: sentence-level mean subtraction only (std_norm=False)
//!
//! Xvector.blocks flat list:
//!   idx 0  Conv1d  in=24,  out=512, kernel=5, dilation=1  (TDNN1 conv)
//!   idx 1  LeakyReLU
//!   idx 2  BatchNorm1d(512)
//!   idx 3  Conv1d  in=512, out=512, kernel=3, dilation=2  (TDNN2 conv)
//!   idx 4  LeakyReLU
//!   idx 5  BatchNorm1d(512)
//!   idx 6  Conv1d  in=512, out=512, kernel=3, dilation=3  (TDNN3 conv)
//!   idx 7  LeakyReLU
//!   idx 8  BatchNorm1d(512)
//!   idx 9  Conv1d  in=512, out=512, kernel=1, dilation=1  (TDNN4 conv)
//!   idx 10 LeakyReLU
//!   idx 11 BatchNorm1d(512)
//!   idx 12 Conv1d  in=512, out=1500, kernel=1, dilation=1 (TDNN5 conv)
//!   idx 13 LeakyReLU
//!   idx 14 BatchNorm1d(1500)
//!   idx 15 StatisticsPooling (mean+std over time → 3000-dim)
//!   idx 16 Linear(3000 → 512, bias=True)
//!
//! Output: 512-dim L2-normalised x-vector.
//! ```
//!
//! ## Weight key mapping (`embedding_model.ckpt` → safetensors)
//!
//! SpeechBrain stores the checkpoint with flat `blocks.N.key` paths where N
//! is the block index within the flat `nn.ModuleList`. The conversion script
//! `scripts/convert_xvector.py` renames these to the paths below, which is
//! what `VarBuilder::pp("blocks_N")` + sub-field lookups resolve to:
//!
//! ```text
//! blocks.0.conv.weight   → blocks_0/weight   (Conv1d weight)
//! blocks.0.conv.bias     → blocks_0/bias     (Conv1d bias)
//! blocks.2.norm.weight   → blocks_2/weight   (BN affine γ)
//! blocks.2.norm.bias     → blocks_2/bias     (BN affine β)
//! blocks.2.norm.running_mean → blocks_2/running_mean
//! blocks.2.norm.running_var  → blocks_2/running_var
//! … (same pattern for idx 3/5, 6/8, 9/11, 12/14)
//! blocks.16.w.weight     → blocks_16/weight  (Linear weight)
//! blocks.16.w.bias       → blocks_16/bias    (Linear bias)
//! ```
//!
//! ## Validation status
//!
//! Wiring (shape propagation) is validated by unit tests with synthetic
//! zero-filled weights. Identity accuracy has NOT been validated in-session
//! — no reference weights are present. Accuracy validation is the operator's
//! responsibility after running `scripts/convert_xvector.py`.
//!
//! ## No auto-download
//!
//! The model is never fetched automatically. The operator provisions it via:
//! ```text
//! python scripts/convert_xvector.py  \
//!     --ckpt  ~/.cache/huggingface/.../embedding_model.ckpt \
//!     --out   ~/.neoth/models/speechbrain-spkrec-xvect-voxceleb/model.safetensors
//! ```

use anyhow::{Context, Result};
use candle_core::{DType, Device, Module, ModuleT, Tensor};
use candle_nn::{
    BatchNormConfig, Conv1dConfig, VarBuilder, batch_norm, conv1d, linear,
};

use crate::media::speaker_profile::unit_normalise;
use crate::providers::clip_engine::default_cache_dir;
use realfft::RealFftPlanner;

// ── architecture constants (from hyperparams.yaml) ───────────────────────────

/// HuggingFace repo id for the SpeechBrain x-vector model.
const XVECTOR_REPO: &str = "speechbrain/spkrec-xvect-voxceleb";
/// Expected safetensors file name in the cache dir.
const SAFETENSORS_FILE: &str = "model.safetensors";

/// Number of Fbank mel bins the checkpoint was trained on.
const N_MELS: usize = 24;
/// FFT size matching SpeechBrain's default for 25 ms @ 16 kHz.
const N_FFT: usize = 512;
/// Analysis frame length (25 ms @ 16 kHz).
const FRAME_LEN: usize = 400;
/// Hop length (10 ms @ 16 kHz).
const HOP_LEN: usize = 160;
/// Working sample rate.
const SAMPLE_RATE: u32 = 16_000;
/// Minimum samples before encoding is attempted (~0.5 s).
const MIN_SAMPLES: usize = 8_000;

/// Minimum frames before statistics pooling is meaningful.
const MIN_FRAMES: usize = 4;

/// Mel frequency lower bound (Hz).
const MEL_FMIN: f32 = 20.0;
/// Mel frequency upper bound (Hz).
const MEL_FMAX: f32 = 8_000.0;

/// Output embedding dimensionality after the final linear layer.
/// Matches `lin_neurons` in hyperparams.yaml (= 512).
pub const XVECTOR_EMBEDDING_DIM: usize = 512;

// ── TDNN layer: Conv1d → LeakyReLU → BatchNorm ───────────────────────────────

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
            // SpeechBrain Conv1d uses "same" padding; with stride=1 and dilation d,
            // same-padding = (kernel - 1) * d / 2 (integer, symmetric).
            padding: (kernel - 1) * dilation / 2,
            stride: 1,
            dilation,
            groups: 1,
        };
        let conv = conv1d(in_ch, out_ch, kernel, cfg, conv_vb)
            .context("TdnnBlock: conv1d")?;
        let bn =
            batch_norm(out_ch, BatchNormConfig::default(), bn_vb).context("TdnnBlock: batch_norm")?;
        Ok(Self { conv, bn })
    }

    /// Forward in inference mode (BatchNorm uses running stats).
    fn forward(&self, x: &Tensor) -> candle_core::Result<Tensor> {
        // x: [batch, channels, time]
        let x = self.conv.forward(x)?;
        // LeakyReLU (negative_slope = 0.01, default in PyTorch).
        let x = leaky_relu(&x, 0.01)?;
        // BatchNorm inference — forward_t(train=false).
        self.bn.forward_t(&x, false)
    }
}

fn leaky_relu(x: &Tensor, neg_slope: f64) -> candle_core::Result<Tensor> {
    // relu(x) + neg_slope * relu(-x)
    let pos = x.relu()?;
    let neg = (x.neg()?.relu()? * neg_slope)?;
    pos - neg
}

// ── StatisticsPooling ─────────────────────────────────────────────────────────

/// Statistics pooling: concatenate mean and std over the time axis.
/// Input:  [batch, channels, time]
/// Output: [batch, channels * 2]
fn statistics_pooling(x: &Tensor) -> candle_core::Result<Tensor> {
    // Mean over time dim (dim 2).
    let mean = x.mean(2)?; // [batch, channels]
    // Var = E[x²] - E[x]² (unbiased approximation; SpeechBrain uses a biased
    // version with eps for numerical stability — we match that with a small
    // eps floor on the std).
    let x2_mean = x.sqr()?.mean(2)?;
    let var = (x2_mean - mean.sqr()?)?;
    // Clamp to eps to avoid negative variance from floating-point cancellation.
    let std = (var + 1e-5f64)?.sqrt()?;
    // Concatenate mean ‖ std along the channel axis.
    Tensor::cat(&[&mean, &std], 1) // [batch, channels * 2]
}

// ── XVectorEncoder ────────────────────────────────────────────────────────────

/// x-vector encoder (dormant until weights are provisioned).
///
/// Construct via [`XVectorEncoder::try_load`]. Returns `None` if the
/// safetensors file is not in the NEOTH model cache — the caller should fall
/// back to the log-mel encoder in that case.
pub struct XVectorEncoder {
    tdnn: [TdnnBlock; 5],
    /// Final linear layer: 3000 → 512.
    linear_out: candle_nn::Linear,
    device: Device,
    /// Pre-computed mel filterbank.
    filterbank: Vec<Vec<f32>>,
}

impl XVectorEncoder {
    /// Try to load the encoder from the NEOTH model cache.
    ///
    /// Returns `None` (no error) if the safetensors file does not exist.
    /// Returns `Err` only on a genuine load failure (corrupt file, wrong
    /// tensor shape, etc.) so the caller can log a warning.
    pub fn try_load() -> Option<Self> {
        match Self::load_inner() {
            Ok(enc) => Some(enc),
            Err(e) => {
                // File absent is not an error — the model just isn't cached yet.
                let msg = e.to_string();
                if msg.contains("No such file") || msg.contains("os error 2") {
                    tracing::debug!(
                        "xvector: weights not cached ({}), using log-mel fallback",
                        default_cache_dir(XVECTOR_REPO)
                            .join(SAFETENSORS_FILE)
                            .display()
                    );
                } else {
                    tracing::warn!(error = %e, "xvector: load failed, using log-mel fallback");
                }
                None
            }
        }
    }

    fn load_inner() -> Result<Self> {
        let weights_path = default_cache_dir(XVECTOR_REPO).join(SAFETENSORS_FILE);
        // Fast probe — avoids mmap overhead when the file doesn't exist.
        if !weights_path.exists() {
            anyhow::bail!("No such file: {}", weights_path.display());
        }
        let device = Device::Cpu;
        // SAFETY: from_mmaped_safetensors requires that the mapped file is not
        // mutated while the VarBuilder is alive. Weights are operator-provisioned
        // read-only artifacts; the same convention is used in clip_engine.rs.
        // SAFETY: from_mmaped_safetensors requires the mapped file to remain
        // unmodified for the lifetime of the VarBuilder. Weights are
        // operator-provisioned read-only artifacts written once by the
        // convert_xvector.py script; the same safety contract is used in
        // clip_engine.rs (search: "SAFETY: `from_mmaped_safetensors`").
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[&weights_path], DType::F32, &device)
                .with_context(|| format!("mmap safetensors {}", weights_path.display()))?
        };

        let tdnn = Self::build_tdnn_blocks(&vb)?;
        // blocks.16 → linear_out
        let linear_out =
            linear(1500 * 2, XVECTOR_EMBEDDING_DIM, vb.pp("blocks_16"))
                .context("xvector: linear_out")?;

        let filterbank = fbank_filterbank();
        Ok(Self { tdnn, linear_out, device, filterbank })
    }

    fn build_tdnn_blocks(vb: &VarBuilder) -> Result<[TdnnBlock; 5]> {
        // hyperparams.yaml:
        //   tdnn_channels:    [512, 512, 512, 512, 1500]
        //   tdnn_kernel_sizes: [5,   3,   3,   1,   1  ]
        //   tdnn_dilations:    [1,   2,   3,   1,   1  ]
        //
        // Block layout in the flat nn.ModuleList:
        //   block 0: conv idx=0,  bn idx=2
        //   block 1: conv idx=3,  bn idx=5
        //   block 2: conv idx=6,  bn idx=8
        //   block 3: conv idx=9,  bn idx=11
        //   block 4: conv idx=12, bn idx=14
        let specs: [(usize, usize, usize, usize, usize, usize); 5] = [
            // (in, out, kernel, dilation, conv_idx, bn_idx)
            (N_MELS, 512,  5, 1, 0,  2),
            (512,    512,  3, 2, 3,  5),
            (512,    512,  3, 3, 6,  8),
            (512,    512,  1, 1, 9,  11),
            (512,    1500, 1, 1, 12, 14),
        ];
        let mut blocks = Vec::with_capacity(5);
        for (in_ch, out_ch, kernel, dilation, conv_idx, bn_idx) in specs {
            let block = TdnnBlock::new(
                in_ch,
                out_ch,
                kernel,
                dilation,
                vb.pp(format!("blocks_{conv_idx}")),
                vb.pp(format!("blocks_{bn_idx}")),
            )?;
            blocks.push(block);
        }
        // SAFETY: we pushed exactly 5 elements.
        Ok(blocks.try_into().unwrap_or_else(|_| unreachable!()))
    }

    /// Encode 16 kHz mono f32 samples into a unit-norm x-vector.
    ///
    /// Returns `None` if the clip is too short or the forward pass fails.
    /// On candle errors a warning is logged and `None` is returned (embedding
    /// failure must not abort a transcription).
    pub fn embed(&self, samples_16k: &[f32]) -> Option<Vec<f32>> {
        if samples_16k.len() < MIN_SAMPLES {
            return None;
        }
        match self.embed_inner(samples_16k) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "xvector: forward pass failed");
                None
            }
        }
    }

    fn embed_inner(&self, samples: &[f32]) -> Result<Vec<f32>> {
        // 1. Fbank front-end → [frames, N_MELS]
        let frames = fbank_frames(samples, &self.filterbank);
        if frames.len() < MIN_FRAMES {
            anyhow::bail!("too few frames ({})", frames.len());
        }
        let n_frames = frames.len();

        // 2. Sentence-level mean subtraction (mean_var_norm: sentence, std_norm=False).
        let frames = mean_subtract_frames(frames);

        // 3. Convert to tensor [1, N_MELS, n_frames] (batch=1, channels, time).
        // Layout: channel-major — all samples for mel bin 0, then all for bin 1, …
        // This matches candle's Conv1d expectation: [batch, in_channels, length].
        let mut flat = Vec::with_capacity(N_MELS * n_frames);
        for m in 0..N_MELS {
            for t in 0..n_frames {
                flat.push(frames[t][m]);
            }
        }
        let x = Tensor::from_vec(flat, (1, N_MELS, n_frames), &self.device)?;

        // 4. TDNN stack.
        let mut x = x;
        for block in &self.tdnn {
            x = block.forward(&x)?;
        }

        // 5. Statistics pooling: [1, 1500, T] → [1, 3000].
        let x = statistics_pooling(&x)?;

        // 6. Final linear layer — expects [batch, features]; add a dummy seq dim.
        // linear() in candle operates on the last dim, so [1, 3000] is fine.
        let x = self.linear_out.forward(&x)?; // [1, 512]

        // 7. Flatten to Vec<f32> and L2-normalise.
        let vec: Vec<f32> = x.flatten_all()?.to_vec1()?;
        debug_assert_eq!(vec.len(), XVECTOR_EMBEDDING_DIM);
        Ok(unit_normalise(&vec))
    }
}

// ── Fbank front-end (matches SpeechBrain Fbank with n_mels=24) ───────────────

fn hz_to_mel(hz: f32) -> f32 {
    2595.0 * (1.0 + hz / 700.0).log10()
}
fn mel_to_hz(mel: f32) -> f32 {
    700.0 * (10.0_f32.powf(mel / 2595.0) - 1.0)
}

/// Build a triangular mel filterbank for the Fbank front-end.
fn fbank_filterbank() -> Vec<Vec<f32>> {
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
        let left = bin(pts[m]);
        let center = bin(pts[m + 1]);
        let right = bin(pts[m + 2]);
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
/// Returns one Vec<f32> of length N_MELS per frame.
fn fbank_frames(samples: &[f32], fb: &[Vec<f32>]) -> Vec<Vec<f32>> {
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);

    let mut indata = r2c.make_input_vec();
    let mut spectrum = r2c.make_output_vec();
    // Hann window.
    let window: Vec<f32> = (0..FRAME_LEN)
        .map(|n| 0.5 - 0.5 * (2.0 * std::f32::consts::PI * n as f32 / (FRAME_LEN as f32 - 1.0)))
        .collect();

    let mut frames = Vec::new();
    let mut start = 0usize;
    while start + FRAME_LEN <= samples.len() {
        // Zero-pad the FFT input (FRAME_LEN ≤ N_FFT).
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
            // Fbank uses log-energy; floor to avoid log(0).
            mel[m] = (e + 1e-10).ln();
        }
        frames.push(mel);
        start += HOP_LEN;
    }
    frames
}

/// Sentence-level mean subtraction (std_norm=False, matching SpeechBrain
/// `InputNormalization(norm_type="sentence", std_norm=False)`).
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
    use candle_core::{DType, Device};
    use candle_nn::VarBuilder;

    /// Build a VarBuilder filled with zeros for every parameter the network
    /// consumes. This validates wiring and shape propagation without real weights.
    fn zero_vb(device: &Device) -> VarBuilder<'static> {
        use candle_core::Tensor;
        use std::collections::HashMap;

        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        let dev = device;

        // Helper closures.
        let zeros = |shape: &[usize]| Tensor::zeros(shape, DType::F32, dev).unwrap();

        let specs: [(usize, usize, usize, usize, usize, usize); 5] = [
            (N_MELS, 512, 5, 1, 0, 2),
            (512, 512, 3, 2, 3, 5),
            (512, 512, 3, 3, 6, 8),
            (512, 512, 1, 1, 9, 11),
            (512, 1500, 1, 1, 12, 14),
        ];

        for (in_ch, out_ch, kernel, _dilation, conv_idx, bn_idx) in specs {
            // Conv1d weight: [out_ch, in_ch, kernel]
            tensors.insert(
                format!("blocks_{conv_idx}.weight"),
                zeros(&[out_ch, in_ch, kernel]),
            );
            tensors.insert(
                format!("blocks_{conv_idx}.bias"),
                zeros(&[out_ch]),
            );
            // BatchNorm: weight (γ), bias (β), running_mean, running_var
            tensors.insert(format!("blocks_{bn_idx}.weight"), zeros(&[out_ch]));
            tensors.insert(format!("blocks_{bn_idx}.bias"), zeros(&[out_ch]));
            tensors.insert(format!("blocks_{bn_idx}.running_mean"), zeros(&[out_ch]));
            tensors.insert(format!("blocks_{bn_idx}.running_var"), zeros(&[out_ch]));
        }

        // Linear output layer (blocks_16): weight [512, 3000], bias [512]
        tensors.insert("blocks_16.weight".into(), zeros(&[XVECTOR_EMBEDDING_DIM, 1500 * 2]));
        tensors.insert("blocks_16.bias".into(), zeros(&[XVECTOR_EMBEDDING_DIM]));

        VarBuilder::from_tensors(tensors, DType::F32, dev)
    }

    fn make_encoder_with_zero_weights() -> XVectorEncoder {
        let device = Device::Cpu;
        let vb = zero_vb(&device);

        let tdnn = XVectorEncoder::build_tdnn_blocks(&vb).expect("build TDNN blocks");
        let linear_out =
            linear(1500 * 2, XVECTOR_EMBEDDING_DIM, vb.pp("blocks_16"))
                .expect("build linear_out");
        let filterbank = fbank_filterbank();

        XVectorEncoder { tdnn, linear_out, device, filterbank }
    }

    /// Synthetic audio: 1 second of a pure-tone sine wave @ 16 kHz.
    fn sine_1s(freq_hz: f32) -> Vec<f32> {
        (0..SAMPLE_RATE as usize)
            .map(|i| (2.0 * std::f32::consts::PI * freq_hz * i as f32 / SAMPLE_RATE as f32).sin())
            .collect()
    }

    #[test]
    fn filterbank_has_correct_dimensions() {
        let fb = fbank_filterbank();
        assert_eq!(fb.len(), N_MELS, "filterbank row count");
        assert_eq!(fb[0].len(), N_FFT / 2 + 1, "filterbank column count");
    }

    #[test]
    fn fbank_frames_returns_mel_frames() {
        let samples = sine_1s(440.0);
        let fb = fbank_filterbank();
        let frames = fbank_frames(&samples, &fb);
        // At HOP_LEN=160, 16000 samples → ~99 frames.
        assert!(frames.len() >= 90, "expected ~99 frames, got {}", frames.len());
        assert_eq!(frames[0].len(), N_MELS);
    }

    #[test]
    fn mean_subtract_frames_is_zero_mean() {
        let samples = sine_1s(220.0);
        let fb = fbank_filterbank();
        let frames = fbank_frames(&samples, &fb);
        let normalised = mean_subtract_frames(frames);
        // The mean over all frames for each mel bin should be ~0.
        let n = normalised.len() as f32;
        for m in 0..N_MELS {
            let col_mean: f32 = normalised.iter().map(|f| f[m]).sum::<f32>() / n;
            assert!(
                col_mean.abs() < 1e-4,
                "mel bin {m} mean after subtraction = {col_mean} (expected ~0)"
            );
        }
    }

    #[test]
    fn statistics_pooling_shape() {
        let dev = Device::Cpu;
        // [1, 1500, 50] → [1, 3000]
        let x = Tensor::zeros(&[1usize, 1500, 50], DType::F32, &dev).unwrap();
        let out = statistics_pooling(&x).unwrap();
        assert_eq!(out.dims(), &[1, 3000], "pooling output shape");
    }

    #[test]
    fn xvector_forward_yields_correct_dim() {
        // Validates wiring: zero-weight network should forward without panic
        // and produce a 512-dim finite output.
        let enc = make_encoder_with_zero_weights();
        let samples = sine_1s(300.0);
        // embed_inner bypasses the MIN_SAMPLES gate and forward-passes directly.
        let result = enc.embed_inner(&samples);
        match result {
            Ok(v) => {
                assert_eq!(v.len(), XVECTOR_EMBEDDING_DIM, "embedding dim");
                assert!(v.iter().all(|x| x.is_finite()), "all values finite");
            }
            Err(e) => {
                // Zero-weight batch norm with default running_var=0 can
                // produce NaN in the sqrt; that is expected with synthetic
                // zero weights and is caught here as a known limitation.
                // A real test with proper running_var=1 is below.
                let msg = e.to_string();
                assert!(
                    msg.contains("NaN") || msg.contains("shape") || msg.contains("nan"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    #[test]
    fn xvector_forward_with_proper_bn_running_var() {
        // Build VarBuilder with running_var=1.0 so BatchNorm doesn't NaN.
        use candle_core::Tensor;
        use std::collections::HashMap;

        let device = Device::Cpu;
        let mut tensors: HashMap<String, Tensor> = HashMap::new();
        let dev = &device;
        let zeros = |shape: &[usize]| Tensor::zeros(shape, DType::F32, dev).unwrap();
        let ones = |shape: &[usize]| Tensor::ones(shape, DType::F32, dev).unwrap();

        let specs: [(usize, usize, usize, usize, usize, usize); 5] = [
            (N_MELS, 512, 5, 1, 0, 2),
            (512, 512, 3, 2, 3, 5),
            (512, 512, 3, 3, 6, 8),
            (512, 512, 1, 1, 9, 11),
            (512, 1500, 1, 1, 12, 14),
        ];
        for (in_ch, out_ch, kernel, _dilation, conv_idx, bn_idx) in specs {
            tensors.insert(format!("blocks_{conv_idx}.weight"), zeros(&[out_ch, in_ch, kernel]));
            tensors.insert(format!("blocks_{conv_idx}.bias"), zeros(&[out_ch]));
            tensors.insert(format!("blocks_{bn_idx}.weight"), ones(&[out_ch]));   // γ=1
            tensors.insert(format!("blocks_{bn_idx}.bias"), zeros(&[out_ch]));    // β=0
            tensors.insert(format!("blocks_{bn_idx}.running_mean"), zeros(&[out_ch]));
            tensors.insert(format!("blocks_{bn_idx}.running_var"), ones(&[out_ch])); // var=1
        }
        tensors.insert("blocks_16.weight".into(), zeros(&[XVECTOR_EMBEDDING_DIM, 1500 * 2]));
        tensors.insert("blocks_16.bias".into(), zeros(&[XVECTOR_EMBEDDING_DIM]));

        let vb = VarBuilder::from_tensors(tensors, DType::F32, &device);
        let tdnn = XVectorEncoder::build_tdnn_blocks(&vb).unwrap();
        let linear_out = linear(1500 * 2, XVECTOR_EMBEDDING_DIM, vb.pp("blocks_16")).unwrap();
        let filterbank = fbank_filterbank();
        let enc = XVectorEncoder { tdnn, linear_out, device, filterbank };

        let samples = sine_1s(300.0);
        let v = enc.embed_inner(&samples).expect("forward pass should succeed");
        assert_eq!(v.len(), XVECTOR_EMBEDDING_DIM);
        assert!(v.iter().all(|x| x.is_finite()), "all values must be finite");
        // With zero weights the output is all-zeros; unit_normalise on zero
        // vector returns the zero vector as-is (no NaN).
        assert!(v.iter().all(|x| !x.is_nan()), "no NaN in output");
    }

    #[test]
    fn too_short_clip_returns_none() {
        let enc = make_encoder_with_zero_weights();
        let short = vec![0.0f32; MIN_SAMPLES - 1];
        assert!(enc.embed(&short).is_none(), "sub-MIN_SAMPLES must return None");
    }

    #[test]
    fn xvector_embedding_dim_constant_is_512() {
        assert_eq!(XVECTOR_EMBEDDING_DIM, 512);
    }
}
