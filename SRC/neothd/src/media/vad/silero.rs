//! Compiled-in Silero VAD backend for the live-capture path.
//!
//! The ONNX asset is intentionally embedded at build time.  This module has no
//! downloader, updater hook, or energy-based fallback: a missing, malformed,
//! or incompatible graph makes [`SileroVad::new`] fail.

use std::{io::Cursor, sync::Arc};

use anyhow::{Context, Result, bail};
use tract_onnx::prelude::*;

const SAMPLE_RATE_HZ: u32 = 16_000;
const FRAME_SAMPLES: usize = 512;
const CONTEXT_SAMPLES: usize = 64;
const MODEL_SAMPLES: usize = FRAME_SAMPLES + CONTEXT_SAMPLES;
const STATE_LAYERS: usize = 2;
const STATE_BATCH: usize = 1;
const STATE_FEATURES: usize = 128;
const STATE_SAMPLES: usize = STATE_LAYERS * STATE_BATCH * STATE_FEATURES;

/// The exact model selected by W186.  Hosted import owns adding this file and
/// validating its provenance before a build is attempted.
const SILERO_MODEL: &[u8] = include_bytes!("../../../assets/silero-vad/silero_vad_16k_op15.onnx");

/// Stateful CPU-only adapter for the embedded 16-kHz Silero ONNX graph.
///
/// `speech_probability` accepts one, and only one, already-normalized mono
/// frame.  The upstream ONNX wrapper prepends the previous 64 samples before
/// invoking its 512-sample model window; this implementation preserves that
/// contract and the model's `[2, 1, 128]` recurrent state.
pub(crate) struct SileroVad {
    // In tract 0.23.8, `into_runnable()` returns an `Arc` around the fixed
    // `TypedRunnableModel` alias. Keep that ownership shape so `run()` uses
    // the API's `self: &Arc<Self>` receiver without cloning model state.
    model: Arc<TypedRunnableModel>,
    state: Vec<f32>,
    context: [f32; CONTEXT_SAMPLES],
}

impl SileroVad {
    /// Load the compiled-in graph and constrain its three inputs to the
    /// upstream `input`, `state`, and `sr` facts.
    pub(crate) fn new() -> Result<Self> {
        let mut graph = tract_onnx::onnx()
            .model_for_read(&mut Cursor::new(SILERO_MODEL))
            .context("decode embedded Silero VAD ONNX graph")?;

        // The model's input order is part of the pinned upstream op15 graph:
        // input [batch, 512 + 64], state [2, batch, 128], sr scalar i64.
        let input_count = graph
            .input_outlets()
            .context("inspect embedded Silero graph inputs")?
            .len();
        if input_count != 3 {
            bail!(
                "embedded Silero graph must expose audio, recurrent-state, and sample-rate inputs; got {}",
                input_count
            );
        }
        graph
            .set_input_fact(0, f32::fact([1, MODEL_SAMPLES]).into())
            .context("validate Silero audio input fact")?;
        graph
            .set_input_fact(
                1,
                f32::fact([STATE_LAYERS, STATE_BATCH, STATE_FEATURES]).into(),
            )
            .context("validate Silero recurrent-state input fact")?;
        graph
            .set_input_fact(2, i64::fact::<[usize; 0]>([]).into())
            .context("validate Silero sample-rate input fact")?;

        let output_count = graph
            .output_outlets()
            .context("inspect embedded Silero graph outputs")?
            .len();
        if output_count != 2 {
            bail!(
                "embedded Silero graph must expose probability and recurrent-state outputs; got {}",
                output_count
            );
        }

        let model = graph
            .into_optimized()
            .context("optimise embedded Silero VAD graph")?
            .into_runnable()
            .context("prepare embedded Silero VAD graph for CPU inference")?;

        Ok(Self {
            model,
            state: vec![0.0; STATE_SAMPLES],
            context: [0.0; CONTEXT_SAMPLES],
        })
    }

    /// Return the graph's speech probability for exactly one 32-ms frame.
    ///
    /// Invalid shape, non-finite PCM, a graph failure, or malformed output is
    /// an error.  Callers must surface that failure; this backend never falls
    /// back to the legacy energy VAD.
    pub(crate) fn speech_probability(&mut self, frame_16k_mono: &[f32]) -> Result<f32> {
        if frame_16k_mono.len() != FRAME_SAMPLES {
            bail!(
                "Silero VAD requires exactly {FRAME_SAMPLES} 16-kHz mono samples; got {}",
                frame_16k_mono.len()
            );
        }
        if frame_16k_mono.iter().any(|sample| !sample.is_finite()) {
            bail!("Silero VAD rejects non-finite PCM samples");
        }

        // Build the upstream [context, frame] input without changing retained
        // state.  We only commit state/context after all returned tensors pass
        // validation, so a failed inference cannot poison the next frame.
        let mut input = Vec::with_capacity(MODEL_SAMPLES);
        input.extend_from_slice(&self.context);
        input.extend_from_slice(frame_16k_mono);
        let state_before = self.state.clone();
        let mut next_context = [0.0; CONTEXT_SAMPLES];
        next_context.copy_from_slice(&frame_16k_mono[FRAME_SAMPLES - CONTEXT_SAMPLES..]);

        let outputs = self
            .model
            .run(tvec![
                Tensor::from_shape(&[1, MODEL_SAMPLES], &input)?.into(),
                Tensor::from_shape(&[STATE_LAYERS, STATE_BATCH, STATE_FEATURES], &state_before)?
                    .into(),
                Tensor::from(SAMPLE_RATE_HZ as i64).into(),
            ])
            .context("run embedded Silero VAD inference")?;
        if outputs.len() != 2 {
            bail!(
                "embedded Silero graph returned {} outputs; expected probability and recurrent state",
                outputs.len()
            );
        }

        let probability = {
            let values = outputs[0]
                .to_plain_array_view::<f32>()
                .context("read Silero speech-probability output as f32")?;
            if values.shape() != &[1, 1] {
                bail!(
                    "Silero speech-probability output must have shape [1, 1]; got {:?}",
                    values.shape()
                );
            }
            let value = *values
                .iter()
                .next()
                .context("Silero speech-probability output was empty")?;
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                bail!("Silero speech probability must be finite and in [0, 1]; got {value}");
            }
            value
        };
        let next_state = {
            let values = outputs[1]
                .to_plain_array_view::<f32>()
                .context("read Silero recurrent-state output as f32")?;
            if values.shape() != &[STATE_LAYERS, STATE_BATCH, STATE_FEATURES] {
                bail!(
                    "Silero recurrent-state output must have shape [2, 1, 128]; got {:?}",
                    values.shape()
                );
            }
            if values.iter().any(|value| !value.is_finite()) {
                bail!("Silero recurrent-state output contains a non-finite value");
            }
            values.iter().copied().collect::<Vec<_>>()
        };

        self.state = next_state;
        self.context = next_context;
        Ok(probability)
    }

    /// Discard all recurrent history between live-capture sessions.
    pub(crate) fn reset(&mut self) {
        self.state.fill(0.0);
        self.context.fill(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_graph_accepts_silence_with_a_valid_probability() {
        let mut vad = SileroVad::new().expect("pinned embedded Silero graph loads");
        let probability = vad
            .speech_probability(&[0.0; FRAME_SAMPLES])
            .expect("silence is a valid 16-kHz mono frame");
        assert!(probability.is_finite() && (0.0..=1.0).contains(&probability));
    }

    #[test]
    fn invalid_frames_fail_before_inference() {
        let mut vad = SileroVad::new().expect("pinned embedded Silero graph loads");
        assert!(vad.speech_probability(&[0.0; FRAME_SAMPLES - 1]).is_err());
        let mut non_finite = [0.0; FRAME_SAMPLES];
        non_finite[0] = f32::NAN;
        assert!(vad.speech_probability(&non_finite).is_err());
    }

    #[test]
    fn reset_restores_the_initial_recurrent_result_for_the_same_frame() {
        let mut vad = SileroVad::new().expect("pinned embedded Silero graph loads");
        let frame = [0.0; FRAME_SAMPLES];
        let initial = vad.speech_probability(&frame).expect("first inference");
        let _ = vad
            .speech_probability(&frame)
            .expect("stateful second inference");
        vad.reset();
        let after_reset = vad
            .speech_probability(&frame)
            .expect("inference after reset");
        assert!((initial - after_reset).abs() <= f32::EPSILON);
    }
}
