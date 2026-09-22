//! GOLD-ADAPT-HANDY-01 — band-limited sinc resampler (rubato).
//!
//! Replaces the crude linear interpolation that `audio.rs` used to feed the
//! STT decode path. Linear resampling aliases (no anti-alias filter), which
//! smears high-frequency content a speech model relies on; rubato's
//! band-limited sinc keeps the spectrum clean. Mono `f32` in/out at an
//! arbitrary `src_sr → dst_sr` ratio.
//!
//! On the rare construction/process failure this falls back to the old linear
//! path (`audio::linear_resample`) so valid audio still degrades gracefully.
//! Invalid rates and non-finite PCM are rejected explicitly; they are caller
//! bugs, not signals that should silently turn into an empty buffer.

use rubato::{
    Resampler, SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction,
};

/// Fixed input chunk fed to rubato per `process` call (frames).
const CHUNK: usize = 1024;
const MAX_RESAMPLE_OUTPUT_SAMPLES: usize = 32 * 1024 * 1024;
#[cfg(any(feature = "live-audio", test))]
const MAX_STREAMING_INPUT_SAMPLES: usize = 4_096;

/// Broad sanity bounds for real-world audio. The lower bound prevents absurd
/// resample ratios and the upper bound still covers professional PCM formats.
pub const MIN_SAMPLE_RATE_HZ: u32 = 1_000;
pub const MAX_SAMPLE_RATE_HZ: u32 = 768_000;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ResampleError {
    #[error(
        "invalid source sample rate {0} Hz (expected {MIN_SAMPLE_RATE_HZ}..={MAX_SAMPLE_RATE_HZ})"
    )]
    InvalidSourceRate(u32),
    #[error(
        "invalid target sample rate {0} Hz (expected {MIN_SAMPLE_RATE_HZ}..={MAX_SAMPLE_RATE_HZ})"
    )]
    InvalidTargetRate(u32),
    #[error("PCM sample at index {index} is not finite")]
    NonFiniteSample { index: usize },
    #[error("resampled output would contain {samples} samples, exceeding the {limit}-sample cap")]
    OutputTooLarge { samples: usize, limit: usize },
    #[error("{stage} allocation failed: {reason}")]
    Allocation { stage: &'static str, reason: String },
    #[error("live capture changed sample rate from {expected} Hz to {actual} Hz without reset")]
    StreamingRateChanged { expected: u32, actual: u32 },
    #[error("live capture block contains {samples} samples, exceeding the {limit}-sample limit")]
    StreamingInputTooLarge { samples: usize, limit: usize },
    #[error("streaming sinc resampler {stage} failed: {reason}")]
    StreamingBackend { stage: &'static str, reason: String },
}

fn validate_rate(rate: u32, source: bool) -> Result<(), ResampleError> {
    if (MIN_SAMPLE_RATE_HZ..=MAX_SAMPLE_RATE_HZ).contains(&rate) {
        Ok(())
    } else if source {
        Err(ResampleError::InvalidSourceRate(rate))
    } else {
        Err(ResampleError::InvalidTargetRate(rate))
    }
}

/// Validate a source mono f32 buffer without allocating or resampling it.
pub fn validate_mono_pcm(input: &[f32], sample_rate_hz: u32) -> Result<(), ResampleError> {
    validate_rate(sample_rate_hz, true)?;
    if let Some(index) = input.iter().position(|sample| !sample.is_finite()) {
        return Err(ResampleError::NonFiniteSample { index });
    }
    Ok(())
}

/// Resample mono `input` from `src_sr` to `dst_sr`.
///
/// Empty input is valid and returns an empty buffer. Invalid rates and
/// NaN/infinite samples are typed errors so callers cannot confuse malformed
/// capture data with a valid silent/empty utterance.
pub fn resample_mono(input: &[f32], src_sr: u32, dst_sr: u32) -> Result<Vec<f32>, ResampleError> {
    validate_mono_pcm(input, src_sr)?;
    validate_rate(dst_sr, false)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let expected = expected_output_samples(input.len(), src_sr, dst_sr)?;
    if expected > MAX_RESAMPLE_OUTPUT_SAMPLES {
        return Err(ResampleError::OutputTooLarge {
            samples: expected,
            limit: MAX_RESAMPLE_OUTPUT_SAMPLES,
        });
    }
    if src_sr == dst_sr {
        let mut cloned = Vec::new();
        cloned
            .try_reserve_exact(input.len())
            .map_err(|error| allocation_error("identity output", error))?;
        cloned.extend_from_slice(input);
        return Ok(cloned);
    }
    match sinc_resample_mono(input, src_sr, dst_sr, expected)? {
        Some(out) => Ok(out),
        // ponytail: rubato only errors on degenerate construction/params;
        // fall back to linear rather than fail the STT path.
        None => crate::media::audio::linear_resample(input, src_sr, dst_sr),
    }
}

/// The rubato sinc path. `None` on any construction/process error so the
/// caller falls back to linear interpolation.
fn sinc_resample_mono(
    input: &[f32],
    src_sr: u32,
    dst_sr: u32,
    expected: usize,
) -> Result<Option<Vec<f32>>, ResampleError> {
    let ratio = dst_sr as f64 / src_sr as f64;
    let params = SincInterpolationParameters {
        sinc_len: 128,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 128,
        window: WindowFunction::BlackmanHarris2,
    };
    // max_resample_ratio_relative = 1.1: we never re-set the ratio at
    // runtime, so a tight bound is fine.
    let Some(mut resampler) = SincFixedIn::<f32>::new(ratio, 1.1, params, CHUNK, 1).ok() else {
        return Ok(None);
    };

    let mut out: Vec<f32> = Vec::new();
    out.try_reserve_exact(expected)
        .map_err(|error| allocation_error("sinc output", error))?;
    let mut pos = 0usize;
    while pos < input.len() {
        // SincFixedIn consumes exactly CHUNK frames per call; zero-pad the
        // final short chunk (the silent tail is trimmed below).
        let take = CHUNK.min(input.len() - pos);
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(CHUNK)
            .map_err(|error| allocation_error("sinc input frame", error))?;
        frame.resize(CHUNK, 0.0f32);
        frame[..take].copy_from_slice(&input[pos..pos + take]);
        let Some(processed) = resampler.process(&[frame], None).ok() else {
            return Ok(None);
        };
        let Some(processed) = processed.first() else {
            return Ok(None);
        };
        let output_len = processed.len().min(expected.saturating_sub(out.len()));
        out.try_reserve_exact(output_len)
            .map_err(|error| allocation_error("grow sinc output", error))?;
        out.extend_from_slice(&processed[..output_len]);
        pos += take;
    }

    // Trim the padding-induced tail to the ideal output length.
    out.truncate(expected.min(out.len()));
    Ok(Some(out))
}

/// Stateful mono resampler for capture callbacks. It retains both the rubato
/// filter history and incomplete source chunks, so arbitrary callback splits
/// cannot reset phase, inject padding, or accumulate a rounded per-callback
/// output length. A device rate is immutable for one instance; [`reset`] is
/// the explicit boundary before accepting a new device/session.
#[cfg(any(feature = "live-audio", test))]
pub(crate) struct StreamingMonoResampler {
    target_rate_hz: u32,
    source_rate_hz: Option<u32>,
    pending: Vec<f32>,
    sinc: Option<SincFixedIn<f32>>,
}

#[cfg(any(feature = "live-audio", test))]
impl StreamingMonoResampler {
    pub(crate) fn new(target_rate_hz: u32) -> Result<Self, ResampleError> {
        validate_rate(target_rate_hz, false)?;
        Ok(Self {
            target_rate_hz,
            source_rate_hz: None,
            pending: Vec::with_capacity(CHUNK + MAX_STREAMING_INPUT_SAMPLES),
            sinc: None,
        })
    }

    /// Append one bounded native callback and return only output backed by full
    /// source chunks. The incomplete tail remains owned by this stream until a
    /// later callback completes it or `reset` discards the session.
    pub(crate) fn push(&mut self, input: &[f32], source_rate_hz: u32) -> Result<Vec<f32>, ResampleError> {
        validate_mono_pcm(input, source_rate_hz)?;
        if input.len() > MAX_STREAMING_INPUT_SAMPLES {
            return Err(ResampleError::StreamingInputTooLarge { samples: input.len(), limit: MAX_STREAMING_INPUT_SAMPLES });
        }
        match self.source_rate_hz {
            Some(expected) if expected != source_rate_hz => return Err(ResampleError::StreamingRateChanged { expected, actual: source_rate_hz }),
            Some(_) => {}
            None => {
                self.source_rate_hz = Some(source_rate_hz);
                if source_rate_hz != self.target_rate_hz {
                    self.sinc = Some(new_sinc_resampler(source_rate_hz, self.target_rate_hz)?);
                }
            }
        }
        if source_rate_hz == self.target_rate_hz {
            let mut output = Vec::new();
            output.try_reserve_exact(input.len()).map_err(|error| allocation_error("streaming identity output", error))?;
            output.extend_from_slice(input);
            return Ok(output);
        }

        self.pending.try_reserve(input.len()).map_err(|error| allocation_error("streaming pending input", error))?;
        self.pending.extend_from_slice(input);
        let mut output = Vec::new();
        while self.pending.len() >= CHUNK {
            let block: Vec<f32> = self.pending.drain(..CHUNK).collect();
            let processed = self.sinc.as_mut().expect("non-identity stream constructs sinc once")
                .process(&[block], None)
                .map_err(|error| ResampleError::StreamingBackend { stage: "process", reason: error.to_string() })?;
            let channel = processed.first().ok_or_else(|| ResampleError::StreamingBackend {
                stage: "process", reason: "mono resampler returned no output channel".into(),
            })?;
            output.try_reserve(channel.len()).map_err(|error| allocation_error("streaming output", error))?;
            output.extend_from_slice(channel);
        }
        Ok(output)
    }

    /// Discard source residue and DSP history. A reset is also the only way to
    /// accept a new device sample rate.
    pub(crate) fn reset(&mut self) {
        self.pending.clear();
        self.source_rate_hz = None;
        if let Some(sinc) = self.sinc.as_mut() {
            sinc.reset();
        }
        self.sinc = None;
    }
}

fn new_sinc_resampler(source_rate_hz: u32, target_rate_hz: u32) -> Result<SincFixedIn<f32>, ResampleError> {
    let params = SincInterpolationParameters {
        sinc_len: 128,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 128,
        window: WindowFunction::BlackmanHarris2,
    };
    SincFixedIn::<f32>::new(target_rate_hz as f64 / source_rate_hz as f64, 1.1, params, CHUNK, 1)
        .map_err(|error| ResampleError::StreamingBackend { stage: "construction", reason: error.to_string() })
}
fn expected_output_samples(
    input_samples: usize,
    src_sr: u32,
    dst_sr: u32,
) -> Result<usize, ResampleError> {
    let numerator = (input_samples as u128)
        .checked_mul(u128::from(dst_sr))
        .and_then(|value| value.checked_add(u128::from(src_sr) - 1))
        .ok_or(ResampleError::OutputTooLarge {
            samples: usize::MAX,
            limit: MAX_RESAMPLE_OUTPUT_SAMPLES,
        })?;
    usize::try_from(numerator / u128::from(src_sr)).map_err(|_| ResampleError::OutputTooLarge {
        samples: usize::MAX,
        limit: MAX_RESAMPLE_OUTPUT_SAMPLES,
    })
}

fn allocation_error(
    stage: &'static str,
    error: std::collections::TryReserveError,
) -> ResampleError {
    ResampleError::Allocation {
        stage,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty() {
        assert!(resample_mono(&[], 16000, 8000).unwrap().is_empty());
    }

    #[test]
    fn invalid_rates_are_typed_errors() {
        assert_eq!(
            resample_mono(&[0.1, 0.2], 0, 8000),
            Err(ResampleError::InvalidSourceRate(0))
        );
        assert_eq!(
            resample_mono(&[0.1, 0.2], 16000, 0),
            Err(ResampleError::InvalidTargetRate(0))
        );
    }

    #[test]
    fn non_finite_pcm_is_a_typed_error() {
        assert_eq!(
            resample_mono(&[0.1, f32::NAN], 16_000, 8_000),
            Err(ResampleError::NonFiniteSample { index: 1 })
        );
    }

    #[test]
    fn identity_rate_returns_clone() {
        let input: Vec<f32> = (0..100).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample_mono(&input, 16000, 16000).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn upsample_doubles_length() {
        // 1 kHz tone, 1000 samples @ 8 kHz → ~2000 @ 16 kHz.
        let input: Vec<f32> = (0..1000)
            .map(|n| (2.0 * std::f32::consts::PI * 1000.0 * (n as f32 / 8000.0)).sin())
            .collect();
        let out = resample_mono(&input, 8000, 16000).unwrap();
        // Band-limited sinc has a small group-delay warmup, so the count is
        // close to (but slightly under) the ideal 2x — assert the ratio, not
        // an exact frame count.
        let ratio = out.len() as f64 / input.len() as f64;
        assert!(
            (ratio - 2.0).abs() < 0.15,
            "upsample should be ~2x, got {} frames (ratio {ratio:.3})",
            out.len()
        );
    }

    #[test]
    fn downsample_halves_length() {
        let input: Vec<f32> = (0..1000)
            .map(|n| (2.0 * std::f32::consts::PI * 1000.0 * (n as f32 / 16000.0)).sin())
            .collect();
        let out = resample_mono(&input, 16000, 8000).unwrap();
        let ratio = out.len() as f64 / input.len() as f64;
        assert!(
            (ratio - 0.5).abs() < 0.15,
            "downsample should be ~0.5x, got {} frames (ratio {ratio:.3})",
            out.len()
        );
    }

    #[test]
    fn upsampled_tone_is_not_silent() {
        // The sinc path must reproduce signal energy, not zeros.
        let input: Vec<f32> = (0..2048)
            .map(|n| (2.0 * std::f32::consts::PI * 440.0 * (n as f32 / 8000.0)).sin())
            .collect();
        let out = resample_mono(&input, 8000, 16000).unwrap();
        let peak = out.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        assert!(
            peak > 0.5,
            "resampled tone should retain amplitude, got peak {peak}"
        );
    }
    #[test]
    fn streaming_sinc_split_matches_contiguous_without_ratio_drift() {
        let input: Vec<f32> = (0..8_192).map(|index| ((index as f32) * 0.017).sin()).collect();
        let mut contiguous = StreamingMonoResampler::new(16_000).unwrap();
        let mut expected = Vec::new();
        for block in input.chunks(1_024) {
            expected.extend(contiguous.push(block, 48_000).unwrap());
        }

        let mut split = StreamingMonoResampler::new(16_000).unwrap();
        let mut actual = Vec::new();
        let mut offset = 0usize;
        for &width in [113usize, 701, 19, 997, 251, 431, 607, 89].iter().cycle() {
            if offset == input.len() { break; }
            let end = (offset + width).min(input.len());
            actual.extend(split.push(&input[offset..end], 48_000).unwrap());
            offset = end;
        }
        assert_eq!(actual, expected, "callback partitioning must not change sample count or phase");
        assert!(!actual.is_empty());
    }

    #[test]
    fn streaming_resampler_rejects_rate_change_until_reset() {
        let mut stream = StreamingMonoResampler::new(16_000).unwrap();
        stream.push(&[0.0; 64], 48_000).unwrap();
        assert!(matches!(stream.push(&[0.0; 64], 44_100), Err(ResampleError::StreamingRateChanged { expected: 48_000, actual: 44_100 })));
        stream.reset();
        assert!(stream.push(&[0.0; 64], 44_100).is_ok());
    }
}
