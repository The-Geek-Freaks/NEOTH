//! GOLD-ADAPT-HANDY-01 — band-limited sinc resampler (rubato).
//!
//! Replaces the crude linear interpolation that `audio.rs` used to feed the
//! STT decode path. Linear resampling aliases (no anti-alias filter), which
//! smears high-frequency content a speech model relies on; rubato's
//! band-limited sinc keeps the spectrum clean. Mono `f32` in/out at an
//! arbitrary `src_sr → dst_sr` ratio.
//!
//! On the rare degenerate construction (a ratio rubato rejects) this falls
//! back to the old linear path (`audio::linear_resample`) so the capture
//! pipeline degrades gracefully instead of dropping audio.

use rubato::{
    Resampler, SincFixedIn, SincInterpolationParameters, SincInterpolationType, WindowFunction,
};

/// Fixed input chunk fed to rubato per `process` call (frames).
const CHUNK: usize = 1024;

/// Resample mono `input` from `src_sr` to `dst_sr`. Returns the resampled
/// mono buffer (empty for empty/degenerate input).
pub fn resample_mono(input: &[f32], src_sr: u32, dst_sr: u32) -> Vec<f32> {
    if input.is_empty() || src_sr == 0 || dst_sr == 0 {
        return Vec::new();
    }
    if src_sr == dst_sr {
        return input.to_vec();
    }
    match sinc_resample_mono(input, src_sr, dst_sr) {
        Some(out) => out,
        // ponytail: rubato only errors on degenerate construction/params;
        // fall back to linear rather than fail the STT path.
        None => crate::media::audio::linear_resample(input, src_sr, dst_sr),
    }
}

/// The rubato sinc path. `None` on any construction/process error so the
/// caller falls back to linear interpolation.
fn sinc_resample_mono(input: &[f32], src_sr: u32, dst_sr: u32) -> Option<Vec<f32>> {
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
    let mut resampler = SincFixedIn::<f32>::new(ratio, 1.1, params, CHUNK, 1).ok()?;

    let mut out: Vec<f32> = Vec::with_capacity((input.len() as f64 * ratio) as usize + CHUNK);
    let mut pos = 0usize;
    while pos < input.len() {
        // SincFixedIn consumes exactly CHUNK frames per call; zero-pad the
        // final short chunk (the silent tail is trimmed below).
        let take = CHUNK.min(input.len() - pos);
        let mut frame = vec![0.0f32; CHUNK];
        frame[..take].copy_from_slice(&input[pos..pos + take]);
        let processed = resampler.process(&[frame], None).ok()?;
        out.extend_from_slice(processed.first()?);
        pos += take;
    }

    // Trim the padding-induced tail to the ideal output length.
    let expected = (input.len() as f64 * ratio).round() as usize;
    out.truncate(expected.min(out.len()));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty() {
        assert!(resample_mono(&[], 16000, 8000).is_empty());
        assert!(resample_mono(&[0.1, 0.2], 0, 8000).is_empty());
        assert!(resample_mono(&[0.1, 0.2], 16000, 0).is_empty());
    }

    #[test]
    fn identity_rate_returns_clone() {
        let input: Vec<f32> = (0..100).map(|i| (i as f32 * 0.01).sin()).collect();
        let out = resample_mono(&input, 16000, 16000);
        assert_eq!(out, input);
    }

    #[test]
    fn upsample_doubles_length() {
        // 1 kHz tone, 1000 samples @ 8 kHz → ~2000 @ 16 kHz.
        let input: Vec<f32> = (0..1000)
            .map(|n| (2.0 * std::f32::consts::PI * 1000.0 * (n as f32 / 8000.0)).sin())
            .collect();
        let out = resample_mono(&input, 8000, 16000);
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
        let out = resample_mono(&input, 16000, 8000);
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
        let out = resample_mono(&input, 8000, 16000);
        let peak = out.iter().fold(0.0f32, |m, &s| m.max(s.abs()));
        assert!(peak > 0.5, "resampled tone should retain amplitude, got peak {peak}");
    }
}
