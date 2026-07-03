//! GOLD-ADAPT-HANDY-02 (extension) — Silero VAD backend gated by the `vad`
//! Cargo feature.
//!
//! When the `vad` feature is enabled, `SileroBackend` replaces the energy
//! heuristic with a neural per-frame speech probability from the Silero VAD
//! ONNX model (silero-team/silero-vad, MIT). The model is downloaded on first
//! use via `media::model_manager` (same pattern as the Whisper auto-download),
//! gated by `updater.allow_huggingface_downloads`.
//!
//! The integration is a scaffold: the ONNX runtime (`ort` crate) is not yet
//! added as a dependency — this file compiles cleanly as a type-only stub so
//! the feature flag can be tested in CI without requiring the ONNX libraries.
//! Swap the body of `speech_prob` when the `ort` dep lands.

use crate::media::vad::smoothed::VadBackend;

/// Silero VAD neural backend (scaffold — ONNX runtime pending).
///
/// Produces per-frame speech probabilities in `[0.0, 1.0]`.
/// Until the `ort` dependency is wired, falls back to the energy threshold.
pub struct SileroBackend {
    /// Energy fallback threshold used until the ONNX session is wired.
    pub energy_threshold: f32,
}

impl Default for SileroBackend {
    fn default() -> Self {
        Self {
            energy_threshold: crate::media::vad::smoothed::DEFAULT_ENERGY_THRESHOLD,
        }
    }
}

impl VadBackend for SileroBackend {
    fn speech_prob(&mut self, frame: &[f32], _sample_rate_hz: u32) -> f32 {
        // TODO: replace with ort Session inference when the `ort` dep is added.
        // The Silero model expects 512-sample windows at 16 kHz (32 ms) or
        // 256-sample windows at 8 kHz. Pad/truncate `frame` before inference.
        //
        // Fallback: energy threshold (same as EnergyBackend).
        if crate::media::stt_dispatch::rms_energy(frame) >= self.energy_threshold {
            1.0
        } else {
            0.0
        }
    }
}
