//! SmoothedVad — pure-Rust energy + smoothing + hangover VAD.
//! No external crate dependencies; no model weights needed.

use crate::media::stt_dispatch::rms_energy;

// ── Constants (Handy audio_toolkit defaults, reconstructed) ─────────────────

/// 20 ms WebRTC-canonical frame size.
pub const FRAME_MS: u32 = 20;

/// RMS energy floor for a speech-candidate frame (quiet room ≈ 0.005–0.015).
pub const DEFAULT_ENERGY_THRESHOLD: f32 = 0.01;

/// Smoothing ring-window length in frames. 5 × 20 ms = 100 ms look-back.
/// Rejects single-tap spikes while remaining responsive to real speech onsets.
pub const DEFAULT_SMOOTH_WINDOW: usize = 5;

/// Fraction of recent frames that must be speech candidates for the detector
/// to enter "speaking" state. 0.60 = 3 of 5 frames.
pub const DEFAULT_SPEECH_PROB: f32 = 0.60;

/// Hangover in milliseconds. The detector stays "speaking" for at least this
/// long after the last above-threshold frame, preventing mid-word dips.
pub const DEFAULT_HANGOVER_MS: u32 = 750;

// ── VadBackend trait (test/extension seam) ───────────────────────────────────

/// Per-frame voice-activity probability source.
///
/// The default implementation derives probability from RMS energy (linear,
/// no model). Callers and tests can supply another implementation without
/// changing the smoothing/hangover state machine.
pub trait VadBackend: Send {
    /// Return a probability in `[0.0, 1.0]` that `frame` contains speech.
    /// `sample_rate_hz` is provided so the backend can compute its own
    /// windowing if needed.
    fn speech_prob(&mut self, frame: &[f32], sample_rate_hz: u32) -> f32;
}

/// Default energy-based backend. No deps, no model weights.
pub struct EnergyBackend {
    /// RMS amplitude at or above which a frame is a speech candidate (prob = 1.0).
    pub energy_threshold: f32,
}

impl Default for EnergyBackend {
    fn default() -> Self {
        Self {
            energy_threshold: DEFAULT_ENERGY_THRESHOLD,
        }
    }
}

impl VadBackend for EnergyBackend {
    fn speech_prob(&mut self, frame: &[f32], _sample_rate_hz: u32) -> f32 {
        // Hard threshold: above → 1.0, below → 0.0.
        // The smoothing layer in SmoothedVad provides the soft-probability
        // behaviour over the window, so we only need a binary per-frame signal.
        if rms_energy(frame) >= self.energy_threshold {
            1.0
        } else {
            0.0
        }
    }
}

// ── Decision type ────────────────────────────────────────────────────────────

/// What the VAD decided about the current frame batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadDecision {
    /// Speech is (or recently was) detected; audio should be forwarded to STT.
    Speaking,
    /// Silence: no speech detected and hangover has elapsed.
    Silence,
}

// ── SmoothedVad ──────────────────────────────────────────────────────────────

/// Stateful energy-based VAD with probability smoothing + hangover.
///
/// # Usage
///
/// ```rust
/// use neothd::media::vad::{SmoothedVad, VadDecision};
///
/// // One second of 16 kHz mono PCM (silence here; real audio in practice).
/// let samples_16k_mono_f32 = vec![0.0f32; 16_000];
///
/// let mut vad = SmoothedVad::default();
/// let decision = vad.process(&samples_16k_mono_f32, 16_000);
/// if decision == VadDecision::Speaking {
///     // forward to STT
/// }
/// ```
pub struct SmoothedVad {
    /// Ring buffer of per-frame speech probabilities. Circular; `head` points
    /// to the slot that will be overwritten on the next frame.
    window: Vec<f32>,
    /// Write head for the ring buffer.
    head: usize,
    /// Number of frames written so far (saturates at `window.len()`).
    filled: usize,
    /// Minimum fraction of window frames that must be speech candidates.
    speech_prob_threshold: f32,
    /// Hangover: ms of silence to tolerate before declaring Silence.
    hangover_ms: u32,
    /// Accumulated silence ms since the last speech frame (counts up during
    /// non-speech; reset when a speech frame is detected).
    silence_ms: u32,
    /// True once at least one speech frame has been seen since last reset.
    ever_seen_speech: bool,
    /// The backend that supplies per-frame speech probabilities.
    backend: Box<dyn VadBackend>,
    /// Sample rate cached for frame-length calculation.
    sample_rate_hz: u32,
}

impl Default for SmoothedVad {
    fn default() -> Self {
        Self::new(
            DEFAULT_SMOOTH_WINDOW,
            DEFAULT_SPEECH_PROB,
            DEFAULT_HANGOVER_MS,
            Box::new(EnergyBackend::default()),
        )
    }
}

impl SmoothedVad {
    /// Construct with explicit parameters.
    ///
    /// `smooth_window` — number of 20-ms frames in the look-back window.
    /// `speech_prob` — fraction of window frames that must be speech.
    /// `hangover_ms` — silence tolerance before declaring silence.
    /// `backend` — per-frame probability source (energy or Silero).
    pub fn new(
        smooth_window: usize,
        speech_prob: f32,
        hangover_ms: u32,
        backend: Box<dyn VadBackend>,
    ) -> Self {
        let window_size = smooth_window.max(1);
        Self {
            window: vec![0.0; window_size],
            head: 0,
            filled: 0,
            speech_prob_threshold: speech_prob.clamp(0.0, 1.0),
            hangover_ms,
            silence_ms: 0,
            ever_seen_speech: false,
            backend,
            sample_rate_hz: 16_000, // overridden by first `process` call
        }
    }

    /// Process a PCM-f32-mono chunk at the given sample rate.
    ///
    /// Internally splits into 20-ms frames, updates the smoothed probability
    /// window and hangover counter, then returns the aggregate decision.
    ///
    /// Returns `VadDecision::Speaking` if the **overall** decision after
    /// processing all frames is that speech is (or was recently) active.
    pub fn process(&mut self, samples: &[f32], sample_rate_hz: u32) -> VadDecision {
        self.sample_rate_hz = sample_rate_hz;
        let frame_len = ((sample_rate_hz as usize) * (FRAME_MS as usize)) / 1000;
        if frame_len == 0 || samples.is_empty() {
            return self.current_decision();
        }

        for frame in samples.chunks(frame_len) {
            let prob = self.backend.speech_prob(frame, sample_rate_hz);
            // Write into the ring window.
            self.window[self.head] = prob;
            self.head = (self.head + 1) % self.window.len();
            if self.filled < self.window.len() {
                self.filled += 1;
            }
            // Smoothed probability = mean over the FULL window (unfilled
            // slots count as silence) — this is what makes a single hot
            // frame a 1-of-5 minority instead of a 1-of-1 majority. Real
            // speech pays a ~3-frame (60 ms) onset latency for it.
            let smoothed: f32 = self.window.iter().sum::<f32>() / self.window.len() as f32;

            if smoothed >= self.speech_prob_threshold {
                // Speech frame: reset silence counter.
                self.silence_ms = 0;
                self.ever_seen_speech = true;
            } else if self.ever_seen_speech {
                // Below threshold but we've seen speech — count silence.
                let frame_ms = (frame.len() as u32 * 1000) / sample_rate_hz.max(1);
                self.silence_ms = self.silence_ms.saturating_add(frame_ms);
            }
        }
        self.current_decision()
    }

    /// True if the most recent `process` call determined speech was active.
    pub fn is_speaking(&self) -> bool {
        self.current_decision() == VadDecision::Speaking
    }

    /// Reset state (e.g. after an utterance has been consumed).
    pub fn reset(&mut self) {
        self.window.fill(0.0);
        self.head = 0;
        self.filled = 0;
        self.silence_ms = 0;
        self.ever_seen_speech = false;
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn current_decision(&self) -> VadDecision {
        if !self.ever_seen_speech {
            return VadDecision::Silence;
        }
        if self.silence_ms < self.hangover_ms {
            VadDecision::Speaking
        } else {
            VadDecision::Silence
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SR: u32 = 16_000;

    /// Generate `ms` milliseconds of constant-amplitude PCM at `sample_rate_hz`.
    fn pcm(amplitude: f32, ms: u32, sample_rate_hz: u32) -> Vec<f32> {
        let n = (sample_rate_hz as usize * ms as usize) / 1000;
        vec![amplitude; n]
    }

    #[test]
    fn silence_before_any_speech_is_silence() {
        let mut vad = SmoothedVad::default();
        // 500 ms of pure silence.
        let decision = vad.process(&pcm(0.0, 500, SR), SR);
        assert_eq!(decision, VadDecision::Silence);
    }

    #[test]
    fn speech_detected_after_enough_frames_in_window() {
        let mut vad = SmoothedVad::default();
        // 200 ms of loud speech (well above threshold) fills ≥ 5 frames.
        let decision = vad.process(&pcm(0.1, 200, SR), SR);
        assert_eq!(
            decision,
            VadDecision::Speaking,
            "loud speech must be detected"
        );
    }

    #[test]
    fn single_frame_spike_rejected_by_smoothing() {
        // Window = 5 frames. A single spike fills 1/5 = 0.20 < 0.60 threshold.
        let mut vad = SmoothedVad::default();
        // One 20-ms loud frame then silence.
        let mut samples = pcm(0.5, 20, SR);
        samples.extend(pcm(0.0, 80, SR));
        let decision = vad.process(&samples, SR);
        // Should be Silence because smoothed probability = 0.20 < 0.60.
        assert_eq!(
            decision,
            VadDecision::Silence,
            "spike must be rejected by smoothing"
        );
    }

    #[test]
    fn hangover_keeps_speaking_during_short_dip() {
        let mut vad = SmoothedVad::default();
        // 200 ms of speech to enter Speaking state.
        vad.process(&pcm(0.1, 200, SR), SR);
        // 400 ms of silence (< 750 ms hangover).
        let decision = vad.process(&pcm(0.0, 400, SR), SR);
        assert_eq!(
            decision,
            VadDecision::Speaking,
            "hangover must hold through a short dip"
        );
    }

    #[test]
    fn hangover_expires_after_full_silence_window() {
        let mut vad = SmoothedVad::default();
        // Enter speaking.
        vad.process(&pcm(0.1, 200, SR), SR);
        // 800 ms of silence (> 750 ms hangover).
        let decision = vad.process(&pcm(0.0, 800, SR), SR);
        assert_eq!(
            decision,
            VadDecision::Silence,
            "hangover must expire after 750 ms"
        );
    }

    #[test]
    fn reset_clears_state() {
        let mut vad = SmoothedVad::default();
        vad.process(&pcm(0.1, 200, SR), SR);
        assert!(vad.is_speaking());
        vad.reset();
        // After reset, a single silence chunk must yield Silence (no speech seen).
        let decision = vad.process(&pcm(0.0, 100, SR), SR);
        assert_eq!(decision, VadDecision::Silence);
    }

    #[test]
    fn custom_parameters_respected() {
        // Tight hangover (200 ms), wide speech prob (0.3).
        let mut vad = SmoothedVad::new(
            3,    // 3-frame window
            0.30, // 30% of frames must be speech
            200,  // 200 ms hangover
            Box::new(EnergyBackend {
                energy_threshold: DEFAULT_ENERGY_THRESHOLD,
            }),
        );
        // 80 ms of speech (> 3 frames).
        vad.process(&pcm(0.1, 80, SR), SR);
        assert!(vad.is_speaking());
        // 300 ms silence — exceeds 200 ms hangover.
        let decision = vad.process(&pcm(0.0, 300, SR), SR);
        assert_eq!(decision, VadDecision::Silence);
    }

    #[test]
    fn mock_backend_drives_vad() {
        /// Always returns 0.0 — synthetic "always silent" backend.
        struct AlwaysSilent;
        impl VadBackend for AlwaysSilent {
            fn speech_prob(&mut self, _frame: &[f32], _sr: u32) -> f32 {
                0.0
            }
        }
        let mut vad = SmoothedVad::new(5, 0.6, 750, Box::new(AlwaysSilent));
        // Even with loud PCM, the backend says silence.
        let decision = vad.process(&pcm(1.0, 500, SR), SR);
        assert_eq!(decision, VadDecision::Silence);
    }

    #[test]
    fn mock_speech_backend_triggers_speaking() {
        /// Always returns 1.0 — synthetic "always speech" backend.
        struct AlwaysSpeech;
        impl VadBackend for AlwaysSpeech {
            fn speech_prob(&mut self, _frame: &[f32], _sr: u32) -> f32 {
                1.0
            }
        }
        let mut vad = SmoothedVad::new(5, 0.6, 750, Box::new(AlwaysSpeech));
        let decision = vad.process(&pcm(0.0, 200, SR), SR);
        assert_eq!(decision, VadDecision::Speaking);
    }
}
