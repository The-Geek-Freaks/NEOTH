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

/// Hard ceiling for the smoothing look-back: 500 × 20 ms = 10 seconds.
///
/// A smoothing window is an onset-noise filter, not a transcript buffer. Ten
/// seconds is already far beyond an interactive speech onset while bounding the
/// allocation controlled by `freedom.yaml` to 2 KiB of `f32` samples.
pub const MAX_SMOOTH_WINDOW: usize = 500;

/// Fraction of recent frames that must be speech candidates for the detector
/// to enter "speaking" state. 0.60 = 3 of 5 frames.
pub const DEFAULT_SPEECH_PROB: f32 = 0.60;

/// Minimum contiguous speech before a fragment opens a turn. A shorter burst
/// is transient noise — a door, a keypress — and must not cancel live playback
/// on the barge-in path (ADOPT31-A6).
pub const DEFAULT_MIN_FRAGMENT_MS: u32 = 100;

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
    /// True once a speech fragment has lasted at least `min_fragment_ms`.
    ever_seen_speech: bool,
    /// Accumulated speech ms in the fragment currently being qualified. Reset
    /// whenever the fragment breaks before reaching `min_fragment_ms`.
    candidate_speech_ms: u32,
    /// Minimum contiguous speech a fragment needs before it counts as speech.
    min_fragment_ms: u32,
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
    /// ADOPT31-A4 — build from the operator's `media.vad` settings.
    ///
    /// Callers must have validated the tuning ([`crate::config::VadTuning::validate`]);
    /// this applies it verbatim rather than re-clamping, so a value that
    /// reaches here is one the operator asked for.
    pub fn from_tuning(tuning: &crate::config::VadTuning) -> Self {
        let mut vad = Self::new(
            tuning.smooth_window,
            tuning.speech_prob,
            tuning.hangover_ms,
            Box::new(EnergyBackend {
                energy_threshold: tuning.energy_threshold,
            }),
        );
        vad.min_fragment_ms = tuning.min_fragment_ms;
        vad
    }

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
        assert!(
            (1..=MAX_SMOOTH_WINDOW).contains(&smooth_window),
            "smooth_window must be in 1..={MAX_SMOOTH_WINDOW}"
        );
        assert!(hangover_ms >= 1, "hangover_ms must be at least 1");
        let window_size = smooth_window;
        Self {
            window: vec![0.0; window_size],
            head: 0,
            filled: 0,
            speech_prob_threshold: speech_prob.clamp(0.0, 1.0),
            hangover_ms,
            silence_ms: 0,
            ever_seen_speech: false,
            candidate_speech_ms: 0,
            min_fragment_ms: DEFAULT_MIN_FRAGMENT_MS,
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

            let frame_ms = (frame.len() as u32 * 1000) / sample_rate_hz.max(1);
            if smoothed >= self.speech_prob_threshold {
                // Speech frame: reset silence counter.
                self.silence_ms = 0;
                // A fragment must last `min_fragment_ms` before it opens a
                // turn. Without this a single spike — a door, a keyboard —
                // sets `ever_seen_speech`, and the hangover then keeps the
                // turn alive long after the noise is gone, cancelling live
                // playback on the barge-in path.
                if !self.ever_seen_speech {
                    self.candidate_speech_ms = self.candidate_speech_ms.saturating_add(frame_ms);
                    if self.candidate_speech_ms >= self.min_fragment_ms {
                        self.ever_seen_speech = true;
                    }
                }
            } else if !self.ever_seen_speech {
                // The fragment broke before qualifying — start over.
                self.candidate_speech_ms = 0;
            } else if self.ever_seen_speech {
                // Below threshold but we've seen speech — count silence.
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
        self.candidate_speech_ms = 0;
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

    /// ADOPT31-A6: a burst shorter than `min_fragment_ms` is noise. Before
    /// this guard the first hot frame set `ever_seen_speech`, and the hangover
    /// then held the turn open long after the sound was gone — on the
    /// barge-in path that cancels live playback for a door closing.
    #[test]
    fn a_burst_shorter_than_the_minimum_fragment_does_not_open_a_turn() {
        struct AlwaysSpeech;
        impl VadBackend for AlwaysSpeech {
            fn speech_prob(&mut self, _frame: &[f32], _sr: u32) -> f32 {
                1.0
            }
        }
        const SR: u32 = 16_000;
        let frame = (SR as usize * FRAME_MS as usize) / 1000;
        // Window of 1 so the smoothing mean cannot mask the guard under test.
        let mut vad = SmoothedVad::new(1, 0.5, 300, Box::new(AlwaysSpeech));

        // Two 20 ms frames = 40 ms, well under the 100 ms minimum.
        let burst = vec![0.5f32; frame * 2];
        assert_eq!(
            vad.process(&burst, SR),
            VadDecision::Silence,
            "a 40 ms burst must not open a turn"
        );
    }

    /// The guard must not swallow real speech: once a fragment reaches the
    /// minimum, the turn opens exactly as before.
    #[test]
    fn speech_past_the_minimum_fragment_still_opens_a_turn() {
        struct AlwaysSpeech;
        impl VadBackend for AlwaysSpeech {
            fn speech_prob(&mut self, _frame: &[f32], _sr: u32) -> f32 {
                1.0
            }
        }
        const SR: u32 = 16_000;
        let frame = (SR as usize * FRAME_MS as usize) / 1000;
        let mut vad = SmoothedVad::new(1, 0.5, 300, Box::new(AlwaysSpeech));

        // Ten 20 ms frames = 200 ms, comfortably past the minimum.
        let speech = vec![0.5f32; frame * 10];
        assert_eq!(vad.process(&speech, SR), VadDecision::Speaking);
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
        // 120 ms of speech. This was 80 ms until ADOPT31-A6 introduced the
        // `min_fragment_ms` guard (100 ms): a burst below that is now treated
        // as noise, so the figure was raised to keep this test about what it
        // is named for — that the custom window/threshold/hangover are
        // respected — rather than silently re-testing the new guard.
        vad.process(&pcm(0.1, 120, SR), SR);
        assert!(vad.is_speaking());
        // 300 ms silence — exceeds 200 ms hangover.
        let decision = vad.process(&pcm(0.0, 300, SR), SR);
        assert_eq!(decision, VadDecision::Silence);
    }

    #[test]
    fn minimum_valid_hangover_preserves_the_current_speech_frame() {
        let mut vad = SmoothedVad::new(
            1,
            0.5,
            1,
            Box::new(EnergyBackend {
                energy_threshold: DEFAULT_ENERGY_THRESHOLD,
            }),
        );
        assert_eq!(vad.process(&pcm(0.1, 100, SR), SR), VadDecision::Speaking);
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
