//! GOLD-ADAPT-HANDY-02 — SmoothedVad: energy-based voice-activity detector with
//! probability smoothing + hangover, wired as a pre-STT gate.
//!
//! # Algorithm
//!
//! Adapted from the Handy audio_toolkit/vad pattern (MIT). The upstream uses a
//! two-stage approach:
//!
//! 1. **Per-frame energy decision** — RMS energy of a 20 ms frame is compared
//!    to `energy_threshold`. Frames above the threshold are "speech candidates".
//!
//! 2. **Probability smoothing** — a fixed-length ring window (`smooth_window`,
//!    default 5 frames = 100 ms) tracks the fraction of recent frames that were
//!    speech candidates. The smoothed probability must exceed `speech_prob` (default
//!    0.6) for the detector to be in the "speaking" state. This rejects
//!    single-frame spikes (phone taps, keyboard clicks) while remaining responsive
//!    to real speech onsets.
//!
//! 3. **Hangover** — once the detector enters the "speaking" state, it stays
//!    there for at least `hangover_ms` (default 750 ms) after the last
//!    above-threshold frame. This prevents mid-word silence dips from cutting
//!    an utterance short.
//!
//! # Upstream algorithm constants (Handy, reconstructed)
//!
//! | Constant | Value | Source |
//! |---|---|---|
//! | `FRAME_MS` | 20 ms | WebRTC VAD canonical frame size |
//! | `DEFAULT_ENERGY_THRESHOLD` | 0.01 (RMS linear) | quiet-room floor |
//! | `DEFAULT_SMOOTH_WINDOW` | 5 frames (100 ms) | Handy audio_toolkit |
//! | `DEFAULT_SPEECH_PROB` | 0.60 | Handy audio_toolkit |
//! | `DEFAULT_HANGOVER_MS` | 750 ms | shared with `stt_dispatch::LiveTranscriptBuffer` |
//!
//! # Testing
//!
//! All tests use synthetic PCM (constant amplitudes) so no model weights are
//! required. Alternative probability sources can be injected through the
//! internal `VadBackend` trait without exposing an inert backend publicly.

// ADOPT31-A4 — the defaults are the documented fallback for `media.vad`, so
// `config` needs them by name rather than duplicating the literals.
pub use smoothed::SmoothedVad;
pub use smoothed::VadDecision;
pub use smoothed::{
    DEFAULT_ENERGY_THRESHOLD, DEFAULT_HANGOVER_MS, DEFAULT_MIN_FRAGMENT_MS, DEFAULT_SMOOTH_WINDOW,
    DEFAULT_SPEECH_PROB, MAX_SMOOTH_WINDOW,
};

mod smoothed;
