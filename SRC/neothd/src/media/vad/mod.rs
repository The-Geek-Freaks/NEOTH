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
//! # Feature gate
//!
//! The `vad` Cargo feature is reserved for a future Silero ONNX backend that
//! replaces the energy decision (step 1) with a neural per-frame probability.
//! The `SmoothedVad` smoothing + hangover layer (steps 2–3) is always compiled;
//! the Silero backend sits behind `#[cfg(feature = "vad")]` and supplies the
//! per-frame probability instead of RMS-based energy.
//!
//! # Testing
//!
//! All tests use synthetic PCM (constant amplitudes) so no model weights are
//! required. The `SileroBackend` is mocked via a `VadBackend` trait.

pub use smoothed::SmoothedVad;
pub use smoothed::VadDecision;

mod smoothed;

#[cfg(feature = "vad")]
mod silero_backend;

#[cfg(feature = "vad")]
pub use silero_backend::SileroBackend;
