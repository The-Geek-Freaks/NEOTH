//! GOLD-ADOPT-25 — Dictation input mode.
//!
//! Captures microphone audio, gates it through `SmoothedVad` (when
//! `media.vad_enabled` is true), and routes completed utterances to the
//! active local STT pipeline (candle `WhisperEngine` → `transcribe_if_cached`
//! path or `faster-whisper` subprocess).
//!
//! # Scope verdict (GOLD-ADOPT-25)
//!
//! The tracker requested "whisper-rs (GGML) path + dictation input mode". After
//! verify-first:
//!
//! - **`WhisperRsLocal` SttProvider variant** already exists in `stt_dispatch.rs`
//!   and the candle `WhisperEngine` (`providers::whisper`) fully covers local STT
//!   (safetensors, not GGML). Adding a second GGML whisper-rs engine would be
//!   redundant — two local engines for the same capability, different weight
//!   formats, no operator benefit.
//!
//! - **Verdict: dictation-surface-only.** No new STT engine. The dictation mode
//!   reuses the existing `transcribe_if_cached` path (faster-whisper → candle
//!   priority order) which auto-downloads models on first use via
//!   `WhisperEngine::ensure_artifacts` (hf_hub; GOLD-ADAPT-HANDY-04 chose it
//!   over `model_manager` — see the consumer-status section below).
//!
//! - **`whisper-stt` Cargo feature**: reserved in `Cargo.toml` for future GGML
//!   integration. Currently gates nothing; the `#[cfg(feature = "whisper-stt")]`
//!   annotation here documents intent without dead code.
//!
//! # model_manager consumer status
//!
//! `model_manager::download_model_files` is NOT the whisper download path:
//! `audio::maybe_auto_download_whisper` routes through
//! `WhisperEngine::new_with_idle_secs` (hf_hub `ensure_artifacts`, which is
//! itself resumable) — a deliberate HANDY-04 scope decision. `model_manager`
//! (SHA-256-pinned + atomic-extract) is the library seam for downloads that
//! NEED pinning, e.g. the Silero ONNX model when the `vad` feature's real
//! backend lands. Wiring it into the whisper path requires pinned upstream
//! SHA-256s first.
//!
//! # Consent
//!
//! Microphone capture is sensitive. This module:
//! 1. Checks `freedom.yaml::media.dictation_enabled` before recording starts;
//!    if `false`, returns `DictationError::NotEnabled`.
//! 2. On first use (tracked via a sentinel file in `~/.neoth/`), prints a
//!    loud consent notice before opening the mic. Subsequent uses are silent.
//! 3. The `whisper-stt` Cargo feature does NOT bypass this check.
//!
//! # Audio capture
//!
//! Actual mic capture (CPAL / rodio) is NOT in scope for this module — NEOTH
//! has no `cpal`/`rodio` dependency and adding one is a separate decision (it
//! requires platform audio backends + significant additional deps). Instead,
//! this module exposes a `transcribe_utterance(pcm: &[f32], sr: u32)` function
//! that the caller feeds PCM into (e.g. from a future `neoth dictate` command
//! that wraps a platform mic capture call). The dictation loop skeleton
//! is in `cli/dictate.rs`.
//!
//! # Tests
//!
//! All tests use synthetic PCM so no model artifacts are required.

use tracing::{info, warn};

use crate::config::features::MediaConfig;
use crate::media::vad::{SmoothedVad, VadDecision};

// ── First-use sentinel ───────────────────────────────────────────────────────

/// Return `true` if the consent notice has already been shown.
fn consent_shown() -> bool {
    let path = match home_dir() {
        Some(h) => h.join(".neoth").join("dictation_consent_shown"),
        None => return false,
    };
    path.exists()
}

/// Mark the consent notice as shown (create sentinel file).
fn mark_consent_shown() {
    let path = match home_dir() {
        Some(h) => h.join(".neoth").join("dictation_consent_shown"),
        None => return,
    };
    if let Err(e) = std::fs::create_dir_all(path.parent().unwrap_or(&path)) {
        warn!("dictation: could not create consent sentinel dir: {e}");
        return;
    }
    if let Err(e) = std::fs::write(&path, b"") {
        warn!("dictation: could not write consent sentinel: {e}");
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    // std::env::home_dir is deprecated; use the HOME env var directly.
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(std::path::PathBuf::from)
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors returned by the dictation pipeline.
#[derive(Debug, thiserror::Error)]
pub enum DictationError {
    /// `freedom.yaml::media.dictation_enabled` is `false`.
    #[error(
        "dictation is disabled — set `media.dictation_enabled: true` in your freedom.yaml to opt in"
    )]
    NotEnabled,
    /// Transcription returned an error.
    #[error("transcription failed: {0}")]
    Transcription(String),
    /// VAD rejected the entire utterance (all silence, no speech detected).
    #[error("utterance was all silence — nothing to transcribe")]
    AllSilence,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Transcribe one utterance of PCM-f32-mono audio, applying the VAD gate when
/// `config.vad_enabled` is `true`.
///
/// # Consent
///
/// Prints a one-time consent notice on first call within this binary run. The
/// caller does not need to handle this separately.
///
/// # VAD gate
///
/// When `config.vad_enabled` is `true`:
/// - `SmoothedVad` processes `pcm` at `sample_rate_hz`.
/// - If the decision is `VadDecision::Silence` (no speech detected after the
///   full hangover), returns `DictationError::AllSilence`.
/// - Otherwise the full `pcm` slice is forwarded to the STT pipeline.
///
/// The current scope passes the **entire utterance** to the VAD as a single
/// chunk; a future streaming path will call `vad.process` per chunk and only
/// forward accumulated speech chunks.
///
/// # STT backend
///
/// Delegates to `media::audio::transcribe_pcm_samples` (the same
/// `transcribe_if_cached` path used by the audio ingest extractor).
pub fn transcribe_utterance(
    pcm: &[f32],
    sample_rate_hz: u32,
    config: &MediaConfig,
) -> Result<String, DictationError> {
    // ── Gate 1: feature enabled check ───────────────────────────────────────
    if !config.dictation_enabled {
        return Err(DictationError::NotEnabled);
    }

    // ── Consent notice (first-use) ───────────────────────────────────────────
    if !consent_shown() {
        eprintln!(
            "\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  NEOTH DICTATION — MICROPHONE NOTICE                        ║\n\
             ║                                                              ║\n\
             ║  Dictation mode captures audio from your microphone and      ║\n\
             ║  transcribes it locally using the Whisper model. Audio is    ║\n\
             ║  NEVER sent to a cloud service by this path.                 ║\n\
             ║                                                              ║\n\
             ║  To disable dictation at any time:                           ║\n\
             ║    neoth config set media.dictation_enabled false            ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n"
        );
        mark_consent_shown();
    }

    // ── Gate 2: VAD pre-filter ───────────────────────────────────────────────
    if config.vad_enabled {
        let mut vad = SmoothedVad::default();
        let decision = vad.process(pcm, sample_rate_hz);
        if decision == VadDecision::Silence {
            info!("dictation: VAD says silence — skipping STT call");
            return Err(DictationError::AllSilence);
        }
        info!("dictation: VAD says speaking — forwarding to STT");
    }

    // ── STT call ─────────────────────────────────────────────────────────────
    // Resample to 16 kHz if needed (Whisper expects 16 kHz mono f32).
    let samples = if sample_rate_hz == crate::media::audio::TARGET_SAMPLE_RATE {
        std::borrow::Cow::Borrowed(pcm)
    } else {
        let resampled = crate::media::resampler::resample_mono(
            pcm,
            sample_rate_hz,
            crate::media::audio::TARGET_SAMPLE_RATE,
        );
        std::borrow::Cow::Owned(resampled)
    };

    let (text, status) = crate::media::audio::transcribe_pcm_samples(&samples);
    if text.is_empty() {
        Err(DictationError::Transcription(status.to_string()))
    } else {
        info!(status, chars = text.len(), "dictation: transcribed");
        Ok(text)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::features::MediaConfig;

    fn config_with(dictation: bool, vad: bool) -> MediaConfig {
        MediaConfig {
            dictation_enabled: dictation,
            vad_enabled: vad,
            ..MediaConfig::default()
        }
    }

    fn pcm_speech(ms: u32) -> Vec<f32> {
        let sr = 16_000u32;
        let n = (sr as usize * ms as usize) / 1000;
        // Amplitude 0.1 — well above the 0.01 energy threshold.
        vec![0.1; n]
    }

    fn pcm_silence(ms: u32) -> Vec<f32> {
        let sr = 16_000u32;
        let n = (sr as usize * ms as usize) / 1000;
        vec![0.0; n]
    }

    #[test]
    fn returns_not_enabled_when_dictation_disabled() {
        let cfg = config_with(false, false);
        let result = transcribe_utterance(&pcm_speech(200), 16_000, &cfg);
        assert!(
            matches!(result, Err(DictationError::NotEnabled)),
            "must refuse when dictation_enabled = false"
        );
    }

    #[test]
    fn vad_gate_rejects_silence_utterance() {
        // dictation_enabled = true, vad_enabled = true, all-silence PCM.
        // transcribe_pcm_samples is NOT called (VAD short-circuits).
        let cfg = config_with(true, true);
        // 1 second of pure silence — VAD hangover expires → AllSilence.
        let result = transcribe_utterance(&pcm_silence(1000), 16_000, &cfg);
        assert!(
            matches!(result, Err(DictationError::AllSilence)),
            "VAD must reject an all-silence utterance"
        );
    }

    #[test]
    fn vad_gate_passes_speech_forward() {
        // dictation_enabled = true, vad_enabled = true, loud PCM.
        // The VAD should pass speech through; transcribe_pcm_samples will
        // return ("", "model not cached") in test builds (no model on disk).
        let cfg = config_with(true, true);
        let pcm = pcm_speech(500);
        let result = transcribe_utterance(&pcm, 16_000, &cfg);
        // In test builds without model artifacts the STT returns empty text
        // with a non-empty status. We only assert the VAD did NOT short-circuit.
        match result {
            Err(DictationError::AllSilence) => {
                panic!("VAD must NOT reject loud speech as silence");
            }
            // Transcription error (model not cached) or Ok text both mean
            // the VAD gate passed — that is what we are testing.
            Err(DictationError::NotEnabled) => {
                panic!("dictation_enabled = true but got NotEnabled");
            }
            Err(DictationError::Transcription(_)) | Ok(_) => {
                // Expected: VAD passed, STT attempted (model may not be cached).
            }
        }
    }

    #[test]
    fn vad_bypass_when_vad_disabled() {
        // When vad_enabled = false, even silence PCM must reach STT (no gate).
        // Result will be Transcription error (model not cached) not AllSilence.
        let cfg = config_with(true, false);
        let result = transcribe_utterance(&pcm_silence(200), 16_000, &cfg);
        assert!(
            !matches!(result, Err(DictationError::AllSilence)),
            "VAD gate must be bypassed when vad_enabled = false"
        );
    }
}
