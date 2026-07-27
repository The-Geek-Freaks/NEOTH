//! GOLD-ADOPT-25 — Dictation input mode.
//!
//! Accepts caller-supplied PCM, gates it through `SmoothedVad` (when
//! `media.vad_enabled` is true), and routes completed utterances through the
//! canonical STT dispatcher. Provider selection, model-download consent,
//! cloud consent, audit, and fallback are enforced in one place.
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
//! - **Verdict: one local engine, one dispatcher.** No redundant GGML engine or
//!   inert feature flag. Candle and faster-whisper remain selectable providers;
//!   both honor the same effective runtime policy and download gate.
//!
//! # Consent
//!
//! Audio transcription is sensitive. This module:
//! 1. Checks `freedom.yaml::media.dictation_enabled` before transcription;
//!    if `false`, returns `DictationError::NotEnabled`.
//! 2. On first use (tracked by a sentinel under `~/.neoth/`), prints a
//!    loud audio/privacy notice. Subsequent uses are silent.
//!
//! # Audio capture
//!
//! Actual mic capture is not implemented; `neoth dictate <file>` decodes a
//! caller-selected audio file and feeds this module PCM.
//!
//! # Tests
//!
//! All tests use synthetic PCM so no model artifacts are required.

use tracing::{info, warn};

use crate::config::features::MediaConfig;
use crate::media::vad::{SmoothedVad, VadDecision};

// ── First-use sentinel ───────────────────────────────────────────────────────

/// Return `true` if the consent notice has already been shown for this
/// effective NEOTH home. Keeping the sentinel below the caller-supplied home
/// prevents custom-home daemons and tests from leaking state into `~/.neoth`.
fn consent_shown(neoth_home: &std::path::Path) -> bool {
    neoth_home.join("dictation_consent_shown").is_file()
}

/// Mark the consent notice as shown (create sentinel file).
fn mark_consent_shown(neoth_home: &std::path::Path) {
    let path = neoth_home.join("dictation_consent_shown");
    if let Err(e) = std::fs::create_dir_all(path.parent().unwrap_or(&path)) {
        warn!("dictation: could not create consent sentinel dir: {e}");
        return;
    }
    if let Err(e) = std::fs::write(&path, b"") {
        warn!("dictation: could not write consent sentinel: {e}");
    }
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
/// Prints a one-time consent notice on first call for this user profile. The
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
/// Routes through `media::stt_provider::dispatch_pcm_f32` — the canonical
/// unified STT entry point that enforces provider selection (honoring
/// `config.stt.primary / model_size / language`), cloud gating, audit, and
/// fallback in one place.
pub async fn transcribe_utterance(
    pcm: &[f32],
    sample_rate_hz: u32,
    config: &MediaConfig,
    updater: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
) -> Result<String, DictationError> {
    transcribe_utterance_with_writer(pcm, sample_rate_hz, config, updater, neoth_home, None).await
}

/// Writer-aware dictation seam. Text-only callers retain
/// [`transcribe_utterance`]; daemon callers can pass their WAL handle so
/// required cloud-media audit remains fail-closed without duplicating STT.
pub async fn transcribe_utterance_with_writer(
    pcm: &[f32],
    sample_rate_hz: u32,
    config: &MediaConfig,
    updater: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<String, DictationError> {
    transcribe_utterance_inner(
        pcm,
        sample_rate_hz,
        config,
        updater,
        neoth_home,
        wal_writer,
        None,
    )
    .await
}

/// Dictation seam for a caller that acquired the global audio-memory budget
/// before decoding. The unforgeable permit remains borrowed across VAD,
/// re-encoding, provider dispatch and fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transcribe_utterance_with_audio_permit(
    pcm: &[f32],
    sample_rate_hz: u32,
    config: &MediaConfig,
    updater: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
    permit: &crate::media::audio::AudioWorkPermit,
) -> Result<String, DictationError> {
    transcribe_utterance_inner(
        pcm,
        sample_rate_hz,
        config,
        updater,
        neoth_home,
        wal_writer,
        Some(permit),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transcribe_utterance_inner(
    pcm: &[f32],
    sample_rate_hz: u32,
    config: &MediaConfig,
    updater: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
    permit: Option<&crate::media::audio::AudioWorkPermit>,
) -> Result<String, DictationError> {
    // ── Gate 1: feature enabled check ───────────────────────────────────────
    if !config.dictation_enabled {
        return Err(DictationError::NotEnabled);
    }
    if pcm.is_empty() {
        return Err(DictationError::Transcription(
            "PCM input is empty".to_string(),
        ));
    }
    crate::media::resampler::validate_mono_pcm(pcm, sample_rate_hz)
        .map_err(|error| DictationError::Transcription(error.to_string()))?;

    // ── Consent notice (first-use) ───────────────────────────────────────────
    if !consent_shown(neoth_home) {
        eprintln!(
            "\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  NEOTH DICTATION — AUDIO PRIVACY NOTICE                     ║\n\
             ║                                                              ║\n\
             ║  Dictation mode transcribes the audio file you selected.     ║\n\
             ║  transcribes it using the configured STT provider            ║\n\
             ║  (local candle Whisper by default; cloud only if explicitly  ║\n\
             ║  enabled in freedom.yaml media.stt).                         ║\n\
             ║                                                              ║\n\
             ║  Live microphone capture is not enabled by this command.     ║\n\
             ║  To disable dictation at any time:                           ║\n\
             ║    neoth config set media.dictation_enabled false            ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n"
        );
        mark_consent_shown(neoth_home);
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

    // B20: dispatch_pcm_f32 is the single production entry for ALL PCM
    // transcription. Cloud gating (cloud_stt_enabled, audit) is enforced inside
    // the dispatcher; the outer needs_cloud guard is removed. Local engines are
    // constructed asynchronously and keyed by the explicit NEOTH home,
    // repository, and idle timeout inside that dispatcher.
    //
    let dispatched = match permit {
        Some(permit) => {
            crate::media::stt_provider::dispatch_pcm_f32_with_audio_permit(
                &config.stt,
                config,
                updater,
                neoth_home,
                pcm,
                sample_rate_hz,
                wal_writer,
                permit,
            )
            .await
        }
        None => {
            crate::media::stt_provider::dispatch_pcm_f32(
                &config.stt,
                config,
                updater,
                neoth_home,
                pcm,
                sample_rate_hz,
                wal_writer,
            )
            .await
        }
    };
    let (text, status) = match dispatched {
        Ok(r) if !r.text.is_empty() => (r.text, "transcribed"),
        Ok(_) => (String::new(), "empty transcript"),
        Err(e) => return Err(DictationError::Transcription(e.to_string())),
    };
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
    fn consent_sentinel_is_scoped_to_effective_neoth_home() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();

        assert!(!consent_shown(first.path()));
        assert!(!consent_shown(second.path()));
        mark_consent_shown(first.path());

        assert!(consent_shown(first.path()));
        assert!(!consent_shown(second.path()));
        assert!(first.path().join("dictation_consent_shown").is_file());
    }

    #[tokio::test]
    async fn returns_not_enabled_when_dictation_disabled() {
        let cfg = config_with(false, false);
        let home = tempfile::tempdir().unwrap();
        let result = transcribe_utterance(
            &pcm_speech(200),
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;
        assert!(
            matches!(result, Err(DictationError::NotEnabled)),
            "must refuse when dictation_enabled = false"
        );
    }

    #[tokio::test]
    async fn vad_gate_rejects_silence_utterance() {
        // dictation_enabled = true, vad_enabled = true, all-silence PCM.
        // transcribe_pcm_samples is NOT called (VAD short-circuits).
        let cfg = config_with(true, true);
        let home = tempfile::tempdir().unwrap();
        // 1 second of pure silence — VAD hangover expires → AllSilence.
        let result = transcribe_utterance(
            &pcm_silence(1000),
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;
        assert!(
            matches!(result, Err(DictationError::AllSilence)),
            "VAD must reject an all-silence utterance"
        );
    }

    #[tokio::test]
    async fn vad_gate_passes_speech_forward() {
        // dictation_enabled = true, vad_enabled = true, loud PCM.
        // The VAD should pass speech through; transcribe_pcm_samples will
        // return ("", "model not cached") in test builds (no model on disk).
        let cfg = config_with(true, true);
        let home = tempfile::tempdir().unwrap();
        let pcm = pcm_speech(500);
        let result = transcribe_utterance(
            &pcm,
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;
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

    #[tokio::test]
    async fn vad_bypass_when_vad_disabled() {
        // When vad_enabled = false, even silence PCM must reach STT (no gate).
        // Result will be Transcription error (model not cached) not AllSilence.
        let cfg = config_with(true, false);
        let home = tempfile::tempdir().unwrap();
        let result = transcribe_utterance(
            &pcm_silence(200),
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;
        assert!(
            !matches!(result, Err(DictationError::AllSilence)),
            "VAD gate must be bypassed when vad_enabled = false"
        );
    }

    // ── B20 unified-dispatcher tests ──────────────────────────────────────────
    //
    // `transcribe_utterance` is async and directly awaits the canonical
    // dispatcher, so executor-thread callers cannot trip a nested block_on.

    /// B20 regression: cloud primary is still blocked without cloud_stt_enabled
    /// when routed through transcribe_utterance. The cloud gate lives inside
    /// dispatch_transcription and fires regardless of the outer caller.
    #[tokio::test]
    async fn cloud_primary_still_blocked_without_flag_via_dictation() {
        use crate::media::stt_dispatch::{MediaSttConfig, SttProvider};

        let home = tempfile::tempdir().unwrap();
        let cfg = MediaConfig {
            dictation_enabled: true,
            vad_enabled: false,
            cloud_stt_enabled: false, // gate is OFF
            stt: MediaSttConfig {
                primary: SttProvider::OpenAiWhisperApi,
                ..Default::default()
            },
            ..MediaConfig::default()
        };
        let result: Result<String, DictationError> = transcribe_utterance(
            &vec![0.1f32; 4_800],
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;

        match result {
            Err(DictationError::Transcription(msg)) => {
                assert!(
                    msg.contains("cloud_stt_enabled"),
                    "cloud gate must fire via dispatch; got: {msg}"
                );
            }
            other => panic!("expected cloud-gate refusal; got: {other:?}"),
        }
    }
}
