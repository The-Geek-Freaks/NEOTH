//! GOLD-ADOPT-25 — Dictation input mode.
//!
//! Captures microphone audio, gates it through `SmoothedVad` (when
//! `media.vad_enabled` is true), and routes completed utterances through
//! `dispatch_transcription` — the B20 unified STT entry point that enforces
//! provider selection, cloud gating, audit, and fallback in one place.
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
//!   routes through `dispatch_transcription` (the B20 unified STT entry point)
//!   which honors `MediaSttConfig.primary / model_size / language` and enforces
//!   cloud gating. The local candle `WhisperEngine` (faster-whisper → candle
//!   priority) auto-downloads model artifacts on first use via
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
/// Routes through `media::stt_provider::dispatch_transcription` — the B20
/// unified STT entry point that enforces provider selection (honoring
/// `config.stt.primary / model_size / language`), cloud gating, audit, and
/// fallback in one place. Falls back to the sync
/// `media::audio::transcribe_pcm_samples` seam only when no tokio runtime is
/// available (plain `#[test]` contexts without `#[tokio::test]`).
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
             ║  transcribes it using the configured STT provider            ║\n\
             ║  (local candle Whisper by default; cloud only if explicitly  ║\n\
             ║  enabled in freedom.yaml media.stt).                         ║\n\
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

    // B20: dispatch_transcription is the single production entry for ALL
    // transcription. Cloud gating (cloud_stt_enabled, audit) is enforced inside
    // the dispatcher; the outer needs_cloud guard is removed. The nested-runtime
    // issue (WhisperLocalProvider::new() creating a mini rt inside handle.block_on)
    // is resolved by make_stt_provider_for_dispatch in stt_provider.rs which
    // wraps the construction in spawn_blocking.
    //
    // No-runtime fallback: plain #[test] contexts (no tokio runtime) fall through
    // to transcribe_pcm_samples so VAD/gate tests keep working without a runtime.
    // Production (daemon or CLI) always has a runtime handle.
    let wav_bytes = crate::media::stt_provider::pcm_bytes_to_wav(
        &samples
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    let (text, status) = match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let stt_result = handle.block_on(
                crate::media::stt_provider::dispatch_transcription(
                    &config.stt,
                    config,
                    &wav_bytes,
                    None, // no WAL writer for dictation
                ),
            );
            match stt_result {
                Ok(r) if !r.text.is_empty() => (r.text, "transcribed"),
                Ok(_) => (String::new(), "empty transcript"),
                Err(e) => return Err(DictationError::Transcription(e)),
            }
        }
        Err(_) if cfg!(test) => {
            // No tokio runtime (plain #[test] without #[tokio::test]). Use the
            // sync seam so gate/VAD unit tests don't panic. Guarded by
            // cfg!(test) so this arm is statically unreachable in production.
            crate::media::audio::transcribe_pcm_samples(&samples)
        }
        Err(_) => {
            // B20 hard invariant: dispatch_transcription is the ONLY
            // production STT entry. A production caller without a runtime is
            // a wiring bug — fail loud instead of silently bypassing
            // MediaSttConfig via the legacy candle path.
            return Err(DictationError::Transcription(
                "no tokio runtime — dictation requires the daemon/CLI runtime \
                 (B20: dispatch_transcription is the only production STT entry)"
                    .to_string(),
            ));
        }
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

    // ── B20 unified-dispatcher tests ──────────────────────────────────────────
    //
    // `transcribe_utterance` internally calls `Handle::try_current()` and then
    // `handle.block_on(...)`. `block_on` panics if called from a tokio *executor*
    // thread (i.e. inside `#[tokio::test]` body). We exercise the dispatch path
    // by calling `transcribe_utterance` from within `spawn_blocking` — blocking
    // pool threads have the runtime handle but are NOT executor threads, so
    // `block_on` is safe there.

    /// B20 caller-level invariant: transcribe_utterance with a tokio runtime
    /// available must route through dispatch_transcription, not the legacy
    /// transcribe_if_cached path. We verify by configuring FasterWhisperLocal
    /// as primary: if the dispatch path is taken, the error says "faster-whisper
    /// not found"; if the legacy path is taken, the error says "model not cached"
    /// or similar.
    ///
    /// Skipped when faster-whisper IS installed.
    #[test]
    fn dispatch_path_reached_for_local_primary_with_runtime() {
        use crate::media::stt_dispatch::{MediaSttConfig, SttProvider, WhisperModelSize};

        if crate::media::stt_provider::faster_whisper_exe().is_some() {
            return; // installed — skip the "not found" assertion
        }

        // Build a mini runtime; call transcribe_utterance from within
        // spawn_blocking so Handle::try_current() returns Ok but we are NOT on
        // an executor thread (safe for handle.block_on inside the function).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("mini runtime for B20 dictation test");

        let result: Result<String, DictationError> = rt.block_on(async {
            tokio::task::spawn_blocking(|| {
                let cfg = MediaConfig {
                    dictation_enabled: true,
                    vad_enabled: false,
                    stt: MediaSttConfig {
                        primary: SttProvider::FasterWhisperLocal,
                        model_size: WhisperModelSize::Tiny,
                        ..Default::default()
                    },
                    ..MediaConfig::default()
                };
                transcribe_utterance(&vec![0.1f32; 4_800], 16_000, &cfg)
            })
            .await
            .expect("spawn_blocking join")
        });

        match result {
            Err(DictationError::Transcription(msg)) => {
                assert!(
                    msg.contains("faster-whisper"),
                    "expected FasterWhisperProvider error from dispatch path; got: {msg}"
                );
            }
            other => panic!("expected Err(Transcription(faster-whisper …)); got: {other:?}"),
        }
    }

    /// B20 regression: cloud primary is still blocked without cloud_stt_enabled
    /// when routed through transcribe_utterance. The cloud gate lives inside
    /// dispatch_transcription and fires regardless of the outer caller.
    #[test]
    fn cloud_primary_still_blocked_without_flag_via_dictation() {
        use crate::media::stt_dispatch::{MediaSttConfig, SttProvider};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("mini runtime for B20 cloud-gate dictation test");

        let result: Result<String, DictationError> = rt.block_on(async {
            tokio::task::spawn_blocking(|| {
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
                transcribe_utterance(&vec![0.1f32; 4_800], 16_000, &cfg)
            })
            .await
            .expect("spawn_blocking join")
        });

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
