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
//! `neoth dictate <file>` decodes caller-selected audio. `neoth dictate --live`
//! consumes bounded native capture frames through the Silero assembler.
//!
//! # Tests
//!
//! All tests use synthetic PCM so no model artifacts are required.

use tracing::{info, warn};

use crate::config::features::MediaConfig;
use crate::media::vad::{SmoothedVad, VadDecision};
#[cfg(feature = "live-audio")]
use crate::media::vad::SileroVad;

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
    /// ADOPT31-A4 — `media.vad` holds a value the VAD cannot act on.
    #[error("invalid VAD configuration: {0}")]
    Config(String),
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
        true,
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
        true,
    )
    .await
}

/// Live-only dispatch seam. Its caller has already applied the mandatory
/// Silero gate while assembling the utterance, so the legacy energy VAD must
/// not become a second decision-maker for live microphone audio.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "live-audio")]
pub(crate) async fn transcribe_live_utterance_with_audio_permit(
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
        false,
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
    apply_legacy_vad: bool,
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
             ║  Dictation mode transcribes selected or captured audio.     ║\n\
             ║  transcribes it using the configured STT provider            ║\n\
             ║  (local candle Whisper by default; cloud only if explicitly  ║\n\
             ║  enabled in freedom.yaml media.stt).                         ║\n\
             ║                                                              ║\n\
             ║  Live microphone: `neoth dictate --live`.     ║\n\
             ║  To disable dictation at any time:                           ║\n\
             ║    neoth config set media.dictation_enabled false            ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n"
        );
        mark_consent_shown(neoth_home);
    }

    // ── Gate 2: VAD pre-filter ───────────────────────────────────────────────
    if apply_legacy_vad && config.vad_enabled {
        // ADOPT31-A4 — honour `media.vad` instead of the compile-time defaults.
        // Validated here rather than clamped: a VAD that quietly ignores its own
        // configuration is worse than one that refuses to run.
        config
            .vad
            .validate()
            .map_err(|e| DictationError::Config(format!("{e:#}")))?;
        let mut vad = SmoothedVad::from_tuning(&config.vad);
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

// ── Live utterance assembly ─────────────────────────────────────────────────

#[cfg(any(feature = "live-audio", test))]
const LIVE_VAD_SAMPLE_RATE_HZ: u32 = 16_000;
#[cfg(any(feature = "live-audio", test))]
const LIVE_VAD_FRAME_SAMPLES: usize = 512;
#[cfg(feature = "live-audio")]
const LIVE_UTTERANCE_MAX_SAMPLES: usize = LIVE_VAD_SAMPLE_RATE_HZ as usize * 30;

/// Internal transitions from the live, content-bearing capture path. PCM never
/// crosses this boundary into CLI output; only the CLI may send a completed
/// utterance to the existing permit-aware STT dispatcher.
#[derive(Debug, PartialEq)]
#[cfg(any(feature = "live-audio", test))]
pub(crate) enum LiveUtteranceEvent {
    SpeechStarted,
    UtteranceReady { sequence: u64, pcm: Vec<f32> },
}

/// Pure utterance-boundary state, separate from the model so probability
/// transitions can be tested without treating synthetic audio as speech.
#[cfg(any(feature = "live-audio", test))]
struct LiveUtteranceState {
    utterance: Vec<f32>,
    speaking: bool,
    trailing_silence_frames: usize,
    hangover_frames: usize,
    speech_probability: f32,
    next_sequence: u64,
    max_utterance_samples: usize,
}

#[cfg(any(feature = "live-audio", test))]
impl LiveUtteranceState {
    fn new(speech_probability: f32, hangover_frames: usize, max_utterance_samples: usize) -> Self {
        Self {
            utterance: Vec::new(),
            speaking: false,
            trailing_silence_frames: 0,
            hangover_frames,
            speech_probability,
            next_sequence: 1,
            max_utterance_samples,
        }
    }

    /// Deterministic state transition seam. Production supplies the probability
    /// only from Silero; tests can verify segmentation without asserting that a
    /// synthetic waveform represents speech.
    fn observe_probability(&mut self, probability: f32, block: Vec<f32>) -> Result<Option<LiveUtteranceEvent>, DictationError> {
        if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
            return Err(DictationError::Transcription("live Silero VAD returned an invalid probability".into()));
        }
        let speech = probability >= self.speech_probability;
        if !self.speaking && !speech {
            return Ok(None);
        }
        let started = !self.speaking;
        if started {
            self.speaking = true;
            self.trailing_silence_frames = 0;
            self.utterance.clear();
        }
        if self.utterance.len().saturating_add(block.len()) > self.max_utterance_samples {
            self.reset();
            return Err(DictationError::Transcription(format!(
                "live utterance exceeded the {}-second limit",
                self.max_utterance_samples / LIVE_VAD_SAMPLE_RATE_HZ as usize
            )));
        }
        self.utterance.extend(block);
        if speech {
            self.trailing_silence_frames = 0;
            return Ok(started.then_some(LiveUtteranceEvent::SpeechStarted));
        }
        self.trailing_silence_frames = self.trailing_silence_frames.saturating_add(1);
        if self.trailing_silence_frames < self.hangover_frames {
            return Ok(None);
        }
        let pcm = std::mem::take(&mut self.utterance);
        self.speaking = false;
        self.trailing_silence_frames = 0;
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(Some(LiveUtteranceEvent::UtteranceReady { sequence, pcm }))
    }

    fn reset(&mut self) {
        self.utterance.clear();
        self.speaking = false;
        self.trailing_silence_frames = 0;
    }
}

/// Stateful Silero-only utterance assembler for one live-capture session.
///
/// The streaming resampler retains filter history and incomplete device chunks;
/// its output is then buffered until an exact 512-sample Silero frame is
/// available. The legacy energy VAD is not a fallback for this path.
#[cfg(feature = "live-audio")]
pub(crate) struct LiveUtteranceAssembler {
    vad: SileroVad,
    resampler: crate::media::resampler::StreamingMonoResampler,
    residual: Vec<f32>,
    state: LiveUtteranceState,
}

#[cfg(feature = "live-audio")]
impl LiveUtteranceAssembler {
    pub(crate) fn new(config: &MediaConfig) -> Result<Self, DictationError> {
        if !config.dictation_enabled {
            return Err(DictationError::NotEnabled);
        }
        config.vad.validate().map_err(|error| DictationError::Config(format!("{error:#}")))?;
        let hangover_samples = usize::try_from(config.vad.hangover_ms)
            .unwrap_or(usize::MAX)
            .saturating_mul(LIVE_VAD_SAMPLE_RATE_HZ as usize)
            / 1_000;
        Ok(Self {
            vad: SileroVad::new().map_err(|error| DictationError::Transcription(format!("live Silero VAD initialization failed: {error}")))?,
            resampler: crate::media::resampler::StreamingMonoResampler::new(LIVE_VAD_SAMPLE_RATE_HZ)
                .map_err(|error| DictationError::Transcription(format!("live streaming resampler initialization failed: {error}")))?,
            residual: Vec::with_capacity(LIVE_VAD_FRAME_SAMPLES * 2),
            state: LiveUtteranceState::new(
                config.vad.speech_prob,
                hangover_samples.div_ceil(LIVE_VAD_FRAME_SAMPLES).max(1),
                LIVE_UTTERANCE_MAX_SAMPLES,
            ),
        })
    }

    /// Consume one bounded device frame. The caller owns cancellation and must
    /// suppress the returned events if its generation is stale.
    pub(crate) fn push_frame(&mut self, frame: &crate::media::live_capture::CapturedPcmFrame) -> Result<Vec<LiveUtteranceEvent>, DictationError> {
        let normalized = self.resampler.push(&frame.pcm, frame.sample_rate_hz)
            .map_err(|error| DictationError::Transcription(format!("live capture streaming normalization failed: {error}")))?;
        self.residual.extend(normalized);

        let mut events = Vec::new();
        while self.residual.len() >= LIVE_VAD_FRAME_SAMPLES {
            let block: Vec<f32> = self.residual.drain(..LIVE_VAD_FRAME_SAMPLES).collect();
            let probability = self.vad.speech_probability(&block)
                .map_err(|error| DictationError::Transcription(format!("live Silero VAD inference failed: {error}")))?;
            if let Some(event) = self.state.observe_probability(probability, block)? {
                if matches!(event, LiveUtteranceEvent::UtteranceReady { .. }) {
                    self.vad.reset();
                }
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Discard partial PCM, resampler history, and recurrent VAD state after
    /// cancellation or a terminal capture failure.
    pub(crate) fn reset(&mut self) {
        self.resampler.reset();
        self.residual.clear();
        self.state.reset();
        self.vad.reset();
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
            Err(DictationError::Config(detail)) => {
                panic!("the default VAD tuning must validate: {detail}");
            }
            Err(DictationError::Transcription(_)) | Ok(_) => {
                // Expected: VAD passed, STT attempted (model may not be cached).
            }
        }
    }

    #[tokio::test]
    async fn vad_gate_honors_operator_energy_threshold_at_the_production_constructor() {
        let mut cfg = config_with(true, true);
        cfg.vad.energy_threshold = 0.5;
        let home = tempfile::tempdir().unwrap();

        let result = transcribe_utterance(
            &pcm_speech(500),
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await;

        assert!(
            matches!(result, Err(DictationError::AllSilence)),
            "the production dictation VAD must use media.vad.energy_threshold"
        );
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
    fn live_state(threshold: f32, hangover_frames: usize, cap: usize) -> LiveUtteranceState {
        LiveUtteranceState::new(threshold, hangover_frames, cap)
    }

    fn vad_block() -> Vec<f32> {
        vec![0.0; LIVE_VAD_FRAME_SAMPLES]
    }

    #[test]
    fn live_utterance_state_uses_probability_not_synthetic_audio_claims() {
        let mut state = live_state(0.6, 2, LIVE_VAD_FRAME_SAMPLES * 8);
        assert_eq!(state.observe_probability(0.1, vad_block()).unwrap(), None);
        assert_eq!(state.observe_probability(0.9, vad_block()).unwrap(), Some(LiveUtteranceEvent::SpeechStarted));
        assert_eq!(state.observe_probability(0.1, vad_block()).unwrap(), None);
        let ready = state.observe_probability(0.1, vad_block()).unwrap();
        assert!(matches!(ready, Some(LiveUtteranceEvent::UtteranceReady { sequence: 1, ref pcm }) if pcm.len() == LIVE_VAD_FRAME_SAMPLES * 3));
    }

    #[test]
    fn live_utterance_state_enforces_cap_and_reset_discards_partial_cancelled_audio() {
        let mut state = live_state(0.6, 2, LIVE_VAD_FRAME_SAMPLES * 2);
        assert!(matches!(state.observe_probability(0.9, vad_block()).unwrap(), Some(LiveUtteranceEvent::SpeechStarted)));
        assert!(state.observe_probability(0.9, vad_block()).is_ok());
        assert!(matches!(state.observe_probability(0.9, vad_block()), Err(DictationError::Transcription(_))));
        assert_eq!(state.observe_probability(0.1, vad_block()).unwrap(), None, "cap error must clear the partial utterance");

        assert!(matches!(state.observe_probability(0.9, vad_block()).unwrap(), Some(LiveUtteranceEvent::SpeechStarted)));
        state.reset();
        assert_eq!(state.observe_probability(0.1, vad_block()).unwrap(), None, "cancel/reset must prevent a later silence block from completing old PCM");
    }
}
