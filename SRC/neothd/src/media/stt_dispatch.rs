//! MM-01 — Speech-to-text dispatcher + live transcript primitives.
//!
//! Mirrors the [`super::tts_dispatch`] split: this module owns the provider
//! enum, request/response model, and live utterance buffer. The production
//! provider factory, cloud consent/audit boundary, and fallback dispatcher
//! live in [`super::stt_provider`].
//!
//! ## Why the buffer ships now
//!
//! The hardest part of live-transcript UX is endpoint detection:
//! "when did the operator finish speaking?". A pure stateful buffer
//! that gates on RMS-energy thresholds + a silence-hangover timer
//! is testable today without any model. When MM-01b lands, the
//! provider just calls `buffer.poll_completed_utterance()` to know
//! when to feed the accumulated audio to whisper.

use serde::{Deserialize, Serialize};

/// One STT backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SttProvider {
    // Note: explicit `rename` per variant — serde's
    // `rename_all="snake_case"` splits at case boundaries which
    // would write `open_ai_whisper_api` and `whisper_rs_local`
    // (acceptable but ugly). Pinning each wire form provides a
    // stable serde contract independent of as_str() display values.
    // NB: WhisperRsLocal serde wire = "whisper_rs_local" (kept for
    //     backward compat); as_str() = "candle_whisper_local" (honest).
    #[serde(rename = "whisper_rs_local")]
    WhisperRsLocal,
    #[serde(rename = "openai_whisper_api")]
    OpenAiWhisperApi,
    #[serde(rename = "azure_speech")]
    AzureSpeech,
    /// JV-VOICE-02/03 — the `faster_whisper` Python module with int8
    /// quantisation, invoked through NEOTH's bounded JSONL bridge. Significantly
    /// faster than the candle-based `WhisperRsLocal` on CPU (CTranslate2
    /// backend). Model downloads remain subject to the updater policy; inference
    /// is local and the transcript stays private.
    #[serde(rename = "faster_whisper_local")]
    FasterWhisperLocal,
}

impl SttProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            // Display "candle_whisper_local" — the actual backend is candle
            // (safetensors), not whisper-rs (GGML).  The serde wire value is
            // pinned to "whisper_rs_local" via #[serde(rename)] for backward
            // compat; as_str() is the operator-facing display only.
            Self::WhisperRsLocal => "candle_whisper_local",
            Self::OpenAiWhisperApi => "openai_whisper_api",
            Self::AzureSpeech => "azure_speech",
            Self::FasterWhisperLocal => "faster_whisper_local",
        }
    }

    pub fn is_local(self) -> bool {
        matches!(self, Self::WhisperRsLocal | Self::FasterWhisperLocal)
    }

    pub fn requires_credentials(self) -> bool {
        matches!(self, Self::OpenAiWhisperApi | Self::AzureSpeech)
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::WhisperRsLocal => {
                "Local candle Whisper (safetensors, CPU/GPU, no cloud, no network for inference)"
            }
            Self::OpenAiWhisperApi => "OpenAI Whisper API — best quality, paid + cloud",
            Self::AzureSpeech => "Azure Speech — cloud, regional endpoints, paid",
            Self::FasterWhisperLocal => {
                "faster-whisper int8 — local Python-module bridge, CTranslate2, faster than candle"
            }
        }
    }
}

/// Whisper model size — pinned because operators see it in the
/// wizard and switching costs (download size, RAM, latency) differ
/// non-trivially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhisperModelSize {
    Tiny,
    Base,
    Small,
    Medium,
    Large,
}

impl WhisperModelSize {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Base => "base",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    /// Approximate on-disk size in MB. Used by the wizard to warn
    /// operators on slow internet / small SSD.
    pub fn approx_size_mb(self) -> u32 {
        match self {
            Self::Tiny => 75,
            Self::Base => 142,
            Self::Small => 466,
            Self::Medium => 1_500,
            Self::Large => 3_100,
        }
    }
}

/// Audio byte format supplied to an STT provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioFormat {
    /// Headerless signed 16-bit little-endian mono PCM.
    PcmS16leMono,
    /// Headerless IEEE f32 little-endian mono PCM.
    PcmF32leMono,
    /// A RIFF/WAVE container containing signed 16-bit mono PCM.
    WavPcmS16leMono,
}

impl AudioFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PcmS16leMono => "pcm_s16le_mono",
            Self::PcmF32leMono => "pcm_f32le_mono",
            Self::WavPcmS16leMono => "wav_pcm_s16le_mono",
        }
    }
}

/// One STT request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptionRequest {
    /// IETF BCP 47 tag (e.g. `"de"` / `"en"` / `"de-DE"`). Empty
    /// = auto-detect (provider-dependent).
    pub language: String,
    pub model_size: WhisperModelSize,
    pub format: AudioFormat,
    /// Sample rate in Hz. Whisper wants 16 kHz; the provider
    /// resamples when this doesn't match.
    pub sample_rate_hz: u32,
    /// Optional initial prompt — operator-specified vocabulary
    /// hints (e.g. "NEOTH, Hyperswarm, paperless-ngx") that bias
    /// recognition toward those terms.
    #[serde(default)]
    pub initial_prompt: String,
}

impl Default for TranscriptionRequest {
    fn default() -> Self {
        Self {
            language: String::new(),
            model_size: WhisperModelSize::Base,
            format: AudioFormat::PcmS16leMono,
            sample_rate_hz: 16_000,
            initial_prompt: String::new(),
        }
    }
}

/// One time-tagged transcript segment. Mirrors whisper's per-
/// segment output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextSegment {
    pub start_ms: u32,
    pub end_ms: u32,
    pub text: String,
}

/// Aggregate result of a transcription pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptionResult {
    /// Concatenated text — `segments.iter().map(.text).join(" ")`.
    pub text: String,
    pub segments: Vec<TextSegment>,
    /// Provider-detected language; empty when not provided.
    #[serde(default)]
    pub language: String,
    /// Optional 0.0-1.0 confidence. Providers that don't surface
    /// confidence return `None`; tests assert non-degradation.
    #[serde(default)]
    pub confidence: Option<f32>,
    /// Optional speaker re-identification labels. With timed segments this is
    /// index-aligned with `segments`, including `None` for an unlabeled segment.
    /// A result without timed segments may carry one whole-utterance label.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub speaker_labels: Vec<Option<String>>,
    /// B20 — `SttProviderKind::as_str()` of the provider that actually produced
    /// this transcript. Stamped by `dispatch_transcription` (primary or fallback
    /// arm) so audit/metadata surfaces describe the same effective provider that
    /// handled the bytes. Empty when the result came from a direct low-level
    /// provider call (tests / internal use).
    #[serde(default)]
    pub provider: String,
}

/// Reasonable default for the silence-hangover used by
/// `LiveTranscriptBuffer`. 750 ms matches the "natural pause
/// between sentences" feel without cutting off long thinking
/// pauses.
pub const DEFAULT_HANGOVER_MS: u32 = 750;

/// RMS energy threshold below which a frame is considered silence.
/// 0.01 corresponds to a quiet room; the wizard exposes this so
/// operators with noisier mics can raise it.
pub const DEFAULT_SILENCE_RMS_THRESHOLD: f32 = 0.01;

/// Frame size in ms for the buffer's RMS pass. 20 ms is the WebRTC-
/// VAD canonical frame; whisper itself doesn't care, but 20 ms
/// stays cheap to compute.
pub const FRAME_MS: u32 = 20;

/// Stateful live-transcript buffer. Operator audio arrives as
/// `feed_pcm_f32(...)` calls; the buffer:
///
///   - Computes per-frame RMS energy.
///   - Tracks a silence-hangover timer.
///   - When the hangover elapses without speech, emits the
///     accumulated PCM as one utterance for the STT provider.
///
/// Pure stateful struct — no I/O, no async. Caller drives the
/// I/O + invokes [`feed_pcm_f32`] + [`poll_completed_utterance`].
#[derive(Debug, Clone)]
pub struct LiveTranscriptBuffer {
    sample_rate_hz: u32,
    silence_rms_threshold: f32,
    hangover_ms: u32,
    /// Accumulated PCM since the last completed utterance.
    pending: Vec<f32>,
    /// Total ms of silence (below threshold) accumulated since the
    /// last frame that was speech.
    silence_ms: u32,
    /// True after at least one speech frame has been observed in
    /// the current utterance. Prevents the buffer from emitting an
    /// empty "silence-only" utterance when the operator's mic was
    /// open but they didn't talk.
    seen_speech: bool,
}

impl LiveTranscriptBuffer {
    pub fn new(sample_rate_hz: u32) -> Self {
        Self {
            sample_rate_hz,
            silence_rms_threshold: DEFAULT_SILENCE_RMS_THRESHOLD,
            hangover_ms: DEFAULT_HANGOVER_MS,
            pending: Vec::new(),
            silence_ms: 0,
            seen_speech: false,
        }
    }

    pub fn with_thresholds(mut self, silence_rms: f32, hangover_ms: u32) -> Self {
        self.silence_rms_threshold = silence_rms;
        self.hangover_ms = hangover_ms;
        self
    }

    /// Bytes of pending PCM not yet emitted as an utterance.
    pub fn pending_samples(&self) -> usize {
        self.pending.len()
    }

    /// Reset the buffer (e.g. after a successful transcription
    /// completes + the audio was consumed).
    pub fn reset(&mut self) {
        self.pending.clear();
        self.silence_ms = 0;
        self.seen_speech = false;
    }

    /// Feed one PCM-f32-mono chunk. Updates internal state +
    /// returns the post-feed completion status — caller checks via
    /// `poll_completed_utterance` and drains when present.
    pub fn feed_pcm_f32(&mut self, samples: &[f32]) {
        // Process in 20 ms frames. A frame at sample_rate_hz =
        // sample_rate_hz * 20 / 1000 samples.
        let frame_len = (self.sample_rate_hz as usize * FRAME_MS as usize) / 1000;
        if frame_len == 0 {
            self.pending.extend_from_slice(samples);
            return;
        }
        for chunk in samples.chunks(frame_len) {
            self.pending.extend_from_slice(chunk);
            let rms = rms_energy(chunk);
            if rms >= self.silence_rms_threshold {
                self.silence_ms = 0;
                self.seen_speech = true;
            } else {
                let frame_ms = (chunk.len() as u32 * 1000) / self.sample_rate_hz.max(1);
                self.silence_ms = self.silence_ms.saturating_add(frame_ms);
            }
        }
    }

    /// Returns and drains a completed utterance when the silence
    /// hangover has elapsed AND speech was seen in the current
    /// window. Returns `None` when still listening / silence-only.
    pub fn poll_completed_utterance(&mut self) -> Option<Vec<f32>> {
        if !self.seen_speech {
            return None;
        }
        if self.silence_ms < self.hangover_ms {
            return None;
        }
        let out = std::mem::take(&mut self.pending);
        self.silence_ms = 0;
        self.seen_speech = false;
        Some(out)
    }

    /// Finish an input stream and drain its final speech utterance even when
    /// no trailing hangover silence arrived. Silence-only input is discarded.
    /// The buffer is fully reset in both cases and can immediately be reused.
    pub fn finish(&mut self) -> Option<Vec<f32>> {
        let out = self.seen_speech.then(|| std::mem::take(&mut self.pending));
        self.reset();
        out
    }
}

/// Compute RMS energy over a PCM-f32 chunk. Public for tests +
/// caller-side mic-meter UIs.
pub fn rms_energy(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum_sq: f32 = samples.iter().map(|s| s * s).sum();
    (sum_sq / samples.len() as f32).sqrt()
}

// GOLD-ADAPT-HANDY-02 note (2026-07-04 B10 cleanup): the `feed_with_vad`
// streaming helper that lived here was deleted — no streaming capture loop
// exists (cpal is out of scope) and `media::dictation::transcribe_utterance`
// runs the SmoothedVad gate inline on whole utterances. Re-derive from git
// history if a live capture loop ever lands.

// HANDY-03 + HANDY-06 are WIRED in `stt_provider::transcribe_and_audit`:
// clean_transcript() runs on every `result.text`; resolve_language() (below)
// steers an unsupported requested language to a safe fallback using each
// provider's `SttProviderImpl::supported_languages()` (default empty = accept
// any, so unrestricted backends never trip the guard).

// ── HANDY-06 primitives ─────────────────────────────────────────────────────

/// Result of [`resolve_language`]: either the requested language (if
/// supported) or a safe fallback, with a flag indicating which path was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLanguage {
    /// The language tag to use for the transcription request.  Always a
    /// non-empty BCP-47 tag OR the empty string meaning "auto-detect".
    pub language: String,
    /// `true` when the requested language was not in `supported` and a
    /// fallback was chosen.  Callers log this so operators know their
    /// language hint was silently substituted.
    pub fell_back: bool,
    /// The originally requested tag, present only when `fell_back` is
    /// `true` (useful for structured log fields).
    pub fallback_from: Option<String>,
}

/// Choose the language to send to an STT provider.
///
/// - `requested = None` (or empty string) → auto-detect (`""` wire value).
/// - `requested = Some(tag)` and `supported` is empty → treat as "any
///   language accepted" and pass through.
/// - `requested = Some(tag)` and `supported` is non-empty → if the tag
///   (or its primary subtag, e.g. `"de"` from `"de-DE"`) is in `supported`,
///   use it; otherwise fall back to `""` (auto-detect) and set `fell_back`.
///
/// Matching is case-insensitive and also checks the primary language subtag
/// (`"de"` from `"de-DE"`) against the supported list so that requesting
/// `"de-AT"` against a provider that lists only `"de"` succeeds without a
/// fallback.
pub fn resolve_language(requested: Option<&str>, supported: &[&str]) -> ResolvedLanguage {
    let requested = requested.filter(|s| !s.is_empty());
    match requested {
        // No preference → auto-detect.
        None => ResolvedLanguage {
            language: String::new(),
            fell_back: false,
            fallback_from: None,
        },
        Some(tag) => {
            // Empty supported list → provider accepts anything; pass through.
            if supported.is_empty() {
                return ResolvedLanguage {
                    language: tag.to_string(),
                    fell_back: false,
                    fallback_from: None,
                };
            }
            let tag_lower = tag.to_lowercase();
            // Primary subtag: "de" from "de-DE", "en" from "en-US".
            let primary_lower = tag_lower.split('-').next().unwrap_or(&tag_lower);
            let is_supported = supported.iter().any(|s| {
                let sl = s.to_lowercase();
                sl == tag_lower
                    || sl == primary_lower
                    || sl
                        .split('-')
                        .next()
                        .map(|p| p == primary_lower)
                        .unwrap_or(false)
            });
            if is_supported {
                ResolvedLanguage {
                    language: tag.to_string(),
                    fell_back: false,
                    fallback_from: None,
                }
            } else {
                // Requested language not supported → auto-detect fallback.
                ResolvedLanguage {
                    language: String::new(), // "" = provider auto-detect
                    fell_back: true,
                    fallback_from: Some(tag.to_string()),
                }
            }
        }
    }
}

/// Canonical per-call STT config embedded under `media.stt` in `MediaConfig`.
///
/// This is the B20-introduced config struct that replaces the scattered use of
/// `SttDispatcherConfig`. Wire it via `MediaConfig::stt`; the outer
/// `MediaConfig::cloud_stt_enabled` flag and audit sink still gate cloud calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaSttConfig {
    pub primary: SttProvider,
    #[serde(default)]
    pub fallback: Option<SttProvider>,
    pub model_size: WhisperModelSize,
    pub language: String,
    /// Required for `AzureSpeech` provider; empty = Azure provider cannot be used.
    #[serde(default)]
    pub azure_region: String,
}

impl Default for MediaSttConfig {
    fn default() -> Self {
        Self {
            primary: SttProvider::WhisperRsLocal,
            fallback: None,
            model_size: WhisperModelSize::Base,
            language: String::new(),
            azure_region: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── provider surface ──────────────────────────────────────────

    #[test]
    fn provider_as_str_pinned() {
        assert_eq!(SttProvider::WhisperRsLocal.as_str(), "candle_whisper_local");
        assert_eq!(SttProvider::OpenAiWhisperApi.as_str(), "openai_whisper_api");
        assert_eq!(SttProvider::AzureSpeech.as_str(), "azure_speech");
        assert_eq!(
            SttProvider::FasterWhisperLocal.as_str(),
            "faster_whisper_local"
        );
    }

    #[test]
    fn provider_locality_classification() {
        assert!(SttProvider::WhisperRsLocal.is_local());
        assert!(SttProvider::FasterWhisperLocal.is_local());
        assert!(!SttProvider::OpenAiWhisperApi.is_local());
        assert!(!SttProvider::AzureSpeech.is_local());
    }

    #[test]
    fn provider_credentials_classification() {
        assert!(SttProvider::OpenAiWhisperApi.requires_credentials());
        assert!(SttProvider::AzureSpeech.requires_credentials());
        assert!(!SttProvider::WhisperRsLocal.requires_credentials());
        assert!(!SttProvider::FasterWhisperLocal.requires_credentials());
    }

    #[test]
    fn provider_description_strings_present() {
        for p in [
            SttProvider::WhisperRsLocal,
            SttProvider::OpenAiWhisperApi,
            SttProvider::AzureSpeech,
            SttProvider::FasterWhisperLocal,
        ] {
            assert!(!p.description().is_empty(), "{p:?}");
        }
    }

    #[test]
    fn faster_whisper_local_serde_roundtrip() {
        let json = serde_json::to_string(&SttProvider::FasterWhisperLocal).unwrap();
        assert_eq!(json, "\"faster_whisper_local\"");
        let back: SttProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SttProvider::FasterWhisperLocal);
    }

    #[test]
    fn removed_vosk_wire_value_is_rejected() {
        let error = serde_yaml::from_str::<MediaSttConfig>(
            "primary: vosk\nfallback: null\nmodel_size: base\nlanguage: ''\nazure_region: ''\n",
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("unknown variant `vosk`"), "got: {message}");
    }

    // ── model size surface ────────────────────────────────────────

    #[test]
    fn model_size_as_str_pinned() {
        assert_eq!(WhisperModelSize::Tiny.as_str(), "tiny");
        assert_eq!(WhisperModelSize::Base.as_str(), "base");
        assert_eq!(WhisperModelSize::Small.as_str(), "small");
        assert_eq!(WhisperModelSize::Medium.as_str(), "medium");
        assert_eq!(WhisperModelSize::Large.as_str(), "large");
    }

    #[test]
    fn model_size_approx_mb_monotonic_increasing() {
        let sizes = [
            WhisperModelSize::Tiny,
            WhisperModelSize::Base,
            WhisperModelSize::Small,
            WhisperModelSize::Medium,
            WhisperModelSize::Large,
        ];
        for w in sizes.windows(2) {
            assert!(
                w[0].approx_size_mb() < w[1].approx_size_mb(),
                "{:?} should be smaller than {:?}",
                w[0],
                w[1]
            );
        }
    }

    // ── format surface ────────────────────────────────────────────

    #[test]
    fn format_as_str_pinned() {
        assert_eq!(AudioFormat::PcmS16leMono.as_str(), "pcm_s16le_mono");
        assert_eq!(AudioFormat::PcmF32leMono.as_str(), "pcm_f32le_mono");
        assert_eq!(AudioFormat::WavPcmS16leMono.as_str(), "wav_pcm_s16le_mono");
    }

    // ── request defaults ──────────────────────────────────────────

    #[test]
    fn request_default_is_pcm_s16le_mono_16k_base_auto() {
        let r = TranscriptionRequest::default();
        assert_eq!(r.format, AudioFormat::PcmS16leMono);
        assert_eq!(r.sample_rate_hz, 16_000);
        assert_eq!(r.model_size, WhisperModelSize::Base);
        assert_eq!(r.language, "");
        assert_eq!(r.initial_prompt, "");
    }

    // ── rms ───────────────────────────────────────────────────────

    #[test]
    fn rms_empty_is_zero() {
        assert_eq!(rms_energy(&[]), 0.0);
    }

    #[test]
    fn rms_silence_is_zero() {
        assert_eq!(rms_energy(&[0.0; 100]), 0.0);
    }

    #[test]
    fn rms_constant_signal_equals_amplitude() {
        let signal = vec![0.5_f32; 100];
        let r = rms_energy(&signal);
        assert!((r - 0.5).abs() < 1e-6);
    }

    // ── live transcript buffer ────────────────────────────────────

    #[test]
    fn buffer_silence_only_never_emits() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        // 2 seconds of silence.
        b.feed_pcm_f32(&vec![0.0; 16_000 * 2]);
        assert!(b.poll_completed_utterance().is_none());
        assert!(b.pending_samples() > 0); // silence stays in pending
    }

    #[test]
    fn buffer_speech_then_silence_emits_after_hangover() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        // 500 ms of "speech" (above-threshold constant).
        b.feed_pcm_f32(&vec![0.3; 16_000 / 2]);
        assert!(b.poll_completed_utterance().is_none()); // still talking
        // 1 second of silence (> 750 ms hangover).
        b.feed_pcm_f32(&[0.0; 16_000]);
        let utt = b.poll_completed_utterance();
        assert!(utt.is_some(), "should emit after hangover elapsed");
        let pcm = utt.unwrap();
        assert!(!pcm.is_empty());
    }

    #[test]
    fn buffer_speech_alone_no_silence_does_not_emit() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        // 2 seconds of speech, no trailing silence yet.
        b.feed_pcm_f32(&vec![0.3; 16_000 * 2]);
        assert!(b.poll_completed_utterance().is_none());
    }

    #[test]
    fn buffer_resets_state_after_emit() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        b.feed_pcm_f32(&vec![0.3; 16_000 / 2]); // speech
        b.feed_pcm_f32(&vec![0.0; 16_000]); // silence > hangover
        let _ = b.poll_completed_utterance().expect("emit");
        // After emit, buffer should be empty + ready for the next
        // utterance.
        assert_eq!(b.pending_samples(), 0);
        assert!(b.poll_completed_utterance().is_none());
    }

    #[test]
    fn buffer_with_thresholds_overrides_defaults() {
        let mut b = LiveTranscriptBuffer::new(16_000).with_thresholds(0.1, 200);
        // 0.05 amplitude is BELOW the raised threshold → silence.
        b.feed_pcm_f32(&vec![0.05; 16_000 / 2]); // 500 ms "silence"
        // But seen_speech is false → no emit even after hangover.
        assert!(b.poll_completed_utterance().is_none());
        // 0.5 amplitude is above threshold → speech.
        b.feed_pcm_f32(&vec![0.5; 16_000 / 4]); // 250 ms speech
        b.feed_pcm_f32(&vec![0.05; 16_000 / 4]); // 250 ms silence (> 200ms hangover)
        assert!(b.poll_completed_utterance().is_some());
    }

    #[test]
    fn buffer_pending_samples_tracks_total_fed() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        b.feed_pcm_f32(&[0.0; 100]);
        b.feed_pcm_f32(&[0.0; 50]);
        assert_eq!(b.pending_samples(), 150);
    }

    #[test]
    fn buffer_reset_clears_pending() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        b.feed_pcm_f32(&vec![0.3; 1000]);
        assert!(b.pending_samples() > 0);
        b.reset();
        assert_eq!(b.pending_samples(), 0);
        assert!(b.poll_completed_utterance().is_none());
    }

    #[test]
    fn buffer_finish_drains_final_speech_without_hangover() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        let speech = vec![0.3; 4_000];
        b.feed_pcm_f32(&speech);

        assert_eq!(b.finish(), Some(speech));
        assert_eq!(b.pending_samples(), 0);
        assert!(b.poll_completed_utterance().is_none());
    }

    #[test]
    fn buffer_finish_discards_silence_only_and_resets() {
        let mut b = LiveTranscriptBuffer::new(16_000);
        b.feed_pcm_f32(&vec![0.0; 8_000]);

        assert!(b.finish().is_none());
        assert_eq!(b.pending_samples(), 0);

        let speech = vec![0.4; 1_000];
        b.feed_pcm_f32(&speech);
        assert_eq!(b.finish(), Some(speech));
    }

    // ── HANDY-06 resolve_language ─────────────────────────────────

    #[test]
    fn resolve_supported_language_used_as_is() {
        let r = resolve_language(Some("de"), &["en", "de", "fr"]);
        assert_eq!(r.language, "de");
        assert!(!r.fell_back);
        assert!(r.fallback_from.is_none());
    }

    #[test]
    fn resolve_unsupported_language_falls_back_to_auto() {
        let r = resolve_language(Some("ja"), &["en", "de", "fr"]);
        assert_eq!(r.language, ""); // auto-detect
        assert!(r.fell_back);
        assert_eq!(r.fallback_from.as_deref(), Some("ja"));
    }

    #[test]
    fn resolve_none_returns_auto_no_fallback() {
        let r = resolve_language(None, &["en", "de"]);
        assert_eq!(r.language, "");
        assert!(!r.fell_back);
        assert!(r.fallback_from.is_none());
    }

    #[test]
    fn resolve_empty_string_treated_as_none() {
        let r = resolve_language(Some(""), &["en", "de"]);
        assert_eq!(r.language, "");
        assert!(!r.fell_back);
    }

    #[test]
    fn resolve_primary_subtag_match_succeeds() {
        // Requesting "de-AT" when provider only lists "de" → match via primary.
        let r = resolve_language(Some("de-AT"), &["en", "de", "fr"]);
        assert_eq!(r.language, "de-AT");
        assert!(!r.fell_back);
    }

    #[test]
    fn resolve_case_insensitive() {
        let r = resolve_language(Some("DE"), &["en", "de", "fr"]);
        assert_eq!(r.language, "DE");
        assert!(!r.fell_back);
    }

    #[test]
    fn resolve_empty_supported_list_passes_through_any() {
        // Empty supported list means "provider accepts anything".
        let r = resolve_language(Some("zh"), &[]);
        assert_eq!(r.language, "zh");
        assert!(!r.fell_back);
    }

    // ── serde ─────────────────────────────────────────────────────

    #[test]
    fn provider_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&SttProvider::OpenAiWhisperApi).unwrap(),
            "\"openai_whisper_api\"",
        );
    }

    #[test]
    fn model_size_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&WhisperModelSize::Medium).unwrap(),
            "\"medium\"",
        );
    }

    #[test]
    fn transcription_result_serde_roundtrip() {
        let r = TranscriptionResult {
            text: "Hallo Welt".into(),
            segments: vec![TextSegment {
                start_ms: 0,
                end_ms: 1200,
                text: "Hallo Welt".into(),
            }],
            language: "de".into(),
            confidence: Some(0.93),
            speaker_labels: vec![Some("SPEAKER_01".into())],
            provider: "openai_whisper_api".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: TranscriptionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
