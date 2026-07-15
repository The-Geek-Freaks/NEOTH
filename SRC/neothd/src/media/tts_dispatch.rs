//! MM-03 — TTS dispatcher primitive.
//!
//! Operator-facing surface for picking a TTS provider, validating a request,
//! and carrying the complete non-secret `freedom.yaml::media.tts` contract.
//! Every accepted provider has a production implementation behind
//! [`super::tts_cloud::make_tts_provider`]; there are no reserved enum values.
//!
//!   - [`TtsProvider`] enum + audit tags.
//!   - [`TtsRequest`] / [`TtsResponse`] / [`TtsFormat`] data shapes.
//!   - [`TtsDispatcher`] config + provider-selection logic.
//!   - [`cached_filename`] deterministic filename for cached audio
//!     so dispatchers can skip re-synth when the same text+voice
//!     was rendered before.
//!   - [`pick_voice_for_locale`] convenience defaults.

use serde::{Deserialize, Serialize};

/// Audio container/codec the dispatcher returns to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtsFormat {
    /// PCM s16le raw — easy to feed into a system audio sink.
    PcmS16le,
    /// 16-bit WAV with header — operators can save+play directly.
    Wav,
    /// MP3 — smallest file, cloud providers default to this.
    Mp3,
    /// Opus — best quality/size for streaming.
    Opus,
}

impl TtsFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PcmS16le => "pcm_s16le",
            Self::Wav => "wav",
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
        }
    }

    pub fn file_extension(self) -> &'static str {
        match self {
            Self::PcmS16le => "pcm",
            Self::Wav => "wav",
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
        }
    }
}

/// One TTS backend. Selection happens at dispatch time per the
/// operator's freedom.yaml::tts.provider knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtsProvider {
    /// Local Piper CLI + operator-provided ONNX voice — zero network.
    Piper,
    /// Azure TTS REST — Microsoft's cloud, high-quality voices.
    AzureTts,
    /// ElevenLabs REST — best multilingual quality, paid + cloud.
    ElevenLabs,
    /// OS-native (macOS `say`, Linux `espeak-ng`, Windows SAPI).
    /// Lowest quality but zero install footprint — sensible default
    /// before the operator opts into a real model.
    SystemNative,
    /// JV-VOICE-01 — `edge-tts` Python CLI subprocess. The process runs
    /// locally, but synthesis is performed by Microsoft's online Edge speech
    /// service: text leaves the machine even though no API key is required.
    /// Requires `pip install edge-tts`. Output: MP3 via stdout.
    EdgeTts,
    /// GOLD-ADAPT-SYS-02 — ViitorVoice HTTP sidecar (viitor-voice-nar gateway).
    /// Zero-shot voice CLONING: POSTs a reference-audio sample + the text to a
    /// self-hosted `{endpoint}/v1/voice-clone` and gets back synthesised audio
    /// in the cloned voice. Not local (text + ref audio leave the process to the
    /// sidecar), so it sits behind the `media.cloud_tts_enabled` gate. The
    /// `voice_id` field carries the reference-audio file path.
    ViitorVoice,
}

impl TtsProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Piper => "piper",
            Self::AzureTts => "azure_tts",
            Self::ElevenLabs => "eleven_labs",
            Self::SystemNative => "system_native",
            Self::EdgeTts => "edge_tts",
            Self::ViitorVoice => "viitor_voice",
        }
    }

    /// True only when synthesis is guaranteed to stay on this machine.
    /// A local subprocess is not sufficient: `edge-tts` calls Microsoft's
    /// online speech service and therefore remains cloud egress.
    pub fn is_local(self) -> bool {
        matches!(self, Self::Piper | Self::SystemNative)
    }

    /// True when the provider requires a paid account or API key.
    pub fn requires_credentials(self) -> bool {
        matches!(self, Self::AzureTts | Self::ElevenLabs)
    }

    /// Operator-facing one-liner shown in the wizard picker.
    pub fn description(self) -> &'static str {
        match self {
            Self::Piper => "Local Piper CLI + operator-provided ONNX voice — zero network",
            Self::AzureTts => "Azure TTS — cloud, high quality, requires API key",
            Self::ElevenLabs => "ElevenLabs — cloud, best multilingual, paid",
            Self::SystemNative => "OS-native (say/espeak-ng/SAPI) — zero install, lowest quality",
            Self::EdgeTts => {
                "edge-tts — Microsoft online speech via a local CLI; cloud consent required, no API key"
            }
            Self::ViitorVoice => {
                "ViitorVoice — self-hosted voice-cloning sidecar (needs media.cloud_tts_enabled + endpoint)"
            }
        }
    }

    /// Parse CLI aliases without accepting names that lack a production
    /// implementation. Serde remains pinned to snake_case.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "piper" => Some(Self::Piper),
            "azure" | "azure_tts" => Some(Self::AzureTts),
            "elevenlabs" | "eleven_labs" => Some(Self::ElevenLabs),
            "system" | "system_native" => Some(Self::SystemNative),
            "edge" | "edge_tts" => Some(Self::EdgeTts),
            "viitor" | "viitor_voice" => Some(Self::ViitorVoice),
            _ => None,
        }
    }

    pub const fn known_names() -> &'static str {
        "piper, system_native, edge_tts, eleven_labs, azure_tts, viitor_voice"
    }
}

/// One synthesis request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtsRequest {
    pub text: String,
    /// Provider-specific voice id (e.g. piper `de_DE-thorsten-low`,
    /// AzureTTS `de-DE-KatjaNeural`, ElevenLabs `Rachel`).
    pub voice_id: String,
    /// Locale tag — kept here so the dispatcher can default the
    /// voice when `voice_id` is empty via
    /// [`pick_voice_for_locale`].
    pub locale: String,
    pub format: TtsFormat,
    /// Output sample rate in Hz. 22050 is a sensible default for
    /// piper; cloud providers may upsample.
    pub sample_rate_hz: u32,
}

impl TtsRequest {
    /// Provider-neutral constructor. The canonical dispatcher fills the voice
    /// only after it knows the actual primary/fallback provider.
    pub fn for_locale(text: impl Into<String>, locale: impl Into<String>) -> Self {
        let locale = locale.into();
        Self {
            text: text.into(),
            voice_id: String::new(),
            locale,
            format: TtsFormat::Wav,
            sample_rate_hz: 22_050,
        }
    }
}

/// Response from the provider. Audio bytes are owned + the
/// duration is the dispatcher's best estimate (set by the
/// provider impl after synth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtsResponse {
    pub audio_bytes: Vec<u8>,
    pub format: TtsFormat,
    pub duration_ms: u32,
}

/// Operator-config for the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtsDispatcherConfig {
    pub primary: TtsProvider,
    /// Fallback when the primary fails (e.g. cloud provider returns
    /// 5xx). `None` = surface the error without fallback.
    #[serde(default)]
    pub fallback: Option<TtsProvider>,
    /// Maximum text length the dispatcher accepts in one request.
    /// Longer texts SHOULD be chunked by sentence; the dispatcher
    /// itself doesn't chunk (caller does — chunking strategy varies
    /// by use case).
    #[serde(default = "default_max_chars")]
    pub max_chars_per_request: usize,
    /// Default output format when the request leaves it unset.
    #[serde(default = "default_format")]
    pub default_format: TtsFormat,
    /// Locale used when the caller does not override it.
    #[serde(default = "default_locale")]
    pub locale: String,
    /// Provider-specific voice id. Empty selects the locale default.
    #[serde(default)]
    pub voice: String,
    /// Piper model path, relative to `~/.neoth/models/piper/` or an absolute
    /// path contained by that directory. No download is attempted.
    #[serde(default)]
    pub piper_model: Option<std::path::PathBuf>,
    /// Piper JSON config path under the same containment root. When omitted,
    /// `<model>.json` is used (for example `voice.onnx.json`).
    #[serde(default)]
    pub piper_config: Option<std::path::PathBuf>,
    /// Azure Speech region (for example `westeurope`). Not a secret.
    #[serde(default)]
    pub azure_region: Option<String>,
    /// Operator-selected Viitor sidecar URL. Not a credential.
    #[serde(default)]
    pub viitor_endpoint: Option<String>,
}

fn default_max_chars() -> usize {
    8_000
}
fn default_format() -> TtsFormat {
    TtsFormat::Wav
}
fn default_locale() -> String {
    "en-US".to_string()
}

impl Default for TtsDispatcherConfig {
    fn default() -> Self {
        Self {
            // A clean install speaks through an offline OS facility. Piper is
            // selected explicitly once its operator-provided model is present.
            primary: TtsProvider::SystemNative,
            fallback: None,
            max_chars_per_request: default_max_chars(),
            default_format: default_format(),
            locale: default_locale(),
            voice: String::new(),
            piper_model: None,
            piper_config: None,
            azure_region: None,
            viitor_endpoint: None,
        }
    }
}

/// Dispatcher decision — operator wants `primary`, but the request
/// validation might force a fallback (e.g. cloud provider absent
/// API key + text length over limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchDecision {
    Use(TtsProvider),
    /// Request was rejected for the named reason — caller surfaces
    /// to the operator instead of attempting synth.
    Reject {
        reason: String,
    },
}

/// Pure-function dispatcher: given config + request, decide which
/// provider to use. Reject when text exceeds `max_chars_per_request`
/// — chunking is the caller's job.
pub fn dispatch(config: &TtsDispatcherConfig, request: &TtsRequest) -> DispatchDecision {
    if request.text.trim().is_empty() {
        return DispatchDecision::Reject {
            reason: "empty text — nothing to synthesise".to_string(),
        };
    }
    let char_count = request.text.chars().count();
    if char_count > config.max_chars_per_request {
        return DispatchDecision::Reject {
            reason: format!(
                "text length {} exceeds max_chars_per_request {} — chunk by sentence and call again",
                char_count, config.max_chars_per_request,
            ),
        };
    }
    DispatchDecision::Use(config.primary)
}

/// On primary-provider error, return the fallback decision (or
/// Reject when no fallback configured). Caller chains this after
/// a failed synth attempt.
pub fn dispatch_fallback(config: &TtsDispatcherConfig, primary_error: &str) -> DispatchDecision {
    match config.fallback {
        Some(p) => DispatchDecision::Use(p),
        None => DispatchDecision::Reject {
            reason: format!("primary failed ({primary_error}) + no fallback configured"),
        },
    }
}

/// Deterministic filename for cached audio output. Format:
/// `<provider>-<voice>-<xxh3-of-text>.<ext>`. Two identical
/// requests produce the same filename → cache-hit short-circuit.
pub fn cached_filename(provider: TtsProvider, request: &TtsRequest) -> String {
    let hash_input = format!(
        "{}|{}|{}",
        request.text,
        request.voice_id,
        request.format.as_str()
    );
    let h = xxhash_rust::xxh3::xxh3_64(hash_input.as_bytes());
    let safe_voice = request
        .voice_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();
    format!(
        "{}-{}-{:016x}.{}",
        provider.as_str(),
        safe_voice,
        h,
        request.format.file_extension(),
    )
}

/// Conservative locale-to-voice defaults. The wizard surfaces these
/// when the operator hasn't set a `voice_id` for the active
/// provider. Returns `None` when no canned default exists — caller
/// asks the operator to pick.
pub fn pick_voice_for_locale(locale: &str, provider: TtsProvider) -> Option<&'static str> {
    let lc = locale.to_lowercase();
    match (provider, lc.as_str()) {
        (TtsProvider::Piper, "de" | "de-de" | "de_de") => Some("de_DE-thorsten-low"),
        (TtsProvider::Piper, "en" | "en-us" | "en_us") => Some("en_US-lessac-medium"),
        (TtsProvider::Piper, "en-gb" | "en_gb") => Some("en_GB-alan-medium"),
        (TtsProvider::AzureTts, "de" | "de-de" | "de_de") => Some("de-DE-KatjaNeural"),
        (TtsProvider::AzureTts, "en" | "en-us" | "en_us") => Some("en-US-AriaNeural"),
        (TtsProvider::ElevenLabs, "de" | "de-de" | "de_de") => Some("Rachel"),
        // EdgeTts voices — Microsoft neural voice IDs (same pool as AzureTts).
        (TtsProvider::EdgeTts, "de" | "de-de" | "de_de") => Some("de-DE-KatjaNeural"),
        (TtsProvider::EdgeTts, "de-at" | "de_at") => Some("de-AT-IngridNeural"),
        (TtsProvider::EdgeTts, "de-ch" | "de_ch") => Some("de-CH-LeniNeural"),
        (TtsProvider::EdgeTts, "en" | "en-us" | "en_us") => Some("en-US-AriaNeural"),
        (TtsProvider::EdgeTts, "en-gb" | "en_gb") => Some("en-GB-SoniaNeural"),
        (TtsProvider::EdgeTts, "en-au" | "en_au") => Some("en-AU-NatashaNeural"),
        (TtsProvider::EdgeTts, "fr" | "fr-fr" | "fr_fr") => Some("fr-FR-DeniseNeural"),
        (TtsProvider::EdgeTts, "es" | "es-es" | "es_es") => Some("es-ES-ElviraNeural"),
        (TtsProvider::EdgeTts, "it" | "it-it" | "it_it") => Some("it-IT-ElsaNeural"),
        (TtsProvider::EdgeTts, "pt" | "pt-br" | "pt_br") => Some("pt-BR-FranciscaNeural"),
        (TtsProvider::EdgeTts, "nl" | "nl-nl" | "nl_nl") => Some("nl-NL-ColetteNeural"),
        (TtsProvider::EdgeTts, "pl" | "pl-pl" | "pl_pl") => Some("pl-PL-ZofiaNeural"),
        (TtsProvider::EdgeTts, "ru" | "ru-ru" | "ru_ru") => Some("ru-RU-SvetlanaNeural"),
        (TtsProvider::EdgeTts, "ja" | "ja-jp" | "ja_jp") => Some("ja-JP-NanamiNeural"),
        (TtsProvider::EdgeTts, "zh" | "zh-cn" | "zh_cn") => Some("zh-CN-XiaoxiaoNeural"),
        (TtsProvider::EdgeTts, "ko" | "ko-kr" | "ko_kr") => Some("ko-KR-SunHiNeural"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn format_as_str_pinned() {
        assert_eq!(TtsFormat::PcmS16le.as_str(), "pcm_s16le");
        assert_eq!(TtsFormat::Wav.as_str(), "wav");
        assert_eq!(TtsFormat::Mp3.as_str(), "mp3");
        assert_eq!(TtsFormat::Opus.as_str(), "opus");
    }

    #[test]
    fn format_file_extension_pinned() {
        assert_eq!(TtsFormat::PcmS16le.file_extension(), "pcm");
        assert_eq!(TtsFormat::Wav.file_extension(), "wav");
        assert_eq!(TtsFormat::Mp3.file_extension(), "mp3");
        assert_eq!(TtsFormat::Opus.file_extension(), "opus");
    }

    #[test]
    fn provider_as_str_pinned() {
        assert_eq!(TtsProvider::Piper.as_str(), "piper");
        assert_eq!(TtsProvider::AzureTts.as_str(), "azure_tts");
        assert_eq!(TtsProvider::ElevenLabs.as_str(), "eleven_labs");
        assert_eq!(TtsProvider::SystemNative.as_str(), "system_native");
        assert_eq!(TtsProvider::EdgeTts.as_str(), "edge_tts");
        assert_eq!(TtsProvider::ViitorVoice.as_str(), "viitor_voice");
    }

    #[test]
    fn provider_is_local_correct() {
        assert!(TtsProvider::Piper.is_local());
        assert!(TtsProvider::SystemNative.is_local());
        assert!(!TtsProvider::EdgeTts.is_local());
        assert!(!TtsProvider::AzureTts.is_local());
        assert!(!TtsProvider::ElevenLabs.is_local());
        assert!(!TtsProvider::ViitorVoice.is_local());
    }

    #[test]
    fn provider_requires_credentials_correct() {
        assert!(TtsProvider::AzureTts.requires_credentials());
        assert!(TtsProvider::ElevenLabs.requires_credentials());
        assert!(!TtsProvider::Piper.requires_credentials());
        assert!(!TtsProvider::SystemNative.requires_credentials());
        assert!(!TtsProvider::EdgeTts.requires_credentials());
        assert!(!TtsProvider::ViitorVoice.requires_credentials());
    }

    #[test]
    fn provider_description_strings_present() {
        for p in [
            TtsProvider::Piper,
            TtsProvider::AzureTts,
            TtsProvider::ElevenLabs,
            TtsProvider::SystemNative,
            TtsProvider::EdgeTts,
            TtsProvider::ViitorVoice,
        ] {
            assert!(!p.description().is_empty(), "{p:?}");
        }
    }

    // ── config defaults ───────────────────────────────────────────

    #[test]
    fn default_config_is_offline_system_native() {
        let c = TtsDispatcherConfig::default();
        assert_eq!(c.primary, TtsProvider::SystemNative);
        assert_eq!(c.fallback, None);
        assert_eq!(c.max_chars_per_request, 8_000);
        assert_eq!(c.default_format, TtsFormat::Wav);
        assert_eq!(c.locale, "en-US");
    }

    // ── for_locale ────────────────────────────────────────────────

    #[test]
    fn for_locale_is_provider_neutral() {
        let r = TtsRequest::for_locale("Hallo", "de-DE");
        assert_eq!(r.voice_id, "");
        assert_eq!(r.format, TtsFormat::Wav);
        assert_eq!(r.sample_rate_hz, 22_050);
    }

    #[test]
    fn for_locale_unknown_voice_empty_string() {
        let r = TtsRequest::for_locale("hi", "xx");
        assert_eq!(r.voice_id, "");
    }

    // ── dispatch ──────────────────────────────────────────────────

    #[test]
    fn dispatch_uses_primary_for_normal_request() {
        let c = TtsDispatcherConfig::default();
        let r = TtsRequest::for_locale("hello", "en-us");
        assert_eq!(
            dispatch(&c, &r),
            DispatchDecision::Use(TtsProvider::SystemNative)
        );
    }

    #[test]
    fn dispatch_rejects_empty_text() {
        let c = TtsDispatcherConfig::default();
        let r = TtsRequest::for_locale("", "en-us");
        match dispatch(&c, &r) {
            DispatchDecision::Reject { reason } => {
                assert!(reason.contains("empty text"));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_rejects_oversize_text_with_chunking_hint() {
        let c = TtsDispatcherConfig {
            max_chars_per_request: 10,
            ..TtsDispatcherConfig::default()
        };
        let r = TtsRequest::for_locale("x".repeat(20), "en-us");
        match dispatch(&c, &r) {
            DispatchDecision::Reject { reason } => {
                assert!(reason.contains("exceeds"));
                assert!(reason.contains("chunk"));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ── fallback dispatch ─────────────────────────────────────────

    #[test]
    fn dispatch_fallback_returns_configured_fallback() {
        let c = TtsDispatcherConfig {
            fallback: Some(TtsProvider::SystemNative),
            ..TtsDispatcherConfig::default()
        };
        assert_eq!(
            dispatch_fallback(&c, "network 5xx"),
            DispatchDecision::Use(TtsProvider::SystemNative),
        );
    }

    #[test]
    fn dispatch_fallback_reject_when_none_configured() {
        let c = TtsDispatcherConfig {
            fallback: None,
            ..TtsDispatcherConfig::default()
        };
        match dispatch_fallback(&c, "boom") {
            DispatchDecision::Reject { reason } => {
                assert!(reason.contains("no fallback"));
                assert!(reason.contains("boom"));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // ── cached_filename determinism ───────────────────────────────

    #[test]
    fn cached_filename_deterministic_for_same_request() {
        let r = TtsRequest::for_locale("hello world", "en-us");
        let a = cached_filename(TtsProvider::Piper, &r);
        let b = cached_filename(TtsProvider::Piper, &r);
        assert_eq!(a, b);
    }

    #[test]
    fn cached_filename_differs_on_text_change() {
        let mut r = TtsRequest::for_locale("hello", "en-us");
        let a = cached_filename(TtsProvider::Piper, &r);
        r.text = "goodbye".to_string();
        let b = cached_filename(TtsProvider::Piper, &r);
        assert_ne!(a, b);
    }

    #[test]
    fn cached_filename_differs_on_voice_change() {
        let mut r = TtsRequest::for_locale("hi", "en-us");
        let a = cached_filename(TtsProvider::Piper, &r);
        r.voice_id = "en_US-other-voice".to_string();
        let b = cached_filename(TtsProvider::Piper, &r);
        assert_ne!(a, b);
    }

    #[test]
    fn cached_filename_uses_provider_prefix_and_format_extension() {
        let r = TtsRequest {
            text: "hi".into(),
            voice_id: "v1".into(),
            locale: "en".into(),
            format: TtsFormat::Mp3,
            sample_rate_hz: 22_050,
        };
        let name = cached_filename(TtsProvider::AzureTts, &r);
        assert!(name.starts_with("azure_tts-"));
        assert!(name.ends_with(".mp3"));
    }

    #[test]
    fn cached_filename_strips_unsafe_chars_from_voice() {
        let r = TtsRequest {
            text: "hi".into(),
            voice_id: "weird/voice with spaces".into(),
            locale: "en".into(),
            format: TtsFormat::Wav,
            sample_rate_hz: 22_050,
        };
        let name = cached_filename(TtsProvider::Piper, &r);
        // No slashes, no spaces in output.
        assert!(!name.contains('/'));
        assert!(!name.contains(' '));
        // The recognisable safe chars from the voice survive.
        assert!(name.contains("weirdvoicewithspaces"));
    }

    // ── locale → voice defaults ───────────────────────────────────

    #[test]
    fn pick_voice_for_locale_piper_de_returns_thorsten() {
        assert_eq!(
            pick_voice_for_locale("de-DE", TtsProvider::Piper),
            Some("de_DE-thorsten-low"),
        );
        assert_eq!(
            pick_voice_for_locale("de", TtsProvider::Piper),
            Some("de_DE-thorsten-low"),
        );
    }

    #[test]
    fn pick_voice_for_locale_piper_en_us_returns_lessac() {
        assert_eq!(
            pick_voice_for_locale("en-US", TtsProvider::Piper),
            Some("en_US-lessac-medium"),
        );
    }

    #[test]
    fn pick_voice_for_locale_azure_de_returns_katja() {
        assert_eq!(
            pick_voice_for_locale("de-de", TtsProvider::AzureTts),
            Some("de-DE-KatjaNeural"),
        );
    }

    #[test]
    fn pick_voice_for_locale_unknown_returns_none() {
        assert!(pick_voice_for_locale("xx", TtsProvider::Piper).is_none());
        assert!(pick_voice_for_locale("de", TtsProvider::SystemNative).is_none());
    }

    #[test]
    fn pick_voice_for_locale_edge_tts_de_returns_katja_neural() {
        assert_eq!(
            pick_voice_for_locale("de-DE", TtsProvider::EdgeTts),
            Some("de-DE-KatjaNeural"),
        );
        assert_eq!(
            pick_voice_for_locale("de", TtsProvider::EdgeTts),
            Some("de-DE-KatjaNeural"),
        );
    }

    #[test]
    fn pick_voice_for_locale_edge_tts_en_us_returns_aria_neural() {
        assert_eq!(
            pick_voice_for_locale("en-US", TtsProvider::EdgeTts),
            Some("en-US-AriaNeural"),
        );
        assert_eq!(
            pick_voice_for_locale("en", TtsProvider::EdgeTts),
            Some("en-US-AriaNeural"),
        );
    }

    #[test]
    fn pick_voice_for_locale_edge_tts_unknown_returns_none() {
        assert!(pick_voice_for_locale("xx", TtsProvider::EdgeTts).is_none());
    }

    #[test]
    fn edge_tts_provider_is_cloud_egress_without_credentials() {
        assert!(!TtsProvider::EdgeTts.is_local());
        assert!(!TtsProvider::EdgeTts.requires_credentials());
    }

    // ── serde ─────────────────────────────────────────────────────

    #[test]
    fn provider_serialises_snake_case() {
        let json = serde_json::to_string(&TtsProvider::AzureTts).unwrap();
        assert_eq!(json, "\"azure_tts\"");
    }

    #[test]
    fn format_serialises_snake_case() {
        let json = serde_json::to_string(&TtsFormat::PcmS16le).unwrap();
        assert_eq!(json, "\"pcm_s16le\"");
    }

    #[test]
    fn config_serde_roundtrip_keeps_optional_fallback() {
        let c = TtsDispatcherConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: TtsDispatcherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn removed_coqui_value_fails_deserialization() {
        let err = serde_json::from_str::<TtsProvider>("\"coqui\"").unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn parse_accepts_only_implemented_provider_aliases() {
        assert_eq!(
            TtsProvider::parse("elevenlabs"),
            Some(TtsProvider::ElevenLabs)
        );
        assert_eq!(TtsProvider::parse("edge_tts"), Some(TtsProvider::EdgeTts));
        assert_eq!(TtsProvider::parse("coqui"), None);
    }
}
