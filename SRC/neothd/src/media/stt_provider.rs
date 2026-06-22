//! MM-01b — cloud STT providers: OpenAI Whisper API + Azure Speech (REST).
//!
//! Implements the [`SttProviderImpl`] trait (parallel to the TTS
//! [`super::tts_provider::TtsProvider`] surface) over the request/result types
//! already defined in [`super::stt_dispatch`]. A [`make_stt_provider`] factory
//! bridges a [`SttProviderKind`] + operator creds to a live transcriber.
//!
//! ## Privacy
//!
//! STT output is NEVER written to the WAL — transcript text stays in memory /
//! the caller's hands per the NEOTH privacy model. There is no STT WAL event;
//! the only durable trace is whatever the caller chooses to persist.
//!
//! ## Network-guard posture
//!
//! Both clients build their `reqwest::Client` via
//! [`crate::providers::http_client::build_client`] (inside `providers/`, already
//! allow-listed), so this file under `src/media/` carries no forbidden
//! construction token. Operator-configured cloud STT — an explicit, credentialed
//! upstream.
//!
//! ## Deferred
//!
//! - **Local candle backend** — the codebase already has a pure-Rust candle
//!   `providers::whisper::WhisperEngine`; wiring it as an `SttProviderImpl`
//!   needs a `bytes -> f32 PCM` decode bridge (symphonia) and is its own slice.
//! - **Vosk** — a C-FFI engine (cmake + C++), same build-risk class as
//!   whisper-rs/piper-rs; deferred. `make_stt_provider` returns a clear error.

use async_trait::async_trait;

use super::stt_dispatch::{
    SttProvider as SttProviderKind, TextSegment, TranscriptionRequest, TranscriptionResult,
};
use crate::providers::http_client;
use crate::secret::SecretString;

/// Common STT backend surface — every transcriber implements this. `audio` is a
/// COMPLETE encoded audio file (WAV/MP3 bytes) the cloud endpoints upload as-is.
#[async_trait]
pub trait SttProviderImpl: Send + Sync {
    /// The dispatcher's pinned [`SttProviderKind`] variant for this impl.
    fn kind(&self) -> SttProviderKind;

    /// Transcribe `audio` (an encoded audio file). Errors carry an
    /// operator-readable string.
    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, String>;

    /// Languages this provider supports (IETF BCP 47 tags). Empty = accept
    /// any (auto-detect / no restriction), the default. A language-restricted
    /// backend overrides this so the dispatcher's fallback guard
    /// (GOLD-ADAPT-HANDY-06) can steer an unsupported request to a safe
    /// language instead of letting the backend fail.
    fn supported_languages(&self) -> &'static [&'static str] {
        &[]
    }
}

// ── OpenAI Whisper API (multipart upload) ───────────────────────────────────

/// `POST https://api.openai.com/v1/audio/transcriptions`. Auth: bearer key.
/// Multipart form: `file` (audio), `model=whisper-1`, `response_format=
/// verbose_json` (so we get per-segment timestamps).
pub struct OpenAiWhisperClient {
    api_key: SecretString,
    base_url: String,
}

impl OpenAiWhisperClient {
    pub fn new(api_key: SecretString) -> Self {
        Self {
            api_key,
            base_url: "https://api.openai.com".to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/v1/audio/transcriptions",
            self.base_url.trim_end_matches('/')
        )
    }
}

/// Parse OpenAI's `verbose_json` transcription response into a
/// [`TranscriptionResult`]. PURE — the network is the caller's. The API returns
/// `start`/`end` in SECONDS (float); we convert to ms.
pub fn parse_openai_whisper(
    body: &[u8],
    req_language: &str,
) -> Result<TranscriptionResult, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("openai whisper decode: {e}"))?;
    let text = v
        .get("text")
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();
    let language = v
        .get("language")
        .and_then(|l| l.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| req_language.to_string());
    let segments = v
        .get("segments")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|seg| {
                    let start = seg.get("start").and_then(|x| x.as_f64())?;
                    let end = seg.get("end").and_then(|x| x.as_f64())?;
                    let text = seg.get("text").and_then(|x| x.as_str())?.to_string();
                    Some(TextSegment {
                        start_ms: (start * 1000.0).max(0.0) as u32,
                        end_ms: (end * 1000.0).max(0.0) as u32,
                        text,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(TranscriptionResult {
        text,
        segments,
        language,
        confidence: None, // the API does not return a confidence
    })
}

#[async_trait]
impl SttProviderImpl for OpenAiWhisperClient {
    fn kind(&self) -> SttProviderKind {
        SttProviderKind::OpenAiWhisperApi
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, String> {
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let part = reqwest::multipart::Part::bytes(audio.to_vec())
            .file_name("audio.wav")
            .mime_str("audio/wav")
            .map_err(|e| format!("multipart part: {e}"))?;
        let mut form = reqwest::multipart::Form::new()
            .text("model", "whisper-1")
            .text("response_format", "verbose_json")
            .part("file", part);
        if !request.language.is_empty() {
            form = form.text("language", request.language.clone());
        }
        if !request.initial_prompt.is_empty() {
            form = form.text("prompt", request.initial_prompt.clone());
        }
        let resp = client
            .post(self.endpoint())
            .bearer_auth(self.api_key.expose())
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("openai whisper request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("openai whisper returned HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("openai whisper body: {e}"))?;
        parse_openai_whisper(&body, &request.language)
    }
}

// ── Azure Speech (REST batch) ───────────────────────────────────────────────

/// `POST https://{region}.stt.speech.microsoft.com/speech/recognition/
/// conversation/cognitiveservices/v1`. Auth: `Ocp-Apim-Subscription-Key`. Body:
/// raw WAV bytes. Returns `{RecognitionStatus, DisplayText}` — no per-segment
/// timestamps, so the result carries a single whole-utterance segment.
pub struct AzureSpeechClient {
    region: String,
    api_key: SecretString,
    base_url: String,
}

impl AzureSpeechClient {
    pub fn new(region: impl Into<String>, api_key: SecretString) -> Self {
        let region = region.into();
        let base_url = format!("https://{region}.stt.speech.microsoft.com");
        Self {
            region,
            api_key,
            base_url,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn endpoint(&self, language: &str) -> String {
        let lang = if language.is_empty() {
            "en-US"
        } else {
            language
        };
        format!(
            "{}/speech/recognition/conversation/cognitiveservices/v1?language={}",
            self.base_url.trim_end_matches('/'),
            lang
        )
    }
}

/// Parse Azure's REST recognition response. PURE. A `RecognitionStatus` other
/// than `Success` is an error; on success the `DisplayText` becomes the whole
/// transcript with a single 0-length segment (the batch endpoint has no
/// timestamps).
pub fn parse_azure_speech(body: &[u8], language: &str) -> Result<TranscriptionResult, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("azure speech decode: {e}"))?;
    let status = v
        .get("RecognitionStatus")
        .and_then(|s| s.as_str())
        .unwrap_or("Unknown");
    if status != "Success" {
        return Err(format!("azure speech recognition status: {status}"));
    }
    let text = v
        .get("DisplayText")
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();
    let segments = if text.is_empty() {
        Vec::new()
    } else {
        vec![TextSegment {
            start_ms: 0,
            end_ms: 0,
            text: text.clone(),
        }]
    };
    Ok(TranscriptionResult {
        text,
        segments,
        language: language.to_string(),
        confidence: None,
    })
}

/// GOLD-ADAPT-HANDY-06 / F66 — primary language subtags Azure Speech-to-Text
/// supports. The dispatcher's `resolve_language` matches a requested tag's
/// PRIMARY subtag (e.g. `de` from `de-DE`) against this list, so listing primary
/// subtags covers every regional variant; a request outside the set (e.g. a
/// made-up `xx-YY`) steers to provider auto-detect instead of a hard HTTP error.
/// Representative of Azure's published locale set (not exhaustive — Azure's full
/// list is ~140 regional locales, all of which collapse to these primaries).
const AZURE_SPEECH_LANGUAGES: &[&str] = &[
    "ar", "bg", "ca", "zh", "hr", "cs", "da", "nl", "en", "et", "fi", "fr", "de", "el", "gu",
    "he", "hi", "hu", "id", "it", "ja", "kn", "ko", "lv", "lt", "ms", "mr", "nb", "pl", "pt",
    "ro", "ru", "sk", "sl", "es", "sv", "ta", "te", "th", "tr", "uk", "vi",
];

#[async_trait]
impl SttProviderImpl for AzureSpeechClient {
    fn kind(&self) -> SttProviderKind {
        SttProviderKind::AzureSpeech
    }

    /// F66 — engage the dispatcher's HANDY-06 fallback guard: Azure rejects an
    /// unknown locale with an HTTP error, so declare the supported set and let
    /// `resolve_language` fall an unsupported request back to auto-detect.
    fn supported_languages(&self) -> &'static [&'static str] {
        AZURE_SPEECH_LANGUAGES
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, String> {
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(self.endpoint(&request.language))
            .header("Ocp-Apim-Subscription-Key", self.api_key.expose())
            .header(
                "Content-Type",
                "audio/wav; codecs=audio/pcm; samplerate=16000",
            )
            .header("Accept", "application/json")
            .body(audio.to_vec())
            .send()
            .await
            .map_err(|e| format!("azure speech request ({}): {e}", self.region))?;
        if !resp.status().is_success() {
            return Err(format!("azure speech returned HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("azure speech body: {e}"))?;
        parse_azure_speech(&body, &request.language)
    }
}

/// MM-01b bridge: build a live STT provider for `kind` from operator creds.
/// Cloud kinds (OpenAI Whisper / Azure Speech) are live; the local candle
/// backend + Vosk are deferred (see module docs).
pub fn make_stt_provider(
    kind: SttProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<Box<dyn SttProviderImpl>, String> {
    // P0 ENFORCEMENT — a CLOUD STT provider may only be constructed when the
    // operator has opted in (`media.cloud_stt_enabled`). The safe-mode rail makes
    // this visible; this gate makes it REAL — audio cannot leave the device for a
    // cloud transcriber while the flag is off. Local STT carries no gate.
    if !kind.is_local() && !media_cfg.cloud_stt_enabled {
        return Err(format!(
            "cloud STT ({}) is disabled — set media.cloud_stt_enabled: true to send \
             audio to a cloud transcriber (your audio then LEAVES the device)",
            kind.as_str()
        ));
    }
    match kind {
        SttProviderKind::OpenAiWhisperApi => {
            let key = api_key.ok_or("openai whisper requires an api key")?;
            Ok(Box::new(OpenAiWhisperClient::new(key)))
        }
        SttProviderKind::AzureSpeech => {
            let key = api_key.ok_or("azure speech requires an api key")?;
            let region = azure_region.ok_or("azure speech requires a region")?;
            Ok(Box::new(AzureSpeechClient::new(region, key)))
        }
        SttProviderKind::WhisperRsLocal => Err(
            "local whisper STT is deferred — wire it over the existing candle \
             `providers::whisper::WhisperEngine` with a bytes->PCM decode bridge"
                .to_string(),
        ),
        SttProviderKind::Vosk => Err(
            "vosk STT is deferred — a C-FFI engine (cmake + C++ toolchain), same \
             build-risk class as whisper-rs"
                .to_string(),
        ),
    }
}

/// P0 — transcribe through `provider` and emit the metadata-only
/// `0xCC STT_TRANSCRIBED` audit. Records that audio went to a cloud provider
/// (provider id + audio byte count + transcript char count) — NEVER the
/// transcript itself. This is the audited entry point a cloud-STT consumer
/// uses; the audit is best-effort (a WAL error logs, never fails the call).
pub async fn transcribe_and_audit(
    provider: &dyn SttProviderImpl,
    audio: &[u8],
    request: &TranscriptionRequest,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    required_audit: bool,
) -> Result<TranscriptionResult, String> {
    // P0 fail-closed pre-flight: under proof-hardline, refuse BEFORE the cloud
    // call when there is no audit sink — never transcribe unprovably.
    crate::media::enforce_cloud_media_audit(required_audit, writer.is_some())?;
    // GOLD-ADAPT-HANDY-06 — steer an unsupported requested language to a safe
    // fallback BEFORE the call instead of letting the backend fail. Providers
    // that accept any language (the default) never trip this.
    let resolved = crate::media::stt_dispatch::resolve_language(
        (!request.language.is_empty()).then_some(request.language.as_str()),
        provider.supported_languages(),
    );
    let mut result = if resolved.fell_back {
        tracing::warn!(
            provider = provider.kind().as_str(),
            requested = resolved.fallback_from.as_deref().unwrap_or(""),
            chosen = %resolved.language,
            "stt: requested language unsupported by provider — falling back",
        );
        let mut req = request.clone();
        req.language = resolved.language.clone();
        provider.transcribe(audio, &req).await?
    } else {
        provider.transcribe(audio, request).await?
    };
    // GOLD-ADAPT-HANDY-03 — strip filler words + stutters from the transcript
    // on every transcription (conservative; never deletes content words).
    result.text = crate::media::stt_postprocess::clean_transcript(&result.text);
    // GOLD-ADAPT-SPEAKR-02b/02c — speaker re-identification. The self-contained
    // log-mel encoder (speaker_encoder) turns each per-utterance PCM segment
    // into a voice embedding; each is matched against the persisted
    // speaker-profile store + learns the centroid (EMA). The config read, the
    // CPU-bound encode, AND the profile-store I/O all run inside ONE
    // spawn_blocking so nothing blocks the async executor (no sync fs read on
    // the runtime, no FFT on a worker thread). Only the raw-PCM input formats
    // are handled; anything else is a graceful no-op.
    if matches!(
        request.format,
        crate::media::stt_dispatch::AudioFormat::PcmS16leMono
            | crate::media::stt_dispatch::AudioFormat::PcmF32leMono
    ) {
        let audio_owned = audio.to_vec();
        let segments = result.segments.clone();
        let format = request.format;
        let sample_rate = request.sample_rate_hz;
        let labels = tokio::task::spawn_blocking(move || {
            if !crate::config::FreedomConfig::load_from_default_path()
                .map(|c| c.media.auto_speaker_labels)
                .unwrap_or(false)
            {
                return Vec::new();
            }
            let embeddings = crate::media::speaker_encoder::embed_segments(
                &audio_owned,
                format,
                sample_rate,
                &segments,
            );
            if embeddings.is_empty() {
                return Vec::new();
            }
            crate::media::speaker_profile::label_embeddings(
                &crate::config::FreedomConfig::default_neoth_home(),
                &embeddings,
            )
        })
        .await
        .unwrap_or_default();
        let labelled = labels.iter().filter(|l| l.is_some()).count();
        if labelled > 0 {
            tracing::info!(speakers = ?labels, labelled, "SPEAKR-02c speaker re-id");
        }
    }
    if let Some(w) = writer {
        emit_stt_transcribed(w, provider.kind(), audio.len(), result.text.chars().count()).await;
    }
    Ok(result)
}

async fn emit_stt_transcribed(
    writer: &crate::wal::writer::WalWriterHandle,
    provider: SttProviderKind,
    audio_bytes: usize,
    output_chars: usize,
) {
    let ts_unix = crate::time::now_unix_secs();
    let payload = match serde_json::to_vec(&serde_json::json!({
        "provider": provider.as_str(),
        "audio_bytes": audio_bytes,
        "output_chars": output_chars,
        "ts_unix": ts_unix,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize STT_TRANSCRIBED (0xCC) failed");
            return;
        }
    };
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_STT_TRANSCRIBED, &payload);
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append STT_TRANSCRIBED (0xCC) failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::stt_dispatch::{AudioFormat, WhisperModelSize};

    fn req(lang: &str) -> TranscriptionRequest {
        TranscriptionRequest {
            language: lang.into(),
            model_size: WhisperModelSize::Base,
            format: AudioFormat::PcmS16leMono,
            sample_rate_hz: 16_000,
            initial_prompt: String::new(),
        }
    }

    #[test]
    fn parse_openai_maps_segments_to_ms() {
        let body = br#"{"text":"hello world","language":"en",
            "segments":[{"start":0.0,"end":1.5,"text":"hello"},
                        {"start":1.5,"end":2.25,"text":" world"}]}"#;
        let r = parse_openai_whisper(body, "").unwrap();
        assert_eq!(r.text, "hello world");
        assert_eq!(r.language, "en");
        assert_eq!(r.segments.len(), 2);
        assert_eq!(r.segments[0].start_ms, 0);
        assert_eq!(r.segments[0].end_ms, 1500);
        assert_eq!(r.segments[1].end_ms, 2250);
        assert!(r.confidence.is_none());
    }

    #[test]
    fn parse_openai_falls_back_to_request_language() {
        let body = br#"{"text":"hallo"}"#;
        let r = parse_openai_whisper(body, "de").unwrap();
        assert_eq!(r.text, "hallo");
        assert_eq!(
            r.language, "de",
            "no language in response → request language"
        );
        assert!(r.segments.is_empty());
    }

    #[test]
    fn parse_azure_success_makes_one_segment() {
        let body = br#"{"RecognitionStatus":"Success","DisplayText":"guten tag"}"#;
        let r = parse_azure_speech(body, "de-DE").unwrap();
        assert_eq!(r.text, "guten tag");
        assert_eq!(r.segments.len(), 1);
        assert_eq!(r.segments[0].text, "guten tag");
        assert_eq!(r.language, "de-DE");
    }

    #[test]
    fn parse_azure_non_success_is_error() {
        let body = br#"{"RecognitionStatus":"NoMatch","DisplayText":""}"#;
        assert!(parse_azure_speech(body, "en-US").is_err());
    }

    #[test]
    fn azure_endpoint_uses_language_and_default() {
        let c = AzureSpeechClient::new("westeurope", SecretString::from("k"));
        assert!(c.endpoint("de-DE").contains("language=de-DE"));
        assert!(c.endpoint("").contains("language=en-US"));
        assert!(
            c.endpoint("de-DE")
                .starts_with("https://westeurope.stt.speech.microsoft.com")
        );
    }

    #[test]
    fn openai_endpoint_path() {
        let c = OpenAiWhisperClient::new(SecretString::from("k"));
        assert_eq!(
            c.endpoint(),
            "https://api.openai.com/v1/audio/transcriptions"
        );
    }

    fn cloud_on() -> crate::config::MediaConfig {
        crate::config::MediaConfig {
            cloud_stt_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn factory_returns_right_kind_or_deferral() {
        let on = cloud_on();
        assert_eq!(
            make_stt_provider(
                SttProviderKind::OpenAiWhisperApi,
                Some(SecretString::from("k")),
                None,
                &on
            )
            .unwrap()
            .kind(),
            SttProviderKind::OpenAiWhisperApi
        );
        assert_eq!(
            make_stt_provider(
                SttProviderKind::AzureSpeech,
                Some(SecretString::from("k")),
                Some("eastus".into()),
                &on,
            )
            .unwrap()
            .kind(),
            SttProviderKind::AzureSpeech
        );
        assert!(make_stt_provider(SttProviderKind::OpenAiWhisperApi, None, None, &on).is_err());
        assert!(
            make_stt_provider(
                SttProviderKind::AzureSpeech,
                Some(SecretString::from("k")),
                None,
                &on
            )
            .is_err()
        );
        assert!(make_stt_provider(SttProviderKind::WhisperRsLocal, None, None, &on).is_err());
        assert!(make_stt_provider(SttProviderKind::Vosk, None, None, &on).is_err());
    }

    #[test]
    fn cloud_kind_refused_when_flag_off() {
        // P0 — with cloud_stt_enabled OFF (the default), a cloud transcriber
        // cannot be constructed even with valid creds. Local kinds are unaffected
        // by the gate (they fail later as deferred, not as a privacy refusal).
        let off = crate::config::MediaConfig::default();
        let err = make_stt_provider(
            SttProviderKind::OpenAiWhisperApi,
            Some(SecretString::from("k")),
            None,
            &off,
        )
        .err()
        .unwrap();
        assert!(
            err.contains("cloud STT") && err.contains("LEAVES the device"),
            "got: {err}"
        );
        // Azure likewise refused by the gate (region present, still blocked).
        assert!(
            make_stt_provider(
                SttProviderKind::AzureSpeech,
                Some(SecretString::from("k")),
                Some("eastus".into()),
                &off,
            )
            .err()
            .unwrap()
            .contains("cloud STT")
        );
    }

    #[tokio::test]
    async fn transcribe_surfaces_error_on_unreachable_host() {
        let c =
            OpenAiWhisperClient::new(SecretString::from("k")).with_base_url("http://127.0.0.1:1");
        let err = c.transcribe(b"RIFF....", &req("en")).await.unwrap_err();
        assert!(
            err.contains("openai whisper"),
            "expected an openai error, got: {err}"
        );
    }

    struct MockStt;
    #[async_trait]
    impl SttProviderImpl for MockStt {
        fn kind(&self) -> SttProviderKind {
            SttProviderKind::OpenAiWhisperApi
        }
        async fn transcribe(
            &self,
            _audio: &[u8],
            _request: &TranscriptionRequest,
        ) -> Result<TranscriptionResult, String> {
            Ok(TranscriptionResult {
                text: "hello there".into(), // 11 chars
                segments: vec![],
                language: "en".into(),
                confidence: None,
            })
        }
    }

    #[test]
    fn azure_supported_languages_engages_handy06_fallback() {
        // F66 — with the Azure list declared, an unsupported requested language
        // steers to auto-detect; a supported one (incl. a regional variant) passes.
        let client = AzureSpeechClient::new("westeurope", SecretString::from("k"));
        let supported = client.supported_languages();
        assert!(!supported.is_empty(), "Azure must declare a supported set");

        let de = crate::media::stt_dispatch::resolve_language(Some("de-DE"), supported);
        assert!(!de.fell_back, "de-DE primary 'de' is supported");
        assert_eq!(de.language, "de-DE");

        let bad = crate::media::stt_dispatch::resolve_language(Some("xx-YY"), supported);
        assert!(bad.fell_back, "unsupported locale must fall back");
        assert_eq!(bad.language, "", "fallback = provider auto-detect");
        assert_eq!(bad.fallback_from.as_deref(), Some("xx-YY"));
    }

    #[tokio::test]
    async fn transcribe_and_audit_refuses_when_required_and_no_writer() {
        // P0 proof-hardline: required_audit + no sink → refuse BEFORE transcribing.
        let audio = vec![0u8; 16];
        let err = transcribe_and_audit(&MockStt, &audio, &req("en"), None, true)
            .await
            .unwrap_err();
        assert!(err.contains("required_audit_for_cloud_media"), "got: {err}");
        // Without required-audit, a writerless call still transcribes (best-effort).
        assert!(
            transcribe_and_audit(&MockStt, &audio, &req("en"), None, false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn transcribe_and_audit_emits_metadata_only_0xcc() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("stt.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let audio = vec![0u8; 4096];
        let out = transcribe_and_audit(&MockStt, &audio, &req("en"), Some(&writer), false)
            .await
            .unwrap();
        assert_eq!(out.text, "hello there");
        drop(writer);
        let _ = join.await;

        // Decode the 0xCC frame: metadata only, NEVER the transcript text.
        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut found = false;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_STT_TRANSCRIBED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["provider"], "openai_whisper_api");
                assert_eq!(v["audio_bytes"], 4096);
                assert_eq!(v["output_chars"], 11);
                assert!(
                    !dec.payload.windows(5).any(|w| w == b"hello"),
                    "transcript text must NEVER be in the audit frame"
                );
                found = true;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert!(found, "expected a 0xCC STT_TRANSCRIBED frame");
    }
}
