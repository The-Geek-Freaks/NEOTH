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
        format!("{}/v1/audio/transcriptions", self.base_url.trim_end_matches('/'))
    }
}

/// Parse OpenAI's `verbose_json` transcription response into a
/// [`TranscriptionResult`]. PURE — the network is the caller's. The API returns
/// `start`/`end` in SECONDS (float); we convert to ms.
pub fn parse_openai_whisper(body: &[u8], req_language: &str) -> Result<TranscriptionResult, String> {
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

#[async_trait]
impl SttProviderImpl for AzureSpeechClient {
    fn kind(&self) -> SttProviderKind {
        SttProviderKind::AzureSpeech
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
            .header("Content-Type", "audio/wav; codecs=audio/pcm; samplerate=16000")
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
) -> Result<Box<dyn SttProviderImpl>, String> {
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
        assert_eq!(r.language, "de", "no language in response → request language");
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
        assert!(c.endpoint("de-DE").starts_with("https://westeurope.stt.speech.microsoft.com"));
    }

    #[test]
    fn openai_endpoint_path() {
        let c = OpenAiWhisperClient::new(SecretString::from("k"));
        assert_eq!(c.endpoint(), "https://api.openai.com/v1/audio/transcriptions");
    }

    #[test]
    fn factory_returns_right_kind_or_deferral() {
        assert_eq!(
            make_stt_provider(SttProviderKind::OpenAiWhisperApi, Some(SecretString::from("k")), None)
                .unwrap()
                .kind(),
            SttProviderKind::OpenAiWhisperApi
        );
        assert_eq!(
            make_stt_provider(
                SttProviderKind::AzureSpeech,
                Some(SecretString::from("k")),
                Some("eastus".into())
            )
            .unwrap()
            .kind(),
            SttProviderKind::AzureSpeech
        );
        assert!(make_stt_provider(SttProviderKind::OpenAiWhisperApi, None, None).is_err());
        assert!(make_stt_provider(SttProviderKind::AzureSpeech, Some(SecretString::from("k")), None).is_err());
        assert!(make_stt_provider(SttProviderKind::WhisperRsLocal, None, None).is_err());
        assert!(make_stt_provider(SttProviderKind::Vosk, None, None).is_err());
    }

    #[tokio::test]
    async fn transcribe_surfaces_error_on_unreachable_host() {
        let c = OpenAiWhisperClient::new(SecretString::from("k")).with_base_url("http://127.0.0.1:1");
        let err = c.transcribe(b"RIFF....", &req("en")).await.unwrap_err();
        assert!(err.contains("openai whisper"), "expected an openai error, got: {err}");
    }
}
