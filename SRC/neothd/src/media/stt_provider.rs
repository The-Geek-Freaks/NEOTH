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
//! the caller's hands per the NEOTH privacy model. Cloud calls emit only the
//! metadata-only `0xCC STT_TRANSCRIBED` event (provider, byte/character counts).
//!
//! ## Network-guard posture
//!
//! Both clients build their `reqwest::Client` via
//! [`crate::providers::http_client::build_client`] (inside `providers/`, already
//! allow-listed), so this file under `src/media/` carries no forbidden
//! construction token. Operator-configured cloud STT — an explicit, credentialed
//! upstream.
//!
//! The local candle and faster-whisper providers are wired alongside the two
//! explicit cloud backends. Every accepted provider has a concrete runtime.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use super::model_manager::{ArtifactKind, CacheHealth, RequiredArtifact};
use super::stt_dispatch::{
    SttProvider as SttProviderKind, TextSegment, TranscriptionRequest, TranscriptionResult,
    WhisperModelSize,
};
use crate::providers::http_client;
use crate::secret::SecretString;

/// Whether an STT failure may safely fall through to the explicitly configured
/// fallback provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SttFailureClass {
    Retryable,
    Permanent,
}

/// Failure returned by a constructed STT provider.
///
/// Classification is assigned at the typed source (HTTP status, reqwest error,
/// process state, decoder input) rather than reconstructed from display text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SttProviderError {
    #[error("retryable STT provider failure: {message}")]
    Retryable { message: String },
    #[error("permanent STT provider failure: {message}")]
    Permanent { message: String },
}

impl SttProviderError {
    fn retryable(message: impl Into<String>) -> Self {
        Self::Retryable {
            message: message.into(),
        }
    }

    fn permanent(message: impl Into<String>) -> Self {
        Self::Permanent {
            message: message.into(),
        }
    }

    pub fn class(&self) -> SttFailureClass {
        match self {
            Self::Retryable { .. } => SttFailureClass::Retryable,
            Self::Permanent { .. } => SttFailureClass::Permanent,
        }
    }
}

/// Failure while constructing an STT provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SttFactoryError {
    #[error("retryable STT provider factory failure: {message}")]
    Retryable { message: String },
    #[error("permanent STT provider factory failure: {message}")]
    Permanent { message: String },
}

impl SttFactoryError {
    fn retryable(message: impl Into<String>) -> Self {
        Self::Retryable {
            message: message.into(),
        }
    }

    fn permanent(message: impl Into<String>) -> Self {
        Self::Permanent {
            message: message.into(),
        }
    }

    pub fn class(&self) -> SttFailureClass {
        match self {
            Self::Retryable { .. } => SttFailureClass::Retryable,
            Self::Permanent { .. } => SttFailureClass::Permanent,
        }
    }
}

/// Common STT backend surface — every transcriber implements this. `audio` is a
/// COMPLETE encoded audio file (WAV/MP3 bytes) the cloud endpoints upload as-is.
#[async_trait]
pub trait SttProviderImpl: Send + Sync {
    /// The dispatcher's pinned [`SttProviderKind`] variant for this impl.
    fn kind(&self) -> SttProviderKind;

    /// Transcribe `audio` (an encoded audio file). Errors carry an
    /// typed retryability plus an operator-readable message.
    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, SttProviderError>;

    /// Languages this provider supports (IETF BCP 47 tags). Empty = accept
    /// any (auto-detect / no restriction), the default. A language-restricted
    /// backend overrides this so the dispatcher's fallback guard
    /// (GOLD-ADAPT-HANDY-06) can steer an unsupported request to a safe
    /// language instead of letting the backend fail.
    fn supported_languages(&self) -> &'static [&'static str] {
        &[]
    }

    /// The concrete model identifier this provider will run (e.g. the
    /// faster-whisper model size). `None` when the backend has no
    /// caller-selectable model. B20 — lets factory tests and status surfaces
    /// verify the configured model actually reached the provider.
    fn model_id(&self) -> Option<String> {
        None
    }
}

fn request_error(provider: &str, error: reqwest::Error) -> SttProviderError {
    let message = format!("{provider} request: {error}");
    if error.is_timeout() || error.is_connect() || error.is_body() {
        SttProviderError::retryable(message)
    } else {
        SttProviderError::permanent(message)
    }
}

fn http_status_error(provider: &str, status: reqwest::StatusCode) -> SttProviderError {
    let message = format!("{provider} returned HTTP {status}");
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        SttProviderError::retryable(message)
    } else {
        SttProviderError::permanent(message)
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
        speaker_labels: Vec::new(),
        provider: String::new(),
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
    ) -> Result<TranscriptionResult, SttProviderError> {
        let client = http_client::build_client()
            .map_err(|e| SttProviderError::permanent(format!("http client config: {e:#}")))?;
        let part = reqwest::multipart::Part::bytes(audio.to_vec())
            .file_name("audio.wav")
            .mime_str("audio/wav")
            .map_err(|e| SttProviderError::permanent(format!("multipart part: {e}")))?;
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
            .map_err(|e| request_error("openai whisper", e))?;
        if !resp.status().is_success() {
            return Err(http_status_error("openai whisper", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| request_error("openai whisper response body", e))?;
        parse_openai_whisper(&body, &request.language).map_err(SttProviderError::permanent)
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
        speaker_labels: Vec::new(),
        provider: String::new(),
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
    "ar", "bg", "ca", "zh", "hr", "cs", "da", "nl", "en", "et", "fi", "fr", "de", "el", "gu", "he",
    "hi", "hu", "id", "it", "ja", "kn", "ko", "lv", "lt", "ms", "mr", "nb", "pl", "pt", "ro", "ru",
    "sk", "sl", "es", "sv", "ta", "te", "th", "tr", "uk", "vi",
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
    ) -> Result<TranscriptionResult, SttProviderError> {
        let client = http_client::build_client()
            .map_err(|e| SttProviderError::permanent(format!("http client config: {e:#}")))?;
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
            .map_err(|e| request_error(&format!("azure speech ({})", self.region), e))?;
        if !resp.status().is_success() {
            return Err(http_status_error("azure speech", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| request_error("azure speech response body", e))?;
        parse_azure_speech(&body, &request.language).map_err(SttProviderError::permanent)
    }
}

// ── JV-VOICE-02/03: FasterWhisperProvider ───────────────────────────────────

/// JV-VOICE-02/03 — NEOTH-owned bridge to the `faster-whisper` Python module.
/// Uses
/// CTranslate2 int8 quantisation for significantly faster CPU transcription
/// compared to the candle-based path. Requires `pip install faster-whisper`.
/// A cache miss is allowed to download only after the effective
/// [`crate::config::ops::UpdaterConfig`] permits the exact repository id.
///
/// The subprocess is invoked as `<python> -c <NEOTH bridge> ...`; the bridge
/// imports `WhisperModel`, runs the exact repository id, and emits JSONL.
///
/// Output: JSONL — one JSON object per segment, each line:
///   `{"text": "...", "start": 0.0, "end": 1.2}`
#[derive(Debug)]
pub struct FasterWhisperProvider {
    /// Operator-facing size for status surfaces.
    pub model_size: String,
    model_id: String,
    python_executable: PathBuf,
    cache_root: PathBuf,
    cache_path: PathBuf,
    updater_cfg: crate::config::ops::UpdaterConfig,
    shared_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    model_download_writer: Option<crate::wal::writer::WalWriterHandle>,
}

type FasterReadyMap =
    std::collections::HashMap<(PathBuf, String), std::sync::Weak<std::sync::atomic::AtomicBool>>;

fn faster_ready_state(
    cache_root: &Path,
    model_id: &str,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    static STATES: std::sync::OnceLock<std::sync::Mutex<FasterReadyMap>> =
        std::sync::OnceLock::new();
    let states = STATES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut states = states
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    states.retain(|_, state| state.strong_count() > 0);
    let key = (cache_root.to_path_buf(), model_id.to_string());
    if let Some(state) = states.get(&key).and_then(std::sync::Weak::upgrade) {
        return state;
    }
    let state = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    states.insert(key, std::sync::Arc::downgrade(&state));
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WhisperModelSpec {
    candle_repo: &'static str,
    faster_whisper_repo: &'static str,
}

const fn whisper_model_spec(size: WhisperModelSize) -> WhisperModelSpec {
    match size {
        WhisperModelSize::Tiny => WhisperModelSpec {
            candle_repo: "openai/whisper-tiny",
            faster_whisper_repo: "Systran/faster-whisper-tiny",
        },
        WhisperModelSize::Base => WhisperModelSpec {
            candle_repo: "openai/whisper-base",
            faster_whisper_repo: "Systran/faster-whisper-base",
        },
        WhisperModelSize::Small => WhisperModelSpec {
            candle_repo: "openai/whisper-small",
            faster_whisper_repo: "Systran/faster-whisper-small",
        },
        WhisperModelSize::Medium => WhisperModelSpec {
            candle_repo: "openai/whisper-medium",
            faster_whisper_repo: "Systran/faster-whisper-medium",
        },
        WhisperModelSize::Large => WhisperModelSpec {
            candle_repo: "openai/whisper-large-v3",
            faster_whisper_repo: "Systran/faster-whisper-large-v3",
        },
    }
}

pub(crate) const fn candle_whisper_model_id(size: WhisperModelSize) -> &'static str {
    whisper_model_spec(size).candle_repo
}

pub(crate) const fn faster_whisper_model_id(size: WhisperModelSize) -> &'static str {
    whisper_model_spec(size).faster_whisper_repo
}

#[derive(Debug, Clone)]
struct SttRuntimeEnvironment {
    faster_whisper_python: Option<PathBuf>,
    faster_whisper_python_is_explicit: bool,
    faster_whisper_cache_root: PathBuf,
    faster_whisper_cache_owned_by_neoth: bool,
    candle_cache_root: PathBuf,
}

fn choose_faster_whisper_python(
    explicit: Option<PathBuf>,
    python: Option<PathBuf>,
    python3: Option<PathBuf>,
) -> (Option<PathBuf>, bool) {
    match explicit {
        Some(path) => (Some(path), true),
        None => (python.or(python3), false),
    }
}

impl SttRuntimeEnvironment {
    fn from_process() -> Self {
        Self::for_home(&crate::config::FreedomConfig::default_neoth_home())
    }

    fn for_home(neoth_home: &Path) -> Self {
        let external_faster_cache = std::env::var_os("HUGGINGFACE_HUB_CACHE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| {
                std::env::var_os("HF_HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .map(|path| path.join("hub"))
            })
            .or_else(|| {
                std::env::var_os("XDG_CACHE_HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .map(|path| path.join("huggingface").join("hub"))
            });
        let (faster_whisper_cache_root, faster_whisper_cache_owned_by_neoth) =
            match external_faster_cache {
                Some(path) => (path, false),
                None => (
                    neoth_home.join("cache").join("huggingface").join("hub"),
                    true,
                ),
            };
        let explicit_python = std::env::var_os("NEOTH_FASTER_WHISPER_PYTHON")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let (faster_whisper_python, faster_whisper_python_is_explicit) =
            choose_faster_whisper_python(
                explicit_python,
                crate::media::tts_provider::find_on_path("python"),
                crate::media::tts_provider::find_on_path("python3"),
            );
        Self {
            faster_whisper_python,
            faster_whisper_python_is_explicit,
            faster_whisper_cache_root,
            faster_whisper_cache_owned_by_neoth,
            candle_cache_root: neoth_home.join("models"),
        }
    }
}

fn huggingface_repo_cache_dir(cache_root: &Path, model_id: &str) -> PathBuf {
    cache_root.join(format!("models--{}", model_id.replace('/', "--")))
}

#[derive(Clone, Copy)]
struct FasterWhisperArtifactManifest {
    revision: &'static str,
    artifacts: [RequiredArtifact; 3],
}

const fn faster_artifact_manifest(
    revision: &'static str,
    model_len: u64,
    model_sha256: &'static str,
    config_len: u64,
    config_sha256: &'static str,
    tokenizer_len: u64,
    tokenizer_sha256: &'static str,
) -> FasterWhisperArtifactManifest {
    use super::model_manager::ExpectedArtifactFingerprint;
    FasterWhisperArtifactManifest {
        revision,
        artifacts: [
            RequiredArtifact {
                filename: "model.bin",
                kind: ArtifactKind::NonEmpty { minimum_bytes: 16 },
                expected: Some(ExpectedArtifactFingerprint {
                    len: model_len,
                    sha256: model_sha256,
                }),
            },
            RequiredArtifact {
                filename: "config.json",
                kind: ArtifactKind::JsonObject,
                expected: Some(ExpectedArtifactFingerprint {
                    len: config_len,
                    sha256: config_sha256,
                }),
            },
            RequiredArtifact {
                filename: "tokenizer.json",
                kind: ArtifactKind::JsonObject,
                expected: Some(ExpectedArtifactFingerprint {
                    len: tokenizer_len,
                    sha256: tokenizer_sha256,
                }),
            },
        ],
    }
}

fn faster_whisper_artifact_manifest(model_id: &str) -> Option<FasterWhisperArtifactManifest> {
    Some(match model_id {
        "Systran/faster-whisper-tiny" => faster_artifact_manifest(
            "d90ca5fe260221311c53c58e660288d3deb8d356",
            75_538_270,
            "dcb76c6586fc06cbdac6dd21f14cfd129cc4cdd9dce19bf4ffa62e59cbe6e6d1",
            2_249,
            "a73a28cdfe1c43ccc7202fa333d1f89c202477271407ae9a7f19afa52039cac8",
            2_203_239,
            "fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab",
        ),
        "Systran/faster-whisper-base" => faster_artifact_manifest(
            "ebe41f70d5b6dfa9166e2c581c45c9c0cfc57b66",
            145_217_532,
            "d01c3014881c9c6f3133c182f3d2887eb6ca1c789a7538c5c007196857a0a6a9",
            2_309,
            "56a6d8110d311f19c8f0471e562832c7527f146b567275bfca59fcf7c184da9a",
            2_203_239,
            "fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab",
        ),
        "Systran/faster-whisper-small" => faster_artifact_manifest(
            "536b0662742c02347bc0e980a01041f333bce120",
            483_546_902,
            "3e305921506d8872816023e4c273e75d2419fb89b24da97b4fe7bce14170d671",
            2_370,
            "b55496ac7940a7ae47d2c01eab40edfd8701feec1229d9cce3b40014383fb828",
            2_203_239,
            "fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab",
        ),
        "Systran/faster-whisper-medium" => faster_artifact_manifest(
            "08e178d48790749d25932bbc082711ddcfdfbc4f",
            1_527_906_378,
            "9b45e1009dcc4ab601eff815b61d80e60ce3fd8c74c1a14f4a282258286b51ae",
            2_257,
            "3622a2ddc41ec0e0fd4e68c13c6830f03b90c38d89aaad184de02c8c642cf807",
            2_203_239,
            "fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab",
        ),
        "Systran/faster-whisper-large-v3" => faster_artifact_manifest(
            "edaa852ec7e145841d8ffdb056a99866b5f0a478",
            3_087_284_237,
            "69f74147e3334731bc3a76048724833325d2ec74642fb52620eda87352e3d4f1",
            2_394,
            "a9306624f5ec14270a014b647e5c316b6e03a662c369758d1b90697a7b0655b9",
            2_480_617,
            "6d8cbd7cd0d8d5815e478dac67b85a26bbe77c1f5e0c6d76d1ce2abc0e5f21ca",
        ),
        _ => return None,
    })
}

fn faster_whisper_snapshot(cache_root: &Path, model_id: &str) -> Result<PathBuf, CacheHealth> {
    let repo_cache = huggingface_repo_cache_dir(cache_root, model_id);
    let Some(manifest) = faster_whisper_artifact_manifest(model_id) else {
        return Err(CacheHealth::Corrupt {
            path: repo_cache,
            reason: format!(
                "unsupported faster-whisper repository `{model_id}` has no reviewed manifest"
            ),
        });
    };
    if !repo_cache.is_dir() {
        return Err(CacheHealth::Missing { path: repo_cache });
    }
    Ok(repo_cache.join("snapshots").join(manifest.revision))
}

fn faster_whisper_cache_health(cache_root: &Path, model_id: &str) -> CacheHealth {
    let repo_cache = huggingface_repo_cache_dir(cache_root, model_id);
    let lifecycle = super::model_manager::cache_health(&repo_cache, &[]);
    if !lifecycle.is_ready() {
        return lifecycle;
    }
    let snapshot = match faster_whisper_snapshot(cache_root, model_id) {
        Ok(snapshot) => snapshot,
        Err(health) => return health,
    };
    let Some(manifest) = faster_whisper_artifact_manifest(model_id) else {
        return CacheHealth::Corrupt {
            path: snapshot,
            reason: "faster-whisper artifact manifest disappeared".to_string(),
        };
    };
    super::model_manager::cache_health(&snapshot, &manifest.artifacts)
}

fn verified_faster_whisper_cache_health(cache_root: &Path, model_id: &str) -> CacheHealth {
    verified_faster_whisper_cache_health_for_attempt(cache_root, model_id, false)
}

fn verified_faster_whisper_cache_health_for_attempt(
    cache_root: &Path,
    model_id: &str,
    during_attempt: bool,
) -> CacheHealth {
    let repo_cache = huggingface_repo_cache_dir(cache_root, model_id);
    let lifecycle = if during_attempt {
        super::model_manager::cache_health_during_install(&repo_cache, &[])
    } else {
        super::model_manager::cache_health(&repo_cache, &[])
    };
    if !lifecycle.is_ready() {
        return lifecycle;
    }
    let snapshot = match faster_whisper_snapshot(cache_root, model_id) {
        Ok(snapshot) => snapshot,
        Err(health) => return health,
    };
    let Some(manifest) = faster_whisper_artifact_manifest(model_id) else {
        return CacheHealth::Corrupt {
            path: snapshot,
            reason: "faster-whisper artifact manifest disappeared".to_string(),
        };
    };
    if during_attempt {
        super::model_manager::verified_cache_health_during_install(&snapshot, &manifest.artifacts)
    } else {
        super::model_manager::verified_cache_health(&snapshot, &manifest.artifacts)
    }
}

fn candle_cache_dir(cache_root: &Path, model_id: &str) -> PathBuf {
    crate::providers::whisper::cache_dir_at(cache_root, model_id)
}

fn candle_cache_health(cache_root: &Path, model_id: &str) -> CacheHealth {
    crate::providers::whisper::cache_health_at(cache_root, model_id)
}

/// Exact local Whisper model selected against the same process environment as
/// the runtime provider factory. The Python interpreter details remain private;
/// model-management callers only receive the stable backend/repository/cache
/// facts they need for list, pull, prune, and hardware status.
#[derive(Clone)]
pub(crate) struct LocalWhisperTarget {
    backend: SttProviderKind,
    model_id: String,
    cache_path: PathBuf,
    runtime: SttRuntimeEnvironment,
}

impl std::fmt::Debug for LocalWhisperTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalWhisperTarget")
            .field("backend", &self.backend)
            .field("model_id", &self.model_id)
            .field("cache_path", &self.cache_path)
            .field("cache_health", &self.cache_health())
            .finish()
    }
}

impl LocalWhisperTarget {
    pub(crate) fn backend(&self) -> SttProviderKind {
        self.backend
    }

    pub(crate) fn model_id(&self) -> &str {
        &self.model_id
    }

    pub(crate) fn cache_path(&self) -> &Path {
        &self.cache_path
    }

    /// Re-check the exact runtime cache so a successful pull is immediately
    /// visible without resolving a second target.
    pub(crate) fn cached(&self) -> bool {
        self.cache_health().is_ready()
    }

    pub(crate) fn cache_health(&self) -> CacheHealth {
        match self.backend {
            SttProviderKind::WhisperRsLocal => {
                candle_cache_health(&self.runtime.candle_cache_root, &self.model_id)
            }
            SttProviderKind::FasterWhisperLocal => {
                faster_whisper_cache_health(&self.runtime.faster_whisper_cache_root, &self.model_id)
            }
            SttProviderKind::OpenAiWhisperApi | SttProviderKind::AzureSpeech => {
                CacheHealth::Corrupt {
                    path: self.cache_path.clone(),
                    reason: format!("backend `{}` has no local cache", self.backend.as_str()),
                }
            }
        }
    }

    pub(crate) fn verified_cache_health(&self, during_attempt: bool) -> CacheHealth {
        match self.backend {
            SttProviderKind::WhisperRsLocal => crate::providers::whisper::verified_cache_health_at(
                &self.runtime.candle_cache_root,
                &self.model_id,
                during_attempt,
            ),
            SttProviderKind::FasterWhisperLocal => {
                verified_faster_whisper_cache_health_for_attempt(
                    &self.runtime.faster_whisper_cache_root,
                    &self.model_id,
                    during_attempt,
                )
            }
            SttProviderKind::OpenAiWhisperApi | SttProviderKind::AzureSpeech => self.cache_health(),
        }
    }

    pub(crate) fn cache_is_neoth_owned(&self) -> bool {
        match self.backend {
            SttProviderKind::WhisperRsLocal => true,
            SttProviderKind::FasterWhisperLocal => self.runtime.faster_whisper_cache_owned_by_neoth,
            _ => false,
        }
    }
}

/// Resolve the exact model repository and cache directory used by a local STT
/// backend. Cloud providers have no managed local Whisper cache and
/// are rejected instead of silently pointing model management at Candle.
pub(crate) fn resolve_local_whisper_target(
    neoth_home: &Path,
    backend: SttProviderKind,
    size: WhisperModelSize,
) -> Result<LocalWhisperTarget, SttFactoryError> {
    resolve_local_whisper_target_with_runtime(
        backend,
        size,
        SttRuntimeEnvironment::for_home(neoth_home),
    )
}

fn resolve_local_whisper_target_with_runtime(
    backend: SttProviderKind,
    size: WhisperModelSize,
    runtime: SttRuntimeEnvironment,
) -> Result<LocalWhisperTarget, SttFactoryError> {
    let (model_id, cache_path) = match backend {
        SttProviderKind::WhisperRsLocal => {
            let model_id = candle_whisper_model_id(size);
            (
                model_id,
                candle_cache_dir(&runtime.candle_cache_root, model_id),
            )
        }
        SttProviderKind::FasterWhisperLocal => {
            let model_id = faster_whisper_model_id(size);
            (
                model_id,
                huggingface_repo_cache_dir(&runtime.faster_whisper_cache_root, model_id),
            )
        }
        SttProviderKind::OpenAiWhisperApi | SttProviderKind::AzureSpeech => {
            return Err(SttFactoryError::permanent(format!(
                "STT backend `{}` has no managed local Whisper model; configure \
                 `media.stt.primary` as `whisper_rs_local` or `faster_whisper_local`, \
                 or choose an explicit local model-management backend",
                backend.as_str()
            )));
        }
    };
    Ok(LocalWhisperTarget {
        backend,
        model_id: model_id.to_string(),
        cache_path,
        runtime,
    })
}

#[cfg(test)]
async fn append_model_download_event(
    writer: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    model_id: &str,
    complete: Option<(&Path, u64)>,
) -> Result<(), String> {
    let ts_unix = crate::time::now_unix_secs();
    let payload = match complete {
        None => serde_json::to_vec(&serde_json::json!({
            "model_id": model_id,
            "status": "started",
            "ts_unix": ts_unix,
            "trigger": "implicit",
        })),
        Some((cached_path, duration_ms)) => serde_json::to_vec(&serde_json::json!({
            "model_id": model_id,
            "cached_path": cached_path.to_string_lossy(),
            "duration_ms": duration_ms,
            "status": "ready",
            "ts_unix": ts_unix,
            "trigger": "implicit",
        })),
    }
    .map_err(|error| format!("serialize model-download audit event: {error}"))?;
    let header = crate::wal::make_header(event_type, &payload);
    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| format!("append model-download audit event: {error}"))
}

#[cfg(test)]
async fn append_model_download_failure(
    writer: &crate::wal::writer::WalWriterHandle,
    model_id: &str,
    duration_ms: u64,
    reason: &str,
) -> Result<(), String> {
    let reason: String = reason.chars().take(512).collect();
    let payload = serde_json::to_vec(&serde_json::json!({
        "model_id": model_id,
        "duration_ms": duration_ms,
        "reason": reason,
        "status": "failed",
        "ts_unix": crate::time::now_unix_secs(),
        "trigger": "implicit",
    }))
    .map_err(|error| format!("serialize model-download failure audit event: {error}"))?;
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
        &payload,
    );
    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| format!("append model-download failure audit event: {error}"))
}

fn require_model_download_writer(
    download_required: bool,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<(), SttFactoryError> {
    if download_required && writer.is_none() {
        return Err(SttFactoryError::permanent(
            "model download requires the caller WAL writer for D7/D8 proof; refusing network",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandleProviderPlan {
    model_id: &'static str,
    cache_path: PathBuf,
    idle_unload_secs: Option<u64>,
}

/// Process-lifetime owner key for a local Candle Whisper engine.
///
/// The owner deliberately keeps the lightweight engine shell alive after an
/// individual transcription provider is dropped. `WhisperEngine` itself owns
/// the idle watcher, which unloads only the heavyweight model slot after the
/// configured timeout. Keying every residency-affecting input prevents a
/// config reload from accidentally reusing an engine with the old model root,
/// repository, or idle policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CandleEngineKey {
    cache_root: PathBuf,
    model_id: String,
    idle_unload_secs: Option<u64>,
}

impl CandleEngineKey {
    fn new(cache_root: &Path, model_id: &str, idle_unload_secs: Option<u64>) -> Self {
        Self {
            cache_root: cache_root.to_path_buf(),
            model_id: model_id.to_string(),
            idle_unload_secs,
        }
    }
}

type CandleEngineMap = std::collections::HashMap<
    CandleEngineKey,
    std::sync::Arc<crate::providers::whisper::WhisperEngine>,
>;

/// Serialises first construction so concurrent first-use calls cannot perform
/// duplicate health checks/downloads for the same engine generation.
static CANDLE_PROVIDER_BUILD: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

/// Strong process-lifetime owners. Providers only borrow an `Arc`; dropping a
/// per-call provider therefore does not cancel the engine's idle watcher.
static CANDLE_ENGINES: std::sync::OnceLock<std::sync::Mutex<CandleEngineMap>> =
    std::sync::OnceLock::new();

fn candle_engines() -> &'static std::sync::Mutex<CandleEngineMap> {
    CANDLE_ENGINES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn plan_candle_provider(
    media_cfg: &crate::config::MediaConfig,
    runtime: &SttRuntimeEnvironment,
) -> CandleProviderPlan {
    let model_id = candle_whisper_model_id(media_cfg.stt.model_size);
    let cache_path = candle_cache_dir(&runtime.candle_cache_root, model_id);
    CandleProviderPlan {
        model_id,
        cache_path,
        idle_unload_secs: media_cfg.whisper_idle_unload_secs,
    }
}

fn plan_faster_whisper_provider(
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    runtime: &SttRuntimeEnvironment,
) -> Result<FasterWhisperProvider, SttFactoryError> {
    let model_id = faster_whisper_model_id(media_cfg.stt.model_size);
    let python_executable = runtime.faster_whisper_python.clone().ok_or_else(|| {
        SttFactoryError::retryable(
            "Python is unavailable; install Python and the `faster-whisper` package",
        )
    })?;
    Ok(FasterWhisperProvider {
        model_size: media_cfg.stt.model_size.as_str().to_string(),
        model_id: model_id.to_string(),
        python_executable,
        cache_root: runtime.faster_whisper_cache_root.clone(),
        cache_path: huggingface_repo_cache_dir(&runtime.faster_whisper_cache_root, model_id),
        updater_cfg: updater_cfg.clone(),
        shared_ready: faster_ready_state(&runtime.faster_whisper_cache_root, model_id),
        model_download_writer: None,
    })
}

/// Compatibility status probe used by the dictation surface.
///
/// The official package has no `faster-whisper` console executable. This now
/// returns the configured/discovered Python interpreter candidate; the
/// canonical async factory additionally verifies `import faster_whisper` before
/// accepting the provider.
pub fn faster_whisper_exe() -> Option<PathBuf> {
    SttRuntimeEnvironment::from_process().faster_whisper_python
}

#[async_trait]
trait FasterWhisperPythonProbe: Send + Sync {
    async fn verify(
        &self,
        python: &Path,
        explicitly_configured: bool,
    ) -> Result<(), SttFactoryError>;
}

struct ProcessFasterWhisperPythonProbe;

#[async_trait]
impl FasterWhisperPythonProbe for ProcessFasterWhisperPythonProbe {
    async fn verify(
        &self,
        python: &Path,
        explicitly_configured: bool,
    ) -> Result<(), SttFactoryError> {
        static VERIFIED_PYTHONS: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashSet<PathBuf>>,
        > = std::sync::OnceLock::new();
        let verified = VERIFIED_PYTHONS
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
        if verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(python)
        {
            return Ok(());
        }
        let mut command = tokio::process::Command::new(python);
        command
            .args(["-c", "import faster_whisper"])
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("HF_DATASETS_OFFLINE", "1")
            .env("PYTHONIOENCODING", "utf-8")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(std::time::Duration::from_secs(15), command.output())
            .await
            .map_err(|_| {
                SttFactoryError::retryable(format!(
                    "Python import probe timed out for `{}`",
                    python.display()
                ))
            })?
            .map_err(|error| {
                let message = format!(
                    "cannot start Python interpreter `{}`: {error}",
                    python.display()
                );
                if explicitly_configured {
                    SttFactoryError::permanent(format!(
                        "NEOTH_FASTER_WHISPER_PYTHON is invalid: {message}"
                    ))
                } else {
                    SttFactoryError::retryable(message)
                }
            })?;
        if output.status.success() {
            verified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(python.to_path_buf());
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(SttFactoryError::retryable(format!(
            "Python `{}` cannot import faster_whisper: {}",
            python.display(),
            stderr.trim()
        )))
    }
}

/// NEOTH-owned bridge for the official `faster-whisper` Python package.
/// stdout is deliberately JSONL so the Rust parser remains the only wire
/// decoder. `local_files_only` is passed explicitly and reinforced with child
/// offline environment variables on cache hits.
const FASTER_WHISPER_PYTHON_BRIDGE: &str = r#"
import json
import sys

from faster_whisper import WhisperModel
from huggingface_hub import snapshot_download

mode, model_id, revision, audio_path, language, local_only, cache_root = sys.argv[1:8]
snapshot = snapshot_download(
    repo_id=model_id,
    revision=revision,
    cache_dir=cache_root,
    local_files_only=(local_only == "1"),
)
model = WhisperModel(
    snapshot,
    device="cpu",
    compute_type="int8",
    local_files_only=True,
)
if mode == "prefetch":
    sys.exit(0)
if mode != "transcribe":
    raise ValueError(f"unsupported NEOTH faster-whisper bridge mode: {mode}")
kwargs = {}
if language != "auto":
    kwargs["language"] = language
segments, _ = model.transcribe(audio_path, **kwargs)
for segment in segments:
    print(json.dumps({
        "text": segment.text,
        "start": segment.start,
        "end": segment.end,
    }, ensure_ascii=False), flush=True)
"#;

#[derive(Debug, Clone, Copy)]
enum FasterWhisperBridgeMode<'a> {
    Transcribe {
        audio_path: &'a Path,
        language: &'a str,
    },
    Prefetch,
}

#[derive(Debug)]
struct FasterWhisperBridgeFailure {
    class: SttFailureClass,
    message: String,
}

fn faster_whisper_bridge_command(
    python: &Path,
    model_id: &str,
    revision: &str,
    cache_root: &Path,
    mode: FasterWhisperBridgeMode<'_>,
    offline: bool,
) -> tokio::process::Command {
    let (mode_name, audio_path, language) = match mode {
        FasterWhisperBridgeMode::Transcribe {
            audio_path,
            language,
        } => ("transcribe", audio_path, language),
        FasterWhisperBridgeMode::Prefetch => ("prefetch", Path::new(""), "auto"),
    };
    let mut command = tokio::process::Command::new(python);
    command
        .args(["-c", FASTER_WHISPER_PYTHON_BRIDGE])
        .arg(mode_name)
        .arg(model_id)
        .arg(revision)
        .arg(audio_path)
        .arg(language)
        .arg(if offline { "1" } else { "0" })
        .arg(cache_root)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUTF8", "1")
        .env("HUGGINGFACE_HUB_CACHE", cache_root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    if offline {
        command
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("HF_DATASETS_OFFLINE", "1");
    }
    command
}

async fn run_faster_whisper_bridge(
    python: &Path,
    model_id: &str,
    cache_root: &Path,
    mode: FasterWhisperBridgeMode<'_>,
    offline: bool,
) -> Result<std::process::Output, FasterWhisperBridgeFailure> {
    let revision = faster_whisper_artifact_manifest(model_id)
        .map(|manifest| manifest.revision)
        .ok_or_else(|| FasterWhisperBridgeFailure {
            class: SttFailureClass::Permanent,
            message: format!(
                "unsupported faster-whisper repository `{model_id}` has no reviewed manifest"
            ),
        })?;
    let mut command =
        faster_whisper_bridge_command(python, model_id, revision, cache_root, mode, offline);
    let output = tokio::time::timeout(std::time::Duration::from_secs(600), command.output())
        .await
        .map_err(|_| FasterWhisperBridgeFailure {
            class: SttFailureClass::Retryable,
            message: "faster-whisper process timed out".to_string(),
        })?
        .map_err(|error| FasterWhisperBridgeFailure {
            class: SttFailureClass::Retryable,
            message: format!("faster-whisper spawn: {error}"),
        })?;
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(FasterWhisperBridgeFailure {
        class: if output.status.code() == Some(2) {
            SttFailureClass::Permanent
        } else {
            SttFailureClass::Retryable
        },
        message: format!(
            "faster-whisper exited {:?}: {}",
            output.status,
            stderr.trim()
        ),
    })
}

#[async_trait]
trait LocalWhisperPrefetchExecutor: Send + Sync {
    async fn prefetch(
        &self,
        target: &LocalWhisperTarget,
        attempt: Option<&super::model_manager::ModelDownloadAttempt>,
    ) -> Result<(), SttFactoryError>;
}

struct RuntimeLocalWhisperPrefetchExecutor;

#[async_trait]
impl LocalWhisperPrefetchExecutor for RuntimeLocalWhisperPrefetchExecutor {
    async fn prefetch(
        &self,
        target: &LocalWhisperTarget,
        attempt: Option<&super::model_manager::ModelDownloadAttempt>,
    ) -> Result<(), SttFactoryError> {
        match target.backend {
            SttProviderKind::WhisperRsLocal => {
                let engine_result = match attempt {
                    Some(attempt) => {
                        crate::providers::whisper::WhisperEngine::new_for_download_attempt(
                            Some(target.model_id.clone()),
                            Some(0),
                            &target.runtime.candle_cache_root,
                            attempt,
                        )
                        .await
                    }
                    None => {
                        crate::providers::whisper::WhisperEngine::new_with_models_root(
                            Some(target.model_id.clone()),
                            Some(0),
                            &target.runtime.candle_cache_root,
                        )
                        .await
                    }
                };
                let engine = engine_result.map_err(|error| {
                    SttFactoryError::retryable(format!(
                        "Candle Whisper model `{}` could not be prefetched: {error:#}",
                        target.model_id
                    ))
                })?;
                engine.validate_load().await.map_err(|error| {
                    SttFactoryError::retryable(format!(
                        "Candle Whisper model `{}` failed backend validation: {error:#}",
                        target.model_id
                    ))
                })?;
                Ok(())
            }
            SttProviderKind::FasterWhisperLocal => {
                let python = target
                    .runtime
                    .faster_whisper_python
                    .as_deref()
                    .ok_or_else(|| {
                        SttFactoryError::retryable(
                            "Python is unavailable; install Python and the `faster-whisper` package",
                        )
                    })?;
                ProcessFasterWhisperPythonProbe
                    .verify(python, target.runtime.faster_whisper_python_is_explicit)
                    .await?;
                let already_verified = target.verified_cache_health(attempt.is_some()).is_ready();
                let allow_network = !already_verified
                    && attempt.is_some_and(|attempt| {
                        attempt.network_authorized(&target.cache_path, &target.model_id)
                    });
                if !allow_network && !already_verified {
                    return Err(SttFactoryError::permanent(format!(
                        "faster-whisper cache `{}` is not verified and no confirmed D7 attempt authorises network",
                        target.cache_path.display()
                    )));
                }
                run_faster_whisper_bridge(
                    python,
                    &target.model_id,
                    &target.runtime.faster_whisper_cache_root,
                    FasterWhisperBridgeMode::Prefetch,
                    !allow_network,
                )
                .await
                .map_err(|failure| match failure.class {
                    SttFailureClass::Retryable => SttFactoryError::retryable(failure.message),
                    SttFailureClass::Permanent => SttFactoryError::permanent(failure.message),
                })?;
                let cache_root = target.runtime.faster_whisper_cache_root.clone();
                let model_id = target.model_id.clone();
                let health = if attempt.is_some() {
                    tokio::task::spawn_blocking(move || {
                        verified_faster_whisper_cache_health_for_attempt(
                            &cache_root,
                            &model_id,
                            true,
                        )
                    })
                    .await
                    .map_err(|error| {
                        SttFactoryError::retryable(format!(
                            "join faster-whisper SHA-256 validation: {error}"
                        ))
                    })?
                } else {
                    verified_faster_whisper_cache_health(&cache_root, &model_id)
                };
                if !health.is_ready() {
                    return Err(SttFactoryError::permanent(format!(
                        "faster-whisper model `{}` failed post-load integrity validation: {health}",
                        target.model_id
                    )));
                }
                Ok(())
            }
            SttProviderKind::OpenAiWhisperApi | SttProviderKind::AzureSpeech => {
                Err(SttFactoryError::permanent(format!(
                    "STT backend `{}` is not a prefetchable local Whisper backend",
                    target.backend.as_str()
                )))
            }
        }
    }
}

/// Prefetch a resolved local Whisper target through the canonical runtime
/// loader. The exact repository policy is checked immediately before any
/// network-capable loader starts. Callers own the surrounding D7/D8 audit
/// lifecycle so CLI-local and daemon-forwarded audit paths remain unified.
pub(crate) async fn prefetch_local_whisper(
    target: &LocalWhisperTarget,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    attempt: Option<&super::model_manager::ModelDownloadAttempt>,
) -> Result<(), SttFactoryError> {
    prefetch_local_whisper_with(
        target,
        updater_cfg,
        attempt,
        &RuntimeLocalWhisperPrefetchExecutor,
    )
    .await
}

async fn prefetch_local_whisper_with(
    target: &LocalWhisperTarget,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    attempt: Option<&super::model_manager::ModelDownloadAttempt>,
    executor: &dyn LocalWhisperPrefetchExecutor,
) -> Result<(), SttFactoryError> {
    let network_needed = !target.verified_cache_health(attempt.is_some()).is_ready();
    if network_needed {
        updater_cfg
            .check_model_download(&target.model_id, Some("whisper"))
            .map_err(SttFactoryError::permanent)?;
        let authorised = attempt.is_some_and(|attempt| {
            attempt.network_authorized(&target.cache_path, &target.model_id)
        });
        if !authorised {
            return Err(SttFactoryError::permanent(
                "local Whisper download requires a confirmed durable D7 attempt",
            ));
        }
    }
    executor.prefetch(target, attempt).await?;
    let health = target.verified_cache_health(attempt.is_some());
    if health.is_ready() {
        Ok(())
    } else {
        Err(SttFactoryError::permanent(format!(
            "local Whisper prefetch for `{}` completed without a ready cache at `{}`: {health}",
            target.model_id,
            target.cache_path.display()
        )))
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PcmEncodingError {
    #[error("raw f32 PCM byte length {len} is not divisible by 4")]
    MisalignedF32Bytes { len: usize },
    #[error("raw s16 PCM byte length {len} is not divisible by 2")]
    MisalignedS16Bytes { len: usize },
    #[error("PCM sample at index {index} is not finite")]
    NonFiniteSample { index: usize },
    #[error("invalid PCM sample rate {0} Hz")]
    InvalidSampleRate(u32),
    #[error("PCM payload is too large for a RIFF/WAVE data chunk")]
    PayloadTooLarge,
}

fn pcm_s16le_bytes_to_wav(pcm_s16le: &[u8], sample_rate: u32) -> Result<Vec<u8>, PcmEncodingError> {
    if !(crate::media::resampler::MIN_SAMPLE_RATE_HZ..=crate::media::resampler::MAX_SAMPLE_RATE_HZ)
        .contains(&sample_rate)
    {
        return Err(PcmEncodingError::InvalidSampleRate(sample_rate));
    }
    if pcm_s16le.len() % 2 != 0 {
        return Err(PcmEncodingError::MisalignedS16Bytes {
            len: pcm_s16le.len(),
        });
    }
    let data_len = u32::try_from(pcm_s16le.len()).map_err(|_| PcmEncodingError::PayloadTooLarge)?;
    let channels: u16 = 1;
    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate
        .checked_mul(channels as u32)
        .and_then(|rate| rate.checked_mul((bits_per_sample / 8) as u32))
        .ok_or(PcmEncodingError::InvalidSampleRate(sample_rate))?;
    let block_align = channels * (bits_per_sample / 8);
    let chunk_size = 36u32
        .checked_add(data_len)
        .ok_or(PcmEncodingError::PayloadTooLarge)?;
    let mut wav = Vec::with_capacity(44 + data_len as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&chunk_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&channels.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&bits_per_sample.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(pcm_s16le);
    Ok(wav)
}

/// Convert mono f32 PCM into a minimal 16 kHz mono PCM16 WAV container.
pub fn pcm_f32_to_wav(samples: &[f32]) -> Result<Vec<u8>, PcmEncodingError> {
    if let Some(index) = samples.iter().position(|sample| !sample.is_finite()) {
        return Err(PcmEncodingError::NonFiniteSample { index });
    }
    let byte_capacity = samples
        .len()
        .checked_mul(2)
        .ok_or(PcmEncodingError::PayloadTooLarge)?;
    if byte_capacity > u32::MAX as usize {
        return Err(PcmEncodingError::PayloadTooLarge);
    }
    let mut pcm_s16le = Vec::with_capacity(byte_capacity);
    for sample in samples {
        let encoded = (sample.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
        pcm_s16le.extend_from_slice(&encoded.to_le_bytes());
    }
    pcm_s16le_bytes_to_wav(&pcm_s16le, crate::media::audio::TARGET_SAMPLE_RATE)
}

/// Convert raw little-endian f32 mono 16 kHz PCM bytes into WAV.
///
/// Kept for the low-level faster-whisper compatibility seam. New callers
/// should pass typed samples to [`pcm_f32_to_wav`] or [`dispatch_pcm_f32`].
pub fn pcm_bytes_to_wav(audio_bytes: &[u8]) -> Result<Vec<u8>, PcmEncodingError> {
    if audio_bytes.len() % 4 != 0 {
        return Err(PcmEncodingError::MisalignedF32Bytes {
            len: audio_bytes.len(),
        });
    }
    let samples: Vec<f32> = audio_bytes
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();
    pcm_f32_to_wav(&samples)
}

/// Parse faster-whisper's JSONL stdout. Each line is one segment:
///   `{"text": "hello", "start": 0.0, "end": 1.2}`
/// Returns (full_text, segments).
pub fn parse_faster_whisper_output(stdout: &[u8]) -> (String, Vec<TextSegment>) {
    let mut segments = Vec::new();
    for line in stdout.split(|&b| b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let text = v
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let start_ms =
            (v.get("start").and_then(|x| x.as_f64()).unwrap_or(0.0) * 1000.0).max(0.0) as u32;
        let end_ms =
            (v.get("end").and_then(|x| x.as_f64()).unwrap_or(0.0) * 1000.0).max(0.0) as u32;
        segments.push(TextSegment {
            start_ms,
            end_ms,
            text,
        });
    }
    let full = segments
        .iter()
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    (full.trim().to_string(), segments)
}

impl FasterWhisperProvider {
    async fn ensure_model_ready(&self) -> Result<(), SttProviderError> {
        use std::sync::atomic::Ordering;

        if self.shared_ready.load(Ordering::Acquire)
            && faster_whisper_cache_health(&self.cache_root, &self.model_id).is_ready()
        {
            return Ok(());
        }

        let mut attempt = super::model_manager::ModelDownloadAttempt::acquire(
            &self.cache_path,
            &self.model_id,
            "implicit",
        )
        .await
        .map_err(|error| {
            SttProviderError::retryable(format!(
                "faster-whisper: acquire model lifecycle: {error:#}"
            ))
        })?;

        if let Some(super::model_manager::PendingModelDownloadOutcome::Failed { .. }) =
            attempt.pending_outcome()
        {
            let writer = self.model_download_writer.as_ref().ok_or_else(|| {
                SttProviderError::permanent(
                    "pending model download requires the caller WAL writer for D8 recovery",
                )
            })?;
            attempt.replay_terminal(writer).await.map_err(|error| {
                SttProviderError::permanent(format!("faster-whisper: replay failed D8: {error:#}"))
            })?;
        }

        let during_attempt = attempt.is_pending();
        let cache_root = self.cache_root.clone();
        let model_id = self.model_id.clone();
        let health = tokio::task::spawn_blocking(move || {
            verified_faster_whisper_cache_health_for_attempt(&cache_root, &model_id, during_attempt)
        })
        .await
        .map_err(|error| {
            SttProviderError::retryable(format!("join faster-whisper SHA-256 validation: {error}"))
        })?;

        if health.is_ready() && !attempt.is_pending() {
            self.shared_ready.store(true, Ordering::Release);
            return Ok(());
        }

        let writer = self.model_download_writer.as_ref().ok_or_else(|| {
            SttProviderError::permanent(
                "model download or D8 recovery requires the caller WAL writer; refusing network",
            )
        })?;

        if attempt.is_pending()
            && attempt.pending_outcome().is_none()
            && !attempt.network_authorized(&self.cache_path, &self.model_id)
        {
            attempt.ensure_started(writer).await.map_err(|error| {
                SttProviderError::permanent(format!(
                    "faster-whisper: recover pending D7: {error:#}"
                ))
            })?;
        }

        if matches!(
            attempt.pending_outcome(),
            Some(super::model_manager::PendingModelDownloadOutcome::Ready)
        ) || health.is_ready()
        {
            let validation = run_faster_whisper_bridge(
                &self.python_executable,
                &self.model_id,
                &self.cache_root,
                FasterWhisperBridgeMode::Prefetch,
                true,
            )
            .await;
            if let Err(failure) = validation {
                let terminal = attempt.finish_failed(writer, &failure.message).await;
                return Err(match terminal {
                    Ok(()) => match failure.class {
                        SttFailureClass::Retryable => SttProviderError::retryable(failure.message),
                        SttFailureClass::Permanent => SttProviderError::permanent(failure.message),
                    },
                    Err(audit_error) => SttProviderError::permanent(format!(
                        "{}; terminal D8 failed: {audit_error:#}",
                        failure.message
                    )),
                });
            }
            attempt
                .finish_ready(writer, &self.cache_path)
                .await
                .map_err(|error| {
                    SttProviderError::permanent(format!("faster-whisper: emit ready D8: {error:#}"))
                })?;
            self.shared_ready.store(true, Ordering::Release);
            return Ok(());
        }

        if let Err(policy_error) = self
            .updater_cfg
            .check_model_download(&self.model_id, Some("whisper"))
        {
            let message = policy_error.to_string();
            if attempt.is_pending() {
                attempt
                    .finish_failed(writer, &message)
                    .await
                    .map_err(|audit_error| {
                        SttProviderError::permanent(format!(
                            "{message}; terminal D8 failed: {audit_error:#}"
                        ))
                    })?;
            }
            return Err(SttProviderError::permanent(message));
        }
        attempt.ensure_started(writer).await.map_err(|error| {
            SttProviderError::permanent(format!(
                "faster-whisper: emit D7 before network: {error:#}"
            ))
        })?;

        let prefetch = run_faster_whisper_bridge(
            &self.python_executable,
            &self.model_id,
            &self.cache_root,
            FasterWhisperBridgeMode::Prefetch,
            false,
        )
        .await;
        if let Err(failure) = prefetch {
            let terminal = attempt.finish_failed(writer, &failure.message).await;
            return Err(match terminal {
                Ok(()) => match failure.class {
                    SttFailureClass::Retryable => SttProviderError::retryable(failure.message),
                    SttFailureClass::Permanent => SttProviderError::permanent(failure.message),
                },
                Err(audit_error) => SttProviderError::permanent(format!(
                    "{}; terminal D8 failed: {audit_error:#}",
                    failure.message
                )),
            });
        }

        let cache_root = self.cache_root.clone();
        let model_id = self.model_id.clone();
        let health = tokio::task::spawn_blocking(move || {
            verified_faster_whisper_cache_health_for_attempt(&cache_root, &model_id, true)
        })
        .await
        .map_err(|error| {
            SttProviderError::retryable(format!(
                "join faster-whisper post-download validation: {error}"
            ))
        })?;
        if !health.is_ready() {
            let reason =
                format!("faster-whisper prefetch completed without a verified cache: {health}");
            let terminal = attempt.finish_failed(writer, &reason).await;
            return Err(match terminal {
                Ok(()) => SttProviderError::permanent(reason),
                Err(audit_error) => SttProviderError::permanent(format!(
                    "{reason}; terminal D8 failed: {audit_error:#}"
                )),
            });
        }

        attempt
            .finish_ready(writer, &self.cache_path)
            .await
            .map_err(|error| {
                SttProviderError::permanent(format!("faster-whisper: emit ready D8: {error:#}"))
            })?;
        self.shared_ready.store(true, Ordering::Release);
        Ok(())
    }
}

#[async_trait]
impl SttProviderImpl for FasterWhisperProvider {
    fn kind(&self) -> SttProviderKind {
        SttProviderKind::FasterWhisperLocal
    }

    fn model_id(&self) -> Option<String> {
        Some(self.model_id.clone())
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, SttProviderError> {
        // Model acquisition and backend-load validation finish their D7/D8
        // lifecycle before audio is handled. Transcription is always offline.
        self.ensure_model_ready().await?;
        let _model_lock = super::model_manager::lock_model_cache(&self.cache_path)
            .await
            .map_err(|error| {
                SttProviderError::retryable(format!(
                    "faster-whisper: lock cache for offline transcription: {error:#}"
                ))
            })?;
        let health = faster_whisper_cache_health(&self.cache_root, &self.model_id);
        if !health.is_ready() {
            self.shared_ready
                .store(false, std::sync::atomic::Ordering::Release);
            return Err(SttProviderError::permanent(format!(
                "faster-whisper cache became unavailable before offline transcription: {health}"
            )));
        }
        // The request format is authoritative. Never reinterpret a labelled
        // WAV container (or raw s16 bytes) as raw f32 PCM.
        let wav_bytes = match request.format {
            crate::media::stt_dispatch::AudioFormat::WavPcmS16leMono => {
                if audio.len() < 12
                    || !audio.starts_with(b"RIFF")
                    || audio.get(8..12) != Some(b"WAVE")
                {
                    return Err(SttProviderError::permanent(
                        "faster-whisper: request says WAV but RIFF/WAVE header is missing",
                    ));
                }
                audio.to_vec()
            }
            crate::media::stt_dispatch::AudioFormat::PcmF32leMono => pcm_bytes_to_wav(audio)
                .map_err(|e| SttProviderError::permanent(format!("faster-whisper: {e}")))?,
            crate::media::stt_dispatch::AudioFormat::PcmS16leMono => {
                pcm_s16le_bytes_to_wav(audio, request.sample_rate_hz)
                    .map_err(|e| SttProviderError::permanent(format!("faster-whisper: {e}")))?
            }
        };
        // `TempPath` owns cleanup across success, error, timeout, and future
        // cancellation. The file handle is closed before the external process
        // opens it, which is required on Windows.
        let temp = tempfile::Builder::new()
            .prefix("neoth-fw-")
            .suffix(".wav")
            .tempfile()
            .map_err(|e| {
                SttProviderError::retryable(format!("faster-whisper: create tmp WAV: {e}"))
            })?;
        std::fs::write(temp.path(), &wav_bytes).map_err(|e| {
            SttProviderError::retryable(format!("faster-whisper: write tmp WAV: {e}"))
        })?;
        let tmp_path = temp.into_temp_path();

        let language = if request.language.is_empty() {
            "auto".to_string()
        } else {
            request.language.clone()
        };
        let bridge = run_faster_whisper_bridge(
            &self.python_executable,
            &self.model_id,
            &self.cache_root,
            FasterWhisperBridgeMode::Transcribe {
                audio_path: &tmp_path,
                language: &language,
            },
            true,
        )
        .await;
        let out = match bridge {
            Ok(output) => output,
            Err(failure) => {
                self.shared_ready
                    .store(false, std::sync::atomic::Ordering::Release);
                return Err(match failure.class {
                    SttFailureClass::Retryable => SttProviderError::retryable(failure.message),
                    SttFailureClass::Permanent => SttProviderError::permanent(failure.message),
                });
            }
        };
        let (full_text, segments) = parse_faster_whisper_output(&out.stdout);
        let cleaned = crate::media::stt_postprocess::clean_transcript(&full_text);
        Ok(TranscriptionResult {
            text: cleaned,
            segments,
            language: request.language.clone(),
            confidence: None,
            speaker_labels: Vec::new(),
            provider: String::new(),
        })
    }
}

// ── HANDY-05: WhisperLocalProvider ──────────────────────────────────────────

/// Local candle-based STT provider wrapping the shared `WhisperEngine`.
///
/// The canonical factory constructs the configured repository only after its
/// download policy has been checked. The engine's idle watcher uses the
/// effective `media.whisper_idle_unload_secs` value.
///
/// Audio bytes are decoded from WAV/MP3/… → 16 kHz mono f32 PCM via
/// symphonia (same codec path as `media::audio::decode_from_bytes`).
pub struct WhisperLocalProvider {
    engine: std::sync::Arc<crate::providers::whisper::WhisperEngine>,
    model_id: String,
}

impl WhisperLocalProvider {
    fn from_shared_engine(
        engine: std::sync::Arc<crate::providers::whisper::WhisperEngine>,
        model_id: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            model_id: model_id.into(),
        }
    }
}

/// Decode `audio` bytes (WAV/MP3/FLAC/Ogg/M4A) into 16 kHz mono f32 PCM
/// for the candle Whisper engine. This is the decode path from
/// `media::audio::decode_from_bytes`, extracted for reuse in
/// `WhisperLocalProvider::transcribe`.
fn decode_audio_bytes_to_pcm(audio: &[u8], mime_hint: &str) -> Result<Vec<f32>, String> {
    use std::io::Cursor;
    use symphonia::core::audio::SampleBuffer;
    use symphonia::core::codecs::DecoderOptions;
    use symphonia::core::errors::Error as SymError;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    let cursor = Cursor::new(audio.to_vec());
    let mss = MediaSourceStream::new(Box::new(cursor), Default::default());
    let mut hint = Hint::new();
    if !mime_hint.is_empty() {
        hint.mime_type(mime_hint);
    }
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| format!("whisper local: audio probe: {e}"))?;
    let mut format = probed.format;
    let track = format
        .default_track()
        .ok_or("whisper local: no default track in container")?;
    let track_id = track.id;
    let codec_params = track.codec_params.clone();
    let original_sr = match codec_params.sample_rate {
        Some(sr) if sr > 0 => sr,
        _ => return Err("whisper local: codec reported no/zero sample rate".to_string()),
    };
    let channels = codec_params.channels.map(|c| c.count()).unwrap_or(1);
    let mut decoder = symphonia::default::get_codecs()
        .make(&codec_params, &DecoderOptions::default())
        .map_err(|e| format!("whisper local: codec init: {e}"))?;

    let mut decoded_mono: Vec<f32> = Vec::new();
    let mut buf: Option<SampleBuffer<f32>> = None;
    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(SymError::ResetRequired) => break,
            Err(e) => return Err(format!("whisper local: packet: {e}")),
        };
        if packet.track_id() != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(audio_buf) => {
                let spec = *audio_buf.spec();
                if buf.is_none() {
                    buf = Some(SampleBuffer::<f32>::new(audio_buf.capacity() as u64, spec));
                }
                if let Some(b) = buf.as_mut() {
                    b.copy_interleaved_ref(audio_buf);
                    let ch = channels.max(1);
                    let frame_count = b.samples().len() / ch;
                    let samples = b.samples();
                    for f in 0..frame_count {
                        let mut sum = 0f32;
                        for c in 0..ch {
                            sum += samples[f * ch + c];
                        }
                        decoded_mono.push(sum / ch as f32);
                    }
                }
            }
            Err(SymError::DecodeError(_)) => continue,
            Err(SymError::IoError(_)) => break,
            Err(e) => return Err(format!("whisper local: decode: {e}")),
        }
    }

    // Resample to 16 kHz if needed (same path as media::audio).
    let target_sr = crate::media::audio::TARGET_SAMPLE_RATE;
    let pcm = if original_sr == target_sr {
        decoded_mono
    } else {
        crate::media::resampler::resample_mono(&decoded_mono, original_sr, target_sr)
            .map_err(|e| format!("whisper local: resample: {e}"))?
    };
    Ok(pcm)
}

#[async_trait::async_trait]
impl SttProviderImpl for WhisperLocalProvider {
    fn kind(&self) -> SttProviderKind {
        SttProviderKind::WhisperRsLocal
    }

    fn model_id(&self) -> Option<String> {
        Some(self.model_id.clone())
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResult, SttProviderError> {
        // Decode audio bytes → 16 kHz f32 PCM (synchronously on spawn_blocking).
        let audio_owned = audio.to_vec();
        let mime = if audio_owned.starts_with(b"RIFF") {
            "audio/wav"
        } else if audio_owned.starts_with(b"ID3") || audio_owned.starts_with(&[0xFF, 0xFB]) {
            "audio/mpeg"
        } else {
            ""
        };
        let mime_str = mime.to_string();
        let pcm =
            tokio::task::spawn_blocking(move || decode_audio_bytes_to_pcm(&audio_owned, &mime_str))
                .await
                .map_err(|e| {
                    SttProviderError::retryable(format!("whisper local: decode join: {e}"))
                })?
                .map_err(SttProviderError::permanent)?;

        // Build WhisperOptions from the STT request (language passthrough).
        let mut opts = crate::providers::whisper::WhisperOptions::default();
        if !request.language.is_empty() {
            opts.language = request.language.clone();
            opts.auto_detect_language = false;
        }

        let text = self.engine.transcribe(&pcm, opts).await.map_err(|e| {
            SttProviderError::retryable(format!("whisper local: transcribe: {e:#}"))
        })?;

        let cleaned = crate::media::stt_postprocess::clean_transcript(&text);
        Ok(TranscriptionResult {
            text: cleaned,
            segments: vec![],
            language: request.language.clone(),
            confidence: None,
            speaker_labels: Vec::new(),
            provider: String::new(),
        })
    }
}

/// Build a live STT provider from the effective operator configuration.
///
/// Every model download is planned against `updater_cfg` before a provider can
/// start a process or construct a network-capable model loader.
pub async fn make_stt_provider(
    kind: SttProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<Box<dyn SttProviderImpl>, SttFactoryError> {
    let runtime = SttRuntimeEnvironment::from_process();
    let python_probe = ProcessFasterWhisperPythonProbe;
    make_stt_provider_with_runtime(
        kind,
        api_key,
        azure_region,
        media_cfg,
        updater_cfg,
        wal_writer,
        &runtime,
        &python_probe,
    )
    .await
}

async fn make_stt_provider_with_runtime(
    kind: SttProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
    runtime: &SttRuntimeEnvironment,
    python_probe: &dyn FasterWhisperPythonProbe,
) -> Result<Box<dyn SttProviderImpl>, SttFactoryError> {
    // P0 ENFORCEMENT — a CLOUD STT provider may only be constructed when the
    // operator has opted in (`media.cloud_stt_enabled`). The safe-mode rail makes
    // this visible; this gate makes it REAL — audio cannot leave the device for a
    // cloud transcriber while the flag is off. Local STT carries no gate.
    if !kind.is_local() && !media_cfg.cloud_stt_enabled {
        return Err(SttFactoryError::permanent(format!(
            "cloud STT ({}) is disabled — set media.cloud_stt_enabled: true to send \
             audio to a cloud transcriber (your audio then LEAVES the device)",
            kind.as_str()
        )));
    }
    match kind {
        SttProviderKind::OpenAiWhisperApi => {
            let key = api_key
                .ok_or_else(|| SttFactoryError::permanent("openai whisper requires an api key"))?;
            Ok(Box::new(OpenAiWhisperClient::new(key)))
        }
        SttProviderKind::AzureSpeech => {
            let key = api_key
                .ok_or_else(|| SttFactoryError::permanent("azure speech requires an api key"))?;
            let region = azure_region
                .filter(|region| !region.trim().is_empty())
                .ok_or_else(|| SttFactoryError::permanent("azure speech requires a region"))?;
            Ok(Box::new(AzureSpeechClient::new(region, key)))
        }
        SttProviderKind::FasterWhisperLocal => {
            let mut provider = plan_faster_whisper_provider(media_cfg, updater_cfg, runtime)?;
            let lifecycle_required =
                !faster_whisper_cache_health(&provider.cache_root, &provider.model_id).is_ready()
                    || super::model_manager::has_pending_download(&provider.cache_path)
                        .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
            require_model_download_writer(lifecycle_required, wal_writer)?;
            provider.model_download_writer = wal_writer.cloned();
            python_probe
                .verify(
                    &provider.python_executable,
                    runtime.faster_whisper_python_is_explicit,
                )
                .await?;
            Ok(Box::new(provider))
        }
        SttProviderKind::WhisperRsLocal => {
            let _build_guard = CANDLE_PROVIDER_BUILD
                .get_or_init(|| tokio::sync::Mutex::new(()))
                .lock()
                .await;
            let model_id = candle_whisper_model_id(media_cfg.stt.model_size);
            let engine_key = CandleEngineKey::new(
                &runtime.candle_cache_root,
                model_id,
                media_cfg.whisper_idle_unload_secs,
            );
            if let Some(engine) = candle_engines()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&engine_key)
                .cloned()
            {
                return Ok(Box::new(WhisperLocalProvider::from_shared_engine(
                    engine, model_id,
                )));
            }
            let plan = plan_candle_provider(media_cfg, runtime);
            let mut attempt = super::model_manager::ModelDownloadAttempt::acquire(
                &plan.cache_path,
                plan.model_id,
                "implicit",
            )
            .await
            .map_err(|error| SttFactoryError::retryable(error.to_string()))?;

            if let Some(super::model_manager::PendingModelDownloadOutcome::Failed { .. }) =
                attempt.pending_outcome()
            {
                let writer = wal_writer.ok_or_else(|| {
                    SttFactoryError::permanent(
                        "pending model download requires the caller WAL writer for D8 recovery",
                    )
                })?;
                attempt
                    .replay_terminal(writer)
                    .await
                    .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
            }

            let models_root = runtime.candle_cache_root.clone();
            let health_model_id = plan.model_id.to_string();
            let during_attempt = attempt.is_pending();
            let health = tokio::task::spawn_blocking(move || {
                crate::providers::whisper::verified_cache_health_at(
                    &models_root,
                    &health_model_id,
                    during_attempt,
                )
            })
            .await
            .map_err(|error| SttFactoryError::retryable(error.to_string()))?;
            let network_needed = !health.is_ready();

            if network_needed
                && matches!(
                    attempt.pending_outcome(),
                    Some(super::model_manager::PendingModelDownloadOutcome::Ready)
                )
            {
                let writer = wal_writer.ok_or_else(|| {
                    SttFactoryError::permanent(
                        "pending ready model attempt requires a WAL writer for correction",
                    )
                })?;
                let reason =
                    format!("pending ready Whisper generation no longer validates: {health}");
                attempt
                    .finish_failed(writer, &reason)
                    .await
                    .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
                return Err(SttFactoryError::retryable(reason));
            }

            if network_needed {
                let writer = wal_writer.ok_or_else(|| {
                    SttFactoryError::permanent(
                        "model download requires the caller WAL writer for D7/D8 proof",
                    )
                })?;
                if let Err(policy_error) =
                    updater_cfg.check_model_download(plan.model_id, Some("whisper"))
                {
                    let message = policy_error.to_string();
                    if attempt.is_pending() {
                        attempt
                            .finish_failed(writer, &message)
                            .await
                            .map_err(|audit_error| {
                                SttFactoryError::permanent(format!(
                                    "{message}; terminal D8 failed: {audit_error:#}"
                                ))
                            })?;
                    }
                    return Err(SttFactoryError::permanent(message));
                }
                attempt
                    .ensure_started(writer)
                    .await
                    .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
            } else {
                require_model_download_writer(attempt.is_pending(), wal_writer)?;
                if attempt.is_pending()
                    && attempt.pending_outcome().is_none()
                    && !attempt.network_authorized(&plan.cache_path, plan.model_id)
                {
                    attempt
                        .ensure_started(wal_writer.ok_or_else(|| {
                            SttFactoryError::permanent(
                                "pending model recovery lost its caller WAL writer",
                            )
                        })?)
                        .await
                        .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
                }
            }

            let engine_result = if attempt.is_pending() {
                crate::providers::whisper::WhisperEngine::new_for_download_attempt(
                    Some(plan.model_id.to_string()),
                    plan.idle_unload_secs,
                    &runtime.candle_cache_root,
                    &attempt,
                )
                .await
            } else {
                crate::providers::whisper::WhisperEngine::new_with_models_root(
                    Some(plan.model_id.to_string()),
                    plan.idle_unload_secs,
                    &runtime.candle_cache_root,
                )
                .await
            };
            let engine = match engine_result {
                Ok(engine) => engine,
                Err(error) => {
                    let message = format!(
                        "candle whisper model `{}` could not be initialised: {error:#}",
                        plan.model_id
                    );
                    if attempt.is_pending() {
                        let writer = wal_writer.ok_or_else(|| {
                            SttFactoryError::permanent("model download WAL writer disappeared")
                        })?;
                        attempt
                            .finish_failed(writer, &message)
                            .await
                            .map_err(|audit| {
                                SttFactoryError::permanent(format!(
                                    "{message}; terminal D8 failed: {audit:#}"
                                ))
                            })?;
                    }
                    return Err(if network_needed {
                        SttFactoryError::retryable(message)
                    } else {
                        SttFactoryError::permanent(message)
                    });
                }
            };
            if let Err(error) = engine.validate_load().await {
                let message = format!(
                    "candle whisper model `{}` failed backend validation: {error:#}",
                    plan.model_id
                );
                if attempt.is_pending() {
                    let writer = wal_writer.ok_or_else(|| {
                        SttFactoryError::permanent("model download WAL writer disappeared")
                    })?;
                    attempt
                        .finish_failed(writer, &message)
                        .await
                        .map_err(|audit| {
                            SttFactoryError::permanent(format!(
                                "{message}; terminal D8 failed: {audit:#}"
                            ))
                        })?;
                }
                return Err(if network_needed {
                    SttFactoryError::retryable(message)
                } else {
                    SttFactoryError::permanent(message)
                });
            }
            if attempt.is_pending() {
                let writer = wal_writer.ok_or_else(|| {
                    SttFactoryError::permanent("model download WAL writer disappeared")
                })?;
                attempt
                    .finish_ready(writer, &plan.cache_path)
                    .await
                    .map_err(|error| SttFactoryError::permanent(error.to_string()))?;
            }
            let engine = std::sync::Arc::new(engine);
            candle_engines()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(engine_key, std::sync::Arc::clone(&engine));
            Ok(Box::new(WhisperLocalProvider::from_shared_engine(
                engine,
                plan.model_id,
            )))
        }
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
    media_cfg: &crate::config::MediaConfig,
    neoth_home: &Path,
) -> Result<TranscriptionResult, SttProviderError> {
    // P0 fail-closed pre-flight: under proof-hardline, refuse BEFORE the cloud
    // call when there is no audit sink — never transcribe unprovably.
    let is_cloud = !provider.kind().is_local();
    if is_cloud {
        crate::media::enforce_cloud_media_audit(
            media_cfg.required_audit_for_cloud_media,
            writer.is_some(),
        )
        .map_err(SttProviderError::permanent)?;
    }
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
    // GOLD-ADAPT-SPEAKR-02b/02c — speaker re-identification.
    //
    // Encoder selection (inside spawn_blocking):
    //   1. Try EcapaTdnn::try_load() — highest accuracy; activates when operator
    //      provisions weights via `scripts/convert_ecapa.py`. 192-dim output.
    //   2. Try XVectorEncoder::try_load() — fallback neural encoder; activates
    //      when operator provisions weights via `scripts/convert_xvector.py`.
    //      512-dim output.
    //   3. Fall back to the log-mel encoder (embed_segments). 80-dim output.
    //
    // The dim difference across encoders is safe: speaker_profile::load_profiles
    // gates on embedding_dim and resets the store on a mismatch rather than
    // silently returning cosine 0.0 for every speaker.
    //
    // The config read, the CPU-bound encode, AND the profile-store I/O all run
    // inside ONE spawn_blocking so nothing blocks the async executor. Raw PCM
    // and the canonical PCM16 WAV container are decoded explicitly.
    if media_cfg.auto_speaker_labels
        && matches!(
            request.format,
            crate::media::stt_dispatch::AudioFormat::PcmS16leMono
                | crate::media::stt_dispatch::AudioFormat::PcmF32leMono
                | crate::media::stt_dispatch::AudioFormat::WavPcmS16leMono
        )
    {
        let audio_owned = audio.to_vec();
        let segments = result.segments.clone();
        let format = request.format;
        let sample_rate = request.sample_rate_hz;
        let neoth_home = neoth_home.to_path_buf();
        let labels = tokio::task::spawn_blocking(move || -> Result<Vec<Option<String>>, String> {
            // Decode to 16 kHz f32 first so all neural encoder paths share
            // the same decoded buffer.  embed_segments handles decoding
            // internally; we replicate it here for the neural paths.
            use crate::media::speaker_encoder_ecapa::EcapaTdnn;
            use crate::media::speaker_encoder_xvector::XVectorEncoder;

            /// Encode segments from a pre-decoded 16 kHz f32 buffer using the
            /// given per-sample closure.  Returns one embedding per segment
            /// (or one for the whole clip when `segments` is empty).
            fn encode_aligned<F>(
                decoded: &[f32],
                segments: &[crate::media::stt_dispatch::TextSegment],
                embed: F,
            ) -> Vec<Option<Vec<f32>>>
            where
                F: Fn(&[f32]) -> Option<Vec<f32>>,
            {
                const SR: u32 = 16_000;
                if segments.is_empty() {
                    vec![embed(decoded)]
                } else {
                    segments
                        .iter()
                        .map(|s| {
                            let start = (s.start_ms as u64 * SR as u64 / 1000)
                                .min(decoded.len() as u64)
                                as usize;
                            let end = (s.end_ms as u64 * SR as u64 / 1000).min(decoded.len() as u64)
                                as usize;
                            if start >= end {
                                None
                            } else {
                                embed(&decoded[start..end])
                            }
                        })
                        .collect()
                }
            }

            fn empty_aligned_labels(
                segments: &[crate::media::stt_dispatch::TextSegment],
            ) -> Vec<Option<String>> {
                if segments.is_empty() {
                    Vec::new()
                } else {
                    vec![None; segments.len()]
                }
            }

            // ── Encoder priority: ECAPA → x-vector → log-mel ─────────────
            let aligned_embeddings: Vec<Option<Vec<f32>>> = if let Some(ecapa) =
                EcapaTdnn::try_load()
            {
                // Highest accuracy: ECAPA-TDNN, 192-dim.
                let decoded =
                    crate::media::speaker_encoder::decode_to_f32(&audio_owned, format, sample_rate)
                        .map_err(|e| format!("speaker audio decode: {e}"))?;
                if decoded.is_empty() {
                    return Ok(empty_aligned_labels(&segments));
                }
                encode_aligned(&decoded, &segments, |s| ecapa.embed(s))
            } else if let Some(xvec) = XVectorEncoder::try_load() {
                // Fallback neural: x-vector TDNN, 512-dim.
                let decoded =
                    crate::media::speaker_encoder::decode_to_f32(&audio_owned, format, sample_rate)
                        .map_err(|e| format!("speaker audio decode: {e}"))?;
                if decoded.is_empty() {
                    return Ok(empty_aligned_labels(&segments));
                }
                encode_aligned(&decoded, &segments, |s| xvec.embed(s))
            } else {
                // Log-mel fallback (always available, no weights needed).
                let decoded =
                    crate::media::speaker_encoder::decode_to_f32(&audio_owned, format, sample_rate)
                        .map_err(|e| format!("speaker audio decode: {e}"))?;
                if decoded.is_empty() {
                    return Ok(empty_aligned_labels(&segments));
                }
                encode_aligned(
                    &decoded,
                    &segments,
                    crate::media::speaker_encoder::embed_samples,
                )
            };

            if aligned_embeddings.is_empty() {
                return Ok(Vec::new());
            }
            let present: Vec<bool> = aligned_embeddings.iter().map(Option::is_some).collect();
            let embeddings: Vec<Vec<f32>> = aligned_embeddings.into_iter().flatten().collect();
            if embeddings.is_empty() {
                return Ok(vec![None; present.len()]);
            }
            let mut labels =
                crate::media::speaker_profile::label_embeddings(&neoth_home, &embeddings)
                    .into_iter();
            Ok(present
                .into_iter()
                .map(|has_embedding| {
                    if has_embedding {
                        labels.next().unwrap_or(None)
                    } else {
                        None
                    }
                })
                .collect())
        })
        .await;
        match labels {
            Ok(Ok(labels)) => {
                let labelled = labels.iter().filter(|label| label.is_some()).count();
                result.speaker_labels = labels;
                if labelled > 0 {
                    tracing::info!(speakers = ?result.speaker_labels, labelled, "SPEAKR-02c speaker re-id");
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "speaker re-id skipped: invalid audio input");
            }
            Err(error) => {
                tracing::error!(%error, "speaker re-id worker failed");
            }
        }
    }
    if is_cloud && let Some(w) = writer {
        let audit =
            emit_stt_transcribed(w, provider.kind(), audio.len(), result.text.chars().count())
                .await;
        if let Err(error) = audit {
            if media_cfg.required_audit_for_cloud_media {
                // The cloud call already happened, so this is deliberately
                // permanent: a fallback would duplicate the egress/cost while
                // still failing to prove the first call.
                return Err(SttProviderError::permanent(format!(
                    "required STT audit append failed after cloud transcription: {error}"
                )));
            }
            tracing::warn!(%error, "WAL append STT_TRANSCRIBED (0xCC) failed (non-fatal)");
        }
    }
    Ok(result)
}

async fn emit_stt_transcribed(
    writer: &crate::wal::writer::WalWriterHandle,
    provider: SttProviderKind,
    audio_bytes: usize,
    output_chars: usize,
) -> Result<(), String> {
    let ts_unix = crate::time::now_unix_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider.as_str(),
        "audio_bytes": audio_bytes,
        "output_chars": output_chars,
        "ts_unix": ts_unix,
    }))
    .map_err(|error| format!("serialize STT_TRANSCRIBED (0xCC): {error}"))?;
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_STT_TRANSCRIBED, &payload);
    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| format!("append STT_TRANSCRIBED (0xCC): {error}"))
}

/// Read STT API key from environment for provider `kind`.
/// Keychain wiring is a follow-up; env var is the current source of truth.
#[derive(Default)]
struct SttCredentials {
    openai: Option<SecretString>,
    azure: Option<SecretString>,
}

impl SttCredentials {
    fn from_process() -> Self {
        Self {
            openai: std::env::var("STT_OPENAI_KEY").ok().map(SecretString::from),
            azure: std::env::var("STT_AZURE_KEY").ok().map(SecretString::from),
        }
    }

    fn for_kind(&self, kind: SttProviderKind) -> Option<SecretString> {
        match kind {
            SttProviderKind::OpenAiWhisperApi => self.openai.clone(),
            SttProviderKind::AzureSpeech => self.azure.clone(),
            SttProviderKind::WhisperRsLocal | SttProviderKind::FasterWhisperLocal => None,
        }
    }
}

#[async_trait]
trait SttProviderFactory: Send + Sync {
    async fn build(
        &self,
        kind: SttProviderKind,
    ) -> Result<Box<dyn SttProviderImpl>, SttFactoryError>;
}

struct ConfiguredSttProviderFactory<'a> {
    media_cfg: &'a crate::config::MediaConfig,
    updater_cfg: &'a crate::config::ops::UpdaterConfig,
    credentials: SttCredentials,
    azure_region: Option<String>,
    wal_writer: Option<&'a crate::wal::writer::WalWriterHandle>,
    runtime: SttRuntimeEnvironment,
}

#[async_trait]
impl SttProviderFactory for ConfiguredSttProviderFactory<'_> {
    async fn build(
        &self,
        kind: SttProviderKind,
    ) -> Result<Box<dyn SttProviderImpl>, SttFactoryError> {
        let python_probe = ProcessFasterWhisperPythonProbe;
        make_stt_provider_with_runtime(
            kind,
            self.credentials.for_kind(kind),
            self.azure_region.clone(),
            self.media_cfg,
            self.updater_cfg,
            self.wal_writer,
            &self.runtime,
            &python_probe,
        )
        .await
    }
}

#[derive(Debug, thiserror::Error)]
enum SttAttemptError {
    #[error("{0}")]
    Factory(#[from] SttFactoryError),
    #[error("{0}")]
    Provider(#[from] SttProviderError),
}

impl SttAttemptError {
    fn class(&self) -> SttFailureClass {
        match self {
            Self::Factory(error) => error.class(),
            Self::Provider(error) => error.class(),
        }
    }
}

async fn run_stt_attempt(
    factory: &dyn SttProviderFactory,
    kind: SttProviderKind,
    audio: &[u8],
    request: &TranscriptionRequest,
    media_cfg: &crate::config::MediaConfig,
    neoth_home: &Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<TranscriptionResult, SttAttemptError> {
    let provider = factory.build(kind).await?;
    let mut result = transcribe_and_audit(
        provider.as_ref(),
        audio,
        request,
        wal_writer,
        media_cfg,
        neoth_home,
    )
    .await?;
    result.provider = provider.kind().as_str().to_string();
    Ok(result)
}

/// Unified STT dispatcher — the single entry point for ALL transcription in NEOTH.
///
/// Routes BOTH `neoth dictate` (dictation.rs) and channel/attachment audio ingest
/// (audio.rs) through the same provider selection, cloud gate, audit, and fallback
/// logic. Local is the default; cloud requires explicit provider + credentials +
/// region + `media.cloud_stt_enabled = true` + audit sink (when
/// `media.required_audit_for_cloud_media = true`).
///
/// # Fallback policy
///
/// Fallback fires ONLY on classified retryable/transient failures. Auth, config,
/// permanent, or missing-credentials errors propagate immediately — no blind
/// fallthrough. `cloud_stt_enabled = true` alone never injects a cloud fallback;
/// the fallback provider must be explicitly named in `stt_cfg.fallback`.
pub async fn dispatch_transcription(
    stt_cfg: &crate::media::stt_dispatch::MediaSttConfig,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    neoth_home: &Path,
    audio: &[u8],
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<TranscriptionResult, String> {
    let azure_region =
        (!stt_cfg.azure_region.trim().is_empty()).then(|| stt_cfg.azure_region.clone());
    let factory = ConfiguredSttProviderFactory {
        media_cfg,
        updater_cfg,
        credentials: SttCredentials::from_process(),
        azure_region,
        wal_writer,
        runtime: SttRuntimeEnvironment::for_home(neoth_home),
    };
    dispatch_transcription_with_factory(stt_cfg, media_cfg, neoth_home, audio, wal_writer, &factory)
        .await
}

async fn dispatch_transcription_with_factory(
    stt_cfg: &crate::media::stt_dispatch::MediaSttConfig,
    media_cfg: &crate::config::MediaConfig,
    neoth_home: &Path,
    audio: &[u8],
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
    factory: &dyn SttProviderFactory,
) -> Result<TranscriptionResult, String> {
    use crate::media::stt_dispatch::AudioFormat;

    if audio.len() < 12 || !audio.starts_with(b"RIFF") || audio.get(8..12) != Some(b"WAVE") {
        return Err(
            "STT dispatcher expects a RIFF/WAVE PCM16 container; use dispatch_pcm_f32 for raw PCM"
                .to_string(),
        );
    }

    let request = TranscriptionRequest {
        language: stt_cfg.language.clone(),
        model_size: stt_cfg.model_size,
        format: AudioFormat::WavPcmS16leMono,
        sample_rate_hz: 16_000,
        initial_prompt: String::new(),
    };

    let primary_error = match run_stt_attempt(
        factory,
        stt_cfg.primary,
        audio,
        &request,
        media_cfg,
        neoth_home,
        wal_writer,
    )
    .await
    {
        Ok(result) => return Ok(result),
        Err(error) if error.class() == SttFailureClass::Permanent => {
            return Err(format!(
                "STT primary ({}) failed permanently: {error}",
                stt_cfg.primary.as_str()
            ));
        }
        Err(error) => {
            tracing::warn!(
                provider = stt_cfg.primary.as_str(),
                error = %error,
                "STT primary retryable failure — trying fallback"
            );
            error
        }
    };

    // Fallback path (retryable failure only).
    let fb_kind = match stt_cfg.fallback {
        Some(fb) => fb,
        // primary_result is Err here (retryable) — no fallback configured.
        None => {
            return Err(format!(
                "STT primary ({}) failed and no fallback is configured: {primary_error}",
                stt_cfg.primary.as_str()
            ));
        }
    };

    // Fallback to cloud requires explicit consent — same gate as primary.
    if !fb_kind.is_local() && !media_cfg.cloud_stt_enabled {
        return Err(format!(
            "STT primary failed (retryable) but fallback ({}) is cloud and \
             cloud_stt_enabled=false — refusing to send audio to cloud",
            fb_kind.as_str()
        ));
    }

    run_stt_attempt(
        factory, fb_kind, audio, &request, media_cfg, neoth_home, wal_writer,
    )
    .await
    .map_err(|fallback_error| {
        format!(
            "STT primary ({}) failed: {primary_error}; fallback ({}) failed: \
                 {fallback_error}",
            stt_cfg.primary.as_str(),
            fb_kind.as_str()
        )
    })
}

#[derive(Debug, thiserror::Error)]
pub enum PcmSttError {
    #[error("PCM input is empty")]
    EmptyInput,
    #[error(transparent)]
    Resample(#[from] crate::media::resampler::ResampleError),
    #[error(transparent)]
    Encode(#[from] PcmEncodingError),
    #[error("STT dispatch failed: {0}")]
    Dispatch(String),
}

fn prepare_pcm_f32_wav(samples: &[f32], sample_rate_hz: u32) -> Result<Vec<u8>, PcmSttError> {
    if samples.is_empty() {
        return Err(PcmSttError::EmptyInput);
    }
    let samples_16k = crate::media::resampler::resample_mono(
        samples,
        sample_rate_hz,
        crate::media::audio::TARGET_SAMPLE_RATE,
    )?;
    Ok(pcm_f32_to_wav(&samples_16k)?)
}

/// Canonical entry point for mono f32 PCM.
///
/// Validates the rate and every sample, resamples once to Whisper's 16 kHz
/// working rate, wraps a truthful PCM16 WAV container, then enters
/// [`dispatch_transcription`] so provider selection, cloud consent, required
/// audit, post-processing, speaker encoding, and fallback cannot be bypassed.
pub async fn dispatch_pcm_f32(
    stt_cfg: &crate::media::stt_dispatch::MediaSttConfig,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    neoth_home: &Path,
    samples: &[f32],
    sample_rate_hz: u32,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<TranscriptionResult, PcmSttError> {
    let wav = prepare_pcm_f32_wav(samples, sample_rate_hz)?;
    dispatch_transcription(
        stt_cfg,
        media_cfg,
        updater_cfg,
        neoth_home,
        &wav,
        wal_writer,
    )
    .await
    .map_err(PcmSttError::Dispatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::stt_dispatch::{AudioFormat, WhisperModelSize};

    fn test_neoth_home() -> tempfile::TempDir {
        tempfile::tempdir().expect("create isolated NEOTH home")
    }

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

    #[tokio::test]
    async fn cloud_factory_is_typed_and_never_contacts_the_provider() {
        let on = cloud_on();
        let updater = crate::config::ops::UpdaterConfig::default();
        let openai = make_stt_provider(
            SttProviderKind::OpenAiWhisperApi,
            Some(SecretString::from("k")),
            None,
            &on,
            &updater,
            None,
        )
        .await
        .unwrap();
        assert_eq!(openai.kind(), SttProviderKind::OpenAiWhisperApi);

        let azure = make_stt_provider(
            SttProviderKind::AzureSpeech,
            Some(SecretString::from("k")),
            Some("eastus".into()),
            &on,
            &updater,
            None,
        )
        .await
        .unwrap();
        assert_eq!(azure.kind(), SttProviderKind::AzureSpeech);

        let missing_key = make_stt_provider(
            SttProviderKind::OpenAiWhisperApi,
            None,
            None,
            &on,
            &updater,
            None,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(missing_key.class(), SttFailureClass::Permanent);
    }

    #[tokio::test]
    async fn cloud_consent_and_config_fail_permanently() {
        let off = crate::config::MediaConfig::default();
        let updater = crate::config::ops::UpdaterConfig::default();
        let error = make_stt_provider(
            SttProviderKind::OpenAiWhisperApi,
            Some(SecretString::from("k")),
            None,
            &off,
            &updater,
            None,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.class(), SttFailureClass::Permanent);
        assert!(error.to_string().contains("LEAVES the device"));

        let error = make_stt_provider(
            SttProviderKind::AzureSpeech,
            Some(SecretString::from("k")),
            None,
            &cloud_on(),
            &updater,
            None,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.class(), SttFailureClass::Permanent);
        assert!(error.to_string().contains("region"));
    }

    #[test]
    fn typed_http_statuses_drive_retryability_without_string_matching() {
        for status in [
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::BAD_GATEWAY,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            reqwest::StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert_eq!(
                http_status_error("test", status).class(),
                SttFailureClass::Retryable
            );
        }
        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
        ] {
            assert_eq!(
                http_status_error("test", status).class(),
                SttFailureClass::Permanent
            );
        }
    }

    #[test]
    fn every_whisper_size_maps_to_exact_candle_and_faster_repositories() {
        let cases = [
            (
                WhisperModelSize::Tiny,
                "openai/whisper-tiny",
                "Systran/faster-whisper-tiny",
            ),
            (
                WhisperModelSize::Base,
                "openai/whisper-base",
                "Systran/faster-whisper-base",
            ),
            (
                WhisperModelSize::Small,
                "openai/whisper-small",
                "Systran/faster-whisper-small",
            ),
            (
                WhisperModelSize::Medium,
                "openai/whisper-medium",
                "Systran/faster-whisper-medium",
            ),
            (
                WhisperModelSize::Large,
                "openai/whisper-large-v3",
                "Systran/faster-whisper-large-v3",
            ),
        ];
        for (size, candle, faster) in cases {
            let spec = whisper_model_spec(size);
            assert_eq!(spec.candle_repo, candle);
            assert_eq!(spec.faster_whisper_repo, faster);
        }
    }

    #[test]
    fn python_resolution_prefers_explicit_then_python_then_python3() {
        assert_eq!(
            choose_faster_whisper_python(
                Some(PathBuf::from("configured-python")),
                Some(PathBuf::from("python")),
                Some(PathBuf::from("python3")),
            ),
            (Some(PathBuf::from("configured-python")), true)
        );
        assert_eq!(
            choose_faster_whisper_python(
                None,
                Some(PathBuf::from("python")),
                Some(PathBuf::from("python3")),
            ),
            (Some(PathBuf::from("python")), false)
        );
        assert_eq!(
            choose_faster_whisper_python(None, None, Some(PathBuf::from("python3"))),
            (Some(PathBuf::from("python3")), false)
        );
    }

    fn fake_runtime(root: &Path, executable: Option<PathBuf>) -> SttRuntimeEnvironment {
        SttRuntimeEnvironment {
            faster_whisper_python: executable,
            faster_whisper_python_is_explicit: false,
            faster_whisper_cache_root: root.join("hf"),
            faster_whisper_cache_owned_by_neoth: true,
            candle_cache_root: root.join("candle"),
        }
    }

    #[test]
    fn candle_engine_owner_key_covers_every_residency_input() {
        let root = PathBuf::from("models-a");
        let baseline = CandleEngineKey::new(&root, "openai/whisper-small", Some(120));
        assert_eq!(
            baseline,
            CandleEngineKey::new(&root, "openai/whisper-small", Some(120)),
            "identical effective configurations must reuse one process owner"
        );
        assert_ne!(
            baseline,
            CandleEngineKey::new(Path::new("models-b"), "openai/whisper-small", Some(120)),
            "different NEOTH homes must not share model residency"
        );
        assert_ne!(
            baseline,
            CandleEngineKey::new(&root, "openai/whisper-medium", Some(120)),
            "a model change must create a new engine generation"
        );
        assert_ne!(
            baseline,
            CandleEngineKey::new(&root, "openai/whisper-small", None),
            "an idle-policy reload must not retain the old watcher policy"
        );
    }

    fn write_minimal_safetensors(path: &Path) {
        let header = br#"{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let mut bytes = Vec::with_capacity(8 + header.len() + 4);
        bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&[0_u8; 4]);
        std::fs::write(path, bytes).unwrap();
    }

    fn read_model_download_events(path: &Path) -> Vec<(u8, serde_json::Value)> {
        let bytes = std::fs::read(path).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = segment_header.header_len();
        let mut events = Vec::new();
        while cursor < bytes.len() {
            let decoded = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if matches!(
                decoded.header.event_type,
                crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START
                    | crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE
            ) {
                events.push((
                    decoded.header.event_type,
                    serde_json::from_slice(decoded.payload).unwrap(),
                ));
            }
            cursor += decoded.header.total_len as usize;
        }
        events
    }

    fn materialize_local_whisper_target(target: &LocalWhisperTarget) {
        match target.backend() {
            SttProviderKind::WhisperRsLocal => {
                std::fs::create_dir_all(target.cache_path()).unwrap();
                std::fs::write(
                    target
                        .cache_path()
                        .join(crate::providers::whisper::TOKENIZER_FILE),
                    b"{}",
                )
                .unwrap();
                std::fs::write(
                    target
                        .cache_path()
                        .join(crate::providers::whisper::CONFIG_FILE),
                    b"{}",
                )
                .unwrap();
                write_minimal_safetensors(
                    &target
                        .cache_path()
                        .join(crate::providers::whisper::SAFETENSORS_FILE),
                );
            }
            SttProviderKind::FasterWhisperLocal => {
                const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let snapshot = target.cache_path().join("snapshots").join(REVISION);
                std::fs::create_dir_all(&snapshot).unwrap();
                std::fs::create_dir_all(target.cache_path().join("refs")).unwrap();
                std::fs::write(target.cache_path().join("refs").join("main"), REVISION).unwrap();
                std::fs::write(snapshot.join("model.bin"), [0_u8; 16]).unwrap();
                std::fs::write(snapshot.join("config.json"), b"{}").unwrap();
                std::fs::write(snapshot.join("tokenizer.json"), b"{}").unwrap();
            }
            other => panic!("unexpected local Whisper target: {}", other.as_str()),
        }
    }

    #[test]
    fn candle_target_is_scoped_to_explicit_neoth_home() {
        let home = tempfile::tempdir().unwrap();
        let target = resolve_local_whisper_target(
            home.path(),
            SttProviderKind::WhisperRsLocal,
            WhisperModelSize::Small,
        )
        .unwrap();

        assert_eq!(target.model_id(), "openai/whisper-small");
        assert_eq!(
            target.cache_path(),
            home.path().join("models").join("openai-whisper-small")
        );
    }

    #[test]
    fn local_whisper_target_uses_exact_backend_repo_and_runtime_cache() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(dir.path(), Some(PathBuf::from("python-test")));

        let candle = resolve_local_whisper_target_with_runtime(
            SttProviderKind::WhisperRsLocal,
            WhisperModelSize::Small,
            runtime.clone(),
        )
        .unwrap();
        assert_eq!(candle.backend(), SttProviderKind::WhisperRsLocal);
        assert_eq!(candle.model_id(), "openai/whisper-small");
        assert_eq!(
            candle.cache_path(),
            runtime.candle_cache_root.join("openai-whisper-small")
        );
        assert!(!candle.cached());
        materialize_local_whisper_target(&candle);
        assert!(candle.cached(), "cached() must re-check after a pull");

        let faster = resolve_local_whisper_target_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            WhisperModelSize::Medium,
            runtime.clone(),
        )
        .unwrap();
        assert_eq!(faster.backend(), SttProviderKind::FasterWhisperLocal);
        assert_eq!(faster.model_id(), "Systran/faster-whisper-medium");
        assert_eq!(
            faster.cache_path(),
            runtime
                .faster_whisper_cache_root
                .join("models--Systran--faster-whisper-medium")
        );
        assert!(!faster.cached());
        materialize_local_whisper_target(&faster);
        assert!(faster.cached());
    }

    #[test]
    fn local_whisper_cache_health_rejects_corruption_and_unreferenced_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(dir.path(), Some(PathBuf::from("python-test")));
        let candle = resolve_local_whisper_target_with_runtime(
            SttProviderKind::WhisperRsLocal,
            WhisperModelSize::Small,
            runtime.clone(),
        )
        .unwrap();
        materialize_local_whisper_target(&candle);
        std::fs::write(
            candle
                .cache_path()
                .join(crate::providers::whisper::SAFETENSORS_FILE),
            b"truncated",
        )
        .unwrap();
        assert!(matches!(candle.cache_health(), CacheHealth::Corrupt { .. }));
        assert!(!candle.cached());

        let faster = resolve_local_whisper_target_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            WhisperModelSize::Small,
            runtime,
        )
        .unwrap();
        let unreferenced = faster.cache_path().join("snapshots").join("orphan");
        std::fs::create_dir_all(&unreferenced).unwrap();
        std::fs::write(unreferenced.join("model.bin"), [0_u8; 16]).unwrap();
        std::fs::write(unreferenced.join("config.json"), b"{}").unwrap();
        std::fs::write(unreferenced.join("tokenizer.json"), b"{}").unwrap();
        assert!(matches!(faster.cache_health(), CacheHealth::Missing { .. }));

        materialize_local_whisper_target(&faster);
        assert!(matches!(faster.cache_health(), CacheHealth::Ready));
        let active_snapshot = faster
            .cache_path()
            .join("snapshots")
            .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        std::fs::write(active_snapshot.join("config.json"), b"not-json").unwrap();
        assert!(matches!(faster.cache_health(), CacheHealth::Corrupt { .. }));
        assert!(!faster.cached());
    }

    #[test]
    fn local_whisper_target_rejects_cloud_backends_actionably() {
        let dir = tempfile::tempdir().unwrap();
        for backend in [
            SttProviderKind::OpenAiWhisperApi,
            SttProviderKind::AzureSpeech,
        ] {
            let error = resolve_local_whisper_target_with_runtime(
                backend,
                WhisperModelSize::Base,
                fake_runtime(dir.path(), None),
            )
            .unwrap_err();
            assert_eq!(error.class(), SttFailureClass::Permanent);
            let message = error.to_string();
            assert!(message.contains(backend.as_str()), "got: {message}");
            assert!(message.contains("whisper_rs_local"), "got: {message}");
            assert!(message.contains("faster_whisper_local"), "got: {message}");
        }
    }

    struct InjectedLocalWhisperPrefetchExecutor {
        materialize: bool,
        calls: std::sync::atomic::AtomicUsize,
        allow_network: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl LocalWhisperPrefetchExecutor for InjectedLocalWhisperPrefetchExecutor {
        async fn prefetch(
            &self,
            target: &LocalWhisperTarget,
            attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
        ) -> Result<(), SttFactoryError> {
            let allow_network = attempt.is_some_and(|attempt| {
                attempt.network_authorized(target.cache_path(), target.model_id())
            });
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.allow_network
                .store(allow_network, std::sync::atomic::Ordering::SeqCst);
            if self.materialize {
                materialize_local_whisper_target(target);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn local_whisper_prefetch_gates_then_rechecks_exact_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let target = resolve_local_whisper_target_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            WhisperModelSize::Tiny,
            fake_runtime(dir.path(), Some(PathBuf::from("python-test"))),
        )
        .unwrap();
        let mut blocked = crate::config::ops::UpdaterConfig::default();
        blocked.allow_huggingface_downloads = false;
        let executor = InjectedLocalWhisperPrefetchExecutor {
            materialize: true,
            calls: std::sync::atomic::AtomicUsize::new(0),
            allow_network: std::sync::atomic::AtomicBool::new(false),
        };
        let error = prefetch_local_whisper_with(&target, &blocked, None, &executor)
            .await
            .unwrap_err();
        assert_eq!(error.class(), SttFailureClass::Permanent);
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let incomplete = InjectedLocalWhisperPrefetchExecutor {
            materialize: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
            allow_network: std::sync::atomic::AtomicBool::new(false),
        };
        let error = prefetch_local_whisper_with(
            &target,
            &crate::config::ops::UpdaterConfig::default(),
            None,
            &incomplete,
        )
        .await
        .unwrap_err();
        assert_eq!(error.class(), SttFailureClass::Permanent);
        assert!(error.to_string().contains("confirmed durable D7"));
        assert_eq!(
            incomplete.calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn cached_local_whisper_prefetch_skips_gate_but_verifies_with_executor() {
        let dir = tempfile::tempdir().unwrap();
        let target = resolve_local_whisper_target_with_runtime(
            SttProviderKind::WhisperRsLocal,
            WhisperModelSize::Base,
            fake_runtime(dir.path(), None),
        )
        .unwrap();
        materialize_local_whisper_target(&target);
        let mut blocked = crate::config::ops::UpdaterConfig::default();
        blocked.allow_huggingface_downloads = false;
        let executor = InjectedLocalWhisperPrefetchExecutor {
            materialize: false,
            calls: std::sync::atomic::AtomicUsize::new(0),
            allow_network: std::sync::atomic::AtomicBool::new(true),
        };

        let error = prefetch_local_whisper_with(&target, &blocked, None, &executor)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("confirmed durable D7"));
        assert_eq!(executor.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            !executor
                .allow_network
                .load(std::sync::atomic::Ordering::SeqCst),
            "a complete cache must be verified strictly offline"
        );
    }

    #[test]
    fn candle_plan_is_side_effect_free_and_honors_idle_unload() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(dir.path(), None);
        let mut media = crate::config::MediaConfig::default();
        media.stt.model_size = WhisperModelSize::Small;
        media.whisper_idle_unload_secs = Some(37);
        let allowed = plan_candle_provider(&media, &runtime);
        assert_eq!(allowed.model_id, "openai/whisper-small");
        assert_eq!(allowed.idle_unload_secs, Some(37));
        assert_eq!(
            allowed.cache_path,
            runtime.candle_cache_root.join("openai-whisper-small")
        );
    }

    #[tokio::test]
    async fn model_download_lifecycle_uses_the_caller_wal_directly() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("model-download.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let cache = dir.path().join("cache");

        append_model_download_event(
            &writer,
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START,
            "openai/whisper-base",
            None,
        )
        .await
        .unwrap();
        append_model_download_event(
            &writer,
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
            "openai/whisper-base",
            Some((&cache, 42)),
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;

        let events = read_model_download_events(&segment);
        assert!(events.iter().all(|(_, payload)| {
            payload["model_id"] == "openai/whisper-base" && payload["trigger"] == "implicit"
        }));
        assert_eq!(
            events
                .iter()
                .map(|(event_type, payload)| (*event_type, payload["status"].as_str().unwrap()))
                .collect::<Vec<_>>(),
            vec![
                (
                    crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START,
                    "started",
                ),
                (
                    crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
                    "ready",
                ),
            ]
        );
        assert_eq!(
            require_model_download_writer(true, None)
                .unwrap_err()
                .class(),
            SttFailureClass::Permanent
        );
    }

    #[tokio::test]
    async fn model_download_failure_closes_started_lifecycle_with_terminal_d8() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("model-download-failed.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        append_model_download_event(
            &writer,
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START,
            "openai/whisper-base",
            None,
        )
        .await
        .unwrap();
        append_model_download_failure(
            &writer,
            "openai/whisper-base",
            43,
            "post-download validation failed",
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;

        let events = read_model_download_events(&segment);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].0,
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START
        );
        assert_eq!(events[0].1["status"], "started");
        assert_eq!(
            events[1].0,
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE
        );
        assert_eq!(events[1].1["status"], "failed");
        assert_eq!(events[1].1["reason"], "post-download validation failed");
    }

    #[test]
    fn faster_whisper_plan_is_fail_closed_or_explicitly_offline() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(dir.path(), Some(PathBuf::from("faster-whisper-test")));
        let mut media = crate::config::MediaConfig::default();
        media.stt.model_size = WhisperModelSize::Small;
        let mut updater = crate::config::ops::UpdaterConfig::default();
        updater.allow_huggingface_downloads = false;

        let blocked = plan_faster_whisper_provider(&media, &updater, &runtime).unwrap();
        assert!(!blocked.updater_cfg.allow_huggingface_downloads);

        let allowed = plan_faster_whisper_provider(
            &media,
            &crate::config::ops::UpdaterConfig::default(),
            &runtime,
        )
        .unwrap();
        assert!(
            !allowed
                .shared_ready
                .load(std::sync::atomic::Ordering::Acquire),
            "cache miss must remain unvalidated until the shared prefetch lifecycle"
        );

        let target = resolve_local_whisper_target_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            WhisperModelSize::Small,
            runtime.clone(),
        )
        .unwrap();
        materialize_local_whisper_target(&target);
        let provider = plan_faster_whisper_provider(&media, &updater, &runtime).unwrap();
        assert!(
            !provider
                .shared_ready
                .load(std::sync::atomic::Ordering::Acquire),
            "structural cache presence alone must not claim backend readiness"
        );
        assert_eq!(
            provider.model_id(),
            Some("Systran/faster-whisper-small".to_string())
        );

        let missing_exe = fake_runtime(dir.path(), None);
        let error = plan_faster_whisper_provider(&media, &updater, &missing_exe).unwrap_err();
        assert_eq!(error.class(), SttFailureClass::Retryable);
    }

    struct InjectedPythonProbe {
        result: Result<(), SttFactoryError>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl FasterWhisperPythonProbe for InjectedPythonProbe {
        async fn verify(
            &self,
            python: &Path,
            _explicitly_configured: bool,
        ) -> Result<(), SttFactoryError> {
            assert_eq!(python, Path::new("python-test"));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn faster_whisper_factory_uses_injected_python_module_probe() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = fake_runtime(dir.path(), Some(PathBuf::from("python-test")));
        let mut media = crate::config::MediaConfig::default();
        media.stt.model_size = WhisperModelSize::Tiny;
        let target = resolve_local_whisper_target_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            WhisperModelSize::Tiny,
            runtime.clone(),
        )
        .unwrap();
        materialize_local_whisper_target(&target);
        let updater = crate::config::ops::UpdaterConfig::default();
        let probe = InjectedPythonProbe {
            result: Ok(()),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let provider = make_stt_provider_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            None,
            None,
            &media,
            &updater,
            None,
            &runtime,
            &probe,
        )
        .await
        .unwrap();
        assert_eq!(provider.kind(), SttProviderKind::FasterWhisperLocal);
        assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let unavailable = InjectedPythonProbe {
            result: Err(SttFactoryError::retryable(
                "Python cannot import faster_whisper",
            )),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let error = make_stt_provider_with_runtime(
            SttProviderKind::FasterWhisperLocal,
            None,
            None,
            &media,
            &updater,
            None,
            &runtime,
            &unavailable,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.class(), SttFailureClass::Retryable);
        assert_eq!(
            unavailable.calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn python_bridge_pins_local_only_and_jsonl_contract() {
        assert!(FASTER_WHISPER_PYTHON_BRIDGE.contains("from faster_whisper import WhisperModel"));
        assert!(FASTER_WHISPER_PYTHON_BRIDGE.contains("local_files_only="));
        assert!(FASTER_WHISPER_PYTHON_BRIDGE.contains("download_root=cache_root"));
        assert!(FASTER_WHISPER_PYTHON_BRIDGE.contains("mode == \"prefetch\""));
        assert_eq!(
            FASTER_WHISPER_PYTHON_BRIDGE
                .match_indices("WhisperModel(")
                .count(),
            1,
            "prefetch and transcription must share one model-load path"
        );
        assert!(FASTER_WHISPER_PYTHON_BRIDGE.contains("json.dumps"));
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
        ) -> Result<TranscriptionResult, SttProviderError> {
            Ok(TranscriptionResult {
                text: "hello there".into(), // 11 chars
                segments: vec![],
                language: "en".into(),
                confidence: None,
                speaker_labels: Vec::new(),
                provider: String::new(),
            })
        }
    }

    struct SegmentedLocalMockStt;

    #[async_trait]
    impl SttProviderImpl for SegmentedLocalMockStt {
        fn kind(&self) -> SttProviderKind {
            SttProviderKind::WhisperRsLocal
        }

        async fn transcribe(
            &self,
            _audio: &[u8],
            _request: &TranscriptionRequest,
        ) -> Result<TranscriptionResult, SttProviderError> {
            Ok(TranscriptionResult {
                text: "two segments".into(),
                segments: vec![
                    TextSegment {
                        start_ms: 0,
                        end_ms: 1_000,
                        text: "two".into(),
                    },
                    TextSegment {
                        start_ms: 1_000,
                        end_ms: 2_000,
                        text: "segments".into(),
                    },
                ],
                language: "en".into(),
                confidence: None,
                speaker_labels: Vec::new(),
                provider: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn speaker_labels_use_supplied_home_and_serialize_aligned_results() {
        let mut media_cfg = crate::config::MediaConfig::default();
        media_cfg.auto_speaker_labels = true;
        let mut request = req("en");
        request.format = AudioFormat::WavPcmS16leMono;
        let samples: Vec<f32> = (0..32_000)
            .map(|i| (2.0 * std::f32::consts::PI * 220.0 * i as f32 / 16_000.0).sin())
            .collect();
        let audio = pcm_f32_to_wav(&samples).unwrap();
        let neoth_home = test_neoth_home();

        let result = transcribe_and_audit(
            &SegmentedLocalMockStt,
            &audio,
            &request,
            None,
            &media_cfg,
            neoth_home.path(),
        )
        .await
        .unwrap();

        assert_eq!(result.speaker_labels.len(), 2);
        let serialized = serde_json::to_value(&result).unwrap();
        assert_eq!(serialized["speaker_labels"].as_array().unwrap().len(), 2);
        assert!(
            crate::media::speaker_profile::profiles_path(neoth_home.path()).exists(),
            "speaker profiles must persist under the caller-supplied NEOTH home"
        );
    }

    // ── FasterWhisperProvider surface ────────────────────────────

    #[test]
    fn faster_whisper_provider_is_local() {
        assert!(SttProviderKind::FasterWhisperLocal.is_local());
        assert!(!SttProviderKind::FasterWhisperLocal.requires_credentials());
    }

    #[test]
    fn pcm_bytes_to_wav_produces_valid_riff_header() {
        // 100 f32 samples of silence
        let samples: Vec<f32> = vec![0.0_f32; 100];
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let wav = pcm_bytes_to_wav(&bytes).unwrap();
        assert!(wav.starts_with(b"RIFF"), "WAV must start with RIFF");
        assert_eq!(&wav[8..12], b"WAVE", "WAVE marker must be present");
        assert_eq!(&wav[12..16], b"fmt ", "fmt chunk must be present");
        // 44-byte header + 2 bytes/sample * 100 samples = 244 total.
        assert_eq!(wav.len(), 44 + 100 * 2);
    }

    #[test]
    fn pcm_bytes_to_wav_rejects_odd_and_non_finite_pcm() {
        assert_eq!(
            pcm_bytes_to_wav(&[0, 1, 2]),
            Err(PcmEncodingError::MisalignedF32Bytes { len: 3 })
        );
        assert_eq!(
            pcm_bytes_to_wav(&f32::NAN.to_le_bytes()),
            Err(PcmEncodingError::NonFiniteSample { index: 0 })
        );
    }

    #[test]
    fn parse_faster_whisper_output_empty() {
        let (text, segs) = parse_faster_whisper_output(b"");
        assert!(text.is_empty());
        assert!(segs.is_empty());
    }

    #[test]
    fn parse_faster_whisper_output_single_segment() {
        let jsonl = br#"{"text": "hello world", "start": 0.0, "end": 1.5}"#;
        let (text, segs) = parse_faster_whisper_output(jsonl);
        assert_eq!(text, "hello world");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].start_ms, 0);
        assert_eq!(segs[0].end_ms, 1500);
        assert_eq!(segs[0].text, "hello world");
    }

    #[test]
    fn parse_faster_whisper_output_multiple_segments_joined() {
        let jsonl = b"{\"text\": \"hello\", \"start\": 0.0, \"end\": 1.0}\n{\"text\": \"world\", \"start\": 1.0, \"end\": 2.0}\n";
        let (text, segs) = parse_faster_whisper_output(jsonl);
        assert_eq!(text, "hello world");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn parse_faster_whisper_output_skips_malformed_lines() {
        let jsonl = b"{\"text\": \"ok\", \"start\": 0.0, \"end\": 1.0}\nnot-json\n";
        let (text, segs) = parse_faster_whisper_output(jsonl);
        assert_eq!(text, "ok");
        assert_eq!(segs.len(), 1);
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
        let neoth_home = test_neoth_home();
        let audio = vec![0u8; 16];
        let mut required = cloud_on();
        required.required_audit_for_cloud_media = true;
        let err = transcribe_and_audit(
            &MockStt,
            &audio,
            &req("en"),
            None,
            &required,
            neoth_home.path(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("required_audit_for_cloud_media"),
            "got: {err}"
        );
        // Without required-audit, a writerless call still transcribes (best-effort).
        assert!(
            transcribe_and_audit(
                &MockStt,
                &audio,
                &req("en"),
                None,
                &cloud_on(),
                neoth_home.path(),
            )
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
        let mut media_cfg = cloud_on();
        media_cfg.required_audit_for_cloud_media = true;
        let out = transcribe_and_audit(
            &MockStt,
            &audio,
            &req("en"),
            Some(&writer),
            &media_cfg,
            dir.path(),
        )
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

    #[tokio::test]
    async fn required_audit_never_reports_success_on_closed_writer() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) = crate::wal::writer::spawn(dir.path().join("closed.wal")).unwrap();
        join.abort();
        let _ = join.await;

        let mut required = cloud_on();
        required.required_audit_for_cloud_media = true;
        let error = transcribe_and_audit(
            &MockStt,
            &[0u8; 16],
            &req("en"),
            Some(&writer),
            &required,
            dir.path(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.class(), SttFailureClass::Permanent);
        assert!(
            error
                .to_string()
                .contains("required STT audit append failed")
        );

        let best_effort = transcribe_and_audit(
            &MockStt,
            &[0u8; 16],
            &req("en"),
            Some(&writer),
            &cloud_on(),
            dir.path(),
        )
        .await;
        assert!(best_effort.is_ok());
    }

    // ── B20: dispatch_transcription unit tests ────────────────────

    #[derive(Clone)]
    enum InjectedProviderOutcome {
        Success,
        Error(SttProviderError),
    }

    struct InjectedProvider {
        kind: SttProviderKind,
        outcome: InjectedProviderOutcome,
    }

    #[async_trait]
    impl SttProviderImpl for InjectedProvider {
        fn kind(&self) -> SttProviderKind {
            self.kind
        }

        async fn transcribe(
            &self,
            _audio: &[u8],
            request: &TranscriptionRequest,
        ) -> Result<TranscriptionResult, SttProviderError> {
            match &self.outcome {
                InjectedProviderOutcome::Success => Ok(TranscriptionResult {
                    text: "injected transcript".into(),
                    segments: Vec::new(),
                    language: request.language.clone(),
                    confidence: None,
                    speaker_labels: Vec::new(),
                    provider: String::new(),
                }),
                InjectedProviderOutcome::Error(error) => Err(error.clone()),
            }
        }
    }

    #[derive(Clone)]
    enum InjectedFactoryOutcome {
        Provider(InjectedProviderOutcome),
        Error(SttFactoryError),
    }

    struct InjectedFactory {
        outcomes: std::collections::HashMap<SttProviderKind, InjectedFactoryOutcome>,
        calls: std::sync::Mutex<Vec<SttProviderKind>>,
    }

    impl InjectedFactory {
        fn new(
            outcomes: impl IntoIterator<Item = (SttProviderKind, InjectedFactoryOutcome)>,
        ) -> Self {
            Self {
                outcomes: outcomes.into_iter().collect(),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<SttProviderKind> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SttProviderFactory for InjectedFactory {
        async fn build(
            &self,
            kind: SttProviderKind,
        ) -> Result<Box<dyn SttProviderImpl>, SttFactoryError> {
            self.calls.lock().unwrap().push(kind);
            match self.outcomes.get(&kind).cloned().unwrap_or_else(|| {
                InjectedFactoryOutcome::Error(SttFactoryError::permanent(
                    "no injected provider plan",
                ))
            }) {
                InjectedFactoryOutcome::Provider(outcome) => {
                    Ok(Box::new(InjectedProvider { kind, outcome }))
                }
                InjectedFactoryOutcome::Error(error) => Err(error),
            }
        }
    }

    fn wav_fixture() -> Vec<u8> {
        pcm_bytes_to_wav(&[]).unwrap()
    }

    #[tokio::test]
    async fn retryable_primary_factory_failure_reaches_fallback_once() {
        let primary = SttProviderKind::FasterWhisperLocal;
        let fallback = SttProviderKind::WhisperRsLocal;
        let factory = InjectedFactory::new([
            (
                primary,
                InjectedFactoryOutcome::Error(SttFactoryError::retryable(
                    "local executable unavailable",
                )),
            ),
            (
                fallback,
                InjectedFactoryOutcome::Provider(InjectedProviderOutcome::Success),
            ),
        ]);
        let stt_cfg = crate::media::stt_dispatch::MediaSttConfig {
            primary,
            fallback: Some(fallback),
            ..Default::default()
        };
        let media_cfg = crate::config::MediaConfig::default();
        let neoth_home = test_neoth_home();

        let result = dispatch_transcription_with_factory(
            &stt_cfg,
            &media_cfg,
            neoth_home.path(),
            &wav_fixture(),
            None,
            &factory,
        )
        .await
        .unwrap();

        assert_eq!(result.provider, fallback.as_str());
        assert_eq!(factory.calls(), vec![primary, fallback]);
    }

    #[tokio::test]
    async fn permanent_primary_factory_failure_never_builds_fallback() {
        let primary = SttProviderKind::OpenAiWhisperApi;
        let fallback = SttProviderKind::WhisperRsLocal;
        let factory = InjectedFactory::new([
            (
                primary,
                InjectedFactoryOutcome::Error(SttFactoryError::permanent("credential missing")),
            ),
            (
                fallback,
                InjectedFactoryOutcome::Provider(InjectedProviderOutcome::Success),
            ),
        ]);
        let stt_cfg = crate::media::stt_dispatch::MediaSttConfig {
            primary,
            fallback: Some(fallback),
            ..Default::default()
        };
        let media_cfg = crate::config::MediaConfig::default();
        let neoth_home = test_neoth_home();

        let error = dispatch_transcription_with_factory(
            &stt_cfg,
            &media_cfg,
            neoth_home.path(),
            &wav_fixture(),
            None,
            &factory,
        )
        .await
        .unwrap_err();

        assert!(error.contains("failed permanently"));
        assert!(error.contains("credential missing"));
        assert_eq!(factory.calls(), vec![primary]);
    }

    #[tokio::test]
    async fn fallback_factory_failure_is_surfaced_without_a_second_retry() {
        let primary = SttProviderKind::FasterWhisperLocal;
        let fallback = SttProviderKind::WhisperRsLocal;
        let factory = InjectedFactory::new([
            (
                primary,
                InjectedFactoryOutcome::Provider(InjectedProviderOutcome::Error(
                    SttProviderError::retryable("primary timeout"),
                )),
            ),
            (
                fallback,
                InjectedFactoryOutcome::Error(SttFactoryError::retryable(
                    "fallback model unavailable",
                )),
            ),
        ]);
        let stt_cfg = crate::media::stt_dispatch::MediaSttConfig {
            primary,
            fallback: Some(fallback),
            ..Default::default()
        };
        let neoth_home = test_neoth_home();

        let error = dispatch_transcription_with_factory(
            &stt_cfg,
            &crate::config::MediaConfig::default(),
            neoth_home.path(),
            &wav_fixture(),
            None,
            &factory,
        )
        .await
        .unwrap_err();

        assert!(error.contains("fallback model unavailable"));
        assert_eq!(factory.calls(), vec![primary, fallback]);
    }

    /// B20 regression: cloud is still blocked without cloud_stt_enabled=true,
    /// even when dispatch_transcription is called directly. Complements the
    /// existing cloud_kind_refused_when_flag_off factory test.
    #[tokio::test]
    async fn dispatch_transcription_cloud_primary_blocked_without_flag() {
        use crate::media::stt_dispatch::MediaSttConfig;

        let stt_cfg = MediaSttConfig {
            primary: SttProviderKind::OpenAiWhisperApi,
            ..Default::default()
        };
        let media_cfg = crate::config::MediaConfig::default(); // cloud off
        let updater_cfg = crate::config::ops::UpdaterConfig::default();
        let neoth_home = test_neoth_home();
        let wav = pcm_bytes_to_wav(&[]).unwrap();

        let err = dispatch_transcription(
            &stt_cfg,
            &media_cfg,
            &updater_cfg,
            neoth_home.path(),
            &wav,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("cloud_stt_enabled"),
            "cloud primary must be blocked by gate; got: {err}"
        );
        assert!(
            err.contains("LEAVES the device"),
            "error must warn about audio leaving the device; got: {err}"
        );
    }

    #[test]
    fn canonical_pcm_preparation_validates_empty_rate_and_nan() {
        assert!(matches!(
            prepare_pcm_f32_wav(&[], 16_000),
            Err(PcmSttError::EmptyInput)
        ));
        assert!(matches!(
            prepare_pcm_f32_wav(&[0.1], 0),
            Err(PcmSttError::Resample(
                crate::media::resampler::ResampleError::InvalidSourceRate(0)
            ))
        ));
        assert!(matches!(
            prepare_pcm_f32_wav(&[0.1, f32::NAN], 16_000),
            Err(PcmSttError::Resample(
                crate::media::resampler::ResampleError::NonFiniteSample { index: 1 }
            ))
        ));
    }

    #[tokio::test]
    async fn dispatch_pcm_f32_rejects_invalid_input_before_provider_setup() {
        let stt_cfg = crate::media::stt_dispatch::MediaSttConfig::default();
        let media_cfg = crate::config::MediaConfig::default();
        let updater_cfg = crate::config::ops::UpdaterConfig::default();
        let neoth_home = test_neoth_home();

        assert!(matches!(
            dispatch_pcm_f32(
                &stt_cfg,
                &media_cfg,
                &updater_cfg,
                neoth_home.path(),
                &[],
                16_000,
                None,
            )
            .await,
            Err(PcmSttError::EmptyInput)
        ));
        assert!(matches!(
            dispatch_pcm_f32(
                &stt_cfg,
                &media_cfg,
                &updater_cfg,
                neoth_home.path(),
                &[0.1],
                0,
                None,
            )
            .await,
            Err(PcmSttError::Resample(
                crate::media::resampler::ResampleError::InvalidSourceRate(0)
            ))
        ));
        assert!(matches!(
            dispatch_pcm_f32(
                &stt_cfg,
                &media_cfg,
                &updater_cfg,
                neoth_home.path(),
                &[f32::NAN],
                16_000,
                None
            )
            .await,
            Err(PcmSttError::Resample(
                crate::media::resampler::ResampleError::NonFiniteSample { index: 0 }
            ))
        ));
    }

    #[test]
    fn canonical_pcm_preparation_resamples_to_16k_wav() {
        let input = vec![0.25f32; 8_000];
        let wav = prepare_pcm_f32_wav(&input, 8_000).expect("valid 8 kHz PCM");

        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(u32::from_le_bytes(wav[24..28].try_into().unwrap()), 16_000);
        let data_len = u32::from_le_bytes(wav[40..44].try_into().unwrap()) as usize;
        let sample_count = data_len / 2;
        assert!(
            (15_900..=16_100).contains(&sample_count),
            "one second at 8 kHz must become about 16k samples, got {sample_count}"
        );
        assert_eq!(wav.len(), 44 + data_len);
    }
}
