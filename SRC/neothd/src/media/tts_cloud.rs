//! MM-03b — canonical TTS factory, audited dispatch, and cloud clients.
//!
//! Both implement the [`super::tts_provider::TtsProvider`] trait alongside the
//! shipped [`super::tts_provider::SystemNativeProvider`], and a
//! [`make_tts_provider_at`] bridges a [`TtsProviderKind`] + operator creds
//! to a live `Box<dyn TtsProvider>` the dispatcher can `synth` through.
//!
//! ## Network-guard posture
//!
//! No provider constructs a `reqwest::Client` directly. Credential-bearing
//! public requests use the shared no-redirect builder; trusted local/private
//! ViitorVoice requests additionally bypass proxies. The endpoints are either
//! fixed vendor origins or an explicitly configured URL that passes the
//! HTTPS/private-self-hosted validator.
//!
//! Piper is a native subprocess provider over an operator-supplied ONNX voice;
//! the factory never downloads model bytes. Edge is also a subprocess but is
//! classified as cloud egress because it calls Microsoft's online service.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::tts_dispatch::{TtsFormat, TtsProvider as TtsProviderKind, TtsRequest, TtsResponse};
use super::tts_provider::{EdgeTtsProvider, PiperProvider, SystemNativeProvider, TtsProvider};
use crate::providers::http_client;
use crate::secret::SecretString;

/// Map a [`TtsFormat`] to Azure's `X-Microsoft-OutputFormat` header value
/// (24 kHz mono — Azure's standard neural-voice rates). PURE.
fn azure_output_format(fmt: TtsFormat) -> &'static str {
    match fmt {
        TtsFormat::Wav => "riff-24khz-16bit-mono-pcm",
        TtsFormat::PcmS16le => "raw-24khz-16bit-mono-pcm",
        TtsFormat::Mp3 => "audio-24khz-48kbitrate-mono-mp3",
        TtsFormat::Opus => "ogg-24khz-16bit-mono-opus",
    }
}

/// Escape a text run for inclusion in an SSML element (RFC: XML 1.0 §2.4).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the SSML body Azure's `cognitiveservices/v1` endpoint expects. PURE.
fn azure_ssml(req: &TtsRequest) -> String {
    let lang = if req.locale.is_empty() {
        "en-US"
    } else {
        &req.locale
    };
    format!(
        "<speak version='1.0' xml:lang='{lang}'><voice name='{voice}'>{text}</voice></speak>",
        lang = xml_escape(lang),
        voice = xml_escape(&req.voice_id),
        text = xml_escape(&req.text),
    )
}

fn validate_azure_region(region: &str) -> Result<(), String> {
    let bytes = region.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(
            "azure tts region must be a single ASCII DNS label (letters, digits, hyphens)"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_elevenlabs_voice_id(voice_id: &str) -> Result<(), String> {
    if voice_id.is_empty()
        || voice_id.len() > 128
        || !voice_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            "elevenlabs voice id must contain only ASCII letters, digits, '-' or '_'".to_string(),
        );
    }
    Ok(())
}

/// Validate and canonicalise the operator-configured ViitorVoice base URL.
/// Public hosts require HTTPS. Plain HTTP is accepted only for the same
/// loopback/private/CGNAT/ULA address policy used by the self-hosted OMI
/// endpoint guard. URL userinfo, query strings, and fragments are rejected so
/// neither reference audio nor future credentials can be redirected or
/// smuggled into an ambiguous target.
fn validate_viitor_endpoint(raw: &str) -> Result<(url::Url, bool), String> {
    if raw.is_empty() || raw.trim() != raw {
        return Err(
            "viitor_voice endpoint must be a non-empty URL without outer whitespace".into(),
        );
    }
    let mut parsed = url::Url::parse(raw)
        .map_err(|error| format!("invalid viitor_voice endpoint {raw:?}: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("viitor_voice endpoint must use http:// or https://".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("viitor_voice endpoint must not contain URL userinfo".into());
    }
    parsed
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| "viitor_voice endpoint has an empty host".to_string())?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("viitor_voice endpoint must not contain a query or fragment".into());
    }

    let direct = crate::installers::omi::is_local_endpoint(raw).is_ok();
    if parsed.scheme() == "http" && !direct {
        return Err(
            "public viitor_voice endpoints must use https://; http:// is allowed only for explicit loopback/private self-hosted addresses"
                .into(),
        );
    }

    let base_path = parsed.path().trim_end_matches('/');
    let clone_path = if base_path.is_empty() {
        "/v1/voice-clone".to_string()
    } else {
        format!("{base_path}/v1/voice-clone")
    };
    parsed.set_path(&clone_path);
    Ok((parsed, direct))
}

/// Azure Cognitive Services neural TTS (REST). Auth: `Ocp-Apim-Subscription-Key`.
struct AzureTtsClient {
    region: String,
    api_key: SecretString,
    /// Validated Azure service origin derived from `region`.
    base_url: String,
}

impl AzureTtsClient {
    fn new(region: impl Into<String>, api_key: SecretString) -> Result<Self, String> {
        let region = region.into();
        validate_azure_region(&region)?;
        let base_url = format!("https://{region}.tts.speech.microsoft.com");
        Ok(Self {
            region,
            api_key,
            base_url,
        })
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/cognitiveservices/v1",
            self.base_url.trim_end_matches('/')
        )
    }
}

#[async_trait]
impl TtsProvider for AzureTtsClient {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::AzureTts
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        let client =
            http_client::build_client_no_redirect().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(self.endpoint())
            .header("Ocp-Apim-Subscription-Key", self.api_key.expose())
            .header("Content-Type", "application/ssml+xml")
            .header(
                "X-Microsoft-OutputFormat",
                azure_output_format(request.format),
            )
            .header("User-Agent", "neoth")
            .body(azure_ssml(request))
            .send()
            .await
            .map_err(|e| format!("azure tts request ({}): {e}", self.region))?;
        if !resp.status().is_success() {
            return Err(format!("azure tts returned HTTP {}", resp.status()));
        }
        let audio_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("azure tts body: {e}"))?
            .to_vec();
        Ok(TtsResponse {
            audio_bytes,
            format: request.format,
            duration_ms: 0, // unknown without decoding the returned audio
        })
    }
}

/// ElevenLabs TTS (REST). Auth: `xi-api-key`. Returns MP3 by default.
struct ElevenLabsClient {
    api_key: SecretString,
    /// `https://api.elevenlabs.io` by default; overridable for tests.
    base_url: String,
}

impl ElevenLabsClient {
    fn new(api_key: SecretString) -> Self {
        Self {
            api_key,
            base_url: "https://api.elevenlabs.io".to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn endpoint(&self, voice_id: &str) -> Result<String, String> {
        validate_elevenlabs_voice_id(voice_id)?;
        Ok(format!(
            "{}/v1/text-to-speech/{}",
            self.base_url.trim_end_matches('/'),
            voice_id
        ))
    }
}

#[async_trait]
impl TtsProvider for ElevenLabsClient {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::ElevenLabs
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        let endpoint = self.endpoint(&request.voice_id)?;
        let client =
            http_client::build_client_no_redirect().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(endpoint)
            .header("xi-api-key", self.api_key.expose())
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "text": request.text,
                "model_id": "eleven_multilingual_v2",
                "voice_settings": { "stability": 0.5, "similarity_boost": 0.75 },
            }))
            .send()
            .await
            .map_err(|e| format!("elevenlabs request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("elevenlabs returned HTTP {}", resp.status()));
        }
        let audio_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("elevenlabs body: {e}"))?
            .to_vec();
        // ElevenLabs returns MP3 regardless of the requested PCM/WAV; report Mp3
        // so the caller writes the right extension.
        Ok(TtsResponse {
            audio_bytes,
            format: TtsFormat::Mp3,
            duration_ms: 0,
        })
    }
}

/// GOLD-ADAPT-SYS-02 — ViitorVoice voice-cloning sidecar client. POSTs a
/// reference-audio sample (the request's `voice_id` is its file path) + the
/// text as `multipart/form-data` to a self-hosted `{endpoint}/v1/voice-clone`
/// (the viitor-voice-nar gateway) and returns the synthesised audio in the
/// cloned voice. The endpoint is validated before the reference file is read,
/// and its no-redirect client prevents a sidecar from bouncing that file to a
/// different origin.
struct ViitorVoiceClient {
    clone_url: url::Url,
    direct: bool,
}

impl ViitorVoiceClient {
    fn new(endpoint: impl AsRef<str>) -> Result<Self, String> {
        let (clone_url, direct) = validate_viitor_endpoint(endpoint.as_ref())?;
        Ok(Self { clone_url, direct })
    }

    fn clone_url(&self) -> &url::Url {
        &self.clone_url
    }
}

#[async_trait]
impl TtsProvider for ViitorVoiceClient {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::ViitorVoice
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        // The voice to clone is the request's voice_id (a reference-audio path).
        let ref_path = request.voice_id.trim();
        if ref_path.is_empty() {
            return Err(
                "viitor_voice requires a reference-audio path in voice_id (the voice to clone)"
                    .to_string(),
            );
        }
        let ref_bytes = tokio::fs::read(ref_path)
            .await
            .map_err(|e| format!("viitor_voice: read reference audio {ref_path}: {e}"))?;
        let file_name = std::path::Path::new(ref_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("ref_audio.wav")
            .to_string();

        let client = if self.direct {
            http_client::build_direct_client_no_redirect()
        } else {
            http_client::build_client_no_redirect()
        }
        .map_err(|e| format!("http client: {e}"))?;
        let form = reqwest::multipart::Form::new()
            .text("text", request.text.clone())
            .part(
                "ref_audio",
                reqwest::multipart::Part::bytes(ref_bytes).file_name(file_name),
            );
        let resp = client
            .post(self.clone_url().clone())
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("viitor_voice request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("viitor_voice returned HTTP {}", resp.status()));
        }
        let audio_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("viitor_voice body: {e}"))?
            .to_vec();
        // The gateway echoes the requested container; report what we asked for.
        Ok(TtsResponse {
            audio_bytes,
            format: request.format,
            duration_ms: 0,
        })
    }
}

/// MM-03b bridge: build a live TTS provider for `kind` from operator creds.
/// The first config → `Box<dyn TtsProvider>` factory; the dispatcher decides
/// WHICH kind, this turns that decision into a synthesiser.
///
/// `api_key` is required for the selected credentialed cloud provider;
/// `azure_region` additionally for Azure. Piper reads only operator-provided
/// files under `~/.neoth/models/piper`.
#[cfg(test)]
fn make_tts_provider(
    kind: TtsProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    viitor_endpoint: Option<String>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<Box<dyn TtsProvider>, String> {
    make_tts_provider_at(
        &crate::config::FreedomConfig::default_neoth_home(),
        kind,
        api_key,
        azure_region,
        viitor_endpoint,
        media_cfg,
    )
}

/// Home-scoped provider factory. All local model discovery is rooted below the
/// explicit NEOTH home; the function is private so external providers cannot
/// be obtained and invoked around the canonical permission/WAL boundary.
fn make_tts_provider_at(
    neoth_home: &std::path::Path,
    kind: TtsProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    viitor_endpoint: Option<String>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<Box<dyn TtsProvider>, String> {
    // P0 ENFORCEMENT — a CLOUD TTS provider sends the text-to-speak to a third
    // party. It may only be constructed when the operator opted in
    // (`media.cloud_tts_enabled`). The safe-mode rail makes this visible; this
    // gate makes it REAL. Guaranteed-local engines pass.
    if !kind.is_local() && !media_cfg.cloud_tts_enabled {
        return Err(format!(
            "cloud TTS ({}) is disabled — set media.cloud_tts_enabled: true to send \
             the spoken text to a cloud voice (your text then LEAVES the device)",
            kind.as_str()
        ));
    }
    match kind {
        TtsProviderKind::SystemNative => Ok(Box::new(SystemNativeProvider::new())),
        // JV-VOICE-01 — the executable is local, but it sends text to
        // Microsoft's online Edge speech service. `is_local()` therefore stays
        // false and the cloud_tts_enabled gate above applies. No API key is
        // required; the `edge-tts` CLI must be installed on PATH.
        TtsProviderKind::EdgeTts => Ok(Box::new(EdgeTtsProvider::new())),
        TtsProviderKind::ElevenLabs => {
            let key = api_key.ok_or("elevenlabs requires an api key")?;
            Ok(Box::new(ElevenLabsClient::new(key)))
        }
        TtsProviderKind::AzureTts => {
            let key = api_key.ok_or("azure tts requires an api key")?;
            let region = azure_region.ok_or("azure tts requires a region")?;
            Ok(Box::new(AzureTtsClient::new(region, key)?))
        }
        // GOLD-ADAPT-SYS-02 — voice-cloning sidecar. Not local (is_local()==false),
        // so the P0 cloud_tts_enabled gate above already applies. No API key —
        // the self-hosted gateway is reached by URL; the reference voice sample
        // is the request's voice_id path.
        TtsProviderKind::ViitorVoice => {
            let ep = viitor_endpoint
                .ok_or("viitor_voice requires an endpoint (the viitor-voice-nar gateway URL)")?;
            Ok(Box::new(ViitorVoiceClient::new(ep)?))
        }
        TtsProviderKind::Piper => Ok(Box::new(PiperProvider::new(
            neoth_home.join("models/piper"),
            media_cfg.tts.piper_model.clone(),
            media_cfg.tts.piper_config.clone(),
        )?)),
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct TtsAuditBase {
    invocation_id: String,
    provider: String,
    destination: String,
    request_binding_sha256: String,
    input_hash: String,
    input_bytes: usize,
    sends_reference_audio: bool,
}

/// Typed lifecycle written under the existing 0xCD TTS event code. Payloads
/// are metadata-only: neither spoken text, credentials, nor a reference-audio
/// path is ever serialized.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum TtsAuditEvent {
    Intent {
        #[serde(flatten)]
        base: TtsAuditBase,
        ts_unix: u64,
    },
    Success {
        #[serde(flatten)]
        base: TtsAuditBase,
        audio_bytes: usize,
        ts_unix: u64,
    },
    Failure {
        #[serde(flatten)]
        base: TtsAuditBase,
        error_class: &'static str,
        error_hash_sha256: String,
        ts_unix: u64,
    },
}

/// Canonical provider-call choke point. Every production TTS caller reaches
/// this function immediately before the provider's HTTP request (or Edge-TTS
/// subprocess egress). External providers require a durable Intent before the
/// call and a durable Success/Failure afterwards; an unavailable WAL fails
/// closed before any text or reference audio can leave the device.
async fn synth_and_audit(
    provider: &dyn TtsProvider,
    request: &TtsRequest,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    destination: &str,
) -> Result<TtsResponse, String> {
    if !provider.kind().is_local() && writer.is_none() {
        return Err(format!(
            "external TTS ({}) requires an available audit WAL before egress",
            provider.kind().as_str()
        ));
    }

    let base = tts_audit_base(provider.kind(), destination, request);
    if let Some(writer) = writer {
        append_tts_audit(
            writer,
            TtsAuditEvent::Intent {
                base: base.clone(),
                ts_unix: crate::time::now_unix_secs(),
            },
        )
        .await?;
    }

    let result = match provider.synth(request).await {
        Ok(response) if response.audio_bytes.is_empty() => {
            Err(format!("{} produced empty audio", provider.kind().as_str()))
        }
        Ok(response) if response.format != request.format => Err(format!(
            "{} returned {} but output requires {}; refusing mislabeled audio",
            provider.kind().as_str(),
            response.format.as_str(),
            request.format.as_str()
        )),
        other => other,
    };

    match result {
        Ok(response) => {
            if let Some(writer) = writer {
                append_tts_audit(
                    writer,
                    TtsAuditEvent::Success {
                        base,
                        audio_bytes: response.audio_bytes.len(),
                        ts_unix: crate::time::now_unix_secs(),
                    },
                )
                .await?;
            }
            Ok(response)
        }
        Err(error) => {
            if let Some(writer) = writer {
                let audit_result = append_tts_audit(
                    writer,
                    TtsAuditEvent::Failure {
                        base,
                        error_class: classify_tts_error(&error),
                        error_hash_sha256: hex::encode(Sha256::digest(error.as_bytes())),
                        ts_unix: crate::time::now_unix_secs(),
                    },
                )
                .await;
                if let Err(audit_error) = audit_result {
                    return Err(format!(
                        "{error}; required TTS failure audit could not be persisted: {audit_error}"
                    ));
                }
            }
            Err(error)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TtsConfirmMode {
    /// Operator-invoked CLI: use a TTY prompt when one is actually available.
    InteractiveCli,
    /// Daemon/tools/cron callers cannot synthesize through a Confirm decision.
    #[default]
    NonInteractive,
}

/// Per-invocation overrides for the canonical TTS path. Secret values never
/// enter `freedom.yaml`; the optional key is an ephemeral CLI override.
#[derive(Default)]
pub struct TtsRunOverrides {
    pub provider: Option<TtsProviderKind>,
    pub voice: Option<String>,
    pub locale: Option<String>,
    pub piper_model: Option<std::path::PathBuf>,
    pub piper_config: Option<std::path::PathBuf>,
    pub api_key: Option<SecretString>,
    pub confirm_mode: TtsConfirmMode,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TtsFileResult {
    pub provider: String,
    pub voice: String,
    pub bytes: usize,
    pub mime: String,
    pub duration_ms: u32,
    pub out_path: String,
}

/// Canonical production entry point used by both `neoth tts speak` and the
/// deprecated `tools::tts` compatibility layer. It performs provider dispatch,
/// cloud consent, credential resolution, metadata-only audit, response-format
/// validation, fallback, and a crash-safe atomic output commit.
pub async fn synthesize_to_file_at(
    neoth_home: &std::path::Path,
    config: &crate::config::FreedomConfig,
    credentials: &crate::config::credentials::Credentials,
    text: String,
    format: TtsFormat,
    out_path: &std::path::Path,
    overrides: TtsRunOverrides,
) -> Result<TtsFileResult, String> {
    let confirm_mode = overrides.confirm_mode;
    let mut media = config.media.clone();
    if let Some(provider) = overrides.provider {
        media.tts.primary = provider;
    }
    if let Some(voice) = overrides.voice {
        media.tts.voice = voice;
    }
    if let Some(locale) = overrides.locale {
        media.tts.locale = locale;
    }
    if let Some(model) = overrides.piper_model {
        media.tts.piper_model = Some(model);
    }
    if let Some(config_path) = overrides.piper_config {
        media.tts.piper_config = Some(config_path);
    }

    let request = TtsRequest {
        text,
        voice_id: effective_voice(media.tts.primary, &media.tts.locale, &media.tts.voice),
        locale: media.tts.locale.clone(),
        format,
        sample_rate_hz: 22_050,
    };
    let kind = match super::tts_dispatch::dispatch(&media.tts, &request) {
        super::tts_dispatch::DispatchDecision::Use(kind) => kind,
        super::tts_dispatch::DispatchDecision::Reject { reason } => return Err(reason),
    };

    let external_provider_may_run = !kind.is_local()
        || media
            .tts
            .fallback
            .is_some_and(|fallback| !fallback.is_local());
    let audit = open_tts_audit_writer(neoth_home, external_provider_may_run)?;
    let writer = audit.as_ref().map(|(writer, _)| writer);
    let autonomy_policy = config.autonomy_policy();
    let synthesis_context = TtsSynthesisContext {
        neoth_home,
        media: &media,
        credentials,
        writer,
        autonomy_policy: &autonomy_policy,
        confirm_mode,
    };
    let primary_result = synthesize_one(
        &synthesis_context,
        kind,
        request.clone(),
        overrides.api_key.as_ref(),
    )
    .await;
    let synthesis = match primary_result {
        Ok(result) => Ok(result),
        Err(primary_error) => {
            match super::tts_dispatch::dispatch_fallback(&media.tts, &primary_error) {
                super::tts_dispatch::DispatchDecision::Use(fallback) => {
                    let mut fallback_request = request;
                    fallback_request.voice_id =
                        effective_voice(fallback, &fallback_request.locale, "");
                    synthesize_one(
                        &synthesis_context,
                        fallback,
                        fallback_request,
                        None,
                    )
                    .await
                    .map_err(|fallback_error| {
                        format!(
                            "TTS primary {} failed ({primary_error}); fallback {} failed ({fallback_error})",
                            kind.as_str(),
                            fallback.as_str()
                        )
                    })
                }
                super::tts_dispatch::DispatchDecision::Reject { .. } => Err(primary_error),
            }
        }
    };

    if let Some((writer, join)) = audit {
        drop(writer);
        let _ = join.await;
    }
    let (actual_kind, actual_request, response) = synthesis?;
    write_tts_output_atomic(out_path, &response.audio_bytes)?;
    Ok(TtsFileResult {
        provider: actual_kind.as_str().to_string(),
        voice: actual_request.voice_id,
        bytes: response.audio_bytes.len(),
        mime: format_mime(response.format).to_string(),
        duration_ms: response.duration_ms,
        out_path: out_path.display().to_string(),
    })
}

/// Commit a complete, validated audio response with a same-directory atomic
/// rename. A failure before the rename leaves any prior target byte-for-byte
/// intact; partial provider output is never exposed at the requested path.
pub fn write_tts_output_atomic(path: &std::path::Path, audio: &[u8]) -> Result<(), String> {
    if audio.is_empty() {
        return Err("refusing to write empty TTS audio".to_string());
    }
    crate::util::atomic_write::atomic_write_private(path, audio)
        .map_err(|e| format!("atomically write TTS output {}: {e}", path.display()))
}

/// Shared configuration and audit state for one primary/fallback TTS attempt.
struct TtsSynthesisContext<'a> {
    neoth_home: &'a std::path::Path,
    media: &'a crate::config::MediaConfig,
    credentials: &'a crate::config::credentials::Credentials,
    writer: Option<&'a crate::wal::writer::WalWriterHandle>,
    autonomy_policy: &'a crate::permissions::AutonomyPolicySnapshot,
    confirm_mode: TtsConfirmMode,
}

async fn synthesize_one(
    context: &TtsSynthesisContext<'_>,
    kind: TtsProviderKind,
    request: TtsRequest,
    cli_key: Option<&SecretString>,
) -> Result<(TtsProviderKind, TtsRequest, TtsResponse), String> {
    validate_provider_format(kind, request.format)?;
    let api_key = resolve_tts_key(kind, context.credentials, cli_key);
    let provider = make_tts_provider_at(
        context.neoth_home,
        kind,
        api_key,
        context.media.tts.azure_region.clone(),
        context.media.tts.viitor_endpoint.clone(),
        context.media,
    )?;
    let destination = tts_destination(kind, context.media)?;
    authorize_external_tts(
        kind,
        &destination,
        &request,
        context.writer,
        context.autonomy_policy,
        context.confirm_mode,
    )
    .await?;
    let response =
        synth_and_audit(provider.as_ref(), &request, context.writer, &destination).await?;
    Ok((kind, request, response))
}

async fn authorize_external_tts<P: crate::permissions::PolicyArgument>(
    kind: TtsProviderKind,
    destination: &str,
    request: &TtsRequest,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    autonomy_policy: P,
    confirm_mode: TtsConfirmMode,
) -> Result<(), String> {
    if kind.is_local() {
        return Ok(());
    }
    let writer = writer.ok_or_else(|| {
        format!(
            "external TTS ({}) requires an available audit WAL before permission evaluation",
            kind.as_str()
        )
    })?;
    let action = crate::permissions::Action::ExternalTtsSynthesis {
        provider: kind.as_str().to_string(),
        destination: destination.to_string(),
        sends_reference_audio: kind == TtsProviderKind::ViitorVoice,
        request_binding_sha256: tts_request_binding(kind, destination, request),
    };
    let confirm = match confirm_mode {
        TtsConfirmMode::InteractiveCli => crate::permissions::gate::Gate::auto_confirm(),
        TtsConfirmMode::NonInteractive => crate::permissions::gate::ConfirmStrategy::FailClosed,
    };
    crate::permissions::gate::Gate::for_policy(autonomy_policy.policy_snapshot())
        .with_confirm(confirm)
        .check_required_audit(&action, writer)
        .await
        .map_err(|error| format!("external TTS permission gate: {error}"))
}

fn tts_destination(
    kind: TtsProviderKind,
    media: &crate::config::MediaConfig,
) -> Result<String, String> {
    match kind {
        TtsProviderKind::SystemNative | TtsProviderKind::Piper => Ok("local".to_string()),
        TtsProviderKind::EdgeTts => Ok("microsoft-edge-speech".to_string()),
        TtsProviderKind::ElevenLabs => Ok("https://api.elevenlabs.io".to_string()),
        TtsProviderKind::AzureTts => {
            let region = media
                .tts
                .azure_region
                .as_deref()
                .ok_or("azure tts requires a region")?;
            validate_azure_region(region)?;
            Ok(format!("https://{region}.tts.speech.microsoft.com"))
        }
        TtsProviderKind::ViitorVoice => {
            let endpoint = media
                .tts
                .viitor_endpoint
                .as_deref()
                .ok_or("viitor_voice requires an endpoint")?;
            let (clone_url, _) = validate_viitor_endpoint(endpoint)?;
            Ok(clone_url.to_string())
        }
    }
}

fn tts_request_binding(kind: TtsProviderKind, destination: &str, request: &TtsRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        kind.as_str().as_bytes(),
        destination.as_bytes(),
        request.voice_id.as_bytes(),
        request.locale.as_bytes(),
        request.format.as_str().as_bytes(),
        request.text.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex::encode(digest.finalize())
}

fn tts_audit_base(kind: TtsProviderKind, destination: &str, request: &TtsRequest) -> TtsAuditBase {
    TtsAuditBase {
        invocation_id: uuid::Uuid::now_v7().to_string(),
        provider: kind.as_str().to_string(),
        destination: destination.to_string(),
        request_binding_sha256: tts_request_binding(kind, destination, request),
        input_hash: format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(request.text.as_bytes())
        ),
        input_bytes: request.text.len(),
        sends_reference_audio: kind == TtsProviderKind::ViitorVoice,
    }
}

fn classify_tts_error(error: &str) -> &'static str {
    if error.contains("returned HTTP") {
        "http_status"
    } else if error.contains(" body:") {
        "response_body"
    } else if error.contains("empty audio") || error.contains("mislabeled audio") {
        "invalid_response"
    } else {
        "provider"
    }
}

fn effective_voice(kind: TtsProviderKind, locale: &str, configured: &str) -> String {
    if !configured.trim().is_empty() {
        return configured.trim().to_string();
    }
    super::tts_dispatch::pick_voice_for_locale(locale, kind)
        .unwrap_or("")
        .to_string()
}

fn validate_provider_format(kind: TtsProviderKind, format: TtsFormat) -> Result<(), String> {
    let supported = match kind {
        TtsProviderKind::Piper | TtsProviderKind::SystemNative => format == TtsFormat::Wav,
        TtsProviderKind::EdgeTts | TtsProviderKind::ElevenLabs => format == TtsFormat::Mp3,
        TtsProviderKind::AzureTts | TtsProviderKind::ViitorVoice => true,
    };
    if supported {
        Ok(())
    } else {
        Err(format!(
            "{} cannot produce {}; choose a matching output extension (no implicit conversion)",
            kind.as_str(),
            format.as_str()
        ))
    }
}

fn resolve_tts_key(
    kind: TtsProviderKind,
    credentials: &crate::config::credentials::Credentials,
    cli_key: Option<&SecretString>,
) -> Option<SecretString> {
    let env_secret = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
            .map(SecretString::from)
    };
    match kind {
        TtsProviderKind::ElevenLabs => cli_key
            .cloned()
            .or_else(|| {
                env_secret(&[
                    "NEOTH_ELEVENLABS_TTS_KEY",
                    "ELEVENLABS_API_KEY",
                    "NEOTH_TTS_KEY",
                ])
            })
            .or_else(|| credentials.elevenlabs_tts_api_key.clone()),
        TtsProviderKind::AzureTts => cli_key
            .cloned()
            .or_else(|| env_secret(&["NEOTH_AZURE_TTS_KEY", "AZURE_SPEECH_KEY", "NEOTH_TTS_KEY"]))
            .or_else(|| credentials.azure_tts_api_key.clone()),
        _ => None,
    }
}

fn open_tts_audit_writer(
    neoth_home: &std::path::Path,
    required: bool,
) -> Result<
    Option<(
        crate::wal::writer::WalWriterHandle,
        tokio::task::JoinHandle<()>,
    )>,
    String,
> {
    let wal_dir = neoth_home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        if required {
            return Err(format!(
                "external TTS audit WAL directory {} is unavailable: {error}",
                wal_dir.display()
            ));
        }
        tracing::warn!(%error, "local TTS audit WAL directory unavailable");
        return Ok(None);
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "tts");
    match crate::wal::writer::spawn(segment) {
        Ok(pair) => Ok(Some(pair)),
        Err(error) => {
            if required {
                Err(format!(
                    "external TTS audit WAL writer unavailable: {error}"
                ))
            } else {
                tracing::warn!(%error, "local TTS audit WAL writer unavailable");
                Ok(None)
            }
        }
    }
}

pub fn format_mime(format: TtsFormat) -> &'static str {
    match format {
        TtsFormat::PcmS16le => "audio/L16",
        TtsFormat::Wav => "audio/wav",
        TtsFormat::Mp3 => "audio/mpeg",
        TtsFormat::Opus => "audio/opus",
    }
}

async fn append_tts_audit(
    writer: &crate::wal::writer::WalWriterHandle,
    event: TtsAuditEvent,
) -> Result<(), String> {
    let payload = serde_json::to_vec(&event)
        .map_err(|error| format!("serialize typed TTS audit lifecycle: {error}"))?;
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_TTS_SYNTHESIZED, &payload);
    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| format!("append typed TTS audit lifecycle: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str, voice: &str, fmt: TtsFormat) -> TtsRequest {
        TtsRequest {
            text: text.into(),
            voice_id: voice.into(),
            locale: "de-DE".into(),
            format: fmt,
            sample_rate_hz: 24_000,
        }
    }

    fn tts_events(path: &std::path::Path) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(path).unwrap();
        let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = header.header_len();
        let mut events = Vec::new();
        while cursor < bytes.len() {
            let decoded = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(decoded) => decoded,
                Err(_) => break,
            };
            if decoded.header.event_type == crate::wal::events::EVENT_TYPE_TTS_SYNTHESIZED {
                events.push(serde_json::from_slice(decoded.payload).unwrap());
            }
            let total = decoded.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        events
    }

    #[test]
    fn azure_output_format_maps_each_format() {
        assert_eq!(
            azure_output_format(TtsFormat::Wav),
            "riff-24khz-16bit-mono-pcm"
        );
        assert_eq!(
            azure_output_format(TtsFormat::Mp3),
            "audio-24khz-48kbitrate-mono-mp3"
        );
        assert!(azure_output_format(TtsFormat::Opus).contains("opus"));
        assert!(azure_output_format(TtsFormat::PcmS16le).contains("raw"));
    }

    #[test]
    fn azure_ssml_escapes_and_wraps() {
        let s = azure_ssml(&req("Tom & <Jerry>", "de-DE-KatjaNeural", TtsFormat::Wav));
        assert!(s.contains("xml:lang='de-DE'"));
        assert!(s.contains("name='de-DE-KatjaNeural'"));
        assert!(
            s.contains("Tom &amp; &lt;Jerry&gt;"),
            "text must be XML-escaped"
        );
        assert!(s.starts_with("<speak") && s.ends_with("</speak>"));
    }

    #[test]
    fn azure_ssml_defaults_locale() {
        let mut r = req("hi", "v", TtsFormat::Wav);
        r.locale = String::new();
        assert!(azure_ssml(&r).contains("xml:lang='en-US'"));
    }

    #[test]
    fn azure_endpoint_appends_path() {
        let c = AzureTtsClient::new("westeurope", SecretString::from("k")).unwrap();
        assert_eq!(
            c.endpoint(),
            "https://westeurope.tts.speech.microsoft.com/cognitiveservices/v1"
        );
    }

    #[test]
    fn elevenlabs_endpoint_includes_voice() {
        let c = ElevenLabsClient::new(SecretString::from("k"));
        assert_eq!(
            c.endpoint("Rachel").unwrap(),
            "https://api.elevenlabs.io/v1/text-to-speech/Rachel"
        );
    }

    #[test]
    fn credential_bearing_provider_targets_reject_host_and_path_injection() {
        for bad_region in ["eastus@evil.example", "eastus/path", ".eastus", "eastus."] {
            assert!(
                AzureTtsClient::new(bad_region, SecretString::from("k")).is_err(),
                "accepted injected Azure region: {bad_region}"
            );
        }
        let elevenlabs = ElevenLabsClient::new(SecretString::from("k"));
        for bad_voice in ["../capture", "voice?x=1", "//evil.example", ""] {
            assert!(
                elevenlabs.endpoint(bad_voice).is_err(),
                "accepted injected ElevenLabs voice id: {bad_voice}"
            );
        }
    }

    #[test]
    fn viitor_endpoint_policy_accepts_explicit_https_and_private_http() {
        let (public_https, direct) =
            validate_viitor_endpoint("https://voice.example.com/gateway").unwrap();
        assert_eq!(
            public_https.as_str(),
            "https://voice.example.com/gateway/v1/voice-clone"
        );
        assert!(!direct);

        for endpoint in [
            "http://localhost:8200",
            "http://127.0.0.1:8200",
            "http://10.0.0.4:8200/base",
            "http://192.168.1.5:8200",
            "http://100.64.0.5:8200",
            "http://[fc00::1]:8200",
        ] {
            let (_, direct) = validate_viitor_endpoint(endpoint)
                .unwrap_or_else(|error| panic!("{endpoint} should pass: {error}"));
            assert!(direct, "{endpoint} must bypass external proxies");
        }
    }

    #[test]
    fn viitor_endpoint_policy_rejects_untrusted_or_ambiguous_urls() {
        for endpoint in [
            "http://voice.example.com",
            "http://localhost.evil.example:8200",
            "http://8.8.8.8:8200",
            "http://169.254.169.254/latest/meta-data",
            "file:///tmp/voice",
            "ws://127.0.0.1:8200",
            "https://user:pass@voice.example.com",
            "https://voice.example.com?next=http://127.0.0.1",
            "https://voice.example.com/#fragment",
            " https://voice.example.com",
        ] {
            assert!(
                validate_viitor_endpoint(endpoint).is_err(),
                "accepted untrusted ViitorVoice endpoint: {endpoint}"
            );
        }
    }

    fn cloud_on() -> crate::config::MediaConfig {
        crate::config::MediaConfig {
            cloud_tts_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn factory_returns_right_kind_or_deferral() {
        let on = cloud_on();
        assert_eq!(
            make_tts_provider(TtsProviderKind::SystemNative, None, None, None, &on)
                .unwrap()
                .kind(),
            TtsProviderKind::SystemNative
        );
        // EdgeTts is cloud egress but needs no API key; explicit cloud consent
        // in `on` is still mandatory.
        assert_eq!(
            make_tts_provider(TtsProviderKind::EdgeTts, None, None, None, &on)
                .unwrap()
                .kind(),
            TtsProviderKind::EdgeTts
        );
        assert_eq!(
            make_tts_provider(
                TtsProviderKind::ElevenLabs,
                Some(SecretString::from("k")),
                None,
                None,
                &on
            )
            .unwrap()
            .kind(),
            TtsProviderKind::ElevenLabs
        );
        assert_eq!(
            make_tts_provider(
                TtsProviderKind::AzureTts,
                Some(SecretString::from("k")),
                Some("eastus".into()),
                None,
                &on,
            )
            .unwrap()
            .kind(),
            TtsProviderKind::AzureTts
        );
        // Missing cloud credentials produce clear errors.
        assert!(make_tts_provider(TtsProviderKind::ElevenLabs, None, None, None, &on).is_err());
        assert!(
            make_tts_provider(
                TtsProviderKind::AzureTts,
                Some(SecretString::from("k")),
                None,
                None,
                &on
            )
            .is_err()
        );
    }

    #[test]
    fn cloud_kind_refused_when_flag_off() {
        // P0 — cloud_tts_enabled OFF (default): a cloud voice cannot be built even
        // with valid creds. `system_native` (local) is unaffected by the gate.
        let off = crate::config::MediaConfig::default();
        let err = make_tts_provider(
            TtsProviderKind::ElevenLabs,
            Some(SecretString::from("k")),
            None,
            None,
            &off,
        )
        .err()
        .unwrap();
        assert!(
            err.contains("cloud TTS") && err.contains("LEAVES the device"),
            "got: {err}"
        );
        assert!(
            make_tts_provider(
                TtsProviderKind::AzureTts,
                Some(SecretString::from("k")),
                Some("eastus".into()),
                None,
                &off,
            )
            .err()
            .unwrap()
            .contains("cloud TTS")
        );
        // Guaranteed-local synthesis stays constructible regardless of the flag.
        assert!(make_tts_provider(TtsProviderKind::SystemNative, None, None, None, &off).is_ok());
        // EdgeTts uses a remote Microsoft service and must not bypass consent
        // merely because the adapter itself is a local subprocess.
        assert!(make_tts_provider(TtsProviderKind::EdgeTts, None, None, None, &off).is_err());
    }

    #[test]
    fn factory_edge_tts_requires_no_api_key() {
        // P0 guard: explicit cloud consent is required, but no API key is.
        let mut on = crate::config::MediaConfig::default();
        on.cloud_tts_enabled = true;
        let provider = make_tts_provider(TtsProviderKind::EdgeTts, None, None, None, &on);
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().kind(), TtsProviderKind::EdgeTts);
    }

    #[tokio::test]
    async fn synth_surfaces_error_on_unreachable_host() {
        // Point at a closed local port → connection refused → Err (no real
        // network call to a cloud endpoint).
        let c = ElevenLabsClient::new(SecretString::from("k")).with_base_url("http://127.0.0.1:1");
        let err = c
            .synth(&req("hi", "Rachel", TtsFormat::Mp3))
            .await
            .unwrap_err();
        assert!(
            err.contains("elevenlabs"),
            "expected an elevenlabs error, got: {err}"
        );
    }

    #[tokio::test]
    async fn credentialed_tts_does_not_follow_cross_origin_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        let source = MockServer::start().await;
        let location = format!("{}/capture", target.uri());
        Mock::given(method("POST"))
            .and(path("/v1/text-to-speech/Rachel"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", location))
            .mount(&source)
            .await;

        let client = ElevenLabsClient::new(SecretString::from("credential-must-not-leak"))
            .with_base_url(source.uri());
        let error = client
            .synth(&req("spoken secret", "Rachel", TtsFormat::Mp3))
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 307"), "got: {error}");
        assert!(
            target.received_requests().await.unwrap().is_empty(),
            "redirect target received the API key or spoken text"
        );
    }

    #[tokio::test]
    async fn viitor_voice_file_does_not_follow_cross_origin_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        let source = MockServer::start().await;
        let location = format!("{}/capture", target.uri());
        Mock::given(method("POST"))
            .and(path("/v1/voice-clone"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", location))
            .mount(&source)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let reference = dir.path().join("reference.wav");
        std::fs::write(&reference, b"private-reference-audio").unwrap();

        let client = ViitorVoiceClient::new(source.uri()).unwrap();
        let error = client
            .synth(&req(
                "spoken secret",
                reference.to_str().unwrap(),
                TtsFormat::Wav,
            ))
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 307"), "got: {error}");
        assert!(
            target.received_requests().await.unwrap().is_empty(),
            "redirect target received spoken text or reference audio"
        );
    }

    struct MockTts;
    #[async_trait]
    impl TtsProvider for MockTts {
        fn kind(&self) -> TtsProviderKind {
            TtsProviderKind::ElevenLabs
        }
        async fn synth(&self, _request: &TtsRequest) -> Result<TtsResponse, String> {
            Ok(TtsResponse {
                audio_bytes: vec![1u8; 2048],
                format: TtsFormat::Mp3,
                duration_ms: 0,
            })
        }
    }

    struct MockLocalTts;
    #[async_trait]
    impl TtsProvider for MockLocalTts {
        fn kind(&self) -> TtsProviderKind {
            TtsProviderKind::SystemNative
        }
        async fn synth(&self, _request: &TtsRequest) -> Result<TtsResponse, String> {
            Ok(TtsResponse {
                audio_bytes: b"RIFF0000WAVEdata".to_vec(),
                format: TtsFormat::Wav,
                duration_ms: 1,
            })
        }
    }

    struct MockFailingTts;
    #[async_trait]
    impl TtsProvider for MockFailingTts {
        fn kind(&self) -> TtsProviderKind {
            TtsProviderKind::ElevenLabs
        }

        async fn synth(&self, _request: &TtsRequest) -> Result<TtsResponse, String> {
            Err("elevenlabs returned HTTP 503 with private diagnostic".to_string())
        }
    }

    #[tokio::test]
    async fn external_synth_and_audit_always_refuses_without_writer() {
        let r = req("words", "Rachel", TtsFormat::Mp3);
        let err = synth_and_audit(&MockTts, &r, None, "https://api.elevenlabs.io")
            .await
            .unwrap_err();
        assert!(
            err.contains("requires an available audit WAL"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn synth_and_audit_emits_metadata_only_0xcd() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("tts.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let r = req("secret spoken words", "Rachel", TtsFormat::Mp3);
        let resp = synth_and_audit(&MockTts, &r, Some(&writer), "https://api.elevenlabs.io")
            .await
            .unwrap();
        assert_eq!(resp.audio_bytes.len(), 2048);
        drop(writer);
        let _ = join.await;

        let events = tts_events(&seg);
        assert_eq!(events.len(), 2, "intent + success must close the lifecycle");
        assert_eq!(events[0]["phase"], "intent");
        assert_eq!(events[1]["phase"], "success");
        assert_eq!(events[1]["audio_bytes"], 2048);
        assert_eq!(events[0]["invocation_id"], events[1]["invocation_id"]);
        for event in &events {
            assert_eq!(event["provider"], "eleven_labs");
            assert_eq!(event["input_bytes"], "secret spoken words".len());
            assert_eq!(event["destination"], "https://api.elevenlabs.io");
            assert_eq!(
                event["input_hash"],
                format!(
                    "{:016x}",
                    xxhash_rust::xxh3::xxh3_64(b"secret spoken words")
                )
            );
            let serialized = serde_json::to_vec(event).unwrap();
            assert!(
                !serialized.windows(6).any(|window| window == b"secret"),
                "spoken text must NEVER be in an audit frame"
            );
        }
    }

    #[tokio::test]
    async fn failed_external_synthesis_closes_audit_without_raw_error() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("tts-failure.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let request = req("never serialize me", "Rachel", TtsFormat::Mp3);
        let error = synth_and_audit(
            &MockFailingTts,
            &request,
            Some(&writer),
            "https://api.elevenlabs.io",
        )
        .await
        .unwrap_err();
        assert!(error.contains("HTTP 503"));
        drop(writer);
        let _ = join.await;

        let events = tts_events(&segment);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["phase"], "intent");
        assert_eq!(events[1]["phase"], "failure");
        assert_eq!(events[1]["error_class"], "http_status");
        assert_eq!(events[0]["invocation_id"], events[1]["invocation_id"]);
        let bytes = std::fs::read(segment).unwrap();
        assert!(
            !bytes
                .windows(b"never serialize me".len())
                .any(|window| { window == b"never serialize me" })
        );
        assert!(
            !bytes
                .windows(b"private diagnostic".len())
                .any(|window| { window == b"private diagnostic" })
        );
    }

    #[tokio::test]
    async fn local_synthesis_also_emits_metadata_only_audit_when_writer_exists() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("tts-local.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let request = req("private local words", "", TtsFormat::Wav);
        synth_and_audit(&MockLocalTts, &request, Some(&writer), "local")
            .await
            .unwrap();
        drop(writer);
        let _ = join.await;

        let bytes = std::fs::read(seg).unwrap();
        assert!(
            bytes
                .windows(b"system_native".len())
                .any(|w| w == b"system_native")
        );
        assert!(
            !bytes
                .windows(b"private local words".len())
                .any(|w| w == b"private local words")
        );
    }

    #[tokio::test]
    async fn noninteractive_external_gate_fails_closed_below_elevated() {
        use crate::permissions::AutonomyLevel;

        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("tts-gate.wal");
        let (writer, join) = crate::wal::writer::spawn(segment).unwrap();
        let request = req("gate-bound words", "Rachel", TtsFormat::Mp3);
        for level in [
            AutonomyLevel::Strict,
            AutonomyLevel::Standard,
            AutonomyLevel::Custom,
        ] {
            let error = authorize_external_tts(
                TtsProviderKind::ElevenLabs,
                "https://api.elevenlabs.io",
                &request,
                Some(&writer),
                level,
                TtsConfirmMode::NonInteractive,
            )
            .await
            .unwrap_err();
            assert!(error.contains("fail-closed"), "{level:?}: {error}");
        }
        for level in [AutonomyLevel::Elevated, AutonomyLevel::Full] {
            authorize_external_tts(
                TtsProviderKind::ElevenLabs,
                "https://api.elevenlabs.io",
                &request,
                Some(&writer),
                level,
                TtsConfirmMode::NonInteractive,
            )
            .await
            .unwrap_or_else(|error| panic!("{level:?} should allow: {error}"));
        }
        authorize_external_tts(
            TtsProviderKind::Piper,
            "local",
            &request,
            None,
            AutonomyLevel::Strict,
            TtsConfirmMode::NonInteractive,
        )
        .await
        .expect("local TTS does not require an external egress gate");
        drop(writer);
        let _ = join.await;
    }

    #[test]
    fn tts_output_commit_is_atomic_and_failure_preserves_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("voice.wav");
        std::fs::write(&target, b"old").unwrap();
        write_tts_output_atomic(&target, b"RIFF0000WAVEnew").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"RIFF0000WAVEnew");

        std::fs::write(&target, b"stable-old").unwrap();
        let temp = target.with_file_name(format!(
            "{}.{}.tmp",
            target.file_name().unwrap().to_string_lossy(),
            std::process::id()
        ));
        std::fs::create_dir(&temp).unwrap();
        assert!(write_tts_output_atomic(&target, b"replacement").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"stable-old");
    }

    // ── GOLD-ADAPT-SYS-02 — ViitorVoice voice-cloning sidecar ────────────────

    #[test]
    fn viitor_clone_url_appends_path_trimming_slash() {
        assert_eq!(
            ViitorVoiceClient::new("http://127.0.0.1:8200/")
                .unwrap()
                .clone_url()
                .as_str(),
            "http://127.0.0.1:8200/v1/voice-clone"
        );
        assert_eq!(
            ViitorVoiceClient::new("http://127.0.0.1:8200")
                .unwrap()
                .clone_url()
                .as_str(),
            "http://127.0.0.1:8200/v1/voice-clone"
        );
    }

    #[test]
    fn viitor_factory_gated_and_requires_endpoint() {
        // Not local → the P0 cloud_tts_enabled gate applies even with an endpoint.
        let off = crate::config::MediaConfig::default();
        assert!(
            make_tts_provider(
                TtsProviderKind::ViitorVoice,
                None,
                None,
                Some("http://127.0.0.1:8200".into()),
                &off,
            )
            .err()
            .unwrap()
            .contains("cloud TTS"),
            "ViitorVoice must be blocked by the cloud_tts_enabled gate"
        );
        // Enabled but no endpoint → clear error.
        let on = cloud_on();
        assert!(
            make_tts_provider(TtsProviderKind::ViitorVoice, None, None, None, &on)
                .err()
                .unwrap()
                .contains("requires an endpoint"),
            "ViitorVoice must demand an endpoint"
        );
        let untrusted = make_tts_provider(
            TtsProviderKind::ViitorVoice,
            None,
            None,
            Some("http://voice.example.com".into()),
            &on,
        )
        .err()
        .unwrap();
        assert!(untrusted.contains("must use https://"), "got: {untrusted}");
        // Enabled + endpoint → constructs the right kind (no API key needed).
        assert_eq!(
            make_tts_provider(
                TtsProviderKind::ViitorVoice,
                None,
                None,
                Some("http://127.0.0.1:8200".into()),
                &on,
            )
            .unwrap()
            .kind(),
            TtsProviderKind::ViitorVoice
        );
    }

    #[tokio::test]
    async fn viitor_synth_requires_ref_audio_path() {
        // Empty voice_id (= the reference-audio path) → refuse before any network.
        let c = ViitorVoiceClient::new("http://127.0.0.1:1").unwrap();
        let err = c
            .synth(&req("hallo", "", TtsFormat::Wav))
            .await
            .unwrap_err();
        assert!(
            err.contains("reference-audio path"),
            "expected a ref-audio error, got: {err}"
        );
    }
}
