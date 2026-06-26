//! MM-03b — cloud TTS providers: Azure Cognitive Services + ElevenLabs.
//!
//! Both implement the [`super::tts_provider::TtsProvider`] trait alongside the
//! shipped [`super::tts_provider::SystemNativeProvider`], and a
//! [`make_tts_provider`] factory bridges a [`TtsProviderKind`] + operator creds
//! to a live `Box<dyn TtsProvider>` the dispatcher can `synth` through.
//!
//! ## Network-guard posture
//!
//! Neither client constructs a `reqwest::Client` directly — both go through
//! [`crate::providers::http_client::build_client`] (built inside `providers/`,
//! already allow-listed by `tests/no_outbound_network.rs`). So this file under
//! `src/media/` carries no forbidden construction token and the
//! "NEOTH-never-phones-home" guard is not tripped. The endpoints are
//! operator-configured cloud TTS — an explicit, credentialed upstream, never an
//! unsolicited phone-home.
//!
//! ## Deferred
//!
//! Piper / Coqui local engines stay deferred — each needs a C-FFI crate
//! (piper-rs / onnxruntime) that requires cmake + a C++ toolchain at build time
//! (unverifiable on a plain Windows MSVC box) plus an ONNX voice-model download.
//! The candle stack already covers local STT; local TTS lands when the dep tree
//! allows the ONNX runtime. `make_tts_provider` returns a clear deferral error.

use async_trait::async_trait;

use super::tts_dispatch::{TtsFormat, TtsProvider as TtsProviderKind, TtsRequest, TtsResponse};
use super::tts_provider::{EdgeTtsProvider, SystemNativeProvider, TtsProvider};
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

/// Azure Cognitive Services neural TTS (REST). Auth: `Ocp-Apim-Subscription-Key`.
pub struct AzureTtsClient {
    region: String,
    api_key: SecretString,
    /// `https://{region}.tts.speech.microsoft.com` by default; overridable for
    /// tests (point at an unreachable local port to exercise the error path).
    base_url: String,
}

impl AzureTtsClient {
    pub fn new(region: impl Into<String>, api_key: SecretString) -> Self {
        let region = region.into();
        let base_url = format!("https://{region}.tts.speech.microsoft.com");
        Self {
            region,
            api_key,
            base_url,
        }
    }

    /// Test seam: override the base URL (e.g. a wiremock / unreachable port).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
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
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
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
pub struct ElevenLabsClient {
    api_key: SecretString,
    /// `https://api.elevenlabs.io` by default; overridable for tests.
    base_url: String,
}

impl ElevenLabsClient {
    pub fn new(api_key: SecretString) -> Self {
        Self {
            api_key,
            base_url: "https://api.elevenlabs.io".to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn endpoint(&self, voice_id: &str) -> String {
        format!(
            "{}/v1/text-to-speech/{}",
            self.base_url.trim_end_matches('/'),
            voice_id
        )
    }
}

#[async_trait]
impl TtsProvider for ElevenLabsClient {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::ElevenLabs
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(self.endpoint(&request.voice_id))
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

/// MM-03b bridge: build a live TTS provider for `kind` from operator creds.
/// The first config → `Box<dyn TtsProvider>` factory; the dispatcher decides
/// WHICH kind, this turns that decision into a synthesiser.
///
/// `api_key` is required for the cloud providers; `azure_region` additionally
/// for Azure. Piper/Coqui are deferred (no local engine dep yet).
pub fn make_tts_provider(
    kind: TtsProviderKind,
    api_key: Option<SecretString>,
    azure_region: Option<String>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<Box<dyn TtsProvider>, String> {
    // P0 ENFORCEMENT — a CLOUD TTS provider sends the text-to-speak to a third
    // party. It may only be constructed when the operator opted in
    // (`media.cloud_tts_enabled`). The safe-mode rail makes this visible; this
    // gate makes it REAL. `system_native` (and the deferred local engines) pass.
    if !kind.is_local() && !media_cfg.cloud_tts_enabled {
        return Err(format!(
            "cloud TTS ({}) is disabled — set media.cloud_tts_enabled: true to send \
             the spoken text to a cloud voice (your text then LEAVES the device)",
            kind.as_str()
        ));
    }
    match kind {
        TtsProviderKind::SystemNative => Ok(Box::new(SystemNativeProvider::new())),
        // JV-VOICE-01 — EdgeTts is local (is_local() == true): the P0 cloud gate
        // above does NOT apply. No API key required; relies on the `edge-tts`
        // Python CLI installed by the operator.
        TtsProviderKind::EdgeTts => Ok(Box::new(EdgeTtsProvider::new())),
        TtsProviderKind::ElevenLabs => {
            let key = api_key.ok_or("elevenlabs requires an api key")?;
            Ok(Box::new(ElevenLabsClient::new(key)))
        }
        TtsProviderKind::AzureTts => {
            let key = api_key.ok_or("azure tts requires an api key")?;
            let region = azure_region.ok_or("azure tts requires a region")?;
            Ok(Box::new(AzureTtsClient::new(region, key)))
        }
        TtsProviderKind::Piper | TtsProviderKind::Coqui => Err(format!(
            "{kind:?} local TTS is deferred — needs an ONNX/C++ engine dep \
             (piper-rs / onnxruntime) + a voice-model download. Use system_native, \
             edge_tts, elevenlabs, or azure_tts."
        )),
    }
}

/// P0 — synthesise through `provider` and emit the metadata-only
/// `0xCD TTS_SYNTHESIZED` audit. Records that text went to a cloud provider
/// (provider id + input xxh3-64 HASH + input/audio byte counts) — NEVER the
/// input text. Best-effort audit (a WAL error logs, never fails the call).
pub async fn synth_and_audit(
    provider: &dyn TtsProvider,
    request: &TtsRequest,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    required_audit: bool,
) -> Result<TtsResponse, String> {
    // P0 fail-closed pre-flight: under proof-hardline, refuse BEFORE the cloud
    // call when there is no audit sink — never synthesise unprovably.
    crate::media::enforce_cloud_media_audit(required_audit, writer.is_some())?;
    let resp = provider.synth(request).await?;
    if let Some(w) = writer {
        emit_tts_synthesized(w, provider.kind(), &request.text, resp.audio_bytes.len()).await;
    }
    Ok(resp)
}

async fn emit_tts_synthesized(
    writer: &crate::wal::writer::WalWriterHandle,
    provider: TtsProviderKind,
    input_text: &str,
    audio_bytes: usize,
) {
    let ts_unix = crate::time::now_unix_secs();
    let payload = match serde_json::to_vec(&serde_json::json!({
        "provider": provider.as_str(),
        "input_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(input_text.as_bytes())),
        "input_bytes": input_text.len(),
        "audio_bytes": audio_bytes,
        "ts_unix": ts_unix,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize TTS_SYNTHESIZED (0xCD) failed");
            return;
        }
    };
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_TTS_SYNTHESIZED, &payload);
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append TTS_SYNTHESIZED (0xCD) failed (non-fatal)");
    }
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
        let c = AzureTtsClient::new("westeurope", SecretString::from("k"));
        assert_eq!(
            c.endpoint(),
            "https://westeurope.tts.speech.microsoft.com/cognitiveservices/v1"
        );
    }

    #[test]
    fn elevenlabs_endpoint_includes_voice() {
        let c = ElevenLabsClient::new(SecretString::from("k"));
        assert_eq!(
            c.endpoint("Rachel"),
            "https://api.elevenlabs.io/v1/text-to-speech/Rachel"
        );
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
            make_tts_provider(TtsProviderKind::SystemNative, None, None, &on)
                .unwrap()
                .kind(),
            TtsProviderKind::SystemNative
        );
        // EdgeTts is local — constructible without API key and with cloud flag off.
        assert_eq!(
            make_tts_provider(TtsProviderKind::EdgeTts, None, None, &on)
                .unwrap()
                .kind(),
            TtsProviderKind::EdgeTts
        );
        assert_eq!(
            make_tts_provider(
                TtsProviderKind::ElevenLabs,
                Some(SecretString::from("k")),
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
                &on,
            )
            .unwrap()
            .kind(),
            TtsProviderKind::AzureTts
        );
        // Missing creds + deferred engines → clear errors.
        assert!(make_tts_provider(TtsProviderKind::ElevenLabs, None, None, &on).is_err());
        assert!(
            make_tts_provider(
                TtsProviderKind::AzureTts,
                Some(SecretString::from("k")),
                None,
                &on
            )
            .is_err()
        );
        assert!(make_tts_provider(TtsProviderKind::Piper, None, None, &on).is_err());
        assert!(make_tts_provider(TtsProviderKind::Coqui, None, None, &on).is_err());
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
                &off,
            )
            .err()
            .unwrap()
            .contains("cloud TTS")
        );
        // Local stays constructible regardless of the flag.
        assert!(make_tts_provider(TtsProviderKind::SystemNative, None, None, &off).is_ok());
        // EdgeTts likewise local — unaffected by cloud_tts_enabled flag.
        assert!(make_tts_provider(TtsProviderKind::EdgeTts, None, None, &off).is_ok());
    }

    #[test]
    fn factory_edge_tts_requires_no_api_key() {
        // P0 guard: EdgeTts is local; cloud flag irrelevant; no key required.
        let off = crate::config::MediaConfig::default();
        let provider = make_tts_provider(TtsProviderKind::EdgeTts, None, None, &off);
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

    #[tokio::test]
    async fn synth_and_audit_refuses_when_required_and_no_writer() {
        // P0 proof-hardline: required_audit + no sink → refuse BEFORE synthesising.
        let r = req("words", "Rachel", TtsFormat::Mp3);
        let err = synth_and_audit(&MockTts, &r, None, true).await.unwrap_err();
        assert!(err.contains("required_audit_for_cloud_media"), "got: {err}");
        assert!(synth_and_audit(&MockTts, &r, None, false).await.is_ok());
    }

    #[tokio::test]
    async fn synth_and_audit_emits_metadata_only_0xcd() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("tts.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let r = req("secret spoken words", "Rachel", TtsFormat::Mp3);
        let resp = synth_and_audit(&MockTts, &r, Some(&writer), false)
            .await
            .unwrap();
        assert_eq!(resp.audio_bytes.len(), 2048);
        drop(writer);
        let _ = join.await;

        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut found = false;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_TTS_SYNTHESIZED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["provider"], "eleven_labs");
                assert_eq!(v["input_bytes"], "secret spoken words".len());
                assert_eq!(v["audio_bytes"], 2048);
                assert_eq!(
                    v["input_hash"],
                    format!(
                        "{:016x}",
                        xxhash_rust::xxh3::xxh3_64(b"secret spoken words")
                    )
                );
                assert!(
                    !dec.payload.windows(6).any(|w| w == b"secret"),
                    "spoken text must NEVER be in the audit frame"
                );
                found = true;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert!(found, "expected a 0xCD TTS_SYNTHESIZED frame");
    }
}
