//! MM-02b — multimodal vision synthesizers: Anthropic / OpenAI / Gemini (REST).
//!
//! Each takes a [`MultimodalRequest`] (prompt + decoded [`Frame`]s) and returns
//! the provider's synthesised answer. Body builders + response parsers are PURE
//! (the HTTP call is the thin shell). Clients construct their `reqwest::Client`
//! via [`crate::providers::http_client::build_client`] so this `src/media/` file
//! carries no forbidden construction token (the network guard is not tripped).
//!
//! Model ids are caller-overridable (`MultimodalRequest::model_id`) — NEOTH is
//! model-version-agnostic, so the per-provider defaults below are only fallbacks.

use async_trait::async_trait;
use base64::Engine;

use super::video_frames::{Frame, MultimodalProvider, MultimodalRequest};
use crate::providers::http_client;
use crate::secret::SecretString;

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-7-sonnet-latest";
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o";
const DEFAULT_GEMINI_MODEL: &str = "gemini-1.5-pro";

/// Common vision-synthesis surface.
#[async_trait]
pub trait MultimodalSynthesizer: Send + Sync {
    fn provider(&self) -> MultimodalProvider;
    /// Run the prompt-guided synthesis over the request's frames; return the
    /// provider's answer text. Errors carry an operator-readable string.
    async fn synthesize(&self, request: &MultimodalRequest) -> Result<String, String>;
}

/// Base64 (standard) of a frame's encoded bytes.
fn frame_b64(frame: &Frame) -> String {
    base64::engine::general_purpose::STANDARD.encode(&frame.pixels)
}

fn model_or<'a>(req: &'a MultimodalRequest, default: &'a str) -> &'a str {
    if req.model_id.is_empty() {
        default
    } else {
        &req.model_id
    }
}

// ── Anthropic ───────────────────────────────────────────────────────────────

/// Build the Anthropic `/v1/messages` body: one user message whose content is
/// the frames (base64 image blocks) followed by the prompt text. PURE.
pub fn anthropic_body(req: &MultimodalRequest) -> serde_json::Value {
    let mut content: Vec<serde_json::Value> = req
        .frames
        .iter()
        .map(|f| {
            serde_json::json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": f.format.mime_type(),
                    "data": frame_b64(f),
                },
            })
        })
        .collect();
    content.push(serde_json::json!({ "type": "text", "text": req.prompt }));
    serde_json::json!({
        "model": model_or(req, DEFAULT_ANTHROPIC_MODEL),
        "max_tokens": req.max_tokens,
        "messages": [{ "role": "user", "content": content }],
    })
}

/// Extract the joined text from an Anthropic messages response. PURE.
pub fn parse_anthropic_text(body: &[u8]) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("anthropic decode: {e}"))?;
    let text: String = v
        .get("content")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    if text.is_empty() {
        return Err("anthropic returned no text content".into());
    }
    Ok(text)
}

/// Anthropic vision client.
pub struct AnthropicVisionClient {
    api_key: SecretString,
    base_url: String,
}

impl AnthropicVisionClient {
    pub fn new(api_key: SecretString) -> Self {
        Self {
            api_key,
            base_url: "https://api.anthropic.com".to_string(),
        }
    }
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

#[async_trait]
impl MultimodalSynthesizer for AnthropicVisionClient {
    fn provider(&self) -> MultimodalProvider {
        MultimodalProvider::AnthropicClaude
    }
    async fn synthesize(&self, request: &MultimodalRequest) -> Result<String, String> {
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(format!(
                "{}/v1/messages",
                self.base_url.trim_end_matches('/')
            ))
            .header("x-api-key", self.api_key.expose())
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&anthropic_body(request))
            .send()
            .await
            .map_err(|e| format!("anthropic vision request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("anthropic vision returned HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("anthropic body: {e}"))?;
        parse_anthropic_text(&body)
    }
}

// ── OpenAI ──────────────────────────────────────────────────────────────────

/// Build the OpenAI `/v1/chat/completions` body: prompt text + one
/// `image_url` data-URI per frame. PURE.
pub fn openai_body(req: &MultimodalRequest) -> serde_json::Value {
    let mut content: Vec<serde_json::Value> =
        vec![serde_json::json!({ "type": "text", "text": req.prompt })];
    for f in &req.frames {
        content.push(serde_json::json!({
            "type": "image_url",
            "image_url": { "url": format!("data:{};base64,{}", f.format.mime_type(), frame_b64(f)) },
        }));
    }
    serde_json::json!({
        "model": model_or(req, DEFAULT_OPENAI_MODEL),
        "max_tokens": req.max_tokens,
        "messages": [{ "role": "user", "content": content }],
    })
}

/// Extract the assistant message text from an OpenAI chat response. PURE.
pub fn parse_openai_text(body: &[u8]) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("openai decode: {e}"))?;
    v.get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "openai returned no message content".into())
}

/// OpenAI GPT-4o vision client.
pub struct OpenAiVisionClient {
    api_key: SecretString,
    base_url: String,
}

impl OpenAiVisionClient {
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
}

#[async_trait]
impl MultimodalSynthesizer for OpenAiVisionClient {
    fn provider(&self) -> MultimodalProvider {
        MultimodalProvider::OpenAiGpt4o
    }
    async fn synthesize(&self, request: &MultimodalRequest) -> Result<String, String> {
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(format!(
                "{}/v1/chat/completions",
                self.base_url.trim_end_matches('/')
            ))
            .bearer_auth(self.api_key.expose())
            .json(&openai_body(request))
            .send()
            .await
            .map_err(|e| format!("openai vision request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("openai vision returned HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("openai body: {e}"))?;
        parse_openai_text(&body)
    }
}

// ── Gemini ──────────────────────────────────────────────────────────────────

/// Build the Gemini `:generateContent` body: a `parts` array of the prompt +
/// one `inlineData` per frame. PURE.
pub fn gemini_body(req: &MultimodalRequest) -> serde_json::Value {
    let mut parts: Vec<serde_json::Value> = vec![serde_json::json!({ "text": req.prompt })];
    for f in &req.frames {
        parts.push(serde_json::json!({
            "inlineData": { "mimeType": f.format.mime_type(), "data": frame_b64(f) },
        }));
    }
    serde_json::json!({
        "contents": [{ "parts": parts }],
        "generationConfig": { "maxOutputTokens": req.max_tokens },
    })
}

/// Extract the joined candidate text from a Gemini response. PURE.
pub fn parse_gemini_text(body: &[u8]) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("gemini decode: {e}"))?;
    let text: String = v
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    if text.is_empty() {
        return Err("gemini returned no text".into());
    }
    Ok(text)
}

/// Google Gemini vision client. The api key goes in the `x-goog-api-key`
/// header (not the URL query string — GOLD-SEC-22 / A-60).
pub struct GeminiVisionClient {
    api_key: SecretString,
    base_url: String,
    model: String,
}

impl GeminiVisionClient {
    pub fn new(api_key: SecretString) -> Self {
        Self {
            api_key,
            base_url: "https://generativelanguage.googleapis.com".to_string(),
            model: DEFAULT_GEMINI_MODEL.to_string(),
        }
    }
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

#[async_trait]
impl MultimodalSynthesizer for GeminiVisionClient {
    fn provider(&self) -> MultimodalProvider {
        MultimodalProvider::GoogleGemini
    }
    async fn synthesize(&self, request: &MultimodalRequest) -> Result<String, String> {
        let model = if request.model_id.is_empty() {
            &self.model
        } else {
            &request.model_id
        };
        // GOLD-SEC-22 / A-60: send the key in the `x-goog-api-key` header,
        // not the `?key=` query param — URLs leak into request/proxy/tracing
        // logs, headers do not.
        let url = format!(
            "{}/v1beta/models/{}:generateContent",
            self.base_url.trim_end_matches('/'),
            model,
        );
        let client = http_client::build_client().map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(url)
            .header("x-goog-api-key", self.api_key.expose())
            .json(&gemini_body(request))
            .send()
            .await
            .map_err(|e| format!("gemini vision request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("gemini vision returned HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("gemini body: {e}"))?;
        parse_gemini_text(&body)
    }
}

/// MM-02b bridge: build a live cloud-vision synthesizer for `provider` from creds.
pub fn make_multimodal_synth(
    provider: MultimodalProvider,
    api_key: Option<SecretString>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<Box<dyn MultimodalSynthesizer>, String> {
    // P0 ENFORCEMENT — a CLOUD vision synthesizer ships frames (image bytes) to
    // a third-party provider. It may only be constructed when the operator opted
    // in (`media.cloud_vision_enabled`). The safe-mode rail makes this visible;
    // this gate makes it REAL. Every offered provider is cloud-backed.
    if !media_cfg.cloud_vision_enabled {
        return Err(format!(
            "cloud vision ({}) is disabled — set media.cloud_vision_enabled: true to send \
             image frames to a cloud model (those frames then LEAVE the device)",
            provider.as_str()
        ));
    }
    let key = || {
        api_key
            .clone()
            .ok_or_else(|| format!("{} requires an api key", provider.as_str()))
    };
    match provider {
        MultimodalProvider::AnthropicClaude => Ok(Box::new(AnthropicVisionClient::new(key()?))),
        MultimodalProvider::OpenAiGpt4o => Ok(Box::new(OpenAiVisionClient::new(key()?))),
        MultimodalProvider::GoogleGemini => Ok(Box::new(GeminiVisionClient::new(key()?))),
    }
}

#[cfg(test)]
mod tests {
    use super::super::video_frames::FrameFormat;
    use super::*;

    fn frame(byte: u8) -> Frame {
        Frame {
            ts_ms: 0,
            width: 1,
            height: 1,
            format: FrameFormat::Jpeg,
            pixels: vec![byte; 3],
        }
    }
    fn req(n: usize) -> MultimodalRequest {
        MultimodalRequest::new("describe", (0..n).map(|i| frame(i as u8)).collect(), 256).unwrap()
    }

    #[test]
    fn anthropic_body_has_frames_then_prompt() {
        let b = anthropic_body(&req(2));
        let content = b["messages"][0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 3, "2 images + 1 text");
        assert_eq!(content[0]["type"], "image");
        assert_eq!(content[0]["source"]["media_type"], "image/jpeg");
        assert!(!content[0]["source"]["data"].as_str().unwrap().is_empty());
        assert_eq!(content[2]["type"], "text");
        assert_eq!(content[2]["text"], "describe");
        assert_eq!(b["model"], DEFAULT_ANTHROPIC_MODEL);
    }

    #[test]
    fn anthropic_body_honours_model_override() {
        let mut r = req(1);
        r.model_id = "claude-custom".into();
        assert_eq!(anthropic_body(&r)["model"], "claude-custom");
    }

    #[test]
    fn openai_body_text_then_image_urls() {
        let b = openai_body(&req(2));
        let content = b["messages"][0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 3, "1 text + 2 image_url");
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image_url");
        assert!(
            content[1]["image_url"]["url"]
                .as_str()
                .unwrap()
                .starts_with("data:image/jpeg;base64,")
        );
    }

    #[test]
    fn gemini_body_inline_data_parts() {
        let b = gemini_body(&req(2));
        let parts = b["contents"][0]["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 3, "1 text + 2 inlineData");
        assert_eq!(parts[0]["text"], "describe");
        assert_eq!(parts[1]["inlineData"]["mimeType"], "image/jpeg");
        assert_eq!(b["generationConfig"]["maxOutputTokens"], 256);
    }

    #[test]
    fn parse_anthropic_joins_text_blocks() {
        let body = br#"{"content":[{"type":"text","text":"a "},{"type":"text","text":"clip"}]}"#;
        assert_eq!(parse_anthropic_text(body).unwrap(), "a clip");
        assert!(parse_anthropic_text(br#"{"content":[]}"#).is_err());
    }

    #[test]
    fn parse_openai_reads_message_content() {
        let body = br#"{"choices":[{"message":{"content":"a person waving"}}]}"#;
        assert_eq!(parse_openai_text(body).unwrap(), "a person waving");
        assert!(parse_openai_text(br#"{"choices":[]}"#).is_err());
    }

    #[test]
    fn parse_gemini_joins_parts() {
        let body =
            br#"{"candidates":[{"content":{"parts":[{"text":"sunset "},{"text":"over sea"}]}}]}"#;
        assert_eq!(parse_gemini_text(body).unwrap(), "sunset over sea");
        assert!(parse_gemini_text(br#"{"candidates":[]}"#).is_err());
    }

    fn vision_on() -> crate::config::MediaConfig {
        crate::config::MediaConfig {
            cloud_vision_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn factory_returns_right_provider_or_deferral() {
        let on = vision_on();
        assert_eq!(
            make_multimodal_synth(
                MultimodalProvider::AnthropicClaude,
                Some(SecretString::from("k")),
                &on
            )
            .unwrap()
            .provider(),
            MultimodalProvider::AnthropicClaude
        );
        assert!(make_multimodal_synth(MultimodalProvider::OpenAiGpt4o, None, &on).is_err());
    }

    #[test]
    fn cloud_vision_refused_when_flag_off() {
        // P0 — cloud_vision_enabled OFF (default): no cloud vision synth even with
        // credentials.
        let off = crate::config::MediaConfig::default();
        let err = make_multimodal_synth(
            MultimodalProvider::AnthropicClaude,
            Some(SecretString::from("k")),
            &off,
        )
        .err()
        .unwrap();
        assert!(
            err.contains("cloud vision") && err.contains("LEAVE the device"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn synthesize_surfaces_error_on_unreachable_host() {
        let c =
            AnthropicVisionClient::new(SecretString::from("k")).with_base_url("http://127.0.0.1:1");
        let err = c.synthesize(&req(1)).await.unwrap_err();
        assert!(
            err.contains("anthropic"),
            "expected an anthropic error, got: {err}"
        );
    }
}
