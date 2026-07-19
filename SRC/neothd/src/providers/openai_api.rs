//! OpenAI REST adapter (`api.openai.com` and OpenAI-compatible endpoints).
//!
//! POST {endpoint}/chat/completions with a Bearer token. Supports both the
//! upstream OpenAI service and OpenAI-compatible endpoints (LM Studio, vLLM,
//! Ollama /v1, Anthropic via OAI-shim, etc.). A non-official endpoint supplied
//! through the OpenAI constructor is deliberately reclassified as
//! `openai_api_custom`: it cannot inherit the reviewed official price table.
//!
//! Streaming: `stream()` sends `stream: true` and reads the response body as
//! Server-Sent Events (SSE), parsing each `data: {...}` line as an OpenAI
//! streaming chunk and mapping it to `CompletionChunk`. Works with any
//! OpenAI-compat endpoint including Ollama's `/v1/chat/completions` path.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::{
    ChunkStream, Completion, CompletionChunk, Provider, ProviderDispatchPermit,
    ProviderRequestControls, Request,
};
use crate::secret::SecretString;

fn is_official_openai_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("api.openai.com")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().trim_end_matches('/') == "/v1"
}

/// Adapter for OpenAI REST + compatibles.
pub struct OpenAiAdapter {
    /// e.g. `https://api.openai.com/v1` — no trailing slash.
    endpoint: String,
    /// `Authorization: Bearer <key>`. SecretString so Debug stays redacted.
    api_key: SecretString,
    /// Default model when the per-request override is None.
    default_model: String,
    /// Shared HTTP client.
    http: reqwest::Client,
    /// Adapter name surfaced in logs + WAL events. Allows the OpenAI-compat
    /// alias to identify itself differently from upstream OpenAI even though
    /// the wire protocol is identical.
    name: &'static str,
}

impl OpenAiAdapter {
    pub fn new_openai(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        let name = if is_official_openai_endpoint(&endpoint) {
            "openai_api"
        } else {
            "openai_api_custom"
        };
        Self::build(endpoint, api_key, default_model, name)
    }

    pub fn new_compat(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::build(endpoint, api_key, default_model, "openai_compat")
    }

    /// GOLD-ADAPT-ODY-15 — Copilot-endpoint variant. Identical wire format to
    /// `new_openai` but names itself `"copilot_api"` so `Provider::name()`
    /// returns the correct cost-table key. The session token is a short-lived
    /// credential managed by `CopilotAdapter::fetch_or_refresh_token`; this
    /// constructor just records it as the bearer key for the one call.
    pub fn new_copilot(
        endpoint: String,
        session_token: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::build(endpoint, session_token, default_model, "copilot_api")
    }

    fn build(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
        name: &'static str,
    ) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client_no_redirect()?;
        Ok(Self {
            endpoint,
            api_key,
            default_model,
            http,
            name,
        })
    }

    fn chat_request(
        &self,
        model: String,
        messages: Vec<ChatMessage>,
        stream: bool,
        req: &Request,
    ) -> ChatRequest {
        let (max_completion_tokens, max_tokens) =
            if matches!(self.name, "openai_compat" | "openai_api_custom") {
                // Generic OpenAI-compatible servers (vLLM, LM Studio, Ollama,
                // OpenRouter) consistently implement the legacy `max_tokens`
                // field, while `max_completion_tokens` is an OpenAI/Azure-era
                // extension that several of them reject as unknown.
                (None, Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING))
            } else {
                (Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING), None)
            };
        ChatRequest {
            model,
            messages,
            stream,
            max_completion_tokens,
            max_tokens,
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.sampling_seed,
            stop: (!req.stop_sequences.is_empty()).then(|| req.stop_sequences.clone()),
        }
    }
}

#[async_trait]
impl Provider for OpenAiAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        let kind = match self.name {
            "openai_compat" => crate::cli::init::ProviderKind::OpenaiCompat,
            "copilot_api" => crate::cli::init::ProviderKind::GitHubCopilot,
            _ => crate::cli::init::ProviderKind::OpenaiApi,
        };
        Some(crate::consent::ConsentRoute::new(
            kind,
            Some(&self.endpoint),
        ))
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
    }

    fn streams_on_wire(&self) -> bool {
        true
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        // GR-04: wrap in circuit breaker so persistent provider
        // outages stop hammering the upstream + surface as a fast
        // local error after the failure threshold trips.
        crate::providers::circuit_breaker::run_with_breaker(self.name, async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            let mut messages = Vec::new();
            if let Some(sys) = &req.system {
                messages.push(ChatMessage {
                    role: "system",
                    content: sys.clone(),
                });
            }
            messages.push(ChatMessage {
                role: "user",
                content: req.prompt.clone(),
            });

            let body = self.chat_request(model.clone(), messages, false, &req);

            let url = format!("{}/chat/completions", self.endpoint);
            let response = self
                .http
                .post(&url)
                .bearer_auth(self.api_key.expose())
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = response.status();
            if !status.is_success() {
                // 429 carries a Retry-After header that the quota tracker needs.
                // We extract it BEFORE consuming the body so the caller can
                // downcast the error to `QuotaError` and update the tracker
                // without re-parsing the response. Body is still shown to the
                // operator for diagnostics.
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let body = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .replace(self.api_key.expose(), "[REDACTED]");
                    return Err(anyhow::Error::new(QuotaError {
                        provider: self.name,
                        retry_after,
                        body: body.trim().to_string(),
                    }));
                }
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into())
                    .replace(self.api_key.expose(), "[REDACTED]");
                anyhow::bail!(
                    "{} returned HTTP {}: {}",
                    self.name,
                    status.as_u16(),
                    body.trim()
                );
            }

            let parsed: ChatResponse = response
                .json()
                .await
                .with_context(|| format!("parse {} response JSON", self.name))?;

            // CDX-07 silent-fail-to-empty fix: surface the malformed shape
            // as an error instead of silently returning "". An OpenAI-compat
            // response without choices is almost always a content-filter
            // refusal or a backend error envelope mistakenly returned as
            // 200 — operator wants to see WHY, not a blank reply.
            let text = parsed
                .choices
                .into_iter()
                .next()
                .map(|c| c.message.content)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} returned 200 OK but the response has no choices[].message.content — \
                     likely a content-filter refusal or upstream error envelope. \
                     Inspect the raw HTTP body via NEOTH_LOG_LEVEL=debug.",
                        self.name
                    )
                })?;

            let latency = started.elapsed();
            debug!(
                adapter = self.name,
                model = %model,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "openai completion"
            );

            Ok(Completion {
                text,
                identity: Default::default(),
                model,
                latency,
                input_tokens: parsed.usage.as_ref().map(|u| u.prompt_tokens),
                output_tokens: parsed.usage.as_ref().map(|u| u.completion_tokens),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }

    /// SSE streaming completion. Sends `stream: true` and parses the response
    /// body as Server-Sent Events. Each `data: {...}` line is decoded as an
    /// `OpenAI streaming chunk`; `data: [DONE]` terminates the stream.
    ///
    /// Works with any OpenAI-compat endpoint that honours `stream: true`,
    /// including Ollama's `/v1/chat/completions` path and LM Studio.
    async fn stream_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        crate::providers::circuit_breaker_stream::run_stream_with_breaker(self.name, async {
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            let mut messages = Vec::new();
            if let Some(sys) = &req.system {
                messages.push(ChatMessage {
                    role: "system",
                    content: sys.clone(),
                });
            }
            messages.push(ChatMessage {
                role: "user",
                content: req.prompt.clone(),
            });

            let body = self.chat_request(model.clone(), messages, true, &req);

            let url = format!("{}/chat/completions", self.endpoint);
            let response = self
                .http
                .post(&url)
                .bearer_auth(self.api_key.expose())
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url} (stream)"))?;

            let status = response.status();
            if !status.is_success() {
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let body_text = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .replace(self.api_key.expose(), "[REDACTED]");
                    return Err(anyhow::Error::new(QuotaError {
                        provider: self.name,
                        retry_after,
                        body: body_text.trim().to_string(),
                    }));
                }
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into())
                    .replace(self.api_key.expose(), "[REDACTED]");
                anyhow::bail!(
                    "{} stream returned HTTP {}: {}",
                    self.name,
                    status.as_u16(),
                    body_text.trim()
                );
            }

            let name = self.name;
            let byte_stream = response.bytes_stream();
            // Buffer partial lines across byte chunks (SSE lines may be split
            // across reqwest byte chunks on slow connections).
            let inner: ChunkStream = Box::pin(async_stream::try_stream! {
                let mut buf = String::new();
                let mut input_tokens: Option<u32> = None;
                let mut output_tokens: Option<u32> = None;

                tokio::pin!(byte_stream);
                while let Some(chunk_result) = byte_stream.next().await {
                    let bytes = chunk_result
                        .with_context(|| format!("{name}: SSE byte read error"))?;
                    let text = std::str::from_utf8(&bytes)
                        .with_context(|| format!("{name}: SSE chunk not valid UTF-8"))?;
                    buf.push_str(text);

                    // Process all complete lines (\n-terminated SSE lines).
                    while let Some(newline_pos) = buf.find('\n') {
                        let line = buf[..newline_pos].trim_end_matches('\r').to_string();
                        buf.drain(..=newline_pos);

                        if line.is_empty() || line.starts_with(':') {
                            // SSE comment or blank separator — skip.
                            continue;
                        }
                        let Some(data) = sse_data(&line) else {
                            continue;
                        };
                        if data == "[DONE]" {
                            // Emit the final done-chunk with token counts.
                            yield CompletionChunk {
                                delta: String::new(),
                                done: true,
                                identity: Default::default(),
                                input_tokens,
                                output_tokens,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                            return;
                        }
                        // Parse the streaming JSON chunk.
                        let parsed: SseChunk = match serde_json::from_str(data) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(
                                    adapter = name,
                                    error = %e,
                                    raw = data,
                                    "SSE chunk parse error; skipping"
                                );
                                continue;
                            }
                        };
                        // Capture token counts from any usage block the endpoint
                        // injects (Ollama compat includes them on the last data
                        // line, OpenAI includes them only with stream_options).
                        if let Some(u) = &parsed.usage {
                            input_tokens = Some(u.prompt_tokens);
                            output_tokens = Some(u.completion_tokens);
                        }
                        let delta = parsed
                            .choices
                            .into_iter()
                            .next()
                            .and_then(|c| c.delta.content)
                            .unwrap_or_default();
                        if !delta.is_empty() {
                            yield CompletionChunk {
                                delta,
                                done: false,
                                identity: Default::default(),
                                input_tokens: None,
                                output_tokens: None,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                        }
                    }
                }
                // EOF residual: parse a final `data:` line the endpoint ended
                // WITHOUT a trailing newline (the line-loop never consumed it), so
                // a newline-less last delta or usage block isn't dropped before the
                // terminator. `[DONE]`/empty just falls through to the terminator.
                let tail = buf.trim();
                if let Some(data) = sse_data(tail) {
                    let data = data.trim();
                    if !data.is_empty() && data != "[DONE]"
                        && let Ok(parsed) = serde_json::from_str::<SseChunk>(data) {
                            if let Some(u) = &parsed.usage {
                                input_tokens = Some(u.prompt_tokens);
                                output_tokens = Some(u.completion_tokens);
                            }
                            if let Some(delta) = parsed
                                .choices
                                .into_iter()
                                .next()
                                .and_then(|c| c.delta.content)
                                && !delta.is_empty() {
                                    yield CompletionChunk {
                                        delta,
                                        done: false,
                                        identity: Default::default(),
                                        input_tokens: None,
                                        output_tokens: None,
                                        cache_creation_tokens: None,
                                        cache_read_tokens: None,
                                    };
                                }
                        }
                }
                // Stream ended without [DONE] — emit a done-chunk so consumers
                // see a clean terminator even from misbehaving endpoints.
                yield CompletionChunk {
                    delta: String::new(),
                    done: true,
                    identity: Default::default(),
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                };
            });

            debug!(adapter = name, model = %model, "openai SSE stream started");
            Ok(inner)
        })
        .await
    }
}

// ── Wire types ─────────────────────────────────────────────────────────────
//
// Minimal shapes — only the fields we read or send. The remote may include
// many more; serde tolerates that with `#[serde(default)]` + ignoring unknown.

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

// ── SSE streaming wire types ────────────────────────────────────────────────
//
// OpenAI streaming format: each `data:` line is a JSON object with a
// `choices[].delta.content` field.  The final line is `data: [DONE]`.
// Usage is only present when the endpoint opts in (stream_options or
// Ollama's own done-chunk injection); it is always optional here.

#[derive(Deserialize)]
struct SseChunk {
    #[serde(default)]
    choices: Vec<SseChoice>,
    #[serde(default)]
    usage: Option<SseUsage>,
}

/// Return the payload of an SSE `data` field. The single space after `:` is
/// optional per the wire format, so `data:{...}` and `data: {...}` must take
/// the same parser path in both the line loop and the EOF residual handler.
fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:")
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
}

#[derive(Deserialize)]
struct SseChoice {
    delta: SseDelta,
}

#[derive(Deserialize)]
struct SseDelta {
    content: Option<String>,
}

#[derive(Deserialize)]
struct SseUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    /// We don't run a live HTTP server in unit tests — that lives in an
    /// integration test once mockito/wiremock is added. Here we just verify
    /// the adapter constructs and reports its name. The actual HTTP round
    /// trip is covered by mocking-based tests in `tests/openai_mock.rs`
    /// (Phase 5A-6).
    #[test]
    fn adapter_constructs_with_endpoint_and_key() {
        let a = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-4o".to_string(),
        )
        .expect("construct");
        assert_eq!(a.name(), "openai_api");

        let b = OpenAiAdapter::new_compat(
            "http://localhost:8080/v1".to_string(),
            SecretString::from(""),
            "local-llama".to_string(),
        )
        .expect("construct compat");
        assert_eq!(b.name(), "openai_compat");
    }

    #[test]
    fn custom_openai_endpoint_has_a_distinct_unknown_pricing_identity() {
        let custom = OpenAiAdapter::new_openai(
            "https://gateway.example.test/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        assert_eq!(custom.name(), "openai_api_custom");
        assert!(crate::providers::cost::lookup_price(custom.name(), "gpt-5").is_none());
        let request = serde_json::to_value(custom.chat_request(
            "gpt-5".into(),
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }],
            false,
            &Request::default(),
        ))
        .unwrap();
        assert_eq!(request["max_tokens"], 4096);
        assert!(request.get("max_completion_tokens").is_none());
    }

    #[test]
    fn only_the_exact_official_openai_origin_and_v1_path_keep_official_identity() {
        for endpoint in [
            "https://api.openai.com/v1",
            "https://api.openai.com:443/v1/",
        ] {
            let adapter = OpenAiAdapter::new_openai(
                endpoint.into(),
                SecretString::from("sk-test"),
                "gpt-5".into(),
            )
            .unwrap();
            assert_eq!(adapter.name(), "openai_api", "endpoint={endpoint}");
        }

        for endpoint in [
            "http://api.openai.com/v1",
            "https://api.openai.com.evil.example/v1",
            "https://api.openai.com/v1/extra",
            "https://api.openai.com/v1?route=other",
            "https://user@api.openai.com/v1",
        ] {
            let adapter = OpenAiAdapter::new_openai(
                endpoint.into(),
                SecretString::from("sk-test"),
                "gpt-5".into(),
            )
            .unwrap();
            assert_eq!(adapter.name(), "openai_api_custom", "endpoint={endpoint}");
        }
    }

    #[test]
    fn native_copilot_and_compat_requests_use_supported_output_cap_fields() {
        let native = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let copilot = OpenAiAdapter::new_copilot(
            "https://api.githubcopilot.com".to_string(),
            SecretString::from("copilot-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let compat = OpenAiAdapter::new_compat(
            "http://localhost:8080/v1".to_string(),
            SecretString::from(""),
            "local-llama".to_string(),
        )
        .unwrap();
        let message = || {
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }]
        };

        for streaming in [false, true] {
            let native_json = serde_json::to_value(native.chat_request(
                "gpt-5".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(native_json["stream"], streaming);
            assert_eq!(native_json["max_completion_tokens"], 4096);
            assert!(native_json.get("max_tokens").is_none());

            let copilot_json = serde_json::to_value(copilot.chat_request(
                "gpt-5".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(copilot_json["stream"], streaming);
            assert_eq!(copilot_json["max_completion_tokens"], 4096);
            assert!(copilot_json.get("max_tokens").is_none());

            let compat_json = serde_json::to_value(compat.chat_request(
                "local-llama".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(compat_json["stream"], streaming);
            assert_eq!(compat_json["max_tokens"], 4096);
            assert!(compat_json.get("max_completion_tokens").is_none());
        }
    }

    #[test]
    fn request_controls_are_serialized_and_absent_controls_are_omitted() {
        let adapter = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let message = || {
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }]
        };
        let empty = serde_json::to_value(adapter.chat_request(
            "gpt-5".into(),
            message(),
            false,
            &Request::default(),
        ))
        .unwrap();
        for field in ["temperature", "top_p", "seed", "stop"] {
            assert!(empty.get(field).is_none(), "unexpected {field}: {empty}");
        }

        let controlled = serde_json::to_value(adapter.chat_request(
            "gpt-5".into(),
            message(),
            false,
            &Request {
                temperature: Some(0.4),
                top_p: Some(0.8),
                sampling_seed: Some(42),
                stop_sequences: vec!["END".into()],
                ..Request::default()
            },
        ))
        .unwrap();
        assert_eq!(controlled["temperature"].as_f64(), Some(f64::from(0.4_f32)));
        assert_eq!(controlled["top_p"].as_f64(), Some(f64::from(0.8_f32)));
        assert_eq!(controlled["seed"], 42);
        assert_eq!(controlled["stop"], serde_json::json!(["END"]));
    }

    #[test]
    fn trailing_slash_in_endpoint_is_stripped() {
        let a = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1/".to_string(),
            SecretString::from("sk-test"),
            "gpt-4o".to_string(),
        )
        .expect("construct");
        assert_eq!(a.endpoint, "https://api.openai.com/v1");
    }

    // ── Pick #31 (Session 14) — wiremock-backed e2e shape tests ──────
    //
    // Codex feedback #4 asked for live provider/council e2e. The
    // CI-runnable half lives here: wiremock spins up a local HTTP
    // server, the adapter dials it as if it were OpenAI, we assert
    // the request shape + response handling for the four classes
    // (200 OK / 429 rate-limited / 401 auth-fail / 500 server-error)
    // without burning real tokens. The live half (real OpenAI key)
    // is on the operator to run + post results — flagged in PROGRESS.md.

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(server_uri: &str) -> OpenAiAdapter {
        OpenAiAdapter::build(
            server_uri.to_string(),
            SecretString::from("sk-test-mock-key"),
            "gpt-4o-mock".to_string(),
            "openai_api",
        )
        .expect("adapter constructs against mock URI")
    }

    fn build_compat_adapter_against(server_uri: &str) -> OpenAiAdapter {
        OpenAiAdapter::new_compat(
            server_uri.to_string(),
            SecretString::from("compat-test-key"),
            "local-llama".to_string(),
        )
        .expect("compat adapter constructs against mock URI")
    }

    #[tokio::test]
    async fn mock_200_ok_returns_completion_with_token_counts() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer sk-test-mock-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-mock-1",
                "object": "chat.completion",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o-mock",
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": "hello from mock" },
                    "finish_reason": "stop"
                }],
                "usage": { "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "say hi".into(),
            ..Default::default()
        };
        let completion = adapter.complete(req).await.expect("200 OK must succeed");
        assert_eq!(completion.text, "hello from mock");
        assert_eq!(completion.input_tokens, Some(7));
        assert_eq!(completion.output_tokens, Some(3));
        assert_eq!(completion.model, "gpt-4o-mock");
    }

    #[tokio::test]
    async fn mock_429_rate_limited_returns_quota_error_with_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "12")
                    .set_body_raw(
                        r#"{"error":{"message":"rate_limit_exceeded"}}"#,
                        "application/json",
                    ),
            )
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "should rate-limit".into(),
            ..Default::default()
        };
        let err = adapter
            .complete(req)
            .await
            .expect_err("429 must surface as QuotaError");
        // QuotaError carries Retry-After + body. Downcast to inspect.
        let quota = err
            .downcast_ref::<QuotaError>()
            .expect("downcast to QuotaError");
        assert_eq!(quota.provider, "openai_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(12)));
        assert!(quota.body.contains("rate_limit_exceeded"));
    }

    #[tokio::test]
    async fn mock_401_auth_fail_returns_descriptive_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_raw(
                r#"{"error":{"message":"Incorrect API key provided"}}"#,
                "application/json",
            ))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("401 must surface as error");
        let msg = err.to_string();
        assert!(msg.contains("401"), "error must name status; got: {msg}");
        assert!(
            msg.contains("openai_api"),
            "error must name provider; got: {msg}"
        );
    }

    #[tokio::test]
    async fn mock_500_transient_returns_status_in_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_raw(
                r#"{"error":{"message":"backend timeout"}}"#,
                "application/json",
            ))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("500 must surface as error");
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("backend timeout"));
    }

    #[tokio::test]
    async fn custom_endpoint_does_not_follow_cross_origin_redirects() {
        let redirect_target = MockServer::start().await;
        let source = MockServer::start().await;
        let location = format!("{}/capture", redirect_target.uri());
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", location))
            .mount(&source)
            .await;

        let adapter =
            OpenAiAdapter::new_openai(source.uri(), SecretString::from("sk-test"), "gpt-5".into())
                .unwrap();
        let error = adapter
            .complete(Request {
                prompt: "must stay on source origin".into(),
                ..Default::default()
            })
            .await
            .expect_err("307 must surface instead of being followed");
        assert!(error.to_string().contains("307"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("request recording enabled")
                .is_empty(),
            "the redirected origin must receive no request"
        );
    }

    #[tokio::test]
    async fn mock_200_with_no_choices_surfaces_cdx07_silent_fail_guard() {
        // CDX-07 silent-fail-to-empty: a 200 with no choices[] must
        // NOT return Ok(text=""). The provider explicitly errors so
        // the operator sees the content-filter / refusal signal.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-filtered",
                "model": "gpt-4o-mock",
                "choices": [],
                "usage": { "prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "filtered".into(),
                ..Default::default()
            })
            .await
            .expect_err("empty choices[] must error, not return Ok(\"\")");
        let msg = err.to_string();
        assert!(
            msg.contains("no choices") || msg.contains("content-filter"),
            "error must explain WHY; got: {msg}"
        );
    }

    #[tokio::test]
    async fn mock_200_with_missing_usage_returns_none_token_counts() {
        // Pick #34 (Session 14, test-gap audit-fix): OpenAI-compat
        // endpoints (vLLM, LM Studio, some Ollama versions) routinely
        // omit the `usage` field. Prior tests always supplied `usage`
        // so the `Option<u32>` fall-through path was never pinned —
        // a future refactor changing `input_tokens` to non-optional
        // would silently break those endpoints. This pins the
        // contract: missing usage → `None` token counts, no error.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-no-usage",
                "model": "gpt-4o-mock",
                "choices": [{
                    "message": { "role": "assistant", "content": "fine" }
                }]
                // NOTE: no `usage` key — endpoint dropped it
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect("missing usage must not cause an error");
        assert_eq!(completion.text, "fine");
        assert_eq!(completion.input_tokens, None);
        assert_eq!(completion.output_tokens, None);
    }

    #[tokio::test]
    async fn mock_request_carries_correct_bearer_and_payload() {
        // The 200-success test already verifies the bearer header
        // matches via `wiremock::matchers::header`. This test
        // additionally asserts the JSON body shape (system + user
        // messages in `messages[]`, model from override, stream=false).
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "gpt-5.5-override",
                "messages": [
                    { "role": "system", "content": "you are NEOTH" },
                    { "role": "user", "content": "ping" }
                ],
                "stream": false,
                "max_completion_tokens": 4096,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": { "role": "assistant", "content": "pong" }
                }],
                "usage": { "prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "ping".into(),
            system: Some("you are NEOTH".into()),
            model: Some("gpt-5.5-override".into()),
            ..Default::default()
        };
        let completion = adapter
            .complete(req)
            .await
            .expect("body-shape mock must match");
        assert_eq!(completion.text, "pong");
        assert_eq!(completion.model, "gpt-5.5-override");
    }

    #[tokio::test]
    async fn mock_compat_complete_uses_only_legacy_max_tokens() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "local-llama",
                "messages": [{ "role": "user", "content": "ping" }],
                "stream": false,
                "max_tokens": 4096,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": { "role": "assistant", "content": "pong" }
                }]
            })))
            .mount(&mock)
            .await;

        let completion = build_compat_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("compat complete body must use max_tokens");
        assert_eq!(completion.text, "pong");
    }

    // ── SSE streaming tests ────────────────────────────────────────────

    /// Proves the SSE stream() override accepts both legal `data:` forms:
    /// with and without the optional space after the colon.
    #[tokio::test]
    async fn mock_sse_stream_delivers_progressive_chunks() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data:{\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n",
            "data: [DONE]\n\n",
        );

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer sk-test-mock-key"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "say hi".into(),
            ..Default::default()
        };

        let mut stream = adapter.stream(req).await.expect("stream must start");
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("chunk must be Ok"));
        }

        // Must have received at least 2 content chunks + 1 done chunk.
        assert!(
            chunks.len() >= 3,
            "expected ≥3 chunks (2 content + 1 done), got {}",
            chunks.len()
        );

        // Last chunk must be done.
        let last = chunks.last().unwrap();
        assert!(last.done, "last chunk must have done=true");

        // Content chunks must NOT have done=true.
        let content_chunks: Vec<_> = chunks.iter().filter(|c| !c.done).collect();
        assert!(
            !content_chunks.is_empty(),
            "must have at least one non-done content chunk"
        );

        // Accumulated text must equal "Hello world".
        let accumulated: String = content_chunks.iter().map(|c| c.delta.as_str()).collect();
        assert_eq!(accumulated, "Hello world");
    }

    /// Proves that stream:true is sent in the request body (not false like complete()).
    #[tokio::test]
    async fn mock_sse_stream_sends_stream_true_in_body() {
        use futures_util::StreamExt;

        let sse_body = "data: [DONE]\n\n";

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "gpt-4o-mock",
                "messages": [{"role": "user", "content": "ping"}],
                "stream": true,
                "max_completion_tokens": 4096,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "ping".into(),
            ..Default::default()
        };

        let mut stream = adapter.stream(req).await.expect("stream must start");
        // Drain — we only care that the mock matched (body_json assertion verifies stream:true).
        while stream.next().await.is_some() {}
    }

    #[tokio::test]
    async fn mock_compat_stream_uses_only_legacy_max_tokens() {
        use futures_util::StreamExt;

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "local-llama",
                "messages": [{ "role": "user", "content": "ping" }],
                "stream": true,
                "max_tokens": 4096,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw("data: [DONE]\n\n", "text/event-stream"),
            )
            .mount(&mock)
            .await;

        let mut stream = build_compat_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("compat stream body must use max_tokens");
        while stream.next().await.is_some() {}
    }
}
