//! Native Ollama `/api/chat` adapter (GOLD-ADAPT-AWE-NANO-01).
//!
//! Uses Ollama's own streaming protocol: POST `/api/chat` with NDJSON response
//! (one JSON object per line, NOT SSE). This gives access to Ollama-specific
//! options (`keep_alive`, `think`, `options.num_predict`, etc.) that the
//! OpenAI-compat `/v1/chat/completions` shim does not expose.
//!
//! For operators who want Ollama via the standard OpenAI-compat wire format
//! (e.g. to share a single adapter with vLLM/LM Studio), the `openai_compat`
//! provider kind still works and now also has full SSE streaming via the
//! `openai_api::OpenAiAdapter::stream()` implementation added in the same
//! item.
//!
//! # Provider registration
//!
//! `ProviderKind::LocalOllama` / `InferenceProvider::LocalOllama` route here
//! through `providers::from_config`. Loopback endpoints identify as
//! `"local_ollama"`; every other endpoint identifies as `"ollama_remote"`
//! so quota/privacy/cost guards cannot inherit a false local bypass.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::response_bounds;
use super::termination::ProviderTermination;
use super::{
    ChunkStream, Completion, CompletionChunk, CompletionUsageMeasurements, Provider,
    ProviderDispatchPermit,
    ProviderRequestControls, Request,
};

/// Default Ollama base URL when the operator hasn't overridden it.
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434";
/// Default model when the operator hasn't set one.
pub const DEFAULT_MODEL: &str = "llama3.2";

/// An Ollama endpoint is an untrusted byte source even on loopback: the daemon
/// proxies model-controlled output and a remote endpoint is fully hostile.
/// These caps bound allocation before any parse.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_SUCCESS_BODY_BYTES: usize = response_bounds::MAX_SUCCESS_JSON_BODY_BYTES;
const MAX_NDJSON_FRAME_BYTES: usize = response_bounds::MAX_SSE_FRAME_BYTES;
const ERROR_BODY_EVIDENCE_DOMAIN: &[u8] = b"ollama-http-error-body/v1";
const SUCCESS_BODY_EVIDENCE_DOMAIN: &[u8] = b"ollama-success-body/v1";
const NDJSON_FRAME_EVIDENCE_DOMAIN: &[u8] = b"ollama-ndjson-frame/v1";
const NDJSON_TRANSPORT_EVIDENCE_DOMAIN: &[u8] = b"ollama-ndjson-transport/v1";
/// Hard generation cap sent as Ollama's `options.num_predict`. This makes a
/// remote Ollama endpoint cost-authorizable instead of relying on its server
/// default, which may be unlimited/model-dependent.
const OUTPUT_TOKEN_CEILING: u32 = super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING;

/// Adapter for Ollama's native `/api/chat` endpoint.
pub struct OllamaAdapter {
    /// e.g. `http://localhost:11434` — no trailing slash.
    base_url: String,
    /// Model name (e.g. `llama3.2`, `qwen2.5:7b`).
    model: String,
    /// Only loopback endpoints are local/free. Private-LAN and public hosts are
    /// remote dispatches and must cross the paid-provider boundary.
    is_loopback_endpoint: bool,
    /// Shared HTTP client.
    http: reqwest::Client,
}

impl OllamaAdapter {
    pub fn new(base_url: String, model: String) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&base_url)
            .with_context(|| format!("parse Ollama endpoint `{base_url}`"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            anyhow::bail!(
                "Ollama endpoint `{base_url}` must use http or https, got `{}`",
                parsed.scheme()
            );
        }
        parsed
            .host()
            .with_context(|| format!("Ollama endpoint `{base_url}` has no host"))?;
        let is_loopback_endpoint = super::http_client::url_has_loopback_host(&parsed);
        let http = if is_loopback_endpoint {
            crate::providers::http_client::build_direct_client_no_redirect()?
        } else {
            crate::providers::http_client::build_client_no_redirect()?
        };
        Ok(Self {
            base_url,
            model,
            is_loopback_endpoint,
            http,
        })
    }
}

#[async_trait]
impl Provider for OllamaAdapter {
    fn name(&self) -> &'static str {
        if self.is_loopback_endpoint {
            "local_ollama"
        } else {
            "ollama_remote"
        }
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING.with_output_token_limit()
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.model)
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        Some(crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::LocalOllama,
            Some(&self.base_url),
        ))
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        effective_output_token_cap(req, self.is_loopback_endpoint)
    }

    fn streams_on_wire(&self) -> bool {
        true
    }

    /// Non-streaming completion via `/api/chat` with `stream: false`.
    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        let provider_name = self.name();
        crate::providers::circuit_breaker::run_with_breaker(provider_name, async {
            let started = Instant::now();
            let model = req.model.clone().unwrap_or_else(|| self.model.clone());

            let body = build_request(&model, &req, false, self.is_loopback_endpoint);
            let url = format!("{}/api/chat", self.base_url);

            let response = self
                .http
                .post(&url)
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = response.status();
            if !status.is_success() {
                let evidence = response_bounds::error_body_evidence(
                    response,
                    ERROR_BODY_EVIDENCE_DOMAIN,
                    MAX_ERROR_BODY_BYTES,
                )
                .await;
                anyhow::bail!(
                    "{provider_name} returned HTTP {} ({evidence})",
                    status.as_u16()
                );
            }

            let parsed: OllamaChatResponse = response_bounds::decode_json(
                response,
                provider_name,
                SUCCESS_BODY_EVIDENCE_DOMAIN,
                MAX_SUCCESS_BODY_BYTES,
            )
            .await?;

            let termination = ProviderTermination::finished(parsed.done_reason.clone());
            let text = parsed.message.content;
            let usage_measurements = match (parsed.prompt_eval_count, parsed.eval_count) {
                (None, None) => None,
                (input_tokens, output_tokens) => Some(
                    CompletionUsageMeasurements::provider_reported(
                        input_tokens,
                        output_tokens,
                        None,
                        None,
                        None,
                        None,
                    )?,
                ),
            };
            let latency = started.elapsed();
            debug!(
                adapter = provider_name,
                model = %model,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "ollama completion"
            );

            Ok(Completion {
                text,
                identity: Default::default(),
                model,
                termination,
                latency,
                input_tokens: parsed.prompt_eval_count,
                output_tokens: parsed.eval_count,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements,
            })
        })
        .await
    }

    /// Streaming completion via `/api/chat` with `stream: true`.
    ///
    /// Ollama returns NDJSON: one JSON object per line, each with
    /// `message.content` (delta text) and `done` (true on the final line).
    /// The final line also carries `prompt_eval_count` and `eval_count` for
    /// token metering.
    async fn stream_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        let provider_name = self.name();
        crate::providers::circuit_breaker_stream::run_stream_with_breaker(provider_name, async {
            let model = req.model.clone().unwrap_or_else(|| self.model.clone());

            let body = build_request(&model, &req, true, self.is_loopback_endpoint);
            let url = format!("{}/api/chat", self.base_url);

            let response = self
                .http
                .post(&url)
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url} (stream)"))?;

            let status = response.status();
            if !status.is_success() {
                let evidence = response_bounds::error_body_evidence(
                    response,
                    ERROR_BODY_EVIDENCE_DOMAIN,
                    MAX_ERROR_BODY_BYTES,
                )
                .await;
                anyhow::bail!(
                    "{provider_name} stream returned HTTP {} ({evidence})",
                    status.as_u16()
                );
            }

            let model_log = model.clone();
            let byte_stream = response.bytes_stream();

            let inner: ChunkStream = Box::pin(async_stream::try_stream! {
                // Raw bytes, not a String: a UTF-8 code point may be split
                // across transport chunks, and an unterminated line must hit a
                // hard cap instead of growing until the process dies.
                let mut line_buf: Vec<u8> = Vec::new();
                let mut input_tokens: Option<u32> = None;
                let mut output_tokens: Option<u32> = None;
                let mut finish_reason: Option<String> = None;

                tokio::pin!(byte_stream);
                while let Some(chunk_result) = byte_stream.next().await {
                    let bytes = match chunk_result {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            let evidence = response_bounds::stream_evidence(
                                NDJSON_TRANSPORT_EVIDENCE_DOMAIN,
                                &[line_buf.as_slice()],
                                true,
                            );
                            Err(anyhow::anyhow!(
                                "{provider_name}: NDJSON transport read failed ({evidence})"
                            ))?
                        }
                    };
                    let mut cursor = 0usize;

                    // Each Ollama response line is a complete JSON object.
                    while let Some(relative_newline) =
                        bytes[cursor..].iter().position(|byte| *byte == b'\n')
                    {
                        let newline_pos = cursor + relative_newline;
                        response_bounds::append_frame_segment(
                            &mut line_buf,
                            &bytes[cursor..newline_pos],
                            provider_name,
                            NDJSON_FRAME_EVIDENCE_DOMAIN,
                            MAX_NDJSON_FRAME_BYTES,
                        )?;
                        cursor = newline_pos + 1;

                        let decoded = decode_ndjson_frame(&line_buf, provider_name)?;
                        line_buf.clear();
                        let Some(chunk) = decoded else {
                            continue;
                        };

                        if chunk.done {
                            // Capture token counts from the done line.
                            input_tokens = chunk.prompt_eval_count;
                            output_tokens = chunk.eval_count;
                            yield CompletionChunk {
                                delta: String::new(),
                                done: true,
                                termination: ProviderTermination::finished(chunk.done_reason),
                                identity: Default::default(),
                                input_tokens,
                                output_tokens,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                            return;
                        }

                        let delta = chunk.message.content;
                        if !delta.is_empty() {
                            yield CompletionChunk {
                                delta,
                                done: false,
                                termination: Default::default(),
                                identity: Default::default(),
                                input_tokens: None,
                                output_tokens: None,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                        }
                    }
                    response_bounds::append_frame_segment(
                        &mut line_buf,
                        &bytes[cursor..],
                        provider_name,
                        NDJSON_FRAME_EVIDENCE_DOMAIN,
                        MAX_NDJSON_FRAME_BYTES,
                    )?;
                }

                // EOF residual: a server may end the FINAL JSON line without a
                // trailing newline, so the line-loop above never consumed it.
                // Parse whatever is left before synthesising the terminator so a
                // newline-less done line (token counts) or content delta is not
                // dropped. A malformed residual fails closed here: skipping it
                // and then emitting the terminator below would report a
                // successful, complete generation that never happened.
                if let Some(chunk) = decode_ndjson_frame(&line_buf, provider_name)? {
                    if chunk.done {
                        input_tokens = chunk.prompt_eval_count;
                        output_tokens = chunk.eval_count;
                        finish_reason = chunk.done_reason;
                    } else if !chunk.message.content.is_empty() {
                        yield CompletionChunk {
                            delta: chunk.message.content,
                            done: false,
                            termination: Default::default(),
                            identity: Default::default(),
                            input_tokens: None,
                            output_tokens: None,
                            cache_creation_tokens: None,
                            cache_read_tokens: None,
                        };
                    }
                }

                // Stream ended; emit a clean terminator carrying any token
                // counts captured from a done line (incl. a newline-less tail).
                yield CompletionChunk {
                    delta: String::new(),
                    done: true,
                    termination: ProviderTermination::finished(finish_reason),
                    identity: Default::default(),
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                };
            });

            debug!(
                adapter = provider_name,
                model = %model_log,
                "ollama NDJSON stream started"
            );
            Ok(inner)
        })
        .await
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// Request body for POST /api/chat.
#[derive(Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    /// How long to keep the model loaded after the request (e.g. "5m").
    /// `None` uses the Ollama server default (5 minutes).
    #[serde(skip_serializing_if = "Option::is_none")]
    keep_alive: Option<String>,
}

#[derive(Serialize)]
struct OllamaMessage {
    role: &'static str,
    content: String,
}

/// Subset of Ollama Modelfile parameters the Request fields map to.
#[derive(Serialize, Default)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop: Vec<String>,
    /// Maps to Request sampling; caps generation length when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

/// One NDJSON line in a streaming response (also the single object when
/// `stream: false`).
#[derive(Deserialize)]
struct OllamaChatChunk {
    message: OllamaResponseMessage,
    done: bool,
    /// Provider-native reason for the final line (for example `stop` or `length`).
    #[serde(default)]
    done_reason: Option<String>,
    /// Present only on the final done=true line.
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    /// Present only on the final done=true line.
    #[serde(default)]
    eval_count: Option<u32>,
}

/// Non-streaming response (stream: false) has the same shape as a done chunk.
type OllamaChatResponse = OllamaChatChunk;

#[derive(Deserialize)]
struct OllamaResponseMessage {
    content: String,
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Decodes one bounded NDJSON frame.
///
/// UTF-8 is validated only here, once a complete line exists, so a code point
/// split across transport chunks stays valid while invalid UTF-8 fails closed.
/// A blank frame is `None`; a malformed frame is an error, never a skip: the
/// stream would otherwise drop real output and still terminate as if the
/// generation had completed successfully. Errors carry digest evidence only —
/// the frame body is model/gateway controlled.
fn decode_ndjson_frame(
    frame: &[u8],
    adapter_name: &'static str,
) -> Result<Option<OllamaChatChunk>> {
    let text = response_bounds::frame_utf8(frame, adapter_name, NDJSON_FRAME_EVIDENCE_DOMAIN)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed).map(Some).map_err(|error| {
        let evidence =
            response_bounds::frame_evidence(NDJSON_FRAME_EVIDENCE_DOMAIN, &[frame], false);
        anyhow::anyhow!(
            "{adapter_name}: malformed NDJSON frame at line {} column {} ({evidence})",
            error.line(),
            error.column()
        )
    })
}

fn build_request(
    model: &str,
    req: &Request,
    stream: bool,
    is_loopback_endpoint: bool,
) -> OllamaChatRequest {
    let mut messages = Vec::new();
    if let Some(sys) = &req.system {
        messages.push(OllamaMessage {
            role: "system",
            content: sys.clone(),
        });
    }
    messages.push(OllamaMessage {
        role: "user",
        content: req.prompt.clone(),
    });

    let options = {
        // The ceiling exists to make a REMOTE endpoint cost-authorizable: it is
        // the wire-enforced output limit paid-call authorization relies on. A
        // loopback endpoint is neither remote nor metered, and sending it there
        // silently truncated long local generations (code, documents) at the
        // cloud ceiling where they previously ran to completion — with no
        // request field to raise it. Local stays on the server's own default.
        let opts = OllamaOptions {
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.sampling_seed,
            stop: req.stop_sequences.clone(),
            num_predict: effective_output_token_cap(req, is_loopback_endpoint),
        };
        // `num_predict` is mandatory for a remote endpoint: it is the
        // wire-enforced output ceiling used by paid-call authorization.
        if opts.temperature.is_some()
            || opts.top_p.is_some()
            || opts.seed.is_some()
            || !opts.stop.is_empty()
            || opts.num_predict.is_some()
        {
            Some(opts)
        } else {
            None
        }
    };

    OllamaChatRequest {
        model: model.to_string(),
        messages,
        stream,
        options,
        keep_alive: None, // use Ollama server default
    }
}

/// The exact wire-enforced Ollama output limit, if one exists.
///
/// Remote endpoints keep their reviewed default ceiling and only accept a
/// narrower request limit. Loopback endpoints do not claim a ceiling for an
/// unknown server default, but explicitly requested limits are serialized and
/// therefore safe to report to authorization.
fn effective_output_token_cap(req: &Request, is_loopback_endpoint: bool) -> Option<u32> {
    match (req.max_output_tokens, is_loopback_endpoint) {
        (Some(requested), true) => Some(requested),
        (Some(requested), false) => Some(requested.min(OUTPUT_TOKEN_CEILING)),
        (None, true) => None,
        (None, false) => Some(OUTPUT_TOKEN_CEILING),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use futures_util::StreamExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(base_url: &str) -> OllamaAdapter {
        // Bounds tests deliberately fail provider calls, and the breaker
        // registry is process-global per adapter identity. Without this reset
        // the fifth deliberate failure opens the breaker and every later test
        // in this file observes that instead of its own fixture. Both
        // identities are reset because the constructor, not the caller, decides
        // which one this base URL resolves to.
        crate::providers::circuit_breaker::reset_for_test("local_ollama");
        crate::providers::circuit_breaker::reset_for_test("ollama_remote");
        OllamaAdapter::new(base_url.to_string(), "llama3.2-mock".to_string())
            .expect("adapter constructs against mock URL")
    }

    #[test]
    fn adapter_name_is_local_ollama() {
        let a = build_adapter_against("http://localhost:11434");
        assert_eq!(a.name(), "local_ollama");
    }

    #[test]
    fn locality_is_derived_from_loopback_endpoint_not_provider_kind() {
        for endpoint in [
            "http://localhost:11434",
            "http://LOCALHOST.:11434",
            "http://127.0.0.42:11434",
            "http://[::1]:11434",
        ] {
            let adapter = build_adapter_against(endpoint);
            assert_eq!(adapter.name(), "local_ollama", "endpoint={endpoint}");
        }

        for endpoint in [
            "https://ollama.example.com",
            "http://192.168.1.20:11434",
            "http://localhost.evil.example:11434",
        ] {
            let adapter = build_adapter_against(endpoint);
            assert_eq!(adapter.name(), "ollama_remote", "endpoint={endpoint}");
            assert!(!crate::providers::is_local_provider(adapter.name()));
        }
    }

    #[tokio::test]
    async fn strict_blocks_remote_ollama_before_any_network_dispatch() {
        let adapter = build_adapter_against("https://ollama.example.com");
        let error = adapter
            .complete_authorized(
                Request::default(),
                &crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                    crate::permissions::AutonomyLevel::Strict,
                ),
                "test.remote_ollama",
            )
            .await
            .expect_err("remote endpoint must cross and fail the paid-provider gate");
        assert!(error.to_string().contains("authorization"));
    }

    #[test]
    fn trailing_slash_in_base_url_is_stripped() {
        let a = OllamaAdapter::new(
            "http://localhost:11434/".to_string(),
            "llama3.2".to_string(),
        )
        .expect("construct");
        assert_eq!(a.base_url, "http://localhost:11434");
    }

    #[test]
    fn is_local_provider_recognises_local_ollama() {
        assert!(
            crate::providers::is_local_provider("local_ollama"),
            "local_ollama must pass the is_local_provider gate"
        );
    }

    /// Non-streaming complete(): mock returns a single Ollama done-JSON.
    #[tokio::test]
    async fn mock_complete_returns_text_and_token_counts() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "llama3.2-mock",
                "created_at": "2026-06-29T00:00:00Z",
                "message": { "role": "assistant", "content": "hello from ollama" },
                "done": true,
                "done_reason": "stop",
                "prompt_eval_count": 8,
                "eval_count": 4
            })))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "say hi".into(),
                ..Default::default()
            })
            .await
            .expect("200 must succeed");
        assert_eq!(completion.text, "hello from ollama");
        assert_eq!(completion.input_tokens, Some(8));
        assert_eq!(completion.output_tokens, Some(4));
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("stop")
        );
    }

    /// Streaming stream(): mock returns three NDJSON lines + a done line;
    /// we must receive ≥2 content chunks and a final done chunk.
    #[tokio::test]
    async fn mock_ndjson_stream_delivers_progressive_chunks() {
        let ndjson_body = concat!(
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"done\":false}\n",
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\" there\"},\"done\":false}\n",
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":5,\"eval_count\":3}\n",
        );

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let mut stream = adapter
            .stream(Request {
                prompt: "say hi".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");

        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("chunk must be Ok"));
        }

        let done_chunks: Vec<_> = chunks.iter().filter(|c| c.done).collect();
        let content_chunks: Vec<_> = chunks.iter().filter(|c| !c.done).collect();

        assert!(!done_chunks.is_empty(), "must have a done chunk");
        assert!(
            content_chunks.len() >= 2,
            "must have ≥2 content chunks, got {}",
            content_chunks.len()
        );

        let accumulated: String = content_chunks.iter().map(|c| c.delta.as_str()).collect();
        assert_eq!(accumulated, "Hi there");

        let done = done_chunks[0];
        assert_eq!(done.input_tokens, Some(5));
        assert_eq!(done.output_tokens, Some(3));
        assert_eq!(done.termination.finish_reason.as_deref(), Some("stop"));
    }

    /// EOF residual (review P2): a server may end the FINAL NDJSON line without a
    /// trailing newline. The done line (with token counts) must still be parsed,
    /// not dropped — so the terminator carries the real counts + the last content
    /// is delivered.
    #[tokio::test]
    async fn mock_ndjson_stream_parses_newline_less_final_done_line() {
        let ndjson_body = concat!(
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"done\":false}\n",
            // final done line — deliberately NO trailing newline:
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"length\",\"prompt_eval_count\":7,\"eval_count\":4}",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let mut stream = adapter
            .stream(Request {
                prompt: "hi".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("chunk must be Ok"));
        }
        let content: String = chunks
            .iter()
            .filter(|c| !c.done)
            .map(|c| c.delta.as_str())
            .collect();
        assert_eq!(content, "Hi");
        let done = chunks
            .iter()
            .find(|c| c.done)
            .expect("must have a done chunk");
        assert_eq!(
            done.input_tokens,
            Some(7),
            "newline-less final done line tokens must be captured"
        );
        assert_eq!(done.output_tokens, Some(4));
        assert_eq!(done.termination.finish_reason.as_deref(), Some("length"));
    }

    /// stream:true must be in the request body (not false like complete()).
    #[tokio::test]
    async fn mock_stream_sends_stream_true() {
        let ndjson_body = "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n";

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "stream": true
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ndjson_body, "application/x-ndjson"),
            )
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let mut stream = adapter
            .stream(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");
        while stream.next().await.is_some() {}
    }

    /// Non-streaming complete() sends stream:false.
    #[tokio::test]
    async fn mock_complete_sends_stream_false() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "stream": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "llama3.2-mock",
                "message": { "role": "assistant", "content": "pong" },
                "done": true
            })))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("stream:false complete must succeed");
        assert_eq!(completion.text, "pong");
    }

    /// HTTP 500 from Ollama must propagate as an error (not Ok).
    #[tokio::test]
    async fn mock_500_complete_surfaces_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_raw(r#"{"error":"model not found"}"#, "application/json"),
            )
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("HTTP 500 must surface as Err");
        let msg = err.to_string();
        assert!(msg.contains("500"), "error must mention status; got: {msg}");
    }

    #[tokio::test]
    async fn loopback_ollama_does_not_follow_redirects_off_origin() {
        let redirect_target = MockServer::start().await;
        let source = MockServer::start().await;
        let location = format!("{}/capture", redirect_target.uri());
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", location))
            .mount(&source)
            .await;

        let adapter = build_adapter_against(&source.uri());
        let error = adapter
            .complete(Request {
                prompt: "stay local".into(),
                ..Default::default()
            })
            .await
            .expect_err("loopback redirect must be surfaced, never followed");
        assert!(error.to_string().contains("307"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("request recording enabled")
                .is_empty(),
            "redirect target must receive no prompt"
        );
    }

    /// Sampling options are forwarded to the request body when set.
    #[tokio::test]
    async fn build_request_includes_options_when_set() {
        let req = Request {
            prompt: "test".into(),
            temperature: Some(0.7),
            top_p: Some(0.9),
            sampling_seed: Some(42),
            stop_sequences: vec!["</s>".into()],
            ..Default::default()
        };
        let body = build_request("llama3.2", &req, false, false);
        let opts = body
            .options
            .expect("options must be present when sampling fields set");
        assert_eq!(opts.temperature, Some(0.7));
        assert_eq!(opts.top_p, Some(0.9));
        assert_eq!(opts.seed, Some(42));
        assert_eq!(opts.stop, vec!["</s>"]);
        assert_eq!(opts.num_predict, Some(OUTPUT_TOKEN_CEILING));
    }

    /// The output cap is present even without sampling overrides — on a REMOTE
    /// endpoint, where it is what makes the call cost-authorizable.
    #[test]
    fn build_request_always_sends_authorized_num_predict_ceiling() {
        let req = Request {
            prompt: "test".into(),
            ..Default::default()
        };
        let body = build_request("llama3.2", &req, false, false);
        assert_eq!(
            body.options
                .expect("num_predict makes options mandatory")
                .num_predict,
            Some(OUTPUT_TOKEN_CEILING)
        );
    }

    /// External review PR4-016: the loopback endpoint is neither remote nor
    /// metered. Sending the cloud ceiling there truncated long local
    /// generations at 4096 tokens where they previously ran to completion, with
    /// no request field to raise it.
    #[test]
    fn loopback_endpoint_keeps_the_servers_own_output_limit() {
        let req = Request {
            prompt: "write a long document".into(),
            ..Default::default()
        };
        let local = build_request("llama3.2", &req, false, true);
        assert!(
            local.options.is_none_or(|opts| opts.num_predict.is_none()),
            "a loopback call must not carry the remote cost ceiling"
        );

        // Sampling overrides still travel on the local path.
        let tuned = Request {
            prompt: "test".into(),
            temperature: Some(0.5),
            ..Default::default()
        };
        let opts = build_request("llama3.2", &tuned, false, true)
            .options
            .expect("sampling overrides still produce options");
        assert_eq!(opts.temperature, Some(0.5));
        assert_eq!(opts.num_predict, None);
    }

    #[test]
    fn requested_output_cap_is_authorized_and_serialized_for_both_endpoint_kinds() {
        let req = Request {
            prompt: "bounded".into(),
            max_output_tokens: Some(88),
            ..Request::default()
        };
        let remote = OllamaAdapter::new("https://ollama.example".into(), "llama3.2".into())
            .expect("remote adapter constructs");
        let local = OllamaAdapter::new("http://127.0.0.1:11434".into(), "llama3.2".into())
            .expect("loopback adapter constructs");
        assert!(remote.request_controls().supports_max_output_tokens());
        assert_eq!(remote.output_token_ceiling(&req), Some(88));
        assert_eq!(local.output_token_ceiling(&req), Some(88));
        assert_eq!(
            build_request("llama3.2", &req, false, false)
                .options
                .expect("explicit cap makes options present")
                .num_predict,
            Some(88)
        );
        assert_eq!(
            build_request("llama3.2", &req, false, true)
                .options
                .expect("explicit local cap makes options present")
                .num_predict,
            Some(88)
        );

        let unbounded_local = Request {
            prompt: "server-default".into(),
            ..Request::default()
        };
        assert_eq!(local.output_token_ceiling(&unbounded_local), None);
    }

    #[test]
    fn remote_requested_output_cap_cannot_widen_the_reviewed_ceiling() {
        let req = Request {
            prompt: "bounded".into(),
            max_output_tokens: Some(crate::providers::MAX_REQUEST_OUTPUT_TOKENS),
            ..Request::default()
        };
        let remote = OllamaAdapter::new("https://ollama.example".into(), "llama3.2".into())
            .expect("remote adapter constructs");
        let local = OllamaAdapter::new("http://127.0.0.1:11434".into(), "llama3.2".into())
            .expect("loopback adapter constructs");
        assert_eq!(
            remote.output_token_ceiling(&req),
            Some(OUTPUT_TOKEN_CEILING)
        );
        assert_eq!(local.output_token_ceiling(&req), req.max_output_tokens);
        assert_eq!(
            build_request("llama3.2", &req, false, false)
                .options
                .expect("remote output cap makes options present")
                .num_predict,
            Some(OUTPUT_TOKEN_CEILING)
        );
        assert_eq!(
            build_request("llama3.2", &req, false, true)
                .options
                .expect("explicit loopback output cap makes options present")
                .num_predict,
            req.max_output_tokens
        );
    }

    // ── Response envelope bounds (GOLD-R4-15k1) ──────────────────────────────

    async fn mount_ndjson(mock: &MockServer, body: impl Into<Vec<u8>>) {
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(body.into(), "application/x-ndjson"),
            )
            .mount(mock)
            .await;
    }

    /// Drains a stream into (deltas, done-chunk count, first error).
    async fn drain(mut stream: ChunkStream) -> (String, usize, Option<String>) {
        let mut deltas = String::new();
        let mut done = 0usize;
        let mut error = None;
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    deltas.push_str(&chunk.delta);
                    if chunk.done {
                        done += 1;
                    }
                }
                Err(err) => {
                    error = Some(err.to_string());
                    break;
                }
            }
        }
        (deltas, done, error)
    }

    #[tokio::test]
    async fn oversized_success_body_fails_before_json_allocation() {
        let secret = "ollama-never-persist-oversized-success";
        let body = format!(
            r#"{{"message":{{"role":"assistant","content":"{secret}{}"}},"done":true}}"#,
            "x".repeat(MAX_SUCCESS_BODY_BYTES)
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&mock)
            .await;

        let message = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect_err("oversized successful body must fail before JSON parsing")
            .to_string();
        assert!(message.contains("successful response body exceeded"));
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn malformed_success_body_reports_only_digest_evidence() {
        let secret = "ollama-never-persist-malformed-success";
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(format!(r#"{{"secret":"{secret}""#), "application/json"),
            )
            .mount(&mock)
            .await;

        let message = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect_err("malformed successful body must fail")
            .to_string();
        assert!(message.contains("malformed successful JSON response"));
        assert!(message.contains("body_sha256="));
        assert!(!message.contains(secret));
    }

    #[tokio::test]
    async fn oversized_http_error_bodies_report_status_and_digest_only() {
        let secret = "ollama-never-persist-http-error";
        let body = format!("{secret}{}", "x".repeat(MAX_ERROR_BODY_BYTES * 2));
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_raw(body, "text/plain"))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());

        let complete_error = adapter
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect_err("HTTP 500 must surface as Err")
            .to_string();
        let stream_error = match adapter
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => panic!("stream handshake 500 must fail before yielding chunks"),
            Err(error) => error.to_string(),
        };

        for message in [complete_error, stream_error] {
            assert!(message.contains("HTTP 500"), "got: {message}");
            assert!(message.contains("body_sha256="));
            assert!(message.contains("truncated=true"));
            assert!(!message.contains(secret));
            assert!(!message.contains(&"x".repeat(128)));
        }
    }

    #[tokio::test]
    async fn newline_free_ndjson_frame_is_bounded_and_secret_safe() {
        let secret = "ollama-never-persist-newline-free-frame";
        let body = format!(
            r#"{{"content":"{secret}{}"#,
            "x".repeat(MAX_NDJSON_FRAME_BYTES)
        );
        let mock = MockServer::start().await;
        mount_ndjson(&mock, body).await;

        let stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("HTTP stream starts before the first frame is decoded");
        let (deltas, done, error) = drain(stream).await;
        let message = error.expect("newline-free oversized frame must fail");
        assert!(message.contains("streaming frame exceeded"));
        assert!(message.contains("frame_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
        assert!(deltas.is_empty());
        assert_eq!(
            done, 0,
            "an over-limit frame must not synthesize a done chunk"
        );
    }

    /// A malformed line used to be logged raw and skipped, after which the
    /// stream still emitted a done terminator — reporting a complete generation
    /// that silently lost output.
    #[tokio::test]
    async fn malformed_ndjson_line_fails_closed_without_synthetic_done() {
        let secret = "ollama-never-persist-malformed-frame";
        let body = format!(
            concat!(
                "{{\"message\":{{\"role\":\"assistant\",\"content\":\"Hi\"}},\"done\":false}}\n",
                "{{\"message\":\"{}\"\n",
                "{{\"message\":{{\"role\":\"assistant\",\"content\":\"\"}},\"done\":true,\"eval_count\":9}}\n"
            ),
            secret
        );
        let mock = MockServer::start().await;
        mount_ndjson(&mock, body).await;

        let stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");
        let (deltas, done, error) = drain(stream).await;
        let message = error.expect("malformed NDJSON line must fail closed");
        assert!(message.contains("malformed NDJSON frame"), "got: {message}");
        assert!(message.contains("frame_sha256="));
        assert!(!message.contains(secret));
        assert_eq!(deltas, "Hi", "output before the malformed frame is real");
        assert_eq!(
            done, 0,
            "a skipped frame must never look like a clean finish"
        );
    }

    #[tokio::test]
    async fn malformed_eof_residual_fails_closed_without_synthetic_done() {
        let secret = "ollama-never-persist-malformed-residual";
        let body = format!(
            "{}{{\"message\":\"{secret}\"",
            "{\"message\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"done\":false}\n"
        );
        let mock = MockServer::start().await;
        mount_ndjson(&mock, body).await;

        let stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");
        let (deltas, done, error) = drain(stream).await;
        let message = error.expect("malformed EOF residual must fail closed");
        assert!(message.contains("malformed NDJSON frame"), "got: {message}");
        assert!(!message.contains(secret));
        assert_eq!(deltas, "Hi");
        assert_eq!(
            done, 0,
            "a truncated tail must not be reported as a finished generation"
        );
    }

    #[tokio::test]
    async fn invalid_utf8_ndjson_line_reports_only_digest_evidence() {
        let mut body =
            b"{\"message\":{\"role\":\"assistant\",\"content\":\"ollama-never-persist-utf8-"
                .to_vec();
        body.extend_from_slice(&[0xff, 0xfe]);
        body.extend_from_slice(b"\"},\"done\":false}\n");
        let mock = MockServer::start().await;
        mount_ndjson(&mock, body).await;

        let stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("stream must start");
        let (deltas, done, error) = drain(stream).await;
        let message = error.expect("invalid UTF-8 frame must fail closed");
        assert!(message.contains("not valid UTF-8"), "got: {message}");
        assert!(message.contains("frame_sha256="));
        assert!(!message.contains("ollama-never-persist-utf8-"));
        assert!(deltas.is_empty());
        assert_eq!(done, 0);
    }

    /// A local HTTP/1.1 server answering one request with a
    /// `Transfer-Encoding: chunked` body split at caller-chosen byte offsets.
    /// A mock server that writes one whole body cannot reproduce a code point
    /// split across transfer chunks, which is exactly the case byte-oriented
    /// framing exists for.
    async fn serve_chunked_ndjson(parts: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind chunked fixture");
        let base = format!("http://{}", listener.local_addr().expect("fixture address"));
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept fixture request");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if socket.read(&mut byte).await.expect("read request head") == 0 {
                    return;
                }
                request.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            let content_length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut request_body = vec![0u8; content_length];
            socket
                .read_exact(&mut request_body)
                .await
                .expect("read request body");

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .expect("write response head");
            for part in parts {
                socket
                    .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await
                    .expect("write chunk size");
                socket.write_all(&part).await.expect("write chunk body");
                socket.write_all(b"\r\n").await.expect("write chunk end");
                socket.flush().await.expect("flush chunk");
            }
            socket
                .write_all(b"0\r\n\r\n")
                .await
                .expect("write terminal chunk");
            socket.flush().await.expect("flush response");
        });
        (base, handle)
    }

    #[tokio::test]
    async fn chunked_transport_reassembles_codepoint_split_across_chunks() {
        let content_line = concat!(
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"ok 🦀 done\"},",
            "\"done\":false}\n"
        );
        let done_line = concat!(
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,",
            "\"done_reason\":\"stop\",\"prompt_eval_count\":11,\"eval_count\":2}\n"
        );
        // Two bytes into the four-byte code point: neither half is valid UTF-8.
        let split = content_line.find('🦀').expect("code point present") + 2;
        let raw = content_line.as_bytes();
        assert!(std::str::from_utf8(&raw[..split]).is_err());

        let (base, server) = serve_chunked_ndjson(vec![
            raw[..split].to_vec(),
            raw[split..].to_vec(),
            done_line.as_bytes().to_vec(),
        ])
        .await;

        let mut stream = build_adapter_against(&base)
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("chunked stream must start");
        let mut deltas = String::new();
        let mut done_chunk = None;
        while let Some(item) = stream.next().await {
            let chunk = item.expect("chunked transport must not error");
            deltas.push_str(&chunk.delta);
            if chunk.done {
                done_chunk = Some(chunk);
            }
        }
        server.await.expect("fixture server completes");

        assert_eq!(deltas, "ok 🦀 done");
        let done = done_chunk.expect("done chunk");
        assert_eq!(done.input_tokens, Some(11));
        assert_eq!(done.output_tokens, Some(2));
        assert_eq!(done.termination.finish_reason.as_deref(), Some("stop"));
    }
}
