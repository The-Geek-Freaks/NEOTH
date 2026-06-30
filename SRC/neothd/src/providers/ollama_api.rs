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
//! through `providers::from_config`. The adapter name is `"local_ollama"`;
//! `is_local_provider("local_ollama")` returns `true` so quota / privacy /
//! WAL audit gating treat it identically to `local_qwen` / `local_ouro`.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{ChunkStream, Completion, CompletionChunk, Provider, Request};

/// Default Ollama base URL when the operator hasn't overridden it.
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434";
/// Default model when the operator hasn't set one.
pub const DEFAULT_MODEL: &str = "llama3.2";

/// Adapter for Ollama's native `/api/chat` endpoint.
pub struct OllamaAdapter {
    /// e.g. `http://localhost:11434` — no trailing slash.
    base_url: String,
    /// Model name (e.g. `llama3.2`, `qwen2.5:7b`).
    model: String,
    /// Shared HTTP client.
    http: reqwest::Client,
}

impl OllamaAdapter {
    pub fn new(base_url: String, model: String) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client()?;
        Ok(Self {
            base_url,
            model,
            http,
        })
    }
}

#[async_trait]
impl Provider for OllamaAdapter {
    fn name(&self) -> &'static str {
        "local_ollama"
    }

    /// Non-streaming completion via `/api/chat` with `stream: false`.
    async fn complete(&self, req: Request) -> Result<Completion> {
        crate::providers::circuit_breaker::run_with_breaker("local_ollama", async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.model.clone());

            let body = build_request(&model, &req, false);
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
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into());
                anyhow::bail!(
                    "local_ollama returned HTTP {}: {}",
                    status.as_u16(),
                    body_text.trim()
                );
            }

            let parsed: OllamaChatResponse = response
                .json()
                .await
                .with_context(|| "parse local_ollama /api/chat response JSON")?;

            let text = parsed.message.content;
            let latency = started.elapsed();
            debug!(
                adapter = "local_ollama",
                model = %model,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "ollama completion"
            );

            Ok(Completion {
                text,
                model,
                latency,
                input_tokens: parsed.prompt_eval_count,
                output_tokens: parsed.eval_count,
                cache_creation_tokens: None,
                cache_read_tokens: None,
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
    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        crate::providers::circuit_breaker_stream::run_stream_with_breaker(
            "local_ollama",
            async {
                let model = req
                    .model
                    .clone()
                    .unwrap_or_else(|| self.model.clone());

                let body = build_request(&model, &req, true);
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
                    let body_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unreadable body>".into());
                    anyhow::bail!(
                        "local_ollama stream returned HTTP {}: {}",
                        status.as_u16(),
                        body_text.trim()
                    );
                }

                let model_log = model.clone();
                let byte_stream = response.bytes_stream();

                let inner: ChunkStream = Box::pin(async_stream::try_stream! {
                    let mut buf = String::new();
                    let mut input_tokens: Option<u32> = None;
                    let mut output_tokens: Option<u32> = None;

                    tokio::pin!(byte_stream);
                    while let Some(chunk_result) = byte_stream.next().await {
                        let bytes = chunk_result
                            .with_context(|| "local_ollama: NDJSON byte read error")?;
                        let text = std::str::from_utf8(&bytes)
                            .with_context(|| "local_ollama: NDJSON chunk not valid UTF-8")?;
                        buf.push_str(text);

                        // Each Ollama response line is a complete JSON object.
                        while let Some(newline_pos) = buf.find('\n') {
                            let line = buf[..newline_pos].trim_end_matches('\r').trim().to_string();
                            buf.drain(..=newline_pos);

                            if line.is_empty() {
                                continue;
                            }

                            let chunk: OllamaChatChunk = match serde_json::from_str(&line) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(
                                        adapter = "local_ollama",
                                        error = %e,
                                        raw = %line,
                                        "NDJSON chunk parse error; skipping"
                                    );
                                    continue;
                                }
                            };

                            if chunk.done {
                                // Capture token counts from the done line.
                                input_tokens = chunk.prompt_eval_count;
                                output_tokens = chunk.eval_count;
                                yield CompletionChunk {
                                    delta: String::new(),
                                    done: true,
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
                                    input_tokens: None,
                                    output_tokens: None,
                                    cache_creation_tokens: None,
                                    cache_read_tokens: None,
                                };
                            }
                        }
                    }

                    // EOF residual: a server may end the FINAL JSON line without a
                    // trailing newline, so the line-loop above never consumed it.
                    // Parse whatever is left before synthesising the terminator so a
                    // newline-less done line (token counts) or content delta is not
                    // dropped.
                    let tail = buf.trim();
                    if !tail.is_empty() {
                        if let Ok(chunk) = serde_json::from_str::<OllamaChatChunk>(tail) {
                            if chunk.done {
                                input_tokens = chunk.prompt_eval_count;
                                output_tokens = chunk.eval_count;
                            } else if !chunk.message.content.is_empty() {
                                yield CompletionChunk {
                                    delta: chunk.message.content,
                                    done: false,
                                    input_tokens: None,
                                    output_tokens: None,
                                    cache_creation_tokens: None,
                                    cache_read_tokens: None,
                                };
                            }
                        } else {
                            tracing::warn!(
                                adapter = "local_ollama",
                                raw = %tail,
                                "NDJSON EOF-residual parse error; dropping tail"
                            );
                        }
                    }

                    // Stream ended; emit a clean terminator carrying any token
                    // counts captured from a done line (incl. a newline-less tail).
                    yield CompletionChunk {
                        delta: String::new(),
                        done: true,
                        input_tokens,
                        output_tokens,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    };
                });

                debug!(
                    adapter = "local_ollama",
                    model = %model_log,
                    "ollama NDJSON stream started"
                );
                Ok(inner)
            },
        )
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

fn build_request(model: &str, req: &Request, stream: bool) -> OllamaChatRequest {
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
        let opts = OllamaOptions {
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.sampling_seed,
            stop: req.stop_sequences.clone(),
            num_predict: None,
        };
        // Only include options when at least one field is set.
        if opts.temperature.is_some()
            || opts.top_p.is_some()
            || opts.seed.is_some()
            || !opts.stop.is_empty()
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use futures_util::StreamExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(base_url: &str) -> OllamaAdapter {
        OllamaAdapter::new(base_url.to_string(), "llama3.2-mock".to_string())
            .expect("adapter constructs against mock URL")
    }

    #[test]
    fn adapter_name_is_local_ollama() {
        let a = build_adapter_against("http://localhost:11434");
        assert_eq!(a.name(), "local_ollama");
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
    }

    /// Streaming stream(): mock returns three NDJSON lines + a done line;
    /// we must receive ≥2 content chunks and a final done chunk.
    #[tokio::test]
    async fn mock_ndjson_stream_delivers_progressive_chunks() {
        let ndjson_body = concat!(
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"done\":false}\n",
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\" there\"},\"done\":false}\n",
            "{\"model\":\"llama3.2-mock\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"prompt_eval_count\":5,\"eval_count\":3}\n",
        );

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(ndjson_body, "application/x-ndjson"),
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
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"prompt_eval_count\":7,\"eval_count\":4}",
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
        let done = chunks.iter().find(|c| c.done).expect("must have a done chunk");
        assert_eq!(
            done.input_tokens,
            Some(7),
            "newline-less final done line tokens must be captured"
        );
        assert_eq!(done.output_tokens, Some(4));
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
                ResponseTemplate::new(200)
                    .set_body_raw(ndjson_body, "application/x-ndjson"),
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
            .respond_with(ResponseTemplate::new(500).set_body_raw(
                r#"{"error":"model not found"}"#,
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
            .expect_err("HTTP 500 must surface as Err");
        let msg = err.to_string();
        assert!(msg.contains("500"), "error must mention status; got: {msg}");
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
        let body = build_request("llama3.2", &req, false);
        let opts = body.options.expect("options must be present when sampling fields set");
        assert_eq!(opts.temperature, Some(0.7));
        assert_eq!(opts.top_p, Some(0.9));
        assert_eq!(opts.seed, Some(42));
        assert_eq!(opts.stop, vec!["</s>"]);
    }

    /// No options field when all sampling fields are None/empty.
    #[tokio::test]
    async fn build_request_omits_options_when_defaults() {
        let req = Request {
            prompt: "test".into(),
            ..Default::default()
        };
        let body = build_request("llama3.2", &req, false);
        assert!(
            body.options.is_none(),
            "options must be omitted when no sampling overrides are set"
        );
    }
}
