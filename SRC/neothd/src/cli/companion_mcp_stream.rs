//! Streamed provider rounds for authenticated companion tool activity.
use anyhow::{Result, bail, ensure};
use futures_util::StreamExt;

use crate::providers::{ChunkStream, Completion, CompletionIdentity, Provider, Request};

const MAX_ROUND_BYTES: usize = 64 * 1024;

/// Wrap the already-authorized leaf; never create a second authorization boundary.
/// Buffer each round until it can be classified by the existing MCP parser.
/// The outer canary guard runs before that parser; only the accepted final answer
/// reaches the common output path, so tool fences cannot become text previews.
pub(super) struct StreamedMcpProvider<'a> {
    pub(super) inner: &'a dyn Provider,
}

#[async_trait::async_trait]
impl Provider for StreamedMcpProvider<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn default_model(&self) -> Option<&str> {
        self.inner.default_model()
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        let started = std::time::Instant::now();
        let stream = self.inner.stream(req).await
            .map_err(|_| anyhow::anyhow!("companion MCP stream could not open"))?;
        let mut completion = collect_stream(stream).await?;
        completion.latency = started.elapsed();
        Ok(completion)
    }
}

async fn collect_stream(mut stream: ChunkStream) -> Result<Completion> {
    let mut completion = Completion::default();
    let mut expected_identity: Option<CompletionIdentity> = None;
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|_| anyhow::anyhow!("companion MCP stream failed"))?;
        ensure!(chunk.identity.is_bound(), "companion MCP stream identity is unbound");
        if let Some(expected) = &expected_identity {
            ensure!(expected == &chunk.identity, "companion MCP stream identity changed");
        } else {
            expected_identity = Some(chunk.identity.clone());
        }
        ensure!(
            completion.text.len().saturating_add(chunk.delta.len()) <= MAX_ROUND_BYTES,
            "companion MCP stream exceeds round limit"
        );
        // Refused or truncated tool syntax must never reach the dispatch parser.
        ensure!(!chunk.termination.is_refusal(), "companion MCP stream refused");
        ensure!(
            !matches!(chunk.termination.finish_reason.as_deref(), Some("length" | "max_tokens")),
            "companion MCP stream truncated"
        );
        completion.text.push_str(&chunk.delta);
        completion.input_tokens = chunk.input_tokens.or(completion.input_tokens);
        completion.output_tokens = chunk.output_tokens.or(completion.output_tokens);
        completion.cache_creation_tokens = chunk.cache_creation_tokens.or(completion.cache_creation_tokens);
        completion.cache_read_tokens = chunk.cache_read_tokens.or(completion.cache_read_tokens);
        if chunk.done {
            completion.model = chunk.identity.wire_model.clone();
            completion.identity = chunk.identity;
            completion.termination = chunk.termination;
            // The existing authorized stream settles before yielding its done
            // chunk. Preserve reported zeroes, but invent no usage provenance.
            return Ok(completion);
        }
    }
    bail!("companion MCP stream ended without terminal")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{CompletionChunk, ProviderTermination, RefusalOrigin};

    fn identity() -> CompletionIdentity {
        CompletionIdentity {
            provider: "companion-test".into(),
            wire_model: "stream-model".into(),
            dispatch_route: Vec::new(),
        }
    }

    fn chunk(text: &str, done: bool) -> CompletionChunk {
        CompletionChunk {
            delta: text.into(),
            done,
            identity: identity(),
            ..Default::default()
        }
    }

    fn stream(chunks: Vec<Result<CompletionChunk>>) -> ChunkStream {
        Box::pin(futures_util::stream::iter(chunks))
    }

    #[tokio::test]
    async fn streamed_mcp_collects_exact_body_and_reported_zero_cache_usage() {
        let mut first = chunk("first ", false);
        first.input_tokens = Some(0);
        first.cache_creation_tokens = Some(0);
        let mut last = chunk("answer", true);
        last.output_tokens = Some(0);
        last.cache_read_tokens = Some(7);
        last.termination = ProviderTermination::finished(Some("stop".into()));
        let result = collect_stream(stream(vec![Ok(first), Ok(last)])).await.unwrap();
        assert_eq!(result.text, "first answer");
        assert_eq!(result.identity, identity());
        assert_eq!(result.model, "stream-model");
        assert_eq!(result.input_tokens, Some(0));
        assert_eq!(result.output_tokens, Some(0));
        assert_eq!(result.cache_creation_tokens, Some(0));
        assert_eq!(result.cache_read_tokens, Some(7));
        assert!(result.usage_measurements.is_none());
        assert_eq!(result.termination.finish_reason.as_deref(), Some("stop"));
    }

    #[tokio::test]
    async fn streamed_mcp_rejects_unbound_or_changed_identity() {
        let mut unbound = chunk("private", true);
        unbound.identity = Default::default();
        assert!(collect_stream(stream(vec![Ok(unbound)])).await.is_err());
        let mut changed = chunk("private", true);
        changed.identity.wire_model = "different".into();
        let error = collect_stream(stream(vec![Ok(chunk("first", false)), Ok(changed)]))
            .await.unwrap_err();
        assert_eq!(error.to_string(), "companion MCP stream identity changed");
    }

    #[tokio::test]
    async fn streamed_mcp_requires_done_and_discards_private_transport_errors() {
        let error = collect_stream(stream(vec![Ok(chunk("unfinished", false))]))
            .await.unwrap_err();
        assert_eq!(error.to_string(), "companion MCP stream ended without terminal");
        let error = collect_stream(stream(vec![Err(anyhow::anyhow!("private body"))]))
            .await.unwrap_err();
        assert_eq!(error.to_string(), "companion MCP stream failed");
    }

    #[tokio::test]
    async fn streamed_mcp_rejects_overflow_refusal_and_truncated_tool_fences() {
        assert!(collect_stream(stream(vec![Ok(chunk(&"x".repeat(MAX_ROUND_BYTES + 1), true))]))
            .await.is_err());
        let mut refused = chunk("```mcp-tool-call", true);
        refused.termination = ProviderTermination::refused(
            Some("content_filter".into()), RefusalOrigin::FinishReason, "content_filter", None,
        );
        assert!(collect_stream(stream(vec![Ok(refused)])).await.is_err());
        for reason in ["length", "max_tokens"] {
            let mut truncated = chunk("```mcp-tool-call", true);
            truncated.termination = ProviderTermination::finished(Some(reason.into()));
            assert!(collect_stream(stream(vec![Ok(truncated)])).await.is_err());
        }
    }
}
