//! Fail-closed input-token cap decorator.
//!
//! The chat assembler performs typed A-E/Conductor degradation once.  This
//! decorator is the final invariant for every later request spawned by the same
//! turn (MCP rounds, clarification, refusal recovery): if a downstream helper
//! appends content, it must still fit the effective cap or no provider leaf is
//! authorized/dispatched.

use anyhow::Result;
use async_trait::async_trait;

use super::cost_authorization::ProviderCallAuthorizer;
use super::{ChunkStream, Completion, Provider, ProviderRequestControls, Request};

// Provider adapters expose one optional system message and one user message.
// These reserves cover role/control tokens and request framing; model and stop
// strings are accounted byte-for-byte below. This boundary is intentionally
// separate from the much larger billing-authorization reserve in cost.rs.
const TOKEN_CAP_REQUEST_OVERHEAD: u64 = 256;
const TOKEN_CAP_PER_MESSAGE_OVERHEAD: u64 = 256;

/// Tokenizer-independent upper bound for the complete provider-facing input,
/// including model/stop strings plus conservative request/message overhead.
pub(crate) fn request_token_upper_bound(req: &Request) -> u32 {
    let system = req.system.as_deref().unwrap_or("");
    let message_count = 1_u64 + u64::from(req.system.is_some());
    let stop_bytes = req.stop_sequences.iter().fold(0_u64, |total, stop| {
        total.saturating_add(stop.len() as u64).saturating_add(1)
    });
    let controlled_bytes = (req.prompt.len() as u64)
        .saturating_add(system.len() as u64)
        .saturating_add(req.model.as_deref().map_or(0, str::len) as u64)
        .saturating_add(stop_bytes);
    controlled_bytes
        .saturating_add(TOKEN_CAP_REQUEST_OVERHEAD)
        .saturating_add(message_count.saturating_mul(TOKEN_CAP_PER_MESSAGE_OVERHEAD))
        .min(u32::MAX as u64) as u32
}

/// Portion of [`request_token_upper_bound`] that is not represented by typed
/// A-E content bytes. The finalizer subtracts it before degradation so success
/// under the content budget implies success at the exact leaf boundary.
pub(crate) fn request_non_content_token_upper_bound(req: &Request) -> u32 {
    request_token_upper_bound(req)
        .saturating_sub(crate::tokens::budget::count_tokens_upper_bound(&req.prompt))
        .saturating_sub(
            req.system
                .as_deref()
                .map(crate::tokens::budget::count_tokens_upper_bound)
                .unwrap_or_default(),
        )
}

pub(crate) fn ensure_request_fits(req: &Request, cap: u32) -> Result<()> {
    let upper_bound = request_token_upper_bound(req);
    if upper_bound > cap {
        anyhow::bail!(
            "provider request has a conservative input-token upper bound of {upper_bound}, above the effective cap {cap}; dispatch refused"
        );
    }
    Ok(())
}

/// Borrowing decorator placed immediately inside the paid-call authorizer.
pub struct TokenCappedProvider<'a> {
    inner: &'a dyn Provider,
    cap: u32,
}

impl<'a> TokenCappedProvider<'a> {
    pub fn new(inner: &'a dyn Provider, cap: u32) -> Self {
        Self { inner, cap }
    }
}

#[async_trait]
impl Provider for TokenCappedProvider<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn request_controls(&self) -> ProviderRequestControls {
        self.inner.request_controls()
    }

    fn validate_request_controls(&self, req: &Request) -> Result<()> {
        ensure_request_fits(req, self.cap)?;
        self.inner.validate_request_controls(req)
    }

    fn default_model(&self) -> Option<&str> {
        self.inner.default_model()
    }

    fn resolve_model_for_wire(&self, requested_model: &str) -> String {
        self.inner.resolve_model_for_wire(requested_model)
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        self.inner.output_token_ceiling(req)
    }

    fn streams_on_wire(&self) -> bool {
        self.inner.streams_on_wire()
    }

    fn handles_nonstream_quota_backoff(&self) -> bool {
        self.inner.handles_nonstream_quota_backoff()
    }

    fn preserves_inner_response_identity(&self) -> bool {
        true
    }

    async fn complete_authorized(
        &self,
        req: Request,
        authorizer: &ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        ensure_request_fits(&req, self.cap)?;
        self.inner
            .complete_authorized(req, authorizer, call_scope)
            .await
    }

    async fn stream_authorized(
        &self,
        req: Request,
        authorizer: &ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<ChunkStream> {
        ensure_request_fits(&req, self.cap)?;
        self.inner
            .stream_authorized(req, authorizer, call_scope)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_cap_passes_and_one_token_over_blocks() {
        let exact = Request {
            prompt: "x".repeat(8),
            system: Some("y".repeat(8)),
            ..Request::default()
        };
        let bound = request_token_upper_bound(&exact);
        ensure_request_fits(&exact, bound).expect("exact cap is valid");
        let error = ensure_request_fits(&exact, bound - 1).expect_err("over cap must fail closed");
        assert!(error.to_string().contains("dispatch refused"));
    }

    #[test]
    fn prompt_and_system_are_both_accounted() {
        let request = Request {
            prompt: "12345".to_owned(),
            system: Some("abcdefghi".to_owned()),
            ..Request::default()
        };
        assert_eq!(
            request_token_upper_bound(&request),
            request.prompt.len() as u32
                + request.system.as_deref().unwrap().len() as u32
                + TOKEN_CAP_REQUEST_OVERHEAD as u32
                + 2 * TOKEN_CAP_PER_MESSAGE_OVERHEAD as u32
        );
    }

    #[test]
    fn cjk_and_emoji_use_utf8_upper_bound_not_chars_div_four() {
        let request = Request {
            prompt: "界🙂".repeat(100),
            model: Some("future-model".into()),
            ..Request::default()
        };
        let display_estimate = crate::tokens::budget::count_tokens(&request.prompt);
        let hard_bound = request_token_upper_bound(&request);
        assert!(hard_bound > display_estimate * 4);
        let error = ensure_request_fits(&request, display_estimate)
            .expect_err("display heuristic must never authorize non-Latin input");
        assert!(
            error
                .to_string()
                .contains("conservative input-token upper bound")
        );
    }
}
