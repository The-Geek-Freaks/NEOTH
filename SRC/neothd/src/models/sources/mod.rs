//! Provider-specific [`ModelSource`] implementations.
//!
//! Each source resolves the canonical list of models a provider
//! currently exposes. Two implementation strategies:
//!
//!   1. **CLI-pull** — Where the provider ships an OAuth-authed CLI
//!      (Claude Code's `claude`, Google's `gemini`, OpenAI's `codex`),
//!      shell out to it. Most authoritative because the CLI carries
//!      its own session token + service-side rate-limit handling.
//!   2. **API list** — REST `/v1/models` (or equivalent). Used when
//!      the CLI isn't installed or hasn't been authenticated yet.
//!
//! Each source is independent — failing to fetch one does NOT block
//! the others. The orchestrator in [`super::discovery`] runs them
//! concurrently via `futures::join_all` and records partial failures
//! in the catalog's `last_error` field.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;

use super::catalog::{ModelEntry, SourceOrigin};

pub mod anthropic;
pub mod bedrock;
pub mod gemini;
pub mod openai;

/// Per-response and per-refresh bounds for remote model inventories. Provider
/// catalogs are untrusted network input and are later persisted, so both an
/// individual page and the aggregate pagination walk need explicit ceilings.
pub(super) const MAX_LIST_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_LIST_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_LIST_PAGES: usize = 16;

/// Stream and deserialize one successful list page without ever asking
/// reqwest to buffer an unbounded response. Provider-controlled error bodies
/// are deliberately not copied into durable/public errors; the HTTP status is
/// sufficient and cannot echo credentials.
pub(super) async fn read_bounded_list_page<T: DeserializeOwned>(
    mut response: reqwest::Response,
    provider: &str,
    total_bytes: &mut usize,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!(
            "{provider} model-list request returned HTTP {}",
            status.as_u16()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_LIST_PAGE_BYTES as u64)
    {
        anyhow::bail!("{provider} model-list page exceeds {MAX_LIST_PAGE_BYTES} bytes");
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read {provider} model-list response"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_LIST_PAGE_BYTES {
            anyhow::bail!("{provider} model-list page exceeds {MAX_LIST_PAGE_BYTES} bytes");
        }
        if total_bytes.saturating_add(chunk.len()) > MAX_LIST_TOTAL_BYTES {
            anyhow::bail!(
                "{provider} model-list pagination exceeds {MAX_LIST_TOTAL_BYTES} total bytes"
            );
        }
        body.extend_from_slice(&chunk);
        *total_bytes += chunk.len();
    }

    serde_json::from_slice(&body).with_context(|| format!("parse {provider} model-list JSON"))
}

/// Result of one source's fetch attempt.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub provider: &'static str,
    pub origin: SourceOrigin,
    pub models: Vec<ModelEntry>,
}

/// Every per-provider source implements this. Object-safe so the
/// orchestrator can hold `Vec<Box<dyn ModelSource>>` for fan-out.
#[async_trait]
pub trait ModelSource: Send + Sync {
    /// Provider key used to index the catalog. Matches the snake_case
    /// `ProviderKind` strings the rest of the daemon already uses
    /// (`anthropic_api`, `openai_api`, `gemini_api`, `aws_bedrock`).
    fn provider(&self) -> &'static str;

    /// Fetch the current model list. Implementations attempt CLI
    /// first when available, fall through to REST.
    async fn fetch(&self) -> Result<FetchResult>;
}
