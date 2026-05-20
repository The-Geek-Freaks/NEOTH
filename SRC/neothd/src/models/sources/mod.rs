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

use anyhow::Result;
use async_trait::async_trait;

use super::catalog::{ModelEntry, SourceOrigin};

pub mod anthropic;
pub mod bedrock;
pub mod gemini;
pub mod openai;

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
