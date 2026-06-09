//! K-Models-Discovery — proactive model catalog (Session 14 Pick #3).
//!
//! Reality check: every LLM provider iterates model names every few
//! months (Anthropic from `claude-opus-4-5` to `claude-opus-4-7` in
//! seven weeks, Gemini from `2.5-pro` to `3.1-pro-preview` in three
//! months, OpenAI from `gpt-5.3` to `gpt-5.5` in seven weeks). Hard-
//! coded defaults rot fast. NEOTH therefore maintains a per-provider
//! catalog refreshed once per day from each provider's
//! [`crate::models::sources`].
//!
//! Architecture:
//!
//!   - **[`catalog`]** — the on-disk JSON cache at
//!     `~/.neoth/models_catalog.json` (mode 0600). Atomic
//!     temp+rename writes, lazy load on read, TTL-aware
//!     freshness checks.
//!   - **[`discovery`]** — orchestrator that fans out across all
//!     configured providers, merges results, writes the catalog.
//!     Runs from the daily cron task + the `neoth models refresh`
//!     CLI subcommand.
//!   - **[`sources`]** — per-provider implementations of the
//!     [`sources::ModelSource`] trait. Each source attempts CLI-
//!     pull first (where the provider's OAuth CLI exists in PATH)
//!     and falls back to the provider's REST list-models endpoint
//!     when the CLI is absent. The Bedrock source signs against
//!     `ListFoundationModels` via the existing
//!     `crate::providers::aws_sigv4` stack.
//!
//! Self-contained-rule check: the catalog file lives inside
//! `~/.neoth/`; the cron job is the NEOTH-internal scheduler
//! (`cron` crate), not the operator's system cron; CLI-pull paths
//! shell out only to binaries the operator already installed for
//! their LLM workflow.

pub mod catalog;
pub mod cli_detect;
pub mod discovery;
pub mod gguf_variants;
pub mod refresh_task;
pub mod selector;
pub mod sources;

// Public re-exports — surfaced for the CLI subcommand + wizard
// integration that consume the catalog. Marked `allow(unused_imports)`
// because neothd is a binary crate and the re-exports appear unused
// until the `neoth models` CLI subcommand lands (next slice of this
// pick). Removing the re-exports would force every consumer to spell
// out the deep `catalog::` path.
#[allow(unused_imports)]
pub use catalog::{ModelEntry, ModelsCatalog, ProviderCatalog, SourceOrigin};
