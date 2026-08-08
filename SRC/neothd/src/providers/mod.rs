//! LLM provider abstraction.
//!
//! Every LLM backend NEOTH talks to implements the `Provider` trait. The
//! daemon picks one based on `FreedomConfig::provider_kind` and routes user
//! messages through it.
//!
//! **claude_cli is first-class.** Per the operator's existing setup (see
//! `~/.claude/projects/.../memory/neoth-claude-cli-native.md`), NEOTH's
//! primary path is Anthropic's `claude` CLI binary with OAuth — not a REST
//! API key — because that's the auth model the operator already runs in
//! tmux + Claude Code daily. OpenAI / Gemini adapters come second; they are
//! NOT the default fallback.

/// PF-02 — native Anthropic Messages API adapter (key-based, no `claude` CLI).
pub mod abliterated;
pub mod anthropic_api;
pub mod aws_bedrock;
pub mod aws_credentials;
pub mod aws_sigv4;
pub mod azure_openai;
pub mod circuit_breaker;
pub mod circuit_breaker_stream;
pub mod claude_cli;
pub mod claude_pid_hunter;
pub mod claude_retry;
pub mod claude_session;
pub mod claude_tmux;
pub mod clip_engine;
/// PF-02 — native Cohere v2 Chat adapter (hybrid OAI-request/Anthropic-response).
pub mod cohere_api;
/// GOLD-ADAPT-HARNESS-03 — message-history compaction middleware.
pub mod compactor;
pub mod context_guards;
/// GOLD-ADAPT-ODY-15 — GitHub Copilot OAuth provider (variable billing;
/// unbounded paid-call gate without live plan/allowance context).
pub mod copilot;
pub mod cost;
/// B22 — cost authorization bound to each exact provider leaf request.
pub mod cost_authorization;
pub mod effort_override;
pub mod embed;
/// SPEC-03b — per-provider 429 fallback chain (`FallbackProvider` decorator).
pub mod fallback;
pub mod gemini_api;
pub mod http_client;
pub mod known_endpoints;
pub mod local_probe;
pub mod local_qwen;
pub mod meter;
pub mod model_roles;
pub mod ollama_api;
pub mod openai_api;
pub mod ouro;
pub mod pty_session;
pub mod quota;
pub mod recursive_mas;
#[cfg(feature = "recursive-mas")]
pub mod recursive_mas_adapter;
pub(crate) mod response_bounds;
pub mod singleflight;
pub mod termination;
pub mod tmux_session;
pub mod tmux_socket;
pub mod tmux_sweeper;
pub mod tmux_sweeper_task;
pub mod token_cap;
pub mod whisper;

use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::{self, Stream};

use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::secret::SecretString;

pub use termination::{ProviderRefusal, ProviderTermination, RefusalOrigin, Retryability};

/// Exact concrete identity of the provider invocation that produced a result.
/// The paid-call boundary overwrites adapter-supplied/default values after the
/// leaf gate succeeds, so consumers never have to reconstruct this from a
/// decorator name or a pre-resolution model alias.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletionIdentity {
    pub provider: String,
    pub wire_model: String,
    /// Opaque decorator route from the outermost provider to the concrete
    /// authorized leaf. Empty means a direct leaf. Recovery replays this route
    /// instead of asking routing decorators to select a provider again.
    #[doc(hidden)]
    pub(crate) dispatch_route: Vec<u16>,
}

impl CompletionIdentity {
    fn new(provider: &str, wire_model: &str) -> Self {
        Self {
            provider: provider.to_owned(),
            wire_model: wire_model.to_owned(),
            dispatch_route: Vec::new(),
        }
    }

    pub fn is_bound(&self) -> bool {
        !self.provider.is_empty() && !self.wire_model.is_empty()
    }

    pub(crate) fn prepend_dispatch_slot(&mut self, slot: usize) -> Result<()> {
        let slot = u16::try_from(slot).context("provider dispatch slot exceeds u16")?;
        self.dispatch_route.insert(0, slot);
        Ok(())
    }

    pub(crate) fn child_identity_for_slot(&self, slot: usize) -> Result<Self> {
        let Some((&actual, tail)) = self.dispatch_route.split_first() else {
            anyhow::bail!(
                "completion identity for `{}`/`{}` has no pinned decorator route",
                self.provider,
                self.wire_model
            );
        };
        let expected = u16::try_from(slot).context("provider dispatch slot exceeds u16")?;
        if actual != expected {
            anyhow::bail!(
                "completion identity route selected slot {actual}, not requested slot {expected}"
            );
        }
        Ok(Self {
            provider: self.provider.clone(),
            wire_model: self.wire_model.clone(),
            dispatch_route: tail.to_vec(),
        })
    }
}

/// One completion result. `text` is the full final response; `latency` is
/// wall-clock time from request to last token.
#[derive(Debug, Clone, Default)]
pub struct Completion {
    pub text: String,
    /// Typed leaf identity; authoritative for audit, usage and domain events.
    pub identity: CompletionIdentity,
    /// Backward-compatible mirror of `identity.wire_model`.
    pub model: String,
    /// Provider-authoritative finish/refusal/filter metadata. Legacy adapters
    /// leave this at the backward-safe default until they adopt native
    /// termination parsing.
    pub termination: termination::ProviderTermination,
    pub latency: Duration,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// VIEW-03 — tokens written into the Anthropic prompt cache this turn
    /// (billed at 1.25× the normal input rate). `None` for all non-Anthropic
    /// adapters and for Anthropic calls where no cache_control breakpoint was
    /// active. Other adapters leave this `None` via `Default::default()`.
    pub cache_creation_tokens: Option<u32>,
    /// VIEW-03 — tokens served from the Anthropic prompt cache this turn
    /// (billed at 0.10× the normal input rate). `None` when cache was cold
    /// or for non-Anthropic providers.
    pub cache_read_tokens: Option<u32>,
}

/// Render a deterministic NEOTH-authored notice when an upstream refusal has
/// authoritative typed metadata but no displayable body. The provider's
/// message is not fabricated and the typed termination remains unchanged.
#[must_use]
pub fn operator_refusal_notice(completion: &Completion) -> Option<String> {
    if !completion.text.trim().is_empty() {
        return None;
    }
    let refusal = completion.termination.refusal.as_ref()?;
    let clean = |value: &str, fallback: &str| {
        let value = value
            .chars()
            .filter(|character| !character.is_control())
            .take(160)
            .collect::<String>();
        if value.trim().is_empty() {
            fallback.to_owned()
        } else {
            value
        }
    };
    let provider = clean(&completion.identity.provider, "unknown");
    let model = clean(&completion.identity.wire_model, "unknown");
    let reason = clean(&refusal.reason, "unspecified");
    Some(format!(
        "[NEOTH] Upstream `{provider}` (`{model}`) returned a refusal without display text \
         (origin: {}, reason: {reason}).",
        refusal.origin.as_str()
    ))
}

/// A request to send to a Provider. Plain text for Day-5 MVP; multimodal
/// (image / tool-use) comes in later phases.
///
/// Request controls are strict, not advisory. Every concrete leaf declares
/// its [`ProviderRequestControls`]; unsupported or malformed controls fail
/// before authorization and transport. This prevents a CLI flag from looking
/// active while a provider silently drops it.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub prompt: String,
    pub system: Option<String>,
    pub model: Option<String>,
    /// Sampling temperature override for this single call. `None` = adapter
    /// default. Provider ranges are either [0.0, 1.0] or [0.0, 2.0].
    pub temperature: Option<f32>,
    /// Top-p nucleus cutoff. `None` = adapter default. Range (0.0, 1.0].
    pub top_p: Option<f32>,
    /// RNG seed for reproducible sampling. Portable wire range: u32.
    pub sampling_seed: Option<u64>,
    /// L-13 (Session 19, 2026-05-21): stop sequences. When the
    /// decoded body reaches one of these substrings, generation
    /// halts + the output is truncated to the position BEFORE
    /// the stop sequence (the stop string itself is NOT
    /// included in the returned text). Empty = no stop check.
    ///
    /// Supported providers forward this to their native wire field; local
    /// Qwen truncates decoded output at the first match. At most four non-empty
    /// sequences of 256 UTF-8 bytes each are accepted.
    pub stop_sequences: Vec<String>,
    /// GOLD-CCPARITY-EFFORT-03 — per-skill reasoning-budget override.
    /// When `Some(n)`, the `claude_cli` adapter overrides
    /// `MAX_THINKING_TOKENS` to `n` for this specific call before
    /// spawning the claude binary. `None` = use the adapter default
    /// (currently 10 000 tokens, set in `scrub_outbound_env`).
    /// Other adapters reject this control rather than ignoring it.
    pub thinking_budget: Option<u32>,
    /// Maximum completion tokens for this single call. `None` leaves the
    /// provider's reviewed default ceiling in effect. A concrete leaf may only
    /// accept this when it both declares [`ProviderRequestControls::OUTPUT_TOKEN_LIMIT`]
    /// and proves that the same value (or a stricter one) is enforced on wire.
    pub max_output_tokens: Option<u32>,
}

/// Per-leaf request-control capability contract.
///
/// The fields stay private so adapters select one reviewed capability set
/// instead of constructing contradictory values ad hoc. Validation is shared
/// across every leaf and runs before model binding, cost authorization, or I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRequestControls {
    maximum_temperature: Option<u8>,
    top_p: bool,
    sampling_seed: bool,
    stop_sequences: bool,
    thinking_budget: bool,
    max_output_tokens: bool,
}

impl ProviderRequestControls {
    pub const NONE: Self = Self::new(None, false, false, false, false, false);
    /// Per-call maximum completion-token limit only.
    pub const OUTPUT_TOKEN_LIMIT: Self = Self::new(None, false, false, false, false, true);
    /// Temperature up to 2.0, top-p, seed, and stop sequences.
    pub const SAMPLING: Self = Self::new(Some(2), true, true, true, false, false);
    /// Temperature up to 1.0, top-p, seed, and stop sequences.
    pub const SAMPLING_MAX_ONE: Self = Self::new(Some(1), true, true, true, false, false);
    /// Temperature up to 1.0, top-p, and stop sequences; seed unsupported.
    pub const SAMPLING_WITHOUT_SEED: Self = Self::new(Some(1), true, false, true, false, false);
    /// Temperature up to 2.0, top-p, and seed; stop sequences unsupported.
    pub const SAMPLING_WITHOUT_STOPS: Self = Self::new(Some(2), true, true, false, false, false);
    /// Per-call reasoning budget only (Claude CLI).
    pub const THINKING_BUDGET: Self = Self::new(None, false, false, false, true, false);

    const fn new(
        maximum_temperature: Option<u8>,
        top_p: bool,
        sampling_seed: bool,
        stop_sequences: bool,
        thinking_budget: bool,
        max_output_tokens: bool,
    ) -> Self {
        Self {
            maximum_temperature,
            top_p,
            sampling_seed,
            stop_sequences,
            thinking_budget,
            max_output_tokens,
        }
    }

    /// Add the strict per-request output cap to an existing reviewed control
    /// set. Concrete adapters use this instead of open-coding a new capability
    /// constant for every sampling combination.
    pub const fn with_output_token_limit(mut self) -> Self {
        self.max_output_tokens = true;
        self
    }

    pub const fn supports_thinking_budget(self) -> bool {
        self.thinking_budget
    }

    pub const fn supports_temperature(self) -> bool {
        self.maximum_temperature.is_some()
    }

    pub const fn supports_sampling_seed(self) -> bool {
        self.sampling_seed
    }

    pub const fn supports_max_output_tokens(self) -> bool {
        self.max_output_tokens
    }

    /// Project controls onto a different provider leaf for an explicit
    /// cross-provider hop. Unsupported controls are removed and returned for
    /// audit; prompt, system, model, and supported controls remain unchanged.
    pub(crate) fn project_compatible_controls(self, req: &mut Request) -> Vec<&'static str> {
        let mut dropped = Vec::with_capacity(6);
        if req.temperature.is_some_and(|temperature| {
            self.maximum_temperature
                .is_none_or(|maximum| temperature > f32::from(maximum))
        }) {
            req.temperature = None;
            dropped.push("temperature");
        }
        if req.top_p.is_some() && !self.top_p {
            req.top_p = None;
            dropped.push("top_p");
        }
        if req.sampling_seed.is_some() && !self.sampling_seed {
            req.sampling_seed = None;
            dropped.push("sampling_seed");
        }
        if !req.stop_sequences.is_empty() && !self.stop_sequences {
            req.stop_sequences.clear();
            dropped.push("stop_sequences");
        }
        if req.thinking_budget.is_some() && !self.thinking_budget {
            req.thinking_budget = None;
            dropped.push("thinking_budget");
        }
        if req.max_output_tokens.is_some() && !self.max_output_tokens {
            req.max_output_tokens = None;
            dropped.push("max_output_tokens");
        }
        dropped
    }

    /// Capabilities common to both providers in a decorator/fallback path.
    pub const fn intersection(self, other: Self) -> Self {
        let maximum_temperature = match (self.maximum_temperature, other.maximum_temperature) {
            (Some(left), Some(right)) => Some(if left < right { left } else { right }),
            _ => None,
        };
        Self::new(
            maximum_temperature,
            self.top_p && other.top_p,
            self.sampling_seed && other.sampling_seed,
            self.stop_sequences && other.stop_sequences,
            self.thinking_budget && other.thinking_budget,
            self.max_output_tokens && other.max_output_tokens,
        )
    }

    pub fn validate(self, provider: &str, req: &Request) -> Result<()> {
        validate_portable_request_controls(provider, req)?;

        let mut unsupported = Vec::with_capacity(6);
        if req.temperature.is_some() && self.maximum_temperature.is_none() {
            unsupported.push("temperature");
        }
        if req.top_p.is_some() && !self.top_p {
            unsupported.push("top_p");
        }
        if req.sampling_seed.is_some() && !self.sampling_seed {
            unsupported.push("sampling_seed");
        }
        if !req.stop_sequences.is_empty() && !self.stop_sequences {
            unsupported.push("stop_sequences");
        }
        if req.thinking_budget.is_some() && !self.thinking_budget {
            unsupported.push("thinking_budget");
        }
        if req.max_output_tokens.is_some() && !self.max_output_tokens {
            unsupported.push("max_output_tokens");
        }
        if !unsupported.is_empty() {
            anyhow::bail!(
                "provider `{provider}` does not support request control(s): {}",
                unsupported.join(", ")
            );
        }
        if let (Some(temperature), Some(maximum)) = (req.temperature, self.maximum_temperature)
            && temperature > maximum as f32
        {
            anyhow::bail!(
                "provider `{provider}`: temperature must be within [0.0, {maximum}.0], got {temperature}"
            );
        }
        Ok(())
    }
}

/// Validate provider-independent request-control limits. Leaf validation calls
/// this before its capability/model checks; non-dispatch surfaces such as
/// `neoth recipe validate` reuse it so malformed automation is rejected without
/// making a provider call.
pub(crate) fn validate_portable_request_controls(provider: &str, req: &Request) -> Result<()> {
    const MAX_STOP_SEQUENCES: usize = 4;
    const MAX_STOP_SEQUENCE_BYTES: usize = 256;
    const MAX_STOP_SEQUENCE_TOTAL_BYTES: usize = 2_048;
    const MAX_THINKING_BUDGET: u32 = 1_000_000;

    if let Some(temperature) = req.temperature
        && (!temperature.is_finite() || !(0.0..=2.0).contains(&temperature))
    {
        anyhow::bail!(
            "provider `{provider}`: temperature must be finite and within [0.0, 2.0], got {temperature}"
        );
    }
    if let Some(top_p) = req.top_p
        && (!top_p.is_finite() || top_p <= 0.0 || top_p > 1.0)
    {
        anyhow::bail!(
            "provider `{provider}`: top_p must be finite and within (0.0, 1.0], got {top_p}"
        );
    }
    if let Some(seed) = req.sampling_seed
        && seed > u64::from(u32::MAX)
    {
        anyhow::bail!(
            "provider `{provider}`: sampling_seed must be within [0, {}], got {seed}",
            u32::MAX
        );
    }
    if req.stop_sequences.len() > MAX_STOP_SEQUENCES {
        anyhow::bail!(
            "provider `{provider}`: at most {MAX_STOP_SEQUENCES} stop sequences are allowed, got {}",
            req.stop_sequences.len()
        );
    }
    let mut stop_total = 0usize;
    for (index, stop) in req.stop_sequences.iter().enumerate() {
        if stop.is_empty() {
            anyhow::bail!(
                "provider `{provider}`: stop sequence {} must not be empty",
                index + 1
            );
        }
        if stop.len() > MAX_STOP_SEQUENCE_BYTES {
            anyhow::bail!(
                "provider `{provider}`: stop sequence {} exceeds {MAX_STOP_SEQUENCE_BYTES} UTF-8 bytes",
                index + 1
            );
        }
        stop_total = stop_total.saturating_add(stop.len());
    }
    if stop_total > MAX_STOP_SEQUENCE_TOTAL_BYTES {
        anyhow::bail!(
            "provider `{provider}`: stop sequences exceed {MAX_STOP_SEQUENCE_TOTAL_BYTES} total UTF-8 bytes"
        );
    }
    if let Some(thinking_budget) = req.thinking_budget
        && (thinking_budget == 0 || thinking_budget > MAX_THINKING_BUDGET)
    {
        anyhow::bail!(
            "provider `{provider}`: thinking_budget must be within [1, {MAX_THINKING_BUDGET}], got {thinking_budget}"
        );
    }
    if let Some(max_output_tokens) = req.max_output_tokens
        && (max_output_tokens == 0 || max_output_tokens > MAX_REQUEST_OUTPUT_TOKENS)
    {
        anyhow::bail!(
            "provider `{provider}`: max_output_tokens must be within [1, {MAX_REQUEST_OUTPUT_TOKENS}], got {max_output_tokens}"
        );
    }
    Ok(())
}

/// One delta during a streaming response. `delta` is incremental new text
/// since the last chunk; `done` is set on the final chunk along with token
/// totals when the provider reports them.
#[derive(Debug, Clone, Default)]
pub struct CompletionChunk {
    pub delta: String,
    pub done: bool,
    /// Exact leaf identity. The authorization boundary attaches it to every
    /// chunk, including the final usage-bearing chunk.
    pub identity: CompletionIdentity,
    /// Provider-authoritative termination facts. Progressive chunks leave this
    /// at the legacy-safe default; the final `done` chunk carries the complete
    /// finish/refusal/filter outcome.
    pub termination: termination::ProviderTermination,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// VIEW-03 — cache creation tokens from the final done-chunk usage block.
    /// Only populated by the `anthropic_api` streaming path on the last chunk;
    /// all other adapters and non-final chunks leave this `None`.
    pub cache_creation_tokens: Option<u32>,
    /// VIEW-03 — cache read tokens from the final done-chunk usage block.
    pub cache_read_tokens: Option<u32>,
}

/// Stream of completion chunks. Each `Result::Ok` carries one chunk; the
/// stream MUST terminate after emitting one chunk with `done: true`. Errors
/// during streaming come back as `Result::Err` items — once one is yielded,
/// the consumer should stop reading.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<CompletionChunk>> + Send>>;

/// Canonical "is this concrete `Provider::name()` guaranteed offline"
/// predicate. This is the SINGLE place the trusted local-provider set is
/// enumerated — quota tracking, privacy classification, WAL audit gating
/// and the free-price table all key off it. GR-17 (Session 30) extracted
/// this after `local_ouro` (the second local provider, shipped Session 22)
/// was silently missed at five separate `== "local_qwen"` guards: a new
/// local backend must only be added here, not hunted across the codebase.
/// Add a name only when the leaf cannot inherit a network-capable sidecar;
/// decorators must still authorize their concrete children rather than trust
/// the primary name.
///
/// `recursive_mas` is deliberately excluded: it launches an operator-installed
/// Python sidecar with inherited environment/network access, so nominally local
/// model weights do not make it safe to bypass B22 authorization.
///
/// NOTE: this is the "is it guaranteed offline" question. Provider-SPECIFIC checks
/// (e.g. `doctor::check_local_qwen_weights`, which verifies the Qwen weight
/// cache) intentionally stay keyed to their one provider and must NOT route
/// through this helper.
pub fn is_local_provider(name: &str) -> bool {
    matches!(
        name,
        "local_qwen" | "local_ouro" | "local_abliterated" | "local_ollama"
    )
}

/// Convert an operator/config supplied model repository id into one safe path
/// component. Both platform separators and Windows drive separators are
/// flattened so cache paths cannot escape the caller-owned model root.
pub(crate) fn model_cache_component(repo: &str) -> String {
    repo.chars()
        .map(|character| match character {
            '/' | '\\' | ':' => '-',
            control if control.is_control() => '-',
            other => other,
        })
        .collect()
}

/// Hard output cap sent by the cloud adapters that expose the corresponding
/// wire field (`max_tokens`, `maxCompletionTokens`, ...). This is never a
/// fallback authorization guess: a provider that cannot prove and enforce an
/// output ceiling must return `None` from [`Provider::output_token_ceiling`]
/// and dispatch uses the explicit unbounded paid-provider permission path.
pub const DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING: u32 = 4096;

/// Largest portable caller-requested completion budget. Providers can declare
/// narrower model-specific limits, but no request may raise this conservative
/// project-wide guardrail.
pub const MAX_REQUEST_OUTPUT_TOKENS: u32 = 131_072;

/// Capability required by every concrete provider transport. Its field and
/// constructor are private to this module, so safe Rust outside the mandatory
/// authorization boundary cannot manufacture a dispatch permit.
///
/// ```compile_fail
/// use neothd::providers::ProviderDispatchPermit;
///
/// let _forged = ProviderDispatchPermit { _private: () };
/// ```
#[derive(Clone)]
struct ProviderRetryAuthorization {
    authorizer: cost_authorization::ProviderCallAuthorizer,
    provider: &'static str,
    consent_route: Option<crate::consent::ConsentRoute>,
    req: Request,
    call_scope: &'static str,
    output_token_ceiling: Option<u32>,
}

enum ProviderDispatchAuditState {
    Active(Box<cost_authorization::ProviderCallAuditGuard>),
    BetweenAttempts,
    Closed,
    TransportOnly,
}

/// A retry classification that represents another concrete transport send.
/// Authentication failures intentionally have no variant: they must surface
/// without another attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRetryReason {
    EmptyStdout,
    SessionCollision,
    Transient,
}

impl ProviderRetryReason {
    fn terminal_kind(self) -> &'static str {
        match self {
            Self::EmptyStdout => "provider_retry_empty_stdout",
            Self::SessionCollision => "provider_retry_session_collision",
            Self::Transient => "provider_retry_transient",
        }
    }
}

pub struct ProviderDispatchPermit {
    retry: Option<ProviderRetryAuthorization>,
    provider_subject:
        std::sync::Mutex<Option<crate::security::provider_subject::ProviderSubjectIdentifier>>,
    audit: tokio::sync::Mutex<ProviderDispatchAuditState>,
    _private: (),
}

impl ProviderDispatchPermit {
    fn authorized(
        audit: cost_authorization::ProviderCallAuditGuard,
        authorizer: cost_authorization::ProviderCallAuthorizer,
        provider: &'static str,
        consent_route: Option<crate::consent::ConsentRoute>,
        req: Request,
        call_scope: &'static str,
        output_token_ceiling: Option<u32>,
        provider_subject: Option<crate::security::provider_subject::ProviderSubjectIdentifier>,
    ) -> Self {
        Self {
            retry: Some(ProviderRetryAuthorization {
                authorizer,
                provider,
                consent_route,
                req,
                call_scope,
                output_token_ceiling,
            }),
            provider_subject: std::sync::Mutex::new(provider_subject),
            audit: tokio::sync::Mutex::new(ProviderDispatchAuditState::Active(Box::new(audit))),
            _private: (),
        }
    }

    fn transport_only(
        provider_subject: Option<crate::security::provider_subject::ProviderSubjectIdentifier>,
    ) -> Self {
        Self {
            retry: None,
            provider_subject: std::sync::Mutex::new(provider_subject),
            audit: tokio::sync::Mutex::new(ProviderDispatchAuditState::TransportOnly),
            _private: (),
        }
    }

    /// Private wire metadata minted before request-binding authorization.
    /// Concrete adapters cannot replace this with arbitrary caller input.
    pub(crate) fn provider_subject(
        &self,
    ) -> Result<Option<crate::security::provider_subject::ProviderSubjectIdentifier>> {
        self.provider_subject
            .lock()
            .map(|subject| subject.clone())
            .map_err(|_| anyhow::anyhow!("provider-subject dispatch state is poisoned"))
    }

    async fn complete_success(&self, completion: &Completion) -> Result<()> {
        let mut state = self.audit.lock().await;
        match &mut *state {
            ProviderDispatchAuditState::Active(audit) => {
                let result = audit.complete_success(completion).await;
                *state = ProviderDispatchAuditState::Closed;
                result
            }
            ProviderDispatchAuditState::BetweenAttempts => anyhow::bail!(
                "provider completed while its retry permit was between authorized attempts"
            ),
            ProviderDispatchAuditState::Closed | ProviderDispatchAuditState::TransportOnly => {
                Ok(())
            }
        }
    }

    async fn failure(&self, error_kind: &'static str) -> Result<()> {
        let mut state = self.audit.lock().await;
        match &mut *state {
            ProviderDispatchAuditState::Active(audit) => {
                let result = audit.failure(error_kind).await;
                *state = ProviderDispatchAuditState::Closed;
                result
            }
            // A retry-boundary failure has already emitted the terminal for
            // the last real attempt. If the next authorization is denied,
            // there is deliberately no second 0x20 to pair here.
            ProviderDispatchAuditState::BetweenAttempts
            | ProviderDispatchAuditState::Closed
            | ProviderDispatchAuditState::TransportOnly => Ok(()),
        }
    }

    async fn ensure_consent_before_send(&self) -> Result<()> {
        let retry = self.retry.as_ref().ok_or_else(|| {
            anyhow::anyhow!("dispatch permit does not carry live-consent context")
        })?;
        if let Err(error) = retry
            .authorizer
            .ensure_live_consent(retry.consent_route.as_ref())
        {
            if let Err(audit_error) = self.failure("provider_consent_revoked").await {
                return Err(anyhow::anyhow!(
                    "provider consent was revoked and terminal audit failed: {audit_error}; consent error: {error}"
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Close the current leaf before any retry backoff or session repair. A
    /// cancellation while waiting therefore leaves one paired lifecycle and
    /// no phantom authorization for an attempt that never sent.
    pub(crate) async fn finish_attempt_for_retry(&self, reason: ProviderRetryReason) -> Result<()> {
        let mut state = self.audit.lock().await;
        match &mut *state {
            ProviderDispatchAuditState::Active(audit) => {
                let result = audit.failure(reason.terminal_kind()).await;
                *state = ProviderDispatchAuditState::BetweenAttempts;
                result
            }
            ProviderDispatchAuditState::BetweenAttempts => {
                anyhow::bail!("provider retry attempt was already closed")
            }
            ProviderDispatchAuditState::Closed => {
                anyhow::bail!("provider retry requested after the dispatch permit was closed")
            }
            ProviderDispatchAuditState::TransportOnly => {
                anyhow::bail!("transport-only dispatch permits cannot authorize retries")
            }
        }
    }

    /// Re-run the exact leaf's Council budget, cost, permission and durable
    /// 0x20 boundary immediately before another transport send.
    pub(crate) async fn begin_retry_attempt(&self) -> Result<()> {
        {
            let state = self.audit.lock().await;
            if !matches!(&*state, ProviderDispatchAuditState::BetweenAttempts) {
                anyhow::bail!("provider retry authorization requires a closed prior attempt");
            }
        }
        let retry = self.retry.clone().ok_or_else(|| {
            anyhow::anyhow!("dispatch permit does not carry retry authorization context")
        })?;
        let mut authorized = retry
            .authorizer
            .authorize_leaf(
                retry.provider,
                &retry.req,
                retry.call_scope,
                false,
                retry.output_token_ceiling,
            )
            .await?;
        let provider_subject = authorized.take_provider_subject();
        let audit = authorized.begin_dispatch().await?;

        let mut state = self.audit.lock().await;
        if !matches!(&*state, ProviderDispatchAuditState::BetweenAttempts) {
            drop(state);
            drop(audit);
            anyhow::bail!("provider retry permit changed while authorization was in flight");
        }
        *self
            .provider_subject
            .lock()
            .map_err(|_| anyhow::anyhow!("provider-subject retry state is poisoned"))? =
            provider_subject;
        *state = ProviderDispatchAuditState::Active(Box::new(audit));
        drop(state);
        self.ensure_consent_before_send().await
    }
}

/// Resolve the exact model identifier a provider's effective primary will put
/// on the wire. Request assembly uses this before model-aware token budgeting;
/// the authorization boundary calls the same helper again immediately before
/// dispatch. Provider resolvers must therefore be idempotent for canonical
/// model identifiers.
pub(crate) fn resolve_request_model_for_wire<P: Provider + ?Sized>(
    provider: &P,
    requested_model: Option<&str>,
) -> Result<String> {
    let requested_model = requested_model
        .filter(|model| !model.trim().is_empty())
        .or_else(|| {
            provider
                .default_model()
                .filter(|model| !model.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider `{}` has no explicit request model or declared default",
                provider.name()
            )
        })?;
    let wire_model = provider.resolve_model_for_wire(requested_model);
    anyhow::ensure!(
        !wire_model.trim().is_empty(),
        "provider `{}` resolved `{requested_model}` to an empty wire model",
        provider.name()
    );
    Ok(wire_model)
}

/// Resolve a configured/requested model through both model namespaces before
/// any budgeting or authorization decision observes it: first the operator's
/// global one-level alias map, then the concrete adapter's wire canonicalizer.
///
/// Keep this at the provider boundary so non-chat surfaces (n8n, background
/// sessions, Cron, channel helpers) cannot accidentally re-bind a raw
/// `freedom.yaml` alias after [`from_config`] already built a canonical adapter.
pub(crate) fn resolve_configured_request_model_for_wire<P: Provider + ?Sized>(
    config: &FreedomConfig,
    provider: &P,
    requested_model: Option<&str>,
) -> Result<String> {
    let requested_model = requested_model
        .filter(|model| !model.trim().is_empty())
        .or_else(|| {
            provider
                .default_model()
                .filter(|model| !model.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider `{}` has no explicit request model or declared default",
                provider.name()
            )
        })?;
    let aliased_model = config.resolve_model_alias(requested_model);
    resolve_request_model_for_wire(provider, Some(aliased_model))
}

/// Canonical default advertised by an already-built adapter. Callers that
/// wrap providers must prefer this over reusing raw configuration strings:
/// `from_config` has already applied the global alias map and the adapter may
/// have applied a second provider-native normalization step.
pub(crate) fn provider_default_wire_model<P: Provider + ?Sized>(provider: &P) -> Option<String> {
    provider
        .default_model()
        .map(|model| provider.resolve_model_for_wire(model))
        .filter(|model| !model.trim().is_empty())
}

fn bind_wire_identity<P: Provider + ?Sized>(
    provider: &P,
    req: &mut Request,
) -> Result<CompletionIdentity> {
    let wire_model = resolve_request_model_for_wire(provider, req.model.as_deref())?;
    req.model = Some(wire_model.clone());
    Ok(CompletionIdentity::new(provider.name(), &wire_model))
}

fn stamp_completion_identity(
    completion: &mut Completion,
    identity: &CompletionIdentity,
    preserve_bound_identity: bool,
) {
    if !preserve_bound_identity || !completion.identity.is_bound() {
        completion.identity = identity.clone();
        completion.model = identity.wire_model.clone();
    }
}

fn stamp_stream_identity(
    stream: ChunkStream,
    identity: CompletionIdentity,
    preserve_bound_identity: bool,
) -> ChunkStream {
    Box::pin(stream.map(move |item| {
        item.map(|mut chunk| {
            if !preserve_bound_identity || !chunk.identity.is_bound() {
                chunk.identity = identity.clone();
            }
            chunk
        })
    }))
}

/// Every LLM backend implements this. Trait is object-safe by design so the
/// daemon can hold `Box<dyn Provider>` in its registry.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Short identifier for logs + WAL events: "claude_cli", "openai_api", ...
    fn name(&self) -> &'static str;

    /// Controls this concrete provider leaf implements. Decorators delegate or
    /// return the intersection of every leaf they may select.
    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::NONE
    }

    /// Validate both the shared capability contract and any leaf-specific,
    /// model-dependent restrictions. Leaf overrides must call the shared
    /// validator first so malformed and unsupported controls stay fail-closed.
    fn validate_request_controls(&self, req: &Request) -> Result<()> {
        self.request_controls().validate(self.name(), req)
    }

    /// Concrete model the adapter sends when `Request.model` is absent.
    /// Decorators delegate this to their effective primary. The cost boundary
    /// uses it to replace implicit wire defaults with an explicit request model.
    fn default_model(&self) -> Option<&str> {
        None
    }

    /// Concrete outbound route whose durable consent marker must still exist
    /// immediately before every real transport attempt. Decorators that recurse
    /// through `complete_authorized` naturally defer this to their leaf.
    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        crate::consent::kind_from_slug(self.name())
            .map(|kind| crate::consent::ConsentRoute::new(kind, None))
    }

    /// Resolve an operator/config alias to the exact model identifier that the
    /// adapter will put on the wire. Paid-call authorization invokes this
    /// before hashing, pricing, or opening a stream.
    fn resolve_model_for_wire(&self, requested_model: &str) -> String {
        requested_model.to_owned()
    }

    /// Proven maximum billable output tokens this concrete leaf can emit for
    /// `req`. `Some(n)` is valid only when the same adapter invocation enforces
    /// `n` on the wire. `None` means the whole invocation has no proven finite
    /// upper cost bound, so non-local leaves are audited and gated through
    /// `UnboundedPaidProviderCall`; there is no generic 4096-token assumption.
    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        None
    }

    /// Whether this provider's raw streaming implementation requests a
    /// streaming response on its concrete wire protocol. The default stream
    /// buffers [`Self::complete`] into one chunk, so its actual wire mode is
    /// non-streaming and must be audited as such.
    fn streams_on_wire(&self) -> bool {
        false
    }

    /// Whether this decorator owns non-streaming quota preflight for every
    /// candidate in a fallback chain. Callers must keep the ordinary primary
    /// preflight for streaming, because streams intentionally never fail over.
    fn handles_nonstream_quota_backoff(&self) -> bool {
        false
    }

    /// Authorization decorators return the identity stamped by their actual
    /// inner leaf. Concrete transports must keep the default so a raw adapter
    /// cannot forge a different provider/model than the request authorized at
    /// this boundary.
    fn preserves_inner_response_identity(&self) -> bool {
        false
    }

    /// Reissue a request through the exact concrete leaf that produced
    /// `expected`. Routing decorators must consume one route segment and
    /// recurse into that child; ordinary decorators keep the default and may
    /// not change provider/model/route.
    async fn complete_authorized_pinned(
        &self,
        mut req: Request,
        expected: &CompletionIdentity,
        authorizer: &cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        if !expected.dispatch_route.is_empty() {
            anyhow::bail!(
                "provider `{}` cannot consume pinned dispatch route {:?}",
                self.name(),
                expected.dispatch_route
            );
        }
        if self.name() != expected.provider {
            anyhow::bail!(
                "pinned recovery expected provider `{}`, reached `{}`",
                expected.provider,
                self.name()
            );
        }
        req.model = Some(expected.wire_model.clone());
        let resolved = resolve_request_model_for_wire(self, req.model.as_deref())?;
        if resolved != expected.wire_model {
            anyhow::bail!(
                "pinned recovery expected wire model `{}`, provider `{}` resolved `{resolved}`",
                expected.wire_model,
                self.name()
            );
        }
        req.model = Some(resolved);
        let completion = self
            .complete_authorized(req, authorizer, call_scope)
            .await?;
        if completion.identity != *expected {
            anyhow::bail!(
                "pinned recovery identity drifted from `{:?}` to `{:?}`",
                expected,
                completion.identity
            );
        }
        Ok(completion)
    }

    /// Dispatch one concrete non-streaming provider hop through the mandatory
    /// paid-call boundary. Decorators override this method and recurse into
    /// their actual child hop(s); leaf adapters use this default, which binds
    /// the exact wire model and authorizes the exact request immediately before
    /// the network call.
    async fn complete_authorized(
        &self,
        mut req: Request,
        authorizer: &cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        self.validate_request_controls(&req)?;
        let identity = bind_wire_identity(self, &mut req)?;
        let output_token_ceiling = validated_output_token_ceiling(self, &req)?;
        let mut authorized = authorizer
            .authorize_leaf(self.name(), &req, call_scope, false, output_token_ceiling)
            .await?;
        let provider_subject = authorized.take_provider_subject();
        let audit = authorized.begin_dispatch().await?;
        let permit = ProviderDispatchPermit::authorized(
            audit,
            authorizer.clone(),
            self.name(),
            self.consent_route(),
            req.clone(),
            call_scope,
            output_token_ceiling,
            provider_subject,
        );
        permit.ensure_consent_before_send().await?;
        match self.complete_raw(req, &permit).await {
            Ok(mut completion) => {
                stamp_completion_identity(
                    &mut completion,
                    &identity,
                    self.preserves_inner_response_identity(),
                );
                permit.complete_success(&completion).await?;
                Ok(completion)
            }
            Err(error) => {
                if let Err(audit_error) = permit.failure("provider_call_failed").await {
                    return Err(anyhow::anyhow!(
                        "provider call failed and terminal audit failed: {audit_error}; provider error: {error}"
                    ));
                }
                Err(error)
            }
        }
    }

    /// Streaming twin of [`Self::complete_authorized`]. The authorization
    /// payload records streaming mode and is completed before a stream can
    /// open. Decorators recurse into the actual streaming child.
    async fn stream_authorized(
        &self,
        mut req: Request,
        authorizer: &cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<ChunkStream> {
        self.validate_request_controls(&req)?;
        let identity = bind_wire_identity(self, &mut req)?;
        let output_token_ceiling = validated_output_token_ceiling(self, &req)?;
        let streaming = self.streams_on_wire();
        let mut authorized = authorizer
            .authorize_leaf(
                self.name(),
                &req,
                call_scope,
                streaming,
                output_token_ceiling,
            )
            .await?;
        let provider_subject = authorized.take_provider_subject();
        let mut audit = authorized.begin_dispatch().await?;
        if let Err(error) = authorizer.ensure_live_consent(self.consent_route().as_ref()) {
            if let Err(audit_error) = audit.failure("provider_consent_revoked").await {
                return Err(anyhow::anyhow!(
                    "provider stream consent was revoked and terminal audit failed: {audit_error}; consent error: {error}"
                ));
            }
            return Err(error);
        }
        let permit = ProviderDispatchPermit::transport_only(provider_subject);
        match self.stream_raw(req, &permit).await {
            Ok(stream) => Ok(audit.wrap_stream(stamp_stream_identity(
                stream,
                identity,
                self.preserves_inner_response_identity(),
            ))),
            Err(error) => {
                if let Err(audit_error) = audit.failure("stream_open_failed").await {
                    return Err(anyhow::anyhow!(
                        "provider stream open failed and terminal audit failed: {audit_error}; provider error: {error}"
                    ));
                }
                Err(error)
            }
        }
    }

    /// Concrete transport execution. The unforgeable permit is created only
    /// after cost WAL + permission WAL + policy approval succeed.
    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        // Test doubles historically implement `complete`; forwarding here
        // keeps them lightweight. Production adapters implement `complete_raw`
        // directly and the source invariant below rejects other overrides.
        self.complete(req).await
    }

    /// Safe dispatch entry. Only authorization decorators override this in
    /// production; a bare leaf fails before any transport can run.
    async fn complete(&self, req: Request) -> Result<Completion> {
        #[cfg(test)]
        {
            let mut req = req;
            self.validate_request_controls(&req)?;
            let identity = bind_wire_identity(self, &mut req)?;
            let permit = ProviderDispatchPermit::transport_only(None);
            let mut completion = self.complete_raw(req, &permit).await?;
            stamp_completion_identity(&mut completion, &identity, false);
            return Ok(completion);
        }
        #[cfg(not(test))]
        {
            let _ = req;
            anyhow::bail!(
                "raw provider `{}` is not dispatchable; wrap it in an authorized provider boundary",
                self.name()
            )
        }
    }

    /// Safe exact-leaf retry entry. Authorization boundaries override this and
    /// delegate to [`Self::complete_authorized_pinned`]; a bare production leaf
    /// remains non-dispatchable.
    async fn complete_pinned(
        &self,
        req: Request,
        expected: &CompletionIdentity,
    ) -> Result<Completion> {
        #[cfg(test)]
        {
            let completion = self.complete(req).await?;
            if completion.identity != *expected {
                anyhow::bail!(
                    "test provider pinned identity mismatch: expected `{:?}`, got `{:?}`",
                    expected,
                    completion.identity
                );
            }
            return Ok(completion);
        }
        #[cfg(not(test))]
        {
            let _ = (req, expected);
            anyhow::bail!(
                "raw provider `{}` is not pinned-dispatchable; wrap it in an authorized provider boundary",
                self.name()
            )
        }
    }

    /// Streaming completion. Adapters that natively stream (claude_cli with
    /// `--output-format stream-json`, OpenAI SSE, Ollama NDJSON) override this.
    /// Adapters that do not yet support streaming fall through
    /// to the default impl: synchronously call `complete`, wrap the full text
    /// in a single done-chunk. UX-wise that means `neoth chat --stream` on
    /// such adapters still works but emits one chunk at the end, not
    /// progressively.
    async fn stream_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        let completion = self.complete_raw(req, permit).await?;
        let chunk = CompletionChunk {
            delta: completion.text,
            done: true,
            identity: completion.identity,
            termination: completion.termination,
            input_tokens: completion.input_tokens,
            output_tokens: completion.output_tokens,
            // VIEW-03 — propagate cache tokens from the fallback complete() path
            // so the streaming usage_log call site captures them even when the
            // adapter uses the default single-chunk stream implementation.
            cache_creation_tokens: completion.cache_creation_tokens,
            cache_read_tokens: completion.cache_read_tokens,
        };
        Ok(Box::pin(stream::iter(vec![Ok(chunk)])))
    }

    /// Safe streaming entry. Bare leaves fail closed in production.
    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        #[cfg(test)]
        {
            let mut req = req;
            self.validate_request_controls(&req)?;
            let identity = bind_wire_identity(self, &mut req)?;
            let permit = ProviderDispatchPermit::transport_only(None);
            let stream = self.stream_raw(req, &permit).await?;
            return Ok(stamp_stream_identity(stream, identity, false));
        }
        #[cfg(not(test))]
        {
            let _ = req;
            anyhow::bail!(
                "raw provider `{}` is not stream-dispatchable; wrap it in an authorized provider boundary",
                self.name()
            )
        }
    }
}

/// Derive the output ceiling used at the authorization boundary and reject a
/// leaf that claims to support a caller cap without proving it was narrowed on
/// the exact outbound request. The adapter owns `output_token_ceiling` because
/// only it knows the concrete wire field; this common guard prevents a
/// capability declaration from becoming an advisory no-op.
fn validated_output_token_ceiling<P: Provider + ?Sized>(
    provider: &P,
    req: &Request,
) -> Result<Option<u32>> {
    let ceiling = provider.output_token_ceiling(req);
    match (req.max_output_tokens, ceiling) {
        (Some(requested), Some(0)) => anyhow::bail!(
            "provider `{}` returned an invalid zero output-token ceiling for requested max_output_tokens={requested}",
            provider.name()
        ),
        (Some(requested), Some(effective)) if effective > requested => anyhow::bail!(
            "provider `{}` accepted max_output_tokens={requested} but only proved output ceiling {effective}; adapter must enforce the requested cap on wire",
            provider.name()
        ),
        (Some(requested), None) => anyhow::bail!(
            "provider `{}` accepted max_output_tokens={requested} without a proven enforced output ceiling",
            provider.name()
        ),
        (_, Some(0)) => anyhow::bail!(
            "provider `{}` returned an invalid zero output-token ceiling",
            provider.name()
        ),
        (_, ceiling) => Ok(ceiling),
    }
}

/// Apply a non-essential temperature hint only when the selected leaf can put
/// it on the wire. Operator-provided controls never use this helper and remain
/// strict; this is only for internal quality hints that must stay portable.
pub(crate) fn internal_temperature(
    provider: &dyn Provider,
    temperature: f32,
    call_scope: &'static str,
) -> Option<f32> {
    let request = Request {
        temperature: Some(temperature),
        ..Request::default()
    };
    match provider.validate_request_controls(&request) {
        Ok(()) => Some(temperature),
        Err(error) => {
            tracing::warn!(
                provider = provider.name(),
                call_scope,
                temperature,
                error = %error,
                "internal temperature hint omitted because the effective provider model cannot wire it"
            );
            None
        }
    }
}

/// Construct a provider for a specific hemisphere role
/// (Left / Right / Cerebellum). Reads `config.inference.slot_for(role)`
/// and builds the matching adapter. Falls back to the single-mode
/// provider when no per-hemisphere override is set.
///
/// Used by:
///   - `cli::chat` (CH-04) routing as `HemisphereRole::Left` (analytic).
///   - `cli::profile` extraction as `HemisphereRole::Left` (deductive).
///   - `cli::hemispheres test --role <X>` for the sanity check.
///   - Future council router + skill router stages.
///
/// In Single mode this is identical to [`from_config`] — `slot_for`
/// returns `default_slot` for every role and `default_slot.provider`
/// is empty, so the fallback short-circuits to the legacy path.
fn synthetic_config_for_slot(
    config: &FreedomConfig,
    slot: &crate::config::inference::HemisphereSlot,
    provider_kind: ProviderKind,
) -> FreedomConfig {
    let mut synthetic = config.clone();
    synthetic.provider_kind = Some(provider_kind);
    synthetic.provider_model = slot.model.clone();
    synthetic.provider_key = slot.key.clone();
    synthetic.provider_endpoint = slot.endpoint.clone();
    synthetic.inference.openai_compat_profile = slot.openai_compat_profile;
    if let Some(slot_region) = slot.region.clone() {
        synthetic.provider_region = Some(slot_region);
    }
    if let Some(slot_ver) = slot.api_version.clone() {
        synthetic.provider_api_version = Some(slot_ver);
    }
    synthetic
}

pub async fn from_config_for_role(
    config: &FreedomConfig,
    role: crate::config::inference::HemisphereRole,
) -> Result<Box<dyn Provider>> {
    from_config_for_role_inner(config, role, None).await
}

/// Explicit-instance variant used by chat/serve roots. Live catalog defaults
/// belong to that instance; the home-less API above intentionally uses only
/// shipped defaults so process-global state cannot leak across configurations.
pub async fn from_config_for_role_at(
    config: &FreedomConfig,
    role: crate::config::inference::HemisphereRole,
    home: &Path,
) -> Result<Box<dyn Provider>> {
    from_config_for_role_inner(config, role, Some(home)).await
}

async fn from_config_for_role_inner(
    config: &FreedomConfig,
    role: crate::config::inference::HemisphereRole,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    let slot = config.inference.slot_for(role);
    let Some(provider_kind) = slot.provider else {
        let mut selected = config.clone();
        if let Some(home) = home {
            apply_instance_catalog_default(&mut selected, home);
        }
        return from_config_for_instance(&selected, home).await;
    };
    // Build a synthetic FreedomConfig view that pretends the slot's
    // provider is the single-mode config. Reuses `from_config`'s full
    // construction logic without duplicating adapter wiring.
    let mut synthetic = synthetic_config_for_slot(config, slot, provider_kind.to_provider_kind());
    // C-3 Phase 2 (Session 14) — per-slot region wins over the
    // top-level FreedomConfig::provider_region. Only relevant for
    // aws_bedrock today; other providers ignore the field.
    // C-4 Phase 2 (Session 14) — per-slot api_version wins over the
    // top-level FreedomConfig::provider_api_version. Only relevant
    // for azure_openai; other providers ignore.
    if let Some(home) = home {
        apply_instance_catalog_default(&mut synthetic, home);
    }
    from_config_for_instance(&synthetic, home).await
}

/// SPEC-03b — build the chat provider WITH its 429 fallback chain. The
/// primary is the Left-role provider (identical to `from_config_for_role`
/// in Single mode); each `config.fallback.chain` slot is appended as a
/// fallback IFF its cloud-egress consent is granted — a 429 must never
/// silently exfiltrate to a provider the operator never approved (4-lens
/// gremium consensus). Non-cloud slots (local_qwen/ouro) pass the consent
/// gate automatically. Empty chain / all-skipped ⇒ the bare primary
/// (zero decorator overhead, no behaviour change without a `fallback:`
/// section). Callers (`cli/chat.rs`, `serve.rs`) use this in place of
/// `from_config_for_role(.., Left)`.
/// SPEC-03b consent gate — extracted as a pure, side-effect-light seam so
/// the security-critical decision ("never build a cloud fallback the
/// operator has not consented to") is unit-testable without constructing
/// providers or mutating the real `~/.neoth`. Returns the subset of `slots`
/// whose cloud-egress consent is granted under `home`, in order, paired with
/// the resolved provider. Slots with no provider are dropped; non-cloud
/// kinds (`local_qwen`/`local_ouro`) always pass via [`crate::consent::is_granted`].
pub(crate) fn consented_fallback_slots<'a>(
    home: &std::path::Path,
    config: &'a FreedomConfig,
) -> Vec<(
    &'a crate::config::inference::HemisphereSlot,
    crate::config::inference::InferenceProvider,
)> {
    fallback_slots_allowed_by(home, config, None)
}

fn fallback_slots_allowed_by<'a>(
    home: &std::path::Path,
    config: &'a FreedomConfig,
    ephemeral_consent: Option<&crate::consent::EphemeralConsent>,
) -> Vec<(
    &'a crate::config::inference::HemisphereSlot,
    crate::config::inference::InferenceProvider,
)> {
    if config.fallback.max_hops == 0 {
        return Vec::new();
    }
    config
        .fallback
        .chain
        .iter()
        .filter_map(|slot| match slot.provider {
            None => {
                tracing::warn!("fallback slot has no provider set; skipping");
                None
            }
            Some(inf) => {
                let route = crate::consent::route_for_provider_config(
                    inf.to_provider_kind(),
                    slot.endpoint.as_deref(),
                    slot.region.as_deref().or(config.provider_region.as_deref()),
                );
                let durable = crate::consent::is_route_granted(home, &route);
                let ephemeral = ephemeral_consent
                    .map(|consent| match consent.permits_route(&route) {
                        Ok(permitted) => permitted,
                        Err(_) => {
                            tracing::warn!(
                                provider = inf.as_str(),
                                "fallback slot skipped: one-shot consent route is invalid"
                            );
                            false
                        }
                    })
                    .unwrap_or(false);
                if durable || ephemeral {
                    return Some((slot, inf));
                }
                tracing::warn!(
                    provider = inf.as_str(),
                    "fallback slot skipped: cloud-egress consent not granted \
                     (run `neoth consent grant <provider>` to enable)"
                );
                None
            }
        })
        .collect()
}

pub async fn fallback_chain_from_config(
    config: &FreedomConfig,
    home: &std::path::Path,
    wal_writer: Option<crate::wal::writer::WalWriterHandle>,
) -> Result<Box<dyn Provider>> {
    fallback_chain_from_config_inner(config, home, wal_writer, None).await
}

/// Interactive chat builder. It may construct a fallback leaf authorized by
/// this command's exact one-shot capability, but does not consume that
/// capability. The concrete leaf authorizer remains the only consumer.
pub(crate) async fn fallback_chain_from_config_interactive(
    config: &FreedomConfig,
    home: &std::path::Path,
    wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ephemeral_consent: &crate::consent::EphemeralConsent,
) -> Result<Box<dyn Provider>> {
    fallback_chain_from_config_inner(config, home, wal_writer, Some(ephemeral_consent)).await
}

async fn fallback_chain_from_config_inner(
    config: &FreedomConfig,
    home: &std::path::Path,
    wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ephemeral_consent: Option<&crate::consent::EphemeralConsent>,
) -> Result<Box<dyn Provider>> {
    let primary =
        from_config_for_role_at(config, crate::config::inference::HemisphereRole::Left, home)
            .await?;
    if config.fallback.chain.is_empty() || config.fallback.max_hops == 0 {
        return Ok(primary);
    }
    let mut configured_models = vec![provider_default_wire_model(primary.as_ref())];
    let mut chain: Vec<Box<dyn Provider>> = vec![primary];
    // CRITICAL consent gate (4-lens gremium) lives in
    // `consented_fallback_slots` — a regression there would leak operator
    // text to an un-consented cloud provider on every 429, so it is a pure
    // tested seam rather than an inline branch.
    for (slot, inf_provider) in fallback_slots_allowed_by(home, config, ephemeral_consent) {
        let kind = inf_provider.to_provider_kind();
        let mut synthetic = synthetic_config_for_slot(config, slot, kind);
        apply_instance_catalog_default(&mut synthetic, home);
        match from_config_for_instance(&synthetic, Some(home)).await {
            Ok(p) => {
                let wire_model = provider_default_wire_model(p.as_ref());
                chain.push(p);
                configured_models.push(wire_model);
            }
            Err(e) => tracing::warn!(
                provider = inf_provider.as_str(),
                error = %e,
                "fallback slot build failed; skipping"
            ),
        }
    }
    if chain.len() == 1 {
        // Every fallback was skipped (un-consented / build-failed) → no
        // decorator, just the primary.
        return Ok(chain.into_iter().next().expect("primary present"));
    }
    Ok(Box::new(fallback::FallbackProvider::new_with_models_at(
        chain,
        configured_models,
        config.fallback.max_hops,
        wal_writer,
        home.join("quota.json"),
    )))
}

/// E-2 Phase 3 (Session 14) — construct an adapter for an INNER
/// hemisphere within a recursive council, scoped to a specific
/// OUTER role.
///
/// Resolves the slot via
/// [`crate::config::inference::InferenceTopology::slot_for_sub`] —
/// uses `hemisphere_sub_slots[outer_role][inner_role]` when set,
/// otherwise falls back to the outer-level `slot_for(inner_role)`.
/// Then builds the adapter via the same synthetic-config trick that
/// [`from_config_for_role`] uses. Recursion mechanics in
/// `cli::chat::ProviderHemisphere::ask_with_depth` call this when
/// `depth > 1` AND the outer-wrapper carries an `outer_role`.
pub async fn from_config_for_sub_role(
    config: &FreedomConfig,
    outer_role: crate::config::inference::HemisphereRole,
    inner_role: crate::config::inference::HemisphereRole,
) -> Result<Box<dyn Provider>> {
    from_config_for_sub_role_inner(config, outer_role, inner_role, None).await
}

pub async fn from_config_for_sub_role_at(
    config: &FreedomConfig,
    outer_role: crate::config::inference::HemisphereRole,
    inner_role: crate::config::inference::HemisphereRole,
    home: &Path,
) -> Result<Box<dyn Provider>> {
    from_config_for_sub_role_inner(config, outer_role, inner_role, Some(home)).await
}

async fn from_config_for_sub_role_inner(
    config: &FreedomConfig,
    outer_role: crate::config::inference::HemisphereRole,
    inner_role: crate::config::inference::HemisphereRole,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    let slot = config.inference.slot_for_sub(outer_role, inner_role);
    let Some(provider_kind) = slot.provider else {
        // Slot has no provider override at the sub-level → defer
        // to the outer-role path (which still consults sub-fall-
        // back-to-outer in `slot_for_sub` but lands the same way).
        return match home {
            Some(home) => from_config_for_role_at(config, inner_role, home).await,
            None => from_config_for_role(config, inner_role).await,
        };
    };
    let mut synthetic = synthetic_config_for_slot(config, slot, provider_kind.to_provider_kind());
    if let Some(home) = home {
        apply_instance_catalog_default(&mut synthetic, home);
    }
    from_config_for_instance(&synthetic, home).await
}

/// V10-07 (Session 21) — construct the provider the post-reply
/// profile-extract pipeline runs against. Reads
/// `config.profile.learn_provider` (L-06, shipped Session 20) and
/// builds the matching adapter; honours
/// `config.profile.allow_cloud_fallback` (L-07) when the chosen
/// learn-provider build fails (e.g. local_qwen weights missing).
///
/// Resolution order:
///   1. `profile.learn_provider == Some(name)` → build a synthetic
///      FreedomConfig view with that provider + delegate to
///      [`from_config`]. Same trick as
///      [`from_config_for_role`] for hemisphere slots.
///   2. `profile.learn_provider == None` → fall through to
///      [`from_config`] (uses the operator's main provider — the
///      legacy v0.1 behaviour).
///   3. Step 1 fails AND `profile.allow_cloud_fallback == true`
///      → log a warn + fall back to [`from_config`]. This is the
///      operator's explicit opt-in to "spend cloud tokens for
///      profile extract when local doesn't work today".
///   4. Step 1 fails AND `allow_cloud_fallback == false` → propagate
///      the error so the caller can decide to skip the learn pass
///      (default cheap-by-default posture).
pub async fn from_config_for_learn(config: &FreedomConfig) -> Result<Box<dyn Provider>> {
    from_config_for_learn_inner(config, None).await
}

pub async fn from_config_for_learn_at(
    config: &FreedomConfig,
    home: &Path,
) -> Result<Box<dyn Provider>> {
    from_config_for_learn_inner(config, Some(home)).await
}

async fn from_config_for_learn_inner(
    config: &FreedomConfig,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    let Some(learn_name) = config.profile.learn_provider.as_deref() else {
        // No explicit learn provider — use the main one.
        return from_config_with_optional_home(config, home).await;
    };
    // ProviderKind derives serde rename_all="snake_case" so the
    // YAML scalar form parses directly. Saves an explicit from_slug
    // impl just for this one site.
    let parsed: Option<crate::cli::init::ProviderKind> = serde_yaml::from_str(learn_name).ok();
    let Some(kind) = parsed else {
        // Unknown name — surface a clear error so the operator fixes
        // freedom.yaml instead of silently sliding to cloud.
        return Err(anyhow::anyhow!(
            "freedom.yaml::profile.learn_provider = `{learn_name}` is not a recognised provider \
             slug. Valid: local_qwen, local_ouro, claude_cli, openai_api, openai_compat, \
             gemini_api, aws_bedrock, azure_openai, copilot_api, skip. Edit + re-run \
             `neoth reload`. \
             (Antigravity CLI surfaces via the same `gemini_api` provider — `agy` is the \
             operator-side CLI, gemini_api is the upstream REST endpoint it auths against.)"
        ));
    };
    let mut synthetic = config.clone();
    // Secret-boundary guard (mirrors build_utility_config): the cloned
    // provider_key / provider_endpoint / provider_model all belong to the MAIN
    // vendor. When the learn provider is a DIFFERENT vendor, reusing them would
    // ship the main key to the learn vendor's endpoint (secret egress) and a
    // foreign model id (404). Strip them so the learn build resolves its OWN
    // credentials (or fails cleanly). Same-vendor learn keeps the shared key.
    if config.provider_kind != Some(kind) {
        synthetic.provider_key = None;
        synthetic.provider_endpoint = None;
        synthetic.provider_model = None;
    }
    synthetic.provider_kind = Some(kind);
    match from_config_with_optional_home(&synthetic, home).await {
        Ok(p) => Ok(p),
        Err(e) if config.profile.allow_cloud_fallback => {
            tracing::warn!(
                error = %e,
                learn_provider = learn_name,
                "profile.learn_provider build failed; allow_cloud_fallback=true → falling back to main provider"
            );
            from_config_with_optional_home(config, home).await
        }
        Err(e) => Err(e.context(format!(
            "profile.learn_provider `{learn_name}` build failed AND allow_cloud_fallback=false; \
             set allow_cloud_fallback=true to spend main-provider tokens, or fix the local \
             provider setup"
        ))),
    }
}

/// GOLD-ADOPT-21 — build the FAST/CHEAP "utility" provider for low-stakes
/// internal LLM calls (dreaming theme labels, email threat tiebreak, cron jobs,
/// regression re-query). Mirrors [`from_config_for_learn`]'s synthetic-config
/// trick but pins the provider's `ModelRole::Fast` model id so the call lands
/// on the cheapest tier (Haiku / GPT-4o-mini / Gemini Flash-lite).
///
/// Resolution:
///   1. `inference.utility_provider == None` (default) → fall through to
///      [`from_config`] (the operator's MAIN provider) — no routing change, no
///      regression. This is deliberately NOT defaulted to a local model: an
///      operator on `claude_cli` with no local inference must keep working.
///   2. `Some(kind)` → synthetic `FreedomConfig` with that provider kind + its
///      `fast` model id (from the default role table), then [`from_config`].
///      A build failure propagates so best-effort callers fall back to their
///      own deterministic path (cheap-by-default — never silently spends the
///      flagship model the operator was trying to avoid).
pub async fn from_config_for_utility(config: &FreedomConfig) -> Result<Box<dyn Provider>> {
    from_config_for_utility_inner(config, None).await
}

pub async fn from_config_for_utility_at(
    config: &FreedomConfig,
    home: &Path,
) -> Result<Box<dyn Provider>> {
    from_config_for_utility_inner(config, Some(home)).await
}

async fn from_config_for_utility_inner(
    config: &FreedomConfig,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    match build_utility_config(config) {
        // No `utility_provider` configured → use the operator's MAIN provider
        // (no routing change, no regression).
        None => from_config_with_optional_home(config, home).await,
        Some(synthetic) => from_config_with_optional_home(&synthetic, home).await,
    }
}

/// Model that [`from_config_for_utility`] will put on the wire when callers
/// explicitly bind `Request.model`. Keeping this next to
/// [`build_utility_config`] prevents utility cost authorization from drifting
/// to the main/flagship model after routing selected a fast model.
pub(crate) fn utility_model_for_config(config: &FreedomConfig) -> Option<String> {
    let effective = build_utility_config(config);
    let effective = effective.as_ref().unwrap_or(config);
    effective
        .provider_model
        .as_deref()
        .map(|model| effective.resolve_model_alias(model).to_owned())
}

/// GOLD-ADAPT-ODY-08 — build the SOTA teacher provider for escalation when a
/// local model fails or replies with low confidence.
///
/// Resolution order:
///   1. `config.inference.teacher_provider` (explicit operator routing), if set.
///   2. Main provider (`from_config(config)`) as fallback — the operator's cloud
///      flagship then acts as the teacher.
///
/// **Safety gate:** a non-cloud-SOTA `teacher_provider` is rejected with a clear
/// error. Teaching via a local model is circular — the same model class that
/// failed would be asked to correct itself. This also rejects `recursive_mas`:
/// it is intentionally outside the guaranteed-offline classification, but it
/// still is not a cloud SOTA teacher.
///
/// **No key cross-contamination:** if `teacher_provider` differs from the
/// operator's main provider, the synthetic config resets the key/endpoint/model
/// fields (same isolation as `build_utility_config`). Same-vendor routing
/// keeps the shared key.
pub async fn from_config_for_teacher(config: &FreedomConfig) -> Result<Box<dyn Provider>> {
    from_config_for_teacher_inner(config, None).await
}

pub async fn from_config_for_teacher_at(
    config: &FreedomConfig,
    home: &Path,
) -> Result<Box<dyn Provider>> {
    from_config_for_teacher_inner(config, Some(home)).await
}

async fn from_config_for_teacher_inner(
    config: &FreedomConfig,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    let Some(inf_prov) = config.inference.teacher_provider else {
        // No explicit teacher provider — fall through to main provider.
        return from_config_with_optional_home(config, home).await;
    };
    let teacher_str = inf_prov.as_str();
    if is_local_provider(teacher_str) || teacher_str == "recursive_mas" {
        anyhow::bail!(
            "freedom.yaml::inference.teacher_provider = `{teacher_str}` is not a cloud SOTA teacher. \
             Teacher escalation requires a cloud SOTA provider so the correction adds value. \
             Set a cloud provider (e.g. `anthropic_api`, `claude_cli`, `openai_api`, `gemini_api`) \
             or remove `teacher_provider` to fall through to the operator's main provider."
        );
    }
    let teacher_kind = inf_prov.to_provider_kind();
    let main_kind = config.provider_kind;
    let mut synthetic = config.clone();
    // Isolate key/endpoint/model when the teacher is a DIFFERENT vendor than
    // the main provider (same pattern as build_utility_config).
    if main_kind != Some(teacher_kind) {
        synthetic.provider_key = None;
        synthetic.provider_endpoint = None;
        synthetic.provider_model = None;
    }
    synthetic.provider_kind = Some(teacher_kind);
    from_config_with_optional_home(&synthetic, home).await
}

/// GR-027 — build the synthetic [`FreedomConfig`] for the utility provider, or
/// `None` when no `utility_provider` is set (the caller falls back to the main
/// provider).
///
/// **Key isolation:** when the utility provider is a DIFFERENT vendor than the
/// main provider, the cloned `provider_key` / `provider_endpoint` /
/// `provider_model` all belong to the MAIN vendor — reusing them would send the
/// main provider's API key (plus a wrong endpoint + model id) to the utility
/// vendor. They are reset so the utility build resolves its OWN key, or fails
/// cleanly (the best-effort caller then falls back to its deterministic path).
/// A same-vendor utility (e.g. flagship→fast on one provider) legitimately
/// keeps the shared key. Pure (no I/O) so this property is unit-testable.
fn build_utility_config(config: &FreedomConfig) -> Option<FreedomConfig> {
    let kind = config.inference.utility_provider?;
    let utility_kind = kind.to_provider_kind();
    let mut synthetic = config.clone();
    if config.provider_kind != Some(utility_kind) {
        synthetic.provider_key = None;
        synthetic.provider_endpoint = None;
        synthetic.provider_model = None;
    }
    synthetic.provider_kind = Some(utility_kind);
    // Pin the cheapest model for a CLOUD utility provider so a utility call never
    // lands on the flagship. GR-026: use `resolve_exact` (NO flagship fallback) so
    // a provider WITHOUT a `fast` row (aws_bedrock / azure_openai / cohere) leaves
    // the model UNSET → the adapter uses its own default instead of the expensive
    // flagship the operator was trying to avoid. GR-028: never pin for a LOCAL
    // provider — it runs a single loaded model and the table's local `fast` id is
    // a bare name (not a valid HF repo path), so the local adapter manages its own
    // model. GR-076: with `resolve_exact`, a missing `fast` row genuinely leaves
    // `provider_model` unset (the prior `resolve` always returned the flagship).
    if !is_local_provider(kind.as_str())
        && let Some(fast) = crate::providers::model_roles::default_table().resolve_exact(
            kind.as_str(),
            crate::providers::model_roles::ModelRole::Fast,
        )
    {
        synthetic.provider_model = Some(fast.to_string());
    }
    Some(synthetic)
}

/// Construct the provider configured in `~/.neoth/freedom.yaml`.
///
/// Async because `LocalQwen` may need to download model artifacts from HF
/// on first construction.
///
/// Returns `Err` if the operator has not configured a provider yet (provider
/// kind is `Skip` or absent). The caller — typically `cli::chat::run` — is
/// expected to print a helpful "run `neoth init` or `neoth hemispheres set`"
/// message in that case.
/// GOLD-WIRE-03: the default model for a provider when the operator left
/// `provider_model` unset. Resolves from [`model_roles::default_table`] (the
/// single source of truth for ship-time model defaults) and falls back to
/// `hardcoded` only when the provider has no row there. Wiring `from_config`
/// through this means changing a `default_table` Flagship/Balanced entry now
/// changes what the daemon selects — no scattered hardcoded strings to drift.
pub(crate) fn default_model(
    provider_id: &str,
    role: model_roles::ModelRole,
    hardcoded: &str,
) -> String {
    model_roles::default_table()
        .resolve(provider_id, role)
        .unwrap_or(hardcoded)
        .to_string()
}

/// Resolve a catalog-driven flagship only from an explicitly selected instance
/// home. Provider construction without a home deliberately stays on the shipped
/// table; it must never read another instance's process-global catalog.
pub(crate) fn catalog_flagship_model_at(home: &Path, provider_id: &str) -> Option<String> {
    let path = crate::models::catalog::ModelsCatalog::default_path(home);
    let catalog = crate::models::catalog::ModelsCatalog::load_from(&path);
    model_roles::flagship_from_catalog(&catalog, provider_id)
}

fn apply_instance_catalog_default(config: &mut FreedomConfig, home: &Path) {
    if config.provider_model.is_some() {
        return;
    }
    // These are exactly the from_config arms whose implicit default is the
    // Flagship role. Anthropic intentionally defaults to Balanced; providers
    // requiring an explicit deployment/model must continue to fail closed.
    let provider_id = match config.provider_kind {
        Some(ProviderKind::ClaudeCli) => "claude_cli",
        Some(ProviderKind::OpenaiApi) => "openai_api",
        Some(ProviderKind::GeminiApi) => "gemini_api",
        Some(ProviderKind::Cohere) => "cohere_api",
        Some(ProviderKind::GitHubCopilot) => "copilot_api",
        _ => return,
    };
    config.provider_model = catalog_flagship_model_at(home, provider_id);
}

pub async fn from_config(config: &FreedomConfig) -> Result<Box<dyn Provider>> {
    from_config_for_instance(config, None).await
}

async fn from_config_for_instance(
    config: &FreedomConfig,
    instance_home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    #[cfg(not(feature = "recursive-mas"))]
    let _ = instance_home;
    // GOLD-ADAPT-JV-MISC (model-alias map) — resolve the operator's alias ONCE
    // at the single provider chokepoint so every per-kind arm below sees the
    // real model id. Unknown tokens pass through (additive map).
    let aliased_config: Option<FreedomConfig> = match config.provider_model.as_deref() {
        Some(id) => {
            let resolved = config.resolve_model_alias(id);
            if resolved != id {
                tracing::info!(alias = id, model = %resolved, "model alias resolved");
                let mut c = config.clone();
                c.provider_model = Some(resolved.to_string());
                Some(c)
            } else {
                None
            }
        }
        None => None,
    };
    let config = aliased_config.as_ref().unwrap_or(config);
    let kind = config.provider_kind.ok_or_else(|| {
        anyhow::anyhow!("no provider configured. Run `neoth init` or `neoth hemispheres set`.")
    })?;

    match kind {
        ProviderKind::ClaudeCli => {
            let binary = config
                .provider_binary
                .clone()
                .unwrap_or_else(|| "claude".to_string());
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model(
                    "claude_cli",
                    model_roles::ModelRole::Flagship,
                    "claude-opus-4-7",
                )
            });
            // B-6 Item 2: thread freedom.yaml::claude_cli.* through.
            // `to_provider()` lowers the config-layer backend tag into
            // the adapter-layer enum. compaction_rotate_after is the
            // one tmux-config field the adapter constructor currently
            // accepts; idle/hard timeouts + session_scope hook in
            // with Item 3 (retry classifier) + the per-conversation
            // pool follow-up respectively.
            let backend = config.claude_cli.backend.to_provider();
            let cap = config.claude_cli.tmux.compaction_rotate_after;
            // Pick #35 (Session 14, B-6 gap-fix): thread the operator-
            // tunable idle + hard timeout from freedom.yaml all the way
            // into the adapter. Prior code dropped these on the floor
            // and the adapter fell back to the module-level constants —
            // operator could not tune them via config without code edits.
            let idle = config.claude_cli.tmux.idle_timeout_secs;
            let hard = config.claude_cli.tmux.hard_timeout_secs;
            if matches!(
                config.claude_cli.tmux.session_scope,
                crate::config::TmuxSessionScope::PerConversation
            ) {
                tracing::warn!(
                    "claude_cli.tmux.session_scope=per_conversation is reserved for the v0.2 \
                     pool — falling back to singleton scope for now."
                );
            }
            Ok(Box::new(
                claude_cli::ClaudeCliAdapter::new_with_backend_and_timeouts(
                    binary, model, backend, cap, idle, hard,
                )
                .with_resume_session_id(config.claude_cli.resume_session_id.clone()),
            ))
        }
        ProviderKind::OpenaiApi => {
            let key = require_provider_key(config, "openai_api")?;
            let endpoint = config
                .provider_endpoint
                .clone()
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model("openai_api", model_roles::ModelRole::Flagship, "gpt-5.5")
            });
            Ok(Box::new(openai_api::OpenAiAdapter::new_openai(
                endpoint, key, model,
            )?))
        }
        ProviderKind::OpenaiCompat => {
            let key = config
                .provider_key
                .clone()
                .unwrap_or_else(|| SecretString::from(""));
            let endpoint = config.provider_endpoint.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "openai_compat requires an endpoint URL in freedom.yaml. \
                     Run `neoth init --force` to reconfigure."
                )
            })?;
            let model = config.provider_model.clone().ok_or_else(|| {
                anyhow::anyhow!("openai_compat requires a model name in freedom.yaml.")
            })?;
            let profile = config
                .inference
                .openai_compat_profile
                .or_else(|| known_endpoints::profile_for_endpoint(&endpoint))
                .unwrap_or_default();
            Ok(Box::new(openai_api::OpenAiAdapter::new_compat_profiled(
                profile, endpoint, key, model,
            )?))
        }
        ProviderKind::AnthropicApi => {
            // PF-02 — native key-based Anthropic Messages adapter (distinct
            // from ClaudeCli). Uses the same single `provider_key` as the
            // other cloud adapters; default model is operator-overridable
            // via `provider_model`.
            let key = require_provider_key(config, "anthropic_api")?;
            // GOLD-WIRE-03: anthropic_api defaults to BALANCED (sonnet), not
            // Flagship (opus) — a deliberate cost choice on the metered native
            // API (the subscription `claude_cli` path defaults to flagship
            // opus). Operators override via `provider_model`.
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model(
                    "anthropic_api",
                    model_roles::ModelRole::Balanced,
                    "claude-sonnet-4-6",
                )
            });
            Ok(Box::new(anthropic_api::AnthropicAdapter::new(key, model)?))
        }
        ProviderKind::GeminiApi => {
            let key = require_provider_key(config, "gemini_api")?;
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model(
                    "gemini_api",
                    model_roles::ModelRole::Flagship,
                    "gemini-3.1-pro-preview",
                )
            });
            Ok(Box::new(gemini_api::GeminiAdapter::new(key, model)?))
        }
        ProviderKind::Cohere => {
            // PF-02 — native Cohere v2 Chat (Bearer key, metered). Same
            // single `provider_key` as the other cloud adapters.
            let key = require_provider_key(config, "cohere_api")?;
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model(
                    "cohere_api",
                    model_roles::ModelRole::Flagship,
                    "command-a-plus-05-2026",
                )
            });
            Ok(Box::new(cohere_api::CohereAdapter::new(key, model)?))
        }
        ProviderKind::LocalQwen => {
            // First construction downloads model artifacts from Hugging Face
            // (~3 GB); subsequent constructions are cache-fast. Operator-
            // chosen accelerator + sampling defaults thread through from
            // `freedom.yaml::inference`; per-call controls are merged by the
            // adapter after the strict leaf capability gate.
            let repo = config.provider_model.clone();
            let accelerator = config
                .inference
                .accelerator_override
                .as_deref()
                .and_then(crate::daemon::accelerator::Accelerator::from_str);
            let adapter = local_qwen::LocalQwenAdapter::new_with_full_options(
                repo,
                accelerator,
                local_qwen::SamplingConfig::default(),
                config.inference.max_new_tokens,
            )
            .await?;
            Ok(Box::new(adapter))
        }
        ProviderKind::LocalOuro => {
            // Ouro O-2 (Session 22) — `LocalOuroAdapter` mirrors the Qwen
            // shape: hf-hub auto-download on first call (~3 GB BF16,
            // `ByteDance/Ouro-1.4B-Thinking` default), reuses
            // `local_qwen::sample_token` for the generation loop. Operator
            // overrides the checkpoint via `freedom.yaml::provider_model`
            // (e.g. set to `ByteDance/Ouro-2.6B-Thinking` for the larger
            // variant).
            let repo = config.provider_model.clone();
            let accelerator = config
                .inference
                .accelerator_override
                .as_deref()
                .and_then(crate::daemon::accelerator::Accelerator::from_str);
            let adapter = ouro::adapter::LocalOuroAdapter::new_with_options(
                repo,
                accelerator,
                local_qwen::SamplingConfig::default(),
                config.inference.max_new_tokens,
            )
            .await?
            .with_quant_mode(config.inference.ouro_quant_mode);
            Ok(Box::new(adapter))
        }
        ProviderKind::AwsBedrock => {
            // C-3 Phase 2 (Session 14) — hand-rolled SigV4 against
            // `bedrock-runtime.<region>.amazonaws.com/model/<id>/converse`.
            // Region resolves from FreedomConfig::provider_region with
            // fallback to AWS_REGION/AWS_DEFAULT_REGION env, then to
            // `us-east-1`. Credentials walk the closed chain (explicit
            // → env vars → ~/.aws/credentials [default]).
            let region = aws_bedrock::effective_region(config.provider_region.as_deref())?;
            let model = config.provider_model.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "aws_bedrock requires a model id in freedom.yaml \
                     (e.g. anthropic.claude-3-5-sonnet-20241022-v2:0)."
                )
            })?;
            let resolved =
                aws_credentials::resolve_chain(None, &aws_credentials::env_var_getter, None)?;
            tracing::info!(
                source = ?resolved.source,
                region = %region,
                "aws_bedrock credentials resolved"
            );
            Ok(Box::new(aws_bedrock::AwsBedrockAdapter::new(
                region,
                resolved.credentials,
                model,
            )?))
        }
        ProviderKind::AzureOpenAi => {
            // C-4 Phase 2 (Session 14) — Azure OpenAI Service classic
            // deployment endpoint with `api-key` header + api-version
            // query parameter. `provider_endpoint` carries the Azure
            // resource URL; `provider_model` doubles as the
            // deployment name (Azure routes by deployment, not by
            // underlying model). `provider_api_version` overrides
            // the default GA version.
            let key = require_provider_key(config, "azure_openai")?;
            let endpoint = config.provider_endpoint.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "azure_openai requires an endpoint URL in freedom.yaml \
                     (e.g. `https://my-resource.openai.azure.com`). \
                     Run `neoth init --force` to reconfigure."
                )
            })?;
            let deployment = config.provider_model.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "azure_openai requires a deployment name in freedom.yaml \
                     (`provider_model: <your-deployment-name>`). Deployments are \
                     created in the Azure portal under your OpenAI resource → \
                     Deployments."
                )
            })?;
            let api_version = config.provider_api_version.clone();
            Ok(Box::new(azure_openai::AzureOpenAiAdapter::new(
                endpoint,
                key,
                deployment,
                api_version,
            )?))
        }
        ProviderKind::GitHubCopilot => {
            // GOLD-ADAPT-ODY-15: PAT → short-lived session token → OpenAI-compat completions.
            // provider_key holds the operator's GitHub PAT (with `copilot` scope).
            // provider_endpoint and provider_model may be left unset — the adapter
            // defaults to `https://api.githubcopilot.com` and `gpt-4o` respectively.
            let pat = require_provider_key(config, "copilot_api")?;
            let model = config.provider_model.clone().unwrap_or_else(|| {
                default_model("copilot_api", model_roles::ModelRole::Flagship, "gpt-4o")
            });
            Ok(Box::new(copilot::CopilotAdapter::new(pat, model)?))
        }
        ProviderKind::LocalOllama => {
            // GOLD-ADAPT-AWE-NANO-01 — native Ollama /api/chat NDJSON adapter.
            // No API key needed. Default base URL is http://localhost:11434;
            // override via `provider_endpoint` in freedom.yaml.
            // Default model is "llama3.2"; override via `provider_model`.
            let base_url = config
                .provider_endpoint
                .clone()
                .unwrap_or_else(|| ollama_api::DEFAULT_BASE_URL.to_string());
            let model = config
                .provider_model
                .clone()
                .unwrap_or_else(|| ollama_api::DEFAULT_MODEL.to_string());
            Ok(Box::new(ollama_api::OllamaAdapter::new(base_url, model)?))
        }
        // GOLD-ADAPT-RMAS-03 — experimental local sidecar. The live adapter
        // only exists behind the `recursive-mas` feature; the runtime gate
        // (enabled + VRAM + checkout present) runs inside spawn().
        #[cfg(feature = "recursive-mas")]
        ProviderKind::RecursiveMas => {
            Ok(Box::new(recursive_mas_adapter::RecursiveMasAdapter::spawn(
                &config.recursive_mas,
                &instance_home
                    .map(Path::to_path_buf)
                    .unwrap_or_else(FreedomConfig::default_neoth_home),
            )?))
        }
        #[cfg(not(feature = "recursive-mas"))]
        ProviderKind::RecursiveMas => {
            anyhow::bail!(
                "recursive_mas requires a build with the `recursive-mas` Cargo feature \
                 (experimental operator-installed sidecar; see freedom.yaml::recursive_mas)"
            )
        }
        ProviderKind::Skip => {
            anyhow::bail!(
                "provider was set to `skip` during init. Run `neoth init` or \
                 `neoth hemispheres set`."
            )
        }
    }
}

/// Construct the configured provider using the selected instance's live model
/// catalog for implicit Flagship defaults. Callers that know their NEOTH home
/// must use this boundary; [`from_config`] is intentionally process-global-
/// state free for tests and genuinely contextless consumers.
pub async fn from_config_at(config: &FreedomConfig, home: &Path) -> Result<Box<dyn Provider>> {
    let mut selected = config.clone();
    apply_instance_catalog_default(&mut selected, home);
    from_config_for_instance(&selected, Some(home)).await
}

async fn from_config_with_optional_home(
    config: &FreedomConfig,
    home: Option<&Path>,
) -> Result<Box<dyn Provider>> {
    match home {
        Some(home) => from_config_at(config, home).await,
        None => from_config(config).await,
    }
}

/// Day-14b Phase 2 — build the operator-configured embedding
/// provider (if any). Returns `None` when:
///   - `freedom.yaml::inference.embedding_provider` is absent
///   - operator picked a cloud provider that doesn't have an
///     `EmbedProvider` impl yet (only `local_qwen` ships in v0.1)
///   - the local provider failed to construct (no weights, no
///     disk, network blocked on first download)
///
/// Always non-fatal: callers (skill router Stage-2, council
/// dissent, dreaming clustering) fall back to keyword / Jaccard
/// when no provider is available. The L-07 `allow_cloud_fallback:
/// false` safe-default lives on the consumer side — this function
/// just reports availability honestly.
pub async fn embed_provider_from_config(
    config: &FreedomConfig,
) -> Option<std::sync::Arc<dyn crate::providers::embed::EmbedProvider>> {
    let provider_kind = config.inference.embedding_provider?;
    match provider_kind {
        crate::config::inference::InferenceProvider::LocalOuro => {
            let repo = config.provider_model.clone();
            let accelerator = config
                .inference
                .accelerator_override
                .as_deref()
                .and_then(crate::daemon::accelerator::Accelerator::from_str);
            let sampling = crate::providers::local_qwen::SamplingConfig::default();
            let max_new_tokens = config.inference.max_new_tokens;
            match crate::providers::ouro::adapter::LocalOuroAdapter::new_with_options(
                repo,
                accelerator,
                sampling,
                max_new_tokens,
            )
            .await
            {
                Ok(adapter) => Some(std::sync::Arc::new(
                    adapter.with_quant_mode(config.inference.ouro_quant_mode),
                )),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "embed_provider_from_config: local_ouro build failed; Stage-2 disabled"
                    );
                    None
                }
            }
        }
        crate::config::inference::InferenceProvider::LocalQwen => {
            let repo = config.provider_model.clone();
            let accelerator = config
                .inference
                .accelerator_override
                .as_deref()
                .and_then(crate::daemon::accelerator::Accelerator::from_str);
            let sampling = crate::providers::local_qwen::SamplingConfig::default();
            let max_new_tokens = config.inference.max_new_tokens;
            match crate::providers::local_qwen::LocalQwenAdapter::new_with_full_options(
                repo,
                accelerator,
                sampling,
                max_new_tokens,
            )
            .await
            {
                Ok(adapter) => Some(std::sync::Arc::new(adapter)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "embed_provider_from_config: local_qwen build failed; Stage-2 disabled"
                    );
                    None
                }
            }
        }
        other => {
            tracing::warn!(
                provider = %other.as_str(),
                "embed_provider_from_config: no EmbedProvider impl yet; Stage-2 disabled (v0.1 ships local_qwen only)"
            );
            None
        }
    }
}

fn require_provider_key(config: &FreedomConfig, name: &str) -> Result<SecretString> {
    config.provider_key.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "{name} requires an API key. Set NEOTH_PROVIDER_KEY env var or re-run `neoth init --force`."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::config::inference::{
        HemisphereRole, HemisphereSlot, InferenceProvider, InferenceTopology,
        OpenAiCompatibleProfile, SubHemisphereSlots, TopologyMode,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn blank_native_refusal_gets_a_neoth_authored_operator_notice() {
        let completion = Completion {
            identity: CompletionIdentity {
                provider: "openai_api".into(),
                wire_model: "gpt-test".into(),
                dispatch_route: Vec::new(),
            },
            termination: ProviderTermination::refused(
                Some("content_filter".into()),
                RefusalOrigin::FinishReason,
                "content_filter",
                None,
            ),
            ..Completion::default()
        };

        let notice = operator_refusal_notice(&completion).expect("typed blank refusal");
        assert!(notice.starts_with("[NEOTH]"));
        assert!(notice.contains("openai_api"));
        assert!(notice.contains("finish_reason"));
        assert!(notice.contains("content_filter"));
        assert_eq!(completion.text, "");
        assert!(completion.termination.is_refusal());
    }

    struct NoControlProvider {
        calls: AtomicUsize,
    }

    struct OutputCapProvider {
        ceiling: Option<u32>,
    }

    #[async_trait]
    impl Provider for OutputCapProvider {
        fn name(&self) -> &'static str {
            "output_cap"
        }

        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::OUTPUT_TOKEN_LIMIT
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            self.ceiling
        }
    }

    #[async_trait]
    impl Provider for NoControlProvider {
        fn name(&self) -> &'static str {
            "no_controls"
        }

        fn default_model(&self) -> Option<&str> {
            Some("test-model")
        }

        async fn complete_raw(
            &self,
            _req: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion::default())
        }
    }

    #[tokio::test]
    async fn unsupported_control_is_rejected_before_provider_call() {
        let provider = NoControlProvider {
            calls: AtomicUsize::new(0),
        };
        let error = provider
            .complete(Request {
                temperature: Some(0.4),
                ..Request::default()
            })
            .await
            .expect_err("unsupported control must fail");
        assert!(error.to_string().contains("provider `no_controls`"));
        assert!(error.to_string().contains("temperature"));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn default_stream_preserves_native_termination_on_final_chunk() {
        struct NativeRefusalProvider;

        #[async_trait]
        impl Provider for NativeRefusalProvider {
            fn name(&self) -> &'static str {
                "native_refusal"
            }

            fn default_model(&self) -> Option<&str> {
                Some("test-model")
            }

            async fn complete_raw(
                &self,
                _req: Request,
                _permit: &ProviderDispatchPermit,
            ) -> Result<Completion> {
                Ok(Completion {
                    termination: ProviderTermination::refused(
                        Some("content_filter".into()),
                        RefusalOrigin::FinishReason,
                        "content_filter",
                        None,
                    ),
                    ..Completion::default()
                })
            }
        }

        let mut stream = NativeRefusalProvider
            .stream(Request::default())
            .await
            .expect("default stream starts");
        let final_chunk = stream
            .next()
            .await
            .expect("default stream yields one chunk")
            .expect("default stream chunk succeeds");

        assert!(final_chunk.done);
        assert_eq!(
            final_chunk.termination.finish_reason.as_deref(),
            Some("content_filter")
        );
        assert_eq!(
            final_chunk
                .termination
                .refusal
                .as_ref()
                .map(|refusal| refusal.origin),
            Some(RefusalOrigin::FinishReason)
        );
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn internal_temperature_is_omitted_for_unsupported_provider() {
        let provider = NoControlProvider {
            calls: AtomicUsize::new(0),
        };

        assert_eq!(internal_temperature(&provider, 0.4, "test.internal"), None);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn request_control_validation_rejects_non_finite_ranges_and_bad_stops() {
        let controls = ProviderRequestControls::SAMPLING;
        for temperature in [f32::NAN, f32::INFINITY, -0.1, 2.1] {
            let error = controls
                .validate(
                    "test",
                    &Request {
                        temperature: Some(temperature),
                        ..Request::default()
                    },
                )
                .expect_err("invalid temperature");
            assert!(error.to_string().contains("temperature"));
        }
        for top_p in [f32::NAN, f32::INFINITY, 0.0, -0.1, 1.1] {
            let error = controls
                .validate(
                    "test",
                    &Request {
                        top_p: Some(top_p),
                        ..Request::default()
                    },
                )
                .expect_err("invalid top_p");
            assert!(error.to_string().contains("top_p"));
        }
        let seed_error = controls
            .validate(
                "test",
                &Request {
                    sampling_seed: Some(u32::MAX as u64 + 1),
                    ..Request::default()
                },
            )
            .expect_err("oversized seed");
        assert!(seed_error.to_string().contains("sampling_seed"));
        for stops in [vec![String::new()], vec!["x".repeat(257)]] {
            let error = controls
                .validate(
                    "test",
                    &Request {
                        stop_sequences: stops,
                        ..Request::default()
                    },
                )
                .expect_err("invalid stop sequence");
            assert!(error.to_string().contains("stop sequence"));
        }
    }

    #[test]
    fn request_control_intersection_preserves_the_stricter_temperature_limit() {
        ProviderRequestControls::SAMPLING
            .validate(
                "two",
                &Request {
                    temperature: Some(1.5),
                    ..Request::default()
                },
            )
            .expect("two-range provider accepts 1.5");

        let strict = ProviderRequestControls::SAMPLING
            .intersection(ProviderRequestControls::SAMPLING_MAX_ONE);
        let error = strict
            .validate(
                "fallback",
                &Request {
                    temperature: Some(1.5),
                    ..Request::default()
                },
            )
            .expect_err("intersection must retain the narrower leaf range");
        assert!(error.to_string().contains("[0.0, 1.0]"));
    }

    #[test]
    fn output_token_limit_is_strict_and_intersects_projects_and_validates() {
        let requested = Request {
            max_output_tokens: Some(512),
            ..Request::default()
        };
        ProviderRequestControls::OUTPUT_TOKEN_LIMIT
            .validate("capable", &requested)
            .expect("capable leaf accepts a valid requested output cap");
        let unsupported = ProviderRequestControls::SAMPLING
            .validate("sampling-only", &requested)
            .expect_err("leaf without output cap capability must reject it");
        assert!(unsupported.to_string().contains("max_output_tokens"));

        let common = ProviderRequestControls::SAMPLING
            .with_output_token_limit()
            .intersection(ProviderRequestControls::OUTPUT_TOKEN_LIMIT);
        assert!(common.supports_max_output_tokens());
        assert!(!common.supports_temperature());

        let mut projected = Request {
            temperature: Some(0.5),
            max_output_tokens: Some(512),
            ..Request::default()
        };
        assert_eq!(
            ProviderRequestControls::OUTPUT_TOKEN_LIMIT.project_compatible_controls(&mut projected),
            vec!["temperature"]
        );
        assert_eq!(projected.max_output_tokens, Some(512));

        for invalid in [Some(0), Some(MAX_REQUEST_OUTPUT_TOKENS + 1)] {
            let error = ProviderRequestControls::OUTPUT_TOKEN_LIMIT
                .validate(
                    "capable",
                    &Request {
                        max_output_tokens: invalid,
                        ..Request::default()
                    },
                )
                .expect_err("portable output caps must have a finite non-zero range");
            assert!(error.to_string().contains("max_output_tokens"));
        }
    }

    #[test]
    fn requested_output_cap_requires_a_matching_proven_effective_ceiling() {
        let request = Request {
            max_output_tokens: Some(512),
            ..Request::default()
        };
        assert_eq!(
            validated_output_token_ceiling(&OutputCapProvider { ceiling: Some(512) }, &request,)
                .unwrap(),
            Some(512)
        );
        for ceiling in [Some(513), None] {
            assert!(
                validated_output_token_ceiling(&OutputCapProvider { ceiling }, &request).is_err(),
                "requested cap must not become merely advisory"
            );
        }
    }

    #[test]
    fn model_cache_component_flattens_cross_platform_path_escape_syntax() {
        assert_eq!(
            model_cache_component(r"C:\\outside/../../model"),
            "C---outside-..-..-model"
        );
        assert!(!model_cache_component("repo\nname").contains('\n'));
    }

    #[test]
    fn default_model_resolves_from_table_then_falls_back() {
        // GOLD-WIRE-03 / GOLD-PROG-14: home-less provider construction uses
        // shipped defaults only. A live catalog is consulted exclusively via
        // an explicit instance home, exercised in the second half.
        use model_roles::{ModelRole, default_table};

        let tmp = tempfile::TempDir::new().unwrap();

        // Present provider → table value, NOT the hardcoded fallback.
        assert_eq!(
            default_model("claude_cli", ModelRole::Flagship, "IGNORED"),
            "claude-opus-4-7"
        );
        // Catalog-absent: the "changing default_table changes selection" link.
        assert_eq!(
            default_model("claude_cli", ModelRole::Flagship, "IGNORED"),
            default_table()
                .resolve("claude_cli", ModelRole::Flagship)
                .unwrap()
        );
        // anthropic_api defaults to Balanced (cost choice = sonnet). Balanced is
        // never catalog-overridden, so this holds regardless of any catalog.
        assert_eq!(
            default_model("anthropic_api", ModelRole::Balanced, "x"),
            "claude-sonnet-4-6"
        );
        // cohere_api is table-sourced (GOLD-WIRE-03 added its row).
        assert_eq!(
            default_model("cohere_api", ModelRole::Flagship, "x"),
            "command-a-plus-05-2026"
        );
        // Absent provider → the hardcoded fallback is used verbatim.
        assert_eq!(
            default_model("not_in_table", ModelRole::Flagship, "FALLBACK"),
            "FALLBACK"
        );

        // PROG-14: with a live catalog present, the Flagship role takes the
        // catalog's first non-deprecated id (a new flagship flows in without
        // hand-editing default_table); Balanced still ignores the catalog.
        let mut cat = crate::models::catalog::ModelsCatalog::in_memory();
        cat.providers.insert(
            "anthropic_api".to_string(),
            crate::models::catalog::ProviderCatalog {
                fetched_at_unix: 1,
                models: vec![crate::models::catalog::ModelEntry::new(
                    "claude-opus-4-9-NEW",
                )],
                ..Default::default()
            },
        );
        let cat_path = crate::models::catalog::ModelsCatalog::default_path(tmp.path());
        std::fs::create_dir_all(cat_path.parent().unwrap()).unwrap();
        std::fs::write(&cat_path, serde_json::to_vec(&cat).unwrap()).unwrap();

        assert_eq!(
            catalog_flagship_model_at(tmp.path(), "anthropic_api").as_deref(),
            Some("claude-opus-4-9-NEW"),
            "PROG-14: catalog flagship overrides the pinned default_table flagship"
        );
        assert_eq!(
            default_model("anthropic_api", ModelRole::Flagship, "IGNORED"),
            default_table()
                .resolve("anthropic_api", ModelRole::Flagship)
                .unwrap(),
            "home-less construction must not read the instance catalog"
        );
        // Balanced is NOT catalog-driven → still the pinned default.
        assert_eq!(
            default_model("anthropic_api", ModelRole::Balanced, "x"),
            "claude-sonnet-4-6"
        );
    }

    #[test]
    fn catalog_flagship_resolution_is_scoped_to_the_selected_instance_home() {
        fn write_catalog(home: &Path, model: &str) {
            let mut catalog = crate::models::catalog::ModelsCatalog::in_memory();
            catalog.providers.insert(
                "openai_api".to_owned(),
                crate::models::catalog::ProviderCatalog {
                    fetched_at_unix: 1,
                    models: vec![crate::models::catalog::ModelEntry::new(model)],
                    ..Default::default()
                },
            );
            let path = crate::models::catalog::ModelsCatalog::default_path(home);
            std::fs::write(path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        }

        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_catalog(first.path(), "gpt-instance-one");
        write_catalog(second.path(), "gpt-instance-two");

        assert_eq!(
            catalog_flagship_model_at(first.path(), "openai_api").as_deref(),
            Some("gpt-instance-one")
        );
        assert_eq!(
            catalog_flagship_model_at(second.path(), "openai_api").as_deref(),
            Some("gpt-instance-two")
        );
    }

    #[cfg(feature = "recursive-mas")]
    #[tokio::test]
    async fn recursive_mas_builder_uses_the_selected_instance_home_for_code_acknowledgement() {
        let acknowledged_home = tempfile::tempdir().unwrap();
        let selected_home = tempfile::tempdir().unwrap();
        crate::cli::rmas::write_rmas_consent_marker(acknowledged_home.path()).unwrap();
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::RecursiveMas),
            recursive_mas: crate::config::RecursiveMasConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let error = from_config_at(&config, selected_home.path())
            .await
            .err()
            .expect("another instance's acknowledgement must not authorize this one");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("code acknowledgement is missing"));
        assert!(rendered.contains(&format!("{:?}", selected_home.path())));
        assert!(!rendered.contains(&format!("{:?}", acknowledged_home.path())));
    }

    #[test]
    fn is_local_provider_recognises_only_guaranteed_offline_backends() {
        // The canonical guaranteed-offline set. Adding another trusted local
        // backend means adding ONE arm here — every quota/privacy/audit guard
        // routes through this fn, so they cannot drift out of sync (GR-17).
        assert!(is_local_provider("local_qwen"));
        assert!(is_local_provider("local_ouro"));
        assert!(is_local_provider("local_abliterated"));
        assert!(is_local_provider("local_ollama"));
        assert!(
            !is_local_provider("recursive_mas"),
            "network-capable sidecars must not bypass paid-call authorization"
        );
        assert!(!is_local_provider("claude_cli"));
        assert!(!is_local_provider("openai_api"));
        assert!(!is_local_provider("gemini_api"));
        assert!(!is_local_provider("aws_bedrock"));
        assert!(!is_local_provider("azure_openai"));
        assert!(!is_local_provider("")); // defensive: empty name is not local
    }

    #[tokio::test]
    async fn recursive_mas_remains_ineligible_as_teacher() {
        let mut cfg = base_config();
        cfg.inference.teacher_provider = Some(InferenceProvider::RecursiveMas);
        let err = err_or_panic(from_config_for_teacher(&cfg).await);
        assert!(
            err.to_string().contains("not a cloud SOTA teacher"),
            "recursive_mas must not become a teacher merely because it is no longer trusted offline"
        );
    }

    fn base_config() -> FreedomConfig {
        FreedomConfig {
            operator_id: Some("test".into()),
            provider_kind: Some(ProviderKind::ClaudeCli),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn compatible_known_endpoint_is_inferred_and_keeps_vendor_identity() {
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::OpenaiCompat);
        cfg.provider_endpoint = Some("https://api.deepseek.com".into());
        cfg.provider_model = Some("deepseek-v4-pro".into());
        cfg.provider_key = Some(SecretString::from("sk-test"));
        assert_eq!(cfg.inference.openai_compat_profile, None);

        let provider = from_config(&cfg).await.unwrap();
        assert_eq!(provider.name(), "deepseek_api");
        assert_eq!(
            provider.consent_route().unwrap().kind,
            ProviderKind::OpenaiCompat
        );
        let mut request = Request::default();
        let identity = bind_wire_identity(provider.as_ref(), &mut request).unwrap();
        assert_eq!(identity.provider, "deepseek_api");
        assert_eq!(identity.wire_model, "deepseek-v4-pro");
    }

    #[tokio::test]
    async fn explicit_compatible_profile_rejects_endpoint_drift() {
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::OpenaiCompat);
        cfg.provider_endpoint = Some("https://gateway.example.test/v1".into());
        cfg.provider_model = Some("model".into());
        cfg.provider_key = Some(SecretString::from("sk-test"));
        cfg.inference.openai_compat_profile = Some(OpenAiCompatibleProfile::OpenRouter);

        let error = err_or_panic(from_config(&cfg).await).to_string();
        assert!(error.contains("openrouter"));
        assert!(error.contains("does not match"));
    }

    #[tokio::test]
    async fn role_slot_profile_is_propagated_and_rejects_endpoint_mismatch() {
        let mut cfg = base_config();
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.openai_compat_profile = Some(OpenAiCompatibleProfile::DeepSeek);
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("https://gateway.example.test/v1".into()),
            openai_compat_profile: Some(OpenAiCompatibleProfile::OpenRouter),
            model: Some("model".into()),
            key: Some(SecretString::from("sk-test")),
            ..Default::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("https://gateway.example.test/v1".into()),
            model: Some("model".into()),
            key: Some(SecretString::from("sk-test")),
            ..Default::default()
        };

        let error = err_or_panic(from_config_for_role(&cfg, HemisphereRole::Left).await);
        assert!(error.to_string().contains("openrouter"));
        assert!(error.to_string().contains("does not match"));
        let right = from_config_for_role(&cfg, HemisphereRole::Right)
            .await
            .unwrap();
        assert_eq!(right.name(), "openai_compat");
    }

    #[tokio::test]
    async fn fallback_slot_profile_survives_synthetic_config_and_mismatch_validation() {
        let cfg = base_config();
        let slot = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("https://gateway.example.test/v1".into()),
            openai_compat_profile: Some(OpenAiCompatibleProfile::MoonshotKimi),
            model: Some("model".into()),
            key: Some(SecretString::from("sk-test")),
            ..Default::default()
        };
        let synthetic = synthetic_config_for_slot(&cfg, &slot, ProviderKind::OpenaiCompat);
        assert_eq!(
            synthetic.inference.openai_compat_profile,
            Some(OpenAiCompatibleProfile::MoonshotKimi)
        );
        let error = err_or_panic(from_config(&synthetic).await);
        assert!(error.to_string().contains("moonshot_kimi"));
        assert!(error.to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn sub_role_slot_profile_is_propagated_and_rejects_endpoint_mismatch() {
        let mut cfg = base_config();
        cfg.inference.mode = TopologyMode::Custom;
        let mut sub = SubHemisphereSlots::default();
        sub.right = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            endpoint: Some("https://gateway.example.test/v1".into()),
            openai_compat_profile: Some(OpenAiCompatibleProfile::QwenChat),
            model: Some("model".into()),
            key: Some(SecretString::from("sk-test")),
            ..Default::default()
        };
        cfg.inference
            .hemisphere_sub_slots
            .insert(HemisphereRole::Left, sub);

        let error = err_or_panic(
            from_config_for_sub_role(&cfg, HemisphereRole::Left, HemisphereRole::Right).await,
        );
        assert!(error.to_string().contains("qwen_chat"));
        assert!(error.to_string().contains("does not match"));
    }

    /// CH-04 invariant: in Single mode, role-aware routing must produce
    /// the same `synthetic.provider_kind` as the legacy single-mode
    /// path — the role parameter is a no-op so existing operators see
    /// zero behaviour change.
    #[test]
    fn single_mode_role_lookup_returns_default_slot_for_every_role() {
        let cfg = base_config();
        for role in [
            HemisphereRole::Left,
            HemisphereRole::Right,
            HemisphereRole::Cerebellum,
        ] {
            let slot = cfg.inference.slot_for(role);
            assert!(
                slot.provider.is_none(),
                "single mode default_slot must leave per-role provider unset for {role:?}"
            );
        }
    }

    /// CH-04 invariant: in Custom mode, `slot_for` returns the per-role
    /// override — the chat path will then build the matching adapter.
    #[test]
    fn custom_mode_role_lookup_returns_per_role_provider() {
        let mut cfg = base_config();
        cfg.inference = InferenceTopology {
            mode: TopologyMode::Custom,
            left: HemisphereSlot {
                provider: Some(InferenceProvider::ClaudeCli),
                model: Some("claude-opus-4-7".into()),
                ..Default::default()
            },
            right: HemisphereSlot {
                provider: Some(InferenceProvider::Gemini),
                model: Some("gemini-2.5-pro".into()),
                ..Default::default()
            },
            cerebellum: HemisphereSlot {
                provider: Some(InferenceProvider::LocalQwen),
                model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.inference.slot_for(HemisphereRole::Left).provider,
            Some(InferenceProvider::ClaudeCli)
        );
        assert_eq!(
            cfg.inference.slot_for(HemisphereRole::Right).provider,
            Some(InferenceProvider::Gemini)
        );
        assert_eq!(
            cfg.inference.slot_for(HemisphereRole::Cerebellum).provider,
            Some(InferenceProvider::LocalQwen)
        );
    }

    /// `Provider` is dyn-trait without `Debug`, so unwrap_err can't be
    /// used to extract anyhow errors. This helper does the
    /// match-and-extract pattern in one place.
    fn err_or_panic(result: Result<Box<dyn Provider>>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("expected provider construction to fail"),
            Err(e) => e,
        }
    }

    /// Smoke test: with `provider_kind = Skip`, both paths return Err —
    /// the chat path can render the same "run `neoth init` or
    /// `neoth hemispheres set`"
    /// hint regardless of whether the role-aware variant was used.
    #[tokio::test]
    async fn skip_provider_kind_errors_consistently_across_both_entry_points() {
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::Skip);
        let single_err = err_or_panic(from_config(&cfg).await);
        let role_err = err_or_panic(from_config_for_role(&cfg, HemisphereRole::Left).await);
        assert!(single_err.to_string().contains("skip"));
        assert!(role_err.to_string().contains("skip"));
    }

    /// CH-04 invariant: when an operator hasn't picked any provider
    /// (`provider_kind = None`), the role-aware path surfaces the same
    /// "no provider configured" error — keeps the "run `neoth provider
    /// add`" hint reachable from chat in both Single and Custom modes.
    #[tokio::test]
    async fn unset_provider_kind_errors_consistently() {
        let mut cfg = base_config();
        cfg.provider_kind = None;
        let single_err = err_or_panic(from_config(&cfg).await);
        let role_err = err_or_panic(from_config_for_role(&cfg, HemisphereRole::Left).await);
        assert!(single_err.to_string().contains("no provider configured"));
        assert!(role_err.to_string().contains("no provider configured"));
    }

    // ── V10-07 from_config_for_learn (Session 21) ──────────────

    #[tokio::test]
    async fn from_config_for_learn_unknown_slug_returns_actionable_error() {
        let mut cfg = base_config();
        cfg.profile.learn_provider = Some("bogus_provider_name".into());
        let err = err_or_panic(from_config_for_learn(&cfg).await);
        let msg = err.to_string();
        assert!(msg.contains("bogus_provider_name"));
        assert!(msg.contains("not a recognised provider slug"));
        assert!(msg.contains("local_qwen"));
    }

    // ── GOLD-ADOPT-21 from_config_for_utility ──────────────────

    #[tokio::test]
    async fn from_config_for_utility_none_falls_through_to_main_provider() {
        // No utility_provider → behave EXACTLY like from_config (no regression).
        let mut cfg = base_config();
        cfg.inference.utility_provider = None;
        let result = from_config_for_utility(&cfg).await;
        let main_result = from_config(&cfg).await;
        assert_eq!(result.is_ok(), main_result.is_ok());
    }

    #[tokio::test]
    async fn from_config_for_utility_explicit_kind_routes_to_synthetic_provider() {
        // Main provider is ClaudeCli (constructs cleanly). Setting
        // utility_provider = gemini_api (no key) must route to the SYNTHETIC
        // gemini kind — proven by a gemini/key-related build error rather than
        // a clean ClaudeCli construction.
        let mut cfg = base_config();
        cfg.inference.utility_provider = Some(crate::config::inference::InferenceProvider::Gemini);
        let result = from_config_for_utility(&cfg).await;
        if let Err(e) = result {
            let s = e.to_string().to_lowercase();
            assert!(
                s.contains("gemini") || s.contains("key") || s.contains("api"),
                "expected a gemini/key-related error (proves synthetic routing), got: {e}"
            );
        }
        // If it constructed (key present in env), that's also fine — it routed.
    }

    #[test]
    fn utility_pins_the_fast_model_id_per_provider() {
        // The cost guarantee: the utility builder pins each cloud provider's
        // FAST (cheapest) model from the default role table.
        use crate::providers::model_roles::{ModelRole, default_table};
        let t = default_table();
        assert_eq!(
            t.resolve("claude_cli", ModelRole::Fast),
            Some("claude-haiku-4-5-20251001")
        );
        assert_eq!(
            t.resolve("openai_api", ModelRole::Fast),
            Some("gpt-4o-mini")
        );
        assert_eq!(
            t.resolve("gemini_api", ModelRole::Fast),
            Some("gemini-3-flash-lite")
        );
    }

    #[test]
    fn utility_model_resolves_global_alias_before_wrapper_binding() {
        let mut cfg = base_config();
        cfg.inference.utility_provider = None;
        cfg.provider_model = Some("@utility".into());
        cfg.models_aliases
            .insert("@utility".into(), "claude-haiku-4-5-20251001".into());

        assert_eq!(
            utility_model_for_config(&cfg).as_deref(),
            Some("claude-haiku-4-5-20251001")
        );
    }

    #[test]
    fn utility_config_strips_main_key_for_a_different_vendor() {
        // GR-027 regression guard: a utility provider of a DIFFERENT vendor must
        // NOT inherit the main provider's API key — that would leak the main key
        // (and a wrong endpoint) to the utility vendor. Main = OpenAI with a
        // key; utility = Gemini.
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::OpenaiApi);
        cfg.provider_key = Some(crate::secret::SecretString::from("sk-MAIN-secret"));
        cfg.provider_endpoint = Some("https://api.openai.com/v1".into());
        cfg.inference.utility_provider = Some(InferenceProvider::Gemini);

        let synthetic = build_utility_config(&cfg).expect("utility config built");
        assert_eq!(synthetic.provider_kind, Some(ProviderKind::GeminiApi));
        assert!(
            synthetic.provider_key.is_none(),
            "main provider key must NOT cross to a different utility vendor"
        );
        assert!(
            synthetic.provider_endpoint.is_none(),
            "main endpoint must NOT cross to a different utility vendor"
        );
    }

    #[test]
    fn utility_config_keeps_key_for_same_vendor() {
        // A same-vendor utility (flagship→fast on one provider) legitimately
        // shares the single configured key — clearing it would break the
        // intended cost-tier routing.
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::GeminiApi);
        cfg.provider_key = Some(crate::secret::SecretString::from("sk-gemini"));
        cfg.inference.utility_provider = Some(InferenceProvider::Gemini);

        let synthetic = build_utility_config(&cfg).expect("utility config built");
        assert_eq!(synthetic.provider_kind, Some(ProviderKind::GeminiApi));
        assert!(
            synthetic.provider_key.is_some(),
            "same-vendor utility must keep the shared key"
        );
    }

    #[test]
    fn utility_config_no_flagship_or_local_pin() {
        // GR-026: a utility provider WITHOUT a `fast` row (aws_bedrock) must NOT
        // be pinned to the flagship — provider_model stays unset (adapter default).
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::OpenaiApi);
        cfg.provider_key = Some(crate::secret::SecretString::from("sk-main"));
        cfg.inference.utility_provider = Some(InferenceProvider::AwsBedrock);
        let s = build_utility_config(&cfg).expect("built");
        assert_eq!(s.provider_kind, Some(ProviderKind::AwsBedrock));
        assert_eq!(
            s.provider_model, None,
            "no fast row → no flagship pin (GR-026)"
        );

        // GR-028: a LOCAL utility provider must NOT be pinned the table's bare
        // local `fast` id (an invalid HF repo path) — the local adapter manages
        // its own model.
        let mut cfg2 = base_config();
        cfg2.provider_kind = Some(ProviderKind::OpenaiApi);
        cfg2.inference.utility_provider = Some(InferenceProvider::LocalQwen);
        let s2 = build_utility_config(&cfg2).expect("built");
        assert_eq!(s2.provider_kind, Some(ProviderKind::LocalQwen));
        assert_eq!(
            s2.provider_model, None,
            "local utility → no (invalid) HF-path pin (GR-028)"
        );

        // Regression: a cloud provider WITH a fast row still gets pinned to it.
        let mut cfg3 = base_config();
        cfg3.provider_kind = Some(ProviderKind::ClaudeCli);
        cfg3.inference.utility_provider = Some(InferenceProvider::OpenAi);
        let s3 = build_utility_config(&cfg3).expect("built");
        assert_eq!(s3.provider_model.as_deref(), Some("gpt-4o-mini"));
    }

    #[tokio::test]
    async fn from_config_for_learn_none_falls_through_to_main_provider() {
        // Operator hasn't set a learn_provider → uses main provider.
        // Main provider is ClaudeCli which constructs cleanly (binary
        // probe deferred to first call).
        let mut cfg = base_config();
        cfg.profile.learn_provider = None;
        // Don't care about the result type — only that the dispatch
        // routed through from_config(config) verbatim.
        let result = from_config_for_learn(&cfg).await;
        let main_result = from_config(&cfg).await;
        assert_eq!(result.is_ok(), main_result.is_ok());
    }

    #[tokio::test]
    async fn from_config_for_learn_explicit_slug_picks_synthetic_kind() {
        // Operator sets learn_provider = local_qwen → from_config_for_learn
        // builds a synthetic FreedomConfig with that kind. Operator's
        // main provider stays ClaudeCli.
        let mut cfg = base_config();
        cfg.profile.learn_provider = Some("local_qwen".into());
        // We can't easily verify the OWNED provider type without
        // downcasting; instead, verify it constructs SOMETHING (or
        // fails with a known LocalQwen-specific error like "weights
        // not found"). Build failures are L-07 territory — those
        // get an actionable error from the bail path.
        let result = from_config_for_learn(&cfg).await;
        // Either succeeds (weights cached) or fails with a clear
        // local_qwen-related message — NOT a generic provider error.
        if let Err(e) = result {
            let s = e.to_string().to_lowercase();
            assert!(
                s.contains("local_qwen")
                    || s.contains("qwen")
                    || s.contains("weights")
                    || s.contains("model"),
                "expected local-qwen-related error, got: {e}"
            );
        }
    }

    /// GOLD-ADAPT-ODY-15 integration test: proves `from_config` dispatches to
    /// `CopilotAdapter` for `ProviderKind::GitHubCopilot`. This is the canonical
    /// consumer wire — every other builder (`from_config_for_role`, `fallback_chain_from_config`,
    /// etc.) calls this function, so a passing test here covers all paths.
    #[tokio::test]
    async fn from_config_copilot_arm_constructs_adapter() {
        let mut cfg = base_config();
        cfg.provider_kind = Some(ProviderKind::GitHubCopilot);
        cfg.provider_key = Some(crate::secret::SecretString::from(
            "ghp_test_pat_000000000000000000000000",
        ));
        cfg.provider_model = Some("gpt-4o".to_string());
        let provider = from_config(&cfg)
            .await
            .expect("CopilotAdapter must construct");
        // name() == "copilot_api" proves the correct arm was reached.
        assert_eq!(
            provider.name(),
            "copilot_api",
            "from_config(GitHubCopilot) must return a provider named copilot_api"
        );
    }

    #[tokio::test]
    async fn from_config_for_learn_fallback_message_mentions_allow_cloud_fallback() {
        let mut cfg = base_config();
        cfg.profile.learn_provider = Some("local_qwen".into());
        cfg.profile.allow_cloud_fallback = false;
        // If LocalQwen build fails (weights missing on this host),
        // the wrapped error message MUST mention allow_cloud_fallback
        // so the operator knows how to recover.
        if let Err(e) = from_config_for_learn(&cfg).await {
            let s = e.to_string();
            assert!(
                s.contains("allow_cloud_fallback") || s.contains("local_qwen"),
                "expected diagnostic to mention allow_cloud_fallback or local_qwen, got: {s}"
            );
        }
        // Success case (weights cached + GPU works) is fine — no
        // assertion needed; the gate is the error message.
    }

    // ── SPEC-03b consent gate (consented_fallback_slots, Session 29) ──
    // The security-critical seam: a regression here (dropping the gate,
    // flipping the `!`, mis-mapping the kind) would route operator text to
    // an un-consented cloud provider on every 429. These pin the contract.

    fn config_with_fallback(slots: Vec<HemisphereSlot>) -> FreedomConfig {
        let mut config = FreedomConfig::default();
        config.fallback.chain = slots;
        config
    }

    #[test]
    fn consented_slots_drops_unconsented_cloud_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let config = config_with_fallback(vec![HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        }]);
        // No `.granted` marker written → OpenAI (cloud) must be dropped.
        assert!(
            consented_fallback_slots(tmp.path(), &config).is_empty(),
            "un-consented cloud fallback slot must never be built"
        );
    }

    #[test]
    fn consented_slots_keeps_consented_cloud_slot() {
        let tmp = tempfile::tempdir().unwrap();
        crate::consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        let config = config_with_fallback(vec![HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        }]);
        let kept = consented_fallback_slots(tmp.path(), &config);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].1, InferenceProvider::OpenAi);
    }

    #[test]
    fn consented_slots_local_provider_always_passes() {
        let tmp = tempfile::tempdir().unwrap();
        // No marker, no grant — local_qwen is non-cloud so it passes the gate.
        let config = config_with_fallback(vec![HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        }]);
        assert_eq!(
            consented_fallback_slots(tmp.path(), &config).len(),
            1,
            "local provider needs no consent"
        );
    }

    #[test]
    fn consented_slots_treats_ollama_by_endpoint_not_variant_name() {
        let tmp = tempfile::tempdir().unwrap();
        let config = config_with_fallback(vec![
            HemisphereSlot {
                provider: Some(InferenceProvider::LocalOllama),
                endpoint: Some("http://127.0.0.1:11434".into()),
                ..Default::default()
            },
            HemisphereSlot {
                provider: Some(InferenceProvider::LocalOllama),
                endpoint: Some("http://192.168.1.25:11434".into()),
                ..Default::default()
            },
        ]);
        let kept = consented_fallback_slots(tmp.path(), &config);
        assert_eq!(
            kept.len(),
            1,
            "remote Ollama must be dropped without consent"
        );
        assert_eq!(
            kept[0].0.endpoint.as_deref(),
            Some("http://127.0.0.1:11434")
        );

        crate::consent::grant_route(
            tmp.path(),
            &crate::consent::ConsentRoute::new(
                ProviderKind::LocalOllama,
                Some("http://192.168.1.25:11434"),
            ),
        )
        .unwrap();
        assert_eq!(
            consented_fallback_slots(tmp.path(), &config).len(),
            2,
            "explicit Ollama marker authorizes the remote fallback"
        );
    }

    #[test]
    fn consented_slots_drops_slot_without_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let config = config_with_fallback(vec![HemisphereSlot {
            provider: None,
            ..Default::default()
        }]);
        assert!(consented_fallback_slots(tmp.path(), &config).is_empty());
    }

    #[test]
    fn consented_slots_preserves_order_and_filters_mixed() {
        let tmp = tempfile::tempdir().unwrap();
        crate::consent::grant(tmp.path(), ProviderKind::GeminiApi).unwrap();
        // openai (cloud, NOT granted) dropped; gemini (cloud, granted) kept;
        // local_qwen (non-cloud) kept — relative order preserved.
        let config = config_with_fallback(vec![
            HemisphereSlot {
                provider: Some(InferenceProvider::OpenAi),
                ..Default::default()
            },
            HemisphereSlot {
                provider: Some(InferenceProvider::Gemini),
                ..Default::default()
            },
            HemisphereSlot {
                provider: Some(InferenceProvider::LocalQwen),
                ..Default::default()
            },
        ]);
        let kept = consented_fallback_slots(tmp.path(), &config);
        assert_eq!(
            kept.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            vec![InferenceProvider::Gemini, InferenceProvider::LocalQwen]
        );
    }

    #[test]
    fn bedrock_fallback_consent_is_bound_to_effective_slot_region() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = config_with_fallback(vec![HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            region: Some("eu-central-1".into()),
            ..Default::default()
        }]);
        config.provider_region = Some("us-east-1".into());
        crate::consent::grant_route(
            tmp.path(),
            &crate::consent::route_for_provider_config(
                ProviderKind::AwsBedrock,
                None,
                Some("us-east-1"),
            ),
        )
        .unwrap();
        assert!(
            consented_fallback_slots(tmp.path(), &config).is_empty(),
            "a default-region grant must not authorize the slot's EU route"
        );

        crate::consent::grant_route(
            tmp.path(),
            &crate::consent::route_for_provider_config(
                ProviderKind::AwsBedrock,
                None,
                Some("eu-central-1"),
            ),
        )
        .unwrap();
        assert_eq!(consented_fallback_slots(tmp.path(), &config).len(), 1);
    }

    #[test]
    fn interactive_fallback_selection_views_exact_one_shot_without_consuming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = config_with_fallback(vec![
            HemisphereSlot {
                provider: Some(InferenceProvider::AwsBedrock),
                region: Some("eu-central-1".into()),
                ..Default::default()
            },
            HemisphereSlot {
                provider: Some(InferenceProvider::AwsBedrock),
                region: Some("ap-southeast-2".into()),
                ..Default::default()
            },
        ]);
        config.provider_kind = Some(ProviderKind::AwsBedrock);
        config.provider_region = Some("us-east-1".into());
        let primary = crate::consent::route_for_provider_config(
            ProviderKind::AwsBedrock,
            None,
            config.provider_region.as_deref(),
        );
        let fallback = crate::consent::route_for_provider_config(
            ProviderKind::AwsBedrock,
            None,
            config.fallback.chain[0].region.as_deref(),
        );
        let mut ephemeral = crate::consent::EphemeralConsent::default();
        ephemeral.allow_route(&primary).unwrap();
        ephemeral.allow_route(&fallback).unwrap();

        let kept = fallback_slots_allowed_by(tmp.path(), &config, Some(&ephemeral));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0.region.as_deref(), Some("eu-central-1"));
        assert!(ephemeral.permits_route(&primary).unwrap());
        assert!(ephemeral.permits_route(&fallback).unwrap());
        assert!(ephemeral.consume_route(&primary).unwrap());
        assert!(!ephemeral.consume_route(&primary).unwrap());
        assert!(
            ephemeral.permits_route(&fallback).unwrap(),
            "spending the primary route must not consume a distinct fallback"
        );
    }

    #[test]
    fn zero_hop_config_never_selects_fallback_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = config_with_fallback(vec![HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        }]);
        config.fallback.max_hops = 0;
        assert!(consented_fallback_slots(tmp.path(), &config).is_empty());
    }
}
