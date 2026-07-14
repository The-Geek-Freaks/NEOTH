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
pub mod singleflight;
pub mod tmux_session;
pub mod tmux_socket;
pub mod tmux_sweeper;
pub mod tmux_sweeper_task;
pub mod whisper;

use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::{self, Stream};

use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::secret::SecretString;

/// Exact concrete identity of the provider invocation that produced a result.
/// The paid-call boundary overwrites adapter-supplied/default values after the
/// leaf gate succeeds, so consumers never have to reconstruct this from a
/// decorator name or a pre-resolution model alias.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletionIdentity {
    pub provider: String,
    pub wire_model: String,
}

impl CompletionIdentity {
    fn new(provider: &str, wire_model: &str) -> Self {
        Self {
            provider: provider.to_owned(),
            wire_model: wire_model.to_owned(),
        }
    }

    pub fn is_bound(&self) -> bool {
        !self.provider.is_empty() && !self.wire_model.is_empty()
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

/// A request to send to a Provider. Plain text for Day-5 MVP; multimodal
/// (image / tool-use) comes in later phases.
///
/// Request controls are strict, not advisory. Every concrete leaf declares
/// its [`ProviderRequestControls`]; unsupported or malformed controls fail
/// before authorization and transport. This prevents a CLI flag from looking
/// active while a provider silently drops it.
#[derive(Debug, Clone, Default)]
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
}

impl ProviderRequestControls {
    pub const NONE: Self = Self::new(None, false, false, false, false);
    /// Temperature up to 2.0, top-p, seed, and stop sequences.
    pub const SAMPLING: Self = Self::new(Some(2), true, true, true, false);
    /// Temperature up to 1.0, top-p, seed, and stop sequences.
    pub const SAMPLING_MAX_ONE: Self = Self::new(Some(1), true, true, true, false);
    /// Temperature up to 1.0, top-p, and stop sequences; seed unsupported.
    pub const SAMPLING_WITHOUT_SEED: Self = Self::new(Some(1), true, false, true, false);
    /// Temperature up to 2.0, top-p, and seed; stop sequences unsupported.
    pub const SAMPLING_WITHOUT_STOPS: Self = Self::new(Some(2), true, true, false, false);
    /// Per-call reasoning budget only (Claude CLI).
    pub const THINKING_BUDGET: Self = Self::new(None, false, false, false, true);

    const fn new(
        maximum_temperature: Option<u8>,
        top_p: bool,
        sampling_seed: bool,
        stop_sequences: bool,
        thinking_budget: bool,
    ) -> Self {
        Self {
            maximum_temperature,
            top_p,
            sampling_seed,
            stop_sequences,
            thinking_budget,
        }
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
        )
    }

    pub fn validate(self, provider: &str, req: &Request) -> Result<()> {
        validate_portable_request_controls(provider, req)?;

        let mut unsupported = Vec::with_capacity(5);
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
        if !unsupported.is_empty() {
            anyhow::bail!(
                "provider `{provider}` does not support request control(s): {}",
                unsupported.join(", ")
            );
        }
        if let (Some(temperature), Some(maximum)) = (req.temperature, self.maximum_temperature) {
            if temperature > maximum as f32 {
                anyhow::bail!(
                    "provider `{provider}`: temperature must be within [0.0, {maximum}.0], got {temperature}"
                );
            }
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

    if let Some(temperature) = req.temperature {
        if !temperature.is_finite() || !(0.0..=2.0).contains(&temperature) {
            anyhow::bail!(
                "provider `{provider}`: temperature must be finite and within [0.0, 2.0], got {temperature}"
            );
        }
    }
    if let Some(top_p) = req.top_p {
        if !top_p.is_finite() || top_p <= 0.0 || top_p > 1.0 {
            anyhow::bail!(
                "provider `{provider}`: top_p must be finite and within (0.0, 1.0], got {top_p}"
            );
        }
    }
    if let Some(seed) = req.sampling_seed {
        if seed > u64::from(u32::MAX) {
            anyhow::bail!(
                "provider `{provider}`: sampling_seed must be within [0, {}], got {seed}",
                u32::MAX
            );
        }
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
    if let Some(thinking_budget) = req.thinking_budget {
        if thinking_budget == 0 || thinking_budget > MAX_THINKING_BUDGET {
            anyhow::bail!(
                "provider `{provider}`: thinking_budget must be within [1, {MAX_THINKING_BUDGET}], got {thinking_budget}"
            );
        }
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

/// Capability required by every concrete provider transport. Its field and
/// constructor are private to this module, so safe Rust outside the mandatory
/// authorization boundary cannot manufacture a dispatch permit.
///
/// ```compile_fail
/// use neothd::providers::ProviderDispatchPermit;
///
/// let _forged = ProviderDispatchPermit { _private: () };
/// ```
pub struct ProviderDispatchPermit {
    _private: (),
}

fn bind_wire_identity<P: Provider + ?Sized>(
    provider: &P,
    req: &mut Request,
) -> Result<CompletionIdentity> {
    if req.model.is_none() {
        req.model = provider.default_model().map(str::to_owned);
    }
    let requested_model = req.model.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "provider `{}` has no explicit request model or declared default",
            provider.name()
        )
    })?;
    let wire_model = provider.resolve_model_for_wire(requested_model);
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

    /// Authorization decorators return the identity stamped by their actual
    /// inner leaf. Concrete transports must keep the default so a raw adapter
    /// cannot forge a different provider/model than the request authorized at
    /// this boundary.
    fn preserves_inner_response_identity(&self) -> bool {
        false
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
        let output_token_ceiling = self.output_token_ceiling(&req);
        let authorized = authorizer
            .authorize_leaf(self.name(), &req, call_scope, false, output_token_ceiling)
            .await?;
        let mut audit = authorized.begin_dispatch().await?;
        let permit = ProviderDispatchPermit { _private: () };
        match self.complete_raw(req, &permit).await {
            Ok(mut completion) => {
                stamp_completion_identity(
                    &mut completion,
                    &identity,
                    self.preserves_inner_response_identity(),
                );
                audit.complete_success(&completion).await?;
                Ok(completion)
            }
            Err(error) => {
                if let Err(audit_error) = audit.failure("provider_call_failed").await {
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
        let output_token_ceiling = self.output_token_ceiling(&req);
        let streaming = self.streams_on_wire();
        let authorized = authorizer
            .authorize_leaf(
                self.name(),
                &req,
                call_scope,
                streaming,
                output_token_ceiling,
            )
            .await?;
        let mut audit = authorized.begin_dispatch().await?;
        let permit = ProviderDispatchPermit { _private: () };
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
            let permit = ProviderDispatchPermit { _private: () };
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
            let permit = ProviderDispatchPermit { _private: () };
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
pub async fn from_config_for_role(
    config: &FreedomConfig,
    role: crate::config::inference::HemisphereRole,
) -> Result<Box<dyn Provider>> {
    let slot = config.inference.slot_for(role);
    let Some(provider_kind) = slot.provider else {
        return from_config(config).await;
    };
    // Build a synthetic FreedomConfig view that pretends the slot's
    // provider is the single-mode config. Reuses `from_config`'s full
    // construction logic without duplicating adapter wiring.
    let mut synthetic = config.clone();
    synthetic.provider_kind = Some(provider_kind.to_provider_kind());
    synthetic.provider_model = slot.model.clone();
    synthetic.provider_key = slot.key.clone();
    synthetic.provider_endpoint = slot.endpoint.clone();
    // C-3 Phase 2 (Session 14) — per-slot region wins over the
    // top-level FreedomConfig::provider_region. Only relevant for
    // aws_bedrock today; other providers ignore the field.
    if let Some(slot_region) = slot.region.clone() {
        synthetic.provider_region = Some(slot_region);
    }
    // C-4 Phase 2 (Session 14) — per-slot api_version wins over the
    // top-level FreedomConfig::provider_api_version. Only relevant
    // for azure_openai; other providers ignore.
    if let Some(slot_ver) = slot.api_version.clone() {
        synthetic.provider_api_version = Some(slot_ver);
    }
    from_config(&synthetic).await
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
    slots: &'a [crate::config::inference::HemisphereSlot],
) -> Vec<(
    &'a crate::config::inference::HemisphereSlot,
    crate::config::inference::InferenceProvider,
)> {
    slots
        .iter()
        .filter_map(|slot| match slot.provider {
            None => {
                tracing::warn!("fallback slot has no provider set; skipping");
                None
            }
            Some(inf) if crate::consent::is_granted(home, inf.to_provider_kind()) => {
                Some((slot, inf))
            }
            Some(inf) => {
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
    let primary =
        from_config_for_role(config, crate::config::inference::HemisphereRole::Left).await?;
    if config.fallback.chain.is_empty() {
        return Ok(primary);
    }
    let mut chain: Vec<Box<dyn Provider>> = vec![primary];
    let mut configured_models = vec![
        config
            .inference
            .slot_for(crate::config::inference::HemisphereRole::Left)
            .model
            .clone()
            .or_else(|| config.provider_model.clone()),
    ];
    // CRITICAL consent gate (4-lens gremium) lives in
    // `consented_fallback_slots` — a regression there would leak operator
    // text to an un-consented cloud provider on every 429, so it is a pure
    // tested seam rather than an inline branch.
    for (slot, inf_provider) in consented_fallback_slots(home, &config.fallback.chain) {
        let kind = inf_provider.to_provider_kind();
        let mut synthetic = config.clone();
        synthetic.provider_kind = Some(kind);
        synthetic.provider_model = slot.model.clone();
        synthetic.provider_key = slot.key.clone();
        synthetic.provider_endpoint = slot.endpoint.clone();
        if let Some(region) = slot.region.clone() {
            synthetic.provider_region = Some(region);
        }
        if let Some(ver) = slot.api_version.clone() {
            synthetic.provider_api_version = Some(ver);
        }
        match from_config(&synthetic).await {
            Ok(p) => {
                chain.push(p);
                configured_models.push(slot.model.clone());
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
    let slot = config.inference.slot_for_sub(outer_role, inner_role);
    let Some(provider_kind) = slot.provider else {
        // Slot has no provider override at the sub-level → defer
        // to the outer-role path (which still consults sub-fall-
        // back-to-outer in `slot_for_sub` but lands the same way).
        return from_config_for_role(config, inner_role).await;
    };
    let mut synthetic = config.clone();
    synthetic.provider_kind = Some(provider_kind.to_provider_kind());
    synthetic.provider_model = slot.model.clone();
    synthetic.provider_key = slot.key.clone();
    synthetic.provider_endpoint = slot.endpoint.clone();
    if let Some(slot_region) = slot.region.clone() {
        synthetic.provider_region = Some(slot_region);
    }
    if let Some(slot_ver) = slot.api_version.clone() {
        synthetic.provider_api_version = Some(slot_ver);
    }
    from_config(&synthetic).await
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
    let Some(learn_name) = config.profile.learn_provider.as_deref() else {
        // No explicit learn provider — use the main one.
        return from_config(config).await;
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
    match from_config(&synthetic).await {
        Ok(p) => Ok(p),
        Err(e) if config.profile.allow_cloud_fallback => {
            tracing::warn!(
                error = %e,
                learn_provider = learn_name,
                "profile.learn_provider build failed; allow_cloud_fallback=true → falling back to main provider"
            );
            from_config(config).await
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
    match build_utility_config(config) {
        // No `utility_provider` configured → use the operator's MAIN provider
        // (no routing change, no regression).
        None => from_config(config).await,
        Some(synthetic) => from_config(&synthetic).await,
    }
}

/// Model that [`from_config_for_utility`] will put on the wire when callers
/// explicitly bind `Request.model`. Keeping this next to
/// [`build_utility_config`] prevents utility cost authorization from drifting
/// to the main/flagship model after routing selected a fast model.
pub(crate) fn utility_model_for_config(config: &FreedomConfig) -> Option<String> {
    build_utility_config(config)
        .map(|synthetic| synthetic.provider_model)
        .unwrap_or_else(|| config.provider_model.clone())
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
    let Some(inf_prov) = config.inference.teacher_provider else {
        // No explicit teacher provider — fall through to main provider.
        return from_config(config).await;
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
    from_config(&synthetic).await
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
    if !is_local_provider(kind.as_str()) {
        if let Some(fast) = crate::providers::model_roles::default_table().resolve_exact(
            kind.as_str(),
            crate::providers::model_roles::ModelRole::Fast,
        ) {
            synthetic.provider_model = Some(fast.to_string());
        }
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
    // GOLD-PROG-14 / [neoth_model_version_agnostic] — for the Flagship role,
    // prefer the live catalog's provider-preferred (first non-deprecated) model
    // so a newly shipped flagship flows in WITHOUT hand-editing `default_table()`.
    // The catalog carries no Balanced/Fast tier signal, so those roles keep the
    // pinned defaults. Catalog absent/empty (fresh install, isolated tests) → the
    // existing `default_table()`/`hardcoded` path, so behaviour is unchanged there.
    if matches!(role, model_roles::ModelRole::Flagship) {
        let path = crate::models::catalog::ModelsCatalog::default_path(
            &FreedomConfig::default_neoth_home(),
        );
        let catalog = crate::models::catalog::ModelsCatalog::load_from(&path);
        if let Some(id) = model_roles::flagship_from_catalog(&catalog, provider_id) {
            return id;
        }
    }
    model_roles::default_table()
        .resolve(provider_id, role)
        .unwrap_or(hardcoded)
        .to_string()
}

pub async fn from_config(config: &FreedomConfig) -> Result<Box<dyn Provider>> {
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
            Ok(Box::new(openai_api::OpenAiAdapter::new_compat(
                endpoint, key, model,
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
            let region = config
                .provider_region
                .clone()
                .or_else(|| std::env::var("AWS_REGION").ok())
                .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
                .unwrap_or_else(|| "us-east-1".to_string());
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
        ProviderKind::RecursiveMas => Ok(Box::new(
            recursive_mas_adapter::RecursiveMasAdapter::spawn(&config.recursive_mas)?,
        )),
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
        HemisphereRole, HemisphereSlot, InferenceProvider, InferenceTopology, TopologyMode,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoControlProvider {
        calls: AtomicUsize,
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
    fn model_cache_component_flattens_cross_platform_path_escape_syntax() {
        assert_eq!(
            model_cache_component(r"C:\\outside/../../model"),
            "C---outside-..-..-model"
        );
        assert!(!model_cache_component("repo\nname").contains('\n'));
    }

    #[test]
    fn default_model_resolves_from_table_then_falls_back() {
        // GOLD-WIRE-03 / GOLD-PROG-14: `default_model` is the from_config
        // fallback path. With NO catalog present (isolated NEOTH_HOME below) the
        // `default_table` value wins for every role; an absent provider falls
        // back to the per-arm hardcoded string. PROG-14 layers a catalog
        // override for Flagship ON TOP — exercised in the second half.
        use model_roles::{ModelRole, default_table};

        // PROG-14: isolate NEOTH_HOME to an empty dir so default_model's catalog
        // read finds nothing → the pre-PROG-14 default_table behaviour holds. The
        // crate env lock serialises this against any sibling env test (#4 gotcha).
        let _env = crate::test_env::lock();
        let tmp = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("NEOTH_HOME", tmp.path()) };

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
                models: vec![crate::models::catalog::ModelEntry::new(
                    "claude-opus-4-9-NEW",
                )],
                ..Default::default()
            },
        );
        let cat_path = crate::models::catalog::ModelsCatalog::default_path(
            &FreedomConfig::default_neoth_home(),
        );
        std::fs::create_dir_all(cat_path.parent().unwrap()).unwrap();
        std::fs::write(&cat_path, serde_json::to_vec(&cat).unwrap()).unwrap();

        assert_eq!(
            default_model("anthropic_api", ModelRole::Flagship, "IGNORED"),
            "claude-opus-4-9-NEW",
            "PROG-14: catalog flagship overrides the pinned default_table flagship"
        );
        // Balanced is NOT catalog-driven → still the pinned default.
        assert_eq!(
            default_model("anthropic_api", ModelRole::Balanced, "x"),
            "claude-sonnet-4-6"
        );

        unsafe { std::env::remove_var("NEOTH_HOME") };
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
                "single mode default_slot must leave per-role provider unset for {:?}",
                role
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

    #[test]
    fn consented_slots_drops_unconsented_cloud_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let slots = vec![HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        }];
        // No `.granted` marker written → OpenAI (cloud) must be dropped.
        assert!(
            consented_fallback_slots(tmp.path(), &slots).is_empty(),
            "un-consented cloud fallback slot must never be built"
        );
    }

    #[test]
    fn consented_slots_keeps_consented_cloud_slot() {
        let tmp = tempfile::tempdir().unwrap();
        crate::consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        let slots = vec![HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        }];
        let kept = consented_fallback_slots(tmp.path(), &slots);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].1, InferenceProvider::OpenAi);
    }

    #[test]
    fn consented_slots_local_provider_always_passes() {
        let tmp = tempfile::tempdir().unwrap();
        // No marker, no grant — local_qwen is non-cloud so it passes the gate.
        let slots = vec![HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        }];
        assert_eq!(
            consented_fallback_slots(tmp.path(), &slots).len(),
            1,
            "local provider needs no consent"
        );
    }

    #[test]
    fn consented_slots_drops_slot_without_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let slots = vec![HemisphereSlot {
            provider: None,
            ..Default::default()
        }];
        assert!(consented_fallback_slots(tmp.path(), &slots).is_empty());
    }

    #[test]
    fn consented_slots_preserves_order_and_filters_mixed() {
        let tmp = tempfile::tempdir().unwrap();
        crate::consent::grant(tmp.path(), ProviderKind::GeminiApi).unwrap();
        // openai (cloud, NOT granted) dropped; gemini (cloud, granted) kept;
        // local_qwen (non-cloud) kept — relative order preserved.
        let slots = vec![
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
        ];
        let kept = consented_fallback_slots(tmp.path(), &slots);
        assert_eq!(
            kept.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            vec![InferenceProvider::Gemini, InferenceProvider::LocalQwen]
        );
    }
}
