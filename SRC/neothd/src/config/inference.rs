//! Inference-topology config — per-hemisphere LLM routing.
//!
//! NEOTH's "brain" maps onto three logical roles (Brain anatomy plan):
//!
//!   - **Left hemisphere** — analytic / structured reasoning.
//!   - **Right hemisphere** — creative / freeform generation.
//!   - **Cerebellum** — fast pattern matching for routing + summaries.
//!
//! Each role can use a different LLM provider, or all three can share one.
//! The wizard offers three modes:
//!
//!   1. **Single** — one provider for everything (current v0.1 behaviour).
//!   2. **Triplet** — same provider on all three slots (operator wants
//!      hemisphere awareness without per-slot config).
//!   3. **Custom** — explicit per-hemisphere provider + model + key.
//!
//! `InferenceProvider` is the union of LLM backends NEOTH can dispatch to.
//!
//! Removed Session-14 / 2026-05-18 (Codex feedback + the operator's architectural
//! correction): `Hermes` and `OpenClaw` are NOT LLM providers — they are
//! competing gateway systems that NEOTH supersedes. Operators wanting
//! direct access to the LLMs those gateways front (Claude, OpenAI,
//! Gemini, etc.) configure the underlying providers directly. Future
//! Pick #11 Phase C adds the real LLM providers the competitor stacks
//! integrate (DeepSeek-direct, xAI Grok, Mistral, Cohere, Moonshot
//! Kimi, etc.) so NEOTH's coverage is structurally complete.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Identifies one LLM backend NEOTH knows how to dispatch against. The
/// enum is part of the config schema (`freedom.yaml`) — adding a variant
/// is a non-breaking change as long as serde-default fields stay present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceProvider {
    /// Anthropic Claude via the operator's `claude` CLI (OAuth, no API key).
    ClaudeCli,
    /// Direct Anthropic API (key required).
    AnthropicApi,
    /// Direct OpenAI API.
    OpenAi,
    /// OpenAI-compatible endpoint (LM Studio, vLLM, Ollama, …).
    OpenAiCompat,
    /// Direct Google Gemini API.
    Gemini,
    /// Local Qwen3 forward pass via candle. Honours `accelerator_override`
    /// and the auto-detected accelerator.
    LocalQwen,
    /// C-3 (Session 13) — AWS Bedrock Runtime. Enterprise-class: SigV4
    /// auth via AWS SDK credentials chain (env vars / shared config /
    /// IAM role), region-bound model IDs (e.g. `anthropic.claude-opus-4`
    /// in `us-east-1`). NEOTH v0.1 ships the variant + provider-list
    /// surface + consent gate; actual `BedrockAdapter` runtime wiring
    /// is C-3 Phase 2 (separate session). `is_implemented()` returns
    /// `false` so operators selecting it see `[stub]` in the wizard.
    AwsBedrock,
    /// C-4 (Session 13) — Azure OpenAI Service. Enterprise-class:
    /// `api-version` query param (e.g. `2024-10-01-preview`) + deployment
    /// name as model id (operator-managed in Azure portal). Uses an
    /// Azure-issued API key (header `api-key`) NOT a `Bearer` token.
    /// NEOTH v0.1 ships the variant + provider-list surface + consent
    /// gate; actual `AzureOpenAiAdapter` ships in C-4 Phase 2.
    AzureOpenAi,
    /// Ouro O-2 (Session 22) — local Ouro thinking-models via the
    /// `LocalOuroAdapter` shipped in O-1b. Looped decoder-only transformer
    /// from ByteDance Seed (Apache-2.0). Honours `accelerator_override`
    /// like LocalQwen; default checkpoint `ByteDance/Ouro-1.4B-Thinking`
    /// (~3 GB BF16, noob-safe on ≥4 GB VRAM).
    LocalOuro,
    /// PF-02 (Session 31) — direct Cohere v2 Chat API
    /// (`api.cohere.com/v2`, Bearer key). A metered API (no subscription
    /// path). Hybrid wire format: OpenAI-like request (messages with a
    /// `system` role) + Anthropic-like response (`message.content[].text`).
    Cohere,
}

impl InferenceProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            InferenceProvider::ClaudeCli => "claude_cli",
            InferenceProvider::AnthropicApi => "anthropic_api",
            InferenceProvider::OpenAi => "openai_api",
            InferenceProvider::OpenAiCompat => "openai_compat",
            InferenceProvider::Gemini => "gemini_api",
            InferenceProvider::LocalQwen => "local_qwen",
            InferenceProvider::AwsBedrock => "aws_bedrock",
            InferenceProvider::AzureOpenAi => "azure_openai",
            InferenceProvider::LocalOuro => "local_ouro",
            InferenceProvider::Cohere => "cohere_api",
        }
    }

    /// One-line operator-facing label shown in the wizard Select.
    pub fn description(self) -> &'static str {
        match self {
            InferenceProvider::ClaudeCli => {
                "Claude via local `claude` CLI (OAuth, no API key in config)"
            }
            InferenceProvider::AnthropicApi => "Anthropic API (key required)",
            InferenceProvider::OpenAi => "OpenAI API (key required)",
            InferenceProvider::OpenAiCompat => "OpenAI-compatible endpoint (LM Studio, vLLM, …)",
            InferenceProvider::Gemini => "Google Gemini API (key required)",
            InferenceProvider::LocalQwen => "Local Qwen3 via candle (auto-detected accelerator)",
            InferenceProvider::AwsBedrock => {
                "AWS Bedrock Runtime (hand-rolled SigV4 + Converse API, env-creds or freedom.yaml)"
            }
            InferenceProvider::AzureOpenAi => {
                "Azure OpenAI Service (api-key header + api-version query + deployment-as-model)"
            }
            InferenceProvider::LocalOuro => {
                "Local Ouro thinking-models via candle (ByteDance LoopLM, Apache-2.0; 4× compute, explicit reasoning prose)"
            }
            InferenceProvider::Cohere => "Cohere v2 Chat API (key required, BILLED per-token)",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "claude_cli" | "claude" => Some(Self::ClaudeCli),
            "anthropic_api" | "anthropic" => Some(Self::AnthropicApi),
            "openai_api" | "openai" => Some(Self::OpenAi),
            "openai_compat" | "compat" => Some(Self::OpenAiCompat),
            "gemini_api" | "gemini" => Some(Self::Gemini),
            "cohere_api" | "cohere" => Some(Self::Cohere),
            "local_qwen" | "qwen" | "local" => Some(Self::LocalQwen),
            "aws_bedrock" | "bedrock" => Some(Self::AwsBedrock),
            "azure_openai" | "azure" => Some(Self::AzureOpenAi),
            "local_ouro" | "ouro" => Some(Self::LocalOuro),
            _ => None,
        }
    }

    /// Variants the v0.1 dispatcher can actually drive end-to-end. Used by
    /// the wizard to flag a stub choice with `[stub]` in the label.
    /// All variants are wired as of the D14b Phase 2c land — LocalQwen
    /// now runs candle forward-pass + sampling locally. Future variants
    /// (e.g. a new agent backend that ships only as a research note) flip
    /// back to `false` here until their adapter exists.
    ///
    /// C-3 + C-4 Phase 2 (Session 14): both `AwsBedrock` and
    /// `AzureOpenAi` are now real adapters. Every variant ships a
    /// working dispatch path. This test pins the contract so adding
    /// a stub variant in the future re-triggers the wizard's
    /// `[stub]` labelling.
    pub fn is_implemented(self) -> bool {
        // Every variant is wired as of Session 14. Add `false` arms
        // for future stub-only variants when they land.
        true
    }

    /// Bridge to the single-mode `ProviderKind` enum used by
    /// `providers::from_config`. Returns the matching variant so
    /// `from_config_for_role` can reuse the same adapter-construction
    /// logic without duplicating wiring per role.
    ///
    /// PF-02 — `AnthropicApi` now maps to its OWN `ProviderKind::AnthropicApi`
    /// (the native key-based Messages adapter), no longer collapsing to
    /// `ClaudeCli`. Operators wanting Anthropic-direct via an API key get a
    /// real adapter instead of being forced through the `claude` CLI or an
    /// OpenAI-compat shim.
    pub fn to_provider_kind(self) -> crate::cli::init::ProviderKind {
        use crate::cli::init::ProviderKind;
        match self {
            InferenceProvider::ClaudeCli => ProviderKind::ClaudeCli,
            InferenceProvider::AnthropicApi => ProviderKind::AnthropicApi,
            InferenceProvider::OpenAi => ProviderKind::OpenaiApi,
            InferenceProvider::OpenAiCompat => ProviderKind::OpenaiCompat,
            InferenceProvider::Gemini => ProviderKind::GeminiApi,
            InferenceProvider::LocalQwen => ProviderKind::LocalQwen,
            InferenceProvider::AwsBedrock => ProviderKind::AwsBedrock,
            InferenceProvider::AzureOpenAi => ProviderKind::AzureOpenAi,
            InferenceProvider::LocalOuro => ProviderKind::LocalOuro,
            InferenceProvider::Cohere => ProviderKind::Cohere,
        }
    }
}

/// One hemisphere's provider binding. Reuses the existing single-provider
/// schema fields — operator never sees a new credentials format.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HemisphereSlot {
    #[serde(default)]
    pub provider: Option<InferenceProvider>,
    #[serde(default)]
    pub model: Option<String>,
    /// API key when the provider needs one. Stored as `SecretString` so
    /// mlock + zeroize apply, same as the single-provider path.
    #[serde(default)]
    pub key: Option<SecretString>,
    /// Endpoint when the provider is OpenAI-compatible.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// C-3 Phase 2 (Session 14) — AWS region for `aws_bedrock` adapter.
    /// Examples: `us-east-1`, `eu-central-1`, `ap-northeast-1`. The
    /// adapter validates that the configured region matches the
    /// `bedrock-runtime.<region>.amazonaws.com` hostname at signing
    /// time. Ignored by non-AWS providers. None → adapter falls back
    /// to `FreedomConfig::provider_region`, then to `"us-east-1"`.
    #[serde(default)]
    pub region: Option<String>,
    /// C-4 Phase 2 (Session 14) — Azure OpenAI `api-version` query
    /// parameter override per hemisphere slot. None → falls back to
    /// `FreedomConfig::provider_api_version`, then to the adapter
    /// default. Ignored by non-Azure providers.
    #[serde(default)]
    pub api_version: Option<String>,
    /// GOLD-WIRE-04 — optional specialist [`CouncilVoice`] for this
    /// hemisphere. When set, the hemisphere's provider adapter layers the
    /// voice's `system_prompt_fragment()` onto the **system** prompt at the
    /// leaf LLM call (after operator/persona/skill system content), so e.g.
    /// the Left brain reasons as a `SecurityEngineer`. None → no voice
    /// framing. Resolved per recursion tier via `slot_for_sub`, so inner
    /// councils carry their own role's voice without leaking the parent's.
    #[serde(default)]
    pub voice: Option<crate::council::types::CouncilVoice>,
}

/// Top-level inference topology. v0.1 wizard fills `default_slot` only —
/// `hemispheres.left/right/cerebellum` come online once the brain router
/// (R-9+) actually consults them.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InferenceTopology {
    /// `single` (default, all three slots share `default_slot`) or
    /// `triplet` (same provider on all three but separate keys/models
    /// allowed) or `custom` (per-slot configuration).
    #[serde(default)]
    pub mode: TopologyMode,
    /// Operator override for the candle accelerator. `None` = use detected.
    /// Stored as snake_case string so the YAML stays readable: `cuda`,
    /// `metal`, `openvino`, `cpu`.
    #[serde(default)]
    pub accelerator_override: Option<String>,
    /// Where embeddings are computed. Independent of chat provider —
    /// operator might want OpenAI for chat but local Qwen for embeddings.
    #[serde(default)]
    pub embedding_provider: Option<InferenceProvider>,
    /// V10-07 H3 privacy posture: which provider runs the profile-
    /// extraction LLM call (`profile/runner.rs::run_pipeline` stage 3).
    /// The extractor sees the operator's full conversation window — the
    /// most private surface in the daemon. Defaulting this to
    /// `local_qwen` keeps that text on-device.
    ///
    /// Resolution order at call time:
    ///   1. `profile_provider` here, if set.
    ///   2. `embedding_provider` (already local-by-default per the same
    ///      privacy logic), if set.
    ///   3. `LocalQwen` as the hard fallback.
    ///
    /// Operators on hardware without local inference (no GPU + no
    /// CPU budget for Qwen3-4B) can explicitly set this to a cloud
    /// provider; `profile/runner.rs` fires a fire-once WARN in that
    /// case so the privacy posture stays auditable.
    #[serde(default)]
    pub profile_provider: Option<InferenceProvider>,
    /// GOLD-ADOPT-21 — fast/cheap "utility" provider for low-stakes internal
    /// LLM calls (dreaming theme labels, email threat tiebreak, scheduled cron
    /// jobs, regression re-query). When set, `providers::from_config_for_utility`
    /// routes those calls to this provider at its `ModelRole::Fast` model id
    /// (Haiku / GPT-4o-mini / Gemini Flash-lite) instead of the operator's main
    /// (flagship) provider — so the cheap calls stay cheap.
    ///
    /// `None` (default) = NO routing change: utility calls fall through to the
    /// main provider exactly as before (no regression, no surprise dependency
    /// on a local model the operator hasn't set up). Operators opt into the
    /// cost saving by naming a provider here, e.g. `utility_provider: gemini_api`
    /// or `local_qwen`.
    #[serde(default)]
    pub utility_provider: Option<InferenceProvider>,
    /// Per-completion maximum new token budget for local inference.
    /// `None` → adapter default (256 — fits ChatML reply within ~1 KiB
    /// for most operator queries). Operators wanting longer outputs
    /// (profile-extraction JSON, structured agent responses) raise this
    /// in `freedom.yaml`. Hard upper bound enforced at adapter level so
    /// a misconfigured 99999 cannot exhaust RAM / latency budget.
    #[serde(default)]
    pub max_new_tokens: Option<u32>,
    /// Ouro O-5a (Session 22): post-load weight quantisation mode for
    /// `LocalOuroAdapter`. Default `None` (load native BF16/F32 from
    /// safetensors). `Q8` is the operator opt-in for ~50% peak-memory
    /// reduction at the cost of ~30-60 s extra cold-start; O-5a wires
    /// the knob, O-5b ships the QTensor forward-pass swap (until then
    /// `Q8` falls through to `None` with a tracing-warn).
    #[serde(default)]
    pub ouro_quant_mode: crate::providers::ouro::model::OuroQuantMode,
    /// Fallback slot used when `mode = single` or when a hemisphere is
    /// not explicitly configured.
    #[serde(default)]
    pub default_slot: HemisphereSlot,
    /// Per-hemisphere overrides (only consulted when `mode = custom` or
    /// `triplet`).
    #[serde(default)]
    pub left: HemisphereSlot,
    #[serde(default)]
    pub right: HemisphereSlot,
    #[serde(default)]
    pub cerebellum: HemisphereSlot,
    /// E-1 (Session 13) — recursion cap for "fraktale Dimensionen" of
    /// hemispheres. Default `1` means "one outer council, no inner
    /// councils" — equivalent to the v0.1 flat dispatch. `0` is
    /// equivalent (no recursion). `2` enables one level of inner
    /// council on hard sub-questions (each Left/Right/Cerebellum
    /// hemisphere can itself convene a 3-hemisphere debate before
    /// returning). Capped at 4 on deserialise — deeper trees blow
    /// the token budget faster than they add value. Actual recursion
    /// wiring lands in E-2; today this field is type-scaffold only
    /// (read by `run_one` for future use).
    #[serde(default)]
    pub hemisphere_council_depth: HemisphereCouncilDepth,

    /// E-2 Phase 3 (Session 14) — per-outer-role sub-slot overrides
    /// that make recursive councils deliver actual value. Without
    /// these, the Phase 2 recursion mechanic just rebuilds the same
    /// outer-level providers at every inner level — operator pays 3×
    /// the tokens for the same answer.
    ///
    /// Schema (YAML):
    ///
    /// ```yaml
    /// inference:
    ///   hemisphere_council_depth: 2
    ///   hemisphere_sub_slots:
    ///     left:                # outer-Left's inner triplet
    ///       left:       { provider: gemini_api,  model: gemini-3.1-pro-preview }
    ///       right:      { provider: openai_api,  model: gpt-5.5 }
    ///       cerebellum: { provider: local_qwen,  model: Qwen/Qwen2.5-3B-Instruct }
    ///     right:               # outer-Right's inner triplet
    ///       left:       { provider: claude_cli, model: claude-opus-4-7 }
    ///       right:      { provider: aws_bedrock, model: anthropic.claude-opus-4-7 }
    ///       cerebellum: { provider: local_qwen, model: Qwen/Qwen2.5-3B-Instruct }
    /// ```
    ///
    /// Resolution rules:
    ///   - Lookup `hemisphere_sub_slots[outer_role][inner_role]`.
    ///   - When the sub-slot has a provider set, use it.
    ///   - Otherwise fall back to `slot_for(inner_role)` (Phase 2
    ///     behaviour — reuse the outer slot).
    ///
    /// Cost note: even with sub-slots configured, each recursion
    /// level still multiplies LLM calls by 3 (see
    /// `MAX_HEMISPHERE_COUNCIL_DEPTH`). Operator pays the bill.
    /// Phase 3 only changes WHICH providers fire, not how many.
    #[serde(default)]
    pub hemisphere_sub_slots: BTreeMap<HemisphereRole, SubHemisphereSlots>,
}

/// E-2 Phase 3 (Session 14) — one outer-role's inner-council triple.
/// Keyed by inner hemisphere role. Each slot defaults to empty;
/// missing fields fall back to the outer-level slot for that role.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SubHemisphereSlots {
    /// Inner-Left binding when this is the parent outer-hemisphere.
    #[serde(default)]
    pub left: HemisphereSlot,
    /// Inner-Right binding.
    #[serde(default)]
    pub right: HemisphereSlot,
    /// Inner-Cerebellum binding.
    #[serde(default)]
    pub cerebellum: HemisphereSlot,
}

impl SubHemisphereSlots {
    /// Resolve the inner slot for a specific inner-role. Returns the
    /// configured slot regardless of whether it carries a `provider`
    /// — callers decide whether to use it or fall back via
    /// [`InferenceTopology::slot_for_sub`].
    pub fn slot_for(&self, inner_role: HemisphereRole) -> &HemisphereSlot {
        match inner_role {
            HemisphereRole::Left => &self.left,
            HemisphereRole::Right => &self.right,
            HemisphereRole::Cerebellum => &self.cerebellum,
        }
    }
}

/// E-1 (Session 13) newtype around the recursion-depth byte so the
/// type system enforces the [0..=MAX_HEMISPHERE_COUNCIL_DEPTH] bound at
/// every construction site. Default `1` matches the v0.1 flat
/// dispatch (one outer council, no inner ones). Serde derive treats
/// the newtype as a transparent integer in YAML, so freedom.yaml
/// stays readable: `hemisphere_council_depth: 2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HemisphereCouncilDepth(u8);

/// Hard upper bound for `HemisphereCouncilDepth`. Beyond this an
/// operator's freedom.yaml is clamped at deserialise time + a warn-log
/// surfaces what happened. Picked so a worst-case 3^4 = 81 hemisphere
/// invocations per prompt still stays under typical free-tier daily
/// quotas with room to spare; deeper trees deliver diminishing returns
/// vs token cost.
pub const MAX_HEMISPHERE_COUNCIL_DEPTH: u8 = 4;

impl HemisphereCouncilDepth {
    /// Construct after clamping to `[0..=MAX_HEMISPHERE_COUNCIL_DEPTH]`.
    /// Returns the clamped value + a bool indicating whether clamping
    /// happened (caller logs a warn line so the operator's freedom.yaml
    /// edit doesn't silently land below their intent).
    pub fn new_clamped(raw: u8) -> (Self, bool) {
        if raw > MAX_HEMISPHERE_COUNCIL_DEPTH {
            (Self(MAX_HEMISPHERE_COUNCIL_DEPTH), true)
        } else {
            (Self(raw), false)
        }
    }

    pub fn get(self) -> u8 {
        self.0
    }

    /// True when recursion is disabled — outer council fires once, no
    /// hemisphere may spawn an inner council. v0.1 default.
    pub fn is_flat(self) -> bool {
        self.0 <= 1
    }

    // GOLD-HON-13 / GR-031 — `estimated_invocations()` + `cost_warning()` were
    // removed as dead code (only their own unit tests called them). The LIVE
    // operator-facing cost warning is `cli::init::render_council_depth_cost_warning`
    // (used by the wizard step + `neoth serve`, with its own test suite); these
    // were a divergent, never-wired second copy. Re-add a typed accessor here
    // only WITH a real consumer.
}

impl Default for HemisphereCouncilDepth {
    /// Default `1` — outer council fires, inner councils never do.
    /// Matches the v0.1 flat dispatch behaviour exactly.
    fn default() -> Self {
        Self(1)
    }
}

impl<'de> Deserialize<'de> for HemisphereCouncilDepth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = u8::deserialize(deserializer)?;
        let (clamped, was_clamped) = Self::new_clamped(raw);
        if was_clamped {
            tracing::warn!(
                requested = raw,
                clamped_to = MAX_HEMISPHERE_COUNCIL_DEPTH,
                "freedom.yaml `hemisphere_council_depth` exceeds hard cap; clamped"
            );
        }
        Ok(clamped)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyMode {
    #[default]
    Single,
    Triplet,
    Custom,
}

/// Pick #8 SP-2 (Session 14) — council winner-selection mode.
///
/// Operator chooses how the chat dispatcher picks the response to
/// return when 3 hemispheres have spoken:
///
///   - **LegacyMajority** (default) — v0.1 behaviour. The Verdict's
///     `Consensus.winning_text` wins; Split routes to callosum;
///     QuorumFailed surfaces the synth-failure as an error.
///   - **ConsensusOrBest** — On Consensus, use `winning_text`. On
///     Split, fall back to `CouncilDebate::best_response()` keyed
///     by `QualityScore`. Mid-risk: preserves consensus semantics
///     but eliminates the Split→callosum 4th-call latency.
///   - **BestAlways** — Always use `best_response()`, regardless of
///     verdict. The smartest hemisphere wins by quality score even
///     when all three agreed. Maximally role-agnostic, but loses
///     the consensus signal in WAL audit.
///
/// Default stays `LegacyMajority` until v0.3 stability evidence
/// proves score reliability across ≥200 real council runs.
/// Operator opts in via `freedom.yaml::council.selection_mode:
/// consensus_or_best`. (Hard rule from Pick #8 fractal synthesis.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    /// v0.1 majority dispatch — Verdict drives selection.
    #[default]
    LegacyMajority,
    /// Consensus wins when present; else quality-score best_response.
    ConsensusOrBest,
    /// Always pick quality-score best, ignore verdict.
    BestAlways,
}

/// Pick #8 SP-2 (Session 14) — council-specific operator config.
///
/// Lives at `freedom.yaml::council` (top-level under `FreedomConfig`,
/// not inside `inference`) because:
///   - It controls dispatch behaviour, not topology
///   - The cost-cap fields (`max_calls_per_user_message`,
///     `daily_usd_cap`) want a stable home that survives topology
///     reconfigs
///   - Mirrors the `MemoryRoutingConfig` / `SelfReflectConfig`
///     patterns the code-architect verdict proposed
///
/// Every field carries `#[serde(default)]` so older configs round-
/// trip cleanly. The defaults preserve Session-14-and-prior
/// behaviour exactly — operators must explicitly opt in to each
/// new feature to see any change.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CouncilConfig {
    /// Winner-selection strategy. See [`SelectionMode`].
    #[serde(default)]
    pub selection_mode: SelectionMode,

    /// Hard cap on LLM calls a single user message can trigger,
    /// shared across the entire recursion tree via `BudgetToken`.
    /// `None` → use [`DEFAULT_MAX_CALLS_PER_USER_MESSAGE`].
    ///
    /// At depth=2 council (3 outer × 3 inner = 9 leaves) + outer
    /// aggregation, baseline is ~12 calls; 15 leaves 3 for self-
    /// reflect / judge / contingency. Depth=3 (27 leaves) cannot
    /// fit in 15 — `BudgetToken::charge` returns
    /// `BudgetExhausted` at leaf 15 and the partial result is
    /// surfaced (same shape as a timeout).
    #[serde(default)]
    pub max_calls_per_user_message: Option<u32>,

    /// Daily USD budget cap. `None` disables the budget check.
    /// Enforced via `DailyBudget::charge()` immediately before
    /// every outbound LLM call. Counter persists at
    /// `~/.neoth/budget/daily.json`, keyed by UTC date, lazily
    /// reset on first call after midnight.
    #[serde(default)]
    pub daily_usd_cap: Option<f32>,

    /// Maximum concurrent background LLM connections. `None` →
    /// use [`DEFAULT_MAX_BACKGROUND_CONNECTIONS`]. Foreground
    /// (user-visible) reqwest::Client is unbounded; only
    /// prefetch + self-reflect + judge share this semaphore.
    #[serde(default)]
    pub max_background_connections: Option<u32>,

    /// Self-reflect: only fires when the winning hemisphere's
    /// composite `QualityScore::total` is BELOW this threshold.
    /// `None` → use [`DEFAULT_REFINE_THRESHOLD`]. Higher values
    /// trigger refinement more often (less confident); lower
    /// values save tokens.
    #[serde(default)]
    pub refine_threshold: Option<f32>,

    /// Master kill-switch for self-reflect. When `false`, the
    /// threshold gate never evaluates. When `true`, refinement
    /// fires only when score is below the threshold AND the
    /// recursion depth is 0 (the F3 fractal rule). Default `false`
    /// — opt-in.
    #[serde(default)]
    pub self_reflect_enabled: bool,

    /// GOLD-ADAPT-LOWKEY-07 — transparent-core debug mode. When `true`,
    /// every council debate prints a Layer-B reasoning surface to STDERR
    /// (verdict, dissent, per-hemisphere provider/score/latency/refusal,
    /// what was injected, the winner) in addition to the Layer-A answer.
    /// Default `false` — opt-in; `NEOTH_COUNCIL_DEBUG=1` is a per-run
    /// override that does not need a config edit.
    #[serde(default)]
    pub transparent_core: bool,

    /// GOLD-ADAPT-LOWKEY-04 — MIF motive pre-step. When `true`, the
    /// council classifies operator intent BEFORE the hemisphere fan-out;
    /// a `Conflicted` prompt (contradictory goals) is NOT debated — a
    /// disambiguation request is surfaced instead. Default `false` —
    /// opt-in, because the classifier is conservative but a
    /// false-`Conflicted` would block a valid answer.
    #[serde(default)]
    pub mif_enabled: bool,

    /// Weight multiplier on cross-outer dissent score for the
    /// `QualityScore.diversity_bonus` component. `None` → use
    /// [`DEFAULT_DIVERSITY_BONUS_WEIGHT`]. Operator-tunable so a
    /// council that consistently agrees doesn't lose all
    /// diversity signal.
    #[serde(default)]
    pub diversity_bonus_weight: Option<f32>,

    /// Hard cap on `hemisphere_council_depth`. Stronger than the
    /// `MAX_HEMISPHERE_COUNCIL_DEPTH` const because operators
    /// who explicitly raise depth above 2 should also raise the
    /// budget cap — this field guards against unintentional 3^4
    /// = 81 leaf calls. `None` → defaults to 2.
    #[serde(default)]
    pub max_recursion_depth: Option<u8>,

    /// SPEC-03 suppress switch. When `Some(true)`, the council
    /// smart-trigger is hard-disabled — `council::should_convene` is
    /// bypassed and every turn takes the single-hemisphere path
    /// regardless of dissent markers. `None` / `Some(false)` → normal
    /// smart-trigger behaviour. This is the PERSISTENT twin of the
    /// `NEOTH_COUNCIL_DISABLE=1` env override; set it via
    /// `neoth council suppress` and clear it with
    /// `neoth council suppress --off`. The env override still wins when
    /// both are present.
    #[serde(default)]
    pub disabled: Option<bool>,

    /// KF-01 full — persist each hemisphere's VERBATIM response text as a
    /// `0x66 COUNCIL_TRANSCRIPT` WAL frame at debate time, so
    /// `neoth council replay <prompt_hash>` can show the actual prose, not
    /// just the hashed metadata the other council frames carry. DEFAULT
    /// OFF: hemisphere prose is sensitive (it may quote the operator's
    /// memory / the model's full reasoning), so durability-over-privacy is
    /// an explicit operator choice — the same posture as PROVIDER_RESPONSE
    /// hashing the reply by default. When `true`, transcripts land in the
    /// audit chain and are visible to anyone who can read the WAL.
    #[serde(default)]
    pub persist_transcripts: bool,

    /// SPEC-03b — smart-trigger THRESHOLD config surface. Operator overrides
    /// for the four `council::TriggerPolicy` gate knobs (+ extra dissent
    /// markers). Every field is optional and defaults to the built-in
    /// `TriggerPolicy::default()`, so an absent / empty `trigger` block
    /// reproduces the prior hardcoded behaviour EXACTLY. Surfaced under
    /// `freedom.yaml::council.trigger`.
    #[serde(default)]
    pub trigger: CouncilTriggerConfig,
}

/// SPEC-03b operator override surface for the council smart-trigger gates.
/// Maps 1:1 onto the tunable `council::TriggerPolicy` fields; `None` / empty
/// means "keep the default". Lives in config (not `council/`) so it can be
/// `Deserialize`d from `freedom.yaml` without the config layer depending on
/// the trigger internals beyond the one [`Self::to_policy`] bridge.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CouncilTriggerConfig {
    /// Override `TriggerPolicy::min_complex_prompt_chars` (default 80). The
    /// minimum prompt length before the complexity gate even considers
    /// convening — raise it to suppress council on shorter prompts.
    #[serde(default)]
    pub min_complex_prompt_chars: Option<usize>,

    /// Override the rate-cooldown between consecutive convenes, in SECONDS
    /// (default 60). Raise it to space debates further apart.
    #[serde(default)]
    pub min_interval_secs: Option<u64>,

    /// Override `TriggerPolicy::budget_multiplier` (default 3.0) — council
    /// needs `single_call_cost × this` of remaining budget to fire. Raise it
    /// to make the council more budget-conservative.
    #[serde(default)]
    pub budget_multiplier: Option<f32>,

    /// Override `TriggerPolicy::convene_on_high_complexity` (default true).
    /// Set `false` for strict opt-in-only behaviour (only explicit dissent
    /// markers convene; a bare code-fence+question prompt does not).
    #[serde(default)]
    pub convene_on_high_complexity: Option<bool>,

    /// EXTRA dissent markers appended to the built-in list (lowercased on
    /// match). Empty by default. Lets an operator add domain phrases
    /// ("threat model", "migration plan", …) that should always convene.
    #[serde(default)]
    pub extra_dissent_markers: Vec<String>,
}

impl CouncilTriggerConfig {
    /// Build the effective [`crate::council::TriggerPolicy`] by overlaying
    /// these operator overrides on top of `TriggerPolicy::default()`. An
    /// all-`None` / empty config yields exactly the default policy — pinned by
    /// `council_trigger_config_default_matches_policy_default`.
    pub fn to_policy(&self) -> crate::council::TriggerPolicy {
        let mut policy = crate::council::TriggerPolicy::default();
        if let Some(chars) = self.min_complex_prompt_chars {
            policy.min_complex_prompt_chars = chars;
        }
        if let Some(secs) = self.min_interval_secs {
            policy.min_interval = std::time::Duration::from_secs(secs);
        }
        if let Some(mult) = self.budget_multiplier {
            policy.budget_multiplier = mult;
        }
        if let Some(flag) = self.convene_on_high_complexity {
            policy.convene_on_high_complexity = flag;
        }
        // Non-empty entries only — a stray "" would match every prompt.
        policy.extra_markers = self
            .extra_dissent_markers
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| !m.is_empty())
            .collect();
        policy
    }
}

/// SP-2 minimum-viable default: 15 calls per user message. Covers
/// depth=2 council (12 calls) with 3 reserved for self-reflect.
pub const DEFAULT_MAX_CALLS_PER_USER_MESSAGE: u32 = 15;

/// SP-2 minimum-viable default: 6 concurrent background LLM streams.
pub const DEFAULT_MAX_BACKGROUND_CONNECTIONS: u32 = 6;

/// SP-5 default: fire self-reflect only when composite quality score
/// is below 0.90 (winning hemisphere not confident enough).
pub const DEFAULT_REFINE_THRESHOLD: f32 = 0.90;

/// SP-1 default: 10% lift from cross-outer dissent. Matches the
/// architect's recommendation in the Pick #8 synthesis.
pub const DEFAULT_DIVERSITY_BONUS_WEIGHT: f32 = 0.10;

/// SP-2 default: cap recursion at depth=2 unless operator
/// explicitly overrides. 3^2 = 9 leaf calls is the most cost-
/// reasonable budget for an automatic council pass.
pub const DEFAULT_MAX_RECURSION_DEPTH: u8 = 2;

impl CouncilConfig {
    /// Effective `max_calls_per_user_message`, honouring operator
    /// override or falling back to [`DEFAULT_MAX_CALLS_PER_USER_MESSAGE`].
    pub fn effective_max_calls(&self) -> u32 {
        self.max_calls_per_user_message
            .unwrap_or(DEFAULT_MAX_CALLS_PER_USER_MESSAGE)
    }

    /// Effective `max_background_connections`.
    pub fn effective_max_background_connections(&self) -> u32 {
        self.max_background_connections
            .unwrap_or(DEFAULT_MAX_BACKGROUND_CONNECTIONS)
    }

    /// Effective `refine_threshold`.
    pub fn effective_refine_threshold(&self) -> f32 {
        self.refine_threshold.unwrap_or(DEFAULT_REFINE_THRESHOLD)
    }

    /// Effective `diversity_bonus_weight`.
    pub fn effective_diversity_bonus_weight(&self) -> f32 {
        self.diversity_bonus_weight
            .unwrap_or(DEFAULT_DIVERSITY_BONUS_WEIGHT)
    }

    /// Effective `max_recursion_depth`.
    pub fn effective_max_recursion_depth(&self) -> u8 {
        self.max_recursion_depth
            .unwrap_or(DEFAULT_MAX_RECURSION_DEPTH)
    }
}

impl TopologyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TopologyMode::Single => "single",
            TopologyMode::Triplet => "triplet",
            TopologyMode::Custom => "custom",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "single" => Some(Self::Single),
            "triplet" => Some(Self::Triplet),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

impl InferenceTopology {
    /// Resolve the slot for a given hemisphere role. In `single` mode all
    /// roles return `default_slot`. In `triplet`/`custom` mode the explicit
    /// per-slot config wins; absent fields fall back to `default_slot`.
    pub fn slot_for(&self, role: HemisphereRole) -> &HemisphereSlot {
        match self.mode {
            TopologyMode::Single => &self.default_slot,
            TopologyMode::Triplet | TopologyMode::Custom => match role {
                HemisphereRole::Left => slot_or_default(&self.left, &self.default_slot),
                HemisphereRole::Right => slot_or_default(&self.right, &self.default_slot),
                HemisphereRole::Cerebellum => slot_or_default(&self.cerebellum, &self.default_slot),
            },
        }
    }

    /// E-2 Phase 3 (Session 14) — resolve the slot for an INNER
    /// hemisphere when recursing under a specific OUTER role.
    ///
    /// Lookup chain:
    ///
    /// 1. `hemisphere_sub_slots[outer_role][inner_role]` — when its
    ///    `provider` is set, use it.
    /// 2. Otherwise fall back to [`Self::slot_for(inner_role)`]
    ///    (Phase 2 behaviour — reuses the outer level).
    ///
    /// This lets operators configure operationally-distinct sub-providers
    /// per outer role (e.g. "when Left recurses, ask LocalQwen, Gemini,
    /// and Bedrock"), so deep councils actually surface different
    /// reasoning angles rather than the same provider three times.
    pub fn slot_for_sub(
        &self,
        outer_role: HemisphereRole,
        inner_role: HemisphereRole,
    ) -> &HemisphereSlot {
        if let Some(sub) = self.hemisphere_sub_slots.get(&outer_role) {
            let sub_slot = sub.slot_for(inner_role);
            if sub_slot.provider.is_some() {
                return sub_slot;
            }
        }
        self.slot_for(inner_role)
    }

    /// V10-07 H3 privacy resolution. Returns the provider that should
    /// run profile extraction. Operators see the resolution chain in
    /// `neoth doctor --explain v10-07`; per-call WARN in
    /// `profile/runner.rs` surfaces the same answer at runtime.
    ///
    /// Order:
    ///   1. `profile_provider` if explicitly set.
    ///   2. `embedding_provider` if explicitly set (embeddings are
    ///      already local-by-default for the same privacy reasoning).
    ///   3. `InferenceProvider::LocalQwen` as the hard fallback -
    ///      "Gemini never sees raw conversation" per v1.0 GA blocker.
    pub fn resolved_profile_provider(&self) -> InferenceProvider {
        self.profile_provider
            .or(self.embedding_provider)
            .unwrap_or(InferenceProvider::LocalQwen)
    }
}

fn slot_or_default<'a>(
    slot: &'a HemisphereSlot,
    fallback: &'a HemisphereSlot,
) -> &'a HemisphereSlot {
    if slot.provider.is_some() {
        slot
    } else {
        fallback
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HemisphereRole {
    Left,
    Right,
    Cerebellum,
}

impl HemisphereRole {
    pub fn as_str(self) -> &'static str {
        match self {
            HemisphereRole::Left => "left",
            HemisphereRole::Right => "right",
            HemisphereRole::Cerebellum => "cerebellum",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_round_trips_through_from_str() {
        for p in [
            InferenceProvider::ClaudeCli,
            InferenceProvider::AnthropicApi,
            InferenceProvider::OpenAi,
            InferenceProvider::OpenAiCompat,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
        ] {
            assert_eq!(InferenceProvider::from_str(p.as_str()), Some(p));
        }
    }

    #[test]
    fn provider_from_str_accepts_aliases() {
        assert_eq!(
            InferenceProvider::from_str("claude"),
            Some(InferenceProvider::ClaudeCli),
        );
        assert_eq!(
            InferenceProvider::from_str("qwen"),
            Some(InferenceProvider::LocalQwen),
        );
        assert_eq!(
            InferenceProvider::from_str("local"),
            Some(InferenceProvider::LocalQwen),
        );
        assert_eq!(
            InferenceProvider::from_str("OPENAI"),
            Some(InferenceProvider::OpenAi),
        );
    }

    #[test]
    fn topology_mode_round_trips() {
        for m in [
            TopologyMode::Single,
            TopologyMode::Triplet,
            TopologyMode::Custom,
        ] {
            assert_eq!(TopologyMode::from_str(m.as_str()), Some(m));
        }
    }

    #[test]
    fn single_mode_returns_default_for_every_role() {
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Single;
        topo.default_slot.provider = Some(InferenceProvider::ClaudeCli);
        topo.left.provider = Some(InferenceProvider::OpenAi);

        assert_eq!(
            topo.slot_for(HemisphereRole::Left).provider,
            Some(InferenceProvider::ClaudeCli),
            "single mode must ignore per-slot configs",
        );
        assert_eq!(
            topo.slot_for(HemisphereRole::Right).provider,
            Some(InferenceProvider::ClaudeCli),
        );
        assert_eq!(
            topo.slot_for(HemisphereRole::Cerebellum).provider,
            Some(InferenceProvider::ClaudeCli),
        );
    }

    #[test]
    fn custom_mode_uses_per_slot_with_default_fallback() {
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.default_slot.provider = Some(InferenceProvider::ClaudeCli);
        topo.left.provider = Some(InferenceProvider::OpenAi);
        topo.right.provider = Some(InferenceProvider::Gemini);
        // cerebellum left blank → falls back to default_slot

        assert_eq!(
            topo.slot_for(HemisphereRole::Left).provider,
            Some(InferenceProvider::OpenAi),
        );
        assert_eq!(
            topo.slot_for(HemisphereRole::Right).provider,
            Some(InferenceProvider::Gemini),
        );
        assert_eq!(
            topo.slot_for(HemisphereRole::Cerebellum).provider,
            Some(InferenceProvider::ClaudeCli),
            "blank slot falls back to default",
        );
    }

    #[test]
    fn unimplemented_providers_are_flagged() {
        // All variants implemented as of D14b Phase 2c. Test pins the
        // contract so adding a stub variant in the future re-triggers
        // the wizard's `[stub]` labelling path.
        // C-3 + C-4 Phase 2 (Session 14): both AwsBedrock and
        // AzureOpenAi flipped to implemented. No more stubs.
        // Pick #11 Phase A (Session 14): Hermes + OpenClaw removed —
        // they were competitor gateway systems, not LLM providers.
        assert!(InferenceProvider::LocalQwen.is_implemented());
        assert!(InferenceProvider::ClaudeCli.is_implemented());
        assert!(InferenceProvider::OpenAi.is_implemented());
        assert!(InferenceProvider::AwsBedrock.is_implemented());
        assert!(InferenceProvider::AzureOpenAi.is_implemented());
    }

    /// C-3 Phase 2 (Session 14) — pin the round-trip for the new
    /// AwsBedrock variant. Earlier session shipped the variant but
    /// the test loop was not extended; now that the adapter is real,
    /// from_str/as_str must round-trip cleanly so freedom.yaml can
    /// persist + reload it without surprises.
    #[test]
    fn aws_bedrock_round_trips_through_from_str() {
        assert_eq!(
            InferenceProvider::from_str("aws_bedrock"),
            Some(InferenceProvider::AwsBedrock),
        );
        assert_eq!(
            InferenceProvider::from_str("bedrock"),
            Some(InferenceProvider::AwsBedrock),
        );
        assert_eq!(InferenceProvider::AwsBedrock.as_str(), "aws_bedrock");
    }

    #[test]
    fn hemisphere_slot_region_field_round_trips() {
        let yaml = r#"
provider: aws_bedrock
model: anthropic.claude-3-5-sonnet-20241022-v2:0
region: eu-central-1
"#;
        let slot: HemisphereSlot = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(slot.region.as_deref(), Some("eu-central-1"));
    }

    #[test]
    fn hemisphere_mode_single_routes_all_calls_to_one_provider() {
        // GOLD-FEAT-01a: in single mode every role resolves to `default_slot` —
        // the distinct per-role left/right/cerebellum providers are ignored.
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Single;
        topo.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        topo.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        topo.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            ..Default::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        for role in [
            HemisphereRole::Left,
            HemisphereRole::Right,
            HemisphereRole::Cerebellum,
        ] {
            assert_eq!(
                topo.slot_for(role).provider,
                Some(InferenceProvider::LocalQwen),
                "single mode must route {role:?} to default_slot, ignoring its per-role override",
            );
        }
    }

    // ── E-2 Phase 3 (Session 14) sub-slot resolution ────────────────

    #[test]
    fn slot_for_sub_falls_back_to_outer_when_no_sub_slots_configured() {
        // With NO hemisphere_sub_slots configured, sub-slot lookup
        // must return the outer-level slot for the inner role —
        // exact Phase 2 behaviour, no regression.
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        topo.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            ..Default::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };

        // Outer-Left recurses → inner-Left should resolve to outer-Left
        // (ClaudeCli), inner-Right to outer-Right (Gemini), etc.
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Left)
                .provider,
            Some(InferenceProvider::ClaudeCli)
        );
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Right)
                .provider,
            Some(InferenceProvider::Gemini)
        );
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Cerebellum)
                .provider,
            Some(InferenceProvider::LocalQwen)
        );
    }

    #[test]
    fn slot_for_sub_consults_sub_slots_when_configured() {
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        topo.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            ..Default::default()
        };
        // Sub-slots: when outer-Left recurses, its inner triplet is
        // entirely different providers from the outer level.
        let mut sub = SubHemisphereSlots::default();
        sub.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        };
        sub.right = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            ..Default::default()
        };
        sub.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::AzureOpenAi),
            ..Default::default()
        };
        topo.hemisphere_sub_slots.insert(HemisphereRole::Left, sub);

        // Outer-Left's inner triplet → uses sub-slots
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Left)
                .provider,
            Some(InferenceProvider::OpenAi)
        );
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Right)
                .provider,
            Some(InferenceProvider::AwsBedrock)
        );
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Cerebellum)
                .provider,
            Some(InferenceProvider::AzureOpenAi)
        );

        // Outer-Right has NO sub-slots → falls back to outer-level.
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Right, HemisphereRole::Left)
                .provider,
            Some(InferenceProvider::ClaudeCli),
            "outer-Right has no sub-slots; fall back to outer-Left binding"
        );
    }

    #[test]
    fn slot_for_sub_falls_back_when_sub_slot_provider_is_none() {
        // Sub-slots present for outer-Left, but the inner-Right
        // sub-slot itself has no provider → must fall back to the
        // outer-level slot for the inner role.
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            ..Default::default()
        };
        let mut sub = SubHemisphereSlots::default();
        sub.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        };
        // sub.right intentionally left empty → fall through expected.
        topo.hemisphere_sub_slots.insert(HemisphereRole::Left, sub);

        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Left)
                .provider,
            Some(InferenceProvider::OpenAi),
            "inner-Left has explicit sub-slot"
        );
        assert_eq!(
            topo.slot_for_sub(HemisphereRole::Left, HemisphereRole::Right)
                .provider,
            Some(InferenceProvider::Gemini),
            "inner-Right sub-slot empty → falls back to outer-Right (Gemini)"
        );
    }

    #[test]
    fn sub_hemisphere_slots_round_trip_through_yaml() {
        // Provider names use the serde rename_all = "snake_case" form
        // (`open_ai`, not `openai`). The `InferenceProvider::from_str`
        // aliases (`openai`, `gemini`) only resolve through the CLI
        // parser, not direct YAML deserialization.
        let yaml = r#"
mode: custom
left:
  provider: claude_cli
right:
  provider: gemini
cerebellum:
  provider: local_qwen
hemisphere_sub_slots:
  left:
    left:
      provider: open_ai
      model: gpt-5.5
    right:
      provider: gemini
      model: gemini-3.1-pro-preview
    cerebellum:
      provider: local_qwen
      model: Qwen/Qwen2.5-3B-Instruct
"#;
        let topo: InferenceTopology = serde_yaml::from_str(yaml).unwrap();
        let sub = topo
            .hemisphere_sub_slots
            .get(&HemisphereRole::Left)
            .expect("outer-Left sub-slots must round-trip");
        assert_eq!(
            sub.slot_for(HemisphereRole::Left).provider,
            Some(InferenceProvider::OpenAi)
        );
        assert_eq!(
            sub.slot_for(HemisphereRole::Left).model.as_deref(),
            Some("gpt-5.5")
        );
        assert_eq!(
            sub.slot_for(HemisphereRole::Right).provider,
            Some(InferenceProvider::Gemini)
        );
    }

    #[test]
    fn hemisphere_sub_slots_field_defaults_empty_for_older_configs() {
        // freedom.yaml files predating E-2 Phase 3 must round-trip
        // cleanly — the new field is `#[serde(default)]`.
        let yaml = r#"
mode: custom
left:
  provider: claude_cli
"#;
        let topo: InferenceTopology = serde_yaml::from_str(yaml).unwrap();
        assert!(topo.hemisphere_sub_slots.is_empty());
    }

    // ── Pick #8 SP-2 (Session 14) CouncilConfig schema ─────────────

    #[test]
    fn selection_mode_default_is_legacy_majority() {
        // Hard rule from fractal synthesis: default stays LegacyMajority
        // until v0.3 stability evidence proves score reliability.
        let mode = SelectionMode::default();
        assert!(matches!(mode, SelectionMode::LegacyMajority));
    }

    #[test]
    fn selection_mode_round_trips_through_yaml() {
        for variant in [
            SelectionMode::LegacyMajority,
            SelectionMode::ConsensusOrBest,
            SelectionMode::BestAlways,
        ] {
            let s = serde_yaml::to_string(&variant).unwrap();
            let parsed: SelectionMode = serde_yaml::from_str(&s).unwrap();
            assert_eq!(variant, parsed, "round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn council_config_defaults_preserve_session14_behaviour() {
        let cfg = CouncilConfig::default();
        // Every new feature must default to "no effect" to keep the
        // existing 1787 tests passing without modification.
        assert!(matches!(cfg.selection_mode, SelectionMode::LegacyMajority));
        assert_eq!(cfg.max_calls_per_user_message, None);
        assert_eq!(cfg.daily_usd_cap, None);
        assert_eq!(cfg.refine_threshold, None);
        assert!(!cfg.self_reflect_enabled);
        assert_eq!(cfg.diversity_bonus_weight, None);
        assert_eq!(cfg.max_recursion_depth, None);
        // KF-01 full: transcript persistence is OPT-IN — default OFF so
        // hemisphere prose is NOT written to the WAL unless the operator
        // explicitly chooses durability over privacy.
        assert!(
            !cfg.persist_transcripts,
            "persist_transcripts MUST default to false (privacy-first opt-in)"
        );
    }

    #[test]
    fn council_config_effective_falls_back_to_defaults() {
        let cfg = CouncilConfig::default();
        assert_eq!(
            cfg.effective_max_calls(),
            DEFAULT_MAX_CALLS_PER_USER_MESSAGE
        );
        assert_eq!(
            cfg.effective_max_background_connections(),
            DEFAULT_MAX_BACKGROUND_CONNECTIONS
        );
        assert!((cfg.effective_refine_threshold() - DEFAULT_REFINE_THRESHOLD).abs() < 1e-6);
        assert!(
            (cfg.effective_diversity_bonus_weight() - DEFAULT_DIVERSITY_BONUS_WEIGHT).abs() < 1e-6
        );
        assert_eq!(
            cfg.effective_max_recursion_depth(),
            DEFAULT_MAX_RECURSION_DEPTH
        );
    }

    #[test]
    fn council_config_operator_overrides_honoured() {
        let cfg = CouncilConfig {
            max_calls_per_user_message: Some(20),
            daily_usd_cap: Some(10.0),
            max_background_connections: Some(8),
            refine_threshold: Some(0.75),
            diversity_bonus_weight: Some(0.15),
            max_recursion_depth: Some(3),
            ..Default::default()
        };
        assert_eq!(cfg.effective_max_calls(), 20);
        assert_eq!(cfg.daily_usd_cap, Some(10.0));
        assert_eq!(cfg.effective_max_background_connections(), 8);
        assert!((cfg.effective_refine_threshold() - 0.75).abs() < 1e-6);
        assert!((cfg.effective_diversity_bonus_weight() - 0.15).abs() < 1e-6);
        assert_eq!(cfg.effective_max_recursion_depth(), 3);
    }

    #[test]
    fn council_config_round_trips_through_yaml() {
        let yaml = r#"
selection_mode: consensus_or_best
max_calls_per_user_message: 15
daily_usd_cap: 5.0
refine_threshold: 0.9
self_reflect_enabled: true
diversity_bonus_weight: 0.1
max_recursion_depth: 2
"#;
        let cfg: CouncilConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(cfg.selection_mode, SelectionMode::ConsensusOrBest));
        assert_eq!(cfg.max_calls_per_user_message, Some(15));
        assert_eq!(cfg.daily_usd_cap, Some(5.0));
        assert!(cfg.self_reflect_enabled);
        assert_eq!(cfg.max_recursion_depth, Some(2));
    }

    #[test]
    fn council_config_defaults_when_field_missing_from_yaml() {
        // Older freedom.yaml files predating Pick #8 must round-trip
        // cleanly with every new field at its safe default.
        let yaml = "";
        let cfg: CouncilConfig = serde_yaml::from_str(yaml).unwrap_or_default();
        assert!(matches!(cfg.selection_mode, SelectionMode::LegacyMajority));
    }

    #[test]
    fn hemisphere_slot_region_defaults_to_none_for_older_configs() {
        // freedom.yaml files predating C-3 Phase 2 (Session 14) must
        // round-trip cleanly — the new field is `#[serde(default)]`.
        // `claude_cli` happens to be the snake_case wire form for both
        // legacy + current schema; use it as a pre-Phase-2 fixture.
        let yaml = r#"
provider: claude_cli
model: claude-opus-4-7
"#;
        let slot: HemisphereSlot = serde_yaml::from_str(yaml).unwrap();
        assert!(slot.region.is_none());
        assert_eq!(slot.provider, Some(InferenceProvider::ClaudeCli));
    }

    #[test]
    fn description_is_one_line_per_variant() {
        for p in [
            InferenceProvider::ClaudeCli,
            InferenceProvider::AnthropicApi,
            InferenceProvider::OpenAi,
            InferenceProvider::OpenAiCompat,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
            InferenceProvider::AwsBedrock,
            InferenceProvider::AzureOpenAi,
        ] {
            let d = p.description();
            assert!(!d.is_empty());
            assert!(!d.contains('\n'));
        }
    }

    // ── E-1 (Session 13) HemisphereCouncilDepth newtype ──────────────

    #[test]
    fn council_depth_default_is_one() {
        // Default matches v0.1 flat dispatch (one outer council, no inner).
        assert_eq!(HemisphereCouncilDepth::default().get(), 1);
        assert!(HemisphereCouncilDepth::default().is_flat());
    }

    #[test]
    fn council_depth_is_flat_below_two() {
        assert!(HemisphereCouncilDepth::new_clamped(0).0.is_flat());
        assert!(HemisphereCouncilDepth::new_clamped(1).0.is_flat());
        assert!(!HemisphereCouncilDepth::new_clamped(2).0.is_flat());
        assert!(!HemisphereCouncilDepth::new_clamped(3).0.is_flat());
    }

    // GOLD-HON-13 / GR-031 — the cost_warning()/estimated_invocations() test was
    // removed with the dead fns; the live cost warning is covered by
    // cli::init's render_council_depth_cost_warning test suite.

    #[test]
    fn council_depth_new_clamped_passes_values_in_range() {
        for raw in 0..=MAX_HEMISPHERE_COUNCIL_DEPTH {
            let (d, clamped) = HemisphereCouncilDepth::new_clamped(raw);
            assert_eq!(d.get(), raw, "depth {raw} should pass through");
            assert!(!clamped, "depth {raw} should not be clamped");
        }
    }

    #[test]
    fn council_depth_new_clamped_caps_above_max() {
        let (d, clamped) = HemisphereCouncilDepth::new_clamped(MAX_HEMISPHERE_COUNCIL_DEPTH + 1);
        assert_eq!(d.get(), MAX_HEMISPHERE_COUNCIL_DEPTH);
        assert!(clamped);

        let (d, clamped) = HemisphereCouncilDepth::new_clamped(u8::MAX);
        assert_eq!(d.get(), MAX_HEMISPHERE_COUNCIL_DEPTH);
        assert!(clamped);
    }

    #[test]
    fn council_depth_deserialises_from_yaml_integer() {
        let yaml = "hemisphere_council_depth: 3\n";
        let topo: InferenceTopology = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(topo.hemisphere_council_depth.get(), 3);
    }

    #[test]
    fn council_depth_deserialise_clamps_out_of_range() {
        let yaml = "hemisphere_council_depth: 99\n";
        let topo: InferenceTopology = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            topo.hemisphere_council_depth.get(),
            MAX_HEMISPHERE_COUNCIL_DEPTH
        );
    }

    #[test]
    fn council_depth_default_when_field_missing() {
        // Existing freedom.yaml files predate E-1; the field defaults
        // to 1 (flat dispatch) so older configs keep behaviour exactly.
        let yaml = "mode: single\n";
        let topo: InferenceTopology = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(topo.hemisphere_council_depth.get(), 1);
    }

    #[test]
    fn council_depth_serialises_as_transparent_integer() {
        let topo = InferenceTopology {
            hemisphere_council_depth: HemisphereCouncilDepth::new_clamped(2).0,
            ..InferenceTopology::default()
        };
        let yaml = serde_yaml::to_string(&topo).unwrap();
        // The transparent newtype should land as a bare integer, not a
        // mapping. Operator's hand-edits stay readable.
        assert!(
            yaml.contains("hemisphere_council_depth: 2"),
            "yaml should contain transparent integer: {yaml}",
        );
    }

    // ── V10-07 H3 profile_provider resolution ─────────────────────────

    #[test]
    fn resolved_profile_provider_defaults_to_local_qwen() {
        let topo = InferenceTopology::default();
        assert_eq!(
            topo.resolved_profile_provider(),
            InferenceProvider::LocalQwen
        );
    }

    #[test]
    fn resolved_profile_provider_honours_explicit_field() {
        let topo = InferenceTopology {
            profile_provider: Some(InferenceProvider::Gemini),
            ..InferenceTopology::default()
        };
        // Operator opted in — resolver returns their override; the
        // runner's WARN still fires because Gemini is cloud.
        assert_eq!(topo.resolved_profile_provider(), InferenceProvider::Gemini);
    }

    #[test]
    fn resolved_profile_provider_falls_through_to_embedding_provider() {
        let topo = InferenceTopology {
            profile_provider: None,
            embedding_provider: Some(InferenceProvider::LocalQwen),
            ..InferenceTopology::default()
        };
        assert_eq!(
            topo.resolved_profile_provider(),
            InferenceProvider::LocalQwen
        );
    }

    #[test]
    fn resolved_profile_provider_profile_field_beats_embedding_field() {
        let topo = InferenceTopology {
            profile_provider: Some(InferenceProvider::LocalQwen),
            embedding_provider: Some(InferenceProvider::OpenAi),
            ..InferenceTopology::default()
        };
        // profile_provider wins per the resolution chain.
        assert_eq!(
            topo.resolved_profile_provider(),
            InferenceProvider::LocalQwen
        );
    }

    #[test]
    fn profile_provider_serialises_as_snake_case_provider_id() {
        let topo = InferenceTopology {
            profile_provider: Some(InferenceProvider::LocalQwen),
            ..InferenceTopology::default()
        };
        let yaml = serde_yaml::to_string(&topo).unwrap();
        assert!(
            yaml.contains("profile_provider: local_qwen"),
            "yaml must serialise the V10-07 field as snake_case: {yaml}"
        );
    }

    #[test]
    fn profile_provider_round_trips_through_yaml() {
        let topo = InferenceTopology {
            profile_provider: Some(InferenceProvider::LocalQwen),
            ..InferenceTopology::default()
        };
        let yaml = serde_yaml::to_string(&topo).unwrap();
        let back: InferenceTopology = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.profile_provider, Some(InferenceProvider::LocalQwen));
    }

    // ── Ouro O-2: LocalOuro InferenceProvider wiring ──────────────────

    #[test]
    fn local_ouro_provider_as_str_pinned() {
        assert_eq!(InferenceProvider::LocalOuro.as_str(), "local_ouro");
    }

    #[test]
    fn local_ouro_from_str_accepts_canonical_and_short_form() {
        assert_eq!(
            InferenceProvider::from_str("local_ouro"),
            Some(InferenceProvider::LocalOuro)
        );
        assert_eq!(
            InferenceProvider::from_str("ouro"),
            Some(InferenceProvider::LocalOuro)
        );
        // Case-insensitive — `from_str` lowercases first.
        assert_eq!(
            InferenceProvider::from_str("OURO"),
            Some(InferenceProvider::LocalOuro)
        );
    }

    #[test]
    fn local_ouro_to_provider_kind_maps_to_local_ouro_variant() {
        use crate::cli::init::ProviderKind;
        assert_eq!(
            InferenceProvider::LocalOuro.to_provider_kind(),
            ProviderKind::LocalOuro
        );
    }

    #[test]
    fn local_ouro_description_mentions_thinking_and_apache() {
        let desc = InferenceProvider::LocalOuro.description();
        assert!(desc.to_lowercase().contains("ouro"));
        // Operator-readable copy must mention reasoning + license
        // so the wizard's stub-vs-real classification stays auditable.
        assert!(
            desc.to_lowercase().contains("reasoning") || desc.to_lowercase().contains("thinking"),
            "description should mention reasoning/thinking; got: {desc}"
        );
        assert!(desc.contains("Apache-2.0"));
    }

    #[test]
    fn local_ouro_is_implemented_returns_true() {
        assert!(
            InferenceProvider::LocalOuro.is_implemented(),
            "O-1b shipped the full LocalOuroAdapter — is_implemented must be true"
        );
    }

    #[test]
    fn local_ouro_round_trips_via_yaml_in_inference_topology() {
        let topo = InferenceTopology {
            embedding_provider: Some(InferenceProvider::LocalOuro),
            ..InferenceTopology::default()
        };
        let yaml = serde_yaml::to_string(&topo).unwrap();
        let back: InferenceTopology = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.embedding_provider, Some(InferenceProvider::LocalOuro));
    }

    // ── SPEC-03b: council.trigger threshold config surface ──

    #[test]
    fn council_trigger_config_default_matches_policy_default() {
        // An absent / empty `trigger` block must reproduce the prior
        // hardcoded `TriggerPolicy::default()` EXACTLY — no behaviour change.
        assert_eq!(
            CouncilTriggerConfig::default().to_policy(),
            crate::council::TriggerPolicy::default()
        );
        // And it falls out of an empty CouncilConfig the same way.
        assert_eq!(
            CouncilConfig::default().trigger.to_policy(),
            crate::council::TriggerPolicy::default()
        );
    }

    #[test]
    fn council_trigger_config_overrides_apply() {
        let cfg = CouncilTriggerConfig {
            min_complex_prompt_chars: Some(200),
            min_interval_secs: Some(900),
            budget_multiplier: Some(5.0),
            convene_on_high_complexity: Some(false),
            extra_dissent_markers: vec![
                "Threat Model".into(),
                "  ".into(),
                "migration plan".into(),
            ],
        };
        let p = cfg.to_policy();
        assert_eq!(p.min_complex_prompt_chars, 200);
        assert_eq!(p.min_interval, std::time::Duration::from_secs(900));
        assert_eq!(p.budget_multiplier, 5.0);
        assert!(!p.convene_on_high_complexity);
        // Markers are lowercased + trimmed; blank-only entries dropped.
        assert_eq!(p.extra_markers, vec!["threat model", "migration plan"]);
        // Untouched fields stay at the built-in defaults.
        assert_eq!(
            p.dissent_markers,
            crate::council::TriggerPolicy::default().dissent_markers
        );
    }

    #[test]
    fn council_trigger_partial_override_keeps_other_defaults() {
        // Only one knob set ⇒ every other field stays default.
        let cfg = CouncilTriggerConfig {
            min_interval_secs: Some(30),
            ..CouncilTriggerConfig::default()
        };
        let p = cfg.to_policy();
        let d = crate::council::TriggerPolicy::default();
        assert_eq!(p.min_interval, std::time::Duration::from_secs(30));
        assert_eq!(p.min_complex_prompt_chars, d.min_complex_prompt_chars);
        assert_eq!(p.budget_multiplier, d.budget_multiplier);
        assert_eq!(p.convene_on_high_complexity, d.convene_on_high_complexity);
        assert!(p.extra_markers.is_empty());
    }

    #[test]
    fn council_trigger_deserializes_from_yaml() {
        let yaml = "\
trigger:
  min_complex_prompt_chars: 150
  extra_dissent_markers:
    - rollback plan
";
        let cfg: CouncilConfig = serde_yaml::from_str(yaml).unwrap();
        let p = cfg.trigger.to_policy();
        assert_eq!(p.min_complex_prompt_chars, 150);
        assert_eq!(p.extra_markers, vec!["rollback plan"]);
        // Absent knobs keep defaults.
        assert_eq!(
            p.budget_multiplier,
            crate::council::TriggerPolicy::default().budget_multiplier
        );
    }
}
