//! QM-12 — Role-based model mapping (cc-switch `UniversalProviderModels` port).
//!
//! Per `PLAN/QUELLEN_ADOPT_cc-switch_2026-05-21.md` §4 pick #5 + adoption
//! table row "Role-based model mapping (sonnet/opus/haiku)".
//!
//! ## Problem this solves
//!
//! NEOTH's hemisphere Left/Right/Cerebellum and the cli operator pass `model:
//! "claude-opus-4-7"` as a literal string everywhere — `freedom.yaml`,
//! `--model` flag, provider preset YAML, WAL `PROVIDER_REQUEST` frames. When
//! Anthropic releases Opus 4.8 the operator has to find and edit every one
//! of those literals. cc-switch's pattern decouples by giving each provider
//! a role table:
//!
//! ```text
//! anthropic:
//!   roles:
//!     flagship: claude-opus-4-7
//!     balanced: claude-sonnet-4-7
//!     fast:     claude-haiku-4-5-20251001
//! ```
//!
//! The operator (and NEOTH internals) reference the ROLE — `flagship` /
//! `balanced` / `fast` / `vision` / `embedding` — and the provider impl
//! resolves to the actual model id at call time. Upgrades become a
//! one-line edit in the provider's role table; downstream config stays
//! stable.
//!
//! ## What this module ships (QM-12 scope = ~150 LOC per audit)
//!
//! 1. [`ModelRole`] enum — five roles (`Flagship`, `Balanced`, `Fast`,
//!    `Vision`, `Embedding`) covering the cc-switch + NEOTH use cases.
//! 2. [`ModelRoleTable`] — provider → role → model-id lookup with builder
//!    helpers + serde round-trip.
//! 3. [`default_table()`] — pinned defaults for the providers NEOTH ships
//!    today (Anthropic / OpenAI / Gemini / AWS Bedrock / Azure OpenAI /
//!    local Qwen). Operators override per-row via `freedom.yaml` once the
//!    config wiring lands (follow-up commit).
//!
//! Wiring this into `cli::chat::run_chat_with` + per-hemisphere selection
//! is the QM-12 follow-up — the primitive lives here, tested + serde-stable,
//! so the wiring lands as a one-file diff later.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Operator-readable role slots. Decouples NEOTH internals from the
/// fast-moving model-id strings each provider publishes.
///
/// Pinned at five roles per the cc-switch adoption audit + NEOTH's
/// existing surfaces:
///
/// - `Flagship` — highest-quality model the provider offers (Opus, GPT-5,
///   Gemini 3 Pro). Used by Cerebellum + Right hemisphere defaults.
/// - `Balanced` — mid-tier (Sonnet, GPT-4o, Gemini 3 Flash). Used by Left
///   hemisphere defaults + most cost-bounded operators.
/// - `Fast` — smallest/cheapest (Haiku, GPT-4o-mini, Gemini 3 Flash-lite).
///   Used by per-token streaming + cron-tick jobs.
/// - `Vision` — image-capable. Distinct slot because some providers split
///   vision into a sibling model rather than the flagship.
/// - `Embedding` — embedding model. Today fixed per provider; here for
///   completeness so cc-switch's `UniversalProviderModels` shape ports
///   cleanly when the embedding work lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    Flagship,
    Balanced,
    Fast,
    Vision,
    Embedding,
}

impl ModelRole {
    /// Wire-stable string id. Matches the serde `rename_all` mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            ModelRole::Flagship => "flagship",
            ModelRole::Balanced => "balanced",
            ModelRole::Fast => "fast",
            ModelRole::Vision => "vision",
            ModelRole::Embedding => "embedding",
        }
    }

    /// Parse the wire id back to the enum. `None` for unknown strings —
    /// the caller decides whether to fall back to `Flagship` or surface
    /// the unknown role to the operator.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "flagship" => Some(Self::Flagship),
            "balanced" => Some(Self::Balanced),
            "fast" => Some(Self::Fast),
            "vision" => Some(Self::Vision),
            "embedding" => Some(Self::Embedding),
            _ => None,
        }
    }
}

/// Per-provider role → model-id table. One instance per provider; the
/// top-level table ([`ModelRoleTable`]) holds the provider→roles map.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderRoles {
    /// `flagship` model id (e.g. `claude-opus-4-7`).
    pub flagship: Option<String>,
    /// `balanced` model id (e.g. `claude-sonnet-4-6`).
    pub balanced: Option<String>,
    /// `fast` model id (e.g. `claude-haiku-4-5-20251001`).
    pub fast: Option<String>,
    /// `vision` model id when the provider serves vision via a sibling
    /// model rather than the flagship.
    pub vision: Option<String>,
    /// `embedding` model id.
    pub embedding: Option<String>,
}

impl ProviderRoles {
    /// Builder helper — set one role and return self for chaining.
    pub fn with(mut self, role: ModelRole, model_id: impl Into<String>) -> Self {
        let value = Some(model_id.into());
        match role {
            ModelRole::Flagship => self.flagship = value,
            ModelRole::Balanced => self.balanced = value,
            ModelRole::Fast => self.fast = value,
            ModelRole::Vision => self.vision = value,
            ModelRole::Embedding => self.embedding = value,
        }
        self
    }

    /// Read the model id for a role. `None` when the operator hasn't
    /// configured this role on this provider — caller falls back to
    /// `Flagship` or surfaces "not configured" to the operator.
    pub fn get(&self, role: ModelRole) -> Option<&str> {
        match role {
            ModelRole::Flagship => self.flagship.as_deref(),
            ModelRole::Balanced => self.balanced.as_deref(),
            ModelRole::Fast => self.fast.as_deref(),
            ModelRole::Vision => self.vision.as_deref(),
            ModelRole::Embedding => self.embedding.as_deref(),
        }
    }

    /// Resolve `role` with fallback to `Flagship`. Returns `None` only
    /// when neither the requested role NOR `Flagship` are configured
    /// (genuinely empty provider table — the operator hasn't set it up
    /// at all, surface that as "configure the provider first").
    pub fn resolve_with_flagship_fallback(&self, role: ModelRole) -> Option<&str> {
        self.get(role).or_else(|| self.get(ModelRole::Flagship))
    }
}

/// Top-level table — `<provider_id> → ProviderRoles`. Provider ids match
/// the same wire names NEOTH's `Provider::name()` returns
/// (`claude_cli`, `anthropic_api`, `openai_api`, `gemini_api`,
/// `aws_bedrock`, `azure_openai`, `openai_compat`, `local_qwen`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModelRoleTable {
    pub providers: HashMap<String, ProviderRoles>,
}

impl ModelRoleTable {
    /// Empty table. Useful for tests + the operator-config-not-loaded
    /// fallback path.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builder — register a provider's roles.
    pub fn with_provider(mut self, provider_id: impl Into<String>, roles: ProviderRoles) -> Self {
        self.providers.insert(provider_id.into(), roles);
        self
    }

    /// Resolve `<provider_id, role>` to a model id, with Flagship
    /// fallback. Returns `None` when the provider is absent from the
    /// table entirely.
    pub fn resolve(&self, provider_id: &str, role: ModelRole) -> Option<&str> {
        self.providers
            .get(provider_id)
            .and_then(|p| p.resolve_with_flagship_fallback(role))
    }

    /// GR-026 — resolve `<provider_id, role>` to the EXACTLY-configured model id
    /// with NO Flagship fallback. The utility fast-pin uses this so a provider
    /// WITHOUT a `fast` row (aws_bedrock / azure_openai / cohere_api) leaves the
    /// utility model UNSET (cheapest-tier intent) instead of silently pinning the
    /// expensive flagship the operator was trying to avoid. `None` when the
    /// provider is absent OR the role is unset for it.
    pub fn resolve_exact(&self, provider_id: &str, role: ModelRole) -> Option<&str> {
        self.providers.get(provider_id).and_then(|p| p.get(role))
    }
}

/// Pinned defaults for the providers NEOTH ships today. Tracks the
/// 2026-05 model snapshot — operators get sensible defaults out of
/// the box; per-row overrides via `freedom.yaml` once the config
/// wiring lands.
///
/// Update cadence: when a provider ships a new flagship/balanced/fast
/// model AND NEOTH wants the daemon to use it without an operator
/// edit, this function is the single update site. Operators with
/// overrides keep their explicit values.
pub fn default_table() -> ModelRoleTable {
    ModelRoleTable::empty()
        .with_provider(
            "claude_cli",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "claude-opus-4-7")
                .with(ModelRole::Balanced, "claude-sonnet-4-6")
                .with(ModelRole::Fast, "claude-haiku-4-5-20251001"),
        )
        .with_provider(
            "anthropic_api",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "claude-opus-4-7")
                .with(ModelRole::Balanced, "claude-sonnet-4-6")
                .with(ModelRole::Fast, "claude-haiku-4-5-20251001"),
        )
        .with_provider(
            "openai_api",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "gpt-5.5")
                .with(ModelRole::Balanced, "gpt-4o")
                .with(ModelRole::Fast, "gpt-4o-mini")
                .with(ModelRole::Vision, "gpt-4o")
                .with(ModelRole::Embedding, "text-embedding-3-large"),
        )
        .with_provider(
            "gemini_api",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "gemini-3.1-pro-preview")
                .with(ModelRole::Balanced, "gemini-3-flash")
                .with(ModelRole::Fast, "gemini-3-flash-lite")
                .with(ModelRole::Vision, "gemini-3-pro")
                .with(ModelRole::Embedding, "gemini-embedding-001"),
        )
        .with_provider(
            "aws_bedrock",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "anthropic.claude-opus-4-7-v1:0")
                .with(ModelRole::Balanced, "anthropic.claude-sonnet-4-6-v1:0"),
        )
        .with_provider(
            "azure_openai",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "gpt-5.5")
                .with(ModelRole::Balanced, "gpt-4o"),
        )
        .with_provider(
            "local_qwen",
            ProviderRoles::default()
                .with(ModelRole::Flagship, "Qwen3-8B-Instruct-Q8")
                .with(ModelRole::Balanced, "Qwen3-3B-Instruct-Q8")
                .with(ModelRole::Fast, "Qwen3-3B-Instruct-Q4"),
        )
        // GOLD-WIRE-03: cohere completes the SSOT — `from_config` resolves its
        // default model from here instead of a hardcoded string.
        .with_provider(
            "cohere_api",
            ProviderRoles::default().with(ModelRole::Flagship, "command-a-plus-05-2026"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trips_through_serde() {
        for role in [
            ModelRole::Flagship,
            ModelRole::Balanced,
            ModelRole::Fast,
            ModelRole::Vision,
            ModelRole::Embedding,
        ] {
            let s = serde_json::to_string(&role).unwrap();
            let back: ModelRole = serde_json::from_str(&s).unwrap();
            assert_eq!(role, back);
            // as_str matches the serde wire form (without quotes).
            assert_eq!(role.as_str(), s.trim_matches('"'));
            // from_str round-trip.
            assert_eq!(ModelRole::from_str(role.as_str()), Some(role));
        }
    }

    #[test]
    fn role_from_str_returns_none_for_unknown() {
        assert!(ModelRole::from_str("nonexistent").is_none());
        assert!(ModelRole::from_str("").is_none());
        assert!(ModelRole::from_str("FLAGSHIP").is_none()); // case-sensitive
    }

    #[test]
    fn provider_roles_builder_pattern_chains() {
        let r = ProviderRoles::default()
            .with(ModelRole::Flagship, "opus")
            .with(ModelRole::Balanced, "sonnet")
            .with(ModelRole::Fast, "haiku");
        assert_eq!(r.get(ModelRole::Flagship), Some("opus"));
        assert_eq!(r.get(ModelRole::Balanced), Some("sonnet"));
        assert_eq!(r.get(ModelRole::Fast), Some("haiku"));
        assert_eq!(r.get(ModelRole::Vision), None);
        assert_eq!(r.get(ModelRole::Embedding), None);
    }

    #[test]
    fn flagship_fallback_resolves_missing_role() {
        // A provider that only sets Flagship (typical for a new
        // adapter): asking for Fast / Vision falls back to Flagship.
        let r = ProviderRoles::default().with(ModelRole::Flagship, "the-one");
        assert_eq!(
            r.resolve_with_flagship_fallback(ModelRole::Fast),
            Some("the-one")
        );
        assert_eq!(
            r.resolve_with_flagship_fallback(ModelRole::Vision),
            Some("the-one")
        );
        assert_eq!(
            r.resolve_with_flagship_fallback(ModelRole::Flagship),
            Some("the-one")
        );
    }

    #[test]
    fn resolve_exact_has_no_flagship_fallback() {
        // GR-026: resolve_exact returns ONLY a genuinely-set role — no flagship
        // fallback. aws_bedrock / azure_openai / cohere have Flagship but no Fast
        // row, so the utility fast-pin must see None (leave the model unset), not
        // the flagship that `resolve` falls back to.
        let t = default_table();
        assert_eq!(t.resolve_exact("aws_bedrock", ModelRole::Fast), None);
        assert_eq!(t.resolve_exact("azure_openai", ModelRole::Fast), None);
        assert_eq!(t.resolve_exact("cohere_api", ModelRole::Fast), None);
        // Contrast: the flagship-fallback `resolve` DOES return a model for those.
        assert!(t.resolve("aws_bedrock", ModelRole::Fast).is_some());
        // A provider WITH a fast row resolves exactly to it; an absent one → None.
        assert_eq!(t.resolve_exact("openai_api", ModelRole::Fast), Some("gpt-4o-mini"));
        assert_eq!(t.resolve_exact("nope", ModelRole::Fast), None);
    }

    #[test]
    fn flagship_fallback_returns_none_when_provider_is_empty() {
        let r = ProviderRoles::default();
        assert!(r.resolve_with_flagship_fallback(ModelRole::Fast).is_none());
        assert!(
            r.resolve_with_flagship_fallback(ModelRole::Flagship)
                .is_none()
        );
    }

    #[test]
    fn table_resolves_unknown_provider_to_none() {
        let t = ModelRoleTable::empty();
        assert!(t.resolve("does_not_exist", ModelRole::Flagship).is_none());
    }

    #[test]
    fn default_table_covers_every_shipped_provider() {
        // Pin the contract: every adapter NEOTH's `Provider::name()`
        // returns has a row in `default_table`. A future adapter without a
        // row here resolves to None and `from_config` falls back to its
        // per-arm hardcoded default — surface a missing default at
        // adapter-ship time, not at first chat. (GOLD-WIRE-03 added the
        // `cohere_api` row so its `from_config` default is table-sourced too.)
        // Intentionally EXCLUDED (no ship-time default model needed):
        // openai_compat / aws_bedrock / azure_openai require an explicit
        // `provider_model` (from_config errors without one); local_ouro passes
        // `None` to its adapter like local_qwen would for an unset repo.
        let t = default_table();
        for id in [
            "claude_cli",
            "anthropic_api",
            "openai_api",
            "gemini_api",
            "cohere_api",
            "aws_bedrock",
            "azure_openai",
            "local_qwen",
        ] {
            assert!(
                t.resolve(id, ModelRole::Flagship).is_some(),
                "default_table missing Flagship for {id}"
            );
        }
    }

    #[test]
    fn default_table_round_trips_through_json() {
        let t = default_table();
        let json = serde_json::to_string(&t).unwrap();
        let back: ModelRoleTable = serde_json::from_str(&json).unwrap();
        assert_eq!(
            t.resolve("claude_cli", ModelRole::Flagship),
            back.resolve("claude_cli", ModelRole::Flagship)
        );
        assert_eq!(
            t.resolve("openai_api", ModelRole::Embedding),
            back.resolve("openai_api", ModelRole::Embedding)
        );
    }

    #[test]
    fn default_table_serialises_with_provider_ids_as_top_level_keys() {
        // The `#[serde(transparent)]` on ModelRoleTable means the JSON
        // shape is `{ "claude_cli": {...}, "openai_api": {...} }` —
        // not `{ "providers": { ... } }`. Pin that shape so a future
        // refactor doesn't accidentally break operator-written YAML.
        let t = ModelRoleTable::empty().with_provider(
            "test_provider",
            ProviderRoles::default().with(ModelRole::Flagship, "test-model"),
        );
        let json = serde_json::to_string(&t).unwrap();
        assert!(
            json.starts_with("{\"test_provider\":"),
            "expected provider ids as top-level keys, got: {json}"
        );
    }
}
