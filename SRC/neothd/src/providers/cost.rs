//! Pre-call cost prediction — C-14 ex-ante cost transparency.
//!
//! Operator complaint #1 across LLM-agent reddit threads: "I burned $5k
//! at $131/day because the agent ran without me knowing how much each
//! turn cost". The structural fix is to display + gate on a price
//! estimate BEFORE the provider call happens, not after.
//!
//! This module owns a static per-model price table and two deliberately
//! separate estimates: a rolling chars/4 preview for UI display, and a
//! conservative UTF-8-byte/request-overhead bound for the mandatory
//! request-bound `permissions::Action::PaidProviderCall { .. }` gate. The display
//! heuristic must never become an authorization input.

use crate::providers::Request;
use crate::providers::meter::Meter;

/// One row in the static pricing table — input + output cost per
/// million tokens, in euros (USD prices converted at 0.92 fixed rate
/// for v0.1; rotating FX is Phase 2 work).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PriceRow {
    pub input_eur_per_mtok: f32,
    pub output_eur_per_mtok: f32,
}

impl PriceRow {
    const fn free() -> Self {
        Self {
            input_eur_per_mtok: 0.0,
            output_eur_per_mtok: 0.0,
        }
    }

    /// Conservative high-end fallback for unknown cloud models. Used by
    /// `predict()` when `lookup_price` returns `None` for a non-local
    /// provider. This is a deliberately high policy ceiling, not a claim
    /// about current vendor pricing, so the autonomy gate errs on the side
    /// of "confirm before spending" when a model has no reviewed price row.
    const fn unknown_high_estimate() -> Self {
        Self {
            input_eur_per_mtok: 15.0,
            output_eur_per_mtok: 60.0,
        }
    }
}

/// Estimated cost for a single turn. `total_eur` is what the
/// permission gate actually sees; the breakdown is for the UI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CostEstimate {
    pub input_tokens: u32,
    pub output_tokens_est: u32,
    pub input_eur: f32,
    pub output_eur: f32,
    pub total_eur: f32,
}

/// Look up a `PriceRow` for a provider/model pair. Returns the free
/// row for every provider recognized by the canonical
/// [`super::is_local_provider`] predicate. Cloud rows are exact, release-reviewed
/// model identifiers: a new model, alias, deployment name, or typo returns
/// `None` and the authorization boundary treats its price as unknown.
pub fn lookup_price(provider: &str, model: &str) -> Option<PriceRow> {
    if super::is_local_provider(provider) {
        return Some(PriceRow::free());
    }
    // Static, release-reviewed estimates. Matching must stay exact: family
    // substring matching lets a new, premium, or misspelled model silently
    // inherit an old approval estimate. Azure deployment names and generic
    // OpenAI-compatible endpoints cannot prove their underlying model and are
    // therefore intentionally absent.
    match (provider, model) {
        ("claude_cli" | "anthropic_api", "claude-opus-4-7" | "claude-opus-4-7[1m]")
        | ("aws_bedrock", "anthropic.claude-opus-4-7-v1:0") => Some(PriceRow {
            input_eur_per_mtok: 13.8,
            output_eur_per_mtok: 69.0,
        }),
        ("claude_cli" | "anthropic_api", "claude-sonnet-4-6")
        | ("aws_bedrock", "anthropic.claude-sonnet-4-6-v1:0") => Some(PriceRow {
            input_eur_per_mtok: 2.76,
            output_eur_per_mtok: 13.8,
        }),
        ("claude_cli" | "anthropic_api", "claude-haiku-4-5-20251001") => Some(PriceRow {
            input_eur_per_mtok: 0.92,
            output_eur_per_mtok: 4.6,
        }),
        ("openai_api", "gpt-4o" | "gpt-4o-2024-08-06" | "gpt-4o-mini") => Some(PriceRow {
            input_eur_per_mtok: 4.6,
            output_eur_per_mtok: 13.8,
        }),
        ("openai_api", "gpt-5" | "gpt-5.5") => Some(PriceRow {
            input_eur_per_mtok: 9.2,
            output_eur_per_mtok: 27.6,
        }),
        ("gemini_api", "gemini-2.5-pro" | "gemini-3-pro" | "gemini-3.1-pro-preview") => {
            Some(PriceRow {
                input_eur_per_mtok: 1.15, // $1.25
                output_eur_per_mtok: 9.2,
            })
        }
        ("cohere_api", "command-a-plus-05-2026" | "command-r-plus-08-2024") => Some(PriceRow {
            input_eur_per_mtok: 2.3,  // ~$2.5
            output_eur_per_mtok: 9.2, // ~$10
        }),
        ("cohere_api", "command-r-08-2024") => Some(PriceRow {
            input_eur_per_mtok: 0.14,  // ~$0.15
            output_eur_per_mtok: 0.55, // ~$0.6
        }),
        // GitHub Copilot intentionally has no static row. Since 2026-06-01,
        // normal plans use token/AI-credit billing while annual legacy plans
        // can retain request/multiplier billing. Model, plan, allowance and
        // overage state determine marginal cost, none of which this adapter
        // can currently prove at the leaf boundary.
        _ => None,
    }
}

/// Display currencies the operator can request via
/// `freedom.yaml::usage_currency` or `neoth usage --currency`.
/// USD is the storage canonical (cloud providers quote in USD);
/// other currencies are computed by FX conversion at display time.
///
/// FX rates are v0.1 fixed snapshots. Dynamic FX rotation is
/// Phase 2 work — when it lands, this enum's variants stay
/// stable but `rate_per_usd()` becomes a runtime lookup instead
/// of a const match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Currency {
    Usd,
    Eur,
    Gbp,
    Chf,
    Jpy,
    Cny,
}

impl Currency {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "USD" | "US$" | "$" => Some(Self::Usd),
            "EUR" | "€" => Some(Self::Eur),
            "GBP" | "£" => Some(Self::Gbp),
            "CHF" | "FR." => Some(Self::Chf),
            "JPY" | "¥" => Some(Self::Jpy),
            "CNY" | "RMB" => Some(Self::Cny),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Usd => "USD",
            Self::Eur => "EUR",
            Self::Gbp => "GBP",
            Self::Chf => "CHF",
            Self::Jpy => "JPY",
            Self::Cny => "CNY",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Usd => "$",
            Self::Eur => "€",
            Self::Gbp => "£",
            Self::Chf => "Fr.",
            Self::Jpy => "¥",
            Self::Cny => "¥",
        }
    }

    /// FX rate — 1 USD = N <currency>. Fixed v0.1 snapshot taken
    /// 2026-05-22. Dynamic FX rotation lands in Phase 2; until
    /// then operators expecting penny-perfect numbers should keep
    /// the daemon in USD.
    pub fn rate_per_usd(&self) -> f64 {
        match self {
            Self::Usd => 1.0,
            Self::Eur => 0.92,
            Self::Gbp => 0.79,
            Self::Chf => 0.91,
            Self::Jpy => 156.0,
            Self::Cny => 7.25,
        }
    }
}

impl Default for Currency {
    fn default() -> Self {
        Self::Usd
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Convert a USD-denominated amount into `target`. Pure arithmetic.
pub fn convert_from_usd(usd: f64, target: Currency) -> f64 {
    usd * target.rate_per_usd()
}

/// Format a numeric amount with the right grouping for the currency.
/// JPY + CNY conventionally render without fractional cents.
pub fn format_amount(amount: f64, currency: Currency) -> String {
    match currency {
        Currency::Jpy | Currency::Cny => format!("{}{:.0}", currency.symbol(), amount),
        _ => format!("{}{:.4}", currency.symbol(), amount),
    }
}

/// Compute USD cost for an actually-completed call using the same
/// price table as `predict()`. Unlike `predict()`, this takes the
/// real token counts from the provider's `Completion` rather than
/// estimating from the input. Unknown cloud models use the same
/// conservative fallback as the pre-call gate; only canonical local
/// providers and explicitly free price rows report zero.
///
/// Storage canonical: USD. Operators who want other display
/// currencies use `Currency::*` + `convert_from_usd` at the
/// presentation layer.
pub fn actual_cost_usd(provider: &str, model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
    actual_cost_usd_with_cache(provider, model, input_tokens, output_tokens, 0, 0)
}

/// Compute the reviewed terminal cost including Anthropic-compatible prompt
/// cache economics. Provider usage reports normal input, cache creation and
/// cache reads as disjoint dimensions: writes cost 1.25x the input rate and
/// reads cost 0.10x. Keeping this arithmetic canonical is required by both the
/// usage projection and the Council hard-cap settlement.
pub fn actual_cost_usd_with_cache(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_tokens: u32,
    cache_read_tokens: u32,
) -> f64 {
    let price = lookup_price(provider, model).unwrap_or_else(PriceRow::unknown_high_estimate);
    // PriceRow holds EUR per Mtok with the 0.92 conversion baked in.
    // Reverse the rate to recover USD per Mtok.
    const EUR_TO_USD_INV: f64 = 1.0 / 0.92;
    let input_usd_per_mtok = price.input_eur_per_mtok as f64 * EUR_TO_USD_INV;
    let output_usd_per_mtok = price.output_eur_per_mtok as f64 * EUR_TO_USD_INV;
    let billable_input_token_equivalents =
        input_tokens as f64 + cache_creation_tokens as f64 * 1.25 + cache_read_tokens as f64 * 0.10;
    let input_usd = (billable_input_token_equivalents / 1_000_000.0) * input_usd_per_mtok;
    let output_usd = (output_tokens as f64 / 1_000_000.0) * output_usd_per_mtok;
    input_usd + output_usd
}

/// VIEW-03 — compute the net cache savings (USD) for a completed Anthropic call.
///
/// cache_read tokens cost 10% of the normal input rate (saving 90%);
/// cache_creation tokens cost 125% of normal input (a 25% premium).
/// Net savings = read_savings - write_premium (can be negative on the first
/// turn with a large creation count and no reads yet — that is correct
/// economics; do NOT clamp to zero).
///
/// Returns 0.0 for providers with no price row (local / unknown).
pub fn cache_savings_usd(
    provider: &str,
    model: &str,
    cache_creation_tokens: u32,
    cache_read_tokens: u32,
) -> f64 {
    let Some(price) = lookup_price(provider, model) else {
        return 0.0;
    };
    const EUR_TO_USD_INV: f64 = 1.0 / 0.92;
    let input_usd_per_tok = price.input_eur_per_mtok as f64 * EUR_TO_USD_INV / 1_000_000.0;
    // cache_read costs 10% of normal input → saves 90%
    let read_savings = cache_read_tokens as f64 * input_usd_per_tok * 0.90;
    // cache_creation costs 125% of normal input → 25% premium (cost, not saving)
    let write_premium = cache_creation_tokens as f64 * input_usd_per_tok * 0.25;
    read_savings - write_premium
}

/// Convenience: compute the cost in any display currency in one call.
pub fn actual_cost_in(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens: u32,
    currency: Currency,
) -> f64 {
    convert_from_usd(
        actual_cost_usd(provider, model, input_tokens, output_tokens),
        currency,
    )
}

/// Predict the cost of a turn before dispatching the provider call.
/// `input_text` is the assembled prompt + system; we count it via the
/// 4-chars-per-token heuristic (matches tiktoken cl100k to within 5%
/// for English; we don't pull tiktoken yet because the dep is heavy).
/// Output-token estimate comes from the meter's rolling output_tps +
/// p50 latency; fallback to a sensible default for cold meters.
pub fn predict(provider: &str, model: &str, input_text: &str, meter: &Meter) -> CostEstimate {
    let input_tokens = approx_tokens_for_display(input_text);
    let output_tokens_est = predict_output_tokens(meter);

    estimate_for_tokens(provider, model, input_tokens, output_tokens_est)
}

/// Fixed reserve for the provider's request envelope and control tokens. A
/// [`Request`] has at most one system and one user message today; any future
/// history/tool-message expansion must update this bound before it can use the
/// paid-call boundary.
const AUTHORIZATION_REQUEST_OVERHEAD_TOKENS: u64 = 4096;
const AUTHORIZATION_PER_MESSAGE_OVERHEAD_TOKENS: u64 = 256;

fn authorization_input_cost_multiplier(provider: &str, req: &Request) -> f64 {
    // AnthropicApi marks every non-empty system block for ephemeral prompt
    // caching. A cold miss can bill that cacheable prefix at 1.25x. Applying
    // the premium to the complete conservative input bound intentionally
    // over-reserves the non-cacheable prompt/overhead portion, which keeps
    // both consent and the daily cap hard without predicting cache hits.
    if provider == "anthropic_api"
        && req
            .system
            .as_deref()
            .is_some_and(|system| !system.is_empty())
    {
        1.25
    } else {
        1.0
    }
}

/// Provable upper bound for all caller-controlled input text: a tokenizer
/// token cannot consume less than one byte of the UTF-8 input. Model and stop
/// strings are included even though current vendors generally do not bill
/// them as prompt tokens. The fixed reserves cover the two message roles,
/// separators, JSON/request framing, and provider control tokens.
pub(crate) fn authorization_input_token_upper_bound(req: &Request, model: &str) -> u32 {
    let system = req.system.as_deref().unwrap_or("");
    let message_count = 1_u64 + u64::from(req.system.is_some());
    let stop_bytes = req.stop_sequences.iter().fold(0_u64, |total, stop| {
        total.saturating_add(stop.len() as u64).saturating_add(1)
    });
    let controlled_bytes = (req.prompt.len() as u64)
        .saturating_add(system.len() as u64)
        .saturating_add(model.len() as u64)
        .saturating_add(stop_bytes);

    controlled_bytes
        .saturating_add(AUTHORIZATION_REQUEST_OVERHEAD_TOKENS)
        .saturating_add(message_count.saturating_mul(AUTHORIZATION_PER_MESSAGE_OVERHEAD_TOKENS))
        .min(u32::MAX as u64) as u32
}

/// Cost bound used by the mandatory provider-leaf authorization boundary.
/// Unlike [`predict`], this uses neither the display-only chars/4 heuristic nor
/// rolling averages: input is a UTF-8 byte upper bound plus request/message
/// overhead, and output is the concrete cap enforced by the leaf adapter.
pub fn predict_authorization_bound(
    provider: &str,
    model: &str,
    req: &Request,
    output_token_ceiling: u32,
) -> CostEstimate {
    let mut estimate = estimate_for_tokens(
        provider,
        model,
        authorization_input_token_upper_bound(req, model),
        output_token_ceiling.max(1),
    );
    estimate.input_eur *= authorization_input_cost_multiplier(provider, req) as f32;
    estimate.total_eur = estimate.input_eur + estimate.output_eur;
    estimate
}

/// Reviewed USD upper bound for the exact request envelope authorized at a
/// provider leaf. Unlike the UI estimate, this returns `None` for an unknown
/// price row and never substitutes the display-only conservative fallback.
/// The Council daily-cap ledger uses this value for atomic admission.
pub(crate) fn authorization_bound_usd(
    provider: &str,
    model: &str,
    req: &Request,
    output_token_ceiling: u32,
) -> Option<f64> {
    let price = lookup_price(provider, model)?;
    let input_tokens = authorization_input_token_upper_bound(req, model);
    const EUR_PER_USD: f64 = 0.92;
    let input_eur = f64::from(input_tokens) / 1_000_000.0
        * f64::from(price.input_eur_per_mtok)
        * authorization_input_cost_multiplier(provider, req);
    let output_eur =
        f64::from(output_token_ceiling.max(1)) / 1_000_000.0 * f64::from(price.output_eur_per_mtok);
    Some((input_eur + output_eur) / EUR_PER_USD)
}

/// Reviewed USD upper bound for any request that can pass a known hard input
/// cap. Council prompts grow after the initial fan-out (groundtruth, debate,
/// tool output and refinement), so pricing the small trigger request would not
/// bound the later leaves. This helper deliberately charges the complete
/// effective input cap and the complete output ceiling. Anthropic's cold
/// cache-write premium is applied unconditionally because a later Council leaf
/// can add a non-empty system/voice block even when the trigger request did
/// not contain one.
fn authorization_capped_envelope_bound_usd(
    provider: &str,
    model: &str,
    input_token_cap: u32,
    output_token_ceiling: u32,
) -> Option<f64> {
    let price = lookup_price(provider, model)?;
    const EUR_PER_USD: f64 = 0.92;
    let input_multiplier = if provider == "anthropic_api" {
        1.25
    } else {
        1.0
    };
    let input_eur = f64::from(input_token_cap) / 1_000_000.0
        * f64::from(price.input_eur_per_mtok)
        * input_multiplier;
    let output_eur =
        f64::from(output_token_ceiling.max(1)) / 1_000_000.0 * f64::from(price.output_eur_per_mtok);
    Some((input_eur + output_eur) / EUR_PER_USD)
}

/// Conservative pre-fan-out bound for every provider leaf the configured
/// Council can reach. `total_usd` is never lower than the sum of the most
/// expensive `max_calls_per_user_message` leaves; internal recursive wrapper
/// charges can only reduce the number of real provider calls below that cap.
///
/// This is deliberately separate from the UI preview. An unknown price or a
/// provider without a provable output ceiling returns an error, allowing the
/// smart trigger to skip fail-closed whenever a daily USD cap is active.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CouncilTreeCostBound {
    pub(crate) total_usd: f64,
    pub(crate) max_leaf_usd: f64,
    pub(crate) candidate_leaf_count: usize,
    pub(crate) costed_leaf_count: usize,
}

const COUNCIL_ROLES: [crate::config::inference::HemisphereRole; 3] = [
    crate::config::inference::HemisphereRole::Left,
    crate::config::inference::HemisphereRole::Right,
    crate::config::inference::HemisphereRole::Cerebellum,
];

fn collect_council_leaf_slots<'a>(
    topology: &'a crate::config::inference::InferenceTopology,
    slot: &'a crate::config::inference::HemisphereSlot,
    outer_role: Option<crate::config::inference::HemisphereRole>,
    depth: u8,
    leaves: &mut Vec<&'a crate::config::inference::HemisphereSlot>,
) {
    if depth <= 1 {
        leaves.push(slot);
        return;
    }

    match outer_role {
        Some(outer) => {
            // `ProviderHemisphere` builds explicit sub-slots and stamps those
            // wrappers with `outer_role: None`.
            for inner in COUNCIL_ROLES {
                collect_council_leaf_slots(
                    topology,
                    topology.slot_for_sub(outer, inner),
                    None,
                    depth - 1,
                    leaves,
                );
            }
        }
        None => {
            // The next recursive level rebuilds ordinary role slots; those
            // wrappers again carry their concrete outer role.
            for role in COUNCIL_ROLES {
                collect_council_leaf_slots(
                    topology,
                    topology.slot_for(role),
                    Some(role),
                    depth - 1,
                    leaves,
                );
            }
        }
    }
}

fn configured_leaf_binding<'a>(
    config: &'a crate::config::FreedomConfig,
    slot: &'a crate::config::inference::HemisphereSlot,
) -> anyhow::Result<(
    crate::cli::init::ProviderKind,
    Option<&'a str>,
    Option<&'a str>,
)> {
    if let Some(provider) = slot.provider {
        return Ok((
            provider.to_provider_kind(),
            slot.model.as_deref(),
            slot.endpoint.as_deref(),
        ));
    }

    let kind = config.provider_kind.ok_or_else(|| {
        anyhow::anyhow!("Council leaf falls back to an unconfigured primary provider")
    })?;
    Ok((
        kind,
        config.provider_model.as_deref(),
        config.provider_endpoint.as_deref(),
    ))
}

fn configured_leaf_wire_model(
    config: &crate::config::FreedomConfig,
    kind: crate::cli::init::ProviderKind,
    configured_model: Option<&str>,
    home: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    use crate::cli::init::ProviderKind;
    use crate::providers::model_roles::ModelRole;

    let raw = match (
        kind,
        configured_model.filter(|model| !model.trim().is_empty()),
    ) {
        (_, Some(model)) => model.to_owned(),
        (ProviderKind::ClaudeCli, None) => home
            .and_then(|home| super::catalog_flagship_model_at(home, "claude_cli"))
            .unwrap_or_else(|| {
                super::default_model("claude_cli", ModelRole::Flagship, "claude-opus-4-7")
            }),
        (ProviderKind::OpenaiApi, None) => home
            .and_then(|home| super::catalog_flagship_model_at(home, "openai_api"))
            .unwrap_or_else(|| super::default_model("openai_api", ModelRole::Flagship, "gpt-5.5")),
        (ProviderKind::AnthropicApi, None) => {
            super::default_model("anthropic_api", ModelRole::Balanced, "claude-sonnet-4-6")
        }
        (ProviderKind::GeminiApi, None) => home
            .and_then(|home| super::catalog_flagship_model_at(home, "gemini_api"))
            .unwrap_or_else(|| {
                super::default_model("gemini_api", ModelRole::Flagship, "gemini-3.1-pro-preview")
            }),
        (ProviderKind::Cohere, None) => home
            .and_then(|home| super::catalog_flagship_model_at(home, "cohere_api"))
            .unwrap_or_else(|| {
                super::default_model("cohere_api", ModelRole::Flagship, "command-a-plus-05-2026")
            }),
        (ProviderKind::GitHubCopilot, None) => home
            .and_then(|home| super::catalog_flagship_model_at(home, "copilot_api"))
            .unwrap_or_else(|| super::default_model("copilot_api", ModelRole::Flagship, "gpt-4o")),
        (ProviderKind::LocalOllama, None) => super::ollama_api::DEFAULT_MODEL.to_owned(),
        (ProviderKind::RecursiveMas, None) => "recursive_mas".to_owned(),
        (ProviderKind::OpenaiCompat, None) => {
            anyhow::bail!("openai_compat Council leaf has no configured model")
        }
        (ProviderKind::AwsBedrock, None) => {
            anyhow::bail!("aws_bedrock Council leaf has no configured model")
        }
        (ProviderKind::AzureOpenAi, None) => {
            anyhow::bail!("azure_openai Council leaf has no configured deployment")
        }
        (ProviderKind::Skip, None) => {
            anyhow::bail!("Council leaf provider is configured as skip")
        }
        // Guaranteed-offline providers return before model resolution. Keep
        // this arm exhaustive in case that ordering changes later.
        (ProviderKind::LocalQwen | ProviderKind::LocalOuro, None) => {
            anyhow::bail!("local Council leaf has no model")
        }
    };
    let aliased = config.resolve_model_alias(&raw);
    Ok(if kind == ProviderKind::ClaudeCli {
        super::claude_cli::normalise_model(aliased)
    } else {
        aliased.to_owned()
    })
}

fn effective_ollama_provider(endpoint: Option<&str>) -> anyhow::Result<&'static str> {
    let endpoint = endpoint.unwrap_or(super::ollama_api::DEFAULT_BASE_URL);
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|error| anyhow::anyhow!("parse Ollama Council endpoint `{endpoint}`: {error}"))?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host().is_some(),
        "Ollama Council endpoint `{endpoint}` must be an http(s) URL with a host"
    );
    Ok(if super::http_client::url_has_loopback_host(&parsed) {
        "local_ollama"
    } else {
        "ollama_remote"
    })
}

fn council_leaf_authorization_bound_usd(
    config: &crate::config::FreedomConfig,
    slot: &crate::config::inference::HemisphereSlot,
    _base_req: &Request,
    home: Option<&std::path::Path>,
) -> anyhow::Result<f64> {
    use crate::cli::init::ProviderKind;

    let (kind, configured_model, endpoint) = configured_leaf_binding(config, slot)?;
    let provider = if kind == ProviderKind::LocalOllama {
        effective_ollama_provider(endpoint)?
    } else {
        kind.as_provider_id()
    };
    if super::is_local_provider(provider) {
        return Ok(0.0);
    }

    let model = configured_leaf_wire_model(config, kind, configured_model, home)?;
    let output_ceiling = match kind {
        ProviderKind::ClaudeCli | ProviderKind::RecursiveMas => None,
        ProviderKind::LocalQwen | ProviderKind::LocalOuro => None,
        ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::OpenaiCompat
        | ProviderKind::AwsBedrock
        | ProviderKind::AzureOpenAi
        | ProviderKind::GitHubCopilot
        | ProviderKind::LocalOllama => Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING),
        ProviderKind::Skip => None,
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "Council leaf `{provider}` / `{model}` has no provable output-token ceiling"
        )
    })?;

    let input_token_cap =
        crate::tokens::budget::effective_cap(provider, &model, config.tokens.max_per_request);
    authorization_capped_envelope_bound_usd(provider, &model, input_token_cap, output_ceiling)
        .ok_or_else(|| {
            anyhow::anyhow!("Council leaf `{provider}` / `{model}` has no reviewed price bound")
        })
}

pub(crate) fn council_tree_authorization_bound_usd(
    config: &crate::config::FreedomConfig,
    base_req: &Request,
) -> anyhow::Result<CouncilTreeCostBound> {
    council_tree_authorization_bound_usd_inner(config, base_req, None)
}

pub(crate) fn council_tree_authorization_bound_usd_at(
    config: &crate::config::FreedomConfig,
    base_req: &Request,
    home: &std::path::Path,
) -> anyhow::Result<CouncilTreeCostBound> {
    council_tree_authorization_bound_usd_inner(config, base_req, Some(home))
}

fn council_tree_authorization_bound_usd_inner(
    config: &crate::config::FreedomConfig,
    base_req: &Request,
    home: Option<&std::path::Path>,
) -> anyhow::Result<CouncilTreeCostBound> {
    let depth = config.inference.hemisphere_council_depth.get().max(1);
    let mut leaves = Vec::new();
    for role in COUNCIL_ROLES {
        collect_council_leaf_slots(
            &config.inference,
            config.inference.slot_for(role),
            Some(role),
            depth,
            &mut leaves,
        );
    }
    let candidate_leaf_count = leaves.len();
    let max_calls = config.council.effective_max_calls() as usize;
    if max_calls == 0 {
        return Ok(CouncilTreeCostBound {
            total_usd: 0.0,
            max_leaf_usd: 0.0,
            candidate_leaf_count,
            costed_leaf_count: 0,
        });
    }

    // Resolve every candidate before applying the call cap. Recursive tasks
    // race, so any candidate can consume one of the available leaf slots; one
    // unknown paid candidate therefore makes the bounded trigger unavailable.
    let mut debate_bounds = leaves
        .into_iter()
        .map(|slot| council_leaf_authorization_bound_usd(config, slot, base_req, home))
        .collect::<anyhow::Result<Vec<_>>>()?;
    debate_bounds.sort_by(|left, right| right.total_cmp(left));
    // The same BudgetToken now spans debate recursion plus Split/callosum and
    // optional quality-refinement leaves. Include those reachable post-debate
    // calls in the trigger bound instead of authorizing only the initial tree.
    let normal_post_debate_call_ceiling = 1usize
        .saturating_add(usize::from(config.council.self_reflect_enabled))
        .saturating_add(
            if config.council.self_score_action == crate::config::inference::SelfScoreAction::Redo {
                usize::from(config.council.effective_self_score_max_redos())
            } else {
                0
            },
        );
    // A strong-dissent loop can reach ordinary round calls, corrective
    // retries, compaction, a goal judge and loop refinement. They now all
    // charge the same Council BudgetToken; therefore the exact conservative
    // ceiling is every remaining whole-message slot, costed at the most
    // expensive reachable Council leaf.
    let post_debate_call_ceiling = if config.loop_config.auto_invoke_on_dissent {
        max_calls
    } else {
        normal_post_debate_call_ceiling
    };

    // Recursive debate leaves are not the complete reachable price surface.
    // After the debate, Callosum rebuilds the ordinary Cerebellum slot, while
    // self-reflect/redo and the strong-dissent loop can rebuild whichever
    // ordinary outer role won. Those outer slots may be more expensive than
    // every configured sub-slot, so price them independently.
    let post_debate_roles: &[crate::config::inference::HemisphereRole] =
        if config.council.self_reflect_enabled
            || config.council.self_score_action == crate::config::inference::SelfScoreAction::Redo
            || config.loop_config.auto_invoke_on_dissent
        {
            &COUNCIL_ROLES
        } else {
            &[crate::config::inference::HemisphereRole::Cerebellum]
        };
    let post_debate_max_leaf_usd = post_debate_roles
        .iter()
        .map(|role| {
            council_leaf_authorization_bound_usd(
                config,
                config.inference.slot_for(*role),
                base_req,
                home,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .max_by(f64::total_cmp)
        .unwrap_or(0.0);
    let max_leaf_usd = debate_bounds
        .first()
        .copied()
        .unwrap_or(0.0)
        .max(post_debate_max_leaf_usd);

    // Early Council quorum can cancel part of the recursive fan-out, leaving
    // more shared BudgetToken slots for repeated post-debate work. Therefore a
    // fixed `candidate_count + remaining` split is not conservative. Evaluate
    // every possible number of completed debate leaves and retain the largest
    // reachable bound.
    let debate_leaf_ceiling = debate_bounds.len().min(max_calls);
    let mut debate_sum = 0.0_f64;
    let mut total_usd = 0.0_f64;
    let mut costed_leaf_count = 0usize;
    for debate_leaf_count in 0..=debate_leaf_ceiling {
        if debate_leaf_count > 0 {
            debate_sum += debate_bounds[debate_leaf_count - 1];
        }
        let post_debate_leaf_count = max_calls
            .saturating_sub(debate_leaf_count)
            .min(post_debate_call_ceiling);
        let candidate_total = debate_sum + post_debate_max_leaf_usd * post_debate_leaf_count as f64;
        let candidate_count = debate_leaf_count.saturating_add(post_debate_leaf_count);
        if candidate_total > total_usd
            || (candidate_total == total_usd && candidate_count > costed_leaf_count)
        {
            total_usd = candidate_total;
            costed_leaf_count = candidate_count;
        }
    }
    anyhow::ensure!(
        total_usd.is_finite(),
        "Council tree authorization bound overflowed"
    );
    Ok(CouncilTreeCostBound {
        total_usd,
        max_leaf_usd,
        candidate_leaf_count,
        costed_leaf_count,
    })
}

fn estimate_for_tokens(
    provider: &str,
    model: &str,
    input_tokens: u32,
    output_tokens_est: u32,
) -> CostEstimate {
    // Display fail-safe: unknown cloud models do not look free. The provider
    // leaf authorization path does not use this fabricated display estimate;
    // it routes unknown pricing through `UnboundedPaidProviderCall`.
    // Canonically local providers genuinely are free and `lookup_price`
    // returns Some(free) for every name accepted by `is_local_provider`.
    let price = lookup_price(provider, model).unwrap_or_else(|| {
        tracing::warn!(
            provider,
            model,
            "cost: no price row for model — using conservative high-estimate fallback (€/Mtok in=15.0 out=60.0)"
        );
        PriceRow::unknown_high_estimate()
    });
    let input_eur = (input_tokens as f32 / 1_000_000.0) * price.input_eur_per_mtok;
    let output_eur = (output_tokens_est as f32 / 1_000_000.0) * price.output_eur_per_mtok;

    CostEstimate {
        input_tokens,
        output_tokens_est,
        input_eur,
        output_eur,
        total_eur: input_eur + output_eur,
    }
}

/// Render a one-line operator-visible cost preview. Used by the CLI
/// confirm prompt + the WAL `COST_ESTIMATE_SHOWN` payload.
pub fn render_preview(provider: &str, model: &str, est: &CostEstimate) -> String {
    if est.total_eur < 0.0001 {
        format!(
            "{provider}/{model}: {} in + ~{} out tokens (local — free)",
            est.input_tokens, est.output_tokens_est
        )
    } else {
        format!(
            "{provider}/{model}: {} in + ~{} out tokens = ~€{:.4}",
            est.input_tokens, est.output_tokens_est, est.total_eur
        )
    }
}

fn approx_tokens_for_display(text: &str) -> u32 {
    // UI-only English-average estimate. Authorization MUST NOT use this:
    // code and non-ASCII text can tokenize far above chars/4.
    let chars = text.chars().count();
    chars.div_ceil(4).min(u32::MAX as usize) as u32
}

fn predict_output_tokens(meter: &Meter) -> u32 {
    let snap = meter.snapshot();
    // Cold meter — no prior turn. Use a conservative-large default
    // (matches Claude's typical answer length for a 100-token prompt).
    if snap.sample_count == 0 {
        return 250;
    }
    // Snapshot stores tokens/sec and p50-latency. output_tokens ≈
    // out_tps × p50_seconds. Bound to a sane range so a single
    // outlier turn doesn't poison the estimate.
    let p50_s = snap.p50_latency_ms / 1000.0;
    let est = (snap.output_tps * p50_s).clamp(50.0, 4096.0);
    est as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_price_returns_free_for_local() {
        let p = lookup_price("local_qwen", "Qwen/Qwen2.5-3B-Instruct").unwrap();
        assert_eq!(p, PriceRow::free());
    }

    #[test]
    fn lookup_price_unknown_provider_returns_none() {
        assert!(lookup_price("brand_new_provider_2026", "any-model").is_none());
    }

    #[test]
    fn currency_parse_accepts_codes_and_symbols() {
        assert_eq!(Currency::parse("USD"), Some(Currency::Usd));
        assert_eq!(Currency::parse("usd"), Some(Currency::Usd));
        assert_eq!(Currency::parse("$"), Some(Currency::Usd));
        assert_eq!(Currency::parse("EUR"), Some(Currency::Eur));
        assert_eq!(Currency::parse("€"), Some(Currency::Eur));
        assert_eq!(Currency::parse("GBP"), Some(Currency::Gbp));
        assert_eq!(Currency::parse("£"), Some(Currency::Gbp));
        assert_eq!(Currency::parse("CHF"), Some(Currency::Chf));
        assert_eq!(Currency::parse("JPY"), Some(Currency::Jpy));
        assert_eq!(Currency::parse("CNY"), Some(Currency::Cny));
        assert_eq!(Currency::parse("RMB"), Some(Currency::Cny));
        assert_eq!(Currency::parse("brand-new-coin"), None);
        assert_eq!(Currency::parse(""), None);
    }

    #[test]
    fn currency_code_and_symbol_pinned() {
        assert_eq!(Currency::Usd.code(), "USD");
        assert_eq!(Currency::Usd.symbol(), "$");
        assert_eq!(Currency::Eur.code(), "EUR");
        assert_eq!(Currency::Eur.symbol(), "€");
        assert_eq!(Currency::Gbp.symbol(), "£");
        assert_eq!(Currency::Chf.symbol(), "Fr.");
        assert_eq!(Currency::Jpy.symbol(), "¥");
    }

    #[test]
    fn currency_default_is_usd() {
        assert_eq!(Currency::default(), Currency::Usd);
    }

    #[test]
    fn convert_from_usd_uses_pinned_rates() {
        // 1 USD → exactly 1 USD.
        assert!((convert_from_usd(1.0, Currency::Usd) - 1.0).abs() < f64::EPSILON);
        // 100 USD → 92 EUR.
        assert!((convert_from_usd(100.0, Currency::Eur) - 92.0).abs() < 0.01);
        // 100 USD → 79 GBP.
        assert!((convert_from_usd(100.0, Currency::Gbp) - 79.0).abs() < 0.01);
        // 1 USD → 156 JPY (Yen has no cents).
        assert!((convert_from_usd(1.0, Currency::Jpy) - 156.0).abs() < 0.01);
    }

    #[test]
    fn format_amount_yen_has_no_cents() {
        // Use values that aren't half-to-even rounding edge cases.
        assert_eq!(format_amount(1234.7, Currency::Jpy), "¥1235");
        assert_eq!(format_amount(1234.7, Currency::Cny), "¥1235");
        assert_eq!(format_amount(1234.2, Currency::Jpy), "¥1234");
        // Other currencies keep 4 decimals (cost values are often
        // < $0.01 for cheap models — full precision matters).
        let usd = format_amount(1.2345, Currency::Usd);
        assert!(usd.starts_with('$'));
        assert!(usd.contains("1.234"));
    }

    #[test]
    fn actual_cost_usd_matches_known_rates() {
        // gpt-4o: $5 in, $15 out per Mtok. 100 + 50 tokens →
        // (100/1M)*5 + (50/1M)*15 = 0.0005 + 0.00075 = 0.00125.
        let c = actual_cost_usd("openai_api", "gpt-4o", 100, 50);
        assert!((c - 0.00125).abs() < 1e-6, "got {c}");
    }

    #[test]
    fn actual_cost_usd_includes_cache_creation_and_read_rates() {
        // Sonnet is $3/Mtok input and $15/Mtok output. Provider-reported
        // dimensions are disjoint: 100 normal + 200*1.25 creation +
        // 300*0.10 read = 380 billable input-token equivalents.
        let actual =
            actual_cost_usd_with_cache("anthropic_api", "claude-sonnet-4-6", 100, 50, 200, 300);
        let expected = 380.0 / 1_000_000.0 * 3.0 + 50.0 / 1_000_000.0 * 15.0;
        assert!((actual - expected).abs() < 1e-9, "got {actual}");
        assert!(
            actual > actual_cost_usd("anthropic_api", "claude-sonnet-4-6", 100, 50),
            "cache writes and reads must be included in actual spend"
        );
    }

    #[test]
    fn actual_cost_in_eur_equals_usd_times_rate() {
        let usd = actual_cost_usd("openai_api", "gpt-4o", 100, 50);
        let eur = actual_cost_in("openai_api", "gpt-4o", 100, 50, Currency::Eur);
        assert!((eur - usd * 0.92).abs() < 1e-6);
    }

    #[test]
    fn actual_cost_unknown_cloud_model_uses_conservative_fallback() {
        let actual = actual_cost_usd("brand-new-cloud", "future-model", 1_000_000, 1_000_000);
        let expected = (15.0 + 60.0) / 0.92;
        assert!((actual - expected).abs() < 1e-6, "got {actual}");
    }

    #[test]
    fn actual_cost_unknown_local_model_stays_zero() {
        assert_eq!(
            actual_cost_usd("local_ollama", "future-local-model", 1_000_000, 1_000_000),
            0.0
        );
    }

    #[test]
    fn predict_unknown_cloud_model_uses_high_estimate_not_zero() {
        // Codex fail-safe: an operator pointing NEOTH at a brand-new
        // model name that isn't in the price table MUST NOT see €0
        // as the estimate. The permission gate's auto-allow threshold
        // (€0.50 at standard) would silently bypass otherwise.
        let meter = Meter::with_default_window();
        let est = predict("openai_api", "gpt-99-future", "hello world", &meter);
        assert!(
            est.total_eur > 0.0,
            "unknown cloud model must NOT predict zero EUR"
        );
        // High-estimate floor: at 15.0/Mtok input + 60.0/Mtok output,
        // a tiny prompt + cold-meter output estimate must produce a
        // non-trivial figure even for a 3-token input.
        assert!(
            est.input_eur > 0.0,
            "high-estimate fallback must produce non-zero input cost"
        );
    }

    #[test]
    fn predict_unknown_local_model_stays_zero() {
        // Every canonical local provider returns free. The
        // fail-safe high-estimate kicks in only for truly unknown
        // provider names.
        let meter = Meter::with_default_window();
        let est = predict("local_qwen", "Qwen/Some-New-Tag", "hello", &meter);
        assert_eq!(est.total_eur, 0.0);
        // local_ouro is the second local provider (Session 22) — it must
        // also price free, not fall through to the high-estimate fallback.
        let ouro = predict(
            "local_ouro",
            "ByteDance/Ouro-1.4B-Thinking",
            "hello",
            &meter,
        );
        assert_eq!(ouro.total_eur, 0.0);
        assert_eq!(
            predict("local_ollama", "llama3.2", "hello", &meter).total_eur,
            0.0
        );
        assert_eq!(
            predict("local_abliterated", "operator/model", "hello", &meter).total_eur,
            0.0
        );
        assert!(
            predict("recursive_mas", "recursive_mas", "hello", &meter).total_eur > 0.0,
            "operator-installed sidecars with inherited network access are not cost-free local providers"
        );
    }

    #[test]
    fn lookup_price_recognises_claude_opus_variants() {
        let p = lookup_price("claude_cli", "claude-opus-4-7").unwrap();
        assert!(p.input_eur_per_mtok > 0.0);
        assert!(p.output_eur_per_mtok > p.input_eur_per_mtok);
    }

    #[test]
    fn display_estimate_uses_four_chars_per_token() {
        assert_eq!(approx_tokens_for_display(""), 0);
        assert_eq!(approx_tokens_for_display("abcd"), 1);
        assert_eq!(approx_tokens_for_display("hello world"), 3); // 11 chars / 4 → 3
    }

    #[test]
    fn predict_cold_meter_uses_default_output_estimate() {
        let meter = Meter::with_default_window();
        let est = predict("openai_api", "gpt-4o", "hello", &meter);
        assert_eq!(est.output_tokens_est, 250);
        assert!(est.total_eur > 0.0);
    }

    #[test]
    fn leaf_prediction_uses_wire_output_ceiling_not_cold_meter_default() {
        let est = predict_authorization_bound(
            "openai_api",
            "gpt-4o",
            &Request {
                prompt: "hello".into(),
                ..Request::default()
            },
            4096,
        );
        assert_eq!(est.output_tokens_est, 4096);
        assert!(est.total_eur > 0.0);
    }

    #[test]
    fn leaf_prediction_carries_large_reasoning_budget() {
        let est = predict_authorization_bound(
            "claude_cli",
            "claude-opus-4-7",
            &Request {
                prompt: "hello".into(),
                ..Request::default()
            },
            10_000,
        );
        assert_eq!(est.output_tokens_est, 10_000);
        assert!(est.total_eur > 0.0);
    }

    #[test]
    fn authorization_bound_covers_utf8_bytes_and_message_overhead() {
        let req = Request {
            prompt: "世界".into(),
            system: Some("system".into()),
            model: Some("ignored-here".into()),
            stop_sequences: vec!["停止".into()],
            ..Request::default()
        };
        let controlled_bytes = req.prompt.len()
            + req.system.as_deref().unwrap().len()
            + "gpt-5".len()
            + req.stop_sequences[0].len()
            + 1;
        let bound = authorization_input_token_upper_bound(&req, "gpt-5");
        assert!(bound as usize >= controlled_bytes);
        assert_eq!(
            bound as u64,
            controlled_bytes as u64
                + AUTHORIZATION_REQUEST_OVERHEAD_TOKENS
                + 2 * AUTHORIZATION_PER_MESSAGE_OVERHEAD_TOKENS
        );
    }

    #[test]
    fn authorization_bound_reserves_anthropic_cold_cache_premium() {
        let req = Request {
            prompt: "user prompt".into(),
            system: Some("cacheable system policy".into()),
            ..Request::default()
        };
        let model = "claude-sonnet-4-6";
        let output_ceiling = 1_000;
        let bound = authorization_bound_usd("anthropic_api", model, &req, output_ceiling).unwrap();
        let input_bound = f64::from(authorization_input_token_upper_bound(&req, model));
        let expected =
            input_bound / 1_000_000.0 * 3.0 * 1.25 + f64::from(output_ceiling) / 1_000_000.0 * 15.0;
        assert!((bound - expected).abs() < 1e-9, "got {bound}");

        let consent_bound =
            predict_authorization_bound("anthropic_api", model, &req, output_ceiling);
        let base_input_eur = input_bound / 1_000_000.0 * 2.76;
        assert!(
            (f64::from(consent_bound.input_eur) - base_input_eur * 1.25).abs() < 1e-8,
            "paid-call consent must include the same cold-cache premium"
        );

        let no_cache = authorization_bound_usd(
            "anthropic_api",
            model,
            &Request {
                prompt: req.prompt,
                ..Request::default()
            },
            output_ceiling,
        )
        .unwrap();
        assert!(
            bound > no_cache,
            "a cacheable system block needs the cold-write reserve"
        );
    }

    #[test]
    fn council_tree_bound_is_zero_for_an_all_local_topology() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalQwen);
        config.council.daily_usd_cap = Some(0.0);
        let req = Request {
            prompt: "Should this local-only Council review the architecture?".into(),
            system: Some("operator policy".into()),
            ..Request::default()
        };

        let bound = council_tree_authorization_bound_usd(&config, &req).unwrap();
        assert_eq!(bound.total_usd, 0.0);
        assert_eq!(bound.max_leaf_usd, 0.0);
        assert_eq!(bound.candidate_leaf_count, 3);
        assert_eq!(bound.costed_leaf_count, 4);
    }

    #[test]
    fn council_ollama_cost_classification_matches_loopback_runtime_boundary() {
        for endpoint in [
            None,
            Some("http://localhost:11434"),
            Some("http://localhost.:11434/"),
            Some("http://127.42.0.9:11434"),
            Some("http://[::1]:11434"),
        ] {
            assert_eq!(
                effective_ollama_provider(endpoint).unwrap(),
                "local_ollama",
                "not classified local: {endpoint:?}"
            );
        }

        for endpoint in [
            Some("https://localhost.evil.test"),
            Some("http://192.168.1.4:11434"),
            Some("https://ollama.example"),
        ] {
            assert_eq!(
                effective_ollama_provider(endpoint).unwrap(),
                "ollama_remote",
                "not classified remote: {endpoint:?}"
            );
        }
    }

    #[test]
    fn remote_ollama_without_reviewed_price_makes_tree_bound_unavailable() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalOllama);
        config.provider_endpoint = Some("http://192.168.1.4:11434".into());
        config.provider_model = Some("llama3.2".into());
        config.council.daily_usd_cap = Some(10.0);

        let error = council_tree_authorization_bound_usd(&config, &Request::default())
            .expect_err("remote Ollama must not inherit the local/free classification");
        assert!(
            error.to_string().contains("has no reviewed price bound"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn council_tree_bound_sums_all_flat_paid_leaves() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_model = Some("gpt-4o".into());
        config.council.daily_usd_cap = Some(10.0);
        config.inference.hemisphere_council_depth =
            crate::config::inference::HemisphereCouncilDepth::new_clamped(1).0;
        let req = Request {
            prompt: "Compare three concrete release strategies.".into(),
            system: Some("operator policy".into()),
            ..Request::default()
        };
        let single = authorization_capped_envelope_bound_usd(
            "openai_api",
            "gpt-4o",
            crate::tokens::budget::effective_cap(
                "openai_api",
                "gpt-4o",
                config.tokens.max_per_request,
            ),
            crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
        )
        .unwrap();

        let bound = council_tree_authorization_bound_usd(&config, &req).unwrap();
        assert_eq!(bound.candidate_leaf_count, 3);
        assert_eq!(bound.costed_leaf_count, 4);
        assert!((bound.max_leaf_usd - single).abs() < 1e-12);
        assert!((bound.total_usd - single * 4.0).abs() < 1e-12);
    }

    #[test]
    fn council_tree_bound_prices_the_hard_input_cap_not_the_trigger_prompt() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_model = Some("gpt-4o".into());
        config.tokens.max_per_request = 50_000;
        config.council.daily_usd_cap = Some(10.0);

        let tiny = council_tree_authorization_bound_usd(
            &config,
            &Request {
                prompt: "x".into(),
                ..Request::default()
            },
        )
        .unwrap();
        let nearly_full = council_tree_authorization_bound_usd(
            &config,
            &Request {
                prompt: "x".repeat(45_000),
                ..Request::default()
            },
        )
        .unwrap();

        assert_eq!(tiny, nearly_full);
        let leaf_floor = authorization_capped_envelope_bound_usd(
            "openai_api",
            "gpt-4o",
            50_000,
            crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
        )
        .unwrap();
        assert!(tiny.max_leaf_usd >= leaf_floor);
    }

    #[test]
    fn dissent_loop_cost_bound_reserves_every_remaining_shared_call_slot() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_model = Some("gpt-4o".into());
        config.council.daily_usd_cap = Some(10.0);
        config.council.max_calls_per_user_message = Some(7);
        config.loop_config.auto_invoke_on_dissent = true;
        let req = Request {
            prompt: "Resolve a strongly disputed release strategy.".into(),
            ..Request::default()
        };
        let single = authorization_capped_envelope_bound_usd(
            "openai_api",
            "gpt-4o",
            crate::tokens::budget::effective_cap(
                "openai_api",
                "gpt-4o",
                config.tokens.max_per_request,
            ),
            crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
        )
        .unwrap();

        let bound = council_tree_authorization_bound_usd(&config, &req).unwrap();
        assert_eq!(bound.candidate_leaf_count, 3);
        assert_eq!(bound.costed_leaf_count, 7);
        assert!((bound.total_usd - single * 7.0).abs() < 1e-12);
    }

    #[test]
    fn recursive_cheap_subslots_cannot_hide_expensive_outer_dissent_provider() {
        use crate::config::inference::{
            HemisphereCouncilDepth, HemisphereRole, HemisphereSlot, InferenceProvider,
            SubHemisphereSlots, TopologyMode,
        };

        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalQwen);
        config.council.daily_usd_cap = Some(10.0);
        config.council.max_calls_per_user_message = Some(7);
        config.loop_config.auto_invoke_on_dissent = true;
        config.inference.mode = TopologyMode::Custom;
        config.inference.hemisphere_council_depth = HemisphereCouncilDepth::new_clamped(2).0;
        config.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            model: Some("gpt-4o".into()),
            ..HemisphereSlot::default()
        };
        config.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..HemisphereSlot::default()
        };
        config.inference.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..HemisphereSlot::default()
        };
        for outer in [
            HemisphereRole::Left,
            HemisphereRole::Right,
            HemisphereRole::Cerebellum,
        ] {
            let local = || HemisphereSlot {
                provider: Some(InferenceProvider::LocalQwen),
                ..HemisphereSlot::default()
            };
            config.inference.hemisphere_sub_slots.insert(
                outer,
                SubHemisphereSlots {
                    left: local(),
                    right: local(),
                    cerebellum: local(),
                },
            );
        }
        let req = Request {
            prompt: "Resolve a recursively reviewed disputed release strategy.".into(),
            ..Request::default()
        };
        let outer = authorization_capped_envelope_bound_usd(
            "openai_api",
            "gpt-4o",
            crate::tokens::budget::effective_cap(
                "openai_api",
                "gpt-4o",
                config.tokens.max_per_request,
            ),
            crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
        )
        .unwrap();

        let bound = council_tree_authorization_bound_usd(&config, &req).unwrap();
        assert_eq!(bound.candidate_leaf_count, 9);
        assert_eq!(bound.costed_leaf_count, 7);
        assert!((bound.max_leaf_usd - outer).abs() < 1e-12);
        assert!(
            bound.total_usd >= outer * 7.0,
            "post-debate outer provider must price every remaining shared slot: {bound:?}"
        );
    }

    #[test]
    fn recursive_unknown_paid_sub_slot_makes_tree_bound_unavailable() {
        use crate::config::inference::{
            HemisphereCouncilDepth, HemisphereRole, HemisphereSlot, InferenceProvider,
            SubHemisphereSlots,
        };

        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalQwen);
        config.council.daily_usd_cap = Some(10.0);
        config.inference.hemisphere_council_depth = HemisphereCouncilDepth::new_clamped(2).0;
        config.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Left,
            SubHemisphereSlots {
                left: HemisphereSlot {
                    provider: Some(InferenceProvider::GitHubCopilot),
                    model: Some("gpt-4o".into()),
                    ..HemisphereSlot::default()
                },
                ..SubHemisphereSlots::default()
            },
        );

        let error = council_tree_authorization_bound_usd(
            &config,
            &Request {
                prompt: "Review this recursively".into(),
                ..Request::default()
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("no reviewed price bound"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn code_input_crosses_paid_gate_threshold_under_byte_bound() {
        let prompt = "let value = parse::<Payload>(input)?;\n".repeat(700);
        let req = Request {
            prompt: prompt.clone(),
            ..Request::default()
        };
        let old_display_estimate = estimate_for_tokens(
            "unknown_cloud",
            "future-model",
            approx_tokens_for_display(&prompt),
            4096,
        );
        let authorized = predict_authorization_bound("unknown_cloud", "future-model", &req, 4096);
        assert!(old_display_estimate.total_eur < 0.50);
        assert!(
            authorized.total_eur > 0.50,
            "code-heavy input must not auto-pass Standard after a chars/4 undercount: {authorized:?}"
        );
    }

    #[test]
    fn cjk_input_crosses_paid_gate_threshold_under_utf8_byte_bound() {
        let prompt = "界".repeat(7_000);
        let req = Request {
            prompt: prompt.clone(),
            ..Request::default()
        };
        let old_display_estimate = estimate_for_tokens(
            "unknown_cloud",
            "future-model",
            approx_tokens_for_display(&prompt),
            4096,
        );
        let authorized = predict_authorization_bound("unknown_cloud", "future-model", &req, 4096);
        assert!(old_display_estimate.total_eur < 0.50);
        assert!(
            authorized.total_eur > 0.50,
            "CJK input must use UTF-8 bytes rather than chars/4: {authorized:?}"
        );
    }

    #[test]
    fn predict_local_provider_is_always_free() {
        let meter = Meter::with_default_window();
        let est = predict("local_qwen", "any-model", &"a".repeat(10_000), &meter);
        assert_eq!(est.total_eur, 0.0);
    }

    #[test]
    fn render_preview_shows_local_free_path() {
        let est = CostEstimate {
            input_tokens: 100,
            output_tokens_est: 200,
            input_eur: 0.0,
            output_eur: 0.0,
            total_eur: 0.0,
        };
        let s = render_preview("local_qwen", "Qwen", &est);
        assert!(s.contains("free"));
        assert!(s.contains("100 in"));
    }

    #[test]
    fn render_preview_shows_euro_amount_for_cloud() {
        let est = CostEstimate {
            input_tokens: 1000,
            output_tokens_est: 500,
            input_eur: 0.05,
            output_eur: 0.10,
            total_eur: 0.15,
        };
        let s = render_preview("openai_api", "gpt-4o", &est);
        assert!(s.contains("€0.1500"));
    }

    // ── Exact reviewed-model matching ──────────────────────────────────

    #[test]
    fn bedrock_claude_matches_anthropic_pricing() {
        // C-3 Bedrock adapter must produce the same price row as
        // direct Anthropic API — same upstream model, same $/Mtok.
        let opus_direct = lookup_price("anthropic_api", "claude-opus-4-7").unwrap();
        let opus_bedrock = lookup_price("aws_bedrock", "anthropic.claude-opus-4-7-v1:0").unwrap();
        assert_eq!(opus_direct, opus_bedrock);

        let sonnet_direct = lookup_price("anthropic_api", "claude-sonnet-4-6").unwrap();
        let sonnet_bedrock =
            lookup_price("aws_bedrock", "anthropic.claude-sonnet-4-6-v1:0").unwrap();
        assert_eq!(sonnet_direct, sonnet_bedrock);
    }

    #[test]
    fn opaque_azure_deployment_names_never_inherit_openai_pricing() {
        assert!(lookup_price("azure_openai", "gpt-5.5").is_none());
        assert!(lookup_price("azure_openai", "gpt-4o-2024-08-06").is_none());
        assert!(lookup_price("azure_openai", "custom-deployment-xyz").is_none());
    }

    #[test]
    fn bedrock_unknown_model_still_returns_none_for_fallback_path() {
        // Bedrock with a non-Claude model (e.g. Llama, Mistral) has no
        // pricing row yet — caller falls back to unknown_high_estimate
        // via `predict()`.
        assert!(lookup_price("aws_bedrock", "meta.llama3-70b-instruct").is_none());
    }

    #[test]
    fn known_family_substrings_do_not_authorize_unknown_models() {
        for (provider, model) in [
            ("openai_api", "gpt-5-future-premium"),
            ("openai_api", "typo-gpt-4o"),
            ("anthropic_api", "claude-opus-4-unknown"),
            ("gemini_api", "gemini-3-pro-future"),
            ("cohere_api", "command-a-unreviewed"),
        ] {
            assert!(
                lookup_price(provider, model).is_none(),
                "{provider}/{model} must use the unknown-price gate"
            );
        }
    }
}
