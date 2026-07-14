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
    let price = lookup_price(provider, model).unwrap_or_else(PriceRow::unknown_high_estimate);
    // PriceRow holds EUR per Mtok with the 0.92 conversion baked in.
    // Reverse the rate to recover USD per Mtok.
    const EUR_TO_USD_INV: f64 = 1.0 / 0.92;
    let input_usd_per_mtok = price.input_eur_per_mtok as f64 * EUR_TO_USD_INV;
    let output_usd_per_mtok = price.output_eur_per_mtok as f64 * EUR_TO_USD_INV;
    let input_usd = (input_tokens as f64 / 1_000_000.0) * input_usd_per_mtok;
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
    estimate_for_tokens(
        provider,
        model,
        authorization_input_token_upper_bound(req, model),
        output_token_ceiling.max(1),
    )
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
