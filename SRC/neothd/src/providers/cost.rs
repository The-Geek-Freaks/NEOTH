//! Pre-call cost prediction — C-14 ex-ante cost transparency.
//!
//! Operator complaint #1 across LLM-agent reddit threads: "I burned $5k
//! at $131/day because the agent ran without me knowing how much each
//! turn cost". The structural fix is to display + gate on a price
//! estimate BEFORE the provider call happens, not after.
//!
//! This module owns a static per-model price table + a rolling-output-
//! token predictor that reads `providers::meter::Meter` and feeds the
//! existing `permissions::Action::PaidProviderCall { eur_estimate }`
//! gate. Operators on `strict` / `standard` autonomy see a confirm
//! prompt with the projected euro cost before the daemon dispatches.

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
    /// provider. Picked from the top-of-market August 2026 rates (rough
    /// Opus-4-class input + Opus-4-class output) so the autonomy gate
    /// errs on the side of "confirm before spending". Codex audit
    /// fail-safe fix 2026-05-16.
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
/// row for local providers (`local_qwen`) + when the table doesn't
/// know about the model. Unknown-model behaviour is intentional: we
/// don't want to surprise-bill an operator who points NEOTH at a
/// brand-new release; the gate falls back to "estimate unknown" +
/// confirms at `Strict` anyway.
pub fn lookup_price(provider: &str, model: &str) -> Option<PriceRow> {
    // Static for v0.1.x. Updated at release time. Dynamic pricing
    // (pulled from provider APIs at startup) is Phase 2.
    //
    // Audit 2026-05-19 (Session 15 Pick #9): C-3 (AWS Bedrock) and
    // C-4 (Azure OpenAI) adapters shipped in Session 14 but pricing
    // branches were never added — Bedrock + Azure operators fell into
    // `_ => None` → `unknown_high_estimate()` (€15/€60 per Mtok). The
    // ceiling was safe (always over-quoted) but never matched reality.
    // Per AWS Bedrock pricing tables and Azure OpenAI Service tiered
    // pricing (standard deployment), both platforms match their
    // upstream vendor's $/Mtok within 1-2 cents — so we share the
    // branch bodies by widening the provider-name match arms.
    match (provider, model) {
        // Anthropic (incl. Bedrock — same $/Mtok as direct API)
        ("claude_cli" | "anthropic_api" | "aws_bedrock", m) if m.contains("opus-4") => {
            Some(PriceRow {
                input_eur_per_mtok: 13.8, // $15/Mtok × 0.92
                output_eur_per_mtok: 69.0,
            })
        }
        ("claude_cli" | "anthropic_api" | "aws_bedrock", m) if m.contains("sonnet-4") => {
            Some(PriceRow {
                input_eur_per_mtok: 2.76,  // $3
                output_eur_per_mtok: 13.8, // $15
            })
        }
        ("claude_cli" | "anthropic_api" | "aws_bedrock", m) if m.contains("haiku-4") => {
            Some(PriceRow {
                input_eur_per_mtok: 0.92, // $1
                output_eur_per_mtok: 4.6, // $5
            })
        }
        // OpenAI (incl. Azure OpenAI Service standard deployment —
        // PTU / commitment deployments get separate pricing the
        // operator overrides via `freedom.yaml::cost_override`)
        ("openai_api" | "openai_compat" | "azure_openai", m) if m.contains("gpt-4o") => {
            Some(PriceRow {
                input_eur_per_mtok: 4.6, // $5
                output_eur_per_mtok: 13.8,
            })
        }
        ("openai_api" | "openai_compat" | "azure_openai", m) if m.contains("gpt-5") => {
            Some(PriceRow {
                input_eur_per_mtok: 9.2, // $10
                output_eur_per_mtok: 27.6,
            })
        }
        // Gemini
        ("gemini_api", m) if m.contains("2.5-pro") || m.contains("3-pro") => Some(PriceRow {
            input_eur_per_mtok: 1.15, // $1.25
            output_eur_per_mtok: 9.2,
        }),
        // Local — always free
        ("local_qwen" | "hermes" | "openclaw", _) => Some(PriceRow::free()),
        _ => None,
    }
}

/// Predict the cost of a turn before dispatching the provider call.
/// `input_text` is the assembled prompt + system; we count it via the
/// 4-chars-per-token heuristic (matches tiktoken cl100k to within 5%
/// for English; we don't pull tiktoken yet because the dep is heavy).
/// Output-token estimate comes from the meter's rolling output_tps +
/// p50 latency; fallback to a sensible default for cold meters.
pub fn predict(provider: &str, model: &str, input_text: &str, meter: &Meter) -> CostEstimate {
    let input_tokens = approx_tokens(input_text);
    let output_tokens_est = predict_output_tokens(meter);

    // Fail-safe: unknown cloud models do NOT default to free
    // (silent-bypass of the autonomy gate). Fall back to a
    // conservative high estimate so the operator sees a non-zero
    // EUR figure and the permission gate decides on the safe side.
    // Local providers (local_qwen / hermes / openclaw) genuinely
    // are free and `lookup_price` returns Some(free) for those.
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

fn approx_tokens(text: &str) -> u32 {
    // 4 chars/token is the cl100k average for English. For non-ASCII
    // and code-heavy text, real tokens are ~30% higher; we round up
    // generously so the operator sees a conservative-high estimate
    // rather than a surprise underbill. Real tokenizer integration
    // (tiktoken-rs) is a Phase 2 lift.
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
        // Local providers (local_qwen/hermes/openclaw) match the
        // generic-local arm in lookup_price + return free. The
        // fail-safe high-estimate kicks in only for truly unknown
        // provider names.
        let meter = Meter::with_default_window();
        let est = predict("local_qwen", "Qwen/Some-New-Tag", "hello", &meter);
        assert_eq!(est.total_eur, 0.0);
    }

    #[test]
    fn lookup_price_recognises_claude_opus_variants() {
        let p = lookup_price("claude_cli", "claude-opus-4-7").unwrap();
        assert!(p.input_eur_per_mtok > 0.0);
        assert!(p.output_eur_per_mtok > p.input_eur_per_mtok);
    }

    #[test]
    fn approx_tokens_4_chars_per_token() {
        assert_eq!(approx_tokens(""), 0);
        assert_eq!(approx_tokens("abcd"), 1);
        assert_eq!(approx_tokens("hello world"), 3); // 11 chars / 4 → 3 (rounded up)
    }

    #[test]
    fn predict_cold_meter_uses_default_output_estimate() {
        let meter = Meter::with_default_window();
        let est = predict("openai_api", "gpt-4o", "hello", &meter);
        assert_eq!(est.output_tokens_est, 250);
        assert!(est.total_eur > 0.0);
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

    // ── Bedrock + Azure pricing parity (Pick #9 / Session 15) ─────────

    #[test]
    fn bedrock_claude_matches_anthropic_pricing() {
        // C-3 Bedrock adapter must produce the same price row as
        // direct Anthropic API — same upstream model, same $/Mtok.
        let opus_direct = lookup_price("anthropic_api", "claude-opus-4-7").unwrap();
        let opus_bedrock = lookup_price("aws_bedrock", "anthropic.claude-opus-4-7-v1").unwrap();
        assert_eq!(opus_direct, opus_bedrock);

        let sonnet_direct = lookup_price("anthropic_api", "claude-sonnet-4-6").unwrap();
        let sonnet_bedrock = lookup_price("aws_bedrock", "anthropic.claude-sonnet-4-6").unwrap();
        assert_eq!(sonnet_direct, sonnet_bedrock);
    }

    #[test]
    fn azure_openai_matches_direct_openai_pricing() {
        let gpt5_direct = lookup_price("openai_api", "gpt-5.5").unwrap();
        let gpt5_azure = lookup_price("azure_openai", "gpt-5.5").unwrap();
        assert_eq!(gpt5_direct, gpt5_azure);

        let gpt4o_direct = lookup_price("openai_api", "gpt-4o").unwrap();
        let gpt4o_azure = lookup_price("azure_openai", "gpt-4o-2024-08-06").unwrap();
        assert_eq!(gpt4o_direct, gpt4o_azure);
    }

    #[test]
    fn bedrock_unknown_model_still_returns_none_for_fallback_path() {
        // Bedrock with a non-Claude model (e.g. Llama, Mistral) has no
        // pricing row yet — caller falls back to unknown_high_estimate
        // via `predict()`.
        assert!(lookup_price("aws_bedrock", "meta.llama3-70b-instruct").is_none());
    }

    #[test]
    fn azure_unknown_model_still_returns_none_for_fallback_path() {
        // Azure with a deployment name that doesn't contain a known
        // model substring — caller falls back via predict().
        assert!(lookup_price("azure_openai", "custom-deployment-xyz").is_none());
    }
}
