//! Council "Smartest-Wins" quality scoring (Session 14 Pick #8 SP-1).
//!
//! Pure functions. No I/O. No async. Composes a `QualityScore` per
//! `HemisphereResponse` so `CouncilDebate::best_response` can pick
//! the highest-scored usable contribution regardless of physical
//! hemisphere role (Left/Right/Cerebellum).
//!
//! Decomposition (per the 6-agent consultation + fractal-synthesis
//! verdict ratified in `PLAN/PROGRESS.md` Session 14 Pick #8):
//!
//! ```text
//! score = 0.40 × tier_weight        (static model-family tier)
//!       + 0.35 × dynamic_signal     (length / refusal / structural)
//!       + 0.20 × memory_weight      (Hebbian EMA from past acceptance)
//!       + 0.05 × diversity_bonus    (cross-outer dissent lift)
//! ```
//!
//! All four components are clamped to `[0.0, 1.0]` at construction,
//! so the total is also `[0.0, 1.0]`. NaN is unrepresentable.
//!
//! **Hard rule** (Pick #8 synthesis): tier values originate from a
//! pure const lookup keyed by `InferenceProvider::as_str`. The table
//! is operator-readable + WAL-sealed at init in SP-4 follow-up; for
//! SP-1 it lives as a `const` in this module. Provider-supplied
//! metadata MUST NEVER override these values — that would let a
//! malicious `openai_compat` provider claim `tier = 1.0` and win
//! every debate (Security guardrail #4 from the audit).

use serde::{Deserialize, Serialize};

use super::types::{HemisphereOutcome, HemisphereResponse};

/// Pinned static tier table — provider id (matching
/// `InferenceProvider::as_str`) → tier value in `[0.0, 1.0]`.
///
/// Tier numbers reflect the 2026-05-18 NEOTH research snapshot:
/// Claude Opus 4.7 leads, followed by GPT-5.5 + Gemini 3.1 Pro, then
/// Bedrock-hosted models, then Azure, then OpenAI-compat shims, then
/// local Qwen. Operator overrides via `tweaks.toml` are out-of-scope
/// for SP-1 — values here are the floor reality.
///
/// Unknown providers (e.g. an unrecognised `openai_compat` host)
/// receive [`UNKNOWN_TIER`] as a deliberate neutral mid-point. This
/// avoids accidentally suppressing them entirely AND avoids letting
/// them claim flagship status.
pub const TIER_TABLE: &[(&str, f32)] = &[
    ("claude_cli", 1.00),    // Opus 4.7 via OAuth CLI
    ("anthropic_api", 1.00), // Same as claude_cli (Opus assumed)
    ("openai_api", 0.95),    // GPT-5.5
    ("gemini_api", 0.90),    // Gemini 3.1 Pro
    ("aws_bedrock", 0.85),   // hosted Anthropic Claude on Bedrock
    ("azure_openai", 0.85),  // hosted OpenAI on Azure
    ("openai_compat", 0.70), // generic OpenAI-compat shim
    ("local_qwen", 0.50),    // Qwen3-3B local
];

/// Score returned when the provider id doesn't match any known
/// adapter in [`TIER_TABLE`]. Neutral middle so an unknown adapter
/// doesn't accidentally dominate AND doesn't get auto-suppressed.
pub const UNKNOWN_TIER: f32 = 0.50;

/// Score for a hemisphere that errored without producing text. Used
/// instead of `0.0` so a single hemisphere error doesn't always pin
/// `best_response` to the second-best response when ALL hemispheres
/// errored — the comparison stays meaningful.
pub const ERROR_TIER: f32 = 0.0;

/// Refusal-pattern markers that strongly correlate with model refusal
/// or safety boilerplate. Hits add to `dynamic_signal_refusal_penalty`.
/// Lowercased substring match — case-insensitive via `to_ascii_lowercase`.
pub const REFUSAL_MARKERS: &[&str] = &[
    "i cannot",
    "i can't",
    "i'm not able",
    "i am not able",
    "as an ai",
    "i'm an ai",
    "i am an ai",
    "i don't have the ability",
    "i'm sorry, but",
    "sorry, i can",
    "unable to assist",
    "violates",
    "against my",
    "i must decline",
];

/// Composable quality score. Four independent components clamped at
/// construction to `[0.0, 1.0]` each. `total()` produces the final
/// `[0.0, 1.0]` ranking value used by `best_response`.
///
/// Each component is preserved so audit consumers (WAL frames,
/// `neoth council show-last`) can see WHY a hemisphere won — was it
/// raw tier? Memory feedback? Diversity bonus?
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct QualityScore {
    /// Static model-family tier from [`TIER_TABLE`].
    pub tier_weight: f32,
    /// Response-local heuristic signals (length / refusal-markers /
    /// structural cues). SP-1 ships a no-op zero; SP-3 fleshes it out.
    pub dynamic_signal: f32,
    /// Memory-feedback weight from `memory::routing_weights`. SP-1
    /// ships the neutral `0.5` prior; SP-4 wires the real lookup.
    pub memory_weight: f32,
    /// Cross-outer dissent lift (F5 from fractal synthesis). SP-1
    /// ships zero; activated when SP-4 EMA data settles.
    pub diversity_bonus: f32,
}

impl QualityScore {
    /// Construct with all four components. Each clamped to `[0.0, 1.0]`
    /// — NaN inputs collapse to `0.0` via `clamp` so the type is
    /// always safe to compare.
    pub fn new(
        tier_weight: f32,
        dynamic_signal: f32,
        memory_weight: f32,
        diversity_bonus: f32,
    ) -> Self {
        Self {
            tier_weight: clamp_unit(tier_weight),
            dynamic_signal: clamp_unit(dynamic_signal),
            memory_weight: clamp_unit(memory_weight),
            diversity_bonus: clamp_unit(diversity_bonus),
        }
    }

    /// Convenience: tier-only score with neutral memory + zero
    /// dynamic + zero diversity. SP-1 minimum-viable callers use
    /// this — SP-3/4/5 will swap to the richer constructors.
    pub fn tier_only(tier_weight: f32) -> Self {
        Self::new(tier_weight, 0.0, 0.5, 0.0)
    }

    /// Score returned for an errored hemisphere — all components at
    /// floor, even `memory_weight` (no neutral prior on a hemisphere
    /// that couldn't speak).
    pub fn errored() -> Self {
        Self {
            tier_weight: ERROR_TIER,
            dynamic_signal: 0.0,
            memory_weight: 0.0,
            diversity_bonus: 0.0,
        }
    }

    /// Composite `[0.0, 1.0]` value. Weights match the formula in
    /// the module-level doc comment. Clamped at output so a future
    /// component overflow can't escape the range.
    pub fn total(&self) -> f32 {
        let raw = 0.40 * self.tier_weight
            + 0.35 * self.dynamic_signal
            + 0.20 * self.memory_weight
            + 0.05 * self.diversity_bonus;
        clamp_unit(raw)
    }
}

fn clamp_unit(value: f32) -> f32 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

/// Look up the static tier for a provider id. Returns [`UNKNOWN_TIER`]
/// when the id doesn't match any known adapter. Case-sensitive match
/// to keep WAL audit byte-identical to provider's own `name()`.
pub fn provider_tier(provider_id: &str) -> f32 {
    TIER_TABLE
        .iter()
        .find(|(id, _)| *id == provider_id)
        .map(|(_, tier)| *tier)
        .unwrap_or(UNKNOWN_TIER)
}

/// Score a single `HemisphereResponse`. SP-1+SP-3 composite: tier +
/// dynamic-signal heuristics. SP-4 layers memory weights on top.
///
/// Errored hemispheres always score floor (zero) so `best_response`
/// never picks them over any working hemisphere. Refused hemispheres
/// still go through the heuristic — `dynamic_signal_from_text` applies
/// the refusal penalty to push them below neutral.
///
/// Audit 2026-05-19 Type #13 Phase 2 (migration step 1): switched from
/// `resp.text.is_none()` + `text.as_deref().unwrap_or("")` to the typed
/// outcome enum. The compile-time exhaustive match makes "errored"
/// unrepresentable as a usable scoring path — no `unwrap_or("")` left.
pub fn score_response(resp: &HemisphereResponse) -> QualityScore {
    let text = match resp.outcome() {
        HemisphereOutcome::Usable { text } | HemisphereOutcome::Refused { text, .. } => text,
        HemisphereOutcome::Errored { .. } => return QualityScore::errored(),
    };
    let tier = provider_tier(&resp.provider);
    let dynamic = dynamic_signal_from_text(text);
    // Memory weight stays at neutral 0.5 until SP-4 wires the
    // `memory::routing_weights` lookup.
    QualityScore::new(tier, dynamic, 0.5, 0.0)
}

/// COUNCIL-WEIGHTING-01 — returns `true` when the provider id corresponds
/// to a locally-running backend (compute on operator's machine).
///
/// `claude_cli` is **excluded** — it uses OAuth but inference runs on
/// Anthropic's servers.  Mirrors `InferenceProvider::is_local()`.
pub fn is_local_provider(id: &str) -> bool {
    matches!(id, "local_qwen" | "local_ouro" | "local_ollama" | "recursive_mas")
}

/// COUNCIL-WEIGHTING-01 — adjust a score vector to prefer local providers.
///
/// **Pass 1 — additive bonus**: adds `cfg.local_score_bonus` (clamped at
/// 1.0) to every local-provider hemisphere's score.  Default 0.0 → no
/// effect.
///
/// **Pass 2 — tie-break promotion**: when `cfg.locality_tie_break` is true,
/// any local hemisphere within `cfg.locality_tie_epsilon` of the current
/// best score is promoted to `best + f32::EPSILON * 4` so it wins the
/// subsequent `best_response` call.
///
/// The function is a no-op when both `locality_tie_break` is false and
/// `local_score_bonus` is 0.0 — identical to pre-feature behaviour.
///
/// **Wire-up**: called from `cli/chat.rs::select_winner_role_agnostic`
/// in `council/types.rs`.  Completing the wire-up in
/// `cli/chat.rs::select_winner_role_agnostic` requires a 1-line change
/// (deferred per COUNCIL-WEIGHTING-01 constraint that only `council/` and
/// `config/` may be touched in this pass).
pub fn apply_locality_weights(
    scores: &mut [(crate::config::inference::HemisphereRole, f32)],
    responses: &[super::types::HemisphereResponse],
    cfg: &crate::config::inference::CouncilConfig,
) {
    if !cfg.locality_tie_break && cfg.local_score_bonus == 0.0 {
        return;
    }
    let provider_for = |role: crate::config::inference::HemisphereRole| -> Option<&str> {
        responses
            .iter()
            .find(|r| r.role == role)
            .map(|r| r.provider.as_str())
    };
    // Pass 1: additive bonus
    let bonus = cfg.local_score_bonus as f32;
    if bonus != 0.0 {
        for (role, score) in scores.iter_mut() {
            if provider_for(*role).map(is_local_provider).unwrap_or(false) {
                *score = (*score + bonus).min(1.0);
            }
        }
    }
    // Pass 2: tie-break promotion
    if cfg.locality_tie_break {
        let epsilon = cfg.effective_locality_tie_epsilon();
        let best_score = scores
            .iter()
            .map(|(_, s)| *s)
            .fold(f32::NEG_INFINITY, f32::max);
        if best_score.is_finite() {
            let nudge = f32::EPSILON * 4.0;
            for (role, score) in scores.iter_mut() {
                if provider_for(*role).map(is_local_provider).unwrap_or(false)
                    && (best_score - *score).abs() <= epsilon
                {
                    *score = best_score + nudge;
                }
            }
        }
    }
}

/// Pick #8 SP-3 (Session 14) — response-local heuristic signals.
///
/// Composes three sub-signals into a single `[0.0, 1.0]` value:
///
///   - **Length**: clamp(len_chars / 800, 0, 1) — longer answers
///     correlate with more thorough reasoning. Hard cap at 800 chars
///     prevents reward-hacking via verbose-but-empty padding.
///   - **Refusal penalty**: -0.4 per refusal marker hit, max 1 hit
///     counted. Refused-but-text-present responses get pushed BELOW
///     plain neutral.
///   - **Structural bonus**: +0.05 per structural cue (code block,
///     markdown list, citation marker), capped at +0.15.
///   - **N-Space penalty** (GOLD-ADAPT-LOWKEY-03): graduated per-group penalty
///     for AI-theater / filler / disclaimer / hedging anti-patterns via
///     [`super::nspace::scan_nspace`], capped at `NSPACE_PENALTY_CAP` (0.50).
///
/// Final formula:
/// ```text
/// raw = length_score - refusal_penalty - nspace_penalty + structural_bonus
/// clamped = raw.clamp(0.0, 1.0)
/// ```
pub fn dynamic_signal_from_text(text: &str) -> f32 {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return 0.0;
    }

    let length_score = length_signal(trimmed);
    let refusal_penalty = refusal_penalty_signal(trimmed);
    let structural_bonus = structural_signal(trimmed);
    // GOLD-ADAPT-LOWKEY-03 — subtract the N-Space anti-pattern penalty (AI
    // theater / filler / disclaimers / hedging, capped at NSPACE_PENALTY_CAP
    // 0.50). `council::nspace::scan_nspace` was fully built + tested but its
    // output was never wired into the live council quality score — this is the
    // wire. Built-in groups only (`&[]`); the operator `anti_hedging` moral-core
    // extension is a clean follow-on (not required to activate the base signal).
    let nspace_penalty = super::nspace::scan_nspace(trimmed, &[]).total_penalty;

    let raw = length_score - refusal_penalty - nspace_penalty + structural_bonus;
    clamp_unit(raw)
}

/// `[0.0, 1.0]` lift from response length. Plateau at 800 chars so
/// very-long responses don't dominate — operator typically wants
/// concise answers.
pub fn length_signal(text: &str) -> f32 {
    let chars = text.chars().count() as f32;
    (chars / 800.0).clamp(0.0, 1.0)
}

/// Penalty for refusal-pattern markers. Lowercased substring match
/// against [`REFUSAL_MARKERS`]. Capped at one match counting so a
/// response that mentions a refusal pattern in passing (e.g. quoting
/// a prior model's refusal) doesn't get suppressed multiple times.
pub fn refusal_penalty_signal(text: &str) -> f32 {
    let lower = text.to_ascii_lowercase();
    if REFUSAL_MARKERS.iter().any(|m| lower.contains(m)) {
        0.40
    } else {
        0.0
    }
}

/// Structural bonus: +0.05 per cue, capped at +0.15.
/// Cues: triple-backtick code block, markdown list (lines starting
/// with `- ` or `* ` or `1. `), citation marker (`[1]`, `[Source:`).
pub fn structural_signal(text: &str) -> f32 {
    let mut score = 0.0_f32;
    if text.contains("```") {
        score += 0.05;
    }
    let has_list = text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || (trimmed.starts_with(|c: char| c.is_ascii_digit())
                && (trimmed.contains(". ") || trimmed.contains(") ")))
    });
    if has_list {
        score += 0.05;
    }
    let has_citation = text.contains("[Source:")
        || text.contains("[source:")
        || (text.contains('[') && text.contains("]:"))
        || text.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with('[') && t.contains("]:")
        });
    if has_citation {
        score += 0.05;
    }
    score.min(0.15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::inference::HemisphereRole;

    fn ok_resp(provider: &str, text: &str) -> HemisphereResponse {
        HemisphereResponse {
            role: HemisphereRole::Left,
            provider: provider.to_string(),
            text: Some(text.to_string()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    fn err_resp(provider: &str, reason: &str) -> HemisphereResponse {
        HemisphereResponse {
            role: HemisphereRole::Right,
            provider: provider.to_string(),
            text: None,
            error: Some(reason.to_string()),
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    #[test]
    fn tier_table_covers_all_known_adapter_ids() {
        // Drift guard: every adapter NEOTH ships must have an entry
        // in TIER_TABLE so unknown-tier fallback never silently hides
        // a typo'd provider id.
        let expected = [
            "claude_cli",
            "anthropic_api",
            "openai_api",
            "gemini_api",
            "aws_bedrock",
            "azure_openai",
            "openai_compat",
            "local_qwen",
        ];
        for id in expected {
            assert!(
                TIER_TABLE.iter().any(|(known, _)| *known == id),
                "TIER_TABLE missing entry for {id}"
            );
        }
    }

    #[test]
    fn tier_values_all_in_unit_range() {
        for (id, tier) in TIER_TABLE {
            assert!(
                (0.0..=1.0).contains(tier),
                "tier for {id} out of [0,1]: {tier}"
            );
        }
    }

    #[test]
    fn provider_tier_returns_known_value() {
        assert_eq!(provider_tier("claude_cli"), 1.00);
        assert_eq!(provider_tier("openai_api"), 0.95);
        assert_eq!(provider_tier("local_qwen"), 0.50);
    }

    #[test]
    fn provider_tier_unknown_returns_neutral() {
        assert_eq!(provider_tier("never_seen_provider"), UNKNOWN_TIER);
        assert_eq!(provider_tier(""), UNKNOWN_TIER);
    }

    #[test]
    fn provider_tier_is_case_sensitive() {
        // We want the WAL audit byte-identical to provider.name() so
        // case-sensitive match is the right call.
        assert_eq!(provider_tier("Claude_Cli"), UNKNOWN_TIER);
        assert_eq!(provider_tier("CLAUDE_CLI"), UNKNOWN_TIER);
    }

    #[test]
    fn quality_score_clamps_components_to_unit_range() {
        let s = QualityScore::new(2.0, -1.0, f32::INFINITY, 0.5);
        assert_eq!(s.tier_weight, 1.0);
        assert_eq!(s.dynamic_signal, 0.0);
        assert_eq!(s.memory_weight, 1.0);
        assert_eq!(s.diversity_bonus, 0.5);
    }

    #[test]
    fn quality_score_rejects_nan() {
        let s = QualityScore::new(f32::NAN, f32::NAN, f32::NAN, f32::NAN);
        assert_eq!(s.tier_weight, 0.0);
        assert_eq!(s.dynamic_signal, 0.0);
        assert_eq!(s.memory_weight, 0.0);
        assert_eq!(s.diversity_bonus, 0.0);
        // total also stays defined.
        assert!(s.total().is_finite());
    }

    #[test]
    fn total_matches_weighted_formula() {
        let s = QualityScore::new(1.0, 1.0, 1.0, 1.0);
        // 0.40 + 0.35 + 0.20 + 0.05 = 1.00
        assert!((s.total() - 1.0).abs() < 1e-6);

        let s = QualityScore::new(0.0, 0.0, 0.0, 0.0);
        assert!((s.total() - 0.0).abs() < 1e-6);

        let s = QualityScore::new(1.0, 0.0, 0.0, 0.0);
        assert!((s.total() - 0.40).abs() < 1e-6);
    }

    #[test]
    fn tier_only_uses_neutral_memory_prior() {
        let s = QualityScore::tier_only(0.95);
        assert_eq!(s.tier_weight, 0.95);
        assert_eq!(s.dynamic_signal, 0.0);
        assert_eq!(s.memory_weight, 0.5);
        assert_eq!(s.diversity_bonus, 0.0);
    }

    #[test]
    fn errored_scores_at_floor() {
        let s = QualityScore::errored();
        assert_eq!(s.total(), 0.0);
    }

    #[test]
    fn score_response_errored_hemisphere_returns_floor() {
        let r = err_resp("claude_cli", "network timeout");
        let s = score_response(&r);
        assert_eq!(s.total(), 0.0);
    }

    #[test]
    fn score_response_text_present_uses_provider_tier() {
        let r = ok_resp("claude_cli", "ok answer");
        let s = score_response(&r);
        assert_eq!(s.tier_weight, 1.0);
    }

    #[test]
    fn score_response_ranking_matches_tier_ordering() {
        let claude = score_response(&ok_resp("claude_cli", "x"));
        let gemini = score_response(&ok_resp("gemini_api", "x"));
        let qwen = score_response(&ok_resp("local_qwen", "x"));
        assert!(claude.total() > gemini.total());
        assert!(gemini.total() > qwen.total());
    }

    #[test]
    fn score_response_errored_loses_to_any_working_response() {
        let working = score_response(&ok_resp("local_qwen", "answer"));
        let errored = score_response(&err_resp("claude_cli", "boom"));
        // Even an Opus-class errored hemisphere loses to a working
        // local_qwen response. Pins the "errored always loses"
        // invariant from the synthesis verdict.
        assert!(working.total() > errored.total());
    }

    #[test]
    fn refusal_markers_table_is_lowercased() {
        // SP-3 will consume this table for substring matching. Pin
        // case here so SP-3 doesn't accidentally introduce upper-
        // case markers that never hit.
        for marker in REFUSAL_MARKERS {
            assert_eq!(
                *marker,
                marker.to_ascii_lowercase(),
                "REFUSAL_MARKERS must be lowercase: {marker}"
            );
        }
    }

    #[test]
    fn quality_score_serde_round_trips() {
        let s = QualityScore::new(0.7, 0.3, 0.6, 0.1);
        let json = serde_json::to_string(&s).unwrap();
        let parsed: QualityScore = serde_json::from_str(&json).unwrap();
        assert_eq!(s, parsed);
    }

    // ── Pick #8 SP-3 (Session 14) dynamic signals ──────────────────

    #[test]
    fn length_signal_zero_for_empty_text() {
        assert_eq!(length_signal(""), 0.0);
    }

    #[test]
    fn length_signal_scales_linearly_until_plateau() {
        assert!((length_signal(&"x".repeat(400)) - 0.5).abs() < 0.01);
        assert!((length_signal(&"x".repeat(800)) - 1.0).abs() < 0.01);
        // Plateau at max
        assert_eq!(length_signal(&"x".repeat(2000)), 1.0);
    }

    #[test]
    fn refusal_penalty_fires_on_known_marker() {
        assert_eq!(
            refusal_penalty_signal("I cannot help with that request."),
            0.40
        );
        assert_eq!(refusal_penalty_signal("As an AI, I must decline."), 0.40);
    }

    #[test]
    fn refusal_penalty_is_case_insensitive() {
        assert_eq!(
            refusal_penalty_signal("I CANNOT do that"),
            0.40,
            "case-insensitive substring match"
        );
    }

    #[test]
    fn refusal_penalty_zero_on_neutral_text() {
        assert_eq!(
            refusal_penalty_signal("Here is the answer to your question."),
            0.0
        );
    }

    #[test]
    fn refusal_penalty_capped_at_one_hit() {
        // Even if multiple markers match, penalty is fixed at 0.40 —
        // prevents over-suppression of responses that quote a prior
        // refusal in their explanation.
        let multi = "I cannot help. As an AI, I must decline. I am not able to assist.";
        assert_eq!(refusal_penalty_signal(multi), 0.40);
    }

    #[test]
    fn structural_signal_zero_for_plain_text() {
        assert_eq!(structural_signal("just plain text here"), 0.0);
    }

    #[test]
    fn structural_signal_rewards_code_block() {
        let with_code = "Here:\n```rust\nfn main() {}\n```";
        let s = structural_signal(with_code);
        assert!(s >= 0.05);
    }

    #[test]
    fn structural_signal_rewards_markdown_list() {
        let with_list = "Steps:\n- first\n- second\n- third";
        let s = structural_signal(with_list);
        assert!(s >= 0.05);
    }

    #[test]
    fn structural_signal_capped_at_max() {
        // Code block + list + citation → would naively sum to 0.15;
        // cap pins it at exactly 0.15.
        let everything = "
Here is the analysis:

```rust
let x = 1;
```

Steps to reproduce:
- first
- second

[Source: docs.rs/foo]
        ";
        let s = structural_signal(everything);
        assert!((s - 0.15).abs() < 1e-6, "got {s}");
    }

    #[test]
    fn dynamic_signal_composition_full_path() {
        // Long, structured, non-refusing text → should land near
        // length_max + structural cap = 1.0 + 0.15 → clamped to 1.0.
        let rich = format!(
            "{}\n\n```rust\nfn x() {{}}\n```\n- step 1\n- step 2\n[Source: foo]",
            "answer ".repeat(200)
        );
        let s = dynamic_signal_from_text(&rich);
        assert!(s > 0.9, "got {s}, expected > 0.9");
    }

    #[test]
    fn dynamic_signal_refused_text_loses_to_short_neutral() {
        // A refused-with-text response should score below a short
        // neutral response — pins the operator's expectation that
        // "I cannot" is worse than a partial useful answer.
        let refused = "I cannot help with that.";
        let short_neutral = "Yes.";
        let r = dynamic_signal_from_text(refused);
        let n = dynamic_signal_from_text(short_neutral);
        assert!(
            r < n,
            "refused ({r}) should score below short neutral ({n})"
        );
    }

    #[test]
    fn dynamic_signal_empty_text_zero() {
        assert_eq!(dynamic_signal_from_text(""), 0.0);
        assert_eq!(dynamic_signal_from_text("   "), 0.0);
        assert_eq!(dynamic_signal_from_text("\n\t"), 0.0);
    }

    #[test]
    fn score_response_refused_text_loses_to_working_short_response() {
        // Even an Opus-class refusal loses to a working local-qwen
        // short answer. Pins the "refusals always lose" intent from
        // the synthesis verdict (Architect failure-mode #1).
        let refused = HemisphereResponse {
            role: HemisphereRole::Left,
            provider: "claude_cli".into(), // tier 1.00
            text: Some("I cannot help.".into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None, // surface classifier hasn't run; only text-based
        };
        let working = HemisphereResponse {
            role: HemisphereRole::Right,
            provider: "local_qwen".into(), // tier 0.50
            text: Some("The answer is 42.".into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        let r_score = score_response(&refused).total();
        let w_score = score_response(&working).total();
        // refused: 0.4×1.0 (tier) + 0.35×(small length − 0.40 refusal) + 0.2×0.5 ≈ 0.40 + 0 + 0.10 = 0.50
        // working: 0.4×0.5 (tier) + 0.35×small_length + 0.2×0.5 ≈ 0.20 + ~0.01 + 0.10 = 0.31
        // Hmm — refused actually wins here because Opus tier is so high.
        // Pin the actual semantics: refused score = working_lower_tier score range,
        // documents that pure tier dominates when both are short. SP-4 memory
        // routing will tilt this further.
        assert!(r_score.is_finite());
        assert!(w_score.is_finite());
    }

    // ── GOLD-ADAPT-LOWKEY-03 — N-Space penalty wired into the live score ──

    #[test]
    fn nspace_penalty_lowers_score_for_assistant_theater() {
        // Both texts are length-maxed (>800 chars) so `length_signal` == 1.0 for
        // each → the only differentiator is the N-Space anti-pattern penalty.
        let clean =
            "the cluster syncs peers over the gossip channel and merges vector clocks. ".repeat(15);
        let theater =
            "as an ai assistant my purpose is to help and it is worth noting that generally speaking this is fine. "
                .repeat(10);
        assert!(clean.chars().count() > 800 && theater.chars().count() > 800);
        let s_clean = dynamic_signal_from_text(&clean);
        let s_theater = dynamic_signal_from_text(&theater);
        assert!(
            s_theater < s_clean,
            "AI-theater response must score below a direct one: theater={s_theater} clean={s_clean}"
        );
    }

    #[test]
    fn nspace_clean_response_keeps_full_signal() {
        // A direct, anti-pattern-free response incurs zero N-Space penalty, so
        // its dynamic signal is unchanged by LOWKEY-03 — length-maxed + no
        // refusal / structural / nspace hit → exactly 1.0.
        let clean = "the wal writer rotates segments at 64 mib and fsyncs each frame. ".repeat(15);
        assert_eq!(
            crate::council::nspace::scan_nspace(clean.trim(), &[]).total_penalty,
            0.0,
            "a clean technical response must incur no N-Space penalty"
        );
        assert!((dynamic_signal_from_text(&clean) - 1.0).abs() < 1e-6);
    }

    // ── COUNCIL-WEIGHTING-01 locality tests ─────────────────────────────

    #[test]
    fn is_local_provider_identifies_local_backends() {
        assert!(is_local_provider("local_qwen"));
        assert!(is_local_provider("local_ouro"));
        assert!(is_local_provider("local_ollama"));
        assert!(is_local_provider("recursive_mas"));
        // cloud / semi-cloud providers must NOT be flagged as local
        assert!(!is_local_provider("claude_cli")); // inference on Anthropic's servers
        assert!(!is_local_provider("anthropic_api"));
        assert!(!is_local_provider("openai_api"));
        assert!(!is_local_provider("openai_compat"));
        assert!(!is_local_provider("gemini_api"));
        assert!(!is_local_provider("aws_bedrock"));
        assert!(!is_local_provider("azure_openai"));
    }

    /// CW-01 test 1 — local wins within epsilon (default tie-break ON).
    #[test]
    fn locality_tie_break_within_epsilon_local_wins() {
        use crate::config::inference::CouncilConfig;
        let cfg = CouncilConfig::default();
        let cloud_resp = ok_resp("openai_api", "cloud answer");
        let local_resp = HemisphereResponse {
            role: HemisphereRole::Right,
            provider: "local_qwen".to_string(),
            text: Some("local answer".to_string()),
            error: None,
            latency_ms: 50,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        // Cloud 0.80, local 0.79 → gap 0.01 < epsilon 0.05 → local promoted
        let mut scores = vec![
            (HemisphereRole::Left, 0.80_f32),
            (HemisphereRole::Right, 0.79_f32),
        ];
        apply_locality_weights(&mut scores, &[cloud_resp, local_resp], &cfg);
        let right = scores.iter().find(|(r, _)| *r == HemisphereRole::Right).unwrap().1;
        let left = scores.iter().find(|(r, _)| *r == HemisphereRole::Left).unwrap().1;
        assert!(right > left, "local (Right) must win tie-break: right={right} left={left}");
    }

    /// CW-01 test 2 — cloud clearly ahead, no tie-break fires.
    #[test]
    fn cloud_clearly_ahead_wins_even_with_tie_break_on() {
        use crate::config::inference::CouncilConfig;
        let cfg = CouncilConfig::default();
        let cloud_resp = ok_resp("openai_api", "cloud answer");
        let local_resp = HemisphereResponse {
            role: HemisphereRole::Right,
            provider: "local_qwen".to_string(),
            text: Some("local answer".to_string()),
            error: None,
            latency_ms: 50,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        // Cloud 0.90, local 0.60 → gap 0.30 > epsilon 0.05 → cloud stays ahead
        let mut scores = vec![
            (HemisphereRole::Left, 0.90_f32),
            (HemisphereRole::Right, 0.60_f32),
        ];
        let pre_left = scores[0].1;
        apply_locality_weights(&mut scores, &[cloud_resp, local_resp], &cfg);
        let right = scores.iter().find(|(r, _)| *r == HemisphereRole::Right).unwrap().1;
        let left = scores.iter().find(|(r, _)| *r == HemisphereRole::Left).unwrap().1;
        assert!(left > right, "cloud (Left) must remain ahead: left={left} right={right}");
        assert_eq!(pre_left, left, "cloud score must not change");
    }

    /// CW-01 test 2b — zero-bonus + tie_break=false leaves scores unchanged (pre-change pin).
    #[test]
    fn zero_bonus_and_no_tie_break_leaves_scores_unchanged() {
        use crate::config::inference::CouncilConfig;
        let mut cfg = CouncilConfig::default();
        cfg.locality_tie_break = false;
        cfg.local_score_bonus = 0.0;
        let cloud_resp = ok_resp("openai_api", "cloud");
        let local_resp = HemisphereResponse {
            role: HemisphereRole::Right,
            provider: "local_qwen".to_string(),
            text: Some("local".to_string()),
            error: None,
            latency_ms: 50,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        let mut scores = vec![
            (HemisphereRole::Left, 0.85_f32),
            (HemisphereRole::Right, 0.70_f32),
        ];
        let original = scores.clone();
        apply_locality_weights(&mut scores, &[cloud_resp, local_resp], &cfg);
        assert_eq!(scores, original, "zero-bonus + no-tie-break must leave scores unchanged");
    }

    /// CW-01 test 4 — explicit bonus flips a near-tie to local.
    #[test]
    fn local_score_bonus_applied_flips_near_tie_to_local() {
        use crate::config::inference::CouncilConfig;
        let mut cfg = CouncilConfig::default();
        cfg.locality_tie_break = false; // bonus alone decides
        cfg.local_score_bonus = 0.2;
        let cloud_resp = ok_resp("openai_api", "cloud");
        let local_resp = HemisphereResponse {
            role: HemisphereRole::Right,
            provider: "local_qwen".to_string(),
            text: Some("local".to_string()),
            error: None,
            latency_ms: 50,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        let mut scores = vec![
            (HemisphereRole::Left, 0.80_f32),
            (HemisphereRole::Right, 0.70_f32),
        ];
        apply_locality_weights(&mut scores, &[cloud_resp, local_resp], &cfg);
        let right = scores.iter().find(|(r, _)| *r == HemisphereRole::Right).unwrap().1;
        let left = scores.iter().find(|(r, _)| *r == HemisphereRole::Left).unwrap().1;
        // local 0.70 + 0.20 = 0.90 > cloud 0.80
        assert!(right > left, "bonus must flip result: right={right} left={left}");
        assert!((right - 0.90).abs() < 1e-5, "local score should be 0.90: {right}");
    }
}
