//! GOLD-ADAPT-LOWKEY-07 — transparent-core debug mode.
//!
//! Layer-A is the answer the operator already sees. Layer-B is the council's
//! own reasoning surface: which hemispheres ran, what each scored, the verdict
//! + dissent, what was injected, and which hemisphere won. Off by default
//! (`council.transparent_core: false`); opt-in per-run via
//! `NEOTH_COUNCIL_DEBUG=1` or persistently via freedom.yaml.
//!
//! Rendered to STDERR so it never corrupts a piped Layer-A answer — the same
//! surface rule the LOWKEY-05 self-challenge note follows.

use crate::config::FreedomConfig;
use crate::config::inference::HemisphereRole;
use crate::council::CouncilDebate;
use crate::council::Verdict;
use crate::council::quality_score::score_response;

/// True when the transparent-core Layer-B surface should be emitted: the
/// persistent `council.transparent_core` flag OR the per-run
/// `NEOTH_COUNCIL_DEBUG=1` env override.
pub fn transparent_enabled(config: &FreedomConfig) -> bool {
    if config.council.transparent_core {
        return true;
    }
    std::env::var("NEOTH_COUNCIL_DEBUG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Render the Layer-B block for a finished debate. Pure (no I/O) so it is
/// unit-testable. `winner_role`/`winner_score` come from the dispatch path's
/// role-agnostic selection (`None` ⇒ the verdict-driven legacy path; the
/// verdict line still shows the collective outcome).
pub fn render_layer_b(
    outcome: &CouncilDebate,
    winner_role: Option<HemisphereRole>,
    winner_score: Option<f32>,
    system_bytes: usize,
    prompt_bytes: usize,
) -> String {
    let verdict = match &outcome.verdict {
        Verdict::Consensus { .. } => "consensus".to_string(),
        Verdict::Split { .. } => "split".to_string(),
        Verdict::QuorumFailed {
            responded,
            required,
        } => format!("quorum_failed ({responded}/{required})"),
    };

    let mut out = String::new();
    out.push_str("\n── council · Layer-B (transparent-core) ──\n");
    out.push_str(&format!("verdict:  {verdict}\n"));
    out.push_str(&format!("dissent:  {:.2}\n", outcome.dissent.0));
    out.push_str(&format!(
        "injected: system {system_bytes} bytes · prompt {prompt_bytes} bytes\n"
    ));
    out.push_str("hemispheres:\n");
    for r in &outcome.responses {
        let score = score_response(r).total();
        let state = if r.text.is_some() {
            match &r.refusal {
                Some(rf) => format!("refusal={:?}({})", rf.class, rf.class_confidence),
                None => "ok".to_string(),
            }
        } else {
            format!("errored: {}", r.error.as_deref().unwrap_or("unknown"))
        };
        out.push_str(&format!(
            "  [{:?}] provider={} score={:.2} latency={}ms {}\n",
            r.role, r.provider, score, r.latency_ms, state
        ));
    }
    match winner_role {
        Some(role) => out.push_str(&format!(
            "winner:   {:?} (score {:.2})\n",
            role,
            winner_score.unwrap_or(0.0)
        )),
        None => out.push_str("winner:   verdict-driven (legacy selection)\n"),
    }
    out
}

/// If transparent-core is enabled, render + print the Layer-B block to STDERR.
/// No-op (zero overhead beyond the flag check) when disabled.
pub fn maybe_emit_layer_b(
    config: &FreedomConfig,
    outcome: &CouncilDebate,
    winner_role: Option<HemisphereRole>,
    winner_score: Option<f32>,
    req: &crate::providers::Request,
) {
    if !transparent_enabled(config) {
        return;
    }
    let system_bytes = req.system.as_deref().map(str::len).unwrap_or(0);
    eprint!(
        "{}",
        render_layer_b(
            outcome,
            winner_role,
            winner_score,
            system_bytes,
            req.prompt.len()
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::council::dissent::DissentScore;
    use crate::council::types::HemisphereResponse;

    fn resp(role: HemisphereRole, provider: &str, text: Option<&str>) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: provider.to_string(),
            text: text.map(str::to_string),
            error: if text.is_none() {
                Some("timeout".to_string())
            } else {
                None
            },
            latency_ms: 1200,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    fn debate(verdict: Verdict, responses: Vec<HemisphereResponse>) -> CouncilDebate {
        CouncilDebate {
            factual_outcomes: Vec::new(),
            prompt_hash_xxh3: 0,
            responses,
            dissent: DissentScore(0.25),
            verdict,
            total_latency_ms: 1500,
        }
    }

    #[test]
    fn render_includes_verdict_dissent_injected_and_each_hemisphere() {
        let d = debate(
            Verdict::Consensus {
                winning_text: "answer".to_string(),
            },
            vec![
                resp(HemisphereRole::Left, "claude-cli", Some("a")),
                resp(HemisphereRole::Right, "local_qwen", None),
            ],
        );
        let s = render_layer_b(&d, Some(HemisphereRole::Left), Some(0.87), 4096, 120);
        assert!(s.contains("verdict:  consensus"));
        assert!(s.contains("dissent:  0.25"));
        assert!(s.contains("injected: system 4096 bytes"));
        assert!(s.contains("prompt 120 bytes"));
        assert!(s.contains("claude-cli"), "left provider listed");
        assert!(s.contains("local_qwen"), "right provider listed");
        assert!(s.contains("errored: timeout"), "errored hemisphere shown");
        assert!(s.contains("winner:"), "winner line present");
    }

    #[test]
    fn render_quorum_failed_carries_counts_and_legacy_winner() {
        let d = debate(
            Verdict::QuorumFailed {
                responded: 1,
                required: 2,
            },
            vec![resp(HemisphereRole::Left, "claude-cli", None)],
        );
        let s = render_layer_b(&d, None, None, 0, 10);
        assert!(s.contains("quorum_failed (1/2)"));
        assert!(s.contains("verdict-driven (legacy selection)"));
    }

    #[test]
    fn transparent_disabled_by_default() {
        // With the env override unset, the default config keeps Layer-B off.
        if std::env::var("NEOTH_COUNCIL_DEBUG").is_err() {
            let cfg = FreedomConfig::default();
            assert!(!transparent_enabled(&cfg));
        }
    }
}
