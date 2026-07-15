//! GOLD-FEAT-11 — post-init readiness check.
//!
//! Surfaces onboarding gaps that remain after `neoth init` completes:
//! no provider wired, no channel token, autonomy still at the wizard
//! default. These are not hard failures (the daemon boots) but they
//! leave the operator in a degraded state where the most-advertised
//! features don't work.
//!
//! The check also powers the post-init proactive item enqueued by
//! `daemon::post_init_cron`: the same status logic drives both paths
//! so the doctor surface and the proactive nudge always agree.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// GOLD-FEAT-11 — verify that the operator completed the three
/// non-negotiable post-init steps: a provider kind is set, at least
/// one channel credential is present, and autonomy is not still at
/// the hard-coded wizard default of `"standard"` (the wizard always
/// writes `standard`; if it's still there the operator never visited
/// the autonomy step).
pub(crate) fn check_post_init_readiness(home: &Path) -> CheckOutcome {
    // ── 1. Is init complete at all? ───────────────────────────────────
    let initialized_marker = home.join(".initialized");
    if !initialized_marker.exists() {
        return CheckOutcome {
            name: "post-init readiness",
            status: CheckStatus::Warn,
            detail: "neoth init has not been completed yet — run `neoth init` to set up \
                     your provider, channel, and autonomy level"
                .into(),
        };
    }

    // ── 2. freedom.yaml — provider kind present? ─────────────────────
    let readiness = match crate::cli::onboarding_readiness::load(home) {
        Ok((_, readiness)) => readiness,
        Err(_) => {
            // freedom.yaml missing or unparseable — other checks (config domain)
            // already surface this as a Fail. Return a contextual Warn here
            // rather than a redundant error.
            return CheckOutcome {
                name: "post-init readiness",
                status: CheckStatus::Warn,
                detail: "freedom.yaml absent or unreadable — cannot evaluate post-init \
                         readiness. Run `neoth init` to create it."
                    .into(),
            };
        }
    };

    let gaps = readiness.gaps();

    // ── 5. Synthesise result ─────────────────────────────────────────
    if gaps.is_empty() {
        CheckOutcome {
            name: "post-init readiness",
            status: CheckStatus::Pass,
            detail: "provider wired, channel token present — ready for `neoth serve`".into(),
        }
    } else {
        CheckOutcome {
            name: "post-init readiness",
            status: CheckStatus::Warn,
            detail: format!("onboarding gaps detected: {}", gaps.join("; ")),
        }
    }
}

pub(crate) const CHECKS: &[CheckFn] = &[check_post_init_readiness];

pub(crate) const DOCS: &[CheckDoc] = &[CheckDoc {
    name: "post-init readiness",
    purpose: "Verifies that the three post-`neoth init` steps are complete: \
              a provider is wired (API key / local weights), at least one \
              messaging-channel token is present, and the initialized marker \
              file exists. Without these, `neoth serve` boots but proactive \
              delivery and channel inbound are silently dead.",
    common_failures: "Operator ran `neoth init` but skipped the provider or \
                      channel step; credentials.yaml absent; \
                      `.initialized` marker file deleted.",
    fix: "Run `neoth init` to complete the wizard; or `neoth credential set \
          telegram <token>` to wire a channel manually; \
          `neoth provider list` to verify the configured provider.",
}];

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn no_initialized_marker_is_warn() {
        let dir = tempdir().unwrap();
        let out = check_post_init_readiness(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
        assert_eq!(out.name, "post-init readiness");
        assert!(
            out.detail.contains("neoth init"),
            "should mention neoth init: {}",
            out.detail
        );
    }

    #[test]
    fn initialized_marker_with_no_config_is_warn() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        let out = check_post_init_readiness(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
    }

    #[test]
    fn passes_when_initialized_and_credentials_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        // Write a minimal freedom.yaml with a non-local provider
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: test\nprovider_kind: openai_api\n",
        )
        .unwrap();
        // Both the provider key and a channel token are required for this
        // metered provider path.
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "provider_key: \"sk-test\"\ntelegram_token: \"123:abc\"\n",
        )
        .unwrap();
        let out = check_post_init_readiness(dir.path());
        assert_eq!(out.status, CheckStatus::Pass, "detail: {}", out.detail);
        assert!(out.detail.contains("ready"));
    }

    #[test]
    fn warns_when_initialized_but_no_channel() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: test\nprovider_kind: openai_api\n",
        )
        .unwrap();
        // credentials.yaml exists but no channel tokens
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "provider_key: \"sk-test\"\n",
        )
        .unwrap();
        let out = check_post_init_readiness(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(
            out.detail.contains("channel"),
            "should mention missing channel: {}",
            out.detail
        );
    }

    #[test]
    fn local_and_cli_providers_do_not_need_credentials_file() {
        for provider in ["claude_cli", "local_qwen", "local_ouro", "local_ollama"] {
            let dir = tempdir().unwrap();
            std::fs::write(dir.path().join(".initialized"), b"{}").unwrap();
            std::fs::write(
                dir.path().join("freedom.yaml"),
                format!("operator_id: test\nprovider_kind: {provider}\n"),
            )
            .unwrap();
            let out = check_post_init_readiness(dir.path());
            assert!(
                !out.detail.contains("provider"),
                "{provider} was falsely rejected: {}",
                out.detail
            );
        }
    }

    #[test]
    fn docs_cover_the_check_name() {
        // DOCS name must match the check outcome name (drift guard).
        let dir = tempdir().unwrap();
        let outcomes: Vec<_> = CHECKS.iter().map(|f| f(dir.path())).collect();
        let doc_names: std::collections::HashSet<&str> = DOCS.iter().map(|d| d.name).collect();
        for o in &outcomes {
            assert!(
                doc_names.contains(o.name),
                "check `{}` has no DOCS entry",
                o.name
            );
        }
    }
}
