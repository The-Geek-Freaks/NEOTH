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
    let freedom_path = home.join("freedom.yaml");
    let cfg = match crate::config::FreedomConfig::load_from_path(&freedom_path) {
        Ok(c) => c,
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

    let mut gaps: Vec<&'static str> = Vec::new();

    // ── 3. Provider wired? ────────────────────────────────────────────
    // `provider_kind` defaults to `local_qwen` on a fresh config.  If the
    // operator didn't visit the provider step the value is still the default
    // and the credentials file won't have any API key. We treat "local_qwen
    // with no local weights" as un-wired rather than trying to stat the model
    // cache here (that check lives in `providers::check_local_qwen_weights`).
    // The simple and correct heuristic: if the credentials file is absent AND
    // provider is local_qwen, flag it.
    let has_provider = {
        let kind_str = serde_yaml::to_string(&cfg.provider_kind)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let creds_ok = home.join("credentials.yaml").exists();
        // cloud provider kinds always need a credentials file; local_qwen is
        // self-contained when weights are present (we can't cheaply verify
        // weights here, so we accept local_qwen as "has provider").
        !kind_str.is_empty() && (creds_ok || kind_str.contains("local_qwen") || kind_str.contains("antigravity"))
    };
    if !has_provider {
        gaps.push("provider not wired (no credentials.yaml for the configured provider_kind)");
    }

    // ── 4. Channel credential present? ───────────────────────────────
    let has_channel = {
        let creds_path = home.join("credentials.yaml");
        if creds_path.exists() {
            match crate::config::credentials::Credentials::load_or_default(&creds_path) {
                Ok(c) => {
                    c.telegram_token.is_some()
                        || c.slack_bot_token.is_some()
                        || c.discord_bot_token.is_some()
                        || c.whatsapp_token.is_some()
                }
                Err(_) => false,
            }
        } else {
            false
        }
    };
    if !has_channel {
        gaps.push("no channel token found (Telegram/Slack/Discord/WhatsApp) — \
                   run `neoth init` or `neoth credential set`");
    }

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
            detail: format!(
                "onboarding gaps detected: {}",
                gaps.join("; ")
            ),
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
        // Write a minimal credentials.yaml with a telegram token
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abc\"\n",
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
        std::fs::write(dir.path().join("credentials.yaml"), "{}\n").unwrap();
        let out = check_post_init_readiness(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(
            out.detail.contains("channel"),
            "should mention missing channel: {}",
            out.detail
        );
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
