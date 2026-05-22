//! L-08 — `neoth privacy audit` CLI.
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` BATCH-5 + the
//! local-Qwen P2 audit (R2-P2-2). Reports the operator's privacy
//! posture in one place so they see — before sending a prompt —
//! whether the next chat will hit a cloud provider, whether profile
//! learning is active, whether channel adapters carry inbound
//! receive loops, and whether WAL frames carry redaction.
//!
//! Pure read-only: loads `~/.neoth/freedom.yaml` + `credentials.yaml`,
//! classifies provider kinds, reports findings. No network call,
//! no mutation.
//!
//! Output respects the global `--output` flag.

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::credentials::Credentials;

#[derive(Args, Debug, Clone)]
pub struct PrivacyArgs {
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// One privacy finding the audit surfaces. `severity` = info | warn |
/// pii — operator-facing colour coding.
#[derive(Clone, Debug, Serialize)]
pub struct PrivacyFinding {
    pub category: &'static str,
    pub severity: &'static str,
    pub status: String,
    pub detail: String,
}

pub async fn run_privacy(args: PrivacyArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let creds = Credentials::load_or_default(&crate::config::credentials::default_path())
        .unwrap_or_default();
    let findings = audit_posture(&cfg, &creds);
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
        OutputFormat::Jsonl => {
            for f in &findings {
                println!("{}", serde_json::to_string(f)?);
            }
        }
        OutputFormat::Table => {
            println!("# `neoth privacy audit` — operator privacy posture\n");
            for f in &findings {
                println!("[{}] {}:", f.severity.to_uppercase(), f.category);
                println!("    {}", f.status);
                if !f.detail.is_empty() {
                    for line in f.detail.lines() {
                        println!("    {line}");
                    }
                }
                println!();
            }
            println!(
                "Run `neoth glossary --term <name>` for any term above you don't recognise."
            );
        }
    }
    Ok(())
}

/// L-08 pure-function audit. Takes the loaded config + creds and
/// returns the list of findings. Pure so it's straightforward to
/// test against synthetic configs.
pub fn audit_posture(
    cfg: &FreedomConfig,
    creds: &Credentials,
) -> Vec<PrivacyFinding> {
    let mut out = Vec::new();

    // ── Provider ──────────────────────────────────────────────────────
    // ProviderKind serialises snake_case via serde — pull the wire
    // form by round-tripping. No `as_str()` impl, but serde gives
    // us the canonical id.
    let provider_owned = cfg
        .provider_kind
        .as_ref()
        .and_then(|p| serde_json::to_string(p).ok())
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| "local_qwen".to_string());
    let provider = provider_owned.as_str();
    let cloud_provider = provider != "local_qwen";
    out.push(PrivacyFinding {
        category: "provider",
        severity: if cloud_provider { "warn" } else { "info" },
        status: format!(
            "Default provider: `{}` ({})",
            provider,
            if cloud_provider { "CLOUD" } else { "LOCAL ONLY" }
        ),
        detail: if cloud_provider {
            format!(
                "Every chat call posts your prompt to `{provider}`'s servers. \
                 Switch via `neoth providers select local_qwen` for an offline-only path."
            )
        } else {
            "Every chat call stays on this machine — no network egress for inference.".into()
        },
    });

    // ── Profile learning ──────────────────────────────────────────────
    let learn_enabled = cfg.profile.learn_enabled;
    let learn_provider = cfg.profile.learn_provider.as_deref().unwrap_or(provider);
    let learn_is_cloud = learn_provider != "local_qwen";
    out.push(PrivacyFinding {
        category: "profile-learning",
        severity: if !learn_enabled {
            "info"
        } else if learn_is_cloud {
            "warn"
        } else {
            "info"
        },
        status: format!(
            "Profile learning: {} (provider: `{}`)",
            if learn_enabled { "ENABLED" } else { "DISABLED" },
            learn_provider,
        ),
        detail: if learn_enabled && learn_is_cloud {
            format!(
                "Each chat reply triggers a Stage-3 extract LLM call to `{learn_provider}`. \
                 That's a SECOND cloud call per reply. Set `profile.learn_provider: local_qwen` \
                 to keep this offline, or `profile.learn_enabled: false` to disable entirely."
            )
        } else if learn_enabled {
            "Stage-3 extract runs on local_qwen — no cloud touches.".into()
        } else {
            "No automatic profile extraction. Operator-facts only grow via explicit \
             `neoth groundtruth add` calls."
                .into()
        },
    });

    // ── Cloud fallback ────────────────────────────────────────────────
    if cfg.profile.allow_cloud_fallback {
        out.push(PrivacyFinding {
            category: "cloud-fallback",
            severity: "warn",
            status:
                "Profile-learn cloud fallback: ENABLED (L-07 `allow_cloud_fallback: true`)"
                    .to_string(),
            detail: "When the configured `learn_provider` is unavailable (local weights \
                     missing / hardware issue), NEOTH falls back to your main provider — \
                     which posts the prompt to a cloud endpoint. Flip to false to fail \
                     closed instead."
                .into(),
        });
    }

    // ── Channel credentials ────────────────────────────────────────────
    let mut channels: Vec<&'static str> = Vec::new();
    if creds.telegram_token.is_some() {
        channels.push("telegram");
    }
    if creds.slack_bot_token.is_some() || creds.slack_app_token.is_some() {
        channels.push("slack");
    }
    if creds.whatsapp_token.is_some() {
        channels.push("whatsapp");
    }
    out.push(PrivacyFinding {
        category: "channels",
        severity: if channels.is_empty() { "info" } else { "warn" },
        status: format!(
            "Configured channels: {}",
            if channels.is_empty() {
                "none".to_string()
            } else {
                channels.join(", ")
            }
        ),
        detail: if channels.is_empty() {
            "Daemon runs in CLI-only mode. No third-party messenger sees your prompts.".into()
        } else {
            format!(
                "Each configured channel relays your messages to a third-party server \
                 ({}). Run `neoth doctor channels` to see which channels are LIVE inbound \
                 vs OUTBOUND-ONLY. Tokens live at `~/.neoth/credentials.yaml` (mode 0600).",
                channels.join(" / ")
            )
        },
    });

    // ── WAL audit + redaction ─────────────────────────────────────────
    out.push(PrivacyFinding {
        category: "audit-trail",
        severity: "info",
        status: "WAL at `~/.neoth/wal/*.wal` records every action (HMAC-SHA256 sealed)"
            .into(),
        detail: "Operator-private — file mode 0600 on unix, owner-only DACL on Windows. \
                 `neoth wal show` to inspect. Credentials in `PRE_MUTATION_SNAPSHOT` \
                 frames are redacted (K-Sec-5) — `provider_key: sk-...` becomes \
                 `[REDACTED:openai_key]` before bytes touch disk."
            .into(),
    });

    // ── HMAC key DPAPI wrap (Windows-only) ────────────────────────────
    #[cfg(windows)]
    out.push(PrivacyFinding {
        category: "wal-tamper-evidence",
        severity: "info",
        status: "HMAC key DPAPI-wrapped on Windows (K-Sec-4)".into(),
        detail: "`~/.neoth/wal/hmac.key` is wrapped via CryptProtectData, bound to your \
                 Windows user account. A copy of the file lifted off the box is useless \
                 outside your session — attackers can't forge `0x15 COMPACTION_MARKER` \
                 frames."
            .into(),
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credentials::Credentials;
    use crate::secret::SecretString;

    fn cfg_with(provider: &str, learn_enabled: bool, learn_provider: Option<&str>) -> FreedomConfig {
        use crate::cli::init::ProviderKind;
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(match provider {
            "local_qwen" => ProviderKind::LocalQwen,
            "openai_api" => ProviderKind::OpenaiApi,
            _ => ProviderKind::LocalQwen,
        });
        cfg.profile.learn_enabled = learn_enabled;
        cfg.profile.learn_provider = learn_provider.map(|s| s.to_string());
        cfg
    }

    #[test]
    fn audit_reports_local_only_when_provider_is_local_qwen() {
        let cfg = cfg_with("local_qwen", false, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let provider_finding = findings.iter().find(|f| f.category == "provider").unwrap();
        assert_eq!(provider_finding.severity, "info");
        assert!(provider_finding.status.contains("LOCAL ONLY"));
    }

    #[test]
    fn audit_warns_when_provider_is_cloud() {
        let cfg = cfg_with("openai_api", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let provider_finding = findings.iter().find(|f| f.category == "provider").unwrap();
        assert_eq!(provider_finding.severity, "warn");
        assert!(provider_finding.status.contains("CLOUD"));
    }

    #[test]
    fn audit_warns_when_profile_learn_uses_cloud() {
        let cfg = cfg_with("local_qwen", true, Some("openai_api"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let pf = findings
            .iter()
            .find(|f| f.category == "profile-learning")
            .unwrap();
        assert_eq!(pf.severity, "warn");
        assert!(pf.status.contains("openai_api"));
    }

    #[test]
    fn audit_info_when_profile_learn_uses_local() {
        let cfg = cfg_with("openai_api", true, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let pf = findings
            .iter()
            .find(|f| f.category == "profile-learning")
            .unwrap();
        assert_eq!(pf.severity, "info");
        assert!(pf.status.contains("local_qwen"));
    }

    #[test]
    fn audit_lists_no_channels_when_credentials_empty() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let ch = findings.iter().find(|f| f.category == "channels").unwrap();
        assert_eq!(ch.severity, "info");
        assert!(ch.status.contains("none"));
    }

    #[test]
    fn audit_warns_and_lists_configured_channels() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials {
            telegram_token: Some(SecretString::from("123:abc")),
            slack_bot_token: Some(SecretString::from("xoxb-test")),
            ..Default::default()
        };
        let findings = audit_posture(&cfg, &creds);
        let ch = findings.iter().find(|f| f.category == "channels").unwrap();
        assert_eq!(ch.severity, "warn");
        assert!(ch.status.contains("telegram"));
        assert!(ch.status.contains("slack"));
    }

    #[test]
    fn audit_surfaces_cloud_fallback_when_enabled() {
        let mut cfg = cfg_with("local_qwen", true, Some("local_qwen"));
        cfg.profile.allow_cloud_fallback = true;
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(findings.iter().any(|f| f.category == "cloud-fallback"));
    }

    #[test]
    fn audit_omits_cloud_fallback_finding_when_disabled() {
        let cfg = cfg_with("local_qwen", true, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(!findings.iter().any(|f| f.category == "cloud-fallback"));
    }

    #[test]
    fn audit_always_includes_wal_audit_trail_row() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(findings.iter().any(|f| f.category == "audit-trail"));
    }
}
