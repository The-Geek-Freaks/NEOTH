//! `neoth channel list` — read-only inventory of the messaging channels and
//! whether each is configured, parallel to `neoth provider list`.
//!
//! The configured-state predicates here are the SAME ones `cli/serve.rs` uses
//! to decide whether to actually start each channel, so `list` reflects reality
//! (a channel shown CONFIGURED is one the daemon would bring up). Pure +
//! read-only: no network, no mutation, no secrets printed (only presence).
//!
//! The mutating sub-actions (`add`/`test`/`remove`) stay deferred — the
//! credential-writing + live-connection-test surfaces are their own slices.
//! `list` is the safe inventory operators ask for first ("which channels are
//! wired right now?") without grepping `freedom.yaml` + `credentials.yaml`.

use anyhow::Result;
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;
use crate::config::FreedomConfig;

/// One channel's configured-state, derived purely from config + credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelStatus {
    /// Stable channel id (`telegram`, `slack`, `whatsapp`, `keet`, `discord`).
    pub name: &'static str,
    /// True when the credentials the daemon needs to START this channel are
    /// present. Never reflects live reachability — that is `channel test`.
    pub configured: bool,
    /// Operator-readable note: what is set, or exactly what to set. Names the
    /// config/credential key — never the secret value.
    pub detail: String,
}

/// Honest configured-state of every messaging channel. Mirrors the
/// start-decision predicates in `cli/serve.rs` (Telegram bot token in
/// `freedom.yaml`; Slack/WhatsApp/Keet credentials in `credentials.yaml`).
/// PURE — same inputs always yield the same rows.
pub fn channel_statuses(cfg: &FreedomConfig, creds: &Credentials) -> Vec<ChannelStatus> {
    // Telegram — single bot token in freedom.yaml (serve.rs gates on `.is_some()`).
    let telegram = cfg.telegram_token.is_some();
    // Slack — socket mode needs BOTH the bot (xoxb) and app (xapp) tokens.
    let slack = creds.slack_bot_token.is_some() && creds.slack_app_token.is_some();
    // WhatsApp — access token + phone id are the minimum to send; the verify
    // token additionally unlocks the inbound webhook listener.
    let whatsapp = creds.whatsapp_token.is_some() && creds.whatsapp_phone_id.is_some();
    // Keet — the 24-word pairing phrase.
    let keet = creds.keet_seed_phrase.is_some();

    vec![
        ChannelStatus {
            name: "telegram",
            configured: telegram,
            detail: if telegram {
                "bot token set (freedom.yaml::telegram_token)".to_string()
            } else {
                "set freedom.yaml::telegram_token — `neoth init` walks the @BotFather flow".to_string()
            },
        },
        ChannelStatus {
            name: "slack",
            configured: slack,
            detail: if slack {
                "bot (xoxb) + app (xapp) tokens set — socket mode".to_string()
            } else {
                "needs slack_bot_token (xoxb) + slack_app_token (xapp) in credentials.yaml".to_string()
            },
        },
        ChannelStatus {
            name: "whatsapp",
            configured: whatsapp,
            detail: if whatsapp {
                "access token + phone id set (whatsapp_verify_token enables inbound)".to_string()
            } else {
                "needs whatsapp_token + whatsapp_phone_id in credentials.yaml".to_string()
            },
        },
        ChannelStatus {
            name: "keet",
            configured: keet,
            detail: if keet {
                "24-word pairing phrase set".to_string()
            } else {
                "needs keet_seed_phrase (24-word pairing phrase) in credentials.yaml".to_string()
            },
        },
        // Discord ships an outbound adapter but has no credentials.yaml field
        // yet (serve.rs notes the inbound credential wiring is a follow-up), so
        // it is never CONFIGURED via the credential store today — say so plainly
        // rather than implying a path that doesn't exist.
        ChannelStatus {
            name: "discord",
            configured: false,
            detail: "outbound adapter present; no credentials.yaml field yet (inbound wiring is a follow-up)".to_string(),
        },
    ]
}

/// Count of configured channels — small helper the renderers share.
fn configured_count(rows: &[ChannelStatus]) -> usize {
    rows.iter().filter(|r| r.configured).count()
}

/// `neoth channel list` — load config + credentials, render the inventory.
/// Missing/unreadable files degrade to defaults (everything UNCONFIGURED), the
/// honest answer on a fresh install.
pub fn run_list(output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
    let creds = Credentials::load_or_default(&crate::config::credentials::default_path())
        .unwrap_or_default();
    let rows = channel_statuses(&cfg, &creds);
    print!("{}", render(&rows, output)?);
    Ok(())
}

/// Render the inventory as table or JSON. Returned as a String so it is
/// unit-testable without capturing stdout.
fn render(rows: &[ChannelStatus], output: &OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = serde_json::json!({
                "channels": rows,
                "configured": configured_count(rows),
                "total": rows.len(),
            });
            Ok(format!("{}\n", serde_json::to_string_pretty(&obj)?))
        }
        OutputFormat::Table => {
            let mut out = String::new();
            out.push_str("# Messaging channels\n\n");
            out.push_str(&format!("{:<10} {:<12}  detail\n", "channel", "status"));
            out.push_str(&format!(
                "{:<10} {:<12}  {}\n",
                "-".repeat(10),
                "-".repeat(12),
                "-".repeat(40)
            ));
            for r in rows {
                let status = if r.configured { "[configured]" } else { "[ off ]" };
                out.push_str(&format!("{:<10} {:<12}  {}\n", r.name, status, r.detail));
            }
            out.push_str(&format!(
                "\n{} of {} channels configured. Connect via `neoth init` / edit credentials.yaml.\n",
                configured_count(rows),
                rows.len()
            ));
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn creds_empty() -> Credentials {
        Credentials::default()
    }

    #[test]
    fn fresh_install_has_no_configured_channels() {
        let rows = channel_statuses(&FreedomConfig::default(), &creds_empty());
        assert_eq!(rows.len(), 5, "telegram/slack/whatsapp/keet/discord");
        assert_eq!(configured_count(&rows), 0);
        // Every off channel names exactly where to set its credential.
        assert!(rows.iter().all(|r| !r.configured));
        assert!(rows.iter().find(|r| r.name == "telegram").unwrap().detail.contains("telegram_token"));
    }

    #[test]
    fn telegram_configured_via_freedom_yaml_token() {
        let mut cfg = FreedomConfig::default();
        cfg.telegram_token = Some(SecretString::from("123:abc"));
        let rows = channel_statuses(&cfg, &creds_empty());
        let t = rows.iter().find(|r| r.name == "telegram").unwrap();
        assert!(t.configured);
        assert!(t.detail.contains("bot token set"));
        // No secret value ever leaks into the detail string.
        assert!(!t.detail.contains("123:abc"));
    }

    #[test]
    fn slack_needs_both_bot_and_app_token() {
        let mut creds = creds_empty();
        creds.slack_bot_token = Some(SecretString::from("xoxb-1"));
        // Only the bot token → still NOT configured (socket mode needs both).
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(!rows.iter().find(|r| r.name == "slack").unwrap().configured);
        creds.slack_app_token = Some(SecretString::from("xapp-1"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(rows.iter().find(|r| r.name == "slack").unwrap().configured);
    }

    #[test]
    fn whatsapp_needs_token_and_phone_id() {
        let mut creds = creds_empty();
        creds.whatsapp_token = Some(SecretString::from("EAA..."));
        assert!(!channel_statuses(&FreedomConfig::default(), &creds)
            .iter()
            .find(|r| r.name == "whatsapp")
            .unwrap()
            .configured);
        creds.whatsapp_phone_id = Some("1234567890".to_string());
        assert!(channel_statuses(&FreedomConfig::default(), &creds)
            .iter()
            .find(|r| r.name == "whatsapp")
            .unwrap()
            .configured);
    }

    #[test]
    fn keet_configured_by_seed_phrase_and_discord_always_off() {
        let mut creds = creds_empty();
        creds.keet_seed_phrase = Some(SecretString::from("word ".repeat(24)));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(rows.iter().find(|r| r.name == "keet").unwrap().configured);
        // Discord has no credential field → never reported configured.
        let d = rows.iter().find(|r| r.name == "discord").unwrap();
        assert!(!d.configured);
        assert!(d.detail.contains("no credentials.yaml field yet"));
    }

    #[test]
    fn render_table_and_json_reflect_configured_count() {
        let mut cfg = FreedomConfig::default();
        cfg.telegram_token = Some(SecretString::from("t"));
        let rows = channel_statuses(&cfg, &creds_empty());
        let table = render(&rows, &OutputFormat::Table).unwrap();
        assert!(table.contains("[configured]"));
        assert!(table.contains("1 of 5 channels configured"));
        let json = render(&rows, &OutputFormat::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["configured"], 1);
        assert_eq!(v["total"], 5);
        assert_eq!(v["channels"][0]["name"], "telegram");
        assert_eq!(v["channels"][0]["configured"], true);
    }
}
