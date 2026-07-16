//! UX-01 — `neoth connect`: operator-facing channel on-ramp discovery.
//!
//! The post-wizard "how do I hook up Telegram / Slack / WhatsApp?"
//! entry point. It is intentionally a presentation-only adapter over the
//! canonical `neoth channel list/add/test/remove` contract; it owns no second
//! channel registry or readiness predicates.

use anyhow::Result;
use clap::Args;

use crate::channels::probe::ProbeStatus;
use crate::channels::registry::{ChannelId, resolve_channel_id};
use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Show one channel's status + its detailed multi-line on-ramp
    /// (e.g. `neoth connect telegram`). Omit to list every channel.
    pub channel: Option<String>,

    #[arg(skip)]
    pub output: OutputFormat,
}

/// Friendly projection of the canonical static channel probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectStatus {
    /// All static requirements are present. Live reachability still requires
    /// `neoth channel test <name>`.
    Connected,
    /// Some credentials present but not enough for live inbound
    /// (e.g. WhatsApp outbound-only, Slack missing one token).
    Partial,
    /// No credentials configured for this channel.
    NotConnected,
    /// The canonical registry explicitly marks this adapter unavailable.
    Unavailable,
}

impl ConnectStatus {
    pub fn label(self) -> &'static str {
        match self {
            ConnectStatus::Connected => "configured",
            ConnectStatus::Partial => "needs_attention",
            ConnectStatus::NotConnected => "not_configured",
            ConnectStatus::Unavailable => "unavailable",
        }
    }

    /// Counts toward the "N of M statically ready" summary.
    fn is_connected(self) -> bool {
        matches!(self, ConnectStatus::Connected)
    }
}

/// One row in the discovery table.
#[derive(Debug, Clone)]
pub struct ChannelRow {
    pub name: &'static str,
    pub status: ConnectStatus,
    /// Canonical probe detail (what is set / missing; never a secret value).
    pub note: String,
    /// One-line on-ramp shown in the table.
    pub onramp: String,
}

/// Build the friendly discovery rows directly from canonical channel-list rows.
fn connect_rows(statuses: &[crate::cli::channel::ChannelStatus]) -> Vec<ChannelRow> {
    statuses
        .iter()
        .map(|row| ChannelRow {
            name: row.name,
            status: match row.status {
                ProbeStatus::Ok => ConnectStatus::Connected,
                ProbeStatus::Warn | ProbeStatus::Error => ConnectStatus::Partial,
                ProbeStatus::NotConfigured => ConnectStatus::NotConnected,
                ProbeStatus::Unavailable => ConnectStatus::Unavailable,
            },
            note: row.detail.clone(),
            onramp: format!(
                "run `neoth channel add {0}`, then `neoth channel test {0}`",
                row.name
            ),
        })
        .collect()
}

/// Detailed on-ramp shown by `neoth connect <channel>`. Membership is resolved
/// from the canonical registry; the friendly command never maintains its own
/// supported-channel list.
pub fn channel_details(name: &str) -> Option<String> {
    let channel_id = resolve_channel_id(name)?;
    let channel = channel_id.as_str();
    Some(match channel_id {
        ChannelId::Telegram => "Telegram on-ramp:\n\
             1. Create a bot with @BotFather and copy its HTTP API token.\n\
             2. Obtain your exact numeric Telegram user ID.\n\
             3. Run `neoth channel add telegram --token <token> \
             --telegram-user-id <numeric-id>`.\n\
             4. Run `neoth channel test telegram`; `neoth serve` hot-reloads the \
             complete token + sender policy."
            .to_string(),
        ChannelId::Keet => "Keet on-ramp (repository-owned local companion):\n\
             1. Run `neoth-keet-bridge setup`, then start it on loopback.\n\
             2. Exchange peer self IDs and join the same private topic.\n\
             3. Run `neoth channel add keet`; supply URL, bearer, topic, and \
             exact allowed sender IDs when prompted.\n\
             4. Run `neoth channel test keet`; only a versioned authenticated \
             companion proving full-duplex readiness is accepted. Existing \
             Keet application rooms are not accessed."
            .to_string(),
        _ => format!(
            "{channel} on-ramp:\n\
             1. Run `neoth channel add {channel}` and follow the typed prompts.\n\
             2. Run `neoth channel test {channel}` for the adapter's read-only \
             live or explicitly unavailable verdict.\n\
             3. Run `neoth serve`; a running daemon reconciles changed channel \
             credentials without restarting unrelated adapters."
        ),
    })
}

/// `neoth connect` entry point. Read-only.
pub fn run_connect(args: ConnectArgs) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let cred_path = home.join("credentials.yaml");
    let cred_status = crate::config::credentials::Credentials::credential_store_status(&cred_path);
    // Canonical loader: same config/secret backend, strict corruption handling,
    // registry order, and readiness predicates as `neoth channel list`.
    let statuses = crate::cli::channel::load_channel_statuses_at(&home)?;
    let rows = connect_rows(&statuses);

    // Single-channel detail view.
    if let Some(name) = args.channel.as_deref() {
        let requested = name.trim();
        let Some(channel_id) = resolve_channel_id(requested) else {
            anyhow::bail!(
                "unknown channel `{requested}` — known: {}",
                rows.iter().map(|r| r.name).collect::<Vec<_>>().join(", ")
            );
        };
        let name = channel_id.as_str();
        let row = rows
            .iter()
            .find(|row| row.name == name)
            .expect("canonical channel registry and connect rows must stay identical");
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", row_json_with_cred_status(row, cred_status.as_str()));
            }
            OutputFormat::Table => {
                if !matches!(
                    cred_status,
                    crate::config::credentials::CredentialStoreStatus::Ok
                        | crate::config::credentials::CredentialStoreStatus::Missing
                ) {
                    println!(
                        "credential store: {} — {}",
                        cred_path.display(),
                        cred_status.as_str()
                    );
                }
                println!("{} — {}", row.name, row.status.label());
                println!("  {}", row.note);
                if let Some(detail) = channel_details(name) {
                    println!();
                    println!("{detail}");
                }
            }
        }
        return Ok(());
    }

    // Full discovery list.
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Wrap rows in an envelope that carries the credential_store_status
            // so callers can distinguish bad-file from fresh-install.
            let rows_json: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "channel": r.name,
                        "status": r.status.label(),
                        "note": r.note,
                        "onramp": r.onramp.as_str(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "credential_store_status": cred_status.as_str(),
                    "channels": rows_json,
                }))?
            );
        }
        OutputFormat::Table => {
            if !matches!(
                cred_status,
                crate::config::credentials::CredentialStoreStatus::Ok
                    | crate::config::credentials::CredentialStoreStatus::Missing
            ) {
                println!(
                    "credential store: {} — {}",
                    cred_path.display(),
                    cred_status.as_str()
                );
            }
            let connected = rows.iter().filter(|r| r.status.is_connected()).count();
            println!(
                "Channels — {connected} of {} statically ready\n",
                rows.len()
            );
            for r in &rows {
                println!("  {:<22} {:<18} {}", r.name, r.status.label(), r.note);
            }
            println!("\nRun `neoth connect <channel>` for the step-by-step on-ramp.");
        }
    }
    Ok(())
}

#[cfg(test)]
fn row_json(r: &ChannelRow) -> String {
    serde_json::json!({
        "channel": r.name,
        "status": r.status.label(),
        "note": r.note,
        "onramp": r.onramp.as_str(),
    })
    .to_string()
}

/// B17: single-channel JSON with the credential store status included.
fn row_json_with_cred_status(r: &ChannelRow, cred_status: &str) -> String {
    serde_json::json!({
        "channel": r.name,
        "status": r.status.label(),
        "note": r.note,
        "onramp": r.onramp.as_str(),
        "credential_store_status": cred_status,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::registry::channel_descriptors;
    use crate::config::FreedomConfig;
    use crate::config::credentials::Credentials;
    use crate::secret::SecretString;

    fn rows(config: &FreedomConfig, credentials: &Credentials) -> Vec<ChannelRow> {
        let statuses = crate::cli::channel::channel_statuses(config, credentials);
        connect_rows(&statuses)
    }

    fn find<'a>(rows: &'a [ChannelRow], name: &str) -> &'a ChannelRow {
        rows.iter().find(|r| r.name == name).expect("row present")
    }

    #[test]
    fn empty_config_uses_the_complete_canonical_registry() {
        let rows = rows(&FreedomConfig::default(), &Credentials::default());
        assert_eq!(rows.len(), channel_descriptors().len());
        assert!(
            rows.iter()
                .all(|row| row.status == ConnectStatus::NotConnected)
        );
        assert_eq!(find(&rows, "discord").status, ConnectStatus::NotConnected);
        let names: Vec<_> = rows.iter().map(|row| row.name).collect();
        let canonical: Vec<_> = channel_descriptors()
            .iter()
            .map(|descriptor| descriptor.id.as_str())
            .collect();
        assert_eq!(names, canonical);
    }

    #[test]
    fn telegram_requires_token_and_exact_sender_policy() {
        let mut credentials = Credentials::default();
        credentials.telegram_token = Some(SecretString::from("123:abc"));
        assert_eq!(
            find(&rows(&FreedomConfig::default(), &credentials), "telegram").status,
            ConnectStatus::Partial
        );
        let config = FreedomConfig {
            telegram_user_id: Some(42),
            ..Default::default()
        };
        assert_eq!(
            find(&rows(&config, &credentials), "telegram").status,
            ConnectStatus::Connected
        );
    }

    #[test]
    fn slack_needs_tokens_and_sender_policy_else_partial() {
        let config = FreedomConfig::default();
        let mut credentials = Credentials::default();
        credentials.slack_bot_token = Some(SecretString::from("xoxb-1"));
        assert_eq!(
            find(&rows(&config, &credentials), "slack").status,
            ConnectStatus::Partial,
            "bot token alone is partial"
        );
        credentials.slack_app_token = Some(SecretString::from("xapp-1"));
        assert_eq!(
            find(&rows(&config, &credentials), "slack").status,
            ConnectStatus::Partial,
            "tokens without a sender policy remain fail-closed"
        );
        credentials.slack_allowed_user_id = Some("U123456".into());
        assert_eq!(
            find(&rows(&config, &credentials), "slack").status,
            ConnectStatus::Connected,
            "both tokens are statically ready"
        );
    }

    #[test]
    fn whatsapp_and_discord_follow_canonical_probe_status() {
        let config = FreedomConfig::default();
        let mut credentials = Credentials::default();
        credentials.whatsapp_token = Some(SecretString::from("EAA..."));
        assert_eq!(
            find(&rows(&config, &credentials), "whatsapp_business").status,
            ConnectStatus::Partial,
            "token alone is incomplete"
        );
        credentials.whatsapp_phone_id = Some("100000000000000".to_string());
        credentials.whatsapp_verify_token = Some(SecretString::from("verify"));
        credentials.whatsapp_app_secret = Some(SecretString::from("secret"));
        assert_eq!(
            find(&rows(&config, &credentials), "whatsapp_business").status,
            ConnectStatus::Partial,
            "verified webhook without an exact sender policy remains fail-closed"
        );
        credentials.whatsapp_allowed_sender = Some("491701234567".into());
        assert_eq!(
            find(&rows(&config, &credentials), "whatsapp_business").status,
            ConnectStatus::Connected,
            "full inbound set is statically ready"
        );
        credentials.discord_bot_token = Some(SecretString::from("discord-token"));
        assert_eq!(
            find(&rows(&config, &credentials), "discord").status,
            ConnectStatus::Partial,
            "Discord token without an exact sender policy is fail-closed"
        );
        credentials.discord_allowed_user_id = Some("123456789012345678".into());
        assert_eq!(
            find(&rows(&config, &credentials), "discord").status,
            ConnectStatus::Connected
        );
    }

    #[test]
    fn channel_details_cover_registry_and_supported_aliases() {
        for kind in crate::channels::registry::channel_ids() {
            assert!(
                channel_details(kind.as_str()).is_some(),
                "missing on-ramp for {}",
                kind.as_str()
            );
        }
        assert!(channel_details("whatsapp").is_some());
        assert!(channel_details("bluebubbles").is_some());
        assert!(channel_details("google_chat").is_some());
        assert!(channel_details("nonsense").is_none());
    }

    #[test]
    fn row_json_carries_channel_and_status() {
        let rows = rows(&FreedomConfig::default(), &Credentials::default());
        let j = row_json(find(&rows, "telegram"));
        assert!(j.contains("\"channel\":\"telegram\""));
        assert!(j.contains("\"status\":\"not_configured\""));
    }
}
