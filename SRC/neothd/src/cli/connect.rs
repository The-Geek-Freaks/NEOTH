//! UX-01 — `neoth connect`: operator-facing channel on-ramp discovery.
//!
//! The post-wizard "how do I hook up Telegram / Slack / WhatsApp?"
//! entry point. Read-only: loads `~/.neoth/credentials.yaml`, reports
//! each credential-backed channel's connection status + the one-line
//! steps to connect the ones that aren't wired yet. `neoth channel`
//! (hidden) stays the operational add/test/remove surface; this is the
//! friendly discovery layer a fresh operator reaches for.
//!
//! Status classification mirrors `cli::doctor::check_channels_wiring`
//! exactly (same credential fields) so the two never disagree — the
//! difference is that `connect` ALSO lists not-yet-configured channels
//! with their on-ramp, whereas doctor stays silent on those.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;

#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Show one channel's status + its detailed multi-line on-ramp
    /// (e.g. `neoth connect telegram`). Omit to list every channel.
    pub channel: Option<String>,

    #[arg(skip)]
    pub output: OutputFormat,
}

/// Connection state of one channel, derived purely from which
/// credentials are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectStatus {
    /// All credentials for full send + receive are present.
    Connected,
    /// Some credentials present but not enough for live inbound
    /// (e.g. WhatsApp outbound-only, Slack missing one token).
    Partial,
    /// No credentials configured for this channel.
    NotConnected,
    /// Channel implementation exists but is not credentials.yaml-backed
    /// yet (Discord gateway / Keet pairing) — operator wires it via
    /// `neoth channel`, not here.
    Experimental,
}

impl ConnectStatus {
    pub fn label(self) -> &'static str {
        match self {
            ConnectStatus::Connected => "connected",
            ConnectStatus::Partial => "partial",
            ConnectStatus::NotConnected => "not connected",
            ConnectStatus::Experimental => "experimental",
        }
    }

    /// Counts toward the "N of M connected" summary.
    fn is_connected(self) -> bool {
        matches!(self, ConnectStatus::Connected)
    }
}

/// One row in the discovery table.
#[derive(Debug, Clone)]
pub struct ChannelRow {
    pub name: &'static str,
    pub status: ConnectStatus,
    /// Short status note (what works / what's missing).
    pub note: String,
    /// One-line on-ramp shown in the table.
    pub onramp: &'static str,
}

/// Build the channel discovery rows from the operator's credentials.
/// Pure — no IO, no secret material copied out (only `.is_some()`
/// presence checks, matching doctor's policy).
pub fn connect_rows(creds: &Credentials) -> Vec<ChannelRow> {
    vec![
        telegram_row(creds),
        slack_row(creds),
        whatsapp_row(creds),
        ChannelRow {
            name: "discord",
            status: ConnectStatus::Experimental,
            note: "gateway loop ships, but no credentials.yaml field yet".to_string(),
            onramp: "experimental — wire via `neoth channel add discord`",
        },
        ChannelRow {
            name: "keet",
            status: ConnectStatus::Experimental,
            note: "P2P pairing (not token-based)".to_string(),
            onramp: "experimental — wire via `neoth channel add keet`",
        },
    ]
}

fn telegram_row(creds: &Credentials) -> ChannelRow {
    let (status, note) = if creds.telegram_token.is_some() {
        (
            ConnectStatus::Connected,
            "polling loop spawned by serve — send + receive both live".to_string(),
        )
    } else {
        (
            ConnectStatus::NotConnected,
            "no telegram_token in credentials.yaml".to_string(),
        )
    };
    ChannelRow {
        name: "telegram",
        status,
        note,
        onramp: "create a bot via @BotFather → set telegram_token (run `neoth init`)",
    }
}

fn slack_row(creds: &Credentials) -> ChannelRow {
    let (status, note) = match (
        creds.slack_bot_token.is_some(),
        creds.slack_app_token.is_some(),
    ) {
        (true, true) => (
            ConnectStatus::Connected,
            "socket-mode loop spawned by serve — send + receive both live".to_string(),
        ),
        (true, false) | (false, true) => (
            ConnectStatus::Partial,
            "socket mode needs BOTH bot_token (xoxb-) and app_token (xapp-); send still works"
                .to_string(),
        ),
        (false, false) => (
            ConnectStatus::NotConnected,
            "no slack tokens in credentials.yaml".to_string(),
        ),
    };
    ChannelRow {
        name: "slack",
        status,
        note,
        onramp: "create a Slack app (Socket Mode) → set slack_bot_token + slack_app_token",
    }
}

fn whatsapp_row(creds: &Credentials) -> ChannelRow {
    let any = creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some();
    let inbound_ready = creds.whatsapp_verify_token.is_some()
        && creds.whatsapp_app_secret.is_some()
        && creds.whatsapp_phone_id.is_some();
    let (status, note) = if !any {
        (
            ConnectStatus::NotConnected,
            "no whatsapp credentials in credentials.yaml".to_string(),
        )
    } else if inbound_ready {
        (
            ConnectStatus::Connected,
            "Meta webhook listener spawned by serve — send + receive both live".to_string(),
        )
    } else {
        (
            ConnectStatus::Partial,
            "outbound-only; inbound needs whatsapp_verify_token + whatsapp_app_secret + \
             whatsapp_phone_id"
                .to_string(),
        )
    };
    ChannelRow {
        name: "whatsapp",
        status,
        note,
        onramp: "Meta WhatsApp Cloud API → set whatsapp_token + whatsapp_phone_id \
                 (+ verify_token + app_secret for inbound)",
    }
}

/// Detailed, multi-line on-ramp shown by `neoth connect <channel>`.
/// `None` for an unknown channel name.
pub fn channel_details(name: &str) -> Option<&'static str> {
    match name {
        "telegram" => Some(
            "Telegram on-ramp:\n\
             1. Open @BotFather in Telegram, send /newbot, follow the prompts.\n\
             2. Copy the HTTP API token it gives you.\n\
             3. Run `neoth init` and paste the token, OR add\n\
             \x20  `telegram_token: <token>` to ~/.neoth/credentials.yaml.\n\
             4. Restart the daemon — `serve` spawns the polling loop.",
        ),
        "slack" => Some(
            "Slack on-ramp (Socket Mode — no public URL needed):\n\
             1. Create an app at api.slack.com/apps → enable Socket Mode.\n\
             2. Bot token (xoxb-) under OAuth & Permissions → slack_bot_token.\n\
             3. App-level token (xapp-, connections:write) → slack_app_token.\n\
             4. Put both in ~/.neoth/credentials.yaml + restart the daemon.\n\
             Outbound send works with just the bot token; live inbound\n\
             needs BOTH.",
        ),
        "whatsapp" => Some(
            "WhatsApp on-ramp (Meta Cloud API):\n\
             1. Create a Meta app + WhatsApp product; note the phone number id.\n\
             2. credentials.yaml: whatsapp_token + whatsapp_phone_id (outbound).\n\
             3. For inbound, also set whatsapp_verify_token + whatsapp_app_secret\n\
             \x20  and point the Meta webhook at your reverse proxy → the\n\
             \x20  daemon's listener (binds 127.0.0.1, TLS terminates upstream).",
        ),
        "discord" => Some(
            "Discord is experimental: the gateway loop ships but there is no\n\
             credentials.yaml field yet. Track via `neoth channel add discord`.",
        ),
        "keet" => Some(
            "Keet is experimental: P2P pairing-based (not a token). Use\n\
             `neoth channel add keet` to start the pairing flow.",
        ),
        _ => None,
    }
}

/// `neoth connect` entry point. Read-only.
pub fn run_connect(args: ConnectArgs) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let creds = Credentials::load_or_default(&home.join("credentials.yaml")).unwrap_or_default();
    let rows = connect_rows(&creds);

    // Single-channel detail view.
    if let Some(name) = args.channel.as_deref() {
        let name = name.to_lowercase();
        let Some(row) = rows.iter().find(|r| r.name == name) else {
            anyhow::bail!(
                "unknown channel `{name}` — known: {}",
                rows.iter().map(|r| r.name).collect::<Vec<_>>().join(", ")
            );
        };
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", row_json(row));
            }
            OutputFormat::Table => {
                println!("{} — {}", row.name, row.status.label());
                println!("  {}", row.note);
                if let Some(detail) = channel_details(&name) {
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
            let body = rows.iter().map(row_json).collect::<Vec<_>>().join(",\n");
            println!("[\n{body}\n]");
        }
        OutputFormat::Table => {
            let connected = rows.iter().filter(|r| r.status.is_connected()).count();
            println!("Channels — {connected} of {} connected\n", rows.len());
            for r in &rows {
                println!("  {:<9} {:<14} {}", r.name, r.status.label(), r.note);
            }
            println!("\nRun `neoth connect <channel>` for the step-by-step on-ramp.");
        }
    }
    Ok(())
}

fn row_json(r: &ChannelRow) -> String {
    serde_json::json!({
        "channel": r.name,
        "status": r.status.label(),
        "note": r.note,
        "onramp": r.onramp,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn creds() -> Credentials {
        Credentials::default()
    }

    fn find<'a>(rows: &'a [ChannelRow], name: &str) -> &'a ChannelRow {
        rows.iter().find(|r| r.name == name).expect("row present")
    }

    #[test]
    fn empty_credentials_no_channel_connected() {
        let rows = connect_rows(&creds());
        assert_eq!(find(&rows, "telegram").status, ConnectStatus::NotConnected);
        assert_eq!(find(&rows, "slack").status, ConnectStatus::NotConnected);
        assert_eq!(find(&rows, "whatsapp").status, ConnectStatus::NotConnected);
        // discord + keet are experimental regardless of credentials.
        assert_eq!(find(&rows, "discord").status, ConnectStatus::Experimental);
        assert_eq!(find(&rows, "keet").status, ConnectStatus::Experimental);
    }

    #[test]
    fn telegram_token_present_is_connected() {
        let mut c = creds();
        c.telegram_token = Some(SecretString::from("123:abc"));
        assert_eq!(
            find(&connect_rows(&c), "telegram").status,
            ConnectStatus::Connected
        );
    }

    #[test]
    fn slack_needs_both_tokens_else_partial() {
        let mut c = creds();
        c.slack_bot_token = Some(SecretString::from("xoxb-1"));
        assert_eq!(
            find(&connect_rows(&c), "slack").status,
            ConnectStatus::Partial,
            "bot token alone is partial"
        );
        c.slack_app_token = Some(SecretString::from("xapp-1"));
        assert_eq!(
            find(&connect_rows(&c), "slack").status,
            ConnectStatus::Connected,
            "both tokens → connected"
        );
    }

    #[test]
    fn whatsapp_outbound_only_is_partial_full_is_connected() {
        let mut c = creds();
        c.whatsapp_token = Some(SecretString::from("EAA..."));
        assert_eq!(
            find(&connect_rows(&c), "whatsapp").status,
            ConnectStatus::Partial,
            "token alone = outbound-only = partial"
        );
        c.whatsapp_phone_id = Some("100000000000000".to_string());
        c.whatsapp_verify_token = Some(SecretString::from("verify"));
        c.whatsapp_app_secret = Some(SecretString::from("secret"));
        assert_eq!(
            find(&connect_rows(&c), "whatsapp").status,
            ConnectStatus::Connected,
            "full inbound set → connected"
        );
    }

    #[test]
    fn channel_details_known_and_unknown() {
        assert!(channel_details("telegram").is_some());
        assert!(channel_details("slack").is_some());
        assert!(channel_details("whatsapp").is_some());
        assert!(channel_details("nonsense").is_none());
    }

    #[test]
    fn row_json_carries_channel_and_status() {
        let rows = connect_rows(&creds());
        let j = row_json(find(&rows, "telegram"));
        assert!(j.contains("\"channel\":\"telegram\""));
        assert!(j.contains("\"status\":\"not connected\""));
    }
}
