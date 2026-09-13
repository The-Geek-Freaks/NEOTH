//! UX-01 — `neoth connect`: operator-facing channel on-ramp discovery.
//!
//! The post-wizard "how do I hook up Telegram / Slack / WhatsApp?"
//! entry point. It is intentionally a presentation-only adapter over the
//! canonical `neoth channel list/add/test/remove` contract; it owns no second
//! channel registry or readiness predicates.

use anyhow::Result;
use clap::Args;

use crate::channels::probe::ProbeStatus;
use crate::channels::registry::{ChannelAccountId, ChannelId, ChannelRef, resolve_channel_id};
use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Show one channel's status + its detailed multi-line on-ramp
    /// (e.g. `neoth connect telegram`). Omit to list every channel.
    pub channel: Option<String>,

    /// Inspect one explicitly configured Telegram account. Map-mode Telegram
    /// never treats an omitted account or the literal `default` as a fallback.
    #[arg(long)]
    pub account: Option<ChannelAccountId>,

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
    /// Secret-free exact Telegram account projections. Empty is the compatible
    /// legacy/no-map shape, never an inferred default account.
    pub accounts: Vec<ConnectAccountRow>,
    /// Canonical channel status reports an active Telegram map that failed
    /// pair validation. Its empty account list is not legacy/no-map.
    repair_only: bool,
}

/// One account row copied from the canonical `channel list` projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAccountRow {
    pub channel_ref: ChannelRef,
    pub status: ConnectStatus,
    pub note: String,
    /// A current exact-binding daemon observation, if one exists.
    pub runtime: Option<String>,
}

/// Build the friendly discovery rows directly from canonical channel-list rows.
fn connect_rows(statuses: &[crate::cli::channel::ChannelStatus]) -> Vec<ChannelRow> {
    statuses
        .iter()
        .map(|row| {
            let status = match row.status {
                ProbeStatus::Ok => ConnectStatus::Connected,
                ProbeStatus::Warn | ProbeStatus::Error => ConnectStatus::Partial,
                ProbeStatus::NotConfigured => ConnectStatus::NotConnected,
                ProbeStatus::Unavailable => ConnectStatus::Unavailable,
            };
            let accounts = row
                .accounts
                .iter()
                .map(|account| ConnectAccountRow {
                    channel_ref: account.channel_ref.clone(),
                    status: match account.status {
                        ProbeStatus::Ok => ConnectStatus::Connected,
                        ProbeStatus::Warn | ProbeStatus::Error => ConnectStatus::Partial,
                        ProbeStatus::NotConfigured => ConnectStatus::NotConnected,
                        ProbeStatus::Unavailable => ConnectStatus::Unavailable,
                    },
                    note: account.detail.clone(),
                    runtime: account.runtime.clone(),
                })
                .collect::<Vec<_>>();
            let repair_only = row.name == ChannelId::Telegram.as_str()
                && row.configured
                && row.status == ProbeStatus::Error
                && accounts.is_empty();
            let onramp = if repair_only {
                "repair the Telegram account map; no account can be tested until its matching policy and credential entries are complete".to_string()
            } else if row.name == ChannelId::Telegram.as_str() && !accounts.is_empty() {
                "run `neoth connect telegram --account <account-id>` for one exact account"
                    .to_string()
            } else {
                format!(
                    "run `neoth channel add {0}`, then `neoth channel test {0}`",
                    row.name
                )
            };
            ChannelRow {
                name: row.name,
                status,
                note: row.detail.clone(),
                onramp,
                accounts,
                repair_only,
            }
        })
        .collect()
}

/// Resolve the only account-specific Connect detail. A parent map view may
/// enumerate account rows, but has no implicit test command.
fn connect_detail(row: &ChannelRow, account: Option<&ChannelAccountId>) -> Result<String> {
    if row.repair_only {
        return Ok(
            "Telegram account map needs repair. No account is usable or testable until matching policy, nonzero sender, and credential entries are complete."
                .to_string(),
        );
    }
    match account {
        Some(_) if row.name != ChannelId::Telegram.as_str() => {
            anyhow::bail!("--account is supported only for the canonical `telegram` channel")
        }
        Some(account) => {
            let selected = row
                .accounts
                .iter()
                .find(|candidate| candidate.channel_ref.account_id == *account)
                .ok_or_else(|| anyhow::anyhow!("Telegram account `{account}` is not configured"))?;
            Ok(format!(
                "Telegram account {}/{} — {}\n\
                 Runtime: {}\n\
                 Run `neoth channel test telegram --account {}` for the read-only live check.",
                selected.channel_ref.channel_id.as_str(),
                selected.channel_ref.account_id.as_str(),
                selected.note,
                selected.runtime.as_deref().unwrap_or("unknown"),
                selected.channel_ref.account_id.as_str(),
            ))
        }
        None if row.name == ChannelId::Telegram.as_str() && !row.accounts.is_empty() => Ok(
            "Telegram account map configured. Select one exact account with \
             `neoth connect telegram --account <account-id>` before requesting a live test."
                .to_string(),
        ),
        None => channel_details(row.name)
            .ok_or_else(|| anyhow::anyhow!("unknown channel `{}`", row.name)),
    }
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

    if args.account.is_some() && args.channel.is_none() {
        anyhow::bail!("--account requires `neoth connect telegram --account <account-id>`")
    }

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
        let detail = connect_detail(row, args.account.as_ref())?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    row_json_with_cred_status(
                        row,
                        cred_status.as_str(),
                        args.account.as_ref(),
                        &detail
                    )
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
                println!("{} — {}", row.name, row.status.label());
                println!("  {}", row.note);
                println!();
                println!("{detail}");
            }
        }
        return Ok(());
    }

    // Full discovery list.
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Wrap rows in an envelope that carries the credential_store_status
            // so callers can distinguish bad-file from fresh-install.
            let rows_json: Vec<serde_json::Value> = rows.iter().map(row_json_value).collect();
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
                for account in &r.accounts {
                    println!(
                        "    {:<20} {:<18} {:<24} {}",
                        format!(
                            "{}/{}",
                            account.channel_ref.channel_id.as_str(),
                            account.channel_ref.account_id.as_str()
                        ),
                        account.status.label(),
                        account.runtime.as_deref().unwrap_or("unknown"),
                        account.note
                    );
                }
            }
            println!("\nRun `neoth connect <channel>` for the step-by-step on-ramp.");
        }
    }
    Ok(())
}

#[cfg(test)]
fn row_json(r: &ChannelRow) -> String {
    row_json_value(r).to_string()
}

fn row_json_value(r: &ChannelRow) -> serde_json::Value {
    let mut row = serde_json::json!({
        "channel": r.name,
        "status": r.status.label(),
        "note": r.note,
        "onramp": r.onramp.as_str(),
    });
    if !r.accounts.is_empty() {
        row["accounts"] = serde_json::Value::Array(
            r.accounts
                .iter()
                .map(|account| {
                    serde_json::json!({
                        "channel_ref": account.channel_ref,
                        "status": account.status.label(),
                        "note": account.note,
                        "runtime": account.runtime,
                    })
                })
                .collect(),
        );
    }
    row
}

/// B17: single-channel JSON with the credential store status included.
fn row_json_with_cred_status(
    r: &ChannelRow,
    cred_status: &str,
    selected_account: Option<&ChannelAccountId>,
    detail: &str,
) -> String {
    let mut row = row_json_value(r);
    let object = row.as_object_mut().expect("row_json_value is an object");
    object.insert("credential_store_status".to_string(), cred_status.into());
    if selected_account.is_some() && !r.repair_only && !r.accounts.is_empty() {
        object.insert("detail".to_string(), detail.into());
    }
    if let Some(selected_account) =
        selected_account.filter(|_| !r.repair_only && !r.accounts.is_empty())
    {
        object.insert(
            "selected_account".to_string(),
            selected_account.to_string().into(),
        );
    }
    row.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::registry::{ChannelAccountId, ChannelRef, channel_descriptors};
    use crate::cli::channel::{ChannelAccountStatus, ChannelStatus};
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

    fn account(name: &str, runtime: Option<&str>) -> ChannelAccountStatus {
        ChannelAccountStatus {
            channel_ref: ChannelRef::new(
                ChannelId::Telegram,
                ChannelAccountId::new(name).expect("fixture account id"),
            ),
            status: ProbeStatus::Ok,
            detail: format!("{name} configured"),
            runtime: runtime.map(str::to_owned),
        }
    }

    fn mapped_telegram_row() -> ChannelRow {
        connect_rows(&[ChannelStatus {
            name: "telegram",
            status: ProbeStatus::Ok,
            configured: true,
            detail: "Telegram account map configured; per-account readiness is static only."
                .to_string(),
            accounts: vec![
                account("default", None),
                account("ops_a", Some("running")),
                account("ops_b", Some("configured_not_started")),
            ],
        }])
        .pop()
        .expect("Telegram row")
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
        let telegram = find(&rows, "telegram");
        let j = row_json(telegram);
        assert!(j.contains("\"channel\":\"telegram\""));
        assert!(j.contains("\"status\":\"not_configured\""));
        assert!(
            !j.contains("\"accounts\""),
            "legacy rows retain their historical JSON shape"
        );

        let detail = connect_detail(telegram, None).unwrap();
        let detailed: serde_json::Value =
            serde_json::from_str(&row_json_with_cred_status(telegram, "ok", None, &detail))
                .unwrap();
        let keys = detailed
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "channel".to_string(),
                "credential_store_status".to_string(),
                "note".to_string(),
                "onramp".to_string(),
                "status".to_string(),
            ]),
            "legacy single-channel JSON gains no account/detail key"
        );
    }

    #[test]
    fn mapped_connect_row_enumerates_exact_accounts_without_parent_test() {
        let row = mapped_telegram_row();
        assert_eq!(
            row.accounts
                .iter()
                .map(|account| account.channel_ref.account_id.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "ops_a", "ops_b"]
        );
        assert!(row.onramp.contains("connect telegram --account"));
        assert!(!row.onramp.contains("channel test telegram"));

        let json = row_json(&row);
        assert!(json.contains("\"account_id\":\"ops_b\""));
        assert!(json.contains("\"runtime\":\"configured_not_started\""));
    }

    #[test]
    fn mapped_connect_detail_requires_and_binds_exact_account() {
        let row = mapped_telegram_row();
        let map_detail = connect_detail(&row, None).expect("map parent view is readable");
        assert!(map_detail.contains("--account <account-id>"));
        assert!(!map_detail.contains("channel test telegram`"));

        let selected = ChannelAccountId::new("ops_b").unwrap();
        let detail = connect_detail(&row, Some(&selected)).expect("configured account resolves");
        assert!(detail.contains("telegram/ops_b"));
        assert!(detail.contains("--account ops_b"));
        assert!(!detail.contains("ops_a"));

        let explicit_default = ChannelAccountId::default_account();
        assert!(
            connect_detail(&row, Some(&explicit_default))
                .expect("configured default is an exact account")
                .contains("--account default")
        );
        assert!(connect_detail(&row, Some(&ChannelAccountId::new("unknown").unwrap())).is_err());
    }

    #[test]
    fn account_selection_is_refused_for_non_telegram_parent() {
        let row = ChannelRow {
            name: "slack",
            status: ConnectStatus::Connected,
            note: "configured".into(),
            onramp: "legacy".into(),
            accounts: Vec::new(),
            repair_only: false,
        };
        assert!(connect_detail(&row, Some(&ChannelAccountId::new("ops_b").unwrap())).is_err());
    }

    #[test]
    fn invalid_active_map_is_repair_only_and_never_emits_test_instruction() {
        let row = connect_rows(&[ChannelStatus {
            name: "telegram",
            status: ProbeStatus::Error,
            configured: true,
            detail: "Telegram account map is invalid or partial; no account is usable.".into(),
            accounts: Vec::new(),
        }])
        .pop()
        .unwrap();
        assert!(row.repair_only);
        assert!(!row.onramp.contains("channel test telegram"));
        assert!(!row.onramp.contains("--account"));

        let parent = connect_detail(&row, None).unwrap();
        let explicit =
            connect_detail(&row, Some(&ChannelAccountId::new("ops_a").unwrap())).unwrap();
        assert!(parent.contains("needs repair"));
        assert_eq!(parent, explicit);
        assert!(!explicit.contains("channel test telegram"));

        let json = row_json_with_cred_status(
            &row,
            "ok",
            Some(&ChannelAccountId::new("ops_a").unwrap()),
            &explicit,
        );
        assert!(!json.contains("selected_account"));
        assert!(!json.contains("\"detail\""));
    }
}
