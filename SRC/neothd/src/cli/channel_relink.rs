//! Explicit converted-channel relink. Source provenance and fresh transport
//! credentials remain separate: an OpenClaw account is never an auth shortcut.

use std::path::Path;

use anyhow::{Context, Result};
use neoth_openclaw_custody::ConvertedRelinkChannel;

use crate::channels::registry::{ChannelId, ChannelRef};
use crate::cli::OutputFormat;
use crate::cli::channel::converted_relink::{
    ConvertedRelinkRequest, commit_prepared_converted_relink_at, prepare_converted_relink_at,
};
use crate::cli::channel::read_converted_relink_fields_from;
use crate::config::FreedomConfig;

pub(crate) async fn run(
    channel: &str,
    config: &Path,
    source_account: &str,
    target: String,
    output: &OutputFormat,
) -> Result<()> {
    let (source_channel, destination) = match channel {
        "imessage_bluebubbles" => {
            (ConvertedRelinkChannel::IMessage, ChannelId::IMessageBlueBubbles)
        }
        "google_chat" => (ConvertedRelinkChannel::GoogleChat, ChannelId::GoogleChat),
        _ => anyhow::bail!("converted relink requires imessage_bluebubbles or google_chat"),
    };
    anyhow::ensure!(
        !source_account.trim().is_empty(),
        "source account is required"
    );
    anyhow::ensure!(
        !target.trim().is_empty(),
        "exact outbound target is required"
    );
    let source = neoth_openclaw_custody::select_converted_relink_account(
        config,
        source_channel,
        source_account,
        &neoth_openclaw_custody::canonical_known_channel_inventory_sha256(),
    )
    .context("select converted OpenClaw source account")?;
    let fields = read_converted_relink_fields_from(std::io::stdin().lock(), destination)?;
    let home = FreedomConfig::default_neoth_home();
    let prepared = prepare_converted_relink_at(
        &home,
        ConvertedRelinkRequest {
            source,
            source_config: config.to_owned(),
            destination: ChannelRef::default_account(destination),
            fields,
            target,
        },
    )
    .await?;
    let outcome = commit_prepared_converted_relink_at(&home, prepared)?;
    crate::cli::reload::request_reload_at(&home).context(
        "channel relink committed, but live reload was not requested; run neoth reload",
    )?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "channel": destination.as_str(),
                "account": "default",
                "relink_id": outcome.pending_id(),
                "state": "ready",
                "already_ready": outcome.already_ready(),
                "reload_requested": true,
            })
        ),
        OutputFormat::Table => println!(
            "{} default account relinked; exact target verified; reload requested ({}).",
            destination.as_str(),
            outcome.pending_id(),
        ),
    }
    Ok(())
}
