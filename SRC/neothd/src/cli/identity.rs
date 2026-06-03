//! `neoth identity` — SPEC-11 cross-channel identity management.
//!
//! `list` shows each resolved human (UUID v7) + the channel-native aliases that
//! map to them; `merge` folds one identity into another when the same person
//! was minted twice (e.g. they messaged from two channels before NEOTH linked
//! them). The identity rows are produced by the inbound handler's
//! `resolve_or_create_human_uuid` call (serve.rs) as messages arrive.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::channels::identity as identity_store;
use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub action: IdentityAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityAction {
    /// List resolved cross-channel identities + their channel aliases.
    List {
        /// Only show identities with an alias on this channel.
        #[arg(long)]
        channel: Option<String>,
    },
    /// Merge two identities: every alias of <victim> is reassigned to
    /// <canonical>, then <victim> is deleted. Use when the same person was
    /// minted twice (they messaged from two channels before being linked).
    Merge {
        /// The identity to KEEP (a UUID from `neoth identity list`).
        canonical: String,
        /// The identity to FOLD IN + delete (a UUID).
        victim: String,
    },
    /// Show THIS operator's X25519 transfer public key (base64) — share it so
    /// another NEOTH can `neoth transfer export --dest <this>` an encrypted
    /// memory bundle to you. The key is auto-managed at `~/.neoth/wal/transfer.key`.
    Pubkey,
}

pub fn run_identity(args: IdentityArgs, output: OutputFormat) -> Result<()> {
    // `pubkey` needs no db — it derives the operator's X25519 transfer pubkey.
    if let IdentityAction::Pubkey = args.action {
        let secret = crate::memory::transfer_bundle::load_or_init_transfer_key(
            &crate::memory::transfer_bundle::default_transfer_key_path(),
        )
        .context("load transfer key")?;
        let pubkey = crate::memory::transfer_bundle::transfer_pubkey_b64(&secret);
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", serde_json::json!({ "transfer_pubkey_b64": pubkey }))
            }
            OutputFormat::Table => println!("{pubkey}"),
        }
        return Ok(());
    }
    let home = FreedomConfig::default_neoth_home();
    let db_path = home.join("views.db");
    // `store::open` applies the schema, so the identity tables exist even on a
    // fresh install (the list is just empty until messages arrive).
    let conn = store::open(&db_path).context("open views.db")?;
    match args.action {
        IdentityAction::List { channel } => {
            let ids = identity_store::list_identities(&conn, channel.as_deref())?;
            render_list(&ids, output);
            Ok(())
        }
        IdentityAction::Merge { canonical, victim } => {
            let aliases = identity_store::merge_human_uuids(&conn, &canonical, &victim)?;
            let n = aliases.len();
            // SPEC-11 (#4): audit the merge with the full before-state so it's
            // reversible — a future `identity split` reads the 0x9B frame.
            emit_identity_merged(&canonical, &victim, &aliases);
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "canonical": canonical,
                        "victim": victim,
                        "aliases_reassigned": n,
                    })
                ),
                OutputFormat::Table => {
                    println!(
                        "✓ merged {victim} → {canonical} ({n} alias(es) reassigned; \
                         victim tombstoned, audited as 0x9B IDENTITY_MERGED)"
                    )
                }
            }
            Ok(())
        }
        IdentityAction::Pubkey => unreachable!("handled before the db open above"),
    }
}

/// Best-effort `0x9B IDENTITY_MERGED` audit — one-shot writer, daemon-live-skip
/// (mirrors `neoth transfer`/`dream now`). Carries the before-state (the
/// reassigned aliases) so the merge is auditable + a future `split` reversible.
fn emit_identity_merged(canonical: &str, victim: &str, aliases: &[identity_store::Alias]) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    ) {
        tracing::info!("identity: daemon live — skipping one-shot 0x9B audit to avoid a writer race");
        return;
    }
    let segment = FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(p) = segment.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "identity: WAL writer spawn failed; 0x9B not recorded");
            return;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let alias_json: Vec<_> = aliases
        .iter()
        .map(|a| {
            serde_json::json!({
                "channel": a.channel,
                "sender_id": a.sender_id,
                "chat_id": a.chat_id,
            })
        })
        .collect();
    let payload = serde_json::to_vec(&serde_json::json!({
        "canonical": canonical,
        "victim": victim,
        "aliases": alias_json,
        "aliases_reassigned": aliases.len(),
        "ts_unix": now,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_IDENTITY_MERGED,
        &payload,
    )
    .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "identity: 0x9B frame append failed (audit gap)");
    }
}

fn render_list(ids: &[identity_store::Identity], output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(ids).unwrap_or_default())
        }
        OutputFormat::Table => {
            if ids.is_empty() {
                println!("(no identities yet — they appear as channel messages arrive)");
                return;
            }
            for id in ids {
                println!("{}  ({} alias(es))", id.uuid, id.aliases.len());
                for a in &id.aliases {
                    println!("    {} / {} / {}", a.channel, a.sender_id, a.chat_id);
                }
            }
        }
    }
}
