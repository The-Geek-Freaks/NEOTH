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
}

pub fn run_identity(args: IdentityArgs, output: OutputFormat) -> Result<()> {
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
            let n = identity_store::merge_human_uuids(&conn, &canonical, &victim)?;
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
                    println!("✓ merged {victim} → {canonical} ({n} alias(es) reassigned)")
                }
            }
            Ok(())
        }
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
