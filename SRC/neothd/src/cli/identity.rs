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

pub async fn run_identity(args: IdentityArgs, output: OutputFormat) -> Result<()> {
    // `pubkey` needs no db — it derives the operator's X25519 transfer pubkey.
    if let IdentityAction::Pubkey = args.action {
        let secret = crate::memory::transfer_bundle::load_or_init_transfer_key(
            &crate::memory::transfer_bundle::default_transfer_key_path(),
        )
        .context("load transfer key")?;
        // secret is Zeroizing<[u8;32]>; auto-deref coerces to &[u8;32].
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
            // P0: a merge changes attribution semantics — under required-audit it
            // must NOT proceed un-audited when a daemon owns the WAL but its
            // audit-RPC listener is unreachable.
            let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
            let daemon_live = matches!(
                crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
                Ok(Some(_))
            );
            crate::daemon::audit_rpc::enforce_required_audit(
                cfg.audit_rpc.required_for_oneshot_permission_events,
                daemon_live,
                &home,
            )
            .context("identity merge refused: required audit cannot be written")?;
            let aliases = identity_store::merge_human_uuids(&conn, &canonical, &victim)?;
            let n = aliases.len();
            // SPEC-11 (#4): audit the merge with the full before-state so it's
            // reversible — a future `identity split` reads the 0x9B frame. P0:
            // FORWARD over audit-RPC when a daemon owns the WAL (no silent skip).
            // A-27 / GOLD-HON-16: the merge is already committed above; the
            // audit emit is the record of it. If the emit fails, the merge
            // STANDS but is un-audited — surface that audit gap loudly (warn!
            // + an operator-visible "audit forward FAILED" line) rather than
            // swallowing it. We do not fail the command (the merge can't be
            // un-done by returning an error), but the operator is told.
            if let Err(e) =
                emit_identity_merged(&home, daemon_live, &canonical, &victim, &aliases).await
            {
                tracing::warn!(
                    error = %e,
                    "identity merge: 0x9B audit forward FAILED — merge committed but NOT recorded"
                );
                eprintln!(
                    "⚠ audit forward FAILED: the merge succeeded but was NOT recorded to the \
                     audit log (0x9B IDENTITY_MERGED): {e:#}"
                );
            }
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

/// `0x9B IDENTITY_MERGED` audit. P0: when a daemon owns the WAL, FORWARD over
/// the loopback audit-RPC channel (`0x9B` allowlisted) instead of skipping;
/// otherwise open a one-shot writer. Carries the before-state (the reassigned
/// aliases) so the merge is auditable + a future `split` reversible.
async fn emit_identity_merged(
    home: &std::path::Path,
    daemon_live: bool,
    canonical: &str,
    victim: &str,
    aliases: &[identity_store::Alias],
) -> Result<()> {
    let now = crate::time::now_unix_secs();
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
    if daemon_live {
        // A-27 / GOLD-HON-16: a daemon owns the WAL, so the 0x9B frame must
        // forward over audit-RPC. A failure here is an AUDIT GAP, not a
        // routine skip — surface it to the caller (`warn!`-logged + "audit
        // forward FAILED" printed) instead of swallowing it at `debug!`.
        crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            crate::wal::events::EVENT_TYPE_IDENTITY_MERGED,
            &payload,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "0x9B IDENTITY_MERGED audit-RPC forward failed (daemon owns the WAL but its \
                 audit listener is unreachable): {e}"
            )
        })?;
        return Ok(());
    }
    let segment = FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(p) = segment.parent() {
        std::fs::create_dir_all(p).with_context(|| format!("create WAL dir {}", p.display()))?;
    }
    let (writer, _join) = crate::wal::writer::spawn(segment)
        .context("0x9B IDENTITY_MERGED: WAL writer spawn failed; merge not recorded")?;
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_IDENTITY_MERGED, &payload)
            .build();
    writer
        .try_append_sync(header, payload)
        .context("0x9B IDENTITY_MERGED: frame append failed (audit gap)")?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_identity_merged_surfaces_audit_rpc_failure() {
        // A-27 / GOLD-HON-16: daemon_live=true but no daemon audit-RPC
        // sidecar in this temp home → the 0x9B forward must FAIL LOUDLY
        // (return Err so the caller can warn! + print "audit forward
        // FAILED"), never a silent debug-level skip.
        let home = tempfile::tempdir().unwrap();
        let aliases: Vec<identity_store::Alias> = Vec::new();
        let r = emit_identity_merged(home.path(), true, "canon", "victim", &aliases).await;
        assert!(
            r.is_err(),
            "a missing daemon audit listener must surface as Err, not a silent skip"
        );
    }
}
