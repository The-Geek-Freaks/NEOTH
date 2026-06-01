//! `neoth lease` — SL-01a operator surface for capability leases.
//!
//! Grant a paired peer or a plugin a TTL-bounded scoped capability, list
//! the active grants, or revoke one. Each mutation lands in the WAL
//! (`0xA5/0xA6/0xA7`) so `neoth wal show --type lease_granted` is the
//! audit of who may do what, until when.
//!
//! The leases themselves persist to `~/.neoth/leases.json`
//! ([`permissions::lease::LeaseStore`]); the WAL frames are the durable
//! audit twin. Best-effort emit: if `neothd serve` owns the WAL writer we
//! skip the one-shot append (the daemon will re-derive state from
//! leases.json) — the operation itself always succeeds.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};
use crate::wal::events::{
    EVENT_TYPE_LEASE_EXPIRED, EVENT_TYPE_LEASE_GRANTED, EVENT_TYPE_LEASE_REVOKED,
};

#[derive(Args, Debug, Clone)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub action: LeaseAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LeaseAction {
    /// Grant a subject a TTL-bounded scoped capability.
    /// `neoth lease grant <peer-or-plugin> <scope> --ttl 1h`.
    Grant {
        /// Subject: a paired peer pub-key-hex or a plugin id.
        granted_to: String,
        /// Capability scope: `read` / `write_neoth_home` / `channel_send` /
        /// `cluster_task_accept` / `mcp_tool:<id>`.
        scope: String,
        /// Lease lifetime, e.g. `1h`, `30m`, `7d`, `3600` (bare = seconds).
        #[arg(long, default_value = "1h")]
        ttl: String,
    },
    /// Revoke a lease by id (full id or a unique prefix).
    Revoke {
        /// Lease id (or unique prefix) from `neoth lease list`.
        id: String,
    },
    /// List active leases (expired ones are pruned + audited first).
    List,
}

pub async fn run_lease(args: LeaseArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let path = LeaseStore::default_path(&home);
    let now = now_unix();

    match &args.action {
        LeaseAction::Grant {
            granted_to,
            scope,
            ttl,
        } => {
            let scope = LeaseScope::parse(scope)?;
            let ttl_secs = crate::cli::privacy::parse_duration(ttl)? as i64;
            let lease = CapabilityLease::new(granted_to.clone(), scope, ttl_secs, now);

            let mut store = LeaseStore::load(&path)?;
            store.grant(lease.clone());
            store.save(&path)?;
            emit_lease(&home, EVENT_TYPE_LEASE_GRANTED, &lease).await;

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&lease)?);
                }
                OutputFormat::Table => {
                    println!(
                        "✓ granted lease {} — {} may `{}` for {} (until {})",
                        short_id(&lease.lease_id),
                        lease.granted_to,
                        lease.scope.as_str(),
                        ttl,
                        lease.expires_unix
                    );
                }
            }
        }
        LeaseAction::Revoke { id } => {
            let mut store = LeaseStore::load(&path)?;
            let revoked = store.revoke(id).ok_or_else(|| {
                anyhow::anyhow!("no lease matching `{id}` — see `neoth lease list`")
            })?;
            store.save(&path)?;
            emit_lease(&home, EVENT_TYPE_LEASE_REVOKED, &revoked).await;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({ "revoked": revoked.lease_id, "ok": true })
                    );
                }
                OutputFormat::Table => println!("✓ revoked lease {}", short_id(&revoked.lease_id)),
            }
        }
        LeaseAction::List => {
            let mut store = LeaseStore::load(&path)?;
            // Prune + audit any newly-expired leases so the list is honest
            // AND the audit chain records the exact expiry.
            let expired = store.prune_expired(now);
            if !expired.is_empty() {
                store.save(&path)?;
                for l in &expired {
                    emit_lease(&home, EVENT_TYPE_LEASE_EXPIRED, l).await;
                }
            }
            let active = store.active(now);
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&active)?);
                }
                OutputFormat::Table => {
                    if active.is_empty() {
                        println!("(no active leases)");
                        return Ok(());
                    }
                    println!(
                        "{:<14} {:<28} {:<18} {:>10}",
                        "LEASE", "GRANTED_TO", "SCOPE", "TTL_LEFT"
                    );
                    for l in &active {
                        println!(
                            "{:<14} {:<28} {:<18} {:>9}s",
                            short_id(&l.lease_id),
                            truncate(&l.granted_to, 28),
                            l.scope.as_str(),
                            l.ttl_remaining_secs(now),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the audit payload for a lease frame. EXPIRED/REVOKED omit
/// `expires_unix` (the lease is already over); GRANTED carries it.
fn lease_payload(event_type: u8, lease: &CapabilityLease) -> Vec<u8> {
    let mut v = serde_json::json!({
        "lease_id": lease.lease_id,
        "granted_to": lease.granted_to,
        "scope": lease.scope.as_str(),
    });
    if event_type == EVENT_TYPE_LEASE_GRANTED {
        v["expires_unix"] = serde_json::json!(lease.expires_unix);
    }
    serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec())
}

/// Best-effort one-shot WAL emit (mirrors `cli::ingest`): if `neothd
/// serve` owns the writer we skip rather than race the segment — the
/// daemon re-derives lease state from leases.json on its next pass. The
/// lease mutation itself already succeeded on disk before we get here.
async fn emit_lease(home: &std::path::Path, event_type: u8, lease: &CapabilityLease) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(_pid)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        tracing::debug!("lease audit skipped: neothd serve owns the WAL writer");
        return;
    }
    let segment = home.join("wal").join("000001.wal");
    if let Some(parent) = segment.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let payload = lease_payload(event_type, lease);
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    match crate::wal::spawn(segment) {
        Ok((writer, join)) => {
            if let Err(e) = writer.append(header, payload).await {
                tracing::warn!(error = %e, "lease audit append failed (lease still applied)");
            }
            drop(writer);
            let _ = join.await;
        }
        Err(e) => tracing::warn!(error = %e, "could not spawn one-shot WAL writer for lease audit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_payload_granted_carries_expiry_others_do_not() {
        let lease = CapabilityLease::new("peerA", LeaseScope::Read, 3600, 1_700_000_000);
        let granted: serde_json::Value =
            serde_json::from_slice(&lease_payload(EVENT_TYPE_LEASE_GRANTED, &lease)).unwrap();
        assert_eq!(granted["granted_to"], "peerA");
        assert_eq!(granted["scope"], "read");
        assert!(granted.get("expires_unix").is_some());

        let revoked: serde_json::Value =
            serde_json::from_slice(&lease_payload(EVENT_TYPE_LEASE_REVOKED, &lease)).unwrap();
        assert!(
            revoked.get("expires_unix").is_none(),
            "revoked/expired frames omit expiry"
        );
        assert_eq!(revoked["lease_id"], lease.lease_id);
    }

    #[test]
    fn short_id_and_truncate() {
        assert_eq!(short_id("0123456789abcdef"), "0123456789ab");
        assert_eq!(truncate("short", 28), "short");
        assert_eq!(truncate("0123456789", 5), "0123…");
    }
}
