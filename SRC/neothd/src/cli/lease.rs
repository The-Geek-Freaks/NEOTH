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
            if granted_to.trim().is_empty() {
                anyhow::bail!(
                    "subject (granted_to) must not be empty — a lease needs a real \
                     peer pub-key-hex or plugin id; an empty subject would never match"
                );
            }
            let scope = LeaseScope::parse(scope)?;
            let ttl_secs = crate::cli::privacy::parse_duration(ttl)? as i64;
            // GR-032 — a risk-override scope (dangerous_command / egress) is
            // hard-capped so a long `--ttl` can't leave a safety block lifted.
            scope.check_ttl(ttl_secs)?;
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
        // GOLD-COR-02 / A-04: cut on a char boundary (operator/peer strings
        // may be multibyte) so `[..end]` never panics mid-char.
        let mut end = max.saturating_sub(1);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
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
    serde_json::to_vec(&v).expect("lease audit payload is a serde_json::Value")
}

/// Best-effort one-shot WAL emit (mirrors `cli::ingest`): if `neothd
/// serve` owns the writer we skip rather than race the segment — the
/// daemon re-derives lease state from leases.json on its next pass. The
/// lease mutation itself already succeeded on disk before we get here.
async fn emit_lease(home: &std::path::Path, event_type: u8, lease: &CapabilityLease) {
    let payload = lease_payload(event_type, lease);
    let pidfile = home.join("neothd.pid");
    match crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        Ok(Some(_pid)) => {
            // AUDIT-RPC-01: the daemon owns the single WAL writer → forward the
            // lease audit over the same-user OS channel (0xA5/0xA6/0xA7 allowlisted)
            // instead of silently dropping it. Best-effort: a disabled audit route
            // or unreachable listener leaves the already-applied lease unchanged.
            if let Err(e) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
            {
                tracing::debug!(error = %e, "lease audit forward skipped (daemon listener unreachable)");
            }
            return;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                path = %pidfile.display(),
                "lease audit refused an unowned WAL writer"
            );
            return;
        }
    }
    let wal_dir = home.join("wal");
    if std::fs::create_dir_all(&wal_dir).is_err() {
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "lease");
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    match crate::wal::spawn_for_home(segment, home.to_path_buf()) {
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

    #[tokio::test]
    async fn lease_audit_uses_the_selected_home_and_collision_free_segments() {
        let home = tempfile::tempdir().unwrap();
        let lease = CapabilityLease::new("peerA", LeaseScope::Read, 3600, 1_700_000_000);
        emit_lease(home.path(), EVENT_TYPE_LEASE_GRANTED, &lease).await;
        emit_lease(home.path(), EVENT_TYPE_LEASE_REVOKED, &lease).await;

        let wal_dir = home.path().join("wal");
        assert!(wal_dir.join("hmac.key").is_file());
        let segments = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "wal"))
            .count();
        assert_eq!(segments, 2, "one-shot lease writers must not collide");
    }
}
