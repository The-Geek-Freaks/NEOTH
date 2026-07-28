//! `neoth risk-confirm` — GOLD-ADOPT-23 (operator point 3).
//!
//! The operator-friendly wrapper over the risk-override LEASE (the P1.1
//! "operationalised Confirm"). When the MCP dispatch risk gate blocks a tool
//! call with `RISK_GATE_CONFIRM_REQUIRED` (or even a `Deny`), the operator opens
//! a TTL-bounded window with:
//!
//! ```text
//! neoth risk-confirm --ttl 10m            # lift the dangerous-command block
//! neoth risk-confirm --ttl 5m --egress    # also lift the egress block
//! neoth risk-confirm --egress-only --ttl 2m
//! ```
//!
//! It grants the same `operator` / `dangerous_command` (+/- `egress`) lease that
//! `neoth lease grant operator dangerous_command --ttl 300` would — so it's pure
//! sugar over the existing [`crate::permissions::lease`] store the dispatch loop
//! already consults — and emits a DEDICATED `RISK_CONFIRM_GRANTED` (0x54) audit
//! frame so the risk-gate trail is queryable as a unit (`neoth wal show --type
//! risk_confirm_granted`). The window auto-expires (no global `policy=warn`
//! flip) and is revocable early via `neoth lease revoke <id>`.

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};
use crate::security::risk_gate::RISK_LEASE_SUBJECT;
use crate::wal::events::EVENT_TYPE_RISK_CONFIRM_GRANTED;

#[derive(Args, Debug, Clone)]
pub struct RiskConfirmArgs {
    /// How long the confirm window stays open — `10m`, `300s`, `1h`, or a bare
    /// number of seconds. Default `10m`.
    #[arg(long, default_value = "10m")]
    pub ttl: String,
    /// Also lift the egress block (outbound to a non-allowlisted destination),
    /// in addition to the dangerous-command block.
    #[arg(long)]
    pub egress: bool,
    /// Lift ONLY the egress block (leave dangerous commands gated).
    #[arg(long)]
    pub egress_only: bool,
    /// Output format (inherited from the global `--output`).
    #[arg(skip)]
    pub output: OutputFormat,
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

/// Resolve the requested flags into the (dangerous, egress) scopes to grant.
/// `--egress-only` wins; otherwise dangerous is always granted and `--egress`
/// adds the egress dimension.
pub fn resolve_scopes(egress: bool, egress_only: bool) -> (bool, bool) {
    if egress_only {
        (false, true)
    } else {
        (true, egress)
    }
}

pub async fn run_risk_confirm(args: RiskConfirmArgs) -> Result<()> {
    let ttl_secs = crate::cli::privacy::parse_duration(&args.ttl)? as i64;
    if ttl_secs <= 0 {
        anyhow::bail!("--ttl must be greater than zero (e.g. 10m / 300s / 1h)");
    }
    // GR-032 — bound the risk-override window so a `--ttl 9999d` can't leave a
    // safety block permanently lifted. risk-confirm grants dangerous_command
    // (+ optionally egress); both scopes share the same cap.
    LeaseScope::DangerousCommand.check_ttl(ttl_secs)?;
    let (do_dangerous, do_egress) = resolve_scopes(args.egress, args.egress_only);

    let home = FreedomConfig::default_neoth_home();
    let path = LeaseStore::default_path(&home);
    let now = now_unix();

    let mut store = LeaseStore::load(&path).context("load leases.json")?;
    let mut granted: Vec<CapabilityLease> = Vec::new();
    if do_dangerous {
        let l = CapabilityLease::new(
            RISK_LEASE_SUBJECT,
            LeaseScope::DangerousCommand,
            ttl_secs,
            now,
        );
        store.grant(l.clone());
        granted.push(l);
    }
    if do_egress {
        let l = CapabilityLease::new(RISK_LEASE_SUBJECT, LeaseScope::Egress, ttl_secs, now);
        store.grant(l.clone());
        granted.push(l);
    }
    store
        .save(&path)
        .with_context(|| format!("write {}", path.display()))?;

    let expires_unix = now.saturating_add(ttl_secs);
    emit_risk_confirm_granted(&home, &granted, ttl_secs, expires_unix, now).await;

    let scopes: Vec<&str> = granted.iter().map(|l| l.scope.as_str()).collect();
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "subject": RISK_LEASE_SUBJECT,
                    "scopes": scopes,
                    "ttl_secs": ttl_secs,
                    "expires_unix": expires_unix,
                    "lease_ids": granted.iter().map(|l| l.lease_id.clone()).collect::<Vec<_>>(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "✓ risk-confirm window open for {} ({}s) — lifts: {}",
                args.ttl,
                ttl_secs,
                scopes.join(" + ")
            );
            for l in &granted {
                println!(
                    "    lease {} ({}) — auto-expires at unix {}",
                    short_id(&l.lease_id),
                    l.scope.as_str(),
                    l.expires_unix
                );
            }
            println!(
                "  The next blocked tool call in this window proceeds (audited \
                 RISK_CONFIRM_USED). Revoke early: neoth lease revoke {}",
                granted
                    .first()
                    .map(|l| short_id(&l.lease_id))
                    .unwrap_or_else(|| "<id>".to_string())
            );
        }
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Best-effort `RISK_CONFIRM_GRANTED` (0x54) audit emit. Mirrors
/// `cli::lease::emit_lease`: when the daemon owns the WAL, forward over the
/// same-user OS audit-RPC (0x54 is allowlisted); otherwise a one-shot writer
/// appends directly. The lease itself already persisted to disk before this.
async fn emit_risk_confirm_granted(
    home: &std::path::Path,
    granted: &[CapabilityLease],
    ttl_secs: i64,
    expires_unix: i64,
    now: i64,
) {
    if granted.is_empty() {
        return;
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "subject": RISK_LEASE_SUBJECT,
        "scopes": granted.iter().map(|l| l.scope.as_str()).collect::<Vec<_>>(),
        "ttl_secs": ttl_secs,
        "expires_unix": expires_unix,
        "source": "cli",
        "ts_unix": now,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());

    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(_pid)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            EVENT_TYPE_RISK_CONFIRM_GRANTED,
            &payload,
        )
        .await
        {
            tracing::debug!(error = %e, "risk-confirm audit forward skipped (daemon listener unreachable)");
        }
        return;
    }
    let segment = home.join("wal").join("000001.wal");
    if let Some(parent) = segment.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_RISK_CONFIRM_GRANTED, &payload).build();
    match crate::wal::spawn(segment) {
        Ok((writer, join)) => {
            if let Err(e) = writer.append(header, payload).await {
                tracing::warn!(error = %e, "risk-confirm audit append failed (lease still applied)");
            }
            drop(writer);
            let _ = join.await;
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not spawn one-shot WAL writer for risk-confirm audit")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_scopes_default_is_dangerous_only() {
        assert_eq!(resolve_scopes(false, false), (true, false));
    }

    #[test]
    fn resolve_scopes_egress_adds_egress() {
        assert_eq!(resolve_scopes(true, false), (true, true));
    }

    #[test]
    fn resolve_scopes_egress_only_drops_dangerous() {
        assert_eq!(resolve_scopes(true, true), (false, true));
        assert_eq!(resolve_scopes(false, true), (false, true));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn risk_confirm_grants_dangerous_lease_the_gate_will_honour() {
        // End-to-end: `neoth risk-confirm` writes a lease the dispatch loop's
        // RISK_LEASE_SUBJECT/DangerousCommand check (find_covering) accepts.
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let prev = std::env::var("NEOTH_HOME").ok();
        unsafe { std::env::set_var("NEOTH_HOME", dir.path()) };

        let r = run_risk_confirm(RiskConfirmArgs {
            ttl: "10m".to_string(),
            egress: true,
            egress_only: false,
            output: OutputFormat::Json,
        })
        .await;

        // The lease store now carries an active dangerous + egress lease for the
        // operator subject.
        let path = LeaseStore::default_path(dir.path());
        let store = LeaseStore::load(&path).unwrap();
        let now = now_unix();
        let dangerous = store.find_covering(RISK_LEASE_SUBJECT, &LeaseScope::DangerousCommand, now);
        let egress = store.find_covering(RISK_LEASE_SUBJECT, &LeaseScope::Egress, now);

        if let Some(v) = prev {
            unsafe { std::env::set_var("NEOTH_HOME", v) };
        } else {
            unsafe { std::env::remove_var("NEOTH_HOME") };
        }

        assert!(r.is_ok(), "{r:?}");
        assert!(
            dangerous.is_some(),
            "dangerous_command lease must be active"
        );
        assert!(
            egress.is_some(),
            "egress lease must be active with --egress"
        );
        // TTL ~ 600s.
        assert!(dangerous.unwrap().ttl_remaining_secs(now) > 500);
    }

    #[tokio::test]
    async fn zero_ttl_is_rejected() {
        let r = run_risk_confirm(RiskConfirmArgs {
            ttl: "0s".to_string(),
            egress: false,
            egress_only: false,
            output: OutputFormat::Table,
        })
        .await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("greater than zero"));
    }

    #[tokio::test]
    async fn over_cap_ttl_is_rejected() {
        // GR-032: a risk-confirm window beyond the 24h cap is refused before any
        // lease is written — a safety-block override must auto-expire.
        let r = run_risk_confirm(RiskConfirmArgs {
            ttl: "9999d".to_string(),
            egress: false,
            egress_only: false,
            output: OutputFormat::Table,
        })
        .await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("maximum"));
    }
}
