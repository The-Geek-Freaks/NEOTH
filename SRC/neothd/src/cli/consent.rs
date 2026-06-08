//! `neoth consent` — manage first-run outbound-LLM consent (V03-08).
//!
//! Subcommands: `list`, `grant <provider>`, `revoke <provider>`. The chat +
//! serve paths gate cloud-bound provider calls behind a recorded consent
//! marker so the operator's text never reaches a third-party until they
//! explicitly opt in.
//!
//! Consent state lives under `~/.neoth/consent/<provider_kind>.granted`.
//! Operators can audit by hand (`ls ~/.neoth/consent/`) or via this CLI.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::consent;
use crate::wal::events::{EVENT_TYPE_CONSENT_GRANTED, EVENT_TYPE_CONSENT_REVOKED};

#[derive(Args, Debug, Clone)]
pub struct ConsentArgs {
    #[command(subcommand)]
    pub action: ConsentAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConsentAction {
    /// List recorded consent grants under `~/.neoth/consent/`.
    List,
    /// Show consent state for a single provider.
    Show {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
    /// Record consent for sending operator text to a cloud provider.
    Grant {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
    /// Remove a previously recorded consent grant.
    Revoke {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
}

pub async fn run_consent(args: ConsentArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        ConsentAction::List => render_list(&home, args.output),
        ConsentAction::Show { provider } => render_show(&home, provider, args.output),
        ConsentAction::Grant { provider } => render_grant(&home, provider, args.output).await,
        ConsentAction::Revoke { provider } => render_revoke(&home, provider, args.output).await,
    }
}

/// SR-017 / GOLD-SEC-30: record a consent grant/revoke in the WAL. Granting a
/// cloud provider permission to receive operator text is a security-relevant
/// privilege change and must be forensically visible — the marker-file path
/// previously mutated permission state with no audit frame. Mirrors
/// `cli::autonomy::emit_autonomy_change`: forward over the loopback audit-RPC
/// channel when the daemon owns the single WAL writer (0xDB/0xDC are
/// allowlisted there), otherwise open a one-shot writer. Best-effort — the
/// grant/revoke itself already succeeded by the time this runs. Payload (JSON):
/// `{provider, source:"cli", ts_unix}` (provider slug only, never a secret).
/// Best-effort liveness probe for the daemon that owns the single WAL writer.
fn daemon_is_live() -> bool {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    )
}

async fn emit_consent_change(
    event_type: u8,
    provider: ProviderKind,
    daemon_live: bool,
    home: &std::path::Path,
) {
    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = serde_json::to_vec(&json!({
        "provider": consent::slug(provider),
        "source": "cli",
        "ts_unix": ts_unix,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());

    if daemon_live {
        if let Err(e) =
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
        {
            tracing::debug!(error = %e, "consent-change audit forward failed (best-effort)");
        }
    } else {
        let segment = home.join("wal").join("000001.wal");
        if let Some(parent) = segment.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok((writer, join)) = crate::wal::spawn(segment) {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let _ = writer.append(header, payload).await;
            drop(writer);
            let _ = join.await;
        }
    }
}

fn render_list(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let grants = consent::list_grants(home)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload: Vec<serde_json::Value> = grants
                .iter()
                .map(|(k, ts)| {
                    json!({
                        "provider": consent::slug(*k),
                        "granted_unix_ts": ts,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            if grants.is_empty() {
                println!("No consent grants recorded.");
                println!();
                println!("Cloud providers require one-time consent before NEOTH routes");
                println!("any text to them. Run `neoth consent grant <provider>` to grant.");
                return Ok(());
            }
            println!("{:<18}  granted_unix_ts", "provider");
            println!("{}  {}", "-".repeat(18), "-".repeat(20));
            for (kind, ts) in grants {
                println!("{:<18}  {}", consent::slug(kind), ts);
            }
        }
    }
    Ok(())
}

fn render_show(home: &std::path::Path, provider: ProviderKind, output: OutputFormat) -> Result<()> {
    let slug_s = consent::slug(provider);
    let granted = consent::is_granted(home, provider);
    let is_cloud = consent::is_cloud(provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "is_cloud": is_cloud,
                    "granted": granted,
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            if !is_cloud {
                println!("{slug_s}: not a cloud provider — no consent required.");
                return Ok(());
            }
            if granted {
                println!("{slug_s}: GRANTED");
                println!("marker: {}", consent::marker_path(home, provider).display());
            } else {
                println!("{slug_s}: NOT GRANTED");
                println!("run `neoth consent grant {slug_s}` to record consent.");
            }
        }
    }
    Ok(())
}

async fn render_grant(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
) -> Result<()> {
    if !consent::is_cloud(provider) {
        anyhow::bail!(
            "provider `{}` is not a cloud provider — no consent required",
            consent::slug(provider)
        );
    }
    consent::grant(home, provider)?;
    // SR-017 / GOLD-SEC-30: forensic WAL trail for the consent grant.
    emit_consent_change(EVENT_TYPE_CONSENT_GRANTED, provider, daemon_is_live(), home).await;
    let slug_s = consent::slug(provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": "granted",
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("✓ consent granted for `{slug_s}`.");
            println!("marker: {}", consent::marker_path(home, provider).display());
        }
    }
    Ok(())
}

async fn render_revoke(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
) -> Result<()> {
    let slug_s = consent::slug(provider);
    let was_granted = consent::is_granted(home, provider);
    consent::revoke(home, provider)?;
    // SR-017 / GOLD-SEC-30: audit only a real revocation of a cloud marker.
    // (`is_granted` returns true for non-cloud kinds, which never hold a marker,
    // and a no-op revoke of an absent marker changed nothing — neither emits.)
    if was_granted && consent::is_cloud(provider) {
        emit_consent_change(EVENT_TYPE_CONSENT_REVOKED, provider, daemon_is_live(), home).await;
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": if was_granted { "revoked" } else { "noop" },
                }))?
            );
        }
        OutputFormat::Table => {
            if was_granted {
                println!("✓ consent revoked for `{slug_s}`.");
                println!(
                    "next chat against `{slug_s}` will re-prompt (or bail in non-interactive contexts)."
                );
            } else {
                println!("`{slug_s}` had no consent grant — nothing to revoke.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn grant_then_show_then_revoke_round_trip_via_render_helpers() {
        let tmp = TempDir::new().unwrap();
        // Direct module calls — render_* uses default_neoth_home() which we
        // can't override per call without env shimming. These tests pin the
        // underlying consent module behaviour the CLI dispatches to.
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }

    /// Count frames of a given event type in a WAL segment (v1/v2 aware).
    fn count_event_frames(segment: &std::path::Path, want: u8) -> usize {
        let bytes = std::fs::read(segment).unwrap_or_default();
        let mut n = 0usize;
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, dec| {
            if dec.header.event_type == want {
                n += 1;
            }
            Ok(())
        });
        n
    }

    /// SR-017 / GOLD-SEC-30: a one-shot consent grant must leave a
    /// `0xDB CONSENT_GRANTED` frame in the WAL (discoverable via
    /// `neoth wal show --type consent_granted`); a real revoke leaves a
    /// `0xDC CONSENT_REVOKED` frame.
    #[tokio::test]
    async fn grant_and_revoke_emit_consent_audit_frames_via_oneshot() {
        let tmp = TempDir::new().unwrap();
        let segment = tmp.path().join("wal").join("000001.wal");

        // daemon_live=false forces the deterministic one-shot writer path.
        emit_consent_change(
            EVENT_TYPE_CONSENT_GRANTED,
            ProviderKind::OpenaiApi,
            false,
            tmp.path(),
        )
        .await;
        assert_eq!(
            count_event_frames(&segment, EVENT_TYPE_CONSENT_GRANTED),
            1,
            "grant must write one CONSENT_GRANTED frame"
        );
        assert_eq!(count_event_frames(&segment, EVENT_TYPE_CONSENT_REVOKED), 0);

        emit_consent_change(
            EVENT_TYPE_CONSENT_REVOKED,
            ProviderKind::OpenaiApi,
            false,
            tmp.path(),
        )
        .await;
        assert_eq!(
            count_event_frames(&segment, EVENT_TYPE_CONSENT_REVOKED),
            1,
            "revoke must append one CONSENT_REVOKED frame"
        );
        // The grant frame is still present (append-only).
        assert_eq!(count_event_frames(&segment, EVENT_TYPE_CONSENT_GRANTED), 1);
    }

    /// The event-name registry resolves the new codes both ways (the 5-site
    /// registration is complete).
    #[test]
    fn consent_event_codes_resolve_in_the_registry() {
        use crate::wal::events::{event_code_from_filter, event_name_from_code};
        assert_eq!(
            event_code_from_filter("consent_granted"),
            Some(EVENT_TYPE_CONSENT_GRANTED)
        );
        assert_eq!(
            event_code_from_filter("consent_revoked"),
            Some(EVENT_TYPE_CONSENT_REVOKED)
        );
        assert_eq!(
            event_name_from_code(EVENT_TYPE_CONSENT_GRANTED),
            Some("consent_granted")
        );
        assert_eq!(
            event_name_from_code(EVENT_TYPE_CONSENT_REVOKED),
            Some("consent_revoked")
        );
    }
}
