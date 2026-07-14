//! E-18 Workstream N (Session 22) — `neoth telemetry` CLI surface.
//!
//! Subcommands:
//!   - `status`        Print resolved endpoint + on/off + opt-in posture
//!   - `preview`       Print the exact payload that would be sent
//!   - `on`            Flip `freedom.yaml::telemetry.enabled = true`
//!   - `off`           Flip `freedom.yaml::telemetry.enabled = false`
//!   - `send-now`      Build payload + POST once + print outcome
//!
//! Defaults to `status` when no subcommand is given so an operator
//! running `neoth telemetry` lands on the safe, no-side-effect view.
//!
//! `on` + `off` mutate `freedom.yaml` via
//! [`crate::config::FreedomConfig::save_public_to_default_path`].
//! `send-now` honours the current `telemetry.enabled` flag UNLESS
//! `--force` is passed (operators use `--force` to dry-run a send
//! before flipping `enabled` on).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::telemetry::{build_payload, http, preview_for_operator, should_send};

#[derive(Args, Debug, Clone)]
pub struct TelemetryArgs {
    #[command(subcommand)]
    pub action: Option<TelemetryAction>,

    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TelemetryAction {
    /// Print resolved endpoint + on/off + opt-in posture. Default
    /// when no subcommand is given.
    Status,
    /// Print the exact payload that would be sent so the operator
    /// can audit BEFORE flipping `enabled` on.
    Preview,
    /// Flip `freedom.yaml::telemetry.enabled = true`. Operator MUST
    /// run this explicitly; default state is off.
    On,
    /// Flip `freedom.yaml::telemetry.enabled = false`.
    Off,
    /// Build the payload + POST it once + print the outcome. Honours
    /// `telemetry.enabled` unless `--force` is passed.
    SendNow {
        /// Dry-run a send even when `telemetry.enabled = false`.
        /// Useful for testing the endpoint without committing to
        /// daemon-boot pings.
        #[arg(long)]
        force: bool,
    },
}

pub async fn run_telemetry(args: TelemetryArgs) -> Result<()> {
    let action = args.action.unwrap_or(TelemetryAction::Status);
    match action {
        TelemetryAction::Status => run_status().await,
        TelemetryAction::Preview => run_preview().await,
        TelemetryAction::On => run_flip(true).await,
        TelemetryAction::Off => run_flip(false).await,
        TelemetryAction::SendNow { force } => run_send_now(force).await,
    }
}

async fn run_status() -> Result<()> {
    let config = load_config_or_default()?;
    let endpoint = config.telemetry.effective_endpoint();
    println!("telemetry:");
    println!("  enabled       : {}", config.telemetry.enabled);
    println!("  endpoint      : {endpoint}");
    println!(
        "  endpoint type : {}",
        if config.telemetry.endpoint.is_some() {
            "operator-override"
        } else {
            "default"
        }
    );
    if !config.telemetry.enabled {
        println!();
        println!("Telemetry is OFF. Run `neoth telemetry on` to opt in.");
        println!("Run `neoth telemetry preview` to see exactly what would be sent.");
    }
    Ok(())
}

async fn run_preview() -> Result<()> {
    let config = load_config_or_default()?;
    let operator_id = config.operator_id.as_deref().unwrap_or("anonymous");
    let payload = build_payload(env!("CARGO_PKG_VERSION"), operator_id);
    println!("{}", preview_for_operator(&payload));
    println!();
    println!(
        "Effective endpoint: {}",
        config.telemetry.effective_endpoint()
    );
    println!("Currently enabled : {}", config.telemetry.enabled);
    Ok(())
}

async fn run_flip(enabled: bool) -> Result<()> {
    let mut config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if missing")?;
    let was = config.telemetry.enabled;
    config.telemetry.enabled = enabled;
    config
        .save_public_to_default_path()
        .context("persist freedom.yaml::telemetry")?;
    println!(
        "telemetry.enabled : {was} → {enabled} (saved to {})",
        FreedomConfig::default_path().display()
    );
    if enabled {
        println!();
        println!("Telemetry is now ON. Next daemon boot will POST one anonymous payload.");
        println!("Run `neoth telemetry send-now` to verify the endpoint right now.");
    } else {
        println!();
        println!("Telemetry is now OFF. Nothing will be sent.");
    }
    Ok(())
}

async fn run_send_now(force: bool) -> Result<()> {
    let config = load_config_or_default()?;
    let endpoint = config.telemetry.effective_endpoint().to_string();
    let opted_in = should_send(&config.telemetry);

    if !opted_in && !force {
        println!(
            "telemetry is OFF — not sending. Re-run with `--force` to dry-run a send \
             without flipping `enabled` on, or run `neoth telemetry on` to opt in."
        );
        return Ok(());
    }

    let operator_id = config.operator_id.as_deref().unwrap_or("anonymous");
    let payload = build_payload(env!("CARGO_PKG_VERSION"), operator_id);

    println!("POST {endpoint}");
    println!(
        "body : {}",
        serde_json::to_string(&payload)
            .expect("telemetry payload contains only infallibly serializable fields")
    );
    println!();

    let outcome = http::send_payload(&endpoint, &payload).await;
    println!("outcome : {}", outcome.summary());
    if !outcome.is_sent() {
        // Non-zero exit so CI / scripts catch a failed verification.
        // GOLD-COR-01 / A-03: QuietExit instead of process::exit so the stack
        // unwinds and any Drop-time flushes run before the code is applied.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

fn load_config_or_default() -> Result<FreedomConfig> {
    FreedomConfig::load_from_default_path_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{DEFAULT_TELEMETRY_ENDPOINT, TelemetryConfig};

    #[test]
    fn telemetry_args_default_action_is_none_so_status_runs() {
        // `neoth telemetry` (no sub) → Status path inside run_telemetry.
        let args = TelemetryArgs {
            action: None,
            output: OutputFormat::Table,
        };
        // The dispatcher pattern-matches None → Status. We can't easily
        // run_telemetry here (it touches the operator's freedom.yaml),
        // but the unwrap_or default IS the contract.
        let resolved = args.action.unwrap_or(TelemetryAction::Status);
        assert!(matches!(resolved, TelemetryAction::Status));
    }

    #[test]
    fn telemetry_args_status_explicit_round_trips() {
        let args = TelemetryArgs {
            action: Some(TelemetryAction::Status),
            output: OutputFormat::Table,
        };
        assert!(matches!(args.action.unwrap(), TelemetryAction::Status));
    }

    #[test]
    fn telemetry_args_send_now_force_flag_round_trips() {
        let args = TelemetryArgs {
            action: Some(TelemetryAction::SendNow { force: true }),
            output: OutputFormat::Table,
        };
        match args.action.unwrap() {
            TelemetryAction::SendNow { force } => assert!(force),
            other => panic!("expected SendNow, got {other:?}"),
        }
    }

    #[test]
    fn default_endpoint_pinned_https_drift_guard() {
        // Hard rule — re-asserting at the CLI layer so a refactor
        // that swaps the const in mod.rs still trips the test.
        assert!(DEFAULT_TELEMETRY_ENDPOINT.starts_with("https://"));
    }

    #[test]
    fn telemetry_config_default_off_drift_guard() {
        // Hard rule re-asserted at the CLI level too — a default-on
        // regression would trip both this test AND
        // `telemetry::tests::default_config_is_off`.
        let cli_default = TelemetryConfig::default();
        assert!(!cli_default.enabled);
        assert!(cli_default.endpoint.is_none());
    }
}
