//! `neoth os launch` — PC-01 operator/agent surface for gated program launch.
//!
//! The runtime consumer of the `os_tools` app-launch gate: an operator (or the
//! agent) starts a program THROUGH the exec-allowlist + autonomy gate instead
//! of an ungated `Command::spawn`. Allowed only when the program canonicalizes
//! to EXACTLY one `freedom.yaml::tools.os.allowed_exec_paths` entry (default
//! empty = deny-all) AND the autonomy level permits it (Strict denies, Standard
//! + Elevated confirm ⇒ blocked here without a TTY, only Full auto-allows). The
//! launch carries no arguments and uses no shell. The launch (or denial) is
//! WAL-audited (`0xAC`/`0xAD`). Audit emit mirrors the HF-01 best-effort
//! one-shot writer — skip if `neothd serve` owns the WAL, else append one frame.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::os_tools::{OsGateError, launch_os_app};

#[derive(Args, Debug, Clone)]
pub struct OsArgs {
    #[command(subcommand)]
    pub action: OsAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OsAction {
    /// Launch a program through the gated OS-tool surface. Permitted only when
    /// the program canonicalizes to EXACTLY one
    /// `freedom.yaml::tools.os.allowed_exec_paths` entry (default deny-all) AND
    /// the autonomy level allows it (Strict denies; Standard + Elevated confirm
    /// ⇒ blocked here without a TTY; only Full auto-allows). Launched with NO
    /// arguments and NO shell. WAL-audited (`0xAC`/`0xAD`).
    Launch {
        /// Absolute path to the executable to launch (must be an exact entry in
        /// `tools.os.allowed_exec_paths`).
        program: PathBuf,
    },
}

pub async fn run_os(args: OsArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if absent")?;
    match &args.action {
        OsAction::Launch { program } => run_launch(program, &cfg, args.output).await,
    }
}

async fn run_launch(program: &Path, cfg: &FreedomConfig, output: OutputFormat) -> Result<()> {
    let now = now_unix();
    // Same one-shot-WAL pattern as `neoth fs`: skip opening a 2nd writer when
    // the daemon owns the WAL (the launch is gated either way).
    let result = {
        let pidfile = crate::daemon::pidfile::default_pidfile();
        let daemon_live = matches!(
            crate::daemon::pidfile::live_daemon_pid(&pidfile),
            Ok(Some(_))
        );
        if daemon_live {
            launch_os_app(program, &cfg.tools.os, cfg.autonomy, None, now).await
        } else {
            let segment = FreedomConfig::default_neoth_home()
                .join("wal")
                .join("000001.wal");
            if let Some(parent) = segment.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match crate::wal::spawn(segment) {
                Ok((writer, join)) => {
                    let r =
                        launch_os_app(program, &cfg.tools.os, cfg.autonomy, Some(&writer), now)
                            .await;
                    drop(writer);
                    let _ = join.await;
                    r
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "os launch proceeding WITHOUT WAL audit — could not open a one-shot WAL writer"
                    );
                    launch_os_app(program, &cfg.tools.os, cfg.autonomy, None, now).await
                }
            }
        }
    };

    match result {
        Ok((resolved, pid)) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "program": resolved.display().to_string(),
                            "pid": pid,
                            "launched": true,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("✓ launched {} (pid {pid})", resolved.display());
                }
            }
            Ok(())
        }
        // The gate already audited the denial; surface a clean operator error.
        Err(OsGateError::Allowlist(e)) => {
            anyhow::bail!(
                "denied: {e}\n(add the exact executable path to freedom.yaml::tools.os.allowed_exec_paths)"
            )
        }
        Err(e) => anyhow::bail!("os launch denied: {e}"),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
