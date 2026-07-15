//! `neoth fs read` — PC-01 operator/agent surface for gated OS file reads.
//!
//! The real runtime consumer of the `os_tools` gate: an operator (or the
//! agent) fetches file contents THROUGH the allowlist + autonomy gate instead
//! of an ungated `std::fs::read`. Allowed only when the path is under
//! `freedom.yaml::tools.os.allowed_paths` (default empty = deny-all) and the
//! autonomy level permits it; the read (or denial) is WAL-audited (`0xA8` /
//! `0xA9`). Audit emit mirrors the HF-01 best-effort one-shot writer — skip if
//! `neothd serve` owns the WAL, else append one frame.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::os_tools::{AuditSink, OsGateError, read_os_file};

#[derive(Args, Debug, Clone)]
pub struct FsArgs {
    #[command(subcommand)]
    pub action: FsAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum FsAction {
    /// Read a file through the gated OS-tool surface. Permitted only when the
    /// path is under `freedom.yaml::tools.os.allowed_paths` (default deny-all)
    /// AND the autonomy level allows it (Strict confirms ⇒ blocked here, since
    /// this path has no interactive prompt). WAL-audited (`0xA8`/`0xA9`).
    Read {
        /// File to read.
        path: PathBuf,
    },
    /// Write a file through the gated OS-tool surface (PC-01 write slice).
    /// Permitted only when the target's canonical PARENT is under
    /// `freedom.yaml::tools.os.allowed_write_paths` (SEPARATE from the read
    /// allowlist; default deny-all) AND the autonomy level allows it (Strict
    /// denies, Standard confirms ⇒ blocked here without a TTY, Elevated/Full
    /// allow). WAL-audited (`0xAA`/`0xAB`). Best-effort atomic (temp + rename).
    Write {
        /// File to write (its parent dir must exist + be write-allowlisted).
        path: PathBuf,
        /// Content to write.
        content: String,
    },
}

pub async fn run_fs(args: FsArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if absent")?;
    match &args.action {
        FsAction::Read { path } => run_read(path, &cfg, args.output).await,
        FsAction::Write { path, content } => run_write(path, content, &cfg, args.output).await,
    }
}

async fn run_write(
    path: &Path,
    content: &str,
    cfg: &FreedomConfig,
    output: OutputFormat,
) -> Result<()> {
    let now = now_unix();
    let contents = content.as_bytes();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = crate::daemon::pidfile::default_pidfile();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    );
    // AUDIT-RPC-01 #1: under a required-audit posture, refuse the write if the
    // daemon owns the WAL but its audit-RPC listener is unreachable — so the
    // write never happens un-audited.
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    // Same one-shot-WAL pattern as run_read: when the daemon owns the WAL,
    // FORWARD the audit frame to it via the loopback audit-RPC channel
    // (AUDIT-RPC-01) instead of opening a racing 2nd writer; the write is gated
    // either way.
    let result = {
        if daemon_live {
            crate::os_tools::write_os_file(
                path,
                contents,
                &cfg.tools.os,
                &cfg.autonomy_policy(),
                AuditSink::DaemonRpc(&home),
                now,
            )
            .await
        } else {
            let segment = FreedomConfig::default_neoth_home()
                .join("wal")
                .join("000001.wal");
            if let Some(parent) = segment.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match crate::wal::spawn(segment) {
                Ok((writer, join)) => {
                    let r = crate::os_tools::write_os_file(
                        path,
                        contents,
                        &cfg.tools.os,
                        &cfg.autonomy_policy(),
                        AuditSink::Writer(&writer),
                        now,
                    )
                    .await;
                    drop(writer);
                    let _ = join.await;
                    r
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "fs write proceeding WITHOUT WAL audit — could not open a one-shot WAL writer"
                    );
                    crate::os_tools::write_os_file(
                        path,
                        contents,
                        &cfg.tools.os,
                        &cfg.autonomy_policy(),
                        AuditSink::None,
                        now,
                    )
                    .await
                }
            }
        }
    };

    match result {
        Ok(resolved) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": resolved.display().to_string(),
                            "bytes": contents.len(),
                            "written": true,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("✓ wrote {} bytes to {}", contents.len(), resolved.display());
                }
            }
            Ok(())
        }
        Err(e) => {
            // Gated denial / failure — surface it (non-zero exit via anyhow).
            anyhow::bail!("fs write denied: {e}");
        }
    }
}

async fn run_read(path: &Path, cfg: &FreedomConfig, output: OutputFormat) -> Result<()> {
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = crate::daemon::pidfile::default_pidfile();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    );
    // AUDIT-RPC-01 #1: under a required-audit posture, refuse the read if the
    // daemon owns the WAL but its audit-RPC listener is unreachable.
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    // Best-effort one-shot WAL audit (HF-01 pattern): if `neothd serve` owns the
    // writer, FORWARD the audit frame to it via the loopback audit-RPC channel
    // (AUDIT-RPC-01) rather than open a 2nd writer racing the segment. The read
    // is gated either way. Inlined rather than a generic higher-order helper to
    // avoid an unnameable borrow lifetime across the awaited future.
    let result = {
        if daemon_live {
            read_os_file(
                path,
                &cfg.tools.os,
                &cfg.autonomy_policy(),
                AuditSink::DaemonRpc(&home),
                now,
            )
            .await
        } else {
            let segment = FreedomConfig::default_neoth_home()
                .join("wal")
                .join("000001.wal");
            if let Some(parent) = segment.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match crate::wal::spawn(segment) {
                Ok((writer, join)) => {
                    let r = read_os_file(
                        path,
                        &cfg.tools.os,
                        &cfg.autonomy_policy(),
                        AuditSink::Writer(&writer),
                        now,
                    )
                    .await;
                    drop(writer);
                    let _ = join.await;
                    r
                }
                Err(e) => {
                    // Audit-unavailable is NOT silently swallowed: the read
                    // still runs gated, but we surface that no WAL frame was
                    // written so the "every read is audited" contract failing
                    // is visible (disk-full / locked wal dir / perms).
                    tracing::warn!(
                        error = %e,
                        "fs read proceeding WITHOUT WAL audit — could not open a one-shot WAL writer"
                    );
                    read_os_file(
                        path,
                        &cfg.tools.os,
                        &cfg.autonomy_policy(),
                        AuditSink::None,
                        now,
                    )
                    .await
                }
            }
        }
    };

    match result {
        Ok(text) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "path": path.display().to_string(),
                            "bytes": text.len(),
                            "content": text,
                        })
                    );
                }
                OutputFormat::Table => print!("{text}"),
            }
            Ok(())
        }
        // The gate already audited the denial; surface a clean operator error.
        Err(OsGateError::Allowlist(e)) => {
            anyhow::bail!(
                "denied: {e}\n(add the path's prefix to freedom.yaml::tools.os.allowed_paths)"
            )
        }
        Err(e) => anyhow::bail!("{e}"),
    }
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}
