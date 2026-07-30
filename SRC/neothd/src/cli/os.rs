//! `neoth os launch` — PC-01 operator/agent surface for gated program launch.
//!
//! The runtime consumer of the `os_tools` app-launch gate: an operator (or the
//! agent) starts a program THROUGH the exec-allowlist + autonomy gate instead
//! of an ungated `Command::spawn`. Allowed only when the program canonicalizes
//! to EXACTLY one `freedom.yaml::tools.os.allowed_exec_paths` entry (default
//! empty = deny-all) AND the autonomy level permits it (Strict denies, Standard
//! + Elevated confirm ⇒ blocked here without a TTY, only Full auto-allows). The
//! launch carries no arguments and uses no shell. The launch (or denial) is
//! WAL-audited (`0xAC`/`0xAD`). Audit emit routes to a live same-home daemon;
//! otherwise it drains a unique home-bound one-shot segment.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::os_tools::{AuditSink, AuditStatus, OsGateError, launch_os_app};
#[cfg(feature = "os-clipboard")]
use crate::os_tools::{read_os_clipboard, write_os_clipboard};

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
    /// PC-01 (clipboard slice): READ the OS clipboard through the gated surface.
    /// Gated STRICTER than file-read: only Full autonomy auto-allows (Strict
    /// denies, Standard/Elevated confirm ⇒ blocked here without a TTY), AND both
    /// `tools.os.clipboard.enabled` + `.read_enabled` must be set. The content is
    /// printed to YOUR stdout (you asked for it) but NEVER recorded in the WAL —
    /// the `0xBC`/`0xBD` audit frame carries a byte count only.
    #[cfg(feature = "os-clipboard")]
    ClipboardGet,
    /// PC-01 (clipboard slice): WRITE text to the OS clipboard through the gated
    /// surface. Gated STRICTER than app-launch (Strict + Standard deny, Elevated
    /// confirms ⇒ blocked without a TTY, only Full auto-allows) AND requires
    /// `tools.os.clipboard.enabled` + `.write_enabled`. Newline-bearing content is
    /// refused (pastejacking guard) unless `allow_newlines_in_write`.
    #[cfg(feature = "os-clipboard")]
    ClipboardSet {
        /// Text to place on the clipboard. If omitted, read from stdin.
        text: Option<String>,
    },
}

type OneShotAuditWal = (
    crate::wal::writer::WalWriterHandle,
    crate::wal::writer::WalWriterCompletion,
);

fn open_one_shot_audit_wal(home: &Path, surface: &str) -> Result<OneShotAuditWal> {
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create one-shot OS audit WAL dir {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, surface);
    crate::wal::writer::spawn_for_home_with_completion(segment, home.to_path_buf())
        .context("spawn home-bound one-shot OS audit WAL writer")
}

async fn finish_one_shot_audit(
    completion: crate::wal::writer::WalWriterCompletion,
    status: &AuditStatus,
    required: bool,
    action: &str,
) -> Result<()> {
    let finalization_failure = completion.wait().await.err().map(|error| error.to_string());
    finish_tracked_audit(status, finalization_failure, required, action)
}

fn finish_tracked_audit(
    status: &AuditStatus,
    finalization_failure: Option<String>,
    required: bool,
    action: &str,
) -> Result<()> {
    let dispatch_failure = status.failure();
    if required && (dispatch_failure.is_some() || finalization_failure.is_some()) {
        anyhow::bail!(
            "refusing to report {action} as complete: required one-shot audit failed \
             (dispatch={}, finalization={})",
            dispatch_failure.as_deref().unwrap_or("ok"),
            finalization_failure.as_deref().unwrap_or("ok")
        );
    }
    if let Some(error) = dispatch_failure {
        tracing::warn!(
            error = %error,
            action,
            "one-shot OS audit dispatch failed (non-required audit)"
        );
    }
    if let Some(error) = finalization_failure {
        tracing::warn!(
            error = %error,
            action,
            "one-shot OS audit writer failed to finalize (non-required audit)"
        );
    }
    Ok(())
}

pub async fn run_os(args: OsArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if absent")?;
    match &args.action {
        OsAction::Launch { program } => run_launch(program, &cfg, args.output).await,
        #[cfg(feature = "os-clipboard")]
        OsAction::ClipboardGet => run_clipboard_get(&cfg, args.output).await,
        #[cfg(feature = "os-clipboard")]
        OsAction::ClipboardSet { text } => {
            run_clipboard_set(text.as_deref(), &cfg, args.output).await
        }
    }
}

async fn run_launch(program: &Path, cfg: &FreedomConfig, output: OutputFormat) -> Result<()> {
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon ownership via {}", pidfile.display()))?
        .is_some();
    // AUDIT-RPC-01 #1: under a required-audit posture, refuse the launch if the
    // daemon owns the WAL but its audit-RPC listener is unreachable — a launch
    // must never happen un-audited.
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    // Same one-shot-WAL pattern as `neoth fs`: when the daemon owns the WAL,
    // FORWARD the audit frame to it via the same-user OS audit-RPC channel
    // (AUDIT-RPC-01) rather than open a 2nd writer; the launch is gated either way.
    let result = {
        if daemon_live {
            let audit_status = AuditStatus::default();
            let result = launch_os_app(
                program,
                &cfg.tools.os,
                &cfg.autonomy_policy(),
                AuditSink::TrackedDaemonRpc {
                    home: &home,
                    status: &audit_status,
                },
                now,
            )
            .await;
            finish_tracked_audit(
                &audit_status,
                None,
                cfg.audit_rpc.required_for_oneshot_permission_events,
                "OS launch",
            )?;
            result
        } else {
            match open_one_shot_audit_wal(&home, "os-launch") {
                Ok((writer, completion)) => {
                    let audit_status = AuditStatus::default();
                    let r = launch_os_app(
                        program,
                        &cfg.tools.os,
                        &cfg.autonomy_policy(),
                        AuditSink::TrackedWriter {
                            writer: &writer,
                            status: &audit_status,
                        },
                        now,
                    )
                    .await;
                    drop(writer);
                    finish_one_shot_audit(
                        completion,
                        &audit_status,
                        cfg.audit_rpc.required_for_oneshot_permission_events,
                        "OS launch",
                    )
                    .await?;
                    r
                }
                Err(e) => {
                    // GOLD-SEC-13 / A-44: fail closed under a required-audit
                    // posture — a gated privileged launch must never proceed
                    // un-audited just because the one-shot writer failed.
                    if cfg.audit_rpc.required_for_oneshot_permission_events {
                        anyhow::bail!(
                            "refusing to launch un-audited: required-audit posture is set but the \
                             one-shot WAL writer could not be opened ({e})"
                        );
                    }
                    tracing::warn!(
                        error = %e,
                        "os launch proceeding WITHOUT WAL audit — could not open a one-shot WAL writer"
                    );
                    launch_os_app(
                        program,
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

/// PC-01 clipboard READ surface. Mirrors `run_launch`'s one-shot-WAL audit
/// dance (forward to the live daemon over audit-RPC, else open a one-shot
/// writer, else proceed un-audited with a warning) — the gate enforces the
/// kill-switches + autonomy + size cap. On success the content is printed to the
/// operator's OWN stdout (they explicitly asked for it); it is NEVER recorded.
#[cfg(feature = "os-clipboard")]
async fn run_clipboard_get(cfg: &FreedomConfig, output: OutputFormat) -> Result<()> {
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon ownership via {}", pidfile.display()))?
        .is_some();
    // A clipboard read is a permission event ⇒ refuse it un-audited if the
    // daemon owns the WAL but its audit-RPC listener is unreachable.
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    let clip = &cfg.tools.os.clipboard;
    let result = if daemon_live {
        let audit_status = AuditStatus::default();
        let result = read_os_clipboard(
            clip,
            &cfg.autonomy_policy(),
            AuditSink::TrackedDaemonRpc {
                home: &home,
                status: &audit_status,
            },
            now,
        )
        .await;
        finish_tracked_audit(
            &audit_status,
            None,
            cfg.audit_rpc.required_for_oneshot_permission_events,
            "clipboard read",
        )?;
        result
    } else {
        match open_one_shot_audit_wal(&home, "os-clipboard-read") {
            Ok((writer, completion)) => {
                let audit_status = AuditStatus::default();
                let r = read_os_clipboard(
                    clip,
                    &cfg.autonomy_policy(),
                    AuditSink::TrackedWriter {
                        writer: &writer,
                        status: &audit_status,
                    },
                    now,
                )
                .await;
                drop(writer);
                finish_one_shot_audit(
                    completion,
                    &audit_status,
                    cfg.audit_rpc.required_for_oneshot_permission_events,
                    "clipboard read",
                )
                .await?;
                r
            }
            Err(e) => {
                // GOLD-SEC-13 / A-44: fail closed under a required-audit posture.
                if cfg.audit_rpc.required_for_oneshot_permission_events {
                    anyhow::bail!(
                        "refusing un-audited clipboard read: required-audit posture is set but the \
                         one-shot WAL writer could not be opened ({e})"
                    );
                }
                tracing::warn!(error = %e, "clipboard read proceeding WITHOUT WAL audit — could not open a one-shot WAL writer");
                read_os_clipboard(clip, &cfg.autonomy_policy(), AuditSink::None, now).await
            }
        }
    };

    match result {
        Ok(content) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({ "content": content, "bytes": content.len() })
                    );
                }
                OutputFormat::Table => {
                    // Operator-requested content → their stdout. The WAL never saw it.
                    print!("{content}");
                }
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("clipboard read denied: {e}"),
    }
}

/// PC-01 clipboard WRITE surface. Same audit dance as `run_clipboard_get`. The
/// content NEVER appears in the WAL or in the success output (only a byte count).
#[cfg(feature = "os-clipboard")]
async fn run_clipboard_set(
    text: Option<&str>,
    cfg: &FreedomConfig,
    output: OutputFormat,
) -> Result<()> {
    // Resolve the content: explicit arg, else stdin (no echo).
    let content: String = match text {
        Some(t) => t.to_string(),
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("read clipboard text from stdin")?;
            buf
        }
    };

    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon ownership via {}", pidfile.display()))?
        .is_some();
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    let clip = &cfg.tools.os.clipboard;
    let result = if daemon_live {
        let audit_status = AuditStatus::default();
        let result = write_os_clipboard(
            &content,
            clip,
            &cfg.autonomy_policy(),
            AuditSink::TrackedDaemonRpc {
                home: &home,
                status: &audit_status,
            },
            now,
        )
        .await;
        finish_tracked_audit(
            &audit_status,
            None,
            cfg.audit_rpc.required_for_oneshot_permission_events,
            "clipboard write",
        )?;
        result
    } else {
        match open_one_shot_audit_wal(&home, "os-clipboard-write") {
            Ok((writer, completion)) => {
                let audit_status = AuditStatus::default();
                let r = write_os_clipboard(
                    &content,
                    clip,
                    &cfg.autonomy_policy(),
                    AuditSink::TrackedWriter {
                        writer: &writer,
                        status: &audit_status,
                    },
                    now,
                )
                .await;
                drop(writer);
                finish_one_shot_audit(
                    completion,
                    &audit_status,
                    cfg.audit_rpc.required_for_oneshot_permission_events,
                    "clipboard write",
                )
                .await?;
                r
            }
            Err(e) => {
                // GOLD-SEC-13 / A-44: fail closed under a required-audit posture.
                if cfg.audit_rpc.required_for_oneshot_permission_events {
                    anyhow::bail!(
                        "refusing un-audited clipboard write: required-audit posture is set but the \
                         one-shot WAL writer could not be opened ({e})"
                    );
                }
                tracing::warn!(error = %e, "clipboard write proceeding WITHOUT WAL audit — could not open a one-shot WAL writer");
                write_os_clipboard(&content, clip, &cfg.autonomy_policy(), AuditSink::None, now)
                    .await
            }
        }
    };

    match result {
        Ok(bytes) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "bytes": bytes, "written": true }));
                }
                OutputFormat::Table => {
                    // Never echo the content back.
                    println!("✓ clipboard updated ({bytes} bytes)");
                }
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("clipboard write denied: {e}"),
    }
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}
