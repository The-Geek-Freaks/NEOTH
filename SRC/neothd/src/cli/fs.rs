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
        /// Append a bounded, untrusted local codegraph sidecar after a
        /// successful read.  This remains off unless both this switch and the
        /// existing `code_map.outline_enrichment` master switch are enabled.
        #[arg(long, requires = "repository_root")]
        codegraph_enrichment: bool,
        /// Absolute indexed repository root required with
        /// `--codegraph-enrichment`.  It binds the sidecar to one contained
        /// target; it does not expand the OS read allowlist.
        #[arg(long, value_name = "ABSOLUTE_ROOT")]
        repository_root: Option<PathBuf>,
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
        FsAction::Read {
            path,
            codegraph_enrichment,
            repository_root,
        } => {
            let enrichment_root = match (*codegraph_enrichment, repository_root.as_deref()) {
                (false, None) => None,
                (true, Some(root)) if root.is_absolute() => Some(root),
                (true, Some(_)) => anyhow::bail!(
                    "--repository-root must be absolute when --codegraph-enrichment is set"
                ),
                (true, None) => anyhow::bail!(
                    "--codegraph-enrichment requires --repository-root <ABSOLUTE_ROOT>"
                ),
                (false, Some(_)) => {
                    anyhow::bail!("--repository-root requires --codegraph-enrichment")
                }
            };
            run_read(path, &cfg, args.output, enrichment_root).await
        }
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
    let pidfile = home.join("neothd.pid");
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
    // FORWARD the audit frame to it via the same-user OS audit-RPC channel
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
            let wal_dir = home.join("wal");
            let opened = std::fs::create_dir_all(&wal_dir)
                .map_err(crate::wal::error::WalError::Io)
                .and_then(|()| {
                    let segment =
                        crate::wal::writer::unique_standalone_segment_path(&wal_dir, "fs-write");
                    crate::wal::writer::spawn_for_home(segment, home.clone())
                });
            match opened {
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

async fn run_read(
    path: &Path,
    cfg: &FreedomConfig,
    output: OutputFormat,
    enrichment_root: Option<&Path>,
) -> Result<()> {
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
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
    // writer, FORWARD the audit frame to it via the same-user OS audit-RPC channel
    // (AUDIT-RPC-01) rather than open a 2nd writer racing the segment. The read
    // is gated either way. Inlined rather than a generic higher-order helper to
    // avoid an unnameable borrow lifetime across the awaited future.
    let result = {
        if daemon_live {
            read_with_optional_native_enrichment(
                path,
                cfg,
                AuditSink::DaemonRpc(&home),
                now,
                &home,
                enrichment_root,
            )
            .await
        } else {
            let wal_dir = home.join("wal");
            let opened = std::fs::create_dir_all(&wal_dir)
                .map_err(crate::wal::error::WalError::Io)
                .and_then(|()| {
                    let segment =
                        crate::wal::writer::unique_standalone_segment_path(&wal_dir, "fs-read");
                    crate::wal::writer::spawn_for_home(segment, home.clone())
                });
            match opened {
                Ok((writer, join)) => {
                    let r = read_with_optional_native_enrichment(
                        path,
                        cfg,
                        AuditSink::Writer(&writer),
                        now,
                        &home,
                        enrichment_root,
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
                    read_with_optional_native_enrichment(
                        path,
                        cfg,
                        AuditSink::None,
                        now,
                        &home,
                        enrichment_root,
                    )
                    .await
                }
            }
        }
    };

    match result {
        Ok(read) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let mut rendered = serde_json::json!({
                        "path": path.display().to_string(),
                        "bytes": read.text.len(),
                        "content": read.text,
                    });
                    if let Some(enrichment) = read.enrichment {
                        rendered["codegraph_enrichment"] = serde_json::Value::String(enrichment);
                    }
                    println!("{}", rendered);
                }
                OutputFormat::Table => {
                    print!("{}", read.text);
                    if let Some(enrichment) = read.enrichment {
                        print!("\n{enrichment}");
                    }
                }
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

#[derive(Debug)]
struct FsReadOutcome {
    text: String,
    enrichment: Option<String>,
}

/// The default route stays on the compatibility wrapper.  The opt-in route
/// performs the same OS preflight first, then exactly one typed native
/// PreToolUse admission, and only then consumes the opaque gate admission for
/// the existing bounded same-fd reader.
async fn read_with_optional_native_enrichment(
    path: &Path,
    cfg: &FreedomConfig,
    sink: AuditSink<'_>,
    now: i64,
    home: &Path,
    repository_root: Option<&Path>,
) -> Result<FsReadOutcome, OsGateError> {
    read_with_optional_native_enrichment_with_cancellation(
        path,
        cfg,
        sink,
        now,
        home,
        repository_root,
        crate::hooks::PreToolUseCancellation::unbound(),
        crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
    )
    .await
}

async fn read_with_optional_native_enrichment_with_cancellation(
    path: &Path,
    cfg: &FreedomConfig,
    sink: AuditSink<'_>,
    now: i64,
    home: &Path,
    repository_root: Option<&Path>,
    cancellation: crate::hooks::PreToolUseCancellation,
    timeout: std::time::Duration,
) -> Result<FsReadOutcome, OsGateError> {
    let Some(repository_root) = repository_root else {
        return read_os_file(path, &cfg.tools.os, &cfg.autonomy_policy(), sink, now)
            .await
            .map(|text| FsReadOutcome {
                text,
                enrichment: None,
            });
    };

    let admitted = crate::os_tools::gate::preflight_os_file_read(
        path,
        &cfg.tools.os,
        &cfg.autonomy_policy(),
        sink,
        now,
    )
    .await?;
    let root = repository_root.canonicalize().map_err(|error| {
        OsGateError::PreToolUse(format!(
            "cannot canonicalize repository root {}: {error}",
            repository_root.display()
        ))
    })?;
    let arguments = serde_json::json!({
        "path": admitted.canonical_path().display().to_string(),
        "repository_root": root.display().to_string(),
    });
    let context = crate::hooks::PreToolUseContext::admitted(
        crate::hooks::PreToolUseOrigin::DirectCliOsFileRead,
        "native-os-file-read",
        "fs-read",
        &arguments,
        &root,
        &root,
        timeout,
        cancellation,
        crate::hooks::PreToolUseReplay::direct_request(),
    )
    .map_err(|error| OsGateError::PreToolUse(error.to_string()))?;
    let hooks = crate::hooks::load_all_strict(&home.join("hooks"))
        .await
        .map_err(|error| {
            OsGateError::PreToolUse(format!("cannot load configured hooks: {error:#}"))
        })?;
    let once_guard = crate::hooks::SessionOnceGuard::new();
    let hook_enrichment = match crate::hooks::run_pre_tool_use(
        &context,
        crate::hooks::PreToolUseHookPolicy::Configured(&hooks),
        &once_guard,
    ) {
        crate::hooks::PreToolUseDisposition::Block { reason } => {
            return Err(OsGateError::PreToolUse(reason));
        }
        crate::hooks::PreToolUseDisposition::Continue => None,
        crate::hooks::PreToolUseDisposition::Enrich(enrichment) => {
            Some(enrichment.as_str().to_owned())
        }
    };
    let native_plan = crate::mcp::codegraph_server::prepare_native_fs_read_enrichment(
        home,
        &root,
        admitted.canonical_path(),
        &context,
        cfg.code_map.outline_enrichment,
    )
    .unwrap_or_else(|error| {
        tracing::debug!(error = %error, "native fs codegraph sidecar unavailable");
        None
    });
    if context.is_cancelled() || context.deadline_elapsed() {
        return Err(OsGateError::PreToolUse(
            "cancelled or deadline elapsed before the native file read".to_owned(),
        ));
    }
    let text = crate::os_tools::gate::invoke_preflighted_os_file_read(admitted, sink, now).await?;
    let native_enrichment = native_plan
        .and_then(|plan| plan.still_fresh())
        .map(|sidecar| sidecar.as_str().to_owned());
    let enrichment = match (native_enrichment, hook_enrichment) {
        (Some(native), Some(hook)) if native == hook => Some(native),
        (Some(native), Some(hook)) => {
            let combined = format!("{native}\n{hook}");
            if combined.len() <= crate::hooks::pre_tool_use::MAX_PRE_TOOL_USE_ENRICHMENT_BYTES {
                Some(combined)
            } else {
                tracing::debug!(
                    "distinct native and PreToolUse sidecars exceed the bounded direct-read output; retaining native evidence"
                );
                Some(native)
            }
        }
        (Some(native), None) => Some(native),
        (None, Some(hook)) => Some(hook),
        (None, None) => None,
    };
    Ok(FsReadOutcome { text, enrichment })
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn w239_config(root: &Path) -> FreedomConfig {
        let mut config = FreedomConfig::default();
        config.tools.os.allowed_paths = vec![root.canonicalize().unwrap()];
        config.tools.os.max_read_bytes = 1_024;
        config
    }

    fn w239_write_generated_descriptor(home: &Path, repository: &Path) {
        let database = home.join("code_map.db");
        let map = crate::code_map::walker::RepoMapBuilder::new(repository)
            .with_symbols(true)
            .scan()
            .unwrap();
        let mut conn = crate::code_map::persist::open(&database).unwrap();
        crate::code_map::persist::persist_map_and_edges(&mut conn, &map, &[]).unwrap();
        drop(conn);
        let descriptor = crate::mcp::McpServerConfig {
            id: "neoth-codegraph".into(),
            description: None,
            command: std::env::current_exe()
                .unwrap()
                .canonicalize()
                .unwrap()
                .display()
                .to_string(),
            args: vec![
                "mcp".into(),
                "codegraph-serve".into(),
                "--db".into(),
                database.canonicalize().unwrap().display().to_string(),
            ],
            env: std::collections::HashMap::new(),
            enabled: true,
            allow_tools: Some(
                crate::mcp::codegraph_server::TOOL_NAMES
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            ),
            trust_all_tools: false,
            smart_approve: true,
            autonomy_gate: None,
        };
        std::fs::write(
            home.join("mcp_servers.yaml"),
            serde_yaml::to_string(&crate::mcp::McpServers {
                servers: vec![descriptor],
            })
            .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn w239_real_fs_caller_keeps_default_master_off_output_unenriched() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("plain.rs");
        std::fs::write(&file, "fn plain() {}\n").unwrap();
        let config = w239_config(repository.path());
        assert!(!config.code_map.outline_enrichment);

        let outcome = read_with_optional_native_enrichment(
            &file,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .expect("the real fs caller reads normally with the feature master off");
        assert_eq!(outcome.text, "fn plain() {}\n");
        assert!(outcome.enrichment.is_none());
    }

    #[tokio::test]
    async fn w239_real_fs_caller_appends_native_sidecar_only_for_fresh_indexed_target() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("indexed.rs");
        std::fs::write(&file, "fn indexed() {}\n").unwrap();
        w239_write_generated_descriptor(home.path(), repository.path());
        let mut config = w239_config(repository.path());
        config.code_map.outline_enrichment = true;

        let outcome = read_with_optional_native_enrichment(
            &file,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .expect("the real fs caller enriches one fresh indexed local file");
        assert_eq!(outcome.text, "fn indexed() {}\n");
        assert!(
            outcome
                .enrichment
                .as_deref()
                .is_some_and(|sidecar| sidecar.contains("native_origin: direct_cli_os_file_read"))
        );
    }

    #[tokio::test]
    async fn w239_real_fs_caller_denial_stops_before_typed_native_read() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("denied.rs");
        std::fs::write(&file, "fn denied() {}\n").unwrap();
        let mut config = w239_config(repository.path());
        config.tools.os.allowed_paths.clear();

        let error = read_with_optional_native_enrichment(
            &file,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .expect_err("an OS allowlist denial cannot reach native PreToolUse or the reader");
        assert!(matches!(error, OsGateError::Allowlist(_)));
    }

    #[tokio::test]
    async fn w239_real_fs_caller_cancellation_stops_before_native_read() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("cancel.rs");
        std::fs::write(&file, "fn not_read() {}\n").unwrap();
        let config = w239_config(repository.path());
        let cancelled = Arc::new(AtomicBool::new(true));

        let error = read_with_optional_native_enrichment_with_cancellation(
            &file,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
            crate::hooks::PreToolUseCancellation::from_chat_turn(cancelled),
            crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
        )
        .await
        .expect_err("a cancelled typed admission cannot reach the file reader");
        assert!(matches!(error, OsGateError::PreToolUse(_)));
    }

    #[tokio::test]
    async fn w239_real_fs_caller_zero_deadline_drops_admission_without_consuming_bytes() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("deadline.rs");
        std::fs::write(&file, "fn not_consumed() {}\n").unwrap();
        let config = w239_config(repository.path());

        let error = read_with_optional_native_enrichment_with_cancellation(
            &file,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
            crate::hooks::PreToolUseCancellation::unbound(),
            std::time::Duration::ZERO,
        )
        .await
        .expect_err("a zero deadline must drop the admitted descriptor before byte consumption");
        assert!(matches!(error, OsGateError::PreToolUse(_)));
    }
}
