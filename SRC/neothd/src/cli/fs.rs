//! `neoth fs read` — PC-01 operator/agent surface for gated OS file reads.
//!
//! The real runtime consumer of the `os_tools` gate: an operator (or the
//! agent) fetches file contents THROUGH the allowlist + autonomy gate instead
//! of an ungated `std::fs::read`. Allowed only when the path is under
//! `freedom.yaml::tools.os.allowed_paths` (default empty = deny-all) and the
//! autonomy level permits it; the read (or denial) is WAL-audited (`0xA8` /
//! `0xA9`). Audit emit mirrors the HF-01 best-effort one-shot writer — skip if
//! `neothd serve` owns the WAL, else append one frame.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

const DEFAULT_GREP_RESULTS: usize = 20;
const MAX_GREP_RESULTS: usize = 64;
const MAX_GREP_LITERAL_BYTES: usize = 256;
const MAX_GREP_LINE_BYTES: usize = 512;
const GREP_SNIPPET_PAYLOAD_BYTES: usize = MAX_GREP_LINE_BYTES - 6;
const DEFAULT_GLOB_RESULTS: usize = 20;
const MAX_GLOB_RESULTS: usize = 64;
const DEFAULT_GLOB_DEPTH: usize = 8;
const MAX_GLOB_DEPTH: usize = 16;
const MAX_GLOB_ENTRIES: usize = 4096;

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
    /// Search one allowlisted UTF-8 file for a literal string. This is never
    /// recursive, never invokes a shell, and does not interpret regex syntax.
    Grep {
        /// File to search through the gated OS-file-read surface.
        path: PathBuf,
        /// Literal non-empty UTF-8 text to find.
        literal: String,
        /// Maximum line matches to return (1..=64).
        #[arg(long, default_value_t = DEFAULT_GREP_RESULTS, value_parser = parse_grep_max_results)]
        max_results: usize,
        /// Append a bounded, untrusted local codegraph sidecar after a
        /// successful search. It remains off unless the existing outline
        /// enrichment master switch is also enabled.
        #[arg(long, requires = "repository_root")]
        codegraph_enrichment: bool,
        /// Absolute indexed repository root required with codegraph enrichment.
        #[arg(long, value_name = "ABSOLUTE_ROOT")]
        repository_root: Option<PathBuf>,
    },
    /// Enumerate bounded matching files below an allowlisted directory. This
    /// uses retained no-follow directory capabilities and never reads files.
    Glob {
        /// Absolute allowlisted directory root.
        root: PathBuf,
        /// UTF-8 root-relative glob pattern (`*`, `?`, `[]`, `**`).
        pattern: String,
        /// Maximum matches to return (1..=64).
        #[arg(long, default_value_t = DEFAULT_GLOB_RESULTS, value_parser = parse_glob_max_results)]
        max_results: usize,
        /// Maximum directory depth to traverse (0..=16).
        #[arg(long, default_value_t = DEFAULT_GLOB_DEPTH, value_parser = parse_glob_max_depth)]
        max_depth: usize,
        /// Add bounded indexed symbol summaries for returned paths.
        #[arg(long, requires = "repository_root")]
        codegraph_enrichment: bool,
        /// Absolute indexed repository root required with codegraph enrichment.
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

fn parse_grep_max_results(raw: &str) -> std::result::Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("grep max-results must be an integer from 1 through {MAX_GREP_RESULTS}")
    })?;
    if !(1..=MAX_GREP_RESULTS).contains(&value) {
        return Err(format!(
            "grep max-results must be from 1 through {MAX_GREP_RESULTS}"
        ));
    }
    Ok(value)
}

fn parse_glob_max_results(raw: &str) -> std::result::Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("glob max-results must be an integer from 1 through {MAX_GLOB_RESULTS}")
    })?;
    (1..=MAX_GLOB_RESULTS)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| format!("glob max-results must be from 1 through {MAX_GLOB_RESULTS}"))
}

fn parse_glob_max_depth(raw: &str) -> std::result::Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("glob max-depth must be an integer from 0 through {MAX_GLOB_DEPTH}")
    })?;
    (0..=MAX_GLOB_DEPTH)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| format!("glob max-depth must be from 0 through {MAX_GLOB_DEPTH}"))
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
        FsAction::Grep {
            path,
            literal,
            max_results,
            codegraph_enrichment,
            repository_root,
        } => {
            if !(1..=MAX_GREP_RESULTS).contains(max_results) {
                anyhow::bail!("grep max-results must be from 1 through {MAX_GREP_RESULTS}");
            }
            if literal.is_empty() || literal.len() > MAX_GREP_LITERAL_BYTES {
                anyhow::bail!("grep literal must contain 1..={MAX_GREP_LITERAL_BYTES} UTF-8 bytes");
            }
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
            run_grep(
                path,
                literal,
                *max_results,
                &cfg,
                args.output,
                enrichment_root,
            )
            .await
        }
        FsAction::Glob {
            root,
            pattern,
            max_results,
            max_depth,
            codegraph_enrichment,
            repository_root,
        } => {
            validate_glob_pattern(pattern)?;
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
            run_glob(
                root,
                pattern,
                *max_results,
                *max_depth,
                &cfg,
                args.output,
                enrichment_root,
            )
            .await
        }
        FsAction::Write { path, content } => run_write(path, content, &cfg, args.output).await,
    }
}

fn validate_glob_pattern(pattern: &str) -> Result<()> {
    anyhow::ensure!(
        !pattern.is_empty() && pattern.len() <= MAX_GREP_LITERAL_BYTES,
        "glob pattern must contain 1..={MAX_GREP_LITERAL_BYTES} UTF-8 bytes"
    );
    let drive_qualified =
        pattern.as_bytes().get(1) == Some(&b':') && pattern.as_bytes()[0].is_ascii_alphabetic();
    let forbidden = Path::new(pattern).is_absolute()
        || pattern.starts_with(['/', '\\'])
        || drive_qualified
        || pattern.contains('\0')
        || pattern.starts_with('!')
        || pattern.starts_with('#');
    anyhow::ensure!(
        !forbidden,
        "glob pattern must be a non-negated relative path"
    );
    anyhow::ensure!(
        !pattern.split(['/', '\\']).any(|part| part == ".."),
        "glob pattern must not contain `..`"
    );
    Ok(())
}

async fn run_glob(
    root: &Path,
    pattern: &str,
    max_results: usize,
    max_depth: usize,
    cfg: &FreedomConfig,
    output: OutputFormat,
    repository_root: Option<&Path>,
) -> Result<()> {
    anyhow::ensure!(root.is_absolute(), "glob root must be absolute");
    anyhow::ensure!(
        (1..=MAX_GLOB_RESULTS).contains(&max_results),
        "glob max-results must be from 1 through {MAX_GLOB_RESULTS}"
    );
    anyhow::ensure!(
        max_depth <= MAX_GLOB_DEPTH,
        "glob max-depth must be from 0 through {MAX_GLOB_DEPTH}"
    );
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))?.is_some();
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    let rendered = if daemon_live {
        let status = crate::os_tools::AuditStatus::default();
        let result = glob_with_pre_tool_use(
            root,
            pattern,
            GlobBounds {
                max_results,
                max_depth,
            },
            cfg,
            repository_root,
            AuditSink::TrackedDaemonRpc {
                home: &home,
                status: &status,
            },
            now,
            &home,
        )
        .await;
        finish_glob_audit(
            &status,
            None,
            cfg.audit_rpc.required_for_oneshot_permission_events,
        )?;
        result?
    } else {
        let wal_dir = home.join("wal");
        match std::fs::create_dir_all(&wal_dir)
            .map_err(crate::wal::error::WalError::Io)
            .and_then(|()| {
                crate::wal::writer::spawn_for_home_with_completion(
                    crate::wal::writer::unique_standalone_segment_path(&wal_dir, "fs-glob"),
                    home.clone(),
                )
            }) {
            Ok((writer, completion)) => {
                let status = crate::os_tools::AuditStatus::default();
                let result = glob_with_pre_tool_use(
                    root,
                    pattern,
                    GlobBounds {
                        max_results,
                        max_depth,
                    },
                    cfg,
                    repository_root,
                    AuditSink::TrackedWriter {
                        writer: &writer,
                        status: &status,
                    },
                    now,
                    &home,
                )
                .await;
                drop(writer);
                let finalization = completion.wait().await.err().map(|error| error.to_string());
                finish_glob_audit(
                    &status,
                    finalization,
                    cfg.audit_rpc.required_for_oneshot_permission_events,
                )?;
                result?
            }
            Err(error) => {
                if cfg.audit_rpc.required_for_oneshot_permission_events {
                    anyhow::bail!(
                        "refusing fs glob un-audited: required-audit posture is set but one-shot WAL could not open ({error})"
                    );
                }
                tracing::warn!(error = %error, "fs glob proceeding WITHOUT WAL audit — could not open a one-shot WAL writer");
                glob_with_pre_tool_use(
                    root,
                    pattern,
                    GlobBounds {
                        max_results,
                        max_depth,
                    },
                    cfg,
                    repository_root,
                    AuditSink::None,
                    now,
                    &home,
                )
                .await?
            }
        }
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{rendered}"),
        OutputFormat::Table => {
            for path in rendered["matches"].as_array().into_iter().flatten() {
                println!("{}", path.as_str().unwrap_or_default());
            }
        }
    }
    Ok(())
}

fn finish_glob_audit(
    status: &crate::os_tools::AuditStatus,
    finalization: Option<String>,
    required: bool,
) -> Result<()> {
    let dispatch = status.failure();
    if required && (dispatch.is_some() || finalization.is_some()) {
        anyhow::bail!(
            "refusing to report fs glob complete: required audit failed (dispatch={}, finalization={})",
            dispatch.as_deref().unwrap_or("ok"),
            finalization.as_deref().unwrap_or("ok")
        );
    }
    if let Some(error) = dispatch {
        tracing::warn!(error = %error, "fs glob audit dispatch failed");
    }
    if let Some(error) = finalization {
        tracing::warn!(error = %error, "fs glob audit finalization failed");
    }
    Ok(())
}

async fn glob_with_pre_tool_use(
    root: &Path,
    pattern: &str,
    bounds: GlobBounds,
    cfg: &FreedomConfig,
    repository_root: Option<&Path>,
    sink: AuditSink<'_>,
    now: i64,
    home: &Path,
) -> Result<serde_json::Value> {
    let admitted = crate::os_tools::preflight_os_directory_list(
        root,
        &cfg.tools.os,
        &cfg.autonomy_policy(),
        sink,
        now,
    )
    .await?;
    let canonical_root = admitted.canonical_path().to_path_buf();
    let repo = match repository_root {
        Some(path) => path
            .canonicalize()
            .context("canonicalize glob repository root")?,
        None => canonical_root.clone(),
    };
    let arguments = serde_json::json!({"root": canonical_root.display().to_string(), "pattern": pattern, "max_results": bounds.max_results, "max_depth": bounds.max_depth, "repository_root": repository_root.map(|_| repo.display().to_string())});
    let context = crate::hooks::PreToolUseContext::admitted(
        crate::hooks::PreToolUseOrigin::DirectCliOsDirectoryGlob,
        "native-os-directory-glob",
        "fs-glob",
        &arguments,
        &repo,
        &repo,
        crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
        crate::hooks::PreToolUseCancellation::unbound(),
        crate::hooks::PreToolUseReplay::direct_request(),
    )?;
    let hooks = crate::hooks::load_all_strict(&home.join("hooks")).await?;
    let once = crate::hooks::SessionOnceGuard::new();
    let hook_enrichment = match crate::hooks::run_pre_tool_use(
        &context,
        crate::hooks::PreToolUseHookPolicy::Configured(&hooks),
        &once,
    ) {
        crate::hooks::PreToolUseDisposition::Block { reason } => {
            anyhow::bail!("fs glob stopped at typed PreToolUse: {reason}")
        }
        crate::hooks::PreToolUseDisposition::Enrich(value) => Some(value.as_str().to_owned()),
        crate::hooks::PreToolUseDisposition::Continue => None,
    };
    if context.is_cancelled() || context.deadline_elapsed() {
        anyhow::bail!("fs glob cancelled or deadline elapsed before enumeration");
    }
    let plan = if repository_root.is_some() && cfg.code_map.outline_enrichment {
        crate::mcp::codegraph_server::prepare_native_fs_glob_enrichment(
            home,
            &repo,
            &canonical_root,
            admitted.identity(),
            &context,
            true,
        )
        .ok()
        .flatten()
    } else {
        None
    };
    let discovered = discover_glob(
        admitted.directory()?,
        pattern,
        bounds.max_results,
        bounds.max_depth,
        &context,
    )?;
    anyhow::ensure!(
        !context.is_cancelled() && !context.deadline_elapsed(),
        "fs glob cancelled or deadline elapsed before output"
    );
    let empty = discovered.matches.is_empty();
    let mut rendered = serde_json::json!({"root": canonical_root.display().to_string(), "pattern": pattern, "matches": discovered.matches, "empty": empty, "truncated": discovered.truncated});
    if repository_root.is_some() {
        if empty {
            rendered["codegraph_enrichment_status"] =
                serde_json::Value::String("no_matches".to_owned());
        } else if !cfg.code_map.outline_enrichment {
            rendered["codegraph_enrichment_status"] =
                serde_json::Value::String("master_disabled".to_owned());
        } else if let Some(plan) = plan {
            let returned = rendered["matches"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            match plan.freshness_after_glob(&returned) {
                crate::mcp::codegraph_server::NativeFsGlobFreshness::Fresh(value) => {
                    rendered["codegraph_enrichment_status"] =
                        serde_json::Value::String("applied".to_owned());
                    rendered["codegraph_enrichment"] =
                        serde_json::Value::String(value.as_str().to_owned());
                }
                crate::mcp::codegraph_server::NativeFsGlobFreshness::Stale => {
                    rendered["codegraph_enrichment_status"] =
                        serde_json::Value::String("stale".to_owned())
                }
                crate::mcp::codegraph_server::NativeFsGlobFreshness::Unavailable => {
                    rendered["codegraph_enrichment_status"] =
                        serde_json::Value::String("unavailable".to_owned())
                }
            }
        } else {
            rendered["codegraph_enrichment_status"] =
                serde_json::Value::String("unavailable".to_owned());
        }
    }
    if !empty && let Some(enrichment) = hook_enrichment {
        rendered["hook_enrichment"] = serde_json::Value::String(enrichment);
    }
    anyhow::ensure!(
        !context.is_cancelled() && !context.deadline_elapsed(),
        "fs glob cancelled or deadline elapsed before output"
    );
    Ok(rendered)
}
struct GlobBounds {
    max_results: usize,
    max_depth: usize,
}

struct GlobDiscovery {
    matches: Vec<String>,
    truncated: bool,
}

fn discover_glob(
    root: cap_std::fs::Dir,
    pattern: &str,
    max_results: usize,
    max_depth: usize,
    context: &crate::hooks::PreToolUseContext,
) -> Result<GlobDiscovery> {
    let mut builder = ignore::gitignore::GitignoreBuilder::new("/");
    builder
        .add_line(None, pattern)
        .map_err(|error| anyhow::anyhow!("invalid glob pattern: {error}"))?;
    let matcher = builder
        .build()
        .map_err(|error| anyhow::anyhow!("invalid glob pattern: {error}"))?;
    let mut queue = VecDeque::from([(root, String::new(), 0usize)]);
    let mut matches = Vec::new();
    let mut entries = 0usize;
    let mut truncated = false;
    while let Some((directory, prefix, depth)) = queue.pop_front() {
        for entry in directory.entries()? {
            anyhow::ensure!(
                !context.is_cancelled() && !context.deadline_elapsed(),
                "fs glob cancelled or deadline elapsed during enumeration"
            );
            if entries == MAX_GLOB_ENTRIES {
                // A filesystem iterator has no stable global ordering. Once
                // the hard discovery budget is exhausted, publishing its
                // partial prefix would claim deterministic selection when it
                // is not. Return an explicit truncated-empty result instead.
                matches.clear();
                truncated = true;
                break;
            }
            entries += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.is_symlink() || cap_metadata_is_link_or_reparse(&metadata) {
                continue;
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if metadata.is_dir() {
                if depth < max_depth
                    && let Ok(child) = crate::os_tools::gate::open_child_directory_no_follow(
                        &directory,
                        Path::new(&name),
                    )
                {
                    queue.push_back((child, relative, depth + 1));
                }
            } else if metadata.is_file() && matcher.matched(Path::new(&relative), false).is_ignore()
            {
                matches.push(relative);
            }
        }
        if truncated {
            break;
        }
    }
    matches.sort();
    if matches.len() > max_results {
        matches.truncate(max_results);
        truncated = true;
    }
    Ok(GlobDiscovery { matches, truncated })
}

fn cap_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        false
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
                    render_enrichment_status(&mut rendered, read.enrichment_status);
                    println!("{}", rendered);
                }
                OutputFormat::Table => {
                    print!("{}", read.text);
                    if let Some(enrichment) = read.enrichment {
                        print!("\n{enrichment}");
                    }
                    if let Some(status) = read.enrichment_status {
                        print!("\n[codegraph enrichment: {}]", status.as_str());
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

async fn run_grep(
    path: &Path,
    literal: &str,
    max_results: usize,
    cfg: &FreedomConfig,
    output: OutputFormat,
    enrichment_root: Option<&Path>,
) -> Result<()> {
    let now = now_unix();
    let home = FreedomConfig::default_neoth_home();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid")),
        Ok(Some(_))
    );
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )?;
    let read = if daemon_live {
        search_with_optional_native_enrichment(
            path,
            literal,
            max_results,
            cfg,
            AuditSink::DaemonRpc(&home),
            now,
            &home,
            enrichment_root,
        )
        .await
    } else {
        let wal_dir = home.join("wal");
        match std::fs::create_dir_all(&wal_dir)
            .map_err(crate::wal::error::WalError::Io)
            .and_then(|()| {
                crate::wal::writer::spawn_for_home(
                    crate::wal::writer::unique_standalone_segment_path(&wal_dir, "fs-grep"),
                    home.clone(),
                )
            }) {
            Ok((writer, join)) => {
                let result = search_with_optional_native_enrichment(
                    path,
                    literal,
                    max_results,
                    cfg,
                    AuditSink::Writer(&writer),
                    now,
                    &home,
                    enrichment_root,
                )
                .await;
                drop(writer);
                let _ = join.await;
                result
            }
            Err(error) => {
                tracing::warn!(error = %error, "fs grep proceeding WITHOUT WAL audit — could not open a one-shot WAL writer");
                search_with_optional_native_enrichment(
                    path,
                    literal,
                    max_results,
                    cfg,
                    AuditSink::None,
                    now,
                    &home,
                    enrichment_root,
                )
                .await
            }
        }
    };
    let read = read.map_err(|error| anyhow::anyhow!("{error}"))?;
    let matches = read
        .search
        .expect("fs grep retains matches from the admitted descriptor");
    let truncated = matches.truncated;
    let empty = matches.rows.is_empty();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut rendered = serde_json::json!({
                "path": path.display().to_string(),
                "literal": literal,
                "matches": matches.rows,
                "empty": empty,
                "truncated": truncated,
            });
            if let Some(enrichment) = read.enrichment {
                rendered["codegraph_enrichment"] = serde_json::Value::String(enrichment);
            }
            render_enrichment_status(&mut rendered, read.enrichment_status);
            println!("{rendered}");
        }
        OutputFormat::Table => {
            if empty {
                println!("no literal matches");
            }
            for row in matches.rows {
                println!("{}:{}", row.line, row.text);
            }
            if truncated {
                println!("[results truncated]");
            }
            if let Some(enrichment) = read.enrichment {
                print!("\n{enrichment}");
            }
            if let Some(status) = read.enrichment_status {
                print!("\n[codegraph enrichment: {}]", status.as_str());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeEnrichmentStatus {
    MasterDisabled,
    Unavailable,
    Stale,
    Applied,
    NoMatchingLines,
}

impl NativeEnrichmentStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MasterDisabled => "master_disabled",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
            Self::Applied => "applied",
            Self::NoMatchingLines => "no_matching_lines",
        }
    }
}

fn render_enrichment_status(
    rendered: &mut serde_json::Value,
    status: Option<NativeEnrichmentStatus>,
) {
    if let Some(status) = status {
        rendered["codegraph_enrichment_status"] =
            serde_json::Value::String(status.as_str().to_owned());
    }
}

#[derive(Debug, serde::Serialize)]
struct GrepMatch {
    line: usize,
    text: String,
    truncated: bool,
}
#[derive(Debug)]
struct GrepMatches {
    rows: Vec<GrepMatch>,
    truncated: bool,
}

fn literal_matches(text: &str, literal: &str, max_results: usize) -> GrepMatches {
    let mut rows = Vec::new();
    let mut truncated = false;
    for (index, line) in text.lines().enumerate() {
        if !line.contains(literal) {
            continue;
        }
        if rows.len() == max_results {
            truncated = true;
            break;
        }
        let (snippet, line_truncated) = bounded_grep_line(line, literal);
        truncated |= line_truncated;
        rows.push(GrepMatch {
            line: index + 1,
            text: snippet,
            truncated: line_truncated,
        });
    }
    GrepMatches { rows, truncated }
}

fn bounded_grep_line(line: &str, literal: &str) -> (String, bool) {
    if line.len() <= MAX_GREP_LINE_BYTES {
        return (line.to_owned(), false);
    }

    let match_start = line
        .find(literal)
        .expect("matched line contains the literal");
    // Reserve both possible UTF-8 ellipses up front. The returned payload is
    // then always bounded even when the selected window has both sides clipped.
    let mut start = match_start.saturating_sub(128);
    while start < line.len() && !line.is_char_boundary(start) {
        start += 1;
    }
    let mut end = line.len().min(start + GREP_SNIPPET_PAYLOAD_BYTES);
    while end > start && !line.is_char_boundary(end) {
        end -= 1;
    }

    debug_assert!(start <= match_start);
    debug_assert!(end >= match_start + literal.len());
    let prefix = if start > 0 { "…" } else { "" };
    let suffix = if end < line.len() { "…" } else { "" };
    (format!("{prefix}{}{suffix}", &line[start..end]), true)
}

#[cfg(test)]
struct TestPreToolUseOnceGuard(crate::hooks::SessionOnceGuard);

#[cfg(test)]
impl std::fmt::Debug for TestPreToolUseOnceGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestPreToolUseOnceGuard(..)")
    }
}

#[derive(Debug)]
struct FsReadOutcome {
    text: String,
    enrichment: Option<String>,
    enrichment_status: Option<NativeEnrichmentStatus>,
    search: Option<GrepMatches>,
    #[cfg(test)]
    pre_tool_use_context: Option<crate::hooks::PreToolUseContext>,
    #[cfg(test)]
    pre_tool_use_once_guard: Option<TestPreToolUseOnceGuard>,
}

struct NativePreToolUseAdmission {
    cancellation: crate::hooks::PreToolUseCancellation,
    timeout: std::time::Duration,
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
        NativePreToolUseAdmission {
            cancellation: crate::hooks::PreToolUseCancellation::unbound(),
            timeout: crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
        },
        None,
    )
    .await
}

async fn search_with_optional_native_enrichment(
    path: &Path,
    literal: &str,
    max_results: usize,
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
        NativePreToolUseAdmission {
            cancellation: crate::hooks::PreToolUseCancellation::unbound(),
            timeout: crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
        },
        Some((literal, max_results)),
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
    admission: NativePreToolUseAdmission,
    search: Option<(&str, usize)>,
) -> Result<FsReadOutcome, OsGateError> {
    let Some(repository_root) = repository_root else {
        let text = read_os_file(path, &cfg.tools.os, &cfg.autonomy_policy(), sink, now).await?;
        return Ok(FsReadOutcome {
            search: search
                .map(|(literal, max_results)| literal_matches(&text, literal, max_results)),
            text,
            enrichment: None,
            enrichment_status: None,
            #[cfg(test)]
            pre_tool_use_context: None,
            #[cfg(test)]
            pre_tool_use_once_guard: None,
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
    let arguments = match search {
        Some((literal, max_results)) => {
            serde_json::json!({"path": admitted.canonical_path().display().to_string(), "literal": literal, "max_results": max_results, "repository_root": root.display().to_string()})
        }
        None => {
            serde_json::json!({"path": admitted.canonical_path().display().to_string(), "repository_root": root.display().to_string()})
        }
    };
    let context = crate::hooks::PreToolUseContext::admitted(
        if search.is_some() {
            crate::hooks::PreToolUseOrigin::DirectCliOsFileSearch
        } else {
            crate::hooks::PreToolUseOrigin::DirectCliOsFileRead
        },
        if search.is_some() {
            "native-os-file-search"
        } else {
            "native-os-file-read"
        },
        if search.is_some() {
            "fs-grep"
        } else {
            "fs-read"
        },
        &arguments,
        &root,
        &root,
        admission.timeout,
        admission.cancellation,
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
    let (native_plan, mut enrichment_status) = if !cfg.code_map.outline_enrichment {
        (None, Some(NativeEnrichmentStatus::MasterDisabled))
    } else {
        match crate::mcp::codegraph_server::prepare_native_fs_read_enrichment(
            home,
            &root,
            admitted.canonical_path(),
            &context,
            true,
        ) {
            Ok(Some(plan)) => (Some(plan), None),
            Ok(None) => (None, Some(NativeEnrichmentStatus::Unavailable)),
            Err(error) => {
                tracing::debug!(error = %error, "native fs codegraph sidecar unavailable");
                (None, Some(NativeEnrichmentStatus::Unavailable))
            }
        }
    };
    if context.is_cancelled() || context.deadline_elapsed() {
        return Err(OsGateError::PreToolUse(
            "cancelled or deadline elapsed before the native file read".to_owned(),
        ));
    }
    let text = crate::os_tools::gate::invoke_preflighted_os_file_read(admitted, sink, now).await?;
    // For native grep, complete and retain one literal scan over the actual
    // retained-fd bytes before accepting any optional sidecar freshness result.
    let search_matches =
        search.map(|(literal, max_results)| literal_matches(&text, literal, max_results));
    let no_matching_lines = search_matches
        .as_ref()
        .is_some_and(|matches| matches.rows.is_empty());
    let native_enrichment = if no_matching_lines {
        if enrichment_status.is_none() {
            enrichment_status = Some(NativeEnrichmentStatus::NoMatchingLines);
        }
        None
    } else if let Some(plan) = native_plan {
        match plan.freshness_after_read() {
            crate::mcp::codegraph_server::NativeFsReadFreshness::Fresh(sidecar) => {
                enrichment_status = Some(NativeEnrichmentStatus::Applied);
                Some(sidecar.as_str().to_owned())
            }
            crate::mcp::codegraph_server::NativeFsReadFreshness::Stale => {
                enrichment_status = Some(NativeEnrichmentStatus::Stale);
                None
            }
            crate::mcp::codegraph_server::NativeFsReadFreshness::Unavailable => {
                enrichment_status = Some(NativeEnrichmentStatus::Unavailable);
                None
            }
        }
    } else {
        None
    };
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
    let enrichment = if no_matching_lines { None } else { enrichment };
    Ok(FsReadOutcome {
        text,
        enrichment,
        enrichment_status,
        search: search_matches,
        #[cfg(test)]
        pre_tool_use_context: Some(context),
        #[cfg(test)]
        pre_tool_use_once_guard: Some(TestPreToolUseOnceGuard(once_guard)),
    })
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

    fn w279_context(
        root: &Path,
        cancellation: crate::hooks::PreToolUseCancellation,
        timeout: std::time::Duration,
    ) -> crate::hooks::PreToolUseContext {
        crate::hooks::PreToolUseContext::admitted(crate::hooks::PreToolUseOrigin::DirectCliOsDirectoryGlob, "native-os-directory-glob", "fs-glob", &serde_json::json!({"root": root.display().to_string(), "pattern": "**/*.rs", "max_results": 20, "max_depth": 8}), root, root, timeout, cancellation, crate::hooks::PreToolUseReplay::direct_request()).unwrap()
    }

    #[test]
    fn w279_glob_cli_bounds_and_pattern_rejections() {
        use clap::Parser as _;
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "fs",
                "glob",
                "C:/root",
                "**/*.rs",
                "--max-results",
                "64",
                "--max-depth",
                "16"
            ])
            .is_ok()
        );
        for invalid in ["0", "65"] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "neoth",
                    "fs",
                    "glob",
                    "C:/root",
                    "*.rs",
                    "--max-results",
                    invalid
                ])
                .is_err()
            );
        }
        for pattern in [
            "/absolute",
            "\\absolute",
            "C:/absolute",
            "C:relative",
            "../escape",
            "!negated",
            "#comment",
        ] {
            assert!(
                validate_glob_pattern(pattern).is_err(),
                "{pattern} must be refused"
            );
        }
    }

    #[test]
    fn w279_discovery_is_sorted_bounded_and_no_content() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("z.rs"), "secret source").unwrap();
        std::fs::write(root.path().join("a.rs"), "other source").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let cap = crate::os_tools::gate::open_absolute_directory_no_follow(&root_path).unwrap();
        let context = w279_context(
            &root_path,
            crate::hooks::PreToolUseCancellation::unbound(),
            std::time::Duration::from_secs(1),
        );
        let found = discover_glob(cap, "*.rs", 1, 0, &context).unwrap();
        assert_eq!(found.matches, vec!["a.rs"]);
        assert!(found.truncated);
        assert!(!found.matches.iter().any(|item| item.contains("source")));
    }

    #[tokio::test]
    async fn w279_actual_glob_hook_blocks_before_enumeration_and_runs_without_enrichment_opt_in() {
        let home = tempfile::tempdir().unwrap();
        let hooks = home.path().join("hooks");
        std::fs::create_dir(&hooks).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("selected.rs"), "fn selected() {}").unwrap();
        std::fs::write(hooks.join("block.toml"), "name = \"glob-block\"\nstage = \"pre_tool_use\"\n[matcher]\npattern = '\"max_results\":20'\n[action]\nkind = \"block\"\nreason = \"test block\"\n").unwrap();
        let config = w239_config(root.path());
        let blocked = glob_with_pre_tool_use(
            root.path(),
            "*.rs",
            GlobBounds {
                max_results: 20,
                max_depth: 0,
            },
            &config,
            None,
            AuditSink::None,
            0,
            home.path(),
        )
        .await;
        assert!(blocked.unwrap_err().to_string().contains("test block"));
        std::fs::remove_file(hooks.join("block.toml")).unwrap();
        std::fs::write(hooks.join("enrich.toml"), "name = \"glob-enrich\"\nstage = \"pre_tool_use\"\n[matcher]\npattern = '\"max_results\":20'\n[action]\nkind = \"replace\"\ntemplate = \"[glob-hook]\"\n").unwrap();
        let output = glob_with_pre_tool_use(
            root.path(),
            "*.rs",
            GlobBounds {
                max_results: 20,
                max_depth: 0,
            },
            &config,
            None,
            AuditSink::None,
            0,
            home.path(),
        )
        .await
        .unwrap();
        assert_eq!(output["matches"], serde_json::json!(["selected.rs"]));
        let expected_hook_enrichment = serde_json::json!({
            "root": root.path().canonicalize().unwrap().display().to_string(),
            "pattern": "*.rs",
            "max_results": 20,
            "max_depth": 0,
            "repository_root": serde_json::Value::Null,
        })
        .to_string()
        .replacen("\"max_results\":20", "[glob-hook]", 1);
        assert_eq!(
            output["hook_enrichment"], expected_hook_enrichment,
            "the replace hook transforms its matching argument substring exactly once"
        );
        let nohit = glob_with_pre_tool_use(
            root.path(),
            "*.absent",
            GlobBounds {
                max_results: 20,
                max_depth: 0,
            },
            &config,
            None,
            AuditSink::None,
            0,
            home.path(),
        )
        .await
        .unwrap();
        assert_eq!(nohit["matches"], serde_json::json!([]));
        assert!(
            nohit.get("hook_enrichment").is_none(),
            "a no-hit glob executes its hook boundary but attaches no sidecar"
        );
    }

    #[tokio::test]
    async fn w279_actual_glob_attaches_fresh_db_symbol_sidecar() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("hooks")).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("selected.rs"), "fn selected() {}\n").unwrap();
        w239_write_generated_descriptor(home.path(), root.path());
        let mut config = w239_config(root.path());
        config.code_map.outline_enrichment = true;
        let output = glob_with_pre_tool_use(
            root.path(),
            "*.rs",
            GlobBounds {
                max_results: 20,
                max_depth: 0,
            },
            &config,
            Some(root.path()),
            AuditSink::None,
            0,
            home.path(),
        )
        .await
        .unwrap();
        assert_eq!(output["codegraph_enrichment_status"], "applied");
        assert!(
            output["codegraph_enrichment"]
                .as_str()
                .is_some_and(|sidecar| sidecar.contains("symbol: selected.rs :: selected"))
        );
        assert!(
            !output["codegraph_enrichment"]
                .as_str()
                .unwrap()
                .contains("fn selected")
        );
    }

    #[test]
    fn w279_empty_discovery_is_successful_and_not_truncated() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("only.txt"), "x").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let cap = crate::os_tools::gate::open_absolute_directory_no_follow(&root_path).unwrap();
        let context = w279_context(
            &root_path,
            crate::hooks::PreToolUseCancellation::unbound(),
            std::time::Duration::from_secs(1),
        );
        let found = discover_glob(cap, "*.rs", 20, 0, &context).unwrap();
        assert!(found.matches.is_empty());
        assert!(!found.truncated);
    }

    #[test]
    fn w279_cancelled_or_expired_context_refuses_before_walk() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("x.rs"), "x").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_context = w279_context(
            &root_path,
            crate::hooks::PreToolUseCancellation::from_chat_turn(cancelled.clone()),
            std::time::Duration::from_secs(1),
        );
        cancelled.store(true, std::sync::atomic::Ordering::Release);
        let cap = crate::os_tools::gate::open_absolute_directory_no_follow(&root_path).unwrap();
        assert!(discover_glob(cap, "*.rs", 20, 0, &cancelled_context).is_err());
        let expired = crate::hooks::PreToolUseContext::admitted(
            crate::hooks::PreToolUseOrigin::DirectCliOsDirectoryGlob,
            "native-os-directory-glob",
            "fs-glob",
            &serde_json::json!({"root": root_path.display().to_string(), "pattern": "**/*.rs", "max_results": 20, "max_depth": 8}),
            &root_path,
            &root_path,
            std::time::Duration::ZERO,
            crate::hooks::PreToolUseCancellation::unbound(),
            crate::hooks::PreToolUseReplay::direct_request(),
        )
        .expect_err("zero deadline must refuse admission before enumeration");
        assert!(matches!(
            expired,
            crate::hooks::PreToolUseContextError::DeadlineElapsed
        ));
    }

    #[cfg(unix)]
    #[test]
    fn w279_symlink_entries_are_never_returned_or_traversed() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.rs"), "secret").unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let cap = crate::os_tools::gate::open_absolute_directory_no_follow(&root_path).unwrap();
        let context = w279_context(
            &root_path,
            crate::hooks::PreToolUseCancellation::unbound(),
            std::time::Duration::from_secs(1),
        );
        let found = discover_glob(cap, "**/*.rs", 20, 8, &context).unwrap();
        assert!(found.matches.is_empty());
    }
    #[tokio::test]
    async fn w279_required_audit_failure_refuses_glob_success() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("hooks")).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("x.rs"), "x").unwrap();
        let segment = home.path().join("failed.wal");
        let (writer, join) = crate::wal::writer::spawn(segment).unwrap();
        join.abort();
        let _ = join.await;
        let status = crate::os_tools::AuditStatus::default();
        let config = w239_config(root.path());
        let _ = glob_with_pre_tool_use(
            root.path(),
            "*.rs",
            GlobBounds {
                max_results: 20,
                max_depth: 0,
            },
            &config,
            None,
            AuditSink::TrackedWriter {
                writer: &writer,
                status: &status,
            },
            0,
            home.path(),
        )
        .await;
        drop(writer);
        assert!(finish_glob_audit(&status, None, true).is_err());
    }
    #[test]
    fn w269_enrichment_status_json_is_additive_and_bounded() {
        let mut rendered = serde_json::json!({"path": "selected.rs"});
        render_enrichment_status(&mut rendered, Some(NativeEnrichmentStatus::NoMatchingLines));
        assert_eq!(rendered["path"], "selected.rs");
        assert_eq!(rendered["codegraph_enrichment_status"], "no_matching_lines");
        assert_eq!(
            NativeEnrichmentStatus::MasterDisabled.as_str(),
            "master_disabled"
        );
        assert_eq!(NativeEnrichmentStatus::Unavailable.as_str(), "unavailable");
        assert_eq!(NativeEnrichmentStatus::Stale.as_str(), "stale");
        assert_eq!(NativeEnrichmentStatus::Applied.as_str(), "applied");

        let mut opt_out = serde_json::json!({"path": "selected.rs"});
        render_enrichment_status(&mut opt_out, None);
        assert!(opt_out.get("codegraph_enrichment_status").is_none());
    }
    #[test]
    fn w256_grep_cli_parses_default_and_maximum_and_rejects_out_of_range_results() {
        use clap::Parser as _;

        let defaulted =
            crate::cli::Cli::try_parse_from(["neoth", "fs", "grep", "C:/selected.rs", "needle"])
                .expect("default fs grep parses");
        assert!(matches!(
            defaulted.command,
            crate::cli::Commands::Fs(FsArgs {
                action: FsAction::Grep {
                    max_results: DEFAULT_GREP_RESULTS,
                    ..
                },
                ..
            })
        ));

        let maximum = crate::cli::Cli::try_parse_from([
            "neoth",
            "fs",
            "grep",
            "C:/selected.rs",
            "needle",
            "--max-results",
            "64",
        ])
        .expect("maximum fs grep parses");
        assert!(matches!(
            maximum.command,
            crate::cli::Commands::Fs(FsArgs {
                action: FsAction::Grep {
                    max_results: MAX_GREP_RESULTS,
                    ..
                },
                ..
            })
        ));

        for invalid in ["0", "65"] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "neoth",
                    "fs",
                    "grep",
                    "C:/selected.rs",
                    "needle",
                    "--max-results",
                    invalid,
                ])
                .is_err(),
                "max-results {invalid} must be rejected by clap"
            );
        }
    }
    #[test]
    fn w256_literal_search_reports_empty_line_numbers_and_bounded_truncation() {
        let empty = literal_matches("alpha\nbeta", "needle", 20);
        assert!(empty.rows.is_empty());
        assert!(!empty.truncated);

        let matched = literal_matches("zero\nneedle one\nneedle two", "needle", 1);
        assert_eq!(matched.rows.len(), 1);
        assert_eq!(matched.rows[0].line, 2);
        assert_eq!(matched.rows[0].text, "needle one");
        assert!(
            matched.truncated,
            "the second literal match must report the result cap"
        );

        let long = format!("needle{}", "x".repeat(MAX_GREP_LINE_BYTES));
        let clipped = literal_matches(&long, "needle", 1);
        assert!(clipped.rows[0].truncated);
        assert!(clipped.truncated);
        assert!(clipped.rows[0].text.ends_with('…'));

        let late = format!("{}needle{}", "x".repeat(1_024), "y".repeat(64));
        let windowed = literal_matches(&late, "needle", 1);
        assert!(windowed.rows[0].text.contains("needle"));
        assert!(windowed.rows[0].text.len() <= MAX_GREP_LINE_BYTES);

        let maximum_literal = "n".repeat(MAX_GREP_LITERAL_BYTES);
        let boundary = format!(
            "{}{}{}",
            "x".repeat(255),
            maximum_literal,
            "y".repeat(1_024)
        );
        let clipped_boundary = literal_matches(&boundary, &maximum_literal, 1);
        assert!(clipped_boundary.rows[0].text.contains(&maximum_literal));
        assert!(clipped_boundary.rows[0].text.len() <= MAX_GREP_LINE_BYTES);

        let multibyte = format!("{}{}{}", "é".repeat(130), maximum_literal, "界".repeat(200));
        let clipped_multibyte = literal_matches(&multibyte, &maximum_literal, 1);
        assert!(clipped_multibyte.rows[0].text.contains(&maximum_literal));
        assert!(clipped_multibyte.rows[0].text.len() <= MAX_GREP_LINE_BYTES);
    }

    #[tokio::test]
    async fn w256_actual_grep_search_origin_hook_enrichment_and_once_guard() {
        let home = tempfile::tempdir().unwrap();
        let hooks_dir = home.path().join("hooks");
        std::fs::create_dir(&hooks_dir).unwrap();
        std::fs::write(
            hooks_dir.join("search.toml"),
            r#"
name = "search-once"
stage = "pre_tool_use"
once = true
[matcher]
pattern = '"literal":"needle"'
[action]
kind = "replace"
template = "[native-search-hook]"
"#,
        )
        .unwrap();

        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("selected.rs");
        std::fs::write(&file, "needle\n").unwrap();
        let config = w239_config(repository.path());

        let outcome = search_with_optional_native_enrichment(
            &file,
            "needle",
            20,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .expect("a matched retained-fd native grep reaches configured PreToolUse");
        assert_eq!(outcome.search.as_ref().unwrap().rows[0].line, 1);
        assert!(
            outcome
                .enrichment
                .as_deref()
                .is_some_and(|enrichment| enrichment.contains("[native-search-hook]"))
        );

        let context = outcome
            .pre_tool_use_context
            .as_ref()
            .expect("the actual native grep exposes its admitted test snapshot");
        assert_eq!(
            context.origin(),
            crate::hooks::PreToolUseOrigin::DirectCliOsFileSearch
        );
        assert_eq!(context.server(), "native-os-file-search");
        assert_eq!(context.tool(), "fs-grep");
        assert!(
            context
                .arguments()
                .summary()
                .contains(r#""literal":"needle""#)
        );
        assert!(
            context
                .arguments()
                .summary()
                .contains(r#""max_results":20"#)
        );
        let canonical_file = file.canonicalize().unwrap().display().to_string();
        let expected_file_json = serde_json::to_string(&canonical_file).unwrap();
        let canonical_repository = repository
            .path()
            .canonicalize()
            .unwrap()
            .display()
            .to_string();
        let expected_repository_json = serde_json::to_string(&canonical_repository).unwrap();
        let summary = context.arguments().summary();
        assert!(
            summary.contains(&expected_file_json),
            "hook arguments omit JSON-encoded admitted file path: expected fragment {expected_file_json:?}, summary={summary:?}"
        );
        assert!(
            summary.contains(&expected_repository_json),
            "hook arguments omit JSON-encoded repository root: expected fragment {expected_repository_json:?}, summary={summary:?}"
        );
        assert!(!context.arguments().was_truncated());

        let hooks = crate::hooks::load_all_strict(&hooks_dir).await.unwrap();
        let once_guard = outcome
            .pre_tool_use_once_guard
            .as_ref()
            .expect("the actual native grep retains its session once guard for this test");
        assert!(matches!(
            crate::hooks::run_pre_tool_use(
                context,
                crate::hooks::PreToolUseHookPolicy::Configured(&hooks),
                &once_guard.0,
            ),
            crate::hooks::PreToolUseDisposition::Continue
        ));
    }
    #[tokio::test]
    async fn w256_actual_grep_no_hit_drops_codegraph_sidecar_after_retained_fd_scan() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("selected.rs");
        std::fs::write(&file, "fn selected() {}\n").unwrap();
        w239_write_generated_descriptor(home.path(), repository.path());
        let mut config = w239_config(repository.path());
        config.code_map.outline_enrichment = true;

        let outcome = search_with_optional_native_enrichment(
            &file,
            "absent_literal",
            20,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .unwrap();
        assert!(outcome.search.as_ref().unwrap().rows.is_empty());
        assert!(
            outcome.enrichment.is_none(),
            "zero-hit grep must not attach a sidecar"
        );
        assert_eq!(
            outcome.enrichment_status,
            Some(NativeEnrichmentStatus::NoMatchingLines)
        );
    }

    #[tokio::test]
    async fn w269_actual_requested_enrichment_without_descriptor_is_unavailable() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("selected.rs");
        std::fs::write(&file, "needle\n").unwrap();
        let mut config = w239_config(repository.path());
        config.code_map.outline_enrichment = true;

        let outcome = search_with_optional_native_enrichment(
            &file,
            "needle",
            20,
            &config,
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
        )
        .await
        .expect("a requested native grep remains usable without an eligible descriptor");
        assert_eq!(outcome.search.as_ref().unwrap().rows.len(), 1);
        assert!(outcome.enrichment.is_none());
        assert_eq!(
            outcome.enrichment_status,
            Some(NativeEnrichmentStatus::Unavailable)
        );
    }
    #[tokio::test]
    async fn w256_actual_grep_denial_and_cancellation_stop_before_search_output() {
        let home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let file = repository.path().join("selected.rs");
        std::fs::write(&file, "needle\n").unwrap();
        let mut denied = w239_config(repository.path());
        denied.tools.os.allowed_paths.clear();
        assert!(matches!(
            search_with_optional_native_enrichment(
                &file,
                "needle",
                20,
                &denied,
                AuditSink::None,
                0,
                home.path(),
                Some(repository.path())
            )
            .await,
            Err(OsGateError::Allowlist(_))
        ));

        let cancelled = Arc::new(AtomicBool::new(true));
        let error = read_with_optional_native_enrichment_with_cancellation(
            &file,
            &w239_config(repository.path()),
            AuditSink::None,
            0,
            home.path(),
            Some(repository.path()),
            NativePreToolUseAdmission {
                cancellation: crate::hooks::PreToolUseCancellation::from_chat_turn(cancelled),
                timeout: crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
            },
            Some(("needle", 20)),
        )
        .await
        .expect_err("cancelled native grep must not consume the retained descriptor");
        assert!(matches!(error, OsGateError::PreToolUse(_)));
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
                smart_loading: false,
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
        assert_eq!(
            outcome.enrichment_status,
            Some(NativeEnrichmentStatus::MasterDisabled)
        );
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
        assert_eq!(
            outcome.enrichment_status,
            Some(NativeEnrichmentStatus::Applied)
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
            NativePreToolUseAdmission {
                cancellation: crate::hooks::PreToolUseCancellation::from_chat_turn(cancelled),
                timeout: crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
            },
            None,
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
            NativePreToolUseAdmission {
                cancellation: crate::hooks::PreToolUseCancellation::unbound(),
                timeout: std::time::Duration::ZERO,
            },
            None,
        )
        .await
        .expect_err("a zero deadline must drop the admitted descriptor before byte consumption");
        assert!(matches!(error, OsGateError::PreToolUse(_)));
    }
}
