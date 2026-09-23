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

const DEFAULT_GREP_RESULTS: usize = 20;
const MAX_GREP_RESULTS: usize = 64;
const MAX_GREP_LITERAL_BYTES: usize = 256;
const MAX_GREP_LINE_BYTES: usize = 512;
const GREP_SNIPPET_PAYLOAD_BYTES: usize = MAX_GREP_LINE_BYTES - 6;

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
        }
    }
    Ok(())
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
    search: Option<GrepMatches>,
    #[cfg(test)]
    pre_tool_use_context: Option<crate::hooks::PreToolUseContext>,
    #[cfg(test)]
    pre_tool_use_once_guard: Option<TestPreToolUseOnceGuard>,
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
        crate::hooks::PreToolUseCancellation::unbound(),
        crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
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
    cancellation: crate::hooks::PreToolUseCancellation,
    timeout: std::time::Duration,
    search: Option<(&str, usize)>,
) -> Result<FsReadOutcome, OsGateError> {
    let Some(repository_root) = repository_root else {
        let text = read_os_file(path, &cfg.tools.os, &cfg.autonomy_policy(), sink, now).await?;
        return Ok(FsReadOutcome {
            search: search
                .map(|(literal, max_results)| literal_matches(&text, literal, max_results)),
            text,
            enrichment: None,
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
    // For native grep, complete and retain one literal scan over the actual
    // retained-fd bytes before accepting any optional sidecar freshness result.
    let search_matches =
        search.map(|(literal, max_results)| literal_matches(&text, literal, max_results));
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
    let enrichment = if search_matches
        .as_ref()
        .is_some_and(|matches| matches.rows.is_empty())
    {
        None
    } else {
        enrichment
    };
    Ok(FsReadOutcome {
        text,
        enrichment,
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
        assert!(
            context
                .arguments()
                .summary()
                .contains(file.canonicalize().unwrap().to_string_lossy().as_ref())
        );
        assert!(
            context.arguments().summary().contains(
                repository
                    .path()
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
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
            crate::hooks::PreToolUseCancellation::from_chat_turn(cancelled),
            crate::mcp::client::DEFAULT_REQUEST_TIMEOUT,
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
            crate::hooks::PreToolUseCancellation::unbound(),
            std::time::Duration::ZERO,
            None,
        )
        .await
        .expect_err("a zero deadline must drop the admitted descriptor before byte consumption");
        assert!(matches!(error, OsGateError::PreToolUse(_)));
    }
}
