//! `neoth update` — check or apply updates for NEOTH-managed components.
//!
//! Modes:
//!   `--check` (default): probe every component, print a table, do nothing else.
//!   `--apply`: probe then run `npm install -g <pkg>@latest` for each row
//!              flagged as update_available. Prints the post-apply table.
//!   `--list`: human-readable list of components NEOTH knows about. No probe.
//!
//! Output respects the global `--output` flag: table | json | jsonl.
//! See OPEN_DECISIONS.md D-005 (consistent CLI output formatting).

use anyhow::{Context, Result};
use clap::Args;
use tracing::{info, warn};

use crate::cli::OutputFormat;
use crate::updater::{Component, UpdateStatus, check_all, check_and_apply_all};

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    /// Probe every component and print a report. Default when no mode flag set.
    #[arg(long, conflicts_with_all = ["apply", "list"])]
    pub check: bool,

    /// Probe, then update any component where installed != latest.
    /// When combined with `--self`, runs the full daemon self-
    /// update (download → SHA-256 verify → extract → atomic
    /// replace) instead of the per-component CLI update.
    #[arg(long, conflicts_with_all = ["check", "list"])]
    pub apply: bool,

    /// Print the static list of components NEOTH knows how to update.
    #[arg(long, conflicts_with_all = ["check", "apply"])]
    pub list: bool,

    /// V03-09 (2026-05-20): check whether a newer NEOTH daemon
    /// release is published on GitHub. Without `--apply` this is
    /// probe-only (Phase 1). With `--apply` runs the full Phase 2b
    /// flow: download → SHA-256 verify → extract → atomic replace.
    /// Pass `--self-repo owner/name` to point at a fork; default
    /// is `The-Geek-Freaks/NEOTH`.
    #[arg(long = "self", conflicts_with = "list")]
    pub self_check: bool,

    /// Override the GitHub `owner/repo` slug for the self-check.
    #[arg(long = "self-repo", value_name = "OWNER/REPO")]
    pub self_repo: Option<String>,

    /// Accept an UNSIGNED release on `--self --apply`. By default the
    /// updater requires a verified minisign signature (supply-chain
    /// integrity). Releases published before signing was enabled (no
    /// pinned key / no `.minisig`) need this flag — only pass it from a
    /// trusted network; an unsigned binary could be tampered in transit.
    #[arg(long = "allow-unsigned")]
    pub allow_unsigned: bool,

    /// Output format. Inherited from the global `--output` flag if unset.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_update(args: UpdateArgs) -> Result<()> {
    if args.list {
        return render_list(args.output);
    }
    if args.self_check {
        // V03-09 daemon self-check + optional apply path. Default
        // repo is the published public release; operators on a
        // fork override via --self-repo.
        let repo = args.self_repo.as_deref().unwrap_or("The-Geek-Freaks/NEOTH");
        if args.apply {
            info!(
                repo = repo,
                "neoth update --self --apply: full Phase 2b flow"
            );
            return run_self_apply(repo, args.allow_unsigned, args.output).await;
        }
        info!(repo = repo, "neoth update --self: checking GitHub release");
        let outcome = crate::updater::self_update::check_for_update(repo).await?;
        render_self_check(&outcome, args.output);
        return Ok(());
    }
    if args.apply {
        info!("neoth update --apply: probing + installing");
        let home = crate::config::FreedomConfig::default_neoth_home();
        let config_path = home.join("freedom.yaml");
        let config =
            crate::config::FreedomConfig::load_from_path(&config_path).with_context(|| {
                format!(
                    "load operator security policy before applying updates from {}",
                    config_path.display()
                )
            })?;
        let report = check_and_apply_all(&config.security).await;
        render_report(&report, args.output);
        return Ok(());
    }

    // Default mode = --check.
    info!("neoth update --check: probing components");
    let report = check_all().await;
    render_report(&report, args.output);
    Ok(())
}

fn render_self_check(check: &crate::updater::self_update::UpdateCheck, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "current": check.current,
                    "latest": check.latest,
                    "needs_update": check.needs_update,
                    "release_url": check.release_url,
                    "published_at": check.published_at,
                })
            );
        }
        OutputFormat::Table => {
            println!("# NEOTH daemon self-update check");
            println!("  current      : {}", check.current);
            println!("  latest       : {}", check.latest);
            println!("  needs update : {}", check.needs_update);
            if check.needs_update {
                println!();
                println!(
                    "  A newer release is available. Visit:\n  {}",
                    check.release_url
                );
            }
            if !check.published_at.is_empty() {
                println!("  published    : {}", check.published_at);
            }
        }
    }
}

/// V03-09 Phase 2b operator-facing apply path. Probes the release,
/// short-circuits when the daemon is already on the latest version,
/// and otherwise runs the full download → verify → extract →
/// atomic-replace chain against the operator's current binary
/// location (`std::env::current_exe()`).
async fn run_self_apply(repo: &str, allow_unsigned: bool, output: OutputFormat) -> Result<()> {
    use crate::updater::self_update::{
        apply_update, fetch_latest_release, host_target_triple, version_is_newer,
    };

    // GOLD-SEC-10 / GR-043 — SIGNATURE REQUIRED BY DEFAULT for BOTH the staged
    // fast-path below AND the fresh-download path. Compute it once and fail
    // closed HERE when no pinned key exists, so the staged fast-path can no
    // longer apply an unverifiable binary (the prior code gated only the fresh
    // path, which the staged fast-path returned before ever reaching).
    // `apply_from_staged` ALSO re-verifies the staged signature at apply time;
    // this early bail gives the same actionable message the fresh path does.
    let require_signature = !allow_unsigned;
    if require_signature && crate::updater::sig_verify::PINNED_PUBKEY.is_none() {
        anyhow::bail!(
            "this build has no pinned release-signing key yet, so the update cannot be \
             cryptographically verified. Re-run with `--allow-unsigned` to accept an unsigned \
             binary (only from a trusted network — it could be tampered in transit), or wait \
             for a signed release."
        );
    }

    // MV-01b #5 fast-path: if the unattended staging task already downloaded +
    // verified a newer release into ~/.neoth/staged/, apply it WITHOUT
    // re-downloading. Both the staged archive's SHA-256 AND its minisign
    // signature are re-verified inside `apply_from_staged` before any swap.
    {
        let home = crate::config::FreedomConfig::default_neoth_home();
        let stage_dir = home.join("staged");
        if let Some(pending) = crate::updater::self_update::read_pending(&stage_dir) {
            let current = crate::updater::self_update::current_version();
            let staged_present = std::path::Path::new(&pending.staged_archive).exists();
            if staged_present && version_is_newer(&pending.to_version, current).unwrap_or(false) {
                info!(
                    to = %pending.to_version,
                    "applying pre-staged + verified update (skipping download)"
                );
                let exe = std::env::current_exe().context("locate current executable")?;
                let install_dir = exe
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("current_exe() has no parent directory"))?;
                match crate::updater::self_update::apply_from_staged(
                    &pending,
                    install_dir,
                    require_signature,
                ) {
                    Ok(outcome) => {
                        crate::updater::self_update::clear_staged(&stage_dir, &pending);
                        emit_self_update_applied(
                            &outcome,
                            repo,
                            &pending.target_triple,
                            "manual_from_staged",
                        )
                        .await;
                        render_self_apply(&outcome, output);
                        maybe_request_restart();
                        return Ok(());
                    }
                    Err(e) => {
                        if e.downcast_ref::<crate::updater::self_update::IntegrityViolation>()
                            .is_some()
                        {
                            // F55 — the staged artifact failed signature/SHA-256
                            // re-verification at apply time: tamper-suspect (the
                            // stage dir is operator-writable). Clear it, audit the
                            // rejection (0xDE), and REFUSE — do NOT silently fall
                            // back to a fresh download as if it were an I/O blip.
                            warn!(
                                error = %format!("{e:#}"),
                                "staged self-update FAILED integrity/signature re-verification — refusing (tamper-suspect)"
                            );
                            crate::updater::self_update::clear_staged(&stage_dir, &pending);
                            emit_self_update_rejected(
                                repo,
                                &pending,
                                &format!("{e:#}"),
                                "manual_from_staged",
                            )
                            .await;
                            return Err(e.context(
                                "staged self-update failed integrity verification — refusing to apply a tamper-suspect artifact",
                            ));
                        }
                        // Non-security failure (I/O / extraction): clear the broken
                        // stage and fall back to a fresh download.
                        warn!(error = %e, "staged apply failed (non-security); clearing stage and falling back to fresh download");
                        crate::updater::self_update::clear_staged(&stage_dir, &pending);
                    }
                }
            }
        }
    }

    let release = fetch_latest_release(repo).await?;
    let current = crate::updater::self_update::current_version();
    let needs = version_is_newer(&release.tag_name, current).unwrap_or(false);
    if !needs {
        info!(
            current = %current,
            latest = %release.tag_name,
            "already on latest — skipping apply"
        );
        // Surface the no-op clearly so an operator running
        // `--self --apply` in a script doesn't think the update
        // landed when it didn't.
        let check = crate::updater::self_update::UpdateCheck {
            current: current.to_string(),
            latest: release.tag_name.clone(),
            needs_update: false,
            release_url: release.html_url.clone(),
            published_at: release.published_at.clone(),
        };
        render_self_check(&check, output);
        return Ok(());
    }

    let target = host_target_triple().ok_or_else(|| {
        anyhow::anyhow!(
            "host target triple is not in the cargo-dist matrix; \
             cannot self-apply. Install manually from {}",
            release.html_url
        )
    })?;
    let exe = std::env::current_exe().context("locate current executable")?;
    let install_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("current_exe() has no parent directory"))?;

    // GOLD-SEC-10 / A-22 — SIGNATURE REQUIRED BY DEFAULT. `require_signature`
    // (and the no-pinned-key fail-closed bail) was already evaluated at the top
    // of this fn so it covers the staged fast-path too (GR-043); here we just
    // thread it into the fresh-download verify+apply.
    // The on-disk binary + the archive member basename are both `neothd`
    // (the Cargo package name; the release workflow packs `neothd` /
    // `neothd.exe` into each archive). Pre-Session-28f this was the wrong
    // string `"neoth"` (the product/CLI name, not the binary file), so the
    // asset extractor + the atomic-replace target both pointed at a file
    // that didn't exist. Aligned to reality.
    let outcome = apply_update(&release, target, "neothd", install_dir, require_signature).await?;

    // WAL audit frame 0xD2 SELF_UPDATE_APPLIED — best-effort one-shot
    // writer (HF-01 pattern). Guard: if the daemon is live it owns the
    // segment, so skip the open to preserve the single-writer invariant
    // (the binary swap already succeeded; the audit frame is a nicety,
    // never load-bearing for the update itself). `trigger_source =
    // "manual"` — the operator ran `neoth update --self --apply`. The
    // future unattended daemon path emits the same frame with "auto"
    // via the daemon's own WAL writer handle (no one-shot guard).
    emit_self_update_applied(&outcome, repo, target, "manual").await;

    render_self_apply(&outcome, output);
    maybe_request_restart();
    Ok(())
}

/// MV-01b restart contract: after a successful swap, if a supervisor is
/// installed (`config.supervisor.enabled`), drop the `restart.request`
/// marker so a RUNNING daemon picks up the new binary on its next watcher
/// tick (it drains + exits → the supervisor relaunches). No-op when no
/// supervisor is configured (an exit would just leave the daemon down).
fn maybe_request_restart() {
    let enabled = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.supervisor.enabled)
        .unwrap_or(false);
    if !enabled {
        return;
    }
    let home = crate::config::FreedomConfig::default_neoth_home();
    match crate::daemon::supervisor::request_restart(&home) {
        Ok(()) => {
            info!("restart requested — a running daemon will relaunch onto the new binary");
            println!("  A running NEOTH daemon will restart shortly onto the new version.");
        }
        Err(e) => {
            warn!(error = %e, "could not write restart.request marker (restart the daemon manually)");
        }
    }
}

fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

/// Emit the `0xD2 SELF_UPDATE_APPLIED` audit frame after a successful
/// manual `neoth update --self --apply`. Skips silently when the daemon
/// is live (it owns the WAL segment) or the WAL dir is unwritable —
/// every failure is logged at WARN, never fatal.
async fn emit_self_update_applied(
    outcome: &crate::updater::self_update::UpdateApplied,
    repo: &str,
    target: &str,
    trigger_source: &str,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "from_version": outcome.from_version,
        "to_version": outcome.to_version,
        "backup_path": outcome.backup_path.display().to_string(),
        "repo": repo,
        "target_triple": target,
        "archive_sha256": outcome.archive_sha256,
        "download_url": outcome.download_url,
        "signature_status": outcome.signature_status,
        "trigger_source": trigger_source,
        "ts_unix": now_unix_secs(),
    }))
    .unwrap_or_default();
    if let Ok(Some(_pid)) =
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile())
    {
        // AUDIT-RPC-01: daemon owns the writer → forward the 0xD2 frame over
        // the loopback channel instead of silently skipping. Best-effort.
        let home = crate::config::FreedomConfig::default_neoth_home();
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            &home,
            crate::wal::events::EVENT_TYPE_SELF_UPDATE_APPLIED,
            &payload,
        )
        .await
        {
            tracing::debug!(error = %e, "0xD2 audit forward skipped (daemon listener unreachable)");
        }
        return;
    }
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    if std::fs::create_dir_all(&wal_dir).is_err() {
        return;
    }
    let seg = wal_dir.join("000001.wal");
    let (writer, join) = match crate::wal::writer::spawn(seg) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "SELF_UPDATE_APPLIED WAL writer spawn failed (non-fatal)");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_SELF_UPDATE_APPLIED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "SELF_UPDATE_APPLIED WAL emit failed (non-fatal)");
    }
    drop(writer);
    let _ = join.await;
}

/// F55 — audit a tamper-suspect staged-apply rejection (0xDE). Mirrors
/// [`emit_self_update_applied`]'s daemon-RPC-then-direct-WAL plumbing; the
/// payload carries the integrity-violation `reason` (message only, never binary
/// bytes) so the audit chain shows WHY the staged artifact was refused.
async fn emit_self_update_rejected(
    repo: &str,
    pending: &crate::updater::self_update::PendingUpdate,
    reason: &str,
    trigger_source: &str,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "to_version": pending.to_version,
        "repo": repo,
        "target_triple": pending.target_triple,
        "archive_sha256": pending.archive_sha256,
        "reason": reason,
        "trigger_source": trigger_source,
        "ts_unix": now_unix_secs(),
    }))
    .unwrap_or_default();
    if let Ok(Some(_pid)) =
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile())
    {
        let home = crate::config::FreedomConfig::default_neoth_home();
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            &home,
            crate::wal::events::EVENT_TYPE_SELF_UPDATE_REJECTED,
            &payload,
        )
        .await
        {
            tracing::debug!(error = %e, "0xDE audit forward skipped (daemon listener unreachable)");
        }
        return;
    }
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    if std::fs::create_dir_all(&wal_dir).is_err() {
        return;
    }
    let seg = wal_dir.join("000001.wal");
    let (writer, join) = match crate::wal::writer::spawn(seg) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "SELF_UPDATE_REJECTED WAL writer spawn failed (non-fatal)");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_SELF_UPDATE_REJECTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "SELF_UPDATE_REJECTED WAL emit failed (non-fatal)");
    }
    drop(writer);
    let _ = join.await;
}

fn render_self_apply(applied: &crate::updater::self_update::UpdateApplied, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "from_version": applied.from_version,
                    "to_version": applied.to_version,
                    "backup_path": applied.backup_path.display().to_string(),
                    "restart_required": applied.restart_required,
                })
            );
        }
        OutputFormat::Table => {
            println!("# NEOTH daemon self-update applied");
            println!("  from         : {}", applied.from_version);
            println!("  to           : {}", applied.to_version);
            println!("  backup       : {}", applied.backup_path.display());
            if applied.restart_required {
                println!();
                println!("  Restart the daemon to run the new binary.");
            }
        }
    }
}

fn render_list(output: OutputFormat) -> Result<()> {
    let rows: Vec<_> = Component::ALL
        .iter()
        .map(|c| {
            // Components without an npm channel surface the
            // shell-installer URL instead so the operator can see WHERE
            // the binary actually comes from.
            let install_source = c
                .npm_package()
                .map(str::to_string)
                .unwrap_or_else(|| match *c {
                    Component::AntigravityCli => "shell:antigravity.google/cli/install".to_string(),
                    _ => "shell:vendor".to_string(),
                });
            serde_json::json!({
                "component": c.name(),
                "binary": c.binary(),
                "install_source": install_source,
            })
        })
        .collect();

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Jsonl => {
            for r in &rows {
                println!("{}", serde_json::to_string(r)?);
            }
        }
        OutputFormat::Table => {
            println!(
                "{:<16} {:<10} {:<40}",
                "component", "binary", "install_source"
            );
            println!("{}", "-".repeat(68));
            for r in &rows {
                println!(
                    "{:<16} {:<10} {:<40}",
                    r["component"].as_str().unwrap_or("?"),
                    r["binary"].as_str().unwrap_or("?"),
                    r["install_source"].as_str().unwrap_or("?"),
                );
            }
        }
    }
    Ok(())
}

fn render_report(report: &[UpdateStatus], output: OutputFormat) {
    match output {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string_pretty(report) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for row in report {
                if let Ok(s) = serde_json::to_string(row) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Table => {
            println!(
                "{:<14} {:<14} {:<14} {:<10} applied",
                "component", "installed", "latest", "needs?"
            );
            println!("{}", "-".repeat(70));
            for row in report {
                println!(
                    "{:<14} {:<14} {:<14} {:<10} {}",
                    row.component.name(),
                    row.installed.as_deref().unwrap_or("(none)"),
                    row.latest.as_deref().unwrap_or("?"),
                    if row.update_available { "yes" } else { "no" },
                    row.applied.as_deref().unwrap_or("-"),
                );
            }
            let upgradable = report.iter().filter(|r| r.update_available).count();
            if upgradable > 0 {
                println!(
                    "\n{upgradable} component(s) have updates available. \
                     Run `neoth update --apply` to install."
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::Component;

    #[test]
    fn render_list_does_not_panic_on_any_output_format() {
        for fmt in [OutputFormat::Table, OutputFormat::Json, OutputFormat::Jsonl] {
            render_list(fmt).unwrap();
        }
    }

    #[test]
    fn render_report_handles_empty_input() {
        for fmt in [OutputFormat::Table, OutputFormat::Json, OutputFormat::Jsonl] {
            render_report(&[], fmt);
        }
    }

    #[test]
    fn render_report_includes_one_upgradable_marker() {
        let report = vec![UpdateStatus {
            component: Component::ClaudeCli,
            installed: Some("1.0.0".into()),
            latest: Some("1.0.1".into()),
            update_available: true,
            applied: None,
        }];
        // Smoke test that it does not panic; stdout capture would be heavier.
        render_report(&report, OutputFormat::Table);
        render_report(&report, OutputFormat::Json);
        render_report(&report, OutputFormat::Jsonl);
    }
}
