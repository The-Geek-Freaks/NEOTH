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
    /// When combined with `--self`, runs the full release-bundle
    /// update (download, signature + SHA-256 verification,
    /// preflight, transactional replace) instead of the managed-CLI update.
    #[arg(long, conflicts_with_all = ["check", "list"])]
    pub apply: bool,

    /// Print the static list of components NEOTH knows how to update.
    #[arg(long, conflicts_with_all = ["check", "apply"])]
    pub list: bool,

    /// Check whether a newer NEOTH release is published on GitHub.
    /// Without `--apply` this is check-only. With `--apply`, the signed
    /// platform bundle is verified, preflighted, and transactionally applied.
    /// Pass `--self-repo owner/name` to point at a fork; default
    /// is `The-Geek-Freaks/NEOTH`.
    #[arg(long = "self", conflicts_with = "list")]
    pub self_check: bool,

    /// Override the configured GitHub `owner/repo` slug for self-check/apply.
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
        // The manual path consumes the same release policy as daemon probes
        // and staging. `--self-repo` remains the explicit one-shot override.
        let policy = load_self_update_policy()?;
        let repo = args.self_repo.as_deref().unwrap_or(&policy.repo);
        let channel = policy.channel;
        if args.apply {
            info!(
                repo = repo,
                channel = %channel,
                "neoth update --self --apply: verified bundle apply"
            );
            return run_self_apply(
                repo,
                channel,
                policy.target_triple.as_deref(),
                args.allow_unsigned,
                args.output,
            )
            .await;
        }
        info!(repo = repo, channel = %channel, "neoth update --self: checking GitHub release");
        let outcome = crate::updater::self_update::check_for_update_channel(repo, channel).await?;
        render_self_check(&outcome, channel, args.output);
        return Ok(());
    }
    if args.apply {
        info!("neoth update --apply: probing + installing");
        let home = crate::config::FreedomConfig::default_neoth_home();
        let config_path = home.join("freedom.yaml");
        if !config_path.is_file() {
            anyhow::bail!(
                "no freedom.yaml found at {}. Run `neoth init` first; component updates stay blocked until an operator dependency policy exists",
                config_path.display()
            );
        }
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

fn load_self_update_policy() -> Result<crate::config::AutoUpdateConfig> {
    let path = crate::config::FreedomConfig::default_path();
    load_self_update_policy_from(&path)
}

fn load_self_update_policy_from(path: &std::path::Path) -> Result<crate::config::AutoUpdateConfig> {
    if !path.is_file() {
        return Ok(crate::config::AutoUpdateConfig::default());
    }
    crate::config::FreedomConfig::load_from_path(path)
        .map(|config| config.auto_update)
        .with_context(|| format!("load self-update policy from {}", path.display()))
}

fn render_self_check(
    check: &crate::updater::self_update::UpdateCheck,
    channel: crate::config::ReleaseChannel,
    output: OutputFormat,
) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "current": check.current,
                    "latest": check.latest,
                    "channel": channel.as_str(),
                    "needs_update": check.needs_update,
                    "release_url": check.release_url,
                    "published_at": check.published_at,
                })
            );
        }
        OutputFormat::Table => {
            println!("# NEOTH release-bundle self-update check");
            println!("  current      : {}", check.current);
            println!("  latest       : {}", check.latest);
            println!("  channel      : {channel}");
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

/// Operator-facing apply path. Probes the release, short-circuits when the core
/// is current, then runs the verified transactional bundle replacement in the
/// directory containing `std::env::current_exe()`.
async fn run_self_apply(
    repo: &str,
    channel: crate::config::ReleaseChannel,
    configured_target: Option<&str>,
    allow_unsigned: bool,
    output: OutputFormat,
) -> Result<()> {
    use crate::updater::self_update::{
        apply_update, fetch_release_for_channel, resolve_release_target, version_is_newer,
    };

    let target = resolve_release_target(configured_target)?;

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
        if let Some(mut locked_stage) =
            crate::updater::self_update::lock_pending_stage_async(stage_dir.clone()).await?
            && let Some(pending) = locked_stage.pending().cloned()
        {
            let current = crate::updater::self_update::current_version();
            let staged_policy_matches = crate::updater::self_update::pending_matches_policy(
                &pending, repo, channel, target,
            );
            let staged_newer = match version_is_newer(&pending.to_version, current) {
                Ok(newer) => newer,
                Err(error) => {
                    warn!(
                        version = %pending.to_version,
                        error = %error,
                        "discarding staged update with an invalid semantic version"
                    );
                    false
                }
            };
            if !staged_newer || !staged_policy_matches {
                if !staged_policy_matches {
                    warn!(
                        staged_channel = %pending.channel,
                        selected_channel = %channel,
                        staged_repo = %pending.source_repo,
                        selected_repo = %repo,
                        staged_target = %pending.target_triple,
                        selected_target = %target,
                        "discarding staged update that does not match current self-update policy"
                    );
                }
                locked_stage
                    .clear()
                    .context("clear unusable staged self-update")?;
            } else {
                info!(
                    to = %pending.to_version,
                    "applying pre-staged + verified update (skipping download)"
                );
                let exe = std::env::current_exe().context("locate current executable")?;
                let install_dir = exe
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("current_exe() has no parent directory"))?;
                match locked_stage.apply(install_dir, require_signature) {
                    Ok(outcome) => {
                        let cleanup = locked_stage.clear();
                        drop(locked_stage);
                        finish_self_update_outcome(
                            &outcome,
                            repo,
                            channel,
                            &pending.target_triple,
                            "manual_from_staged",
                            output,
                        )
                        .await?;
                        cleanup.context(
                            "self-update applied but its staged payload could not be cleared",
                        )?;
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
                            let cleanup_error = locked_stage.clear().err();
                            drop(locked_stage);
                            if let Err(audit) = emit_self_update_rejected_owned(
                                repo,
                                &pending,
                                &format!("{e:#}"),
                                "manual_from_staged",
                            )
                            .await
                            {
                                return Err(e.context(format!(
                                    "staged self-update failed integrity verification; SELF_UPDATE_REJECTED audit indeterminate: {audit:#}"
                                )));
                            }
                            let context = cleanup_error.map_or_else(
                                || {
                                    "staged self-update failed integrity verification — refusing to apply a tamper-suspect artifact".to_string()
                                },
                                |cleanup| {
                                    format!(
                                        "staged self-update failed integrity verification and capability-bound cleanup also failed: {cleanup:#}"
                                    )
                                },
                            );
                            return Err(e.context(context));
                        }
                        // Non-security failure (I/O / extraction): clear the broken
                        // stage and fall back to a fresh download.
                        warn!(error = %e, "staged apply failed (non-security); clearing stage and falling back to fresh download");
                        locked_stage
                            .clear()
                            .context("clear failed staged self-update before fresh download")?;
                    }
                }
            }
        }
    }

    let release = fetch_release_for_channel(repo, channel).await?;
    let current = crate::updater::self_update::current_version();
    let needs = version_is_newer(&release.tag_name, current)?;
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
        render_self_check(&check, channel, output);
        return Ok(());
    }
    let exe = std::env::current_exe().context("locate current executable")?;
    let install_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("current_exe() has no parent directory"))?;

    // GOLD-SEC-10 / A-22 — SIGNATURE REQUIRED BY DEFAULT. `require_signature`
    // (and the no-pinned-key fail-closed bail) was already evaluated at the top
    // of this fn so it covers the staged fast-path too (GR-043); here we just
    // thread it into the fresh-download verify+apply.
    // The archive is a version-locked bundle. The updater preserves a
    // source-only footprint, but refreshes every installed release companion.
    let outcome = apply_update(
        &release,
        repo,
        channel,
        target,
        "neoth",
        install_dir,
        require_signature,
    )
    .await?;

    // WAL audit frame 0xD2 SELF_UPDATE_APPLIED — same-home audit-RPC when
    // the daemon is live, otherwise a unique home-bound one-shot writer.
    // The binary swap already succeeded; an unacknowledged audit is surfaced before any committed output or restart request.
    // `trigger_source =
    // "manual"` — the operator ran `neoth update --self --apply`. The
    // The daemon's stage-only path emits its own staged-pending frame through
    // the live WAL writer; binary replacement remains operator-initiated.
    finish_self_update_outcome(&outcome, repo, channel, target, "manual", output).await
}

async fn finish_self_update_outcome(
    outcome: &crate::updater::self_update::UpdateApplyOutcome,
    repo: &str,
    channel: crate::config::ReleaseChannel,
    target: &str,
    trigger_source: &str,
    output: OutputFormat,
) -> Result<()> {
    let mut effects = ProductionSelfUpdateFinishEffects {
        repo,
        channel,
        target,
        trigger_source,
        output,
    };
    finish_self_update_outcome_with_effects(outcome, &mut effects).await
}

/// The sole post-apply completion flow. Keeping receipt acknowledgement ahead
/// of operator output and restart scheduling makes the already-applied/
/// audit-indeterminate boundary directly testable without changing production
/// behavior.
async fn finish_self_update_outcome_with_effects<E: SelfUpdateFinishEffects>(
    outcome: &crate::updater::self_update::UpdateApplyOutcome,
    effects: &mut E,
) -> Result<()> {
    match outcome {
        crate::updater::self_update::UpdateApplyOutcome::Applied(applied) => {
            require_self_update_audit_ack(effects.acknowledge_applied(applied).await)?;
            effects.render_applied(applied);
            effects.request_restart()?;
        }
        crate::updater::self_update::UpdateApplyOutcome::HandoffScheduled(scheduled) => {
            effects.render_handoff_scheduled(scheduled);
        }
    }
    Ok(())
}

trait SelfUpdateFinishEffects {
    async fn acknowledge_applied(
        &mut self,
        applied: &crate::updater::self_update::UpdateApplied,
    ) -> Result<()>;
    fn render_applied(&mut self, applied: &crate::updater::self_update::UpdateApplied);
    fn render_handoff_scheduled(
        &mut self,
        scheduled: &crate::updater::self_update::UpdateHandoffScheduled,
    );
    fn request_restart(&mut self) -> Result<()>;
}

struct ProductionSelfUpdateFinishEffects<'a> {
    repo: &'a str,
    channel: crate::config::ReleaseChannel,
    target: &'a str,
    trigger_source: &'a str,
    output: OutputFormat,
}

impl SelfUpdateFinishEffects for ProductionSelfUpdateFinishEffects<'_> {
    async fn acknowledge_applied(
        &mut self,
        applied: &crate::updater::self_update::UpdateApplied,
    ) -> Result<()> {
        emit_self_update_applied_owned(
            applied,
            self.repo,
            self.channel,
            self.target,
            self.trigger_source,
        )
        .await
    }

    fn render_applied(&mut self, applied: &crate::updater::self_update::UpdateApplied) {
        render_self_apply(applied, self.output);
    }

    fn render_handoff_scheduled(
        &mut self,
        scheduled: &crate::updater::self_update::UpdateHandoffScheduled,
    ) {
        render_self_handoff_scheduled(scheduled, self.output);
    }

    fn request_restart(&mut self) -> Result<()> {
        maybe_request_restart()
    }
}

/// MV-01b restart contract: after a successful swap, if a supervisor is
/// installed (`config.supervisor.enabled`), drop the `restart.request`
/// marker so a RUNNING daemon picks up the new binary on its next watcher
/// tick (it drains + exits → the supervisor relaunches). No-op when no
/// supervisor is configured (an exit would just leave the daemon down).
fn maybe_request_restart() -> Result<()> {
    let enabled = crate::config::FreedomConfig::load_from_default_path_or_default()?
        .supervisor
        .enabled;
    if !enabled {
        return Ok(());
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
    Ok(())
}

fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

/// Emit the `0xD2 SELF_UPDATE_APPLIED` audit frame after a successful
/// manual `neoth update --self --apply`. A live daemon receives it over
/// same-home audit-RPC; otherwise a unique home-bound writer is drained.
/// Callers surface an indeterminate acknowledgement before committed output or restart scheduling.
/// Shared applied-update receipt path. Callers must propagate an indeterminate
/// ACK before they render `committed` or schedule post-commit cleanup.
pub(super) async fn emit_self_update_applied(
    outcome: &crate::updater::self_update::UpdateApplied,
    repo: &str,
    channel: crate::config::ReleaseChannel,
    target: &str,
    trigger_source: &str,
) -> Result<()> {
    emit_self_update_applied_owned(outcome, repo, channel, target, trigger_source).await
}
fn require_self_update_audit_ack(audit: Result<()>) -> Result<()> {
    audit.context("SELF_UPDATE_APPLIED already applied; audit acknowledgement is indeterminate")
}

/// Dedicated D2/DE owner transaction: no UUID standalone writer remains.
async fn append_owned_self_update_audit(payload: &[u8], event_type: u8) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    append_owned_self_update_audit_at_home(&home, payload, event_type).await
}

/// Home-bound consumer for the D2/DE owner transaction. Production obtains its
/// home above; keeping the owner selection here makes the exact same path
/// testable against a real temporary same-user endpoint and WAL chain.
async fn append_owned_self_update_audit_at_home(
    home: &std::path::Path,
    payload: &[u8],
    event_type: u8,
) -> Result<()> {
    anyhow::ensure!(
        matches!(event_type, 0xD2 | 0xDE),
        "self-update audit event outside D2/DE contract"
    );
    match crate::daemon::audit_rpc::try_post_self_update_audit_frame(home, event_type, payload)
        .await
    {
        Ok(()) => Ok(()),
        Err(crate::daemon::audit_rpc::SelfUpdateAuditError::OfflinePrewriteAbsent(_)) => {
            let _lease = crate::daemon::pidfile::acquire_offline_self_update_audit_interlock(
                &home.join("neothd.pid"),
            )?
            .ok_or_else(|| {
                anyhow::anyhow!("SELF_UPDATE audit owner became live before offline lease")
            })?;
            let wal_dir = home.join("wal");
            std::fs::create_dir_all(&wal_dir).context("create self-update audit WAL directory")?;
            let base = crate::wal::writer::self_update_audit_chain_base_path(&wal_dir);
            let tail = crate::wal::scan::latest_home_segment_in_chain(
                home,
                &base,
                crate::wal::scan::HomeWalScanLimits::default(),
            )
            .context("resolve canonical self-update audit chain tail")?;
            let (writer, completion) =
                crate::wal::writer::spawn_for_home_with_completion(tail, home.to_path_buf())
                    .context("open canonical self-update audit chain")?;
            let header = crate::wal::HeaderBuilder::new(event_type, payload).build();
            let append = writer.append(header, payload.to_vec()).await;
            drop(writer);
            let finalized = completion.wait().await;
            match (append, finalized) {
                (Ok(_), Ok(())) => Ok(()),
                (Err(append), Ok(())) => Err(anyhow::anyhow!("append self-update audit: {append}")),
                (Ok(_), Err(finalize)) => {
                    Err(anyhow::anyhow!("finalize self-update audit: {finalize}"))
                }
                (Err(append), Err(finalize)) => Err(anyhow::anyhow!(
                    "append self-update audit: {append}; finalization also failed: {finalize}"
                )),
            }
        }
        Err(error) => Err(anyhow::anyhow!("SELF_UPDATE audit indeterminate: {error}")),
    }
}

async fn emit_self_update_applied_owned(
    outcome: &crate::updater::self_update::UpdateApplied,
    repo: &str,
    channel: crate::config::ReleaseChannel,
    target: &str,
    trigger_source: &str,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "from_version": outcome.from_version, "to_version": outcome.to_version,
        "transaction_id": outcome.transaction_id, "recovery": "automatic_crash_recovery",
        "repo": repo, "channel": channel.as_str(), "target_triple": target,
        "archive_sha256": outcome.archive_sha256, "download_url": outcome.download_url,
        "signature_status": outcome.signature_status, "trigger_source": trigger_source,
        "ts_unix": now_unix_secs(),
    }))
    .expect("self-update payload contains only infallible JSON values");
    append_owned_self_update_audit(&payload, crate::wal::events::EVENT_TYPE_SELF_UPDATE_APPLIED)
        .await
}

async fn emit_self_update_rejected_owned(
    repo: &str,
    pending: &crate::updater::self_update::PendingUpdate,
    reason: &str,
    trigger_source: &str,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "to_version": pending.to_version, "repo": repo, "staged_repo": pending.source_repo,
        "channel": pending.channel.as_str(), "target_triple": pending.target_triple,
        "archive_sha256": pending.archive_sha256, "reason": reason,
        "trigger_source": trigger_source, "ts_unix": now_unix_secs(),
    }))
    .expect("self-update rejection payload contains only infallible JSON values");
    append_owned_self_update_audit(
        &payload,
        crate::wal::events::EVENT_TYPE_SELF_UPDATE_REJECTED,
    )
    .await
}
fn render_self_apply(applied: &crate::updater::self_update::UpdateApplied, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "from_version": applied.from_version,
                    "to_version": applied.to_version,
                    "transaction_id": applied.transaction_id,
                    "automatic_crash_recovery": applied.automatic_crash_recovery,
                    "restart_required": applied.restart_required,
                })
            );
        }
        OutputFormat::Table => {
            println!("# NEOTH release-bundle self-update applied");
            println!("  from         : {}", applied.from_version);
            println!("  to           : {}", applied.to_version);
            println!("  transaction  : {}", applied.transaction_id);
            println!("  recovery     : automatic on interrupted commit");
            if applied.restart_required {
                println!();
                println!("  Restart the daemon to run the new binary.");
            }
        }
    }
}

fn render_self_handoff_scheduled(
    scheduled: &crate::updater::self_update::UpdateHandoffScheduled,
    output: OutputFormat,
) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "status": "handoff_scheduled",
                    "from_version": scheduled.from_version,
                    "to_version": scheduled.to_version,
                    "operation_id": scheduled.operation_id,
                    "receipt_path": scheduled.receipt_path,
                    "restart_required": scheduled.restart_required,
                })
            );
        }
        OutputFormat::Table => {
            println!("# NEOTH Windows self-update scheduled");
            println!("  from         : {}", scheduled.from_version);
            println!("  to           : {}", scheduled.to_version);
            println!("  operation    : {}", scheduled.operation_id);
            println!("  receipt      : {}", scheduled.receipt_path.display());
            println!();
            println!(
                "  The signed target helper will finish the update automatically after this command exits."
            );
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

    #[test]
    fn self_update_policy_loader_honors_channel_repo_and_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "auto_update:\n  channel: nightly\n  repo: example/fork\n  target_triple: x86_64-unknown-linux-musl\n",
        )
        .unwrap();
        let policy = load_self_update_policy_from(&path).unwrap();
        assert_eq!(policy.channel, crate::config::ReleaseChannel::Nightly);
        assert_eq!(policy.repo, "example/fork");
        assert_eq!(
            policy.target_triple.as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
    }

    #[test]
    fn self_update_policy_loader_defaults_only_when_file_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.yaml");
        assert_eq!(
            load_self_update_policy_from(&missing).unwrap(),
            crate::config::AutoUpdateConfig::default()
        );

        let invalid = dir.path().join("invalid.yaml");
        std::fs::write(&invalid, "auto_update:\n  channel: beta\n").unwrap();
        assert!(load_self_update_policy_from(&invalid).is_err());
    }
    #[tokio::test]
    async fn w2452_consumer_offline_d2_then_de_continues_preexisting_rotated_tail() {
        let home = tempfile::tempdir().expect("temporary self-update home");
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).expect("create WAL directory");
        let base = crate::wal::writer::self_update_audit_chain_base_path(&wal_dir);
        let rotated_tail = wal_dir.join("self-update-audit-000002.wal");

        // Seed a real rotated chain before the consumer starts. The consumer
        // must select 000002, not reopen 000001 or allocate a UUID namespace.
        for (segment, event, payload) in [
            (base.clone(), 0xD2_u8, &b"preexisting-d2"[..]),
            (rotated_tail.clone(), 0xDE_u8, &b"preexisting-de"[..]),
        ] {
            let (writer, completion) = crate::wal::writer::spawn_for_home_with_completion(
                segment,
                home.path().to_path_buf(),
            )
            .expect("seed canonical self-update chain");
            writer
                .append(
                    crate::wal::HeaderBuilder::new(event, payload).build(),
                    payload.to_vec(),
                )
                .await
                .expect("seed frame");
            drop(writer);
            completion.wait().await.expect("seed completion");
        }

        append_owned_self_update_audit_at_home(home.path(), b"consumer-d2", 0xD2)
            .await
            .expect("offline D2 owner append");
        append_owned_self_update_audit_at_home(home.path(), b"consumer-de", 0xDE)
            .await
            .expect("offline DE owner append");

        let selected = crate::wal::scan::latest_home_segment_in_chain(
            home.path(),
            &base,
            crate::wal::scan::HomeWalScanLimits::default(),
        )
        .expect("resolve canonical chain tail after both consumer calls");
        assert_eq!(
            selected, rotated_tail,
            "consumer must continue the pre-existing rotated tail"
        );
        let tail_bytes = std::fs::read(&selected).expect("read selected tail");
        assert!(
            tail_bytes
                .windows(b"consumer-d2".len())
                .any(|window| window == b"consumer-d2"),
            "D2 must be appended to the selected canonical tail"
        );
        assert!(
            tail_bytes
                .windows(b"consumer-de".len())
                .any(|window| window == b"consumer-de"),
            "DE must be appended to the same canonical tail"
        );
        let base_bytes = std::fs::read(&base).expect("read original base segment");
        assert!(
            !base_bytes
                .windows(b"consumer-d2".len())
                .any(|window| window == b"consumer-d2")
                && !base_bytes
                    .windows(b"consumer-de".len())
                    .any(|window| window == b"consumer-de"),
            "consumer must not reopen the older pre-rotation segment"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn w2452_consumer_connected_postwrite_eof_never_creates_offline_segment() {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::AsyncReadExt as _;

        let home = tempfile::tempdir().expect("temporary same-user home");
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let endpoint = crate::daemon::audit_rpc::endpoint_for_home(home.path(), &nonce)
            .expect("derive exact same-user endpoint");
        let path = match &endpoint {
            crate::daemon::audit_rpc::AuditEndpointV2::UnixSocket { path, .. } => path.clone(),
        };
        let runtime = path.parent().expect("runtime directory");
        let namespace = runtime.parent().expect("home namespace");
        let runtime_root = namespace.parent().expect("private runtime root");
        std::fs::create_dir_all(namespace).expect("create exact endpoint namespace");
        std::fs::set_permissions(runtime_root, std::fs::Permissions::from_mode(0o700))
            .expect("private endpoint runtime root");
        std::fs::set_permissions(namespace, std::fs::Permissions::from_mode(0o700))
            .expect("private endpoint namespace");
        std::fs::create_dir(runtime).expect("create exact endpoint runtime directory");
        std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o700))
            .expect("private endpoint runtime directory");
        let listener =
            tokio::net::UnixListener::bind(&path).expect("bind exact same-user endpoint");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private endpoint socket");

        let _token =
            crate::daemon::audit_rpc::init_rpc_token(home.path()).expect("mint same-user bearer");
        let mut pid_guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("hold daemon PID lock for exact owner proof");
        crate::daemon::audit_rpc::write_sidecar(home.path(), &endpoint, std::process::id(), &nonce)
            .expect("publish exact endpoint sidecar");
        pid_guard
            .publish_endpoint_nonce(&nonce)
            .expect("publish sidecar nonce under PID lock");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept authenticated client");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let header_end = loop {
                let read = stream.read(&mut chunk).await.expect("read client request");
                assert_ne!(
                    read, 0,
                    "client must write a complete request before EOF fixture closes"
                );
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            assert!(request.starts_with(b"POST /updater/self-update-audit HTTP/1.1\r\n"));
            let header = std::str::from_utf8(&request[..header_end]).expect("ASCII request header");
            let content_length = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .expect("sealed client sends a body length")
                .parse::<usize>()
                .expect("numeric content length");
            while request.len() < header_end + content_length {
                let read = stream
                    .read(&mut chunk)
                    .await
                    .expect("read complete client body");
                assert_ne!(read, 0, "client body must finish before EOF fixture closes");
                request.extend_from_slice(&chunk[..read]);
            }
            // Closing after the complete client request simulates a real
            // connected post-write EOF; no response can authorize fallback.
        });
        let result = append_owned_self_update_audit_at_home(
            home.path(),
            br#"{"from_version":"1","to_version":"2","transaction_id":"tx","repo":"r","channel":"stable","target_triple":"x","archive_sha256":"h","download_url":"u","signature_status":"verified","trigger_source":"test","ts_unix":1}"#,
            0xD2,
        )
        .await;
        assert!(
            result.is_err(),
            "post-write EOF must remain a hard audit error"
        );
        server.await.expect("EOF fixture task");
        assert!(
            !home
                .path()
                .join("wal")
                .join("self-update-audit-000001.wal")
                .exists(),
            "connected post-write failure must never create an offline self-update chain"
        );
        drop(pid_guard);
        std::fs::remove_file(&path).expect("remove EOF fixture socket");
        std::fs::remove_dir(runtime).expect("remove EOF fixture runtime directory");
        std::fs::remove_dir(namespace).expect("remove EOF fixture home namespace");
    }
    struct FailingAppliedAuditEffects {
        rendered: bool,
        restart_requested: bool,
    }

    impl SelfUpdateFinishEffects for FailingAppliedAuditEffects {
        async fn acknowledge_applied(
            &mut self,
            _applied: &crate::updater::self_update::UpdateApplied,
        ) -> Result<()> {
            Err(anyhow::anyhow!("post-write EOF"))
        }

        fn render_applied(&mut self, _applied: &crate::updater::self_update::UpdateApplied) {
            self.rendered = true;
        }

        fn render_handoff_scheduled(
            &mut self,
            _scheduled: &crate::updater::self_update::UpdateHandoffScheduled,
        ) {
            panic!("applied outcome must not render a handoff");
        }

        fn request_restart(&mut self) -> Result<()> {
            self.restart_requested = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn w2452_applied_audit_failure_blocks_render_and_restart_gate() {
        let outcome = crate::updater::self_update::UpdateApplyOutcome::Applied(
            crate::updater::self_update::UpdateApplied {
                from_version: "1.0.0".into(),
                to_version: "1.0.1".into(),
                transaction_id: "w2452-test".into(),
                automatic_crash_recovery: false,
                restart_required: true,
                archive_sha256: "a".repeat(64),
                download_url: "https://example.invalid/neoth.zip".into(),
                signature_status: "verified".into(),
            },
        );
        let mut effects = FailingAppliedAuditEffects {
            rendered: false,
            restart_requested: false,
        };

        let error = finish_self_update_outcome_with_effects(&outcome, &mut effects)
            .await
            .expect_err("an already-applied update must stop on audit indeterminacy");

        assert!(
            error
                .to_string()
                .contains("already applied; audit acknowledgement is indeterminate"),
            "the terminal error must preserve the already-applied/audit-indeterminate boundary: {error:#}"
        );
        assert!(
            !effects.rendered,
            "audit indeterminacy must block committed output"
        );
        assert!(
            !effects.restart_requested,
            "audit indeterminacy must block the restart-request marker"
        );
    }
}
