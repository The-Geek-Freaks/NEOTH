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
use tracing::info;

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
        let repo = args
            .self_repo
            .as_deref()
            .unwrap_or("The-Geek-Freaks/NEOTH");
        if args.apply {
            info!(repo = repo, "neoth update --self --apply: full Phase 2b flow");
            return run_self_apply(repo, args.output).await;
        }
        info!(repo = repo, "neoth update --self: checking GitHub release");
        let outcome = crate::updater::self_update::check_for_update(repo).await?;
        render_self_check(&outcome, args.output);
        return Ok(());
    }
    if args.apply {
        info!("neoth update --apply: probing + installing");
        let report = check_and_apply_all().await;
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
async fn run_self_apply(repo: &str, output: OutputFormat) -> Result<()> {
    use crate::updater::self_update::{
        apply_update, fetch_latest_release, host_target_triple, version_is_newer,
    };

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

    let outcome = apply_update(&release, target, "neoth", install_dir).await?;
    render_self_apply(&outcome, output);
    Ok(())
}

fn render_self_apply(
    applied: &crate::updater::self_update::UpdateApplied,
    output: OutputFormat,
) {
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
            serde_json::json!({
                "component": c.name(),
                "binary": c.binary(),
                "npm_package": c.npm_package(),
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
            println!("{:<14} {:<10} {:<30}", "component", "binary", "npm_package");
            println!("{}", "-".repeat(58));
            for c in Component::ALL {
                println!(
                    "{:<14} {:<10} {:<30}",
                    c.name(),
                    c.binary(),
                    c.npm_package()
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
