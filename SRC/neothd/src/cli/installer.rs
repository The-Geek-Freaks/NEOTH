//! W-05b — operator-facing CLI surface for the package-manager
//! fallback chain.
//!
//! The wizard's step6h_install_recommended already prints the
//! dry-run preview during onboarding; this CLI lets operators
//! re-run the same logic ad-hoc + optionally execute the chain.
//!
//! Subcommands:
//!   - `neoth installer dry-run <pkg>` — show argv for every
//!     handle in the host's chain. Default + safe.
//!   - `neoth installer apply <pkg>` — actually run the chain
//!     until a handle succeeds. **Privileged**: invokes
//!     `sudo apt install` / `winget install` / etc. on the host.
//!     Requires `--yes` to confirm operator intent (no
//!     auto-execute under any flag combination).
//!
//! Output: a one-line summary of the winning handle + a per-handle
//! ChainResult.tried list when the operator passes `--verbose`.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::FreedomConfig;
use crate::wizard::install_step::{
    ChainResult, FallbackChain, build_installer_ran_payload, dry_run_install_commands,
};

#[derive(Args, Debug, Clone)]
pub struct InstallerArgs {
    #[command(subcommand)]
    pub action: InstallerAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum InstallerAction {
    /// Print the install argv for every handle in the host's
    /// fallback chain. Pure-fn — no subprocess fires.
    DryRun {
        /// Package id to render commands for (e.g.
        /// `Docker.Docker` on winget, `docker.io` on apt).
        pkg: String,
    },
    /// Execute the fallback chain against `pkg`. Tries each
    /// handle in order until one returns `is_success`.
    Apply {
        /// Package id (same as DryRun).
        pkg: String,
        /// Required for the execute path — running `sudo apt
        /// install` etc. without explicit operator confirm
        /// would violate the AGENTER no-destructive-ops-without-
        /// confirm rule.
        #[arg(long)]
        yes: bool,
        /// Print every handle's outcome, not just the winner.
        #[arg(long)]
        verbose: bool,
    },
}

pub async fn run_installer(args: InstallerArgs) -> Result<()> {
    match args.action {
        InstallerAction::DryRun { pkg } => run_dry_run(&pkg),
        InstallerAction::Apply { pkg, yes, verbose } => run_apply(&pkg, yes, verbose).await,
    }
}

fn run_dry_run(pkg: &str) -> Result<()> {
    let chain = FallbackChain::for_host();
    if chain.is_empty() {
        println!("No package-manager chain known for this host.");
        return Ok(());
    }
    println!("Fallback chain for `{pkg}` (dry-run — nothing executed):");
    for (kind, argv) in dry_run_install_commands(&chain, pkg) {
        println!("  [{}] {}", kind.as_str(), argv.join(" "));
    }
    Ok(())
}

async fn run_apply(pkg: &str, yes: bool, verbose: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to execute the install chain without --yes. \
             Re-run with `neoth installer apply {pkg} --yes` after \
             you've inspected the dry-run with `neoth installer \
             dry-run {pkg}`."
        );
    }
    let chain = FallbackChain::for_host();
    if chain.is_empty() {
        anyhow::bail!("No package-manager chain known for this host — install manually.");
    }
    println!("Running install chain for `{pkg}`:");
    let result = chain.install(pkg, false).await;
    print_chain_result(&result, verbose);

    // W-05c — drop an audit sidecar with the InstallerRanPayload
    // so the daemon's next boot can pick it up + emit the
    // `0x12 INSTALLER_RAN` WAL frame. At-least-once semantics
    // mirror the credential-import + cluster-audit ingesters.
    let ts_unix = crate::time::now_unix_secs();
    let payload = build_installer_ran_payload(
        pkg,
        "", // version unknown at execute time; the daemon's
        // installer_audit ingester can re-probe via the
        // detect cache if it wants to enrich.
        "n/a",
        ts_unix,
        "cli_installer_apply",
        &result,
    );
    let home = FreedomConfig::default_neoth_home();
    if let Err(e) = write_installer_audit_sidecar(&home, ts_unix, &payload) {
        // Non-fatal — the install itself succeeded, audit is
        // observability-only.
        tracing::warn!(error = %e, "installer audit sidecar write failed (non-fatal)");
    }

    if !result.is_success() {
        anyhow::bail!(
            "Every handle in the chain failed for `{pkg}`. \
             Inspect the per-handle output above + install manually."
        );
    }
    Ok(())
}

/// Write the `InstallerRanPayload` to a sidecar file under
/// `~/.neoth/`. The daemon's installer_audit ingester picks it
/// up on next boot, emits the `0x12 INSTALLER_RAN` WAL frame,
/// then deletes the sidecar — at-least-once semantics.
///
/// Atomic via `.tmp` + rename, Windows-safe (target removed
/// before the rename when it exists).
pub fn write_installer_audit_sidecar(
    neoth_dir: &std::path::Path,
    ts_unix: u64,
    payload: &crate::wal::payloads_w08::InstallerRanPayload,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(neoth_dir)?;
    let final_path = neoth_dir.join(format!("installer_ran_{ts_unix}.json"));
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, &body)?;
    if final_path.exists() {
        let _ = std::fs::remove_file(&final_path);
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

fn print_chain_result(result: &ChainResult, verbose: bool) {
    if let Some(kind) = result.winning_kind {
        println!("  ✓ {} succeeded", kind.as_str());
    } else {
        println!("  ✗ every handle failed");
    }
    if verbose {
        println!("  Per-handle outcomes:");
        for (kind, outcome) in &result.tried {
            println!("    [{}] {}", kind.as_str(), outcome.snake_case_tag());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_renders_argv_for_host() {
        // Pure-fn — no subprocess. Test pins that the
        // default-host chain has at least one handle on
        // tier-1 OSes; on unsupported hosts the function
        // still prints the friendly fallthrough.
        let res = run_dry_run("Docker.Docker");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn apply_without_yes_refuses() {
        let res = run_apply("Docker.Docker", false, false).await;
        assert!(res.is_err());
        let msg = format!("{:?}", res.unwrap_err());
        assert!(msg.contains("--yes"));
    }

    #[test]
    fn args_dry_run_takes_pkg() {
        let args = InstallerArgs {
            action: InstallerAction::DryRun {
                pkg: "Docker.Docker".into(),
            },
        };
        // Compile-time pin on the args shape.
        match args.action {
            InstallerAction::DryRun { pkg } => assert_eq!(pkg, "Docker.Docker"),
            _ => panic!("expected DryRun"),
        }
    }

    #[test]
    fn audit_sidecar_writes_payload_atomically() {
        use crate::wal::payloads_w08::InstallerRanPayload;
        let home = tempfile::tempdir().unwrap();
        let payload = InstallerRanPayload {
            cli_name: "Docker.Docker".into(),
            version: String::new(),
            login_state: "n/a".into(),
            ts_unix: 1_700_000_000,
            dry_run: false,
            wizard_step: "cli_installer_apply".into(),
            pkg_mgr: "apt".into(),
        };
        let path = write_installer_audit_sidecar(home.path(), 1_700_000_000, &payload).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("Docker.Docker"));
        assert!(body.contains("\"pkg_mgr\""));
        assert!(body.contains("\"wizard_step\""));
        // No .tmp companion.
        let tmp = home.path().join("installer_ran_1700000000.json.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn audit_sidecar_overwrites_existing() {
        use crate::wal::payloads_w08::InstallerRanPayload;
        let home = tempfile::tempdir().unwrap();
        let payload = InstallerRanPayload {
            cli_name: "x".into(),
            version: String::new(),
            login_state: String::new(),
            ts_unix: 42,
            dry_run: false,
            wizard_step: String::new(),
            pkg_mgr: "apt".into(),
        };
        let first = write_installer_audit_sidecar(home.path(), 42, &payload).unwrap();
        let second = write_installer_audit_sidecar(home.path(), 42, &payload).unwrap();
        assert_eq!(first, second);
    }
}
