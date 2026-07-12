//! `neoth cloud` — operate the local-folder cloud archive mirror (R-8).
//!
//! **Design pin:** NEOTH does not talk to Dropbox/GDrive/OneDrive APIs
//! directly. Instead, the operator runs the cloud vendor's official
//! desktop sync client (Dropbox.exe, "Google Drive for Desktop",
//! OneDrive.exe, iCloud Drive, ...) which exposes the remote as a
//! regular folder. NEOTH mirrors `~/.neoth/archive/sessions/` into a
//! subdir of that folder; the cloud client handles auth, transport,
//! quotas, and retry.
//!
//! Pros: works with every cloud the operator already trusts, no extra
//! credentials in `~/.neoth/`, headless operators on a NAS mount get
//! the same code path.
//!
//! Cons: doesn't work on a literal headless server with no desktop
//! client. The Phase-2 follow-up wires OpenDAL for direct API
//! transports there.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cli::obsidian::sync_archive;
use crate::config::FreedomConfig;
use crate::memory::archive::default_archive_root;

#[derive(Args, Debug, Clone)]
pub struct CloudArgs {
    #[command(subcommand)]
    pub action: CloudAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CloudAction {
    /// Print the configured destination + last-sync state.
    Status,
    /// Run one sync pass right now. Idempotent; re-runs skip unchanged
    /// files.
    Sync {
        /// Override `freedom.yaml::cloud_archive_dest` for this run.
        #[arg(long, value_name = "PATH")]
        dest: Option<PathBuf>,
        /// Override `freedom.yaml::cloud_archive_subdir`. Defaults to
        /// `"NEOTH"`.
        #[arg(long, value_name = "NAME")]
        subdir: Option<String>,
        /// Dry-run: list files that *would* be copied; don't write.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_cloud(args: CloudArgs) -> Result<()> {
    match args.action {
        CloudAction::Status => run_status(&args.output),
        CloudAction::Sync {
            dest,
            subdir,
            dry_run,
        } => run_sync(dest, subdir, dry_run, &args.output).await,
    }
}

fn run_status(output: &OutputFormat) -> Result<()> {
    // Don't silently swallow YAML parse errors — operator running
    // `neoth cloud status` against a corrupt freedom.yaml should see
    // the actual failure, not a misleading "not configured" line.
    // Missing-file is fine (legitimately "not configured yet").
    let cfg = match FreedomConfig::load_from_default_path() {
        Ok(c) => Some(c),
        Err(e) => {
            let s = format!("{e:#}");
            if s.contains("not found") {
                None
            } else {
                eprintln!("warning: could not load freedom.yaml: {s}");
                None
            }
        }
    };
    let dest = cfg.as_ref().and_then(|c| c.cloud_archive_dest.clone());
    let subdir = cfg
        .as_ref()
        .and_then(|c| c.cloud_archive_subdir.clone())
        .unwrap_or_else(|| "NEOTH".to_string());
    let interval_secs = cfg
        .as_ref()
        .and_then(|c| c.cloud_archive_auto_sync_secs)
        .unwrap_or(3600);

    let archive_root = default_archive_root();
    let archive_present = archive_root.exists();
    let dest_present = dest
        .as_ref()
        .map(|d| std::path::Path::new(d).exists())
        .unwrap_or(false);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "configured": dest.is_some(),
                "dest": dest,
                "subdir": subdir,
                "auto_sync_interval_secs": interval_secs,
                "archive_root": archive_root.display().to_string(),
                "archive_root_exists": archive_present,
                "dest_exists": dest_present,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Cloud archive mirror status");
            println!(
                "  destination       : {}",
                dest.as_deref().unwrap_or("(not configured)")
            );
            println!("  subdirectory      : {subdir}");
            println!("  auto-sync (secs)  : {interval_secs}");
            println!("  archive root      : {}", archive_root.display());
            println!("  archive present   : {archive_present}");
            println!("  destination found : {dest_present}");
            if dest.is_none() {
                println!();
                println!(
                    "  Set freedom.yaml::cloud_archive_dest to your cloud client's local \
                     sync folder (e.g. ~/Dropbox or ~/OneDrive)."
                );
            }
        }
    }
    Ok(())
}

async fn run_sync(
    dest_override: Option<PathBuf>,
    subdir_override: Option<String>,
    dry_run: bool,
    output: &OutputFormat,
) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().ok();
    let dest = dest_override
        .or_else(|| {
            cfg.as_ref()
                .and_then(|c| c.cloud_archive_dest.clone())
                .map(PathBuf::from)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no cloud destination configured. Set freedom.yaml::cloud_archive_dest, \
                 or pass --dest <PATH>."
            )
        })?;
    let subdir = subdir_override
        .or_else(|| cfg.as_ref().and_then(|c| c.cloud_archive_subdir.clone()))
        .unwrap_or_else(|| "NEOTH".to_string());
    let archive_root = default_archive_root();

    // GOLD-ADAPT-IGNIS-04: cloud mirror has no daemon WAL writer in scope;
    // conflict detection still gates the write, it just emits no audit frame.
    let stats = sync_archive(&archive_root, &dest, std::path::Path::new(&subdir), dry_run, None)
        .await
        .context("cloud sync pass")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "dest": dest.display().to_string(),
                "subdir": subdir,
                "considered": stats.considered,
                "copied": stats.copied,
                "dry_run": dry_run,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!(
                "cloud sync {} {} → {}/{subdir}: considered={} copied={}",
                if dry_run { "(dry-run)" } else { "" },
                archive_root.display(),
                dest.display(),
                stats.considered,
                stats.copied,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn sync_writes_session_files_to_subdir() {
        let archive_dir = tempdir().unwrap();
        let cloud_dir = tempdir().unwrap();

        // Seed one session under <archive>/sessions/<day>/<file>.md
        let day = archive_dir.path().join("sessions").join("2026-05-15");
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("a.md"), "# alpha\n").unwrap();

        let stats = sync_archive(
            archive_dir.path(),
            cloud_dir.path(),
            std::path::Path::new("NEOTH-test"),
            false,
            None,
        )
        .await
        .expect("sync");
        assert!(stats.copied >= 1, "expected at least one file copied");

        let mirrored = cloud_dir
            .path()
            .join("NEOTH-test")
            .join("2026-05-15")
            .join("a.md");
        assert!(
            mirrored.exists(),
            "mirrored file should land at {}",
            mirrored.display()
        );
    }

    #[tokio::test]
    async fn sync_dry_run_does_not_write_anything() {
        let archive_dir = tempdir().unwrap();
        let cloud_dir = tempdir().unwrap();
        let day = archive_dir.path().join("sessions").join("2026-05-15");
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("b.md"), "# beta\n").unwrap();

        let stats = sync_archive(
            archive_dir.path(),
            cloud_dir.path(),
            std::path::Path::new("NEOTH-test"),
            true,
            None,
        )
        .await
        .expect("dry-run");
        // considered may be >0, copied must be 0 in dry-run mode
        assert_eq!(stats.copied, 0);
        let mirrored = cloud_dir
            .path()
            .join("NEOTH-test")
            .join("2026-05-15")
            .join("b.md");
        assert!(!mirrored.exists(), "dry-run must not write the file");
    }

    // Sync `#[test]` + block_on (not `#[tokio::test]`) so the
    // crate::test_env::lock() guard isn't held across an `.await`
    // (clippy::await_holding_lock under -D warnings).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    #[test]
    fn run_sync_errors_when_no_dest_configured() {
        // No --dest, freedom.yaml empty → should bail. Run with a
        // bogus HOME so the load returns None.
        let _env = crate::test_env::lock();
        let tmp = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("USERPROFILE", tmp.path());
        }
        let r = block_on(run_sync(None, None, true, &OutputFormat::Json));
        if let Some(v) = prev_home {
            unsafe { std::env::set_var("HOME", v) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        if let Some(v) = prev_user {
            unsafe { std::env::set_var("USERPROFILE", v) };
        } else {
            unsafe { std::env::remove_var("USERPROFILE") };
        }
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("no cloud destination"));
    }
}
