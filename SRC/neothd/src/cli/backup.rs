//! `neoth backup` / `neoth restore` — Phase 33c BS-2.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::{backup, vault_mirror};

#[derive(Args, Debug, Clone)]
pub struct BackupArgs {
    /// Private, policy-gated Git WAL mirror operations.
    #[command(subcommand)]
    pub action: Option<BackupAction>,
    /// Output path for the `.tar.gz`. Defaults to
    /// `~/.neoth/backups/neoth-<UTC-timestamp>.tar.gz`.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Skip raw WAL segments. Default behaviour bundles them — the
    /// WAL is the source of truth + the operator-flow audit (2026-05-19)
    /// flagged "default-without-WAL produces inconsistent restores
    /// where views.db cursors reference segments that don't exist".
    /// Pass `--no-wal` to opt out (saves disk, but restored host needs
    /// to re-index from scratch).
    #[arg(long = "no-wal")]
    pub skip_wal: bool,
    /// Include `credentials.yaml` (API keys, channel tokens) in the plaintext
    /// tarball. Excluded by default; use this only when the destination is
    /// operator-controlled encrypted storage. A complete credential restore
    /// requires this explicit opt-in.
    #[arg(long, conflicts_with = "skip_credentials")]
    pub include_credentials: bool,
    /// Deprecated compatibility no-op: credentials are already excluded by
    /// default. Kept so existing safe backup scripts do not break.
    #[arg(long = "no-credentials", hide = true)]
    pub skip_credentials: bool,
    /// Override the ~/.neoth source dir (mostly for tests).
    #[arg(long, value_name = "DIR", global = true)]
    pub home: Option<PathBuf>,
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// Additive mirror surface.  The ordinary `neoth backup` archive behaviour is
/// retained when no subcommand is present.
#[derive(Subcommand, Debug, Clone)]
pub enum BackupAction {
    /// Inspect the durable mirror receipt.  This never starts Git.
    Mirror {
        #[command(subcommand)]
        action: MirrorAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum MirrorAction {
    /// Read the current durable status without starting a Git process.
    Status,
    /// Create a durable WAL-inclusive, credential-free Prepared archive receipt.
    /// It starts no Git process without --push. Pass --push only when manual
    /// publishing is explicitly permitted.
    Run {
        #[arg(long)]
        push: bool,
    },
    /// Reconcile an indeterminate durable push receipt against its exact ref.
    Repair,
}

#[derive(Args, Debug, Clone)]
pub struct RestoreArgs {
    /// Path to the `.tar.gz` to restore.
    pub archive: PathBuf,
    /// Target directory. Defaults to `~/.neoth/`.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Overwrite the target if it's non-empty.
    #[arg(long)]
    pub force: bool,
    /// Output format.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_backup(args: BackupArgs) -> Result<()> {
    if let Some(action) = args.action {
        return run_mirror(action, args.home, args.output).await;
    }
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let out = args.out.unwrap_or_else(backup::default_backup_path);
    let include_wal = !args.skip_wal;
    let include_credentials = args.include_credentials && !args.skip_credentials;
    let outcome = backup::write_backup(&home, &out, include_wal, include_credentials)
        .with_context(|| format!("write backup to {}", out.display()))?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "operation": "backup.create",
                    "wrote": out.display().to_string(),
                    "entries": outcome.included,
                    "include_wal": include_wal,
                    "includes_plaintext_credentials": outcome.included_plaintext_credentials,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "backup written: {} ({} top-level entries)",
                out.display(),
                outcome.included
            );
            if !include_wal {
                println!("(WAL segments skipped per --no-wal; restored host will need re-index)");
            } else {
                println!("(WAL segments bundled — full consistent restore)");
            }
            if !include_credentials {
                println!(
                    "(credentials excluded by default; use --include-credentials only for encrypted storage)"
                );
            }
        }
    }
    // Loud plaintext-secrets warning regardless of output format — the
    // operator must know the archive carries unencrypted API keys/tokens.
    if outcome.included_plaintext_credentials {
        eprintln!(
            "⚠  WARNING: this backup contains credentials.yaml in PLAINTEXT (API keys, channel tokens).\n\
             ⚠  Store it on encrypted media. Re-run without --include-credentials to exclude them."
        );
    }
    Ok(())
}

async fn run_mirror(action: BackupAction, requested_home: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let home = requested_home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let cfg_path = mirror_config_path(&home);
    let cfg = FreedomConfig::load_from_path(&cfg_path)
        .with_context(|| format!("load {} for vault mirror (run `neoth init` first if this is a fresh install)", cfg_path.display()))?;
    let status = match action {
        BackupAction::Mirror {
            action: MirrorAction::Status,
        } => vault_mirror::status(&home, &cfg.vault_mirror),
        BackupAction::Mirror {
            action: MirrorAction::Run { push },
        } => vault_mirror::run_manual(&home, &cfg.vault_mirror, push).await,
        BackupAction::Mirror {
            action: MirrorAction::Repair,
        } => vault_mirror::repair(&home, &cfg.vault_mirror).await,
    };
    render_mirror_status(&status, output)
}

fn mirror_config_path(home: &Path) -> PathBuf {
    home.join("freedom.yaml")
}

/// One credential-safe projection shared verbatim by backup and Buddy.
/// `VaultMirrorStatus` has no raw Git stderr or credentials by construction.
pub(crate) fn mirror_status_wire(status: &vault_mirror::VaultMirrorStatus) -> serde_json::Value {
    serde_json::to_value(status).expect("VaultMirrorStatus is serializable")
}

pub(crate) fn render_mirror_status(
    status: &vault_mirror::VaultMirrorStatus,
    output: OutputFormat,
) -> Result<()> {
    let wire = mirror_status_wire(status);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{wire}"),
        OutputFormat::Table => {
            println!("vault mirror config: {}", wire["config"]);
            println!("phase: {}", wire["receipt"]["phase"]);
            println!("repair: {}", wire["repair"]);
            if let Some(run_id) = wire["receipt"]["run_id"].as_str().filter(|id| !id.is_empty()) {
                println!("run_id: {run_id}");
            }
            if let Some(hash) = wire["receipt"]["archive_sha256"].as_str().filter(|hash| !hash.is_empty()) {
                println!("archive_sha256: {hash}");
            }
        }
    }
    Ok(())
}

pub async fn run_restore(args: RestoreArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let n = backup::restore_backup(&args.archive, &home, args.force)
        .with_context(|| format!("restore from {}", args.archive.display()))?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "restored": home.display().to_string(),
                    "entries": n,
                })
            );
        }
        OutputFormat::Table => {
            println!("restored {n} entry/entries into {}", home.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct BackupCli {
        #[command(flatten)]
        args: BackupArgs,
    }

    #[test]
    fn backup_credentials_are_excluded_by_default() {
        let parsed = BackupCli::try_parse_from(["backup"]).expect("parse default backup args");
        assert!(!parsed.args.include_credentials);
        assert!(!parsed.args.skip_credentials);
    }

    #[test]
    fn backup_credentials_require_explicit_opt_in() {
        let parsed = BackupCli::try_parse_from(["backup", "--include-credentials"])
            .expect("parse explicit credential opt-in");
        assert!(parsed.args.include_credentials);
        assert!(!parsed.args.skip_credentials);
    }

    #[test]
    fn contradictory_credential_flags_are_rejected() {
        let parsed =
            BackupCli::try_parse_from(["backup", "--include-credentials", "--no-credentials"]);
        assert!(parsed.is_err());
    }

    #[test]
    fn mirror_subcommands_do_not_change_ordinary_backup_defaults() {
        let ordinary = BackupCli::try_parse_from(["backup"]).expect("ordinary backup parses");
        assert!(ordinary.args.action.is_none());
        let mirror = BackupCli::try_parse_from(["backup", "mirror", "run", "--push"])
            .expect("mirror push parses");
        assert!(matches!(
            mirror.args.action,
            Some(BackupAction::Mirror { action: MirrorAction::Run { push: true } })
        ));
        let selected_home = BackupCli::try_parse_from([
            "backup",
            "mirror",
            "status",
            "--home",
            "C:/selected-neoth-home",
        ])
        .expect("mirror accepts the existing home override after its subcommand");
        assert_eq!(
            selected_home.args.home,
            Some(PathBuf::from("C:/selected-neoth-home"))
        );
    }

    #[test]
    fn mirror_status_wire_keeps_the_shared_sanitized_status_envelope() {
        let status = vault_mirror::VaultMirrorStatus {
            config: vault_mirror::MirrorConfigStatus::Blocked,
            receipt: None,
            repair: vault_mirror::MirrorRepairAdvice::FixConfig,
        };
        let wire = mirror_status_wire(&status);
        assert_eq!(wire["config"], "blocked");
        assert!(wire["receipt"].is_null());
        assert_eq!(wire["repair"], "fix_config");
        assert!(wire.get("stderr").is_none());
        assert!(wire.get("credential").is_none());
    }

    #[test]
    fn mirror_config_is_bound_to_the_selected_backup_home() {
        let selected = PathBuf::from("C:/test-neoth-home");
        assert_eq!(
            mirror_config_path(&selected),
            PathBuf::from("C:/test-neoth-home/freedom.yaml")
        );
    }
}
