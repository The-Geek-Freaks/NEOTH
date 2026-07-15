//! Private machine-only commands used by authenticated release installers.
//!
//! These commands are intentionally absent from help output.  Their inputs
//! remain fully validated because hidden is not an authorization boundary.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::updater::release_bundle::{
    apply_portable_release_bundle, require_running_bundle_helper,
};

#[derive(Args, Debug)]
pub struct InternalArgs {
    #[command(subcommand)]
    pub action: InternalAction,
}

#[derive(Subcommand, Debug)]
pub enum InternalAction {
    /// Apply an authenticated, exact portable release bundle.
    #[command(name = "bundle-transaction")]
    BundleTransaction(BundleTransactionArgs),
}

#[derive(Args, Debug)]
pub struct BundleTransactionArgs {
    #[command(subcommand)]
    pub action: BundleTransactionAction,
}

#[derive(Subcommand, Debug)]
pub enum BundleTransactionAction {
    /// Validate, recover any interrupted predecessor, and durably commit.
    Apply {
        /// Verified extracted root containing the exact release file set.
        #[arg(long, value_name = "PATH")]
        bundle_root: PathBuf,
        /// Portable installation directory. User config lives elsewhere.
        #[arg(long, value_name = "PATH")]
        install_root: PathBuf,
        /// Canonical target SemVer without the release tag's `v` prefix.
        #[arg(long, value_name = "SEMVER")]
        expected_version: String,
    },
    /// Complete a portable update after the invoking Windows process exits.
    #[cfg(windows)]
    Handoff {
        /// Extracted target release root containing the running helper.
        #[arg(long, value_name = "PATH")]
        bundle_root: PathBuf,
        /// Strict request at the fixed sibling handoff slot.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,
        /// Parent-computed SHA-256 binding for the exact request bytes.
        #[arg(long, value_name = "HEX")]
        request_sha256: String,
        /// PID of the old installed CLI process that must exit first.
        #[arg(long)]
        wait_pid: u32,
    },
    /// Delete a completed Windows handoff after its helper exits.
    #[cfg(windows)]
    #[command(name = "cleanup-handoff")]
    CleanupHandoff {
        #[arg(long)]
        operation_id: String,
        /// Exact SHA-256 of the committed handoff request.
        #[arg(long, value_name = "HEX")]
        request_sha256: String,
        #[arg(long)]
        wait_pid: u32,
    },
}

pub async fn run_internal(args: InternalArgs, output: OutputFormat) -> Result<()> {
    if output != OutputFormat::Json {
        anyhow::bail!("internal release commands require --output json");
    }
    match args.action {
        InternalAction::BundleTransaction(args) => match args.action {
            BundleTransactionAction::Apply {
                bundle_root,
                install_root,
                expected_version,
            } => {
                if expected_version != env!("CARGO_PKG_VERSION") {
                    anyhow::bail!(
                        "release helper version {} does not match expected version {expected_version}",
                        env!("CARGO_PKG_VERSION")
                    );
                }
                require_running_bundle_helper(&bundle_root)?;
                let committed =
                    apply_portable_release_bundle(&bundle_root, &install_root, &expected_version)
                        .with_context(|| {
                        format!(
                            "install exact {} release bundle from {}",
                            committed_profile_hint(),
                            bundle_root.display()
                        )
                    })?;
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "committed",
                        "profile": committed.profile.as_str(),
                        "version": expected_version,
                        "transaction_id": committed.receipt.transaction_id,
                        "members": committed.receipt.members,
                    })
                );
            }
            #[cfg(windows)]
            BundleTransactionAction::Handoff {
                bundle_root,
                request,
                request_sha256,
                wait_pid,
            } => {
                let completed = crate::updater::self_update::run_windows_bundle_handoff(
                    &bundle_root,
                    &request,
                    &request_sha256,
                    wait_pid,
                )?;
                super::update::emit_self_update_applied(
                    &completed.applied,
                    &completed.source_repo,
                    completed.channel,
                    &completed.target_triple,
                    "windows_detached_handoff",
                )
                .await;
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "committed",
                        "operation_id": &completed.operation_id,
                        "version": &completed.applied.to_version,
                        "transaction_id": &completed.applied.transaction_id,
                    })
                );
                if let Err(error) =
                    crate::updater::self_update::spawn_windows_handoff_cleanup(&completed)
                {
                    tracing::warn!(%error, "Windows update committed but staging cleanup could not be scheduled");
                }
            }
            #[cfg(windows)]
            BundleTransactionAction::CleanupHandoff {
                operation_id,
                request_sha256,
                wait_pid,
            } => {
                crate::updater::self_update::cleanup_windows_handoff(
                    &operation_id,
                    &request_sha256,
                    wait_pid,
                )?;
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "cleaned",
                        "operation_id": operation_id,
                    })
                );
            }
        },
    }
    Ok(())
}

fn committed_profile_hint() -> &'static str {
    crate::updater::release_bundle::PortableBundleProfile::current().as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn exact_hidden_command_parses_without_a_free_form_member_list() {
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "--output",
            "json",
            "internal",
            "bundle-transaction",
            "apply",
            "--bundle-root",
            "release",
            "--install-root",
            "installed",
            "--expected-version",
            env!("CARGO_PKG_VERSION"),
        ])
        .unwrap();
        let crate::cli::Commands::Internal(InternalArgs {
            action:
                InternalAction::BundleTransaction(BundleTransactionArgs {
                    action:
                        BundleTransactionAction::Apply {
                            bundle_root,
                            install_root,
                            expected_version,
                        },
                }),
        }) = cli.command
        else {
            panic!("hidden bundle transaction command did not parse");
        };
        assert_eq!(bundle_root, PathBuf::from("release"));
        assert_eq!(install_root, PathBuf::from("installed"));
        assert_eq!(expected_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn internal_command_is_hidden_from_top_level_help() {
        let mut command = crate::cli::Cli::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(!help.contains("bundle-transaction"));
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with("internal"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn detached_windows_handoff_command_has_no_free_form_members() {
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "--output",
            "json",
            "internal",
            "bundle-transaction",
            "handoff",
            "--bundle-root",
            "release",
            "--request",
            "handoff.json",
            "--request-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--wait-pid",
            "123",
        ])
        .unwrap();
        let crate::cli::Commands::Internal(InternalArgs {
            action:
                InternalAction::BundleTransaction(BundleTransactionArgs {
                    action:
                        BundleTransactionAction::Handoff {
                            bundle_root,
                            request,
                            request_sha256,
                            wait_pid,
                        },
                }),
        }) = cli.command
        else {
            panic!("hidden Windows handoff command did not parse");
        };
        assert_eq!(bundle_root, PathBuf::from("release"));
        assert_eq!(request, PathBuf::from("handoff.json"));
        assert_eq!(request_sha256, "a".repeat(64));
        assert_eq!(wait_pid, 123);
    }

    #[cfg(windows)]
    #[test]
    fn detached_windows_cleanup_has_no_caller_supplied_paths() {
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "--output",
            "json",
            "internal",
            "bundle-transaction",
            "cleanup-handoff",
            "--operation-id",
            "0123456789abcdef0123456789abcdef",
            "--request-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--wait-pid",
            "123",
        ])
        .unwrap();
        let crate::cli::Commands::Internal(InternalArgs {
            action:
                InternalAction::BundleTransaction(BundleTransactionArgs {
                    action:
                        BundleTransactionAction::CleanupHandoff {
                            operation_id,
                            request_sha256,
                            wait_pid,
                        },
                }),
        }) = cli.command
        else {
            panic!("hidden Windows cleanup command did not parse");
        };
        assert_eq!(operation_id, "0123456789abcdef0123456789abcdef");
        assert_eq!(request_sha256, "a".repeat(64));
        assert_eq!(wait_pid, 123);
    }
}
