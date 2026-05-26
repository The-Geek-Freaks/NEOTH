//! `neoth proactive` — operator surface for the OB-03 proposal
//! staging chain. Subcommands:
//!
//!   - `neoth proactive list [--status <s>]`
//!     Print pending / approved / rejected / discarded proposals.
//!   - `neoth proactive accept <id> [--note <text>]`
//!     Flip a proposal to Approved.
//!   - `neoth proactive reject <id> [--note <text>]`
//!     Flip to Rejected.
//!   - `neoth proactive show <id>`
//!     Print one proposal's full content + audit fields.
//!   - `neoth proactive sync-vault [--status <s>] [--vault <p>]
//!                                  [--subdir <s>]`
//!     Render proposals matching the filter into
//!     `<vault>/<subdir>/Proposals/<id>.md`.
//!
//! Same shape as `cli/paperless.rs` — a thin shim over the
//! `proactive::action_staging` primitives shipped this session.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::proactive::action_staging::{
    list_proposals, load_proposal, set_proposal_status, sync_proposals_to_obsidian,
    ProposalStatus, ProposedAction,
};

#[derive(Args, Debug, Clone)]
pub struct ProactiveArgs {
    #[command(subcommand)]
    pub action: ProactiveAction,
    /// Override the NEOTH home dir (mostly for tests). Defaults to
    /// `~/.neoth`.
    #[arg(long, value_name = "DIR", global = true)]
    pub home: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProactiveAction {
    /// Print staged proposals.
    List {
        /// Filter: `pending` / `approved` / `rejected` / `all`.
        #[arg(long, default_value = "pending")]
        status: String,
    },
    /// Mark a proposal Approved. Operator copy-pastes the draft
    /// YAML from the vault note into the live config + runs
    /// `neoth config reload`; NEOTH never edits operator config.
    Accept {
        id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Mark a proposal Rejected. Stays on disk for the audit log.
    Reject {
        id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Print one proposal's full content + audit fields.
    Show {
        id: String,
    },
    /// Render proposals into `<vault>/<subdir>/Proposals/<id>.md`.
    SyncVault {
        #[arg(long, default_value = "pending")]
        status: String,
        #[arg(long, value_name = "PATH")]
        vault: Option<PathBuf>,
        #[arg(long, value_name = "NAME", default_value = "NEOTH")]
        subdir: String,
    },
}

pub fn run_proactive(args: ProactiveArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(default_neoth_home);

    match args.action {
        ProactiveAction::List { status } => {
            let filter = parse_status_filter(&status)?;
            let items = list_proposals(&home, filter);
            if items.is_empty() {
                println!("(no proposals matching status={status})");
                return Ok(());
            }
            for p in &items {
                println!(
                    "{id}  [{status}]  {kind:>12}  {title}",
                    id = p.id,
                    status = p.status.as_str(),
                    kind = p.kind.as_str(),
                    title = p.title,
                );
            }
            Ok(())
        }
        ProactiveAction::Accept { id, note } => {
            let updated = set_proposal_status(&home, &id, ProposalStatus::Approved, &note)
                .with_context(|| format!("approve proposal {id}"))?;
            print_status_change(&updated);
            Ok(())
        }
        ProactiveAction::Reject { id, note } => {
            let updated = set_proposal_status(&home, &id, ProposalStatus::Rejected, &note)
                .with_context(|| format!("reject proposal {id}"))?;
            print_status_change(&updated);
            Ok(())
        }
        ProactiveAction::Show { id } => {
            let p = load_proposal(&home, &id)
                .with_context(|| format!("proposal {id} not found"))?;
            print_full_proposal(&p);
            Ok(())
        }
        ProactiveAction::SyncVault {
            status,
            vault,
            subdir,
        } => {
            let filter = parse_status_filter(&status)?;
            let vault_root = vault.unwrap_or_else(default_vault_path);
            let outcome = sync_proposals_to_obsidian(&home, &vault_root, &subdir, filter)
                .with_context(|| {
                    format!(
                        "sync proposals to {}/{subdir}/Proposals/",
                        vault_root.display()
                    )
                })?;
            println!(
                "synced {} proposal(s) to {}/{subdir}/Proposals/",
                outcome.written,
                vault_root.display(),
            );
            Ok(())
        }
    }
}

fn print_status_change(p: &ProposedAction) {
    println!("{id}  → {status}", id = p.id, status = p.status.as_str());
    if !p.operator_note.is_empty() {
        println!("  note: {}", p.operator_note);
    }
}

fn print_full_proposal(p: &ProposedAction) {
    println!("id:       {}", p.id);
    println!("kind:     {}", p.kind.as_str());
    println!("status:   {}", p.status.as_str());
    println!("created:  ts_unix={}", p.generated_ts_unix);
    println!("title:    {}", p.title);
    println!("rationale:");
    for line in p.rationale.lines() {
        println!("  {line}");
    }
    println!("draft_yaml:");
    for line in p.draft_yaml.lines() {
        println!("  {line}");
    }
    if !p.operator_note.is_empty() {
        println!("operator_note:");
        for line in p.operator_note.lines() {
            println!("  {line}");
        }
    }
}

fn parse_status_filter(s: &str) -> Result<Option<ProposalStatus>> {
    match s {
        "pending" => Ok(Some(ProposalStatus::Pending)),
        "approved" => Ok(Some(ProposalStatus::Approved)),
        "rejected" => Ok(Some(ProposalStatus::Rejected)),
        "all" => Ok(None),
        other => anyhow::bail!(
            "unknown status filter {other:?} — expected pending / approved / rejected / all",
        ),
    }
}

fn default_neoth_home() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".neoth")
}

fn default_vault_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Documents").join("NEOTH-Vault")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proactive::action_staging::{
        make_proposal_id, save_proposal, ProposalKind,
    };

    fn sample(id: &str, title: &str) -> ProposedAction {
        ProposedAction {
            id: id.to_string(),
            kind: ProposalKind::CronJob,
            title: title.to_string(),
            rationale: "test rationale".into(),
            draft_yaml: "schedule:\n  cron: '0 9 * * *'\n".into(),
            generated_ts_unix: 100,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        }
    }

    #[test]
    fn parse_status_filter_known_values() {
        assert_eq!(
            parse_status_filter("pending").unwrap(),
            Some(ProposalStatus::Pending),
        );
        assert_eq!(
            parse_status_filter("approved").unwrap(),
            Some(ProposalStatus::Approved),
        );
        assert_eq!(
            parse_status_filter("rejected").unwrap(),
            Some(ProposalStatus::Rejected),
        );
        assert_eq!(parse_status_filter("all").unwrap(), None);
    }

    #[test]
    fn parse_status_filter_rejects_unknown() {
        let err = parse_status_filter("nope").unwrap_err();
        assert!(err.to_string().contains("unknown status filter"));
    }

    #[test]
    fn run_accept_flips_status_and_persists() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::CronJob, "x", "y", 100);
        save_proposal(home.path(), &sample(&id, "Test proposal")).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Accept {
                id: id.clone(),
                note: "looks good".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("accept");
        let loaded = load_proposal(home.path(), &id).unwrap();
        assert_eq!(loaded.status, ProposalStatus::Approved);
        assert_eq!(loaded.operator_note, "looks good");
    }

    #[test]
    fn run_reject_flips_status_and_persists() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::CronJob, "x", "y", 100);
        save_proposal(home.path(), &sample(&id, "Test proposal")).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Reject {
                id: id.clone(),
                note: "not now".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("reject");
        let loaded = load_proposal(home.path(), &id).unwrap();
        assert_eq!(loaded.status, ProposalStatus::Rejected);
        assert_eq!(loaded.operator_note, "not now");
    }

    #[test]
    fn run_accept_missing_id_errors_with_context() {
        let home = tempfile::tempdir().unwrap();
        let args = ProactiveArgs {
            action: ProactiveAction::Accept {
                id: "no-such-proposal".into(),
                note: "".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        let err = run_proactive(args).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("approve proposal"));
    }

    #[test]
    fn run_list_pending_shows_only_pending() {
        let home = tempfile::tempdir().unwrap();
        let pending = sample(&make_proposal_id(ProposalKind::CronJob, "a", "y", 100), "pending one");
        let mut approved = sample(&make_proposal_id(ProposalKind::CronJob, "b", "y", 200), "approved one");
        approved.status = ProposalStatus::Approved;
        save_proposal(home.path(), &pending).unwrap();
        save_proposal(home.path(), &approved).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::List {
                status: "pending".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        // The runner prints to stdout — we just assert it doesn't error.
        run_proactive(args).expect("list pending");
    }

    #[test]
    fn run_show_loads_full_proposal() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::CronJob, "x", "y", 100);
        save_proposal(home.path(), &sample(&id, "Test")).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Show { id: id.clone() },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("show");
    }

    #[test]
    fn run_show_missing_id_errors() {
        let home = tempfile::tempdir().unwrap();
        let args = ProactiveArgs {
            action: ProactiveAction::Show {
                id: "nope".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        let err = run_proactive(args).unwrap_err();
        assert!(format!("{err:?}").contains("nope"));
    }

    #[test]
    fn run_sync_vault_writes_proposal_md() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::CronJob, "x", "y", 100);
        save_proposal(home.path(), &sample(&id, "Test sync")).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::SyncVault {
                status: "pending".into(),
                vault: Some(vault.path().to_path_buf()),
                subdir: "NEOTH".into(),
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("sync");
        let expected = vault
            .path()
            .join("NEOTH")
            .join("Proposals")
            .join(format!("{id}.md"));
        assert!(expected.exists(), "expected vault file: {expected:?}");
    }
}
