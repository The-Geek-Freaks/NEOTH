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

use crate::channels::routing::{CHANNEL_ROUTING_FILE, ChannelRouting};
use crate::proactive::action_staging::{
    ProposalKind, ProposalStatus, ProposedAction, list_proposals, load_proposal,
    set_proposal_status, sync_proposals_to_obsidian,
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
    /// Mark a proposal Approved. For a **Skill** proposal (KF-04 idle
    /// forge) this ADOPTS it — the draft manifest is written live to
    /// `~/.neoth/skills/<id>/skill.yaml` (the operator's accept is the
    /// per-command GO; the skill system still gates loading). For
    /// config/cron proposals NEOTH never edits operator config: the
    /// operator copy-pastes the draft YAML into the live config + runs
    /// `neoth reload`.
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
    Show { id: String },
    /// Render proposals into `<vault>/<subdir>/Proposals/<id>.md`.
    SyncVault {
        #[arg(long, default_value = "pending")]
        status: String,
        #[arg(long, value_name = "PATH")]
        vault: Option<PathBuf>,
        #[arg(long, value_name = "NAME", default_value = "NEOTH")]
        subdir: String,
    },
    /// GOLD-FEAT-13 — view or set per-purpose channel routing for proactive
    /// sends (`~/.neoth/channel_routing.json`). No flags → print the current
    /// routing. `--source X --channel Y` routes source X to channel Y;
    /// `--channel Y --dest Z` sets channel Y's destination id;
    /// `--default --channel Y` sets the default channel;
    /// `--failure --channel Y` sets the failure-alert channel.
    Route {
        /// Source tag to route (e.g. `coding_session`). With `--channel`.
        #[arg(long)]
        source: Option<String>,
        /// Channel name (`telegram`/`slack`/`discord`/`whatsapp`/`keet`).
        #[arg(long)]
        channel: Option<String>,
        /// Per-channel destination id (use with `--channel`).
        #[arg(long)]
        dest: Option<String>,
        /// Set `--channel` as the default proactive destination.
        #[arg(long)]
        default: bool,
        /// Set `--channel` as the failure-alert destination.
        #[arg(long)]
        failure: bool,
    },
}

pub fn run_proactive(args: ProactiveArgs) -> Result<()> {
    let home = args.home.clone().unwrap_or_else(default_neoth_home);

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
            // KF-04: accepting a Skill proposal ADOPTS it — write the draft
            // manifest live so the forge -> propose -> accept loop produces a
            // usable skill, not just a flag flip. The acceptance is already
            // recorded above; a write failure is surfaced as a warning rather
            // than failing the command (re-running `accept` retries the write,
            // which is idempotent).
            if updated.kind == ProposalKind::Skill {
                match write_accepted_skill(&home, &updated) {
                    Ok(path) => println!(
                        "  skill written → {} (live on next `neoth reload` or hot-watch)",
                        path.display(),
                    ),
                    Err(e) => eprintln!(
                        "  warning: proposal accepted but skill write failed: {e:#}\n  \
                         (fix the cause + re-run `neoth proactive accept {id}` to retry)",
                    ),
                }
            }
            Ok(())
        }
        ProactiveAction::Reject { id, note } => {
            let updated = set_proposal_status(&home, &id, ProposalStatus::Rejected, &note)
                .with_context(|| format!("reject proposal {id}"))?;
            print_status_change(&updated);
            Ok(())
        }
        ProactiveAction::Show { id } => {
            let p =
                load_proposal(&home, &id).with_context(|| format!("proposal {id} not found"))?;
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
        ProactiveAction::Route {
            source,
            channel,
            dest,
            default,
            failure,
        } => run_route(&home, source, channel, dest, default, failure),
    }
}

/// GOLD-FEAT-13 — `neoth proactive route`. Loads `channel_routing.json`,
/// applies ONE mutation per invocation (destination > per-source > default >
/// failure), or prints the current routing when no actionable flags are
/// given. Operator-facing surface over the [`ChannelRouting`] side-file.
fn run_route(
    home: &std::path::Path,
    source: Option<String>,
    channel: Option<String>,
    dest: Option<String>,
    default: bool,
    failure: bool,
) -> Result<()> {
    let path = home.join(CHANNEL_ROUTING_FILE);
    let mut routing = ChannelRouting::load_from(&path).context("load channel routing")?;
    let mut changed = false;

    if let (Some(ch), Some(id)) = (channel.as_ref(), dest.as_ref()) {
        if routing.destinations.set_for_channel(ch, id.clone()) {
            println!("destination[{ch}] = {id}");
            changed = true;
        } else {
            anyhow::bail!("unknown channel '{ch}' (use telegram/slack/discord/whatsapp/keet)");
        }
    } else if let (Some(src), Some(ch)) = (source.as_ref(), channel.as_ref()) {
        routing.by_source.insert(src.clone(), ch.clone());
        println!("route: source '{src}' -> {ch}");
        changed = true;
    } else if default {
        let ch = channel.as_ref().context("--default requires --channel")?;
        routing.default_channel = Some(ch.clone());
        println!("default proactive channel -> {ch}");
        changed = true;
    } else if failure {
        let ch = channel.as_ref().context("--failure requires --channel")?;
        routing.failure_channel = Some(ch.clone());
        println!("failure-alert channel -> {ch}");
        changed = true;
    }

    if changed {
        routing.save_to(&path).context("save channel routing")?;
        println!("(saved → {})", path.display());
    } else {
        println!(
            "current channel routing ({}):\n{}",
            path.display(),
            serde_json::to_string_pretty(&routing).unwrap_or_default()
        );
    }
    Ok(())
}

fn print_status_change(p: &ProposedAction) {
    println!("{id}  → {status}", id = p.id, status = p.status.as_str());
    if !p.operator_note.is_empty() {
        println!("  note: {}", p.operator_note);
    }
}

/// KF-04 — write an accepted Skill proposal's manifest live into the
/// operator's skills dir (`<home>/skills/<skill-id>/skill.yaml`), closing
/// the idle-forge -> propose -> accept loop. The proposal's `draft_yaml`
/// IS a loader-compatible [`SkillManifest`] (the forge builds it via
/// `skills::creator::build_manifest`); parse it to recover the skill id
/// (the on-disk directory name), validate the id (which is ALSO the
/// path-traversal guard — `validate_skill_id` rejects anything outside
/// `[a-zA-Z0-9_-]`, so a crafted `../` id can't escape the skills dir),
/// then write atomically via the shared `write_skill_yaml` path the
/// `neoth skills --create` command already uses. Returns the written path.
fn write_accepted_skill(home: &std::path::Path, proposal: &ProposedAction) -> Result<PathBuf> {
    use crate::skills::creator::{validate_skill_id, write_skill_yaml};
    use crate::skills::schema::SkillManifest;

    let manifest: SkillManifest =
        serde_yaml::from_str(&proposal.draft_yaml).with_context(|| {
            format!(
                "accepted skill proposal {} carries a draft_yaml that is not a valid SkillManifest",
                proposal.id,
            )
        })?;
    validate_skill_id(&manifest.id).with_context(|| {
        format!(
            "skill id {:?} is invalid (cannot be a dir name)",
            manifest.id
        )
    })?;
    let skills_dir = home.join("skills");
    write_skill_yaml(&skills_dir, &manifest.id, &proposal.draft_yaml)
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
    use crate::proactive::action_staging::{ProposalKind, make_proposal_id, save_proposal};

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
        let pending = sample(
            &make_proposal_id(ProposalKind::CronJob, "a", "y", 100),
            "pending one",
        );
        let mut approved = sample(
            &make_proposal_id(ProposalKind::CronJob, "b", "y", 200),
            "approved one",
        );
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
            action: ProactiveAction::Show { id: "nope".into() },
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

    // ── KF-04: accepting a Skill proposal adopts it (writes the manifest) ─

    /// Build a Skill `ProposedAction` whose `draft_yaml` is a real,
    /// loader-compatible manifest (same path the forge uses).
    fn skill_proposal(id: &str) -> ProposedAction {
        use crate::skills::creator::{CreateParams, build_manifest};
        let (_, yaml) = build_manifest(&CreateParams {
            id: "dream_kf04_test".into(),
            description: "forged from a test dream".into(),
            keywords: vec!["test".into()],
            system_prompt: "You help with the test theme.".into(),
        })
        .expect("build_manifest");
        ProposedAction {
            id: id.to_string(),
            kind: ProposalKind::Skill,
            title: "Skill: test".into(),
            rationale: "r".into(),
            draft_yaml: yaml,
            generated_ts_unix: 100,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        }
    }

    #[test]
    fn accept_skill_proposal_writes_live_loader_compatible_skill() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::Skill, "skill", "y", 100);
        save_proposal(home.path(), &skill_proposal(&id)).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Accept {
                id: id.clone(),
                note: String::new(),
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("accept skill");

        // Status flipped...
        assert_eq!(
            load_proposal(home.path(), &id).unwrap().status,
            ProposalStatus::Approved,
        );
        // ...AND the manifest landed live at <home>/skills/<id>/skill.yaml,
        // re-parseable by the loader (closes the forge->accept loop).
        let skill_path = home
            .path()
            .join("skills")
            .join("dream_kf04_test")
            .join("skill.yaml");
        assert!(skill_path.exists(), "expected live skill at {skill_path:?}");
        let body = std::fs::read_to_string(&skill_path).unwrap();
        let m: crate::skills::schema::SkillManifest =
            serde_yaml::from_str(&body).expect("written skill must be loader-parseable");
        assert_eq!(m.id, "dream_kf04_test");
    }

    #[test]
    fn accept_non_skill_proposal_writes_no_skill_dir() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::CronJob, "x", "y", 100);
        save_proposal(home.path(), &sample(&id, "cron one")).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Accept {
                id: id.clone(),
                note: String::new(),
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("accept cron");

        // Only Skill proposals adopt-on-accept; a CronJob accept never
        // writes a skill (config/cron stays operator-copies-manually).
        assert!(
            !home.path().join("skills").exists(),
            "non-skill accept must not create a skills dir",
        );
    }

    #[test]
    fn write_accepted_skill_rejects_malformed_draft_and_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let mut p = skill_proposal("p-id");
        // A YAML sequence can't deserialize into the SkillManifest struct.
        p.draft_yaml = "- not\n- a\n- manifest\n".into();
        let err = write_accepted_skill(home.path(), &p).unwrap_err();
        assert!(format!("{err:#}").contains("SkillManifest"));
        assert!(
            !home.path().join("skills").exists(),
            "a malformed draft must not leave a partial skill dir",
        );
    }
}
