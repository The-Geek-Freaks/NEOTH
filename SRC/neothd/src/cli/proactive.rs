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

use std::cmp::Reverse;
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
    /// forge) this installs it — a canonical `enabled: false` manifest is
    /// written to `~/.neoth/skills/<id>/skill.yaml`. Approval permits package
    /// installation only; routing requires a separate activation decision. For
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
    /// GOLD-ADAPT-OH-08 — list reflection observations from the Intelligence
    /// view (`~/.neoth/reflections/staged_observations.jsonl`). Read-only;
    /// observations are NEVER auto-posted into chat.
    Intelligence {
        /// How many entries to show, newest first. 0 = all.
        #[arg(long, default_value = "10")]
        limit: usize,
        /// Output as JSON (for GUI / scripting).
        #[arg(long)]
        json: bool,
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
        /// Channel name (`telegram`/`slack`/`discord`/`whatsapp`/...).
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
            let items = list_proposals(&home, filter)?;
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
            // KF-04: accepting a Skill proposal installs it INACTIVE so the
            // forge -> propose -> accept loop produces a reviewable package,
            // never implicit routing authority. The acceptance is already
            // recorded above; a write failure therefore returns a non-zero
            // command result with explicit partial-state context. Re-running
            // `accept` retries the idempotent transactional write.
            if updated.kind == ProposalKind::Skill {
                match crate::proactive::action_staging::adopt_approved_skill(&home, &updated) {
                    Ok(report) => {
                        println!(
                            "  skill installed inactive → {} (pending explicit activation)",
                            report.path.display(),
                        );
                        for warning in crate::skills::operator_skill_warnings(&report.warnings) {
                            eprintln!("  warning: {warning}");
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "proposal {id} is approved, but Skill adoption failed; fix the cause and re-run `neoth proactive accept {id}`"
                            )
                        });
                    }
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
        ProactiveAction::Intelligence { limit, json } => {
            use crate::reflection::{ReflectionObservation, load_staged_observations};
            let mut obs: Vec<ReflectionObservation> = load_staged_observations(&home);
            // Newest first.
            obs.sort_by_key(|o| Reverse(o.generated_ts_unix));
            if limit > 0 {
                obs.truncate(limit);
            }
            if obs.is_empty() {
                println!("(no reflection observations yet — runs weekly after the first 7 days)");
                return Ok(());
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&obs)
                        .expect("reflection observations contain only serializable fields")
                );
            } else {
                for o in &obs {
                    let dt =
                        chrono::DateTime::<chrono::Utc>::from_timestamp(o.generated_ts_unix, 0)
                            .map(|d| d.format("%Y-%m-%d").to_string())
                            .unwrap_or_else(|| o.generated_ts_unix.to_string());
                    println!(
                        "[{week}]  {dt}  topics: {topics}\n  → {body}\n",
                        week = o.iso_week_tag,
                        topics = o.topics.join(", "),
                        body = o.body,
                    );
                }
            }
            Ok(())
        }
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
        if ch == "keet" {
            anyhow::bail!(
                "Keet's destination is a capability-secret; configure it with `neoth channel add keet --server <topic>` and route only by channel name"
            );
        }
        if ch == "matrix" && !crate::channels::routing::is_valid_matrix_room_id(id) {
            anyhow::bail!("Matrix destination must be a room id like `!opaque:server`");
        }
        if routing.destinations.set_for_channel(ch, id.clone()) {
            println!("destination[{ch}] = {id}");
            #[cfg(not(feature = "matrix-channel"))]
            if ch == "matrix" {
                eprintln!(
                    "warning: Matrix route saved, but this binary lacks `matrix-channel`; delivery remains sidecar-only"
                );
            }
            changed = true;
        } else {
            anyhow::bail!("unknown channel '{ch}'; use a canonical name from `neoth channel list`");
        }
    } else if let (Some(src), Some(ch)) = (source.as_ref(), channel.as_ref()) {
        // F54 — validate the channel name like the --dest branch does, so a
        // typo (`--channel telegrm`) is rejected at config time instead of
        // being stored and silently routed to SidecarOnly at send time.
        if !crate::channels::routing::is_known_channel(ch) {
            anyhow::bail!("unknown channel '{ch}'; use a canonical name from `neoth channel list`");
        }
        routing.by_source.insert(src.clone(), ch.clone());
        println!("route: source '{src}' -> {ch}");
        changed = true;
    } else if default {
        let ch = channel.as_ref().context("--default requires --channel")?;
        if !crate::channels::routing::is_known_channel(ch) {
            anyhow::bail!("unknown channel '{ch}'; use a canonical name from `neoth channel list`");
        }
        routing.default_channel = Some(ch.clone());
        println!("default proactive channel -> {ch}");
        changed = true;
    } else if failure {
        let ch = channel.as_ref().context("--failure requires --channel")?;
        if !crate::channels::routing::is_known_channel(ch) {
            anyhow::bail!("unknown channel '{ch}'; use a canonical name from `neoth channel list`");
        }
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
            serde_json::to_string_pretty(&routing)
                .expect("channel routing contains only serializable fields")
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

    // ── KF-04: accepting a Skill proposal installs it inactive ────────────

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
    fn accept_skill_proposal_installs_loader_compatible_inactive_skill() {
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
        // ...AND the manifest landed at <home>/skills/<id>/skill.yaml,
        // re-parseable but inactive until a separate activation decision.
        let skill_path = home
            .path()
            .join("skills")
            .join("dream_kf04_test")
            .join("skill.yaml");
        assert!(
            skill_path.exists(),
            "expected installed skill at {skill_path:?}"
        );
        let body = std::fs::read_to_string(&skill_path).unwrap();
        let m: crate::skills::schema::SkillManifest =
            serde_yaml::from_str(&body).expect("written skill must be loader-parseable");
        assert_eq!(m.id, "dream_kf04_test");
        assert!(!m.enabled, "proposal acceptance must not grant routing");
    }

    #[test]
    fn accept_skill_proposal_returns_error_when_adoption_is_partial() {
        let home = tempfile::tempdir().unwrap();
        let id = make_proposal_id(ProposalKind::Skill, "broken-skill", "y", 101);
        let mut proposal = skill_proposal(&id);
        proposal.draft_yaml = "- not\n- a\n- manifest\n".to_string();
        save_proposal(home.path(), &proposal).unwrap();

        let error = run_proactive(ProactiveArgs {
            action: ProactiveAction::Accept {
                id: id.clone(),
                note: String::new(),
            },
            home: Some(home.path().to_path_buf()),
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("approved, but Skill adoption failed"));
        assert_eq!(
            load_proposal(home.path(), &id).unwrap().status,
            ProposalStatus::Approved,
            "the recoverable partial status must stay explicit for an idempotent retry"
        );
        assert!(!home.path().join("skills").exists());
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

    // ── GOLD-ADAPT-OH-08: Intelligence subcommand ─────────────────────────

    #[test]
    fn oh08_intelligence_empty_returns_ok() {
        let home = tempfile::tempdir().unwrap();
        let args = ProactiveArgs {
            action: ProactiveAction::Intelligence {
                limit: 10,
                json: false,
            },
            home: Some(home.path().to_path_buf()),
        };
        // No staged_observations.jsonl → "(no reflection observations yet…)" printed.
        run_proactive(args).expect("intelligence empty");
    }

    #[test]
    fn oh08_intelligence_displays_staged_observations() {
        use crate::reflection::{append_staged_observation, build_reflection_observation};
        let home = tempfile::tempdir().unwrap();
        let obs = build_reflection_observation(
            "2026-W25",
            &["rust".to_string(), "memory".to_string()],
            1_700_000_000,
        )
        .unwrap();
        append_staged_observation(home.path(), &obs).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Intelligence {
                limit: 10,
                json: false,
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("intelligence with one entry");
    }

    #[test]
    fn oh08_intelligence_json_mode_returns_ok() {
        use crate::reflection::{append_staged_observation, build_reflection_observation};
        let home = tempfile::tempdir().unwrap();
        let obs =
            build_reflection_observation("2026-W25", &["terraform".to_string()], 1_700_000_000)
                .unwrap();
        append_staged_observation(home.path(), &obs).unwrap();

        let args = ProactiveArgs {
            action: ProactiveAction::Intelligence {
                limit: 10,
                json: true,
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("intelligence json mode");
    }

    #[test]
    fn oh08_intelligence_limit_truncates_results() {
        use crate::reflection::{append_staged_observation, build_reflection_observation};
        let home = tempfile::tempdir().unwrap();
        // Write 5 observations across 5 different weeks.
        for week in 21..=25u32 {
            let obs = build_reflection_observation(
                &format!("2026-W{week:02}"),
                &["rust".to_string()],
                week as i64 * 1000,
            )
            .unwrap();
            append_staged_observation(home.path(), &obs).unwrap();
        }
        // limit=2 → only 2 should be shown (run_proactive returns Ok; no panic).
        let args = ProactiveArgs {
            action: ProactiveAction::Intelligence {
                limit: 2,
                json: false,
            },
            home: Some(home.path().to_path_buf()),
        };
        run_proactive(args).expect("intelligence with limit");
    }

    #[test]
    fn write_accepted_skill_rejects_malformed_draft_and_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let mut p = skill_proposal("p-id");
        // A YAML sequence can't deserialize into the SkillManifest struct.
        p.draft_yaml = "- not\n- a\n- manifest\n".into();
        p.status = ProposalStatus::Approved;
        let err =
            crate::proactive::action_staging::adopt_approved_skill(home.path(), &p).unwrap_err();
        assert!(format!("{err:#}").contains("SkillManifest"));
        assert!(
            !home.path().join("skills").exists(),
            "a malformed draft must not leave a partial skill dir",
        );
    }

    #[test]
    fn matrix_route_destination_is_validated_and_persisted() {
        let home = tempfile::tempdir().unwrap();
        run_route(
            home.path(),
            None,
            Some("matrix".to_string()),
            Some("!ops:example.org".to_string()),
            false,
            false,
        )
        .unwrap();
        let routing = ChannelRouting::load_from(&home.path().join(CHANNEL_ROUTING_FILE)).unwrap();
        assert_eq!(
            routing.destinations.matrix_room_id.as_deref(),
            Some("!ops:example.org")
        );

        let invalid_home = tempfile::tempdir().unwrap();
        let err = run_route(
            invalid_home.path(),
            None,
            Some("matrix".to_string()),
            Some("not-a-room".to_string()),
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("!opaque:server"));
        assert!(
            !invalid_home.path().join(CHANNEL_ROUTING_FILE).exists(),
            "invalid Matrix destination must not create routing state"
        );
    }

    #[test]
    fn keet_capability_is_rejected_from_public_routing_state() {
        let home = tempfile::tempdir().unwrap();
        let capability = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = run_route(
            home.path(),
            None,
            Some("keet".to_string()),
            Some(capability.to_string()),
            false,
            false,
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("capability-secret"));
        assert!(!message.contains(capability));
        assert!(!home.path().join(CHANNEL_ROUTING_FILE).exists());
    }

    #[test]
    fn default_and_failure_routes_reject_unknown_channel_names() {
        for (default, failure) in [(true, false), (false, true)] {
            let home = tempfile::tempdir().unwrap();
            let err = run_route(
                home.path(),
                None,
                Some("matrx".to_string()),
                None,
                default,
                failure,
            )
            .unwrap_err();
            assert!(err.to_string().contains("unknown channel"));
            assert!(!home.path().join(CHANNEL_ROUTING_FILE).exists());
        }
    }
}
