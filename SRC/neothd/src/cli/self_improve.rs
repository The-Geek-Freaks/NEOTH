//! `neoth self-improve` — drive NEOTH's SkillOpt-based self-evolution: enable the
//! switch (ask-first), run a consolidation pass, and show what improved. See
//! `crate::self_improve`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::self_improve as si;

#[derive(Args, Debug, Clone)]
pub struct SelfImproveArgs {
    #[command(subcommand)]
    pub action: SelfImproveAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SelfImproveAction {
    /// Show the switch state, SkillOpt availability, and the last improvement.
    Status,
    /// Enable self-improvement. `--auto` also turns on the nightly sleep cycle.
    Enable {
        #[arg(long)]
        auto: bool,
    },
    /// Turn self-improvement off (keeps the ledger).
    Disable,
    /// Run one SkillOpt consolidation pass — STAGES a proposal for review
    /// (never writes a skill file directly). `--dry-run` only prints the diff.
    Run {
        #[arg(long, default_value = "default")]
        persona: String,
        /// The production skill file SkillOpt should improve.
        #[arg(long, value_name = "PATH")]
        skill: Option<std::path::PathBuf>,
        /// Use this file as the proposed content instead of running SkillOpt
        /// (lets the workflow be driven without the engine installed).
        #[arg(long, value_name = "PATH")]
        from: Option<std::path::PathBuf>,
        /// Only show the diff; don't stage a proposal.
        #[arg(long)]
        dry_run: bool,
    },
    /// List staged proposals + their diffs (review before adopting).
    Review,
    /// Adopt a proposal into its skill file (backs up the replaced content).
    Accept {
        id: String,
    },
    /// Restore a previously accepted proposal's backup (undo the change).
    Rollback {
        id: String,
    },
    /// Contribute an ACCEPTED improvement to a BUNDLED skill back to NEOTH:
    /// prepare a PR bundle (improved file + PR body + submit script). `--submit`
    /// runs it via the operator's authenticated `gh`.
    Pr {
        id: String,
        /// Actually open the PR now (requires `gh`), instead of only preparing it.
        #[arg(long)]
        submit: bool,
    },
    /// Print the improvement ledger (what changed, when, accepted or not).
    Log,
}

pub fn run_self_improve(args: SelfImproveArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    // Full autonomy implies self-improve auto-on (unless the operator chose
    // otherwise) — resolve the live level so `status` + `run` reflect it.
    let autonomy = FreedomConfig::load_from_default_path()
        .map(|c| c.autonomy)
        .unwrap_or_default();
    match args.action {
        SelfImproveAction::Status => status(&home, autonomy, output),
        SelfImproveAction::Enable { auto } => {
            let mut cfg = si::SelfImproveConfig::load(&home);
            cfg.enabled = true;
            cfg.auto = auto;
            cfg.asked = true;
            cfg.save(&home)?;
            println!(
                "self-improvement ENABLED{}. {}",
                if auto { " (nightly auto)" } else { " (manual)" },
                if si::is_installed() {
                    "SkillOpt ready."
                } else {
                    "SkillOpt not installed yet — `pip install skillopt`."
                }
            );
            Ok(())
        }
        SelfImproveAction::Disable => {
            let mut cfg = si::SelfImproveConfig::load(&home);
            cfg.enabled = false;
            cfg.auto = false;
            cfg.save(&home)?;
            println!("self-improvement disabled.");
            Ok(())
        }
        SelfImproveAction::Run {
            persona,
            skill,
            from,
            dry_run,
        } => run_pass(&home, autonomy, &persona, skill, from, dry_run, output),
        SelfImproveAction::Review => review(&home, output),
        SelfImproveAction::Accept { id } => {
            si::accept_proposal(&home, &id)?;
            println!("✓ proposal {id} adopted into its skill file (backup kept — `rollback {id}` to undo).");
            offer_upstream_pr_if_bundled(&home, &id);
            Ok(())
        }
        SelfImproveAction::Rollback { id } => {
            si::rollback_proposal(&home, &id)?;
            println!("✓ proposal {id} rolled back — skill file restored.");
            Ok(())
        }
        SelfImproveAction::Pr { id, submit } => pr(&home, &id, submit, output),
        SelfImproveAction::Log => log(&home, output),
    }
}

fn status(
    home: &std::path::Path,
    autonomy: crate::permissions::AutonomyLevel,
    output: OutputFormat,
) -> Result<()> {
    let stored = si::SelfImproveConfig::load(home);
    let (stored_enabled, stored_auto) = (stored.enabled, stored.auto);
    let cfg = stored.effective(autonomy);
    // Full-auto turned it on implicitly (operator never set it explicitly).
    let implied = cfg.enabled && !stored_enabled;
    let installed = si::is_installed();
    let last = si::last_record(home);
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "enabled": cfg.enabled, "auto": cfg.auto, "asked": cfg.asked,
                "stored_enabled": stored_enabled, "stored_auto": stored_auto,
                "implied_by_full_auto": implied, "autonomy": autonomy.as_str(),
                "skillopt_installed": installed, "last": last,
            })
        );
        return Ok(());
    }
    println!("NEOTH self-improvement (SkillOpt)");
    println!(
        "  switch    : {}{}",
        if cfg.enabled {
            if cfg.auto { "ENABLED (nightly auto)" } else { "ENABLED (manual)" }
        } else {
            "off — `neoth self-improve enable`"
        },
        if implied { " — implied by full-auto mode" } else { "" }
    );
    println!(
        "  SkillOpt  : {}",
        if installed { "installed" } else { "NOT installed — `pip install skillopt`" }
    );
    match last {
        Some(r) => println!(
            "  last      : {} — \"{}\" ({})",
            r.skill,
            r.summary,
            if r.accepted { "improved ✓" } else { "no change kept" }
        ),
        None => println!("  last      : — (no runs yet)"),
    }
    Ok(())
}

fn run_pass(
    home: &std::path::Path,
    autonomy: crate::permissions::AutonomyLevel,
    persona: &str,
    skill: Option<std::path::PathBuf>,
    from: Option<std::path::PathBuf>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let cfg = si::SelfImproveConfig::load(home).effective(autonomy);
    if !cfg.enabled && !dry_run {
        println!("self-improvement is disabled — enable it first: `neoth self-improve enable` (or set full-auto mode)");
        return Ok(());
    }
    // Resolve the production skill file (explicit, else <skills>/<persona>/skill.md).
    let skill_path = skill.unwrap_or_else(|| {
        crate::skills::installer::default_skills_dir()
            .join(persona)
            .join("skill.md")
    });
    let before = std::fs::read_to_string(&skill_path).unwrap_or_default();

    // Proposed content: an explicit file, else SkillOpt's output.
    let after = if let Some(from) = from {
        std::fs::read_to_string(&from).with_context(|| format!("read {}", from.display()))?
    } else if si::is_installed() {
        println!("running SkillOpt for `{persona}` (this can take a while)…");
        match si::skillopt_command(persona).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => {
                println!("SkillOpt run failed: {e}");
                return Ok(());
            }
        }
    } else {
        println!(
            "SkillOpt not installed — `{}` (or stage a proposal with --from <file>)",
            si::SKILLOPT_INSTALL
        );
        return Ok(());
    };

    let diff = si::line_diff(&before, &after);
    if dry_run {
        println!("── DRY RUN (nothing staged, skill file untouched) ──\nskill: {}\n\n{diff}", skill_path.display());
        return Ok(());
    }

    let now = crate::time::now_unix_i64();
    let id = format!("p{now}");
    si::stage_proposal(
        home,
        si::Proposal {
            id: id.clone(),
            skill: persona.to_string(),
            skill_path: skill_path.display().to_string(),
            before,
            after,
            summary: format!("SkillOpt proposal for {persona}"),
            status: si::ProposalStatus::Pending,
            at_unix: now,
            backup: None,
        },
    )?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!("{}", serde_json::json!({ "staged": id, "skill": skill_path.display().to_string() }));
    } else {
        println!(
            "staged proposal {id} (skill file UNCHANGED). Review: `neoth self-improve review` · adopt: `neoth self-improve accept {id}`"
        );
    }
    Ok(())
}

fn review(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let props = si::load_proposals(home);
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!("{}", serde_json::to_string_pretty(&props)?);
        return Ok(());
    }
    if props.is_empty() {
        println!("no proposals staged. Run `neoth self-improve run` to stage one.");
        return Ok(());
    }
    let pending = props
        .iter()
        .filter(|p| p.status == si::ProposalStatus::Pending)
        .count();
    println!("Self-improvement proposals ({} total, {pending} pending):", props.len());
    for p in props.iter().rev().take(10) {
        println!(
            "\n  [{}] {} — {:?} — {}",
            p.id, p.skill, p.status, p.summary
        );
        if p.status == si::ProposalStatus::Pending {
            let diff = si::line_diff(&p.before, &p.after);
            for l in diff.lines().take(24) {
                println!("    {l}");
            }
            println!("    → `neoth self-improve accept {}`", p.id);
        }
    }
    Ok(())
}

/// After adopting a proposal, if its skill is one NEOTH SHIPS (bundled), offer
/// to contribute the improvement upstream. NEOTH asks — the operator decides by
/// running `pr`. Best-effort: a lookup miss just prints nothing.
fn offer_upstream_pr_if_bundled(home: &std::path::Path, id: &str) {
    let Some(p) = si::load_proposals(home).into_iter().find(|p| p.id == id) else {
        return;
    };
    if crate::skills::bundled::is_bundled(&p.skill) {
        println!(
            "\n  ↑ `{}` is a BUNDLED skill — want to contribute this improvement back to NEOTH?\n    `neoth self-improve pr {id}`        (prepare the PR bundle for review)\n    `neoth self-improve pr {id} --submit` (open it now via your `gh`)",
            p.skill
        );
    }
}

fn pr(home: &std::path::Path, id: &str, submit: bool, output: OutputFormat) -> Result<()> {
    let prepared = si::prepare_upstream_pr(home, id)?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "id": id, "dir": prepared.dir.display().to_string(),
                "asset_path": prepared.asset_path, "branch": prepared.branch,
                "title": prepared.title, "submitted": false,
            })
        );
    } else {
        println!("PR bundle prepared for proposal {id}:");
        println!("  dir    : {}", prepared.dir.display());
        println!("  target : {} @ {}", si::NEOTH_REPO, prepared.asset_path);
        println!("  branch : {}", prepared.branch);
        println!("  title  : {}", prepared.title);
    }
    if !submit {
        if !matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            println!(
                "\nReview {}, then submit: `neoth self-improve pr {id} --submit` (or run submit.sh).",
                prepared.dir.join("PR.md").display()
            );
        }
        return Ok(());
    }
    // --submit: needs the operator's authenticated gh.
    if crate::tools::github::locate_gh().is_none() {
        anyhow::bail!(
            "`gh` not found — bundle is ready at {} (run submit.sh once gh is installed + authenticated)",
            prepared.dir.display()
        );
    }
    let script = prepared.dir.join("submit.sh");
    println!("\nopening PR via gh…");
    let status = std::process::Command::new("bash")
        .arg(&script)
        .status()
        .with_context(|| format!("run {}", script.display()))?;
    if !status.success() {
        anyhow::bail!("submit.sh exited with {status} — bundle preserved at {}", prepared.dir.display());
    }
    println!("✓ PR opened against {}.", si::NEOTH_REPO);
    Ok(())
}

fn log(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let ledger = si::load_ledger(home);
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!("{}", serde_json::to_string_pretty(&ledger)?);
        return Ok(());
    }
    if ledger.is_empty() {
        println!("no self-improvement runs recorded yet.");
        return Ok(());
    }
    println!("Self-improvement ledger ({} runs):", ledger.len());
    for r in ledger.iter().rev().take(20) {
        println!(
            "  [{}] {} — {} — \"{}\"",
            r.at_unix,
            r.skill,
            if r.accepted { "improved" } else { "no change" },
            r.summary
        );
    }
    Ok(())
}
