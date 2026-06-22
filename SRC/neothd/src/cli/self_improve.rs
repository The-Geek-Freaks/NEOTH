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
        /// Operator/engine rationale: why this edit is an improvement.
        #[arg(long, value_name = "TEXT")]
        why: Option<String>,
        /// Operator/engine note: known risks or caveats of adopting it.
        #[arg(long, value_name = "TEXT")]
        risk: Option<String>,
        /// Only show the diff; don't stage a proposal.
        #[arg(long)]
        dry_run: bool,
    },
    /// List staged proposals + their diffs (review before adopting).
    Review,
    /// Adopt a proposal into its skill file (backs up the replaced content).
    Accept { id: String },
    /// Restore a previously accepted proposal's backup (undo the change).
    Rollback { id: String },
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
    /// IMPR-03: run a pending proposal through the verification-gated execute
    /// scaffold (verification_command + advisor diff-review loop, max 2 revises).
    /// Does NOT write the skill file — accept is still gated by the operator.
    Execute { id: String },
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
            why,
            risk,
            dry_run,
        } => run_pass(
            &home, autonomy, &persona, skill, from, why, risk, dry_run, output,
        ),
        SelfImproveAction::Review => review(&home, output),
        SelfImproveAction::Accept { id } => {
            si::accept_proposal(&home, &id)?;
            println!(
                "✓ proposal {id} adopted into its skill file (backup kept — `rollback {id}` to undo)."
            );
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
        // IMPR-03: execute scaffold — no provider API at this call site, so the
        // advisor_fn is a stub that reads operator input via stdin for now.
        // neoth: replace the stdin advisor with a cheaper-executor subagent dispatch
        // once the provider API is available at the CLI layer.
        SelfImproveAction::Execute { id } => execute(&home, &id, autonomy, output),
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
            if cfg.auto {
                "ENABLED (nightly auto)"
            } else {
                "ENABLED (manual)"
            }
        } else {
            "off — `neoth self-improve enable`"
        },
        if implied {
            " — implied by full-auto mode"
        } else {
            ""
        }
    );
    println!(
        "  SkillOpt  : {}",
        if installed {
            "installed"
        } else {
            "NOT installed — `pip install skillopt`"
        }
    );
    match last {
        Some(r) => println!(
            "  last      : {} — \"{}\" ({})",
            r.skill,
            r.summary,
            if r.accepted {
                "improved ✓"
            } else {
                "no change kept"
            }
        ),
        None => println!("  last      : — (no runs yet)"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_pass(
    home: &std::path::Path,
    autonomy: crate::permissions::AutonomyLevel,
    persona: &str,
    skill: Option<std::path::PathBuf>,
    from: Option<std::path::PathBuf>,
    why: Option<String>,
    risk: Option<String>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let cfg = si::SelfImproveConfig::load(home).effective(autonomy);
    if !cfg.enabled && !dry_run {
        println!(
            "self-improvement is disabled — enable it first: `neoth self-improve enable` (or set full-auto mode)"
        );
        return Ok(());
    }
    // GR-fix: a dry-run on a DISABLED config must NOT spawn the external SkillOpt
    // engine (a dry-run is supposed to be side-effect-free). The prior `&& !dry_run`
    // gate let a disabled `--dry-run` fall through to the engine-spawn path below.
    if !cfg.enabled && dry_run {
        println!(
            "dry-run: self-improvement is disabled — would run SkillOpt for `{persona}` once enabled (engine NOT spawned)."
        );
        return Ok(());
    }
    // Resolve the production skill file (explicit, else <skills>/<persona>/skill.md).
    let skill_path = skill.unwrap_or_else(|| {
        crate::skills::installer::default_skills_dir()
            .join(persona)
            .join("skill.md")
    });
    let before = std::fs::read_to_string(&skill_path).unwrap_or_default();

    // Proposed content + quality. `--from` is operator-supplied (no engine
    // eval); the engine path may emit a structured envelope (content + scores +
    // rationale), else its stdout is treated as plain content.
    let (after, mut quality, parsed_spec) = if let Some(from) = from {
        let content =
            std::fs::read_to_string(&from).with_context(|| format!("read {}", from.display()))?;
        (content, si::ProposalQuality::default(), None)
    } else if si::is_installed() {
        println!("running SkillOpt for `{persona}` (this can take a while)…");
        match si::skillopt_command(persona).output() {
            Ok(o) => si::parse_proposal_output(&String::from_utf8_lossy(&o.stdout)),
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
    // Operator-supplied rationale overrides whatever the engine reported.
    if let Some(w) = why {
        quality.why_this_improves = w;
    }
    if let Some(r) = risk {
        quality.risk_notes = r;
    }

    let diff = si::line_diff(&before, &after);
    if dry_run {
        println!(
            "── DRY RUN (nothing staged, skill file untouched) ──\nskill: {}\n{}{diff}",
            skill_path.display(),
            quality_lines(
                quality.score_before,
                quality.score_after,
                &quality.heldout_eval_summary,
                &quality.why_this_improves,
                &quality.risk_notes,
            )
        );
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
            score_before: quality.score_before,
            score_after: quality.score_after,
            heldout_eval_summary: quality.heldout_eval_summary,
            why_this_improves: quality.why_this_improves,
            risk_notes: quality.risk_notes,
            // IMPR-01: carry the parsed spec (drift_sha populated inside stage_proposal).
            spec: parsed_spec,
        },
    )?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({ "staged": id, "skill": skill_path.display().to_string() })
        );
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
    println!(
        "Self-improvement proposals ({} total, {pending} pending):",
        props.len()
    );
    for p in props.iter().rev().take(10) {
        println!(
            "\n  [{}] {} — {:?} — {}",
            p.id, p.skill, p.status, p.summary
        );
        if p.status == si::ProposalStatus::Pending {
            // The "why", not just the diff — the quality score block.
            let q = quality_lines(
                p.score_before,
                p.score_after,
                &p.heldout_eval_summary,
                &p.why_this_improves,
                &p.risk_notes,
            );
            print!("{q}");
            // IMPR-01: render ProposalSpec fields when present.
            if let Some(spec) = &p.spec {
                if let Some(vcmd) = &spec.verification_command {
                    println!("    verify: {vcmd}");
                }
                if let Some(done) = &spec.done_criteria {
                    println!("    done  : {done}");
                }
                if !spec.stop_conditions.is_empty() {
                    println!("    stops : {}", spec.stop_conditions.join(", "));
                }
                if let Some(sha) = &spec.drift_sha {
                    println!("    staged: @{sha}");
                }
            }
            let diff = si::line_diff(&p.before, &p.after);
            for l in diff.lines().take(24) {
                println!("    {l}");
            }
            println!("    → `neoth self-improve accept {}`", p.id);
        }
    }
    Ok(())
}

/// Render the quality-score block (indented, trailing newline) for a proposal —
/// scores, held-out eval, why-it-improves, risks. Empty string when nothing was
/// reported (operator-supplied `--from` proposal with no rationale), so the
/// review/dry-run output stays clean.
fn quality_lines(
    score_before: f64,
    score_after: f64,
    heldout: &str,
    why: &str,
    risk: &str,
) -> String {
    let has_score = score_before != 0.0 || score_after != 0.0;
    if !has_score && heldout.is_empty() && why.is_empty() && risk.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    if has_score {
        let delta = score_after - score_before;
        s.push_str(&format!(
            "    score : {score_before:.3} → {score_after:.3} ({delta:+.3})\n"
        ));
    }
    if !heldout.is_empty() {
        s.push_str(&format!("    eval  : {heldout}\n"));
    }
    if !why.is_empty() {
        s.push_str(&format!("    why   : {why}\n"));
    }
    if !risk.is_empty() {
        s.push_str(&format!("    risk  : {risk}\n"));
    }
    s
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

/// IMPR-03: verification-gated execute scaffold for a pending proposal.
///
/// Runs the ProposalSpec's `verification_command` (if any), checks
/// `stop_conditions`, then enters a 2-round advisor diff-review loop. The
/// advisor prompt is printed to stdout and the operator's response is read from
/// stdin — this is the placeholder until a cheaper-executor subagent is wired in.
///
/// The skill file is NEVER written here; `accept` remains the only write path.
fn execute(
    home: &std::path::Path,
    id: &str,
    autonomy: crate::permissions::AutonomyLevel,
    output: OutputFormat,
) -> Result<()> {
    use si::ExecutionVerdict;

    // neoth: replace this stdin advisor with a cheaper-executor subagent dispatch
    // once the provider API is accessible at the CLI layer. The closure below is
    // the hook point: receive `(diff, verification_output)`, return a report
    // string containing APPROVE / REVISE: <reason> / BLOCK: <reason>.
    let advisor_fn = |diff: &str, vout: &str| -> String {
        println!("\n── Advisor review (IMPR-03) ──");
        println!("Diff:\n{diff}");
        if !vout.is_empty() {
            println!("Verification output:\n{vout}");
        }
        println!("Enter verdict (APPROVE / REVISE: <reason> / BLOCK: <reason>):");
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return "BLOCK: could not read advisor input".to_string();
        }
        line.trim().to_string()
    };

    let (verdict, revises) =
        si::execute_proposal_with_verification(home, id, 2, autonomy, advisor_fn)?;

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        let (verdict_str, reason) = match &verdict {
            ExecutionVerdict::Approved => ("approved", String::new()),
            ExecutionVerdict::Revise { reason } => ("revise", reason.clone()),
            ExecutionVerdict::Blocked { reason } => ("blocked", reason.clone()),
        };
        println!(
            "{}",
            serde_json::json!({ "id": id, "verdict": verdict_str, "revises": revises, "reason": reason })
        );
    } else {
        match verdict {
            ExecutionVerdict::Approved => {
                println!(
                    "✓ proposal {id} passed verification + advisor review ({revises} revise rounds).\n  → `neoth self-improve accept {id}` to adopt."
                );
            }
            ExecutionVerdict::Revise { reason } => {
                println!("⚠  proposal {id} REVISE after {revises} rounds: {reason}");
            }
            ExecutionVerdict::Blocked { reason } => {
                println!("✗  proposal {id} BLOCKED: {reason}");
            }
        }
    }
    Ok(())
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
        anyhow::bail!(
            "submit.sh exited with {status} — bundle preserved at {}",
            prepared.dir.display()
        );
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
