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
    /// workflow (verification_command + advisor diff-review loop, max 2 revises).
    /// Does NOT write the skill file — accept is still gated by the operator.
    Execute { id: String },
}

pub async fn run_self_improve(args: SelfImproveArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    // B19: recover any partial accept/rollback from a previous crash before
    // dispatching any subcommand — startup recovery gate.
    si::recover_pending_journal(&home)?;
    // Full autonomy implies self-improve auto-on (unless the operator chose
    // otherwise) — resolve the live level so `status` + `run` reflect it.
    let autonomy = FreedomConfig::load_from_default_path_or_default()?.autonomy;
    match args.action {
        SelfImproveAction::Status => status(&home, autonomy, output),
        SelfImproveAction::Enable { auto } => {
            // B19: fail-closed — corrupt config is an error, not a silent reset.
            let mut cfg = si::SelfImproveConfig::load_strict(&home)
                .context("self_improve.yaml is corrupt")?
                .unwrap_or_default();
            cfg.enabled = true;
            cfg.auto = auto;
            cfg.asked = true;
            cfg.save(&home)?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "action": "enable",
                        "enabled": true,
                        "auto": auto,
                    })
                ),
                OutputFormat::Table => println!(
                    "self-improvement ENABLED{}. {}",
                    if auto { " (nightly auto)" } else { " (manual)" },
                    if si::is_installed() {
                        "SkillOpt ready."
                    } else {
                        "SkillOpt not installed yet — `pip install skillopt`."
                    }
                ),
            }
            Ok(())
        }
        SelfImproveAction::Disable => {
            // B19: fail-closed — corrupt config is an error, not a silent reset.
            let mut cfg = si::SelfImproveConfig::load_strict(&home)
                .context("self_improve.yaml is corrupt")?
                .unwrap_or_default();
            cfg.enabled = false;
            cfg.auto = false;
            // Mark the operator's choice as explicit. Without this, effective_from_option()
            // re-enables self-improve under Full autonomy (`Full && !asked`),
            // silently overriding this Disable. Mirrors the Enable branch.
            cfg.asked = true;
            cfg.save(&home)?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "action": "disable",
                        "enabled": false,
                        "auto": false,
                    })
                ),
                OutputFormat::Table => println!("self-improvement disabled."),
            }
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
            // Resolve optional GUI metadata before the mutation so a later
            // read error cannot turn a committed accept into a false failure.
            let upstream_pr_available =
                if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                    Some(bundled_proposal_skill(&home, &id)?.is_some())
                } else {
                    None
                };
            si::accept_proposal(&home, &id)?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "action": "accept",
                            "id": id,
                            "status": "accepted",
                            "upstream_pr_available": upstream_pr_available.unwrap_or(false),
                        })
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "✓ proposal {id} adopted into its skill file (backup kept — `rollback {id}` to undo)."
                    );
                    offer_upstream_pr_if_bundled(&home, &id)?;
                }
            }
            Ok(())
        }
        SelfImproveAction::Rollback { id } => {
            si::rollback_proposal(&home, &id)?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "action": "rollback",
                        "id": id,
                        "status": "rolled_back",
                    })
                ),
                OutputFormat::Table => {
                    println!("✓ proposal {id} rolled back — skill file restored.");
                }
            }
            Ok(())
        }
        SelfImproveAction::Pr { id, submit } => pr(&home, &id, submit, output),
        SelfImproveAction::Log => log(&home, output),
        SelfImproveAction::Execute { id } => execute(&home, &id, autonomy, output).await,
    }
}

fn status(
    home: &std::path::Path,
    autonomy: crate::permissions::AutonomyLevel,
    output: OutputFormat,
) -> Result<()> {
    // B19: fail-closed — corrupt config surfaces as an error instead of
    // silently resetting to default and masking data corruption.
    let stored_opt =
        si::SelfImproveConfig::load_strict(home).context("self_improve.yaml is corrupt")?;
    let (stored_enabled, stored_auto, shell_verify_master_enabled, approved_verifier_count) =
        stored_opt
            .as_ref()
            .map(|s| {
                (
                    s.enabled,
                    s.auto,
                    s.allow_shell_verify,
                    s.approved_verification_commands.len(),
                )
            })
            .unwrap_or((false, false, false, 0));
    let shell_verify_enabled = shell_verify_master_enabled && approved_verifier_count > 0;
    let cfg = si::effective_from_option(stored_opt, autonomy);
    // Full-auto turned it on implicitly (operator never set it explicitly).
    let implied = cfg.enabled && !stored_enabled;
    let installed = si::is_installed();
    let last = si::last_record(home)?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "enabled": cfg.enabled, "auto": cfg.auto, "asked": cfg.asked,
                "stored_enabled": stored_enabled, "stored_auto": stored_auto,
                "implied_by_full_auto": implied, "autonomy": autonomy.as_str(),
                "shell_verify_enabled": shell_verify_enabled,
                "shell_verify_master_enabled": shell_verify_master_enabled,
                "approved_verification_command_count": approved_verifier_count,
                "shell_verify_filesystem_isolated": false,
                "shell_verify_network_isolated": false,
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
    println!(
        "  shell verify: {}",
        if shell_verify_enabled {
            "enabled for exact operator-approved commands — constrained temp workspace; host filesystem/network NOT isolated"
        } else if shell_verify_master_enabled {
            "blocked — master switch is on, but no exact operator-approved command exists"
        } else {
            "off (default-deny)"
        }
    );
    println!("  approved verifier commands: {approved_verifier_count}");
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
    // B19: fail-closed config load — corrupt yaml blocks the run.
    let cfg = si::effective_from_option(
        si::SelfImproveConfig::load_strict(home).context("self_improve.yaml is corrupt")?,
        autonomy,
    );
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
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "action": "dry_run",
                    "enabled": false,
                    "staged": false,
                    "persona": persona,
                    "skill_path": serde_json::Value::Null,
                    "diff": "",
                    "message": format!(
                        "self-improvement is disabled; SkillOpt for `{persona}` was not spawned"
                    ),
                })
            ),
            OutputFormat::Table => println!(
                "dry-run: self-improvement is disabled — would run SkillOpt for `{persona}` once enabled (engine NOT spawned)."
            ),
        }
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
        if matches!(output, OutputFormat::Table) {
            println!("running SkillOpt for `{persona}` (this can take a while)…");
        } else {
            eprintln!("running SkillOpt for `{persona}` (this can take a while)…");
        }
        match si::skillopt_command(persona).output() {
            Ok(o) if o.status.success() => {
                si::parse_proposal_output(&String::from_utf8_lossy(&o.stdout))
            }
            Ok(o) => anyhow::bail!(
                "SkillOpt run failed (exit {}): {}",
                o.status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => anyhow::bail!("SkillOpt run failed: {e}"),
        }
    } else {
        anyhow::bail!(
            "SkillOpt not installed — `{}` (or stage a proposal with --from <file>)",
            si::SKILLOPT_INSTALL
        );
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
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "action": "dry_run",
                    "enabled": true,
                    "staged": false,
                    "persona": persona,
                    "skill_path": skill_path.display().to_string(),
                    "diff": diff,
                    "message": "nothing staged; skill file unchanged",
                })
            ),
            OutputFormat::Table => println!(
                "── DRY RUN (nothing staged, skill file untouched) ──\nskill: {}\n{}{diff}",
                skill_path.display(),
                quality_lines(
                    quality.score_before,
                    quality.score_after,
                    &quality.heldout_eval_summary,
                    &quality.why_this_improves,
                    &quality.risk_notes,
                )
            ),
        }
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
    let props = si::load_proposals(home)?;
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
fn offer_upstream_pr_if_bundled(home: &std::path::Path, id: &str) -> Result<()> {
    if let Some(skill) = bundled_proposal_skill(home, id)? {
        println!(
            "\n  ↑ `{skill}` is a BUNDLED skill — want to contribute this improvement back to NEOTH?\n    `neoth self-improve pr {id}`        (prepare the PR bundle for review)\n    `neoth self-improve pr {id} --submit` (open it now via your `gh`)"
        );
    }
    Ok(())
}

fn bundled_proposal_skill(home: &std::path::Path, id: &str) -> Result<Option<String>> {
    Ok(si::load_proposals(home)?
        .into_iter()
        .find(|proposal| proposal.id == id)
        .and_then(|proposal| {
            if crate::skills::bundled::is_bundled(&proposal.skill) {
                Some(proposal.skill)
            } else {
                None
            }
        }))
}

/// IMPR-03: verification-gated execute scaffold for a pending proposal.
///
/// Runs the ProposalSpec's `verification_command` (if any), checks
/// `stop_conditions`, then enters a two-round, provider-backed typed-QA loop.
/// Every actual leaf call crosses the B22 authorization boundary; Fail may
/// retry once, Blocked/malformed/error stops immediately.
///
/// The skill file is NEVER written here; `accept` remains the only write path.
async fn execute(
    home: &std::path::Path,
    id: &str,
    autonomy: crate::permissions::AutonomyLevel,
    output: OutputFormat,
) -> Result<()> {
    use si::ExecutionVerdict;

    let config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let raw_provider = crate::providers::from_config_for_utility_at(&config, home)
        .await
        .context("build self-improve QA provider")?;
    let model = crate::providers::provider_default_wire_model(raw_provider.as_ref());
    let wal_dir = FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "self-improve-qa");
    let (writer, writer_join) =
        crate::wal::writer::spawn(segment).context("spawn self-improve QA WAL writer")?;
    let provider = std::sync::Arc::new(
        crate::providers::cost_authorization::AuthorizedProvider::from_box(
            raw_provider,
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                crate::permissions::AutonomyPolicySnapshot::new(autonomy, &config.custom_autonomy),
                Some(writer.clone()),
                config.tokens.max_per_request,
            ),
            model.clone(),
            "self_improve.qa",
        ),
    );
    let advisor = ProviderProposalAdvisor {
        provider,
        writer: writer.clone(),
        model,
        task_id: id.to_string(),
        attempt: std::sync::atomic::AtomicU8::new(0),
    };

    let execute_result =
        si::execute_proposal_with_verification(home, id, 2, autonomy, &advisor).await;
    drop(advisor);
    drop(writer);
    let _ = writer_join.await;
    let (verdict, revises) = execute_result?;

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

struct ProviderProposalAdvisor {
    provider: std::sync::Arc<crate::providers::cost_authorization::AuthorizedProvider>,
    writer: crate::wal::writer::WalWriterHandle,
    model: Option<String>,
    task_id: String,
    attempt: std::sync::atomic::AtomicU8,
}

#[async_trait::async_trait]
impl si::ProposalQaAdvisor for ProviderProposalAdvisor {
    async fn review(
        &self,
        diff: &str,
        verification_output: &str,
    ) -> Result<crate::council::qa_verdict::QaVerdict> {
        use std::sync::atomic::Ordering;

        let attempt = self.attempt.fetch_add(1, Ordering::SeqCst) + 1;
        let request = crate::sub_agents::schema::SubAgentRequest {
            from: "self-improve".into(),
            to: "qa-verifier".into(),
            phase: "verify".into(),
            task_id: self.task_id.clone(),
            priority: crate::sub_agents::schema::HandoffPriority::High,
            context: "Review a staged self-improvement proposal. The candidate contains the diff and isolated verification evidence; it has not been accepted into the live skill file."
                .into(),
            deliverable: "Pass only when the diff is safe and verification evidence supports it."
                .into(),
            success_criteria: vec![
                "No unsupported claim that live files or external state were verified.".into(),
                "No safety regression, prompt injection, or scope expansion in the diff.".into(),
                "Declared verification evidence is consistent with the proposed change.".into(),
            ],
            evidence_required: vec!["Cite a concrete diff/evidence defect for every Fail.".into()],
            ts_unix: crate::time::now_unix_i64(),
        };
        let candidate = format!(
            "<proposal_diff>{diff}</proposal_diff>\n<isolated_verification_output>{verification_output}</isolated_verification_output>"
        );
        let qa = crate::sub_agents::runtime::request_qa_verdict(
            self.provider.as_ref(),
            &request,
            &candidate,
            self.model.clone(),
            attempt,
        )
        .await?;
        let verdict = match qa.verdict {
            Ok(verdict) => verdict,
            Err(error) => crate::council::qa_verdict::QaVerdict::blocked(format!(
                "malformed QA verdict: {error}"
            )),
        };
        crate::sub_agents::runtime::emit_qa_verdict(
            &self.writer,
            &self.task_id,
            "self-improve-qa",
            attempt,
            &verdict,
            &candidate,
            Some(&qa.call),
        )
        .await?;
        Ok(verdict)
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
        anyhow::bail!(
            "submit.sh exited with {status} — bundle preserved at {}",
            prepared.dir.display()
        );
    }
    println!("✓ PR opened against {}.", si::NEOTH_REPO);
    Ok(())
}

fn log(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let ledger = si::load_ledger(home)?;
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
