//! `neoth self-improve` — drive NEOTH's SkillOpt-based self-evolution: enable the
//! switch (ask-first), run a consolidation pass, and show what improved. See
//! `crate::self_improve`.

use anyhow::Result;
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
    /// Run one SkillOpt consolidation pass now (records what improved).
    Run {
        #[arg(long, default_value = "default")]
        persona: String,
    },
    /// Print the improvement ledger (what changed, when, accepted or not).
    Log,
}

pub fn run_self_improve(args: SelfImproveArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        SelfImproveAction::Status => status(&home, output),
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
        SelfImproveAction::Run { persona } => run_pass(&home, &persona, output),
        SelfImproveAction::Log => log(&home, output),
    }
}

fn status(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let cfg = si::SelfImproveConfig::load(home);
    let installed = si::is_installed();
    let last = si::last_record(home);
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "enabled": cfg.enabled, "auto": cfg.auto, "asked": cfg.asked,
                "skillopt_installed": installed, "last": last,
            })
        );
        return Ok(());
    }
    println!("NEOTH self-improvement (SkillOpt)");
    println!(
        "  switch    : {}",
        if cfg.enabled {
            if cfg.auto { "ENABLED (nightly auto)" } else { "ENABLED (manual)" }
        } else {
            "off — `neoth self-improve enable`"
        }
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

fn run_pass(home: &std::path::Path, persona: &str, output: OutputFormat) -> Result<()> {
    let cfg = si::SelfImproveConfig::load(home);
    if !cfg.enabled {
        println!("self-improvement is disabled — enable it first: `neoth self-improve enable`");
        return Ok(());
    }
    if !si::is_installed() {
        println!("SkillOpt is not installed — `{}`", si::SKILLOPT_INSTALL);
        return Ok(());
    }
    println!("running SkillOpt consolidation for persona `{persona}` (this can take a while)…");
    let out = si::skillopt_command(persona).output();
    let (accepted, summary) = match &out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let tail = s
                .lines()
                .map(str::trim)
                .rev()
                .find(|l| !l.is_empty())
                .unwrap_or("completed")
                .to_string();
            (o.status.success(), tail)
        }
        Err(e) => (false, format!("run failed: {e}")),
    };
    let rec = si::ImproveRecord {
        skill: persona.to_string(),
        accepted,
        score_before: 0.0,
        score_after: 0.0,
        summary: summary.clone(),
        at_unix: crate::time::now_unix_i64(),
    };
    si::append_record(home, rec)?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({ "accepted": accepted, "summary": summary, "persona": persona })
        );
    } else if accepted {
        println!("✓ improvement kept: {summary}");
    } else {
        println!("no improvement passed the held-out gate this run: {summary}");
    }
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
