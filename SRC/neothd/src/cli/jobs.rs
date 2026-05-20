//! `neoth jobs` — operator-facing view of the cron job set.
//!
//! Modes:
//!   `--list`     parse `~/.neoth/jobs.yaml`, print table of jobs + next fire.
//!   `--validate` parse + cron-validate every job, exit non-zero on first error.
//!
//! `--run-once <id>` is a follow-up once serve-side scheduler is fully wired.
//! For now operators can drop a job into jobs.yaml and `neoth serve` picks it
//! up on next restart.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::cron::JobsFile;

#[derive(Args, Debug, Clone)]
pub struct JobsArgs {
    /// Print the table of configured jobs with next-fire times.
    #[arg(long, conflicts_with_all = ["validate"])]
    pub list: bool,

    /// Parse + validate jobs.yaml without printing the table. Exits non-zero
    /// on the first invalid job.
    #[arg(long, conflicts_with_all = ["list"])]
    pub validate: bool,

    /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_jobs(args: JobsArgs) -> Result<()> {
    let path = args
        .file
        .clone()
        .unwrap_or_else(|| FreedomConfig::default_neoth_home().join("jobs.yaml"));

    if !path.exists() {
        anyhow::bail!(
            "jobs file not found at {}. Create it manually (see docs) or wait \
             until the wizard's Phase-11d seed-jobs flow lands.",
            path.display()
        );
    }

    let jobs = JobsFile::load_from_path(&path)
        .await
        .with_context(|| format!("load jobs from {}", path.display()))?;
    info!(path = %path.display(), count = jobs.jobs.len(), "jobs loaded");

    if args.validate {
        println!("OK — {} job(s) validated", jobs.jobs.len());
        return Ok(());
    }

    // default + --list
    match args.output {
        OutputFormat::Table => print_table(&jobs),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&jobs)?),
        OutputFormat::Jsonl => {
            for j in &jobs.jobs {
                println!("{}", serde_json::to_string(j)?);
            }
        }
    }
    Ok(())
}

fn print_table(jobs: &JobsFile) {
    let now = Utc::now();
    println!(
        "{:<24} {:<32} {:<8} {:<24} cron",
        "id", "name", "enabled", "next_fire_utc"
    );
    println!("{}", "-".repeat(110));
    for j in &jobs.jobs {
        let next = j
            .schedule
            .next_after(now)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "(never)".to_string());
        let enabled = if j.enabled { "yes" } else { "no" };
        println!(
            "{:<24} {:<32} {:<8} {:<24} {}",
            truncate(&j.id, 24),
            truncate(&j.name, 32),
            enabled,
            next,
            j.schedule.cron,
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
