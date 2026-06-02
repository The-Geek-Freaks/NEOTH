//! `neoth cron run <id>` — fire one scheduled job NOW, out of band of the
//! daemon scheduler.
//!
//! Loads `jobs.yaml`, finds the job by id, and runs it through the configured
//! provider via the shared [`crate::cron::runner::run_job`] — the SAME path the
//! daemon scheduler uses, so it writes the same `0x40 FIRED` → `0x41 SUCCESS` /
//! `0x42 FAILED` WAL frames and delivers through the job's channel if one is
//! set. This makes a REAL provider call (it costs tokens).
//!
//! Refuses while `neoth serve` is live: the daemon owns the single WAL writer,
//! so a second one-shot writer would race the append-only segment. Matching
//! the scheduler, a manual run is NOT autonomy-gated — jobs are operator-
//! authored and the scheduler fires enabled jobs unconditionally; the
//! `autonomy gate` line in `neoth jobs --preview` is diagnostic, not enforced.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::cron::schema::{Job, JobsFile};

#[derive(Args, Debug, Clone)]
pub struct CronArgs {
    #[command(subcommand)]
    pub action: CronAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CronAction {
    /// Fire one job by id immediately, out of band of the scheduler. Makes a
    /// real provider call and (if the job has a delivery channel) delivers the
    /// result. Refused while `neoth serve` is running.
    Run {
        /// The job `id` from jobs.yaml.
        id: String,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

/// Resolve the jobs.yaml path: explicit `--file` else `~/.neoth/jobs.yaml`.
fn jobs_path(file: Option<PathBuf>) -> PathBuf {
    file.unwrap_or_else(|| FreedomConfig::default_neoth_home().join("jobs.yaml"))
}

/// Find a job by id, cloning it out of the file. Pure + hermetically testable;
/// the error names the id so a typo is obvious.
fn find_job(jobs: &JobsFile, id: &str) -> Result<Job> {
    jobs.jobs
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .with_context(|| format!("no job with id `{id}` in jobs.yaml"))
}

pub async fn run_cron(args: CronArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        CronAction::Run { id, file } => run_one(&id, file, output).await,
    }
}

async fn run_one(id: &str, file: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    // Refuse while the daemon owns the WAL — a 2nd one-shot writer would race
    // the single append-only segment. The daemon fires scheduled jobs itself.
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    ) {
        anyhow::bail!(
            "`neoth serve` is running and owns the WAL writer — manual `cron run` can't share it. \
             Stop the daemon (it fires scheduled jobs on schedule itself), then retry."
        );
    }

    let path = jobs_path(file);
    let jobs = JobsFile::load_from_path(&path)
        .await
        .with_context(|| format!("load jobs from {}", path.display()))?;
    let job = find_job(&jobs, id)?;

    let config = FreedomConfig::load_from_default_path().context("load freedom.yaml")?;
    let provider = crate::providers::fallback_chain_from_config(&config, None)
        .await
        .context("construct the provider chain for the job")?;

    // One-shot WAL writer (daemon confirmed not live above, so we hold the
    // segment exclusively). Same segment the daemon scheduler uses.
    let segment = FreedomConfig::default_neoth_home()
        .join("wal")
        .join("000001.wal");
    if let Some(parent) = segment.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let (writer, join) = crate::wal::spawn(segment).context("open a one-shot WAL writer")?;

    let result = crate::cron::runner::run_job(&job, provider.as_ref(), &writer).await;
    drop(writer);
    let _ = join.await;
    let outcome = result.context("run job")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "job_id": job.id,
                "success": outcome.success,
                "duration_ms": outcome.duration.as_millis(),
                "output_bytes": outcome.output_bytes,
                "error": outcome.error,
            })
        ),
        OutputFormat::Table => {
            if outcome.success {
                println!(
                    "✓ job `{}` ran in {} ms ({} output bytes)",
                    job.id,
                    outcome.duration.as_millis(),
                    outcome.output_bytes
                );
            } else {
                println!(
                    "✗ job `{}` FAILED: {}",
                    job.id,
                    outcome.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
    }

    if !outcome.success {
        anyhow::bail!("job `{}` did not complete successfully", job.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_path_defaults_under_neoth_home() {
        let p = jobs_path(None);
        assert!(p.ends_with("jobs.yaml"), "default ends with jobs.yaml: {p:?}");
    }

    #[test]
    fn jobs_path_honours_override() {
        let p = jobs_path(Some(PathBuf::from("/tmp/custom-jobs.yaml")));
        assert_eq!(p, PathBuf::from("/tmp/custom-jobs.yaml"));
    }

    fn jobs_fixture() -> JobsFile {
        // Minimal valid v1 jobs.yaml with one job.
        let yaml = "\
version: 1
jobs:
  - id: morning-brief
    name: Morning Briefing
    enabled: true
    schedule:
      cron: \"0 7 * * *\"
    prompt: \"Summarise overnight events.\"
";
        JobsFile::from_yaml_str(yaml).expect("valid fixture")
    }

    #[test]
    fn find_job_returns_the_matching_job() {
        let jobs = jobs_fixture();
        let job = find_job(&jobs, "morning-brief").expect("present");
        assert_eq!(job.id, "morning-brief");
        assert_eq!(job.prompt, "Summarise overnight events.");
    }

    #[test]
    fn find_job_errors_with_the_id_when_absent() {
        let jobs = jobs_fixture();
        let err = find_job(&jobs, "no-such-job").unwrap_err();
        assert!(
            err.to_string().contains("no-such-job"),
            "error names the missing id: {err}"
        );
    }
}
