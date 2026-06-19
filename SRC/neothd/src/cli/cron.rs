//! `neoth cron` — operator CRUD for scheduled jobs + one-shot fire.
//!
//! Subcommands:
//! - `run <id>`     Fire one job NOW, out-of-band (refused while daemon live).
//! - `add`          Append a new job to jobs.yaml (HERMES-01).
//! - `edit <id>`    Update fields of an existing job by id (HERMES-01).
//! - `remove <id>`  Delete a job by id (HERMES-01).
//! - `list`         Print all jobs with role, schedule, and delivery (HERMES-01).
//!
//! All mutating commands call `Job::validate()` (JV-PRO-01) before saving and
//! surface `preflight()` warnings (JV-PRO-04). `add` also surfaces collision
//! warnings via `schedule_collides()` (JV-PRO-09). Saves are atomic (tmp+rename).
//!
//! Refuses while `neoth serve` is live for `run` only — CRUD operations on
//! jobs.yaml are safe at any time (the scheduler re-reads on restart).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::cron::schema::{
    classify_role, preflight, schedule_collides, Delivery, Job, JobsFile, Schedule,
};

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

    /// Add a new job to jobs.yaml. Validates the schedule and surfaces delivery
    /// warnings before saving. Rejects duplicate ids. HERMES-01 / JV-PRO-01/04/09.
    Add {
        /// Unique job id (slug, no spaces).
        #[arg(long)]
        id: String,
        /// Human-readable job name.
        #[arg(long)]
        name: String,
        /// 5-field cron expression, e.g. "0 7 * * *".
        #[arg(long)]
        cron: String,
        /// Prompt sent to the configured provider when the job fires.
        #[arg(long)]
        prompt: String,
        /// IANA timezone, e.g. "Europe/Berlin". Defaults to UTC.
        #[arg(long)]
        tz: Option<String>,
        /// Delivery channel name ("telegram", "slack", …).
        #[arg(long)]
        channel: Option<String>,
        /// Delivery recipient (chat_id, user_id, …).
        #[arg(long)]
        recipient: Option<String>,
        /// Timeout in seconds. Defaults to 600.
        #[arg(long)]
        timeout: Option<u32>,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Edit an existing job by id. Only supplied flags are updated.
    /// Validates the result and surfaces warnings before saving. HERMES-01.
    Edit {
        /// The job `id` to modify.
        id: String,
        /// Replace the job name.
        #[arg(long)]
        name: Option<String>,
        /// Replace the cron expression.
        #[arg(long)]
        cron: Option<String>,
        /// Replace the prompt.
        #[arg(long)]
        prompt: Option<String>,
        /// Replace the timezone (pass "UTC" to clear).
        #[arg(long)]
        tz: Option<String>,
        /// Replace the delivery channel.
        #[arg(long)]
        channel: Option<String>,
        /// Replace the delivery recipient.
        #[arg(long)]
        recipient: Option<String>,
        /// Replace the timeout in seconds.
        #[arg(long)]
        timeout: Option<u32>,
        /// Enable or disable the job.
        #[arg(long)]
        enabled: Option<bool>,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Remove a job by id from jobs.yaml. HERMES-01.
    Remove {
        /// The job `id` to delete.
        id: String,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// List all jobs with their schedule, role, and delivery. HERMES-01 / JV-PRO-05.
    List {
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
        CronAction::Add {
            id,
            name,
            cron,
            prompt,
            tz,
            channel,
            recipient,
            timeout,
            file,
        } => cron_add(id, name, cron, prompt, tz, channel, recipient, timeout, file),
        CronAction::Edit {
            id,
            name,
            cron,
            prompt,
            tz,
            channel,
            recipient,
            timeout,
            enabled,
            file,
        } => cron_edit(id, name, cron, prompt, tz, channel, recipient, timeout, enabled, file),
        CronAction::Remove { id, file } => cron_remove(id, file),
        CronAction::List { file } => cron_list(file, output),
    }
}

// ── HERMES-01: CRUD helpers ───────────────────────────────────────────────────

/// Load jobs.yaml from disk, creating an empty v1 file if it does not exist.
fn load_or_create(path: &std::path::Path) -> Result<JobsFile> {
    if path.exists() {
        // Use blocking read here (CLI context, not inside an async runtime).
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let parsed: JobsFile =
            serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
        Ok(parsed)
    } else {
        Ok(JobsFile {
            version: 1,
            jobs: Vec::new(),
        })
    }
}

/// Print pre-flight + collision warnings to stderr so they are visible even
/// when stdout is captured for JSON. Returns Ok(()) always.
fn print_warnings(warnings: &[String], label: &str) {
    for w in warnings {
        eprintln!("warn [{label}]: {w}");
    }
}

/// `neoth cron add` — append a new job. HERMES-01 + JV-PRO-01/04/09.
#[allow(clippy::too_many_arguments)]
fn cron_add(
    id: String,
    name: String,
    cron: String,
    prompt: String,
    tz: Option<String>,
    channel: Option<String>,
    recipient: Option<String>,
    timeout: Option<u32>,
    file: Option<PathBuf>,
) -> Result<()> {
    let path = jobs_path(file);
    let mut jf = load_or_create(&path)?;

    // JV-PRO-01: reject duplicate id before touching anything
    if jf.jobs.iter().any(|j| j.id == id) {
        anyhow::bail!("a job with id `{id}` already exists in {}", path.display());
    }

    let delivery = channel.map(|ch| Delivery {
        channel: ch,
        recipient,
    });

    let job = Job {
        id: id.clone(),
        name,
        enabled: true,
        schedule: Schedule { cron, tz },
        prompt,
        timeout_seconds: timeout.unwrap_or(600),
        delivery,
    };

    // JV-PRO-01: validate before saving
    job.validate()?;

    // JV-PRO-04: delivery pre-flight warnings
    let pf = preflight(&job);
    print_warnings(&pf, "preflight");

    // JV-PRO-09: collision warnings
    let collisions = schedule_collides(&job.schedule, &jf.jobs, 48);
    print_warnings(&collisions, "collision");

    jf.jobs.push(job);
    jf.save_to_path(&path)
        .with_context(|| format!("save {}", path.display()))?;
    println!("added job `{id}` to {}", path.display());
    Ok(())
}

/// `neoth cron edit <id>` — patch fields of an existing job. HERMES-01.
#[allow(clippy::too_many_arguments)]
fn cron_edit(
    id: String,
    name: Option<String>,
    cron: Option<String>,
    prompt: Option<String>,
    tz: Option<String>,
    channel: Option<String>,
    recipient: Option<String>,
    timeout: Option<u32>,
    enabled: Option<bool>,
    file: Option<PathBuf>,
) -> Result<()> {
    let path = jobs_path(file);
    let mut jf = load_or_create(&path)?;

    let job = jf
        .jobs
        .iter_mut()
        .find(|j| j.id == id)
        .with_context(|| format!("no job with id `{id}` in {}", path.display()))?;

    if let Some(n) = name {
        job.name = n;
    }
    if let Some(c) = cron {
        job.schedule.cron = c;
    }
    if let Some(t) = tz {
        job.schedule.tz = if t.is_empty() { None } else { Some(t) };
    }
    if let Some(p) = prompt {
        job.prompt = p;
    }
    if let Some(t) = timeout {
        job.timeout_seconds = t;
    }
    if let Some(e) = enabled {
        job.enabled = e;
    }
    // Channel/recipient: update delivery block
    if channel.is_some() || recipient.is_some() {
        let existing_delivery = job.delivery.get_or_insert_with(|| Delivery {
            channel: String::new(),
            recipient: None,
        });
        if let Some(ch) = channel {
            existing_delivery.channel = ch;
        }
        if let Some(r) = recipient {
            existing_delivery.recipient = if r.is_empty() { None } else { Some(r) };
        }
    }

    // JV-PRO-01: validate the mutated job
    job.validate()?;

    // JV-PRO-04: surface warnings
    let pf = preflight(job);
    print_warnings(&pf, "preflight");

    jf.save_to_path(&path)
        .with_context(|| format!("save {}", path.display()))?;
    println!("updated job `{id}` in {}", path.display());
    Ok(())
}

/// `neoth cron remove <id>` — delete a job by id. HERMES-01.
fn cron_remove(id: String, file: Option<PathBuf>) -> Result<()> {
    let path = jobs_path(file);
    let mut jf = load_or_create(&path)?;

    let before = jf.jobs.len();
    jf.jobs.retain(|j| j.id != id);
    if jf.jobs.len() == before {
        anyhow::bail!("no job with id `{id}` in {}", path.display());
    }

    jf.save_to_path(&path)
        .with_context(|| format!("save {}", path.display()))?;
    println!("removed job `{id}` from {}", path.display());
    Ok(())
}

/// `neoth cron list` — print all jobs. HERMES-01 / JV-PRO-05.
fn cron_list(file: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let path = jobs_path(file);
    let jf = load_or_create(&path)?;

    if jf.jobs.is_empty() {
        println!("no jobs defined in {}", path.display());
        return Ok(());
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Emit each job as a JSON object enriched with the role field.
            let rows: Vec<_> = jf
                .jobs
                .iter()
                .map(|j| {
                    serde_json::json!({
                        "id": j.id,
                        "name": j.name,
                        "enabled": j.enabled,
                        "cron": j.schedule.cron,
                        "tz": j.schedule.tz,
                        "role": classify_role(j).to_string(),
                        "timeout_seconds": j.timeout_seconds,
                        "channel": j.delivery.as_ref().map(|d| &d.channel),
                        "recipient": j.delivery.as_ref().and_then(|d| d.recipient.as_deref()),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            println!(
                "{:<20} {:<25} {:<16} {:<13} {:<12} DELIVERY",
                "ID", "NAME", "CRON", "ROLE", "ENABLED"
            );
            println!("{}", "-".repeat(100));
            for j in &jf.jobs {
                let role = classify_role(j);
                let delivery = match &j.delivery {
                    None => "-".to_string(),
                    Some(d) => match &d.recipient {
                        Some(r) => format!("{}:{}", d.channel, r),
                        None => d.channel.clone(),
                    },
                };
                println!(
                    "{:<20} {:<25} {:<16} {:<13} {:<12} {}",
                    j.id,
                    j.name,
                    j.schedule.cron,
                    role,
                    if j.enabled { "yes" } else { "no" },
                    delivery,
                );
            }
        }
    }
    Ok(())
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
        assert!(
            p.ends_with("jobs.yaml"),
            "default ends with jobs.yaml: {p:?}"
        );
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

    // ── CRON-A: HERMES-01 CRUD roundtrip ─────────────────────────────────────

    fn temp_jobs_yaml(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("jobs.yaml");
        std::fs::write(&path, content).expect("write fixture");
        (dir, path)
    }

    #[test]
    fn add_then_list_roundtrip() {
        let (_dir, path) = temp_jobs_yaml("version: 1\njobs: []\n");

        cron_add(
            "nightly-report".to_string(),
            "Nightly Report".to_string(),
            "0 23 * * *".to_string(),
            "Summarise the day's activity in detail.".to_string(),
            None,
            None,
            None,
            None,
            Some(path.clone()),
        )
        .expect("add should succeed");

        let jf = load_or_create(&path).expect("reload");
        assert_eq!(jf.jobs.len(), 1);
        assert_eq!(jf.jobs[0].id, "nightly-report");
        assert_eq!(jf.jobs[0].name, "Nightly Report");
    }

    #[test]
    fn add_duplicate_id_is_rejected() {
        let (_dir, path) = temp_jobs_yaml("version: 1\njobs: []\n");

        cron_add(
            "dup".to_string(),
            "Dup".to_string(),
            "0 6 * * *".to_string(),
            "Do something useful here.".to_string(),
            None,
            None,
            None,
            None,
            Some(path.clone()),
        )
        .expect("first add ok");

        let err = cron_add(
            "dup".to_string(),
            "Dup Again".to_string(),
            "0 6 * * *".to_string(),
            "Do something useful here.".to_string(),
            None,
            None,
            None,
            None,
            Some(path.clone()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn remove_deletes_job() {
        let yaml = "\
version: 1
jobs:
  - id: to-delete
    name: To Delete
    schedule:
      cron: \"0 5 * * *\"
    prompt: \"delete me please now\"
";
        let (_dir, path) = temp_jobs_yaml(yaml);
        cron_remove("to-delete".to_string(), Some(path.clone())).expect("remove ok");
        let jf = load_or_create(&path).expect("reload");
        assert!(jf.jobs.is_empty());
    }

    #[test]
    fn remove_nonexistent_id_errors() {
        let (_dir, path) = temp_jobs_yaml("version: 1\njobs: []\n");
        let err = cron_remove("ghost".to_string(), Some(path)).unwrap_err();
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    #[test]
    fn edit_updates_name_and_timeout() {
        let yaml = "\
version: 1
jobs:
  - id: editable
    name: Old Name
    schedule:
      cron: \"0 8 * * *\"
    prompt: \"do something meaningful here\"
";
        let (_dir, path) = temp_jobs_yaml(yaml);
        cron_edit(
            "editable".to_string(),
            Some("New Name".to_string()),
            None,
            None,
            None,
            None,
            None,
            Some(120),
            None,
            Some(path.clone()),
        )
        .expect("edit ok");

        let jf = load_or_create(&path).expect("reload");
        assert_eq!(jf.jobs[0].name, "New Name");
        assert_eq!(jf.jobs[0].timeout_seconds, 120);
    }
}
