//! `neoth jobs` — operator-facing view of the cron job set.
//!
//! Modes:
//!   `--list`     parse `~/.neoth/jobs.yaml`, print table of jobs + next fire.
//!   `--validate` parse + cron-validate every job, exit non-zero on first error.
//!
//! `--run-once <id>` is a follow-up once serve-side scheduler is fully wired.
//! For now operators can drop a job into jobs.yaml and `neoth serve` picks it
//! up on next restart.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::cron::JobsFile;

#[derive(Args, Debug, Clone)]
pub struct JobsArgs {
    /// Print the table of configured jobs with next-fire times.
    #[arg(long, conflicts_with_all = ["validate", "preview"])]
    pub list: bool,

    /// Parse + validate jobs.yaml without printing the table. Exits non-zero
    /// on the first invalid job.
    #[arg(long, conflicts_with_all = ["list", "preview"])]
    pub validate: bool,

    /// AR-04 (Session 24) — dry-run one job by id: prints the next 3
    /// fire times, the predicted EUR token cost via the existing
    /// cost predictor, and whether the operator's current autonomy
    /// level would allow / confirm / block the call when it
    /// eventually fires. No WAL writes, no provider calls, no
    /// scheduler side effects — purely diagnostic. Pairs with
    /// `--file` for inspecting a draft jobs.yaml before commit.
    #[arg(long, value_name = "ID", conflicts_with_all = ["list", "validate"])]
    pub preview: Option<String>,

    /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// GOLD-ADAPT-ODY-07b — run COMMAND as a DETACHED background job. Its
    /// stdout+stderr stream to `~/.neoth/bgjobs/<id>.log` and its exit code to
    /// `<id>.exit`; the running daemon's bg-monitor tracks completion (and runs
    /// any auto-continue callback). Quote the whole command, e.g.
    /// `neoth jobs --run "cargo build --release" --label build`.
    #[arg(long, value_name = "COMMAND", conflicts_with_all = ["list", "validate", "preview", "bg"])]
    pub run: Option<String>,

    /// Optional label for the `--run` job id (sanitised to `[a-z0-9_-]`;
    /// default `job`). The on-disk id is `<label>-<unix_ts>`.
    #[arg(long, value_name = "NAME", requires = "run")]
    pub label: Option<String>,

    /// GOLD-ADAPT-ODY-07b — list the detached background jobs in
    /// `~/.neoth/bgjobs/` with their status (running / completed + exit code).
    #[arg(long, conflicts_with_all = ["list", "validate", "preview", "run"])]
    pub bg: bool,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_jobs(args: JobsArgs) -> Result<()> {
    // GOLD-ADAPT-ODY-07b — background (detached) job producer + lister. These
    // operate on the `~/.neoth/bgjobs/` on-disk registry that the daemon's
    // bg_monitor watches (NOT jobs.yaml), so handle them before the jobs.yaml
    // load + existence check.
    if let Some(command) = args.run.as_deref() {
        return run_bg_job(command, args.label.as_deref().unwrap_or("job"));
    }
    if args.bg {
        return list_bg_jobs(&args.output);
    }

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

    if let Some(id) = args.preview.as_deref() {
        return run_preview(&jobs, id, &args.output);
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

// ── AR-04 (Session 24) `neoth jobs --preview <id>` ────────────────────

/// Diagnostic snapshot of one job: who fires next, what the call will
/// cost, and whether the operator's current autonomy level lets it
/// through. Pure data — no WAL writes, no provider dispatch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct JobPreview {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub cron: String,
    pub tz: Option<String>,
    /// Next 3 fire timestamps as RFC-3339 UTC strings (operator-readable).
    /// Empty when the schedule resolves to "never" from `now`.
    pub next_fires_utc: Vec<String>,
    pub delivery_channel: Option<String>,
    pub delivery_recipient: Option<String>,
    /// Predicted EUR cost via [`crate::providers::cost::predict`] using
    /// the job's prompt body + the configured provider/model. Defaults
    /// to a conservative high-estimate fallback when no price row
    /// matches (silent free-default would bypass the autonomy gate).
    pub predicted_cost_eur: f32,
    pub predicted_input_tokens: u32,
    pub predicted_output_tokens: u32,
    /// Provider + model the cost prediction targeted. Sourced from
    /// `FreedomConfig.provider_kind` / `provider_model` to match what
    /// the real cron runner would dispatch against.
    pub provider: String,
    pub model: String,
    /// Autonomy verdict at the operator's current level. One of:
    /// `"allow"` / `"confirm"` / `"block"` / `"unknown"`. Mirrors
    /// what the permission gate would render at dispatch time.
    pub autonomy_verdict: String,
    /// Current autonomy level (`"strict"` / `"standard"` / `"elevated"` /
    /// `"full"` / `"custom"`) included so the operator sees WHY they got
    /// the verdict without a second `neoth doctor` call.
    pub autonomy_level: String,
}

fn run_preview(jobs: &JobsFile, id: &str, output: &OutputFormat) -> Result<()> {
    let job = jobs
        .jobs
        .iter()
        .find(|j| j.id == id)
        .with_context(|| format!("no job with id `{id}` in jobs.yaml"))?;

    let preview = build_preview(job)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&preview)?);
        }
        OutputFormat::Table => {
            println!("# Job preview: {}", preview.id);
            println!("  name           : {}", preview.name);
            println!(
                "  enabled        : {}",
                if preview.enabled { "yes" } else { "no" },
            );
            println!("  cron           : {}", preview.cron);
            if let Some(tz) = &preview.tz {
                println!("  tz             : {tz}");
            }
            println!(
                "  delivery       : {} → {}",
                preview.delivery_channel.as_deref().unwrap_or("wal-only"),
                preview
                    .delivery_recipient
                    .as_deref()
                    .unwrap_or("(no recipient)"),
            );
            println!();
            if preview.next_fires_utc.is_empty() {
                println!("  next fires     : (never — cron expression yields no future time)");
            } else {
                println!("  next 3 fires UTC:");
                for ts in &preview.next_fires_utc {
                    println!("    - {ts}");
                }
            }
            println!();
            println!(
                "  cost preview   : {provider}/{model}  ~{in_tok} in + ~{out_tok} out tokens  →  €{eur:.4}",
                provider = preview.provider,
                model = preview.model,
                in_tok = preview.predicted_input_tokens,
                out_tok = preview.predicted_output_tokens,
                eur = preview.predicted_cost_eur,
            );
            println!(
                "  autonomy gate  : {verdict}  (current level: {level})",
                verdict = preview.autonomy_verdict,
                level = preview.autonomy_level,
            );
            println!();
            println!("(dry-run — no WAL writes, no provider dispatch)");
        }
    }
    Ok(())
}

/// Pure-helper: walk one [`crate::cron::schema::Job`] into a [`JobPreview`].
/// Reads `FreedomConfig` from disk for the provider + autonomy lookup;
/// failures fall back to neutral defaults so the preview always renders
/// SOMETHING (operator with a fresh install + `--file ./draft.yaml`
/// shouldn't be blocked by a missing freedom.yaml).
pub fn build_preview(job: &crate::cron::schema::Job) -> Result<JobPreview> {
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();

    let now = crate::time::utc_now();
    let mut next_fires: Vec<String> = Vec::with_capacity(3);
    let mut cursor = now;
    for _ in 0..3 {
        match job.schedule.next_after(cursor) {
            Some(t) => {
                next_fires.push(t.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                cursor = t;
            }
            None => break,
        }
    }

    // Provider + model resolution mirrors how the cron runner picks
    // them at dispatch time. Falls back to "local_qwen" + "unknown"
    // for a freshly-installed operator who hasn't configured a
    // provider yet — keeps the preview informative instead of
    // erroring out.
    // COR-13: canonical provider-id (Skip/None -> "none"); feeds
    // cost::predict + the is_cloud verdict below identically to the old
    // inline match (which had "unconfigured" for Skip).
    let provider = cfg
        .provider_kind
        .map(|k| k.as_provider_id().to_string())
        .unwrap_or_else(|| "none".to_string());
    let model = cfg
        .provider_model
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let meter = crate::providers::meter::Meter::with_default_window();
    let est = crate::providers::cost::predict(&provider, &model, &job.prompt, &meter);

    // AR-04 autonomy verdict — mirrors the dispatch-time gate
    // qualitatively. Strict refuses non-local cloud providers
    // outright; Standard confirms when the cost crosses a tier; Full
    // allows. Local providers + unconfigured both fall under "allow"
    // because there's no spend on a local call and an unconfigured
    // job won't reach a real provider.
    use crate::permissions::AutonomyLevel;
    // Route through the canonical classifier (GOLD-SEC-09 / A-25) — the
    // prior inline set silently MISSED anthropic_api + cohere_api, so jobs
    // on those metered providers escaped the cost/consent verdict. An
    // unknown/unconfigured slug maps to None → not cloud → allow (no spend).
    let is_cloud = crate::consent::kind_from_slug(provider.as_str())
        .map(crate::consent::is_cloud)
        .unwrap_or(false);
    let verdict = match (cfg.autonomy, is_cloud, est.total_eur) {
        (_, false, _) => "allow",
        (AutonomyLevel::Strict, true, _) => "block",
        (AutonomyLevel::Full, true, _) => "allow",
        (AutonomyLevel::Standard, true, eur) if eur >= 0.50 => "confirm",
        (AutonomyLevel::Standard, true, _) => "allow",
        (AutonomyLevel::Elevated, true, eur) if eur >= 5.00 => "confirm",
        (AutonomyLevel::Elevated, true, _) => "allow",
        (AutonomyLevel::Custom, true, _) => "unknown",
    };

    Ok(JobPreview {
        id: job.id.clone(),
        name: job.name.clone(),
        enabled: job.enabled,
        cron: job.schedule.cron.clone(),
        tz: job.schedule.tz.clone(),
        next_fires_utc: next_fires,
        delivery_channel: job.delivery.as_ref().map(|d| d.channel.clone()),
        delivery_recipient: job.delivery.as_ref().and_then(|d| d.recipient.clone()),
        predicted_cost_eur: est.total_eur,
        predicted_input_tokens: est.input_tokens,
        predicted_output_tokens: est.output_tokens_est,
        provider,
        model,
        autonomy_verdict: verdict.into(),
        autonomy_level: format!("{:?}", cfg.autonomy).to_lowercase(),
    })
}

// ── GOLD-ADAPT-ODY-07b — detached background-job producer + lister ──────────

/// Build the detached-job shell wrapper argv. Pure (no spawn) so the redirect +
/// exit-marker contract is unit-testable. The wrapper runs `command`, tees
/// stdout+stderr to `log`, and writes the numeric exit code to `exit` when the
/// command finishes — the two on-disk markers the daemon's bg_monitor reads
/// (`<id>.log` present = running; `<id>.exit` present = done).
fn bg_wrapper_argv(command: &str, log: &Path, exit: &Path) -> (String, Vec<String>) {
    let log = log.display().to_string();
    let exit = exit.display().to_string();
    if cfg!(target_os = "windows") {
        // /V:ON enables delayed expansion so `!ERRORLEVEL!` is the command's real
        // exit code, not the parse-time value `%ERRORLEVEL%` would capture.
        (
            "cmd".to_string(),
            vec![
                "/V:ON".to_string(),
                "/C".to_string(),
                format!("({command}) > \"{log}\" 2>&1 & echo !ERRORLEVEL!> \"{exit}\""),
            ],
        )
    } else {
        (
            "sh".to_string(),
            vec![
                "-c".to_string(),
                format!("({command}) > '{log}' 2>&1; echo $? > '{exit}'"),
            ],
        )
    }
}

/// Sanitise a job label to the `[a-z0-9_-]` shape the registry uses as a file
/// stem (a label becomes part of `<label>-<ts>.log`). Empty → `job`.
fn sanitise_label(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if s.is_empty() { "job".to_string() } else { s }
}

/// ODY-07b — spawn `command` as a detached background job. Writes the bg_jobs
/// on-disk markers (`<id>.log` + `<id>.exit`) the daemon's bg_monitor watches.
/// The `std::process::Child` handle is dropped immediately — dropping it does
/// NOT kill the process, so the job runs detached and survives this CLI exit.
fn run_bg_job(command: &str, label: &str) -> Result<()> {
    if command.trim().is_empty() {
        anyhow::bail!("--run requires a non-empty command");
    }
    let bgjobs_dir = FreedomConfig::default_neoth_home().join("bgjobs");
    std::fs::create_dir_all(&bgjobs_dir).context("create ~/.neoth/bgjobs")?;
    let id = crate::daemon::bg_jobs::BgJobId::new(&sanitise_label(label), crate::time::now_unix_secs());
    let log = bgjobs_dir.join(format!("{}.log", id.as_str()));
    let exit = bgjobs_dir.join(format!("{}.exit", id.as_str()));
    let (program, wrapper_args) = bg_wrapper_argv(command, &log, &exit);
    let child = std::process::Command::new(&program)
        .args(&wrapper_args)
        .spawn()
        .with_context(|| format!("spawn detached job via `{program}`"))?;
    println!("started background job `{}` (pid {})", id.as_str(), child.id());
    println!("  log   : {}", log.display());
    println!("  status: `neoth jobs --bg` (a running daemon's bg-monitor auto-tracks completion)");
    Ok(())
}

/// Pure listing core: scan `bgjobs_dir` for `<id>.log` files and pair each with
/// its `<id>.exit` status. Split out so the directory scan is unit-testable with
/// a tempdir. Returns `(id, status, exit_code)` rows sorted by id.
fn collect_bg_rows(bgjobs_dir: &Path) -> Vec<(String, String, Option<i32>)> {
    let mut rows: Vec<(String, String, Option<i32>)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(bgjobs_dir) else {
        return rows;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("log") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let exit = bgjobs_dir.join(format!("{stem}.exit"));
        let (state, code) = match crate::daemon::bg_jobs::read_job_status(&exit) {
            crate::daemon::bg_jobs::BgJobStatus::Running => ("running".to_string(), None),
            crate::daemon::bg_jobs::BgJobStatus::Completed { code } => {
                ("completed".to_string(), code)
            }
        };
        rows.push((stem.to_string(), state, code));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

fn list_bg_jobs(output: &OutputFormat) -> Result<()> {
    let bgjobs_dir = FreedomConfig::default_neoth_home().join("bgjobs");
    let rows = collect_bg_rows(&bgjobs_dir);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<_> = rows
                .iter()
                .map(|(id, state, code)| {
                    serde_json::json!({ "id": id, "status": state, "exit_code": code })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("no background jobs (start one: `neoth jobs --run \"<command>\"`)");
                return Ok(());
            }
            println!("{:<36} {:<12} exit", "id", "status");
            println!("{}", "-".repeat(58));
            for (id, state, code) in &rows {
                println!(
                    "{:<36} {:<12} {}",
                    truncate(id, 36),
                    state,
                    code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
                );
            }
        }
    }
    Ok(())
}

fn print_table(jobs: &JobsFile) {
    let now = crate::time::utc_now();
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
        // GOLD-COR-02 / A-04: cut on a char boundary so a multibyte job
        // string never panics the truncation.
        let mut end = n.saturating_sub(1);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::schema::{JobsFile, Schedule};

    fn make_job(id: &str, prompt: &str) -> crate::cron::schema::Job {
        crate::cron::schema::Job {
            id: id.into(),
            name: format!("job-{id}"),
            enabled: true,
            schedule: Schedule {
                // Every day at 07:00 UTC — yields a definite "next 3 fires".
                cron: "0 7 * * *".into(),
                tz: None,
            },
            prompt: prompt.into(),
            timeout_seconds: 600,
            delivery: None,
            depends_on: vec![],
        }
    }

    #[test]
    fn ar_04_build_preview_populates_next_3_fires() {
        let job = make_job("daily-briefing", "Hi");
        let preview = super::build_preview(&job).expect("build");
        assert_eq!(preview.id, "daily-briefing");
        assert_eq!(
            preview.next_fires_utc.len(),
            3,
            "every-day cron yields 3 future fires"
        );
        // The first fire must be strictly after now (sanity — operator
        // never sees a "next fire was 5 minutes ago" surprise).
        let first = &preview.next_fires_utc[0];
        assert!(first.contains("07:00:00 UTC"), "got {first}");
    }

    #[test]
    fn ar_04_build_preview_returns_predicted_cost_fields() {
        let job = make_job("expensive", "the quick brown fox jumps over the lazy dog");
        let preview = super::build_preview(&job).expect("build");
        assert!(
            preview.predicted_input_tokens > 0,
            "non-empty prompt → tokens > 0"
        );
        assert!(
            preview.predicted_output_tokens > 0,
            "meter default has a baseline > 0"
        );
        // Cost field exists + finite (could be 0 for local providers).
        assert!(preview.predicted_cost_eur.is_finite());
    }

    #[test]
    fn ar_04_build_preview_autonomy_verdict_is_a_known_string() {
        let job = make_job("any", "hi");
        let preview = super::build_preview(&job).expect("build");
        let allowed = ["allow", "confirm", "block", "unknown"];
        assert!(
            allowed.contains(&preview.autonomy_verdict.as_str()),
            "verdict must be one of {allowed:?}, got {:?}",
            preview.autonomy_verdict,
        );
    }

    #[test]
    fn ar_04_run_preview_errors_for_unknown_job_id() {
        let jobs = JobsFile {
            version: 1,
            jobs: vec![make_job("only-job", "x")],
        };
        let r = super::run_preview(&jobs, "missing-id", &OutputFormat::Json);
        assert!(r.is_err(), "missing id must error");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(
            msg.contains("missing-id") && msg.contains("no job with id"),
            "error must name the missing id + the contract: {msg}",
        );
    }

    #[test]
    fn ar_04_build_preview_serialises_to_json() {
        // Drift guard: the JsonValue path used by `--output json` must
        // round-trip the JobPreview without losing fields.
        let job = make_job("daily-briefing", "Hi");
        let preview = super::build_preview(&job).expect("build");
        let json = serde_json::to_value(&preview).unwrap();
        for field in [
            "id",
            "name",
            "enabled",
            "cron",
            "next_fires_utc",
            "predicted_cost_eur",
            "predicted_input_tokens",
            "predicted_output_tokens",
            "provider",
            "model",
            "autonomy_verdict",
            "autonomy_level",
        ] {
            assert!(
                json.get(field).is_some(),
                "field `{field}` must serialise in JobPreview JSON",
            );
        }
    }

    // ── GOLD-ADAPT-ODY-07b — detached background-job producer + lister ──────

    #[test]
    fn ody07b_bg_wrapper_argv_tees_log_and_writes_exit_code() {
        let log = Path::new("/tmp/j.log");
        let exit = Path::new("/tmp/j.exit");
        let (program, wargs) = super::bg_wrapper_argv("echo hi", log, exit);
        let joined = wargs.join(" ");
        assert!(joined.contains("echo hi"), "must run the command: {joined}");
        assert!(joined.contains("j.log"), "must tee to the log: {joined}");
        assert!(joined.contains("j.exit"), "must write the exit marker: {joined}");
        if cfg!(target_os = "windows") {
            assert_eq!(program, "cmd");
            assert!(
                joined.contains("!ERRORLEVEL!"),
                "windows needs delayed-expansion exit code: {joined}"
            );
        } else {
            assert_eq!(program, "sh");
            assert!(joined.contains("$?"), "unix captures $? as the exit code: {joined}");
        }
    }

    #[test]
    fn ody07b_sanitise_label_keeps_safe_chars_and_defaults_empty() {
        assert_eq!(super::sanitise_label("build-1_x"), "build-1_x");
        assert_eq!(super::sanitise_label("a b/c.d"), "a-b-c-d");
        assert_eq!(super::sanitise_label(""), "job");
        assert_eq!(super::sanitise_label("///"), "---");
    }

    #[test]
    fn ody07b_collect_bg_rows_reports_running_and_completed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // running job: .log only, no .exit
        std::fs::write(dir.join("alpha-100.log"), b"out").unwrap();
        // completed job: .log + .exit (code 0)
        std::fs::write(dir.join("beta-200.log"), b"out").unwrap();
        std::fs::write(dir.join("beta-200.exit"), b"0\n").unwrap();
        // non-log file is ignored
        std::fs::write(dir.join("note.txt"), b"x").unwrap();
        let rows = super::collect_bg_rows(dir);
        assert_eq!(rows.len(), 2, "two .log jobs, txt ignored: {rows:?}");
        assert_eq!(rows[0].0, "alpha-100"); // sorted by id
        assert_eq!(rows[0].1, "running");
        assert_eq!(rows[0].2, None);
        assert_eq!(rows[1].0, "beta-200");
        assert_eq!(rows[1].1, "completed");
        assert_eq!(rows[1].2, Some(0));
    }

    #[test]
    fn ody07b_collect_bg_rows_empty_for_missing_dir() {
        let rows = super::collect_bg_rows(Path::new("/no/such/bgjobs/dir/xyz"));
        assert!(rows.is_empty());
    }
}
