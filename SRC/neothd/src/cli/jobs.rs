//! `neoth jobs` — operator-facing view of the cron job set.
//!
//! Modes:
//!   `--list`     parse `~/.neoth/jobs.yaml`, print table of jobs + next fire.
//!   `--validate` parse + cron-validate every job, exit non-zero on first error.
//!
//! `--run-once <id>` is a follow-up once serve-side scheduler is fully wired.
//! For now operators can drop a job into jobs.yaml and `neoth serve` picks it
//! up on next restart.

use std::io::{ErrorKind, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::cron::JobsFile;
use crate::permissions::{Action, ConfirmStrategy, Decision, Gate, PermissionAuditSink, evaluate};

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
    /// default `job`). The on-disk id is `<label>-<unix_ts>-<random>`.
    #[arg(long, value_name = "NAME", requires = "run")]
    pub label: Option<String>,

    /// Internal GUI handshake: after the graphical confirmation dialog, re-read
    /// live policy and mint a mandatory-audited short-lived approval for the
    /// exact `--run` request. Same-UID operator authority; never overrides Deny.
    #[arg(
        long,
        requires = "run",
        conflicts_with = "gui_approval_token",
        hide = true
    )]
    pub approve_run: bool,

    /// Internal GUI handshake token returned by `--approve-run`.
    #[arg(long, value_name = "TOKEN", requires = "run", hide = true)]
    pub gui_approval_token: Option<String>,

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
        let label = args.label.as_deref().unwrap_or("job");
        if args.approve_run {
            return approve_bg_job(command, label, &args.output).await;
        }
        return run_bg_job(
            command,
            label,
            args.gui_approval_token.as_deref(),
            &args.output,
        )
        .await;
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
                "  delivery       : {}",
                preview
                    .delivery_channel
                    .as_deref()
                    .map(|channel| format!("{channel} (operator-configured route)"))
                    .unwrap_or_else(|| "wal-only".to_string()),
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
/// a genuinely missing file uses neutral defaults so a fresh-install preview
/// still renders. Malformed/unreadable existing policy is surfaced.
pub fn build_preview(job: &crate::cron::schema::Job) -> Result<JobPreview> {
    let cfg = FreedomConfig::load_from_default_path_or_default()?;

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

const BG_COMMAND_MAX_BYTES: usize = 32 * 1024;
const BG_LABEL_MAX_BYTES: usize = 64;
const BG_ID_RANDOM_BYTES: usize = 16;
const BG_ID_RESERVATION_ATTEMPTS: usize = 16;
const BG_JOB_ACTION: &str = "jobs_run";
const BG_JOB_AUDIT_REQUIRED: bool = true;

/// Sanitise a job label to the `[a-z0-9_-]` shape the registry uses as a file
/// stem (a label becomes part of `<label>-<ts>-<random>.log`). Empty → `job`.
fn sanitise_label(label: &str) -> String {
    let s: String = label
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if s.is_empty() { "job".to_string() } else { s }
}

#[derive(Debug, Clone)]
struct BgJobRequest {
    command: String,
    label: String,
    instance: String,
    request_binding_sha256: String,
}

#[derive(Serialize)]
struct BgJobRequestBinding<'a> {
    action: &'static str,
    command: &'a str,
    label: &'a str,
    instance: &'a str,
}

impl BgJobRequest {
    fn new(command: &str, label: &str, instance_home: &Path) -> Result<Self> {
        let command = command.trim();
        anyhow::ensure!(!command.is_empty(), "--run requires a non-empty command");
        anyhow::ensure!(
            command.len() <= BG_COMMAND_MAX_BYTES,
            "--run command is {} bytes; maximum is {BG_COMMAND_MAX_BYTES}",
            command.len()
        );
        anyhow::ensure!(!command.contains('\0'), "--run command contains a NUL byte");
        anyhow::ensure!(
            label.len() <= BG_LABEL_MAX_BYTES,
            "--label is {} bytes; maximum is {BG_LABEL_MAX_BYTES}",
            label.len()
        );

        let command = command.to_owned();
        let label = sanitise_label(label);
        let instance = canonical_instance(instance_home)?;
        let request_binding_sha256 = request_binding_sha256(&command, &label, &instance)?;
        Ok(Self {
            command,
            label,
            instance,
            request_binding_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BgJobReceipt {
    action: String,
    started: bool,
    id: String,
    pid: u32,
    log_path: String,
    request_binding_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BgRunApprovalReceipt {
    action: String,
    approved: bool,
    request_binding_sha256: String,
    token: String,
}

impl BgJobReceipt {
    fn is_bound_to(&self, request: &BgJobRequest) -> bool {
        let Ok(expected) =
            request_binding_sha256(&request.command, &request.label, &request.instance)
        else {
            return false;
        };
        self.action == BG_JOB_ACTION
            && self.started
            && request.request_binding_sha256 == expected
            && self.request_binding_sha256 == expected
    }
}

fn canonical_instance(instance_home: &Path) -> Result<String> {
    let absolute = std::path::absolute(instance_home).with_context(|| {
        format!(
            "resolve background-job instance {}",
            instance_home.display()
        )
    })?;
    let path = match absolute.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == ErrorKind::NotFound => absolute,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "canonicalize background-job instance {}",
                    absolute.display()
                )
            });
        }
    };
    let instance = path.to_string_lossy().into_owned();
    #[cfg(windows)]
    let instance = instance.replace('\\', "/").to_ascii_lowercase();
    Ok(instance)
}

fn request_binding_sha256(command: &str, label: &str, instance: &str) -> Result<String> {
    let canonical = serde_json::to_vec(&BgJobRequestBinding {
        action: BG_JOB_ACTION,
        command,
        label,
        instance,
    })
    .context("serialize canonical background-job request binding")?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn interactive_confirm_strategy() -> ConfirmStrategy {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        ConfirmStrategy::Tty
    } else {
        ConfirmStrategy::FailClosed
    }
}

fn jobs_daemon_is_live() -> Result<bool> {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))
        .map(|pid| pid.is_some())
}

fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes)
        .map_err(|error| anyhow::anyhow!("background job id RNG unavailable: {error}"))
}

fn reserve_bg_job_log(
    bgjobs_dir: &Path,
    label: &str,
    now_unix: u64,
    random: &mut dyn FnMut(&mut [u8]) -> Result<()>,
) -> Result<(crate::daemon::bg_jobs::BgJobId, PathBuf)> {
    for _ in 0..BG_ID_RESERVATION_ATTEMPTS {
        let mut nonce = [0_u8; BG_ID_RANDOM_BYTES];
        random(&mut nonce)?;
        let id =
            crate::daemon::bg_jobs::BgJobId(format!("{label}-{now_unix}-{}", hex::encode(nonce)));
        let log = bgjobs_dir.join(format!("{}.log", id.as_str()));
        match crate::util::atomic_write::write_private_create_new(&log, b"") {
            Ok(()) => return Ok((id, log)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reserve background job log {}", log.display()));
            }
        }
    }
    anyhow::bail!(
        "could not reserve a unique background job id after {BG_ID_RESERVATION_ATTEMPTS} attempts"
    )
}

fn spawn_detached(program: &str, args: &[String]) -> std::io::Result<u32> {
    std::process::Command::new(program)
        .args(args)
        .spawn()
        .map(|child| child.id())
}

struct BgJobPermissionContext<'a> {
    policy: crate::permissions::AutonomyPolicySnapshot,
    confirm: ConfirmStrategy,
    preconfirmed_source: Option<&'static str>,
    audit_sink: PermissionAuditSink<'a>,
    audit_required: bool,
}

async fn execute_bg_job_with(
    request: &BgJobRequest,
    permission: BgJobPermissionContext<'_>,
    bgjobs_dir: &Path,
    random: &mut dyn FnMut(&mut [u8]) -> Result<()>,
    spawn: impl FnOnce(&str, &[String]) -> std::io::Result<u32>,
) -> Result<BgJobReceipt> {
    let mut gate = Gate::for_policy(permission.policy).with_confirm(permission.confirm);
    if let Some(source) = permission.preconfirmed_source {
        gate = gate.with_preconfirmed_confirmation(source);
    }
    gate.check_with_audit_sink(
        &Action::ExecArbitrary,
        permission.audit_sink,
        permission.audit_required,
        Some(&request.request_binding_sha256),
    )
    .await
    .context("background job permission gate denied the request")?;

    std::fs::create_dir_all(bgjobs_dir)
        .with_context(|| format!("create background jobs directory {}", bgjobs_dir.display()))?;
    let (id, log) = reserve_bg_job_log(
        bgjobs_dir,
        &request.label,
        crate::time::now_unix_secs(),
        random,
    )?;
    let exit = bgjobs_dir.join(format!("{}.exit", id.as_str()));
    let (program, wrapper_args) = bg_wrapper_argv(&request.command, &log, &exit);
    let pid = match spawn(&program, &wrapper_args) {
        Ok(pid) => pid,
        Err(spawn_error) => {
            if let Err(cleanup_error) = std::fs::remove_file(&log) {
                anyhow::bail!(
                    "spawn detached job via `{program}` failed: {spawn_error}; cleanup of reserved log {} also failed: {cleanup_error}",
                    log.display()
                );
            }
            return Err(spawn_error).with_context(|| format!("spawn detached job via `{program}`"));
        }
    };

    Ok(BgJobReceipt {
        action: BG_JOB_ACTION.to_owned(),
        started: true,
        id: id.as_str().to_owned(),
        pid,
        log_path: log.display().to_string(),
        request_binding_sha256: request.request_binding_sha256.clone(),
    })
}

async fn approve_bg_job(command: &str, label: &str, output: &OutputFormat) -> Result<()> {
    anyhow::ensure!(
        matches!(output, OutputFormat::Json | OutputFormat::Jsonl),
        "--approve-run is an internal structured GUI handshake and requires --output json"
    );
    let home = FreedomConfig::default_neoth_home();
    let request = BgJobRequest::new(command, label, &home)?;
    let cfg = FreedomConfig::load_from_default_path_or_default()
        .context("load existing freedom.yaml for background job approval policy")?;
    ensure_bg_approval_policy(&cfg.autonomy_policy())?;
    let daemon_live = jobs_daemon_is_live()?;
    anyhow::ensure!(
        daemon_live,
        "GUI background-job confirmation requires a running NEOTH daemon to mint a single-use request-bound token"
    );
    let token =
        crate::daemon::audit_rpc::mint_jobs_run_token(&home, &request.request_binding_sha256)
            .await
            .context("daemon refused the request-bound GUI background-job approval token")?;
    let receipt = BgRunApprovalReceipt {
        action: "jobs_approve_run".to_owned(),
        approved: true,
        request_binding_sha256: request.request_binding_sha256,
        token,
    };
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

/// The GUI token is operator authority only for a canonical `Confirm`
/// decision. A static policy denial remains final; same-UID processes are
/// already inside the operator boundary because they can edit freedom.yaml and
/// read the audit-RPC credential, but they cannot turn Custom/Deny into Allow
/// through this ceremony.
fn ensure_bg_approval_policy(policy: &crate::permissions::AutonomyPolicySnapshot) -> Result<()> {
    if let Decision::Deny(reason) = evaluate(&Action::ExecArbitrary, policy) {
        anyhow::bail!("background job denied by current autonomy policy: {reason}");
    }
    Ok(())
}

/// ODY-07b — spawn `command` as a detached background job. Writes the bg_jobs
/// on-disk markers (`<id>.log` + `<id>.exit`) the daemon's bg_monitor watches.
/// The `std::process::Child` handle is dropped immediately — dropping it does
/// NOT kill the process, so the job runs detached and survives this CLI exit.
async fn run_bg_job(
    command: &str,
    label: &str,
    gui_approval_token: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let request = BgJobRequest::new(command, label, &home)?;
    let cfg = FreedomConfig::load_from_default_path_or_default()
        .context("load existing freedom.yaml for background job permission policy")?;
    let bgjobs_dir = home.join("bgjobs");
    let daemon_live = jobs_daemon_is_live()?;
    // Arbitrary detached execution is never a best-effort-audit action. The
    // permission decision must be durably appended before the subprocess can
    // start, independently of the operator's general one-shot audit posture.
    // A GUI approval additionally has its own mandatory mint audit in the
    // daemon; this run audit binds the consumed capability to the side effect.
    let audit_required = BG_JOB_AUDIT_REQUIRED;
    crate::daemon::audit_rpc::enforce_required_audit(audit_required, daemon_live, &home)?;
    let preconfirmed_source = match gui_approval_token {
        Some(token) => {
            anyhow::ensure!(
                daemon_live,
                "GUI background-job approval token requires the live daemon that minted it"
            );
            anyhow::ensure!(
                crate::daemon::audit_rpc::consume_jobs_run_token(
                    &home,
                    token,
                    &request.request_binding_sha256,
                )
                .await,
                "GUI background-job approval token is invalid, expired, replayed, or bound to a different request"
            );
            Some("gui_request_bound_token")
        }
        None => None,
    };
    let confirm = if preconfirmed_source.is_some() {
        ConfirmStrategy::FailClosed
    } else {
        interactive_confirm_strategy()
    };
    let mut random = fill_os_random;

    let receipt = if daemon_live {
        execute_bg_job_with(
            &request,
            BgJobPermissionContext {
                policy: cfg.autonomy_policy(),
                confirm,
                preconfirmed_source,
                audit_sink: PermissionAuditSink::DaemonRpc(&home),
                audit_required,
            },
            &bgjobs_dir,
            &mut random,
            spawn_detached,
        )
        .await?
    } else {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir)
            .context("required permission audit WAL directory could not be created")?;
        let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "jobs-run");
        let (writer, join) = crate::wal::spawn_for_home(segment, home.clone()).with_context(|| {
            "refusing un-audited background job: mandatory standalone WAL writer could not be opened"
        })?;
        let result = execute_bg_job_with(
            &request,
            BgJobPermissionContext {
                policy: cfg.autonomy_policy(),
                confirm,
                preconfirmed_source,
                audit_sink: PermissionAuditSink::Writer(&writer),
                audit_required,
            },
            &bgjobs_dir,
            &mut random,
            spawn_detached,
        )
        .await;
        drop(writer);
        join.await
            .context("mandatory background-job audit WAL writer task failed")?;
        result?
    };

    debug_assert!(receipt.is_bound_to(&request));

    // I13 — typed ack so the GUI's fail-closed mutation path can verify
    // the spawn instead of trusting exit-0 (R4-05 dead-button rule).
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    println!(
        "started background job `{}` (pid {})",
        receipt.id, receipt.pid
    );
    println!("  log   : {}", receipt.log_path);
    println!("  binding: {}", receipt.request_binding_sha256);
    println!("  status: `neoth jobs --bg` (a running daemon's bg-monitor auto-tracks completion)");
    Ok(())
}

/// Pure listing core: scan `bgjobs_dir` for `<id>.log` files and pair each with
/// its `<id>.exit` status. A genuinely absent registry is empty; directory,
/// entry, file-type, read, and parse errors from an existing registry are
/// surfaced rather than misreported as a healthy empty/running state.
fn collect_bg_rows(bgjobs_dir: &Path) -> Result<Vec<(String, String, Option<i32>)>> {
    let mut rows: Vec<(String, String, Option<i32>)> = Vec::new();
    let rd = match std::fs::read_dir(bgjobs_dir) {
        Ok(rd) => rd,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(rows),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("read background jobs directory {}", bgjobs_dir.display())
            });
        }
    };
    for entry in rd {
        let e = entry.with_context(|| {
            format!(
                "read an entry from background jobs directory {}",
                bgjobs_dir.display()
            )
        })?;
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("log") {
            continue;
        }
        anyhow::ensure!(
            e.file_type()
                .with_context(|| format!("inspect background job log {}", p.display()))?
                .is_file(),
            "background job log is not a regular file: {}",
            p.display()
        );
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("background job log has a non-UTF-8 id: {}", p.display()))?;
        let exit = bgjobs_dir.join(format!("{stem}.exit"));
        let (state, code) = match read_job_status_for_listing(&exit)? {
            crate::daemon::bg_jobs::BgJobStatus::Running => ("running".to_string(), None),
            crate::daemon::bg_jobs::BgJobStatus::Completed { code } => {
                ("completed".to_string(), code)
            }
        };
        rows.push((stem.to_string(), state, code));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows)
}

fn read_job_status_for_listing(exit: &Path) -> Result<crate::daemon::bg_jobs::BgJobStatus> {
    let raw = match std::fs::read_to_string(exit) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(crate::daemon::bg_jobs::BgJobStatus::Running);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read background job exit marker {}", exit.display()));
        }
    };
    let code = raw.trim().parse::<i32>().with_context(|| {
        format!(
            "parse background job exit marker {} as an exit code",
            exit.display()
        )
    })?;
    Ok(crate::daemon::bg_jobs::BgJobStatus::Completed { code: Some(code) })
}

fn list_bg_jobs(output: &OutputFormat) -> Result<()> {
    let bgjobs_dir = FreedomConfig::default_neoth_home().join("bgjobs");
    let rows = collect_bg_rows(&bgjobs_dir)?;
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
                    code.map(|c| c.to_string())
                        .unwrap_or_else(|| "-".to_string()),
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
    use crate::permissions::{
        ActionKind, AutonomyLevel, AutonomyPolicySnapshot, CustomAutonomyConfig, CustomDecision,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn make_job(id: &str, prompt: &str) -> crate::cron::schema::Job {
        crate::cron::schema::Job {
            id: id.into(),
            name: format!("job-{id}"),
            enabled: true,
            schedule: Schedule {
                // Every day at 07:00 UTC — yields a definite "next 3 fires".
                cron: "0 7 * * *".into(),
                tz: None,
                ..Default::default()
            },
            prompt: prompt.into(),
            timeout_seconds: 600,
            delivery: None,
            execution: Default::default(),
            depends_on: vec![],
        }
    }

    fn level_policy(level: AutonomyLevel) -> AutonomyPolicySnapshot {
        AutonomyPolicySnapshot::new(level, &CustomAutonomyConfig::default())
    }

    fn test_request(home: &Path) -> BgJobRequest {
        BgJobRequest::new("echo exact-request", "Test Job", home).unwrap()
    }

    async fn execute_test_job(
        request: &BgJobRequest,
        policy: AutonomyPolicySnapshot,
        confirm: ConfirmStrategy,
        sink: PermissionAuditSink<'_>,
        audit_required: bool,
        bgjobs_dir: &Path,
        spawned: Arc<AtomicBool>,
    ) -> Result<BgJobReceipt> {
        let mut nonce = 1_u8;
        let mut random = move |bytes: &mut [u8]| {
            bytes.fill(nonce);
            nonce = nonce.wrapping_add(1);
            Ok(())
        };
        execute_bg_job_with(
            request,
            BgJobPermissionContext {
                policy,
                confirm,
                preconfirmed_source: None,
                audit_sink: sink,
                audit_required,
            },
            bgjobs_dir,
            &mut random,
            move |_, _| {
                spawned.store(true, Ordering::SeqCst);
                Ok(4_242)
            },
        )
        .await
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
        assert!(
            joined.contains("j.exit"),
            "must write the exit marker: {joined}"
        );
        if cfg!(target_os = "windows") {
            assert_eq!(program, "cmd");
            assert!(
                joined.contains("!ERRORLEVEL!"),
                "windows needs delayed-expansion exit code: {joined}"
            );
        } else {
            assert_eq!(program, "sh");
            assert!(
                joined.contains("$?"),
                "unix captures $? as the exit code: {joined}"
            );
        }
    }

    #[test]
    fn ody07b_sanitise_label_keeps_safe_chars_and_defaults_empty() {
        assert_eq!(super::sanitise_label("build-1_x"), "build-1_x");
        assert_eq!(super::sanitise_label("a b/c.d"), "a-b-c-d");
        assert_eq!(super::sanitise_label("UPPER"), "upper");
        assert_eq!(super::sanitise_label(""), "job");
        assert_eq!(super::sanitise_label("///"), "---");
    }

    #[test]
    fn bg_request_rejects_unbounded_command_and_label() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            BgJobRequest::new(&"x".repeat(BG_COMMAND_MAX_BYTES + 1), "job", home.path()).is_err()
        );
        assert!(
            BgJobRequest::new("echo ok", &"x".repeat(BG_LABEL_MAX_BYTES + 1), home.path()).is_err()
        );
    }

    #[test]
    fn bg_gui_approval_honours_live_custom_deny() {
        let mut deny = CustomAutonomyConfig::default();
        deny.overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Deny);
        assert!(
            ensure_bg_approval_policy(&AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &deny,))
                .is_err()
        );

        let mut confirm = CustomAutonomyConfig::default();
        confirm
            .overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Confirm);
        ensure_bg_approval_policy(&AutonomyPolicySnapshot::new(
            AutonomyLevel::Custom,
            &confirm,
        ))
        .unwrap();
    }

    #[tokio::test]
    async fn bg_full_policy_allows_before_spawn() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let spawned = Arc::new(AtomicBool::new(false));
        let receipt = execute_test_job(
            &request,
            level_policy(AutonomyLevel::Full),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("bgjobs"),
            Arc::clone(&spawned),
        )
        .await
        .unwrap();
        assert!(spawned.load(Ordering::SeqCst));
        assert!(receipt.is_bound_to(&request));
    }

    #[tokio::test]
    async fn bg_strict_policy_denies_without_spawning() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let spawned = Arc::new(AtomicBool::new(false));
        let result = execute_test_job(
            &request,
            level_policy(AutonomyLevel::Strict),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("bgjobs"),
            Arc::clone(&spawned),
        )
        .await;
        assert!(result.is_err());
        assert!(!spawned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn bg_custom_policy_honours_allow_and_deny() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());

        let mut allow = CustomAutonomyConfig::default();
        allow
            .overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Allow);
        let allow_spawned = Arc::new(AtomicBool::new(false));
        execute_test_job(
            &request,
            AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &allow),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("allow"),
            Arc::clone(&allow_spawned),
        )
        .await
        .unwrap();
        assert!(allow_spawned.load(Ordering::SeqCst));

        let mut deny = CustomAutonomyConfig::default();
        deny.overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Deny);
        let deny_spawned = Arc::new(AtomicBool::new(false));
        let result = execute_test_job(
            &request,
            AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &deny),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("deny"),
            Arc::clone(&deny_spawned),
        )
        .await;
        assert!(result.is_err());
        assert!(!deny_spawned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn bg_confirm_fails_closed_without_interactive_confirmation() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let spawned = Arc::new(AtomicBool::new(false));
        let result = execute_test_job(
            &request,
            level_policy(AutonomyLevel::Standard),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("bgjobs"),
            Arc::clone(&spawned),
        )
        .await;
        assert!(result.is_err());
        assert!(!spawned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn bg_request_bound_gui_confirmation_upgrades_confirm_but_not_deny() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let mut random = |bytes: &mut [u8]| {
            bytes.fill(7);
            Ok(())
        };
        let confirmed_spawned = Arc::new(AtomicBool::new(false));
        execute_bg_job_with(
            &request,
            BgJobPermissionContext {
                policy: level_policy(AutonomyLevel::Strict),
                confirm: ConfirmStrategy::FailClosed,
                preconfirmed_source: Some("gui_request_bound_token"),
                audit_sink: PermissionAuditSink::None,
                audit_required: false,
            },
            &home.path().join("confirmed"),
            &mut random,
            {
                let spawned = Arc::clone(&confirmed_spawned);
                move |_, _| {
                    spawned.store(true, Ordering::SeqCst);
                    Ok(9)
                }
            },
        )
        .await
        .unwrap();
        assert!(confirmed_spawned.load(Ordering::SeqCst));

        let mut deny = CustomAutonomyConfig::default();
        deny.overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Deny);
        let denied_spawned = Arc::new(AtomicBool::new(false));
        let result = execute_bg_job_with(
            &request,
            BgJobPermissionContext {
                policy: AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &deny),
                confirm: ConfirmStrategy::FailClosed,
                preconfirmed_source: Some("gui_request_bound_token"),
                audit_sink: PermissionAuditSink::None,
                audit_required: false,
            },
            &home.path().join("denied"),
            &mut random,
            {
                let spawned = Arc::clone(&denied_spawned);
                move |_, _| {
                    spawned.store(true, Ordering::SeqCst);
                    Ok(10)
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!denied_spawned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn bg_required_audit_failure_prevents_spawn() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let spawned = Arc::new(AtomicBool::new(false));
        let bgjobs = home.path().join("bgjobs");
        let result = execute_test_job(
            &request,
            level_policy(AutonomyLevel::Full),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::Fail("injected audit failure"),
            true,
            &bgjobs,
            Arc::clone(&spawned),
        )
        .await;
        assert!(result.is_err());
        assert!(!spawned.load(Ordering::SeqCst));
        assert!(!bgjobs.exists(), "gate must fail before registry mutation");
    }

    #[tokio::test]
    async fn bg_json_receipt_binding_rejects_request_tampering() {
        let home = tempfile::tempdir().unwrap();
        let request = test_request(home.path());
        let receipt = execute_test_job(
            &request,
            level_policy(AutonomyLevel::Full),
            ConfirmStrategy::FailClosed,
            PermissionAuditSink::None,
            false,
            &home.path().join("bgjobs"),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: BgJobReceipt = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.is_bound_to(&request));

        let mut tampered = request.clone();
        tampered.command.push_str(" && echo tampered");
        assert!(!decoded.is_bound_to(&tampered));
    }

    #[test]
    fn bg_id_reservation_retries_collision_and_stays_unique() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path();
        let zero_id = format!("job-42-{}", hex::encode([0_u8; BG_ID_RANDOM_BYTES]));
        std::fs::write(dir.join(format!("{zero_id}.log")), b"existing").unwrap();

        let mut call = 0_u8;
        let mut random = |bytes: &mut [u8]| {
            bytes.fill(call);
            call = call.wrapping_add(1);
            Ok(())
        };
        let (first, _) = reserve_bg_job_log(dir, "job", 42, &mut random).unwrap();
        let (second, _) = reserve_bg_job_log(dir, "job", 42, &mut random).unwrap();
        assert_ne!(first, second);
        assert_ne!(first.as_str(), zero_id);
        assert_eq!(call, 3, "collision consumes one retry, then two claims");
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
        let rows = super::collect_bg_rows(dir).unwrap();
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
        let rows = super::collect_bg_rows(Path::new("/no/such/bgjobs/dir/xyz")).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn bg_listing_surfaces_malformed_exit_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("broken.log"), b"out").unwrap();
        std::fs::write(tmp.path().join("broken.exit"), b"not-an-exit-code").unwrap();
        let error = super::collect_bg_rows(tmp.path()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("broken.exit"), "got: {message}");
        assert!(message.contains("exit code"), "got: {message}");
    }
}
