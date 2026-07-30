//! `neoth cron` — operator CRUD for scheduled jobs + one-shot fire.
//!
//! Subcommands:
//! - `run <id>`     Fire one job NOW, out-of-band (refused while daemon live).
//! - `add`          Append a new job to jobs.yaml (HERMES-01).
//! - `edit <id>`    Update fields of an existing job by id (HERMES-01).
//! - `remove <id>`  Delete a job by id (HERMES-01).
//! - `list`         Print all jobs with role, schedule, and delivery channel (HERMES-01).
//!
//! All mutating commands call `Job::validate()` (JV-PRO-01) before saving and
//! surface `preflight()` warnings (JV-PRO-04). `add` also surfaces collision
//! warnings via `schedule_collides()` (JV-PRO-09). Both `add` and `edit` call
//! `JobsFile::validate_waves()` (JV-PRO-03) to reject cyclic/unknown depends_on
//! before saving. Mutations use a process-local mutex plus an OS advisory lock
//! and commit atomically, so concurrent CLI writers cannot lose updates.
//!
//! Refuses while `neoth serve` is live for `run` only — CRUD operations on
//! jobs.yaml are safe at any time (the scheduler validates and live-reloads a
//! complete generation on its next tick).

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::inference::InferenceProvider;
use crate::cron::schema::{
    Delivery, DeliveryMode, ExecutionPolicy, Job, JobsFile, ProviderTarget, Schedule,
    classify_role, preflight, schedule_collides,
};
use crate::cron::state::RuntimeState;

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "snake_case")]
pub enum DeliveryModeArg {
    Announce,
    Webhook,
    None,
}

impl From<DeliveryModeArg> for DeliveryMode {
    fn from(value: DeliveryModeArg) -> Self {
        match value {
            DeliveryModeArg::Announce => Self::Announce,
            DeliveryModeArg::Webhook => Self::Webhook,
            DeliveryModeArg::None => Self::None,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct CronArgs {
    #[command(subcommand)]
    pub action: CronAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CronAction {
    /// Fire one job by id immediately, out of band of the scheduler. Makes a
    /// real provider call and (if the job has a delivery channel) queues the
    /// result for the daemon's gated proactive dispatcher. Refused while
    /// `neoth serve` is running.
    Run {
        /// The job `id` from jobs.yaml.
        id: String,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Add a new job to jobs.yaml. Validates the schedule and delivery channel,
    /// then surfaces advisory warnings. Rejects duplicate ids. HERMES-01 / JV-PRO-01/04/09.
    #[command(alias = "create")]
    Add {
        /// Unique job id (slug, no spaces).
        #[arg(long)]
        id: String,
        /// Human-readable job name.
        #[arg(long)]
        name: String,
        /// 5-field cron expression, e.g. "0 7 * * *".
        #[arg(long, conflicts_with_all = ["every", "at"])]
        cron: Option<String>,
        /// Fixed interval such as `30s`, `5m`, `2h`, `1d`, or raw seconds.
        #[arg(long, conflicts_with_all = ["cron", "at"])]
        every: Option<String>,
        /// One-shot RFC3339 timestamp, for example `2026-08-01T09:00:00Z`.
        #[arg(long, conflicts_with_all = ["cron", "every"])]
        at: Option<String>,
        /// Prompt sent to the configured provider when the job fires.
        #[arg(long)]
        prompt: String,
        /// IANA timezone, e.g. "Europe/Berlin". Defaults to UTC.
        #[arg(long)]
        tz: Option<String>,
        /// Delivery channel name ("telegram", "slack", …). The destination is
        /// read from the operator-owned channel routing configuration.
        #[arg(long)]
        channel: Option<String>,
        /// Explicit recipient/room/channel id. Must match operator routing.
        #[arg(long, requires = "channel")]
        recipient: Option<String>,
        /// Explicit account selector (rejected if the adapter lacks a wire).
        #[arg(long)]
        account: Option<String>,
        /// Explicit thread/topic selector (rejected if the adapter lacks a wire).
        #[arg(long)]
        thread: Option<String>,
        /// Delivery mode. Inferred as announce for --channel and webhook for
        /// --webhook-url; omitted with no target means none.
        #[arg(long, value_enum)]
        delivery_mode: Option<DeliveryModeArg>,
        /// Exact URL of a registered signed endpoint in freedom.yaml.
        #[arg(long)]
        webhook_url: Option<String>,
        /// Record delivery failure without failing an otherwise successful job.
        #[arg(long)]
        best_effort: bool,
        /// Per-job provider slug (e.g. openai_api, anthropic_api, local_qwen).
        #[arg(long)]
        provider: Option<String>,
        /// Final wire model for this job.
        #[arg(long)]
        model: Option<String>,
        /// Built-in profile preset.
        #[arg(long)]
        profile: Option<String>,
        /// Exact thinking-token budget; unsupported providers fail before spend.
        #[arg(long)]
        thinking_budget: Option<u32>,
        /// 429 fallback as PROVIDER or PROVIDER:MODEL. Repeat for ordering.
        #[arg(long = "fallback")]
        fallback: Vec<String>,
        /// Enabled MCP server id available to the job. Repeat as needed.
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        /// Exact MCP tool name. Requires at least one --capability.
        #[arg(long = "tool")]
        tools: Vec<String>,
        /// Successful prerequisite job id. Repeat to build a dependency wave.
        #[arg(long = "depends-on")]
        depends_on: Vec<String>,
        /// Timeout in seconds. Defaults to 600.
        #[arg(long)]
        timeout: Option<u32>,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Edit an existing job by id. Only supplied flags are updated.
    /// Validates the result and surfaces warnings before saving. HERMES-01.
    #[command(alias = "update")]
    Edit {
        /// The job `id` to modify.
        id: String,
        /// Replace the job name.
        #[arg(long)]
        name: Option<String>,
        /// Replace the cron expression.
        #[arg(long)]
        cron: Option<String>,
        #[arg(long, conflicts_with_all = ["cron", "at"])]
        every: Option<String>,
        #[arg(long, conflicts_with_all = ["cron", "every"])]
        at: Option<String>,
        /// Replace the prompt.
        #[arg(long)]
        prompt: Option<String>,
        /// Replace the timezone.
        #[arg(long, conflicts_with = "clear_timezone")]
        tz: Option<String>,
        /// Clear the timezone and use UTC.
        #[arg(long)]
        clear_timezone: bool,
        /// Replace the delivery channel. The destination is read from the
        /// operator-owned channel routing configuration.
        #[arg(long)]
        channel: Option<String>,
        #[arg(long)]
        recipient: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        thread: Option<String>,
        #[arg(long, value_enum)]
        delivery_mode: Option<DeliveryModeArg>,
        #[arg(long)]
        webhook_url: Option<String>,
        #[arg(long)]
        best_effort: Option<bool>,
        /// Clear the complete delivery target before applying supplied fields.
        #[arg(long)]
        clear_delivery: bool,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        thinking_budget: Option<u32>,
        #[arg(long = "fallback")]
        fallback: Vec<String>,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long = "tool")]
        tools: Vec<String>,
        /// Clear provider/model/profile/thinking/fallback/MCP execution policy
        /// before applying supplied execution fields.
        #[arg(long)]
        clear_execution: bool,
        #[arg(long = "depends-on")]
        depends_on: Vec<String>,
        /// Clear all dependency edges before applying --depends-on values.
        #[arg(long)]
        clear_dependencies: bool,
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
    #[command(alias = "delete")]
    Remove {
        /// The job `id` to delete.
        id: String,
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Pause a job without deleting its configuration.
    Pause {
        id: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Resume a paused job. The live scheduler observes the atomic rewrite.
    Resume {
        id: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Show durable delivery correlation and final/queued status.
    Deliveries {
        /// Optional job id filter.
        #[arg(long)]
        job: Option<String>,
        /// Explicit NEOTH home. Defaults to the active instance home.
        #[arg(long)]
        home: Option<PathBuf>,
    },

    /// List all jobs with their schedule, role, and delivery. HERMES-01 / JV-PRO-05.
    List {
        /// Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Show a per-CronRole count summary (total, enabled, disabled breakdown). Calls classify_role on every job. JV-PRO-05.
    Status {
        /// Group counts by CronRole (enabled + disabled per role).
        #[arg(long)]
        by_role: bool,
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
            every,
            at,
            prompt,
            tz,
            channel,
            recipient,
            account,
            thread,
            delivery_mode,
            webhook_url,
            best_effort,
            provider,
            model,
            profile,
            thinking_budget,
            fallback,
            capabilities,
            tools,
            depends_on,
            timeout,
            file,
        } => {
            let path = jobs_path(file.clone());
            let ack_id = id.clone();
            cron_add_full(
                CronCreate {
                    id,
                    name,
                    schedule: build_schedule(cron, every, at, tz)?,
                    prompt,
                    delivery: build_delivery(
                        delivery_mode,
                        channel,
                        recipient,
                        account,
                        thread,
                        webhook_url,
                        best_effort,
                    )?,
                    execution: build_execution(
                        provider,
                        model,
                        profile,
                        thinking_budget,
                        fallback,
                        capabilities,
                        tools,
                    )?,
                    depends_on,
                    timeout_seconds: timeout.unwrap_or(600),
                },
                file,
            )?;
            emit_cron_mutation(
                output,
                "add",
                &ack_id,
                &format!("added job `{ack_id}` to {}", path.display()),
            );
            Ok(())
        }
        CronAction::Edit {
            id,
            name,
            cron,
            every,
            at,
            prompt,
            tz,
            clear_timezone,
            channel,
            recipient,
            account,
            thread,
            delivery_mode,
            webhook_url,
            best_effort,
            clear_delivery,
            provider,
            model,
            profile,
            thinking_budget,
            fallback,
            capabilities,
            tools,
            clear_execution,
            depends_on,
            clear_dependencies,
            timeout,
            enabled,
            file,
        } => {
            let path = jobs_path(file.clone());
            let ack_id = id.clone();
            cron_edit_full(
                CronEditPatch {
                    id,
                    name,
                    cron,
                    every,
                    at,
                    prompt,
                    tz,
                    clear_timezone,
                    channel,
                    recipient,
                    account,
                    thread,
                    delivery_mode,
                    webhook_url,
                    best_effort,
                    clear_delivery,
                    provider,
                    model,
                    profile,
                    thinking_budget,
                    fallback,
                    capabilities,
                    tools,
                    clear_execution,
                    depends_on,
                    clear_dependencies,
                    timeout,
                    enabled,
                },
                file,
            )?;
            emit_cron_mutation(
                output,
                "edit",
                &ack_id,
                &format!("updated job `{ack_id}` in {}", path.display()),
            );
            Ok(())
        }
        CronAction::Remove { id, file } => {
            let path = jobs_path(file.clone());
            cron_remove(id.clone(), file)?;
            emit_cron_mutation(
                output,
                "remove",
                &id,
                &format!("removed job `{id}` from {}", path.display()),
            );
            Ok(())
        }
        CronAction::Pause { id, file } => {
            let path = jobs_path(file.clone());
            cron_set_enabled(id.clone(), false, file)?;
            emit_cron_mutation(
                output,
                "pause",
                &id,
                &format!("paused job `{id}` in {}", path.display()),
            );
            Ok(())
        }
        CronAction::Resume { id, file } => {
            let path = jobs_path(file.clone());
            cron_set_enabled(id.clone(), true, file)?;
            emit_cron_mutation(
                output,
                "resume",
                &id,
                &format!("resumed job `{id}` in {}", path.display()),
            );
            Ok(())
        }
        CronAction::Deliveries { job, home } => cron_deliveries(job, home, output),
        CronAction::List { file } => cron_list(file, output),
        CronAction::Status { by_role, file } => cron_status(by_role, file, output),
    }
}

fn emit_cron_mutation(output: OutputFormat, action: &str, id: &str, human: &str) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({"ok": true, "action": action, "id": id})
            );
        }
        OutputFormat::Table => println!("{human}"),
    }
}

#[derive(Debug)]
struct CronCreate {
    id: String,
    name: String,
    schedule: Schedule,
    prompt: String,
    delivery: Option<Delivery>,
    execution: ExecutionPolicy,
    depends_on: Vec<String>,
    timeout_seconds: u32,
}

#[derive(Debug)]
struct CronEditPatch {
    id: String,
    name: Option<String>,
    cron: Option<String>,
    every: Option<String>,
    at: Option<String>,
    prompt: Option<String>,
    tz: Option<String>,
    clear_timezone: bool,
    channel: Option<String>,
    recipient: Option<String>,
    account: Option<String>,
    thread: Option<String>,
    delivery_mode: Option<DeliveryModeArg>,
    webhook_url: Option<String>,
    best_effort: Option<bool>,
    clear_delivery: bool,
    provider: Option<String>,
    model: Option<String>,
    profile: Option<String>,
    thinking_budget: Option<u32>,
    fallback: Vec<String>,
    capabilities: Vec<String>,
    tools: Vec<String>,
    clear_execution: bool,
    depends_on: Vec<String>,
    clear_dependencies: bool,
    timeout: Option<u32>,
    enabled: Option<bool>,
}

// ── HERMES-01: CRUD helpers ───────────────────────────────────────────────────

/// Load jobs.yaml from disk, creating an empty v1 file if it does not exist.
fn load_or_create(path: &std::path::Path) -> Result<JobsFile> {
    if path.exists() {
        // Use blocking read here (CLI context, not inside an async runtime).
        let body =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        JobsFile::from_yaml_str(&body).with_context(|| format!("load {}", path.display()))
    } else {
        Ok(JobsFile::empty())
    }
}

/// Print pre-flight + collision warnings to stderr so they are visible even
/// when stdout is captured for JSON. Returns Ok(()) always.
fn print_warnings(warnings: &[String], label: &str) {
    for w in warnings {
        eprintln!("warn [{label}]: {w}");
    }
}

fn parse_interval(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("--every must not be empty");
    }
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&value[..value.len() - 1], 1_u64),
        Some(b'm') | Some(b'M') => (&value[..value.len() - 1], 60),
        Some(b'h') | Some(b'H') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') | Some(b'D') => (&value[..value.len() - 1], 24 * 60 * 60),
        _ => (value, 1),
    };
    let amount = digits
        .parse::<u64>()
        .with_context(|| format!("invalid --every interval `{value}`"))?;
    amount
        .checked_mul(multiplier)
        .with_context(|| format!("--every interval `{value}` is too large"))
}

fn build_schedule(
    cron: Option<String>,
    every: Option<String>,
    at: Option<String>,
    tz: Option<String>,
) -> Result<Schedule> {
    let every_seconds = every.as_deref().map(parse_interval).transpose()?;
    let at = at
        .as_deref()
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|value| value.with_timezone(&Utc))
                .with_context(|| format!("invalid RFC3339 --at timestamp `{value}`"))
        })
        .transpose()?;
    let schedule = Schedule {
        cron: cron.unwrap_or_default(),
        every_seconds,
        anchor_unix: None,
        at,
        tz: tz.filter(|value| !value.is_empty()),
    };
    schedule.validate()?;
    Ok(schedule)
}

#[allow(clippy::too_many_arguments)]
fn build_delivery(
    mode: Option<DeliveryModeArg>,
    channel: Option<String>,
    recipient: Option<String>,
    account: Option<String>,
    thread: Option<String>,
    webhook_url: Option<String>,
    best_effort: bool,
) -> Result<Option<Delivery>> {
    if mode.is_none()
        && channel.is_none()
        && recipient.is_none()
        && account.is_none()
        && thread.is_none()
        && webhook_url.is_none()
    {
        return Ok(None);
    }
    let mode = mode.map(DeliveryMode::from).unwrap_or_else(|| {
        if webhook_url.is_some() {
            DeliveryMode::Webhook
        } else {
            DeliveryMode::Announce
        }
    });
    Ok(Some(Delivery {
        mode,
        channel: channel.unwrap_or_default(),
        recipient,
        account,
        thread,
        webhook_url,
        best_effort,
    }))
}

fn parse_provider(value: &str, flag: &str) -> Result<InferenceProvider> {
    InferenceProvider::from_str(value).with_context(|| {
        format!(
            "unknown {flag} provider `{value}`; use a configured provider slug such as openai_api, anthropic_api, or local_ollama"
        )
    })
}

fn parse_fallback(value: String) -> Result<ProviderTarget> {
    let (provider, model) = value
        .split_once(':')
        .map_or((value.as_str(), None), |(provider, model)| {
            (provider, Some(model.to_string()))
        });
    Ok(ProviderTarget {
        provider: parse_provider(provider, "fallback")?,
        model,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_execution(
    provider: Option<String>,
    model: Option<String>,
    profile: Option<String>,
    thinking_budget: Option<u32>,
    fallback: Vec<String>,
    capabilities: Vec<String>,
    tools: Vec<String>,
) -> Result<ExecutionPolicy> {
    Ok(ExecutionPolicy {
        provider: provider
            .as_deref()
            .map(|value| parse_provider(value, "primary"))
            .transpose()?,
        model,
        profile,
        thinking_budget,
        fallback: fallback
            .into_iter()
            .map(parse_fallback)
            .collect::<Result<_>>()?,
        capabilities,
        tools,
    })
}

fn cron_add_full(create: CronCreate, file: Option<PathBuf>) -> Result<()> {
    let path = jobs_path(file);
    let id = create.id.clone();
    let job = Job {
        id: create.id,
        name: create.name,
        enabled: true,
        schedule: create.schedule,
        prompt: create.prompt,
        timeout_seconds: create.timeout_seconds,
        delivery: create.delivery,
        execution: create.execution,
        depends_on: create.depends_on,
    };

    job.validate()?;
    print_warnings(&preflight(&job), "preflight");
    JobsFile::modify_at_path(&path, |jf| {
        if jf.jobs.iter().any(|existing| existing.id == id) {
            anyhow::bail!("a job with id `{id}` already exists in {}", path.display());
        }
        print_warnings(&schedule_collides(&job.schedule, &jf.jobs, 48), "collision");
        jf.jobs.push(job);
        Ok(())
    })
    .with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

fn cron_edit_full(patch: CronEditPatch, file: Option<PathBuf>) -> Result<()> {
    let CronEditPatch {
        id,
        name,
        cron,
        every,
        at,
        prompt,
        tz,
        clear_timezone,
        channel,
        recipient,
        account,
        thread,
        delivery_mode,
        webhook_url,
        best_effort,
        clear_delivery,
        provider,
        model,
        profile,
        thinking_budget,
        fallback,
        capabilities,
        tools,
        clear_execution,
        depends_on,
        clear_dependencies,
        timeout,
        enabled,
    } = patch;
    let path = jobs_path(file);
    JobsFile::modify_at_path(&path, |jf| {
        let job = jf
            .jobs
            .iter_mut()
            .find(|job| job.id == id)
            .with_context(|| format!("no job with id `{id}` in {}", path.display()))?;

        if let Some(n) = name {
            job.name = n;
        }
        let replaces_schedule = cron.is_some() || every.is_some() || at.is_some();
        if replaces_schedule {
            job.schedule = build_schedule(cron, every, at, if clear_timezone { None } else { tz })?;
        } else if clear_timezone {
            job.schedule.tz = None;
        } else if let Some(tz) = tz {
            job.schedule.tz = (!tz.is_empty()).then_some(tz);
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

        let delivery_fields_supplied = delivery_mode.is_some()
            || channel.is_some()
            || recipient.is_some()
            || account.is_some()
            || thread.is_some()
            || webhook_url.is_some()
            || best_effort.is_some();
        if clear_delivery && !delivery_fields_supplied {
            job.delivery = None;
        } else if clear_delivery || delivery_fields_supplied {
            let current = (!clear_delivery).then(|| job.delivery.clone()).flatten();
            let inferred_mode = delivery_mode.map(DeliveryMode::from).unwrap_or_else(|| {
                if webhook_url.is_some() {
                    DeliveryMode::Webhook
                } else if channel.is_some() {
                    DeliveryMode::Announce
                } else {
                    current
                        .as_ref()
                        .map(|delivery| delivery.mode)
                        .unwrap_or(DeliveryMode::Announce)
                }
            });
            if inferred_mode == DeliveryMode::None {
                let mut none = Delivery::none();
                none.best_effort = best_effort.unwrap_or(false);
                job.delivery = Some(none);
            } else {
                job.delivery = Some(Delivery {
                    mode: inferred_mode,
                    channel: channel
                        .or_else(|| current.as_ref().map(|delivery| delivery.channel.clone()))
                        .unwrap_or_default(),
                    recipient: recipient.or_else(|| {
                        current
                            .as_ref()
                            .and_then(|delivery| delivery.recipient.clone())
                    }),
                    account: account.or_else(|| {
                        current
                            .as_ref()
                            .and_then(|delivery| delivery.account.clone())
                    }),
                    thread: thread.or_else(|| {
                        current
                            .as_ref()
                            .and_then(|delivery| delivery.thread.clone())
                    }),
                    webhook_url: webhook_url.or_else(|| {
                        current
                            .as_ref()
                            .and_then(|delivery| delivery.webhook_url.clone())
                    }),
                    best_effort: best_effort
                        .or_else(|| current.as_ref().map(|delivery| delivery.best_effort))
                        .unwrap_or(false),
                });
            }
        }

        if clear_execution {
            job.execution = ExecutionPolicy::default();
        }
        if let Some(provider) = provider {
            job.execution.provider = Some(parse_provider(&provider, "primary")?);
        }
        if let Some(model) = model {
            job.execution.model = (!model.is_empty()).then_some(model);
        }
        if let Some(profile) = profile {
            job.execution.profile = (!profile.is_empty()).then_some(profile);
        }
        if let Some(thinking_budget) = thinking_budget {
            job.execution.thinking_budget = Some(thinking_budget);
        }
        if !fallback.is_empty() {
            job.execution.fallback = fallback
                .into_iter()
                .map(parse_fallback)
                .collect::<Result<_>>()?;
        }
        if !capabilities.is_empty() {
            job.execution.capabilities = capabilities;
        }
        if !tools.is_empty() {
            job.execution.tools = tools;
        }
        if clear_dependencies {
            job.depends_on.clear();
        }
        if !depends_on.is_empty() {
            job.depends_on = depends_on;
        }

        job.validate()?;
        print_warnings(&preflight(job), "preflight");
        Ok(())
    })
    .with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

/// `neoth cron remove <id>` — delete a job by id. HERMES-01.
fn cron_remove(id: String, file: Option<PathBuf>) -> Result<()> {
    let path = jobs_path(file);
    JobsFile::modify_at_path(&path, |jf| {
        let before = jf.jobs.len();
        jf.jobs.retain(|job| job.id != id);
        if jf.jobs.len() == before {
            anyhow::bail!("no job with id `{id}` in {}", path.display());
        }
        Ok(())
    })
    .with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

fn cron_set_enabled(id: String, enabled: bool, file: Option<PathBuf>) -> Result<()> {
    let path = jobs_path(file);
    JobsFile::modify_at_path(&path, |jf| {
        let job = jf
            .jobs
            .iter_mut()
            .find(|job| job.id == id)
            .with_context(|| format!("no job with id `{id}` in {}", path.display()))?;
        job.enabled = enabled;
        job.validate()?;
        Ok(())
    })
    .with_context(|| format!("update {}", path.display()))?;
    Ok(())
}

fn cron_deliveries(
    job_filter: Option<String>,
    home: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let home = home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let state = RuntimeState::load(&home)
        .with_context(|| format!("load Cron runtime state from {}", home.display()))?;
    let records: Vec<_> = state
        .deliveries
        .values()
        .filter(|record| {
            job_filter
                .as_deref()
                .is_none_or(|job_id| record.job_id == job_id)
        })
        .collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        OutputFormat::Table => {
            if records.is_empty() {
                println!("no Cron delivery records in {}", home.display());
                return Ok(());
            }
            println!(
                "{:<18} {:<20} {:<10} {:<13} {:>8} UPDATED",
                "DELIVERY", "JOB", "MODE", "STATUS", "ATTEMPTS"
            );
            println!("{}", "-".repeat(100));
            for record in records {
                let short_id = record.delivery_id.get(..16).unwrap_or(&record.delivery_id);
                println!(
                    "{short_id:<18} {:<20} {:<10} {:<13} {:>8} {}{}",
                    record.job_id,
                    record.mode.as_str(),
                    record.status.as_str(),
                    record.attempts,
                    record.updated_at.to_rfc3339(),
                    record
                        .error
                        .as_deref()
                        .map(|error| format!(" error={error}"))
                        .unwrap_or_default()
                );
            }
        }
    }
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
                        "schedule": j.schedule,
                        "role": classify_role(j).to_string(),
                        "timeout_seconds": j.timeout_seconds,
                        "delivery": j.delivery,
                        "execution": j.execution,
                        "depends_on": j.depends_on,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            println!(
                "{:<20} {:<25} {:<22} {:<13} {:<9} DELIVERY",
                "ID", "NAME", "SCHEDULE", "ROLE", "ENABLED"
            );
            println!("{}", "-".repeat(100));
            for j in &jf.jobs {
                let role = classify_role(j);
                let delivery = j
                    .delivery
                    .as_ref()
                    .map(|delivery| match delivery.mode {
                        DeliveryMode::Announce => format!(
                            "announce:{}:{}",
                            delivery.channel,
                            delivery.recipient.as_deref().unwrap_or("configured-route")
                        ),
                        DeliveryMode::Webhook => "webhook:registered-url".to_string(),
                        DeliveryMode::None => "none".to_string(),
                    })
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<20} {:<25} {:<22} {:<13} {:<9} {}",
                    j.id,
                    j.name,
                    j.schedule.label(),
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
    // Refuse while the daemon owns scheduling so a manual invocation cannot
    // duplicate a job the daemon may fire concurrently.
    let home = FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
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
    let provider = crate::providers::fallback_chain_from_config(&config, &home, None)
        .await
        .context("construct the provider chain for the job")?;
    let default_model = crate::providers::provider_default_wire_model(provider.as_ref());

    // One-shot WAL writer (daemon confirmed not live above). It owns a unique
    // namespace so stale pidfile detection can never create a dual appender.
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "cron-run");
    let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.clone())
        .context("open a one-shot WAL writer")?;

    let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
        provider,
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            config.autonomy_policy(),
            Some(writer.clone()),
            config.tokens.max_per_request,
        )
        .with_usage_home(home.clone())
        .with_usage_automated(true),
        default_model,
        "cron.manual_run",
    );
    let result = crate::cron::runner::run_job_at(&home, &job, &provider, &writer).await;
    // `AuthorizedProvider` owns an authorizer which in turn owns a WAL handle.
    // Release it before joining the one-shot writer or the channel can never
    // close after a successful manual run.
    drop(provider);
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
                "delivery_queued": outcome.delivery_queued,
                "delivery_id": outcome.delivery_id,
                "delivery_status": outcome.delivery_status.map(|status| status.as_str()),
                "error": outcome.error,
            })
        ),
        OutputFormat::Table => {
            if outcome.success {
                println!(
                    "✓ job `{}` ran in {} ms ({} output bytes, delivery: {})",
                    job.id,
                    outcome.duration.as_millis(),
                    outcome.output_bytes,
                    outcome
                        .delivery_status
                        .map(|status| status.as_str())
                        .unwrap_or("none"),
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

/// `neoth cron status` — per-CronRole count summary. JV-PRO-05.
fn cron_status(by_role: bool, file: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    use std::collections::BTreeMap;
    let path = jobs_path(file);
    let jf = load_or_create(&path)?;

    let total = jf.jobs.len();
    let enabled = jf.jobs.iter().filter(|j| j.enabled).count();
    let disabled = total - enabled;

    if !by_role || total == 0 {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "total": total,
                        "enabled": enabled,
                        "disabled": disabled,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("cron status: {total} job(s) — {enabled} enabled, {disabled} disabled");
            }
        }
        return Ok(());
    }

    // Group by CronRole; BTreeMap keeps roles sorted for stable output.
    let mut by_role_map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for j in &jf.jobs {
        let role = classify_role(j).to_string();
        let entry = by_role_map.entry(role).or_insert((0, 0));
        if j.enabled {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let roles: Vec<_> = by_role_map
                .iter()
                .map(|(r, (en, dis))| serde_json::json!({ "role": r, "enabled": en, "disabled": dis }))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "total": total,
                    "enabled": enabled,
                    "disabled": disabled,
                    "by_role": roles,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# cron status — {total} job(s) ({enabled} enabled, {disabled} disabled)");
            println!();
            println!("{:<16} {:>8} {:>9}", "ROLE", "ENABLED", "DISABLED");
            println!("{}", "-".repeat(36));
            for (role, (en, dis)) in &by_role_map {
                println!("{role:<16} {en:>8} {dis:>9}");
            }
        }
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

    fn cron_create(id: &str, name: &str, cron: &str, prompt: &str) -> CronCreate {
        CronCreate {
            id: id.to_string(),
            name: name.to_string(),
            schedule: build_schedule(Some(cron.to_string()), None, None, None).expect("schedule"),
            prompt: prompt.to_string(),
            delivery: None,
            execution: ExecutionPolicy::default(),
            depends_on: Vec::new(),
            timeout_seconds: 600,
        }
    }

    #[test]
    fn add_then_list_roundtrip() {
        let (_dir, path) = temp_jobs_yaml("version: 1\njobs: []\n");

        cron_add_full(
            cron_create(
                "nightly-report",
                "Nightly Report",
                "0 23 * * *",
                "Summarise the day's activity in detail.",
            ),
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

        cron_add_full(
            cron_create("dup", "Dup", "0 6 * * *", "Do something useful here."),
            Some(path.clone()),
        )
        .expect("first add ok");

        let err = cron_add_full(
            cron_create("dup", "Dup Again", "0 6 * * *", "Do something useful here."),
            Some(path.clone()),
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("already exists"), "{err:#}");
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
        assert!(format!("{err:#}").contains("ghost"), "{err:#}");
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
        cron_edit_full(
            CronEditPatch {
                id: "editable".to_string(),
                name: Some("New Name".to_string()),
                cron: None,
                every: None,
                at: None,
                prompt: None,
                tz: None,
                clear_timezone: false,
                channel: None,
                recipient: None,
                account: None,
                thread: None,
                delivery_mode: None,
                webhook_url: None,
                best_effort: None,
                clear_delivery: false,
                provider: None,
                model: None,
                profile: None,
                thinking_budget: None,
                fallback: Vec::new(),
                capabilities: Vec::new(),
                tools: Vec::new(),
                clear_execution: false,
                depends_on: Vec::new(),
                clear_dependencies: false,
                timeout: Some(120),
                enabled: None,
            },
            Some(path.clone()),
        )
        .expect("edit ok");

        let jf = load_or_create(&path).expect("reload");
        assert_eq!(jf.jobs[0].name, "New Name");
        assert_eq!(jf.jobs[0].timeout_seconds, 120);
    }

    #[test]
    fn full_crud_roundtrip_preserves_and_can_clear_every_gold_contract_field() {
        let yaml = "\
version: 1
jobs:
  - id: prerequisite
    name: Prerequisite
    schedule:
      cron: \"0 6 * * *\"
    prompt: \"produce the prerequisite result\"
";
        let (_dir, path) = temp_jobs_yaml(yaml);
        let mut delivery = Delivery::new("telegram");
        delivery.recipient = Some("operator-room".into());
        delivery.account = Some("primary".into());
        delivery.thread = Some("daily".into());
        delivery.best_effort = true;
        let execution = ExecutionPolicy {
            provider: Some(InferenceProvider::LocalOllama),
            model: Some("qwen3:8b".into()),
            profile: Some("formal".into()),
            thinking_budget: Some(2_048),
            fallback: vec![ProviderTarget {
                provider: InferenceProvider::LocalQwen,
                model: Some("Qwen/Qwen3-4B".into()),
            }],
            capabilities: vec!["files".into()],
            tools: vec!["read_file".into()],
        };

        cron_add_full(
            CronCreate {
                id: "gold-contract".into(),
                name: "Gold Contract".into(),
                schedule: build_schedule(None, Some("5m".into()), None, None).unwrap(),
                prompt: "run the complete scheduled Gold contract".into(),
                delivery: Some(delivery),
                execution,
                depends_on: vec!["prerequisite".into()],
                timeout_seconds: 321,
            },
            Some(path.clone()),
        )
        .unwrap();

        let created = load_or_create(&path).unwrap();
        let job = created
            .jobs
            .iter()
            .find(|job| job.id == "gold-contract")
            .unwrap();
        assert_eq!(job.schedule.every_seconds, Some(300));
        assert_eq!(
            job.delivery.as_ref().unwrap().recipient.as_deref(),
            Some("operator-room")
        );
        assert_eq!(job.execution.provider, Some(InferenceProvider::LocalOllama));
        assert_eq!(job.execution.fallback.len(), 1);
        assert_eq!(job.execution.capabilities, ["files"]);
        assert_eq!(job.execution.tools, ["read_file"]);
        assert_eq!(job.depends_on, ["prerequisite"]);

        cron_set_enabled("gold-contract".into(), false, Some(path.clone())).unwrap();
        assert!(
            !load_or_create(&path)
                .unwrap()
                .jobs
                .iter()
                .find(|job| job.id == "gold-contract")
                .unwrap()
                .enabled
        );
        cron_set_enabled("gold-contract".into(), true, Some(path.clone())).unwrap();

        cron_edit_full(
            CronEditPatch {
                id: "gold-contract".into(),
                name: None,
                cron: None,
                every: None,
                at: Some("2099-01-02T03:04:05Z".into()),
                prompt: None,
                tz: None,
                clear_timezone: true,
                channel: None,
                recipient: None,
                account: None,
                thread: None,
                delivery_mode: None,
                webhook_url: None,
                best_effort: None,
                clear_delivery: true,
                provider: None,
                model: None,
                profile: None,
                thinking_budget: None,
                fallback: Vec::new(),
                capabilities: Vec::new(),
                tools: Vec::new(),
                clear_execution: true,
                depends_on: Vec::new(),
                clear_dependencies: true,
                timeout: None,
                enabled: None,
            },
            Some(path.clone()),
        )
        .unwrap();

        let edited = load_or_create(&path).unwrap();
        let job = edited
            .jobs
            .iter()
            .find(|job| job.id == "gold-contract")
            .unwrap();
        assert_eq!(
            job.schedule.at.unwrap().to_rfc3339(),
            "2099-01-02T03:04:05+00:00"
        );
        assert!(job.schedule.tz.is_none());
        assert!(job.delivery.is_none());
        assert_eq!(job.execution, ExecutionPolicy::default());
        assert!(job.depends_on.is_empty());
        assert!(
            job.enabled,
            "resume must persist before the edit generation"
        );

        cron_remove("gold-contract".into(), Some(path.clone())).unwrap();
        assert!(
            load_or_create(&path)
                .unwrap()
                .jobs
                .iter()
                .all(|job| job.id != "gold-contract")
        );
    }

    // ── JV-PRO-05 cron status ────────────────────────────────────────────────

    #[test]
    fn status_counts_flat_and_by_role() {
        let yaml = "\
version: 1
jobs:
  - id: morning-brief
    name: Morning Briefing
    enabled: true
    schedule:
      cron: \"0 7 * * *\"
    prompt: \"Daily morning briefing report\"
  - id: disk-check
    name: Disk Monitor
    enabled: true
    schedule:
      cron: \"*/15 * * * *\"
    prompt: \"Check disk usage percentage\"
  - id: disabled-task
    name: Disabled
    enabled: false
    schedule:
      cron: \"0 6 * * *\"
    prompt: \"do something else here\"
";
        let (_dir, path) = temp_jobs_yaml(yaml);
        // Flat totals (no --by-role): must succeed over all 3 jobs.
        cron_status(false, Some(path.clone()), OutputFormat::Json)
            .expect("status flat must succeed");
        // Grouped by role: classify_role is applied to every job.
        cron_status(true, Some(path.clone()), OutputFormat::Table)
            .expect("status by-role must succeed");
    }
}
