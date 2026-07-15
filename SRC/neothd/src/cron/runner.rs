//! Job runner — executes one job's prompt through the configured provider
//! and (optionally) delivers the result through a channel.
//!
//! Each invocation writes WAL events 0x40 (FIRED) → 0x41 (SUCCESS) / 0x42 (FAILED).
//!
//! Current execution contract:
//! - Jobs inherit the scheduler provider by default, or select an explicitly
//!   configured provider/model/fallback chain without borrowing credentials
//!   from a different vendor.
//! - Channel delivery is first persisted to the proactive queue and is later
//!   sent through the normal channel dispatcher.
//! - The provider deadline covers the initial call and, for briefing-class
//!   jobs only, one quality-gate regeneration. Provider failures and timeouts
//!   are terminal; rejected briefings are never queued for delivery.

use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::cron::briefing_prompt::render_briefing_system_prompt;
use crate::cron::schema::{CronRole, DeliveryMode, Job, classify_role};
use crate::cron::state::{DeliveryStatus, RuntimeState, target_hash};
use crate::hooks::schema::HookDef;
use crate::hooks::{HookStage, StageOutcome};
use crate::proactive::{ProactiveItem, ProactiveQueue};
use crate::profile::briefing_gate::should_emit_for_briefing;
use crate::profile::briefing_policy::{BriefingPolicy, EmitVerdict};
use crate::profile::estimators::ObservedTurn;
use crate::profile::snapshot::aggregate_and_persist;
use crate::providers::cost_authorization::AuthorizedProvider;
use crate::providers::{Provider, Request};
use crate::wal::events::{
    EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT, EVENT_TYPE_JOB_FAILED, EVENT_TYPE_JOB_FIRED,
    EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_JOB_SUCCESS, EVENT_TYPE_RAW_TEXT,
};
use crate::wal::{EventFlags, writer::WalWriterHandle};

type HookDispatcher = fn(HookStage, &str, &[HookDef]) -> Result<StageOutcome>;

pub struct RunOutcome {
    pub success: bool,
    pub duration: Duration,
    pub output_bytes: usize,
    /// True when a configured delivery was durably present in the proactive
    /// queue. This is not a claim that the asynchronous channel send completed.
    pub delivery_queued: bool,
    /// Stable id joining the provider run, proactive queue/webhook and durable
    /// Cron delivery ledger. None when delivery mode is absent/none.
    pub delivery_id: Option<String>,
    /// Truthful state at return time (`queued` is not `delivered`).
    pub delivery_status: Option<DeliveryStatus>,
    pub error: Option<String>,
}

enum JobProvider<'a> {
    Borrowed(&'a AuthorizedProvider),
    Owned(AuthorizedProvider),
}

impl JobProvider<'_> {
    fn get(&self) -> &AuthorizedProvider {
        match self {
            Self::Borrowed(provider) => provider,
            Self::Owned(provider) => provider,
        }
    }
}

struct CronCompletionDriver<'a> {
    provider: &'a dyn Provider,
    request: Request,
}

impl crate::mcp::dispatch_loop::CompletionDriver for CronCompletionDriver<'_> {
    fn complete<'a>(
        &'a mut self,
        prompt: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        let mut request = self.request.clone();
        request.prompt = prompt.to_string();
        Box::pin(async move {
            self.provider
                .complete(request)
                .await
                .map(|completion| completion.text)
        })
    }
}

pub async fn run_job(
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
) -> Result<RunOutcome> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    run_job_at(&home, job, provider, writer).await
}

/// Execute a job against one explicit daemon/CLI instance home.
///
/// The scheduler must use this entrypoint so hook policy and proactive
/// delivery state cannot leak to the process-global default home.
pub async fn run_job_at(
    home: &Path,
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
) -> Result<RunOutcome> {
    let config_path = home.join("freedom.yaml");
    let config = crate::config::FreedomConfig::load_from_path_or_default(&config_path)
        .with_context(|| format!("load Cron runtime config {}", config_path.display()))?;
    validate_delivery_target(home, job, &config).await?;
    let provider = resolve_job_provider(home, job, provider, writer, &config).await?;
    if job.execution.thinking_budget.is_some()
        && !provider.get().request_controls().supports_thinking_budget()
    {
        anyhow::bail!(
            "Cron job `{}` requests thinking_budget but provider `{}` cannot wire it",
            job.id,
            provider.get().name()
        );
    }
    let proactive_queue_path = home.join("proactive_queue.json");
    let hook_dir = home.join("hooks");
    run_job_with_paths(
        home,
        job,
        provider.get(),
        writer,
        &proactive_queue_path,
        &hook_dir,
        crate::hooks::run_stage,
        &config,
    )
    .await
}

async fn resolve_job_provider<'a>(
    home: &Path,
    job: &Job,
    default_provider: &'a AuthorizedProvider,
    writer: &WalWriterHandle,
    config: &crate::config::FreedomConfig,
) -> Result<JobProvider<'a>> {
    if job.execution.provider.is_none() && job.execution.fallback.is_empty() {
        return Ok(JobProvider::Borrowed(default_provider));
    }

    let mut scoped = config.clone();
    if let Some(primary) = job.execution.provider {
        let provider_kind = primary.to_provider_kind();
        if !crate::consent::is_granted(home, provider_kind) {
            anyhow::bail!(
                "Cron job `{}` cannot use cloud provider `{}` without an explicit consent grant",
                job.id,
                primary.as_str()
            );
        }
        let mut primary_slot = configured_provider_slot(config, primary);
        primary_slot.provider = Some(primary);
        primary_slot.model = job.execution.model.clone().or(primary_slot.model);

        scoped.provider_kind = Some(provider_kind);
        if config.provider_kind != Some(provider_kind) {
            scoped.provider_binary = None;
        }
        scoped.provider_model = primary_slot.model.clone();
        scoped.provider_key = primary_slot.key.clone();
        scoped.provider_endpoint = primary_slot.endpoint.clone();
        scoped.provider_region = primary_slot.region.clone();
        scoped.provider_api_version = primary_slot.api_version.clone();
        scoped.inference.mode = crate::config::inference::TopologyMode::Custom;
        scoped.inference.left = primary_slot;
    }
    if !job.execution.fallback.is_empty() {
        scoped.fallback.chain = job
            .execution
            .fallback
            .iter()
            .map(|target| {
                let mut slot = configured_provider_slot(config, target.provider);
                slot.provider = Some(target.provider);
                slot.model = target.model.clone().or(slot.model);
                slot.voice = None;
                slot
            })
            .collect();
        scoped.fallback.max_hops = u8::try_from(scoped.fallback.chain.len())
            .unwrap_or(u8::MAX)
            .max(1);
    }
    let raw = crate::providers::fallback_chain_from_config(&scoped, home, Some(writer.clone()))
        .await
        .with_context(|| format!("build provider policy for Cron job `{}`", job.id))?;
    let authorized = AuthorizedProvider::from_box(
        raw,
        crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            scoped.autonomy_policy(),
            Some(writer.clone()),
        )
        .with_usage_home(home.to_path_buf())
        .with_usage_automated(true),
        job.execution
            .model
            .clone()
            .or_else(|| scoped.provider_model.clone()),
        "cron.job",
    );
    Ok(JobProvider::Owned(authorized))
}

/// Resolve credentials only from a slot that explicitly names `provider`.
///
/// `FreedomConfig` contains several provider-shaped records. Cloning the
/// top-level record and changing only `provider_kind` would send the primary
/// vendor's key/endpoint to another vendor. This resolver keeps the selected
/// slot atomic: model, key, endpoint, region and API version always originate
/// from the same provider binding. An unconfigured provider receives an empty
/// binding and its adapter therefore fails closed instead of borrowing data.
fn configured_provider_slot(
    config: &crate::config::FreedomConfig,
    provider: crate::config::inference::InferenceProvider,
) -> crate::config::inference::HemisphereSlot {
    use crate::config::inference::{HemisphereRole, HemisphereSlot};

    let topology = &config.inference;
    let active_left = topology.slot_for(HemisphereRole::Left);
    if active_left.provider == Some(provider) {
        return active_left.clone();
    }

    for slot in [
        &topology.default_slot,
        &topology.left,
        &topology.right,
        &topology.cerebellum,
    ] {
        if slot.provider == Some(provider) {
            return slot.clone();
        }
    }
    for sub_slots in topology.hemisphere_sub_slots.values() {
        for slot in [&sub_slots.left, &sub_slots.right, &sub_slots.cerebellum] {
            if slot.provider == Some(provider) {
                return slot.clone();
            }
        }
    }
    if let Some(slot) = config
        .fallback
        .chain
        .iter()
        .find(|slot| slot.provider == Some(provider))
    {
        return slot.clone();
    }
    if config.provider_kind == Some(provider.to_provider_kind()) {
        return HemisphereSlot {
            provider: Some(provider),
            model: config.provider_model.clone(),
            key: config.provider_key.clone(),
            endpoint: config.provider_endpoint.clone(),
            region: config.provider_region.clone(),
            api_version: config.provider_api_version.clone(),
            voice: None,
        };
    }

    HemisphereSlot {
        provider: Some(provider),
        ..HemisphereSlot::default()
    }
}

async fn validate_delivery_target(
    home: &Path,
    job: &Job,
    config: &crate::config::FreedomConfig,
) -> Result<()> {
    let Some(delivery) = &job.delivery else {
        return Ok(());
    };
    match delivery.mode {
        DeliveryMode::None => Ok(()),
        DeliveryMode::Webhook => {
            let url = delivery
                .webhook_url
                .as_deref()
                .context("webhook delivery URL missing after schema validation")?;
            let endpoint = config
                .webhook_manager
                .endpoints
                .iter()
                .find(|endpoint| endpoint.url == url)
                .with_context(|| {
                    format!(
                        "Cron webhook target is not registered in freedom.yaml webhook_manager.endpoints"
                    )
                })?;
            crate::daemon::webhook_manager::validate_cron_endpoint(endpoint)
                .await
                .context("validate Cron webhook before provider spend")
        }
        DeliveryMode::Announce => {
            if delivery.account.is_some() {
                anyhow::bail!(
                    "delivery.account is not supported by the selected channel adapter; provider call blocked"
                );
            }
            if delivery.thread.is_some() {
                anyhow::bail!(
                    "delivery.thread is not supported by the selected channel adapter; provider call blocked"
                );
            }
            if delivery.channel.eq_ignore_ascii_case("keet") {
                if delivery.recipient.is_some() {
                    anyhow::bail!(
                        "Keet Cron delivery resolves its secret topic capability from credentials.yaml; do not copy it into jobs.yaml as delivery.recipient"
                    );
                }
                let credentials_path = home.join("credentials.yaml");
                let credentials = crate::config::credentials::Credentials::load_effective(
                    &credentials_path,
                    config.secrets_backend,
                )
                .with_context(|| {
                    format!("load Keet credentials from {}", credentials_path.display())
                })?;
                let bridge_url = credentials
                    .keet_bridge_url
                    .as_deref()
                    .context("Keet delivery requires keet_bridge_url")?;
                let topic = credentials
                    .keet_topic
                    .as_ref()
                    .context("Keet delivery requires keet_topic")?;
                let allowed_senders = credentials
                    .keet_allowed_senders
                    .as_deref()
                    .context("Keet delivery requires keet_allowed_senders")?;
                let bearer = credentials
                    .keet_bridge_bearer_token
                    .clone()
                    .context("Keet delivery requires keet_bridge_bearer_token")?;
                let channel = crate::channels::keet::KeetChannel::new(
                    bridge_url,
                    bearer,
                    topic.expose(),
                    allowed_senders,
                    home.join(crate::channels::keet::DEFAULT_CURSOR_FILE),
                )
                .context("construct Keet Cron delivery target")?;
                channel
                    .probe()
                    .await
                    .context("Keet Cron target failed its live full-duplex preflight")?;
                return Ok(());
            }
            let Some(recipient) = delivery.recipient.as_deref() else {
                // Backward compatibility for pre-Gold channel-only jobs. New
                // CLI creates explicit targets; the dispatcher still resolves
                // this legacy form from operator-owned routing.
                return Ok(());
            };
            let routing_path = home.join(crate::channels::routing::CHANNEL_ROUTING_FILE);
            let routing = crate::channels::routing::ChannelRouting::load_from(&routing_path)
                .with_context(|| format!("load channel routing {}", routing_path.display()))?;
            let configured = if delivery.channel == "telegram" {
                routing
                    .destinations
                    .telegram_chat_id
                    .clone()
                    .or_else(|| config.telegram_user_id.map(|value| value.to_string()))
            } else {
                routing
                    .destinations
                    .for_channel(&delivery.channel)
                    .map(str::to_string)
            };
            let configured = configured.with_context(|| {
                format!(
                    "no operator-owned destination configured for Cron channel `{}`",
                    delivery.channel
                )
            })?;
            if configured != recipient {
                anyhow::bail!(
                    "Cron recipient does not match the operator-owned `{}` channel route",
                    delivery.channel
                );
            }
            Ok(())
        }
    }
}

async fn run_job_with_paths(
    home: &Path,
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
    proactive_queue_path: &Path,
    hook_dir: &Path,
    hook_dispatch: HookDispatcher,
    config: &crate::config::FreedomConfig,
) -> Result<RunOutcome> {
    let started = Instant::now();

    // ── WAL: FIRED ─────────────────────────────────────────────────────────
    let fired_at_unix_ms = now_unix_ms();
    let fired_payload = serde_json::to_vec(&json!({
        "job_id": job.id,
        "name": job.name,
        "schedule": job.schedule,
        "schedule_label": job.schedule.label(),
        "execution": job.execution,
        "fired_at_unix_ms": fired_at_unix_ms,
    }))?;
    let fired_event_id = write_event(writer, EVENT_TYPE_JOB_FIRED, &fired_payload)
        .await
        .context("write JOB_FIRED")?;

    info!(job_id = %job.id, name = %job.name, "job firing");

    // ── JobFired hooks (Phase 29 R-15) ─────────────────────────────────────
    // Fires after the JOB_FIRED audit frame so the WAL records the job
    // even if the hook blocks it. A Replace rewrites the prompt the
    // provider sees (useful for redacting secrets before they leave the
    // daemon); a Block skips the provider call entirely with a
    // JOB_FAILED frame recording the hook name as the cause.
    let hooks = match crate::hooks::load_all_strict(hook_dir).await {
        Ok(hooks) => hooks,
        Err(error) => {
            warn!(job_id = %job.id, error = %error, "job_fired hook load failed; blocking run");
            return finish_job_fired_failure(
                job,
                writer,
                &started,
                fired_event_id,
                "hook_load_failed",
                format!("failed to load JobFired hooks: {error:#}"),
            )
            .await;
        }
    };
    let effective_prompt = match hook_dispatch(HookStage::JobFired, &job.prompt, &hooks) {
        Ok(StageOutcome::Continue { body, hits }) => {
            for name in &hits {
                let payload = serde_json::to_vec(&json!({
                    "name": name,
                    "stage": "job_fired",
                    "job_id": job.id,
                    "ts_unix_ms": now_unix_ms(),
                }))
                .expect("JobFired hook audit payload contains only JSON-safe fields");
                if let Err(error) =
                    write_event(writer, crate::wal::events::EVENT_TYPE_HOOK_FIRED, &payload).await
                {
                    warn!(job_id = %job.id, hook = %name, error = %error,
                            "HOOK_FIRED audit failed; blocking provider call");
                    return finish_job_fired_failure(
                        job,
                        writer,
                        &started,
                        fired_event_id,
                        "hook_audit_failed",
                        format!("HOOK_FIRED audit failed for `{name}`: {error:#}"),
                    )
                    .await;
                }
            }
            body
        }
        Ok(StageOutcome::Block { name, reason }) => {
            warn!(job_id = %job.id, hook = %name, reason = %reason,
                    "job_fired hook blocked the run");
            let payload = serde_json::to_vec(&json!({
                "name": &name,
                "stage": "job_fired",
                "job_id": job.id,
                "reason": &reason,
                "ts_unix_ms": now_unix_ms(),
            }))
            .expect("JobFired block audit payload contains only JSON-safe fields");
            if let Err(error) = write_event(
                writer,
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &payload,
            )
            .await
            {
                warn!(job_id = %job.id, hook = %name, error = %error,
                        "HOOK_BLOCKED audit failed; run remains blocked");
                return finish_job_fired_failure(
                    job,
                    writer,
                    &started,
                    fired_event_id,
                    "hook_block_audit_failed",
                    format!(
                        "hook `{name}` blocked the run, but HOOK_BLOCKED audit failed: {error:#}"
                    ),
                )
                .await;
            }
            return finish_job_fired_failure(
                job,
                writer,
                &started,
                fired_event_id,
                "hook_blocked",
                format!("blocked by hook `{name}`: {reason}"),
            )
            .await;
        }
        Err(error) => {
            warn!(job_id = %job.id, error = %error,
                    "job_fired hook dispatch failed; blocking provider call");
            return finish_job_fired_failure(
                job,
                writer,
                &started,
                fired_event_id,
                "hook_dispatch_failed",
                format!("JobFired hook dispatch failed: {error:#}"),
            )
            .await;
        }
    };

    // ── OH-06: inject system prompt for Briefing-classified jobs ──────────
    // `classify_role` uses keyword/name heuristic — no I/O.
    // Seed = UTC day number so the greeting is stable across the two 30 s
    // ticks that may both visit the same cron minute, but rotates daily.
    let is_briefing = classify_role(job) == CronRole::Briefing;
    let mut system_prompt: Option<String> = if is_briefing {
        let tz = job.schedule.timezone();
        let now_local = crate::time::utc_now().with_timezone(&tz);
        let local_dt = now_local.format("%A, %Y-%m-%d %H:%M").to_string();
        // Use the IANA name string (via the tz field or "UTC" fallback).
        let tz_name = job.schedule.tz.as_deref().unwrap_or("UTC");
        let _greeting = crate::cron::briefing_prompt::pick_greeting(
            (crate::time::now_unix_i64().max(0) as u64) / 86_400,
        );
        Some(render_briefing_system_prompt(tz_name, &local_dt))
    } else {
        None
    };
    if let Some(profile) = job.execution.profile.as_deref() {
        let preset = crate::profile::presets::ProfilePreset::parse(profile)
            .context("validated Cron profile disappeared")?;
        let addendum = crate::profile::presets::apply_preset(preset).system_addendum;
        if !addendum.trim().is_empty() {
            system_prompt = Some(match system_prompt {
                Some(system) => format!("{system}\n\n{addendum}"),
                None => addendum,
            });
        }
    }

    // ── Provider call (bounded by timeout_seconds) ─────────────────────────
    let req = Request {
        prompt: effective_prompt.clone(),
        system: system_prompt,
        model: job.execution.model.clone(),
        thinking_budget: job.execution.thinking_budget,
        ..Default::default()
    };
    let timeout_dur = Duration::from_secs(job.timeout_seconds.max(1) as u64);
    let provider_deadline = tokio::time::Instant::now() + timeout_dur;
    let result = tokio::time::timeout_at(
        provider_deadline,
        complete_cron_request(home, job, provider, writer, config, req.clone()),
    )
    .await;

    let (mut ok, mut output_text, mut err_text) = match result {
        Ok(Ok(completion)) => {
            debug!(
                job_id = %job.id,
                bytes = completion.text.len(),
                latency_ms = started.elapsed().as_millis(),
                "job provider call ok"
            );
            (true, completion.text, None)
        }
        Ok(Err(e)) => {
            warn!(job_id = %job.id, error = %e, "job provider call failed");
            (false, String::new(), Some(e.to_string()))
        }
        Err(_) => {
            warn!(job_id = %job.id, timeout_s = job.timeout_seconds, "job timed out");
            (
                false,
                String::new(),
                Some(format!("timeout after {}s", job.timeout_seconds)),
            )
        }
    };

    // GOLD-ADAPT-JV-PRO-07 — quality gates must run before delivery. Only
    // Briefing-class jobs use the 80-word/title/citation rubric; arbitrary cron
    // tasks may legitimately return a short token such as "OK". A failed first
    // briefing gets exactly one regeneration through the same AuthorizedProvider
    // (therefore the same final-model cost/consent boundary) and the original
    // whole-job timeout deadline. A second low score is a terminal failure and
    // no delivery item is ever queued.
    if ok && is_briefing {
        let first_score = crate::cron::quality_gate::score_briefing(&output_text, 80);
        if first_score.should_regenerate() {
            warn!(
                job_id = %job.id,
                score = first_score.score,
                words = first_score.word_count,
                filler_ratio = first_score.filler_ratio,
                "JV-PRO-07: low-quality briefing output — regenerating once before delivery"
            );
            let retry_req = Request {
                prompt: format!(
                    "{effective_prompt}\n\nThe previous draft failed the briefing quality gate. Regenerate it once with a clear heading, at least 80 substantive words, concrete facts or citations where available, and no filler. Return only the improved briefing."
                ),
                ..req
            };
            match tokio::time::timeout_at(provider_deadline, provider.complete(retry_req)).await {
                Ok(Ok(completion)) => {
                    let retry_score =
                        crate::cron::quality_gate::score_briefing(&completion.text, 80);
                    if retry_score.should_regenerate() {
                        ok = false;
                        output_text = completion.text;
                        err_text = Some(format!(
                            "briefing quality gate failed after one regeneration (score {:.2}, words {}, filler_ratio {:.2})",
                            retry_score.score, retry_score.word_count, retry_score.filler_ratio,
                        ));
                        warn!(
                            job_id = %job.id,
                            score = retry_score.score,
                            words = retry_score.word_count,
                            filler_ratio = retry_score.filler_ratio,
                            "JV-PRO-07: regenerated briefing still below quality gate; delivery withheld"
                        );
                    } else {
                        output_text = completion.text;
                        info!(
                            job_id = %job.id,
                            score = retry_score.score,
                            words = retry_score.word_count,
                            "JV-PRO-07: regenerated briefing passed quality gate"
                        );
                    }
                }
                Ok(Err(error)) => {
                    ok = false;
                    err_text = Some(format!(
                        "briefing regeneration provider call failed after low-quality first draft: {error}"
                    ));
                }
                Err(_) => {
                    ok = false;
                    err_text = Some(format!(
                        "briefing regeneration timed out within the {}s job deadline",
                        job.timeout_seconds.max(1)
                    ));
                }
            }
        }
    }

    let mut delivery_queued = false;
    let mut delivery_id = None;
    let mut delivery_status = None;
    if ok {
        if let Some(delivery) = &job.delivery {
            match delivery.mode {
                DeliveryMode::None => {
                    delivery_status = Some(DeliveryStatus::Skipped);
                }
                DeliveryMode::Announce | DeliveryMode::Webhook => {
                    let target = if delivery.mode == DeliveryMode::Webhook {
                        delivery
                            .webhook_url
                            .as_deref()
                            .unwrap_or_default()
                            .to_string()
                    } else {
                        format!(
                            "{}:{}:{}:{}",
                            delivery.channel,
                            delivery.recipient.as_deref().unwrap_or("configured-route"),
                            delivery.account.as_deref().unwrap_or("default-account"),
                            delivery.thread.as_deref().unwrap_or("root-thread"),
                        )
                    };
                    let id = cron_delivery_id(&job.id, fired_event_id, &target);
                    let begin = RuntimeState::modify(home, |state| {
                        state.begin_delivery(
                            id.clone(),
                            job.id.clone(),
                            fired_event_id,
                            delivery.mode,
                            target_hash(&target),
                            delivery.best_effort,
                        );
                        Ok(())
                    });
                    if let Err(error) = begin {
                        ok = false;
                        err_text = Some(format!(
                            "provider completed, but Cron delivery state could not be persisted: {error:#}"
                        ));
                    } else {
                        delivery_id = Some(id.clone());
                        match delivery.mode {
                            DeliveryMode::Announce => {
                                let channel = delivery.channel.trim().to_ascii_lowercase();
                                let dedup_key = format!("cron-delivery:{id}");
                                match enqueue_cron_delivery(
                                    proactive_queue_path,
                                    &job.id,
                                    &channel,
                                    &output_text,
                                    &dedup_key,
                                    now_unix_secs(),
                                ) {
                                    Ok(inserted) => {
                                        delivery_queued = true;
                                        delivery_status = Some(DeliveryStatus::Queued);
                                        if let Err(error) = RuntimeState::modify(home, |state| {
                                            state.update_delivery(&id, DeliveryStatus::Queued, None)
                                        }) {
                                            delivery_status = Some(DeliveryStatus::Failed);
                                            ok = false;
                                            err_text = Some(format!(
                                                "delivery was queued, but its durable correlation state could not be updated: {error:#}"
                                            ));
                                            warn!(job_id = %job.id, delivery_id = %id, error = %error,
                                                "Cron announce correlation update failed after enqueue");
                                        } else {
                                            info!(
                                                job_id = %job.id,
                                                channel = %channel,
                                                delivery_id = %id,
                                                inserted,
                                                "Cron announce durably queued; not yet claimed delivered"
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        let message = format!(
                                            "provider completed, but delivery queue persistence failed for channel `{channel}`: {error:#}"
                                        );
                                        delivery_status = Some(DeliveryStatus::Failed);
                                        if let Err(state_error) =
                                            RuntimeState::modify(home, |state| {
                                                state.update_delivery(
                                                    &id,
                                                    DeliveryStatus::Failed,
                                                    Some(message.clone()),
                                                )
                                            })
                                        {
                                            warn!(job_id = %job.id, delivery_id = %id, error = %state_error,
                                                "Cron delivery failure could not be recorded in correlation state");
                                        }
                                        warn!(job_id = %job.id, channel = %channel, error = %error,
                                            "Cron announce enqueue failed");
                                        if !delivery.best_effort {
                                            ok = false;
                                            err_text = Some(message);
                                        }
                                    }
                                }
                            }
                            DeliveryMode::Webhook => {
                                let url = delivery.webhook_url.as_deref().unwrap_or_default();
                                let endpoint = config
                                    .webhook_manager
                                    .endpoints
                                    .iter()
                                    .find(|endpoint| endpoint.url == url)
                                    .expect("validated Cron webhook endpoint must remain present");
                                use crate::daemon::webhook_manager::{
                                    CronWebhookDelivery, deliver_cron_result,
                                };
                                let terminal = deliver_cron_result(
                                    endpoint,
                                    &job.id,
                                    &id,
                                    &output_text,
                                    writer,
                                )
                                .await;
                                let (status, error) = match terminal {
                                    CronWebhookDelivery::Delivered => {
                                        (DeliveryStatus::Delivered, None)
                                    }
                                    CronWebhookDelivery::PermanentFailure => (
                                        DeliveryStatus::Failed,
                                        Some("permanent webhook delivery failure".to_string()),
                                    ),
                                    CronWebhookDelivery::RetryableFailure => (
                                        DeliveryStatus::Failed,
                                        Some("retryable webhook delivery failure".to_string()),
                                    ),
                                };
                                delivery_status = Some(status);
                                if let Err(state_error) = RuntimeState::modify(home, |state| {
                                    state.update_delivery(&id, status, error.clone())
                                }) {
                                    delivery_status = Some(DeliveryStatus::Failed);
                                    ok = false;
                                    err_text = Some(format!(
                                        "webhook reached a terminal state, but its durable correlation state could not be updated: {state_error:#}"
                                    ));
                                    warn!(job_id = %job.id, delivery_id = %id, error = %state_error,
                                        "Cron webhook correlation update failed");
                                }
                                if status != DeliveryStatus::Delivered && !delivery.best_effort {
                                    ok = false;
                                    err_text = error;
                                }
                            }
                            DeliveryMode::None => unreachable!(),
                        }
                    }
                }
            }
        }
    }

    let elapsed = started.elapsed();

    // GOLD-ADAPT-JV-PRO-06 — surface failure cause.
    if !ok {
        // Classify the failure + emit a retrospective with a recommendation,
        // instead of a bare error string the operator has to interpret.
        let exit_kind = if err_text.as_deref().is_some_and(|e| e.contains("timeout")) {
            "timeout"
        } else {
            "error"
        };
        let retro = crate::cron::error_retrospective::build_retrospective(
            err_text.as_deref().unwrap_or(""),
            exit_kind,
            1,
        );
        warn!(
            job_id = %job.id,
            cause = retro.cause.as_str(),
            risk = retro.risk_score,
            recommendation = %retro.recommendation,
            "JV-PRO-06: job failed — retrospective"
        );

        // GOLD-ADAPT-HERMES-07 — self-heal alert: when the risk score
        // is non-trivial (≥ 0.3) emit a WAL audit frame and enqueue a
        // ProactiveItem so the operator is alerted via the drain loop.
        // Both operations are best-effort (`let _ =`) — failure here
        // must never affect the job outcome or block the WAL frame below.
        const SELF_HEAL_RISK_THRESHOLD: f64 = 0.3;
        if retro.risk_score >= SELF_HEAL_RISK_THRESHOLD {
            // (a) WAL audit frame 0x8A CRON_JOB_SELF_HEAL_ALERT
            let alert_payload = serde_json::to_vec(&json!({
                "job_id": job.id,
                "cause": retro.cause.as_str(),
                "risk_score": retro.risk_score,
                "recommendation": retro.recommendation,
                "ts_unix_ms": now_unix_ms(),
            }))
            .expect("cron self-heal audit payload contains only JSON-safe fields");
            if let Err(error) =
                write_event(writer, EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT, &alert_payload).await
            {
                warn!(job_id = %job.id, error = %error,
                    "cron self-heal WAL audit failed after completed job failure");
            }

            // (b) Enqueue a ProactiveItem for the drain loop to surface.
            // Dedup key uses the UTC date so at most one alert per job per day.
            let utc_day = crate::time::utc_now().date_naive();
            let dedup_key = format!("self-heal:{}:{}", job.id, utc_day);
            let body = format!(
                "[CRON SELF-HEAL] Job `{}` failed (cause: {}, risk: {:.2})\n\nRecommendation: {}",
                job.id,
                retro.cause.as_str(),
                retro.risk_score,
                retro.recommendation,
            );
            // The primary job failure is already fixed at this point, so alert
            // delivery is best-effort; persistence errors remain operator-visible.
            if let Err(error) = ProactiveQueue::modify(proactive_queue_path, |queue| {
                let inserted = queue.enqueue(ProactiveItem {
                    priority: 80,
                    dedup_key,
                    channel: "cli".to_string(),
                    source: "hermes_07".to_string(),
                    body,
                    scheduled_for_unix: 0,
                    is_failure: true,
                    expires_unix: crate::time::now_unix_i64().saturating_add(86_400),
                });
                // Persist only when enqueue accepted the item (same as old
                // `if inserted { let _ = queue.save_to(...) }` logic).
                (inserted, inserted)
            }) {
                warn!(job_id = %job.id, error = %error,
                    "cron self-heal alert persistence failed after completed job failure");
            }
        }
    }

    // ── WAL: SUCCESS / FAILED ──────────────────────────────────────────────
    let outcome_payload = serde_json::to_vec(&json!({
        "fired_event_id": fired_event_id,
        "job_id": job.id,
        "name": job.name,
        "duration_ms": elapsed.as_millis() as u64,
        "output_bytes": output_text.len(),
        "error": err_text,
        "delivery_channel": job.delivery.as_ref().map(|delivery| delivery.channel.as_str()),
        "delivery_queued": delivery_queued,
        "delivery_id": delivery_id,
        "delivery_status": delivery_status.map(DeliveryStatus::as_str),
        "delivered": delivery_status == Some(DeliveryStatus::Delivered),
    }))?;
    let event_type = if ok {
        EVENT_TYPE_JOB_SUCCESS
    } else {
        EVENT_TYPE_JOB_FAILED
    };
    write_event(writer, event_type, &outcome_payload)
        .await
        .context("write JOB_SUCCESS/JOB_FAILED")?;

    // ── JobDone hooks (Phase 29 R-15) ──────────────────────────────────────
    // Notification-style stage: hooks read the outcome but cannot un-run
    // the job. Replace/Block are best-effort (we just log them). Useful
    // for "ping me when job X finishes" via a Replace that pipes the
    // output into a tool, or "log every failure to disk" via Allow.
    let outcome_body = if ok {
        output_text.clone()
    } else {
        err_text.clone().unwrap_or_default()
    };
    match hook_dispatch(HookStage::JobDone, &outcome_body, &hooks) {
        Ok(StageOutcome::Continue { hits, .. }) => {
            for name in &hits {
                let payload = serde_json::to_vec(&json!({
                    "name": name,
                    "stage": "job_done",
                    "job_id": job.id,
                    "ok": ok,
                    "ts_unix_ms": now_unix_ms(),
                }))
                .expect("JobDone hook audit payload contains only JSON-safe fields");
                if let Err(error) =
                    write_event(writer, crate::wal::events::EVENT_TYPE_HOOK_FIRED, &payload).await
                {
                    warn!(job_id = %job.id, hook = %name, error = %error,
                        "HOOK_FIRED audit failed after completed job");
                }
            }
        }
        Ok(StageOutcome::Block { name, reason }) => {
            // Can't unwind a completed job — log + emit audit only.
            warn!(job_id = %job.id, hook = %name, reason = %reason,
                "job_done hook returned Block; ignored (job already completed)");
            let payload = serde_json::to_vec(&json!({
                "name": &name,
                "stage": "job_done",
                "job_id": job.id,
                "reason": &reason,
                "ts_unix_ms": now_unix_ms(),
            }))
            .expect("JobDone block audit payload contains only JSON-safe fields");
            if let Err(error) = write_event(
                writer,
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &payload,
            )
            .await
            {
                warn!(job_id = %job.id, hook = %name, error = %error,
                    "HOOK_BLOCKED audit failed after completed job");
            }
        }
        Err(error) => {
            warn!(job_id = %job.id, error = %error, "job_done hook dispatch failed after completed job")
        }
    }

    Ok(RunOutcome {
        success: ok,
        duration: elapsed,
        output_bytes: output_text.len(),
        delivery_queued,
        delivery_id,
        delivery_status,
        error: err_text,
    })
}

fn cron_delivery_id(job_id: &str, fired_event_id: u64, target: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"neoth.cron.delivery.v1\0");
    hasher.update(job_id.as_bytes());
    hasher.update([0]);
    hasher.update(fired_event_id.to_be_bytes());
    hasher.update([0]);
    hasher.update(target.as_bytes());
    hex::encode(hasher.finalize())
}

async fn complete_cron_request(
    home: &Path,
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
    config: &crate::config::FreedomConfig,
    mut request: Request,
) -> Result<crate::providers::Completion> {
    if job.execution.tools.is_empty() {
        return provider.complete(request).await;
    }

    let path = home.join("mcp_servers.yaml");
    let configured = crate::mcp::McpServers::load_from(&path)
        .with_context(|| format!("load Cron MCP capabilities from {}", path.display()))?;
    let scoped = scope_cron_mcp_servers(
        configured,
        &job.execution.capabilities,
        &job.execution.tools,
    )
    .with_context(|| format!("validate Cron MCP scope from {}", path.display()))?;
    let catalogue = crate::mcp::catalogue::assemble_catalogue(&scoped)
        .await
        .context("Cron MCP capability catalogue is empty or unavailable")?;
    request.system = Some(match request.system.take() {
        Some(system) => format!("{system}\n\n{catalogue}"),
        None => catalogue,
    });
    let initial_prompt = request.prompt.clone();
    let mut driver = CronCompletionDriver { provider, request };
    let policy = config.autonomy_policy();
    let outcome = crate::mcp::dispatch_loop::run_tool_loop(
        &mut driver,
        initial_prompt,
        &scoped,
        &policy,
        Some(writer),
        Some(&config.rollback),
        Some(&job.execution.tools),
        &config.security,
    )
    .await?;
    Ok(crate::providers::Completion {
        text: outcome.final_text,
        ..Default::default()
    })
}

fn scope_cron_mcp_servers(
    configured: crate::mcp::McpServers,
    capabilities: &[String],
    tools: &[String],
) -> Result<crate::mcp::McpServers> {
    let wanted: std::collections::HashSet<&str> = capabilities.iter().map(String::as_str).collect();
    let enabled: std::collections::HashSet<&str> = configured
        .enabled()
        .into_iter()
        .map(|server| server.id.as_str())
        .collect();
    if let Some(missing) = wanted.difference(&enabled).next() {
        anyhow::bail!("Cron capability `{missing}` is absent or disabled");
    }

    let mut permitted = std::collections::HashSet::new();
    let servers = configured
        .servers
        .into_iter()
        .filter(|server| server.enabled && wanted.contains(server.id.as_str()))
        .map(|mut server| {
            // The job scope can only narrow the server policy. A server with
            // neither an allow-list nor trust_all_tools remains deny-by-default;
            // jobs.yaml must never turn that boundary into an allow-list.
            let effective: Vec<String> = match &server.allow_tools {
                Some(existing) => tools
                    .iter()
                    .filter(|tool| existing.contains(tool))
                    .cloned()
                    .collect(),
                None if server.trust_all_tools => tools.to_vec(),
                None => Vec::new(),
            };
            permitted.extend(effective.iter().cloned());
            server.allow_tools = Some(effective);
            server.trust_all_tools = false;
            server
        })
        .collect();

    if let Some(missing) = tools.iter().find(|tool| !permitted.contains(*tool)) {
        anyhow::bail!("Cron tool `{missing}` is not permitted by any selected capability");
    }
    Ok(crate::mcp::McpServers {
        servers,
        smart_loading: false,
    })
}

/// Durably enqueue one completed cron result. The dedup key identifies the
/// concrete JOB_FIRED WAL event, so retrying the same event is idempotent while
/// a later scheduled run still produces a distinct notification.
fn enqueue_cron_delivery(
    queue_path: &Path,
    job_id: &str,
    channel: &str,
    output_text: &str,
    dedup_key: &str,
    now_unix: i64,
) -> Result<bool> {
    let item = ProactiveItem {
        priority: 70,
        dedup_key: dedup_key.to_string(),
        channel: channel.to_string(),
        source: format!("cron:{job_id}"),
        body: output_text.to_string(),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: now_unix.saturating_add(86_400),
    };
    ProactiveQueue::modify(queue_path, |queue| {
        let inserted = queue.enqueue(item);
        // `false` is an idempotent retry: this exact JOB_FIRED event is
        // already durable under the same dedup key.
        (inserted, inserted)
    })
}

async fn finish_job_fired_failure(
    job: &Job,
    writer: &WalWriterHandle,
    started: &Instant,
    fired_event_id: u64,
    failure_kind: &str,
    error: String,
) -> Result<RunOutcome> {
    let duration = started.elapsed();
    let payload = serde_json::to_vec(&json!({
        "fired_event_id": fired_event_id,
        "job_id": job.id,
        "name": job.name,
        "duration_ms": duration.as_millis() as u64,
        "output_bytes": 0,
        "error": &error,
        "failure_stage": "job_fired_hook",
        "failure_kind": failure_kind,
        "delivery_channel": job.delivery.as_ref().map(|delivery| delivery.channel.as_str()),
        "delivery_queued": false,
        "delivered": false,
    }))
    .expect("terminal JobFired failure payload contains only JSON-safe fields");
    write_event(writer, EVENT_TYPE_JOB_FAILED, &payload)
        .await
        .with_context(|| format!("write terminal JOB_FAILED after {failure_kind}"))?;
    Ok(RunOutcome {
        success: false,
        duration,
        output_bytes: 0,
        delivery_queued: false,
        delivery_id: None,
        delivery_status: None,
        error: Some(error),
    })
}

fn now_unix_ms() -> u64 {
    crate::time::now_unix_ms()
}

fn now_unix_secs() -> i64 {
    crate::time::now_unix_i64()
}

async fn write_event(writer: &WalWriterHandle, event_type: u8, payload: &[u8]) -> Result<u64> {
    // Phase 33a AU-B3: builder owns header construction. Cron events are
    // SYNTHETIC because no operator turn produced them.
    let header = crate::wal::HeaderBuilder::new(event_type, payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    Ok(writer.append(header, payload.to_vec()).await?)
}

/// P-08 cron consumer (Workstream C, Session 22) — `run_job` wrapper
/// that consults the briefing-gate BEFORE the provider call.
///
/// Verdict flow:
///   - `Skip` → no provider call. A `JOB_SKIPPED_BY_GATE` event is
///     written with the verdict's reason; the returned `RunOutcome`
///     carries `success: false`, `output_bytes: 0`, and an `error`
///     prefixed `"briefing-gate skip: "` so the caller distinguishes
///     gate-skip from a real failure.
///   - `Emit` → delegates to [`run_job`] unchanged. The downstream
///     hooks + WAL frames behave exactly as without the gate.
///
/// `now_unix` + `current_hour` are caller-resolved so tests can pin
/// deterministic verdicts. Production callers compute both via
/// `chrono::Utc::now().with_timezone(&local_tz)`.
pub async fn run_briefing_gated(
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
    home: &Path,
    now_unix: i64,
    current_hour: u8,
    policy: &BriefingPolicy,
) -> Result<RunOutcome> {
    let verdict = should_emit_for_briefing(home, now_unix, current_hour, policy);
    if let EmitVerdict::Skip { reason } = verdict {
        info!(
            job_id = %job.id,
            name = %job.name,
            reason = reason,
            "briefing-gate suppressed job — no provider call this tick"
        );
        let skip_payload = serde_json::to_vec(&json!({
            "job_id": job.id,
            "name": job.name,
            "reason": reason,
            "current_hour": current_hour,
            "ts_unix_ms": now_unix_ms(),
        }))?;
        write_event(writer, EVENT_TYPE_JOB_SKIPPED_BY_GATE, &skip_payload)
            .await
            .context("write JOB_SKIPPED_BY_GATE")?;
        return Ok(RunOutcome {
            success: false,
            duration: Duration::ZERO,
            output_bytes: 0,
            delivery_queued: false,
            delivery_id: None,
            delivery_status: None,
            error: Some(format!("briefing-gate skip: {reason}")),
        });
    }
    run_job_at(home, job, provider, writer).await
}

/// P-01.b cron consumer (Workstream C, Session 22) — daily snapshot
/// aggregator. Walks every `*.wal` segment under `wal_dir`, extracts
/// every RAW_TEXT frame whose HLC physical-ns timestamp lands within
/// the last 30 days, builds a `Vec<ObservedTurn>`, and calls
/// [`aggregate_and_persist`] to write the new behavioural snapshot.
///
/// Returns the number of samples that fed the snapshot — the cron
/// task logs this so operators see "today's run pulled N turns".
///
/// Corrupt / unreadable segments are skipped with a `warn!` (one
/// bad file mustn't fail the whole aggregation). Empty WAL → empty
/// snapshot (still persisted, so `briefing_gate::load_snapshot` finds
/// a file instead of returning None forever).
pub async fn aggregate_profile_snapshot(home: &Path, wal_dir: &Path) -> Result<usize> {
    const WINDOW_SECS: i64 = 30 * 86_400;
    let cutoff = now_unix_secs().saturating_sub(WINDOW_SECS);
    let mut samples: Vec<ObservedTurn> = Vec::new();

    let entries = match std::fs::read_dir(wal_dir) {
        Ok(e) => e,
        Err(_) => {
            // Fresh install — no wal dir yet. Persist an empty snapshot
            // so downstream readers (briefing gate) find SOMETHING
            // instead of forever-None.
            aggregate_and_persist(home, &samples).context("persist empty snapshot")?;
            return Ok(0);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            warn!(segment = %path.display(), "could not read WAL segment; skipping");
            continue;
        };
        // GOLD-ARCH-03: for_each_frame so RAW_TEXT frames inside a v2/zstd-
        // compressed segment feed the profile snapshot, not silently skipped.
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            if frame.header.event_type == EVENT_TYPE_RAW_TEXT {
                let ts_unix = (frame.header.hlc.physical_ns() / 1_000_000_000) as i64;
                if ts_unix >= cutoff
                    && let Ok(text) = std::str::from_utf8(frame.payload)
                {
                    samples.push(ObservedTurn {
                        ts_unix,
                        text: text.to_string(),
                    });
                }
            }
            Ok(())
        });
    }

    let count = samples.len();
    aggregate_and_persist(home, &samples).context("persist aggregated snapshot")?;
    Ok(count)
}

#[cfg(test)]
mod workstream_c_tests {
    use super::*;
    use crate::cron::schema::{Delivery, Job, Schedule};
    use crate::profile::estimators::BehaviouralProfile;
    use crate::profile::snapshot::load_snapshot;
    use crate::providers::{Completion, Provider, Request};
    use crate::wal::events::{
        EVENT_TYPE_HOOK_BLOCKED, EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_RAW_TEXT,
    };
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use crate::wal::spawn as wal_spawn;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    fn authorized(provider: impl Provider + 'static) -> AuthorizedProvider {
        AuthorizedProvider::from_box(
            Box::new(provider),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("test-model".to_string()),
            "cron.runner.test",
        )
    }

    fn briefing_job() -> Job {
        Job {
            id: "morning_brief".into(),
            name: "morning brief".into(),
            enabled: true,
            schedule: Schedule {
                cron: "0 7 * * *".into(),
                tz: Some("UTC".into()),
                ..Default::default()
            },
            prompt: "Summarise overnight activity.".into(),
            timeout_seconds: 30,
            delivery: None,
            execution: Default::default(),
            depends_on: vec![],
        }
    }

    fn delivery_job(channel: &str) -> Job {
        Job {
            id: "delivery-job".into(),
            name: "delivery job".into(),
            enabled: true,
            schedule: Schedule {
                cron: "0 * * * *".into(),
                tz: None,
                ..Default::default()
            },
            prompt: "produce a delivery".into(),
            timeout_seconds: 30,
            delivery: Some(Delivery::new(channel)),
            execution: Default::default(),
            depends_on: vec![],
        }
    }

    #[test]
    fn per_job_provider_never_borrows_another_vendors_credentials() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_model = Some("openai-main-model".into());
        config.provider_key = Some(crate::secret::SecretString::from("openai-main-secret"));
        config.provider_endpoint = Some("https://openai.example/v1".into());

        let slot =
            configured_provider_slot(&config, crate::config::inference::InferenceProvider::Gemini);
        assert_eq!(
            slot.provider,
            Some(crate::config::inference::InferenceProvider::Gemini)
        );
        assert!(slot.model.is_none());
        assert!(slot.key.is_none());
        assert!(slot.endpoint.is_none());
        assert!(slot.region.is_none());
        assert!(slot.api_version.is_none());
    }

    #[test]
    fn per_job_provider_reuses_only_its_explicit_matching_slot() {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_key = Some(crate::secret::SecretString::from("openai-main-secret"));
        config
            .fallback
            .chain
            .push(crate::config::inference::HemisphereSlot {
                provider: Some(crate::config::inference::InferenceProvider::Gemini),
                model: Some("gemini-job-model".into()),
                key: Some(crate::secret::SecretString::from("gemini-slot-secret")),
                endpoint: Some("https://gemini.example".into()),
                region: Some("eu".into()),
                api_version: Some("v2".into()),
                voice: None,
            });

        let slot =
            configured_provider_slot(&config, crate::config::inference::InferenceProvider::Gemini);
        assert_eq!(slot.model.as_deref(), Some("gemini-job-model"));
        assert_eq!(
            slot.key.as_ref().map(crate::secret::SecretString::expose),
            Some("gemini-slot-secret")
        );
        assert_eq!(slot.endpoint.as_deref(), Some("https://gemini.example"));
        assert_eq!(slot.region.as_deref(), Some("eu"));
        assert_eq!(slot.api_version.as_deref(), Some("v2"));
    }

    #[tokio::test]
    async fn per_job_cloud_provider_requires_consent_before_adapter_build() {
        let home = tempfile::tempdir().unwrap();
        let mut job = briefing_job();
        job.execution.provider = Some(crate::config::inference::InferenceProvider::OpenAi);
        job.execution.model = Some("gpt-test".into());
        let calls = Arc::new(AtomicUsize::new(0));
        let default_provider = authorized(CountingProvider {
            calls: calls.clone(),
        });
        let (writer, join) = crate::wal::spawn(home.path().join("cron-consent.wal")).unwrap();

        let error = match resolve_job_provider(
            home.path(),
            &job,
            &default_provider,
            &writer,
            &crate::config::FreedomConfig::default(),
        )
        .await
        {
            Ok(_) => panic!("unconsented cloud override must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("without an explicit consent grant")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        drop(writer);
        join.await.unwrap();
    }

    fn mcp_server(
        id: &str,
        allow_tools: Option<&[&str]>,
        trust_all_tools: bool,
        enabled: bool,
    ) -> crate::mcp::McpServerConfig {
        crate::mcp::McpServerConfig {
            id: id.into(),
            description: None,
            command: "test-mcp".into(),
            args: Vec::new(),
            env: std::collections::HashMap::new(),
            enabled,
            allow_tools: allow_tools
                .map(|tools| tools.iter().map(|tool| (*tool).to_string()).collect()),
            trust_all_tools,
            smart_approve: false,
            autonomy_gate: None,
        }
    }

    #[test]
    fn cron_mcp_scope_is_the_intersection_of_job_and_server_allow_lists() {
        let scoped = scope_cron_mcp_servers(
            crate::mcp::McpServers {
                servers: vec![mcp_server(
                    "files",
                    Some(&["read_file", "write_file"]),
                    false,
                    true,
                )],
                smart_loading: true,
            },
            &["files".into()],
            &["read_file".into()],
        )
        .unwrap();
        assert!(!scoped.smart_loading);
        assert_eq!(scoped.servers.len(), 1);
        assert_eq!(
            scoped.servers[0].allow_tools.as_deref(),
            Some(["read_file".to_string()].as_slice())
        );
        assert!(!scoped.servers[0].trust_all_tools);
    }

    #[test]
    fn cron_mcp_scope_cannot_override_a_server_deny_by_default_policy() {
        let error = scope_cron_mcp_servers(
            crate::mcp::McpServers {
                servers: vec![mcp_server("files", None, false, true)],
                smart_loading: true,
            },
            &["files".into()],
            &["read_file".into()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("not permitted"));
    }

    #[test]
    fn cron_mcp_scope_rejects_disabled_capabilities_before_provider_spend() {
        let error = scope_cron_mcp_servers(
            crate::mcp::McpServers {
                servers: vec![mcp_server("files", Some(&["read_file"]), false, false)],
                smart_loading: true,
            },
            &["files".into()],
            &["read_file".into()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("absent or disabled"));
    }

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Provider for CountingProvider {
        fn name(&self) -> &'static str {
            "counting-mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                text: "ok".into(),
                identity: Default::default(),
                model: "mock".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    struct SequenceProvider {
        calls: Arc<AtomicUsize>,
        prompts: Arc<Mutex<Vec<String>>>,
        outputs: Mutex<std::collections::VecDeque<String>>,
    }

    #[async_trait]
    impl Provider for SequenceProvider {
        fn name(&self) -> &'static str {
            "sequence-mock"
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.prompts.lock().unwrap().push(req.prompt);
            let text = self
                .outputs
                .lock()
                .unwrap()
                .pop_front()
                .expect("test provider output exhausted");
            Ok(Completion {
                text,
                identity: Default::default(),
                model: "mock".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    fn passing_briefing() -> String {
        let facts = (0..90)
            .map(|index| format!("fact-{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("# Morning Brief\n\n{facts}")
    }

    fn wal_json_events(path: &Path) -> Vec<(u8, serde_json::Value)> {
        let bytes = std::fs::read(path).expect("read WAL segment");
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut events = Vec::new();
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode WAL frame");
            let payload = serde_json::from_slice(frame.payload).expect("JSON cron payload");
            events.push((frame.header.event_type, payload));
            cursor = &cursor[frame.header.total_len as usize..];
        }
        events
    }

    fn failing_hook_dispatch(
        _stage: HookStage,
        _body: &str,
        _hooks: &[HookDef],
    ) -> Result<StageOutcome> {
        anyhow::bail!("synthetic hook dispatcher failure")
    }

    #[test]
    fn cron_delivery_enqueue_is_durable_and_idempotent() {
        let dir = tempdir().unwrap();
        let queue_path = dir.path().join("proactive_queue.json");
        let dedup_key = "cron-delivery:delivery-job:42";

        let inserted = enqueue_cron_delivery(
            &queue_path,
            "delivery-job",
            "telegram",
            "finished body",
            dedup_key,
            1_700_000_000,
        )
        .expect("first enqueue must persist");
        assert!(inserted);

        let retry_inserted = enqueue_cron_delivery(
            &queue_path,
            "delivery-job",
            "telegram",
            "finished body",
            dedup_key,
            1_700_000_001,
        )
        .expect("same fired event must remain a successful durable retry");
        assert!(!retry_inserted, "retry must reuse the durable queue entry");

        let queue = ProactiveQueue::load_from(&queue_path).expect("persisted queue");
        assert_eq!(queue.len(), 1);
        let item = &queue.peek()[0];
        assert_eq!(item.dedup_key, dedup_key);
        assert_eq!(item.channel, "telegram");
        assert_eq!(item.source, "cron:delivery-job");
        assert_eq!(item.body, "finished body");
        assert_eq!(item.expires_unix, 1_700_086_400);
    }

    #[tokio::test]
    async fn low_quality_briefing_regenerates_once_before_delivery() {
        let dir = tempdir().unwrap();
        let queue_path = dir.path().join("proactive_queue.json");
        let seg = dir.path().join("quality-retry.wal");
        let (writer, join) = wal_spawn(seg).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let expected = passing_briefing();
        let provider = authorized(SequenceProvider {
            calls: calls.clone(),
            prompts: prompts.clone(),
            outputs: Mutex::new(std::collections::VecDeque::from([
                "too short".to_string(),
                expected.clone(),
            ])),
        });
        let mut job = briefing_job();
        job.delivery = Some(Delivery::new("telegram"));

        let outcome = run_job_with_paths(
            dir.path(),
            &job,
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("quality retry must complete");
        drop(writer);
        let _ = join.await;

        assert!(outcome.success);
        assert!(outcome.delivery_queued);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let prompts = prompts.lock().unwrap();
        assert_eq!(prompts.len(), 2);
        assert!(prompts[1].contains("previous draft failed the briefing quality gate"));
        let queue = ProactiveQueue::load_from(&queue_path).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek()[0].body, expected);
    }

    #[tokio::test]
    async fn second_low_quality_briefing_fails_without_delivery() {
        let dir = tempdir().unwrap();
        let queue_path = dir.path().join("proactive_queue.json");
        let seg = dir.path().join("quality-failure.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(SequenceProvider {
            calls: calls.clone(),
            prompts: Arc::new(Mutex::new(Vec::new())),
            outputs: Mutex::new(std::collections::VecDeque::from([
                "too short".to_string(),
                "still too short".to_string(),
            ])),
        });
        let mut job = briefing_job();
        job.delivery = Some(Delivery::new("telegram"));

        let outcome = run_job_with_paths(
            dir.path(),
            &job,
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("quality failure must be represented in RunOutcome");
        drop(writer);
        let _ = join.await;

        assert!(!outcome.success);
        assert!(!outcome.delivery_queued);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|error| error.contains("quality gate failed after one regeneration"))
        );
        let queue = ProactiveQueue::load_from(&queue_path).unwrap_or_default();
        assert!(
            queue
                .peek()
                .iter()
                .all(|item| item.source != "cron:morning_brief"),
            "the rejected briefing itself must never enter the delivery queue"
        );
        let events = wal_json_events(&seg);
        assert!(events.iter().any(|(kind, payload)| {
            *kind == EVENT_TYPE_JOB_FAILED
                && payload["error"]
                    .as_str()
                    .is_some_and(|error| error.contains("quality gate"))
        }));
    }

    #[tokio::test]
    async fn cron_delivery_persistence_failure_marks_run_failed_closed() {
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"block queue parent creation").unwrap();
        let queue_path = blocker.join("proactive_queue.json");
        let seg = dir.path().join("delivery-failure.wal");
        let (writer, join) = wal_spawn(seg).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });

        let outcome = run_job_with_paths(
            dir.path(),
            &delivery_job("telegram"),
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("delivery persistence is represented in RunOutcome");
        drop(writer);
        let _ = join.await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!outcome.success);
        assert!(!outcome.delivery_queued);
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|error| error.contains("delivery queue persistence failed")),
            "unexpected outcome: {:?}",
            outcome.error
        );
    }

    #[tokio::test]
    async fn malformed_job_fired_hook_blocks_provider_and_writes_terminal_failure() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir(&hook_dir).unwrap();
        std::fs::write(hook_dir.join("broken.toml"), "not = [valid").unwrap();
        let seg = dir.path().join("malformed-hook.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });

        let outcome = run_job_with_paths(
            dir.path(),
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &hook_dir,
            crate::hooks::run_stage,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("hook load failure is a terminal RunOutcome");
        drop(writer);
        let _ = join.await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!outcome.success);
        let events = wal_json_events(&seg);
        assert_eq!(
            events.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![EVENT_TYPE_JOB_FIRED, EVENT_TYPE_JOB_FAILED]
        );
        assert_eq!(events[1].1["failure_kind"], "hook_load_failed");
    }

    #[tokio::test]
    async fn unreadable_job_fired_hook_blocks_provider_and_writes_terminal_failure() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir(&hook_dir).unwrap();
        std::fs::create_dir(hook_dir.join("unreadable.toml")).unwrap();
        let seg = dir.path().join("unreadable-hook.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });

        let outcome = run_job_with_paths(
            dir.path(),
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &hook_dir,
            crate::hooks::run_stage,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("unreadable hook is a terminal RunOutcome");
        drop(writer);
        let _ = join.await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!outcome.success);
        let events = wal_json_events(&seg);
        assert_eq!(
            events.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![EVENT_TYPE_JOB_FIRED, EVENT_TYPE_JOB_FAILED]
        );
        assert_eq!(events[1].1["failure_kind"], "hook_load_failed");
    }

    #[tokio::test]
    async fn job_fired_dispatch_error_blocks_provider_and_writes_terminal_failure() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("dispatch-error.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });

        let outcome = run_job_with_paths(
            dir.path(),
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &dir.path().join("hooks"),
            failing_hook_dispatch,
            &crate::config::FreedomConfig::default(),
        )
        .await
        .expect("hook dispatch failure is a terminal RunOutcome");
        drop(writer);
        let _ = join.await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!outcome.success);
        let events = wal_json_events(&seg);
        assert_eq!(
            events.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![EVENT_TYPE_JOB_FIRED, EVENT_TYPE_JOB_FAILED]
        );
        assert_eq!(events[1].1["failure_kind"], "hook_dispatch_failed");
    }

    #[tokio::test]
    async fn run_job_at_loads_hooks_only_from_the_custom_instance_home() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir(&hook_dir).unwrap();
        std::fs::write(
            hook_dir.join("block.toml"),
            "name = \"cron-kill\"\nstage = \"job_fired\"\n[action]\nkind = \"block\"\nreason = \"operator policy\"\n",
        )
        .unwrap();
        let seg = dir.path().join("hook-block.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });

        let outcome = run_job_at(dir.path(), &briefing_job(), &provider, &writer)
            .await
            .expect("hook block is a terminal RunOutcome");
        drop(writer);
        let _ = join.await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!outcome.success);
        let events = wal_json_events(&seg);
        assert_eq!(
            events.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![
                EVENT_TYPE_JOB_FIRED,
                EVENT_TYPE_HOOK_BLOCKED,
                EVENT_TYPE_JOB_FAILED,
            ]
        );
        assert_eq!(events[2].1["failure_kind"], "hook_blocked");
    }

    // ─── run_briefing_gated ───────────────────────────────────────────

    #[tokio::test]
    async fn run_briefing_gated_skip_path_does_not_call_provider() {
        let home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        // No snapshot on disk → gate's first check (load_snapshot) returns
        // None → Skip { "no behavioural snapshot on disk …" }.
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });
        let job = briefing_job();
        let policy = BriefingPolicy::default();

        let outcome = run_briefing_gated(
            &job,
            &provider,
            &writer,
            home.path(),
            1_700_000_000,
            9,
            &policy,
        )
        .await
        .expect("run_briefing_gated");

        assert!(!outcome.success);
        assert_eq!(outcome.output_bytes, 0);
        assert!(
            outcome
                .error
                .as_deref()
                .map(|e| e.starts_with("briefing-gate skip:"))
                .unwrap_or(false),
            "error must carry the briefing-gate prefix: {:?}",
            outcome.error
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "provider must NOT be called on a gate-Skip"
        );

        drop(writer);
        let _ = join.await;

        // Walk the WAL: a JOB_SKIPPED_BY_GATE frame must be present.
        let bytes = std::fs::read(&seg).unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut saw_skip = false;
        while !cursor.is_empty() {
            let Ok(frame) = decode_frame(cursor) else {
                break;
            };
            if frame.header.event_type == EVENT_TYPE_JOB_SKIPPED_BY_GATE {
                saw_skip = true;
                let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                assert_eq!(payload["job_id"], "morning_brief");
                assert!(payload["reason"].as_str().is_some());
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        assert!(saw_skip, "expected JOB_SKIPPED_BY_GATE frame in WAL");
    }

    #[tokio::test]
    async fn run_briefing_gated_emit_path_delegates_to_run_job() {
        let home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        // Disable the active-window gate + zero out the inactivity
        // skip so the gate's verdict is Emit. Persist an empty snapshot
        // first so `load_snapshot` returns Some.
        aggregate_and_persist(home.path(), &[]).unwrap();
        // Record last-active = now so the inactivity check doesn't skip.
        crate::profile::briefing_gate::record_last_active(home.path(), 1_700_000_000).unwrap();

        let policy = BriefingPolicy {
            silent_after_inactive_secs: 0,
            active_threshold: 0,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = authorized(CountingProvider {
            calls: calls.clone(),
        });
        let job = briefing_job();

        let outcome = run_briefing_gated(
            &job,
            &provider,
            &writer,
            home.path(),
            1_700_000_000,
            9,
            &policy,
        )
        .await
        .expect("run_briefing_gated");

        assert!(outcome.success, "emit path must call run_job successfully");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "provider must be called exactly once on Emit"
        );

        drop(writer);
        let _ = join.await;
    }

    // ─── aggregate_profile_snapshot ───────────────────────────────────

    #[tokio::test]
    async fn aggregate_profile_snapshot_empty_wal_writes_empty_profile() {
        let home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let count = aggregate_profile_snapshot(home.path(), wal_dir.path())
            .await
            .expect("aggregate");
        assert_eq!(count, 0);
        let profile: BehaviouralProfile =
            load_snapshot(home.path()).expect("snapshot persisted even when empty");
        assert_eq!(profile.length.sample_count, 0);
    }

    #[tokio::test]
    async fn aggregate_profile_snapshot_populated_wal_reflects_raw_text_frames() {
        let home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        for body in ["first turn from operator", "second turn", "third turn here"] {
            let header = crate::wal::make_header(EVENT_TYPE_RAW_TEXT, body.as_bytes());
            writer
                .append(header, body.as_bytes().to_vec())
                .await
                .unwrap();
        }
        drop(writer);
        let _ = join.await;

        let count = aggregate_profile_snapshot(home.path(), wal_dir.path())
            .await
            .expect("aggregate");
        assert_eq!(count, 3, "all 3 RAW_TEXT frames feed the snapshot");

        let profile = load_snapshot(home.path()).expect("snapshot persisted");
        assert_eq!(profile.length.sample_count, 3);
    }

    #[tokio::test]
    async fn aggregate_profile_snapshot_missing_wal_dir_persists_empty_snapshot() {
        let home = tempdir().unwrap();
        let nonexistent = home.path().join("definitely-not-here");
        let count = aggregate_profile_snapshot(home.path(), &nonexistent)
            .await
            .expect("aggregate with missing wal dir");
        assert_eq!(count, 0);
        // Even with no WAL dir we still persist an empty snapshot so the
        // briefing-gate's load_snapshot path returns Some(default) instead
        // of forever-None on fresh-install operators.
        assert!(load_snapshot(home.path()).is_some());
    }

    #[test]
    fn event_type_job_skipped_by_gate_lives_in_job_band() {
        // Drift guard — every JOB-family code must stay 0x40..=0x4F so
        // `neoth wal show --filter job` keeps working with one band match.
        assert!((0x40..=0x4F).contains(&EVENT_TYPE_JOB_SKIPPED_BY_GATE));
        assert_ne!(EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_JOB_FIRED);
        assert_ne!(EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_JOB_SUCCESS);
        assert_ne!(EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_JOB_FAILED);
    }

    // ─── GOLD-ADAPT-HERMES-07: self-heal alert path ───────────────────────

    /// A provider that always returns an error, simulating a job failure.
    struct FailingProvider {
        error_msg: String,
    }

    #[async_trait]
    impl Provider for FailingProvider {
        fn name(&self) -> &'static str {
            "failing-mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            anyhow::bail!("{}", self.error_msg)
        }
    }

    #[tokio::test]
    async fn cron_job_failure_uses_custom_home_for_self_heal_queue_and_wal_frame() {
        use crate::proactive::ProactiveQueue;
        use crate::wal::events::EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;

        let home = tempdir().unwrap();
        let wal_dir = tempdir().unwrap();
        let seg = wal_dir.path().join("hermes07.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        // A rate-limit error produces ProviderError cause with risk_score ≥ 0.3
        // (base weight 0.5 * amplifier > 0.3 for consecutive_failures=1).
        let provider = authorized(FailingProvider {
            error_msg: "http status 429 rate limit".to_string(),
        });
        let job = Job {
            id: "test-job".into(),
            name: "test job".into(),
            enabled: true,
            schedule: Schedule {
                cron: "0 * * * *".into(),
                tz: None,
                ..Default::default()
            },
            prompt: "do something".into(),
            timeout_seconds: 30,
            delivery: None,
            execution: Default::default(),
            depends_on: vec![],
        };

        let outcome = run_job_at(home.path(), &job, &provider, &writer)
            .await
            .expect("run_job_at must return provider failures as a terminal RunOutcome");

        drop(writer);
        let _ = join.await;

        // (1) Outcome must be a failure.
        assert!(
            !outcome.success,
            "provider error must produce success:false"
        );

        // (2) WAL segment must contain a 0x8A CRON_JOB_SELF_HEAL_ALERT frame.
        let bytes = std::fs::read(&seg).unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut saw_alert = false;
        let mut alert_payload: Option<serde_json::Value> = None;
        while !cursor.is_empty() {
            let Ok(frame) = decode_frame(cursor) else {
                break;
            };
            if frame.header.event_type == EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT {
                saw_alert = true;
                alert_payload = serde_json::from_slice(frame.payload).ok();
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        assert!(
            saw_alert,
            "expected 0x8A CRON_JOB_SELF_HEAL_ALERT frame in WAL"
        );

        let payload = alert_payload.unwrap();
        assert_eq!(
            payload["job_id"].as_str(),
            Some("test-job"),
            "payload job_id must match"
        );
        assert_eq!(
            payload["cause"].as_str(),
            Some("provider_error"),
            "cause must be provider_error for a 429 error"
        );
        assert!(
            payload["risk_score"].as_f64().unwrap_or(0.0) > 0.0,
            "risk_score must be positive"
        );

        // (3) proactive_queue.json must exist and contain exactly one item.
        let queue_path = home.path().join("proactive_queue.json");
        assert!(
            queue_path.exists(),
            "proactive_queue.json must be written by the self-heal path"
        );
        let queue = ProactiveQueue::load_from(&queue_path).expect("queue must be parseable");
        let items = queue.peek();
        assert_eq!(items.len(), 1, "exactly one self-heal alert must be queued");
        let item = &items[0];
        assert_eq!(item.source, "hermes_07", "source must be hermes_07");
        assert!(
            item.is_failure,
            "is_failure must be true for a failure alert"
        );
        assert!(
            item.dedup_key.starts_with("self-heal:test-job:"),
            "dedup_key must start with self-heal:test-job: got {}",
            item.dedup_key
        );

        // (4) A second failure for the same job on the same day must be deduped
        // (the queue must still have exactly one item after re-running).
        let wal_dir2 = tempdir().unwrap();
        let seg2 = wal_dir2.path().join("hermes07b.wal");
        let (writer2, join2) = wal_spawn(seg2).unwrap();
        let _ = run_job_at(home.path(), &job, &provider, &writer2).await;
        drop(writer2);
        let _ = join2.await;
        let queue2 = ProactiveQueue::load_from(&queue_path).unwrap();
        assert_eq!(
            queue2.peek().len(),
            1,
            "same-day dedup must prevent a second alert for the same job"
        );
    }

    // ─── OH-06: Briefing system-prompt injection ──────────────────────────

    /// A provider that captures the `Request::system` field it receives.
    struct SystemCapturingProvider {
        captured_system: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl Provider for SystemCapturingProvider {
        fn name(&self) -> &'static str {
            "cap-system-mock"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            *self.captured_system.lock().unwrap() = req.system.clone();
            // Return a long enough output so the quality gate (min_words=80)
            // does not warn — it still warns in real production for short
            // outputs but we don't want it to mask the test assertions.
            let long_text = "## Morning Brief — 2026-06-22\n\n\
                Guten Morgen! Here is your daily briefing.\n\n\
                ### Tech\n- Rust 2024 edition shipped with major improvements.\n\
                - Tokio 2.0 beta released with lower p99 latency.\n\
                - Bevy 0.14 reached stable with improved GPU rendering.\n\n\
                ### Calendar\nCalendar: not connected — skipping.\n\n\
                ### News Feed\nNews feed: unavailable. Configure a feed URL to populate this section.\n\n\
                ### Summary\nA quiet morning. Check your feeds once connected.\n\
                More placeholder words to satisfy the 80-word minimum gate check here.\n"
                .to_string();
            Ok(Completion {
                text: long_text,
                identity: Default::default(),
                model: "mock".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(10),
                output_tokens: Some(120),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn briefing_job_receives_system_prompt_with_tz_and_no_fabricate() {
        // Arrange: a morning-briefing job whose name triggers classify_role → Briefing.
        let job = Job {
            id: "morning_brief_oh06".into(),
            name: "Morning Briefing".into(),
            enabled: true,
            schedule: Schedule {
                cron: "0 7 * * *".into(),
                tz: Some("Europe/Berlin".into()),
                ..Default::default()
            },
            prompt: "Summarise the overnight events.".into(),
            timeout_seconds: 30,
            delivery: None,
            execution: Default::default(),
            depends_on: vec![],
        };

        let captured_system: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let provider = authorized(SystemCapturingProvider {
            captured_system: captured_system.clone(),
        });

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("oh06.wal");
        let (writer, join) = crate::wal::spawn(seg).unwrap();

        run_job_at(dir.path(), &job, &provider, &writer)
            .await
            .expect("run_job must succeed");

        drop(writer);
        let _ = join.await;

        // Assert: system prompt was injected and contains required OH clauses.
        let sys = captured_system
            .lock()
            .unwrap()
            .clone()
            .expect("system must be Some(…) for Briefing-classified jobs");

        assert!(
            sys.contains("Europe/Berlin"),
            "tz name must appear in system prompt; got: {sys}"
        );
        assert!(
            sys.contains("200") && sys.contains("400"),
            "word-count target (200–400) must appear in system prompt; got: {sys}"
        );
        assert!(
            sys.to_ascii_lowercase().contains("fabricat")
                || sys.to_ascii_lowercase().contains("invent"),
            "no-fabricate rule must appear in system prompt; got: {sys}"
        );
        assert!(
            sys.to_ascii_lowercase().contains("gap")
                || sys.to_ascii_lowercase().contains("not connected")
                || sys.to_ascii_lowercase().contains("unavailable"),
            "honest-about-gaps rule must appear in system prompt; got: {sys}"
        );
    }

    #[tokio::test]
    async fn non_briefing_job_receives_no_system_prompt() {
        // A maintenance job must NOT get a system prompt injected.
        let job = Job {
            id: "cleanup_oh06".into(),
            name: "Database Cleanup".into(),
            enabled: true,
            schedule: Schedule {
                cron: "0 3 * * *".into(),
                tz: None,
                ..Default::default()
            },
            prompt: "Run database vacuum and prune old records.".into(),
            timeout_seconds: 60,
            delivery: None,
            execution: Default::default(),
            depends_on: vec![],
        };

        let captured_system: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let provider = authorized(SystemCapturingProvider {
            captured_system: captured_system.clone(),
        });

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("oh06_nonbriefing.wal");
        let (writer, join) = crate::wal::spawn(seg).unwrap();

        run_job_at(dir.path(), &job, &provider, &writer)
            .await
            .expect("run_job must succeed");

        drop(writer);
        let _ = join.await;

        let sys = captured_system.lock().unwrap().clone();
        assert!(
            sys.is_none(),
            "non-Briefing job must receive system: None, got Some({:?})",
            sys
        );
    }
}
