//! Job runner — executes one job's prompt through the configured provider
//! and (optionally) delivers the result through a channel.
//!
//! Each invocation writes WAL events 0x40 (FIRED) → 0x41 (SUCCESS) / 0x42 (FAILED).
//!
//! Current execution contract:
//! - Jobs use the scheduler's authorized provider. Per-job provider/model
//!   selection is tracked as an explicit Gold contract gap in the roadmap.
//! - Channel delivery is first persisted to the proactive queue and is later
//!   sent through the normal channel dispatcher.
//! - The provider deadline covers the initial call and, for briefing-class
//!   jobs only, one quality-gate regeneration. Provider failures and timeouts
//!   are terminal; rejected briefings are never queued for delivery.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::cron::briefing_prompt::render_briefing_system_prompt;
use crate::cron::schema::{CronRole, Job, classify_role};
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
    pub error: Option<String>,
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
    let proactive_queue_path = home.join("proactive_queue.json");
    let hook_dir = home.join("hooks");
    run_job_with_paths(
        job,
        provider,
        writer,
        &proactive_queue_path,
        &hook_dir,
        crate::hooks::run_stage,
    )
    .await
}

async fn run_job_with_paths(
    job: &Job,
    provider: &AuthorizedProvider,
    writer: &WalWriterHandle,
    proactive_queue_path: &Path,
    hook_dir: &Path,
    hook_dispatch: HookDispatcher,
) -> Result<RunOutcome> {
    let started = Instant::now();

    // ── WAL: FIRED ─────────────────────────────────────────────────────────
    let fired_at_unix_ms = now_unix_ms();
    let fired_payload = serde_json::to_vec(&json!({
        "job_id": job.id,
        "name": job.name,
        "schedule_expr": job.schedule.cron,
        "tz": job.schedule.tz.clone().unwrap_or_else(|| "UTC".to_string()),
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
    let system_prompt: Option<String> = if is_briefing {
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

    // ── Provider call (bounded by timeout_seconds) ─────────────────────────
    let req = Request {
        prompt: effective_prompt.clone(),
        system: system_prompt,
        model: None,
        ..Default::default()
    };
    let timeout_dur = Duration::from_secs(job.timeout_seconds.max(1) as u64);
    let provider_deadline = tokio::time::Instant::now() + timeout_dur;
    let result = tokio::time::timeout_at(provider_deadline, provider.complete(req.clone())).await;

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

    let elapsed = started.elapsed();
    let mut delivery_queued = false;
    if ok {
        if let Some(delivery) = &job.delivery {
            let channel = delivery.channel.trim().to_ascii_lowercase();
            let dedup_key = format!("cron-delivery:{}:{fired_event_id}", job.id);
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
                    info!(
                        job_id = %job.id,
                        channel = %channel,
                        dedup_key = %dedup_key,
                        inserted,
                        "cron delivery durably queued for proactive dispatch"
                    );
                }
                Err(error) => {
                    let message = format!(
                        "provider completed, but delivery queue persistence failed for channel \
                         `{channel}`: {error:#}"
                    );
                    warn!(job_id = %job.id, channel = %channel, error = %error,
                        "cron delivery enqueue failed; marking run failed closed");
                    ok = false;
                    err_text = Some(message);
                }
            }
        }
    }

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
        "delivered": false,
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
        error: err_text,
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
            },
            prompt: "Summarise overnight activity.".into(),
            timeout_seconds: 30,
            delivery: None,
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
            },
            prompt: "produce a delivery".into(),
            timeout_seconds: 30,
            delivery: Some(Delivery::new(channel)),
            depends_on: vec![],
        }
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
            &job,
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
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
            &job,
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
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
            &delivery_job("telegram"),
            &provider,
            &writer,
            &queue_path,
            &dir.path().join("hooks"),
            crate::hooks::run_stage,
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
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &hook_dir,
            crate::hooks::run_stage,
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
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &hook_dir,
            crate::hooks::run_stage,
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
            &briefing_job(),
            &provider,
            &writer,
            &dir.path().join("queue.json"),
            &dir.path().join("hooks"),
            failing_hook_dispatch,
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
            },
            prompt: "do something".into(),
            timeout_seconds: 30,
            delivery: None,
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
            },
            prompt: "Summarise the overnight events.".into(),
            timeout_seconds: 30,
            delivery: None,
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
            },
            prompt: "Run database vacuum and prune old records.".into(),
            timeout_seconds: 60,
            delivery: None,
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
