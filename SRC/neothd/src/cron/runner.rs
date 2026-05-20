//! Job runner — executes one job's prompt through the configured provider
//! and (optionally) delivers the result through a channel.
//!
//! Each invocation writes WAL events 0x40 (FIRED) → 0x41 (SUCCESS) / 0x42 (FAILED).
//!
//! V1 simplifying assumptions:
//! - All jobs share the operator's primary provider (from `freedom.yaml`).
//!   Per-job model overrides arrive when the plugin SDK lands.
//! - Channel delivery uses the same `channels::Channel::send_proactive` path
//!   the heartbeat loop (Phase 11c) will share.
//! - Timeout enforced via `tokio::time::timeout`. On timeout the job goes to
//!   FAILED. No retry today.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::cron::schema::Job;
use crate::providers::{Provider, Request};
use crate::wal::events::{EVENT_TYPE_JOB_FAILED, EVENT_TYPE_JOB_FIRED, EVENT_TYPE_JOB_SUCCESS};
use crate::wal::{EventFlags, writer::WalWriterHandle};

pub struct RunOutcome {
    pub success: bool,
    pub duration: Duration,
    pub output_bytes: usize,
    pub error: Option<String>,
}

pub async fn run_job(
    job: &Job,
    provider: &dyn Provider,
    writer: &WalWriterHandle,
) -> Result<RunOutcome> {
    let started = Instant::now();

    // ── WAL: FIRED ─────────────────────────────────────────────────────────
    let fired_payload = serde_json::to_vec(&json!({
        "job_id": job.id,
        "name": job.name,
        "schedule_expr": job.schedule.cron,
        "tz": job.schedule.tz.clone().unwrap_or_else(|| "UTC".to_string()),
        "fired_at_unix_ms": now_unix_ms(),
    }))?;
    write_event(writer, EVENT_TYPE_JOB_FIRED, &fired_payload)
        .await
        .context("write JOB_FIRED")?;

    info!(job_id = %job.id, name = %job.name, "job firing");

    // ── JobFired hooks (Phase 29 R-15) ─────────────────────────────────────
    // Fires after the JOB_FIRED audit frame so the WAL records the job
    // even if the hook blocks it. A Replace rewrites the prompt the
    // provider sees (useful for redacting secrets before they leave the
    // daemon); a Block skips the provider call entirely with a
    // JOB_FAILED frame recording the hook name as the cause.
    let hook_dir = crate::config::FreedomConfig::default_neoth_home().join("hooks");
    let hooks = crate::hooks::load_all(&hook_dir).await.unwrap_or_default();
    let effective_prompt =
        match crate::hooks::run_stage(crate::hooks::HookStage::JobFired, &job.prompt, &hooks) {
            Ok(crate::hooks::StageOutcome::Continue { body, hits }) => {
                for name in &hits {
                    if let Ok(payload) = serde_json::to_vec(&json!({
                        "name": name,
                        "stage": "job_fired",
                        "job_id": job.id,
                        "ts_unix_ms": now_unix_ms(),
                    })) {
                        let _ = write_event(
                            writer,
                            crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                            &payload,
                        )
                        .await;
                    }
                }
                body
            }
            Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                warn!(job_id = %job.id, hook = %name, reason = %reason,
                "job_fired hook blocked the run");
                if let Ok(payload) = serde_json::to_vec(&json!({
                    "name": name,
                    "stage": "job_fired",
                    "job_id": job.id,
                    "reason": reason,
                    "ts_unix_ms": now_unix_ms(),
                })) {
                    let _ = write_event(
                        writer,
                        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                        &payload,
                    )
                    .await;
                }
                return Ok(RunOutcome {
                    success: false,
                    duration: started.elapsed(),
                    output_bytes: 0,
                    error: Some(format!("blocked by hook `{name}`: {reason}")),
                });
            }
            Err(e) => {
                warn!(job_id = %job.id, error = %e, "job_fired hook dispatch failed");
                job.prompt.clone()
            }
        };

    // ── Provider call (bounded by timeout_seconds) ─────────────────────────
    let req = Request {
        prompt: effective_prompt,
        system: None,
        model: None,
        ..Default::default()
    };
    let timeout_dur = Duration::from_secs(job.timeout_seconds.max(1) as u64);
    let result = timeout(timeout_dur, provider.complete(req)).await;

    let elapsed = started.elapsed();

    let (ok, output_text, err_text) = match result {
        Ok(Ok(completion)) => {
            debug!(
                job_id = %job.id,
                bytes = completion.text.len(),
                latency_ms = elapsed.as_millis(),
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

    // ── WAL: SUCCESS / FAILED ──────────────────────────────────────────────
    let outcome_payload = serde_json::to_vec(&json!({
        "job_id": job.id,
        "name": job.name,
        "duration_ms": elapsed.as_millis() as u64,
        "output_bytes": output_text.len(),
        "error": err_text,
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
    match crate::hooks::run_stage(crate::hooks::HookStage::JobDone, &outcome_body, &hooks) {
        Ok(crate::hooks::StageOutcome::Continue { hits, .. }) => {
            for name in &hits {
                if let Ok(payload) = serde_json::to_vec(&json!({
                    "name": name,
                    "stage": "job_done",
                    "job_id": job.id,
                    "ok": ok,
                    "ts_unix_ms": now_unix_ms(),
                })) {
                    let _ =
                        write_event(writer, crate::wal::events::EVENT_TYPE_HOOK_FIRED, &payload)
                            .await;
                }
            }
        }
        Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
            // Can't unwind a completed job — log + emit audit only.
            warn!(job_id = %job.id, hook = %name, reason = %reason,
                "job_done hook returned Block; ignored (job already completed)");
        }
        Err(e) => warn!(job_id = %job.id, error = %e, "job_done hook dispatch failed"),
    }

    // Channel delivery is deferred to a future iteration that wires the
    // proactive-send trait method on Channel. For now we land the output in
    // the WAL only; recall finds it via idx_episode.

    Ok(RunOutcome {
        success: ok,
        duration: elapsed,
        output_bytes: output_text.len(),
        error: err_text,
    })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn write_event(writer: &WalWriterHandle, event_type: u8, payload: &[u8]) -> Result<u64> {
    // Phase 33a AU-B3: builder owns header construction. Cron events are
    // SYNTHETIC because no operator turn produced them.
    let header = crate::wal::HeaderBuilder::new(event_type, payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    Ok(writer.append(header, payload.to_vec()).await?)
}
