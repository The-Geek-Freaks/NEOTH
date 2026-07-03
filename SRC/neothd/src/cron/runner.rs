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

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::cron::briefing_prompt::render_briefing_system_prompt;
use crate::cron::schema::{classify_role, CronRole, Job};
use crate::profile::briefing_gate::should_emit_for_briefing;
use crate::profile::briefing_policy::{BriefingPolicy, EmitVerdict};
use crate::profile::estimators::ObservedTurn;
use crate::profile::snapshot::aggregate_and_persist;
use crate::providers::{Provider, Request};
use crate::proactive::{ProactiveItem, ProactiveQueue};
use crate::wal::events::{
    EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT, EVENT_TYPE_JOB_FAILED, EVENT_TYPE_JOB_FIRED,
    EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_JOB_SUCCESS, EVENT_TYPE_RAW_TEXT,
};
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

    // ── OH-06: inject system prompt for Briefing-classified jobs ──────────
    // `classify_role` uses keyword/name heuristic — no I/O.
    // Seed = UTC day number so the greeting is stable across the two 30 s
    // ticks that may both visit the same cron minute, but rotates daily.
    let system_prompt: Option<String> = if classify_role(job) == CronRole::Briefing {
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
        prompt: effective_prompt,
        system: system_prompt,
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

    // GOLD-ADAPT-JV-PRO-07 / JV-PRO-06 — surface output quality + failure cause.
    if ok {
        // Score the briefing's quality; a thin / filler-heavy proactive output is
        // worse than none — make it visible so the operator can tune/regenerate.
        // OH-06: raise floor to 80 words — the OH spec targets 200-400 words;
        // 40 was a pre-OH generic floor. 80 is the minimum sane "morning coffee
        // read" check (a proper 200-word brief with headings still passes at 80
        // via title/citation bonuses; pure-filler outputs are caught by filler_ratio).
        let q = crate::cron::quality_gate::score_briefing(&output_text, 80);
        if q.should_regenerate() {
            warn!(
                job_id = %job.id,
                score = q.score,
                words = q.word_count,
                filler_ratio = q.filler_ratio,
                "JV-PRO-07: low-quality briefing output — consider regenerating"
            );
        }
    } else {
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
            if let Ok(alert_payload) = serde_json::to_vec(&json!({
                "job_id": job.id,
                "cause": retro.cause.as_str(),
                "risk_score": retro.risk_score,
                "recommendation": retro.recommendation,
                "ts_unix_ms": now_unix_ms(),
            })) {
                let _ = write_event(writer, EVENT_TYPE_CRON_JOB_SELF_HEAL_ALERT, &alert_payload)
                    .await;
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
            let home = crate::config::FreedomConfig::default_neoth_home();
            let queue_path = home.join("proactive_queue.json");
            // Locked load→mutate→save; tolerates a corrupt file (same as
            // the old `unwrap_or_default()`) by silently ignoring the error
            // (this whole block is best-effort, same as `let _ =` on save).
            let _ = ProactiveQueue::modify(&queue_path, |queue| {
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
            });
        }
    }

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
    provider: &dyn Provider,
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
            error: Some(format!("briefing-gate skip: {reason}")),
        });
    }
    run_job(job, provider, writer).await
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
    use crate::cron::schema::{Job, Schedule};
    use crate::profile::estimators::BehaviouralProfile;
    use crate::profile::snapshot::load_snapshot;
    use crate::providers::{Completion, Provider, Request};
    use crate::wal::events::{EVENT_TYPE_JOB_SKIPPED_BY_GATE, EVENT_TYPE_RAW_TEXT};
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use crate::wal::spawn as wal_spawn;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tempfile::tempdir;

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
                model: "mock".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
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
        let provider = CountingProvider {
            calls: calls.clone(),
        };
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
        let provider = CountingProvider {
            calls: calls.clone(),
        };
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
    async fn cron_job_failure_enqueues_self_heal_alert_and_writes_wal_frame() {
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
        let provider = FailingProvider {
            error_msg: "http status 429 rate limit".to_string(),
        };
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

        // Set NEOTH_HOME for the duration of the test and immediately drop the
        // lock so it is NOT held across await points (clippy::await_holding_lock).
        // SAFETY: env-var mutation serialized by the lock; lock dropped before
        // any await so no MutexGuard is live across an async suspension point.
        {
            let _env = crate::test_env::lock();
            unsafe {
                std::env::set_var("NEOTH_HOME", home.path());
            }
        } // lock released here — before the first .await

        let outcome = run_job(&job, &provider, &writer)
            .await
            .expect("run_job must not error (failures are Ok(RunOutcome { success:false }))");

        drop(writer);
        let _ = join.await;

        // (1) Outcome must be a failure.
        assert!(!outcome.success, "provider error must produce success:false");

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
        assert!(saw_alert, "expected 0x8A CRON_JOB_SELF_HEAL_ALERT frame in WAL");

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
        assert!(item.is_failure, "is_failure must be true for a failure alert");
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
        let _ = run_job(&job, &provider, &writer2).await;
        drop(writer2);
        let _ = join2.await;
        let queue2 = ProactiveQueue::load_from(&queue_path).unwrap();
        assert_eq!(
            queue2.peek().len(),
            1,
            "same-day dedup must prevent a second alert for the same job"
        );

        // Cleanup: remove env var under the lock (symmetric with set above).
        {
            let _env = crate::test_env::lock();
            unsafe {
                std::env::remove_var("NEOTH_HOME");
            }
        }
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
        let provider = SystemCapturingProvider {
            captured_system: captured_system.clone(),
        };

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("oh06.wal");
        let (writer, join) = crate::wal::spawn(seg).unwrap();

        run_job(&job, &provider, &writer).await.expect("run_job must succeed");

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
        let provider = SystemCapturingProvider {
            captured_system: captured_system.clone(),
        };

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("oh06_nonbriefing.wal");
        let (writer, join) = crate::wal::spawn(seg).unwrap();

        run_job(&job, &provider, &writer).await.expect("run_job must succeed");

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
