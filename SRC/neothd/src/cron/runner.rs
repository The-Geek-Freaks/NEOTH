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

use crate::cron::schema::Job;
use crate::profile::briefing_gate::should_emit_for_briefing;
use crate::profile::briefing_policy::{BriefingPolicy, EmitVerdict};
use crate::profile::estimators::ObservedTurn;
use crate::profile::snapshot::aggregate_and_persist;
use crate::providers::{Provider, Request};
use crate::wal::events::{
    EVENT_TYPE_JOB_FAILED, EVENT_TYPE_JOB_FIRED, EVENT_TYPE_JOB_SKIPPED_BY_GATE,
    EVENT_TYPE_JOB_SUCCESS, EVENT_TYPE_RAW_TEXT,
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

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
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
}
