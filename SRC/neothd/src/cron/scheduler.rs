//! Scheduler task — ticks every 30 s, compares each job's next-run-time
//! against `now`, dispatches the runner when due.
//!
//! Design:
//! - Stateless tick. `Schedule::next_after(now)` is cheap (parsed cron is
//!   amortised per call but each parse is < 5 µs). We don't pre-compute a
//!   priority queue; for ≤100 jobs the linear scan is fine.
//! - One "last fired" timestamp kept in memory per job_id to prevent double
//!   firing inside the same minute when the tick interval (30 s) is shorter
//!   than the cron resolution (1 min).
//! - Disabled jobs are skipped at scan time.
//! - Per-job timeouts and WAL events are handled inside `runner::run_job`.
//!
//! Shutdown: the loop is cancel-safe — drop the spawn handle to exit cleanly.
//! Tests cover the firing decision in isolation; live scheduler runs are
//! exercised by the integration smoke test.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::cron::runner::run_job;
use crate::cron::schema::{Job, JobsFile};
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

/// Default tick = 30 s. Cron resolution is 1 min so this hits every cron
/// boundary at most twice; the in-memory `last_fired` map deduplicates.
pub const DEFAULT_TICK: Duration = Duration::from_secs(30);

/// Run the scheduler loop until the future is dropped.
pub async fn run_scheduler(
    jobs_file: JobsFile,
    provider: Arc<dyn Provider>,
    writer: WalWriterHandle,
) -> Result<()> {
    let mut last_fired: HashMap<String, DateTime<Utc>> = HashMap::new();
    // JV-PRO-03 — actual completion times (`job_id` → `completed_at`), updated by
    // each spawned `run_job` task on success. `ready_jobs` reads this so a job
    // with `depends_on` only fires AFTER its dependencies have COMPLETED (not
    // merely fired) within the freshness window — the wave/dependency gate.
    let completed: Arc<Mutex<HashMap<String, DateTime<Utc>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut ticker = interval(DEFAULT_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(jobs = jobs_file.jobs.len(), "cron scheduler online");
    loop {
        ticker.tick().await;
        let now = Utc::now();
        // Snapshot completions (brief lock; never held across an await), then ask
        // the validated wave scheduler which jobs are dependency-ready this tick.
        // A job with no `depends_on` is always ready, so no-dependency behaviour
        // is byte-identical to before.
        let completed_at: HashMap<String, DateTime<Utc>> = completed.lock().unwrap().clone();
        let completed_set: HashSet<String> = completed_at.keys().cloned().collect();
        let ready: HashSet<String> = crate::cron::schema::ready_jobs(
            &jobs_file.jobs,
            &completed_set,
            now,
            &completed_at,
            crate::cron::schema::DEFAULT_FRESHNESS,
        )
        .into_iter()
        .collect();
        for job in &jobs_file.jobs {
            if !job.enabled {
                continue;
            }
            // JV-PRO-03 — hold a job whose `depends_on` are unmet or stale, even
            // if its cron time is due.
            if !ready.contains(&job.id) {
                continue;
            }
            if should_fire_now(job, now, last_fired.get(&job.id).copied()) {
                last_fired.insert(job.id.clone(), now);
                let writer_for_task = writer.clone();
                let provider_for_task = provider.clone();
                let job_for_task = job.clone();
                let completed_for_task = completed.clone();
                let job_id = job.id.clone();
                tokio::spawn(async move {
                    match run_job(&job_for_task, provider_for_task.as_ref(), &writer_for_task).await
                    {
                        Ok(_) => {
                            // Record completion so dependents become ready.
                            completed_for_task
                                .lock()
                                .unwrap()
                                .insert(job_id, Utc::now());
                        }
                        Err(e) => {
                            warn!(job_id = %job_for_task.id, error = %e, "job dispatch error");
                        }
                    }
                });
            }
        }
        debug!("scheduler tick complete");
    }
}

/// Should this job fire on this tick?
///
/// Decision = ("the most recent scheduled fire time at or before now") is
/// strictly after the last time we actually fired it. Within the same minute
/// we therefore fire exactly once, even though the 30 s tick visits twice.
pub fn should_fire_now(job: &Job, now: DateTime<Utc>, last_fired: Option<DateTime<Utc>>) -> bool {
    let Ok(sched) = job.schedule.parse() else {
        return false;
    };
    let tz = job.schedule.timezone();
    let now_local = now.with_timezone(&tz);
    // The cron crate doesn't expose `prev`. We walk forward from a window
    // start (now - 2 min) and pick the latest fire <= now.
    let window_start = (now_local - chrono::Duration::minutes(2)).with_timezone(&tz);
    let latest_due = sched
        .after(&window_start)
        .take(5)
        .filter(|t| *t <= now_local)
        .last()
        .map(|t| t.with_timezone(&Utc));
    let Some(due) = latest_due else {
        return false;
    };
    match last_fired {
        Some(prev) => due > prev,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::schema::Schedule;
    use chrono::TimeZone;

    fn job_at(cron: &str) -> Job {
        Job {
            id: "j".to_string(),
            name: "j".to_string(),
            enabled: true,
            schedule: Schedule {
                cron: cron.to_string(),
                tz: Some("UTC".to_string()),
            },
            prompt: "hi".to_string(),
            timeout_seconds: 60,
            delivery: None,
            depends_on: vec![],
        }
    }

    #[test]
    fn fires_at_exact_minute_match() {
        // Cron: every minute at second 0. The normalization in
        // schema.rs prepends "0 " so the underlying expr is "0 * * * * *",
        // i.e. fires at every minute boundary.
        let job = job_at("* * * * *");
        // 2026-05-14 12:00:00 UTC — a clean minute boundary.
        let now = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        assert!(should_fire_now(&job, now, None));
    }

    #[test]
    fn does_not_refire_within_same_minute() {
        let job = job_at("* * * * *");
        let t0 = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        // Second visit 20 s later — same cron boundary.
        let t1 = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 20).unwrap();
        assert!(should_fire_now(&job, t0, None));
        assert!(!should_fire_now(&job, t1, Some(t0)));
    }

    #[test]
    fn fires_again_after_next_boundary() {
        let job = job_at("* * * * *");
        let t0 = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        let t1 = Utc.with_ymd_and_hms(2026, 5, 14, 12, 1, 5).unwrap();
        assert!(should_fire_now(&job, t1, Some(t0)));
    }

    #[test]
    fn disabled_jobs_are_skipped_by_caller() {
        // `should_fire_now` does not check enabled — that's the loop's job.
        // But the function should still return correct timing for disabled
        // jobs so the scheduler can render previews.
        let mut job = job_at("* * * * *");
        job.enabled = false;
        let now = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        assert!(should_fire_now(&job, now, None));
    }

    #[test]
    fn far_future_cron_returns_false_safely() {
        // Cron that has matched once and won't match again in the lookback window.
        let job = job_at("0 7 * * *"); // 7:00 daily
        // It's 12:15 — last 7am was hours ago, outside the 2 min window.
        let now = Utc.with_ymd_and_hms(2026, 5, 14, 12, 15, 0).unwrap();
        assert!(!should_fire_now(&job, now, None));
    }
}
