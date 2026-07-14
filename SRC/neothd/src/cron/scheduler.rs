//! Scheduler task — reloads `jobs.yaml`, compares each job's next-run-time
//! against `now`, and dispatches the runner when due.
//!
//! Design:
//! - Each tick stages and validates a fresh file generation. Invalid rewrites
//!   keep the last valid snapshot active and raise an operator-visible warning.
//! - Runtime state is separate from the snapshot. Reload preserves state for
//!   surviving IDs, prunes deleted/re-added IDs, and keeps in-flight guards.
//! - One "last fired" timestamp kept in memory per job_id to prevent double
//!   firing inside the same minute when the tick interval (30 s) is shorter
//!   than the cron resolution (1 min).
//! - Disabled jobs are skipped. In-flight jobs finish across edit/pause/delete.
//! - Per-job timeouts and WAL events are handled inside `runner::run_job`.
//!
//! Shutdown: the loop is cancel-safe — drop the spawn handle to exit cleanly.
//! Tests cover the firing decision in isolation; live scheduler runs are
//! exercised by the integration smoke test.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::cron::runner::run_job_at;
use crate::cron::schema::{Job, JobsFile};
use crate::permissions::AutonomyLevel;
use crate::providers::cost_authorization::AuthorizedProvider;
use crate::wal::writer::WalWriterHandle;

/// Default tick = 30 s. Cron resolution is 1 min so this hits every cron
/// boundary at most twice; the in-memory `last_fired` map deduplicates.
pub const DEFAULT_TICK: Duration = Duration::from_secs(30);

/// Cron is a standing unattended capability, so the non-linear Custom policy
/// never enables it. Per-action overrides still govern explicit one-shot
/// commands, but a daemon scheduler requires one of the three linear levels
/// that intentionally opt into scheduled automation.
pub(crate) fn autonomy_allows_scheduler(autonomy: AutonomyLevel) -> bool {
    matches!(
        autonomy,
        AutonomyLevel::Standard | AutonomyLevel::Elevated | AutonomyLevel::Full
    )
}

#[derive(Debug, PartialEq, Eq)]
enum ReloadOutcome {
    Applied {
        previous_jobs: usize,
        current_jobs: usize,
        recovered: bool,
    },
    Unchanged {
        recovered: bool,
    },
    Rejected {
        error: String,
        changed_error: bool,
    },
}

/// State that must survive every validated jobs-file generation swap.
struct SchedulerState {
    jobs_file: JobsFile,
    last_fired: HashMap<String, DateTime<Utc>>,
    completed: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    running: Arc<Mutex<HashSet<String>>>,
    /// Deleted IDs whose old generation is still running. Their late result
    /// must not repopulate `completed` after reload pruning.
    retired_running: Arc<Mutex<HashSet<String>>>,
    last_reload_error: Option<String>,
}

impl SchedulerState {
    fn new(jobs_file: JobsFile) -> Self {
        Self {
            jobs_file,
            last_fired: HashMap::new(),
            completed: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(HashSet::new())),
            retired_running: Arc::new(Mutex::new(HashSet::new())),
            last_reload_error: None,
        }
    }

    /// Stage + validate first, then swap the complete in-memory generation.
    /// A missing file is a valid empty generation.
    async fn reload(&mut self, path: &Path) -> ReloadOutcome {
        let loaded = match JobsFile::load_from_path(path).await {
            Ok(jobs) => Ok(jobs),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(JobsFile::empty())
            }
            Err(error) => Err(format!("{error:#}")),
        };
        match loaded {
            Ok(next) => {
                let recovered = self.last_reload_error.take().is_some();
                if next == self.jobs_file {
                    ReloadOutcome::Unchanged { recovered }
                } else {
                    let previous_jobs = self.jobs_file.jobs.len();
                    let current_jobs = next.jobs.len();
                    let previous_ids: HashSet<&str> = self
                        .jobs_file
                        .jobs
                        .iter()
                        .map(|job| job.id.as_str())
                        .collect();
                    let current_ids: HashSet<&str> =
                        next.jobs.iter().map(|job| job.id.as_str()).collect();
                    let surviving_ids: HashSet<&str> =
                        previous_ids.intersection(&current_ids).copied().collect();
                    let running = self.running.lock().unwrap();
                    let mut retired_running = self.retired_running.lock().unwrap();
                    for deleted_id in previous_ids.difference(&current_ids) {
                        if running.contains(*deleted_id) {
                            retired_running.insert((*deleted_id).to_string());
                        }
                    }
                    self.last_fired
                        .retain(|id, _| surviving_ids.contains(id.as_str()));
                    self.completed
                        .lock()
                        .unwrap()
                        .retain(|id, _| surviving_ids.contains(id.as_str()));
                    self.jobs_file = next;
                    ReloadOutcome::Applied {
                        previous_jobs,
                        current_jobs,
                        recovered,
                    }
                }
            }
            Err(error) => {
                let changed_error = self.last_reload_error.as_deref() != Some(error.as_str());
                self.last_reload_error = Some(error.clone());
                ReloadOutcome::Rejected {
                    error,
                    changed_error,
                }
            }
        }
    }
}

/// Clears the in-flight gate on success, error, cancellation, or panic.
struct RunningJobGuard {
    job_id: String,
    running: Arc<Mutex<HashSet<String>>>,
    retired_running: Arc<Mutex<HashSet<String>>>,
}

impl Drop for RunningJobGuard {
    fn drop(&mut self) {
        let mut running = self.running.lock().unwrap();
        let mut retired_running = self.retired_running.lock().unwrap();
        running.remove(&self.job_id);
        retired_running.remove(&self.job_id);
    }
}

fn record_completion_if_current(
    completed: &Mutex<HashMap<String, DateTime<Utc>>>,
    retired_running: &Mutex<HashSet<String>>,
    job_id: String,
    completed_at: DateTime<Utc>,
) -> bool {
    let retired = retired_running.lock().unwrap();
    if retired.contains(&job_id) {
        return false;
    }
    completed.lock().unwrap().insert(job_id, completed_at);
    true
}

/// Run the scheduler loop until the future is dropped.
pub async fn run_scheduler(
    home: PathBuf,
    jobs_path: PathBuf,
    jobs_file: JobsFile,
    provider: Arc<AuthorizedProvider>,
    writer: WalWriterHandle,
    reload_controller: Arc<crate::config::reload::ReloadController>,
) -> Result<()> {
    let mut state = SchedulerState::new(jobs_file);
    let mut ticker = interval(DEFAULT_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut dispatch_enabled = true;

    info!(jobs = state.jobs_file.jobs.len(), path = %jobs_path.display(), "cron scheduler online");
    loop {
        ticker.tick().await;
        let autonomy = reload_controller.latest().autonomy;
        if !autonomy_allows_scheduler(autonomy) {
            if dispatch_enabled {
                info!(
                    autonomy = autonomy.as_str(),
                    "cron scheduler paused by reloaded autonomy policy; no new jobs will dispatch"
                );
            }
            dispatch_enabled = false;
            continue;
        }
        if !dispatch_enabled {
            info!(
                autonomy = autonomy.as_str(),
                "cron scheduler resumed by reloaded autonomy policy"
            );
            dispatch_enabled = true;
        }
        match state.reload(&jobs_path).await {
            ReloadOutcome::Applied {
                previous_jobs,
                current_jobs,
                recovered,
            } => info!(
                path = %jobs_path.display(),
                previous_jobs,
                current_jobs,
                recovered,
                "cron jobs snapshot reloaded"
            ),
            ReloadOutcome::Unchanged { recovered: true } => info!(
                path = %jobs_path.display(),
                jobs = state.jobs_file.jobs.len(),
                "cron jobs file valid again; continuing with current snapshot"
            ),
            ReloadOutcome::Rejected {
                error,
                changed_error: true,
            } => warn!(
                path = %jobs_path.display(),
                error = %error,
                jobs = state.jobs_file.jobs.len(),
                "cron jobs reload rejected; keeping last valid snapshot"
            ),
            ReloadOutcome::Rejected {
                error,
                changed_error: false,
            } => debug!(
                path = %jobs_path.display(),
                error = %error,
                "cron jobs reload still invalid; keeping last valid snapshot"
            ),
            ReloadOutcome::Unchanged { recovered: false } => {}
        }
        let now = crate::time::utc_now();
        // Snapshot completions (brief lock; never held across an await), then ask
        // the validated wave scheduler which jobs are dependency-ready this tick.
        // A job with no `depends_on` is always ready, so no-dependency behaviour
        // is byte-identical to before.
        let completed_at: HashMap<String, DateTime<Utc>> = state.completed.lock().unwrap().clone();
        let completed_set: HashSet<String> = completed_at.keys().cloned().collect();
        // All decisions in this tick use one immutable validated generation.
        let jobs = state.jobs_file.jobs.clone();
        let ready: HashSet<String> = crate::cron::schema::ready_jobs(
            &jobs,
            &completed_set,
            now,
            &completed_at,
            crate::cron::schema::DEFAULT_FRESHNESS,
        )
        .into_iter()
        .collect();
        for job in &jobs {
            if !job.enabled {
                continue;
            }
            // JV-PRO-03 — hold a job whose `depends_on` are unmet or stale, even
            // if its cron time is due.
            if !ready.contains(&job.id) {
                continue;
            }
            if should_fire_now(job, now, state.last_fired.get(&job.id).copied()) {
                // Preserve the in-flight gate across reloads; a changed job id
                // cannot dispatch twice while its old generation still runs.
                if !state.running.lock().unwrap().insert(job.id.clone()) {
                    debug!(job_id = %job.id, "cron job still running; skipping overlapping fire");
                    continue;
                }
                state.last_fired.insert(job.id.clone(), now);
                let writer_for_task = writer.clone();
                let provider_for_task = provider.clone();
                let job_for_task = job.clone();
                let completed_for_task = state.completed.clone();
                let running_for_task = state.running.clone();
                let retired_for_task = state.retired_running.clone();
                let job_id = job.id.clone();
                let home_for_task = home.clone();
                tokio::spawn(async move {
                    let _running_guard = RunningJobGuard {
                        job_id: job_id.clone(),
                        running: running_for_task,
                        retired_running: retired_for_task.clone(),
                    };
                    match run_job_at(
                        &home_for_task,
                        &job_for_task,
                        provider_for_task.as_ref(),
                        &writer_for_task,
                    )
                    .await
                    {
                        Ok(_) => {
                            // Deleted generations may finish, but their result
                            // must not satisfy dependencies of a re-added ID.
                            record_completion_if_current(
                                &completed_for_task,
                                &retired_for_task,
                                job_id,
                                crate::time::utc_now(),
                            );
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
    fn scheduler_autonomy_rail_is_explicit_and_custom_fail_closed() {
        assert!(!autonomy_allows_scheduler(AutonomyLevel::Strict));
        assert!(!autonomy_allows_scheduler(AutonomyLevel::Custom));
        for allowed in [
            AutonomyLevel::Standard,
            AutonomyLevel::Elevated,
            AutonomyLevel::Full,
        ] {
            assert!(autonomy_allows_scheduler(allowed), "{allowed:?}");
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

    fn snapshot(jobs: Vec<Job>) -> JobsFile {
        JobsFile { version: 1, jobs }
    }

    #[tokio::test]
    async fn live_reload_applies_add_edit_pause_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let mut state = SchedulerState::new(JobsFile::empty());
        let mut job = job_at("* * * * *");
        job.id = "live".into();
        job.name = "Initial".into();

        snapshot(vec![job.clone()]).save_to_path(&path).unwrap();
        assert_eq!(
            state.reload(&path).await,
            ReloadOutcome::Applied {
                previous_jobs: 0,
                current_jobs: 1,
                recovered: false,
            }
        );

        job.name = "Edited".into();
        job.prompt = "edited prompt".into();
        snapshot(vec![job.clone()]).save_to_path(&path).unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Applied { .. }
        ));
        assert_eq!(state.jobs_file.jobs[0].prompt, "edited prompt");

        job.enabled = false;
        snapshot(vec![job]).save_to_path(&path).unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Applied { .. }
        ));
        assert!(!state.jobs_file.jobs[0].enabled);

        JobsFile::empty().save_to_path(&path).unwrap();
        assert_eq!(
            state.reload(&path).await,
            ReloadOutcome::Applied {
                previous_jobs: 1,
                current_jobs: 0,
                recovered: false,
            }
        );
    }

    #[tokio::test]
    async fn invalid_rewrite_keeps_snapshot_and_runtime_state_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let valid = snapshot(vec![job_at("* * * * *")]);
        valid.save_to_path(&path).unwrap();
        let mut state = SchedulerState::new(valid.clone());
        let fired_at = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        state.last_fired.insert("j".into(), fired_at);
        state.completed.lock().unwrap().insert("j".into(), fired_at);
        state.running.lock().unwrap().insert("j".into());

        std::fs::write(&path, "version: 1\njobs: [").unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Rejected {
                changed_error: true,
                ..
            }
        ));
        assert_eq!(state.jobs_file, valid);
        assert_eq!(state.last_fired["j"], fired_at);
        assert_eq!(state.completed.lock().unwrap()["j"], fired_at);
        assert!(state.running.lock().unwrap().contains("j"));
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Rejected {
                changed_error: false,
                ..
            }
        ));

        valid.save_to_path(&path).unwrap();
        assert_eq!(
            state.reload(&path).await,
            ReloadOutcome::Unchanged { recovered: true }
        );
    }

    #[tokio::test]
    async fn reload_does_not_double_fire_or_forget_running_job() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let mut job = job_at("* * * * *");
        let initial = snapshot(vec![job.clone()]);
        initial.save_to_path(&path).unwrap();
        let mut state = SchedulerState::new(initial);
        let fired_at = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        state.last_fired.insert("j".into(), fired_at);
        state.running.lock().unwrap().insert("j".into());

        job.prompt = "new generation, same logical job".into();
        snapshot(vec![job]).save_to_path(&path).unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Applied { .. }
        ));
        let same_boundary = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 20).unwrap();
        assert!(!should_fire_now(
            &state.jobs_file.jobs[0],
            same_boundary,
            state.last_fired.get("j").copied(),
        ));
        assert!(!state.running.lock().unwrap().insert("j".into()));
    }

    #[tokio::test]
    async fn missing_file_is_empty_generation_and_prunes_deleted_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let valid = snapshot(vec![job_at("* * * * *")]);
        let mut state = SchedulerState::new(valid);
        let fired_at = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        state.last_fired.insert("j".into(), fired_at);
        state.completed.lock().unwrap().insert("j".into(), fired_at);
        state.running.lock().unwrap().insert("j".into());
        assert_eq!(
            state.reload(&path).await,
            ReloadOutcome::Applied {
                previous_jobs: 1,
                current_jobs: 0,
                recovered: false,
            }
        );
        assert!(state.jobs_file.jobs.is_empty());
        assert!(state.last_fired.is_empty());
        assert!(state.completed.lock().unwrap().is_empty());
        assert!(
            state.running.lock().unwrap().contains("j"),
            "in-flight deletion guard must live until the task exits"
        );
        assert!(
            state.retired_running.lock().unwrap().contains("j"),
            "late completion from the deleted generation must be suppressed"
        );
        assert!(!record_completion_if_current(
            &state.completed,
            &state.retired_running,
            "j".into(),
            fired_at,
        ));
        assert!(state.completed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn readded_id_cannot_inherit_completion_written_after_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let valid = snapshot(vec![job_at("* * * * *")]);
        let mut state = SchedulerState::new(valid);
        let completed_at = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();

        JobsFile::empty().save_to_path(&path).unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Applied { .. }
        ));
        // Simulate the deleted generation finishing after the delete reload.
        state
            .completed
            .lock()
            .unwrap()
            .insert("j".into(), completed_at);

        snapshot(vec![job_at("* * * * *")])
            .save_to_path(&path)
            .unwrap();
        assert!(matches!(
            state.reload(&path).await,
            ReloadOutcome::Applied { .. }
        ));
        assert!(
            state.completed.lock().unwrap().is_empty(),
            "a re-added ID must start without the deleted generation's completion"
        );
    }
}
