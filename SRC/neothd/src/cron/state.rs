//! Durable Cron runtime and delivery truth.
//!
//! jobs.yaml is operator intent. This sidecar stores only scheduler cursors and
//! delivery outcomes, keyed by a SHA-256 job-generation fingerprint. A job edit
//! keeps the logical schedule's fire cursor to prevent restart double-fires,
//! while completion state is generation-bound and is never inherited.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::schema::{DeliveryMode, Job};

static STATE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeState {
    #[serde(default = "state_version")]
    pub version: u32,
    #[serde(default)]
    pub jobs: BTreeMap<String, JobRuntimeState>,
    #[serde(default)]
    pub deliveries: BTreeMap<String, DeliveryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRuntimeState {
    pub generation_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fired: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Queued,
    Delivered,
    Failed,
    Suppressed,
    SidecarOnly,
    Skipped,
    CrashUnknown,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Suppressed => "suppressed",
            Self::SidecarOnly => "sidecar_only",
            Self::Skipped => "skipped",
            Self::CrashUnknown => "crash_unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub delivery_id: String,
    pub job_id: String,
    pub fired_event_id: u64,
    pub mode: DeliveryMode,
    pub target_sha256: String,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub best_effort: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn state_version() -> u32 {
    1
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            version: state_version(),
            jobs: BTreeMap::new(),
            deliveries: BTreeMap::new(),
        }
    }
}

pub fn path(home: &Path) -> PathBuf {
    home.join("cron_runtime_state.json")
}

pub fn job_generation(job: &Job) -> Result<String> {
    let bytes = serde_json::to_vec(job).context("serialize Cron job generation")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn target_hash(target: &str) -> String {
    hex::encode(Sha256::digest(target.as_bytes()))
}

impl RuntimeState {
    pub fn load(home: &Path) -> Result<Self> {
        Self::load_unlocked(home)
    }

    fn load_unlocked(home: &Path) -> Result<Self> {
        let path = path(home);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let state: Self =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        if state.version != state_version() {
            anyhow::bail!(
                "unsupported Cron runtime-state version {} at {}",
                state.version,
                path.display()
            );
        }
        Ok(state)
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        let _guard = STATE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("Cron runtime-state lock poisoned"))?;
        self.save_unlocked(home)
    }

    fn save_unlocked(&self, home: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize Cron runtime state")?;
        crate::util::atomic_write::atomic_write_private(&path(home), &bytes)
            .context("persist Cron runtime state")
    }

    /// Serialised read-modify-write so scheduler cursors and asynchronous
    /// delivery outcomes cannot overwrite one another.
    pub fn modify<T>(home: &Path, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let _guard = STATE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("Cron runtime-state lock poisoned"))?;
        let mut state = Self::load_unlocked(home)?;
        let result = f(&mut state)?;
        state.save_unlocked(home)?;
        Ok(result)
    }

    pub fn reconcile(&mut self, jobs: &[Job]) -> Result<()> {
        let mut next = BTreeMap::new();
        for job in jobs {
            let generation_sha256 = job_generation(job)?;
            let entry = self.jobs.get(&job.id);
            let reconciled = match entry {
                Some(entry) if entry.generation_sha256 == generation_sha256 => entry.clone(),
                Some(entry) => JobRuntimeState {
                    generation_sha256,
                    // The id identifies one logical schedule. Preserve its last
                    // consumed boundary across prompt/delivery edits so a
                    // restart inside the lookback window cannot fire it twice.
                    last_fired: entry.last_fired,
                    // A successful outcome belongs to the exact job generation
                    // that produced it and must not satisfy edited dependencies.
                    completed_at: None,
                },
                None => JobRuntimeState {
                    generation_sha256,
                    last_fired: None,
                    completed_at: None,
                },
            };
            next.insert(job.id.clone(), reconciled);
        }
        self.jobs = next;
        Ok(())
    }

    pub fn record_fire(&mut self, job: &Job, fired_at: DateTime<Utc>) -> Result<()> {
        let generation = job_generation(job)?;
        let entry = self.jobs.entry(job.id.clone()).or_insert(JobRuntimeState {
            generation_sha256: generation.clone(),
            last_fired: None,
            completed_at: None,
        });
        if entry.generation_sha256 != generation {
            *entry = JobRuntimeState {
                generation_sha256: generation,
                last_fired: None,
                completed_at: None,
            };
        }
        entry.last_fired = Some(fired_at);
        Ok(())
    }

    pub fn record_completion(&mut self, job: &Job, completed_at: DateTime<Utc>) -> Result<bool> {
        let generation = job_generation(job)?;
        let Some(entry) = self.jobs.get_mut(&job.id) else {
            return Ok(false);
        };
        if entry.generation_sha256 != generation {
            return Ok(false);
        }
        entry.last_fired.get_or_insert(completed_at);
        entry.completed_at = Some(completed_at);
        Ok(true)
    }

    pub fn begin_delivery(
        &mut self,
        delivery_id: String,
        job_id: String,
        fired_event_id: u64,
        mode: DeliveryMode,
        target_sha256: String,
        best_effort: bool,
    ) {
        let now = crate::time::utc_now();
        self.deliveries
            .entry(delivery_id.clone())
            .or_insert(DeliveryRecord {
                delivery_id,
                job_id,
                fired_event_id,
                mode,
                target_sha256,
                status: DeliveryStatus::Pending,
                attempts: 0,
                best_effort,
                created_at: now,
                updated_at: now,
                error: None,
            });
        const MAX_RECORDS: usize = 2_000;
        while self.deliveries.len() > MAX_RECORDS {
            let Some(oldest) = self
                .deliveries
                .iter()
                .min_by_key(|(_, record)| record.updated_at)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.deliveries.remove(&oldest);
        }
    }

    pub fn update_delivery(
        &mut self,
        delivery_id: &str,
        status: DeliveryStatus,
        error: Option<String>,
    ) -> Result<()> {
        let record = self
            .deliveries
            .get_mut(delivery_id)
            .with_context(|| format!("unknown Cron delivery id `{delivery_id}`"))?;
        record.status = status;
        record.attempts = record.attempts.saturating_add(1);
        record.updated_at = crate::time::utc_now();
        record.error = error;
        Ok(())
    }
}

/// Correlate the proactive dispatcher's final channel result back to the exact
/// Cron delivery. Non-Cron items are ignored.
pub fn update_announce_result(
    home: &Path,
    dedup_key: &str,
    status: DeliveryStatus,
) -> Result<bool> {
    let Some(delivery_id) = dedup_key.strip_prefix("cron-delivery:") else {
        return Ok(false);
    };
    RuntimeState::modify(home, |state| {
        if !state.deliveries.contains_key(delivery_id) {
            return Ok(false);
        }
        state.update_delivery(delivery_id, status, None)?;
        Ok(true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::schema::{ExecutionPolicy, Schedule};

    fn job(prompt: &str) -> Job {
        Job {
            id: "j".into(),
            name: "job".into(),
            enabled: true,
            schedule: Schedule {
                every_seconds: Some(60),
                ..Default::default()
            },
            prompt: prompt.into(),
            timeout_seconds: 60,
            delivery: None,
            execution: ExecutionPolicy::default(),
            depends_on: vec![],
        }
    }

    #[test]
    fn edited_generation_keeps_fire_cursor_but_not_completion() {
        let mut state = RuntimeState::default();
        let first = job("first");
        state.reconcile(std::slice::from_ref(&first)).unwrap();
        let fired_at = crate::time::utc_now();
        state.record_fire(&first, fired_at).unwrap();
        state.record_completion(&first, fired_at).unwrap();
        let edited = job("second");
        state.reconcile(std::slice::from_ref(&edited)).unwrap();
        assert_eq!(state.jobs["j"].last_fired, Some(fired_at));
        assert!(state.jobs["j"].completed_at.is_none());
    }

    #[test]
    fn stale_generation_completion_cannot_replace_current_disk_state() {
        let mut state = RuntimeState::default();
        let first = job("first");
        state.reconcile(std::slice::from_ref(&first)).unwrap();
        let first_fire = crate::time::utc_now();
        state.record_fire(&first, first_fire).unwrap();
        let edited = job("second");
        state.reconcile(std::slice::from_ref(&edited)).unwrap();
        let generation_before = state.jobs["j"].generation_sha256.clone();

        assert!(
            !state
                .record_completion(&first, first_fire + chrono::Duration::seconds(1))
                .unwrap(),
            "a completion from the retired generation must be ignored"
        );
        let current = &state.jobs["j"];
        assert_eq!(current.generation_sha256, generation_before);
        assert_eq!(current.last_fired, Some(first_fire));
        assert!(current.completed_at.is_none());
    }

    #[test]
    fn delivery_round_trip_keeps_correlation() {
        let home = tempfile::tempdir().unwrap();
        let mut state = RuntimeState::default();
        state.begin_delivery(
            "abc".into(),
            "j".into(),
            7,
            DeliveryMode::Announce,
            target_hash("telegram:123"),
            false,
        );
        state.save(home.path()).unwrap();
        update_announce_result(home.path(), "cron-delivery:abc", DeliveryStatus::Delivered)
            .unwrap();
        let loaded = RuntimeState::load(home.path()).unwrap();
        assert_eq!(loaded.deliveries["abc"].status, DeliveryStatus::Delivered);
    }
}
