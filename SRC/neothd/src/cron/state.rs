//! Durable Cron runtime and delivery truth.
//!
//! jobs.yaml is operator intent. This sidecar stores only scheduler cursors and
//! delivery outcomes, keyed by a SHA-256 job-generation fingerprint. A job edit
//! keeps the logical schedule's fire cursor to prevent restart double-fires,
//! while completion state is generation-bound and is never inherited.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::schema::{DeliveryMode, Job};

static STATE_LOCK: Mutex<()> = Mutex::new(());
const STATE_FILE_LOCK: &str = "cron_runtime_state.lock";
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeState {
    #[serde(default = "state_version")]
    pub version: u32,
    #[serde(default)]
    pub jobs: BTreeMap<String, JobRuntimeState>,
    #[serde(default)]
    pub deliveries: BTreeMap<String, DeliveryRecord>,
    /// ADR-003 calendar boundary consumed before Dream effects start.
    #[serde(default)]
    pub dream: DreamRuntimeState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DreamRuntimeState {
    /// ISO local date (`YYYY-MM-DD`) of the newest claimed boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_claimed_local_date: Option<String>,
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
    /// Exact proactive egress intents already projected into this delivery.
    /// The set makes recovery replay a logical no-op without relying on
    /// timestamps or a lossy high-water mark.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub projected_egress_intents: BTreeSet<String>,
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
            dream: DreamRuntimeState::default(),
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
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "Cron runtime state is not a regular file: {}",
            path.display()
        );
        anyhow::ensure!(
            metadata.len() > 0 && metadata.len() <= MAX_STATE_BYTES,
            "Cron runtime state length is outside 1..={MAX_STATE_BYTES} bytes: {}",
            path.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "Cron runtime state is not current-user-only: {}",
                path.display()
            );
        }
        #[cfg(windows)]
        crate::wal::win_native::verify_private_file_handle(&file)
            .with_context(|| format!("verify private Cron runtime state {}", path.display()))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= MAX_STATE_BYTES,
            "Cron runtime state changed or exceeded its bound during read: {}",
            path.display()
        );
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
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &home.join(STATE_FILE_LOCK),
            "Cron runtime state",
        )?;
        self.save_unlocked(home)
    }

    fn save_unlocked(&self, home: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize Cron runtime state")?;
        let state_path = path(home);
        crate::util::atomic_write::atomic_write_private(&state_path, &bytes)
            .context("atomically persist Cron runtime state")?;
        crate::util::atomic_write::sync_parent_directory_required(&state_path)
            .context("durably commit Cron runtime state")
    }

    /// Serialised read-modify-write so scheduler cursors and asynchronous
    /// delivery outcomes cannot overwrite one another.
    pub fn modify<T>(home: &Path, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let _guard = STATE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("Cron runtime-state lock poisoned"))?;
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &home.join(STATE_FILE_LOCK),
            "Cron runtime state",
        )?;
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
                projected_egress_intents: BTreeSet::new(),
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

    /// Apply one proactive egress projection exactly once for its durable
    /// intent id. A replay leaves status, attempts, timestamp and error byte
    /// identical and returns `false`.
    pub fn update_delivery_once(
        &mut self,
        delivery_id: &str,
        intent_id: &str,
        status: DeliveryStatus,
        error: Option<String>,
    ) -> Result<bool> {
        let record = self
            .deliveries
            .get_mut(delivery_id)
            .with_context(|| format!("unknown Cron delivery id `{delivery_id}`"))?;
        if record.projected_egress_intents.contains(intent_id) {
            return Ok(false);
        }
        record.status = status;
        record.attempts = record.attempts.saturating_add(1);
        record.updated_at = crate::time::utc_now();
        record.error = error;
        record
            .projected_egress_intents
            .insert(intent_id.to_string());
        Ok(true)
    }

    /// Mark an already-passed boundary during task startup without executing
    /// it. This is the explicit no-boot-catch-up contract.
    pub fn skip_dream_boundary_on_start(&mut self, local_date: &str) {
        let should_advance = match self.dream.last_claimed_local_date.as_deref() {
            Some(last) => last < local_date,
            None => true,
        };
        if should_advance {
            self.dream.last_claimed_local_date = Some(local_date.to_string());
        }
    }

    /// Claim one local calendar date before any Dream effect runs. The claim is
    /// persisted by `RuntimeState::modify`; equal or older dates are rejected,
    /// making restarts and backward clock movement at-most-once.
    pub fn claim_dream_boundary(&mut self, local_date: &str) -> bool {
        if self
            .dream
            .last_claimed_local_date
            .as_deref()
            .is_some_and(|last| last >= local_date)
        {
            return false;
        }
        self.dream.last_claimed_local_date = Some(local_date.to_string());
        true
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

/// Intent-bound variant used by crash-recoverable proactive egress. Replaying
/// the same authenticated intent persists a durability barrier but does not
/// increment attempts or mutate the already-recorded outcome.
pub fn update_announce_result_once(
    home: &Path,
    dedup_key: &str,
    intent_id: &str,
    status: DeliveryStatus,
) -> Result<bool> {
    let Some(delivery_id) = dedup_key.strip_prefix("cron-delivery:") else {
        return Ok(false);
    };
    RuntimeState::modify(home, |state| {
        if !state.deliveries.contains_key(delivery_id) {
            return Ok(false);
        }
        state.update_delivery_once(delivery_id, intent_id, status, None)
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
    fn dream_boundary_claim_is_restart_safe_and_monotonic() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            RuntimeState::modify(home.path(), |state| {
                Ok(state.claim_dream_boundary("2026-10-25"))
            })
            .unwrap()
        );
        assert!(
            !RuntimeState::modify(home.path(), |state| {
                Ok(state.claim_dream_boundary("2026-10-25"))
            })
            .unwrap(),
            "same local date must not be claimed after a restart"
        );
        assert!(
            !RuntimeState::modify(home.path(), |state| {
                Ok(state.claim_dream_boundary("2026-10-24"))
            })
            .unwrap(),
            "clock rollback must not reopen an older boundary"
        );
        assert!(
            RuntimeState::modify(home.path(), |state| {
                Ok(state.claim_dream_boundary("2026-10-26"))
            })
            .unwrap()
        );
    }

    #[test]
    fn dream_boot_skip_consumes_passed_boundary_without_effect_claim() {
        let mut state = RuntimeState::default();
        state.skip_dream_boundary_on_start("2026-03-29");
        assert!(!state.claim_dream_boundary("2026-03-29"));
        assert!(state.claim_dream_boundary("2026-03-30"));
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

    #[test]
    fn same_egress_intent_is_a_byte_stable_logical_replay() {
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
        assert!(
            update_announce_result_once(
                home.path(),
                "cron-delivery:abc",
                "018f5c62-8a2b-7def-8123-001122334455",
                DeliveryStatus::Delivered,
            )
            .unwrap()
        );
        let first = RuntimeState::load(home.path()).unwrap().deliveries["abc"].clone();
        assert!(
            !update_announce_result_once(
                home.path(),
                "cron-delivery:abc",
                "018f5c62-8a2b-7def-8123-001122334455",
                DeliveryStatus::Failed,
            )
            .unwrap()
        );
        let replay = RuntimeState::load(home.path()).unwrap().deliveries["abc"].clone();
        assert_eq!(replay.status, first.status);
        assert_eq!(replay.attempts, first.attempts);
        assert_eq!(replay.updated_at, first.updated_at);
        assert_eq!(replay.error, first.error);
    }

    #[test]
    fn different_egress_intent_projects_exactly_once() {
        let mut state = RuntimeState::default();
        state.begin_delivery(
            "abc".into(),
            "j".into(),
            7,
            DeliveryMode::Announce,
            target_hash("telegram:123"),
            false,
        );
        assert!(
            state
                .update_delivery_once("abc", "intent-one", DeliveryStatus::Delivered, None)
                .unwrap()
        );
        assert!(
            state
                .update_delivery_once(
                    "abc",
                    "intent-two",
                    DeliveryStatus::Failed,
                    Some("visible failure".into()),
                )
                .unwrap()
        );
        assert!(
            !state
                .update_delivery_once("abc", "intent-two", DeliveryStatus::Delivered, None,)
                .unwrap()
        );
        let record = &state.deliveries["abc"];
        assert_eq!(record.attempts, 2);
        assert_eq!(record.status, DeliveryStatus::Failed);
        assert_eq!(record.error.as_deref(), Some("visible failure"));
    }

    #[test]
    fn legacy_delivery_record_without_egress_markers_migrates() {
        let mut state = RuntimeState::default();
        state.begin_delivery(
            "abc".into(),
            "j".into(),
            7,
            DeliveryMode::Announce,
            target_hash("telegram:123"),
            false,
        );
        let mut value = serde_json::to_value(&state).unwrap();
        value["deliveries"]["abc"]
            .as_object_mut()
            .unwrap()
            .remove("projected_egress_intents");
        let decoded: RuntimeState = serde_json::from_value(value).unwrap();
        assert!(
            decoded.deliveries["abc"]
                .projected_egress_intents
                .is_empty()
        );
    }

    #[test]
    fn failed_intent_and_error_survive_durable_round_trip() {
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
        state
            .update_delivery_once(
                "abc",
                "intent-failed",
                DeliveryStatus::Failed,
                Some("operator-visible failure".into()),
            )
            .unwrap();
        state.save(home.path()).unwrap();
        let loaded = RuntimeState::load(home.path()).unwrap();
        assert_eq!(loaded.deliveries["abc"].status, DeliveryStatus::Failed);
        assert_eq!(
            loaded.deliveries["abc"].error.as_deref(),
            Some("operator-visible failure")
        );
    }

    #[test]
    fn modify_holds_the_cross_process_state_lock() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().to_path_buf();
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_entered = std::sync::Arc::clone(&entered);
        let worker_release = std::sync::Arc::clone(&release);
        let worker = std::thread::spawn(move || {
            RuntimeState::modify(&path, |_state| {
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            })
            .unwrap();
        });
        entered.wait();
        let second = crate::util::locked_file::try_lock_file_once(
            &home.path().join(STATE_FILE_LOCK),
            "Cron runtime state test",
        )
        .unwrap();
        assert!(second.is_none(), "modify did not hold its OS file lock");
        release.wait();
        worker.join().unwrap();
    }
}
