//! Durable integration-job store and service foundation.
//!
//! `setup.db` is the only durable job truth. Every mutation uses an immediate
//! SQLite transaction, commits before broadcasting, and increments the job's
//! revision. A cross-process owner lock prevents two engines from claiming the
//! store concurrently. Production daemon ownership and IPC are not wired yet,
//! and no public surface or production Ready-evidence issuer consumes this
//! service today.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, anyhow};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use super::catalog::{CapabilityCatalog, CapabilityId};
use super::events::{
    DEFAULT_JOB_EVENT_CAPACITY, IntegrationJobEvent, IntegrationJobEventBus,
    IntegrationJobEventKind, IntegrationJobSubscription,
};
use super::state::{
    CancellationEvidence, IntegrationJob, JobEvidenceContract, JobFailure, JobId, JobOperation,
    JobProgress, JobRequester, JobState, ProgressEvidence, ProgressEvidenceReceipt, ReadyEvidence,
    ReadyEvidenceReceipt, RecoveryDispositionEvidence, RestartDecision, ResumeEvidence,
    Sha256Digest, StateValidationError, validate_release_version, validate_step,
};

const COMPONENT: &str = "integrations";
const SCHEMA_VERSION: i64 = 2;
const DB_FILE_NAME: &str = "setup.db";
const OWNER_LOCK_FILE_NAME: &str = "setup.db.integration-owner.lock";

const JOB_COLUMNS: &str = "job_id, capability_id, operation, release_version, \
    manifest_sha256, state, state_revision, current_step, completed_steps, total_steps, \
    bytes_done, bytes_total, created_at, started_at, updated_at, terminal_at, error_code, \
    redacted_error, ready_evidence_json, retry_of, requested_by, cancel_requested, \
    evidence_contract_json, progress_evidence_json";

const EXPECTED_V1_JOB_COLUMNS: [&str; 22] = [
    "job_id",
    "capability_id",
    "operation",
    "release_version",
    "manifest_sha256",
    "state",
    "state_revision",
    "current_step",
    "completed_steps",
    "total_steps",
    "bytes_done",
    "bytes_total",
    "created_at",
    "started_at",
    "updated_at",
    "terminal_at",
    "error_code",
    "redacted_error",
    "ready_evidence_json",
    "retry_of",
    "requested_by",
    "cancel_requested",
];

const EXPECTED_JOB_COLUMNS: [&str; 24] = [
    "job_id",
    "capability_id",
    "operation",
    "release_version",
    "manifest_sha256",
    "state",
    "state_revision",
    "current_step",
    "completed_steps",
    "total_steps",
    "bytes_done",
    "bytes_total",
    "created_at",
    "started_at",
    "updated_at",
    "terminal_at",
    "error_code",
    "redacted_error",
    "ready_evidence_json",
    "retry_of",
    "requested_by",
    "cancel_requested",
    "evidence_contract_json",
    "progress_evidence_json",
];

const CREATE_INTEGRATION_JOBS_TABLE: &str =
    "CREATE TABLE integration_jobs (
        job_id TEXT PRIMARY KEY NOT NULL,
        capability_id TEXT NOT NULL,
        operation TEXT NOT NULL CHECK(operation IN ('install','repair','update','uninstall')),
        release_version TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('queued','running','validating','configuring','ready','failed','cancelled')),
        state_revision INTEGER NOT NULL CHECK(state_revision >= 0),
        current_step TEXT,
        completed_steps INTEGER NOT NULL CHECK(completed_steps >= 0),
        total_steps INTEGER NOT NULL CHECK(total_steps > 0 AND total_steps >= completed_steps),
        bytes_done INTEGER NOT NULL CHECK(bytes_done >= 0),
        bytes_total INTEGER CHECK(bytes_total IS NULL OR bytes_total >= bytes_done),
        created_at INTEGER NOT NULL CHECK(created_at >= 0),
        started_at INTEGER CHECK(started_at IS NULL OR started_at >= 0),
        updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
        terminal_at INTEGER CHECK(terminal_at IS NULL OR terminal_at >= 0),
        error_code TEXT,
        redacted_error TEXT,
        ready_evidence_json TEXT,
        retry_of TEXT REFERENCES integration_jobs(job_id),
        requested_by TEXT NOT NULL CHECK(requested_by IN ('buddy','cli','daemon','doctor','first_use','gui','migration','wizard')),
        cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)),
        evidence_contract_json TEXT,
        progress_evidence_json TEXT,
        CHECK((state = 'failed') = (error_code IS NOT NULL AND redacted_error IS NOT NULL)),
        CHECK((state = 'ready') = (ready_evidence_json IS NOT NULL)),
        CHECK((state IN ('ready','failed','cancelled')) = (terminal_at IS NOT NULL)),
        CHECK(state NOT IN ('running','validating','configuring') OR
              (current_step IS NOT NULL AND started_at IS NOT NULL)),
        CHECK(state != 'ready' OR
              (completed_steps = total_steps AND
               (bytes_total IS NULL OR bytes_done = bytes_total) AND
               started_at IS NOT NULL)),
        CHECK(evidence_contract_json IS NOT NULL OR state IN ('failed','cancelled')),
        CHECK((completed_steps = 0 AND bytes_done = 0) OR
              progress_evidence_json IS NOT NULL OR state IN ('failed','cancelled'))
     );";

const CREATE_ACTIVE_CAPABILITY_INDEX: &str =
    "CREATE UNIQUE INDEX integration_jobs_one_active_capability
       ON integration_jobs(capability_id)
       WHERE state IN ('queued','running','validating','configuring');";
const CREATE_RETRY_CHILD_INDEX: &str = "CREATE UNIQUE INDEX integration_jobs_one_retry_child
       ON integration_jobs(retry_of)
       WHERE retry_of IS NOT NULL;";
const CREATE_UPDATED_INDEX: &str =
    "CREATE INDEX integration_jobs_updated ON integration_jobs(updated_at, job_id);";

#[derive(Clone, Debug)]
pub struct EnqueueIntegrationJob {
    pub(in crate::integrations) capability_id: CapabilityId,
    pub(in crate::integrations) operation: JobOperation,
    pub(in crate::integrations) release_version: String,
    pub(in crate::integrations) manifest_sha256: Sha256Digest,
    pub(in crate::integrations) evidence_contract: JobEvidenceContract,
    pub(in crate::integrations) requested_by: JobRequester,
    pub(in crate::integrations) total_steps: u32,
    pub(in crate::integrations) bytes_total: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueueResult {
    pub job: IntegrationJob,
    /// False means an identical active job was returned rather than duplicated.
    pub created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupRecovery {
    pub previous_state: JobState,
    pub job: IntegrationJob,
}

pub trait RestartValidator: Send + Sync {
    /// Validate the exact release/staging contract and certify disposition of
    /// the pre-crash process tree. Every decision must prove that resuming or
    /// releasing the durable capability lock cannot race an orphaned worker.
    fn validate(&self, job: &IntegrationJob) -> RestartDecision;
}

impl<F> RestartValidator for F
where
    F: Fn(&IntegrationJob) -> RestartDecision + Send + Sync,
{
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        self(job)
    }
}

/// Single owner of durable adoption work. Clone shares the same owner lease.
#[derive(Clone)]
pub struct IntegrationJobService {
    store: Arc<JobStore>,
    catalog: Arc<CapabilityCatalog>,
    events: IntegrationJobEventBus,
    /// Serializes commit plus publish across all clones. SQLite serializes the
    /// commits; this guard also preserves that exact order on the event bus.
    mutation_sequencer: Arc<Mutex<()>>,
    startup_recovery: Arc<Vec<StartupRecovery>>,
    // The exact open handle owns the cross-process lease until all clones drop.
    _owner_lock: Arc<std::fs::File>,
}

impl IntegrationJobService {
    fn mutation_guard(&self) -> MutexGuard<'_, ()> {
        self.mutation_sequencer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn open<V>(
        home: &Path,
        catalog: Arc<CapabilityCatalog>,
        restart_validator: &V,
    ) -> Result<Self, JobServiceError>
    where
        V: RestartValidator + ?Sized,
    {
        let (store, owner_lock) = open_owned_store(home)?;
        let startup_recovery = store.recover_interrupted(&catalog, restart_validator)?;
        let events = IntegrationJobEventBus::new(DEFAULT_JOB_EVENT_CAPACITY);

        Ok(Self {
            store,
            catalog,
            events,
            mutation_sequencer: Arc::new(Mutex::new(())),
            startup_recovery: Arc::new(startup_recovery),
            _owner_lock: owner_lock,
        })
    }

    /// Open only when no crash recovery is required. Without an adapter that
    /// can prove process-tree and staging disposition, active rows remain
    /// untouched and continue blocking their capability.
    pub fn open_fail_closed(
        home: &Path,
        catalog: Arc<CapabilityCatalog>,
    ) -> Result<Self, JobServiceError> {
        let (store, owner_lock) = open_owned_store(home)?;
        if !store.list(true)?.is_empty() {
            return Err(JobServiceError::RecoveryValidationUnavailable);
        }
        Ok(Self {
            store,
            catalog,
            events: IntegrationJobEventBus::new(DEFAULT_JOB_EVENT_CAPACITY),
            mutation_sequencer: Arc::new(Mutex::new(())),
            startup_recovery: Arc::new(Vec::new()),
            _owner_lock: owner_lock,
        })
    }

    pub fn catalog(&self) -> &CapabilityCatalog {
        &self.catalog
    }

    pub fn startup_recovery(&self) -> &[StartupRecovery] {
        &self.startup_recovery
    }

    pub fn get(&self, job_id: &JobId) -> Result<Option<IntegrationJob>, JobServiceError> {
        self.store.get(job_id)
    }

    pub fn snapshot(&self) -> Result<Vec<IntegrationJob>, JobServiceError> {
        self.store.list(false)
    }

    pub fn active_snapshot(&self) -> Result<Vec<IntegrationJob>, JobServiceError> {
        self.store.list(true)
    }

    /// Subscribe before taking the snapshot. The subscription drops overlap,
    /// accepts only contiguous per-job revisions, and demands resync on gaps.
    pub fn subscribe(&self) -> Result<IntegrationJobSubscription, JobServiceError> {
        let receiver = self.events.subscribe();
        let snapshot = self.snapshot()?;
        Ok(IntegrationJobSubscription::new(snapshot, receiver))
    }

    pub fn enqueue(
        &self,
        request: EnqueueIntegrationJob,
    ) -> Result<EnqueueResult, JobServiceError> {
        let _sequence = self.mutation_guard();
        if !self.catalog.contains(&request.capability_id) {
            return Err(JobServiceError::UnknownCapability(request.capability_id));
        }
        validate_release_version(&request.release_version)?;
        ensure_sql_u64(request.bytes_total.unwrap_or(0), "bytes_total")?;

        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(active) = find_active_job(&transaction, &request.capability_id)? {
            transaction.commit()?;
            if active.operation == request.operation
                && active.release_version == request.release_version
                && active.manifest_sha256 == request.manifest_sha256
            {
                if active.progress.total_steps != request.total_steps
                    || active.progress.bytes_total != request.bytes_total
                    || active.evidence_contract.as_ref() != Some(&request.evidence_contract)
                {
                    return Err(JobServiceError::ActivePlanMismatch {
                        capability_id: request.capability_id,
                        active_job: active.job_id,
                    });
                }
                return Ok(EnqueueResult {
                    job: active,
                    created: false,
                });
            }
            return Err(JobServiceError::CapabilityBusy {
                capability_id: request.capability_id,
                active_job: active.job_id,
            });
        }

        let now = crate::time::now_unix_i64();
        let job = IntegrationJob {
            job_id: JobId::new(),
            capability_id: request.capability_id,
            operation: request.operation,
            release_version: request.release_version,
            manifest_sha256: request.manifest_sha256,
            state: JobState::Queued,
            state_revision: 0,
            current_step: None,
            progress: JobProgress::new(request.total_steps, request.bytes_total),
            created_at: now,
            started_at: None,
            updated_at: now,
            terminal_at: None,
            failure: None,
            evidence_contract: Some(request.evidence_contract),
            progress_evidence: None,
            ready_evidence: None,
            retry_of: None,
            requested_by: request.requested_by,
            cancel_requested: false,
        };
        job.validate()?;
        insert_job(&transaction, &job)?;
        transaction.commit()?;
        self.events.publish(IntegrationJobEvent {
            event: IntegrationJobEventKind::Created,
            job: job.clone(),
        });
        Ok(EnqueueResult { job, created: true })
    }

    pub fn start(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        current_step: impl Into<String>,
    ) -> Result<IntegrationJob, JobServiceError> {
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Running,
            Some(current_step.into()),
            None,
            None,
            None,
        )
    }

    pub fn begin_validation(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        current_step: impl Into<String>,
    ) -> Result<IntegrationJob, JobServiceError> {
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Validating,
            Some(current_step.into()),
            None,
            None,
            None,
        )
    }

    pub fn begin_configuration(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        current_step: impl Into<String>,
    ) -> Result<IntegrationJob, JobServiceError> {
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Configuring,
            Some(current_step.into()),
            None,
            None,
            None,
        )
    }

    pub fn mark_ready(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        evidence: ReadyEvidence,
    ) -> Result<IntegrationJob, JobServiceError> {
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Ready,
            None,
            None,
            Some(evidence),
            None,
        )
    }

    pub fn fail(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        failure: JobFailure,
    ) -> Result<IntegrationJob, JobServiceError> {
        failure.validate()?;
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Failed,
            None,
            Some(failure),
            None,
            None,
        )
    }

    pub fn update_progress(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        expected_state: JobState,
        progress: JobProgress,
        current_step: Option<String>,
        evidence: ProgressEvidence,
    ) -> Result<IntegrationJob, JobServiceError> {
        let _sequence = self.mutation_guard();
        if let Some(step) = &current_step {
            validate_step(step)?;
        }
        ensure_progress_fits_sql(&progress)?;
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut job = require_job(&transaction, job_id)?;
        require_expected_revision(&job, expected_revision)?;
        if job.state != expected_state {
            return Err(JobServiceError::StaleState {
                expected: expected_state,
                current: job.state,
            });
        }
        if !job.state.permits_progress() {
            return Err(JobServiceError::ProgressNotAllowed(job.state));
        }
        if job.cancel_requested {
            return Err(JobServiceError::CancellationPending);
        }
        progress.validate_monotonic_from(&job.progress)?;
        let checkpoint_step = current_step
            .as_deref()
            .or(job.current_step.as_deref())
            .ok_or_else(|| {
                StateValidationError::InvalidInvariant(
                    "progress checkpoint lacks a bound current_step".into(),
                )
            })?
            .to_owned();
        let progress_evidence = evidence
            .receipt_for(
                &job,
                &progress,
                expected_revision,
                expected_state,
                &checkpoint_step,
            )
            .ok_or(JobServiceError::ProgressEvidenceMismatch)?;
        let persisted_revision = job.state_revision;
        job.progress = progress;
        job.progress_evidence = Some(progress_evidence);
        job.current_step = Some(checkpoint_step);
        job.state_revision = next_revision(job.state_revision)?;
        job.updated_at = mutation_now(&job);
        job.validate()?;
        update_mutable_job(&transaction, &job, persisted_revision)?;
        transaction.commit()?;
        self.events.publish(IntegrationJobEvent {
            event: IntegrationJobEventKind::Progress,
            job: job.clone(),
        });
        Ok(job)
    }

    /// Persist cancellation intent. A queued job is cancelled immediately;
    /// active work must stop its owned process tree then call
    /// [`Self::acknowledge_cancel`].
    pub fn request_cancel(
        &self,
        job_id: &JobId,
        expected_revision: u64,
    ) -> Result<IntegrationJob, JobServiceError> {
        let _sequence = self.mutation_guard();
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut job = require_job(&transaction, job_id)?;
        require_expected_revision(&job, expected_revision)?;
        if job.state.is_terminal() {
            return Err(JobServiceError::TerminalJob(job.state));
        }
        if job.cancel_requested {
            transaction.commit()?;
            return Ok(job);
        }
        let previous = job.state;
        let expected_revision = job.state_revision;
        let now = mutation_now(&job);
        job.cancel_requested = true;
        job.state_revision = next_revision(job.state_revision)?;
        job.updated_at = now;
        let event = if previous == JobState::Queued {
            job.state = JobState::Cancelled;
            job.terminal_at = Some(now);
            IntegrationJobEventKind::StateChanged { previous }
        } else {
            IntegrationJobEventKind::CancellationRequested
        };
        job.validate()?;
        update_mutable_job(&transaction, &job, expected_revision)?;
        transaction.commit()?;
        self.events.publish(IntegrationJobEvent {
            event,
            job: job.clone(),
        });
        Ok(job)
    }

    pub fn acknowledge_cancel(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        evidence: CancellationEvidence,
    ) -> Result<IntegrationJob, JobServiceError> {
        self.transition_state(
            job_id,
            expected_revision,
            JobState::Cancelled,
            None,
            None,
            None,
            Some(evidence),
        )
    }

    /// Retry is a new immutable history row bound to the exact old release
    /// manifest and immutable step plan. Progress is preserved only when the
    /// exact persisted checkpoint is revalidated; otherwise it resets to zero.
    pub fn retry(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        evidence: ResumeEvidence,
        requested_by: JobRequester,
    ) -> Result<IntegrationJob, JobServiceError> {
        let _sequence = self.mutation_guard();
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = require_job(&transaction, job_id)?;
        require_expected_revision(&old, expected_revision)?;
        if !matches!(old.state, JobState::Failed | JobState::Cancelled) {
            return Err(JobServiceError::RetryNotAllowed(old.state));
        }
        if old.evidence_contract.is_none() {
            return Err(JobServiceError::EvidenceContractUnavailable);
        }
        if !evidence.matches_contract(&old) {
            return Err(JobServiceError::ResumeEvidenceMismatch);
        }
        if !self.catalog.contains(&old.capability_id) {
            return Err(JobServiceError::UnknownCapability(old.capability_id));
        }
        if let Some(retry_job) = find_retry_child(&transaction, &old.job_id)? {
            return Err(JobServiceError::AlreadyRetried {
                original_job: old.job_id,
                retry_job,
            });
        }
        if let Some(active) = find_active_job(&transaction, &old.capability_id)? {
            return Err(JobServiceError::CapabilityBusy {
                capability_id: old.capability_id,
                active_job: active.job_id,
            });
        }

        let now = crate::time::now_unix_i64().max(old.updated_at);
        let retry_id = JobId::new();
        let preserve_progress =
            !has_persisted_checkpoint(&old) || evidence.matches_checkpoint(&old);
        let (current_step, progress, progress_evidence) = if preserve_progress {
            let checkpoint_step = old
                .progress_evidence
                .as_ref()
                .map(|receipt| receipt.checkpoint_step().to_owned())
                .or_else(|| old.current_step.clone());
            (
                checkpoint_step,
                old.progress,
                old.progress_evidence
                    .as_ref()
                    .map(|receipt| receipt.rebound_to(retry_id.clone())),
            )
        } else {
            (
                None,
                JobProgress::new(old.progress.total_steps, old.progress.bytes_total),
                None,
            )
        };
        let retry = IntegrationJob {
            job_id: retry_id,
            capability_id: old.capability_id,
            operation: old.operation,
            release_version: old.release_version,
            manifest_sha256: old.manifest_sha256,
            state: JobState::Queued,
            state_revision: 0,
            current_step,
            progress,
            created_at: now,
            started_at: None,
            updated_at: now,
            terminal_at: None,
            failure: None,
            evidence_contract: old.evidence_contract,
            progress_evidence,
            ready_evidence: None,
            retry_of: Some(old.job_id.clone()),
            requested_by,
            cancel_requested: false,
        };
        retry.validate()?;
        insert_job(&transaction, &retry)?;
        transaction.commit()?;
        self.events.publish(IntegrationJobEvent {
            event: IntegrationJobEventKind::Retried {
                retry_of: old.job_id,
            },
            job: retry.clone(),
        });
        Ok(retry)
    }

    fn transition_state(
        &self,
        job_id: &JobId,
        expected_revision: u64,
        next: JobState,
        current_step: Option<String>,
        failure: Option<JobFailure>,
        ready_evidence: Option<ReadyEvidence>,
        cancellation_evidence: Option<CancellationEvidence>,
    ) -> Result<IntegrationJob, JobServiceError> {
        let _sequence = self.mutation_guard();
        if let Some(step) = &current_step {
            validate_step(step)?;
        }
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut job = require_job(&transaction, job_id)?;
        require_expected_revision(&job, expected_revision)?;
        let previous = job.state;
        if !previous.can_transition_to(next) {
            return Err(JobServiceError::IllegalTransition {
                from: previous,
                to: next,
            });
        }
        if job.cancel_requested && !matches!(next, JobState::Cancelled | JobState::Failed) {
            return Err(JobServiceError::CancellationPending);
        }
        if next == JobState::Cancelled && !job.cancel_requested {
            return Err(JobServiceError::CancellationNotRequested);
        }
        if next == JobState::Cancelled {
            let evidence = cancellation_evidence
                .as_ref()
                .ok_or(JobServiceError::CancellationEvidenceRequired)?;
            if !evidence.matches(&job) {
                return Err(JobServiceError::CancellationEvidenceMismatch);
            }
        } else if cancellation_evidence.is_some() {
            return Err(JobServiceError::CancellationEvidenceUnexpected);
        }
        let ready_receipt = if next == JobState::Ready {
            let evidence = ready_evidence
                .as_ref()
                .ok_or(JobServiceError::ReadyEvidenceRequired)?;
            let receipt = evidence
                .receipt_for(&job)
                .ok_or(JobServiceError::ReadyEvidenceMismatch)?;
            if job.progress.completed_steps != job.progress.total_steps
                || job
                    .progress
                    .bytes_total
                    .is_some_and(|total| job.progress.bytes_done != total)
            {
                return Err(JobServiceError::IncompleteProgress);
            }
            Some(receipt)
        } else if ready_evidence.is_some() {
            return Err(JobServiceError::ReadyEvidenceUnexpected);
        } else {
            None
        };
        if next == JobState::Failed && failure.is_none() {
            return Err(JobServiceError::FailureRequired);
        }
        if next != JobState::Failed && failure.is_some() {
            return Err(JobServiceError::FailureUnexpected);
        }

        let persisted_revision = job.state_revision;
        let now = mutation_now(&job);
        job.state = next;
        job.state_revision = next_revision(job.state_revision)?;
        job.updated_at = now;
        if next == JobState::Running && job.started_at.is_none() {
            job.started_at = Some(now);
        }
        if let Some(step) = current_step {
            job.current_step = Some(step);
        }
        job.failure = failure;
        job.ready_evidence = ready_receipt;
        if next.is_terminal() {
            job.terminal_at = Some(now);
            if matches!(next, JobState::Ready | JobState::Failed) {
                job.cancel_requested = false;
            }
        }
        job.validate()?;
        update_mutable_job(&transaction, &job, persisted_revision)?;
        transaction.commit()?;
        self.events.publish(IntegrationJobEvent {
            event: IntegrationJobEventKind::StateChanged { previous },
            job: job.clone(),
        });
        Ok(job)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JobServiceError {
    #[error("integration job service is already owned via {0}")]
    AlreadyOwned(PathBuf),
    #[error("unknown capability `{0}`")]
    UnknownCapability(CapabilityId),
    #[error("integration job `{0}` does not exist")]
    JobNotFound(JobId),
    #[error("capability `{capability_id}` already has active job `{active_job}`")]
    CapabilityBusy {
        capability_id: CapabilityId,
        active_job: JobId,
    },
    #[error("capability `{capability_id}` active job `{active_job}` has a different progress plan")]
    ActivePlanMismatch {
        capability_id: CapabilityId,
        active_job: JobId,
    },
    #[error("illegal integration job transition {from} -> {to}")]
    IllegalTransition { from: JobState, to: JobState },
    #[error("progress updates are not allowed in state {0}")]
    ProgressNotAllowed(JobState),
    #[error("terminal job in state {0} is immutable")]
    TerminalJob(JobState),
    #[error("cancellation has not been requested")]
    CancellationNotRequested,
    #[error("cancellation acknowledgement requires verified process cleanup evidence")]
    CancellationEvidenceRequired,
    #[error("cancellation cleanup evidence does not match the durable job revision")]
    CancellationEvidenceMismatch,
    #[error("cancellation cleanup evidence is only valid for cancellation acknowledgement")]
    CancellationEvidenceUnexpected,
    #[error("only cancellation or failure is legal after cancellation was requested")]
    CancellationPending,
    #[error("retry is not allowed in state {0}")]
    RetryNotAllowed(JobState),
    #[error("integration job `{original_job}` was already retried as `{retry_job}`")]
    AlreadyRetried {
        original_job: JobId,
        retry_job: JobId,
    },
    #[error("legacy job has no immutable evidence contract and cannot be retried")]
    EvidenceContractUnavailable,
    #[error("resume evidence does not match the durable job contract")]
    ResumeEvidenceMismatch,
    #[error("interrupted integration work requires adapter recovery validation")]
    RecoveryValidationUnavailable,
    #[error("restart recovery decision is incompatible with durable cancellation intent")]
    RecoveryDecisionInvalid,
    #[error("restart process and staging disposition does not match the durable job revision")]
    RecoveryDispositionMismatch,
    #[error("progress evidence does not match the durable job and checkpoint")]
    ProgressEvidenceMismatch,
    #[error("ready transition requires complete artifact/config/probe evidence")]
    ReadyEvidenceRequired,
    #[error("ready evidence does not match the durable job contract")]
    ReadyEvidenceMismatch,
    #[error("ready evidence is only valid on the Ready transition")]
    ReadyEvidenceUnexpected,
    #[error("ready transition requires complete progress counters")]
    IncompleteProgress,
    #[error("failed transition requires a stable redacted failure")]
    FailureRequired,
    #[error("failure record is only valid on the Failed transition")]
    FailureUnexpected,
    #[error("integration setup schema version {found} is unsupported (expected {expected})")]
    UnsupportedSchema { found: i64, expected: i64 },
    #[error("integration setup schema is corrupt")]
    CorruptSchema,
    #[error("integration job revision overflow")]
    RevisionOverflow,
    #[error("integration job changed concurrently")]
    ConcurrentMutation,
    #[error("stale integration job revision (expected {expected}, current {current})")]
    StaleRevision { expected: u64, current: u64 },
    #[error("stale integration job state (expected {expected}, current {current})")]
    StaleState {
        expected: JobState,
        current: JobState,
    },
    #[error("invalid integration job numeric value: {0}")]
    NumericOverflow(&'static str),
    #[error(transparent)]
    State(#[from] StateValidationError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Persistence(#[from] anyhow::Error),
}

struct JobStore {
    path: PathBuf,
}

impl JobStore {
    fn open(path: PathBuf) -> Result<Self, JobServiceError> {
        prepare_private_database_file(&path)?;
        let mut connection = open_connection(&path, true)?;
        apply_schema(&mut connection)?;
        validate_schema(&connection)?;
        protect_private_file(&path)?;
        Ok(Self { path })
    }

    fn connection(&self) -> Result<Connection, JobServiceError> {
        open_connection(&self.path, false)
    }

    fn get(&self, job_id: &JobId) -> Result<Option<IntegrationJob>, JobServiceError> {
        let connection = self.connection()?;
        fetch_job(&connection, job_id).map_err(Into::into)
    }

    fn list(&self, active_only: bool) -> Result<Vec<IntegrationJob>, JobServiceError> {
        let connection = self.connection()?;
        let sql = if active_only {
            format!(
                "SELECT {JOB_COLUMNS} FROM integration_jobs \
                 WHERE state IN ('queued','running','validating','configuring') \
                 ORDER BY created_at, job_id"
            )
        } else {
            format!("SELECT {JOB_COLUMNS} FROM integration_jobs ORDER BY created_at, job_id")
        };
        let mut statement = connection.prepare(&sql)?;
        let jobs = statement
            .query_map([], row_to_job)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(jobs)
    }

    fn recover_interrupted<V>(
        &self,
        catalog: &CapabilityCatalog,
        validator: &V,
    ) -> Result<Vec<StartupRecovery>, JobServiceError>
    where
        V: RestartValidator + ?Sized,
    {
        let active = self.list(true)?;
        let mut prepared = Vec::with_capacity(active.len());
        for original in active {
            let decision = validator.validate(&original);
            let (intent, disposition) = match decision {
                RestartDecision::Resume {
                    evidence,
                    disposition,
                } => {
                    if original.cancel_requested {
                        return Err(JobServiceError::RecoveryDecisionInvalid);
                    }
                    let intent = if catalog.contains(&original.capability_id) {
                        RecoveryIntent::Resume(evidence)
                    } else {
                        RecoveryIntent::Fail(capability_missing_after_restart_failure())
                    };
                    (intent, disposition)
                }
                RestartDecision::Reject {
                    failure,
                    disposition,
                } => {
                    failure.validate()?;
                    let intent = if original.cancel_requested {
                        RecoveryIntent::Cancel
                    } else if catalog.contains(&original.capability_id) {
                        RecoveryIntent::Fail(failure)
                    } else {
                        RecoveryIntent::Fail(capability_missing_after_restart_failure())
                    };
                    (intent, disposition)
                }
            };
            prepared.push(PreparedRecovery {
                original,
                intent,
                disposition,
            });
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut recovered = Vec::with_capacity(prepared.len());
        for prepared in prepared {
            let previous_state = prepared.original.state;
            let mut current = require_job(&transaction, &prepared.original.job_id)?;
            if current.state_revision != prepared.original.state_revision
                || !current.state.is_active()
            {
                return Err(JobServiceError::ConcurrentMutation);
            }
            if !prepared.disposition.matches(&current) {
                return Err(JobServiceError::RecoveryDispositionMismatch);
            }
            let outcome = match prepared.intent {
                RecoveryIntent::Resume(evidence) if !evidence.matches_contract(&current) => {
                    RecoveryOutcome::Fail(restart_revalidation_failure())
                }
                RecoveryIntent::Resume(evidence) => RecoveryOutcome::Resume {
                    preserve_progress: !has_persisted_checkpoint(&current)
                        || evidence.matches_checkpoint(&current),
                },
                RecoveryIntent::Fail(failure) => RecoveryOutcome::Fail(failure),
                RecoveryIntent::Cancel => RecoveryOutcome::Cancel,
            };
            let expected_revision = current.state_revision;
            let now = mutation_now(&current);
            current.state_revision = next_revision(current.state_revision)?;
            current.updated_at = now;
            match outcome {
                RecoveryOutcome::Resume { preserve_progress } => {
                    // Recovery-only edge: active -> Queued. It is unavailable
                    // through the normal transition table and requires evidence.
                    current.state = JobState::Queued;
                    current.terminal_at = None;
                    current.failure = None;
                    current.ready_evidence = None;
                    current.cancel_requested = false;
                    if preserve_progress {
                        if let Some(receipt) = &current.progress_evidence {
                            current.current_step = Some(receipt.checkpoint_step().to_owned());
                        }
                    } else {
                        current.current_step = None;
                        current.progress = JobProgress::new(
                            current.progress.total_steps,
                            current.progress.bytes_total,
                        );
                        current.progress_evidence = None;
                    }
                }
                RecoveryOutcome::Fail(failure) => {
                    current.state = JobState::Failed;
                    current.terminal_at = Some(now);
                    current.failure = Some(failure);
                    current.ready_evidence = None;
                    current.cancel_requested = false;
                }
                RecoveryOutcome::Cancel => {
                    current.state = JobState::Cancelled;
                    current.terminal_at = Some(now);
                    current.failure = None;
                    current.ready_evidence = None;
                    // Retain the durable cancellation intent in terminal
                    // history; the recovery disposition authorized cleanup.
                    current.cancel_requested = true;
                }
            }
            current.validate()?;
            update_mutable_job(&transaction, &current, expected_revision)?;
            recovered.push(StartupRecovery {
                previous_state,
                job: current,
            });
        }
        transaction.commit()?;
        Ok(recovered)
    }
}

struct PreparedRecovery {
    original: IntegrationJob,
    intent: RecoveryIntent,
    disposition: RecoveryDispositionEvidence,
}

enum RecoveryIntent {
    Resume(ResumeEvidence),
    Fail(JobFailure),
    Cancel,
}

enum RecoveryOutcome {
    Resume { preserve_progress: bool },
    Fail(JobFailure),
    Cancel,
}

fn restart_revalidation_failure() -> JobFailure {
    JobFailure::new(
        "restart_revalidation_failed",
        "The prior release manifest, step plan, or staging checkpoint could not be revalidated.",
    )
    .expect("static recovery failure is valid")
}

fn capability_missing_after_restart_failure() -> JobFailure {
    JobFailure::new(
        "capability_missing_after_restart",
        "The capability is absent from the current validated catalog.",
    )
    .expect("static recovery failure is valid")
}

fn open_owned_store(home: &Path) -> Result<(Arc<JobStore>, Arc<std::fs::File>), JobServiceError> {
    prepare_private_directory(home)?;
    let owner_path = home.join(OWNER_LOCK_FILE_NAME);
    reject_existing_nonregular_path(&owner_path, "integration job owner lock")?;
    let owner_lock =
        crate::util::locked_file::try_lock_file_once(&owner_path, "integration job owner")?
            .ok_or_else(|| JobServiceError::AlreadyOwned(owner_path.clone()))?;
    protect_private_file(&owner_path)?;
    let store = Arc::new(JobStore::open(home.join(DB_FILE_NAME))?);
    Ok((store, Arc::new(owner_lock)))
}

fn open_connection(path: &Path, initialize: bool) -> Result<Connection, JobServiceError> {
    let connection = Connection::open(path)
        .with_context(|| format!("open integration setup DB {}", path.display()))?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    if initialize {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 100i64)?;
        connection.pragma_update(None, "journal_size_limit", 16_777_216i64)?;
    }
    Ok(connection)
}

fn apply_schema(connection: &mut Connection) -> Result<(), JobServiceError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS setup_component_schema (
            component TEXT PRIMARY KEY NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0)
         );",
    )?;
    let version: Option<i64> = connection
        .query_row(
            "SELECT version FROM setup_component_schema WHERE component = ?1",
            [COMPONENT],
            |row| row.get(0),
        )
        .optional()?;
    match version {
        Some(SCHEMA_VERSION) => return Ok(()),
        Some(1) => return migrate_v1_to_v2(connection),
        Some(found) => {
            return Err(JobServiceError::UnsupportedSchema {
                found,
                expected: SCHEMA_VERSION,
            });
        }
        None => {}
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(CREATE_INTEGRATION_JOBS_TABLE)?;
    create_integration_job_indexes(&transaction)?;
    transaction.execute(
        "INSERT INTO setup_component_schema(component, version) VALUES (?1, ?2)",
        params![COMPONENT, SCHEMA_VERSION],
    )?;
    validate_schema(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v1_to_v2(connection: &mut Connection) -> Result<(), JobServiceError> {
    if integration_job_columns(connection)? != EXPECTED_V1_JOB_COLUMNS {
        return Err(JobServiceError::CorruptSchema);
    }
    validate_active_index(connection)?;

    connection.pragma_update(None, "foreign_keys", "OFF")?;
    let migration = (|| -> Result<(), JobServiceError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision_overflow: i64 = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM integration_jobs
               WHERE state IN ('queued','running','validating','configuring','ready')
                 AND state_revision >= 9223372036854775807
             )",
            [],
            |row| row.get(0),
        )?;
        if revision_overflow != 0 {
            return Err(JobServiceError::CorruptSchema);
        }

        transaction.execute_batch(
            "ALTER TABLE integration_jobs RENAME TO integration_jobs_v1;
             DROP INDEX IF EXISTS integration_jobs_one_active_capability;
             DROP INDEX IF EXISTS integration_jobs_one_retry_child;
             DROP INDEX IF EXISTS integration_jobs_updated;",
        )?;
        transaction.execute_batch(CREATE_INTEGRATION_JOBS_TABLE)?;
        let migration_time = crate::time::now_unix_i64();
        transaction.execute(
            "INSERT INTO integration_jobs (
               job_id, capability_id, operation, release_version, manifest_sha256, state,
               state_revision, current_step, completed_steps, total_steps, bytes_done,
               bytes_total, created_at, started_at, updated_at, terminal_at, error_code,
               redacted_error, ready_evidence_json, retry_of, requested_by, cancel_requested,
               evidence_contract_json, progress_evidence_json
             )
             SELECT
               job_id, capability_id, operation, release_version, manifest_sha256,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN 'failed' ELSE state END,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN state_revision + 1 ELSE state_revision END,
               current_step, completed_steps,
               CASE WHEN total_steps < 1 THEN 1 ELSE total_steps END,
               bytes_done, bytes_total, created_at, started_at,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN MAX(updated_at, created_at, COALESCE(started_at, 0), ?1)
                    ELSE updated_at END,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN MAX(updated_at, created_at, COALESCE(started_at, 0), ?1)
                    ELSE terminal_at END,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN 'evidence_contract_migration_required' ELSE error_code END,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN 'This historical integration job predates binding evidence and must be started again.'
                    ELSE redacted_error END,
               NULL, retry_of, requested_by,
               CASE WHEN state IN ('queued','running','validating','configuring','ready')
                    THEN 0 ELSE cancel_requested END,
               NULL, NULL
             FROM integration_jobs_v1",
            [migration_time],
        )?;
        transaction.execute_batch("DROP TABLE integration_jobs_v1;")?;
        create_integration_job_indexes(&transaction)?;
        transaction.execute(
            "UPDATE setup_component_schema SET version=?2 WHERE component=?1",
            params![COMPONENT, SCHEMA_VERSION],
        )?;
        validate_schema(&transaction)?;
        transaction.commit()?;
        Ok(())
    })();
    let restore_foreign_keys = connection.pragma_update(None, "foreign_keys", "ON");
    migration?;
    restore_foreign_keys?;
    validate_foreign_key_integrity(connection)
}

fn create_integration_job_indexes(connection: &Connection) -> Result<(), JobServiceError> {
    connection.execute_batch(CREATE_ACTIVE_CAPABILITY_INDEX)?;
    connection.execute_batch(CREATE_RETRY_CHILD_INDEX)?;
    connection.execute_batch(CREATE_UPDATED_INDEX)?;
    Ok(())
}

fn integration_job_columns(connection: &Connection) -> Result<Vec<String>, JobServiceError> {
    let mut statement = connection.prepare("PRAGMA table_info(integration_jobs)")?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn validate_schema(connection: &Connection) -> Result<(), JobServiceError> {
    let version: i64 = connection.query_row(
        "SELECT version FROM setup_component_schema WHERE component = ?1",
        [COMPONENT],
        |row| row.get(0),
    )?;
    if version != SCHEMA_VERSION {
        return Err(JobServiceError::UnsupportedSchema {
            found: version,
            expected: SCHEMA_VERSION,
        });
    }
    if integration_job_columns(connection)? != EXPECTED_JOB_COLUMNS {
        return Err(JobServiceError::CorruptSchema);
    }
    validate_schema_sql(
        connection,
        "table",
        "integration_jobs",
        CREATE_INTEGRATION_JOBS_TABLE,
    )?;
    validate_index_contract(
        connection,
        "integration_jobs_one_active_capability",
        CREATE_ACTIVE_CAPABILITY_INDEX,
        true,
        true,
        &["capability_id"],
    )?;
    validate_index_contract(
        connection,
        "integration_jobs_one_retry_child",
        CREATE_RETRY_CHILD_INDEX,
        true,
        true,
        &["retry_of"],
    )?;
    validate_index_contract(
        connection,
        "integration_jobs_updated",
        CREATE_UPDATED_INDEX,
        false,
        false,
        &["updated_at", "job_id"],
    )?;
    validate_retry_foreign_key(connection)?;
    validate_foreign_key_integrity(connection)?;
    validate_all_jobs(connection)?;
    Ok(())
}

fn validate_foreign_key_integrity(connection: &Connection) -> Result<(), JobServiceError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        return Err(JobServiceError::CorruptSchema);
    }
    Ok(())
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_ascii_lowercase()
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> Result<(), JobServiceError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    if actual
        .as_deref()
        .is_none_or(|sql| normalized_schema_sql(sql) != normalized_schema_sql(expected))
    {
        return Err(JobServiceError::CorruptSchema);
    }
    Ok(())
}

fn validate_index_contract(
    connection: &Connection,
    name: &str,
    expected_sql: &str,
    expected_unique: bool,
    expected_partial: bool,
    expected_columns: &[&str],
) -> Result<(), JobServiceError> {
    validate_schema_sql(connection, "index", name, expected_sql)?;
    let mut list = connection.prepare("PRAGMA index_list(integration_jobs)")?;
    let metadata = list
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(4)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .find(|(candidate, _, _)| candidate == name);
    if metadata.as_ref().is_none_or(|(_, unique, partial)| {
        *unique != expected_unique || *partial != expected_partial
    }) {
        return Err(JobServiceError::CorruptSchema);
    }

    let mut info = connection.prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?;
    let columns = info
        .query_map([name], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns != expected_columns {
        return Err(JobServiceError::CorruptSchema);
    }
    Ok(())
}

fn validate_active_index(connection: &Connection) -> Result<(), JobServiceError> {
    validate_index_contract(
        connection,
        "integration_jobs_one_active_capability",
        CREATE_ACTIVE_CAPABILITY_INDEX,
        true,
        true,
        &["capability_id"],
    )
}

fn validate_retry_foreign_key(connection: &Connection) -> Result<(), JobServiceError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_list(integration_jobs)")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows
        != [(
            "integration_jobs".to_owned(),
            "retry_of".to_owned(),
            "job_id".to_owned(),
            "NO ACTION".to_owned(),
            "NO ACTION".to_owned(),
            "NONE".to_owned(),
        )]
    {
        return Err(JobServiceError::CorruptSchema);
    }
    Ok(())
}

fn validate_all_jobs(connection: &Connection) -> Result<(), JobServiceError> {
    let mut statement = connection
        .prepare(&format!("SELECT {JOB_COLUMNS} FROM integration_jobs"))
        .map_err(|_| JobServiceError::CorruptSchema)?;
    let mut rows = statement
        .query([])
        .map_err(|_| JobServiceError::CorruptSchema)?;
    while let Some(row) = rows.next().map_err(|_| JobServiceError::CorruptSchema)? {
        row_to_job(row).map_err(|_| JobServiceError::CorruptSchema)?;
    }
    Ok(())
}

fn insert_job(transaction: &Transaction<'_>, job: &IntegrationJob) -> Result<(), JobServiceError> {
    ensure_progress_fits_sql(&job.progress)?;
    let ready_evidence = job
        .ready_evidence
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize integration readiness evidence")?;
    let evidence_contract = job
        .evidence_contract
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize integration evidence contract")?;
    let progress_evidence = job
        .progress_evidence
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize integration progress evidence")?;
    transaction.execute(
        "INSERT INTO integration_jobs (
           job_id, capability_id, operation, release_version, manifest_sha256, state,
           state_revision, current_step, completed_steps, total_steps, bytes_done,
           bytes_total, created_at, started_at, updated_at, terminal_at, error_code,
           redacted_error, ready_evidence_json, retry_of, requested_by, cancel_requested,
           evidence_contract_json, progress_evidence_json
         ) VALUES (
           ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,
           ?23,?24
         )",
        params![
            job.job_id.as_str(),
            job.capability_id.as_str(),
            job.operation.as_str(),
            &job.release_version,
            job.manifest_sha256.as_str(),
            job.state.as_str(),
            i64::try_from(job.state_revision)
                .map_err(|_| JobServiceError::NumericOverflow("state_revision"))?,
            job.current_step.as_deref(),
            i64::from(job.progress.completed_steps),
            i64::from(job.progress.total_steps),
            i64::try_from(job.progress.bytes_done)
                .map_err(|_| JobServiceError::NumericOverflow("bytes_done"))?,
            job.progress
                .bytes_total
                .map(i64::try_from)
                .transpose()
                .map_err(|_| JobServiceError::NumericOverflow("bytes_total"))?,
            job.created_at,
            job.started_at,
            job.updated_at,
            job.terminal_at,
            job.failure.as_ref().map(|failure| failure.code.as_str()),
            job.failure
                .as_ref()
                .map(|failure| failure.redacted_message.as_str()),
            ready_evidence,
            job.retry_of.as_ref().map(JobId::as_str),
            job.requested_by.as_str(),
            i64::from(job.cancel_requested),
            evidence_contract,
            progress_evidence,
        ],
    )?;
    Ok(())
}

fn update_mutable_job(
    transaction: &Transaction<'_>,
    job: &IntegrationJob,
    expected_revision: u64,
) -> Result<(), JobServiceError> {
    ensure_progress_fits_sql(&job.progress)?;
    let ready_evidence = job
        .ready_evidence
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize integration readiness evidence")?;
    let progress_evidence = job
        .progress_evidence
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize integration progress evidence")?;
    let changed = transaction.execute(
        "UPDATE integration_jobs SET
           state=?1, state_revision=?2, current_step=?3, completed_steps=?4,
           total_steps=?5, bytes_done=?6, bytes_total=?7, started_at=?8,
           updated_at=?9, terminal_at=?10, error_code=?11, redacted_error=?12,
           ready_evidence_json=?13, cancel_requested=?14, progress_evidence_json=?15
         WHERE job_id=?16 AND state_revision=?17",
        params![
            job.state.as_str(),
            i64::try_from(job.state_revision)
                .map_err(|_| JobServiceError::NumericOverflow("state_revision"))?,
            job.current_step.as_deref(),
            i64::from(job.progress.completed_steps),
            i64::from(job.progress.total_steps),
            i64::try_from(job.progress.bytes_done)
                .map_err(|_| JobServiceError::NumericOverflow("bytes_done"))?,
            job.progress
                .bytes_total
                .map(i64::try_from)
                .transpose()
                .map_err(|_| JobServiceError::NumericOverflow("bytes_total"))?,
            job.started_at,
            job.updated_at,
            job.terminal_at,
            job.failure.as_ref().map(|failure| failure.code.as_str()),
            job.failure
                .as_ref()
                .map(|failure| failure.redacted_message.as_str()),
            ready_evidence,
            i64::from(job.cancel_requested),
            progress_evidence,
            job.job_id.as_str(),
            i64::try_from(expected_revision)
                .map_err(|_| JobServiceError::NumericOverflow("state_revision"))?,
        ],
    )?;
    if changed != 1 {
        return Err(JobServiceError::ConcurrentMutation);
    }
    Ok(())
}

fn fetch_job(connection: &Connection, job_id: &JobId) -> rusqlite::Result<Option<IntegrationJob>> {
    connection
        .query_row(
            &format!("SELECT {JOB_COLUMNS} FROM integration_jobs WHERE job_id=?1"),
            [job_id.as_str()],
            row_to_job,
        )
        .optional()
}

fn require_job(
    transaction: &Transaction<'_>,
    job_id: &JobId,
) -> Result<IntegrationJob, JobServiceError> {
    fetch_job(transaction, job_id)?.ok_or_else(|| JobServiceError::JobNotFound(job_id.clone()))
}

fn find_active_job(
    transaction: &Transaction<'_>,
    capability_id: &CapabilityId,
) -> rusqlite::Result<Option<IntegrationJob>> {
    transaction
        .query_row(
            &format!(
                "SELECT {JOB_COLUMNS} FROM integration_jobs \
                 WHERE capability_id=?1 AND state IN ('queued','running','validating','configuring')"
            ),
            [capability_id.as_str()],
            row_to_job,
        )
        .optional()
}

fn find_retry_child(
    transaction: &Transaction<'_>,
    original_job: &JobId,
) -> Result<Option<JobId>, JobServiceError> {
    let child = transaction
        .query_row(
            "SELECT job_id FROM integration_jobs WHERE retry_of=?1",
            [original_job.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    child.map(JobId::parse).transpose().map_err(Into::into)
}

fn row_to_job(row: &Row<'_>) -> rusqlite::Result<IntegrationJob> {
    let capability_id = CapabilityId::parse(row.get::<_, String>(1)?)
        .map_err(|error| conversion_error(1, rusqlite::types::Type::Text, error))?;
    let operation = JobOperation::from_str(&row.get::<_, String>(2)?)
        .map_err(|error| conversion_error(2, rusqlite::types::Type::Text, error))?;
    let manifest_sha256 = Sha256Digest::parse(row.get::<_, String>(4)?)
        .map_err(|error| conversion_error(4, rusqlite::types::Type::Text, error))?;
    let state = JobState::from_str(&row.get::<_, String>(5)?)
        .map_err(|error| conversion_error(5, rusqlite::types::Type::Text, error))?;
    let revision = nonnegative_u64(row.get(6)?, 6)?;
    let completed_steps = nonnegative_u32(row.get(8)?, 8)?;
    let total_steps = nonnegative_u32(row.get(9)?, 9)?;
    let bytes_done = nonnegative_u64(row.get(10)?, 10)?;
    let bytes_total = row
        .get::<_, Option<i64>>(11)?
        .map(|value| nonnegative_u64(value, 11))
        .transpose()?;
    let error_code: Option<String> = row.get(16)?;
    let redacted_error: Option<String> = row.get(17)?;
    let failure = match (error_code, redacted_error) {
        (Some(code), Some(message)) => Some(
            JobFailure::new(code, message)
                .map_err(|error| conversion_error(16, rusqlite::types::Type::Text, error))?,
        ),
        (None, None) => None,
        _ => {
            return Err(conversion_error(
                16,
                rusqlite::types::Type::Text,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "partial integration failure record",
                ),
            ));
        }
    };
    let ready_evidence = row
        .get::<_, Option<String>>(18)?
        .map(|value| {
            serde_json::from_str::<ReadyEvidenceReceipt>(&value)
                .map_err(|error| conversion_error(18, rusqlite::types::Type::Text, error))
        })
        .transpose()?;
    let retry_of = row
        .get::<_, Option<String>>(19)?
        .map(JobId::parse)
        .transpose()
        .map_err(|error| conversion_error(19, rusqlite::types::Type::Text, error))?;
    let requested_by = JobRequester::from_str(&row.get::<_, String>(20)?)
        .map_err(|error| conversion_error(20, rusqlite::types::Type::Text, error))?;
    let cancel_value: i64 = row.get(21)?;
    let cancel_requested = match cancel_value {
        0 => false,
        1 => true,
        _ => {
            return Err(conversion_error(
                21,
                rusqlite::types::Type::Integer,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid cancel_requested value",
                ),
            ));
        }
    };
    let evidence_contract = row
        .get::<_, Option<String>>(22)?
        .map(|value| {
            serde_json::from_str::<JobEvidenceContract>(&value)
                .map_err(|error| conversion_error(22, rusqlite::types::Type::Text, error))
        })
        .transpose()?;
    let progress_evidence = row
        .get::<_, Option<String>>(23)?
        .map(|value| {
            serde_json::from_str::<ProgressEvidenceReceipt>(&value)
                .map_err(|error| conversion_error(23, rusqlite::types::Type::Text, error))
        })
        .transpose()?;
    let job = IntegrationJob {
        job_id: JobId::parse(row.get::<_, String>(0)?)
            .map_err(|error| conversion_error(0, rusqlite::types::Type::Text, error))?,
        capability_id,
        operation,
        release_version: row.get(3)?,
        manifest_sha256,
        state,
        state_revision: revision,
        current_step: row.get(7)?,
        progress: JobProgress {
            completed_steps,
            total_steps,
            bytes_done,
            bytes_total,
        },
        created_at: row.get(12)?,
        started_at: row.get(13)?,
        updated_at: row.get(14)?,
        terminal_at: row.get(15)?,
        failure,
        evidence_contract,
        progress_evidence,
        ready_evidence,
        retry_of,
        requested_by,
        cancel_requested,
    };
    job.validate()
        .map_err(|error| conversion_error(0, rusqlite::types::Type::Text, error))?;
    Ok(job)
}

fn conversion_error(
    index: usize,
    data_type: rusqlite::types::Type,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, data_type, Box::new(error))
}

fn nonnegative_u64(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|error| conversion_error(index, rusqlite::types::Type::Integer, error))
}

fn nonnegative_u32(value: i64, index: usize) -> rusqlite::Result<u32> {
    u32::try_from(value)
        .map_err(|error| conversion_error(index, rusqlite::types::Type::Integer, error))
}

fn next_revision(current: u64) -> Result<u64, JobServiceError> {
    current
        .checked_add(1)
        .ok_or(JobServiceError::RevisionOverflow)
}

fn require_expected_revision(job: &IntegrationJob, expected: u64) -> Result<(), JobServiceError> {
    if job.state_revision != expected {
        return Err(JobServiceError::StaleRevision {
            expected,
            current: job.state_revision,
        });
    }
    Ok(())
}

fn mutation_now(job: &IntegrationJob) -> i64 {
    crate::time::now_unix_i64().max(job.updated_at)
}

fn ensure_sql_u64(value: u64, field: &'static str) -> Result<(), JobServiceError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| JobServiceError::NumericOverflow(field))
}

fn ensure_progress_fits_sql(progress: &JobProgress) -> Result<(), JobServiceError> {
    progress.validate()?;
    ensure_sql_u64(progress.bytes_done, "bytes_done")?;
    if let Some(total) = progress.bytes_total {
        ensure_sql_u64(total, "bytes_total")?;
    }
    Ok(())
}

fn has_persisted_checkpoint(job: &IntegrationJob) -> bool {
    job.progress.completed_steps > 0
        || job.progress.bytes_done > 0
        || job.current_step.is_some()
        || job.progress_evidence.is_some()
}

fn prepare_private_directory(path: &Path) -> Result<(), JobServiceError> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(JobServiceError::Persistence(anyhow!(
                "integration home is not a real directory: {}",
                path.display()
            )));
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(JobServiceError::Persistence(anyhow!(
                "integration home permissions are not private"
            )));
        }
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl(path)?;
        crate::wal::win_native::verify_private_directory_dacl(path)?;
    }
    Ok(())
}

fn reject_existing_nonregular_path(path: &Path, what: &'static str) -> Result<(), JobServiceError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(JobServiceError::Persistence(anyhow!(
                "{what} is not a real regular file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn prepare_private_database_file(path: &Path) -> Result<(), JobServiceError> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JobServiceError::Persistence(anyhow!(
                "integration setup DB is not a regular file: {}",
                path.display()
            )));
        }
    } else {
        crate::util::atomic_write::write_private_create_new(path, b"")?;
    }
    protect_private_file(path)
}

fn protect_private_file(path: &Path) -> Result<(), JobServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(JobServiceError::Persistence(anyhow!(
                "integration state permissions are not private: {}",
                path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_dacl(path)?;
        crate::wal::win_native::verify_private_dacl(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::integrations::catalog::{
        CapabilityCategory, CapabilityDescriptor, CapabilitySurface, SupportTier,
        TargetAvailability, TargetSelector, TargetSupport,
    };
    use crate::integrations::events::IntegrationJobReceiveError;
    use crate::integrations::state::ProgressEvidenceFixture;

    fn id(value: &str) -> CapabilityId {
        CapabilityId::parse(value).unwrap()
    }

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::parse(character.to_string().repeat(64)).unwrap()
    }

    fn descriptor(value: &str) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: id(value),
            display_name: value.replace('-', " "),
            category: CapabilityCategory::Runtime,
            support_tier: SupportTier::Managed,
            dependencies: Vec::new(),
            targets: vec![TargetSupport {
                target: TargetSelector::parse("x86_64-pc-windows-msvc").unwrap(),
                availability: TargetAvailability::Supported,
            }],
            lifecycle_adapter: Some("fixture-adapter".into()),
            probe: Some("fixture-authenticated-probe".into()),
            surfaces: BTreeSet::from([
                CapabilitySurface::Cli,
                CapabilitySurface::Doctor,
                CapabilitySurface::Gui,
            ]),
        }
    }

    fn catalog() -> Arc<CapabilityCatalog> {
        Arc::new(
            CapabilityCatalog::new(vec![descriptor("managed-node"), descriptor("qwen-model")])
                .unwrap(),
        )
    }

    fn home(root: &tempfile::TempDir) -> PathBuf {
        root.path().join("neoth-home")
    }

    fn service(root: &tempfile::TempDir) -> IntegrationJobService {
        IntegrationJobService::open_fail_closed(&home(root), catalog()).unwrap()
    }

    fn request(capability: &str) -> EnqueueIntegrationJob {
        EnqueueIntegrationJob {
            capability_id: id(capability),
            operation: JobOperation::Install,
            release_version: "1.0.0".into(),
            manifest_sha256: digest('a'),
            evidence_contract: JobEvidenceContract::verified(
                digest('b'),
                digest('c'),
                digest('d'),
                digest('e'),
            ),
            requested_by: JobRequester::Cli,
            total_steps: 3,
            bytes_total: Some(100),
        }
    }

    fn ready_evidence(job: &IntegrationJob) -> ReadyEvidence {
        ReadyEvidence::verified(
            job.job_id.clone(),
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d'),
            digest('e'),
        )
    }

    fn progress_evidence_for_step(
        job: &IntegrationJob,
        progress: &JobProgress,
        current_step: &str,
    ) -> ProgressEvidence {
        ProgressEvidence::verified(ProgressEvidenceFixture {
            job_id: job.job_id.clone(),
            manifest_sha256: digest('a'),
            step_plan_sha256: digest('e'),
            staging_binding_sha256: digest('f'),
            expected_revision: job.state_revision,
            expected_state: job.state,
            current_phase: current_step.to_owned(),
            completed_steps: progress.completed_steps,
            bytes_done: progress.bytes_done,
        })
    }

    fn progress_evidence(job: &IntegrationJob, progress: &JobProgress) -> ProgressEvidence {
        progress_evidence_for_step(
            job,
            progress,
            job.current_step
                .as_deref()
                .expect("progress fixture must have a current phase"),
        )
    }

    fn resume_evidence(job: &IntegrationJob, staging: char) -> ResumeEvidence {
        ResumeEvidence::verified(
            job.job_id.clone(),
            digest('a'),
            digest('e'),
            digest(staging),
        )
    }

    fn cancellation_evidence(job: &IntegrationJob) -> CancellationEvidence {
        CancellationEvidence::verified(
            job.job_id.clone(),
            digest('a'),
            digest('e'),
            job.state_revision,
            digest('b'),
            digest('c'),
        )
    }

    fn recovery_disposition(job: &IntegrationJob) -> RecoveryDispositionEvidence {
        RecoveryDispositionEvidence::verified(
            job.job_id.clone(),
            digest('a'),
            digest('e'),
            job.state_revision,
            digest('b'),
            digest('c'),
        )
    }

    fn resume_decision(job: &IntegrationJob, staging: char) -> RestartDecision {
        RestartDecision::Resume {
            evidence: resume_evidence(job, staging),
            disposition: recovery_disposition(job),
        }
    }

    fn reject_decision(job: &IntegrationJob, code: &str) -> RestartDecision {
        RestartDecision::Reject {
            failure: JobFailure::new(code, "The interrupted job was safely rejected.").unwrap(),
            disposition: recovery_disposition(job),
        }
    }

    fn persisted_job(home: &Path, job_id: &JobId) -> IntegrationJob {
        let connection = open_connection(&home.join(DB_FILE_NAME), false).unwrap();
        fetch_job(&connection, job_id).unwrap().unwrap()
    }

    #[test]
    fn complete_lifecycle_is_durable_revisioned_and_evented() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let mut subscription = service.subscribe().unwrap();
        assert!(subscription.snapshot.is_empty());

        let created = service.enqueue(request("qwen-model")).unwrap();
        assert!(created.created);
        assert_eq!(created.job.state, JobState::Queued);
        assert_eq!(created.job.state_revision, 0);
        assert!(matches!(
            subscription.try_recv().unwrap().event,
            IntegrationJobEventKind::Created
        ));

        let coalesced = service.enqueue(request("qwen-model")).unwrap();
        assert!(!coalesced.created);
        assert_eq!(coalesced.job.job_id, created.job.job_id);
        assert!(matches!(
            subscription.try_recv(),
            Err(IntegrationJobReceiveError::Empty)
        ));

        let running = service
            .start(&created.job.job_id, created.job.state_revision, "download")
            .unwrap();
        assert_eq!(running.state, JobState::Running);
        let download_progress = JobProgress {
            completed_steps: 1,
            total_steps: 3,
            bytes_done: 100,
            bytes_total: Some(100),
        };
        let progress = service
            .update_progress(
                &running.job_id,
                running.state_revision,
                running.state,
                download_progress.clone(),
                Some("download complete".into()),
                progress_evidence_for_step(&running, &download_progress, "download complete"),
            )
            .unwrap();
        assert_eq!(progress.state_revision, 2);
        let validating = service
            .begin_validation(
                &progress.job_id,
                progress.state_revision,
                "validate artifact",
            )
            .unwrap();
        let validated_progress = JobProgress {
            completed_steps: 2,
            total_steps: 3,
            bytes_done: 100,
            bytes_total: Some(100),
        };
        let validated = service
            .update_progress(
                &validating.job_id,
                validating.state_revision,
                validating.state,
                validated_progress.clone(),
                None,
                progress_evidence(&validating, &validated_progress),
            )
            .unwrap();
        let configuring = service
            .begin_configuration(&validated.job_id, validated.state_revision, "configure")
            .unwrap();
        let configured_progress = JobProgress {
            completed_steps: 3,
            total_steps: 3,
            bytes_done: 100,
            bytes_total: Some(100),
        };
        let configured = service
            .update_progress(
                &configuring.job_id,
                configuring.state_revision,
                configuring.state,
                configured_progress.clone(),
                Some("authenticated probe complete".into()),
                progress_evidence_for_step(
                    &configuring,
                    &configured_progress,
                    "authenticated probe complete",
                ),
            )
            .unwrap();
        let ready = service
            .mark_ready(
                &configured.job_id,
                configured.state_revision,
                ready_evidence(&configured),
            )
            .unwrap();
        assert_eq!(ready.state, JobState::Ready);
        assert_eq!(ready.state_revision, 7);
        assert!(ready.terminal_at.is_some());
        assert_eq!(service.get(&ready.job_id).unwrap(), Some(ready.clone()));
        assert!(matches!(
            service.update_progress(
                &ready.job_id,
                ready.state_revision,
                ready.state,
                ready.progress.clone(),
                None,
                progress_evidence(&ready, &ready.progress),
            ),
            Err(JobServiceError::ProgressNotAllowed(JobState::Ready))
        ));
        assert!(matches!(
            service.fail(
                &ready.job_id,
                ready.state_revision,
                JobFailure::new("late_failure", "Too late.").unwrap()
            ),
            Err(JobServiceError::IllegalTransition {
                from: JobState::Ready,
                ..
            })
        ));

        drop(service);
        let reopened = IntegrationJobService::open_fail_closed(&home(&root), catalog()).unwrap();
        assert_eq!(reopened.get(&ready.job_id).unwrap(), Some(ready));
        assert!(reopened.startup_recovery().is_empty());
    }

    #[test]
    fn concurrent_commits_publish_in_revision_order() {
        let root = tempfile::tempdir().unwrap();
        let mut service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let mut subscription = service.subscribe().unwrap();

        let (first_publish_tx, first_publish_rx) = std::sync::mpsc::sync_channel(1);
        let (second_publish_tx, second_publish_rx) = std::sync::mpsc::sync_channel(1);
        let release_first = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let hook_gate = release_first.clone();
        service.events = service
            .events
            .clone()
            .with_before_publish(Arc::new(move |event| {
                if event.job.state_revision == 2 {
                    first_publish_tx.send(()).unwrap();
                    let (lock, condition) = &*hook_gate;
                    let mut released = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    while !*released {
                        released = condition
                            .wait(released)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                } else if event.job.state_revision == 3 {
                    second_publish_tx.send(()).unwrap();
                }
            }));

        let first_progress = JobProgress {
            completed_steps: 1,
            total_steps: 3,
            bytes_done: 10,
            bytes_total: Some(100),
        };
        let first_evidence = progress_evidence(&running, &first_progress);
        let first_service = service.clone();
        let first_id = running.job_id.clone();
        let first = std::thread::spawn(move || {
            first_service
                .update_progress(
                    &first_id,
                    running.state_revision,
                    running.state,
                    first_progress,
                    None,
                    first_evidence,
                )
                .unwrap()
        });
        first_publish_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        let second_progress = JobProgress {
            completed_steps: 2,
            total_steps: 3,
            bytes_done: 20,
            bytes_total: Some(100),
        };
        let second_evidence = ProgressEvidence::verified(ProgressEvidenceFixture {
            job_id: running.job_id.clone(),
            manifest_sha256: digest('a'),
            step_plan_sha256: digest('e'),
            staging_binding_sha256: digest('f'),
            expected_revision: 2,
            expected_state: JobState::Running,
            current_phase: "download".into(),
            completed_steps: second_progress.completed_steps,
            bytes_done: second_progress.bytes_done,
        });
        let second_service = service.clone();
        let second_id = running.job_id.clone();
        let second = std::thread::spawn(move || {
            second_service
                .update_progress(
                    &second_id,
                    2,
                    JobState::Running,
                    second_progress,
                    None,
                    second_evidence,
                )
                .unwrap()
        });

        let reordered = second_publish_rx
            .recv_timeout(Duration::from_millis(250))
            .is_ok();
        let (lock, condition) = &*release_first;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        condition.notify_all();
        first.join().unwrap();
        second.join().unwrap();

        assert!(
            !reordered,
            "revision 3 published before revision 2 was released"
        );
        assert_eq!(subscription.try_recv().unwrap().job.state_revision, 2);
        assert_eq!(subscription.try_recv().unwrap().job.state_revision, 3);
    }

    #[test]
    fn ready_requires_complete_progress_and_exact_manifest_evidence() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let validating = service
            .begin_validation(&running.job_id, running.state_revision, "validate")
            .unwrap();
        let configuring = service
            .begin_configuration(&validating.job_id, validating.state_revision, "configure")
            .unwrap();
        assert!(matches!(
            service.mark_ready(
                &job.job_id,
                configuring.state_revision,
                ready_evidence(&job),
            ),
            Err(JobServiceError::IncompleteProgress)
        ));
        let complete = JobProgress {
            completed_steps: 3,
            total_steps: 3,
            bytes_done: 100,
            bytes_total: Some(100),
        };
        let wrong_checkpoint = ProgressEvidence::verified(ProgressEvidenceFixture {
            job_id: JobId::new(),
            manifest_sha256: digest('a'),
            step_plan_sha256: digest('e'),
            staging_binding_sha256: digest('f'),
            expected_revision: configuring.state_revision,
            expected_state: configuring.state,
            current_phase: configuring.current_step.clone().unwrap(),
            completed_steps: 3,
            bytes_done: 100,
        });
        assert!(matches!(
            service.update_progress(
                &job.job_id,
                configuring.state_revision,
                configuring.state,
                complete.clone(),
                None,
                wrong_checkpoint,
            ),
            Err(JobServiceError::ProgressEvidenceMismatch)
        ));
        assert_eq!(
            service
                .get(&job.job_id)
                .unwrap()
                .unwrap()
                .progress
                .bytes_done,
            0
        );
        let completed = service
            .update_progress(
                &job.job_id,
                configuring.state_revision,
                configuring.state,
                complete.clone(),
                None,
                progress_evidence(&configuring, &complete),
            )
            .unwrap();
        let wrong = ReadyEvidence::verified(
            job.job_id.clone(),
            digest('f'),
            digest('b'),
            digest('c'),
            digest('d'),
            digest('e'),
        );
        assert!(matches!(
            service.mark_ready(&job.job_id, completed.state_revision, wrong),
            Err(JobServiceError::ReadyEvidenceMismatch)
        ));
    }

    #[test]
    fn stale_worker_cannot_write_progress_after_phase_transition() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let stale_progress = JobProgress {
            completed_steps: 1,
            total_steps: 3,
            bytes_done: 10,
            bytes_total: Some(100),
        };
        let stale_evidence = progress_evidence(&running, &stale_progress);
        let validating = service
            .begin_validation(&running.job_id, running.state_revision, "validate")
            .unwrap();

        assert!(matches!(
            service.update_progress(
                &running.job_id,
                running.state_revision,
                running.state,
                stale_progress,
                None,
                stale_evidence,
            ),
            Err(JobServiceError::StaleRevision { .. })
        ));
        let durable = service.get(&running.job_id).unwrap().unwrap();
        assert_eq!(durable.state_revision, validating.state_revision);
        assert_eq!(durable.state, JobState::Validating);
        assert_eq!(durable.progress.completed_steps, 0);
        assert!(durable.progress_evidence.is_none());
    }

    #[test]
    fn progress_step_change_requires_evidence_for_new_step() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let checkpoint = JobProgress {
            completed_steps: 1,
            total_steps: 3,
            bytes_done: 10,
            bytes_total: Some(100),
        };
        let evidence_for_old_step = progress_evidence(&running, &checkpoint);

        assert!(matches!(
            service.update_progress(
                &running.job_id,
                running.state_revision,
                running.state,
                checkpoint,
                Some("download complete".into()),
                evidence_for_old_step,
            ),
            Err(JobServiceError::ProgressEvidenceMismatch)
        ));
        assert_eq!(service.get(&running.job_id).unwrap(), Some(running));
    }

    #[test]
    fn progress_step_change_with_exact_evidence_reopens_bound_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let job_id = {
            let service = service(&root);
            let job = service.enqueue(request("qwen-model")).unwrap().job;
            let running = service
                .start(&job.job_id, job.state_revision, "download")
                .unwrap();
            let checkpoint = JobProgress {
                completed_steps: 1,
                total_steps: 3,
                bytes_done: 10,
                bytes_total: Some(100),
            };
            let checkpoint_evidence =
                progress_evidence_for_step(&running, &checkpoint, "download complete");
            let updated = service
                .update_progress(
                    &running.job_id,
                    running.state_revision,
                    running.state,
                    checkpoint,
                    Some("download complete".into()),
                    checkpoint_evidence,
                )
                .unwrap();
            assert_eq!(updated.current_step.as_deref(), Some("download complete"));
            updated.validate().unwrap();
            let validating = service
                .begin_validation(&updated.job_id, updated.state_revision, "validate artifact")
                .unwrap();
            assert_eq!(
                validating.current_step.as_deref(),
                Some("validate artifact")
            );
            assert_eq!(
                serde_json::to_value(validating.progress_evidence.as_ref().unwrap()).unwrap()["current_step"],
                "download complete"
            );
            validating.validate().unwrap();
            validating.job_id
        };

        let validator = |job: &IntegrationJob| resume_decision(job, 'f');
        let reopened = IntegrationJobService::open(&home(&root), catalog(), &validator).unwrap();
        let recovered = reopened.get(&job_id).unwrap().unwrap();
        assert_eq!(recovered.state, JobState::Queued);
        assert_eq!(recovered.current_step.as_deref(), Some("download complete"));
        assert_eq!(recovered.progress.completed_steps, 1);
        assert_eq!(
            serde_json::to_value(recovered.progress_evidence.as_ref().unwrap()).unwrap()["current_step"],
            "download complete"
        );
        recovered.validate().unwrap();
    }

    #[test]
    fn stale_transition_and_failure_cannot_overwrite_newer_revision() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let queued = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&queued.job_id, queued.state_revision, "download")
            .unwrap();

        assert!(matches!(
            service.begin_validation(&queued.job_id, queued.state_revision, "stale validate"),
            Err(JobServiceError::StaleRevision { .. })
        ));
        assert_eq!(service.get(&running.job_id).unwrap(), Some(running.clone()));

        let validating = service
            .begin_validation(&running.job_id, running.state_revision, "validate")
            .unwrap();
        assert!(matches!(
            service.fail(
                &running.job_id,
                running.state_revision,
                JobFailure::new("stale_worker", "A stale worker tried to fail the job.").unwrap(),
            ),
            Err(JobServiceError::StaleRevision { .. })
        ));
        assert_eq!(service.get(&validating.job_id).unwrap(), Some(validating));
    }

    #[test]
    fn different_active_operation_is_busy_but_other_capability_is_independent() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let first = service.enqueue(request("qwen-model")).unwrap().job;
        let mut competing = request("qwen-model");
        competing.operation = JobOperation::Repair;
        assert!(matches!(
            service.enqueue(competing),
            Err(JobServiceError::CapabilityBusy { active_job, .. }) if active_job == first.job_id
        ));
        assert!(service.enqueue(request("managed-node")).unwrap().created);
        assert_eq!(service.active_snapshot().unwrap().len(), 2);
    }

    #[test]
    fn coalescing_rejects_an_incompatible_progress_contract() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let first = service.enqueue(request("qwen-model")).unwrap().job;

        let mut different_steps = request("qwen-model");
        different_steps.total_steps = 4;
        assert!(matches!(
            service.enqueue(different_steps),
            Err(JobServiceError::ActivePlanMismatch { active_job, .. })
                if active_job == first.job_id
        ));
        let mut different_bytes = request("qwen-model");
        different_bytes.bytes_total = Some(101);
        assert!(matches!(
            service.enqueue(different_bytes),
            Err(JobServiceError::ActivePlanMismatch { active_job, .. })
                if active_job == first.job_id
        ));
        let mut different_evidence = request("qwen-model");
        different_evidence.evidence_contract =
            JobEvidenceContract::verified(digest('f'), digest('c'), digest('d'), digest('e'));
        assert!(matches!(
            service.enqueue(different_evidence),
            Err(JobServiceError::ActivePlanMismatch { active_job, .. })
                if active_job == first.job_id
        ));
    }

    #[test]
    fn cancellation_is_durable_and_blocks_forward_progress() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);

        let queued = service.enqueue(request("managed-node")).unwrap().job;
        assert!(matches!(
            service.acknowledge_cancel(
                &queued.job_id,
                queued.state_revision,
                cancellation_evidence(&queued),
            ),
            Err(JobServiceError::CancellationNotRequested)
        ));
        assert_eq!(service.get(&queued.job_id).unwrap(), Some(queued.clone()));
        let queued = service
            .request_cancel(&queued.job_id, queued.state_revision)
            .unwrap();
        assert_eq!(queued.state, JobState::Cancelled);
        assert!(queued.cancel_requested);

        let running = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&running.job_id, running.state_revision, "download")
            .unwrap();
        assert!(matches!(
            service.request_cancel(&running.job_id, 0),
            Err(JobServiceError::StaleRevision { .. })
        ));
        let requested = service
            .request_cancel(&running.job_id, running.state_revision)
            .unwrap();
        assert_eq!(requested.state, JobState::Running);
        assert!(requested.cancel_requested);
        assert!(matches!(
            service.acknowledge_cancel(
                &requested.job_id,
                requested.state_revision,
                cancellation_evidence(&running),
            ),
            Err(JobServiceError::CancellationEvidenceMismatch)
        ));
        assert!(matches!(
            service.begin_validation(
                &running.job_id,
                requested.state_revision,
                "must not continue",
            ),
            Err(JobServiceError::CancellationPending)
        ));
        assert!(matches!(
            service.update_progress(
                &running.job_id,
                requested.state_revision,
                requested.state,
                JobProgress {
                    completed_steps: 1,
                    total_steps: 3,
                    bytes_done: 10,
                    bytes_total: Some(100),
                },
                Some("must not continue".into()),
                ProgressEvidence::verified(ProgressEvidenceFixture {
                    job_id: running.job_id.clone(),
                    manifest_sha256: digest('a'),
                    step_plan_sha256: digest('e'),
                    staging_binding_sha256: digest('f'),
                    expected_revision: requested.state_revision,
                    expected_state: requested.state,
                    current_phase: "must not continue".into(),
                    completed_steps: 1,
                    bytes_done: 10,
                }),
            ),
            Err(JobServiceError::CancellationPending)
        ));
        let cancelled = service
            .acknowledge_cancel(
                &running.job_id,
                requested.state_revision,
                cancellation_evidence(&requested),
            )
            .unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        assert!(matches!(
            service.acknowledge_cancel(
                &running.job_id,
                cancelled.state_revision,
                cancellation_evidence(&cancelled),
            ),
            Err(JobServiceError::CancellationNotRequested)
                | Err(JobServiceError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn retry_is_new_history_bound_to_manifest_and_verified_staging() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let checkpoint = JobProgress {
            completed_steps: 1,
            total_steps: 3,
            bytes_done: 40,
            bytes_total: Some(100),
        };
        let checkpointed = service
            .update_progress(
                &job.job_id,
                running.state_revision,
                running.state,
                checkpoint.clone(),
                None,
                progress_evidence(&running, &checkpoint),
            )
            .unwrap();
        let failed = service
            .fail(
                &job.job_id,
                checkpointed.state_revision,
                JobFailure::new("offline", "Network became unavailable.").unwrap(),
            )
            .unwrap();
        let wrong =
            ResumeEvidence::verified(job.job_id.clone(), digest('f'), digest('e'), digest('f'));
        assert!(matches!(
            service.retry(
                &job.job_id,
                failed.state_revision - 1,
                resume_evidence(&job, 'f'),
                JobRequester::Gui,
            ),
            Err(JobServiceError::StaleRevision { .. })
        ));
        assert!(matches!(
            service.retry(&job.job_id, failed.state_revision, wrong, JobRequester::Gui,),
            Err(JobServiceError::ResumeEvidenceMismatch)
        ));

        let mut subscription = service.subscribe().unwrap();
        let retry = service
            .retry(
                &job.job_id,
                failed.state_revision,
                resume_evidence(&job, 'f'),
                JobRequester::Gui,
            )
            .unwrap();
        let event = subscription.try_recv().unwrap();
        assert_eq!(event.job.job_id, retry.job_id);
        assert!(matches!(
            event.event,
            IntegrationJobEventKind::Retried { retry_of } if retry_of == job.job_id
        ));
        assert_ne!(retry.job_id, job.job_id);
        assert_eq!(retry.retry_of, Some(job.job_id.clone()));
        assert_eq!(retry.manifest_sha256, job.manifest_sha256);
        assert_eq!(retry.progress.bytes_done, 40);
        assert_eq!(retry.current_step.as_deref(), Some("download"));
        assert_eq!(
            serde_json::to_value(retry.progress_evidence.as_ref().unwrap()).unwrap()["current_step"],
            "download"
        );
        let old = service.get(&job.job_id).unwrap().unwrap();
        assert_eq!(old.state, JobState::Failed);
        assert!(old.failure.is_some());

        let retry_failed = service
            .fail(
                &retry.job_id,
                retry.state_revision,
                JobFailure::new("retry_failed", "The retry failed safely.").unwrap(),
            )
            .unwrap();
        assert_eq!(retry_failed.state, JobState::Failed);
        assert!(matches!(
            service.retry(
                &job.job_id,
                failed.state_revision,
                resume_evidence(&job, 'f'),
                JobRequester::Gui,
            ),
            Err(JobServiceError::AlreadyRetried {
                original_job,
                retry_job,
            }) if original_job == job.job_id && retry_job == retry.job_id
        ));
    }

    #[test]
    fn retry_resets_null_counter_checkpoint_when_evidence_differs() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        let running = service
            .start(&job.job_id, job.state_revision, "download")
            .unwrap();
        let checkpoint = JobProgress {
            completed_steps: 0,
            total_steps: 3,
            bytes_done: 0,
            bytes_total: Some(100),
        };
        let checkpointed = service
            .update_progress(
                &job.job_id,
                running.state_revision,
                running.state,
                checkpoint.clone(),
                Some("download checkpoint".into()),
                progress_evidence_for_step(&running, &checkpoint, "download checkpoint"),
            )
            .unwrap();
        let failed = service
            .fail(
                &job.job_id,
                checkpointed.state_revision,
                JobFailure::new("offline", "Network became unavailable.").unwrap(),
            )
            .unwrap();

        let retry = service
            .retry(
                &job.job_id,
                failed.state_revision,
                resume_evidence(&job, '9'),
                JobRequester::Gui,
            )
            .unwrap();
        assert_eq!(retry.progress.completed_steps, 0);
        assert_eq!(retry.progress.bytes_done, 0);
        assert_eq!(retry.progress.total_steps, 3);
        assert_eq!(retry.progress.bytes_total, Some(100));
        assert!(retry.progress_evidence.is_none());
        assert!(retry.current_step.is_none());
    }

    #[test]
    fn restart_resumes_only_after_exact_manifest_and_staging_validation() {
        let root = tempfile::tempdir().unwrap();
        let job_id = {
            let service = service(&root);
            let job = service.enqueue(request("qwen-model")).unwrap().job;
            let running = service
                .start(&job.job_id, job.state_revision, "download")
                .unwrap();
            let checkpoint = JobProgress {
                completed_steps: 1,
                total_steps: 3,
                bytes_done: 25,
                bytes_total: Some(100),
            };
            service
                .update_progress(
                    &job.job_id,
                    running.state_revision,
                    running.state,
                    checkpoint.clone(),
                    None,
                    progress_evidence(&running, &checkpoint),
                )
                .unwrap();
            job.job_id
        };

        let validator = |job: &IntegrationJob| resume_decision(job, 'f');
        let reopened = IntegrationJobService::open(&home(&root), catalog(), &validator).unwrap();
        let recovered = reopened.get(&job_id).unwrap().unwrap();
        assert_eq!(recovered.state, JobState::Queued);
        assert_eq!(recovered.progress.bytes_done, 25);
        assert_eq!(recovered.current_step.as_deref(), Some("download"));
        assert_eq!(
            serde_json::to_value(recovered.progress_evidence.as_ref().unwrap()).unwrap()["current_step"],
            "download"
        );
        assert_eq!(reopened.startup_recovery().len(), 1);
        assert_eq!(
            reopened.startup_recovery()[0].previous_state,
            JobState::Running
        );
    }

    #[test]
    fn restart_resets_null_counter_checkpoint_when_staging_changed() {
        let root = tempfile::tempdir().unwrap();
        let job_id = {
            let service = service(&root);
            let job = service.enqueue(request("qwen-model")).unwrap().job;
            let running = service
                .start(&job.job_id, job.state_revision, "download")
                .unwrap();
            let checkpoint = JobProgress {
                completed_steps: 0,
                total_steps: 3,
                bytes_done: 0,
                bytes_total: Some(100),
            };
            service
                .update_progress(
                    &job.job_id,
                    running.state_revision,
                    running.state,
                    checkpoint.clone(),
                    Some("download checkpoint".into()),
                    progress_evidence_for_step(&running, &checkpoint, "download checkpoint"),
                )
                .unwrap();
            job.job_id
        };

        let validator = |job: &IntegrationJob| resume_decision(job, '9');
        let reopened = IntegrationJobService::open(&home(&root), catalog(), &validator).unwrap();
        let recovered = reopened.get(&job_id).unwrap().unwrap();
        assert_eq!(recovered.state, JobState::Queued);
        assert_eq!(recovered.progress.completed_steps, 0);
        assert_eq!(recovered.progress.bytes_done, 0);
        assert!(recovered.progress_evidence.is_none());
        assert!(recovered.current_step.is_none());
    }

    #[test]
    fn restart_without_cleanup_proof_preserves_active_row_and_verified_cancel_completes() {
        let rejected_root = tempfile::tempdir().unwrap();
        let queued = {
            let service = service(&rejected_root);
            service.enqueue(request("qwen-model")).unwrap().job
        };
        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home(&rejected_root), catalog()),
            Err(JobServiceError::RecoveryValidationUnavailable)
        ));
        assert_eq!(persisted_job(&home(&rejected_root), &queued.job_id), queued);

        let cancelled_root = tempfile::tempdir().unwrap();
        let pending_cancel = {
            let service = service(&cancelled_root);
            let job = service.enqueue(request("qwen-model")).unwrap().job;
            let running = service
                .start(&job.job_id, job.state_revision, "download")
                .unwrap();
            service
                .request_cancel(&job.job_id, running.state_revision)
                .unwrap()
        };
        let invalid_resume = |job: &IntegrationJob| resume_decision(job, 'f');
        assert!(matches!(
            IntegrationJobService::open(&home(&cancelled_root), catalog(), &invalid_resume),
            Err(JobServiceError::RecoveryDecisionInvalid)
        ));
        assert_eq!(
            persisted_job(&home(&cancelled_root), &pending_cancel.job_id),
            pending_cancel
        );
        let reject = |job: &IntegrationJob| reject_decision(job, "cancelled_after_restart");
        let reopened =
            IntegrationJobService::open(&home(&cancelled_root), catalog(), &reject).unwrap();
        let cancelled = reopened.get(&pending_cancel.job_id).unwrap().unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        assert!(cancelled.cancel_requested);
        assert!(cancelled.failure.is_none());
    }

    #[test]
    fn restart_disposition_mismatch_rolls_back_all_active_rows_atomically() {
        let root = tempfile::tempdir().unwrap();
        let (qwen_running, node_running) = {
            let service = service(&root);
            let qwen = service.enqueue(request("qwen-model")).unwrap().job;
            let node = service.enqueue(request("managed-node")).unwrap().job;
            (
                service
                    .start(&qwen.job_id, qwen.state_revision, "download")
                    .unwrap(),
                service
                    .start(&node.job_id, node.state_revision, "install")
                    .unwrap(),
            )
        };
        let stale_disposition = |job: &IntegrationJob| RestartDecision::Resume {
            evidence: resume_evidence(job, 'f'),
            disposition: RecoveryDispositionEvidence::verified(
                job.job_id.clone(),
                digest('a'),
                digest('e'),
                if job.capability_id.as_str() == "managed-node" {
                    job.state_revision + 1
                } else {
                    job.state_revision
                },
                digest('b'),
                digest('c'),
            ),
        };
        assert!(matches!(
            IntegrationJobService::open(&home(&root), catalog(), &stale_disposition),
            Err(JobServiceError::RecoveryDispositionMismatch)
        ));
        assert_eq!(
            persisted_job(&home(&root), &qwen_running.job_id),
            qwen_running
        );
        assert_eq!(
            persisted_job(&home(&root), &node_running.job_id),
            node_running
        );
    }

    #[test]
    fn process_owner_lock_prevents_false_crash_recovery() {
        let root = tempfile::tempdir().unwrap();
        let first = service(&root);
        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home(&root), catalog()),
            Err(JobServiceError::AlreadyOwned(_))
        ));
        drop(first);
        IntegrationJobService::open_fail_closed(&home(&root), catalog()).unwrap();
    }

    #[test]
    fn empty_steps_fail_and_clock_rollback_is_clamped() {
        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        let job = service.enqueue(request("qwen-model")).unwrap().job;
        assert!(matches!(
            service.start(&job.job_id, job.state_revision, ""),
            Err(JobServiceError::State(
                StateValidationError::InvalidPublicText { .. }
            ))
        ));

        let future = crate::time::now_unix_i64() + 10_000;
        let connection = Connection::open(&service.store.path).unwrap();
        connection
            .execute(
                "UPDATE integration_jobs SET updated_at=?1 WHERE job_id=?2",
                params![future, job.job_id.as_str()],
            )
            .unwrap();
        drop(connection);
        let cancelled = service
            .request_cancel(&job.job_id, job.state_revision)
            .unwrap();
        assert_eq!(cancelled.updated_at, future);
        assert_eq!(cancelled.terminal_at, Some(future));
        cancelled.validate().unwrap();
    }

    #[test]
    fn schema_v1_migrates_active_work_to_fail_closed_history() {
        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(&home).unwrap();
        let database = home.join(DB_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE setup_component_schema (
                   component TEXT PRIMARY KEY NOT NULL,
                   version INTEGER NOT NULL
                 );
                 INSERT INTO setup_component_schema(component, version)
                   VALUES ('integrations', 1);
                 CREATE TABLE integration_jobs (
                   job_id TEXT PRIMARY KEY NOT NULL, capability_id TEXT NOT NULL,
                   operation TEXT NOT NULL, release_version TEXT NOT NULL,
                   manifest_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                   state_revision INTEGER NOT NULL, current_step TEXT,
                   completed_steps INTEGER NOT NULL, total_steps INTEGER NOT NULL,
                   bytes_done INTEGER NOT NULL, bytes_total INTEGER,
                   created_at INTEGER NOT NULL, started_at INTEGER,
                   updated_at INTEGER NOT NULL, terminal_at INTEGER,
                   error_code TEXT, redacted_error TEXT, ready_evidence_json TEXT,
                   retry_of TEXT, requested_by TEXT NOT NULL,
                   cancel_requested INTEGER NOT NULL
                 );
                 CREATE UNIQUE INDEX integration_jobs_one_active_capability
                   ON integration_jobs(capability_id)
                   WHERE state IN ('queued','running','validating','configuring');
                 CREATE INDEX integration_jobs_updated
                   ON integration_jobs(updated_at, job_id);",
            )
            .unwrap();
        let job_id = JobId::new();
        connection
            .execute(
                "INSERT INTO integration_jobs VALUES (
                   ?1,'qwen-model','install','1.0.0',?2,'queued',0,NULL,
                   0,3,0,100,100,NULL,100,NULL,NULL,NULL,NULL,NULL,'cli',0
                 )",
                params![job_id.as_str(), digest('a').as_str()],
            )
            .unwrap();
        drop(connection);

        let service = IntegrationJobService::open_fail_closed(&home, catalog()).unwrap();
        let migrated = service.get(&job_id).unwrap().unwrap();
        assert_eq!(migrated.state, JobState::Failed);
        assert_eq!(migrated.state_revision, 1);
        assert!(migrated.evidence_contract.is_none());
        assert_eq!(
            migrated.failure.unwrap().code,
            "evidence_contract_migration_required"
        );
    }

    #[test]
    fn schema_v1_foreign_key_failure_rolls_back_without_losing_source_history() {
        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(&home).unwrap();
        let database = home.join(DB_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE setup_component_schema (
                   component TEXT PRIMARY KEY NOT NULL,
                   version INTEGER NOT NULL
                 );
                 INSERT INTO setup_component_schema(component, version)
                   VALUES ('integrations', 1);
                 CREATE TABLE integration_jobs (
                   job_id TEXT PRIMARY KEY NOT NULL, capability_id TEXT NOT NULL,
                   operation TEXT NOT NULL, release_version TEXT NOT NULL,
                   manifest_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                   state_revision INTEGER NOT NULL, current_step TEXT,
                   completed_steps INTEGER NOT NULL, total_steps INTEGER NOT NULL,
                   bytes_done INTEGER NOT NULL, bytes_total INTEGER,
                   created_at INTEGER NOT NULL, started_at INTEGER,
                   updated_at INTEGER NOT NULL, terminal_at INTEGER,
                   error_code TEXT, redacted_error TEXT, ready_evidence_json TEXT,
                   retry_of TEXT, requested_by TEXT NOT NULL,
                   cancel_requested INTEGER NOT NULL
                 );
                 CREATE UNIQUE INDEX integration_jobs_one_active_capability
                   ON integration_jobs(capability_id)
                   WHERE state IN ('queued','running','validating','configuring');
                 CREATE INDEX integration_jobs_updated
                   ON integration_jobs(updated_at, job_id);",
            )
            .unwrap();
        let job_id = JobId::new();
        let missing_parent = JobId::new();
        connection
            .execute(
                "INSERT INTO integration_jobs VALUES (
                   ?1,'qwen-model','install','1.0.0',?2,'failed',1,NULL,
                   0,3,0,100,100,100,101,101,'offline','Offline.',NULL,?3,'cli',0
                 )",
                params![
                    job_id.as_str(),
                    digest('a').as_str(),
                    missing_parent.as_str()
                ],
            )
            .unwrap();
        drop(connection);

        let error = match IntegrationJobService::open_fail_closed(&home, catalog()) {
            Ok(_) => panic!("dangling retry history must fail migration"),
            Err(error) => error,
        };
        assert!(matches!(error, JobServiceError::CorruptSchema));

        let connection = Connection::open(&database).unwrap();
        let version: i64 = connection
            .query_row(
                "SELECT version FROM setup_component_schema WHERE component='integrations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        let source_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM integration_jobs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(source_rows, 1);
        let temporary_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='integration_jobs_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(temporary_table, 0);
        let retry_of: String = connection
            .query_row(
                "SELECT retry_of FROM integration_jobs WHERE job_id=?1",
                [job_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retry_of, missing_parent.as_str());
    }

    #[test]
    fn schema_v1_malformed_terminal_history_rolls_back_without_relabeling_source() {
        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(&home).unwrap();
        let database = home.join(DB_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE setup_component_schema (
                   component TEXT PRIMARY KEY NOT NULL,
                   version INTEGER NOT NULL
                 );
                 INSERT INTO setup_component_schema(component, version)
                   VALUES ('integrations', 1);
                 CREATE TABLE integration_jobs (
                   job_id TEXT PRIMARY KEY NOT NULL, capability_id TEXT NOT NULL,
                   operation TEXT NOT NULL, release_version TEXT NOT NULL,
                   manifest_sha256 TEXT NOT NULL, state TEXT NOT NULL,
                   state_revision INTEGER NOT NULL, current_step TEXT,
                   completed_steps INTEGER NOT NULL, total_steps INTEGER NOT NULL,
                   bytes_done INTEGER NOT NULL, bytes_total INTEGER,
                   created_at INTEGER NOT NULL, started_at INTEGER,
                   updated_at INTEGER NOT NULL, terminal_at INTEGER,
                   error_code TEXT, redacted_error TEXT, ready_evidence_json TEXT,
                   retry_of TEXT, requested_by TEXT NOT NULL,
                   cancel_requested INTEGER NOT NULL
                 );
                 CREATE UNIQUE INDEX integration_jobs_one_active_capability
                   ON integration_jobs(capability_id)
                   WHERE state IN ('queued','running','validating','configuring');
                 CREATE INDEX integration_jobs_updated
                   ON integration_jobs(updated_at, job_id);",
            )
            .unwrap();
        let job_id = JobId::new();
        connection
            .execute(
                "INSERT INTO integration_jobs VALUES (
                   ?1,'qwen-model','install','1.0.0','not-a-sha256','failed',1,NULL,
                   0,3,0,100,100,100,101,101,'offline','Offline.',NULL,NULL,'cli',0
                 )",
                [job_id.as_str()],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home, catalog()),
            Err(JobServiceError::CorruptSchema)
        ));
        let connection = Connection::open(&database).unwrap();
        let version: i64 = connection
            .query_row(
                "SELECT version FROM setup_component_schema WHERE component='integrations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        let manifest: String = connection
            .query_row(
                "SELECT manifest_sha256 FROM integration_jobs WHERE job_id=?1",
                [job_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(manifest, "not-a-sha256");
    }

    #[test]
    fn schema_v2_rejects_same_name_wrong_index_contract() {
        let root = tempfile::tempdir().unwrap();
        let database = {
            let service = service(&root);
            service.store.path.clone()
        };
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "DROP INDEX integration_jobs_one_active_capability;
                 CREATE INDEX integration_jobs_one_active_capability
                   ON integration_jobs(job_id)
                   WHERE state IN ('queued','running','validating','configuring');",
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home(&root), catalog()),
            Err(JobServiceError::CorruptSchema)
        ));
    }

    #[test]
    fn schema_v2_rejects_missing_retry_foreign_key_with_same_columns() {
        let root = tempfile::tempdir().unwrap();
        let database = {
            let service = service(&root);
            service.store.path.clone()
        };
        let connection = Connection::open(&database).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection
            .execute_batch(
                "DROP INDEX integration_jobs_one_active_capability;
                 DROP INDEX integration_jobs_one_retry_child;
                 DROP INDEX integration_jobs_updated;
                 ALTER TABLE integration_jobs RENAME TO integration_jobs_old;",
            )
            .unwrap();
        let without_retry_fk = CREATE_INTEGRATION_JOBS_TABLE.replace(
            "retry_of TEXT REFERENCES integration_jobs(job_id)",
            "retry_of TEXT",
        );
        connection.execute_batch(&without_retry_fk).unwrap();
        create_integration_job_indexes(&connection).unwrap();
        connection
            .execute_batch("DROP TABLE integration_jobs_old;")
            .unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        drop(connection);

        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home(&root), catalog()),
            Err(JobServiceError::CorruptSchema)
        ));
    }

    #[test]
    fn corrupt_schema_error_never_echoes_column_identifiers() {
        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(&home).unwrap();
        let connection = Connection::open(home.join(DB_FILE_NAME)).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE setup_component_schema (
                   component TEXT PRIMARY KEY NOT NULL,
                   version INTEGER NOT NULL
                 );
                 INSERT INTO setup_component_schema(component, version)
                   VALUES ('integrations', 2);
                 CREATE TABLE integration_jobs (
                   \"Bearer super-secret-column\" TEXT
                 );",
            )
            .unwrap();
        drop(connection);

        let error = match IntegrationJobService::open_fail_closed(&home, catalog()) {
            Ok(_) => panic!("corrupt schema must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(&error, JobServiceError::CorruptSchema));
        let rendered = error.to_string();
        assert!(!rendered.contains("super-secret-column"));
        assert_eq!(rendered, "integration setup schema is corrupt");
    }

    #[test]
    fn existing_nonregular_owner_lock_is_rejected_before_open() {
        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(home.join(OWNER_LOCK_FILE_NAME)).unwrap();
        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home, catalog()),
            Err(JobServiceError::Persistence(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_lock_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let home = home(&root);
        std::fs::create_dir_all(&home).unwrap();
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        symlink(&sentinel, home.join(OWNER_LOCK_FILE_NAME)).unwrap();
        assert!(matches!(
            IntegrationJobService::open_fail_closed(&home, catalog()),
            Err(JobServiceError::Persistence(_))
        ));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn setup_database_and_parent_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let service = service(&root);
        drop(service);
        let home = home(&root);
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(home.join(DB_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
