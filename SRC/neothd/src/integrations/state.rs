//! Exhaustive integration-job state and evidence contracts.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::catalog::CapabilityId;

const MAX_STEP_LEN: usize = 160;
const MAX_ERROR_LEN: usize = 2_048;
const MAX_ERROR_CODE_LEN: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(String);

impl JobId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, StateValidationError> {
        let value = value.into();
        let parsed =
            uuid::Uuid::parse_str(&value).map_err(|_| StateValidationError::InvalidJobId)?;
        if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
            return Err(StateValidationError::InvalidJobId);
        }
        Ok(Self(parsed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for JobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JobId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, StateValidationError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
        {
            return Err(StateValidationError::InvalidSha256);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Validating,
    Configuring,
    Ready,
    Failed,
    Cancelled,
}

impl JobState {
    pub const ALL: [Self; 7] = [
        Self::Queued,
        Self::Running,
        Self::Validating,
        Self::Configuring,
        Self::Ready,
        Self::Failed,
        Self::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Validating => "validating",
            Self::Configuring => "configuring",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed | Self::Cancelled)
    }

    pub fn is_active(self) -> bool {
        !self.is_terminal()
    }

    pub fn permits_progress(self) -> bool {
        matches!(self, Self::Running | Self::Validating | Self::Configuring)
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Failed | Self::Cancelled)
                | (
                    Self::Running,
                    Self::Validating | Self::Failed | Self::Cancelled
                )
                | (
                    Self::Validating,
                    Self::Configuring | Self::Failed | Self::Cancelled
                )
                | (
                    Self::Configuring,
                    Self::Ready | Self::Failed | Self::Cancelled
                )
        )
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobState {
    type Err = StateValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "validating" => Ok(Self::Validating),
            "configuring" => Ok(Self::Configuring),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(StateValidationError::UnknownState),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOperation {
    Install,
    Repair,
    Update,
    Uninstall,
}

impl JobOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Repair => "repair",
            Self::Update => "update",
            Self::Uninstall => "uninstall",
        }
    }
}

impl FromStr for JobOperation {
    type Err = StateValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "install" => Ok(Self::Install),
            "repair" => Ok(Self::Repair),
            "update" => Ok(Self::Update),
            "uninstall" => Ok(Self::Uninstall),
            _ => Err(StateValidationError::UnknownOperation),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRequester {
    Buddy,
    Cli,
    Daemon,
    Doctor,
    FirstUse,
    Gui,
    Migration,
    Wizard,
}

impl JobRequester {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buddy => "buddy",
            Self::Cli => "cli",
            Self::Daemon => "daemon",
            Self::Doctor => "doctor",
            Self::FirstUse => "first_use",
            Self::Gui => "gui",
            Self::Migration => "migration",
            Self::Wizard => "wizard",
        }
    }
}

impl FromStr for JobRequester {
    type Err = StateValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "buddy" => Ok(Self::Buddy),
            "cli" => Ok(Self::Cli),
            "daemon" => Ok(Self::Daemon),
            "doctor" => Ok(Self::Doctor),
            "first_use" => Ok(Self::FirstUse),
            "gui" => Ok(Self::Gui),
            "migration" => Ok(Self::Migration),
            "wizard" => Ok(Self::Wizard),
            _ => Err(StateValidationError::UnknownRequester),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobProgress {
    pub completed_steps: u32,
    pub total_steps: u32,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
}

impl JobProgress {
    pub fn new(total_steps: u32, bytes_total: Option<u64>) -> Self {
        Self {
            completed_steps: 0,
            total_steps,
            bytes_done: 0,
            bytes_total,
        }
    }

    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.total_steps == 0 {
            return Err(StateValidationError::InvalidProgress(
                "total_steps must be greater than zero".into(),
            ));
        }
        if self.completed_steps > self.total_steps {
            return Err(StateValidationError::InvalidProgress(
                "completed_steps exceeds total_steps".into(),
            ));
        }
        if let Some(total) = self.bytes_total
            && self.bytes_done > total
        {
            return Err(StateValidationError::InvalidProgress(
                "bytes_done exceeds bytes_total".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_monotonic_from(&self, previous: &Self) -> Result<(), StateValidationError> {
        self.validate()?;
        if self.completed_steps < previous.completed_steps || self.bytes_done < previous.bytes_done
        {
            return Err(StateValidationError::InvalidProgress(
                "progress counters cannot decrease".into(),
            ));
        }
        if self.total_steps != previous.total_steps {
            return Err(StateValidationError::InvalidProgress(
                "total_steps is immutable for a job".into(),
            ));
        }
        if let Some(old_total) = previous.bytes_total
            && self.bytes_total != Some(old_total)
        {
            return Err(StateValidationError::InvalidProgress(
                "known bytes_total is immutable for a job".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobFailure {
    pub code: String,
    pub redacted_message: String,
}

impl JobFailure {
    pub fn new(
        code: impl Into<String>,
        redacted_message: impl Into<String>,
    ) -> Result<Self, StateValidationError> {
        let failure = Self {
            code: code.into(),
            redacted_message: redacted_message.into(),
        };
        failure.validate()?;
        Ok(failure)
    }

    pub fn validate(&self) -> Result<(), StateValidationError> {
        validate_machine_code(&self.code)?;
        validate_bounded_public_text(&self.redacted_message, MAX_ERROR_LEN, "job failure")?;
        if self.redacted_message.is_empty() {
            return Err(StateValidationError::InvalidFailure(
                "redacted_message is empty".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable release and execution bindings fixed before a job is enqueued.
///
/// Construction is intentionally limited to reviewed lifecycle adapters under
/// `integrations`; public callers cannot declare their own expected evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobEvidenceContract {
    artifact_binding_sha256: Sha256Digest,
    config_binding_sha256: Sha256Digest,
    authenticated_probe_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
}

impl JobEvidenceContract {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(
        artifact_binding_sha256: Sha256Digest,
        config_binding_sha256: Sha256Digest,
        authenticated_probe_sha256: Sha256Digest,
        step_plan_sha256: Sha256Digest,
    ) -> Self {
        Self {
            artifact_binding_sha256,
            config_binding_sha256,
            authenticated_probe_sha256,
            step_plan_sha256,
        }
    }

    pub fn artifact_binding_sha256(&self) -> &Sha256Digest {
        &self.artifact_binding_sha256
    }

    pub fn config_binding_sha256(&self) -> &Sha256Digest {
        &self.config_binding_sha256
    }

    pub fn authenticated_probe_sha256(&self) -> &Sha256Digest {
        &self.authenticated_probe_sha256
    }

    pub fn step_plan_sha256(&self) -> &Sha256Digest {
        &self.step_plan_sha256
    }
}

/// Persisted receipt for the exact checkpoint represented by progress.
/// This type is never accepted as mutation authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressEvidenceReceipt {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
    staging_binding_sha256: Sha256Digest,
    current_step: String,
    completed_steps: u32,
    bytes_done: u64,
}

/// Persisted readiness receipt. Mutation APIs accept only the non-deserializable
/// [`ReadyEvidence`] token below, never this stored representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyEvidenceReceipt {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    artifact_binding_sha256: Sha256Digest,
    config_binding_sha256: Sha256Digest,
    authenticated_probe_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
}

/// Adapter-issued checkpoint evidence. It is deliberately not deserializable
/// and its fields are private, so wire data cannot manufacture a proof token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressEvidence {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
    staging_binding_sha256: Sha256Digest,
    expected_revision: u64,
    expected_state: JobState,
    current_phase: String,
    completed_steps: u32,
    bytes_done: u64,
}

#[cfg(test)]
pub(in crate::integrations) struct ProgressEvidenceFixture {
    pub job_id: JobId,
    pub manifest_sha256: Sha256Digest,
    pub step_plan_sha256: Sha256Digest,
    pub staging_binding_sha256: Sha256Digest,
    pub expected_revision: u64,
    pub expected_state: JobState,
    pub current_phase: String,
    pub completed_steps: u32,
    pub bytes_done: u64,
}

impl ProgressEvidence {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(fixture: ProgressEvidenceFixture) -> Self {
        Self {
            job_id: fixture.job_id,
            manifest_sha256: fixture.manifest_sha256,
            step_plan_sha256: fixture.step_plan_sha256,
            staging_binding_sha256: fixture.staging_binding_sha256,
            expected_revision: fixture.expected_revision,
            expected_state: fixture.expected_state,
            current_phase: fixture.current_phase,
            completed_steps: fixture.completed_steps,
            bytes_done: fixture.bytes_done,
        }
    }

    pub(in crate::integrations) fn receipt_for(
        &self,
        job: &IntegrationJob,
        progress: &JobProgress,
        expected_revision: u64,
        expected_state: JobState,
        checkpoint_step: &str,
    ) -> Option<ProgressEvidenceReceipt> {
        let contract = job.evidence_contract.as_ref()?;
        if self.job_id != job.job_id
            || self.manifest_sha256 != job.manifest_sha256
            || self.step_plan_sha256 != contract.step_plan_sha256
            || self.expected_revision != expected_revision
            || expected_revision != job.state_revision
            || self.expected_state != expected_state
            || expected_state != job.state
            || self.current_phase != checkpoint_step
            || self.completed_steps != progress.completed_steps
            || self.bytes_done != progress.bytes_done
        {
            return None;
        }
        Some(ProgressEvidenceReceipt {
            job_id: self.job_id.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            step_plan_sha256: self.step_plan_sha256.clone(),
            staging_binding_sha256: self.staging_binding_sha256.clone(),
            current_step: checkpoint_step.to_owned(),
            completed_steps: self.completed_steps,
            bytes_done: self.bytes_done,
        })
    }
}

/// Adapter-issued readiness evidence. Only integrations lifecycle adapters can
/// construct it; the job service compares every field with durable expectations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyEvidence {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    artifact_binding_sha256: Sha256Digest,
    config_binding_sha256: Sha256Digest,
    authenticated_probe_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
}

impl ReadyEvidence {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(
        job_id: JobId,
        manifest_sha256: Sha256Digest,
        artifact_binding_sha256: Sha256Digest,
        config_binding_sha256: Sha256Digest,
        authenticated_probe_sha256: Sha256Digest,
        step_plan_sha256: Sha256Digest,
    ) -> Self {
        Self {
            job_id,
            manifest_sha256,
            artifact_binding_sha256,
            config_binding_sha256,
            authenticated_probe_sha256,
            step_plan_sha256,
        }
    }

    pub(in crate::integrations) fn receipt_for(
        &self,
        job: &IntegrationJob,
    ) -> Option<ReadyEvidenceReceipt> {
        let contract = job.evidence_contract.as_ref()?;
        if self.job_id != job.job_id
            || self.manifest_sha256 != job.manifest_sha256
            || self.artifact_binding_sha256 != contract.artifact_binding_sha256
            || self.config_binding_sha256 != contract.config_binding_sha256
            || self.authenticated_probe_sha256 != contract.authenticated_probe_sha256
            || self.step_plan_sha256 != contract.step_plan_sha256
        {
            return None;
        }
        Some(ReadyEvidenceReceipt {
            job_id: self.job_id.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            artifact_binding_sha256: self.artifact_binding_sha256.clone(),
            config_binding_sha256: self.config_binding_sha256.clone(),
            authenticated_probe_sha256: self.authenticated_probe_sha256.clone(),
            step_plan_sha256: self.step_plan_sha256.clone(),
        })
    }
}

/// Adapter-issued proof that the owned process tree stopped and staged side
/// effects were rolled back before an active job becomes durably Cancelled.
/// Wire data cannot construct this token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationEvidence {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
    expected_revision: u64,
    process_tree_receipt_sha256: Sha256Digest,
    rollback_receipt_sha256: Sha256Digest,
}

impl CancellationEvidence {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(
        job_id: JobId,
        manifest_sha256: Sha256Digest,
        step_plan_sha256: Sha256Digest,
        expected_revision: u64,
        process_tree_receipt_sha256: Sha256Digest,
        rollback_receipt_sha256: Sha256Digest,
    ) -> Self {
        Self {
            job_id,
            manifest_sha256,
            step_plan_sha256,
            expected_revision,
            process_tree_receipt_sha256,
            rollback_receipt_sha256,
        }
    }

    pub(in crate::integrations) fn matches(&self, job: &IntegrationJob) -> bool {
        job.evidence_contract.as_ref().is_some_and(|contract| {
            self.job_id == job.job_id
                && self.manifest_sha256 == job.manifest_sha256
                && self.step_plan_sha256 == contract.step_plan_sha256
                && self.expected_revision == job.state_revision
                && job.cancel_requested
                && !self.process_tree_receipt_sha256.as_str().is_empty()
                && !self.rollback_receipt_sha256.as_str().is_empty()
        })
    }
}

/// Adapter-issued restart proof. It is compared with the durable contract and
/// durable progress receipt inside the recovery transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeEvidence {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
    staging_binding_sha256: Sha256Digest,
}

impl ResumeEvidence {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(
        job_id: JobId,
        manifest_sha256: Sha256Digest,
        step_plan_sha256: Sha256Digest,
        staging_binding_sha256: Sha256Digest,
    ) -> Self {
        Self {
            job_id,
            manifest_sha256,
            step_plan_sha256,
            staging_binding_sha256,
        }
    }

    pub(in crate::integrations) fn matches_contract(&self, job: &IntegrationJob) -> bool {
        job.evidence_contract.as_ref().is_some_and(|contract| {
            self.job_id == job.job_id
                && self.manifest_sha256 == job.manifest_sha256
                && self.step_plan_sha256 == contract.step_plan_sha256
        })
    }

    pub(in crate::integrations) fn matches_checkpoint(&self, job: &IntegrationJob) -> bool {
        self.matches_contract(job)
            && job.progress_evidence.as_ref().is_some_and(|receipt| {
                receipt.job_id == job.job_id
                    && receipt.manifest_sha256 == job.manifest_sha256
                    && receipt.step_plan_sha256 == self.step_plan_sha256
                    && receipt.staging_binding_sha256 == self.staging_binding_sha256
                    && receipt.completed_steps == job.progress.completed_steps
                    && receipt.bytes_done == job.progress.bytes_done
            })
    }
}

impl ProgressEvidenceReceipt {
    pub(in crate::integrations) fn checkpoint_step(&self) -> &str {
        &self.current_step
    }

    pub(in crate::integrations) fn rebound_to(&self, job_id: JobId) -> Self {
        let mut rebound = self.clone();
        rebound.job_id = job_id;
        rebound
    }
}

/// Restart-time proof that the pre-crash process tree was either terminated or
/// safely adopted and that staging ownership was reconciled before the active
/// row may release its capability lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryDispositionEvidence {
    job_id: JobId,
    manifest_sha256: Sha256Digest,
    step_plan_sha256: Sha256Digest,
    expected_revision: u64,
    process_disposition_sha256: Sha256Digest,
    staging_disposition_sha256: Sha256Digest,
}

impl RecoveryDispositionEvidence {
    #[cfg(test)]
    pub(in crate::integrations) fn verified(
        job_id: JobId,
        manifest_sha256: Sha256Digest,
        step_plan_sha256: Sha256Digest,
        expected_revision: u64,
        process_disposition_sha256: Sha256Digest,
        staging_disposition_sha256: Sha256Digest,
    ) -> Self {
        Self {
            job_id,
            manifest_sha256,
            step_plan_sha256,
            expected_revision,
            process_disposition_sha256,
            staging_disposition_sha256,
        }
    }

    pub(in crate::integrations) fn matches(&self, job: &IntegrationJob) -> bool {
        job.evidence_contract.as_ref().is_some_and(|contract| {
            self.job_id == job.job_id
                && self.manifest_sha256 == job.manifest_sha256
                && self.step_plan_sha256 == contract.step_plan_sha256
                && self.expected_revision == job.state_revision
                && !self.process_disposition_sha256.as_str().is_empty()
                && !self.staging_disposition_sha256.as_str().is_empty()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    Resume {
        evidence: ResumeEvidence,
        disposition: RecoveryDispositionEvidence,
    },
    Reject {
        failure: JobFailure,
        disposition: RecoveryDispositionEvidence,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationJob {
    pub job_id: JobId,
    pub capability_id: CapabilityId,
    pub operation: JobOperation,
    pub release_version: String,
    pub manifest_sha256: Sha256Digest,
    pub state: JobState,
    pub state_revision: u64,
    pub current_step: Option<String>,
    pub progress: JobProgress,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub updated_at: i64,
    pub terminal_at: Option<i64>,
    pub failure: Option<JobFailure>,
    pub evidence_contract: Option<JobEvidenceContract>,
    pub progress_evidence: Option<ProgressEvidenceReceipt>,
    pub ready_evidence: Option<ReadyEvidenceReceipt>,
    pub retry_of: Option<JobId>,
    pub requested_by: JobRequester,
    pub cancel_requested: bool,
}

impl IntegrationJob {
    pub fn validate(&self) -> Result<(), StateValidationError> {
        self.progress.validate()?;
        validate_release_version(&self.release_version)?;
        if let Some(step) = &self.current_step {
            validate_step(step)?;
        }
        if let Some(receipt) = &self.progress_evidence {
            validate_step(&receipt.current_step)?;
        }
        if matches!(
            self.state,
            JobState::Running | JobState::Validating | JobState::Configuring
        ) && self.current_step.is_none()
        {
            return Err(StateValidationError::InvalidInvariant(
                "active execution state lacks current_step".into(),
            ));
        }
        if matches!(
            self.state,
            JobState::Running | JobState::Validating | JobState::Configuring | JobState::Ready
        ) && self.started_at.is_none()
        {
            return Err(StateValidationError::InvalidInvariant(
                "started execution state lacks started_at".into(),
            ));
        }
        if self.created_at < 0 || self.updated_at < 0 {
            return Err(StateValidationError::InvalidTimestamp);
        }
        if self.started_at.is_some_and(|value| value < 0)
            || self.terminal_at.is_some_and(|value| value < 0)
        {
            return Err(StateValidationError::InvalidTimestamp);
        }
        if self.created_at > self.updated_at
            || self
                .started_at
                .is_some_and(|started| started < self.created_at || started > self.updated_at)
            || self.terminal_at.is_some_and(|terminal| {
                terminal < self.created_at
                    || terminal > self.updated_at
                    || self.started_at.is_some_and(|started| terminal < started)
            })
        {
            return Err(StateValidationError::InvalidTimestampOrder);
        }
        if self.state.is_terminal() != self.terminal_at.is_some() {
            return Err(StateValidationError::InvalidInvariant(
                "terminal state and terminal_at disagree".into(),
            ));
        }
        if self.evidence_contract.is_none()
            && !matches!(self.state, JobState::Failed | JobState::Cancelled)
        {
            return Err(StateValidationError::InvalidInvariant(
                "non-legacy job lacks immutable evidence contract".into(),
            ));
        }
        match &self.progress_evidence {
            Some(receipt)
                if self.evidence_contract.as_ref().is_none_or(|contract| {
                    receipt.job_id != self.job_id
                        || receipt.manifest_sha256 != self.manifest_sha256
                        || receipt.step_plan_sha256 != contract.step_plan_sha256
                        || receipt.completed_steps != self.progress.completed_steps
                        || receipt.bytes_done != self.progress.bytes_done
                }) =>
            {
                return Err(StateValidationError::InvalidInvariant(
                    "progress receipt does not bind the durable job checkpoint".into(),
                ));
            }
            None if (self.progress.completed_steps > 0 || self.progress.bytes_done > 0)
                && !matches!(self.state, JobState::Failed | JobState::Cancelled) =>
            {
                return Err(StateValidationError::InvalidInvariant(
                    "durable progress lacks exact staging and step evidence".into(),
                ));
            }
            _ => {}
        }
        match self.state {
            JobState::Failed if self.failure.is_none() => {
                return Err(StateValidationError::InvalidInvariant(
                    "failed job lacks failure record".into(),
                ));
            }
            JobState::Failed => {
                self.failure.as_ref().expect("checked").validate()?;
            }
            _ if self.failure.is_some() => {
                return Err(StateValidationError::InvalidInvariant(
                    "non-failed job carries failure record".into(),
                ));
            }
            _ => {}
        }
        match self.state {
            JobState::Ready if self.ready_evidence.is_none() => {
                return Err(StateValidationError::InvalidInvariant(
                    "ready job lacks readiness evidence".into(),
                ));
            }
            JobState::Ready => {
                let contract = self.evidence_contract.as_ref().ok_or_else(|| {
                    StateValidationError::InvalidInvariant(
                        "ready job lacks immutable evidence contract".into(),
                    )
                })?;
                if self.ready_evidence.as_ref().is_some_and(|receipt| {
                    receipt.job_id != self.job_id
                        || receipt.manifest_sha256 != self.manifest_sha256
                        || receipt.artifact_binding_sha256 != contract.artifact_binding_sha256
                        || receipt.config_binding_sha256 != contract.config_binding_sha256
                        || receipt.authenticated_probe_sha256 != contract.authenticated_probe_sha256
                        || receipt.step_plan_sha256 != contract.step_plan_sha256
                }) {
                    return Err(StateValidationError::InvalidInvariant(
                        "readiness receipt does not match the durable job contract".into(),
                    ));
                }
                if self.progress.completed_steps != self.progress.total_steps
                    || self
                        .progress
                        .bytes_total
                        .is_some_and(|total| self.progress.bytes_done != total)
                {
                    return Err(StateValidationError::InvalidInvariant(
                        "ready job carries incomplete progress".into(),
                    ));
                }
            }
            _ if self.ready_evidence.is_some() => {
                return Err(StateValidationError::InvalidInvariant(
                    "non-ready job carries readiness evidence".into(),
                ));
            }
            _ => {}
        }
        if self.retry_of.as_ref() == Some(&self.job_id) {
            return Err(StateValidationError::InvalidInvariant(
                "job cannot retry itself".into(),
            ));
        }
        if matches!(self.state, JobState::Ready | JobState::Failed) && self.cancel_requested {
            return Err(StateValidationError::InvalidInvariant(
                "ready/failed job cannot retain a cancellation request".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateValidationError {
    #[error("invalid v7 job id")]
    InvalidJobId,
    #[error("invalid lowercase SHA-256 digest")]
    InvalidSha256,
    #[error("unknown integration job state")]
    UnknownState,
    #[error("unknown integration job operation")]
    UnknownOperation,
    #[error("unknown integration job requester")]
    UnknownRequester,
    #[error("invalid integration job progress: {0}")]
    InvalidProgress(String),
    #[error("invalid integration job failure: {0}")]
    InvalidFailure(String),
    #[error("invalid integration job timestamp")]
    InvalidTimestamp,
    #[error("integration job timestamps are not monotonically ordered")]
    InvalidTimestampOrder,
    #[error("invalid integration job invariant: {0}")]
    InvalidInvariant(String),
    #[error("invalid release version")]
    InvalidReleaseVersion,
    #[error("illegal integration job transition {from} -> {to}")]
    IllegalTransition { from: JobState, to: JobState },
    #[error("{field} contains non-public or unbounded text")]
    InvalidPublicText { field: &'static str },
}

pub fn validate_release_version(value: &str) -> Result<(), StateValidationError> {
    let canonical_semver = semver::Version::parse(value)
        .ok()
        .is_some_and(|version| version.to_string() == value);
    if !canonical_semver
        || value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
        || value.contains('/')
        || value.contains('\\')
        || crate::security::redact::redact_if_secret(value).1
    {
        return Err(StateValidationError::InvalidReleaseVersion);
    }
    Ok(())
}

pub fn validate_step(value: &str) -> Result<(), StateValidationError> {
    if value.is_empty() {
        return Err(StateValidationError::InvalidPublicText {
            field: "current step",
        });
    }
    validate_bounded_public_text(value, MAX_STEP_LEN, "current step")
}

fn validate_machine_code(value: &str) -> Result<(), StateValidationError> {
    if value.is_empty()
        || value.len() > MAX_ERROR_CODE_LEN
        || !value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'_' | b'-' | b'.')
        })
        || crate::security::redact::redact_if_secret(value).1
    {
        return Err(StateValidationError::InvalidFailure(
            "machine code must be bounded lowercase ASCII".into(),
        ));
    }
    Ok(())
}

fn validate_bounded_public_text(
    value: &str,
    max_len: usize,
    field: &'static str,
) -> Result<(), StateValidationError> {
    if value.len() > max_len
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(StateValidationError::InvalidPublicText { field });
    }
    if crate::security::redact::redact_if_secret(value).1 {
        return Err(StateValidationError::InvalidPublicText { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_contract() -> JobEvidenceContract {
        JobEvidenceContract::verified(
            Sha256Digest::parse("b".repeat(64)).unwrap(),
            Sha256Digest::parse("c".repeat(64)).unwrap(),
            Sha256Digest::parse("d".repeat(64)).unwrap(),
            Sha256Digest::parse("e".repeat(64)).unwrap(),
        )
    }

    #[test]
    fn transition_table_is_exhaustive_and_fail_closed() {
        let legal = [
            (JobState::Queued, JobState::Running),
            (JobState::Queued, JobState::Failed),
            (JobState::Queued, JobState::Cancelled),
            (JobState::Running, JobState::Validating),
            (JobState::Running, JobState::Failed),
            (JobState::Running, JobState::Cancelled),
            (JobState::Validating, JobState::Configuring),
            (JobState::Validating, JobState::Failed),
            (JobState::Validating, JobState::Cancelled),
            (JobState::Configuring, JobState::Ready),
            (JobState::Configuring, JobState::Failed),
            (JobState::Configuring, JobState::Cancelled),
        ];
        for from in JobState::ALL {
            for to in JobState::ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    legal.contains(&(from, to)),
                    "unexpected transition verdict for {from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn progress_is_monotonic_and_totals_are_bound() {
        let old = JobProgress {
            completed_steps: 1,
            total_steps: 4,
            bytes_done: 10,
            bytes_total: Some(100),
        };
        let new = JobProgress {
            completed_steps: 2,
            total_steps: 4,
            bytes_done: 50,
            bytes_total: Some(100),
        };
        new.validate_monotonic_from(&old).unwrap();
        let mut invalid = new.clone();
        invalid.bytes_done = 9;
        assert!(invalid.validate_monotonic_from(&old).is_err());
        invalid = new;
        invalid.bytes_total = Some(101);
        assert!(invalid.validate_monotonic_from(&old).is_err());
        assert!(JobProgress::new(0, None).validate().is_err());
    }

    #[test]
    fn hashes_and_redacted_errors_are_strict() {
        Sha256Digest::parse("a".repeat(64)).unwrap();
        assert!(Sha256Digest::parse("A".repeat(64)).is_err());
        assert!(JobFailure::new("checksum_mismatch", "Artifact checksum did not match.").is_ok());
        assert!(JobFailure::new("bad", "API_TOKEN=leaked-value").is_err());
        assert!(JobFailure::new("bad", format!("sk-{}", "C".repeat(32))).is_err());
        assert!(JobFailure::new("bad", format!("Bearer {}", "d".repeat(32))).is_err());
    }

    #[test]
    fn active_step_and_timestamp_order_are_required() {
        assert!(validate_step("").is_err());
        assert!(validate_step("download").is_ok());

        let mut job = IntegrationJob {
            job_id: JobId::new(),
            capability_id: CapabilityId::parse("fixture").unwrap(),
            operation: JobOperation::Install,
            release_version: "1.0.0".into(),
            manifest_sha256: Sha256Digest::parse("a".repeat(64)).unwrap(),
            state: JobState::Queued,
            state_revision: 0,
            current_step: None,
            progress: JobProgress::new(1, None),
            created_at: 100,
            started_at: None,
            updated_at: 100,
            terminal_at: None,
            failure: None,
            evidence_contract: Some(evidence_contract()),
            progress_evidence: None,
            ready_evidence: None,
            retry_of: None,
            requested_by: JobRequester::Daemon,
            cancel_requested: false,
        };
        job.validate().unwrap();
        job.state = JobState::Running;
        assert!(matches!(
            job.validate(),
            Err(StateValidationError::InvalidInvariant(_))
        ));
        job.current_step = Some("download".into());
        assert!(matches!(
            job.validate(),
            Err(StateValidationError::InvalidInvariant(_))
        ));
        job.started_at = Some(101);
        assert_eq!(
            job.validate().unwrap_err(),
            StateValidationError::InvalidTimestampOrder
        );
        job.started_at = Some(100);
        job.updated_at = 99;
        assert_eq!(
            job.validate().unwrap_err(),
            StateValidationError::InvalidTimestampOrder
        );
    }

    #[test]
    fn ready_truth_requires_bound_evidence_and_complete_progress() {
        let manifest = Sha256Digest::parse("a".repeat(64)).unwrap();
        let job_id = JobId::new();
        let contract = evidence_contract();
        let mut job = IntegrationJob {
            job_id: job_id.clone(),
            capability_id: CapabilityId::parse("fixture").unwrap(),
            operation: JobOperation::Install,
            release_version: "1.0.0".into(),
            manifest_sha256: manifest.clone(),
            state: JobState::Ready,
            state_revision: 4,
            current_step: Some("probe".into()),
            progress: JobProgress::new(1, Some(10)),
            created_at: 100,
            started_at: Some(100),
            updated_at: 101,
            terminal_at: Some(101),
            failure: None,
            evidence_contract: Some(contract.clone()),
            progress_evidence: None,
            ready_evidence: Some(ReadyEvidenceReceipt {
                job_id: job_id.clone(),
                manifest_sha256: manifest.clone(),
                artifact_binding_sha256: contract.artifact_binding_sha256.clone(),
                config_binding_sha256: contract.config_binding_sha256.clone(),
                authenticated_probe_sha256: contract.authenticated_probe_sha256.clone(),
                step_plan_sha256: contract.step_plan_sha256.clone(),
            }),
            retry_of: None,
            requested_by: JobRequester::Daemon,
            cancel_requested: false,
        };
        assert!(matches!(
            job.validate(),
            Err(StateValidationError::InvalidInvariant(_))
        ));
        job.progress.completed_steps = 1;
        job.progress.bytes_done = 10;
        job.progress_evidence = Some(ProgressEvidenceReceipt {
            job_id,
            manifest_sha256: manifest,
            step_plan_sha256: contract.step_plan_sha256,
            staging_binding_sha256: Sha256Digest::parse("f".repeat(64)).unwrap(),
            current_step: "probe".into(),
            completed_steps: 1,
            bytes_done: 10,
        });
        job.validate().unwrap();
    }

    #[test]
    fn progress_receipt_validates_checkpoint_step_independently_from_live_phase() {
        let manifest = Sha256Digest::parse("a".repeat(64)).unwrap();
        let job_id = JobId::new();
        let contract = evidence_contract();
        let mut job = IntegrationJob {
            job_id: job_id.clone(),
            capability_id: CapabilityId::parse("fixture").unwrap(),
            operation: JobOperation::Install,
            release_version: "1.0.0".into(),
            manifest_sha256: manifest.clone(),
            state: JobState::Running,
            state_revision: 2,
            current_step: Some("download complete".into()),
            progress: JobProgress {
                completed_steps: 1,
                total_steps: 3,
                bytes_done: 10,
                bytes_total: Some(100),
            },
            created_at: 100,
            started_at: Some(100),
            updated_at: 101,
            terminal_at: None,
            failure: None,
            evidence_contract: Some(contract.clone()),
            progress_evidence: Some(ProgressEvidenceReceipt {
                job_id,
                manifest_sha256: manifest,
                step_plan_sha256: contract.step_plan_sha256,
                staging_binding_sha256: Sha256Digest::parse("f".repeat(64)).unwrap(),
                current_step: String::new(),
                completed_steps: 1,
                bytes_done: 10,
            }),
            ready_evidence: None,
            retry_of: None,
            requested_by: JobRequester::Daemon,
            cancel_requested: false,
        };

        assert!(matches!(
            job.validate(),
            Err(StateValidationError::InvalidPublicText {
                field: "current step"
            })
        ));
        job.progress_evidence.as_mut().unwrap().current_step = "download".into();
        job.validate().unwrap();
    }

    #[test]
    fn ids_and_release_versions_are_canonical() {
        let job_id = JobId::new();
        assert_eq!(JobId::parse(job_id.to_string()).unwrap(), job_id);
        assert!(JobId::parse(job_id.to_string().to_ascii_uppercase()).is_err());
        assert!(JobId::parse(job_id.to_string().replace('-', "")).is_err());
        assert!(JobId::parse(format!("{{{job_id}}}")).is_err());

        assert!(validate_release_version("1.0.0").is_ok());
        assert!(validate_release_version("1.0.0-rc.1").is_ok());
        assert!(validate_release_version("v1.0.0").is_err());
        assert!(validate_release_version("01.0.0").is_err());
        assert!(validate_release_version(&format!("sk-{}", "x".repeat(32))).is_err());
    }

    #[test]
    fn rejected_identifiers_never_echo_untrusted_input() {
        let untrusted = "Bearer super-secret-value";
        let errors = [
            JobId::parse(untrusted).unwrap_err().to_string(),
            Sha256Digest::parse(untrusted).unwrap_err().to_string(),
            validate_release_version(untrusted).unwrap_err().to_string(),
            JobState::from_str(untrusted).unwrap_err().to_string(),
            JobOperation::from_str(untrusted).unwrap_err().to_string(),
            JobRequester::from_str(untrusted).unwrap_err().to_string(),
        ];
        for error in errors {
            assert!(!error.contains(untrusted));
            assert!(!error.contains("super-secret-value"));
        }
    }
}
