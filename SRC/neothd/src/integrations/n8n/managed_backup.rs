//! Exact-ID, stopped-SQLite managed n8n backup custody.
//!
//! A managed backup is deliberately a separate operation from repair or
//! update.  It records every Docker effect before dispatch, streams no archive
//! bytes through the job store, and never replays an interrupted copy.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    InspectOutcome, IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation,
    JobRequester, ManagedDockerRunner, N8N_CAPABILITY_ID, RuntimeBinding, RuntimePhase,
    is_managed_job, read_binding, sha256_parts, validate_binding, validate_existing_identity,
};
use crate::integrations::{
    catalog::CapabilityId,
    jobs::{EnqueueIntegrationJob, RestartValidator},
    state::{
        JobFailure, JobProgress, JobState, ProgressEvidence, ProgressEvidenceClaim, ReadyEvidence,
        RecoveryDispositionEvidence, RestartDecision, ResumeEvidence,
    },
};

const BACKUP_FILE: &str = "n8n-managed-backup.v1.json";
const BACKUP_GENERATION_FILE: &str = "n8n-managed-backup-generation.v1.json";
const BACKUP_DIR: &str = "n8n-backups";
pub(crate) const MAX_N8N_BACKUP_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const STEPS: [&str; 6] = [
    "validate-ready-runtime-binding",
    "stop-exact-runtime",
    "copy-stopped-n8n-volume",
    "restore-original-running-state",
    "publish-backup-receipt",
    "mark-backup-ready",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackupPhase {
    IntentPersisted,
    StopDispatched,
    StoppedObserved,
    CopyDispatched,
    CopyVerified,
    RestartDispatched,
    RestartedObserved,
    FailedRestored,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCustody {
    schema_version: u8,
    phase: BackupPhase,
    backup_job_id: String,
    backup_manifest_sha256: String,
    source_install_job_id: String,
    source_install_manifest_sha256: String,
    generation: u64,
    container_id: String,
    image: String,
    volume: String,
    was_running: bool,
    #[serde(default)]
    restoration_dispatched: bool,
    archive_path: String,
    archive_sha256: Option<String>,
    archive_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupGeneration {
    schema_version: u8,
    generation: u64,
}

/// Content-free projection used by status and the CLI. Archive contents,
/// archive member names, Docker stdout and credentials never enter this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceiptView {
    pub schema_version: u8,
    pub backup_job_id: String,
    pub backup_manifest_sha256: String,
    pub source_install_job_id: String,
    pub source_pinned_image: String,
    pub source_container_id: String,
    pub volume_name: String,
    pub generation: u64,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub original_running_state: bool,
    pub restored_running_state: bool,
}

fn custody_path(home: &Path) -> PathBuf {
    home.join(BACKUP_FILE)
}
fn generation_path(home: &Path) -> PathBuf {
    home.join(BACKUP_GENERATION_FILE)
}
fn backup_dir(home: &Path) -> PathBuf {
    home.join(BACKUP_DIR)
}
fn receipt_path(home: &Path, job_id: &str) -> PathBuf {
    home.join(format!("n8n-backup-{job_id}.receipt.json"))
}

fn archive_path(home: &Path, job_id: &str) -> Result<PathBuf, &'static str> {
    if crate::integrations::state::JobId::parse(job_id.to_owned()).is_err() {
        return Err("n8n_backup_job_id_invalid");
    }
    let dir = backup_dir(home);
    if let Ok(metadata) = std::fs::symlink_metadata(&dir)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err("n8n_backup_directory_invalid");
    }
    Ok(dir.join(format!("{job_id}.tar")))
}

/// The runner accepts only an existing real parent. Create that parent here,
/// where `home` is the already-bound NEOTH state root, and reject links or
/// broad permissions before handing its derived child path to Docker streaming.
fn ensure_private_backup_dir(home: &Path) -> Result<PathBuf, &'static str> {
    let dir = backup_dir(home);
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(windows)]
            crate::wal::win_native::create_private_directory_new(&dir)
                .map_err(|_| "n8n_backup_directory_create_failed")?;
            #[cfg(not(windows))]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(&dir)
                    .map_err(|_| "n8n_backup_directory_create_failed")?;
            }
        }
        Err(_) => return Err("n8n_backup_directory_invalid"),
    }
    let metadata = std::fs::symlink_metadata(&dir).map_err(|_| "n8n_backup_directory_invalid")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("n8n_backup_directory_invalid");
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(&dir)
        .map_err(|_| "n8n_backup_directory_invalid")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err("n8n_backup_directory_invalid");
        }
    }
    Ok(dir)
}

fn read_private_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    invalid: &'static str,
) -> Result<Option<T>, &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32 * 1024 {
        return Err(invalid);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| invalid)?
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid)?;
    if bytes.len() > 32 * 1024 {
        return Err(invalid);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid)
}

fn read_custody(home: &Path) -> Result<Option<BackupCustody>, &'static str> {
    read_private_json(&custody_path(home), "n8n_backup_custody_invalid")
}
fn write_custody(home: &Path, custody: &BackupCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_backup_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_backup_custody_write_failed")
}
fn create_custody(home: &Path, custody: &BackupCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_backup_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_backup_custody_create_failed")
}
fn write_receipt(home: &Path, receipt: &BackupReceiptView) -> Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &receipt_path(home, &receipt.backup_job_id),
        &serde_json::to_vec(receipt).map_err(|_| "n8n_backup_receipt_serialize_failed")?,
    )
    .map_err(|_| "n8n_backup_receipt_write_failed")
}
fn read_receipt(home: &Path, job_id: &str) -> Result<Option<BackupReceiptView>, &'static str> {
    read_private_json(&receipt_path(home, job_id), "n8n_backup_receipt_invalid")
}

fn next_generation(home: &Path) -> Result<u64, &'static str> {
    let prior = match read_private_json::<BackupGeneration>(
        &generation_path(home),
        "n8n_backup_generation_invalid",
    )? {
        Some(value) if value.schema_version == 1 => value.generation,
        Some(_) => return Err("n8n_backup_generation_invalid"),
        None => 0,
    };
    let generation = prior
        .checked_add(1)
        .ok_or("n8n_backup_generation_exhausted")?;
    crate::util::atomic_write::atomic_write_private(
        &generation_path(home),
        &serde_json::to_vec(&BackupGeneration {
            schema_version: 1,
            generation,
        })
        .map_err(|_| "n8n_backup_generation_serialize_failed")?,
    )
    .map_err(|_| "n8n_backup_generation_write_failed")?;
    Ok(generation)
}

fn backup_manifest(
    binding: &RuntimeBinding,
    source: &IntegrationJob,
    generation: u64,
) -> crate::integrations::state::Sha256Digest {
    backup_manifest_scalars(
        source,
        binding.container_id.as_deref().unwrap_or(""),
        binding.image.as_str(),
        binding.volume.as_str(),
        generation,
    )
}
fn backup_manifest_scalars(
    source: &IntegrationJob,
    container_id: &str,
    image: &str,
    volume: &str,
    generation: u64,
) -> crate::integrations::state::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-backup-v1",
        source.job_id.as_str(),
        source.manifest_sha256.as_str(),
        container_id,
        image,
        volume,
        &generation.to_string(),
    ])
}

fn backup_contract(
    source: &IntegrationJob,
    container_id: &str,
    volume: &str,
    manifest: crate::integrations::state::Sha256Digest,
) -> JobEvidenceContract {
    JobEvidenceContract::verified(
        manifest,
        sha256_parts(&[
            "n8n-managed-backup-runtime",
            source.job_id.as_str(),
            container_id,
            volume,
        ]),
        sha256_parts(&["n8n-managed-backup-content-free-receipt"]),
        sha256_parts(&STEPS),
    )
}

fn enqueue_backup(
    service: &IntegrationJobService,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
    generation: u64,
) -> Result<IntegrationJob> {
    validate_binding(binding, source).map_err(anyhow::Error::msg)?;
    let manifest = backup_manifest(binding, source, generation);
    let contract = backup_contract(
        source,
        binding.container_id.as_deref().unwrap_or(""),
        &binding.volume,
        manifest.clone(),
    );
    Ok(service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static"),
            operation: JobOperation::Backup,
            release_version: "1.4.0".into(),
            manifest_sha256: manifest,
            evidence_contract: contract,
            requested_by: JobRequester::Cli,
            total_steps: STEPS.len() as u32,
            bytes_total: None,
        })?
        .job)
}

fn source_ready(
    service: &IntegrationJobService,
    home: &Path,
) -> Result<(RuntimeBinding, IntegrationJob)> {
    let binding = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("no_matching_managed_runtime"))?;
    let source = service
        .snapshot()?
        .into_iter()
        .find(|job| {
            job.job_id.as_str() == binding.job_id
                && job.manifest_sha256.as_str() == binding.manifest_sha256
        })
        .ok_or_else(|| anyhow::anyhow!("no_matching_managed_runtime"))?;
    validate_binding(&binding, &source).map_err(anyhow::Error::msg)?;
    if source.operation != JobOperation::Install
        || source.state != JobState::Ready
        || !is_managed_job(&source)
        || binding.phase != RuntimePhase::Ready
        || binding.container_id.is_none()
    {
        anyhow::bail!("no_matching_managed_runtime");
    }
    Ok((binding, source))
}

fn validate_custody(
    home: &Path,
    c: &BackupCustody,
    job: &IntegrationJob,
    source: &IntegrationJob,
) -> Result<(), &'static str> {
    if c.schema_version != 1
        || c.generation == 0
        || job.operation != JobOperation::Backup
        || c.backup_job_id != job.job_id.as_str()
        || c.backup_manifest_sha256 != job.manifest_sha256.as_str()
        || c.source_install_job_id != source.job_id.as_str()
        || c.source_install_manifest_sha256 != source.manifest_sha256.as_str()
        || !super::valid_container_id(&c.container_id)
        || !super::valid_volume_name(&c.volume)
        || c.image != crate::installers::n8n::N8N_OCI_REFERENCE
        || c.archive_path
            != archive_path(home, &c.backup_job_id)
                .map_err(|_| "n8n_backup_custody_mismatch")?
                .to_string_lossy()
    {
        return Err("n8n_backup_custody_mismatch");
    }
    if source.operation != JobOperation::Install
        || source.state != JobState::Ready
        || !is_managed_job(source)
        || !is_managed_job(job)
        || job.progress.total_steps != STEPS.len() as u32
        || backup_manifest_scalars(source, &c.container_id, &c.image, &c.volume, c.generation)
            != job.manifest_sha256
        || job.evidence_contract.as_ref()
            != Some(&backup_contract(
                source,
                &c.container_id,
                &c.volume,
                job.manifest_sha256.clone(),
            ))
    {
        return Err("n8n_backup_custody_mismatch");
    }
    match c.phase {
        BackupPhase::CopyVerified
        | BackupPhase::RestartDispatched
        | BackupPhase::RestartedObserved
        | BackupPhase::Completed => {
            if c.archive_sha256
                .as_deref()
                .is_none_or(|v| !super::valid_manifest_sha256(v))
                || c.archive_bytes
                    .is_none_or(|bytes| bytes == 0 || bytes > MAX_N8N_BACKUP_ARCHIVE_BYTES)
            {
                return Err("n8n_backup_custody_mismatch");
            }
        }
        _ if c.archive_sha256.is_some() || c.archive_bytes.is_some() => {
            return Err("n8n_backup_custody_mismatch");
        }
        _ => {}
    }
    Ok(())
}

fn checkpoint(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    completed: u32,
    step: &str,
    bytes_done: u64,
) -> Result<IntegrationJob> {
    let contract = job
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_backup_contract_missing"))?;
    Ok(service.update_progress(
        &job.job_id,
        job.state_revision,
        job.state,
        JobProgress {
            completed_steps: completed,
            total_steps: STEPS.len() as u32,
            bytes_done,
            bytes_total: None,
        },
        Some(step.into()),
        ProgressEvidence::claimed(ProgressEvidenceClaim {
            job_id: job.job_id.clone(),
            manifest_sha256: job.manifest_sha256.clone(),
            step_plan_sha256: contract.step_plan_sha256().clone(),
            staging_binding_sha256: sha256_parts(&["n8n-managed-backup-checkpoint", step]),
            expected_revision: job.state_revision,
            expected_state: job.state,
            current_phase: step.into(),
            completed_steps: completed,
            bytes_done,
        }),
    )?)
}

fn verify_exact(
    found: &super::ObservedContainer,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<(), anyhow::Error> {
    let request = validate_binding(binding, source).map_err(anyhow::Error::msg)?;
    validate_existing_identity(found, Some(binding), &request, source).map_err(anyhow::Error::msg)
}

async fn observe_exact<R: ManagedDockerRunner>(
    runner: &mut R,
    c: &BackupCustody,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
    expected_running: bool,
) -> Result<()> {
    let found = match runner
        .inspect_exact(&c.container_id)
        .await
        .map_err(anyhow::Error::msg)?
    {
        InspectOutcome::Found(found) if found.id == c.container_id => found,
        _ => anyhow::bail!("n8n_backup_runtime_state_unknown"),
    };
    verify_exact(&found, binding, source)?;
    if runner
        .running_exact(&c.container_id)
        .await
        .map_err(anyhow::Error::msg)?
        != expected_running
    {
        anyhow::bail!("n8n_backup_runtime_state_unknown");
    }
    Ok(())
}

async fn observe_identity<R: ManagedDockerRunner>(
    runner: &mut R,
    c: &BackupCustody,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<()> {
    let found = match runner
        .inspect_exact(&c.container_id)
        .await
        .map_err(anyhow::Error::msg)?
    {
        InspectOutcome::Found(found) if found.id == c.container_id => found,
        _ => anyhow::bail!("n8n_backup_runtime_state_unknown"),
    };
    verify_exact(&found, binding, source)
}

fn durable_archive_matches(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "n8n_backup_archive_missing")?;
    if expected_bytes == 0
        || expected_bytes > MAX_N8N_BACKUP_ARCHIVE_BYTES
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected_bytes
    {
        return Err("n8n_backup_archive_mismatch");
    }
    let mut reader = std::fs::File::open(path)
        .map_err(|_| "n8n_backup_archive_read_failed")?
        .take(expected_bytes + 1);
    let mut actual_bytes = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| "n8n_backup_archive_read_failed")?;
        if read == 0 {
            break;
        }
        actual_bytes += read as u64;
        digest.update(&buffer[..read]);
    }
    if actual_bytes != expected_bytes || hex::encode(digest.finalize()) != expected_sha256 {
        return Err("n8n_backup_archive_mismatch");
    }
    Ok(())
}

/// A copy is never repeated. This helper is only the controlled restoration
/// path for a source that was known running before this backup acquired it.
async fn restore_running<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
    c: &mut BackupCustody,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<()> {
    if !c.was_running {
        observe_exact(runner, c, binding, source, false).await?;
        c.phase = BackupPhase::RestartedObserved;
        return write_custody(home, c).map_err(anyhow::Error::msg);
    }
    if c.phase != BackupPhase::RestartedObserved {
        c.phase = BackupPhase::RestartDispatched;
        write_custody(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(&c.container_id).await;
    }
    observe_exact(runner, c, binding, source, true).await?;
    c.phase = BackupPhase::RestartedObserved;
    write_custody(home, c).map_err(anyhow::Error::msg)
}

/// Preserve `CopyDispatched` as the irreversible recovery boundary while
/// still putting a source known-running before the copy back under exact-ID
/// control. A later reentry observes only; it never dispatches another copy.
async fn restore_after_copy_unknown<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
    c: &mut BackupCustody,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<()> {
    if !c.was_running {
        return observe_exact(runner, c, binding, source, false).await;
    }
    if !c.restoration_dispatched {
        c.restoration_dispatched = true;
        write_custody(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(&c.container_id).await;
    }
    observe_exact(runner, c, binding, source, true).await
}

fn retire_custody(home: &Path) -> Result<()> {
    crate::util::atomic_write::durable_remove_file(&custody_path(home))
        .map_err(|_| anyhow::anyhow!("n8n_backup_custody_retire_failed"))
}

fn fail_restored(
    service: &IntegrationJobService,
    home: &Path,
    job: &IntegrationJob,
    custody: &mut BackupCustody,
) -> Result<IntegrationJob> {
    custody.phase = BackupPhase::FailedRestored;
    write_custody(home, custody).map_err(anyhow::Error::msg)?;
    let failed = service.fail(&job.job_id, job.state_revision, JobFailure::new(
        "n8n_backup_copy_outcome_unknown",
        "The archive copy was not verified. The original runtime state was restored; no successful backup receipt was published.",
    ).expect("static failure is valid"))?;
    retire_custody(home)?;
    Ok(failed)
}

struct ExplicitBackupRestartValidator {
    home: PathBuf,
}
impl RestartValidator for ExplicitBackupRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Backup {
            return super::super::N8nRestartValidator::new(&self.home).validate(job);
        }
        if let Ok(Some(custody)) = read_custody(&self.home)
            && custody.backup_job_id == job.job_id.as_str()
            && custody.backup_manifest_sha256 == job.manifest_sha256.as_str()
            && (custody.phase != BackupPhase::Completed
                || read_receipt(&self.home, &custody.backup_job_id)
                    .ok()
                    .flatten()
                    .is_some_and(|receipt| {
                        receipt.schema_version == 1
                            && receipt.backup_job_id == custody.backup_job_id
                            && receipt.backup_manifest_sha256 == custody.backup_manifest_sha256
                            && receipt.archive_sha256
                                == custody.archive_sha256.clone().unwrap_or_default()
                            && receipt.archive_bytes == custody.archive_bytes.unwrap_or(0)
                            && durable_archive_matches(
                                &archive_path(&self.home, &custody.backup_job_id)
                                    .unwrap_or_default(),
                                receipt.archive_bytes,
                                &receipt.archive_sha256,
                            )
                            .is_ok()
                    }))
            && let Ok(service) = IntegrationJobService::read_only_snapshot(&self.home)
            && let Some(source) = service.into_iter().find(|candidate| {
                candidate.job_id.as_str() == custody.source_install_job_id
                    && candidate.manifest_sha256.as_str() == custody.source_install_manifest_sha256
            })
            && source.operation == JobOperation::Install
            && source.state == JobState::Ready
            && let Some(binding) = read_binding(&self.home).ok().flatten()
            && binding.container_id.as_deref() == Some(custody.container_id.as_str())
            && binding.image == custody.image
            && binding.volume == custody.volume
            && binding.phase == RuntimePhase::Ready
            && validate_binding(&binding, &source).is_ok()
            && validate_custody(&self.home, &custody, job, &source).is_ok()
            && backup_manifest(&binding, &source, custody.generation) == job.manifest_sha256
            && let Some(contract) = job.evidence_contract.as_ref()
        {
            let staging = sha256_parts(&["n8n-managed-backup-custody-reconcile"]);
            return RestartDecision::Resume {
                evidence: ResumeEvidence::verified(
                    job.job_id.clone(),
                    job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(),
                    staging.clone(),
                ),
                disposition: RecoveryDispositionEvidence::verified(
                    job.job_id.clone(),
                    job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(),
                    job.state_revision,
                    sha256_parts(&["n8n-backup-observe-only-resume"]),
                    staging,
                ),
            };
        }
        RestartDecision::Hold { failure: JobFailure::new("n8n_backup_reconciliation_required", "The interrupted managed backup retains exact copy custody and must not replay an uncertain archive stream.").expect("static") }
    }
}
fn open_backup_service(home: &Path) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(
        home,
        super::super::n8n_catalog(),
        &ExplicitBackupRestartValidator {
            home: home.to_owned(),
        },
    )?)
}

/// Production full SQLite-volume backup. The archive receiver owns a private
/// NEOTH-derived path and returns only hash/length, never payload bytes.
pub(crate) async fn backup_managed_at(home: &Path) -> Result<IntegrationJob> {
    backup_managed_at_with(home, &mut super::DockerManagedRunner).await
}

pub(in crate::integrations) async fn backup_managed_at_with<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
) -> Result<IntegrationJob> {
    let _operation_lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )?
    .ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    if super::managed_repair::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::managed_uninstall::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::super::managed_purge::repair_has_pending_custody(home)
            .map_err(anyhow::Error::msg)?
    {
        anyhow::bail!("n8n_backup_conflicting_custody");
    }
    let service = open_backup_service(home)?;
    let existing = read_custody(home).map_err(anyhow::Error::msg)?;
    let (binding, source) = match existing.as_ref() {
        Some(c) => {
            let source = service
                .snapshot()?
                .into_iter()
                .find(|job| {
                    job.job_id.as_str() == c.source_install_job_id
                        && job.manifest_sha256.as_str() == c.source_install_manifest_sha256
                })
                .ok_or_else(|| anyhow::anyhow!("n8n_backup_source_missing"))?;
            let binding = read_binding(home)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("n8n_backup_binding_missing"))?;
            validate_binding(&binding, &source).map_err(anyhow::Error::msg)?;
            if binding.container_id.as_deref() != Some(c.container_id.as_str())
                || binding.image != c.image
                || binding.volume != c.volume
            {
                anyhow::bail!("n8n_backup_custody_mismatch");
            }
            (binding, source)
        }
        None => source_ready(&service, home)?,
    };
    super::verify_runtime_volume_owner(runner, &binding)
        .await
        .map_err(anyhow::Error::msg)?;
    let generation = match existing.as_ref() {
        Some(custody) => custody.generation,
        None => next_generation(home).map_err(anyhow::Error::msg)?,
    };
    let queued = if let Some(custody) = existing.as_ref() {
        let id = crate::integrations::state::JobId::parse(custody.backup_job_id.clone())
            .map_err(anyhow::Error::msg)?;
        service
            .get(&id)?
            .ok_or_else(|| anyhow::anyhow!("n8n_backup_job_missing"))?
    } else {
        enqueue_backup(&service, &binding, &source, generation)?
    };
    let mut custody = match existing {
        Some(c) => {
            validate_custody(home, &c, &queued, &source).map_err(anyhow::Error::msg)?;
            c
        }
        None => {
            let path = archive_path(home, queued.job_id.as_str()).map_err(anyhow::Error::msg)?;
            // A deterministic collision is known before any source mutation.
            // Publication still uses create-new semantics for the race window.
            if let Err(code) = super::preflight_private_archive_destination(&path) {
                // The job row already exists for its immutable ID; close this
                // pre-effect collision explicitly rather than leaving a
                // queued job without custody. No source effect occurred.
                return Ok(service.fail(&queued.job_id, queued.state_revision,
                    JobFailure::new(code, "The derived managed n8n backup archive path is unavailable before source mutation.").expect("static"))?);
            }
            let c = BackupCustody {
                schema_version: 1,
                phase: BackupPhase::IntentPersisted,
                backup_job_id: queued.job_id.as_str().into(),
                backup_manifest_sha256: queued.manifest_sha256.as_str().into(),
                source_install_job_id: source.job_id.as_str().into(),
                source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
                generation,
                container_id: binding.container_id.clone().expect("validated"),
                image: binding.image.clone(),
                volume: binding.volume.clone(),
                was_running: false,
                restoration_dispatched: false,
                archive_path: path.to_string_lossy().into_owned(),
                archive_sha256: None,
                archive_bytes: None,
            };
            create_custody(home, &c).map_err(anyhow::Error::msg)?;
            c
        }
    };
    // Create and validate the archive parent before the source can be stopped.
    // A local path failure must therefore never strand a known-running n8n.
    let _ = ensure_private_backup_dir(home).map_err(anyhow::Error::msg)?;
    let mut active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        state if state.is_active() => queued,
        JobState::Ready => {
            let _ = completed_receipt_at(home, &queued)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("n8n_backup_receipt_missing"))?;
            if read_custody(home).map_err(anyhow::Error::msg)?.is_some() {
                crate::util::atomic_write::durable_remove_file(&custody_path(home))
                    .map_err(|_| anyhow::anyhow!("n8n_backup_custody_retire_failed"))?;
            }
            return Ok(queued);
        }
        JobState::Failed if custody.phase == BackupPhase::FailedRestored => {
            retire_custody(home)?;
            return Ok(queued);
        }
        _ => anyhow::bail!("n8n_backup_terminal_custody_mismatch"),
    };
    if active.state == JobState::Running {
        active = service.begin_validation(&active.job_id, active.state_revision, STEPS[0])?;
    }
    if active.progress.completed_steps == 0 {
        active = checkpoint(&service, &active, 1, STEPS[0], 0)?;
    }

    if custody.phase == BackupPhase::IntentPersisted
        && let Err(code) = super::preflight_private_archive_destination(
            &archive_path(home, &custody.backup_job_id).map_err(anyhow::Error::msg)?,
        )
    {
        let failed = service.fail(
            &active.job_id,
            active.state_revision,
            JobFailure::new(
                code,
                "The backup archive destination is unavailable before source mutation.",
            )
            .expect("static failure is valid"),
        )?;
        retire_custody(home)?;
        return Ok(failed);
    }
    if custody.phase == BackupPhase::IntentPersisted {
        observe_identity(runner, &custody, &binding, &source).await?;
        custody.was_running = runner
            .running_exact(&custody.container_id)
            .await
            .map_err(anyhow::Error::msg)?;
        if custody.was_running {
            custody.phase = BackupPhase::StopDispatched;
            write_custody(home, &custody).map_err(anyhow::Error::msg)?;
            // The command receipt may be lost after Docker has stopped the
            // exact container. The next observation, not the exit code,
            // determines whether a consistent copy is allowed.
            let _ = runner.stop_exact(&custody.container_id).await;
        } else {
            custody.phase = BackupPhase::StoppedObserved;
            write_custody(home, &custody).map_err(anyhow::Error::msg)?;
        }
    }
    if custody.phase == BackupPhase::StopDispatched {
        observe_exact(runner, &custody, &binding, &source, false)
            .await
            .map_err(|_| anyhow::anyhow!("n8n_backup_stop_outcome_unknown"))?;
        custody.phase = BackupPhase::StoppedObserved;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == BackupPhase::FailedRestored {
        return fail_restored(&service, home, &active, &mut custody);
    }
    if custody.phase == BackupPhase::StoppedObserved {
        if active.state == JobState::Validating {
            active =
                service.begin_configuration(&active.job_id, active.state_revision, STEPS[2])?;
        }
        if active.progress.completed_steps < 2 {
            active = checkpoint(&service, &active, 2, STEPS[1], 0)?;
        }
        custody.phase = BackupPhase::CopyDispatched;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
        let archive = archive_path(home, &custody.backup_job_id).map_err(anyhow::Error::msg)?;
        let result = runner
            .archive_exact_n8n_dir_to_private_file(
                &custody.container_id,
                &archive,
                MAX_N8N_BACKUP_ARCHIVE_BYTES,
            )
            .await;
        let receipt = match result {
            Ok(receipt)
                if super::valid_manifest_sha256(&receipt.archive_sha256)
                    && receipt.archive_bytes > 0
                    && receipt.archive_bytes <= MAX_N8N_BACKUP_ARCHIVE_BYTES
                    && durable_archive_matches(
                        &archive,
                        receipt.archive_bytes,
                        &receipt.archive_sha256,
                    )
                    .is_ok() =>
            {
                receipt
            }
            _ => {
                restore_after_copy_unknown(home, runner, &mut custody, &binding, &source).await?;
                return fail_restored(&service, home, &active, &mut custody);
            }
        };
        custody.archive_sha256 = Some(receipt.archive_sha256);
        custody.archive_bytes = Some(receipt.archive_bytes);
        custody.phase = BackupPhase::CopyVerified;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == BackupPhase::CopyDispatched {
        // A crashed stream may have written any prefix. Restore only the
        // original runtime state, then retain a terminal failed job.
        restore_after_copy_unknown(home, runner, &mut custody, &binding, &source).await?;
        return fail_restored(&service, home, &active, &mut custody);
    }
    if custody.phase == BackupPhase::CopyVerified {
        if active.progress.completed_steps < 3 {
            active = checkpoint(
                &service,
                &active,
                3,
                STEPS[2],
                custody.archive_bytes.unwrap_or(0),
            )?;
        }
        restore_running(home, runner, &mut custody, &binding, &source).await?;
    }
    if custody.phase == BackupPhase::RestartDispatched {
        observe_exact(runner, &custody, &binding, &source, true)
            .await
            .map_err(|_| anyhow::anyhow!("n8n_backup_restore_outcome_unknown"))?;
        custody.phase = BackupPhase::RestartedObserved;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == BackupPhase::RestartedObserved {
        if active.progress.completed_steps < 4 {
            active = checkpoint(
                &service,
                &active,
                4,
                STEPS[3],
                custody.archive_bytes.unwrap_or(0),
            )?;
        }
        let receipt = BackupReceiptView {
            schema_version: 1,
            backup_job_id: custody.backup_job_id.clone(),
            backup_manifest_sha256: custody.backup_manifest_sha256.clone(),
            source_install_job_id: custody.source_install_job_id.clone(),
            source_pinned_image: custody.image.clone(),
            source_container_id: custody.container_id.clone(),
            volume_name: custody.volume.clone(),
            generation: custody.generation,
            archive_sha256: custody
                .archive_sha256
                .clone()
                .ok_or_else(|| anyhow::anyhow!("n8n_backup_receipt_invalid"))?,
            archive_bytes: custody
                .archive_bytes
                .ok_or_else(|| anyhow::anyhow!("n8n_backup_receipt_invalid"))?,
            original_running_state: custody.was_running,
            restored_running_state: custody.was_running,
        };
        if let Some(existing) =
            read_receipt(home, &custody.backup_job_id).map_err(anyhow::Error::msg)?
        {
            if existing != receipt {
                anyhow::bail!("n8n_backup_receipt_mismatch");
            }
        } else {
            write_receipt(home, &receipt).map_err(anyhow::Error::msg)?;
        }
        custody.phase = BackupPhase::Completed;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if active.state == JobState::Validating {
        active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[4])?;
    }
    if active.progress.completed_steps < 5 {
        active = checkpoint(
            &service,
            &active,
            5,
            STEPS[4],
            custody.archive_bytes.unwrap_or(0),
        )?;
    }
    if active.progress.completed_steps < 6 {
        active = checkpoint(
            &service,
            &active,
            6,
            STEPS[5],
            custody.archive_bytes.unwrap_or(0),
        )?;
    }
    let contract = active
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_backup_contract_missing"))?;
    let ready = ReadyEvidence::verified(
        active.job_id.clone(),
        active.manifest_sha256.clone(),
        contract.artifact_binding_sha256().clone(),
        contract.config_binding_sha256().clone(),
        contract.authenticated_probe_sha256().clone(),
        contract.step_plan_sha256().clone(),
    );
    let completed = service.mark_ready(&active.job_id, active.state_revision, ready)?;
    // The per-job receipt/archive are immutable historical evidence. The
    // mutable active-custody sidecar is retired only after Ready, allowing a
    // later independent Backup while an interruption here remains reconcilable.
    crate::util::atomic_write::durable_remove_file(&custody_path(home))
        .map_err(|_| anyhow::anyhow!("n8n_backup_custody_retire_failed"))?;
    Ok(completed)
}

/// Return a receipt only when both immutable Ready job and custody agree.
pub(crate) fn completed_receipt_at(
    home: &Path,
    job: &IntegrationJob,
) -> Result<Option<BackupReceiptView>, &'static str> {
    if job.operation != JobOperation::Backup || job.state != JobState::Ready {
        return Ok(None);
    }
    let receipt = read_receipt(home, job.job_id.as_str())?.ok_or("n8n_backup_receipt_missing")?;
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_backup_source_read_failed")?;
    let source = jobs
        .iter()
        .find(|candidate| candidate.job_id.as_str() == receipt.source_install_job_id)
        .ok_or("n8n_backup_source_missing")?;
    if receipt.schema_version != 1
        || receipt.backup_job_id != job.job_id.as_str()
        || receipt.backup_manifest_sha256 != job.manifest_sha256.as_str()
        || source.operation != JobOperation::Install
        || source.state != JobState::Ready
        || !is_managed_job(source)
        || !super::valid_container_id(&receipt.source_container_id)
        || !super::valid_volume_name(&receipt.volume_name)
        || receipt.source_pinned_image != crate::installers::n8n::N8N_OCI_REFERENCE
        || receipt.generation == 0
        || receipt.archive_bytes > MAX_N8N_BACKUP_ARCHIVE_BYTES
        || receipt.original_running_state != receipt.restored_running_state
        || !super::valid_manifest_sha256(&receipt.archive_sha256)
        || backup_manifest_scalars(
            source,
            &receipt.source_container_id,
            &receipt.source_pinned_image,
            &receipt.volume_name,
            receipt.generation,
        ) != job.manifest_sha256
    {
        return Err("n8n_backup_receipt_mismatch");
    }
    if let Some(custody) = read_custody(home)?
        && custody.backup_job_id == job.job_id.as_str()
        && (custody.phase != BackupPhase::Completed
            || custody.backup_manifest_sha256 != job.manifest_sha256.as_str()
            || receipt.generation != custody.generation
            || receipt.archive_sha256 != custody.archive_sha256.clone().unwrap_or_default()
            || receipt.archive_bytes != custody.archive_bytes.unwrap_or(0)
            || receipt.source_container_id != custody.container_id
            || receipt.volume_name != custody.volume
            || receipt.source_pinned_image != custody.image
            || receipt.original_running_state != custody.was_running
            || receipt.restored_running_state != custody.was_running)
    {
        return Err("n8n_backup_receipt_mismatch");
    }
    durable_archive_matches(
        &archive_path(home, job.job_id.as_str())?,
        receipt.archive_bytes,
        &receipt.archive_sha256,
    )?;
    Ok(Some(receipt))
}

/// Fence all other lifecycle operations. A malformed, sidecar-only or
/// unfinished backup remains a blocker even if its database row disappeared.
pub(crate) fn backup_has_pending_custody(home: &Path) -> Result<bool, &'static str> {
    let Some(custody) = read_custody(home)? else {
        return Ok(false);
    };
    if custody.phase != BackupPhase::Completed {
        return Ok(true);
    }
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_backup_source_read_failed")?;
    let Some(job) = jobs.iter().find(|job| {
        job.job_id.as_str() == custody.backup_job_id
            && job.manifest_sha256.as_str() == custody.backup_manifest_sha256
    }) else {
        return Ok(true);
    };
    if job.operation != JobOperation::Backup || job.state != JobState::Ready {
        return Ok(true);
    }
    Ok(completed_receipt_at(home, job).is_err())
}

/// Narrow public lifecycle fence used by n8n open, repair, uninstall and
/// purge. The caller maps this to its existing typed reconciliation Hold.
pub(crate) fn reject_pending_backup(home: &Path) -> Result<(), &'static str> {
    if backup_has_pending_custody(home)? {
        Err("n8n_backup_custody_pending")
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "managed_backup_tests.rs"]
mod tests;
