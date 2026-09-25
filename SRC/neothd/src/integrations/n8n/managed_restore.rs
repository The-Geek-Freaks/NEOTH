//! Durable, isolated n8n restore candidate custody.
//! Only the new candidate may change. The archive and live installation are never targets.
use std::{io::Read, path::{Path, PathBuf}};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use super::{
    managed_backup::{completed_verified_archive_at, VerifiedBackupArchive},
    managed_restore_candidate::{restore_volume_name, valid_restore_volume_name,
        InspectRestoreCandidateOutcome, RestoreCandidateContentReceipt, RestoreCandidateSpec},
    sha256_parts, valid_container_id, InspectVolumeOutcome,
    IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation,
    JobRequester, ManagedDockerRunner, N8N_CAPABILITY_ID,
};
use crate::integrations::{
    catalog::CapabilityId,
    jobs::{EnqueueIntegrationJob, RestartValidator},
    state::{JobFailure, JobId, JobProgress, JobState, ProgressEvidence,
        ProgressEvidenceClaim, ReadyEvidence, RecoveryDispositionEvidence,
        RestartDecision, ResumeEvidence},
};

const FILE: &str = "n8n-managed-restore.v1.json";
const STEPS: [&str; 7] = [
    "resolve-ready-backup", "create-derived-volume", "create-stopped-candidate",
    "extract-verified-archive", "start-isolated-candidate", "validate-restored-content",
    "remove-candidate-and-publish-receipt",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent, VolumeDispatched, VolumeObserved, CandidateDispatched, CandidateStopped,
    ExtractDispatched, Extracted, StartDispatched, CandidateRunning, ValidateDispatched,
    Validated, RemoveDispatched, CandidateAbsent, ReceiptPublished, Completed,
    CompensateCandidateDispatched, CompensateCandidateAbsent,
    CompensateVolumeDispatched, CompensateVolumeAbsent,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    schema_version: u8,
    phase: Phase,
    restore_job_id: String,
    restore_manifest_sha256: String,
    backup_job_id: String,
    backup_manifest_sha256: String,
    backup_generation: u64,
    source_pinned_image: String,
    source_archive_sha256: String,
    source_archive_bytes: u64,
    restore_volume: String,
    candidate_id: Option<String>,
    content: Option<RestoreCandidateContentReceipt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceiptView {
    pub schema_version: u8,
    pub restore_job_id: String,
    pub restore_manifest_sha256: String,
    pub backup_job_id: String,
    pub backup_manifest_sha256: String,
    pub backup_generation: u64,
    pub source_pinned_image: String,
    pub source_archive_sha256: String,
    pub source_archive_bytes: u64,
    pub restore_volume: String,
    pub candidate_container_id: String,
    pub candidate_only: bool,
    pub workflow_count: u32,
    pub credential_count: u32,
    pub credential_decryption_proven: bool,
    pub evidence_sha256: String,
}
fn sidecar(home: &Path) -> PathBuf { home.join(FILE) }
fn receipt_path(home: &Path, id: &str) -> PathBuf {
    home.join(format!("n8n-restore-{id}.receipt.json"))
}
fn read_json<T: for<'a> Deserialize<'a>>(
    path: &Path, code: &'static str,
) -> std::result::Result<Option<T>, &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(code),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32768 {
        return Err(code);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| code)?.take(32769)
        .read_to_end(&mut bytes).map_err(|_| code)?;
    if bytes.len() > 32768 { return Err(code); }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| code)
}
fn read(home: &Path) -> std::result::Result<Option<Custody>, &'static str> {
    read_json(&sidecar(home), "n8n_restore_custody_invalid")
}
fn write(home: &Path, custody: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(&sidecar(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_restore_custody_serialize_failed")?)
        .map_err(|_| "n8n_restore_custody_write_failed")
}
fn create(home: &Path, custody: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(&sidecar(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_restore_custody_serialize_failed")?)
        .map_err(|_| "n8n_restore_custody_create_failed")
}
fn retire(home: &Path) -> Result<()> {
    crate::util::atomic_write::durable_remove_file(&sidecar(home))
        .map_err(|_| anyhow::anyhow!("n8n_restore_custody_retire_failed"))
}
fn read_receipt(home: &Path, id: &str) -> std::result::Result<Option<RestoreReceiptView>, &'static str> {
    read_json(&receipt_path(home, id), "n8n_restore_receipt_invalid")
}
fn write_receipt(home: &Path, receipt: &RestoreReceiptView) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &receipt_path(home, &receipt.restore_job_id),
        &serde_json::to_vec(receipt).map_err(|_| "n8n_restore_receipt_serialize_failed")?)
        .map_err(|_| "n8n_restore_receipt_write_failed")
}
pub(crate) fn reject_pending_restore(home: &Path) -> std::result::Result<(), &'static str> {
    if read(home)?.is_some() { Err("n8n_restore_custody_pending") } else { Ok(()) }
}
fn manifest(backup: &VerifiedBackupArchive) -> crate::integrations::state::Sha256Digest {
    let receipt = &backup.receipt;
    sha256_parts(&["n8n-managed-restore-v1", &receipt.backup_job_id,
        &receipt.backup_manifest_sha256, &receipt.generation.to_string(),
        &receipt.source_pinned_image, &receipt.archive_sha256, &receipt.archive_bytes.to_string()])
}
fn contract(value: crate::integrations::state::Sha256Digest, backup: &VerifiedBackupArchive) -> JobEvidenceContract {
    JobEvidenceContract::verified(value,
        sha256_parts(&["n8n-managed-restore-candidate", &backup.receipt.backup_job_id, &backup.receipt.archive_sha256]),
        sha256_parts(&["n8n-managed-restore-content", &backup.receipt.source_pinned_image]),
        sha256_parts(&STEPS))
}
fn new_custody(backup: &VerifiedBackupArchive, job: &IntegrationJob) -> Custody {
    Custody {
        schema_version: 1, phase: Phase::Intent,
        restore_job_id: job.job_id.as_str().into(),
        restore_manifest_sha256: job.manifest_sha256.as_str().into(),
        backup_job_id: backup.receipt.backup_job_id.clone(),
        backup_manifest_sha256: backup.receipt.backup_manifest_sha256.clone(),
        backup_generation: backup.receipt.generation,
        source_pinned_image: backup.receipt.source_pinned_image.clone(),
        source_archive_sha256: backup.receipt.archive_sha256.clone(),
        source_archive_bytes: backup.receipt.archive_bytes,
        restore_volume: restore_volume_name(&job.job_id), candidate_id: None, content: None,
    }
}
fn valid(c: &Custody, job: &IntegrationJob, backup: &VerifiedBackupArchive) -> bool {
    let candidate_required = !matches!(c.phase, Phase::Intent | Phase::VolumeDispatched
        | Phase::VolumeObserved | Phase::CandidateDispatched);
    let content_required = matches!(c.phase, Phase::Validated | Phase::RemoveDispatched
        | Phase::CandidateAbsent | Phase::ReceiptPublished | Phase::Completed);
    c.schema_version == 1 && job.operation == JobOperation::Restore
        && super::is_managed_job(job) && job.progress.total_steps == STEPS.len() as u32
        && job.manifest_sha256 == manifest(backup)
        && job.evidence_contract.as_ref() == Some(&contract(manifest(backup), backup))
        && c.restore_job_id == job.job_id.as_str()
        && c.restore_manifest_sha256 == job.manifest_sha256.as_str()
        && c.backup_job_id == backup.receipt.backup_job_id
        && c.backup_manifest_sha256 == backup.receipt.backup_manifest_sha256
        && c.backup_generation == backup.receipt.generation
        && c.source_pinned_image == backup.receipt.source_pinned_image
        && c.source_archive_sha256 == backup.receipt.archive_sha256
        && c.source_archive_bytes == backup.receipt.archive_bytes
        && valid_restore_volume_name(&c.restore_volume, &job.job_id)
        && c.candidate_id.as_deref().is_none_or(valid_container_id)
        && (!candidate_required || c.candidate_id.is_some())
        && c.content.as_ref().is_none_or(super::managed_restore_content::valid_receipt)
        && (!content_required || c.content.is_some())
}
fn owned_volume(volume: &super::ObservedVolume, c: &Custody) -> bool {
    volume.name == c.restore_volume
        && volume.labels.get(super::MANAGED_LABEL_KEY).map(String::as_str) == Some(super::MANAGED_LABEL_VALUE)
        && volume.labels.get("io.neoth.n8n-restore").map(String::as_str) == Some(c.restore_job_id.as_str())
        && volume.labels.get("io.neoth.n8n-restore-schema").map(String::as_str) == Some("1")
}
fn resolve_backup(home: &Path, id: &str) -> std::result::Result<VerifiedBackupArchive, &'static str> {
    let jobs = IntegrationJobService::read_only_snapshot(home).map_err(|_| "n8n_restore_backup_read_failed")?;
    let job = jobs.iter().find(|job| job.job_id.as_str() == id).ok_or("n8n_restore_backup_missing")?;
    completed_verified_archive_at(home, job)?.ok_or("n8n_restore_backup_not_ready")
}
struct RestoreRestartValidator { home: PathBuf }
impl RestartValidator for RestoreRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Restore {
            return super::super::N8nRestartValidator::new(&self.home).validate(job);
        }
        if let Ok(Some(c)) = read(&self.home)
            && (c.phase != Phase::CandidateDispatched || c.candidate_id.is_some())
            && let Ok(backup) = resolve_backup(&self.home, &c.backup_job_id)
            && valid(&c, job, &backup)
            && let Some(evidence) = job.evidence_contract.as_ref()
        {
            let staging = sha256_parts(&["n8n-restore-observe-only-recovery"]);
            return RestartDecision::Resume {
                evidence: ResumeEvidence::verified(job.job_id.clone(), job.manifest_sha256.clone(),
                    evidence.step_plan_sha256().clone(), staging.clone()),
                disposition: RecoveryDispositionEvidence::verified(job.job_id.clone(),
                    job.manifest_sha256.clone(), evidence.step_plan_sha256().clone(),
                    job.state_revision, sha256_parts(&["n8n-restore-custody-reconcile"]), staging),
            };
        }
        RestartDecision::Hold { failure: JobFailure::new("n8n_restore_reconciliation_required",
            "The interrupted restore requires its exact archive and candidate custody.").expect("static") }
    }
}
fn open(home: &Path) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(home, super::super::n8n_catalog(),
        &RestoreRestartValidator { home: home.to_owned() })?)
}
fn tick(service: &IntegrationJobService, job: &IntegrationJob, completed: u32, step: &str) -> Result<IntegrationJob> {
    if job.progress.completed_steps >= completed { return Ok(job.clone()); }
    let evidence = job.evidence_contract.as_ref().ok_or_else(|| anyhow::anyhow!("n8n_restore_contract_missing"))?;
    Ok(service.update_progress(&job.job_id, job.state_revision, job.state,
        JobProgress { completed_steps: completed, total_steps: STEPS.len() as u32, bytes_done: 0, bytes_total: None },
        Some(step.into()), ProgressEvidence::claimed(ProgressEvidenceClaim {
            job_id: job.job_id.clone(), manifest_sha256: job.manifest_sha256.clone(),
            step_plan_sha256: evidence.step_plan_sha256().clone(),
            staging_binding_sha256: sha256_parts(&["n8n-managed-restore-checkpoint", step]),
            expected_revision: job.state_revision, expected_state: job.state,
            current_phase: step.into(), completed_steps: completed, bytes_done: 0,
        }))?)
}
fn fail(service: &IntegrationJobService, job: &IntegrationJob, code: &'static str) -> Result<IntegrationJob> {
    Ok(service.fail(&job.job_id, job.state_revision, JobFailure::new(code,
        "The isolated managed n8n restore candidate was not retained.").expect("static"))?)
}
fn matches_candidate(found: &super::managed_restore_candidate::ObservedRestoreCandidate, c: &Custody) -> bool {
    c.candidate_id.as_deref() == Some(found.id.as_str()) && found.image == c.source_pinned_image
        && found.restore_job_id == c.restore_job_id && found.volume == c.restore_volume
}
async fn candidate<R: ManagedDockerRunner>(runner: &mut R, c: &Custody, running: bool) -> Result<()> {
    let id = c.candidate_id.as_deref().ok_or_else(|| anyhow::anyhow!("n8n_restore_candidate_missing"))?;
    match runner.inspect_restore_candidate_exact(id).await.map_err(anyhow::Error::msg)? {
        InspectRestoreCandidateOutcome::Found(found) if matches_candidate(&found, c) && found.running == running => Ok(()),
        _ => anyhow::bail!("n8n_restore_candidate_outcome_unknown"),
    }
}
async fn absent<R: ManagedDockerRunner>(runner: &mut R, c: &Custody) -> Result<()> {
    let id = c.candidate_id.as_deref().ok_or_else(|| anyhow::anyhow!("n8n_restore_candidate_missing"))?;
    match runner.inspect_restore_candidate_exact(id).await.map_err(anyhow::Error::msg)? {
        InspectRestoreCandidateOutcome::Absent => Ok(()),
        _ => anyhow::bail!("n8n_restore_candidate_absence_unknown"),
    }
}
fn compensation_phase(phase: Phase) -> bool {
    matches!(phase, Phase::CompensateCandidateDispatched | Phase::CompensateCandidateAbsent
        | Phase::CompensateVolumeDispatched | Phase::CompensateVolumeAbsent)
}
async fn compensate<R: ManagedDockerRunner>(home: &Path, runner: &mut R, c: &mut Custody) -> Result<()> {
    if !compensation_phase(c.phase) {
        let id = c.candidate_id.as_deref().ok_or_else(|| anyhow::anyhow!("n8n_restore_candidate_ownership_unknown"))?;
        match runner.inspect_restore_candidate_exact(id).await.map_err(anyhow::Error::msg)? {
            InspectRestoreCandidateOutcome::Absent => {
                c.phase = Phase::CompensateCandidateAbsent;
                write(home, c).map_err(anyhow::Error::msg)?;
            }
            InspectRestoreCandidateOutcome::Found(found) if matches_candidate(&found, c) => {
                c.phase = Phase::CompensateCandidateDispatched;
                write(home, c).map_err(anyhow::Error::msg)?;
                let _ = runner.remove(&found.id).await;
            }
            _ => anyhow::bail!("n8n_restore_candidate_ownership_unknown"),
        }
    }
    if c.phase == Phase::CompensateCandidateDispatched {
        // A lost removal response is resolved by observation only, never redispatched.
        absent(runner, c).await?;
        c.phase = Phase::CompensateCandidateAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CompensateCandidateAbsent {
        match runner.inspect_volume(&c.restore_volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Absent => {
                c.phase = Phase::CompensateVolumeAbsent;
                write(home, c).map_err(anyhow::Error::msg)?;
            }
            InspectVolumeOutcome::Found(volume) if owned_volume(&volume, c) => {
                c.phase = Phase::CompensateVolumeDispatched;
                write(home, c).map_err(anyhow::Error::msg)?;
                let _ = runner.remove_volume(&c.restore_volume).await;
            }
            _ => anyhow::bail!("n8n_restore_volume_ownership_unknown"),
        }
    }
    if c.phase == Phase::CompensateVolumeDispatched {
        match runner.inspect_volume(&c.restore_volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Absent => {},
            _ => anyhow::bail!("n8n_restore_volume_absence_unknown"),
        }
        c.phase = Phase::CompensateVolumeAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}
fn receipt_from(c: &Custody) -> Result<RestoreReceiptView> {
    let content = c.content.as_ref().ok_or_else(|| anyhow::anyhow!("n8n_restore_content_missing"))?;
    Ok(RestoreReceiptView {
        schema_version: 1, restore_job_id: c.restore_job_id.clone(),
        restore_manifest_sha256: c.restore_manifest_sha256.clone(), backup_job_id: c.backup_job_id.clone(),
        backup_manifest_sha256: c.backup_manifest_sha256.clone(), backup_generation: c.backup_generation,
        source_pinned_image: c.source_pinned_image.clone(), source_archive_sha256: c.source_archive_sha256.clone(),
        source_archive_bytes: c.source_archive_bytes, restore_volume: c.restore_volume.clone(),
        candidate_container_id: c.candidate_id.clone().ok_or_else(|| anyhow::anyhow!("n8n_restore_candidate_missing"))?,
        candidate_only: true, workflow_count: content.workflow_count, credential_count: content.credential_count,
        credential_decryption_proven: content.credential_decryption_proven,
        evidence_sha256: content.evidence_sha256.clone(),
    })
}
pub(crate) async fn restore_managed_at(home: &Path, backup: &JobId) -> Result<IntegrationJob> {
    restore_managed_at_with(home, backup, &mut super::DockerManagedRunner).await
}
pub(in crate::integrations) async fn restore_managed_at_with<R: ManagedDockerRunner>(
    home: &Path, backup: &JobId, runner: &mut R,
) -> Result<IntegrationJob> {
    let _lock = crate::util::locked_file::try_lock_file_once(&super::operation_lock_path(home),
        "n8n managed runtime operation")?.ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    super::managed_backup::reject_pending_backup(home).map_err(anyhow::Error::msg)?;
    if super::managed_repair::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::managed_uninstall::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::super::managed_purge::repair_has_pending_custody(home).map_err(anyhow::Error::msg)? {
        anyhow::bail!("n8n_restore_conflicting_custody");
    }
    let prior = read(home).map_err(anyhow::Error::msg)?;
    if prior.as_ref().is_some_and(|c| c.backup_job_id != backup.as_str()) {
        anyhow::bail!("n8n_restore_requested_backup_mismatch");
    }
    let verified = resolve_backup(home, backup.as_str()).map_err(anyhow::Error::msg)?;
    let service = open(home)?;
    let queued = match &prior {
        Some(c) => {
            let id = JobId::parse(c.restore_job_id.clone()).map_err(anyhow::Error::msg)?;
            service.get(&id)?.ok_or_else(|| anyhow::anyhow!("n8n_restore_job_missing"))?
        }
        None => service.enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static"),
            operation: JobOperation::Restore, release_version: "1.4.0".into(),
            manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified),
            requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None,
        })?.job,
    };
    let mut custody = match prior {
        Some(c) => c,
        None => {
            let c = new_custody(&verified, &queued);
            create(home, &c).map_err(anyhow::Error::msg)?;
            c
        }
    };
    if !valid(&custody, &queued, &verified) { anyhow::bail!("n8n_restore_custody_mismatch"); }
    if queued.state == JobState::Ready {
        let receipt = completed_receipt_at(home, &queued).map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("n8n_restore_receipt_missing"))?;
        if !matches!(custody.phase, Phase::ReceiptPublished | Phase::Completed)
            || receipt_from(&custody)? != receipt { anyhow::bail!("n8n_restore_receipt_mismatch"); }
        retire(home)?;
        return Ok(queued);
    }
    if queued.state == JobState::Failed && custody.phase == Phase::CompensateVolumeAbsent {
        retire(home)?;
        return Ok(queued);
    }
    let mut active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        state if state.is_active() => queued,
        _ => anyhow::bail!("n8n_restore_terminal_custody_mismatch"),
    };
    if active.state == JobState::Running {
        active = service.begin_validation(&active.job_id, active.state_revision, STEPS[0])?;
    }
    if active.state == JobState::Validating {
        active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[0])?;
    }
    active = tick(&service, &active, 1, STEPS[0])?;
    if matches!(custody.phase, Phase::ExtractDispatched | Phase::ValidateDispatched)
        || compensation_phase(custody.phase) {
        compensate(home, runner, &mut custody).await?;
        let failed = fail(&service, &active, "n8n_restore_irreversible_effect_unknown")?;
        retire(home)?;
        return Ok(failed);
    }
    if custody.phase == Phase::Intent {
        match runner.inspect_volume(&custody.restore_volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Absent => {},
            _ => anyhow::bail!("n8n_restore_volume_preexisting_or_unknown"),
        }
        custody.phase = Phase::VolumeDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let _ = runner.create_restore_volume_exact(&active.job_id).await;
    }
    if custody.phase == Phase::VolumeDispatched {
        match runner.inspect_volume(&custody.restore_volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Found(volume) if owned_volume(&volume, &custody) => {},
            _ => anyhow::bail!("n8n_restore_volume_create_outcome_unknown"),
        }
        custody.phase = Phase::VolumeObserved;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        active = tick(&service, &active, 2, STEPS[1])?;
    }
    if custody.phase == Phase::VolumeObserved {
        custody.phase = Phase::CandidateDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let result = runner.create_restore_candidate_exact(RestoreCandidateSpec {
            restore_job_id: &active.job_id, image: &custody.source_pinned_image,
        }).await;
        custody.candidate_id = result.ok().filter(|r| r.command.succeeded).and_then(|r| r.container_id);
        write(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == Phase::CandidateDispatched {
        candidate(runner, &custody, false).await?;
        custody.phase = Phase::CandidateStopped;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        active = tick(&service, &active, 3, STEPS[2])?;
    }
    if custody.phase == Phase::CandidateStopped {
        candidate(runner, &custody, false).await?;
        custody.phase = Phase::ExtractDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let result = runner.extract_private_archive_to_exact_container(&verified.archive_path,
            &custody.source_archive_sha256, custody.source_archive_bytes,
            custody.candidate_id.as_deref().expect("observed")).await;
        if !result.is_ok_and(|r| r.archive_bytes == custody.source_archive_bytes
            && r.archive_sha256 == custody.source_archive_sha256) {
            compensate(home, runner, &mut custody).await?;
            let failed = fail(&service, &active, "n8n_restore_archive_extract_failed")?;
            retire(home)?;
            return Ok(failed);
        }
        candidate(runner, &custody, false).await?;
        custody.phase = Phase::Extracted;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        active = tick(&service, &active, 4, STEPS[3])?;
    }
    if custody.phase == Phase::Extracted {
        candidate(runner, &custody, false).await?;
        custody.phase = Phase::StartDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(custody.candidate_id.as_deref().expect("observed")).await;
    }
    if custody.phase == Phase::StartDispatched {
        candidate(runner, &custody, true).await?;
        custody.phase = Phase::CandidateRunning;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        active = tick(&service, &active, 5, STEPS[4])?;
    }
    if custody.phase == Phase::CandidateRunning {
        candidate(runner, &custody, true).await?;
        custody.phase = Phase::ValidateDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let proof = runner.validate_restore_candidate_content_exact(
            custody.candidate_id.as_deref().expect("observed")).await;
        let proof = match proof {
            Ok(proof) if super::managed_restore_content::valid_receipt(&proof) => proof,
            _ => {
                compensate(home, runner, &mut custody).await?;
                let failed = fail(&service, &active, "n8n_restore_content_validation_failed")?;
                retire(home)?;
                return Ok(failed);
            }
        };
        candidate(runner, &custody, true).await?;
        custody.content = Some(proof);
        custody.phase = Phase::Validated;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        active = tick(&service, &active, 6, STEPS[5])?;
    }
    if custody.phase == Phase::Validated {
        candidate(runner, &custody, true).await?;
        custody.phase = Phase::RemoveDispatched;
        write(home, &custody).map_err(anyhow::Error::msg)?;
        let _ = runner.remove(custody.candidate_id.as_deref().expect("observed")).await;
    }
    if custody.phase == Phase::RemoveDispatched {
        absent(runner, &custody).await?;
        custody.phase = Phase::CandidateAbsent;
        write(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == Phase::CandidateAbsent {
        match runner.inspect_volume(&custody.restore_volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Found(volume) if owned_volume(&volume, &custody) => {},
            _ => anyhow::bail!("n8n_restore_volume_ownership_unknown"),
        }
        let receipt = receipt_from(&custody)?;
        match read_receipt(home, &custody.restore_job_id).map_err(anyhow::Error::msg)? {
            Some(old) if old != receipt => anyhow::bail!("n8n_restore_receipt_mismatch"),
            Some(_) => {},
            None => write_receipt(home, &receipt).map_err(anyhow::Error::msg)?,
        }
        custody.phase = Phase::ReceiptPublished;
        write(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase != Phase::ReceiptPublished { anyhow::bail!("n8n_restore_phase_invalid"); }
    if read_receipt(home, &custody.restore_job_id).map_err(anyhow::Error::msg)? != Some(receipt_from(&custody)?) {
        anyhow::bail!("n8n_restore_receipt_mismatch");
    }
    active = tick(&service, &active, 7, STEPS[6])?;
    let evidence = active.evidence_contract.as_ref().expect("validated contract");
    let done = service.mark_ready(&active.job_id, active.state_revision, ReadyEvidence::verified(
        active.job_id.clone(), active.manifest_sha256.clone(), evidence.artifact_binding_sha256().clone(),
        evidence.config_binding_sha256().clone(), evidence.authenticated_probe_sha256().clone(),
        evidence.step_plan_sha256().clone()))?;
    custody.phase = Phase::Completed;
    write(home, &custody).map_err(anyhow::Error::msg)?;
    retire(home)?;
    Ok(done)
}
pub(crate) fn completed_receipt_at(home: &Path, job: &IntegrationJob)
    -> std::result::Result<Option<RestoreReceiptView>, &'static str> {
    if job.operation != JobOperation::Restore || job.state != JobState::Ready { return Ok(None); }
    let receipt = read_receipt(home, job.job_id.as_str())?.ok_or("n8n_restore_receipt_missing")?;
    let backup = resolve_backup(home, &receipt.backup_job_id)?;
    let custody = Custody {
        schema_version: receipt.schema_version, phase: Phase::Completed,
        restore_job_id: receipt.restore_job_id.clone(), restore_manifest_sha256: receipt.restore_manifest_sha256.clone(),
        backup_job_id: receipt.backup_job_id.clone(), backup_manifest_sha256: receipt.backup_manifest_sha256.clone(),
        backup_generation: receipt.backup_generation, source_pinned_image: receipt.source_pinned_image.clone(),
        source_archive_sha256: receipt.source_archive_sha256.clone(), source_archive_bytes: receipt.source_archive_bytes,
        restore_volume: receipt.restore_volume.clone(), candidate_id: Some(receipt.candidate_container_id.clone()),
        content: Some(RestoreCandidateContentReceipt { workflow_count: receipt.workflow_count,
            credential_count: receipt.credential_count, credential_decryption_proven: receipt.credential_decryption_proven,
            evidence_sha256: receipt.evidence_sha256.clone() }),
    };
    if !receipt.candidate_only || !valid(&custody, job, &backup) { return Err("n8n_restore_receipt_mismatch"); }
    if let Some(active) = read(home)?
        && active.restore_job_id == job.job_id.as_str()
        && (!matches!(active.phase, Phase::ReceiptPublished | Phase::Completed)
            || !valid(&active, job, &backup)
            || receipt_from(&active).map_err(|_| "n8n_restore_receipt_mismatch")? != receipt) {
        return Err("n8n_restore_receipt_mismatch");
    }
    Ok(Some(receipt))
}

#[cfg(test)]
#[path = "managed_restore_tests.rs"]
mod tests;
