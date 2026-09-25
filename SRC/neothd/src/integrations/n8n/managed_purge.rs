//! Confirmed deletion of one receipt-proven retained n8n bootstrap volume.
//!
//! This is deliberately separate from normal uninstall. The caller selects a
//! Ready uninstall job, never a Docker name, and a durable dispatch marker
//! makes an uncertain remove result inspect-only on every later invocation.

use std::{io::Read, path::{Path, PathBuf}};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation, JobRequester,
    JobProgress, JobState, ProgressEvidence, ProgressEvidenceClaim, ReadyEvidence,
    RecoveryDispositionEvidence, RestartDecision, RestartValidator, sha256_parts,
};
use super::managed_runtime::{
    InspectVolumeOutcome, ManagedDockerRunner, ManagedN8nRequest, ObservedVolume,
    RetainedReinstallSource, MANAGED_LABEL_KEY, MANAGED_LABEL_VALUE, N8N_CAPABILITY_ID,
};
use crate::integrations::{catalog::CapabilityId, jobs::EnqueueIntegrationJob, state::JobId};

const CUSTODY_FILE: &str = "n8n-managed-purge.v1.json";
const RECEIPT_FILE_PREFIX: &str = "n8n-purge-";
const STEPS: [&str; 4] = [
    "validate-ready-uninstall-receipt",
    "inspect-retained-bootstrap-volume",
    "dispatch-exact-volume-remove",
    "verify-volume-absence",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PurgePlan {
    pub uninstall_job_id: String,
    pub volume: String,
    pub confirmation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PurgePhase { IntentPersisted, RemoveDispatched, AbsentVerified, Completed }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurgeCustody {
    schema_version: u8,
    phase: PurgePhase,
    purge_job_id: String,
    purge_manifest_sha256: String,
    uninstall_job_id: String,
    uninstall_manifest_sha256: String,
    source_install_job_id: String,
    source_install_manifest_sha256: String,
    volume: String,
    volume_owner_install_job_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurgeCompletionReceipt {
    schema_version: u8,
    purge_job_id: String,
    purge_manifest_sha256: String,
    uninstall_job_id: String,
    volume: String,
    disposition: String,
}

fn custody_path(home: &Path) -> PathBuf { home.join(CUSTODY_FILE) }
fn receipt_path(home: &Path, job: &str) -> PathBuf { home.join(format!("{RECEIPT_FILE_PREFIX}{job}.receipt.json")) }

fn read_custody(home: &Path) -> Result<Option<PurgeCustody>, &'static str> {
    let path = custody_path(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_purge_custody_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 {
        return Err("n8n_purge_custody_invalid");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| "n8n_purge_custody_read_failed")?
        .take(16 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| "n8n_purge_custody_read_failed")?;
    if bytes.len() > 16 * 1024 { return Err("n8n_purge_custody_invalid"); }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| "n8n_purge_custody_invalid")
}
fn remove_custody(home: &Path) -> Result<(), &'static str> {
    let path = custody_path(home);
    if path.exists() {
        crate::util::atomic_write::durable_remove_file(&path)
            .map_err(|_| "n8n_purge_custody_remove_failed")?;
    }
    Ok(())
}

fn write_custody(home: &Path, custody: &PurgeCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home), &serde_json::to_vec(custody).map_err(|_| "n8n_purge_custody_serialize_failed")?,
    ).map_err(|_| "n8n_purge_custody_write_failed")
}
fn create_custody(home: &Path, custody: &PurgeCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home), &serde_json::to_vec(custody).map_err(|_| "n8n_purge_custody_serialize_failed")?,
    ).map_err(|_| "n8n_purge_custody_create_failed")
}
fn write_receipt(home: &Path, custody: &PurgeCustody) -> Result<(), &'static str> {
    let receipt = PurgeCompletionReceipt {
        schema_version: 1, purge_job_id: custody.purge_job_id.clone(),
        purge_manifest_sha256: custody.purge_manifest_sha256.clone(),
        uninstall_job_id: custody.uninstall_job_id.clone(), volume: custody.volume.clone(),
        disposition: "volume_removed".into(),
    };
    crate::util::atomic_write::atomic_write_private(
        &receipt_path(home, &receipt.purge_job_id),
        &serde_json::to_vec(&receipt).map_err(|_| "n8n_purge_receipt_serialize_failed")?,
    ).map_err(|_| "n8n_purge_receipt_write_failed")
}
fn read_receipt(home: &Path, job: &IntegrationJob, custody: &PurgeCustody) -> Result<Option<PurgeCompletionReceipt>, &'static str> {
    let path = receipt_path(home, job.job_id.as_str());
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_purge_receipt_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err("n8n_purge_receipt_invalid");
    }
    let receipt: PurgeCompletionReceipt = serde_json::from_slice(
        &std::fs::read(&path).map_err(|_| "n8n_purge_receipt_read_failed")?,
    ).map_err(|_| "n8n_purge_receipt_invalid")?;
    if receipt.schema_version != 1
        || receipt.purge_job_id != job.job_id.as_str()
        || receipt.purge_manifest_sha256 != job.manifest_sha256.as_str()
        || receipt.uninstall_job_id != custody.uninstall_job_id
        || receipt.volume != custody.volume
        || receipt.disposition != "volume_removed"
    { return Err("n8n_purge_receipt_mismatch"); }
    Ok(Some(receipt))
}

fn source(request: &ManagedN8nRequest) -> Result<&RetainedReinstallSource, &'static str> {
    request.retained_reinstall_source().filter(|source| source.bootstrap_volume)
        .ok_or("n8n_purge_volume_unproven")
}
fn plan_from_request(uninstall_id: &JobId, request: &ManagedN8nRequest) -> Result<PurgePlan, &'static str> {
    let _ = source(request)?;
    let job = uninstall_id.as_str().to_owned();
    let volume = request.volume().to_owned();
    Ok(PurgePlan { confirmation: format!("PURGE N8N VOLUME {job} {volume}"), uninstall_job_id: job, volume })
}

fn purge_manifest(plan: &PurgePlan, source: &RetainedReinstallSource) -> super::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-retained-volume-purge-v1", "PURGE N8N VOLUME", plan.uninstall_job_id.as_str(),
        source.uninstall_manifest_sha256.as_str(), source.source_install_job_id.as_str(),
        source.source_install_manifest_sha256.as_str(), plan.volume.as_str(),
        source.volume_owner_install_job_id.as_str(),
    ])
}

fn purge_contract(plan: &PurgePlan, source: &RetainedReinstallSource) -> JobEvidenceContract {
    let manifest = purge_manifest(plan, source);
    JobEvidenceContract::verified(
        manifest.clone(),
        sha256_parts(&["n8n-purge-volume", plan.volume.as_str(), source.volume_owner_install_job_id.as_str()]),
        sha256_parts(&["n8n-purge-ready-uninstall", plan.uninstall_job_id.as_str(), source.uninstall_manifest_sha256.as_str()]),
        sha256_parts(&STEPS),
    )
}
fn enqueue_purge(service: &IntegrationJobService, plan: &PurgePlan, source: &RetainedReinstallSource) -> Result<IntegrationJob> {
    let manifest = purge_manifest(plan, source);
    let contract = purge_contract(plan, source);
    Ok(service.enqueue(EnqueueIntegrationJob {
        capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static capability"),
        operation: JobOperation::Purge, release_version: "1.4.0".into(), manifest_sha256: manifest,
        evidence_contract: contract, requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32,
        bytes_total: None,
    })?.job)
}

fn validate_observed_volume(request: &ManagedN8nRequest, found: &ObservedVolume) -> Result<(), &'static str> {
    let source = source(request)?;
    if found.name != request.volume()
        || found.labels.get(MANAGED_LABEL_KEY).map(String::as_str) != Some(MANAGED_LABEL_VALUE)
        || found.labels.get("io.neoth.n8n-job").map(String::as_str) != Some(source.volume_owner_install_job_id.as_str())
        || found.labels.get("io.neoth.n8n-bootstrap").map(String::as_str) != Some(super::managed_bootstrap::BOOTSTRAP_SCHEMA)
    { Err("n8n_purge_volume_foreign") } else { Ok(()) }
}
fn validate_custody(custody: &PurgeCustody, job: &IntegrationJob, plan: &PurgePlan, source: &RetainedReinstallSource) -> Result<(), &'static str> {
    if custody.schema_version != 1
        || job.operation != JobOperation::Purge
        || custody.purge_job_id != job.job_id.as_str()
        || custody.purge_manifest_sha256 != job.manifest_sha256.as_str()
        || custody.uninstall_job_id != plan.uninstall_job_id
        || custody.uninstall_manifest_sha256 != source.uninstall_manifest_sha256
        || custody.source_install_job_id != source.source_install_job_id
        || custody.source_install_manifest_sha256 != source.source_install_manifest_sha256
        || custody.volume != plan.volume
        || custody.volume_owner_install_job_id != source.volume_owner_install_job_id
        || (custody.phase != PurgePhase::Completed && job.state == JobState::Ready)
        || (custody.phase == PurgePhase::Completed && job.state.is_terminal() && job.state != JobState::Ready)
        // The inspection checkpoint is durable before the dispatch marker. A
        // crash in that narrow interval is still pre-dispatch and must resume
        // by re-inspecting labels before the first and only remove attempt.
        || (custody.phase == PurgePhase::IntentPersisted && job.progress.completed_steps > 2)
        || (matches!(custody.phase, PurgePhase::RemoveDispatched | PurgePhase::AbsentVerified) && job.progress.completed_steps < 2)
        || (custody.phase == PurgePhase::Completed && job.progress.completed_steps < 3)
    { Err("n8n_purge_custody_mismatch") } else { Ok(()) }
}
fn validate_completed_history(service: &IntegrationJobService, home: &Path, custody: &PurgeCustody) -> Result<(), &'static str> {
    if custody.phase != PurgePhase::Completed { return Err("n8n_purge_custody_mismatch"); }
    let purge_id = JobId::parse(custody.purge_job_id.clone()).map_err(|_| "n8n_purge_custody_mismatch")?;
    let uninstall_id = JobId::parse(custody.uninstall_job_id.clone()).map_err(|_| "n8n_purge_custody_mismatch")?;
    let job = service.get(&purge_id).map_err(|_| "n8n_purge_custody_mismatch")?.ok_or("n8n_purge_custody_mismatch")?;
    let request = super::managed_runtime::managed_uninstall::retained_reinstall_request_in_service(service, home, &uninstall_id)?;
    let plan = plan_from_request(&uninstall_id, &request)?;
    let source = source(&request)?;
    validate_custody(custody, &job, &plan, source)?;
    if job.state != JobState::Ready { return Err("n8n_purge_custody_mismatch"); }
    read_receipt(home, &job, custody)?.ok_or("n8n_purge_receipt_missing")?;
    Ok(())
}

fn checkpoint(service: &IntegrationJobService, job: &IntegrationJob, done: u32, step: &str) -> Result<IntegrationJob> {
    let contract = job.evidence_contract.as_ref().ok_or_else(|| anyhow::anyhow!("n8n_purge_contract_missing"))?;
    let evidence = ProgressEvidence::claimed(ProgressEvidenceClaim {
        job_id: job.job_id.clone(), manifest_sha256: job.manifest_sha256.clone(),
        step_plan_sha256: contract.step_plan_sha256().clone(),
        staging_binding_sha256: sha256_parts(&["n8n-purge-checkpoint", step]),
        expected_revision: job.state_revision, expected_state: job.state, current_phase: step.into(),
        completed_steps: done, bytes_done: 0,
    });
    Ok(service.update_progress(&job.job_id, job.state_revision, job.state, JobProgress {
        completed_steps: done, total_steps: STEPS.len() as u32, bytes_done: 0, bytes_total: None,
    }, Some(step.into()), evidence)?)
}

struct PurgeRestartValidator {
    home: PathBuf,
    plan: PurgePlan,
    source: RetainedReinstallSource,
}
impl RestartValidator for PurgeRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Purge { return super::N8nRestartValidator::new(&self.home).validate(job); }
        if job.manifest_sha256 != purge_manifest(&self.plan, &self.source)
            || job.evidence_contract.as_ref() != Some(&purge_contract(&self.plan, &self.source))
        {
            return RestartDecision::Hold { failure: super::JobFailure::new("n8n_purge_reconciliation_required", "The purge lacks its immutable evidence contract.").expect("static") };
        }
        if let Some(custody) = match read_custody(&self.home) {
            Ok(custody) => custody,
            Err(_) => return RestartDecision::Hold { failure: super::JobFailure::new("n8n_purge_reconciliation_required", "The purge custody is unreadable.").expect("static") },
        } {
            if validate_custody(&custody, job, &self.plan, &self.source).is_err() {
                return RestartDecision::Hold { failure: super::JobFailure::new("n8n_purge_reconciliation_required", "The purge custody does not bind the selected receipt provenance.").expect("static") };
            }
        } else if job.state != JobState::Queued {
            return RestartDecision::Hold { failure: super::JobFailure::new("n8n_purge_reconciliation_required", "An active purge lacks durable dispatch custody.").expect("static") };
        }
        let contract = job.evidence_contract.as_ref().expect("validated above");
        RestartDecision::Resume {
            evidence: super::ResumeEvidence::verified(job.job_id.clone(), job.manifest_sha256.clone(), contract.step_plan_sha256().clone(), sha256_parts(&["n8n-purge-reconcile"])),
            disposition: RecoveryDispositionEvidence::verified(job.job_id.clone(), job.manifest_sha256.clone(), contract.step_plan_sha256().clone(), job.state_revision, sha256_parts(&["n8n-purge-no-remove-on-restart"]), sha256_parts(&["n8n-purge-custody-retained"])),
        }
    }
}
fn open_service(home: &Path, plan: &PurgePlan, source: &RetainedReinstallSource) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(home, super::n8n_catalog(), &PurgeRestartValidator {
        home: home.into(), plan: plan.clone(), source: source.clone(),
    })?)
}
fn validate_locked_preflight(
    service: &IntegrationJobService,
    home: &Path,
    uninstall_id: &JobId,
    plan: &PurgePlan,
    expected_source: &RetainedReinstallSource,
) -> Result<ManagedN8nRequest> {
    if super::managed_runtime::has_runtime_binding(home).map_err(anyhow::Error::msg)? {
        anyhow::bail!("n8n_purge_runtime_active");
    }
    let locked_request = super::managed_runtime::managed_uninstall::retained_reinstall_request_in_service(
        service, home, uninstall_id,
    ).map_err(anyhow::Error::msg)?;
    let locked_plan = plan_from_request(uninstall_id, &locked_request).map_err(anyhow::Error::msg)?;
    let locked_source = source(&locked_request).map_err(anyhow::Error::msg)?;
    if locked_plan != *plan || locked_source != expected_source { anyhow::bail!("n8n_purge_source_changed"); }
    Ok(locked_request)
}

pub(crate) fn prepare_purge_at(home: &Path, uninstall_id: &JobId) -> Result<PurgePlan> {
    if super::managed_runtime::has_runtime_binding(home).map_err(anyhow::Error::msg)? { anyhow::bail!("n8n_purge_runtime_active"); }
    let request = super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
        home, uninstall_id, IntegrationJobService::read_only_snapshot(home)?,
    ).map_err(anyhow::Error::msg)?;
    plan_from_request(uninstall_id, &request).map_err(anyhow::Error::msg)
}

pub(crate) async fn purge_retained_volume_at(home: &Path, uninstall_id: &JobId, confirmation: &str) -> Result<IntegrationJob> {
    purge_retained_volume_at_with(home, uninstall_id, confirmation, &mut super::managed_runtime::DockerManagedRunner).await
}

pub(crate) async fn purge_retained_volume_at_with<R: ManagedDockerRunner>(home: &Path, uninstall_id: &JobId, confirmation: &str, runner: &mut R) -> Result<IntegrationJob> {
    if super::managed_runtime::has_runtime_binding(home).map_err(anyhow::Error::msg)? { anyhow::bail!("n8n_purge_runtime_active"); }
    let request = super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
        home, uninstall_id, IntegrationJobService::read_only_snapshot(home)?,
    ).map_err(anyhow::Error::msg)?;
    let plan = plan_from_request(uninstall_id, &request).map_err(anyhow::Error::msg)?;
    if confirmation != plan.confirmation { anyhow::bail!("n8n_purge_confirmation_mismatch"); }
    let source = source(&request).map_err(anyhow::Error::msg)?;
    let service = open_service(home, &plan, source)?;
    // The pre-lock snapshot was needed to reject a wrong confirmation without
    // touching recovery. Recheck binding and receipt provenance under the
    // owner lease before any custody or Docker effect.
    let request = validate_locked_preflight(&service, home, uninstall_id, &plan, source)?;
    if let Some(previous) = read_custody(home).map_err(anyhow::Error::msg)?
        && previous.uninstall_job_id != plan.uninstall_job_id
    {
        // One custody path is retained for the current generation. Replace it
        // only after proving the older generation's immutable job and receipt.
        validate_completed_history(&service, home, &previous).map_err(anyhow::Error::msg)?;
        remove_custody(home).map_err(anyhow::Error::msg)?;
    }
    let (mut custody, queued) = match read_custody(home).map_err(anyhow::Error::msg)? {
        Some(custody) => {
            let job_id = JobId::parse(custody.purge_job_id.clone()).map_err(|_| anyhow::anyhow!("n8n_purge_custody_mismatch"))?;
            let job = service.get(&job_id)?.ok_or_else(|| anyhow::anyhow!("n8n_purge_custody_mismatch"))?;
            validate_custody(&custody, &job, &plan, source).map_err(anyhow::Error::msg)?;
            if custody.phase == PurgePhase::Completed && job.state == JobState::Ready {
                read_receipt(home, &job, &custody).map_err(anyhow::Error::msg)?
                    .ok_or_else(|| anyhow::anyhow!("n8n_purge_receipt_missing"))?;
                return Ok(job);
            }
            (custody, job)
        }
        None => {
            let queued = enqueue_purge(&service, &plan, source)?;
            let custody = PurgeCustody { schema_version: 1, phase: PurgePhase::IntentPersisted,
                purge_job_id: queued.job_id.as_str().into(), purge_manifest_sha256: queued.manifest_sha256.as_str().into(),
                uninstall_job_id: plan.uninstall_job_id.clone(), uninstall_manifest_sha256: source.uninstall_manifest_sha256.clone(),
                source_install_job_id: source.source_install_job_id.clone(), source_install_manifest_sha256: source.source_install_manifest_sha256.clone(),
                volume: plan.volume.clone(), volume_owner_install_job_id: source.volume_owner_install_job_id.clone() };
            create_custody(home, &custody).map_err(anyhow::Error::msg)?;
            (custody, queued)
        }
    };
    validate_custody(&custody, &queued, &plan, source).map_err(anyhow::Error::msg)?;
    let running = if queued.state == JobState::Queued { service.start(&queued.job_id, queued.state_revision, STEPS[0])? } else { queued };
    let validating = if running.state == JobState::Running { service.begin_validation(&running.job_id, running.state_revision, STEPS[0])? } else { running };
    let mut active = if validating.progress.completed_steps < 1 { checkpoint(&service, &validating, 1, STEPS[0])? } else { validating };
    if custody.phase == PurgePhase::IntentPersisted {
        match runner.inspect_volume(&custody.volume).await.map_err(anyhow::Error::msg)? {
            InspectVolumeOutcome::Found(found) => validate_observed_volume(&request, &found).map_err(anyhow::Error::msg)?,
            InspectVolumeOutcome::Absent => anyhow::bail!("n8n_purge_volume_absent"),
            InspectVolumeOutcome::Unknown => anyhow::bail!("n8n_purge_volume_unknown"),
        }
        active = checkpoint(&service, &active, 2, STEPS[1])?;
        custody.phase = PurgePhase::RemoveDispatched;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
        let _ = runner.remove_volume(&custody.volume).await;
    }
    if custody.phase == PurgePhase::RemoveDispatched {
        match runner.inspect_volume(&custody.volume).await {
            Ok(InspectVolumeOutcome::Absent) => { custody.phase = PurgePhase::AbsentVerified; write_custody(home, &custody).map_err(anyhow::Error::msg)?; }
            _ => anyhow::bail!("n8n_purge_removal_unproven"),
        }
    }
    if custody.phase != PurgePhase::AbsentVerified && custody.phase != PurgePhase::Completed { anyhow::bail!("n8n_purge_custody_mismatch"); }
    if active.state == JobState::Validating { active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[2])?; }
    if active.progress.completed_steps < 3 { active = checkpoint(&service, &active, 3, STEPS[2])?; }
    write_receipt(home, &custody).map_err(anyhow::Error::msg)?;
    custody.phase = PurgePhase::Completed;
    write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    active = checkpoint(&service, &active, 4, STEPS[3])?;
    let contract = active.evidence_contract.as_ref().ok_or_else(|| anyhow::anyhow!("n8n_purge_contract_missing"))?;
    let ready = service.mark_ready(&active.job_id, active.state_revision, ReadyEvidence::verified(
        active.job_id.clone(), active.manifest_sha256.clone(), contract.artifact_binding_sha256().clone(),
        contract.config_binding_sha256().clone(), contract.authenticated_probe_sha256().clone(), contract.step_plan_sha256().clone(),
    ))?;
    Ok(ready)
}

#[cfg(test)]
#[path = "managed_purge_tests.rs"]
mod tests;
