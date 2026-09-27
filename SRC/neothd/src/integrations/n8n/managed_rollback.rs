//! Rename-first historical n8n rollback custody.
//!
//! This transaction intentionally retains the displaced container and both
//! volumes.  Every Docker effect is preceded by durable custody, and an
//! interrupted rename/create is reconciliation-only: it is never replayed by
//! container name.

use super::{
    InspectOutcome, IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation,
    JobRequester, ManagedDockerRunner, ManagedN8nRequest, N8N_CAPABILITY_ID,
    RollbackRuntimeLineage, RuntimeBinding, RuntimeLineage, RuntimePhase, is_active_runtime_source,
    read_binding, read_binding_bytes, retired_container_name, sha256_parts, valid_container_id,
    valid_historical_n8n_image, valid_manifest_sha256, write_binding,
};
use crate::{
    integrations::{
        catalog::CapabilityId,
        jobs::{EnqueueIntegrationJob, RestartValidator},
        state::{
            JobFailure, JobId, JobState, RecoveryDispositionEvidence, RestartDecision,
            ResumeEvidence,
        },
    },
    secret::SecretString,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const FILE: &str = "n8n-managed-rollback.v1.json";
const STEPS: [&str; 4] = [
    "validate-loopback-endpoint",
    "authenticated-precommit-probe",
    "publish-config-and-secret",
    "authenticated-postcommit-probe",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    IntentPersisted,
    OldStopDispatched,
    OldStoppedObserved,
    RenameDispatched,
    OldRenamedObserved,
    NewCreateDispatched,
    NewCreatedObserved,
    NewBindingPublished,
    ReceiptPrepared,
    PublishDispatched,
    AdoptionCustodyResolved,
    PublishedReady,
    CompensateNewRemoveDispatched,
    CompensateNewAbsent,
    CompensateRenameBackDispatched,
    CompensateOldLiveObserved,
    CompensateOldStartDispatched,
    CompensateOldRunningObserved,
    Compensated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    schema_version: u8,
    phase: Phase,
    rollback_job_id: String,
    rollback_manifest_sha256: String,
    restore_job_id: String,
    restore_manifest_sha256: String,
    backup_job_id: String,
    backup_manifest_sha256: String,
    image: String,
    restore_volume: String,
    old_container_id: String,
    old_image: String,
    old_volume: String,
    host_port: u16,
    old_was_running: bool,
    retired_name: String,
    original_binding_sha256: String,
    original_binding: Vec<u8>,
    new_container_id: Option<String>,
}

/// Persisted-safe completion projection.  It contains no key, config snapshot,
/// archive payload, Docker output, or credential-sidecar state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackReceiptView {
    pub schema_version: u8,
    pub rollback_job_id: String,
    pub rollback_manifest_sha256: String,
    pub restore_job_id: String,
    pub restore_manifest_sha256: String,
    pub backup_job_id: String,
    pub backup_manifest_sha256: String,
    pub new_container_id: String,
    pub source_pinned_image: String,
    pub host_port: u16,
    pub restore_volume: String,
    pub retained_source_container_id: String,
    pub retained_source_name: String,
    pub evidence_sha256: String,
}

fn custody_path(home: &Path) -> PathBuf {
    home.join(FILE)
}
fn receipt_path(home: &Path, id: &str) -> PathBuf {
    home.join(format!("n8n-rollback-{id}.receipt.json"))
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    code: &'static str,
) -> std::result::Result<Option<T>, &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(code),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
        return Err(code);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| code)?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| code)?;
    if bytes.len() > 65536 {
        return Err(code);
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| code)
}
fn read(home: &Path) -> std::result::Result<Option<Custody>, &'static str> {
    read_json(&custody_path(home), "n8n_rollback_custody_invalid")
}
fn write(home: &Path, value: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home),
        &serde_json::to_vec(value).map_err(|_| "n8n_rollback_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_rollback_custody_write_failed")
}
fn create(home: &Path, value: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home),
        &serde_json::to_vec(value).map_err(|_| "n8n_rollback_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_rollback_custody_create_failed")
}
fn retire(home: &Path) -> Result<()> {
    crate::util::atomic_write::durable_remove_file(&custody_path(home))
        .map_err(|_| anyhow::anyhow!("n8n_rollback_custody_retire_failed"))
}
fn read_receipt(
    home: &Path,
    id: &str,
) -> std::result::Result<Option<RollbackReceiptView>, &'static str> {
    read_json(&receipt_path(home, id), "n8n_rollback_receipt_invalid")
}
fn write_receipt(
    home: &Path,
    value: &RollbackReceiptView,
) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &receipt_path(home, &value.rollback_job_id),
        &serde_json::to_vec(value).map_err(|_| "n8n_rollback_receipt_serialize_failed")?,
    )
    .map_err(|_| "n8n_rollback_receipt_write_failed")
}

pub(crate) fn reject_pending_rollback(home: &Path) -> std::result::Result<(), &'static str> {
    if read(home)?.is_some() {
        Err("n8n_rollback_custody_pending")
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn manifest(
    restore: &super::managed_restore::RestoreReceiptView,
    old: &RuntimeBinding,
) -> crate::integrations::state::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-rollback-v1",
        &restore.restore_job_id,
        &restore.restore_manifest_sha256,
        &restore.backup_job_id,
        &restore.backup_manifest_sha256,
        &restore.source_pinned_image,
        old.container_id.as_deref().unwrap_or(""),
        &old.image,
        &old.volume,
        &old.host_port.to_string(),
    ])
}
fn contract(
    manifest: crate::integrations::state::Sha256Digest,
    restore: &super::managed_restore::RestoreReceiptView,
    endpoint: &crate::config::LoopbackHttpEndpoint,
) -> JobEvidenceContract {
    JobEvidenceContract::verified(
        manifest,
        sha256_parts(&[
            "n8n-managed-rollback-runtime",
            &restore.restore_job_id,
            &restore.restore_volume,
        ]),
        super::super::expected_authenticated_probe_sha256(endpoint),
        sha256_parts(&STEPS),
    )
}

fn resolve_restore(
    home: &Path,
    id: &JobId,
) -> std::result::Result<(IntegrationJob, super::managed_restore::RestoreReceiptView), &'static str>
{
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_rollback_restore_read_failed")?;
    let job = jobs
        .into_iter()
        .find(|candidate| candidate.job_id == *id)
        .ok_or("n8n_rollback_restore_missing")?;
    let receipt = super::managed_restore::completed_receipt_at(home, &job)?
        .ok_or("n8n_rollback_restore_not_ready")?;
    Ok((job, receipt))
}
fn verify_chain(
    home: &Path,
    restore_id: &JobId,
) -> std::result::Result<(IntegrationJob, super::managed_restore::RestoreReceiptView), &'static str>
{
    let (restore_job, restore) = resolve_restore(home, restore_id)?;
    if restore.restore_job_id != restore_job.job_id.as_str()
        || restore.restore_manifest_sha256 != restore_job.manifest_sha256.as_str()
        || !restore.candidate_only
        || !valid_historical_n8n_image(&restore.source_pinned_image)
    {
        return Err("n8n_rollback_restore_receipt_mismatch");
    }
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_rollback_backup_read_failed")?;
    let backup = jobs
        .iter()
        .find(|candidate| candidate.job_id.as_str() == restore.backup_job_id)
        .ok_or("n8n_rollback_backup_missing")?;
    let verified = super::managed_backup::completed_receipt_at(home, backup)?
        .ok_or("n8n_rollback_backup_not_ready")?;
    if verified.backup_manifest_sha256 != restore.backup_manifest_sha256
        || verified.source_pinned_image != restore.source_pinned_image
    {
        return Err("n8n_rollback_backup_receipt_mismatch");
    }
    Ok((restore_job, restore))
}

fn active_source(home: &Path) -> Result<(RuntimeBinding, IntegrationJob, Vec<u8>)> {
    let binding = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("n8n_rollback_runtime_missing"))?;
    let raw = read_binding_bytes(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("n8n_rollback_binding_bytes_missing"))?;
    let source = IntegrationJobService::read_only_snapshot(home)?
        .into_iter()
        .find(|job| {
            job.job_id.as_str() == binding.job_id
                && job.manifest_sha256.as_str() == binding.manifest_sha256
        })
        .ok_or_else(|| anyhow::anyhow!("n8n_rollback_runtime_source_missing"))?;
    if !is_active_runtime_source(home, &binding, &source) || binding.container_id.is_none() {
        anyhow::bail!("n8n_rollback_runtime_not_ready");
    }
    Ok((binding, source, raw))
}

struct RollbackRestartValidator {
    home: PathBuf,
}
impl RestartValidator for RollbackRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Rollback {
            return super::super::N8nRestartValidator::new(&self.home).validate(job);
        }
        let resume = read(&self.home).ok().flatten().is_some_and(|c| {
            c.rollback_job_id == job.job_id.as_str()
                && !matches!(
                    c.phase,
                    Phase::RenameDispatched
                        | Phase::NewCreateDispatched
                        | Phase::PublishDispatched
                        | Phase::CompensateNewRemoveDispatched
                        | Phase::CompensateRenameBackDispatched
                        | Phase::CompensateOldStartDispatched
                )
        });
        if resume && let Some(contract) = job.evidence_contract.as_ref() {
            let staging = sha256_parts(&["n8n-rollback-observe-only-recovery"]);
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
                    sha256_parts(&["n8n-rollback-custody-reconcile"]),
                    staging,
                ),
            };
        }
        RestartDecision::Hold { failure: JobFailure::new("n8n_rollback_reconciliation_required", "The interrupted historical rollback retains exact container and credential custody.").expect("static") }
    }
}
fn open(home: &Path) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(
        home,
        super::super::n8n_catalog(),
        &RollbackRestartValidator {
            home: home.to_owned(),
        },
    )?)
}
fn observed_exact(found: InspectOutcome, id: &str) -> Result<super::ObservedContainer> {
    match found {
        InspectOutcome::Found(found) if found.id == id => Ok(found),
        _ => anyhow::bail!("n8n_rollback_exact_identity_unknown"),
    }
}
fn receipt_evidence(c: &Custody, new_id: &str) -> crate::integrations::state::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-rollback-receipt-v1",
        &c.rollback_job_id,
        &c.restore_job_id,
        &c.restore_manifest_sha256,
        &c.backup_job_id,
        &c.backup_manifest_sha256,
        new_id,
        &c.image,
        &c.host_port.to_string(),
        &c.restore_volume,
        &c.old_container_id,
        &c.retired_name,
    ])
}
fn receipt_from(c: &Custody) -> Result<RollbackReceiptView> {
    let new_id = c
        .new_container_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("n8n_rollback_new_id_missing"))?;
    let evidence = receipt_evidence(c, &new_id);
    Ok(RollbackReceiptView {
        schema_version: 1,
        rollback_job_id: c.rollback_job_id.clone(),
        rollback_manifest_sha256: c.rollback_manifest_sha256.clone(),
        restore_job_id: c.restore_job_id.clone(),
        restore_manifest_sha256: c.restore_manifest_sha256.clone(),
        backup_job_id: c.backup_job_id.clone(),
        backup_manifest_sha256: c.backup_manifest_sha256.clone(),
        new_container_id: new_id,
        source_pinned_image: c.image.clone(),
        host_port: c.host_port,
        restore_volume: c.restore_volume.clone(),
        retained_source_container_id: c.old_container_id.clone(),
        retained_source_name: c.retired_name.clone(),
        evidence_sha256: evidence.as_str().into(),
    })
}

fn new_binding(c: &Custody) -> Result<RuntimeBinding> {
    Ok(RuntimeBinding {
        schema_version: 3,
        phase: RuntimePhase::Ready,
        job_id: c.rollback_job_id.clone(),
        manifest_sha256: c.rollback_manifest_sha256.clone(),
        container_name: super::MANAGED_CONTAINER_NAME.into(),
        container_id: Some(
            c.new_container_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("n8n_rollback_new_id_missing"))?,
        ),
        image: c.image.clone(),
        host_port: c.host_port,
        volume: c.restore_volume.clone(),
        retained_reinstall: None,
        bootstrap_volume_owner_job_id: None,
        lineage: RuntimeLineage::Rollback(RollbackRuntimeLineage {
            restore_job_id: c.restore_job_id.clone(),
            backup_job_id: c.backup_job_id.clone(),
            restore_volume_owner_job_id: c.restore_job_id.clone(),
            retained_source_container_id: c.old_container_id.clone(),
            retained_source_name: c.retired_name.clone(),
        }),
    })
}

/// Rollback current managed runtime onto a previously verified isolated Restore volume.
/// `api_key` is caller-owned stdin material and is never serialized by this module.
pub(crate) async fn rollback_managed_at(
    home: &Path,
    restore: &JobId,
    api_key: SecretString,
) -> Result<IntegrationJob> {
    rollback_managed_at_with_readiness(
        home,
        restore,
        api_key,
        &mut super::DockerManagedRunner,
        &super::HttpN8nApiProbe,
        &super::ProductionReadiness,
    )
    .await
}
#[cfg(test)]
pub(in crate::integrations) async fn rollback_managed_at_with<
    R: ManagedDockerRunner,
    P: super::N8nApiProbe + ?Sized,
>(
    home: &Path,
    restore_id: &JobId,
    api_key: SecretString,
    runner: &mut R,
    probe: &P,
) -> Result<IntegrationJob> {
    rollback_managed_at_with_readiness(home, restore_id, api_key, runner, probe, &TestReadiness)
        .await
}
#[cfg(test)]
struct TestReadiness;
#[cfg(test)]
#[async_trait::async_trait]
impl super::ManagedReadiness for TestReadiness {
    async fn health(&self, _: u16) -> bool {
        true
    }
}
pub(in crate::integrations) async fn rollback_managed_at_with_readiness<
    R: ManagedDockerRunner,
    P: super::N8nApiProbe + ?Sized,
    H: super::ManagedReadiness,
>(
    home: &Path,
    restore_id: &JobId,
    api_key: SecretString,
    runner: &mut R,
    probe: &P,
    readiness: &H,
) -> Result<IntegrationJob> {
    let _lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )?
    .ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    super::managed_backup::reject_pending_backup(home).map_err(anyhow::Error::msg)?;
    super::managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    if super::managed_repair::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::managed_uninstall::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::super::managed_purge::repair_has_pending_custody(home)
            .map_err(anyhow::Error::msg)?
    {
        anyhow::bail!("n8n_rollback_conflicting_custody");
    }
    let prior = read(home).map_err(anyhow::Error::msg)?;
    if prior
        .as_ref()
        .is_some_and(|c| c.restore_job_id != restore_id.as_str())
    {
        anyhow::bail!("n8n_rollback_requested_restore_mismatch");
    }
    let (_, restore) = verify_chain(home, restore_id).map_err(anyhow::Error::msg)?;
    let service = open(home)?;
    // Once the new v3 binding has been published, the old Install binding is
    // deliberately no longer active.  Re-entry must therefore use immutable
    // rollback custody, not demand that the displaced generation remains the
    // current binding.
    let original = if prior.is_none() {
        Some(active_source(home)?)
    } else {
        None
    };
    // A completed historical rollback already owns the requested Restore
    // volume. Repeating that exact request is a read-only idempotent result,
    // not a second cutover from that volume onto itself. `active_source`
    // proves the live binding still belongs to this exact Ready job, and the
    // completed receipt resolves and verifies the Restore/Backup chain.
    if let Some((_, source_job, _)) = original.as_ref()
        && source_job.operation == JobOperation::Rollback
        && source_job.state == JobState::Ready
        && let Some(receipt) = completed_receipt_at(home, source_job).map_err(anyhow::Error::msg)?
        && receipt.restore_job_id == restore.restore_job_id
        && receipt.restore_manifest_sha256 == restore.restore_manifest_sha256
        && receipt.backup_job_id == restore.backup_job_id
        && receipt.backup_manifest_sha256 == restore.backup_manifest_sha256
        && receipt.source_pinned_image == restore.source_pinned_image
        && receipt.restore_volume == restore.restore_volume
    {
        return Ok(source_job.clone());
    }
    let queued = if let Some(c) = prior.as_ref() {
        service
            .get(&JobId::parse(c.rollback_job_id.clone()).map_err(anyhow::Error::msg)?)?
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_job_missing"))?
    } else {
        let source = &original.as_ref().expect("new rollback has active source").0;
        let endpoint = crate::config::LoopbackHttpEndpoint::parse(format!(
            "http://127.0.0.1:{}",
            source.host_port
        ))
        .map_err(anyhow::Error::msg)?;
        let value = manifest(&restore, source);
        service
            .enqueue(EnqueueIntegrationJob {
                capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static"),
                operation: JobOperation::Rollback,
                release_version: "1.4.0".into(),
                manifest_sha256: value.clone(),
                evidence_contract: contract(value, &restore, &endpoint),
                requested_by: JobRequester::Cli,
                total_steps: STEPS.len() as u32,
                bytes_total: None,
            })?
            .job
    };
    let mut c = match prior {
        Some(value) => value,
        None => {
            let (old, _source, raw) = original.expect("new rollback has active source");
            let old_id = old.container_id.clone().expect("active source has id");
            let retired_name =
                retired_container_name(queued.job_id.as_str()).map_err(anyhow::Error::msg)?;
            let value = Custody {
                schema_version: 1,
                phase: Phase::IntentPersisted,
                rollback_job_id: queued.job_id.as_str().into(),
                rollback_manifest_sha256: queued.manifest_sha256.as_str().into(),
                restore_job_id: restore.restore_job_id.clone(),
                restore_manifest_sha256: restore.restore_manifest_sha256.clone(),
                backup_job_id: restore.backup_job_id.clone(),
                backup_manifest_sha256: restore.backup_manifest_sha256.clone(),
                image: restore.source_pinned_image.clone(),
                restore_volume: restore.restore_volume.clone(),
                old_container_id: old_id.clone(),
                old_image: old.image.clone(),
                old_volume: old.volume.clone(),
                host_port: old.host_port,
                old_was_running: false,
                retired_name,
                original_binding_sha256: sha256(&raw),
                original_binding: raw,
                new_container_id: None,
            };
            create(home, &value).map_err(anyhow::Error::msg)?;
            value
        }
    };
    let original_binding: RuntimeBinding = serde_json::from_slice(&c.original_binding)
        .map_err(|_| anyhow::anyhow!("n8n_rollback_custody_mismatch"))?;
    if c.schema_version != 1
        || c.rollback_job_id != queued.job_id.as_str()
        || c.rollback_manifest_sha256 != queued.manifest_sha256.as_str()
        || c.restore_job_id != restore.restore_job_id
        || c.restore_manifest_sha256 != restore.restore_manifest_sha256
        || c.backup_job_id != restore.backup_job_id
        || c.backup_manifest_sha256 != restore.backup_manifest_sha256
        || c.image != restore.source_pinned_image
        || c.restore_volume != restore.restore_volume
        || c.old_volume == c.restore_volume
        || !valid_container_id(&c.old_container_id)
        || !valid_historical_n8n_image(&c.image)
        || c.original_binding_sha256 != sha256(&c.original_binding)
        || c.retired_name
            != retired_container_name(&c.rollback_job_id).map_err(anyhow::Error::msg)?
        || c.old_container_id != original_binding.container_id.as_deref().unwrap_or("")
        || c.old_image != original_binding.image
        || c.old_volume != original_binding.volume
        || c.host_port != original_binding.host_port
        || manifest(&restore, &original_binding) != queued.manifest_sha256
    {
        anyhow::bail!("n8n_rollback_custody_mismatch");
    }
    if queued.state == JobState::Ready {
        let receipt = completed_receipt_at(home, &queued)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_receipt_missing"))?;
        if receipt != receipt_from(&c)? {
            anyhow::bail!("n8n_rollback_receipt_mismatch");
        }
        retire(home)?;
        return Ok(queued);
    }
    if queued.state == JobState::Failed && c.phase == Phase::Compensated {
        validate_compensated(home, runner, &c, probe, readiness).await?;
        retire(home)?;
        return Ok(queued);
    }
    let active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        state if state.is_active() => queued,
        _ => anyhow::bail!("n8n_rollback_terminal_custody_mismatch"),
    };
    // Compensation starts only after the publisher's private custody resolver
    // has succeeded and the first compensation phase is durably recorded.
    // On restart this continues by observation; dispatched effects are never
    // sent a second time.
    if matches!(
        c.phase,
        Phase::AdoptionCustodyResolved
            | Phase::CompensateNewRemoveDispatched
            | Phase::CompensateNewAbsent
            | Phase::CompensateRenameBackDispatched
            | Phase::CompensateOldLiveObserved
            | Phase::CompensateOldStartDispatched
            | Phase::CompensateOldRunningObserved
            | Phase::Compensated
    ) {
        compensate(home, runner, &mut c, probe, readiness).await?;
        let current = service
            .get(&active.job_id)?
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_job_missing"))?;
        let failed = service.fail(
            &current.job_id,
            current.state_revision,
            JobFailure::new(
                "n8n_rollback_compensated",
                "Historical rollback was compensated to the exact retained runtime.",
            )
            .expect("static"),
        )?;
        retire(home)?;
        return Ok(failed);
    }
    // Dispatch ambiguity is never retried.  The caller must inspect and repair
    // the precise retained containers after a Hold.
    if c.phase == Phase::IntentPersisted {
        let found = observed_exact(
            runner
                .inspect_exact_named(&c.old_container_id, super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            &c.old_container_id,
        )?;
        if found.job != original_binding.job_id
            || found.image != c.old_image
            || found.volume != c.old_volume
            || found.host_port != c.host_port
            || found.host_ip != "127.0.0.1"
            || found.managed != super::MANAGED_LABEL_VALUE
            || found.mount_destination != "/home/node/.n8n"
        {
            anyhow::bail!("n8n_rollback_old_runtime_mismatch");
        }
        if !matches!(
            runner
                .inspect_name(&c.retired_name)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) {
            anyhow::bail!("n8n_rollback_retired_name_not_absent");
        }
        c.old_was_running = runner
            .running_exact(&c.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?;
        if c.old_was_running {
            c.phase = Phase::OldStopDispatched;
            write(home, &c).map_err(anyhow::Error::msg)?;
            let _ = runner.stop_exact(&c.old_container_id).await;
        } else {
            c.phase = Phase::OldStoppedObserved;
            write(home, &c).map_err(anyhow::Error::msg)?;
        }
    }
    if c.phase == Phase::OldStopDispatched {
        if runner
            .running_exact(&c.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_rollback_stop_outcome_unknown");
        }
        c.phase = Phase::OldStoppedObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::OldStoppedObserved {
        observed_exact(
            runner
                .inspect_exact_named(&c.old_container_id, super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            &c.old_container_id,
        )?;
        c.phase = Phase::RenameDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner
            .rename_exact(&c.old_container_id, &c.retired_name)
            .await;
    }
    if c.phase == Phase::RenameDispatched {
        observed_exact(
            runner
                .inspect_exact_named(&c.old_container_id, &c.retired_name)
                .await
                .map_err(anyhow::Error::msg)?,
            &c.old_container_id,
        )?;
        if !matches!(
            runner
                .inspect_name(super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) {
            anyhow::bail!("n8n_rollback_live_name_not_absent");
        }
        c.phase = Phase::OldRenamedObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::OldRenamedObserved {
        let request = ManagedN8nRequest::historical_rollback(
            c.host_port,
            c.image.clone(),
            c.restore_volume.clone(),
        )
        .map_err(anyhow::Error::msg)?;
        if !matches!(
            runner
                .inspect_name(super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) {
            anyhow::bail!("n8n_rollback_live_name_not_absent");
        }
        match runner
            .inspect_volume(&c.restore_volume)
            .await
            .map_err(anyhow::Error::msg)?
        {
            super::InspectVolumeOutcome::Found(volume)
                if volume.name == c.restore_volume
                    && volume
                        .labels
                        .get(super::MANAGED_LABEL_KEY)
                        .map(String::as_str)
                        == Some(super::MANAGED_LABEL_VALUE)
                    && volume
                        .labels
                        .get("io.neoth.n8n-restore")
                        .map(String::as_str)
                        == Some(c.restore_job_id.as_str())
                    && volume
                        .labels
                        .get("io.neoth.n8n-restore-schema")
                        .map(String::as_str)
                        == Some("1") => {}
            _ => anyhow::bail!("n8n_rollback_restore_volume_owner_mismatch"),
        }
        c.phase = Phase::NewCreateDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let created = runner
            .create_with_exact_id(&request.create_command(active.job_id.as_str()))
            .await;
        let Some(new_id) = created
            .ok()
            .filter(|value| value.command.succeeded)
            .and_then(|value| value.container_id)
            .filter(|id| valid_container_id(id))
        else {
            anyhow::bail!("n8n_rollback_reconciliation_required");
        };
        c.new_container_id = Some(new_id);
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::NewCreateDispatched {
        let id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_reconciliation_required"))?;
        let found = observed_exact(
            runner
                .inspect_exact_named(id, super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            id,
        )?;
        if found.job != c.rollback_job_id
            || found.image != c.image
            || found.volume != c.restore_volume
            || found.host_ip != "127.0.0.1"
            || found.host_port != c.host_port
            || found.managed != super::MANAGED_LABEL_VALUE
            || found.mount_destination != "/home/node/.n8n"
        {
            anyhow::bail!("n8n_rollback_new_runtime_mismatch");
        }
        c.phase = Phase::NewCreatedObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::NewCreatedObserved {
        let binding = new_binding(&c)?;
        write_binding(home, &binding).map_err(anyhow::Error::msg)?;
        c.phase = Phase::NewBindingPublished;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::NewBindingPublished {
        let new_id = c.new_container_id.as_deref().expect("observed new id");
        if !wait_ready(runner, readiness, new_id, c.host_port).await {
            compensate(home, runner, &mut c, probe, readiness).await?;
            let failed = service.fail(&active.job_id, active.state_revision, JobFailure::new("n8n_rollback_new_runtime_not_ready", "The historical runtime did not become ready before configuration publication; the original runtime was restored.").expect("static"))?;
            retire(home)?;
            return Ok(failed);
        }
        let receipt = receipt_from(&c)?;
        match read_receipt(home, &c.rollback_job_id).map_err(anyhow::Error::msg)? {
            Some(existing) if existing != receipt => anyhow::bail!("n8n_rollback_receipt_mismatch"),
            Some(_) => {}
            None => write_receipt(home, &receipt).map_err(anyhow::Error::msg)?,
        }
        c.phase = Phase::ReceiptPrepared;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::ReceiptPrepared {
        c.phase = Phase::PublishDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::PublishDispatched {
        let endpoint =
            crate::config::LoopbackHttpEndpoint::parse(format!("http://127.0.0.1:{}", c.host_port))
                .expect("validated port");
        let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
        match super::super::publish_adoption_in_job_with_cancel(
            &service,
            &active,
            home,
            endpoint,
            api_key,
            probe,
            &mut cancel,
        )
        .await
        {
            Ok(ready) => {
                if read_receipt(home, &c.rollback_job_id).map_err(anyhow::Error::msg)?
                    != Some(receipt_from(&c)?)
                {
                    anyhow::bail!("n8n_rollback_receipt_mismatch");
                }
                c.phase = Phase::PublishedReady;
                write(home, &c).map_err(anyhow::Error::msg)?;
                let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
                    &home.join("freedom.yaml"),
                    &home.join("credentials.yaml"),
                    ready.job_id.as_str(),
                );
                retire(home)?;
                return Ok(ready);
            }
            Err(error) => {
                super::super::rollback_adoption_if_prepared(
                    home,
                    &active.job_id,
                    error.custody_may_exist,
                )
                .map_err(|_| anyhow::anyhow!("n8n_rollback_adoption_custody_unknown"))?;
                c.phase = Phase::AdoptionCustodyResolved;
                write(home, &c).map_err(anyhow::Error::msg)?;
                compensate(home, runner, &mut c, probe, readiness).await?;
                let current = service
                    .get(&active.job_id)?
                    .ok_or_else(|| anyhow::anyhow!("n8n_rollback_job_missing"))?;
                let failed = service.fail(&current.job_id, current.state_revision, JobFailure::new(error.code, "Historical rollback configuration publication did not complete; the original runtime was restored.").expect("static"))?;
                retire(home)?;
                return Ok(failed);
            }
        }
    }
    anyhow::bail!("n8n_rollback_phase_invalid")
}

async fn wait_ready<R: ManagedDockerRunner, H: super::ManagedReadiness>(
    runner: &mut R,
    readiness: &H,
    id: &str,
    port: u16,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    while tokio::time::Instant::now() < deadline {
        if matches!(runner.inspect_exact(id).await, Ok(InspectOutcome::Found(_)))
            && runner.running_exact(id).await == Ok(true)
            && readiness.health(port).await
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

async fn compensate<
    R: ManagedDockerRunner,
    P: super::N8nApiProbe + ?Sized,
    H: super::ManagedReadiness,
>(
    home: &Path,
    runner: &mut R,
    c: &mut Custody,
    probe: &P,
    readiness: &H,
) -> Result<()> {
    if !matches!(
        c.phase,
        Phase::CompensateNewRemoveDispatched
            | Phase::CompensateNewAbsent
            | Phase::CompensateRenameBackDispatched
            | Phase::CompensateOldLiveObserved
            | Phase::CompensateOldStartDispatched
            | Phase::CompensateOldRunningObserved
            | Phase::Compensated
    ) {
        let new_id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_new_id_missing"))?;
        observed_exact(
            runner
                .inspect_exact_named(new_id, super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            new_id,
        )?;
        c.phase = Phase::CompensateNewRemoveDispatched;
        write(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner.remove(new_id).await;
    }
    if c.phase == Phase::CompensateNewRemoveDispatched {
        let new_id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_rollback_new_id_missing"))?;
        if !matches!(
            runner
                .inspect_exact(new_id)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) || !matches!(
            runner
                .inspect_name(super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) {
            anyhow::bail!("n8n_rollback_new_remove_outcome_unknown");
        }
        c.phase = Phase::CompensateNewAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CompensateNewAbsent {
        observed_exact(
            runner
                .inspect_exact_named(&c.old_container_id, &c.retired_name)
                .await
                .map_err(anyhow::Error::msg)?,
            &c.old_container_id,
        )?;
        c.phase = Phase::CompensateRenameBackDispatched;
        write(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner
            .rename_exact(&c.old_container_id, super::MANAGED_CONTAINER_NAME)
            .await;
    }
    if c.phase == Phase::CompensateRenameBackDispatched {
        observed_exact(
            runner
                .inspect_exact_named(&c.old_container_id, super::MANAGED_CONTAINER_NAME)
                .await
                .map_err(anyhow::Error::msg)?,
            &c.old_container_id,
        )?;
        super::restore_binding_bytes(home, &c.original_binding).map_err(anyhow::Error::msg)?;
        c.phase = Phase::CompensateOldLiveObserved;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CompensateOldLiveObserved && c.old_was_running {
        c.phase = Phase::CompensateOldStartDispatched;
        write(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(&c.old_container_id).await;
    }
    if c.phase == Phase::CompensateOldStartDispatched {
        if !runner
            .running_exact(&c.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_rollback_old_start_outcome_unknown");
        }
        c.phase = Phase::CompensateOldRunningObserved;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if matches!(
        c.phase,
        Phase::CompensateOldLiveObserved | Phase::CompensateOldRunningObserved
    ) {
        if c.old_was_running
            != runner
                .running_exact(&c.old_container_id)
                .await
                .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_rollback_old_running_state_unknown");
        }
        // The credential subsystem has already restored its exact pre-Rollback
        // generation.  Prove that this restored binding authenticates the
        // reactivated retained runtime before terminalizing compensation.
        let (endpoint, api_key) =
            crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
                &home.join("freedom.yaml"),
                &home.join("credentials.yaml"),
            )
            .map_err(|_| anyhow::anyhow!("n8n_rollback_old_binding_unavailable"))?;
        if c.old_was_running {
            if !wait_ready(runner, readiness, &c.old_container_id, c.host_port).await {
                anyhow::bail!("n8n_rollback_old_runtime_not_ready");
            }
            probe
                .negative_control(&endpoint.endpoint)
                .await
                .map_err(|_| anyhow::anyhow!("n8n_rollback_old_runtime_authentication_failed"))?;
            probe
                .authenticated_probe(&endpoint.endpoint, &api_key)
                .await
                .map_err(|_| anyhow::anyhow!("n8n_rollback_old_runtime_authentication_failed"))?;
        } else {
            let _ = (endpoint, api_key);
        }
        c.phase = Phase::Compensated;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

async fn validate_compensated<
    R: ManagedDockerRunner,
    P: super::N8nApiProbe + ?Sized,
    H: super::ManagedReadiness,
>(
    home: &Path,
    runner: &mut R,
    c: &Custody,
    probe: &P,
    readiness: &H,
) -> Result<()> {
    observed_exact(
        runner
            .inspect_exact_named(&c.old_container_id, super::MANAGED_CONTAINER_NAME)
            .await
            .map_err(anyhow::Error::msg)?,
        &c.old_container_id,
    )?;
    if c.old_was_running
        != runner
            .running_exact(&c.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        || read_binding_bytes(home)
            .map_err(anyhow::Error::msg)?
            .as_deref()
            != Some(c.original_binding.as_slice())
    {
        anyhow::bail!("n8n_rollback_compensation_recovery_mismatch");
    }
    let (endpoint, api_key) =
        crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
            &home.join("freedom.yaml"),
            &home.join("credentials.yaml"),
        )
        .map_err(|_| anyhow::anyhow!("n8n_rollback_old_binding_unavailable"))?;
    if c.old_was_running {
        if !wait_ready(runner, readiness, &c.old_container_id, c.host_port).await {
            anyhow::bail!("n8n_rollback_old_runtime_not_ready");
        }
        probe
            .negative_control(&endpoint.endpoint)
            .await
            .map_err(|_| anyhow::anyhow!("n8n_rollback_old_runtime_authentication_failed"))?;
        probe
            .authenticated_probe(&endpoint.endpoint, &api_key)
            .await
            .map_err(|_| anyhow::anyhow!("n8n_rollback_old_runtime_authentication_failed"))?;
    } else {
        let _ = (endpoint, api_key);
    }
    Ok(())
}

/// Receipt resolver deliberately validates receipt/job/Restore/Backup only.
/// It never reads RuntimeBinding, so downstream lineage validation cannot form
/// a recursive receipt chain.
pub(crate) fn completed_receipt_at(
    home: &Path,
    job: &IntegrationJob,
) -> std::result::Result<Option<RollbackReceiptView>, &'static str> {
    if job.operation != JobOperation::Rollback || job.state != JobState::Ready {
        return Ok(None);
    }
    let receipt = read_receipt(home, job.job_id.as_str())?.ok_or("n8n_rollback_receipt_missing")?;
    if receipt.schema_version != 1
        || receipt.rollback_job_id != job.job_id.as_str()
        || receipt.rollback_manifest_sha256 != job.manifest_sha256.as_str()
        || !valid_container_id(&receipt.new_container_id)
        || !valid_container_id(&receipt.retained_source_container_id)
        || !valid_historical_n8n_image(&receipt.source_pinned_image)
        || receipt.host_port == 0
        || !super::valid_volume_name(&receipt.restore_volume)
        || receipt.retained_source_name != retired_container_name(&receipt.rollback_job_id)?
        || !valid_manifest_sha256(&receipt.evidence_sha256)
    {
        return Err("n8n_rollback_receipt_mismatch");
    }
    let restore = JobId::parse(receipt.restore_job_id.clone())
        .map_err(|_| "n8n_rollback_receipt_mismatch")?;
    let (_, resolved) = verify_chain(home, &restore)?;
    if resolved.restore_manifest_sha256 != receipt.restore_manifest_sha256
        || resolved.backup_job_id != receipt.backup_job_id
        || resolved.backup_manifest_sha256 != receipt.backup_manifest_sha256
        || resolved.restore_volume != receipt.restore_volume
        || resolved.source_pinned_image != receipt.source_pinned_image
    {
        return Err("n8n_rollback_receipt_mismatch");
    }
    let expected = sha256_parts(&[
        "n8n-managed-rollback-receipt-v1",
        &receipt.rollback_job_id,
        &receipt.restore_job_id,
        &receipt.restore_manifest_sha256,
        &receipt.backup_job_id,
        &receipt.backup_manifest_sha256,
        &receipt.new_container_id,
        &receipt.source_pinned_image,
        &receipt.host_port.to_string(),
        &receipt.restore_volume,
        &receipt.retained_source_container_id,
        &receipt.retained_source_name,
    ]);
    if receipt.evidence_sha256 != expected.as_str() {
        return Err("n8n_rollback_receipt_mismatch");
    }
    Ok(Some(receipt))
}
pub(crate) fn resolve_ready_receipt_at(
    home: &Path,
    job: &IntegrationJob,
) -> std::result::Result<Option<RollbackReceiptView>, &'static str> {
    completed_receipt_at(home, job)
}

#[cfg(test)]
#[path = "managed_rollback_tests.rs"]
mod tests;
