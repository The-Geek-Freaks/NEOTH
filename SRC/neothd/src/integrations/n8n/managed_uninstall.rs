//! Exact-ID, volume-retaining managed n8n uninstall custody.
//!
//! A Docker name is never a deletion selector here. The original Ready install
//! binding supplies the exact ID and identity; this sidecar records the
//! destructive dispatch boundary before `remove` is attempted.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    InspectOutcome, IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation,
    JobRequester, ManagedDockerRunner, ManagedN8nRequest, N8N_CAPABILITY_ID,
    RetainedReinstallSource, RollbackRestoreRetention, RuntimeBinding, RuntimePhase,
    UpdateRetention, is_managed_job, managed_manifest, read_binding, remove_binding, sha256_parts,
    validate_binding, validate_existing_identity,
};
use crate::integrations::{
    catalog::CapabilityId,
    jobs::EnqueueIntegrationJob,
    jobs::RestartValidator,
    state::{
        JobId, JobProgress, JobState, ProgressEvidence, ProgressEvidenceClaim, ReadyEvidence,
        RecoveryDispositionEvidence, RestartDecision, ResumeEvidence, Sha256Digest,
    },
};

const UNINSTALL_BINDING_FILE: &str = "n8n-managed-uninstall.v1.json";
const STEPS: [&str; 4] = [
    "validate-ready-runtime-binding",
    "persist-remove-dispatch",
    "verify-exact-container-absence",
    "clear-owned-config-binding",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UninstallPhase {
    IntentPersisted,
    RemoveDispatched,
    AbsentVerified,
    ConfigCleanupPending,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallCustody {
    schema_version: u8,
    phase: UninstallPhase,
    uninstall_job_id: String,
    uninstall_manifest_sha256: String,
    source_install_job_id: String,
    source_install_manifest_sha256: String,
    container_id: String,
    image: String,
    host_port: u16,
    volume: String,
    cleanup_disposition: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallCompletionReceipt {
    schema_version: u8,
    uninstall_job_id: String,
    uninstall_manifest_sha256: String,
    source_install_job_id: String,
    source_install_manifest_sha256: String,
    cleanup_disposition: String,
    #[serde(default)]
    source_container_id: Option<String>,
    #[serde(default)]
    source_image: Option<String>,
    #[serde(default)]
    source_host_port: Option<u16>,
    #[serde(default)]
    source_volume: Option<String>,
    #[serde(default)]
    source_bootstrap_volume: Option<bool>,
    #[serde(default)]
    source_volume_owner_install_job_id: Option<String>,
    #[serde(default)]
    source_retained_reinstall: Option<RetainedReinstallSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_restore: Option<RollbackRestoreRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    update: Option<UpdateRetention>,
}

fn custody_path(home: &Path) -> PathBuf {
    home.join(UNINSTALL_BINDING_FILE)
}
fn receipt_path(home: &Path, job_id: &str) -> PathBuf {
    home.join(format!("n8n-uninstall-{job_id}.receipt.json"))
}

fn read_custody(home: &Path) -> Result<Option<UninstallCustody>, &'static str> {
    let path = custody_path(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_uninstall_custody_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 {
        return Err("n8n_uninstall_custody_invalid");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|_| "n8n_uninstall_custody_read_failed")?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "n8n_uninstall_custody_read_failed")?;
    if bytes.len() > 16 * 1024 {
        return Err("n8n_uninstall_custody_invalid");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "n8n_uninstall_custody_invalid")
}

fn write_custody(home: &Path, custody: &UninstallCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_uninstall_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_uninstall_custody_write_failed")
}

fn create_custody(home: &Path, custody: &UninstallCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_uninstall_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_uninstall_custody_create_failed")
}

fn remove_custody(home: &Path) -> Result<(), &'static str> {
    let path = custody_path(home);
    if path.exists() {
        crate::util::atomic_write::durable_remove_file(&path)
            .map_err(|_| "n8n_uninstall_custody_remove_failed")?;
    }
    Ok(())
}

/// A repair must not run beside an incomplete exact-ID deletion transaction.
pub(crate) fn repair_has_pending_custody(home: &Path) -> Result<bool, &'static str> {
    // A Completed uninstall sidecar can still be paired with the live source
    // binding after a crash before its finalizer. Only the explicit uninstall
    // path may reconcile and retire it; repair must never recreate that
    // possibly already-uninstalled runtime.
    Ok(read_custody(home)?.is_some())
}

fn write_completion_receipt(
    home: &Path,
    custody: &UninstallCustody,
    source: &IntegrationJob,
) -> Result<(), &'static str> {
    let cleanup_disposition = custody
        .cleanup_disposition
        .as_deref()
        .ok_or("n8n_uninstall_cleanup_disposition_missing")?;
    let binding = read_binding(home)?.ok_or("n8n_uninstall_receipt_source_binding_missing")?;
    if binding.job_id != custody.source_install_job_id
        || binding.manifest_sha256 != custody.source_install_manifest_sha256
        || binding.container_id.as_deref() != Some(custody.container_id.as_str())
        || binding.image != custody.image
        || binding.host_port != custody.host_port
        || binding.volume != custody.volume
    {
        return Err("n8n_uninstall_receipt_source_binding_mismatch");
    }
    let (bootstrap_volume, volume_owner_install_job_id, retained_reinstall) = match &binding.lineage
    {
        super::RuntimeLineage::Update(lineage) => {
            (false, Some(lineage.update_job_id.clone()), None)
        }
        _ => match binding.retained_reinstall.clone() {
            Some(source) if super::valid_retained_reinstall_source(&source) => (
                source.bootstrap_volume,
                Some(source.volume_owner_install_job_id.clone()),
                Some(source),
            ),
            Some(_) => return Err("n8n_uninstall_receipt_source_binding_mismatch"),
            None => match binding.bootstrap_volume_owner_job_id.clone() {
                Some(owner) if owner == custody.source_install_job_id => (true, Some(owner), None),
                Some(_) => return Err("n8n_uninstall_receipt_source_binding_mismatch"),
                None => (false, None, None),
            },
        },
    };
    let (rollback_restore, update) = match &binding.lineage {
        super::RuntimeLineage::Install => (
            binding
                .retained_reinstall
                .as_ref()
                .and_then(|source| source.rollback_restore.clone()),
            None,
        ),
        super::RuntimeLineage::Rollback(lineage) => {
            let receipt = super::managed_rollback::resolve_ready_receipt_at(home, source)?
                .ok_or("n8n_uninstall_rollback_receipt_missing")?;
            if receipt.rollback_job_id != binding.job_id
                || receipt.rollback_manifest_sha256 != binding.manifest_sha256
                || receipt.restore_job_id != lineage.restore_job_id
                || receipt.backup_job_id != lineage.backup_job_id
                || receipt.restore_volume != binding.volume
                || receipt.new_container_id != custody.container_id
                || receipt.source_pinned_image != custody.image
                || receipt.host_port != custody.host_port
                || receipt.retained_source_container_id != lineage.retained_source_container_id
                || receipt.retained_source_name != lineage.retained_source_name
            {
                return Err("n8n_uninstall_rollback_receipt_mismatch");
            }
            (
                Some(RollbackRestoreRetention {
                    rollback_job_id: receipt.rollback_job_id,
                    rollback_manifest_sha256: receipt.rollback_manifest_sha256,
                    restore_job_id: lineage.restore_job_id.clone(),
                    restore_manifest_sha256: receipt.restore_manifest_sha256,
                    backup_job_id: lineage.backup_job_id.clone(),
                    backup_manifest_sha256: receipt.backup_manifest_sha256,
                    restore_volume: binding.volume.clone(),
                    retained_source_container_id: lineage.retained_source_container_id.clone(),
                    retained_source_name: lineage.retained_source_name.clone(),
                }),
                None,
            )
        }
        super::RuntimeLineage::Update(lineage) => {
            let receipt = super::managed_update::completed_receipt_at(home, source)?
                .ok_or("n8n_uninstall_update_receipt_missing")?;
            if receipt.update_job_id != binding.job_id
                || receipt.update_manifest_sha256 != binding.manifest_sha256
                || receipt.runtime_image != binding.image
                || receipt.update_volume != binding.volume
                || receipt.selector != lineage.admitted_selector
                || receipt.version != lineage.admitted_version
                || receipt.platform != lineage.admitted_platform
                || receipt.repo_digest != lineage.admitted_repo_digest
                || receipt.catalog_evidence_sha256 != lineage.catalog_evidence_sha256
                || receipt.index_digest != lineage.index_digest
                || receipt.child_manifest_digest != lineage.child_manifest_digest
                || receipt.config_digest != lineage.config_digest
                || receipt.source_job_id != lineage.source_job_id
                || receipt.source_manifest_sha256 != lineage.source_manifest_sha256
                || receipt.source_archive_sha256 != lineage.source_archive_sha256
                || receipt.source_archive_bytes != lineage.source_archive_bytes
                || receipt.source_container_id != lineage.source_container_id
                || receipt.source_volume != lineage.source_volume
                || receipt.retained_source_container_id != lineage.retained_source_container_id
                || receipt.retained_source_name != lineage.retained_source_name
            {
                return Err("n8n_uninstall_update_receipt_mismatch");
            }
            if receipt.new_container_id != custody.container_id
                && !super::managed_repair::completed_replacement_matches(
                    home,
                    &binding,
                    source,
                    &receipt.new_container_id,
                )?
            {
                return Err("n8n_uninstall_update_receipt_mismatch");
            }
            (
                None,
                Some(UpdateRetention {
                    update_job_id: receipt.update_job_id,
                    update_manifest_sha256: receipt.update_manifest_sha256,
                    selector: receipt.selector,
                    version: receipt.version,
                    platform: receipt.platform,
                    runtime_image: receipt.runtime_image,
                    repo_digest: receipt.repo_digest,
                    catalog_evidence_sha256: receipt.catalog_evidence_sha256,
                    index_digest: receipt.index_digest,
                    child_manifest_digest: receipt.child_manifest_digest,
                    config_digest: receipt.config_digest,
                    source_job_id: receipt.source_job_id,
                    source_manifest_sha256: receipt.source_manifest_sha256,
                    source_archive_sha256: receipt.source_archive_sha256,
                    source_archive_bytes: receipt.source_archive_bytes,
                    source_container_id: receipt.source_container_id,
                    source_image: receipt.source_image,
                    source_volume: receipt.source_volume,
                    host_port: receipt.host_port,
                    baseline_workflow_count: receipt.baseline_workflow_count,
                    baseline_credential_count: receipt.baseline_credential_count,
                    baseline_content_sha256: receipt.baseline_content_sha256,
                    migrated_workflow_count: receipt.migrated_workflow_count,
                    migrated_credential_count: receipt.migrated_credential_count,
                    migrated_content_sha256: receipt.migrated_content_sha256,
                    update_volume: receipt.update_volume,
                    retained_source_container_id: receipt.retained_source_container_id,
                    retained_source_name: receipt.retained_source_name,
                }),
            )
        }
    };
    let receipt = UninstallCompletionReceipt {
        schema_version: if update.is_some() {
            3
        } else if rollback_restore.is_some() {
            2
        } else {
            1
        },
        uninstall_job_id: custody.uninstall_job_id.clone(),
        uninstall_manifest_sha256: custody.uninstall_manifest_sha256.clone(),
        source_install_job_id: custody.source_install_job_id.clone(),
        source_install_manifest_sha256: custody.source_install_manifest_sha256.clone(),
        cleanup_disposition: cleanup_disposition.to_owned(),
        source_container_id: Some(custody.container_id.clone()),
        source_image: Some(custody.image.clone()),
        source_host_port: Some(custody.host_port),
        source_volume: Some(custody.volume.clone()),
        source_bootstrap_volume: Some(bootstrap_volume),
        source_volume_owner_install_job_id: volume_owner_install_job_id,
        source_retained_reinstall: retained_reinstall,
        rollback_restore,
        update,
    };
    crate::util::atomic_write::atomic_write_private(
        &receipt_path(home, &receipt.uninstall_job_id),
        &serde_json::to_vec(&receipt).map_err(|_| "n8n_uninstall_receipt_serialize_failed")?,
    )
    .map_err(|_| "n8n_uninstall_receipt_write_failed")
}

fn read_completion_receipt(
    home: &Path,
    job: &IntegrationJob,
) -> Result<Option<UninstallCompletionReceipt>, &'static str> {
    let path = receipt_path(home, job.job_id.as_str());
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_uninstall_receipt_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err("n8n_uninstall_receipt_invalid");
    }
    let bytes = std::fs::read(&path).map_err(|_| "n8n_uninstall_receipt_read_failed")?;
    let receipt: UninstallCompletionReceipt =
        serde_json::from_slice(&bytes).map_err(|_| "n8n_uninstall_receipt_invalid")?;
    if !matches!(receipt.schema_version, 1..=3)
        || receipt.uninstall_job_id != job.job_id.as_str()
        || receipt.uninstall_manifest_sha256 != job.manifest_sha256.as_str()
        || (receipt.schema_version == 1
            && (receipt.rollback_restore.is_some() || receipt.update.is_some()))
        || (receipt.schema_version == 2
            && (receipt.rollback_restore.is_none() || receipt.update.is_some()))
        || (receipt.schema_version == 3
            && (receipt.rollback_restore.is_some() || receipt.update.is_none()))
    {
        return Err("n8n_uninstall_receipt_mismatch");
    }
    Ok(Some(receipt))
}

/// Resolve a completed uninstall receipt while the caller owns the n8n job
/// service. Legacy receipts deliberately remain readable for status but cannot
/// authorize attaching a retained Docker volume.
pub(crate) fn retained_reinstall_request_in_service(
    service: &IntegrationJobService,
    home: &Path,
    uninstall_id: &JobId,
) -> Result<ManagedN8nRequest, &'static str> {
    retained_reinstall_request_from_snapshot(
        home,
        uninstall_id,
        service
            .snapshot()
            .map_err(|_| "n8n_retained_reinstall_job_read_failed")?,
    )
}

/// Resolve a retained-volume authorization from a read-only job snapshot.  This
/// keeps confirmation previews observational: callers need not acquire the job
/// owner lease or apply restart recovery merely to print the exact phrase.
pub(crate) fn retained_reinstall_request_from_snapshot(
    home: &Path,
    uninstall_id: &JobId,
    jobs: Vec<IntegrationJob>,
) -> Result<ManagedN8nRequest, &'static str> {
    let uninstall = jobs
        .iter()
        .find(|job| job.job_id == *uninstall_id)
        .cloned()
        .ok_or("n8n_retained_reinstall_job_missing")?;
    if uninstall.operation != JobOperation::Uninstall || uninstall.state != JobState::Ready {
        return Err("n8n_retained_reinstall_job_not_ready");
    }
    let receipt = read_completion_receipt(home, &uninstall)?
        .ok_or("n8n_retained_reinstall_receipt_missing")?;
    if let Some(update) = receipt.update.clone() {
        return update_reinstall_request(home, &uninstall, &receipt, &update, jobs);
    }
    if let Some(rollback) = receipt.rollback_restore.clone() {
        return rollback_restore_reinstall_request(home, &uninstall, &receipt, &rollback, jobs);
    }
    let (container_id, image, host_port, volume, bootstrap_volume, volume_owner_install_job_id) =
        match (
            receipt.source_container_id.as_deref(),
            receipt.source_image.as_deref(),
            receipt.source_host_port,
            receipt.source_volume.as_deref(),
            receipt.source_bootstrap_volume,
            receipt.source_volume_owner_install_job_id.as_deref(),
        ) {
            (
                Some(container_id),
                Some(image),
                Some(host_port),
                Some(volume),
                Some(true),
                Some(owner),
            ) if super::valid_container_id(container_id)
                && super::valid_volume_name(volume)
                && host_port != 0
                && JobId::parse(owner.to_owned()).is_ok() =>
            {
                (container_id, image, host_port, volume, true, owner)
            }
            (Some(_), Some(_), Some(_), Some(_), Some(false), _) => {
                return Err("n8n_retained_reinstall_volume_unproven");
            }
            _ => return Err("n8n_retained_reinstall_receipt_incomplete"),
        };
    if image != crate::installers::n8n::N8N_OCI_REFERENCE {
        return Err("n8n_retained_reinstall_receipt_mismatch");
    }
    let source = jobs
        .into_iter()
        .find(|job| job.job_id.as_str() == receipt.source_install_job_id)
        .ok_or("n8n_retained_reinstall_source_missing")?;
    // A rollback's Restore-owned volume has distinct provenance and must not
    // be coerced into the bootstrap retained-reinstall contract below. Until
    // that dedicated receipt format exists, fail before constructing a false
    // Install-shaped request.
    if source.operation != JobOperation::Install
        || source.state != JobState::Ready
        || !is_managed_job(&source)
        || source.manifest_sha256.as_str() != receipt.source_install_manifest_sha256
    {
        return Err("n8n_retained_reinstall_source_mismatch");
    }
    let source_reinstall = receipt.source_retained_reinstall.clone();
    match &source_reinstall {
        Some(previous)
            if super::valid_retained_reinstall_source(previous)
                && previous.bootstrap_volume
                && previous.volume_owner_install_job_id == volume_owner_install_job_id => {}
        Some(_) => return Err("n8n_retained_reinstall_source_mismatch"),
        None if volume_owner_install_job_id != source.job_id.as_str() => {
            return Err("n8n_retained_reinstall_source_mismatch");
        }
        None => {}
    }
    let mut source_request = ManagedN8nRequest::new_with_volume(
        host_port,
        crate::installers::n8n::N8N_OCI_REFERENCE,
        volume.into(),
    )?;
    if let Some(previous) = source_reinstall.clone() {
        source_request = source_request.with_retained_reinstall(previous);
    }
    if source.manifest_sha256 != managed_manifest(&source_request) {
        return Err("n8n_retained_reinstall_source_manifest_mismatch");
    }
    if uninstall.manifest_sha256
        != uninstall_manifest_from_identity(
            source.job_id.as_str(),
            source.manifest_sha256.as_str(),
            container_id,
            image,
            host_port,
            volume,
            volume_owner_install_job_id,
        )
    {
        return Err("n8n_retained_reinstall_uninstall_manifest_mismatch");
    }
    Ok(ManagedN8nRequest::new_with_volume(
        host_port,
        crate::installers::n8n::N8N_OCI_REFERENCE,
        volume.into(),
    )?
    .with_retained_reinstall(RetainedReinstallSource {
        uninstall_job_id: uninstall.job_id.as_str().into(),
        uninstall_manifest_sha256: uninstall.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        bootstrap_volume,
        volume_owner_install_job_id: volume_owner_install_job_id.into(),
        rollback_restore: None,
        update: None,
    }))
}

fn rollback_restore_reinstall_request(
    home: &Path,
    uninstall: &IntegrationJob,
    receipt: &UninstallCompletionReceipt,
    rollback: &RollbackRestoreRetention,
    jobs: Vec<IntegrationJob>,
) -> Result<ManagedN8nRequest, &'static str> {
    let rollback_job = jobs
        .iter()
        .find(|job| job.job_id.as_str() == rollback.rollback_job_id)
        .ok_or("n8n_restore_volume_rollback_missing")?;
    let immediate = jobs
        .iter()
        .find(|job| job.job_id.as_str() == receipt.source_install_job_id)
        .ok_or("n8n_restore_volume_source_missing")?;
    if rollback_job.operation != JobOperation::Rollback
        || rollback_job.state != JobState::Ready
        || !is_managed_job(rollback_job)
        || rollback_job.manifest_sha256.as_str() != rollback.rollback_manifest_sha256
        || receipt.source_volume.as_deref() != Some(rollback.restore_volume.as_str())
        || !matches!(receipt.source_image.as_deref(), Some(image) if super::valid_historical_n8n_image(image))
        || !matches!(receipt.source_host_port, Some(port) if port != 0)
    {
        return Err("n8n_restore_volume_receipt_mismatch");
    }
    match immediate.operation {
        JobOperation::Rollback if immediate.job_id == rollback_job.job_id => {
            if immediate.manifest_sha256.as_str() != rollback.rollback_manifest_sha256 {
                return Err("n8n_restore_volume_source_mismatch");
            }
        }
        JobOperation::Install
            if immediate.state == JobState::Ready
                && is_managed_job(immediate)
                && immediate.manifest_sha256.as_str() == receipt.source_install_manifest_sha256 =>
        {
            let source = receipt
                .source_retained_reinstall
                .as_ref()
                .filter(|source| source.rollback_restore.as_ref() == Some(rollback))
                .filter(|source| super::valid_retained_reinstall_source(source))
                .ok_or("n8n_restore_volume_source_mismatch")?;
            let request = ManagedN8nRequest::historical_rollback(
                receipt.source_host_port.unwrap_or_default(),
                receipt.source_image.clone().unwrap_or_default(),
                rollback.restore_volume.clone(),
            )?
            .with_retained_reinstall(source.clone());
            if managed_manifest(&request) != immediate.manifest_sha256 {
                return Err("n8n_restore_volume_source_mismatch");
            }
        }
        _ => return Err("n8n_restore_volume_source_mismatch"),
    }
    let resolved = super::managed_rollback::resolve_ready_receipt_at(home, rollback_job)
        .map_err(|_| "n8n_restore_volume_rollback_receipt_invalid")?
        .ok_or("n8n_restore_volume_rollback_receipt_missing")?;
    if resolved.rollback_job_id != rollback.rollback_job_id
        || resolved.rollback_manifest_sha256 != rollback.rollback_manifest_sha256
        || resolved.restore_job_id != rollback.restore_job_id
        || resolved.restore_manifest_sha256 != rollback.restore_manifest_sha256
        || resolved.backup_job_id != rollback.backup_job_id
        || resolved.backup_manifest_sha256 != rollback.backup_manifest_sha256
        || resolved.restore_volume != rollback.restore_volume
        || resolved.source_pinned_image != receipt.source_image.as_deref().unwrap_or("")
        || resolved.host_port != receipt.source_host_port.unwrap_or_default()
        || resolved.retained_source_container_id != rollback.retained_source_container_id
        || resolved.retained_source_name != rollback.retained_source_name
    {
        return Err("n8n_restore_volume_chain_mismatch");
    }
    if immediate.operation == JobOperation::Rollback
        && resolved.new_container_id != receipt.source_container_id.as_deref().unwrap_or("")
    {
        return Err("n8n_restore_volume_chain_mismatch");
    }
    for (id, manifest, operation) in [
        (
            &rollback.restore_job_id,
            &rollback.restore_manifest_sha256,
            JobOperation::Restore,
        ),
        (
            &rollback.backup_job_id,
            &rollback.backup_manifest_sha256,
            JobOperation::Backup,
        ),
    ] {
        let job = jobs
            .iter()
            .find(|job| job.job_id.as_str() == id.as_str())
            .ok_or("n8n_restore_volume_chain_job_missing")?;
        if job.operation != operation
            || job.state != JobState::Ready
            || !is_managed_job(job)
            || job.manifest_sha256.as_str() != manifest.as_str()
        {
            return Err("n8n_restore_volume_chain_mismatch");
        }
    }
    ManagedN8nRequest::historical_rollback(
        receipt.source_host_port.unwrap_or_default(),
        receipt.source_image.clone().unwrap_or_default(),
        rollback.restore_volume.clone(),
    )
    .map(|request| {
        request.with_retained_reinstall(RetainedReinstallSource {
            uninstall_job_id: uninstall.job_id.as_str().into(),
            uninstall_manifest_sha256: uninstall.manifest_sha256.as_str().into(),
            source_install_job_id: immediate.job_id.as_str().into(),
            source_install_manifest_sha256: immediate.manifest_sha256.as_str().into(),
            bootstrap_volume: false,
            volume_owner_install_job_id: rollback.restore_job_id.clone(),
            rollback_restore: Some(rollback.clone()),
            update: None,
        })
    })
}

fn uninstall_manifest_from_identity(
    source_job_id: &str,
    source_manifest_sha256: &str,
    container_id: &str,
    image: &str,
    host_port: u16,
    volume: &str,
    volume_owner_install_job_id: &str,
) -> super::super::Sha256Digest {
    let port = host_port.to_string();
    sha256_parts(&[
        "n8n-managed-uninstall-v1",
        source_job_id,
        source_manifest_sha256,
        container_id,
        image,
        &port,
        volume,
        "n8n-managed-retained-volume-provenance-v1",
        volume_owner_install_job_id,
    ])
}

/// Reinstall an Update-retained volume only after independently resolving the
/// non-cyclic completed Update receipt and the compiled catalog target.  The
/// uninstall receipt carries custody; it never becomes target authority.
fn update_reinstall_request(
    home: &Path,
    uninstall: &IntegrationJob,
    receipt: &UninstallCompletionReceipt,
    update: &UpdateRetention,
    jobs: Vec<IntegrationJob>,
) -> Result<ManagedN8nRequest, &'static str> {
    let update_manifest_sha256 = Sha256Digest::parse(update.update_manifest_sha256.clone())
        .map_err(|_| "n8n_update_volume_receipt_mismatch")?;
    let update_job = jobs
        .iter()
        .find(|job| job.job_id.as_str() == update.update_job_id)
        .ok_or("n8n_update_volume_update_missing")?;
    let immediate = jobs
        .iter()
        .find(|job| job.job_id.as_str() == receipt.source_install_job_id)
        .ok_or("n8n_update_volume_source_missing")?;
    if update_job.operation != JobOperation::Update
        || update_job.state != JobState::Ready
        || update_job.manifest_sha256 != update_manifest_sha256
        || receipt.source_volume.as_deref() != Some(update.update_volume.as_str())
        || receipt.source_image.as_deref() != Some(update.runtime_image.as_str())
        || !matches!(receipt.source_container_id.as_deref(), Some(id) if super::valid_container_id(id))
        || !matches!(receipt.source_host_port, Some(port) if port != 0)
    {
        return Err("n8n_update_volume_receipt_mismatch");
    }
    let resolved = super::managed_update::completed_receipt_at(home, update_job)?
        .ok_or("n8n_update_volume_update_receipt_missing")?;
    if resolved.update_job_id != update.update_job_id
        || resolved.update_manifest_sha256 != update.update_manifest_sha256
        || resolved.selector != update.selector
        || resolved.version != update.version
        || resolved.platform != update.platform
        || resolved.runtime_image != update.runtime_image
        || resolved.repo_digest != update.repo_digest
        || resolved.catalog_evidence_sha256 != update.catalog_evidence_sha256
        || resolved.index_digest != update.index_digest
        || resolved.child_manifest_digest != update.child_manifest_digest
        || resolved.config_digest != update.config_digest
        || resolved.source_job_id != update.source_job_id
        || resolved.source_manifest_sha256 != update.source_manifest_sha256
        || resolved.source_archive_sha256 != update.source_archive_sha256
        || resolved.source_archive_bytes != update.source_archive_bytes
        || resolved.source_container_id != update.source_container_id
        || resolved.source_image != update.source_image
        || resolved.source_volume != update.source_volume
        || resolved.host_port != update.host_port
        || resolved.baseline_workflow_count != update.baseline_workflow_count
        || resolved.baseline_credential_count != update.baseline_credential_count
        || resolved.baseline_content_sha256 != update.baseline_content_sha256
        || resolved.migrated_workflow_count != update.migrated_workflow_count
        || resolved.migrated_credential_count != update.migrated_credential_count
        || resolved.migrated_content_sha256 != update.migrated_content_sha256
        || resolved.update_volume != update.update_volume
        || resolved.retained_source_container_id != update.retained_source_container_id
        || resolved.retained_source_name != update.retained_source_name
    {
        return Err("n8n_update_volume_update_receipt_mismatch");
    }
    let target = super::super::managed_update_target::resolve_admitted_target(&update.selector)
        .map_err(|_| "n8n_update_volume_target_invalid")?;
    if target.version != update.version
        || target.runtime_image != update.runtime_image
        || target.repo_digest != update.repo_digest
        || target.catalog_evidence_sha256 != update.catalog_evidence_sha256
        || target.index_digest != update.index_digest
        || !target.platforms.iter().any(|platform| {
            format!("{}/{}", platform.os, platform.architecture) == update.platform
                && platform.child_manifest_digest == update.child_manifest_digest
        })
    {
        return Err("n8n_update_volume_target_mismatch");
    }
    let inherited = RetainedReinstallSource {
        uninstall_job_id: uninstall.job_id.as_str().into(),
        uninstall_manifest_sha256: uninstall.manifest_sha256.as_str().into(),
        source_install_job_id: immediate.job_id.as_str().into(),
        source_install_manifest_sha256: immediate.manifest_sha256.as_str().into(),
        bootstrap_volume: false,
        volume_owner_install_job_id: update.update_job_id.clone(),
        rollback_restore: None,
        update: Some(update.clone()),
    };
    match immediate.operation {
        JobOperation::Update if immediate.job_id == update_job.job_id => {
            if immediate.manifest_sha256 != update_manifest_sha256 {
                return Err("n8n_update_volume_source_mismatch");
            }
        }
        JobOperation::Install
            if immediate.state == JobState::Ready && is_managed_job(immediate) =>
        {
            let previous = receipt
                .source_retained_reinstall
                .as_ref()
                .filter(|source| source.update.as_ref() == Some(update))
                .filter(|source| super::valid_retained_reinstall_source(source))
                .ok_or("n8n_update_volume_source_mismatch")?;
            let previous_request = ManagedN8nRequest::admitted_update(
                receipt.source_host_port.unwrap_or_default(),
                &target,
                update.update_volume.clone(),
            )?
            .with_retained_reinstall(previous.clone());
            if managed_manifest(&previous_request) != immediate.manifest_sha256 {
                return Err("n8n_update_volume_source_mismatch");
            }
        }
        _ => return Err("n8n_update_volume_source_mismatch"),
    }
    if receipt.source_install_manifest_sha256 != immediate.manifest_sha256.as_str()
        || uninstall.manifest_sha256
            != uninstall_manifest_from_identity(
                immediate.job_id.as_str(),
                immediate.manifest_sha256.as_str(),
                receipt.source_container_id.as_deref().unwrap_or(""),
                receipt.source_image.as_deref().unwrap_or(""),
                receipt.source_host_port.unwrap_or_default(),
                receipt.source_volume.as_deref().unwrap_or(""),
                update.update_job_id.as_str(),
            )
    {
        return Err("n8n_update_volume_uninstall_manifest_mismatch");
    }
    let request = ManagedN8nRequest::admitted_update(
        receipt.source_host_port.unwrap_or_default(),
        &target,
        update.update_volume.clone(),
    )?
    .with_retained_reinstall(inherited);
    Ok(request)
}

fn uninstall_manifest(binding: &RuntimeBinding) -> super::super::Sha256Digest {
    let owner = binding
        .retained_reinstall
        .as_ref()
        .map(|source| source.volume_owner_install_job_id.as_str())
        .or(binding.bootstrap_volume_owner_job_id.as_deref())
        .unwrap_or("");
    uninstall_manifest_from_identity(
        binding.job_id.as_str(),
        binding.manifest_sha256.as_str(),
        binding.container_id.as_deref().unwrap_or(""),
        binding.image.as_str(),
        binding.host_port,
        binding.volume.as_str(),
        owner,
    )
}

fn enqueue_uninstall(
    service: &IntegrationJobService,
    binding: &RuntimeBinding,
) -> Result<IntegrationJob> {
    let manifest = uninstall_manifest(binding);
    let contract = JobEvidenceContract::verified(
        manifest.clone(),
        sha256_parts(&["n8n-managed-volume-retained", binding.volume.as_str()]),
        sha256_parts(&[
            "n8n-managed-exact-id-removal",
            binding.container_id.as_deref().unwrap_or(""),
        ]),
        sha256_parts(&STEPS),
    );
    Ok(service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static capability"),
            operation: JobOperation::Uninstall,
            release_version: "1.4.0".into(),
            manifest_sha256: manifest,
            evidence_contract: contract,
            requested_by: JobRequester::Cli,
            total_steps: STEPS.len() as u32,
            bytes_total: None,
        })?
        .job)
}

fn source_ready_binding(
    service: &IntegrationJobService,
    home: &Path,
) -> Result<(RuntimeBinding, IntegrationJob)> {
    let binding = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("no_matching_managed_runtime"))?;
    let source = service
        .snapshot()?
        .into_iter()
        .find(|job| job.job_id.as_str() == binding.job_id.as_str())
        .ok_or_else(|| anyhow::anyhow!("n8n_uninstall_source_job_missing"))?;
    validate_binding(&binding, &source).map_err(anyhow::Error::msg)?;
    if !super::super::managed_runtime::is_active_runtime_source(home, &binding, &source)
        || !is_managed_job(&source)
        || binding.phase != RuntimePhase::Ready
        || binding.container_id.is_none()
    {
        anyhow::bail!("no_matching_managed_runtime");
    }
    Ok((binding, source))
}

fn validate_custody(
    custody: &UninstallCustody,
    job: &IntegrationJob,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<(), &'static str> {
    if custody.schema_version != 1
        || job.operation != JobOperation::Uninstall
        || custody.uninstall_job_id != job.job_id.as_str()
        || custody.uninstall_manifest_sha256 != job.manifest_sha256.as_str()
        || custody.source_install_job_id != source.job_id.as_str()
        || custody.source_install_manifest_sha256 != source.manifest_sha256.as_str()
        || custody.container_id != binding.container_id.as_deref().unwrap_or("")
        || !super::valid_container_id(&custody.container_id)
        || custody.image != binding.image
        || custody.host_port != binding.host_port
        || custody.volume != binding.volume
    {
        Err("n8n_uninstall_custody_mismatch")
    } else {
        Ok(())
    }
}

fn checkpoint(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    completed_steps: u32,
    step: &str,
) -> Result<IntegrationJob> {
    let contract = job
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_uninstall_contract_missing"))?;
    let progress = JobProgress {
        completed_steps,
        total_steps: STEPS.len() as u32,
        bytes_done: 0,
        bytes_total: None,
    };
    let evidence = ProgressEvidence::claimed(ProgressEvidenceClaim {
        job_id: job.job_id.clone(),
        manifest_sha256: job.manifest_sha256.clone(),
        step_plan_sha256: contract.step_plan_sha256().clone(),
        staging_binding_sha256: sha256_parts(&["n8n-managed-uninstall-checkpoint", step]),
        expected_revision: job.state_revision,
        expected_state: job.state,
        current_phase: step.into(),
        completed_steps,
        bytes_done: 0,
    });
    Ok(service.update_progress(
        &job.job_id,
        job.state_revision,
        job.state,
        progress,
        Some(step.into()),
        evidence,
    )?)
}

/// Restart inspection is deliberately synchronous and inspect-only.  It gives
/// recovery a small test seam without ever exposing a delete capability.
trait UninstallRestartInspector: Send + Sync {
    fn inspect_exact(&self, id: &str) -> std::result::Result<InspectOutcome, &'static str>;
}

struct DockerUninstallRestartInspector;
impl UninstallRestartInspector for DockerUninstallRestartInspector {
    fn inspect_exact(&self, id: &str) -> std::result::Result<InspectOutcome, &'static str> {
        super::sync_inspect_exact(id)
    }
}

impl<F> UninstallRestartInspector for F
where
    F: Fn(&str) -> std::result::Result<InspectOutcome, &'static str> + Send + Sync,
{
    fn inspect_exact(&self, id: &str) -> std::result::Result<InspectOutcome, &'static str> {
        self(id)
    }
}

struct ExplicitUninstallRestartValidator<'a, I: UninstallRestartInspector> {
    home: PathBuf,
    inspector: &'a I,
}
impl<I: UninstallRestartInspector> ExplicitUninstallRestartValidator<'_, I> {
    fn hold(message: &'static str) -> RestartDecision {
        RestartDecision::Hold {
            failure: crate::integrations::state::JobFailure::new(
                "n8n_uninstall_reconciliation_required",
                message,
            )
            .expect("static"),
        }
    }

    fn reject_pre_effect(job: &IntegrationJob, message: &'static str) -> RestartDecision {
        let Some(contract) = job.evidence_contract.as_ref() else {
            return Self::hold(message);
        };
        let staging = sha256_parts(&["n8n-managed-uninstall-pre-effect"]);
        RestartDecision::Reject {
            failure: crate::integrations::state::JobFailure::new(
                "n8n_uninstall_pre_effect_recovery_required",
                message,
            )
            .expect("static"),
            disposition: RecoveryDispositionEvidence::verified(
                job.job_id.clone(),
                job.manifest_sha256.clone(),
                contract.step_plan_sha256().clone(),
                job.state_revision,
                sha256_parts(&["n8n-uninstall-pre-effect-reject"]),
                staging,
            ),
        }
    }

    fn resume(job: &IntegrationJob) -> RestartDecision {
        let Some(contract) = job.evidence_contract.as_ref() else {
            return RestartDecision::Hold {
                failure: crate::integrations::state::JobFailure::new(
                    "n8n_uninstall_reconciliation_required",
                    "The interrupted uninstall lacks its immutable evidence contract.",
                )
                .expect("static"),
            };
        };
        let step = match &job.progress_evidence {
            Some(receipt) => receipt.checkpoint_step(),
            None if job.progress.completed_steps == 0 => "n8n-managed-uninstall-pre-effect",
            None => return Self::hold("The interrupted uninstall lacks its durable checkpoint."),
        };
        let staging = sha256_parts(&["n8n-managed-uninstall-checkpoint", step]);
        RestartDecision::Resume {
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
                sha256_parts(&["n8n-uninstall-inspect-only-resume", step]),
                staging,
            ),
        }
    }
}
impl<I: UninstallRestartInspector> RestartValidator for ExplicitUninstallRestartValidator<'_, I> {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Uninstall {
            return super::super::N8nRestartValidator::new(&self.home).validate(job);
        }
        let Ok(custody) = read_custody(&self.home) else {
            return Self::hold("The interrupted uninstall custody is unreadable.");
        };
        let Some(custody) = custody else {
            return if job.progress.completed_steps == 0
                && matches!(job.state, JobState::Queued | JobState::Running)
            {
                Self::reject_pre_effect(
                    job,
                    "The uninstall crashed before its deletion custody was persisted.",
                )
            } else {
                Self::hold("The interrupted uninstall custody is unavailable.")
            };
        };
        if custody.uninstall_job_id != job.job_id.as_str()
            || custody.uninstall_manifest_sha256 != job.manifest_sha256.as_str()
        {
            return Self::hold("The interrupted uninstall custody does not match its active job.");
        }
        if custody.phase == UninstallPhase::RemoveDispatched {
            match self.inspector.inspect_exact(&custody.container_id) {
                Ok(InspectOutcome::Absent) => Self::resume(job),
                _ => Self::hold(
                    "The dispatched delete is not proven absent; retain custody without retrying removal.",
                ),
            }
        } else {
            Self::resume(job)
        }
    }
}

fn open_explicit_uninstall_service_with<I: UninstallRestartInspector>(
    home: &Path,
    inspector: &I,
) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(
        home,
        super::super::n8n_catalog(),
        &ExplicitUninstallRestartValidator {
            home: home.to_owned(),
            inspector,
        },
    )?)
}

/// Production uninstall. All runner errors after the durable dispatch marker
/// are ambiguous and deliberately retained for inspect-only restart handling.
pub(crate) async fn uninstall_managed_at(home: &Path) -> Result<IntegrationJob> {
    uninstall_managed_at_with(home, &mut super::DockerManagedRunner).await
}

pub(crate) async fn uninstall_managed_at_with<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
) -> Result<IntegrationJob> {
    uninstall_managed_at_with_restart_inspector(home, runner, &DockerUninstallRestartInspector)
        .await
}

async fn uninstall_managed_at_with_restart_inspector<
    R: ManagedDockerRunner,
    I: UninstallRestartInspector,
>(
    home: &Path,
    runner: &mut R,
    inspector: &I,
) -> Result<IntegrationJob> {
    let _operation_lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )?
    .ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    super::managed_backup::reject_pending_backup(home).map_err(anyhow::Error::msg)?;
    super::managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    super::managed_rollback::reject_pending_rollback(home).map_err(anyhow::Error::msg)?;
    super::managed_update::reject_pending_update(home).map_err(anyhow::Error::msg)?;
    if super::managed_repair::repair_has_pending_custody(home).map_err(anyhow::Error::msg)? {
        anyhow::bail!("n8n_uninstall_repair_custody_pending");
    }
    let service = open_explicit_uninstall_service_with(home, inspector)?;
    if let Some(custody) = read_custody(home).map_err(anyhow::Error::msg)?
        && custody.phase == UninstallPhase::Completed
        && let Some(ready) = service.snapshot()?.into_iter().find(|job| {
            job.operation == JobOperation::Uninstall
                && job.state == JobState::Ready
                && job.job_id.as_str() == custody.uninstall_job_id
                && job.manifest_sha256.as_str() == custody.uninstall_manifest_sha256
        })
    {
        finalize_ready_uninstall_custody_locked(home, &ready).map_err(anyhow::Error::msg)?;
        if read_binding(home).map_err(anyhow::Error::msg)?.is_none() {
            return Ok(ready);
        }
    }
    if read_binding(home).map_err(anyhow::Error::msg)?.is_none() {
        if let Some(ready) = service
            .snapshot()?
            .into_iter()
            .filter(|job| {
                job.operation == JobOperation::Uninstall
                    && job.state == super::super::JobState::Ready
            })
            .max_by_key(|job| (job.updated_at, job.job_id.clone()))
        {
            return Ok(ready);
        }
        anyhow::bail!("no_matching_managed_runtime");
    }
    let (binding, source) = source_ready_binding(&service, home)?;
    let queued = enqueue_uninstall(&service, &binding)?;
    let mut custody = match read_custody(home).map_err(anyhow::Error::msg)? {
        Some(existing) => {
            validate_custody(&existing, &queued, &binding, &source).map_err(anyhow::Error::msg)?;
            existing
        }
        None => {
            let value = UninstallCustody {
                schema_version: 1,
                phase: UninstallPhase::IntentPersisted,
                uninstall_job_id: queued.job_id.as_str().into(),
                uninstall_manifest_sha256: queued.manifest_sha256.as_str().into(),
                source_install_job_id: source.job_id.as_str().into(),
                source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
                container_id: binding.container_id.clone().expect("validated"),
                image: binding.image.clone(),
                host_port: binding.host_port,
                volume: binding.volume.clone(),
                cleanup_disposition: None,
            };
            create_custody(home, &value).map_err(anyhow::Error::msg)?;
            value
        }
    };
    let running = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        state if state.is_active() => queued,
        _ => return Ok(queued),
    };
    let validating = if running.state == JobState::Running {
        service.begin_validation(&running.job_id, running.state_revision, STEPS[0])?
    } else {
        running
    };
    let mut active =
        if validating.state == JobState::Validating && validating.progress.completed_steps == 0 {
            checkpoint(&service, &validating, 1, STEPS[0])?
        } else {
            validating
        };
    if matches!(custody.phase, UninstallPhase::IntentPersisted) {
        match runner
            .inspect_exact(&custody.container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectOutcome::Found(found) => {
                let request = validate_binding(&binding, &source).map_err(anyhow::Error::msg)?;
                validate_existing_identity(&found, Some(&binding), &request, &source)
                    .map_err(anyhow::Error::msg)?;
            }
            InspectOutcome::Absent => {
                custody.phase = UninstallPhase::AbsentVerified;
                write_custody(home, &custody).map_err(anyhow::Error::msg)?;
            }
            InspectOutcome::Unknown => anyhow::bail!("uninstall_state_unknown"),
        }
        if custody.phase == UninstallPhase::IntentPersisted {
            custody.phase = UninstallPhase::RemoveDispatched;
            write_custody(home, &custody).map_err(anyhow::Error::msg)?;
            let _ = runner.remove(&custody.container_id).await;
            match runner.inspect_exact(&custody.container_id).await {
                Ok(InspectOutcome::Absent) => {
                    custody.phase = UninstallPhase::AbsentVerified;
                    write_custody(home, &custody).map_err(anyhow::Error::msg)?;
                }
                _ => anyhow::bail!("uninstall_state_unknown"),
            }
        }
    }
    if custody.phase == UninstallPhase::RemoveDispatched {
        match runner.inspect_exact(&custody.container_id).await {
            Ok(InspectOutcome::Absent) => {
                custody.phase = UninstallPhase::AbsentVerified;
                write_custody(home, &custody).map_err(anyhow::Error::msg)?;
            }
            Ok(InspectOutcome::Found(found)) => {
                let request = validate_binding(&binding, &source).map_err(anyhow::Error::msg)?;
                validate_existing_identity(&found, Some(&binding), &request, &source)
                    .map_err(anyhow::Error::msg)?;
                anyhow::bail!("uninstall_failed_container_retained");
            }
            _ => anyhow::bail!("uninstall_state_unknown"),
        }
    }
    if active.state == JobState::Validating {
        active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[2])?;
    }
    if active.progress.completed_steps < 3 {
        active = checkpoint(&service, &active, 3, STEPS[2])?;
    }
    if custody.phase == UninstallPhase::AbsentVerified {
        custody.phase = UninstallPhase::ConfigCleanupPending;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == UninstallPhase::ConfigCleanupPending {
        let endpoint = validate_binding(&binding, &source)
            .map_err(anyhow::Error::msg)?
            .endpoint();
        let outcome = crate::config::credentials::Credentials::clear_owned_n8n_binding_at(
            &home.join("freedom.yaml"),
            &home.join("credentials.yaml"),
            source.job_id.as_str(),
            &endpoint,
        )?;
        custody.cleanup_disposition = Some(outcome.as_str().to_owned());
        custody.phase = UninstallPhase::Completed;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    write_completion_receipt(home, &custody, &source).map_err(anyhow::Error::msg)?;
    if active.progress.completed_steps < 4 {
        active = checkpoint(&service, &active, 4, STEPS[3])?;
    }
    let contract = active
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_uninstall_contract_missing"))?;
    let ready = ReadyEvidence::verified(
        active.job_id.clone(),
        active.manifest_sha256.clone(),
        contract.artifact_binding_sha256().clone(),
        contract.config_binding_sha256().clone(),
        contract.authenticated_probe_sha256().clone(),
        contract.step_plan_sha256().clone(),
    );
    let completed = service.mark_ready(&active.job_id, active.state_revision, ready)?;
    finalize_ready_uninstall_custody_locked(home, &completed).map_err(anyhow::Error::msg)?;
    Ok(completed)
}

/// Remove only the two exact custody sidecars after an immutable successful
/// uninstall Ready row. The install job itself is never changed or removed.
fn finalize_ready_uninstall_custody_locked(
    home: &Path,
    job: &IntegrationJob,
) -> Result<(), &'static str> {
    let Some(custody) = read_custody(home)? else {
        return Ok(());
    };
    if job.operation != JobOperation::Uninstall
        || job.state != super::super::JobState::Ready
        || custody.phase != UninstallPhase::Completed
        || custody.uninstall_job_id != job.job_id.as_str()
        || custody.uninstall_manifest_sha256 != job.manifest_sha256.as_str()
    {
        return Err("n8n_uninstall_finalize_mismatch");
    }
    match read_binding(home)? {
        Some(binding) => {
            if binding.job_id != custody.source_install_job_id
                || binding.manifest_sha256 != custody.source_install_manifest_sha256
                || binding.container_id.as_deref() != Some(custody.container_id.as_str())
            {
                return Err("n8n_uninstall_finalize_mismatch");
            }
            super::managed_repair::retire_completed_for_uninstall(home)?;
            remove_binding(home)?;
        }
        None => {
            if read_completion_receipt(home, job)?.is_none() {
                return Err("n8n_uninstall_finalize_mismatch");
            }
        }
    }
    remove_custody(home)
}

/// Public finalizer used by ordinary adapter open. Explicit uninstall already
/// holds this non-reentrant lock and calls the locked inner finalizer instead.
pub(crate) fn finalize_ready_uninstall_custody(
    home: &Path,
    job: &IntegrationJob,
) -> Result<(), &'static str> {
    let _operation_lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )
    .map_err(|_| "n8n_managed_operation_lock_failed")?
    .ok_or("n8n_managed_operation_busy")?;
    finalize_ready_uninstall_custody_locked(home, job)
}

pub(crate) fn disposition(job: &IntegrationJob) -> &'static str {
    if job.operation == JobOperation::Uninstall && job.state == super::super::JobState::Ready {
        "container_removed_data_volume_retained"
    } else if job.operation == JobOperation::Uninstall && !job.state.is_terminal() {
        "uninstall_pending"
    } else {
        "no_matching_managed_runtime"
    }
}

pub(crate) fn cleanup_disposition_at(
    home: &Path,
    job: &IntegrationJob,
) -> Result<Option<&'static str>, &'static str> {
    if job.operation != JobOperation::Uninstall || job.state != super::super::JobState::Ready {
        return Ok(None);
    }
    let Some(receipt) = read_completion_receipt(home, job)? else {
        return Ok(Some("unknown_or_preserved"));
    };
    let value = match receipt.cleanup_disposition.as_str() {
        "cleared" => "cleared",
        "already_absent" => "already_absent",
        "preserved_unproven" => "preserved_unproven",
        "preserved_changed" => "preserved_changed",
        _ => return Err("n8n_uninstall_receipt_invalid"),
    };
    Ok(Some(value))
}

#[cfg(test)]
#[path = "managed_uninstall_tests.rs"]
mod tests;
