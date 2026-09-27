//! Managed n8n Update custody.
//!
//! This is deliberately a rename-last transaction.  Target admission is
//! compiled authority, while this file records only observations and opaque
//! archive custody.  In particular receipt resolution never reads the active
//! runtime binding, avoiding a binding/receipt validation cycle.

use super::{
    InspectOutcome, InspectVolumeOutcome, IntegrationJob, IntegrationJobService,
    JobEvidenceContract, JobOperation, JobRequester, MANAGED_CONTAINER_NAME, ManagedDockerRunner,
    ManagedN8nRequest, N8N_CAPABILITY_ID, RuntimeBinding, RuntimeLineage, RuntimePhase,
    UpdateRuntimeLineage, is_active_runtime_source, is_managed_job, read_binding,
    read_binding_bytes, retired_container_name, sha256_parts, valid_container_id,
    valid_manifest_sha256, valid_volume_name,
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

const FILE: &str = "n8n-managed-update.v1.json";
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
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
    TargetProved,
    SourceStopDispatched,
    SourceStopped,
    ArchiveDispatched,
    ArchiveCaptured,
    VolumeCreateDispatched,
    VolumeObserved,
    SeedCreateDispatched,
    SeedObserved,
    SeedExtractDispatched,
    SeedExtracted,
    SeedStartDispatched,
    BaselineObserved,
    SeedRemoveDispatched,
    SeedAbsent,
    CandidateCreateDispatched,
    CandidateObserved,
    CandidateStartDispatched,
    CandidateStarted,
    MigrationObserved,
    CandidateRemoveDispatched,
    ContentObserved,
    OldRenameDispatched,
    OldRenamed,
    LiveCreateDispatched,
    LiveCreated,
    BindingPublished,
    ReceiptPrepared,
    PublishDispatched,
    PublishedReady,
    CompensateLiveRemoveDispatched,
    CompensateLiveAbsent,
    CompensateRenameBackDispatched,
    CompensateOldLive,
    CompensateOldStartDispatched,
    Compensated,
    CleanupCandidateRemoveDispatched,
    CleanupCandidateAbsent,
    CleanupSeedRemoveDispatched,
    CleanupSeedAbsent,
    CleanupVolumeRemoveDispatched,
    CleanupVolumeAbsent,
    CleanupComplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    schema_version: u8,
    phase: Phase,
    update_job_id: String,
    update_manifest_sha256: String,
    selector: String,
    platform: String,
    version: String,
    runtime_image: String,
    repo_digest: String,
    catalog_evidence_sha256: String,
    index_digest: String,
    child_manifest_digest: String,
    config_digest: String,
    source_job_id: String,
    source_manifest_sha256: String,
    source_container_id: String,
    source_image: String,
    source_volume: String,
    host_port: u16,
    source_was_running: bool,
    original_binding: Vec<u8>,
    original_binding_sha256: String,
    archive_sha256: Option<String>,
    archive_bytes: Option<u64>,
    baseline_workflow_count: Option<u32>,
    baseline_credential_count: Option<u32>,
    baseline_content_sha256: Option<String>,
    migrated_workflow_count: Option<u32>,
    migrated_credential_count: Option<u32>,
    migrated_content_sha256: Option<String>,
    /// Set before compensation begins so an interrupted cleanup can complete
    /// the same terminal failure without inventing a different cause.
    failure_code: Option<String>,
    seed_id: Option<String>,
    candidate_id: Option<String>,
    new_container_id: Option<String>,
    retained_source_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateReceiptView {
    pub schema_version: u8,
    pub update_job_id: String,
    pub update_manifest_sha256: String,
    pub selector: String,
    pub version: String,
    pub platform: String,
    pub runtime_image: String,
    pub repo_digest: String,
    pub catalog_evidence_sha256: String,
    pub index_digest: String,
    pub child_manifest_digest: String,
    pub config_digest: String,
    pub source_job_id: String,
    pub source_manifest_sha256: String,
    pub source_container_id: String,
    pub source_image: String,
    pub source_volume: String,
    pub host_port: u16,
    pub source_archive_sha256: String,
    pub source_archive_bytes: u64,
    pub update_volume: String,
    pub new_container_id: String,
    pub retained_source_container_id: String,
    pub retained_source_name: String,
    pub baseline_workflow_count: u32,
    pub baseline_credential_count: u32,
    pub baseline_content_sha256: String,
    pub migrated_workflow_count: u32,
    pub migrated_credential_count: u32,
    pub migrated_content_sha256: String,
    pub evidence_sha256: String,
}

fn custody_path(home: &Path) -> PathBuf {
    home.join(FILE)
}
fn archive_path(home: &Path, id: &str) -> PathBuf {
    home.join("n8n-updates").join(format!("{id}.tar"))
}
fn ensure_private_archive_dir(home: &Path) -> Result<PathBuf> {
    let dir = home.join("n8n-updates");
    match std::fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            }
            #[cfg(windows)]
            crate::wal::win_native::create_private_directory_new(&dir)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(&dir)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("n8n_update_archive_directory_invalid");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            anyhow::bail!("n8n_update_archive_directory_not_private");
        }
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(&dir)?;
    Ok(dir)
}
fn receipt_path(home: &Path, id: &str) -> PathBuf {
    home.join(format!("n8n-update-{id}.receipt.json"))
}
fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    code: &'static str,
) -> std::result::Result<Option<T>, &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    read_json(&custody_path(home), "n8n_update_custody_invalid")
}
fn write(home: &Path, c: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home),
        &serde_json::to_vec(c).map_err(|_| "n8n_update_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_update_custody_write_failed")
}
fn create(home: &Path, c: &Custody) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home),
        &serde_json::to_vec(c).map_err(|_| "n8n_update_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_update_custody_create_failed")
}
fn read_receipt(
    home: &Path,
    id: &str,
) -> std::result::Result<Option<UpdateReceiptView>, &'static str> {
    read_json(&receipt_path(home, id), "n8n_update_receipt_invalid")
}
fn write_receipt(home: &Path, r: &UpdateReceiptView) -> std::result::Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &receipt_path(home, &r.update_job_id),
        &serde_json::to_vec(r).map_err(|_| "n8n_update_receipt_serialize_failed")?,
    )
    .map_err(|_| "n8n_update_receipt_write_failed")
}
fn archive_matches(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> std::result::Result<(), &'static str> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "n8n_update_archive_missing")?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.len() != expected_bytes
        || expected_bytes == 0
        || expected_bytes > MAX_ARCHIVE_BYTES
    {
        return Err("n8n_update_archive_mismatch");
    }
    let mut file = std::fs::File::open(path).map_err(|_| "n8n_update_archive_read_failed")?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buf)
            .map_err(|_| "n8n_update_archive_read_failed")?;
        if count == 0 {
            break;
        };
        total = total
            .checked_add(count as u64)
            .ok_or("n8n_update_archive_mismatch")?;
        if total > MAX_ARCHIVE_BYTES {
            return Err("n8n_update_archive_mismatch");
        };
        digest.update(&buf[..count]);
    }
    if total != expected_bytes || format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err("n8n_update_archive_mismatch");
    }
    Ok(())
}

async fn wait_live_ready<R: ManagedDockerRunner, H: super::ManagedReadiness>(
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
async fn wait_candidate_ready<R: ManagedDockerRunner>(runner: &mut R, id: &str) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        if runner.running_exact(id).await.map_err(anyhow::Error::msg)?
            && runner
                .update_candidate_ready_exact(id)
                .await
                .map_err(anyhow::Error::msg)?
        {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(false)
}

fn source_observation_matches(c: &Custody, found: &super::ObservedContainer) -> bool {
    found.id == c.source_container_id
        && found.job == c.source_job_id
        && found.image == c.source_image
        && found.volume == c.source_volume
        && found.host_ip == "127.0.0.1"
        && found.host_port == c.host_port
        && found.managed == super::MANAGED_LABEL_VALUE
        && found.mount_destination == "/home/node/.n8n"
}

fn live_observation_matches(c: &Custody, found: &super::ObservedContainer) -> bool {
    let Ok(job_id) = JobId::parse(c.update_job_id.clone()) else {
        return false;
    };
    found.id == c.new_container_id.as_deref().unwrap_or_default()
        && found.job == c.update_job_id
        && found.image == c.runtime_image
        && found.volume == super::managed_update_candidate::update_volume_name(&job_id)
        && found.host_ip == "127.0.0.1"
        && found.host_port == c.host_port
        && found.managed == super::MANAGED_LABEL_VALUE
        && found.mount_destination == "/home/node/.n8n"
}

fn valid_oci_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(valid_manifest_sha256)
}

/// Persisted fields are validated before a recovery path accesses them.  A
/// malformed optional field is never allowed to turn an interrupted effect
/// into a replayable one.
fn validate_custody(
    home: &Path,
    c: &Custody,
    job: &IntegrationJob,
) -> std::result::Result<(), &'static str> {
    if c.schema_version != 1
        || c.update_job_id != job.job_id.as_str()
        || c.update_manifest_sha256 != job.manifest_sha256.as_str()
        || job.operation != JobOperation::Update
        || !super::is_managed_job(job)
        || !valid_container_id(&c.source_container_id)
        || !valid_manifest_sha256(&c.update_manifest_sha256)
        || !valid_manifest_sha256(&c.source_manifest_sha256)
        || !valid_volume_name(&c.source_volume)
        || c.host_port == 0
        || !super::valid_historical_n8n_image(&c.source_image)
        || !super::valid_historical_n8n_image(&c.runtime_image)
        || !c
            .repo_digest
            .strip_prefix("n8nio/n8n@")
            .is_some_and(valid_oci_digest)
        || !valid_manifest_sha256(&c.catalog_evidence_sha256)
        || !valid_oci_digest(&c.index_digest)
        || !valid_oci_digest(&c.child_manifest_digest)
        || !valid_oci_digest(&c.config_digest)
        || !super::valid_retired_container_name(&c.retained_source_name)
        || c.original_binding.is_empty()
        || format!("{:x}", Sha256::digest(&c.original_binding)) != c.original_binding_sha256
    {
        return Err("n8n_update_custody_invalid");
    }
    let binding: RuntimeBinding = serde_json::from_slice(&c.original_binding)
        .map_err(|_| "n8n_update_custody_original_binding_invalid")?;
    if binding.container_id.as_deref() != Some(c.source_container_id.as_str())
        || binding.job_id != c.source_job_id
        || binding.manifest_sha256 != c.source_manifest_sha256
        || binding.image != c.source_image
        || binding.volume != c.source_volume
        || binding.host_port != c.host_port
    {
        return Err("n8n_update_custody_original_binding_invalid");
    }
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_update_source_read_failed")?;
    let source = jobs
        .iter()
        .find(|source| {
            source.job_id.as_str() == c.source_job_id
                && source.manifest_sha256.as_str() == c.source_manifest_sha256
        })
        .ok_or("n8n_update_source_missing")?;
    if source.state != JobState::Ready || !super::is_managed_job(source) {
        return Err("n8n_update_source_not_ready");
    }
    super::validate_binding(&binding, source)?;
    let expected = sha256_parts(&[
        "n8n-managed-update-v1",
        &c.selector,
        &c.version,
        &c.platform,
        &c.runtime_image,
        &c.repo_digest,
        &c.index_digest,
        &c.child_manifest_digest,
        &c.config_digest,
        &c.catalog_evidence_sha256,
        &c.source_job_id,
        &c.source_manifest_sha256,
        &c.source_container_id,
        &c.source_image,
        &c.source_volume,
        &c.host_port.to_string(),
    ]);
    if expected != job.manifest_sha256 {
        return Err("n8n_update_custody_manifest_mismatch");
    }
    let archive_required = !matches!(
        c.phase,
        Phase::IntentPersisted
            | Phase::TargetProved
            | Phase::SourceStopDispatched
            | Phase::SourceStopped
            | Phase::ArchiveDispatched
    );
    if archive_required
        && (!c
            .archive_sha256
            .as_deref()
            .is_some_and(valid_manifest_sha256)
            || !c
                .archive_bytes
                .is_some_and(|bytes| bytes > 0 && bytes <= MAX_ARCHIVE_BYTES))
    {
        return Err("n8n_update_custody_archive_invalid");
    }
    let seed_required = matches!(
        c.phase,
        Phase::SeedCreateDispatched
            | Phase::SeedObserved
            | Phase::SeedExtractDispatched
            | Phase::SeedExtracted
            | Phase::SeedStartDispatched
            | Phase::BaselineObserved
            | Phase::SeedRemoveDispatched
            | Phase::SeedAbsent
            | Phase::CandidateCreateDispatched
            | Phase::CandidateObserved
            | Phase::CandidateStartDispatched
            | Phase::CandidateStarted
            | Phase::MigrationObserved
            | Phase::CandidateRemoveDispatched
            | Phase::ContentObserved
            | Phase::OldRenameDispatched
            | Phase::OldRenamed
            | Phase::LiveCreateDispatched
            | Phase::LiveCreated
            | Phase::BindingPublished
            | Phase::ReceiptPrepared
            | Phase::PublishDispatched
            | Phase::PublishedReady
    );
    if seed_required && !c.seed_id.as_deref().is_some_and(valid_container_id) {
        return Err("n8n_update_custody_seed_missing");
    }
    let candidate_required = matches!(
        c.phase,
        Phase::CandidateCreateDispatched
            | Phase::CandidateObserved
            | Phase::CandidateStartDispatched
            | Phase::CandidateStarted
            | Phase::MigrationObserved
            | Phase::CandidateRemoveDispatched
            | Phase::ContentObserved
            | Phase::OldRenameDispatched
            | Phase::OldRenamed
            | Phase::LiveCreateDispatched
            | Phase::LiveCreated
            | Phase::BindingPublished
            | Phase::ReceiptPrepared
            | Phase::PublishDispatched
            | Phase::PublishedReady
    );
    if candidate_required && !c.candidate_id.as_deref().is_some_and(valid_container_id) {
        return Err("n8n_update_custody_candidate_missing");
    }
    let live_required = matches!(
        c.phase,
        Phase::LiveCreateDispatched
            | Phase::LiveCreated
            | Phase::BindingPublished
            | Phase::ReceiptPrepared
            | Phase::PublishDispatched
            | Phase::PublishedReady
            | Phase::CompensateLiveRemoveDispatched
            | Phase::CompensateLiveAbsent
    );
    if live_required
        && !c
            .new_container_id
            .as_deref()
            .is_some_and(valid_container_id)
    {
        return Err("n8n_update_custody_live_missing");
    }
    if [&c.seed_id, &c.candidate_id, &c.new_container_id]
        .into_iter()
        .any(|id| id.as_deref().is_some_and(|id| !valid_container_id(id)))
    {
        return Err("n8n_update_custody_container_id_invalid");
    }
    let baseline_required = matches!(
        c.phase,
        Phase::BaselineObserved
            | Phase::SeedRemoveDispatched
            | Phase::SeedAbsent
            | Phase::CandidateCreateDispatched
            | Phase::CandidateObserved
            | Phase::CandidateStartDispatched
            | Phase::CandidateStarted
            | Phase::MigrationObserved
            | Phase::CandidateRemoveDispatched
            | Phase::ContentObserved
            | Phase::OldRenameDispatched
            | Phase::OldRenamed
            | Phase::LiveCreateDispatched
            | Phase::LiveCreated
            | Phase::BindingPublished
            | Phase::ReceiptPrepared
            | Phase::PublishDispatched
            | Phase::PublishedReady
    );
    if baseline_required
        && (c.baseline_workflow_count.is_none()
            || c.baseline_credential_count.is_none()
            || !c
                .baseline_content_sha256
                .as_deref()
                .is_some_and(valid_manifest_sha256))
    {
        return Err("n8n_update_custody_baseline_invalid");
    }
    let parity_required = matches!(
        c.phase,
        Phase::MigrationObserved
            | Phase::CandidateRemoveDispatched
            | Phase::ContentObserved
            | Phase::OldRenameDispatched
            | Phase::OldRenamed
            | Phase::LiveCreateDispatched
            | Phase::LiveCreated
            | Phase::BindingPublished
            | Phase::ReceiptPrepared
            | Phase::PublishDispatched
            | Phase::PublishedReady
    );
    if parity_required
        && (c.migrated_workflow_count != c.baseline_workflow_count
            || c.migrated_credential_count != c.baseline_credential_count
            || c.migrated_content_sha256 != c.baseline_content_sha256)
    {
        return Err("n8n_update_custody_content_mismatch");
    }
    Ok(())
}

/// Compensation is observation-first.  It never reissues an unknown create or
/// rename: a missing exact witness leaves durable custody for recovery.
async fn compensate<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
    c: &mut Custody,
) -> Result<()> {
    let start_was_dispatched = c.phase == Phase::CompensateOldStartDispatched;
    if c.phase == Phase::CompensateLiveRemoveDispatched {
        let id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_compensation_live_unknown"))?;
        if !matches!(
            runner.inspect_exact(id).await.map_err(anyhow::Error::msg)?,
            InspectOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_compensation_live_unknown");
        }
        c.phase = Phase::CompensateLiveAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if let Some(new_id) = c.new_container_id.as_deref()
        && !matches!(
            c.phase,
            Phase::CompensateLiveAbsent
                | Phase::CompensateRenameBackDispatched
                | Phase::CompensateOldLive
                | Phase::CompensateOldStartDispatched
                | Phase::Compensated
        )
    {
        match runner
            .inspect_exact(new_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectOutcome::Absent => c.phase = Phase::CompensateLiveAbsent,
            InspectOutcome::Found(found) if live_observation_matches(c, &found) => {
                c.phase = Phase::CompensateLiveRemoveDispatched;
                write(home, c).map_err(anyhow::Error::msg)?;
                let _ = runner.remove(new_id).await;
                match runner
                    .inspect_exact(new_id)
                    .await
                    .map_err(anyhow::Error::msg)?
                {
                    InspectOutcome::Absent => c.phase = Phase::CompensateLiveAbsent,
                    _ => anyhow::bail!("n8n_update_compensation_live_unknown"),
                }
            }
            _ => anyhow::bail!("n8n_update_compensation_live_unknown"),
        }
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if matches!(c.phase, Phase::CompensateLiveRemoveDispatched) {
        anyhow::bail!("n8n_update_compensation_live_unknown");
    }
    match runner
        .inspect_exact_named(&c.source_container_id, &c.retained_source_name)
        .await
        .map_err(anyhow::Error::msg)?
    {
        InspectOutcome::Found(found) if source_observation_matches(c, &found) => {
            if c.phase == Phase::CompensateRenameBackDispatched {
                anyhow::bail!("n8n_update_compensation_rename_unknown")
            }
            c.phase = Phase::CompensateRenameBackDispatched;
            write(home, c).map_err(anyhow::Error::msg)?;
            let _ = runner
                .rename_exact(&c.source_container_id, MANAGED_CONTAINER_NAME)
                .await;
        }
        InspectOutcome::Absent => match runner
            .inspect_exact_named(&c.source_container_id, MANAGED_CONTAINER_NAME)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectOutcome::Found(found) if source_observation_matches(c, &found) => {
                super::restore_binding_bytes(home, &c.original_binding)
                    .map_err(anyhow::Error::msg)?;
                if !start_was_dispatched {
                    c.phase = Phase::CompensateOldLive;
                    write(home, c).map_err(anyhow::Error::msg)?;
                }
                if c.source_was_running
                    && !runner
                        .running_exact(&c.source_container_id)
                        .await
                        .map_err(anyhow::Error::msg)?
                {
                    if start_was_dispatched {
                        anyhow::bail!("n8n_update_compensation_start_unknown")
                    }
                    c.phase = Phase::CompensateOldStartDispatched;
                    write(home, c).map_err(anyhow::Error::msg)?;
                    let _ = runner.start_exact(&c.source_container_id).await;
                }
                if runner
                    .running_exact(&c.source_container_id)
                    .await
                    .map_err(anyhow::Error::msg)?
                    != c.source_was_running
                {
                    anyhow::bail!("n8n_update_compensation_start_unknown")
                }
                c.phase = Phase::Compensated;
                write(home, c).map_err(anyhow::Error::msg)?;
                return Ok(());
            }
            _ => anyhow::bail!("n8n_update_compensation_source_unknown"),
        },
        _ => {}
    }
    match runner
        .inspect_exact_named(&c.source_container_id, MANAGED_CONTAINER_NAME)
        .await
        .map_err(anyhow::Error::msg)?
    {
        InspectOutcome::Found(found) if source_observation_matches(c, &found) => {}
        _ => anyhow::bail!("n8n_update_compensation_rename_unknown"),
    }
    super::restore_binding_bytes(home, &c.original_binding).map_err(anyhow::Error::msg)?;
    if !start_was_dispatched {
        c.phase = Phase::CompensateOldLive;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.source_was_running
        && !runner
            .running_exact(&c.source_container_id)
            .await
            .map_err(anyhow::Error::msg)?
    {
        if start_was_dispatched {
            anyhow::bail!("n8n_update_compensation_start_unknown")
        }
        c.phase = Phase::CompensateOldStartDispatched;
        write(home, c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(&c.source_container_id).await;
    }
    if runner
        .running_exact(&c.source_container_id)
        .await
        .map_err(anyhow::Error::msg)?
        != c.source_was_running
    {
        anyhow::bail!("n8n_update_compensation_start_unknown")
    }
    c.phase = Phase::Compensated;
    write(home, c).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Remove only exact Update-owned resources after the original runtime is
/// back.  A dispatched removal is never repeated; its next call observes it.
async fn cleanup_owned<R: ManagedDockerRunner>(
    home: &Path,
    runner: &mut R,
    c: &mut Custody,
) -> Result<()> {
    let job = JobId::parse(c.update_job_id.clone()).map_err(anyhow::Error::msg)?;
    if c.phase == Phase::Compensated {
        if let Some(id) = c.candidate_id.as_deref() {
            match runner
                .inspect_update_server_candidate_exact(id)
                .await
                .map_err(anyhow::Error::msg)?
            {
                super::managed_update_candidate::InspectUpdateServerCandidateOutcome::Absent => {
                    c.phase = Phase::CleanupCandidateAbsent
                }
                super::managed_update_candidate::InspectUpdateServerCandidateOutcome::Found(
                    found,
                ) if found.id == id
                    && found.update_job_id == c.update_job_id
                    && found.image == c.runtime_image
                    && found.volume
                        == super::managed_update_candidate::update_volume_name(&job) =>
                {
                    c.phase = Phase::CleanupCandidateRemoveDispatched;
                    write(home, c).map_err(anyhow::Error::msg)?;
                    let _ = runner.remove(id).await;
                }
                _ => anyhow::bail!("n8n_update_cleanup_candidate_unknown"),
            }
        } else {
            c.phase = Phase::CleanupCandidateAbsent
        };
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupCandidateRemoveDispatched {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_cleanup_candidate_unknown"))?;
        if !matches!(
            runner
                .inspect_update_server_candidate_exact(id)
                .await
                .map_err(anyhow::Error::msg)?,
            super::managed_update_candidate::InspectUpdateServerCandidateOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_cleanup_candidate_unknown")
        };
        c.phase = Phase::CleanupCandidateAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupCandidateAbsent {
        if let Some(id) = c.seed_id.as_deref() {
            match runner
                .inspect_update_seed_exact(id)
                .await
                .map_err(anyhow::Error::msg)?
            {
                super::managed_update_candidate::InspectUpdateSeedOutcome::Absent => {
                    c.phase = Phase::CleanupSeedAbsent
                }
                super::managed_update_candidate::InspectUpdateSeedOutcome::Found(found)
                    if found.id == id
                        && found.update_job_id == c.update_job_id
                        && found.image == c.source_image
                        && found.volume
                            == super::managed_update_candidate::update_volume_name(&job) =>
                {
                    c.phase = Phase::CleanupSeedRemoveDispatched;
                    write(home, c).map_err(anyhow::Error::msg)?;
                    let _ = runner.remove(id).await;
                }
                _ => anyhow::bail!("n8n_update_cleanup_seed_unknown"),
            }
        } else {
            c.phase = Phase::CleanupSeedAbsent
        };
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupSeedRemoveDispatched {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_cleanup_seed_unknown"))?;
        if !matches!(
            runner
                .inspect_update_seed_exact(id)
                .await
                .map_err(anyhow::Error::msg)?,
            super::managed_update_candidate::InspectUpdateSeedOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_cleanup_seed_unknown")
        };
        c.phase = Phase::CleanupSeedAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupSeedAbsent {
        match runner
            .inspect_update_volume_exact(&job)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectVolumeOutcome::Absent => c.phase = Phase::CleanupVolumeAbsent,
            InspectVolumeOutcome::Found(found)
                if found.name == super::managed_update_candidate::update_volume_name(&job)
                    && super::managed_update_candidate::valid_update_volume_labels(
                        &found.labels,
                        &job,
                    ) =>
            {
                c.phase = Phase::CleanupVolumeRemoveDispatched;
                write(home, c).map_err(anyhow::Error::msg)?;
                let _ = runner.remove_volume(&found.name).await;
            }
            _ => anyhow::bail!("n8n_update_cleanup_volume_unknown"),
        };
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupVolumeRemoveDispatched {
        if !matches!(
            runner
                .inspect_update_volume_exact(&job)
                .await
                .map_err(anyhow::Error::msg)?,
            InspectVolumeOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_cleanup_volume_unknown")
        };
        c.phase = Phase::CleanupVolumeAbsent;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CleanupVolumeAbsent {
        c.phase = Phase::CleanupComplete;
        write(home, c).map_err(anyhow::Error::msg)?;
    }
    if c.phase != Phase::CleanupComplete {
        anyhow::bail!("n8n_update_cleanup_phase_invalid")
    }
    Ok(())
}

async fn compensate_and_fail<R: ManagedDockerRunner>(
    service: &IntegrationJobService,
    home: &Path,
    runner: &mut R,
    active: &IntegrationJob,
    c: &mut Custody,
    code: &str,
) -> Result<IntegrationJob> {
    match c.failure_code.as_deref() {
        Some(existing) if existing != code => anyhow::bail!("n8n_update_failure_code_mismatch"),
        Some(_) => {}
        None => {
            c.failure_code = Some(code.into());
            write(home, c).map_err(anyhow::Error::msg)?;
        }
    }
    if !matches!(
        c.phase,
        Phase::Compensated
            | Phase::CleanupCandidateRemoveDispatched
            | Phase::CleanupCandidateAbsent
            | Phase::CleanupSeedRemoveDispatched
            | Phase::CleanupSeedAbsent
            | Phase::CleanupVolumeRemoveDispatched
            | Phase::CleanupVolumeAbsent
            | Phase::CleanupComplete
    ) {
        compensate(home, runner, c).await?;
    }
    cleanup_owned(home, runner, c).await?;
    if c.phase != Phase::CleanupComplete {
        anyhow::bail!("n8n_update_cleanup_incomplete");
    }
    let current = service
        .get(&active.job_id)?
        .ok_or_else(|| anyhow::anyhow!("n8n_update_job_missing"))?;
    let failed = service.fail(
        &current.job_id,
        current.state_revision,
        JobFailure::new(
            code,
            "The managed n8n update did not complete; the original runtime was restored.",
        )
        .map_err(|_| anyhow::anyhow!("n8n_update_failure_code_invalid"))?,
    )?;
    crate::util::atomic_write::durable_remove_file(&custody_path(home))
        .map_err(|_| anyhow::anyhow!("n8n_update_custody_retire_failed"))?;
    Ok(failed)
}

pub(crate) fn reject_pending_update(home: &Path) -> std::result::Result<(), &'static str> {
    if read(home)?.is_some() {
        Err("n8n_update_custody_pending")
    } else {
        Ok(())
    }
}

struct ExplicitUpdateRestartValidator {
    home: PathBuf,
}

impl RestartValidator for ExplicitUpdateRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation != JobOperation::Update {
            return super::super::N8nRestartValidator::new(&self.home).validate(job);
        }
        if let Ok(Some(custody)) = read(&self.home)
            && validate_custody(&self.home, &custody, job).is_ok()
            && let Some(contract) = job.evidence_contract.as_ref()
        {
            let phase = format!("{:?}", custody.phase);
            let observed = sha256_parts(&[
                "n8n-update-observe-only-recovery",
                &custody.update_job_id,
                &custody.update_manifest_sha256,
                &phase,
            ]);
            return RestartDecision::Resume {
                evidence: ResumeEvidence::verified(
                    job.job_id.clone(),
                    job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(),
                    observed.clone(),
                ),
                disposition: RecoveryDispositionEvidence::verified(
                    job.job_id.clone(),
                    job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(),
                    job.state_revision,
                    sha256_parts(&["n8n-update-custody-retained"]),
                    observed,
                ),
            };
        }
        RestartDecision::Hold {
            failure: JobFailure::new(
                "n8n_update_reconciliation_required",
                "The interrupted update retains exact source, candidate, and publication custody; rerun n8n update only after its durable effects can be observed.",
            ).expect("static failure is valid"),
        }
    }
}

fn open_update_service(home: &Path) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(
        home,
        super::super::n8n_catalog(),
        &ExplicitUpdateRestartValidator {
            home: home.to_owned(),
        },
    )?)
}

fn receipt_evidence(
    c: &Custody,
    new_id: &str,
    archive: &str,
    bytes: u64,
) -> crate::integrations::state::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-update-receipt-v1",
        &c.update_job_id,
        &c.update_manifest_sha256,
        &c.selector,
        &c.version,
        &c.platform,
        &c.runtime_image,
        &c.repo_digest,
        &c.catalog_evidence_sha256,
        &c.index_digest,
        &c.child_manifest_digest,
        &c.config_digest,
        &c.source_job_id,
        &c.source_manifest_sha256,
        &c.source_container_id,
        &c.source_image,
        &c.source_volume,
        &c.host_port.to_string(),
        archive,
        &bytes.to_string(),
        new_id,
        &c.retained_source_name,
        &c.baseline_workflow_count.unwrap_or(0).to_string(),
        &c.baseline_credential_count.unwrap_or(0).to_string(),
        c.baseline_content_sha256.as_deref().unwrap_or(""),
        &c.migrated_workflow_count.unwrap_or(0).to_string(),
        &c.migrated_credential_count.unwrap_or(0).to_string(),
        c.migrated_content_sha256.as_deref().unwrap_or(""),
    ])
}
fn receipt_from(c: &Custody) -> Result<UpdateReceiptView> {
    let archive = c
        .archive_sha256
        .clone()
        .ok_or_else(|| anyhow::anyhow!("n8n_update_archive_missing"))?;
    let bytes = c
        .archive_bytes
        .ok_or_else(|| anyhow::anyhow!("n8n_update_archive_missing"))?;
    let new_id = c
        .new_container_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("n8n_update_new_id_missing"))?;
    let workflows = c
        .baseline_workflow_count
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    let credentials = c
        .baseline_credential_count
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    let content = c
        .baseline_content_sha256
        .clone()
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    let migrated_workflows = c
        .migrated_workflow_count
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    let migrated_credentials = c
        .migrated_credential_count
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    let migrated_content = c
        .migrated_content_sha256
        .clone()
        .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
    Ok(UpdateReceiptView {
        schema_version: 1,
        update_job_id: c.update_job_id.clone(),
        update_manifest_sha256: c.update_manifest_sha256.clone(),
        selector: c.selector.clone(),
        version: c.version.clone(),
        platform: c.platform.clone(),
        runtime_image: c.runtime_image.clone(),
        repo_digest: c.repo_digest.clone(),
        catalog_evidence_sha256: c.catalog_evidence_sha256.clone(),
        index_digest: c.index_digest.clone(),
        child_manifest_digest: c.child_manifest_digest.clone(),
        config_digest: c.config_digest.clone(),
        source_job_id: c.source_job_id.clone(),
        source_manifest_sha256: c.source_manifest_sha256.clone(),
        source_container_id: c.source_container_id.clone(),
        source_image: c.source_image.clone(),
        source_volume: c.source_volume.clone(),
        host_port: c.host_port,
        source_archive_sha256: archive.clone(),
        source_archive_bytes: bytes,
        update_volume: super::managed_update_candidate::update_volume_name(
            &JobId::parse(c.update_job_id.clone()).map_err(anyhow::Error::msg)?,
        ),
        new_container_id: new_id.clone(),
        retained_source_container_id: c.source_container_id.clone(),
        retained_source_name: c.retained_source_name.clone(),
        baseline_workflow_count: workflows,
        baseline_credential_count: credentials,
        baseline_content_sha256: content,
        migrated_workflow_count: migrated_workflows,
        migrated_credential_count: migrated_credentials,
        migrated_content_sha256: migrated_content,
        evidence_sha256: receipt_evidence(c, &new_id, &archive, bytes)
            .as_str()
            .into(),
    })
}

fn receipt_manifest(r: &UpdateReceiptView) -> crate::integrations::state::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-update-v1",
        &r.selector,
        &r.version,
        &r.platform,
        &r.runtime_image,
        &r.repo_digest,
        &r.index_digest,
        &r.child_manifest_digest,
        &r.config_digest,
        &r.catalog_evidence_sha256,
        &r.source_job_id,
        &r.source_manifest_sha256,
        &r.source_container_id,
        &r.source_image,
        &r.source_volume,
        &r.host_port.to_string(),
    ])
}

/// Non-cyclic immutable receipt resolver.  It intentionally validates only the
/// Ready Update job, compiled target, exact source job and archive bytes.
pub(crate) fn completed_receipt_at(
    home: &Path,
    job: &IntegrationJob,
) -> std::result::Result<Option<UpdateReceiptView>, &'static str> {
    if job.operation != JobOperation::Update || job.state != JobState::Ready {
        return Ok(None);
    }
    let r = read_receipt(home, job.job_id.as_str())?.ok_or("n8n_update_receipt_missing")?;
    let target = super::super::managed_update_target::resolve_admitted_target(&r.selector)
        .map_err(|_| "n8n_update_receipt_target_invalid")?;
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_update_receipt_source_read_failed")?;
    let source = jobs
        .iter()
        .find(|j| j.job_id.as_str() == r.source_job_id)
        .ok_or("n8n_update_receipt_source_missing")?;
    if r.schema_version != 1
        || r.update_job_id != job.job_id.as_str()
        || r.update_manifest_sha256 != job.manifest_sha256.as_str()
        || r.update_manifest_sha256 != receipt_manifest(&r).as_str()
        || r.selector != target.selector
        || r.version != target.version
        || r.runtime_image != target.runtime_image
        || r.repo_digest != target.repo_digest
        || r.index_digest != target.index_digest
        || r.catalog_evidence_sha256 != target.catalog_evidence_sha256
        || !target.platforms.iter().any(|p| {
            format!("{}/{}", p.os, p.architecture) == r.platform
                && p.child_manifest_digest == r.child_manifest_digest
        })
        || !valid_oci_digest(&r.config_digest)
        || source.job_id.as_str() != r.source_job_id
        || source.manifest_sha256.as_str() != r.source_manifest_sha256
        || !matches!(
            source.operation,
            JobOperation::Install | JobOperation::Rollback | JobOperation::Update
        )
        || source.state != JobState::Ready
        || !is_managed_job(source)
        || !valid_container_id(&r.source_container_id)
        || !valid_container_id(&r.new_container_id)
        || !valid_container_id(&r.retained_source_container_id)
        || r.retained_source_container_id != r.source_container_id
        || !super::valid_retired_container_name(&r.retained_source_name)
        || !valid_volume_name(&r.source_volume)
        || r.host_port == 0
        || !super::valid_historical_n8n_image(&r.source_image)
        || !super::managed_update_candidate::valid_update_volume_name(&r.update_volume, &job.job_id)
        || !valid_manifest_sha256(&r.source_archive_sha256)
        || r.source_archive_bytes == 0
        || r.source_archive_bytes > MAX_ARCHIVE_BYTES
        || r.baseline_workflow_count != r.migrated_workflow_count
        || r.baseline_credential_count != r.migrated_credential_count
        || !valid_manifest_sha256(&r.baseline_content_sha256)
        || r.baseline_content_sha256 != r.migrated_content_sha256
    {
        return Err("n8n_update_receipt_mismatch");
    }
    let c = Custody {
        schema_version: 1,
        phase: Phase::ReceiptPrepared,
        update_job_id: r.update_job_id.clone(),
        update_manifest_sha256: r.update_manifest_sha256.clone(),
        selector: r.selector.clone(),
        platform: r.platform.clone(),
        version: r.version.clone(),
        runtime_image: r.runtime_image.clone(),
        repo_digest: r.repo_digest.clone(),
        catalog_evidence_sha256: r.catalog_evidence_sha256.clone(),
        index_digest: r.index_digest.clone(),
        child_manifest_digest: r.child_manifest_digest.clone(),
        config_digest: r.config_digest.clone(),
        source_job_id: r.source_job_id.clone(),
        source_manifest_sha256: r.source_manifest_sha256.clone(),
        source_container_id: r.source_container_id.clone(),
        source_image: r.source_image.clone(),
        source_volume: r.source_volume.clone(),
        host_port: r.host_port,
        source_was_running: false,
        original_binding: Vec::new(),
        original_binding_sha256: String::new(),
        archive_sha256: Some(r.source_archive_sha256.clone()),
        archive_bytes: Some(r.source_archive_bytes),
        baseline_workflow_count: Some(r.baseline_workflow_count),
        baseline_credential_count: Some(r.baseline_credential_count),
        baseline_content_sha256: Some(r.baseline_content_sha256.clone()),
        migrated_workflow_count: Some(r.migrated_workflow_count),
        migrated_credential_count: Some(r.migrated_credential_count),
        migrated_content_sha256: Some(r.migrated_content_sha256.clone()),
        failure_code: None,
        seed_id: None,
        candidate_id: None,
        new_container_id: Some(r.new_container_id.clone()),
        retained_source_name: r.retained_source_name.clone(),
    };
    if r.evidence_sha256
        != receipt_evidence(
            &c,
            &r.new_container_id,
            &r.source_archive_sha256,
            r.source_archive_bytes,
        )
        .as_str()
    {
        return Err("n8n_update_receipt_mismatch");
    }
    archive_matches(
        &archive_path(home, job.job_id.as_str()),
        r.source_archive_bytes,
        &r.source_archive_sha256,
    )?;
    Ok(Some(r))
}

fn source(home: &Path) -> Result<(RuntimeBinding, IntegrationJob, Vec<u8>)> {
    let b = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("n8n_update_runtime_missing"))?;
    let raw = read_binding_bytes(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("n8n_update_binding_missing"))?;
    let j = IntegrationJobService::read_only_snapshot(home)?
        .into_iter()
        .find(|j| j.job_id.as_str() == b.job_id && j.manifest_sha256.as_str() == b.manifest_sha256)
        .ok_or_else(|| anyhow::anyhow!("n8n_update_source_missing"))?;
    if !is_active_runtime_source(home, &b, &j) || !is_managed_job(&j) || b.container_id.is_none() {
        anyhow::bail!("n8n_update_source_not_ready")
    }
    Ok((b, j, raw))
}
fn enqueue(
    service: &IntegrationJobService,
    target: &super::super::managed_update_target::TargetImageProof,
    source: &IntegrationJob,
    binding: &RuntimeBinding,
) -> Result<IntegrationJob> {
    let manifest = sha256_parts(&[
        "n8n-managed-update-v1",
        &target.selector,
        &target.version,
        &target.platform,
        &target.runtime_image,
        &target.repo_digest,
        &target.index_digest,
        &target.child_manifest_digest,
        &target.config_digest,
        &target.catalog_evidence_sha256,
        source.job_id.as_str(),
        source.manifest_sha256.as_str(),
        binding.container_id.as_deref().unwrap_or(""),
        &binding.image,
        &binding.volume,
        &binding.host_port.to_string(),
    ]);
    Ok(service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static"),
            operation: JobOperation::Update,
            release_version: "1.4.0".into(),
            manifest_sha256: manifest.clone(),
            evidence_contract: JobEvidenceContract::verified(
                manifest,
                sha256_parts(&["n8n-update", target.runtime_image.as_str(), &binding.volume]),
                super::super::expected_authenticated_probe_sha256(&binding_endpoint(binding)?),
                sha256_parts(&STEPS),
            ),
            requested_by: JobRequester::Cli,
            total_steps: STEPS.len() as u32,
            bytes_total: None,
        })?
        .job)
}
fn binding_endpoint(binding: &RuntimeBinding) -> Result<crate::config::LoopbackHttpEndpoint> {
    crate::config::LoopbackHttpEndpoint::parse(format!("http://127.0.0.1:{}", binding.host_port))
        .map_err(|_| anyhow::anyhow!("n8n_update_endpoint_invalid"))
}

/// Production entrypoint.  Target proof is made through the managed engine;
/// the old standalone preflight command is not part of this lifecycle.
pub(crate) async fn update_managed_at(
    home: &Path,
    selector: &str,
    platform: &str,
    api_key: SecretString,
) -> Result<IntegrationJob> {
    let reader = super::super::managed_update_target::DockerHubRegistryTargetReader::new()?;
    update_managed_at_with(
        home,
        selector,
        platform,
        api_key,
        &mut super::DockerManagedRunner,
        &reader,
        &super::ProductionReadiness,
        &super::HttpN8nApiProbe,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_managed_at_with<R, D, H, P>(
    home: &Path,
    selector: &str,
    platform: &str,
    api_key: SecretString,
    runner: &mut R,
    reader: &D,
    readiness: &H,
    probe: &P,
) -> Result<IntegrationJob>
where
    R: ManagedDockerRunner + super::super::managed_update_target::UpdateTargetDockerRunner,
    D: super::super::managed_update_target::RegistryTargetReader,
    H: super::ManagedReadiness,
    P: super::super::N8nApiProbe + ?Sized,
{
    let _lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )?
    .ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    super::managed_backup::reject_pending_backup(home).map_err(anyhow::Error::msg)?;
    super::managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    super::managed_rollback::reject_pending_rollback(home).map_err(anyhow::Error::msg)?;
    if super::managed_repair::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::managed_uninstall::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::super::managed_purge::repair_has_pending_custody(home)
            .map_err(anyhow::Error::msg)?
    {
        anyhow::bail!("n8n_update_conflicting_custody")
    }
    let existing = read(home).map_err(anyhow::Error::msg)?;
    let service = open_update_service(home)?;
    let (binding, queued, mut c, target) = if let Some(c) = existing {
        let target = super::super::managed_update_target::resolve_admitted_target(&c.selector)
            .map_err(|_| anyhow::anyhow!("n8n_update_custody_target_invalid"))?;
        if c.platform != platform
            || c.selector != selector
            || c.runtime_image != target.runtime_image
            || c.version != target.version
            || c.repo_digest != target.repo_digest
            || c.index_digest != target.index_digest
            || c.catalog_evidence_sha256 != target.catalog_evidence_sha256
            || !target.platforms.iter().any(|p| {
                format!("{}/{}", p.os, p.architecture) == c.platform
                    && p.child_manifest_digest == c.child_manifest_digest
            })
        {
            anyhow::bail!("n8n_update_custody_mismatch")
        }
        let id = JobId::parse(c.update_job_id.clone()).map_err(anyhow::Error::msg)?;
        let job = service
            .get(&id)?
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_job_missing"))?;
        validate_custody(home, &c, &job).map_err(anyhow::Error::msg)?;
        let binding: RuntimeBinding = serde_json::from_slice(&c.original_binding)
            .map_err(|_| anyhow::anyhow!("n8n_update_custody_original_binding_invalid"))?;
        (binding, job, c, target)
    } else {
        if let Some(active) = read_binding(home).map_err(anyhow::Error::msg)?
            && let RuntimeLineage::Update(lineage) = &active.lineage
            && active.phase == RuntimePhase::Ready
            && lineage.admitted_selector == selector
        {
            if lineage.admitted_platform != platform {
                anyhow::bail!("n8n_update_active_platform_mismatch");
            }
            let id = JobId::parse(active.job_id.clone()).map_err(anyhow::Error::msg)?;
            let job = service
                .get(&id)?
                .ok_or_else(|| anyhow::anyhow!("n8n_update_active_job_missing"))?;
            super::validate_active_runtime_lineage(home, &active, &job)
                .map_err(anyhow::Error::msg)?;
            if completed_receipt_at(home, &job)
                .map_err(anyhow::Error::msg)?
                .is_none()
            {
                anyhow::bail!("n8n_update_ready_receipt_missing");
            }
            return Ok(job);
        }
        let target = super::super::managed_update_target::resolve_admitted_target(selector)
            .map_err(|_| anyhow::anyhow!("n8n_update_target_invalid"))?;
        let proof = super::super::managed_update_target::prove_admitted_target_with(
            &target, platform, reader, runner,
        )
        .await?;
        let (binding, source, raw) = source(home)?;
        let queued = enqueue(&service, &proof, &source, &binding)?;
        let old_id = binding
            .container_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_source_not_ready"))?;
        let c = Custody {
            schema_version: 1,
            phase: Phase::IntentPersisted,
            update_job_id: queued.job_id.as_str().into(),
            update_manifest_sha256: queued.manifest_sha256.as_str().into(),
            selector: proof.selector.clone(),
            platform: proof.platform.clone(),
            version: proof.version.clone(),
            runtime_image: proof.runtime_image.clone(),
            repo_digest: proof.repo_digest.clone(),
            catalog_evidence_sha256: proof.catalog_evidence_sha256.clone(),
            index_digest: proof.index_digest.clone(),
            child_manifest_digest: proof.child_manifest_digest.clone(),
            config_digest: proof.config_digest.clone(),
            source_job_id: source.job_id.as_str().into(),
            source_manifest_sha256: source.manifest_sha256.as_str().into(),
            source_container_id: old_id.clone(),
            source_image: binding.image.clone(),
            source_volume: binding.volume.clone(),
            host_port: binding.host_port,
            source_was_running: runner
                .running_exact(&old_id)
                .await
                .map_err(anyhow::Error::msg)?,
            original_binding_sha256: format!("{:x}", Sha256::digest(&raw)),
            original_binding: raw,
            archive_sha256: None,
            archive_bytes: None,
            baseline_workflow_count: None,
            baseline_credential_count: None,
            baseline_content_sha256: None,
            migrated_workflow_count: None,
            migrated_credential_count: None,
            migrated_content_sha256: None,
            failure_code: None,
            seed_id: None,
            candidate_id: None,
            new_container_id: None,
            retained_source_name: retired_container_name(queued.job_id.as_str())
                .map_err(anyhow::Error::msg)?,
        };
        create(home, &c).map_err(anyhow::Error::msg)?;
        (binding, queued, c, target)
    };
    if c.update_job_id != queued.job_id.as_str()
        || c.update_manifest_sha256 != queued.manifest_sha256.as_str()
    {
        anyhow::bail!("n8n_update_custody_mismatch")
    }
    let active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        s if s.is_active() => queued,
        JobState::Ready => {
            if completed_receipt_at(home, &queued)
                .map_err(anyhow::Error::msg)?
                .is_none()
            {
                anyhow::bail!("n8n_update_ready_receipt_missing");
            }
            let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
                &home.join("freedom.yaml"),
                &home.join("credentials.yaml"),
                queued.job_id.as_str(),
            );
            crate::util::atomic_write::durable_remove_file(&custody_path(home))
                .map_err(|_| anyhow::anyhow!("n8n_update_custody_retire_failed"))?;
            return Ok(queued);
        }
        JobState::Failed
            if c.phase == Phase::CleanupComplete
                && c.failure_code.as_deref()
                    == queued.failure.as_ref().map(|failure| failure.code.as_str()) =>
        {
            crate::util::atomic_write::durable_remove_file(&custody_path(home))
                .map_err(|_| anyhow::anyhow!("n8n_update_custody_retire_failed"))?;
            return Ok(queued);
        }
        _ => anyhow::bail!("n8n_update_job_terminal"),
    };
    if let Some(code) = c.failure_code.clone() {
        return compensate_and_fail(&service, home, runner, &active, &mut c, &code).await;
    }
    if c.phase == Phase::IntentPersisted {
        c.phase = Phase::TargetProved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::TargetProved {
        if !matches!(runner.inspect_exact_named(&c.source_container_id,MANAGED_CONTAINER_NAME).await.map_err(anyhow::Error::msg)?,InspectOutcome::Found(found) if source_observation_matches(&c,&found))
        {
            anyhow::bail!("n8n_update_source_identity_unknown")
        }
        if c.source_was_running {
            c.phase = Phase::SourceStopDispatched;
            write(home, &c).map_err(anyhow::Error::msg)?;
            let _ = runner.stop_exact(&c.source_container_id).await;
        } else {
            c.phase = Phase::SourceStopped;
            write(home, &c).map_err(anyhow::Error::msg)?;
        }
    }
    if c.phase == Phase::SourceStopDispatched {
        if runner
            .running_exact(&c.source_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_update_stop_outcome_unknown")
        };
        c.phase = Phase::SourceStopped;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::SourceStopped {
        if !matches!(runner.inspect_exact_named(&c.source_container_id,MANAGED_CONTAINER_NAME).await.map_err(anyhow::Error::msg)?,InspectOutcome::Found(found) if source_observation_matches(&c,&found))
            || runner
                .running_exact(&c.source_container_id)
                .await
                .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_update_source_snapshot_not_stopped")
        }
        c.phase = Phase::ArchiveDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let p = ensure_private_archive_dir(home)?.join(format!("{}.tar", c.update_job_id));
        let r = runner
            .archive_exact_n8n_dir_to_private_file(&c.source_container_id, &p, MAX_ARCHIVE_BYTES)
            .await
            .map_err(anyhow::Error::msg)?;
        if !valid_manifest_sha256(&r.archive_sha256) || r.archive_bytes == 0 {
            anyhow::bail!("n8n_update_archive_invalid")
        }
        c.archive_sha256 = Some(r.archive_sha256);
        c.archive_bytes = Some(r.archive_bytes);
        c.phase = Phase::ArchiveCaptured;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    let jid = JobId::parse(c.update_job_id.clone()).map_err(anyhow::Error::msg)?;
    let volume = super::managed_update_candidate::update_volume_name(&jid);
    if c.phase == Phase::ArchiveCaptured {
        c.phase = Phase::VolumeCreateDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner
            .create_update_volume_exact(super::managed_update_candidate::UpdateVolumeSpec {
                update_job_id: &jid,
            })
            .await;
    }
    if c.phase == Phase::VolumeCreateDispatched {
        match runner
            .inspect_update_volume_exact(&jid)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectVolumeOutcome::Found(v)
                if v.name == volume
                    && super::managed_update_candidate::valid_update_volume_labels(
                        &v.labels, &jid,
                    ) => {}
            _ => anyhow::bail!("n8n_update_volume_outcome_unknown"),
        };
        c.phase = Phase::VolumeObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::VolumeObserved {
        c.phase = Phase::SeedCreateDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let x = runner
            .create_update_seed_exact(super::managed_update_candidate::UpdateSeedSpec {
                update_job_id: &jid,
                image: &c.source_image,
                volume: &volume,
            })
            .await
            .map_err(anyhow::Error::msg)?;
        c.seed_id = x.container_id.filter(|id| valid_container_id(id));
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::SeedCreateDispatched {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_seed_outcome_unknown"))?;
        match runner
            .inspect_update_seed_exact(id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            super::managed_update_candidate::InspectUpdateSeedOutcome::Found(x)
                if !x.running
                    && x.image == c.source_image
                    && x.update_job_id == c.update_job_id
                    && x.volume == volume => {}
            _ => anyhow::bail!("n8n_update_seed_outcome_unknown"),
        };
        c.phase = Phase::SeedObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::SeedObserved {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_seed_missing"))?;
        let archive = c
            .archive_sha256
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_archive_invalid"))?;
        let bytes = c
            .archive_bytes
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_archive_invalid"))?;
        c.phase = Phase::SeedExtractDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let r = runner
            .extract_private_archive_to_exact_container(
                &archive_path(home, &c.update_job_id),
                archive,
                bytes,
                id,
            )
            .await
            .map_err(anyhow::Error::msg)?;
        if r.archive_sha256 != archive || r.archive_bytes != bytes {
            anyhow::bail!("n8n_update_extract_mismatch")
        }
        c.phase = Phase::SeedExtracted;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::SeedExtractDispatched {
        anyhow::bail!("n8n_update_seed_copy_outcome_unknown")
    }
    // Content fingerprint implementation is provided by managed_update_content;
    // its call is deliberately after source-image copy and before any rename.
    if c.phase == Phase::SeedExtracted {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_seed_missing"))?;
        c.phase = Phase::SeedStartDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(id).await;
    }
    if c.phase == Phase::SeedStartDispatched {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_seed_missing"))?;
        if !runner.running_exact(id).await.map_err(anyhow::Error::msg)? {
            anyhow::bail!("n8n_update_seed_start_unknown")
        };
        let f = runner
            .fingerprint_update_candidate_exact(id)
            .await
            .map_err(anyhow::Error::msg)?;
        c.baseline_workflow_count = Some(f.workflow_count);
        c.baseline_credential_count = Some(f.credential_count);
        c.baseline_content_sha256 = Some(f.content_sha256);
        c.phase = Phase::BaselineObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::BaselineObserved {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_seed_missing"))?;
        c.phase = Phase::SeedRemoveDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner.remove(id).await;
    }
    if c.phase == Phase::SeedRemoveDispatched {
        let id = c
            .seed_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_seed_missing"))?;
        if !matches!(
            runner
                .inspect_update_seed_exact(id)
                .await
                .map_err(anyhow::Error::msg)?,
            super::managed_update_candidate::InspectUpdateSeedOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_seed_remove_unknown")
        };
        c.phase = Phase::SeedAbsent;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::SeedAbsent {
        c.phase = Phase::CandidateCreateDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let x = runner
            .create_update_server_candidate_exact(
                super::managed_update_candidate::UpdateServerCandidateSpec {
                    update_job_id: &jid,
                    image: &c.runtime_image,
                    volume: &volume,
                },
            )
            .await
            .map_err(anyhow::Error::msg)?;
        c.candidate_id = x.container_id.filter(|id| valid_container_id(id));
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CandidateCreateDispatched {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_candidate_outcome_unknown"))?;
        match runner
            .inspect_update_server_candidate_exact(id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            super::managed_update_candidate::InspectUpdateServerCandidateOutcome::Found(x)
                if !x.running
                    && x.image == c.runtime_image
                    && x.update_job_id == c.update_job_id
                    && x.volume == volume => {}
            _ => anyhow::bail!("n8n_update_candidate_outcome_unknown"),
        };
        c.phase = Phase::CandidateObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CandidateObserved {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_candidate_missing"))?;
        c.phase = Phase::CandidateStartDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner.start_exact(id).await;
    }
    if c.phase == Phase::CandidateStartDispatched {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_candidate_missing"))?;
        if !runner.running_exact(id).await.map_err(anyhow::Error::msg)? {
            anyhow::bail!("n8n_update_candidate_start_unknown")
        };
        c.phase = Phase::CandidateStarted;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::CandidateStarted {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_candidate_missing"))?;
        if !wait_candidate_ready(runner, id).await? {
            return compensate_and_fail(
                &service,
                home,
                runner,
                &active,
                &mut c,
                "n8n_update_candidate_not_ready",
            )
            .await;
        };
        let migrated = runner
            .fingerprint_update_candidate_exact(id)
            .await
            .map_err(anyhow::Error::msg)?;
        let baseline = super::managed_update_content::UpdateContentFingerprint {
            workflow_count: c
                .baseline_workflow_count
                .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?,
            credential_count: c
                .baseline_credential_count
                .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?,
            content_sha256: c
                .baseline_content_sha256
                .clone()
                .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?,
        };
        if super::managed_update_content::UpdateContentProof::new(baseline, migrated.clone())
            .is_err()
        {
            return compensate_and_fail(
                &service,
                home,
                runner,
                &active,
                &mut c,
                "n8n_update_content_mismatch",
            )
            .await;
        };
        c.migrated_workflow_count = Some(migrated.workflow_count);
        c.migrated_credential_count = Some(migrated.credential_count);
        c.migrated_content_sha256 = Some(migrated.content_sha256);
        c.phase = Phase::MigrationObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    // Candidate must be removed before reusing the live name.  The source is
    // still retained under its original name until the next durable phase.
    if c.phase == Phase::MigrationObserved {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_candidate_missing"))?;
        c.phase = Phase::CandidateRemoveDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner.remove(id).await;
    }
    if c.phase == Phase::CandidateRemoveDispatched {
        let id = c
            .candidate_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_candidate_missing"))?;
        if !matches!(
            runner
                .inspect_update_server_candidate_exact(id)
                .await
                .map_err(anyhow::Error::msg)?,
            super::managed_update_candidate::InspectUpdateServerCandidateOutcome::Absent
        ) {
            anyhow::bail!("n8n_update_candidate_remove_unknown")
        };
        c.phase = Phase::ContentObserved;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::ContentObserved {
        if !matches!(runner.inspect_exact_named(&c.source_container_id,MANAGED_CONTAINER_NAME).await.map_err(anyhow::Error::msg)?,InspectOutcome::Found(x) if source_observation_matches(&c,&x))
        {
            anyhow::bail!("n8n_update_source_name_unknown")
        };
        c.phase = Phase::OldRenameDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let _ = runner
            .rename_exact(&c.source_container_id, &c.retained_source_name)
            .await;
    }
    if c.phase == Phase::OldRenameDispatched {
        match runner
            .inspect_exact_named(&c.source_container_id, &c.retained_source_name)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectOutcome::Found(x) if source_observation_matches(&c, &x) => {}
            _ => anyhow::bail!("n8n_update_rename_outcome_unknown"),
        };
        c.phase = Phase::OldRenamed;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::OldRenamed {
        let request =
            ManagedN8nRequest::admitted_update(binding.host_port, &target, volume.clone())
                .map_err(anyhow::Error::msg)?;
        c.phase = Phase::LiveCreateDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
        let x = runner
            .create_with_exact_id(&request.create_command(active.job_id.as_str()))
            .await
            .map_err(anyhow::Error::msg)?;
        c.new_container_id = x.container_id.filter(|id| valid_container_id(id));
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::LiveCreateDispatched {
        let id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_live_create_unknown"))?;
        match runner
            .inspect_exact_named(id, MANAGED_CONTAINER_NAME)
            .await
            .map_err(anyhow::Error::msg)?
        {
            InspectOutcome::Found(x) if live_observation_matches(&c, &x) => {}
            _ => anyhow::bail!("n8n_update_live_create_unknown"),
        };
        c.phase = Phase::LiveCreated;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::LiveCreated {
        let id = c
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_live_missing"))?;
        let archive = c
            .archive_sha256
            .clone()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_archive_invalid"))?;
        let archive_bytes = c
            .archive_bytes
            .ok_or_else(|| anyhow::anyhow!("n8n_update_custody_archive_invalid"))?;
        let baseline_workflows = c
            .baseline_workflow_count
            .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?;
        let baseline_credentials = c
            .baseline_credential_count
            .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?;
        let baseline_content = c
            .baseline_content_sha256
            .clone()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_baseline_missing"))?;
        let migrated_workflows = c
            .migrated_workflow_count
            .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
        let migrated_credentials = c
            .migrated_credential_count
            .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
        let migrated_content = c
            .migrated_content_sha256
            .clone()
            .ok_or_else(|| anyhow::anyhow!("n8n_update_content_missing"))?;
        if !wait_live_ready(runner, readiness, id, binding.host_port).await {
            return compensate_and_fail(
                &service,
                home,
                runner,
                &active,
                &mut c,
                "n8n_update_live_not_ready",
            )
            .await;
        };
        let b = RuntimeBinding {
            schema_version: 4,
            phase: RuntimePhase::Ready,
            job_id: c.update_job_id.clone(),
            manifest_sha256: c.update_manifest_sha256.clone(),
            container_name: MANAGED_CONTAINER_NAME.into(),
            container_id: Some(id.into()),
            image: c.runtime_image.clone(),
            host_port: binding.host_port,
            volume: volume.clone(),
            retained_reinstall: None,
            bootstrap_volume_owner_job_id: None,
            lineage: RuntimeLineage::Update(UpdateRuntimeLineage {
                update_job_id: c.update_job_id.clone(),
                update_manifest_sha256: c.update_manifest_sha256.clone(),
                admitted_selector: c.selector.clone(),
                admitted_version: c.version.clone(),
                admitted_platform: c.platform.clone(),
                admitted_runtime_image: c.runtime_image.clone(),
                admitted_repo_digest: c.repo_digest.clone(),
                catalog_evidence_sha256: c.catalog_evidence_sha256.clone(),
                index_digest: c.index_digest.clone(),
                child_manifest_digest: c.child_manifest_digest.clone(),
                config_digest: c.config_digest.clone(),
                source_job_id: c.source_job_id.clone(),
                source_manifest_sha256: c.source_manifest_sha256.clone(),
                source_container_id: c.source_container_id.clone(),
                source_image: c.source_image.clone(),
                source_volume: c.source_volume.clone(),
                source_archive_sha256: archive,
                source_archive_bytes: archive_bytes,
                baseline_workflow_count: baseline_workflows,
                baseline_credential_count: baseline_credentials,
                baseline_content_sha256: baseline_content,
                migrated_workflow_count: migrated_workflows,
                migrated_credential_count: migrated_credentials,
                migrated_content_sha256: migrated_content,
                update_volume_owner_job_id: c.update_job_id.clone(),
                retained_source_container_id: c.source_container_id.clone(),
                retained_source_name: c.retained_source_name.clone(),
            }),
        };
        super::write_binding(home, &b).map_err(anyhow::Error::msg)?;
        c.phase = Phase::BindingPublished;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::BindingPublished {
        let r = receipt_from(&c)?;
        match read_receipt(home, &c.update_job_id).map_err(anyhow::Error::msg)? {
            Some(existing) if existing == r => {}
            Some(_) => anyhow::bail!("n8n_update_receipt_mismatch"),
            None => write_receipt(home, &r).map_err(anyhow::Error::msg)?,
        };
        c.phase = Phase::ReceiptPrepared;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::ReceiptPrepared {
        c.phase = Phase::PublishDispatched;
        write(home, &c).map_err(anyhow::Error::msg)?;
    }
    if c.phase == Phase::PublishDispatched {
        if active.state != JobState::Running {
            anyhow::bail!("n8n_update_publish_reconciliation_required");
        }
        let endpoint = binding_endpoint(&binding)?;
        let (_tx, mut cancel) = tokio::sync::oneshot::channel();
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
                c.phase = Phase::PublishedReady;
                write(home, &c).map_err(anyhow::Error::msg)?;
                let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
                    &home.join("freedom.yaml"),
                    &home.join("credentials.yaml"),
                    ready.job_id.as_str(),
                );
                crate::util::atomic_write::durable_remove_file(&custody_path(home))
                    .map_err(|_| anyhow::anyhow!("n8n_update_custody_retire_failed"))?;
                return Ok(ready);
            }
            Err(error) => {
                super::super::rollback_adoption_if_prepared(
                    home,
                    &active.job_id,
                    error.custody_may_exist,
                )
                .map_err(|_| anyhow::anyhow!("n8n_update_adoption_custody_unknown"))?;
                return compensate_and_fail(&service, home, runner, &active, &mut c, error.code)
                    .await;
            }
        }
    }
    anyhow::bail!("n8n_update_reconciliation_required")
}

#[cfg(test)]
#[path = "managed_update_tests.rs"]
mod tests;
