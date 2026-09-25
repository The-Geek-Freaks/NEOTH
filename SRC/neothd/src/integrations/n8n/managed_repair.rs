//! Same-generation repair for an already Ready managed n8n runtime.
//!
//! The repair job owns a separate, durable receipt.  It never changes the
//! source install job or its credential binding.  A recreate can only publish
//! an id returned after a successful `docker run` receipt; an uncertain create
//! is held for operator inspection and is never adopted from labels or name.

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    HttpN8nApiProbe, IntegrationJob, IntegrationJobService, JobEvidenceContract, JobOperation,
    JobRequester, ManagedDockerRunner, N8N_CAPABILITY_ID, N8nApiProbe,
    ProductionReadiness, RuntimeBinding, RuntimePhase, is_managed_job, read_binding,
    read_binding_bytes, sha256_parts, validate_binding, validate_existing_identity, write_binding,
};
use crate::{
    integrations::{
        catalog::CapabilityId,
        jobs::{EnqueueIntegrationJob, RestartValidator},
        state::{
            JobFailure, JobProgress, JobState, ProgressEvidence, ProgressEvidenceClaim,
            ReadyEvidence, RestartDecision,
        },
    },
    secret::SecretString,
};

const REPAIR_FILE: &str = "n8n-managed-repair.v1.json";
const REPAIR_GENERATION_FILE: &str = "n8n-managed-repair-generation.v1.json";
const STEPS: [&str; 5] = [
    "validate-ready-runtime-binding",
    "persist-effect-intent",
    "verify-runtime",
    "authenticated-readiness",
    "publish-repair-receipt",
];
const DEADLINE: Duration = Duration::from_secs(45);

struct ExplicitRepairRestartValidator;
impl RestartValidator for ExplicitRepairRestartValidator {
    fn validate(&self, _job: &IntegrationJob) -> RestartDecision {
        RestartDecision::Hold { failure: JobFailure::new("n8n_repair_reconciliation_required", "The interrupted managed repair retains exact effect custody; rerun n8n repair to inspect it without repeating an uncertain effect.").expect("static") }
    }
}
fn open_repair_service(home: &Path) -> Result<IntegrationJobService> {
    Ok(IntegrationJobService::open(
        home,
        super::super::n8n_catalog(),
        &ExplicitRepairRestartValidator,
    )?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RepairPhase {
    IntentPersisted,
    StartDispatched,
    RecreateDispatched,
    CreateIdWitnessed,
    BindingCommitDispatched,
    RuntimeVerified,
    ReadinessVerified,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairCustody {
    schema_version: u8,
    phase: RepairPhase,
    repair_job_id: String,
    repair_manifest_sha256: String,
    generation: u64,
    source_install_job_id: String,
    source_install_manifest_sha256: String,
    action: Option<String>,
    old_container_id: String,
    new_container_id: Option<String>,
    old_binding: RuntimeBinding,
    new_binding: Option<RuntimeBinding>,
    old_binding_bytes: Vec<u8>,
    new_binding_bytes: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairGeneration {
    schema_version: u8,
    generation: u64,
}

fn custody_path(home: &Path) -> PathBuf {
    home.join(REPAIR_FILE)
}
fn generation_path(home: &Path) -> PathBuf {
    home.join(REPAIR_GENERATION_FILE)
}
fn next_generation(home: &Path) -> Result<u64, &'static str> {
    let path = generation_path(home);
    let prior = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<RepairGeneration>(&bytes)
            .map_err(|_| "n8n_repair_generation_invalid")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RepairGeneration {
            schema_version: 1,
            generation: 0,
        },
        Err(_) => return Err("n8n_repair_generation_read_failed"),
    };
    if prior.schema_version != 1 {
        return Err("n8n_repair_generation_invalid");
    }
    let generation = prior
        .generation
        .checked_add(1)
        .ok_or("n8n_repair_generation_exhausted")?;
    crate::util::atomic_write::atomic_write_private(
        &path,
        &serde_json::to_vec(&RepairGeneration {
            schema_version: 1,
            generation,
        })
        .map_err(|_| "n8n_repair_generation_serialize_failed")?,
    )
    .map_err(|_| "n8n_repair_generation_write_failed")?;
    Ok(generation)
}
fn read_custody(home: &Path) -> Result<Option<RepairCustody>, &'static str> {
    let path = custody_path(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_repair_custody_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32 * 1024 {
        return Err("n8n_repair_custody_invalid");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "n8n_repair_custody_read_failed")?
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "n8n_repair_custody_read_failed")?;
    if bytes.len() > 32 * 1024 {
        return Err("n8n_repair_custody_invalid");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "n8n_repair_custody_invalid")
}
fn write_custody(home: &Path, custody: &RepairCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_repair_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_repair_custody_write_failed")
}
fn create_custody(home: &Path, custody: &RepairCustody) -> Result<(), &'static str> {
    crate::util::atomic_write::write_private_create_new_durable(
        &custody_path(home),
        &serde_json::to_vec(custody).map_err(|_| "n8n_repair_custody_serialize_failed")?,
    )
    .map_err(|_| "n8n_repair_custody_create_failed")
}

fn repair_manifest(
    binding: &RuntimeBinding,
    source: &IntegrationJob,
    generation: u64,
) -> super::super::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-repair-v2",
        source.job_id.as_str(),
        source.manifest_sha256.as_str(),
        binding.container_id.as_deref().unwrap_or(""),
        binding.image.as_str(),
        binding.volume.as_str(),
        &binding.host_port.to_string(),
        &generation.to_string(),
    ])
}
fn enqueue_repair(
    service: &IntegrationJobService,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
    generation: u64,
) -> Result<IntegrationJob> {
    let request = validate_binding(binding, source).map_err(anyhow::Error::msg)?;
    let manifest = repair_manifest(binding, source, generation);
    let contract = JobEvidenceContract::verified(
        manifest.clone(),
        sha256_parts(&[
            "n8n-managed-repair-runtime",
            source.job_id.as_str(),
            request.volume(),
        ]),
        super::expected_authenticated_probe_sha256(&request.endpoint()),
        sha256_parts(&STEPS),
    );
    Ok(service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static"),
            operation: JobOperation::Repair,
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
    c: &RepairCustody,
    job: &IntegrationJob,
    source: &IntegrationJob,
) -> Result<(), &'static str> {
    if c.schema_version != 1
        || c.generation == 0
        || job.operation != JobOperation::Repair
        || c.repair_job_id != job.job_id.as_str()
        || c.repair_manifest_sha256 != job.manifest_sha256.as_str()
        || c.source_install_job_id != source.job_id.as_str()
        || c.source_install_manifest_sha256 != source.manifest_sha256.as_str()
        || c.old_binding.job_id != source.job_id.as_str()
        || c.old_binding.container_id.as_deref() != Some(c.old_container_id.as_str())
        || c.old_binding_bytes.is_empty()
        || !super::valid_container_id(&c.old_container_id)
    {
        Err("n8n_repair_custody_mismatch")
    } else {
        Ok(())
    }
}
fn checkpoint(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    completed: u32,
    step: &str,
) -> Result<IntegrationJob> {
    let contract = job
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_repair_contract_missing"))?;
    Ok(service.update_progress(
        &job.job_id,
        job.state_revision,
        job.state,
        JobProgress {
            completed_steps: completed,
            total_steps: STEPS.len() as u32,
            bytes_done: 0,
            bytes_total: None,
        },
        Some(step.into()),
        ProgressEvidence::claimed(ProgressEvidenceClaim {
            job_id: job.job_id.clone(),
            manifest_sha256: job.manifest_sha256.clone(),
            step_plan_sha256: contract.step_plan_sha256().clone(),
            staging_binding_sha256: sha256_parts(&["n8n-managed-repair-checkpoint", step]),
            expected_revision: job.state_revision,
            expected_state: job.state,
            current_phase: step.into(),
            completed_steps: completed,
            bytes_done: 0,
        }),
    )?)
}
fn expected_recreated_binding(c: &RepairCustody, id: String) -> RuntimeBinding {
    let mut next = c.old_binding.clone();
    next.container_id = Some(id);
    next.phase = RuntimePhase::Ready;
    next
}
fn verify_exact(
    found: &super::ObservedContainer,
    binding: &RuntimeBinding,
    source: &IntegrationJob,
) -> Result<(), anyhow::Error> {
    let request = validate_binding(binding, source).map_err(anyhow::Error::msg)?;
    validate_existing_identity(found, Some(binding), &request, source).map_err(anyhow::Error::msg)
}

/// Injectable complete backend seam. `api_key` is borrowed solely for the
/// final authenticated probe and never enters custody or the repair job.
pub(in crate::integrations) async fn repair_managed_at_with<
    R: ManagedDockerRunner,
    H: super::ManagedReadiness,
    P: N8nApiProbe + ?Sized,
>(
    home: &Path,
    api_key: SecretString,
    runner: &mut R,
    readiness: &H,
    probe: &P,
) -> Result<IntegrationJob> {
    let _operation_lock = crate::util::locked_file::try_lock_file_once(
        &super::operation_lock_path(home),
        "n8n managed runtime operation",
    )?
    .ok_or_else(|| anyhow::anyhow!("n8n_managed_operation_busy"))?;
    if super::managed_uninstall::repair_has_pending_custody(home).map_err(anyhow::Error::msg)?
        || super::super::managed_purge::repair_has_pending_custody(home)
            .map_err(anyhow::Error::msg)?
    {
        anyhow::bail!("n8n_repair_conflicting_custody");
    }
    let service = open_repair_service(home)?;
    // A post-create crash may already have committed the source binding's new
    // id.  Resume from the original custody bytes so idempotent enqueue binds
    // the same repair job, never a second repair plan.
    let mut existing_custody = read_custody(home).map_err(anyhow::Error::msg)?;
    if let Some(custody) = existing_custody.as_ref()
        && custody.phase == RepairPhase::Completed
        && let Some(ready) = service.snapshot()?.into_iter().find(|job| {
            job.operation == JobOperation::Repair
                && job.state == JobState::Ready
                && job.job_id.as_str() == custody.repair_job_id
                && job.manifest_sha256.as_str() == custody.repair_manifest_sha256
        })
    {
        let source = service.snapshot()?.into_iter().find(|job| {
            job.job_id.as_str() == custody.source_install_job_id
                && job.manifest_sha256.as_str() == custody.source_install_manifest_sha256
        });
        let expected = custody.new_binding.as_ref().unwrap_or(&custody.old_binding);
        let still_ready = async {
            let source = source.ok_or_else(|| anyhow::anyhow!("n8n_repair_source_missing"))?;
            let current = read_binding(home)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("n8n_repair_binding_missing"))?;
            if current != *expected {
                anyhow::bail!("n8n_repair_receipt_stale");
            }
            let request = validate_binding(&current, &source).map_err(anyhow::Error::msg)?;
            super::verify_runtime_volume_owner(runner, &current)
                .await
                .map_err(anyhow::Error::msg)?;
            let id = current
                .container_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("n8n_repair_receipt_stale"))?;
            let found = match runner.inspect_exact(id).await.map_err(anyhow::Error::msg)? {
                super::InspectOutcome::Found(found) => found,
                _ => anyhow::bail!("n8n_repair_receipt_stale"),
            };
            if !runner.running_exact(id).await.map_err(anyhow::Error::msg)? {
                anyhow::bail!("n8n_repair_receipt_stale");
            }
            verify_exact(&found, &current, &source)?;
            if !readiness.health(current.host_port).await {
                anyhow::bail!("n8n_repair_receipt_stale");
            }
            probe
                .negative_control(&request.endpoint())
                .await
                .map_err(|error| anyhow::anyhow!(error.code()))?;
            probe
                .authenticated_probe(&request.endpoint(), &api_key)
                .await
                .map_err(|error| anyhow::anyhow!(error.code()))?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if still_ready.is_ok() {
            return Ok(ready);
        }
        crate::util::atomic_write::durable_remove_file(&custody_path(home))
            .map_err(|_| anyhow::anyhow!("n8n_repair_receipt_retire_failed"))?;
        existing_custody = None;
    }
    let (binding, source) = match existing_custody.as_ref() {
        Some(custody) => {
            let source = service
                .snapshot()?
                .into_iter()
                .find(|job| {
                    job.job_id.as_str() == custody.source_install_job_id
                        && job.manifest_sha256.as_str() == custody.source_install_manifest_sha256
                })
                .ok_or_else(|| anyhow::anyhow!("n8n_repair_source_missing"))?;
            validate_binding(&custody.old_binding, &source).map_err(anyhow::Error::msg)?;
            (custody.old_binding.clone(), source)
        }
        None => source_ready(&service, home)?,
    };
    let generation = match existing_custody.as_ref() {
        Some(custody) => custody.generation,
        None => next_generation(home).map_err(anyhow::Error::msg)?,
    };
    let queued = enqueue_repair(&service, &binding, &source, generation)?;
    let mut custody = match existing_custody {
        Some(value) => {
            validate_custody(&value, &queued, &source).map_err(anyhow::Error::msg)?;
            value
        }
        None => {
            let value = RepairCustody {
                schema_version: 1,
                phase: RepairPhase::IntentPersisted,
                repair_job_id: queued.job_id.as_str().into(),
                repair_manifest_sha256: queued.manifest_sha256.as_str().into(),
                generation,
                source_install_job_id: source.job_id.as_str().into(),
                source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
                action: None,
                old_container_id: binding.container_id.clone().expect("validated"),
                new_container_id: None,
                old_binding: binding.clone(),
                new_binding: None,
                old_binding_bytes: read_binding_bytes(home)
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| anyhow::anyhow!("n8n_repair_binding_missing"))?,
                new_binding_bytes: None,
            };
            create_custody(home, &value).map_err(anyhow::Error::msg)?;
            value
        }
    };
    let mut active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, STEPS[0])?,
        state if state.is_active() => queued,
        _ => return Ok(queued),
    };
    if active.state == JobState::Running {
        active = service.begin_validation(&active.job_id, active.state_revision, STEPS[0])?;
    }
    if active.progress.completed_steps == 0 {
        active = checkpoint(&service, &active, 1, STEPS[0])?;
    }
    let request = validate_binding(&custody.old_binding, &source).map_err(anyhow::Error::msg)?;
    super::verify_runtime_volume_owner(runner, &custody.old_binding)
        .await
        .map_err(anyhow::Error::msg)?;
    if custody.phase == RepairPhase::IntentPersisted {
        match runner
            .inspect_exact(&custody.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            super::InspectOutcome::Found(found) => {
                verify_exact(&found, &custody.old_binding, &source)?;
                if runner
                    .running_exact(&custody.old_container_id)
                    .await
                    .map_err(anyhow::Error::msg)?
                {
                    custody.action = Some("healthy".into());
                    custody.phase = RepairPhase::RuntimeVerified;
                    write_custody(home, &custody).map_err(anyhow::Error::msg)?;
                } else {
                    custody.action = Some("started".into());
                    custody.phase = RepairPhase::StartDispatched;
                    write_custody(home, &custody).map_err(anyhow::Error::msg)?;
                    let receipt = runner.start_exact(&custody.old_container_id).await;
                    if !matches!(receipt, Ok(ref value) if value.succeeded) {
                        anyhow::bail!("n8n_repair_start_outcome_uncertain");
                    }
                }
            }
            super::InspectOutcome::Absent => {
                match runner.inspect_named().await.map_err(anyhow::Error::msg)? {
                    super::InspectOutcome::Absent => {
                        custody.action = Some("recreated".into());
                        custody.phase = RepairPhase::RecreateDispatched;
                        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
                        let receipt = runner
                            .create_with_exact_id(&request.create_command(source.job_id.as_str()))
                            .await;
                        let Ok(receipt) = receipt else {
                            anyhow::bail!("n8n_repair_create_outcome_uncertain");
                        };
                        if !receipt.command.succeeded {
                            anyhow::bail!("n8n_repair_create_outcome_uncertain");
                        }
                        let Some(id) = receipt
                            .container_id
                            .filter(|id| super::valid_container_id(id))
                        else {
                            anyhow::bail!("n8n_repair_create_id_unwitnessed");
                        };
                        custody.new_container_id = Some(id);
                        custody.phase = RepairPhase::CreateIdWitnessed;
                        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
                    }
                    _ => anyhow::bail!("n8n_repair_named_container_present"),
                }
            }
            super::InspectOutcome::Unknown => anyhow::bail!("n8n_repair_runtime_state_unknown"),
        }
    }
    if custody.phase == RepairPhase::StartDispatched {
        let found = match runner
            .inspect_exact(&custody.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            super::InspectOutcome::Found(found) => found,
            _ => anyhow::bail!("n8n_repair_start_outcome_uncertain"),
        };
        if !runner
            .running_exact(&custody.old_container_id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_repair_start_outcome_uncertain");
        }
        verify_exact(&found, &custody.old_binding, &source)?;
        custody.phase = RepairPhase::RuntimeVerified;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == RepairPhase::RecreateDispatched {
        // No receipt-derived ID survived this crash window. Labels and name
        // are only discovery and cannot adopt a potentially foreign process.
        anyhow::bail!("n8n_repair_create_outcome_uncertain");
    }
    if custody.phase == RepairPhase::CreateIdWitnessed {
        let id = custody
            .new_container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_repair_create_id_unwitnessed"))?;
        let found = match runner.inspect_exact(id).await.map_err(anyhow::Error::msg)? {
            super::InspectOutcome::Found(found) if found.id == id => found,
            _ => anyhow::bail!("n8n_repair_create_outcome_uncertain"),
        };
        let next = expected_recreated_binding(&custody, found.id.clone());
        verify_exact(&found, &next, &source)?;
        if !runner
            .running_exact(&found.id)
            .await
            .map_err(anyhow::Error::msg)?
        {
            anyhow::bail!("n8n_repair_recreated_not_running");
        }
        custody.new_container_id = Some(found.id);
        custody.new_binding_bytes = Some(
            serde_json::to_vec(&next)
                .map_err(|_| anyhow::anyhow!("n8n_repair_custody_serialize_failed"))?,
        );
        custody.new_binding = Some(next);
        custody.phase = RepairPhase::BindingCommitDispatched;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == RepairPhase::BindingCommitDispatched {
        let next = custody
            .new_binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("n8n_repair_custody_mismatch"))?;
        let next_bytes = custody
            .new_binding_bytes
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_repair_custody_mismatch"))?;
        let observed = read_binding_bytes(home)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("n8n_repair_binding_missing"))?;
        if observed == custody.old_binding_bytes {
            write_binding(home, next).map_err(anyhow::Error::msg)?;
            if read_binding_bytes(home)
                .map_err(anyhow::Error::msg)?
                .as_deref()
                != Some(next_bytes)
            {
                anyhow::bail!("n8n_repair_binding_compare_and_set_failed");
            }
        } else if observed.as_slice() != next_bytes {
            anyhow::bail!("n8n_repair_binding_compare_and_set_failed");
        }
        let id = next
            .container_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("n8n_repair_custody_mismatch"))?;
        let found = match runner.inspect_exact(id).await.map_err(anyhow::Error::msg)? {
            super::InspectOutcome::Found(found) => found,
            _ => anyhow::bail!("n8n_repair_recreated_outcome_uncertain"),
        };
        if !runner.running_exact(id).await.map_err(anyhow::Error::msg)? {
            anyhow::bail!("n8n_repair_recreated_outcome_uncertain");
        }
        verify_exact(&found, next, &source)?;
        custody.phase = RepairPhase::RuntimeVerified;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if custody.phase == RepairPhase::RuntimeVerified {
        if active.state == JobState::Validating {
            active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[2])?;
        }
        if active.progress.completed_steps < 3 {
            active = checkpoint(&service, &active, 3, STEPS[2])?;
        }
        let deadline = Instant::now() + DEADLINE;
        while !readiness.health(custody.old_binding.host_port).await {
            if Instant::now() >= deadline {
                anyhow::bail!("n8n_repair_loopback_health_timeout");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        probe
            .negative_control(&request.endpoint())
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        probe
            .authenticated_probe(&request.endpoint(), &api_key)
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        custody.phase = RepairPhase::ReadinessVerified;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    // A crash after the readiness custody write may reopen this job while it
    // still has the pre-publication Validating state. This guard belongs to
    // the already-persisted readiness stage, so it uses STEPS[3] without
    // claiming that either probe ran again. Ready is legal only from
    // Configuring.
    if active.state == JobState::Validating {
        active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[3])?;
    }
    if active.progress.completed_steps < 4 {
        active = checkpoint(&service, &active, 4, STEPS[3])?;
    }
    if custody.phase == RepairPhase::ReadinessVerified {
        custody.phase = RepairPhase::Completed;
        write_custody(home, &custody).map_err(anyhow::Error::msg)?;
    }
    if active.progress.completed_steps < 5 {
        active = checkpoint(&service, &active, 5, STEPS[4])?;
    }
    let contract = active
        .evidence_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_repair_contract_missing"))?;
    let ready = ReadyEvidence::verified(
        active.job_id.clone(),
        active.manifest_sha256.clone(),
        contract.artifact_binding_sha256().clone(),
        contract.config_binding_sha256().clone(),
        contract.authenticated_probe_sha256().clone(),
        contract.step_plan_sha256().clone(),
    );
    service
        .mark_ready(&active.job_id, active.state_revision, ready)
        .map_err(Into::into)
}

pub(crate) async fn repair_managed_at(home: &Path) -> Result<IntegrationJob> {
    let (configured, key) = crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
    )?;
    let service = IntegrationJobService::read_only_snapshot(home)?;
    let binding = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("no_matching_managed_runtime"))?;
    let endpoint = super::ManagedN8nRequest::new_with_volume(
        binding.host_port,
        crate::installers::n8n::N8N_OCI_REFERENCE,
        binding.volume.clone(),
    )
    .map_err(anyhow::Error::msg)?
    .endpoint();
    if configured.endpoint != endpoint
        || !service
            .iter()
            .any(|job| job.job_id.as_str() == binding.job_id && job.state == JobState::Ready)
    {
        anyhow::bail!("n8n_repair_config_custody_mismatch");
    }
    repair_managed_at_with(
        home,
        key,
        &mut super::DockerManagedRunner,
        &ProductionReadiness,
        &HttpN8nApiProbe,
    )
    .await
}

/// Stable redacted projection for the CLI receipt. The durable sidecar stays
/// available after Ready so a later status call can state exactly which
/// same-generation action was authenticated without exposing credentials.
pub(crate) fn completed_action_at(
    home: &Path,
    job: &IntegrationJob,
) -> Result<Option<&'static str>, &'static str> {
    if job.operation != JobOperation::Repair || job.state != JobState::Ready {
        return Ok(None);
    }
    let Some(custody) = read_custody(home)? else {
        return Ok(None);
    };
    if custody.phase != RepairPhase::Completed
        || custody.repair_job_id != job.job_id.as_str()
        || custody.repair_manifest_sha256 != job.manifest_sha256.as_str()
    {
        return Err("n8n_repair_receipt_mismatch");
    }
    let _ = completed_authority(home, &custody)?;
    match custody.action.as_deref() {
        Some("healthy") => Ok(Some("healthy")),
        Some("started") => Ok(Some("started")),
        Some("recreated") => Ok(Some("recreated")),
        _ => Err("n8n_repair_receipt_mismatch"),
    }
}

/// Inverse lifecycle fence for uninstall/purge. Malformed, interrupted, or
/// stale completed repair custody is retained as a blocker; only a completed
/// receipt whose source Ready witness and current binding still agree can be
/// ignored by a later destructive operation.
pub(crate) fn repair_has_pending_custody(home: &Path) -> Result<bool, &'static str> {
    let Some(custody) = read_custody(home)? else {
        return Ok(false);
    };
    if custody.phase != RepairPhase::Completed {
        return Ok(true);
    }
    Ok(completed_authority(home, &custody).is_err())
}

fn completed_authority(
    home: &Path,
    custody: &RepairCustody,
) -> Result<(IntegrationJob, RuntimeBinding), &'static str> {
    let jobs = IntegrationJobService::read_only_snapshot(home)
        .map_err(|_| "n8n_repair_source_read_failed")?;
    let source = jobs
        .iter()
        .find(|job| {
            job.job_id.as_str() == custody.source_install_job_id
                && job.manifest_sha256.as_str() == custody.source_install_manifest_sha256
        })
        .cloned()
        .ok_or("n8n_repair_source_missing")?;
    let repair = jobs
        .iter()
        .find(|job| {
            job.job_id.as_str() == custody.repair_job_id
                && job.manifest_sha256.as_str() == custody.repair_manifest_sha256
        })
        .cloned()
        .ok_or("n8n_repair_job_missing")?;
    if repair.operation != JobOperation::Repair
        || repair.state != JobState::Ready
        || repair.manifest_sha256
            != repair_manifest(&custody.old_binding, &source, custody.generation)
    {
        return Err("n8n_repair_receipt_mismatch");
    }
    validate_custody(custody, &repair, &source)?;
    let expected = custody.new_binding.as_ref().unwrap_or(&custody.old_binding);
    let current = read_binding(home)?.ok_or("n8n_repair_binding_missing")?;
    if source.operation != JobOperation::Install
        || source.state != JobState::Ready
        || !is_managed_job(&source)
        || current != *expected
    {
        return Err("n8n_repair_receipt_mismatch");
    }
    validate_binding(&current, &source)?;
    Ok((source, current))
}

/// Retire only a completed repair receipt that still proves the current source
/// Ready binding. Uninstall calls this while the shared operation lock is held,
/// immediately before it removes that binding; interrupted or stale custody is
/// deliberately left as a destructive-operation fence.
pub(crate) fn retire_completed_for_uninstall(home: &Path) -> Result<(), &'static str> {
    let Some(custody) = read_custody(home)? else {
        return Ok(());
    };
    if custody.phase != RepairPhase::Completed {
        return Err("n8n_repair_custody_pending");
    }
    let _ = completed_authority(home, &custody)?;
    crate::util::atomic_write::durable_remove_file(&custody_path(home))
        .map_err(|_| "n8n_repair_receipt_retire_failed")
}

#[cfg(test)]
#[path = "managed_repair_tests.rs"]
mod tests;
