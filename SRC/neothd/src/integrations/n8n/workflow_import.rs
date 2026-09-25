//! Durable, one-shot import of NEOTH's bundled inactive n8n workflows.
//!
//! A POST whose result was lost is deliberately never retried. The custody
//! sidecar records an intent before POST and an exact returned id before GET;
//! recovery can only read that exact id.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::Result;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::LoopbackHttpEndpoint;
use crate::integrations::jobs::EnqueueIntegrationJob;
use crate::integrations::state::{
    IntegrationJob, JobEvidenceContract, JobId, JobOperation, JobProgress, JobRequester,
    JobState, ProgressEvidence, ProgressEvidenceClaim, ReadyEvidence, Sha256Digest,
};
use crate::integrations::{EnqueueResult, IntegrationJobService, JobServiceError};
use crate::installers::n8n_starter_workflows::all_known_workflows;
use crate::installers::n8n_workflows::BootstrapWorkflow;
use crate::secret::SecretString;

use super::{expected_authenticated_probe_sha256, sha256_parts, N8N_CAPABILITY_ID};

const IMPORT_RELEASE_VERSION: &str = "1.0.0";
const IMPORT_RESPONSE_MAX: usize = 256 * 1024;
const IMPORT_STEPS: u32 = 13;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum ImportEntryState {
    Prepared,
    IntentPersisted,
    Created { workflow_id: String },
    ReadBack { workflow_id: String, normalized_readback_sha256: Sha256Digest },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowImportEntry {
    slug: String,
    source_sha256: Sha256Digest,
    create_dto_sha256: Sha256Digest,
    state: ImportEntryState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowImportCustody {
    job_id: JobId,
    endpoint_binding_sha256: Sha256Digest,
    credential_binding_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    entries: Vec<WorkflowImportEntry>,
}

#[derive(Clone, Debug)]
struct WorkflowImportManifest {
    entries: Vec<ManifestWorkflow>,
    manifest_sha256: Sha256Digest,
}

#[derive(Clone, Debug)]
struct ManifestWorkflow {
    slug: String,
    source_sha256: Sha256Digest,
    dto: serde_json::Value,
    dto_sha256: Sha256Digest,
}

struct WorkflowImportBinding {
    endpoint: LoopbackHttpEndpoint,
    key: SecretString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportErrorKind { Local, Rejected, Ambiguous, Drift }

#[derive(Debug)]
pub(super) struct ImportError { kind: ImportErrorKind, pub(super) code: &'static str }

impl ImportError {
    fn local(code: &'static str) -> Self { Self { kind: ImportErrorKind::Local, code } }
    fn rejected(code: &'static str) -> Self { Self { kind: ImportErrorKind::Rejected, code } }
    fn ambiguous(code: &'static str) -> Self { Self { kind: ImportErrorKind::Ambiguous, code } }
    fn drift(code: &'static str) -> Self { Self { kind: ImportErrorKind::Drift, code } }
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(format!("{:x}", Sha256::digest(bytes))).expect("sha256 is always valid")
}

fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, ImportError> {
    serde_json::to_vec(value).map_err(|_| ImportError::local("workflow_import_json_encode_failed"))
}

fn import_manifest() -> Result<WorkflowImportManifest, ImportError> {
    let workflows = all_known_workflows();
    if workflows.len() != IMPORT_STEPS as usize { return Err(ImportError::local("workflow_import_manifest_count")); }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(workflows.len());
    for workflow in workflows {
        if !seen.insert(workflow.slug) { return Err(ImportError::local("workflow_import_duplicate_slug")); }
        let source_sha256 = digest_bytes(workflow.body.as_bytes());
        let dto = create_dto(workflow)?;
        let dto_sha256 = digest_bytes(&json_bytes(&dto)?);
        entries.push(ManifestWorkflow { slug: workflow.slug.to_owned(), source_sha256, dto, dto_sha256 });
    }
    let joined = entries.iter().map(|entry| format!("{}:{}:{}", entry.slug, entry.source_sha256.as_str(), entry.dto_sha256.as_str())).collect::<Vec<_>>().join("\n");
    Ok(WorkflowImportManifest { entries, manifest_sha256: digest_bytes(joined.as_bytes()) })
}

fn create_dto(workflow: &BootstrapWorkflow) -> Result<serde_json::Value, ImportError> {
    let mut source: serde_json::Map<String, serde_json::Value> = serde_json::from_str(workflow.body)
        .map_err(|_| ImportError::local("workflow_import_source_invalid"))?;
    if source.get("active").and_then(serde_json::Value::as_bool) != Some(false) {
        return Err(ImportError::local("workflow_import_source_not_inactive"));
    }
    for forbidden in ["description", "active", "tags"] { source.remove(forbidden); }
    for required in ["name", "nodes", "connections", "settings"] {
        if !source.contains_key(required) { return Err(ImportError::local("workflow_import_source_missing_graph")); }
    }
    Ok(serde_json::Value::Object(source))
}

fn custody_path(home: &Path, job_id: &JobId) -> PathBuf {
    home.join(format!(".n8n-workflow-import-{}.custody.yaml", job_id.as_str()))
}

pub(super) fn import_lock_path(home: &Path) -> PathBuf {
    home.join(".n8n-workflow-import.lock")
}

fn custody_name(job_id: &JobId) -> OsString {
    OsString::from(format!(".n8n-workflow-import-{}.custody.yaml", job_id.as_str()))
}

fn save_custody(home: &Path, custody: &WorkflowImportCustody) -> Result<(), ImportError> {
    let path = custody_path(home, &custody.job_id);
    let bytes = serde_yaml::to_string(custody)
        .map_err(|_| ImportError::local("workflow_import_custody_encode"))?;
    crate::util::atomic_write::atomic_write_private(&path, bytes.as_bytes())
        .map_err(|_| ImportError::local("workflow_import_custody_write"))?;
    crate::util::atomic_write::sync_parent_directory_required(&path)
        .map_err(|_| ImportError::local("workflow_import_custody_publish"))?;
    Ok(())
}

fn custody_exists(home: &Path, job_id: &JobId) -> Result<bool, ImportError> {
    let path = custody_path(home, job_id);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(ImportError::ambiguous("workflow_import_custody_not_regular")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ImportError::ambiguous("workflow_import_custody_inspect")),
    }
}

fn load_custody(home: &Path, job_id: &JobId) -> Result<WorkflowImportCustody, ImportError> {
    let path = custody_path(home, job_id);
    let Some(directory) = crate::skills::store::open_bound_directory(
        home, false, "n8n workflow import custody directory",
    ).map_err(|_| ImportError::ambiguous("workflow_import_custody_missing"))? else {
        return Err(ImportError::ambiguous("workflow_import_custody_missing"));
    };
    let raw = crate::skills::store::read_regular_file_bounded(
        &directory.dir, &custody_name(job_id), &path, 64 * 1024,
    ).map_err(|_| ImportError::ambiguous("workflow_import_custody_invalid"))?;
    serde_yaml::from_slice(&raw).map_err(|_| ImportError::ambiguous("workflow_import_custody_invalid"))
}

/// A terminal failure is safe only when the exact durable custody proves that
/// no create request has been intended. Any missing, malformed, or advanced
/// sidecar is deliberately held for operator inspection.
pub(super) fn safe_to_terminalize_import(home: &Path, job: &IntegrationJob, error: &ImportError) -> bool {
    match custody_exists(home, &job.job_id) {
        // A queued job has not crossed `service.start`, which is the boundary
        // immediately before its first possible POST. A missing sidecar is
        // therefore proven pre-effect only in this state.
        Ok(false) => job.state == JobState::Queued,
        Ok(true) => load_custody(home, &job.job_id).is_ok_and(|custody| match error.kind {
            ImportErrorKind::Local => custody.entries.iter().all(|entry| matches!(entry.state, ImportEntryState::Prepared)),
            // An exact non-success create reply proves the server rejected that
            // one request. We retain its Intent and any prior readbacks, but
            // terminalize rather than retry the rejected credential/request.
            ImportErrorKind::Rejected => custody.entries.iter().all(|entry| {
                matches!(entry.state, ImportEntryState::Prepared | ImportEntryState::IntentPersisted | ImportEntryState::ReadBack { .. })
            }),
            ImportErrorKind::Ambiguous | ImportErrorKind::Drift => false,
        }),
        Err(_) => false,
    }
}

#[async_trait::async_trait]
pub(super) trait WorkflowImportTransport: Send + Sync {
    async fn create(&self, endpoint: &LoopbackHttpEndpoint, key: &SecretString, dto: &serde_json::Value) -> Result<String, ImportError>;
    async fn get_exact(&self, endpoint: &LoopbackHttpEndpoint, key: &SecretString, id: &str) -> Result<serde_json::Value, ImportError>;
}

pub(super) struct HttpWorkflowImportTransport;

async fn bounded_json(response: reqwest::Response, create: bool) -> Result<serde_json::Value, ImportError> {
    if response.status().is_redirection() { return Err(ImportError::ambiguous("workflow_import_redirect")); }
    if response.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR || response.status().is_server_error() { return Err(ImportError::ambiguous("workflow_import_server_error")); }
    if !response.status().is_success() {
        return Err(match (create, response.status()) {
            (true, reqwest::StatusCode::BAD_REQUEST) => ImportError::rejected("workflow_import_create_rejected"),
            (true, reqwest::StatusCode::UNAUTHORIZED) => ImportError::rejected("workflow_import_credential_rejected"),
            (true, reqwest::StatusCode::FORBIDDEN) => ImportError::rejected("workflow_import_legacy_credential_rejected"),
            (true, _) => ImportError::ambiguous("workflow_import_create_status_ambiguous"),
            (false, _) => ImportError::drift("workflow_import_readback_rejected"),
        });
    }
    if response.content_length().is_some_and(|size| size > IMPORT_RESPONSE_MAX as u64) { return Err(ImportError::ambiguous("workflow_import_response_too_large")); }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ImportError::ambiguous("workflow_import_transport"))?;
        if bytes.len().saturating_add(chunk.len()) > IMPORT_RESPONSE_MAX { return Err(ImportError::ambiguous("workflow_import_response_too_large")); }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ImportError::ambiguous("workflow_import_response_invalid"))
}

#[async_trait::async_trait]
impl WorkflowImportTransport for HttpWorkflowImportTransport {
    async fn create(&self, endpoint: &LoopbackHttpEndpoint, key: &SecretString, dto: &serde_json::Value) -> Result<String, ImportError> {
        let response = super::bounded_n8n_client().map_err(|_| ImportError::ambiguous("workflow_import_client"))?
            .post(format!("{}{}", endpoint.origin(), super::N8N_WORKFLOWS_PATH))
            .header("X-N8N-API-KEY", key.expose()).json(dto).send().await
            .map_err(|_| ImportError::ambiguous("workflow_import_transport"))?;
        let value = bounded_json(response, true).await?;
        let id = value.get("id").or_else(|| value.get("data").and_then(|data| data.get("id"))).and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
            .ok_or_else(|| ImportError::ambiguous("workflow_import_create_id_invalid"))?;
        Ok(id.to_owned())
    }
    async fn get_exact(&self, endpoint: &LoopbackHttpEndpoint, key: &SecretString, id: &str) -> Result<serde_json::Value, ImportError> {
        let encoded: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
        let response = super::bounded_n8n_client().map_err(|_| ImportError::ambiguous("workflow_import_client"))?
            .get(format!("{}{}/{}", endpoint.origin(), super::N8N_WORKFLOWS_PATH, encoded))
            .header("X-N8N-API-KEY", key.expose()).send().await
            .map_err(|_| ImportError::ambiguous("workflow_import_transport"))?;
        bounded_json(response, false).await
    }
}

fn normalized_graph(dto: &serde_json::Value, expected_id: &str, read: &serde_json::Value) -> Result<Sha256Digest, ImportError> {
    let read = read.get("data").unwrap_or(read);
    if read.get("id").and_then(serde_json::Value::as_str) != Some(expected_id) {
        return Err(ImportError::drift("workflow_import_readback_id_mismatch"));
    }
    if read.get("active").and_then(serde_json::Value::as_bool) != Some(false) { return Err(ImportError::drift("workflow_import_readback_active")); }
    let mut expected = serde_json::Map::new();
    let mut observed = serde_json::Map::new();
    for field in ["name", "nodes", "connections", "settings"] {
        expected.insert(field.to_owned(), dto.get(field).cloned().ok_or_else(|| ImportError::local("workflow_import_dto_missing_graph"))?);
        observed.insert(field.to_owned(), read.get(field).cloned().ok_or_else(|| ImportError::drift("workflow_import_readback_missing_graph"))?);
    }
    if expected != observed { return Err(ImportError::drift("workflow_import_readback_drift")); }
    Ok(digest_bytes(&json_bytes(&serde_json::Value::Object(observed))?))
}

fn binding_digests(endpoint: &LoopbackHttpEndpoint, key: &SecretString) -> (Sha256Digest, Sha256Digest) {
    (sha256_parts(&["n8n-workflow-import-endpoint", endpoint.origin()]), digest_bytes(key.expose().as_bytes()))
}

pub(super) fn enqueue_managed_workflow_import(service: &IntegrationJobService, home: &Path, requester: JobRequester) -> Result<EnqueueResult, JobServiceError> {
    let manifest = import_manifest().map_err(|_| JobServiceError::State(crate::integrations::state::StateValidationError::InvalidInvariant("workflow import manifest is invalid".into())))?;
    let (instance, key) = crate::config::credentials::Credentials::read_n8n_adoption_binding_at(&home.join("freedom.yaml"), &home.join("credentials.yaml"))
        .map_err(|_| JobServiceError::State(crate::integrations::state::StateValidationError::InvalidInvariant("managed n8n binding is not Ready".into())))?;
    if !super::has_ready_managed_binding(service, home, &instance.endpoint)? {
        return Err(JobServiceError::State(crate::integrations::state::StateValidationError::InvalidInvariant("managed n8n binding is not Ready".into())));
    }
    enqueue_workflow_import_with_binding(service, manifest, instance.endpoint, key, requester)
}

fn enqueue_workflow_import_with_binding(
    service: &IntegrationJobService,
    manifest: WorkflowImportManifest,
    endpoint: LoopbackHttpEndpoint,
    key: SecretString,
    requester: JobRequester,
) -> Result<EnqueueResult, JobServiceError> {
    let (endpoint_digest, credential_digest) = binding_digests(&endpoint, &key);
    let contract = JobEvidenceContract::verified(manifest.manifest_sha256.clone(), sha256_parts(&[endpoint_digest.as_str(), credential_digest.as_str()]), expected_authenticated_probe_sha256(&endpoint), sha256_parts(&["n8n-workflow-import-step-plan-v1", "13"]));
    // `enqueue` coalesces only active rows. A completed Import must be
    // explicitly reused: creating a new one would issue another 13 POSTs.
    // Any different terminal Import is retained as an ambiguity boundary for
    // operator repair rather than silently beginning a second generation.
    for previous in service.snapshot()?.into_iter().filter(|job| {
        job.capability_id.as_str() == N8N_CAPABILITY_ID && job.operation == JobOperation::Import
    }) {
        if previous.state == JobState::Ready
            && previous.release_version == IMPORT_RELEASE_VERSION
            && previous.manifest_sha256 == manifest.manifest_sha256
            && previous.evidence_contract.as_ref() == Some(&contract)
        {
            return Ok(EnqueueResult { job: previous, created: false });
        }
        if previous.state.is_terminal() {
            return Err(JobServiceError::State(crate::integrations::state::StateValidationError::InvalidInvariant(
                "a prior n8n workflow import differs from the current binding; inspect its custody before another import".into(),
            )));
        }
    }
    service.enqueue(EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).expect("static id"), operation: JobOperation::Import, release_version: IMPORT_RELEASE_VERSION.into(), manifest_sha256: manifest.manifest_sha256, evidence_contract: contract, requested_by: requester, total_steps: IMPORT_STEPS, bytes_total: None })
}

pub(super) async fn execute_managed_workflow_import_at<T: WorkflowImportTransport + ?Sized>(service: &IntegrationJobService, queued: IntegrationJob, home: &Path, transport: &T) -> Result<IntegrationJob, ImportError> {
    let manifest = import_manifest()?;
    if queued.manifest_sha256 != manifest.manifest_sha256 { return Err(ImportError::drift("workflow_import_manifest_drift")); }
    let (instance, key) = crate::config::credentials::Credentials::read_n8n_adoption_binding_at(&home.join("freedom.yaml"), &home.join("credentials.yaml")).map_err(|_| ImportError::local("workflow_import_binding_missing"))?;
    if !super::has_ready_managed_binding(service, home, &instance.endpoint).map_err(|_| ImportError::local("workflow_import_binding_missing"))? {
        return Err(ImportError::local("workflow_import_managed_binding_not_ready"));
    }
    execute_workflow_import_with_binding(
        service, queued, home, transport, manifest,
        WorkflowImportBinding { endpoint: instance.endpoint, key },
    ).await
}

async fn execute_workflow_import_with_binding<T: WorkflowImportTransport + ?Sized>(
    service: &IntegrationJobService,
    queued: IntegrationJob,
    home: &Path,
    transport: &T,
    manifest: WorkflowImportManifest,
    binding: WorkflowImportBinding,
) -> Result<IntegrationJob, ImportError> {
    if queued.manifest_sha256 != manifest.manifest_sha256 {
        return Err(ImportError::drift("workflow_import_manifest_drift"));
    }
    let (endpoint_digest, credential_digest) = binding_digests(&binding.endpoint, &binding.key);
    let contract = queued.evidence_contract.as_ref()
        .ok_or_else(|| ImportError::local("workflow_import_contract_missing"))?;
    if contract.artifact_binding_sha256() != &manifest.manifest_sha256
        || contract.config_binding_sha256() != &sha256_parts(&[endpoint_digest.as_str(), credential_digest.as_str()])
        || contract.authenticated_probe_sha256() != &expected_authenticated_probe_sha256(&binding.endpoint)
        || contract.step_plan_sha256() != &sha256_parts(&["n8n-workflow-import-step-plan-v1", "13"])
    {
        return Err(ImportError::drift("workflow_import_contract_binding_drift"));
    }
    let has_custody = custody_exists(home, &queued.job_id)?;
    let mut custody = if has_custody {
        let custody = load_custody(home, &queued.job_id)?;
        if custody.job_id != queued.job_id
            || custody.manifest_sha256 != manifest.manifest_sha256
            || custody.endpoint_binding_sha256 != endpoint_digest
            || custody.credential_binding_sha256 != credential_digest
            || custody.entries.len() != manifest.entries.len()
            || custody.entries.iter().zip(&manifest.entries).any(|(stored, expected)| {
                stored.slug != expected.slug
                    || stored.source_sha256 != expected.source_sha256
                    || stored.create_dto_sha256 != expected.dto_sha256
            })
        {
            return Err(ImportError::drift("workflow_import_custody_binding_drift"));
        }
        custody
    } else if queued.state != JobState::Queued {
        return Err(ImportError::ambiguous("workflow_import_active_custody_missing"));
    } else {
        let custody = WorkflowImportCustody { job_id: queued.job_id.clone(), endpoint_binding_sha256: endpoint_digest, credential_binding_sha256: credential_digest, manifest_sha256: manifest.manifest_sha256.clone(), entries: manifest.entries.iter().map(|entry| WorkflowImportEntry { slug: entry.slug.clone(), source_sha256: entry.source_sha256.clone(), create_dto_sha256: entry.dto_sha256.clone(), state: ImportEntryState::Prepared }).collect() };
        save_custody(home, &custody)?;
        custody
    };
    let mut active = match queued.state {
        JobState::Queued => service.start(&queued.job_id, queued.state_revision, "import-workflow-01").map_err(|_| ImportError::local("workflow_import_job_start"))?,
        JobState::Running | JobState::Validating | JobState::Configuring | JobState::Ready => queued,
        JobState::Failed | JobState::Cancelled => return Err(ImportError::local("workflow_import_terminal_job")),
    };
    let ready_repeat = active.state == JobState::Ready;
    for (index, item) in manifest.entries.iter().enumerate() {
        let state = custody.entries.get(index).ok_or_else(|| ImportError::local("workflow_import_custody_entries"))?.state.clone();
        match state {
            ImportEntryState::Prepared if ready_repeat => return Err(ImportError::drift("workflow_import_ready_not_complete")),
            ImportEntryState::Prepared => {
                custody.entries[index].state = ImportEntryState::IntentPersisted;
                save_custody(home, &custody)?;
                let id = transport.create(&binding.endpoint, &binding.key, &item.dto).await?;
                custody.entries[index].state = ImportEntryState::Created { workflow_id: id };
                save_custody(home, &custody)?;
            }
            ImportEntryState::IntentPersisted => return Err(ImportError::ambiguous("workflow_import_post_ambiguous")),
            _ => {}
        }
        let state = custody.entries[index].state.clone();
        let id = match &state { ImportEntryState::Created { workflow_id } | ImportEntryState::ReadBack { workflow_id, .. } => workflow_id.clone(), _ => return Err(ImportError::ambiguous("workflow_import_state_ambiguous")) };
        let read = transport.get_exact(&binding.endpoint, &binding.key, &id).await?;
        let normalized = normalized_graph(&item.dto, &id, &read)?;
        if let ImportEntryState::ReadBack { normalized_readback_sha256, .. } = state
            && normalized_readback_sha256 != normalized
        {
            return Err(ImportError::drift("workflow_import_readback_drift"));
        }
        if !ready_repeat {
            custody.entries[index].state = ImportEntryState::ReadBack { workflow_id: id, normalized_readback_sha256: normalized };
            save_custody(home, &custody)?;
        }
        if active.state.permits_progress() {
            let completed_steps = active.progress.completed_steps.max((index + 1) as u32);
            let step_plan_sha256 = active.evidence_contract.as_ref()
                .ok_or_else(|| ImportError::local("workflow_import_contract_missing"))?
                .step_plan_sha256().clone();
            let job_id = active.job_id.clone();
            let manifest_sha256 = active.manifest_sha256.clone();
            let expected_revision = active.state_revision;
            let expected_state = active.state;
            let current_phase = format!("import-workflow-{:02}", index + 1);
            let staging_binding_sha256 = digest_bytes(&serde_yaml::to_string(&custody)
                .map_err(|_| ImportError::local("workflow_import_custody_encode"))?.into_bytes());
            active = service.update_progress(&job_id, expected_revision, expected_state,
                JobProgress { completed_steps, total_steps: IMPORT_STEPS, bytes_done: 0, bytes_total: None },
                Some(current_phase.clone()),
                ProgressEvidence::claimed(ProgressEvidenceClaim {
                    job_id, manifest_sha256, step_plan_sha256, staging_binding_sha256,
                    expected_revision, expected_state, current_phase, completed_steps, bytes_done: 0,
                })).map_err(|_| ImportError::local("workflow_import_progress"))?;
        }
    }
    if active.state == JobState::Ready { return Ok(active); }
    if active.state == JobState::Running {
        active = service.begin_validation(&active.job_id, active.state_revision, "validate-import-readback")
            .map_err(|_| ImportError::local("workflow_import_validation"))?;
    }
    if active.state == JobState::Validating {
        active = service.begin_configuration(&active.job_id, active.state_revision, "finalize-import-readback")
            .map_err(|_| ImportError::local("workflow_import_configuration"))?;
    }
    let contract = active.evidence_contract.as_ref().ok_or_else(|| ImportError::local("workflow_import_contract_missing"))?;
    service.mark_ready(&active.job_id, active.state_revision, ReadyEvidence::verified(active.job_id.clone(), active.manifest_sha256.clone(), contract.artifact_binding_sha256().clone(), contract.config_binding_sha256().clone(), contract.authenticated_probe_sha256().clone(), contract.step_plan_sha256().clone())).map_err(|_| ImportError::local("workflow_import_ready"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeTransportState {
        creates: u32,
        reads: Vec<String>,
        graphs: std::collections::BTreeMap<String, serde_json::Value>,
        fail_create_once: bool,
        reject_create_at: Option<u32>,
        fail_get_once: bool,
    }

    #[derive(Default)]
    struct FakeTransport(Arc<Mutex<FakeTransportState>>);

    #[async_trait::async_trait]
    impl WorkflowImportTransport for FakeTransport {
        async fn create(&self, _: &LoopbackHttpEndpoint, _: &SecretString, dto: &serde_json::Value) -> Result<String, ImportError> {
            let mut state = self.0.lock().unwrap();
            state.creates += 1;
            if state.reject_create_at == Some(state.creates) {
                return Err(ImportError::rejected("workflow_import_create_rejected"));
            }
            if std::mem::take(&mut state.fail_create_once) {
                return Err(ImportError::ambiguous("workflow_import_transport"));
            }
            let id = format!("workflow-{}", state.creates);
            state.graphs.insert(id.clone(), dto.clone());
            Ok(id)
        }

        async fn get_exact(&self, _: &LoopbackHttpEndpoint, _: &SecretString, id: &str) -> Result<serde_json::Value, ImportError> {
            let mut state = self.0.lock().unwrap();
            state.reads.push(id.into());
            if std::mem::take(&mut state.fail_get_once) {
                return Err(ImportError::ambiguous("workflow_import_transport"));
            }
            let dto = state.graphs.get(id).cloned()
                .ok_or_else(|| ImportError::drift("workflow_import_fake_unknown_id"))?;
            Ok(serde_json::json!({
                "id": id, "active": false,
                "name": dto.get("name").cloned().unwrap(),
                "nodes": dto.get("nodes").cloned().unwrap(),
                "connections": dto.get("connections").cloned().unwrap(),
                "settings": dto.get("settings").cloned().unwrap(),
            }))
        }
    }

    fn harness() -> (tempfile::TempDir, IntegrationJobService, IntegrationJob, WorkflowImportManifest, WorkflowImportBinding) {
        let home = tempfile::tempdir().unwrap();
        let service = IntegrationJobService::open(home.path(), super::super::n8n_catalog(), &super::super::N8nRestartValidator::new(home.path())).unwrap();
        let manifest = import_manifest().unwrap();
        let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
        let key = SecretString::from("test-key");
        let (endpoint_digest, credential_digest) = binding_digests(&endpoint, &key);
        let contract = JobEvidenceContract::verified(
            manifest.manifest_sha256.clone(),
            sha256_parts(&[endpoint_digest.as_str(), credential_digest.as_str()]),
            expected_authenticated_probe_sha256(&endpoint),
            sha256_parts(&["n8n-workflow-import-step-plan-v1", "13"]),
        );
        let job = service.enqueue(EnqueueIntegrationJob {
            capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(),
            operation: JobOperation::Import, release_version: IMPORT_RELEASE_VERSION.into(),
            manifest_sha256: manifest.manifest_sha256.clone(), evidence_contract: contract,
            requested_by: JobRequester::Cli, total_steps: IMPORT_STEPS, bytes_total: None,
        }).unwrap().job;
        (home, service, job, manifest, WorkflowImportBinding { endpoint, key })
    }

    fn ready_job(service: &IntegrationJobService, job: IntegrationJob) -> IntegrationJob {
        let running = service.start(&job.job_id, job.state_revision, "import-workflow-01").unwrap();
        let validating = service.begin_validation(&running.job_id, running.state_revision, "validate-import-readback").unwrap();
        let configuring = service.begin_configuration(&validating.job_id, validating.state_revision, "finalize-import-readback").unwrap();
        let contract = configuring.evidence_contract.as_ref().unwrap();
        service.mark_ready(&configuring.job_id, configuring.state_revision, ReadyEvidence::verified(
            configuring.job_id.clone(), configuring.manifest_sha256.clone(),
            contract.artifact_binding_sha256().clone(), contract.config_binding_sha256().clone(),
            contract.authenticated_probe_sha256().clone(), contract.step_plan_sha256().clone(),
        )).unwrap()
    }

    #[test]
    fn manifest_contains_the_exact_ordered_unique_bundle() {
        let manifest = import_manifest().unwrap();
        assert_eq!(manifest.entries.len(), IMPORT_STEPS as usize);
        let slugs: Vec<_> = manifest.entries.iter().map(|entry| entry.slug.as_str()).collect();
        assert_eq!(slugs, all_known_workflows().iter().map(|workflow| workflow.slug).collect::<Vec<_>>());
        assert_eq!(slugs.iter().collect::<BTreeSet<_>>().len(), IMPORT_STEPS as usize);
    }

    #[test]
    fn dto_removes_import_forbidden_fields_but_preserves_graph_and_notes() {
        let workflow = all_known_workflows().into_iter()
            .find(|workflow| workflow.slug == "dream_obsidian_sync").unwrap();
        let source: serde_json::Value = serde_json::from_str(workflow.body).unwrap();
        let dto = create_dto(workflow).unwrap();
        assert!(dto.get("description").is_none());
        assert!(dto.get("active").is_none());
        assert!(dto.get("tags").is_none());
        assert_eq!(dto.get("nodes"), source.get("nodes"));
        assert!(source["nodes"].as_array().unwrap().iter().any(|node| node.get("notes").is_some()));
    }

    #[test]
    fn noninactive_source_and_wrong_readback_id_fail_closed() {
        let source = BootstrapWorkflow { slug: "bad", name: "bad", description: "bad", body: r#"{"name":"bad","active":true,"nodes":[],"connections":{},"settings":{}}"# };
        assert_eq!(create_dto(&source).unwrap_err().code, "workflow_import_source_not_inactive");
        let dto = serde_json::json!({"name":"n","nodes":[],"connections":{},"settings":{}});
        let wrong = serde_json::json!({"id":"other","active":false,"name":"n","nodes":[],"connections":{},"settings":{}});
        assert_eq!(normalized_graph(&dto, "expected", &wrong).unwrap_err().code, "workflow_import_readback_id_mismatch");
    }

    #[test]
    fn custody_round_trip_is_bounded_and_atomic_replace_safe() {
        let home = tempfile::tempdir().unwrap();
        let job_id = JobId::new();
        let manifest = import_manifest().unwrap();
        let custody = WorkflowImportCustody {
            job_id: job_id.clone(), endpoint_binding_sha256: digest_bytes(b"endpoint"),
            credential_binding_sha256: digest_bytes(b"credential"), manifest_sha256: manifest.manifest_sha256,
            entries: manifest.entries.into_iter().map(|entry| WorkflowImportEntry {
                slug: entry.slug, source_sha256: entry.source_sha256, create_dto_sha256: entry.dto_sha256,
                state: ImportEntryState::Prepared,
            }).collect(),
        };
        save_custody(home.path(), &custody).unwrap();
        save_custody(home.path(), &custody).unwrap();
        assert_eq!(load_custody(home.path(), &job_id).unwrap().entries.len(), IMPORT_STEPS as usize);
        let queued = IntegrationJob {
            job_id: job_id.clone(), capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(),
            operation: JobOperation::Import, release_version: IMPORT_RELEASE_VERSION.into(),
            manifest_sha256: custody.manifest_sha256.clone(), state: JobState::Queued, state_revision: 0,
            current_step: None, progress: JobProgress::new(IMPORT_STEPS, None), created_at: 0, started_at: None,
            updated_at: 0, terminal_at: None, failure: None, evidence_contract: None, progress_evidence: None,
            ready_evidence: None, retry_of: None, requested_by: JobRequester::Cli, cancel_requested: false,
        };
        assert!(safe_to_terminalize_import(home.path(), &queued, &ImportError::local("pre_intent")));
    }

    #[test]
    fn importer_lifetime_lock_rejects_a_contender_before_dispatch() {
        let home = tempfile::tempdir().unwrap();
        let path = import_lock_path(home.path());
        let holder = crate::util::locked_file::lock_file_blocking(&path, "n8n workflow import").unwrap();
        assert!(crate::util::locked_file::try_lock_file_once(&path, "n8n workflow import").unwrap().is_none());
        drop(holder);
        assert!(crate::util::locked_file::try_lock_file_once(&path, "n8n workflow import").unwrap().is_some());
    }

    #[tokio::test]
    async fn all_thirteen_then_ready_repeat_is_read_only() {
        let (home, service, job, manifest, binding) = harness();
        let transport = FakeTransport::default();
        let ready = execute_workflow_import_with_binding(&service, job, home.path(), &transport, manifest, binding).await.unwrap();
        assert_eq!(ready.state, JobState::Ready);
        assert_eq!(transport.0.lock().unwrap().creates, IMPORT_STEPS);
        let sidecar = std::fs::read(custody_path(home.path(), &ready.job_id)).unwrap();
        drop(service);
        let service = IntegrationJobService::open(home.path(), super::super::n8n_catalog(), &super::super::N8nRestartValidator::new(home.path())).unwrap();
        let repeat_manifest = import_manifest().unwrap();
        let repeat_binding = WorkflowImportBinding { endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), key: SecretString::from("test-key") };
        let repeated_admission = enqueue_workflow_import_with_binding(
            &service, repeat_manifest, repeat_binding.endpoint, repeat_binding.key, JobRequester::Cli,
        ).unwrap();
        assert!(!repeated_admission.created);
        assert_eq!(repeated_admission.job.job_id, ready.job_id);
        assert_eq!(repeated_admission.job.state_revision, ready.state_revision);
        assert_eq!(service.snapshot().unwrap().iter().filter(|job| job.operation == JobOperation::Import).count(), 1);
        execute_workflow_import_with_binding(&service, repeated_admission.job, home.path(), &transport, import_manifest().unwrap(), WorkflowImportBinding { endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), key: SecretString::from("test-key") }).await.unwrap();
        assert_eq!(transport.0.lock().unwrap().creates, IMPORT_STEPS);
        assert_eq!(std::fs::read(custody_path(home.path(), &ready.job_id)).unwrap(), sidecar);
    }

    #[tokio::test]
    async fn lost_post_reply_keeps_intent_and_never_posts_again() {
        let (home, service, job, manifest, binding) = harness();
        let transport = FakeTransport::default();
        transport.0.lock().unwrap().fail_create_once = true;
        assert_eq!(execute_workflow_import_with_binding(&service, job.clone(), home.path(), &transport, manifest, binding).await.unwrap_err().code, "workflow_import_transport");
        assert!(matches!(load_custody(home.path(), &job.job_id).unwrap().entries[0].state, ImportEntryState::IntentPersisted));
        let repeat = service.get(&job.job_id).unwrap().unwrap();
        let error = execute_workflow_import_with_binding(&service, repeat, home.path(), &transport, import_manifest().unwrap(), WorkflowImportBinding { endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), key: SecretString::from("test-key") }).await.unwrap_err();
        assert_eq!(error.code, "workflow_import_post_ambiguous");
        assert_eq!(transport.0.lock().unwrap().creates, 1);
    }

    #[tokio::test]
    async fn rejected_create_after_readback_reuses_its_active_import_job() {
        let (home, service, job, manifest, binding) = harness();
        let transport = FakeTransport::default();
        transport.0.lock().unwrap().reject_create_at = Some(2);
        assert_eq!(execute_workflow_import_with_binding(&service, job.clone(), home.path(), &transport, manifest, binding).await.unwrap_err().code, "workflow_import_create_rejected");
        assert!(matches!(load_custody(home.path(), &job.job_id).unwrap().entries[0].state, ImportEntryState::ReadBack { .. }));
        let admission = enqueue_workflow_import_with_binding(&service, import_manifest().unwrap(), LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), SecretString::from("test-key"), JobRequester::Cli).unwrap();
        assert!(!admission.created);
        assert_eq!(admission.job.job_id, job.job_id);
        assert_eq!(transport.0.lock().unwrap().creates, 2);
        assert_eq!(service.snapshot().unwrap().iter().filter(|job| job.operation == JobOperation::Import).count(), 1);
        let sidecar = std::fs::read(custody_path(home.path(), &job.job_id)).unwrap();
        let current = service.get(&job.job_id).unwrap().unwrap();
        let error = ImportError::rejected("workflow_import_create_rejected");
        assert!(safe_to_terminalize_import(home.path(), &current, &error));
        let failed = service.fail(&current.job_id, current.state_revision, JobFailure::new(
            error.code,
            "The n8n workflow import received a confirmed local or create-rejection failure; retain its custody record and repair before starting a new import.",
        ).unwrap()).unwrap();
        assert_eq!(failed.state, JobState::Failed);
        drop(service);
        let reopened = IntegrationJobService::open(home.path(), super::super::n8n_catalog(), &super::super::N8nRestartValidator::new(home.path())).unwrap();
        assert!(enqueue_workflow_import_with_binding(&reopened, import_manifest().unwrap(), LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), SecretString::from("test-key"), JobRequester::Cli).is_err());
        assert_eq!(reopened.snapshot().unwrap().iter().filter(|job| job.operation == JobOperation::Import).count(), 1);
        assert_eq!(transport.0.lock().unwrap().creates, 2);
        assert_eq!(std::fs::read(custody_path(home.path(), &job.job_id)).unwrap(), sidecar);
    }

    #[tokio::test]
    async fn create_id_is_durable_before_get_failure_then_resume_reads_exact_id() {
        let (home, service, job, manifest, binding) = harness();
        let transport = FakeTransport::default();
        transport.0.lock().unwrap().fail_get_once = true;
        assert_eq!(execute_workflow_import_with_binding(&service, job.clone(), home.path(), &transport, manifest, binding).await.unwrap_err().code, "workflow_import_transport");
        assert!(matches!(load_custody(home.path(), &job.job_id).unwrap().entries[0].state, ImportEntryState::Created { .. }));
        let resumed = service.get(&job.job_id).unwrap().unwrap();
        let ready = execute_workflow_import_with_binding(&service, resumed, home.path(), &transport, import_manifest().unwrap(), WorkflowImportBinding { endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), key: SecretString::from("test-key") }).await.unwrap();
        assert_eq!(ready.state, JobState::Ready);
        assert_eq!(transport.0.lock().unwrap().reads[1], "workflow-1");
    }

    #[tokio::test]
    async fn drifted_readback_holds_without_a_second_post() {
        let (home, service, job, manifest, binding) = harness();
        let transport = FakeTransport::default();
        let ready = execute_workflow_import_with_binding(&service, job, home.path(), &transport, manifest, binding).await.unwrap();
        transport.0.lock().unwrap().graphs.get_mut("workflow-1").unwrap()["name"] = serde_json::json!("drift");
        let error = execute_workflow_import_with_binding(&service, ready, home.path(), &transport, import_manifest().unwrap(), WorkflowImportBinding { endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(), key: SecretString::from("test-key") }).await.unwrap_err();
        assert_eq!(error.code, "workflow_import_readback_drift");
        assert_eq!(transport.0.lock().unwrap().creates, IMPORT_STEPS);
    }

    #[tokio::test]
    async fn ready_job_without_custody_never_writes_or_posts() {
        let (home, service, job, manifest, binding) = harness();
        let ready = ready_job(&service, job);
        let transport = FakeTransport::default();
        assert_eq!(execute_workflow_import_with_binding(&service, ready.clone(), home.path(), &transport, manifest, binding).await.unwrap_err().code, "workflow_import_active_custody_missing");
        assert_eq!(transport.0.lock().unwrap().creates, 0);
        assert!(!custody_path(home.path(), &ready.job_id).exists());
    }

    #[tokio::test]
    async fn running_job_without_custody_never_recreates_prepared_or_posts() {
        let (home, service, job, manifest, binding) = harness();
        let running = service.start(&job.job_id, job.state_revision, "import-workflow-01").unwrap();
        let transport = FakeTransport::default();
        assert_eq!(execute_workflow_import_with_binding(&service, running.clone(), home.path(), &transport, manifest, binding).await.unwrap_err().code, "workflow_import_active_custody_missing");
        assert_eq!(transport.0.lock().unwrap().creates, 0);
        assert!(!custody_path(home.path(), &running.job_id).exists());
    }
}
