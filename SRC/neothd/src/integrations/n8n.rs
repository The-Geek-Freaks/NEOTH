//! Durable adoption and managed-runtime transactions for a loopback n8n instance.
//!
//! Ordinary adoption leaves process ownership with the operator. Managed install
//! separately owns an exact pinned Docker container. API verification uses
//! an authenticated, bounded request to the exact literal-loopback origin the
//! operator supplied.  The API key is borrowed for that request only and is
//! never included in a receipt, error, job, or status view.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use crate::config::LoopbackHttpEndpoint;
use crate::secret::SecretString;

use super::catalog::{
    CapabilityCatalog, CapabilityCategory, CapabilityDescriptor, CapabilityId, CapabilitySurface,
    SupportTier, TargetAvailability, TargetSelector, TargetSupport,
};
use super::jobs::EnqueueIntegrationJob;
use super::state::{
    CancellationEvidence, IntegrationJob, JobEvidenceContract, JobFailure, JobId, JobOperation,
    JobProgress, JobRequester, JobState, ProgressEvidence, ProgressEvidenceClaim, ReadyEvidence,
    RecoveryDispositionEvidence, RestartDecision, Sha256Digest,
};
use super::{EnqueueResult, IntegrationJobService, JobServiceError, RestartValidator};

pub(crate) mod bootstrap_transport;
pub(crate) mod managed_bootstrap;
pub(crate) mod managed_purge;
pub(crate) mod managed_runtime;
pub(crate) mod workflow_import;

pub const N8N_CAPABILITY_ID: &str = "n8n-instance";
const ADAPTER_REVISION: &str = "n8n-adoption-v1";
// This is the lifecycle schema release, not a claim about the adopted n8n
// binary. The revision remains inside the artifact binding provenance.
const ADAPTER_RELEASE_VERSION: &str = "1.0.0";
const N8N_WORKFLOWS_PATH: &str = "/api/v1/workflows";
const N8N_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const N8N_PROBE_BODY_MAX: usize = 32 * 1024;
const N8N_ADOPTION_STEPS: [&str; 4] = [
    "validate-loopback-endpoint",
    "authenticated-precommit-probe",
    "publish-config-and-secret",
    "authenticated-postcommit-probe",
];

/// Non-secret public receipt from the documented `GET /api/v1/workflows`
/// response. n8n does not expose a version or instance identifier from this
/// endpoint, so the receipt deliberately does not invent either field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::integrations) struct N8nProbeReceipt {
    endpoint: LoopbackHttpEndpoint,
    http_status: u16,
    workflow_rows: u32,
    has_next_cursor: bool,
}

impl N8nProbeReceipt {
    pub fn authenticated_probe_sha256(&self) -> Sha256Digest {
        sha256_parts(&[
            "n8n-authenticated-workflows-probe-v1",
            self.endpoint.origin(),
            &self.http_status.to_string(),
            "documented-workflows-envelope",
        ])
    }
}

fn expected_authenticated_probe_sha256(endpoint: &LoopbackHttpEndpoint) -> Sha256Digest {
    sha256_parts(&[
        "n8n-authenticated-workflows-probe-v1",
        endpoint.origin(),
        "200",
        "documented-workflows-envelope",
    ])
}

/// Fixed, redacted outcome codes.  No server text, URL query, header, or key
/// reaches this type because callers persist its code/message in the job DB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::integrations) enum N8nProbeError {
    Unauthorized,
    Timeout,
    Redirect,
    ResponseTooLarge,
    NegativeControlUnexpectedSuccess,
    NegativeControlNotFound,
    NegativeControlServerError,
    NegativeControlUnexpectedStatus,
    AuthenticatedNotFound,
    AuthenticatedServerError,
    AuthenticatedUnexpectedStatus,
    ResponseJsonInvalid,
    ResponseEnvelopeInvalid,
    ResponseCursorInvalid,
    Transport,
}

impl N8nProbeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "n8n_unauthorized",
            Self::Timeout => "n8n_probe_timeout",
            Self::Redirect => "n8n_redirect_rejected",
            Self::ResponseTooLarge => "n8n_response_too_large",
            Self::NegativeControlUnexpectedSuccess => "n8n_negative_control_unexpected_success",
            Self::NegativeControlNotFound => "n8n_negative_control_not_found",
            Self::NegativeControlServerError => "n8n_negative_control_server_error",
            Self::NegativeControlUnexpectedStatus => "n8n_negative_control_unexpected_status",
            Self::AuthenticatedNotFound => "n8n_authenticated_not_found",
            Self::AuthenticatedServerError => "n8n_authenticated_server_error",
            Self::AuthenticatedUnexpectedStatus => "n8n_authenticated_unexpected_status",
            Self::ResponseJsonInvalid => "n8n_response_json_invalid",
            Self::ResponseEnvelopeInvalid => "n8n_response_envelope_invalid",
            Self::ResponseCursorInvalid => "n8n_response_cursor_invalid",
            Self::Transport => "n8n_probe_transport",
        }
    }
}

fn negative_control_status_error(status: reqwest::StatusCode) -> N8nProbeError {
    if status.is_success() {
        N8nProbeError::NegativeControlUnexpectedSuccess
    } else if status == reqwest::StatusCode::NOT_FOUND {
        N8nProbeError::NegativeControlNotFound
    } else if status.is_server_error() {
        N8nProbeError::NegativeControlServerError
    } else {
        N8nProbeError::NegativeControlUnexpectedStatus
    }
}

fn authenticated_status_error(status: reqwest::StatusCode) -> N8nProbeError {
    if status == reqwest::StatusCode::NOT_FOUND {
        N8nProbeError::AuthenticatedNotFound
    } else if status.is_server_error() {
        N8nProbeError::AuthenticatedServerError
    } else {
        N8nProbeError::AuthenticatedUnexpectedStatus
    }
}

#[async_trait]
pub(in crate::integrations) trait N8nApiProbe: Send + Sync {
    async fn negative_control(&self, endpoint: &LoopbackHttpEndpoint) -> Result<(), N8nProbeError>;

    async fn authenticated_probe(
        &self,
        endpoint: &LoopbackHttpEndpoint,
        api_key: &SecretString,
    ) -> Result<N8nProbeReceipt, N8nProbeError>;
}

/// Production HTTP probe. Redirect following is disabled before the key is
/// attached, and the header is attached to exactly one URL built from the
/// validated origin.
pub(in crate::integrations) struct HttpN8nApiProbe;

#[async_trait]
impl N8nApiProbe for HttpN8nApiProbe {
    async fn negative_control(&self, endpoint: &LoopbackHttpEndpoint) -> Result<(), N8nProbeError> {
        let client = bounded_n8n_client()?;
        let response = client
            .get(format!("{}{}", endpoint.origin(), N8N_WORKFLOWS_PATH))
            .query(&[("limit", "1")])
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    N8nProbeError::Timeout
                } else {
                    N8nProbeError::Transport
                }
            })?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            Ok(())
        } else {
            Err(negative_control_status_error(response.status()))
        }
    }

    async fn authenticated_probe(
        &self,
        endpoint: &LoopbackHttpEndpoint,
        api_key: &SecretString,
    ) -> Result<N8nProbeReceipt, N8nProbeError> {
        let client = bounded_n8n_client()?;
        let url = format!("{}{}", endpoint.origin(), N8N_WORKFLOWS_PATH);
        let response = client
            .get(url)
            .query(&[("limit", "1")])
            .header("X-N8N-API-KEY", api_key.expose())
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    N8nProbeError::Timeout
                } else {
                    N8nProbeError::Transport
                }
            })?;
        if response.status().is_redirection() {
            return Err(N8nProbeError::Redirect);
        }
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(N8nProbeError::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(authenticated_status_error(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > N8N_PROBE_BODY_MAX as u64)
        {
            return Err(N8nProbeError::ResponseTooLarge);
        }
        let status = response.status().as_u16();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                if error.is_timeout() {
                    N8nProbeError::Timeout
                } else {
                    N8nProbeError::Transport
                }
            })?;
            if body.len().saturating_add(chunk.len()) > N8N_PROBE_BODY_MAX {
                return Err(N8nProbeError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        parse_workflows_response(endpoint.clone(), status, &body)
    }
}

fn bounded_n8n_client() -> Result<reqwest::Client, N8nProbeError> {
    reqwest::Client::builder()
        // An n8n API key must never traverse an ambient HTTP(S)_PROXY,
        // even when the target itself is literal loopback.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(N8N_PROBE_TIMEOUT)
        .build()
        .map_err(|_| N8nProbeError::Transport)
}

fn parse_workflows_response(
    endpoint: LoopbackHttpEndpoint,
    http_status: u16,
    body: &[u8],
) -> Result<N8nProbeReceipt, N8nProbeError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| N8nProbeError::ResponseJsonInvalid)?;
    let object = value
        .as_object()
        .ok_or(N8nProbeError::ResponseEnvelopeInvalid)?;
    let rows = object
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or(N8nProbeError::ResponseEnvelopeInvalid)?;
    let has_next_cursor = match object.get("nextCursor") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(cursor))
            if !cursor.is_empty()
                && cursor.len() <= 1024
                && !cursor.chars().any(char::is_control) =>
        {
            true
        }
        _ => return Err(N8nProbeError::ResponseCursorInvalid),
    };
    let workflow_rows =
        u32::try_from(rows.len()).map_err(|_| N8nProbeError::ResponseEnvelopeInvalid)?;
    Ok(N8nProbeReceipt {
        endpoint,
        http_status,
        workflow_rows,
        has_next_cursor,
    })
}

/// Public, persisted-safe CLI projection. It intentionally has no live probe,
/// raw response, credentials, or PATH/process assertions.
#[derive(Clone, Debug, serde::Serialize)]
pub struct N8nStatusView {
    pub configured_endpoint: Option<LoopbackHttpEndpoint>,
    pub api_key_present: bool,
    pub job: Option<N8nJobStatusView>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct N8nJobStatusView {
    pub id: JobId,
    pub operation: JobOperation,
    pub state: JobState,
    pub disposition: Option<&'static str>,
    pub config_cleanup: Option<&'static str>,
    pub current_step: Option<String>,
    pub completed_steps: u32,
    pub total_steps: u32,
    pub failure_code: Option<String>,
}

impl From<&IntegrationJob> for N8nJobStatusView {
    fn from(job: &IntegrationJob) -> Self {
        Self {
            id: job.job_id.clone(),
            operation: job.operation,
            state: job.state,
            disposition: match job.operation {
                JobOperation::Uninstall => {
                    Some(managed_runtime::managed_uninstall::disposition(job))
                }
                JobOperation::Purge if job.state == JobState::Ready => Some("volume_removed"),
                JobOperation::Purge => Some("reconciliation_required"),
                _ => None,
            },
            config_cleanup: None,
            current_step: job.current_step.clone(),
            completed_steps: job.progress.completed_steps,
            total_steps: job.progress.total_steps,
            failure_code: job.failure.as_ref().map(|failure| failure.code.clone()),
        }
    }
}

pub(in crate::integrations) fn n8n_descriptor() -> CapabilityDescriptor {
    CapabilityDescriptor {
        id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static n8n capability id is valid"),
        display_name: "Adopted n8n instance".into(),
        category: CapabilityCategory::Workflow,
        support_tier: SupportTier::Optional,
        dependencies: Vec::new(),
        targets: vec![TargetSupport {
            target: TargetSelector::parse("local").expect("static target is valid"),
            availability: TargetAvailability::Supported,
        }],
        lifecycle_adapter: Some("n8n-adoption".into()),
        probe: Some("n8n-authenticated-workflows".into()),
        // Doctor has no consumer for adoption evidence yet. Advertising it
        // would turn a CLI-only binding into a false product claim.
        surfaces: BTreeSet::from([CapabilitySurface::Cli]),
    }
}

pub(in crate::integrations) fn n8n_catalog() -> Arc<CapabilityCatalog> {
    Arc::new(CapabilityCatalog::new(vec![n8n_descriptor()]).expect("static n8n catalog is valid"))
}

/// Enqueue the immutable four-step adoption contract before touching remote or
/// configuration state. The caller must run the pre-commit probe, prepared
/// config/secret publication and post-commit probe before calling `mark_ready`.
pub(in crate::integrations) fn enqueue_adoption(
    service: &IntegrationJobService,
    endpoint: &LoopbackHttpEndpoint,
    requester: JobRequester,
) -> Result<EnqueueResult, JobServiceError> {
    let artifact = sha256_parts(&[N8N_CAPABILITY_ID, ADAPTER_REVISION, endpoint.origin()]);
    let config = sha256_parts(&[
        N8N_CAPABILITY_ID,
        endpoint.origin(),
        "credentials.n8n_api_key",
    ]);
    let contract = JobEvidenceContract::verified(
        artifact.clone(),
        config,
        expected_authenticated_probe_sha256(endpoint),
        step_plan_sha256(),
    );
    service.enqueue(EnqueueIntegrationJob {
        capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static id is valid"),
        operation: JobOperation::Install,
        release_version: ADAPTER_RELEASE_VERSION.into(),
        manifest_sha256: artifact,
        evidence_contract: contract,
        requested_by: requester,
        total_steps: N8N_ADOPTION_STEPS.len() as u32,
        bytes_total: None,
    })
}

pub(crate) fn enqueue_required_input_failure(
    service: &IntegrationJobService,
    endpoint: &LoopbackHttpEndpoint,
    requester: JobRequester,
) -> Result<IntegrationJob, JobServiceError> {
    enqueue_terminal_failure(
        service,
        endpoint,
        requester,
        "required_input",
        "Provide the n8n API key through standard input and retry the adopt command.",
    )
}

fn enqueue_terminal_failure(
    service: &IntegrationJobService,
    endpoint: &LoopbackHttpEndpoint,
    requester: JobRequester,
    code: &str,
    message: &str,
) -> Result<IntegrationJob, JobServiceError> {
    let artifact = sha256_parts(&[N8N_CAPABILITY_ID, ADAPTER_REVISION, endpoint.origin()]);
    let contract = JobEvidenceContract::verified(
        artifact.clone(),
        sha256_parts(&[
            N8N_CAPABILITY_ID,
            endpoint.origin(),
            "credentials.n8n_api_key",
        ]),
        sha256_parts(&["n8n-probe-not-run"]),
        step_plan_sha256(),
    );
    let queued = service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static id is valid"),
            operation: JobOperation::Install,
            release_version: ADAPTER_RELEASE_VERSION.into(),
            manifest_sha256: artifact,
            evidence_contract: contract,
            requested_by: requester,
            total_steps: N8N_ADOPTION_STEPS.len() as u32,
            bytes_total: None,
        })?
        .job;
    service.fail(
        &queued.job_id,
        queued.state_revision,
        JobFailure::new(code, message).expect("fixed n8n terminal failure is valid"),
    )
}

/// Owns the only durable n8n consumer and proves restart disposition against
/// the exact config/credential custody sidecar. It never treats an active job
/// as recoverable merely because an HTTP endpoint happens to answer.
pub(in crate::integrations) struct N8nRestartValidator {
    freedom_path: PathBuf,
    credentials_path: PathBuf,
}

impl N8nRestartValidator {
    pub fn new(home: &Path) -> Self {
        Self {
            freedom_path: home.join("freedom.yaml"),
            credentials_path: home.join("credentials.yaml"),
        }
    }
}

impl RestartValidator for N8nRestartValidator {
    fn validate(&self, job: &IntegrationJob) -> RestartDecision {
        if job.operation == JobOperation::Uninstall {
            // Opening a job service never repeats an interrupted delete. The
            // explicit uninstall command reconciles its exact persisted ID.
            return RestartDecision::Hold {
                failure: JobFailure::new(
                    "n8n_uninstall_reconciliation_required",
                    "The interrupted uninstall retains custody; run n8n uninstall to inspect its exact container without repeating removal.",
                )
                .expect("static failure is valid"),
            };
        }
        if job.operation == JobOperation::Purge {
            return RestartDecision::Hold {
                failure: JobFailure::new(
                    "n8n_purge_reconciliation_required",
                    "The retained-volume purge retains durable dispatch custody; rerun n8n purge to inspect exact absence without retrying deletion.",
                )
                .expect("static failure is valid"),
            };
        }
        if job.operation == JobOperation::Import {
            return RestartDecision::Hold {
                failure: JobFailure::new(
                    "n8n_workflow_import_recovery_hold",
                    "The interrupted workflow import may have crossed a create request boundary; inspect its exact custody sidecar before resuming.",
                )
                .expect("static failure is valid"),
            };
        }
        // The durable foundation has a separate migration path for legacy
        // rows without a contract. Do not panic here: a validator must never
        // certify custody when it cannot bind its disposition to a contract.
        let Some(contract) = job.evidence_contract.as_ref() else {
            return RestartDecision::Reject {
                failure: JobFailure::new(
                    "evidence_contract_migration_required",
                    "The interrupted n8n adoption has no immutable evidence contract and needs a fresh retry.",
                ).expect("static failure is valid"),
                // This deliberately cannot match a contract-less row. The job
                // service converts such legacy active rows to terminal history
                // before invoking an adapter validator.
                disposition: RecoveryDispositionEvidence::verified(
                    job.job_id.clone(), job.manifest_sha256.clone(),
                    Sha256Digest::parse("0".repeat(64)).expect("static digest"),
                    job.state_revision, sha256_parts(&["n8n-no-owned-process"]),
                    sha256_parts(&["n8n-no-contract-custody-unproven"]),
                ),
            };
        };
        if managed_runtime::is_managed_job(job) {
            let hold = || {
                RestartDecision::Hold {
                failure: JobFailure::new(
                    "n8n_managed_cleanup_required",
                    "The managed n8n runtime retains custody; cleanup must be proven before this job can finish.",
                ).expect("static failure is valid"),
            }
            };
            let Some(home) = self.freedom_path.parent() else {
                return hold();
            };
            // Bootstrap has a live isolated container/volume phase before a
            // normal runtime binding exists.  It must be inspected/resumed by
            // its custody dispatcher; ordinary recovery must never infer that
            // this Running job owns no process merely because that binding is
            // absent or malformed.
            if managed_bootstrap::recovery_requires_hold(home, job) {
                return managed_bootstrap::recovery_decision(home, job).unwrap_or_else(hold);
            }
            let Ok(process_disposition) = managed_runtime::recover_interrupted(home, job) else {
                return hold();
            };
            if crate::config::credentials::Credentials::rollback_n8n_adoption_at(
                &self.freedom_path,
                &self.credentials_path,
                job.job_id.as_str(),
            )
            .is_err()
            {
                return hold();
            }
            return RestartDecision::Reject {
                failure: JobFailure::new(
                    "n8n_managed_interrupted_recovered",
                    "The interrupted managed n8n runtime was removed and its binding rolled back.",
                )
                .expect("static failure is valid"),
                disposition: RecoveryDispositionEvidence::verified(
                    job.job_id.clone(),
                    job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(),
                    job.state_revision,
                    process_disposition,
                    sha256_parts(&["n8n-custody-rolled-back"]),
                ),
            };
        }
        let disposition = |custody| {
            RecoveryDispositionEvidence::verified(
                job.job_id.clone(),
                job.manifest_sha256.clone(),
                contract.step_plan_sha256().clone(),
                job.state_revision,
                sha256_parts(&["n8n-no-owned-process"]),
                sha256_parts(&[custody]),
            )
        };
        let reject = |code: &str| {
            RestartDecision::Reject {
            failure: JobFailure::new(code, "The interrupted n8n adoption could not prove its exact durable binding; retry adoption.")
                .expect("static failure is valid"),
            disposition: disposition("n8n-custody-rolled-back"),
        }
        };
        // There is no daemon worker to resume after this process exits. An
        // active adoption must therefore compensate its exact custody record
        // and become terminal; returning Queued would leave an unowned
        // credential-capability lock and could later reach Ready without the
        // required post-commit probe.
        match crate::config::credentials::Credentials::rollback_n8n_adoption_at(
            &self.freedom_path, &self.credentials_path, job.job_id.as_str(),
        ) {
            Ok(()) => reject("adoption_interrupted_recovered"),
            // Cleanup was not proven. The capability lock can only be
            // released because the terminal failure retains the exact private
            // custody record; its disposition deliberately says so.
            Err(_) => RestartDecision::Reject {
                failure: JobFailure::new(
                    "adoption_cleanup_failed",
                    "The interrupted n8n adoption needs operator repair before its retained binding can be trusted.",
                ).expect("static failure is valid"),
                disposition: disposition("n8n-custody-retained-for-repair"),
            },
        }
    }
}

pub(super) fn has_ready_managed_binding(
    service: &IntegrationJobService,
    home: &Path,
    endpoint: &crate::config::LoopbackHttpEndpoint,
) -> Result<bool, JobServiceError> {
    for job in service.snapshot()? {
        if job.state == JobState::Ready
            && job.operation == JobOperation::Install
            && managed_runtime::is_managed_job(&job)
            && job.capability_id.as_str() == N8N_CAPABILITY_ID
            && expected_authenticated_probe_sha256(endpoint)
                == job
                    .evidence_contract
                    .as_ref()
                    .map(JobEvidenceContract::authenticated_probe_sha256)
                    .cloned()
                    .unwrap_or_else(|| sha256_parts(&["missing-contract"]))
            && managed_runtime::ready_binding_matches(home, &job, endpoint).unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn open_n8n_job_service(home: &Path) -> Result<IntegrationJobService, JobServiceError> {
    let service =
        IntegrationJobService::open(home, n8n_catalog(), &N8nRestartValidator::new(home))?;
    // A Ready row is immutable evidence of a completed publication. If the
    // best-effort custody-file removal was interrupted after Ready, retry only
    // that removal on the next owned adapter open. Failure intentionally leaves
    // Ready untouched and retains the custody record as the repair boundary.
    for job in service
        .snapshot()?
        .into_iter()
        .filter(|job| job.capability_id.as_str() == N8N_CAPABILITY_ID)
    {
        if job.operation == JobOperation::Uninstall {
            if job.state == JobState::Ready {
                let _ = managed_runtime::managed_uninstall::finalize_ready_uninstall_custody(
                    home, &job,
                );
            }
            continue;
        }
        if job.operation == JobOperation::Purge {
            continue;
        }
        if managed_runtime::is_managed_job(&job) {
            // Keep runtime custody until the matching durable terminal exists.
            // A failed reconciliation retains the sidecar for a later retry.
            if job.state == JobState::Ready {
                let _ = managed_runtime::reconcile_ready_custody(home, &job);
            } else if matches!(job.state, JobState::Failed | JobState::Cancelled) {
                let _ = managed_runtime::finalize_terminal_custody(home, &job);
            }
        }
        if job.state != JobState::Ready {
            continue;
        }
        // Ready evidence is already durable. A failed custody-file cleanup is
        // retained for status/open repair; it must not turn a completed
        // adoption into an unredacted open error or touch another capability.
        if crate::config::credentials::Credentials::finish_n8n_adoption_at(
            &home.join("freedom.yaml"),
            &home.join("credentials.yaml"),
            job.job_id.as_str(),
        )
        .is_err()
        {}
    }
    Ok(service)
}

/// Check the ordinary managed-install prerequisite before it can create a job
/// or process custody. The coherent reader takes config locks and may recover
/// an already prepared config transaction; it does not initialize a fresh home.
/// Initialization remains an explicit `neoth init` operation.
pub(super) fn ensure_initialized_home_for_new_managed_install(home: &Path) -> anyhow::Result<()> {
    match crate::config::load_optional_runtime_config_pair_read_only_with_store_from_path(
        &home.join("freedom.yaml"),
        None,
    ) {
        Ok((Some(_), _)) => Ok(()),
        Ok((None, _)) => anyhow::bail!("n8n_managed_home_uninitialized"),
        Err(_) => anyhow::bail!("n8n_managed_home_invalid"),
    }
}

/// Import all bundled inactive workflows through an independent durable Import
/// job. It only consumes an already published n8n binding and has no Docker
/// process ownership.
pub(crate) async fn import_managed_workflows_at(home: &Path) -> anyhow::Result<IntegrationJob> {
    // The service's DB owner lease excludes independent processes while it is
    // open, but it does not cover the gap before idempotent enqueue nor two
    // callers sharing an already-open process. Retain this sibling lock over
    // every custody read/write and POST boundary.
    let _import_lock = crate::util::locked_file::lock_file_blocking(
        &workflow_import::import_lock_path(home),
        "n8n workflow import",
    )?;
    let service = open_n8n_job_service(home)?;
    let queued =
        workflow_import::enqueue_managed_workflow_import(&service, home, JobRequester::Cli)?;
    let job_id = queued.job.job_id.clone();
    let result = workflow_import::execute_managed_workflow_import_at(
        &service,
        queued.job,
        home,
        &workflow_import::HttpWorkflowImportTransport,
    )
    .await;
    match result {
        Ok(job) => Ok(job),
        Err(error) => {
            let current = service
                .get(&job_id)?
                .ok_or_else(|| anyhow::anyhow!("n8n workflow import job disappeared"))?;
            if !workflow_import::safe_to_terminalize_import(home, &current, &error) {
                return Err(anyhow::anyhow!(error.code));
            }
            if current.state.is_terminal() {
                return Ok(current);
            }
            let failed = service.fail(
                &current.job_id,
                current.state_revision,
                JobFailure::new(error.code, "The n8n workflow import received a confirmed local or create-rejection failure; retain its custody record and repair before starting a new import.")?,
            )?;
            Ok(failed)
        }
    }
}

/// Execute one complete adoption while holding no process ownership over n8n.
/// Every post-publication error compensates the exact prepared generation
/// before its terminal job state is written.
#[cfg(test)]
pub(crate) async fn adopt_at(
    home: &Path,
    endpoint: LoopbackHttpEndpoint,
    api_key: SecretString,
) -> anyhow::Result<IntegrationJob> {
    let (_cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    adopt_at_with_cancel(home, endpoint, api_key, &mut cancel_rx).await
}

/// Same adoption path with a narrow, injected cancellation seam. Production
/// wires this to Ctrl-C; adapter tests can cancel a single bounded probe
/// without installing a host signal handler.
pub(crate) async fn adopt_at_with_cancel(
    home: &Path,
    endpoint: LoopbackHttpEndpoint,
    api_key: SecretString,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    let service = open_n8n_job_service(home)?;
    let queued = enqueue_adoption(&service, &endpoint, JobRequester::Cli)?.job;
    if cancel_rx.try_recv().is_ok() {
        return Ok(service.request_cancel(&queued.job_id, queued.state_revision)?);
    }
    let running = service.start(&queued.job_id, queued.state_revision, N8N_ADOPTION_STEPS[0])?;
    match publish_adoption_in_job_with_cancel(
        &service,
        &running,
        home,
        endpoint,
        api_key,
        &HttpN8nApiProbe,
        cancel_rx,
    )
    .await
    {
        Ok(ready) => {
            // Ready is durable; failed private-sidecar cleanup is retried at open.
            let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
                &home.join("freedom.yaml"),
                &home.join("credentials.yaml"),
                ready.job_id.as_str(),
            );
            Ok(ready)
        }
        Err(error) => {
            let current = service
                .get(&running.job_id)?
                .ok_or_else(|| anyhow::anyhow!("n8n adoption job disappeared"))?;
            if error.cancelled || current.cancel_requested {
                let requested = if current.cancel_requested {
                    current
                } else {
                    service.request_cancel(&current.job_id, current.state_revision)?
                };
                cancel_if_requested(&service, &requested, home, error.custody_may_exist)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("n8n cancellation acknowledgement was not produced")
                    })
            } else {
                rollback_and_fail(
                    &service,
                    &current,
                    home,
                    error.code,
                    error.custody_may_exist,
                )
                .await
            }
        }
    }
}

/// Redacted failure of the shared publisher. The caller still owns every
/// process/config effect and must compensate before terminalizing this job.
#[derive(Debug, Clone, Copy)]
pub(super) struct AdoptionPublishError {
    pub(super) code: &'static str,
    pub(super) cancelled: bool,
    pub(super) custody_may_exist: bool,
}

impl AdoptionPublishError {
    fn failed(code: &'static str) -> Self {
        Self {
            code,
            cancelled: false,
            custody_may_exist: false,
        }
    }
    fn cancelled() -> Self {
        Self {
            code: "n8n_adoption_cancelled",
            cancelled: true,
            custody_may_exist: false,
        }
    }
    fn after_prepare(mut self) -> Self {
        self.custody_may_exist = true;
        self
    }
}

fn check_publish_cancel(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), AdoptionPublishError> {
    let current = service
        .get(&job.job_id)
        .map_err(|_| AdoptionPublishError::failed("adoption_job_read_failed"))?
        .ok_or_else(|| AdoptionPublishError::failed("adoption_job_missing"))?;
    let cancelled = current.cancel_requested
        || !matches!(
            cancel_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
    if cancelled {
        if !current.cancel_requested {
            service
                .request_cancel(&current.job_id, current.state_revision)
                .map_err(|_| AdoptionPublishError::failed("adoption_cancel_request_failed"))?;
        }
        return Err(AdoptionPublishError::cancelled());
    }
    Ok(())
}

/// The sole config/key publisher for ordinary adoption and managed install.
/// It never enqueues a second job and never compensates a caller-owned runtime.
/// On failure the caller reloads the current job revision before compensation.
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_adoption_in_job_with_cancel<P: N8nApiProbe + ?Sized>(
    service: &IntegrationJobService,
    active: &IntegrationJob,
    home: &Path,
    endpoint: LoopbackHttpEndpoint,
    api_key: SecretString,
    probe: &P,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<IntegrationJob, AdoptionPublishError> {
    check_publish_cancel(service, active, cancel_rx)?;
    let running = checkpoint(
        service,
        active,
        1,
        N8N_ADOPTION_STEPS[0],
        "n8n-endpoint-validated",
    )
    .map_err(|_| AdoptionPublishError::failed("adoption_progress_failed"))?;
    let validating = service
        .begin_validation(
            &running.job_id,
            running.state_revision,
            N8N_ADOPTION_STEPS[1],
        )
        .map_err(|_| AdoptionPublishError::failed("adoption_validation_failed"))?;
    let negative = tokio::select! {
        biased;
        _ = &mut *cancel_rx => return Err(AdoptionPublishError::cancelled()),
        result = probe.negative_control(&endpoint) => result,
    };
    negative.map_err(|error| AdoptionPublishError::failed(error.code()))?;
    check_publish_cancel(service, &validating, cancel_rx)?;
    let precommit = tokio::select! {
        biased;
        _ = &mut *cancel_rx => return Err(AdoptionPublishError::cancelled()),
        result = probe.authenticated_probe(&endpoint, &api_key) => result,
    }
    .map_err(|error| AdoptionPublishError::failed(error.code()))?;
    check_publish_cancel(service, &validating, cancel_rx)?;
    let validating = checkpoint(
        service,
        &validating,
        2,
        N8N_ADOPTION_STEPS[1],
        "n8n-precommit-probed",
    )
    .map_err(|_| AdoptionPublishError::failed("adoption_progress_failed"))?;
    let expected_key_digest = Sha256::digest(api_key.expose().as_bytes());
    let prepared = crate::config::credentials::Credentials::prepare_n8n_adoption_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        validating.job_id.as_str(),
        crate::config::N8nInstanceConfig {
            endpoint: endpoint.clone(),
            api_version: None,
        },
        api_key,
    )
    .map_err(|_| AdoptionPublishError::failed("adoption_prepare_failed").after_prepare())?;
    let configuring = service
        .begin_configuration(
            &validating.job_id,
            validating.state_revision,
            N8N_ADOPTION_STEPS[2],
        )
        .map_err(|_| AdoptionPublishError::failed("adoption_prepare_failed").after_prepare())?;
    check_publish_cancel(service, &configuring, cancel_rx)
        .map_err(AdoptionPublishError::after_prepare)?;
    crate::config::credentials::Credentials::commit_prepared_n8n_adoption_at(prepared)
        .map_err(|_| AdoptionPublishError::failed("adoption_publish_failed").after_prepare())?;
    let configuring = checkpoint(
        service,
        &configuring,
        3,
        N8N_ADOPTION_STEPS[2],
        "n8n-binding-published",
    )
    .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed").after_prepare())?;
    check_publish_cancel(service, &configuring, cancel_rx)
        .map_err(AdoptionPublishError::after_prepare)?;
    let (stored, stored_key) =
        crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
            &home.join("freedom.yaml"),
            &home.join("credentials.yaml"),
        )
        .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed").after_prepare())?;
    // The probe receipt binds the origin. Compare the persisted secret too:
    // changing a key must not be hidden behind an otherwise healthy endpoint.
    if stored.endpoint != endpoint
        || Sha256::digest(stored_key.expose().as_bytes()) != expected_key_digest
    {
        return Err(AdoptionPublishError::failed("n8n_postcommit_probe_failed").after_prepare());
    }
    let postcommit = tokio::select! {
        biased;
        _ = &mut *cancel_rx => return Err(AdoptionPublishError::cancelled().after_prepare()),
        result = probe.authenticated_probe(&stored.endpoint, &stored_key) => result,
    }
    .map_err(|_| AdoptionPublishError::failed("n8n_postcommit_probe_failed").after_prepare())?;
    if postcommit.authenticated_probe_sha256() != precommit.authenticated_probe_sha256() {
        return Err(AdoptionPublishError::failed("n8n_postcommit_probe_failed").after_prepare());
    }
    check_publish_cancel(service, &configuring, cancel_rx)
        .map_err(AdoptionPublishError::after_prepare)?;
    let configuring = checkpoint(
        service,
        &configuring,
        4,
        N8N_ADOPTION_STEPS[3],
        "n8n-postcommit-probed",
    )
    .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed").after_prepare())?;
    check_publish_cancel(service, &configuring, cancel_rx)
        .map_err(AdoptionPublishError::after_prepare)?;
    let contract = configuring
        .evidence_contract
        .as_ref()
        .ok_or_else(|| AdoptionPublishError::failed("adoption_contract_missing").after_prepare())?;
    let ready = ReadyEvidence::verified(
        configuring.job_id.clone(),
        configuring.manifest_sha256.clone(),
        contract.artifact_binding_sha256().clone(),
        contract.config_binding_sha256().clone(),
        postcommit.authenticated_probe_sha256(),
        contract.step_plan_sha256().clone(),
    );
    service
        .mark_ready(&configuring.job_id, configuring.state_revision, ready)
        .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed").after_prepare())
}

pub(crate) fn status_at(
    home: &Path,
    selected_job: Option<&JobId>,
) -> anyhow::Result<N8nStatusView> {
    let (configured_endpoint, api_key_present) =
        crate::config::credentials::Credentials::read_n8n_adoption_status_at(
            &home.join("freedom.yaml"),
            &home.join("credentials.yaml"),
        )?;
    let jobs: Vec<_> = IntegrationJobService::read_only_snapshot(home)?
        .into_iter()
        .filter(|candidate| candidate.capability_id.as_str() == N8N_CAPABILITY_ID)
        .collect();
    let job = match selected_job {
        Some(id) => jobs.into_iter().find(|candidate| &candidate.job_id == id),
        None => jobs
            .into_iter()
            .max_by_key(|candidate| (candidate.updated_at, candidate.job_id.clone())),
    };
    let job = job.as_ref().map(|job| {
        let mut view = N8nJobStatusView::from(job);
        if job.operation == JobOperation::Uninstall {
            view.config_cleanup = Some(
                managed_runtime::managed_uninstall::cleanup_disposition_at(home, job)
                    .ok()
                    .flatten()
                    .unwrap_or("unknown_or_preserved"),
            );
        }
        view
    });
    Ok(N8nStatusView {
        configured_endpoint,
        api_key_present,
        job,
    })
}

fn checkpoint(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    completed_steps: u32,
    step: &str,
    staging: &str,
) -> Result<IntegrationJob, JobServiceError> {
    let contract = job
        .evidence_contract
        .as_ref()
        .expect("n8n job has immutable evidence contract");
    let progress = JobProgress {
        completed_steps,
        total_steps: N8N_ADOPTION_STEPS.len() as u32,
        bytes_done: 0,
        bytes_total: None,
    };
    let evidence = ProgressEvidence::claimed(ProgressEvidenceClaim {
        job_id: job.job_id.clone(),
        manifest_sha256: job.manifest_sha256.clone(),
        step_plan_sha256: contract.step_plan_sha256().clone(),
        staging_binding_sha256: sha256_parts(&[staging]),
        expected_revision: job.state_revision,
        expected_state: job.state,
        current_phase: step.into(),
        completed_steps,
        bytes_done: 0,
    });
    service.update_progress(
        &job.job_id,
        job.state_revision,
        job.state,
        progress,
        Some(step.into()),
        evidence,
    )
}

/// Compensate a binding only when this job has durably prepared custody. The
/// precommit probes run before preparation, so a missing exact sidecar proves
/// this job has not published config or credential state to roll back.
pub(super) fn rollback_adoption_if_prepared(
    home: &Path,
    job_id: &JobId,
    custody_may_exist: bool,
) -> anyhow::Result<bool> {
    let custody = home.join(format!(".n8n-adoption-{}.custody.yaml", job_id.as_str()));
    match std::fs::symlink_metadata(&custody) {
        Ok(metadata) if metadata.file_type().is_file() => {
            crate::config::credentials::Credentials::rollback_n8n_adoption_at(
                &home.join("freedom.yaml"),
                &home.join("credentials.yaml"),
                job_id.as_str(),
            )?;
            Ok(true)
        }
        Ok(_) => anyhow::bail!("n8n adoption custody path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !custody_may_exist => {
            Ok(false)
        }
        Err(error) => Err(error)
            .with_context(|| format!("inspect n8n adoption custody {}", custody.display())),
    }
}

async fn rollback_and_fail(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    home: &Path,
    requested_code: &str,
    custody_may_exist: bool,
) -> anyhow::Result<IntegrationJob> {
    let rollback = rollback_adoption_if_prepared(home, &job.job_id, custody_may_exist);
    let (code, message) = if rollback.is_ok() {
        (
            requested_code,
            "The post-publication n8n probe failed; the endpoint and credential binding were rolled back.",
        )
    } else {
        (
            "adoption_cleanup_failed",
            "The n8n binding could not be verified and automatic cleanup needs operator repair.",
        )
    };
    let failed = service.fail(
        &job.job_id,
        job.state_revision,
        JobFailure::new(code, message).expect("static failure is valid"),
    )?;
    Ok(failed)
}

/// Observe a durable cancel request between bounded operations. Before
/// acknowledgement this compensates the exact prepared/published binding; a
/// cleanup error becomes a redacted terminal failure rather than Cancelled.
fn cancel_if_requested(
    service: &IntegrationJobService,
    known: &IntegrationJob,
    home: &Path,
    custody_may_exist: bool,
) -> anyhow::Result<Option<IntegrationJob>> {
    let Some(job) = service.get(&known.job_id)? else {
        return Ok(None);
    };
    if !job.cancel_requested {
        return Ok(None);
    }
    let rollback = rollback_adoption_if_prepared(home, &job.job_id, custody_may_exist);
    if rollback.is_err() {
        return Ok(Some(
            service.fail(
                &job.job_id,
                job.state_revision,
                JobFailure::new(
                    "adoption_cleanup_failed",
                    "The n8n adoption was cancelled but automatic cleanup needs operator repair.",
                )
                .expect("static failure is valid"),
            )?,
        ));
    }
    let contract = job
        .evidence_contract
        .as_ref()
        .expect("active n8n job has evidence contract");
    let evidence = CancellationEvidence::verified(
        job.job_id.clone(),
        job.manifest_sha256.clone(),
        contract.step_plan_sha256().clone(),
        job.state_revision,
        sha256_parts(&["n8n-no-owned-process"]),
        sha256_parts(&["n8n-custody-rolled-back"]),
    );
    Ok(Some(service.acknowledge_cancel(
        &job.job_id,
        job.state_revision,
        evidence,
    )?))
}

pub(in crate::integrations) fn step_plan_sha256() -> Sha256Digest {
    sha256_parts(&N8N_ADOPTION_STEPS)
}

fn sha256_parts(parts: &[&str]) -> Sha256Digest {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    Sha256Digest::parse(format!("{:x}", digest.finalize()))
        .expect("SHA-256 formatting is canonical")
}

#[cfg(test)]
#[path = "n8n_tests.rs"]
mod tests;
