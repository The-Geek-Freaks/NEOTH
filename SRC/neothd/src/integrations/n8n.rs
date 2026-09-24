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

pub(crate) mod managed_runtime;

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
    InvalidResponse,
    Transport,
}

impl N8nProbeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "n8n_unauthorized",
            Self::Timeout => "n8n_probe_timeout",
            Self::Redirect => "n8n_redirect_rejected",
            Self::ResponseTooLarge => "n8n_response_too_large",
            Self::InvalidResponse => "n8n_invalid_response",
            Self::Transport => "n8n_probe_transport",
        }
    }

    pub fn redacted_message(self) -> &'static str {
        match self {
            Self::Unauthorized => {
                "The n8n API key was rejected by the configured loopback instance."
            }
            Self::Timeout => {
                "The configured loopback n8n API did not respond before the bounded timeout."
            }
            Self::Redirect => {
                "The configured loopback n8n API returned a redirect, which adoption rejects."
            }
            Self::ResponseTooLarge => "The n8n API response exceeded the adoption body limit.",
            Self::InvalidResponse => {
                "The configured endpoint did not return the documented n8n workflows response."
            }
            Self::Transport => "The configured loopback n8n API could not be reached.",
        }
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
            Err(N8nProbeError::InvalidResponse)
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
            return Err(N8nProbeError::InvalidResponse);
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
        serde_json::from_slice(body).map_err(|_| N8nProbeError::InvalidResponse)?;
    let object = value.as_object().ok_or(N8nProbeError::InvalidResponse)?;
    let rows = object
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or(N8nProbeError::InvalidResponse)?;
    let has_next_cursor = match object.get("nextCursor") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(cursor))
            if !cursor.is_empty()
                && cursor.len() <= 1024
                && !cursor.chars().any(char::is_control) =>
        {
            true
        }
        _ => return Err(N8nProbeError::InvalidResponse),
    };
    let workflow_rows = u32::try_from(rows.len()).map_err(|_| N8nProbeError::InvalidResponse)?;
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
    pub state: JobState,
    pub current_step: Option<String>,
    pub completed_steps: u32,
    pub total_steps: u32,
    pub failure_code: Option<String>,
}

impl From<&IntegrationJob> for N8nJobStatusView {
    fn from(job: &IntegrationJob) -> Self {
        Self {
            id: job.job_id.clone(),
            state: job.state,
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
            let hold = || RestartDecision::Hold {
                failure: JobFailure::new(
                    "n8n_managed_cleanup_required",
                    "The managed n8n runtime retains custody; cleanup must be proven before this job can finish.",
                ).expect("static failure is valid"),
            };
            let Some(home) = self.freedom_path.parent() else { return hold(); };
            let Ok(process_disposition) = managed_runtime::recover_interrupted(home, job) else {
                return hold();
            };
            if crate::config::credentials::Credentials::rollback_n8n_adoption_at(
                &self.freedom_path, &self.credentials_path, job.job_id.as_str(),
            ).is_err() {
                return hold();
            }
            return RestartDecision::Reject {
                failure: JobFailure::new(
                    "n8n_managed_interrupted_recovered",
                    "The interrupted managed n8n runtime was removed and its binding rolled back.",
                ).expect("static failure is valid"),
                disposition: RecoveryDispositionEvidence::verified(
                    job.job_id.clone(), job.manifest_sha256.clone(),
                    contract.step_plan_sha256().clone(), job.state_revision,
                    process_disposition, sha256_parts(&["n8n-custody-rolled-back"]),
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

pub(crate) fn open_n8n_job_service(home: &Path) -> Result<IntegrationJobService, JobServiceError> {
    let service =
        IntegrationJobService::open(home, n8n_catalog(), &N8nRestartValidator::new(home))?;
    // A Ready row is immutable evidence of a completed publication. If the
    // best-effort custody-file removal was interrupted after Ready, retry only
    // that removal on the next owned adapter open. Failure intentionally leaves
    // Ready untouched and retains the custody record as the repair boundary.
    for job in service.snapshot()?.into_iter().filter(|job| {
        job.capability_id.as_str() == N8N_CAPABILITY_ID
    }) {
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
        &service, &running, home, endpoint, api_key, &HttpN8nApiProbe, cancel_rx,
    ).await {
        Ok(ready) => {
            // Ready is durable; failed private-sidecar cleanup is retried at open.
            let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
                &home.join("freedom.yaml"), &home.join("credentials.yaml"), ready.job_id.as_str(),
            );
            Ok(ready)
        }
        Err(error) => {
            let current = service.get(&running.job_id)?
                .ok_or_else(|| anyhow::anyhow!("n8n adoption job disappeared"))?;
            if error.cancelled || current.cancel_requested {
                let requested = if current.cancel_requested { current } else {
                    service.request_cancel(&current.job_id, current.state_revision)?
                };
                cancel_if_requested(&service, &requested, home)?
                    .ok_or_else(|| anyhow::anyhow!("n8n cancellation acknowledgement was not produced"))
            } else {
                rollback_and_fail(&service, &current, home, error.code).await
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
}

impl AdoptionPublishError {
    fn failed(code: &'static str) -> Self { Self { code, cancelled: false } }
    fn cancelled() -> Self { Self { code: "n8n_adoption_cancelled", cancelled: true } }
}

fn check_publish_cancel(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), AdoptionPublishError> {
    let current = service.get(&job.job_id)
        .map_err(|_| AdoptionPublishError::failed("adoption_job_read_failed"))?
        .ok_or_else(|| AdoptionPublishError::failed("adoption_job_missing"))?;
    let cancelled = current.cancel_requested || !matches!(
        cancel_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    );
    if cancelled {
        if !current.cancel_requested {
            service.request_cancel(&current.job_id, current.state_revision)
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
    let running = checkpoint(service, active, 1, N8N_ADOPTION_STEPS[0], "n8n-endpoint-validated")
        .map_err(|_| AdoptionPublishError::failed("adoption_progress_failed"))?;
    let validating = service.begin_validation(&running.job_id, running.state_revision, N8N_ADOPTION_STEPS[1])
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
    }.map_err(|error| AdoptionPublishError::failed(error.code()))?;
    check_publish_cancel(service, &validating, cancel_rx)?;
    let validating = checkpoint(service, &validating, 2, N8N_ADOPTION_STEPS[1], "n8n-precommit-probed")
        .map_err(|_| AdoptionPublishError::failed("adoption_progress_failed"))?;
    let expected_key_digest = Sha256::digest(api_key.expose().as_bytes());
    let prepared = crate::config::credentials::Credentials::prepare_n8n_adoption_at(
        &home.join("freedom.yaml"), &home.join("credentials.yaml"), validating.job_id.as_str(),
        crate::config::N8nInstanceConfig { endpoint: endpoint.clone(), api_version: None }, api_key,
    ).map_err(|_| AdoptionPublishError::failed("adoption_prepare_failed"))?;
    let configuring = service.begin_configuration(&validating.job_id, validating.state_revision, N8N_ADOPTION_STEPS[2])
        .map_err(|_| AdoptionPublishError::failed("adoption_prepare_failed"))?;
    check_publish_cancel(service, &configuring, cancel_rx)?;
    crate::config::credentials::Credentials::commit_prepared_n8n_adoption_at(prepared)
        .map_err(|_| AdoptionPublishError::failed("adoption_publish_failed"))?;
    let configuring = checkpoint(service, &configuring, 3, N8N_ADOPTION_STEPS[2], "n8n-binding-published")
        .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed"))?;
    check_publish_cancel(service, &configuring, cancel_rx)?;
    let (stored, stored_key) = crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
        &home.join("freedom.yaml"), &home.join("credentials.yaml"),
    ).map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed"))?;
    // The probe receipt binds the origin. Compare the persisted secret too:
    // changing a key must not be hidden behind an otherwise healthy endpoint.
    if stored.endpoint != endpoint || Sha256::digest(stored_key.expose().as_bytes()) != expected_key_digest {
        return Err(AdoptionPublishError::failed("n8n_postcommit_probe_failed"));
    }
    let postcommit = tokio::select! {
        biased;
        _ = &mut *cancel_rx => return Err(AdoptionPublishError::cancelled()),
        result = probe.authenticated_probe(&stored.endpoint, &stored_key) => result,
    }.map_err(|_| AdoptionPublishError::failed("n8n_postcommit_probe_failed"))?;
    if postcommit.authenticated_probe_sha256() != precommit.authenticated_probe_sha256() {
        return Err(AdoptionPublishError::failed("n8n_postcommit_probe_failed"));
    }
    check_publish_cancel(service, &configuring, cancel_rx)?;
    let configuring = checkpoint(service, &configuring, 4, N8N_ADOPTION_STEPS[3], "n8n-postcommit-probed")
        .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed"))?;
    check_publish_cancel(service, &configuring, cancel_rx)?;
    let contract = configuring.evidence_contract.as_ref()
        .ok_or_else(|| AdoptionPublishError::failed("adoption_contract_missing"))?;
    let ready = ReadyEvidence::verified(
        configuring.job_id.clone(), configuring.manifest_sha256.clone(),
        contract.artifact_binding_sha256().clone(), contract.config_binding_sha256().clone(),
        postcommit.authenticated_probe_sha256(), contract.step_plan_sha256().clone(),
    );
    service.mark_ready(&configuring.job_id, configuring.state_revision, ready)
        .map_err(|_| AdoptionPublishError::failed("adoption_cleanup_failed"))
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
    Ok(N8nStatusView {
        configured_endpoint,
        api_key_present,
        job: job.as_ref().map(N8nJobStatusView::from),
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

async fn rollback_and_fail(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    home: &Path,
    requested_code: &str,
) -> anyhow::Result<IntegrationJob> {
    let rollback = crate::config::credentials::Credentials::rollback_n8n_adoption_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        job.job_id.as_str(),
    );
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
) -> anyhow::Result<Option<IntegrationJob>> {
    let Some(job) = service.get(&known.job_id)? else {
        return Ok(None);
    };
    if !job.cancel_requested {
        return Ok(None);
    }
    let rollback = crate::config::credentials::Credentials::rollback_n8n_adoption_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        job.job_id.as_str(),
    );
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
