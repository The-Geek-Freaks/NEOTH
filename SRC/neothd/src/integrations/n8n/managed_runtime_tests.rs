use super::*;
use std::sync::{Arc, Mutex};

fn initialize_home(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}

fn receipt(succeeded: bool) -> ManagedCommandReceipt {
    ManagedCommandReceipt {
        succeeded,
        output_sha256: "a".repeat(64),
    }
}

#[derive(Clone)]
struct RunnerState {
    container: Option<ObservedContainer>,
    create_error_after_effect: bool,
    remove_succeeds: bool,
    named_unknown: bool,
    exact_unknown: bool,
    calls: Vec<String>,
}
struct FakeRunner(Arc<Mutex<RunnerState>>);
impl FakeRunner {
    fn fresh() -> (Self, Arc<Mutex<RunnerState>>) {
        let state = Arc::new(Mutex::new(RunnerState {
            container: None,
            create_error_after_effect: false,
            remove_succeeds: true,
            named_unknown: false,
            exact_unknown: false,
            calls: Vec::new(),
        }));
        (Self(state.clone()), state)
    }
    fn foreign(job: &str, port: u16) -> (Self, Arc<Mutex<RunnerState>>) {
        let (runner, state) = Self::fresh();
        state.lock().unwrap().container = Some(observed("f".repeat(64), job, port));
        (runner, state)
    }
}
fn observed(id: String, job: &str, port: u16) -> ObservedContainer {
    ObservedContainer {
        id,
        image: N8N_OCI_REFERENCE.into(),
        managed: MANAGED_LABEL_VALUE.into(),
        job: job.into(),
        host_ip: "127.0.0.1".into(),
        host_port: port,
        volume: DEFAULT_VOLUME.into(),
        mount_destination: "/home/node/.n8n".into(),
    }
}

#[async_trait::async_trait]
impl ManagedDockerRunner for FakeRunner {
    async fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push("inspect_named".into());
        if state.named_unknown {
            Ok(InspectOutcome::Unknown)
        } else {
            Ok(state
                .container
                .clone()
                .map(InspectOutcome::Found)
                .unwrap_or(InspectOutcome::Absent))
        }
    }
    async fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("inspect_exact:{id}"));
        if state.exact_unknown {
            return Ok(InspectOutcome::Unknown);
        }
        Ok(match &state.container {
            Some(found) if found.id == id => InspectOutcome::Found(found.clone()),
            _ => InspectOutcome::Absent,
        })
    }
    async fn create(&mut self, argv: &[String]) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push("create".into());
        let job = argv
            .windows(2)
            .find(|pair| pair[0] == "--label" && pair[1].starts_with("io.neoth.n8n-job="))
            .map(|pair| pair[1].trim_start_matches("io.neoth.n8n-job=").to_owned())
            .ok_or("fake_missing_job_label")?;
        let port = argv
            .windows(2)
            .find(|pair| pair[0] == "-p")
            .and_then(|pair| pair[1].split(':').nth(1))
            .and_then(|value| value.parse().ok())
            .ok_or("fake_missing_loopback_port")?;
        state.container = Some(observed("c".repeat(64), &job, port));
        if state.create_error_after_effect {
            Err("fake_create_interrupted")
        } else {
            Ok(receipt(true))
        }
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("remove:{id}"));
        if state.remove_succeeds && state.container.as_ref().is_some_and(|found| found.id == id) {
            state.container = None;
            Ok(receipt(true))
        } else {
            Ok(receipt(false))
        }
    }
}

struct Ready;
#[async_trait::async_trait]
impl ManagedReadiness for Ready {
    async fn health(&self, _: u16) -> bool {
        true
    }
}

#[derive(Clone, Copy)]
enum AuthPlan {
    Ok,
    Unauthorized,
    Invalid,
    HangAndCancel,
}
struct Probe {
    auth: Arc<Mutex<Vec<AuthPlan>>>,
    cancel: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}
impl Probe {
    fn new(steps: Vec<AuthPlan>) -> Self {
        Self {
            auth: Arc::new(Mutex::new(steps)),
            cancel: Arc::new(Mutex::new(None)),
        }
    }
    fn with_cancellation(steps: Vec<AuthPlan>, sender: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            auth: Arc::new(Mutex::new(steps)),
            cancel: Arc::new(Mutex::new(Some(sender))),
        }
    }
}
#[async_trait::async_trait]
impl super::super::N8nApiProbe for Probe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<(), super::super::N8nProbeError> {
        Ok(())
    }
    async fn authenticated_probe(
        &self,
        endpoint: &crate::config::LoopbackHttpEndpoint,
        _: &crate::secret::SecretString,
    ) -> Result<super::super::N8nProbeReceipt, super::super::N8nProbeError> {
        let plan = { self.auth.lock().unwrap().remove(0) };
        match plan {
            AuthPlan::Ok => super::super::parse_workflows_response(
                endpoint.clone(),
                200,
                br#"{"data":[],"nextCursor":null}"#,
            ),
            AuthPlan::Unauthorized => Err(super::super::N8nProbeError::Unauthorized),
            AuthPlan::Invalid => Err(super::super::N8nProbeError::ResponseEnvelopeInvalid),
            AuthPlan::HangAndCancel => {
                if let Some(sender) = self.cancel.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                std::future::pending().await
            }
        }
    }
}
fn request() -> ManagedN8nRequest {
    ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap()
}
fn key() -> crate::secret::SecretString {
    crate::secret::SecretString::from("test-n8n-key")
}

struct PanicProbe;
#[async_trait::async_trait]
impl super::super::N8nApiProbe for PanicProbe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<(), super::super::N8nProbeError> {
        panic!("preflight must reject before a probe")
    }

    async fn authenticated_probe(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
        _: &crate::secret::SecretString,
    ) -> Result<super::super::N8nProbeReceipt, super::super::N8nProbeError> {
        panic!("preflight must reject before a probe")
    }
}

#[tokio::test]
async fn uninitialized_home_rejects_managed_install_before_job_custody_or_docker() {
    let home = tempfile::tempdir().unwrap();
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();

    let error = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &PanicProbe,
        &mut cancel,
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "n8n_managed_home_uninitialized");
    assert!(state.lock().unwrap().calls.is_empty());
    assert!(
        super::super::IntegrationJobService::read_only_snapshot(home.path())
            .unwrap()
            .is_empty()
    );
    assert_eq!(read_binding(home.path()).unwrap(), None);
    assert!(!home.path().join("setup.db").exists());
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn invalid_home_rejects_managed_install_before_job_custody_or_docker() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("freedom.yaml"), "not: [valid").unwrap();
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();

    let error = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &PanicProbe,
        &mut cancel,
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "n8n_managed_home_invalid");
    assert!(state.lock().unwrap().calls.is_empty());
    assert!(
        super::super::IntegrationJobService::read_only_snapshot(home.path())
            .unwrap()
            .is_empty()
    );
    assert_eq!(read_binding(home.path()).unwrap(), None);
    assert!(!home.path().join("setup.db").exists());
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn production_readiness_waits_for_readiness_after_liveness_is_live() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for (expected_path, response) in [
            ("/healthz", "HTTP/1.1 200 OK"),
            ("/healthz/readiness", "HTTP/1.1 503 Service Unavailable"),
            ("/healthz/readiness", "HTTP/1.1 200 OK"),
        ] {
            let exchange = async {
                let (mut stream, _) = listener.accept().await?;
                let mut request = Vec::with_capacity(128);
                let mut chunk = [0_u8; 128];
                while request.len() < 512 && !request.windows(2).any(|pair| pair == b"\r\n") {
                    let read_len = (512 - request.len()).min(chunk.len());
                    let read = stream.read(&mut chunk[..read_len]).await?;
                    if read == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "fixture client closed before request line",
                        ));
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                let saw_request_line = request.windows(2).any(|pair| pair == b"\r\n");
                assert!(saw_request_line, "fixture request line exceeded 512 bytes");
                let expected_request = format!("GET {expected_path} ");
                assert!(String::from_utf8_lossy(&request).starts_with(&expected_request));
                stream
                    .write_all(format!("{response}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await
            };
            tokio::time::timeout(std::time::Duration::from_secs(2), exchange)
                .await
                .expect("bounded fixture exchange")
                .unwrap();
        }
    });

    assert_eq!(
        crate::installers::n8n::probe_n8n_endpoint(port).await,
        crate::installers::n8n::N8nProbeOutcome::Reachable
    );
    assert!(!ProductionReadiness.health(port).await);
    assert!(ProductionReadiness.health(port).await);
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("bounded fixture join")
        .unwrap();
}

#[test]
fn managed_runtime_rejects_non_loopback_and_unpinned_requests_before_docker() {
    assert!(ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).is_ok());
    assert!(ManagedN8nRequest::new(0, N8N_OCI_REFERENCE).is_err());
    assert!(ManagedN8nRequest::new(5678, "docker.io/n8nio/n8n:latest").is_err());
    assert!(ManagedN8nRequest::new(5678, "docker.io/n8nio/n8n@sha256:bad").is_err());
}

#[tokio::test]
async fn managed_success_is_one_ready_job_with_bound_runtime_and_persisted_adoption() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![AuthPlan::Ok, AuthPlan::Ok]),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Ready);
    let jobs = super::super::IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].job_id, job.job_id);
    let binding = read_binding(home.path()).unwrap().unwrap();
    assert_eq!(binding.phase, RuntimePhase::Ready);
    assert_eq!(binding.job_id, job.job_id.as_str());
    assert_eq!(
        binding.container_id.as_deref(),
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    );
    let (stored, stored_key) =
        crate::config::credentials::Credentials::read_n8n_adoption_binding_at(
            &home.path().join("freedom.yaml"),
            &home.path().join("credentials.yaml"),
        )
        .unwrap();
    assert_eq!(stored.endpoint, request().endpoint());
    assert_eq!(stored_key.expose(), "test-n8n-key");
    assert_eq!(
        state.lock().unwrap().calls,
        vec!["inspect_named", "create", "inspect_named"]
    );
}

#[tokio::test]
async fn precommit_failure_removes_exact_container_and_restores_config_before_terminal_failure() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![AuthPlan::Unauthorized]),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Failed);
    assert_eq!(job.failure.unwrap().code, "n8n_unauthorized");
    assert!(state.lock().unwrap().container.is_none());
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        before
    );
    assert!(!home.path().join("credentials.yaml").exists());
    assert_eq!(read_binding(home.path()).unwrap(), None);
}

#[tokio::test]
async fn postcommit_failure_removes_exact_container_and_restores_published_config() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![AuthPlan::Ok, AuthPlan::Invalid]),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Failed);
    assert_eq!(job.failure.unwrap().code, "n8n_postcommit_probe_failed");
    assert!(state.lock().unwrap().container.is_none());
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn cancellation_after_bound_hanging_authenticated_probe_is_durable_only_after_exact_removal()
{
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    let (sender, mut cancel) = tokio::sync::oneshot::channel();
    let probe = Probe::with_cancellation(vec![AuthPlan::HangAndCancel], sender);
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &probe,
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Cancelled);
    assert!(job.cancel_requested);
    let calls = state.lock().unwrap().calls.clone();
    assert!(calls.iter().any(|call| call.starts_with("remove:cccc")));
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("inspect_exact:cccc"))
    );
    assert!(state.lock().unwrap().container.is_none());
    assert_eq!(read_binding(home.path()).unwrap(), None);
}

#[tokio::test]
async fn ambiguous_create_reconciles_exact_effect_and_foreign_named_container_is_never_removed() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    state.lock().unwrap().create_error_after_effect = true;
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![AuthPlan::Ok, AuthPlan::Ok]),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Ready);
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::Ready
    );
    let foreign_home = tempfile::tempdir().unwrap();
    initialize_home(foreign_home.path());
    let (mut foreign, foreign_state) = FakeRunner::foreign("another-job", 5678);
    let (_foreign_cancel_tx, mut foreign_cancel) = tokio::sync::oneshot::channel();
    let foreign_job = install_managed_at_with(
        foreign_home.path(),
        request(),
        key(),
        &mut foreign,
        &Ready,
        &Probe::new(vec![]),
        &mut foreign_cancel,
    )
    .await
    .unwrap();
    assert_eq!(foreign_job.state, super::super::JobState::Failed);
    assert_eq!(
        foreign_job.failure.unwrap().code,
        "n8n_preexisting_container_unowned_or_mismatch"
    );
    assert_eq!(
        foreign_state
            .lock()
            .unwrap()
            .container
            .as_ref()
            .unwrap()
            .job,
        "another-job"
    );
    assert!(
        !foreign_state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call.starts_with("remove:"))
    );
}

#[test]
fn runtime_sidecar_denies_unknown_fields() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let binding = RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::Bound,
        job_id: "job-a".into(),
        manifest_sha256: "a".repeat(64),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: Some("c".repeat(64)),
        image: N8N_OCI_REFERENCE.into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
    };
    write_binding(home.path(), &binding).unwrap();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(binding_path(home.path())).unwrap()).unwrap();
    raw.as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::Value::Bool(true));
    std::fs::write(binding_path(home.path()), serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        read_binding(home.path()),
        Err("n8n_runtime_binding_invalid")
    );
}

struct FakeRecovery(Arc<Mutex<RunnerState>>);
impl ManagedRecoveryRunner for FakeRecovery {
    fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push("recovery_inspect_named".into());
        if state.named_unknown {
            Ok(InspectOutcome::Unknown)
        } else {
            Ok(state
                .container
                .clone()
                .map(InspectOutcome::Found)
                .unwrap_or(InspectOutcome::Absent))
        }
    }
    fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("recovery_inspect_exact:{id}"));
        if state.exact_unknown {
            return Ok(InspectOutcome::Unknown);
        }
        Ok(match &state.container {
            Some(found) if found.id == id => InspectOutcome::Found(found.clone()),
            _ => InspectOutcome::Absent,
        })
    }
    fn remove(&mut self, id: &str) -> Result<bool, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("recovery_remove:{id}"));
        if state.remove_succeeds && state.container.as_ref().is_some_and(|found| found.id == id) {
            state.container = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn active_managed_job(home: &std::path::Path) -> super::super::IntegrationJob {
    let service = super::super::open_n8n_job_service(home).unwrap();
    let queued = enqueue_prepared(&service, &request()).unwrap();
    service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap()
}

fn queued_managed_job(home: &std::path::Path) -> super::super::IntegrationJob {
    let service = super::super::open_n8n_job_service(home).unwrap();
    enqueue_prepared(&service, &request()).unwrap()
}

fn bound_binding(job: &super::super::IntegrationJob, id: String) -> RuntimeBinding {
    RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::Bound,
        job_id: job.job_id.as_str().into(),
        manifest_sha256: job.manifest_sha256.as_str().into(),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: Some(id),
        image: N8N_OCI_REFERENCE.into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
    }
}

#[test]
fn terminal_after_absence_retains_active_job_and_reports_primary_cleanup_codes() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let service = super::super::open_n8n_job_service(home.path()).unwrap();
    let queued = enqueue_prepared(&service, &request()).unwrap();
    let running = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let mut binding = bound_binding(&running, "c".repeat(64));
    binding.phase = RuntimePhase::AbsentVerified;
    write_binding(home.path(), &binding).unwrap();

    let error = terminal_after_absence(
        &service,
        &running,
        home.path(),
        &binding,
        "adoption_prepare_failed",
        false,
        true,
    )
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "adoption_prepare_failed:adoption_cleanup_failed"
    );
    assert_eq!(
        super::super::IntegrationJobService::read_only_snapshot(home.path()).unwrap()[0].state,
        super::super::JobState::Running
    );
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::AbsentVerified
    );
}

#[tokio::test]
async fn precreate_cancellation_performs_zero_docker_calls_and_finalizes_only_after_cancelled_job()
{
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    let (cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    cancel_tx.send(()).unwrap();
    let job = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![]),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_eq!(job.state, super::super::JobState::Cancelled);
    assert!(job.cancel_requested);
    assert!(state.lock().unwrap().calls.is_empty());
    assert_eq!(read_binding(home.path()).unwrap(), None);
}

#[tokio::test]
async fn failed_removal_after_cancellation_retains_active_cancel_intent_and_bound_custody() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    state.lock().unwrap().remove_succeeds = false;
    let (sender, mut cancel) = tokio::sync::oneshot::channel();
    let probe = Probe::with_cancellation(vec![AuthPlan::HangAndCancel], sender);
    assert!(
        install_managed_at_with(
            home.path(),
            request(),
            key(),
            &mut runner,
            &Ready,
            &probe,
            &mut cancel
        )
        .await
        .is_err()
    );
    let job = super::super::IntegrationJobService::read_only_snapshot(home.path())
        .unwrap()
        .pop()
        .unwrap();
    assert!(job.cancel_requested);
    assert_ne!(job.state, super::super::JobState::Cancelled);
    assert_ne!(job.state, super::super::JobState::Failed);
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::Bound
    );
    assert!(state.lock().unwrap().container.is_some());
}

#[tokio::test]
async fn unknown_exact_inspection_after_cancellation_retains_active_bound_custody_without_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let (mut runner, state) = FakeRunner::fresh();
    state.lock().unwrap().exact_unknown = true;
    let (sender, mut cancel) = tokio::sync::oneshot::channel();
    let probe = Probe::with_cancellation(vec![AuthPlan::HangAndCancel], sender);
    assert!(
        install_managed_at_with(
            home.path(),
            request(),
            key(),
            &mut runner,
            &Ready,
            &probe,
            &mut cancel
        )
        .await
        .is_err()
    );
    let job = super::super::IntegrationJobService::read_only_snapshot(home.path())
        .unwrap()
        .pop()
        .unwrap();
    assert!(job.cancel_requested);
    assert_ne!(job.state, super::super::JobState::Cancelled);
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::Bound
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call.starts_with("remove:"))
    );
}

#[tokio::test]
async fn foreign_ready_binding_is_unchanged_and_blocks_a_second_queued_job() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let binding = RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::Ready,
        job_id: "foreign-job".into(),
        manifest_sha256: "a".repeat(64),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: Some("c".repeat(64)),
        image: N8N_OCI_REFERENCE.into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
    };
    write_binding(home.path(), &binding).unwrap();
    let before = std::fs::read(binding_path(home.path())).unwrap();
    let (mut runner, state) = FakeRunner::fresh();
    let (_cancel_tx, mut cancel) = tokio::sync::oneshot::channel();
    let result = install_managed_at_with(
        home.path(),
        request(),
        key(),
        &mut runner,
        &Ready,
        &Probe::new(vec![]),
        &mut cancel,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(std::fs::read(binding_path(home.path())).unwrap(), before);
    assert!(state.lock().unwrap().calls.is_empty());
    assert!(
        super::super::IntegrationJobService::read_only_snapshot(home.path())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn restart_recovery_removes_only_exact_bound_container_then_retains_absence_tombstone() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = active_managed_job(home.path());
    let id = "c".repeat(64);
    write_binding(home.path(), &bound_binding(&job, id.clone())).unwrap();
    let state = Arc::new(Mutex::new(RunnerState {
        container: Some(observed(id.clone(), job.job_id.as_str(), 5678)),
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: false,
        exact_unknown: false,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert!(recover_interrupted_with(home.path(), &job, &mut recovery).is_ok());
    assert!(state.lock().unwrap().container.is_none());
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::AbsentVerified
    );
    assert!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == &format!("recovery_remove:{id}"))
    );
}

#[test]
fn restart_recovery_with_unknown_exact_inspection_retains_bound_custody_and_active_job() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = active_managed_job(home.path());
    let id = "c".repeat(64);
    write_binding(home.path(), &bound_binding(&job, id.clone())).unwrap();
    let state = Arc::new(Mutex::new(RunnerState {
        container: Some(observed(id, job.job_id.as_str(), 5678)),
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: false,
        exact_unknown: true,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert_eq!(
        recover_interrupted_with(home.path(), &job, &mut recovery),
        Err("n8n_managed_cleanup_failed")
    );
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::Bound
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call.starts_with("recovery_remove:"))
    );
}

#[test]
fn create_intent_restart_discovers_exact_owned_container_then_removes_it() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = active_managed_job(home.path());
    let id = "c".repeat(64);
    write_binding(
        home.path(),
        &RuntimeBinding {
            schema_version: 2,
            phase: RuntimePhase::CreateIntent,
            job_id: job.job_id.as_str().into(),
            manifest_sha256: job.manifest_sha256.as_str().into(),
            container_name: MANAGED_CONTAINER_NAME.into(),
            container_id: None,
            image: N8N_OCI_REFERENCE.into(),
            host_port: 5678,
            volume: DEFAULT_VOLUME.into(),
        },
    )
    .unwrap();
    let state = Arc::new(Mutex::new(RunnerState {
        container: Some(observed(id, job.job_id.as_str(), 5678)),
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: false,
        exact_unknown: false,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert!(recover_interrupted_with(home.path(), &job, &mut recovery).is_ok());
    assert!(state.lock().unwrap().container.is_none());
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::AbsentVerified
    );
    assert!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == "recovery_inspect_named")
    );
}

#[test]
fn create_intent_restart_unknown_named_inspection_retains_custody_without_removal() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = active_managed_job(home.path());
    write_binding(
        home.path(),
        &RuntimeBinding {
            schema_version: 2,
            phase: RuntimePhase::CreateIntent,
            job_id: job.job_id.as_str().into(),
            manifest_sha256: job.manifest_sha256.as_str().into(),
            container_name: MANAGED_CONTAINER_NAME.into(),
            container_id: None,
            image: N8N_OCI_REFERENCE.into(),
            host_port: 5678,
            volume: DEFAULT_VOLUME.into(),
        },
    )
    .unwrap();
    let state = Arc::new(Mutex::new(RunnerState {
        container: None,
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: true,
        exact_unknown: false,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert_eq!(
        recover_interrupted_with(home.path(), &job, &mut recovery),
        Err("n8n_managed_cleanup_failed")
    );
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::CreateIntent
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call.starts_with("recovery_remove:"))
    );
}

#[test]
fn active_bound_custody_refuses_finalization() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = active_managed_job(home.path());
    write_binding(home.path(), &bound_binding(&job, "c".repeat(64))).unwrap();
    assert_eq!(
        finalize_terminal_custody(home.path(), &job),
        Err("n8n_managed_custody_finalize_mismatch")
    );
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::Bound
    );
}

#[test]
fn postwrite_create_intent_error_keeps_queued_job_recoverable_without_docker() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = queued_managed_job(home.path());
    let intent = RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::CreateIntent,
        job_id: job.job_id.as_str().into(),
        manifest_sha256: job.manifest_sha256.as_str().into(),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: None,
        image: N8N_OCI_REFERENCE.into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
    };
    let outcome = persist_create_intent_with(home.path(), &intent, |path, bytes| {
        std::fs::write(path, bytes).map_err(|_| "fixture_write_failed")?;
        Err("simulated_postwrite_error")
    })
    .unwrap();
    assert_eq!(outcome, CreateIntentWrite::Uncertain);
    let state = Arc::new(Mutex::new(RunnerState {
        container: None,
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: false,
        exact_unknown: false,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert!(recover_interrupted_with(home.path(), &job, &mut recovery).is_ok());
    assert!(state.lock().unwrap().calls.is_empty());
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().phase,
        RuntimePhase::AbsentVerified
    );
}

#[test]
fn queued_foreign_create_intent_stays_fail_closed_without_docker_inspection() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job = queued_managed_job(home.path());
    let foreign = RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::CreateIntent,
        job_id: "another-job".into(),
        manifest_sha256: job.manifest_sha256.as_str().into(),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: None,
        image: N8N_OCI_REFERENCE.into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
    };
    write_binding(home.path(), &foreign).unwrap();
    let state = Arc::new(Mutex::new(RunnerState {
        container: None,
        create_error_after_effect: false,
        remove_succeeds: true,
        named_unknown: false,
        exact_unknown: false,
        calls: Vec::new(),
    }));
    let mut recovery = FakeRecovery(state.clone());
    assert_eq!(
        recover_interrupted_with(home.path(), &job, &mut recovery),
        Err("n8n_managed_custody_mismatch")
    );
    assert!(state.lock().unwrap().calls.is_empty());
    assert_eq!(
        read_binding(home.path()).unwrap().unwrap().job_id,
        "another-job"
    );
}
