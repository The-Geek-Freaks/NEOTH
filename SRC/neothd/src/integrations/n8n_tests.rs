use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn scripted_loopback(responses: Vec<&'static str>) -> LoopbackHttpEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        LoopbackHttpEndpoint::parse(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    endpoint
}

fn initialize_home(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}

#[test]
fn parses_documented_workflows_shape_without_invented_identity_fields() {
    let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
    let receipt =
        parse_workflows_response(endpoint, 200, br#"{"data":[],"nextCursor":null}"#).unwrap();
    assert_eq!(receipt.http_status, 200);
    assert_eq!(receipt.workflow_rows, 0);
    assert!(!receipt.has_next_cursor);
}

#[test]
fn rejects_non_documented_or_unbounded_workflows_shapes() {
    let endpoint = LoopbackHttpEndpoint::parse("http://[::1]:5678").unwrap();
    for body in [br#"{}"#.as_slice(), br#"{"data":{}}"#.as_slice()] {
        assert_eq!(
            parse_workflows_response(endpoint.clone(), 200, body),
            Err(N8nProbeError::ResponseEnvelopeInvalid)
        );
    }
    assert_eq!(
        parse_workflows_response(endpoint.clone(), 200, b"not json"),
        Err(N8nProbeError::ResponseJsonInvalid)
    );
    for body in [
        br#"{"data":[],"nextCursor":12}"#.as_slice(),
        br#"{"data":[],"nextCursor":"\n"}"#.as_slice(),
    ] {
        assert_eq!(
            parse_workflows_response(endpoint.clone(), 200, body),
            Err(N8nProbeError::ResponseCursorInvalid)
        );
    }
}

#[test]
fn descriptor_and_step_plan_are_stable_and_local_only() {
    let descriptor = n8n_descriptor();
    descriptor.validate().unwrap();
    assert_eq!(descriptor.id.as_str(), N8N_CAPABILITY_ID);
    assert_eq!(descriptor.targets.len(), 1);
    super::super::state::validate_release_version(ADAPTER_RELEASE_VERSION).unwrap();
    assert_eq!(step_plan_sha256().as_str().len(), 64);
}

#[tokio::test]
async fn generic_200_workflows_envelope_without_key_rejection_is_not_adoption_evidence() {
    let endpoint = scripted_loopback(vec![
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"data\":[],\"nextCursor\":null}",
    ]).await;
    assert_eq!(
        HttpN8nApiProbe.negative_control(&endpoint).await,
        Err(N8nProbeError::NegativeControlUnexpectedSuccess)
    );
}

#[tokio::test]
async fn local_loopback_probe_status_categories_are_redacted_and_stage_specific() {
    for (response, expected) in [
        (
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            N8nProbeError::NegativeControlNotFound,
        ),
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            N8nProbeError::NegativeControlServerError,
        ),
    ] {
        let endpoint = scripted_loopback(vec![response]).await;
        assert_eq!(
            HttpN8nApiProbe.negative_control(&endpoint).await,
            Err(expected)
        );
    }
    for (response, expected) in [
        (
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            N8nProbeError::AuthenticatedNotFound,
        ),
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            N8nProbeError::AuthenticatedServerError,
        ),
        (
            "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n",
            N8nProbeError::AuthenticatedUnexpectedStatus,
        ),
    ] {
        let endpoint = scripted_loopback(vec![response]).await;
        assert_eq!(
            HttpN8nApiProbe
                .authenticated_probe(&endpoint, &SecretString::from("test-n8n-key"))
                .await,
            Err(expected)
        );
    }
}

#[tokio::test]
async fn adoption_requires_unauthenticated_rejection_then_persists_and_reports_ready_without_key() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let endpoint = scripted_loopback(vec![
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"data\":[],\"nextCursor\":null}",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"data\":[],\"nextCursor\":null}",
    ]).await;
    let job = adopt_at(
        home.path(),
        endpoint.clone(),
        SecretString::from("test-n8n-key"),
    )
    .await
    .unwrap();
    assert_eq!(job.state, JobState::Ready);
    let view = status_at(home.path(), Some(&job.job_id)).unwrap();
    assert_eq!(view.configured_endpoint, Some(endpoint));
    assert!(view.api_key_present);
    assert_eq!(view.job.as_ref().unwrap().state, JobState::Ready);
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("test-n8n-key")
    );
}

#[test]
fn missing_custody_after_prepare_remains_fail_closed() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let job_id = JobId::new();
    let prepared = crate::config::credentials::Credentials::prepare_n8n_adoption_at(
        &home.path().join("freedom.yaml"),
        &home.path().join("credentials.yaml"),
        job_id.as_str(),
        crate::config::N8nInstanceConfig {
            endpoint: LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap(),
            api_version: None,
        },
        SecretString::from("test-n8n-key"),
    )
    .unwrap();
    drop(prepared);
    std::fs::remove_file(
        home.path()
            .join(format!(".n8n-adoption-{}.custody.yaml", job_id.as_str())),
    )
    .unwrap();

    assert!(rollback_adoption_if_prepared(home.path(), &job_id, true).is_err());
}
#[tokio::test]
async fn precommit_unauthorized_fails_durably_without_config_or_credential_write() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let freedom_before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let endpoint = scripted_loopback(vec![
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
    ])
    .await;
    let job = adopt_at(home.path(), endpoint, SecretString::from("test-n8n-key"))
        .await
        .unwrap();
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(job.failure.as_ref().unwrap().code, "n8n_unauthorized");
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        freedom_before
    );
    assert!(!home.path().join("credentials.yaml").exists());
    let jobs = IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].failure.as_ref().unwrap().code, "n8n_unauthorized");
}

#[tokio::test]
async fn postcommit_failure_restores_exact_preimage_and_never_reaches_ready() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let freedom_before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let endpoint = scripted_loopback(vec![
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"data\":[],\"nextCursor\":null}",
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
    ]).await;
    let job = adopt_at(home.path(), endpoint, SecretString::from("test-n8n-key"))
        .await
        .unwrap();
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(
        job.failure.as_ref().unwrap().code,
        "n8n_postcommit_probe_failed"
    );
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        freedom_before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn injected_cancellation_is_durable_and_never_publishes_a_binding() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let freedom_before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let endpoint = scripted_loopback(vec![
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"data\":[],\"nextCursor\":null}",
    ]).await;
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    cancel_tx.send(()).unwrap();
    let job = adopt_at_with_cancel(
        home.path(),
        endpoint,
        SecretString::from("test-n8n-key"),
        &mut cancel_rx,
    )
    .await
    .unwrap();
    assert_eq!(job.state, JobState::Cancelled);
    assert!(job.cancel_requested);
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        freedom_before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn active_hanging_precommit_probe_is_cancelled_without_publishing() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let freedom_before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        LoopbackHttpEndpoint::parse(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut negative, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 2048];
        let _ = negative.read(&mut request).await.unwrap();
        negative
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let (mut precommit, _) = listener.accept().await.unwrap();
        let _ = precommit.read(&mut request).await.unwrap();
        cancel_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let job = adopt_at_with_cancel(
        home.path(),
        endpoint,
        SecretString::from("test-n8n-key"),
        &mut cancel_rx,
    )
    .await
    .unwrap();
    assert_eq!(job.state, JobState::Cancelled);
    assert!(job.cancel_requested);
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        freedom_before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[tokio::test]
async fn active_hanging_negative_control_is_cancelled_without_publishing() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let freedom_before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        LoopbackHttpEndpoint::parse(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut negative, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 2048];
        let _ = negative.read(&mut request).await.unwrap();
        cancel_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let job = adopt_at_with_cancel(
        home.path(),
        endpoint,
        SecretString::from("test-n8n-key"),
        &mut cancel_rx,
    )
    .await
    .unwrap();
    assert_eq!(job.state, JobState::Cancelled);
    assert!(job.cancel_requested);
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        freedom_before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[test]
fn missing_input_is_a_terminal_required_input_job_without_config_mutation() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
    let service = open_n8n_job_service(home.path()).unwrap();
    let job = enqueue_required_input_failure(&service, &endpoint, JobRequester::Cli).unwrap();
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(job.failure.as_ref().unwrap().code, "required_input");
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        before
    );
    assert!(!home.path().join("credentials.yaml").exists());
}

#[test]
fn restart_of_unowned_active_job_is_terminal_and_releases_the_capability_lock() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = LoopbackHttpEndpoint::parse("http://127.0.0.1:5678").unwrap();
    let job_id = {
        let service = open_n8n_job_service(home.path()).unwrap();
        let queued = enqueue_adoption(&service, &endpoint, JobRequester::Cli)
            .unwrap()
            .job;
        service
            .start(&queued.job_id, queued.state_revision, N8N_ADOPTION_STEPS[0])
            .unwrap()
            .job_id
    };
    let service = open_n8n_job_service(home.path()).unwrap();
    let recovered = service.get(&job_id).unwrap().unwrap();
    assert_eq!(recovered.state, JobState::Failed);
    assert!(
        recovered.failure.as_ref().unwrap().code == "adoption_interrupted_recovered"
            || recovered.failure.as_ref().unwrap().code == "adoption_cleanup_failed"
    );
}

#[test]
fn read_only_status_of_absent_state_creates_no_config_or_job_database() {
    let home = tempfile::tempdir().unwrap();
    let view = status_at(home.path(), None).unwrap();
    assert!(view.configured_endpoint.is_none());
    assert!(view.job.is_none());
    assert!(!home.path().join("freedom.yaml").exists());
    assert!(!home.path().join("setup.db").exists());
}

#[test]
fn uninstall_service_open_holds_without_rewriting_job_or_configuration() {
    let home = tempfile::tempdir().unwrap();
    initialize_home(home.path());
    let before = std::fs::read(home.path().join("freedom.yaml")).unwrap();
    let job = {
        let service = open_n8n_job_service(home.path()).unwrap();
        let digest = sha256_parts(&["uninstall-recovery-hold-fixture"]);
        let queued = service
            .enqueue(EnqueueIntegrationJob {
                capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(),
                operation: JobOperation::Uninstall,
                release_version: "1.0.0".into(),
                manifest_sha256: digest.clone(),
                evidence_contract: JobEvidenceContract::verified(
                    digest.clone(),
                    digest.clone(),
                    digest.clone(),
                    digest,
                ),
                requested_by: JobRequester::Cli,
                total_steps: 1,
                bytes_total: None,
            })
            .unwrap()
            .job;
        service
            .start(
                &queued.job_id,
                queued.state_revision,
                "inspect-exact-container",
            )
            .unwrap()
    };
    assert!(matches!(
        open_n8n_job_service(home.path()),
        Err(JobServiceError::RecoveryHold { failure })
            if failure.code == "n8n_uninstall_reconciliation_required"
    ));
    let jobs = IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert_eq!(jobs, vec![job.clone()]);
    let view = status_at(home.path(), Some(&job.job_id)).unwrap();
    let status = view.job.unwrap();
    assert_eq!(status.operation, JobOperation::Uninstall);
    assert_eq!(status.state, JobState::Running);
    assert!(status.disposition.is_some());
    assert_eq!(status.config_cleanup, Some("unknown_or_preserved"));
    assert_eq!(
        std::fs::read(home.path().join("freedom.yaml")).unwrap(),
        before
    );
    assert!(!home.path().join("credentials.yaml").exists());
    assert_eq!(
        IntegrationJobService::read_only_snapshot(home.path()).unwrap(),
        jobs
    );
}
