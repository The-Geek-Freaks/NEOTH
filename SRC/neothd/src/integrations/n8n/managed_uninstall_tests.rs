use super::super::super::managed_bootstrap::BOOTSTRAP_SCHEMA;
use super::super::{
    DEFAULT_VOLUME, InspectOutcome, InspectVolumeOutcome, MANAGED_LABEL_KEY, MANAGED_LABEL_VALUE,
    ManagedCommandReceipt, ManagedDockerRunner, ManagedN8nRequest, ManagedReadiness,
    ObservedContainer, ObservedVolume, install_managed_at_with, install_retained_at_with,
    write_binding,
};
use super::{
    STEPS, UninstallCustody, UninstallPhase, checkpoint, cleanup_disposition_at, create_custody,
    enqueue_uninstall, finalize_ready_uninstall_custody, open_explicit_uninstall_service_with,
    read_binding, read_custody, receipt_path, retained_reinstall_request_in_service,
    source_ready_binding, uninstall_managed_at_with, uninstall_managed_at_with_restart_inspector,
    write_custody,
};
use crate::installers::n8n::N8N_OCI_REFERENCE;
use crate::integrations::jobs::{IntegrationJobService, JobServiceError};
use crate::integrations::n8n::{
    N8nApiProbe, N8nProbeError, N8nProbeReceipt, parse_workflows_response,
};
use crate::integrations::state::{IntegrationJob, JobOperation, JobState};
use std::sync::{Arc, Mutex};

fn initialize(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}
fn observed(id: &str, job: &str) -> ObservedContainer {
    ObservedContainer {
        id: id.into(),
        image: N8N_OCI_REFERENCE.into(),
        managed: MANAGED_LABEL_VALUE.into(),
        job: job.into(),
        host_ip: "127.0.0.1".into(),
        host_port: 5678,
        volume: DEFAULT_VOLUME.into(),
        mount_destination: "/home/node/.n8n".into(),
    }
}
#[derive(Default)]
struct FakeState {
    container: Option<ObservedContainer>,
    volume: Option<ObservedVolume>,
    calls: Vec<String>,
    remove_error: bool,
    exact_unknown: bool,
    volume_unknown: bool,
}
struct Fake(Arc<Mutex<FakeState>>);
#[async_trait::async_trait]
impl ManagedDockerRunner for Fake {
    async fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        let state = self.0.lock().unwrap();
        Ok(state
            .container
            .clone()
            .map(InspectOutcome::Found)
            .unwrap_or(InspectOutcome::Absent))
    }
    async fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("inspect:{id}"));
        if state.exact_unknown {
            return Ok(InspectOutcome::Unknown);
        }
        Ok(state
            .container
            .clone()
            .filter(|found| found.id == id)
            .map(InspectOutcome::Found)
            .unwrap_or(InspectOutcome::Absent))
    }
    async fn inspect_volume(&mut self, name: &str) -> Result<InspectVolumeOutcome, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("inspect_volume:{name}"));
        if state.volume_unknown {
            Ok(InspectVolumeOutcome::Unknown)
        } else {
            Ok(state
                .volume
                .clone()
                .filter(|volume| volume.name == name)
                .map(InspectVolumeOutcome::Found)
                .unwrap_or(InspectVolumeOutcome::Absent))
        }
    }
    async fn create(&mut self, argv: &[String]) -> Result<ManagedCommandReceipt, &'static str> {
        let job = argv
            .windows(2)
            .find(|pair| pair[0] == "--label" && pair[1].starts_with("io.neoth.n8n-job="))
            .ok_or("missing_job")?[1]
            .trim_start_matches("io.neoth.n8n-job=");
        let volume = argv
            .windows(2)
            .find(|pair| pair[0] == "-v")
            .and_then(|pair| pair[1].split(':').next())
            .ok_or("missing_volume")?;
        let mut state = self.0.lock().unwrap();
        state.calls.push("create".into());
        state.container = Some(observed_with_volume(&"c".repeat(64), job, volume));
        Ok(ManagedCommandReceipt {
            succeeded: true,
            output_sha256: "a".repeat(64),
        })
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("remove:{id}"));
        if state.remove_error {
            return Err("interrupted_after_dispatch");
        }
        if state.container.as_ref().is_some_and(|found| found.id == id) {
            state.container = None;
        }
        Ok(ManagedCommandReceipt {
            succeeded: true,
            output_sha256: "b".repeat(64),
        })
    }
}
struct Ready;
#[async_trait::async_trait]
impl ManagedReadiness for Ready {
    async fn health(&self, _: u16) -> bool {
        true
    }
}
struct Probe;
#[async_trait::async_trait]
impl N8nApiProbe for Probe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<(), N8nProbeError> {
        Ok(())
    }
    async fn authenticated_probe(
        &self,
        endpoint: &crate::config::LoopbackHttpEndpoint,
        _: &crate::secret::SecretString,
    ) -> Result<N8nProbeReceipt, N8nProbeError> {
        parse_workflows_response(endpoint.clone(), 200, br#"{"data":[],"nextCursor":null}"#)
    }
}
async fn installed(home: &std::path::Path, runner: &mut Fake) -> IntegrationJob {
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    install_managed_at_with(
        home,
        ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(),
        crate::secret::SecretString::from("test-key"),
        runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap()
}

async fn installed_bootstrap_like(home: &std::path::Path, runner: &mut Fake) -> IntegrationJob {
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let job = install_managed_at_with(
        home,
        ManagedN8nRequest::new_with_volume(
            5678,
            N8N_OCI_REFERENCE,
            "neoth_n8n_bootstrap_test".into(),
        )
        .unwrap(),
        crate::secret::SecretString::from("test-key"),
        runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    let mut binding = read_binding(home).unwrap().unwrap();
    binding.bootstrap_volume_owner_job_id = Some(job.job_id.as_str().into());
    write_binding(home, &binding).unwrap();
    job
}

async fn completed_bootstrap_uninstall_seed(
    home: &std::path::Path,
    runner: &mut Fake,
) -> (IntegrationJob, IntegrationJob) {
    let source = installed_bootstrap_like(home, runner).await;
    runner.0.lock().unwrap().volume = Some(ObservedVolume {
        name: "neoth_n8n_bootstrap_test".into(),
        labels: std::collections::BTreeMap::from([
            (MANAGED_LABEL_KEY.into(), MANAGED_LABEL_VALUE.into()),
            ("io.neoth.n8n-job".into(), source.job_id.as_str().into()),
            ("io.neoth.n8n-bootstrap".into(), BOOTSTRAP_SCHEMA.into()),
        ]),
    });
    let uninstall = uninstall_managed_at_with(home, runner).await.unwrap();
    assert!(read_binding(home).unwrap().is_none());
    (source, uninstall)
}

fn job_snapshot(home: &std::path::Path) -> Vec<u8> {
    serde_json::to_vec(&IntegrationJobService::read_only_snapshot(home).unwrap()).unwrap()
}

fn assert_receipt_selector_rejected_without_docker(
    home: &std::path::Path,
    state: &Arc<Mutex<FakeState>>,
    selector: &crate::integrations::state::JobId,
    jobs_before: &[u8],
    calls_before: usize,
) {
    let inspector = restart_inspector(state.clone());
    let service = open_explicit_uninstall_service_with(home, &inspector).unwrap();
    assert!(retained_reinstall_request_in_service(&service, home, selector).is_err());
    assert!(read_binding(home).unwrap().is_none());
    assert_eq!(job_snapshot(home), jobs_before.to_vec());
    assert_eq!(state.lock().unwrap().calls.len(), calls_before);
}

fn observed_with_volume(id: &str, job: &str, volume: &str) -> ObservedContainer {
    let mut observed = observed(id, job);
    observed.volume = volume.into();
    observed
}

fn restart_inspector(
    state: Arc<Mutex<FakeState>>,
) -> impl Fn(&str) -> Result<InspectOutcome, &'static str> + Send + Sync {
    move |id| {
        let state = state.lock().unwrap();
        if state.exact_unknown {
            return Ok(InspectOutcome::Unknown);
        }
        Ok(state
            .container
            .clone()
            .filter(|found| found.id == id)
            .map(InspectOutcome::Found)
            .unwrap_or(InspectOutcome::Absent))
    }
}

fn completed_custody(
    job: &IntegrationJob,
    binding: &super::super::RuntimeBinding,
) -> UninstallCustody {
    UninstallCustody {
        schema_version: 1,
        phase: UninstallPhase::Completed,
        uninstall_job_id: job.job_id.as_str().into(),
        uninstall_manifest_sha256: job.manifest_sha256.as_str().into(),
        source_install_job_id: binding.job_id.as_str().into(),
        source_install_manifest_sha256: binding.manifest_sha256.as_str().into(),
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        host_port: binding.host_port,
        volume: binding.volume.clone(),
        cleanup_disposition: Some("cleared".into()),
    }
}

#[tokio::test]
async fn exact_id_uninstall_removes_container_never_volume_and_repeats_without_docker() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let job = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(job.state, JobState::Ready);
    let calls = state.lock().unwrap().calls.clone();
    assert!(calls.iter().any(|call| call.starts_with("remove:")));
    assert!(!calls.iter().any(|call| call.contains("volume")));
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(matches!(
        cleanup_disposition_at(home.path(), &job).unwrap(),
        Some("cleared" | "already_absent")
    ));
    let before = calls.len();
    assert_eq!(
        uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap()
            .job_id,
        job.job_id
    );
    assert_eq!(state.lock().unwrap().calls.len(), before);
}

#[tokio::test]
async fn retained_bootstrap_volume_reinstalls_twice_with_the_original_label_owner() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let original = installed_bootstrap_like(home.path(), &mut runner).await;
    state.lock().unwrap().volume = Some(ObservedVolume {
        name: "neoth_n8n_bootstrap_test".into(),
        labels: std::collections::BTreeMap::from([
            (MANAGED_LABEL_KEY.into(), MANAGED_LABEL_VALUE.into()),
            ("io.neoth.n8n-job".into(), original.job_id.as_str().into()),
            ("io.neoth.n8n-bootstrap".into(), BOOTSTRAP_SCHEMA.into()),
        ]),
    });

    let first_uninstall = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let first_calls = state.lock().unwrap().calls.len();
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let first_reinstall = install_retained_at_with(
        home.path(),
        &first_uninstall.job_id,
        crate::secret::SecretString::from("test-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    assert_ne!(first_reinstall.job_id, original.job_id);
    assert_ne!(first_reinstall.job_id, first_uninstall.job_id);
    let first_reinstall_calls = state.lock().unwrap().calls[first_calls..].to_vec();
    let inspect = first_reinstall_calls
        .iter()
        .position(|call| call == "inspect_volume:neoth_n8n_bootstrap_test")
        .unwrap();
    let create = first_reinstall_calls
        .iter()
        .position(|call| call == "create")
        .unwrap();
    assert!(inspect < create);

    let second_uninstall = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let before_second_reinstall = state.lock().unwrap().calls.len();
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let second_reinstall = install_retained_at_with(
        home.path(),
        &second_uninstall.job_id,
        crate::secret::SecretString::from("test-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    assert_ne!(second_reinstall.job_id, first_reinstall.job_id);
    let calls = state.lock().unwrap().calls[before_second_reinstall..].to_vec();
    assert!(
        calls
            .iter()
            .any(|call| call == "inspect_volume:neoth_n8n_bootstrap_test")
    );
    assert!(calls.iter().any(|call| call == "create"));
    let binding = read_binding(home.path()).unwrap().unwrap();
    assert_eq!(binding.volume, "neoth_n8n_bootstrap_test");
    assert_eq!(
        binding
            .retained_reinstall
            .unwrap()
            .volume_owner_install_job_id,
        original.job_id.as_str(),
    );
}

#[tokio::test]
async fn retained_reinstall_rejects_unproven_missing_unknown_and_foreign_volumes_before_create() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let ordinary = installed(home.path(), &mut runner).await;
    let ordinary_uninstall = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let before = state.lock().unwrap().calls.len();
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    assert!(
        install_retained_at_with(
            home.path(),
            &ordinary_uninstall.job_id,
            crate::secret::SecretString::from("test-key"),
            &mut runner,
            &Ready,
            &Probe,
            &mut cancel,
        )
        .await
        .is_err()
    );
    assert_eq!(ordinary.state, JobState::Ready);
    assert!(
        !state.lock().unwrap().calls[before..]
            .iter()
            .any(|call| call == "create")
    );

    for case in ["missing", "unknown", "foreign"] {
        let home = tempfile::tempdir().unwrap();
        initialize(home.path());
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut runner = Fake(state.clone());
        let original = installed_bootstrap_like(home.path(), &mut runner).await;
        let uninstall = uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
        match case {
            "missing" => {}
            "unknown" => state.lock().unwrap().volume_unknown = true,
            "foreign" => {
                state.lock().unwrap().volume = Some(ObservedVolume {
                    name: "neoth_n8n_bootstrap_test".into(),
                    labels: Default::default(),
                })
            }
            _ => unreachable!(),
        }
        let before = state.lock().unwrap().calls.len();
        let (_tx, mut cancel) = tokio::sync::oneshot::channel();
        assert!(
            install_retained_at_with(
                home.path(),
                &uninstall.job_id,
                crate::secret::SecretString::from("test-key"),
                &mut runner,
                &Ready,
                &Probe,
                &mut cancel,
            )
            .await
            .is_err()
        );
        let calls = state.lock().unwrap().calls[before..].to_vec();
        assert!(
            calls
                .iter()
                .any(|call| call == "inspect_volume:neoth_n8n_bootstrap_test")
        );
        assert!(!calls.iter().any(|call| call == "create"));
        assert_eq!(original.state, JobState::Ready);
    }
}

#[tokio::test]
async fn retained_reinstall_rejects_missing_legacy_malformed_and_mismatched_receipts_without_docker()
 {
    for case in ["missing", "legacy", "malformed", "mismatched"] {
        let home = tempfile::tempdir().unwrap();
        initialize(home.path());
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut runner = Fake(state.clone());
        let (source, uninstall) =
            completed_bootstrap_uninstall_seed(home.path(), &mut runner).await;
        let jobs_before = job_snapshot(home.path());
        let calls_before = state.lock().unwrap().calls.len();
        let path = receipt_path(home.path(), uninstall.job_id.as_str());
        match case {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "legacy" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value.as_object_mut().unwrap().remove("source_container_id");
                std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "malformed" => std::fs::write(&path, b"{").unwrap(),
            "mismatched" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value.as_object_mut().unwrap().insert(
                    "uninstall_manifest_sha256".into(),
                    serde_json::Value::String("d".repeat(64)),
                );
                std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        assert_receipt_selector_rejected_without_docker(
            home.path(),
            &state,
            &uninstall.job_id,
            &jobs_before,
            calls_before,
        );
        assert_eq!(source.state, JobState::Ready);
        assert_eq!(uninstall.state, JobState::Ready);
    }
}

#[tokio::test]
async fn retained_reinstall_rejects_selected_or_mutated_source_evidence_without_docker() {
    for case in [
        "selected_install",
        "source_operation",
        "source_manifest",
        "source_image",
        "source_port",
        "source_volume",
        "source_owner",
        "source_container",
    ] {
        let home = tempfile::tempdir().unwrap();
        initialize(home.path());
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut runner = Fake(state.clone());
        let (source, uninstall) =
            completed_bootstrap_uninstall_seed(home.path(), &mut runner).await;
        let jobs_before = job_snapshot(home.path());
        let calls_before = state.lock().unwrap().calls.len();
        let mut selector = uninstall.job_id.clone();
        if case == "selected_install" {
            selector = source.job_id.clone();
        } else {
            let path = receipt_path(home.path(), uninstall.job_id.as_str());
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let receipt = value.as_object_mut().unwrap();
            match case {
                "source_operation" => {
                    receipt.insert(
                        "source_install_job_id".into(),
                        serde_json::Value::String(uninstall.job_id.as_str().into()),
                    );
                    receipt.insert(
                        "source_install_manifest_sha256".into(),
                        serde_json::Value::String(uninstall.manifest_sha256.as_str().into()),
                    );
                }
                "source_manifest" => {
                    receipt.insert(
                        "source_install_manifest_sha256".into(),
                        serde_json::Value::String("d".repeat(64)),
                    );
                }
                "source_image" => {
                    receipt.insert(
                        "source_image".into(),
                        serde_json::Value::String("unreviewed:image".into()),
                    );
                }
                "source_port" => {
                    receipt.insert("source_host_port".into(), serde_json::json!(5679));
                }
                "source_volume" => {
                    receipt.insert(
                        "source_volume".into(),
                        serde_json::Value::String("neoth_n8n_other".into()),
                    );
                }
                "source_owner" => {
                    receipt.insert(
                        "source_volume_owner_install_job_id".into(),
                        serde_json::Value::String(uuid::Uuid::now_v7().to_string()),
                    );
                }
                "source_container" => {
                    receipt.insert(
                        "source_container_id".into(),
                        serde_json::Value::String("d".repeat(64)),
                    );
                }
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        assert_receipt_selector_rejected_without_docker(
            home.path(),
            &state,
            &selector,
            &jobs_before,
            calls_before,
        );
        assert_eq!(source.state, JobState::Ready);
        assert_eq!(uninstall.state, JobState::Ready);
    }
}

#[tokio::test]
async fn dispatched_error_never_repeats_remove_and_retains_custody() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(
        uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector)
            .await
            .is_err()
    );
    let removes = state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.starts_with("remove:"))
        .count();
    assert_eq!(removes, 1);
    assert_eq!(
        read_custody(home.path()).unwrap().unwrap().phase,
        UninstallPhase::RemoveDispatched
    );
    state.lock().unwrap().container = None;
    let ready = uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector)
        .await
        .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.starts_with("remove:"))
            .count(),
        1
    );
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(matches!(
        cleanup_disposition_at(home.path(), &ready).unwrap(),
        Some("cleared" | "already_absent")
    ));
}

#[tokio::test]
async fn dispatched_live_or_unknown_restart_holds_without_another_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(
        uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector)
            .await
            .is_err()
    );
    let removals = state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.starts_with("remove:"))
        .count();
    assert!(
        matches!(open_explicit_uninstall_service_with(home.path(), &inspector), Err(error) if matches!(error.downcast_ref::<JobServiceError>(), Some(JobServiceError::RecoveryHold { .. })))
    );
    let active = IntegrationJobService::read_only_snapshot(home.path())
        .unwrap()
        .into_iter()
        .find(|job| job.operation == JobOperation::Uninstall)
        .unwrap();
    assert!(active.state.is_active());
    state.lock().unwrap().exact_unknown = true;
    assert!(
        matches!(open_explicit_uninstall_service_with(home.path(), &inspector), Err(error) if matches!(error.downcast_ref::<JobServiceError>(), Some(JobServiceError::RecoveryHold { .. })))
    );
    let active = IntegrationJobService::read_only_snapshot(home.path())
        .unwrap()
        .into_iter()
        .find(|job| job.operation == JobOperation::Uninstall)
        .unwrap();
    assert!(active.state.is_active());
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.starts_with("remove:"))
            .count(),
        removals
    );
}

#[tokio::test]
async fn missing_runtime_binding_has_zero_docker_mutations() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    assert!(
        uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .is_err()
    );
    assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn foreign_exact_identity_never_dispatches_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let binding = read_binding(home.path()).unwrap().unwrap();
    state.lock().unwrap().container = Some(observed(
        binding.container_id.as_deref().unwrap(),
        "foreign-managed-job",
    ));
    assert!(
        uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .is_err()
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call.starts_with("remove:"))
    );
    assert_eq!(
        read_custody(home.path()).unwrap().unwrap().phase,
        UninstallPhase::IntentPersisted
    );
}

#[tokio::test]
async fn ready_finalizer_reentry_handles_both_post_ready_crash_boundaries() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let binding = read_binding(home.path()).unwrap().unwrap();
    let ready = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();

    write_binding(home.path(), &binding).unwrap();
    let custody = completed_custody(&ready, &binding);
    write_custody(home.path(), &custody).unwrap();
    finalize_ready_uninstall_custody(home.path(), &ready).unwrap();
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());

    write_custody(home.path(), &custody).unwrap();
    finalize_ready_uninstall_custody(home.path(), &ready).unwrap();
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(matches!(
        cleanup_disposition_at(home.path(), &ready).unwrap(),
        Some("cleared" | "already_absent")
    ));
}

#[tokio::test]
async fn queued_before_custody_is_terminalized_without_orphaning_the_runtime_binding() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let (binding, _source) = source_ready_binding(&service, home.path()).unwrap();
    let queued = enqueue_uninstall(&service, &binding).unwrap();
    drop(service);
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let recovered = service.get(&queued.job_id).unwrap().unwrap();
    assert_eq!(recovered.state, JobState::Failed);
    assert!(read_binding(home.path()).unwrap().is_some());
    assert!(read_custody(home.path()).unwrap().is_none());
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
async fn configuring_between_checkpoint_one_and_three_reopens_from_the_durable_receipt() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let _source = installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let (binding, source) = source_ready_binding(&service, home.path()).unwrap();
    let queued = enqueue_uninstall(&service, &binding).unwrap();
    let custody = UninstallCustody {
        schema_version: 1,
        phase: UninstallPhase::IntentPersisted,
        uninstall_job_id: queued.job_id.as_str().into(),
        uninstall_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        host_port: binding.host_port,
        volume: binding.volume.clone(),
        cleanup_disposition: None,
    };
    create_custody(home.path(), &custody).unwrap();
    let running = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let validating = service
        .begin_validation(&running.job_id, running.state_revision, STEPS[0])
        .unwrap();
    let first = checkpoint(&service, &validating, 1, STEPS[0]).unwrap();
    let configuring = service
        .begin_configuration(&first.job_id, first.state_revision, STEPS[2])
        .unwrap();
    assert_eq!(configuring.current_step.as_deref(), Some(STEPS[2]));
    drop(service);
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let recovered = service.get(&queued.job_id).unwrap().unwrap();
    assert_eq!(recovered.state, JobState::Queued);
    assert_eq!(recovered.progress.completed_steps, 1);
    assert_eq!(recovered.current_step.as_deref(), Some(STEPS[0]));
    assert_eq!(source.operation, JobOperation::Install);
}

#[tokio::test]
async fn later_uninstall_recovery_never_finalizes_an_earlier_ready_uninstall() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let first = uninstall_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(
        uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector)
            .await
            .is_err()
    );
    state.lock().unwrap().container = None;
    let second = uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector)
        .await
        .unwrap();
    assert_ne!(first.job_id, second.job_id);
    let history = IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert_eq!(
        history
            .into_iter()
            .find(|job| job.job_id == first.job_id)
            .unwrap()
            .state,
        JobState::Ready
    );
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());
}
