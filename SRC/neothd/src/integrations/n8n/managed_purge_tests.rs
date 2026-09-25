use super::*;
use crate::installers::n8n::N8N_OCI_REFERENCE;
use crate::integrations::n8n::managed_runtime::managed_uninstall::uninstall_managed_at_with;
use crate::integrations::n8n::managed_runtime::{
    InspectOutcome, ManagedCommandReceipt, ManagedReadiness, ObservedContainer,
    install_managed_at_with, mark_bootstrap_volume_owner_for_test,
};
use crate::integrations::n8n::{
    N8nApiProbe, N8nProbeError, N8nProbeReceipt, parse_workflows_response,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FakeState {
    container: Option<ObservedContainer>,
    volume: Option<ObservedVolume>,
    calls: Vec<String>,
    remove_error: bool,
    remove_leaves_volume: bool,
    volume_unknown: bool,
}
struct Fake(Arc<Mutex<FakeState>>);
fn observed(id: &str, job: &str, volume: &str) -> ObservedContainer {
    ObservedContainer {
        id: id.into(),
        image: N8N_OCI_REFERENCE.into(),
        managed: MANAGED_LABEL_VALUE.into(),
        job: job.into(),
        host_ip: "127.0.0.1".into(),
        host_port: 5678,
        volume: volume.into(),
        mount_destination: "/home/node/.n8n".into(),
    }
}

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
            return Ok(InspectVolumeOutcome::Unknown);
        }
        Ok(state
            .volume
            .clone()
            .filter(|found| found.name == name)
            .map(InspectVolumeOutcome::Found)
            .unwrap_or(InspectVolumeOutcome::Absent))
    }
    async fn remove_volume(&mut self, name: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("remove_volume:{name}"));
        if !state.remove_leaves_volume {
            state.volume = None;
        }
        if state.remove_error {
            return Err("interrupted_after_dispatch");
        }
        Ok(ManagedCommandReceipt {
            succeeded: true,
            output_sha256: "c".repeat(64),
        })
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
        state.container = Some(observed(&"a".repeat(64), job, volume));
        Ok(ManagedCommandReceipt {
            succeeded: true,
            output_sha256: "a".repeat(64),
        })
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("remove:{id}"));
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
fn initialize(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}
fn calls(state: &Arc<Mutex<FakeState>>, prefix: &str) -> usize {
    state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.starts_with(prefix))
        .count()
}
fn snapshot(home: &std::path::Path) -> Vec<u8> {
    serde_json::to_vec(&IntegrationJobService::read_only_snapshot(home).unwrap()).unwrap()
}

async fn ready_bootstrap_uninstall(
    home: &std::path::Path,
    runner: &mut Fake,
) -> (IntegrationJob, IntegrationJob) {
    let (_sender, mut cancel) = tokio::sync::oneshot::channel();
    let source = install_managed_at_with(
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
    mark_bootstrap_volume_owner_for_test(home, source.job_id.as_str()).unwrap();
    runner.0.lock().unwrap().volume = Some(ObservedVolume {
        name: "neoth_n8n_bootstrap_test".into(),
        labels: std::collections::BTreeMap::from([
            (MANAGED_LABEL_KEY.into(), MANAGED_LABEL_VALUE.into()),
            ("io.neoth.n8n-job".into(), source.job_id.as_str().into()),
            (
                "io.neoth.n8n-bootstrap".into(),
                super::super::managed_bootstrap::BOOTSTRAP_SCHEMA.into(),
            ),
        ]),
    });
    let uninstall = uninstall_managed_at_with(home, runner).await.unwrap();
    assert_eq!(uninstall.state, JobState::Ready);
    (source, uninstall)
}

#[tokio::test]
async fn purge_ready_uninstall_removes_only_the_label_proven_volume_and_repeats_read_only() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let uninstall_receipt = std::fs::read(
        home.path()
            .join(format!("n8n-uninstall-{}.receipt.json", uninstall.job_id)),
    )
    .unwrap();
    let plan = prepare_purge_at(home.path(), &uninstall.job_id).unwrap();
    assert_eq!(
        plan.confirmation,
        format!(
            "PURGE N8N VOLUME {} neoth_n8n_bootstrap_test",
            uninstall.job_id
        )
    );
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.operation, JobOperation::Purge);
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:neoth_n8n_bootstrap_test"), 1);
    assert_eq!(
        std::fs::read(
            home.path()
                .join(format!("n8n-uninstall-{}.receipt.json", uninstall.job_id))
        )
        .unwrap(),
        uninstall_receipt
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipt_path(home.path(), ready.job_id.as_str())).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["uninstall_job_id"], uninstall.job_id.as_str());
    assert_eq!(receipt["volume"], "neoth_n8n_bootstrap_test");
    let before = state.lock().unwrap().calls.len();
    assert_eq!(
        purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner
        )
        .await
        .unwrap()
        .job_id,
        ready.job_id
    );
    assert_eq!(state.lock().unwrap().calls.len(), before);
    assert_eq!(
        IntegrationJobService::read_only_snapshot(home.path())
            .unwrap()
            .into_iter()
            .find(|job| job.job_id == source.job_id)
            .unwrap()
            .state,
        JobState::Ready
    );
}

#[tokio::test]
async fn purge_wrong_confirmation_and_bad_receipts_never_open_or_mutate_docker() {
    for case in [
        "wrong_confirmation",
        "missing_receipt",
        "malformed_receipt",
        "wrong_selector",
    ] {
        let home = tempfile::tempdir().unwrap();
        initialize(home.path());
        let state = Arc::new(Mutex::new(FakeState::default()));
        let mut runner = Fake(state.clone());
        let (source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
        let before_calls = state.lock().unwrap().calls.len();
        let before_jobs = snapshot(home.path());
        let path = home
            .path()
            .join(format!("n8n-uninstall-{}.receipt.json", uninstall.job_id));
        let selector = if case == "wrong_selector" {
            &source.job_id
        } else {
            &uninstall.job_id
        };
        if case == "missing_receipt" {
            std::fs::remove_file(&path).unwrap();
        }
        if case == "malformed_receipt" {
            std::fs::write(&path, b"{").unwrap();
        }
        let confirmation = if case == "wrong_confirmation" {
            "PURGE N8N VOLUME wrong".into()
        } else {
            format!("PURGE N8N VOLUME {} neoth_n8n_bootstrap_test", selector)
        };
        assert!(
            purge_retained_volume_at_with(home.path(), selector, &confirmation, &mut runner)
                .await
                .is_err()
        );
        assert_eq!(state.lock().unwrap().calls.len(), before_calls);
        if case == "wrong_confirmation" || case == "wrong_selector" {
            assert_eq!(snapshot(home.path()), before_jobs);
        }
        assert_eq!(calls(&state, "remove_volume:"), 0);
    }
}

#[tokio::test]
async fn purge_rejects_active_runtime_and_foreign_or_unknown_volume_without_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_sender, mut cancel) = tokio::sync::oneshot::channel();
    let install = install_managed_at_with(
        home.path(),
        ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(),
        crate::secret::SecretString::from("test-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    assert!(
        purge_retained_volume_at_with(
            home.path(),
            &install.job_id,
            "PURGE N8N VOLUME",
            &mut runner
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&state, "remove_volume:"), 0);
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let plan = prepare_purge_at(home.path(), &uninstall.job_id).unwrap();
    runner
        .0
        .lock()
        .unwrap()
        .volume
        .as_mut()
        .unwrap()
        .labels
        .insert("io.neoth.n8n-job".into(), uuid::Uuid::now_v7().to_string());
    assert!(
        purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&state, "remove_volume:"), 0);
    runner.0.lock().unwrap().volume_unknown = true;
    assert!(
        purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&state, "remove_volume:"), 0);
}

#[tokio::test]
async fn dispatched_purge_reconciles_only_by_later_absence_without_a_second_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let plan = prepare_purge_at(home.path(), &uninstall.job_id).unwrap();
    {
        let mut value = state.lock().unwrap();
        value.remove_error = true;
        value.remove_leaves_volume = true;
    }
    assert!(
        purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&state, "remove_volume:"), 1);
    assert_eq!(
        read_custody(home.path()).unwrap().unwrap().phase,
        PurgePhase::RemoveDispatched
    );
    state.lock().unwrap().volume = None;
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:"), 1);
    assert_eq!(
        read_custody(home.path()).unwrap().unwrap().phase,
        PurgePhase::Completed
    );
}

#[tokio::test]
async fn remove_error_after_effect_is_accepted_only_after_exact_absence() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let plan = prepare_purge_at(home.path(), &uninstall.job_id).unwrap();
    state.lock().unwrap().remove_error = true;
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:"), 1);
}

#[tokio::test]
async fn completed_custody_rotates_only_after_a_valid_new_bootstrap_uninstall_generation() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_first_source, first_uninstall) =
        ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let first_plan = prepare_purge_at(home.path(), &first_uninstall.job_id).unwrap();
    let first = purge_retained_volume_at_with(
        home.path(),
        &first_uninstall.job_id,
        &first_plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(first.state, JobState::Ready);

    let (_second_source, second_uninstall) =
        ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let second_plan = prepare_purge_at(home.path(), &second_uninstall.job_id).unwrap();
    let second = purge_retained_volume_at_with(
        home.path(),
        &second_uninstall.job_id,
        &second_plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(second.state, JobState::Ready);
    assert_ne!(first.job_id, second.job_id);
    assert_eq!(calls(&state, "remove_volume:neoth_n8n_bootstrap_test"), 2);
    assert_eq!(
        read_custody(home.path()).unwrap().unwrap().uninstall_job_id,
        second_uninstall.job_id.as_str()
    );
}

#[tokio::test]
async fn purge_owner_lock_contention_keeps_the_preflight_read_only_and_never_calls_docker() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let plan = prepare_purge_at(home.path(), &uninstall.job_id).unwrap();
    let before_jobs = snapshot(home.path());
    let before_calls = state.lock().unwrap().calls.len();
    let _owner =
        IntegrationJobService::open_fail_closed(home.path(), super::super::n8n_catalog()).unwrap();
    assert!(
        purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner
        )
        .await
        .is_err()
    );
    assert_eq!(snapshot(home.path()), before_jobs);
    assert_eq!(state.lock().unwrap().calls.len(), before_calls);
    assert_eq!(calls(&state, "remove_volume:"), 0);
}

#[tokio::test]
async fn locked_preflight_rechecks_a_binding_created_after_read_only_plan_resolution() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let request =
        super::super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
            home.path(),
            &uninstall.job_id,
            IntegrationJobService::read_only_snapshot(home.path()).unwrap(),
        )
        .unwrap();
    let plan = plan_from_request(&uninstall.job_id, &request).unwrap();
    let retained_source = source(&request).unwrap();
    let (_sender, mut cancel) = tokio::sync::oneshot::channel();
    install_managed_at_with(
        home.path(),
        ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(),
        crate::secret::SecretString::from("test-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    let service = open_service(home.path(), &plan, retained_source).unwrap();
    let before = state.lock().unwrap().calls.len();
    assert!(
        validate_locked_preflight(
            &service,
            home.path(),
            &uninstall.job_id,
            &plan,
            retained_source
        )
        .is_err()
    );
    assert_eq!(state.lock().unwrap().calls.len(), before);
    assert_eq!(calls(&state, "remove_volume:"), 0);
}

#[tokio::test]
async fn intent_with_durable_inspection_checkpoint_recovers_and_removes_once() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let request =
        super::super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
            home.path(),
            &uninstall.job_id,
            IntegrationJobService::read_only_snapshot(home.path()).unwrap(),
        )
        .unwrap();
    let plan = plan_from_request(&uninstall.job_id, &request).unwrap();
    let retained_source = source(&request).unwrap();
    let service = open_service(home.path(), &plan, retained_source).unwrap();
    let queued = enqueue_purge(&service, &plan, retained_source).unwrap();
    let custody = PurgeCustody {
        schema_version: 1,
        phase: PurgePhase::IntentPersisted,
        purge_job_id: queued.job_id.as_str().into(),
        purge_manifest_sha256: queued.manifest_sha256.as_str().into(),
        uninstall_job_id: plan.uninstall_job_id.clone(),
        uninstall_manifest_sha256: retained_source.uninstall_manifest_sha256.clone(),
        source_install_job_id: retained_source.source_install_job_id.clone(),
        source_install_manifest_sha256: retained_source.source_install_manifest_sha256.clone(),
        volume: plan.volume.clone(),
        volume_owner_install_job_id: retained_source.volume_owner_install_job_id.clone(),
    };
    create_custody(home.path(), &custody).unwrap();
    let running = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let validating = service
        .begin_validation(&running.job_id, running.state_revision, STEPS[0])
        .unwrap();
    let first = checkpoint(&service, &validating, 1, STEPS[0]).unwrap();
    let inspected = checkpoint(&service, &first, 2, STEPS[1]).unwrap();
    assert_eq!(inspected.progress.completed_steps, 2);
    drop(service);
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:"), 1);
}

#[tokio::test]
async fn completed_custody_with_receipt_before_ready_recovers_without_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let request =
        super::super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
            home.path(),
            &uninstall.job_id,
            IntegrationJobService::read_only_snapshot(home.path()).unwrap(),
        )
        .unwrap();
    let plan = plan_from_request(&uninstall.job_id, &request).unwrap();
    let retained_source = source(&request).unwrap();
    let service = open_service(home.path(), &plan, retained_source).unwrap();
    let queued = enqueue_purge(&service, &plan, retained_source).unwrap();
    let mut custody = PurgeCustody {
        schema_version: 1,
        phase: PurgePhase::AbsentVerified,
        purge_job_id: queued.job_id.as_str().into(),
        purge_manifest_sha256: queued.manifest_sha256.as_str().into(),
        uninstall_job_id: plan.uninstall_job_id.clone(),
        uninstall_manifest_sha256: retained_source.uninstall_manifest_sha256.clone(),
        source_install_job_id: retained_source.source_install_job_id.clone(),
        source_install_manifest_sha256: retained_source.source_install_manifest_sha256.clone(),
        volume: plan.volume.clone(),
        volume_owner_install_job_id: retained_source.volume_owner_install_job_id.clone(),
    };
    create_custody(home.path(), &custody).unwrap();
    let running = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let validating = service
        .begin_validation(&running.job_id, running.state_revision, STEPS[0])
        .unwrap();
    let first = checkpoint(&service, &validating, 1, STEPS[0]).unwrap();
    let second = checkpoint(&service, &first, 2, STEPS[1]).unwrap();
    let configuring = service
        .begin_configuration(&second.job_id, second.state_revision, STEPS[2])
        .unwrap();
    let third = checkpoint(&service, &configuring, 3, STEPS[2]).unwrap();
    custody.phase = PurgePhase::Completed;
    write_receipt(home.path(), &custody).unwrap();
    write_custody(home.path(), &custody).unwrap();
    assert_eq!(third.progress.completed_steps, 3);
    drop(service);
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:"), 0);
}

#[tokio::test]
async fn absent_verified_custody_before_configuration_recovers_without_remove() {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut runner = Fake(state.clone());
    let (_source, uninstall) = ready_bootstrap_uninstall(home.path(), &mut runner).await;
    let request =
        super::super::managed_runtime::managed_uninstall::retained_reinstall_request_from_snapshot(
            home.path(),
            &uninstall.job_id,
            IntegrationJobService::read_only_snapshot(home.path()).unwrap(),
        )
        .unwrap();
    let plan = plan_from_request(&uninstall.job_id, &request).unwrap();
    let retained_source = source(&request).unwrap();
    let service = open_service(home.path(), &plan, retained_source).unwrap();
    let queued = enqueue_purge(&service, &plan, retained_source).unwrap();
    let custody = PurgeCustody {
        schema_version: 1,
        phase: PurgePhase::AbsentVerified,
        purge_job_id: queued.job_id.as_str().into(),
        purge_manifest_sha256: queued.manifest_sha256.as_str().into(),
        uninstall_job_id: plan.uninstall_job_id.clone(),
        uninstall_manifest_sha256: retained_source.uninstall_manifest_sha256.clone(),
        source_install_job_id: retained_source.source_install_job_id.clone(),
        source_install_manifest_sha256: retained_source.source_install_manifest_sha256.clone(),
        volume: plan.volume.clone(),
        volume_owner_install_job_id: retained_source.volume_owner_install_job_id.clone(),
    };
    create_custody(home.path(), &custody).unwrap();
    let running = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let validating = service
        .begin_validation(&running.job_id, running.state_revision, STEPS[0])
        .unwrap();
    let first = checkpoint(&service, &validating, 1, STEPS[0]).unwrap();
    checkpoint(&service, &first, 2, STEPS[1]).unwrap();
    drop(service);
    let ready = purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "remove_volume:"), 0);
}
