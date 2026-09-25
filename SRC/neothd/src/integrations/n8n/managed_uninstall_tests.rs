use super::{
    checkpoint, cleanup_disposition_at, create_custody, enqueue_uninstall,
    finalize_ready_uninstall_custody, open_explicit_uninstall_service_with, read_binding,
    read_custody, source_ready_binding, uninstall_managed_at_with,
    uninstall_managed_at_with_restart_inspector, write_custody, UninstallCustody,
    UninstallPhase, STEPS,
};
use super::super::{
    install_managed_at_with, InspectOutcome, ManagedCommandReceipt, ManagedDockerRunner,
    ManagedN8nRequest, ManagedReadiness, ObservedContainer, DEFAULT_VOLUME,
    MANAGED_LABEL_VALUE, write_binding,
};
use crate::installers::n8n::N8N_OCI_REFERENCE;
use crate::integrations::n8n::{
    parse_workflows_response, N8nApiProbe, N8nProbeError, N8nProbeReceipt,
};
use crate::integrations::jobs::{IntegrationJobService, JobServiceError};
use crate::integrations::state::{IntegrationJob, JobOperation, JobState};
use std::sync::{Arc, Mutex};

fn initialize(home: &std::path::Path) {
    std::fs::write(home.join("freedom.yaml"), serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap()).unwrap();
}
fn observed(id: &str, job: &str) -> ObservedContainer {
    ObservedContainer { id: id.into(), image: N8N_OCI_REFERENCE.into(), managed: MANAGED_LABEL_VALUE.into(), job: job.into(), host_ip: "127.0.0.1".into(), host_port: 5678, volume: DEFAULT_VOLUME.into(), mount_destination: "/home/node/.n8n".into() }
}
#[derive(Default)] struct FakeState { container: Option<ObservedContainer>, calls: Vec<String>, remove_error: bool, exact_unknown: bool }
struct Fake(Arc<Mutex<FakeState>>);
#[async_trait::async_trait]
impl ManagedDockerRunner for Fake {
    async fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        let state = self.0.lock().unwrap(); Ok(state.container.clone().map(InspectOutcome::Found).unwrap_or(InspectOutcome::Absent))
    }
    async fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        let mut state = self.0.lock().unwrap(); state.calls.push(format!("inspect:{id}"));
        if state.exact_unknown { return Ok(InspectOutcome::Unknown); }
        Ok(state.container.clone().filter(|found| found.id == id).map(InspectOutcome::Found).unwrap_or(InspectOutcome::Absent))
    }
    async fn create(&mut self, argv: &[String]) -> Result<ManagedCommandReceipt, &'static str> {
        let job = argv.windows(2).find(|pair| pair[0] == "--label" && pair[1].starts_with("io.neoth.n8n-job=")).ok_or("missing_job")?[1].trim_start_matches("io.neoth.n8n-job=");
        self.0.lock().unwrap().container = Some(observed(&"c".repeat(64), job));
        Ok(ManagedCommandReceipt { succeeded: true, output_sha256: "a".repeat(64) })
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let mut state = self.0.lock().unwrap(); state.calls.push(format!("remove:{id}"));
        if state.remove_error { return Err("interrupted_after_dispatch"); }
        if state.container.as_ref().is_some_and(|found| found.id == id) { state.container = None; }
        Ok(ManagedCommandReceipt { succeeded: true, output_sha256: "b".repeat(64) })
    }
}
struct Ready;
#[async_trait::async_trait] impl ManagedReadiness for Ready { async fn health(&self, _: u16) -> bool { true } }
struct Probe;
#[async_trait::async_trait]
impl N8nApiProbe for Probe {
    async fn negative_control(&self, _: &crate::config::LoopbackHttpEndpoint) -> Result<(), N8nProbeError> { Ok(()) }
    async fn authenticated_probe(&self, endpoint: &crate::config::LoopbackHttpEndpoint, _: &crate::secret::SecretString) -> Result<N8nProbeReceipt, N8nProbeError> {
        parse_workflows_response(endpoint.clone(), 200, br#"{"data":[],"nextCursor":null}"#)
    }
}
async fn installed(home: &std::path::Path, runner: &mut Fake) -> IntegrationJob {
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    install_managed_at_with(home, ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(), crate::secret::SecretString::from("test-key"), runner, &Ready, &Probe, &mut cancel).await.unwrap()
}

fn restart_inspector(state: Arc<Mutex<FakeState>>) -> impl Fn(&str) -> Result<InspectOutcome, &'static str> + Send + Sync {
    move |id| {
        let state = state.lock().unwrap();
        if state.exact_unknown { return Ok(InspectOutcome::Unknown); }
        Ok(state.container.clone().filter(|found| found.id == id).map(InspectOutcome::Found).unwrap_or(InspectOutcome::Absent))
    }
}

fn completed_custody(job: &IntegrationJob, binding: &super::super::RuntimeBinding) -> UninstallCustody {
    UninstallCustody {
        schema_version: 1, phase: UninstallPhase::Completed,
        uninstall_job_id: job.job_id.as_str().into(), uninstall_manifest_sha256: job.manifest_sha256.as_str().into(),
        source_install_job_id: binding.job_id.as_str().into(), source_install_manifest_sha256: binding.manifest_sha256.as_str().into(),
        container_id: binding.container_id.clone().unwrap(), image: binding.image.clone(), host_port: binding.host_port,
        volume: binding.volume.clone(), cleanup_disposition: Some("cleared".into()),
    }
}

#[tokio::test]
async fn exact_id_uninstall_removes_container_never_volume_and_repeats_without_docker() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let job = uninstall_managed_at_with(home.path(), &mut runner).await.unwrap();
    assert_eq!(job.state, JobState::Ready);
    let calls = state.lock().unwrap().calls.clone();
    assert!(calls.iter().any(|call| call.starts_with("remove:")));
    assert!(!calls.iter().any(|call| call.contains("volume")));
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(matches!(cleanup_disposition_at(home.path(), &job).unwrap(), Some("cleared" | "already_absent")));
    let before = calls.len();
    assert_eq!(uninstall_managed_at_with(home.path(), &mut runner).await.unwrap().job_id, job.job_id);
    assert_eq!(state.lock().unwrap().calls.len(), before);
}

#[tokio::test]
async fn dispatched_error_never_repeats_remove_and_retains_custody() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector).await.is_err());
    let removes = state.lock().unwrap().calls.iter().filter(|call| call.starts_with("remove:")).count();
    assert_eq!(removes, 1);
    assert_eq!(read_custody(home.path()).unwrap().unwrap().phase, UninstallPhase::RemoveDispatched);
    state.lock().unwrap().container = None;
    let ready = uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector).await.unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(state.lock().unwrap().calls.iter().filter(|call| call.starts_with("remove:")).count(), 1);
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(matches!(cleanup_disposition_at(home.path(), &ready).unwrap(), Some("cleared" | "already_absent")));
}

#[tokio::test]
async fn dispatched_live_or_unknown_restart_holds_without_another_remove() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector).await.is_err());
    let removals = state.lock().unwrap().calls.iter().filter(|call| call.starts_with("remove:")).count();
    assert!(matches!(open_explicit_uninstall_service_with(home.path(), &inspector), Err(error) if matches!(error.downcast_ref::<JobServiceError>(), Some(JobServiceError::RecoveryHold { .. }))));
    let active = IntegrationJobService::read_only_snapshot(home.path()).unwrap().into_iter().find(|job| job.operation == JobOperation::Uninstall).unwrap();
    assert!(active.state.is_active());
    state.lock().unwrap().exact_unknown = true;
    assert!(matches!(open_explicit_uninstall_service_with(home.path(), &inspector), Err(error) if matches!(error.downcast_ref::<JobServiceError>(), Some(JobServiceError::RecoveryHold { .. }))));
    let active = IntegrationJobService::read_only_snapshot(home.path()).unwrap().into_iter().find(|job| job.operation == JobOperation::Uninstall).unwrap();
    assert!(active.state.is_active());
    assert_eq!(state.lock().unwrap().calls.iter().filter(|call| call.starts_with("remove:")).count(), removals);
}

#[tokio::test]
async fn missing_runtime_binding_has_zero_docker_mutations() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    assert!(uninstall_managed_at_with(home.path(), &mut runner).await.is_err());
    assert!(state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn foreign_exact_identity_never_dispatches_remove() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let binding = read_binding(home.path()).unwrap().unwrap();
    state.lock().unwrap().container = Some(observed(binding.container_id.as_deref().unwrap(), "foreign-managed-job"));
    assert!(uninstall_managed_at_with(home.path(), &mut runner).await.is_err());
    assert!(!state.lock().unwrap().calls.iter().any(|call| call.starts_with("remove:")));
    assert_eq!(read_custody(home.path()).unwrap().unwrap().phase, UninstallPhase::IntentPersisted);
}

#[tokio::test]
async fn ready_finalizer_reentry_handles_both_post_ready_crash_boundaries() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let binding = read_binding(home.path()).unwrap().unwrap();
    let ready = uninstall_managed_at_with(home.path(), &mut runner).await.unwrap();

    write_binding(home.path(), &binding).unwrap();
    let custody = completed_custody(&ready, &binding);
    write_custody(home.path(), &custody).unwrap();
    finalize_ready_uninstall_custody(home.path(), &ready).unwrap();
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());

    write_custody(home.path(), &custody).unwrap();
    finalize_ready_uninstall_custody(home.path(), &ready).unwrap();
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(matches!(cleanup_disposition_at(home.path(), &ready).unwrap(), Some("cleared" | "already_absent")));
}

#[tokio::test]
async fn queued_before_custody_is_terminalized_without_orphaning_the_runtime_binding() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let (binding, source) = source_ready_binding(&service, home.path()).unwrap();
    let queued = enqueue_uninstall(&service, &binding, &source).unwrap();
    drop(service);
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let recovered = service.get(&queued.job_id).unwrap().unwrap();
    assert_eq!(recovered.state, JobState::Failed);
    assert!(read_binding(home.path()).unwrap().is_some());
    assert!(read_custody(home.path()).unwrap().is_none());
    assert!(!state.lock().unwrap().calls.iter().any(|call| call.starts_with("remove:")));
}

#[tokio::test]
async fn configuring_between_checkpoint_one_and_three_reopens_from_the_durable_receipt() {
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    let _source = installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    let service = open_explicit_uninstall_service_with(home.path(), &inspector).unwrap();
    let (binding, source) = source_ready_binding(&service, home.path()).unwrap();
    let queued = enqueue_uninstall(&service, &binding, &source).unwrap();
    let custody = UninstallCustody { schema_version: 1, phase: UninstallPhase::IntentPersisted,
        uninstall_job_id: queued.job_id.as_str().into(), uninstall_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(), source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        container_id: binding.container_id.clone().unwrap(), image: binding.image.clone(), host_port: binding.host_port,
        volume: binding.volume.clone(), cleanup_disposition: None };
    create_custody(home.path(), &custody).unwrap();
    let running = service.start(&queued.job_id, queued.state_revision, STEPS[0]).unwrap();
    let validating = service.begin_validation(&running.job_id, running.state_revision, STEPS[0]).unwrap();
    let first = checkpoint(&service, &validating, 1, STEPS[0]).unwrap();
    let configuring = service.begin_configuration(&first.job_id, first.state_revision, STEPS[2]).unwrap();
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
    let home = tempfile::tempdir().unwrap(); initialize(home.path());
    let state = Arc::new(Mutex::new(FakeState::default())); let mut runner = Fake(state.clone());
    installed(home.path(), &mut runner).await;
    let first = uninstall_managed_at_with(home.path(), &mut runner).await.unwrap();
    installed(home.path(), &mut runner).await;
    let inspector = restart_inspector(state.clone());
    state.lock().unwrap().remove_error = true;
    assert!(uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector).await.is_err());
    state.lock().unwrap().container = None;
    let second = uninstall_managed_at_with_restart_inspector(home.path(), &mut runner, &inspector).await.unwrap();
    assert_ne!(first.job_id, second.job_id);
    let history = IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert_eq!(history.into_iter().find(|job| job.job_id == first.job_id).unwrap().state, JobState::Ready);
    assert!(read_binding(home.path()).unwrap().is_none());
    assert!(read_custody(home.path()).unwrap().is_none());
}
