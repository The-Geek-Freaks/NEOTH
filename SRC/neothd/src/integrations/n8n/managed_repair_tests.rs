//! Behavioural tests for same-generation managed n8n repair.
use super::*;
use std::sync::{Arc, Mutex};

fn initialize(home: &std::path::Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}

fn key() -> SecretString {
    SecretString::from("repair-test-key")
}

fn receipt() -> super::super::ManagedCommandReceipt {
    super::super::ManagedCommandReceipt {
        succeeded: true,
        output_sha256: "a".repeat(64),
    }
}

fn observed(id: String, job: &str, port: u16, volume: String) -> super::super::ObservedContainer {
    super::super::ObservedContainer {
        id,
        image: super::super::N8N_OCI_REFERENCE.into(),
        managed: super::super::MANAGED_LABEL_VALUE.into(),
        job: job.into(),
        host_ip: "127.0.0.1".into(),
        host_port: port,
        volume,
        mount_destination: "/home/node/.n8n".into(),
    }
}

#[derive(Default)]
struct State {
    container: Option<super::super::ObservedContainer>,
    running: bool,
    calls: Vec<String>,
    unknown_create: bool,
    next_container: u64,
    volume_present: bool,
    volume_labels: std::collections::BTreeMap<String, String>,
}
struct Runner(Arc<Mutex<State>>);
#[async_trait::async_trait]
impl super::super::ManagedDockerRunner for Runner {
    async fn inspect_named(&mut self) -> Result<super::super::InspectOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(s.container
            .clone()
            .map(super::super::InspectOutcome::Found)
            .unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn inspect_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("exact:{id}"));
        Ok(s.container
            .clone()
            .filter(|c| c.id == id)
            .map(super::super::InspectOutcome::Found)
            .unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn running_exact(&mut self, id: &str) -> Result<bool, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(s.container.as_ref().is_some_and(|c| c.id == id) && s.running)
    }
    async fn inspect_volume(
        &mut self,
        name: &str,
    ) -> Result<super::super::InspectVolumeOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(if s.volume_present {
            super::super::InspectVolumeOutcome::Found(super::super::ObservedVolume {
                name: name.into(),
                labels: s.volume_labels.clone(),
            })
        } else {
            super::super::InspectVolumeOutcome::Absent
        })
    }
    async fn create(
        &mut self,
        argv: &[String],
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("create".into());
        if s.unknown_create {
            return Err("uncertain_create");
        }
        let job = argv
            .windows(2)
            .find(|x| x[0] == "--label" && x[1].starts_with("io.neoth.n8n-job="))
            .unwrap()[1]
            .trim_start_matches("io.neoth.n8n-job=")
            .to_owned();
        let port = argv.windows(2).find(|x| x[0] == "-p").unwrap()[1]
            .split(':')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let volume = argv.windows(2).find(|x| x[0] == "-v").unwrap()[1]
            .split(':')
            .next()
            .unwrap()
            .to_owned();
        s.next_container += 1;
        let id = format!("{:064x}", s.next_container);
        s.container = Some(observed(id, &job, port, volume));
        s.running = true;
        s.volume_present = true;
        Ok(receipt())
    }
    async fn create_with_exact_id(
        &mut self,
        argv: &[String],
    ) -> Result<super::super::ManagedCreateReceipt, &'static str> {
        let command = self.create(argv).await?;
        let container_id = self
            .0
            .lock()
            .unwrap()
            .container
            .as_ref()
            .map(|container| container.id.clone());
        Ok(super::super::ManagedCreateReceipt {
            command,
            container_id,
        })
    }
    async fn start_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("start:{id}"));
        if s.container.as_ref().is_some_and(|c| c.id == id) {
            s.running = true;
            Ok(receipt())
        } else {
            Err("wrong_id")
        }
    }
    async fn remove(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("remove:{id}"));
        if s.container.as_ref().is_some_and(|c| c.id == id) {
            s.container = None;
            Ok(receipt())
        } else {
            Err("wrong_remove_id")
        }
    }
    async fn remove_volume(
        &mut self,
        name: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("remove_volume:{name}"));
        s.volume_present = false;
        Ok(receipt())
    }
}
struct Ready(bool);
#[async_trait::async_trait]
impl super::super::ManagedReadiness for Ready {
    async fn health(&self, _: u16) -> bool {
        self.0
    }
}
struct Probe(bool);
#[async_trait::async_trait]
impl super::super::N8nApiProbe for Probe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<(), super::super::super::N8nProbeError> {
        Ok(())
    }
    async fn authenticated_probe(
        &self,
        e: &crate::config::LoopbackHttpEndpoint,
        _: &SecretString,
    ) -> Result<super::super::super::N8nProbeReceipt, super::super::super::N8nProbeError> {
        if self.0 {
            super::super::super::parse_workflows_response(
                e.clone(),
                200,
                br#"{"data":[],"nextCursor":null}"#,
            )
        } else {
            Err(super::super::super::N8nProbeError::Unauthorized)
        }
    }
}
async fn installed(home: &std::path::Path, runner: &mut Runner) -> IntegrationJob {
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    super::super::install_managed_at_with(
        home,
        super::super::ManagedN8nRequest::new(5678, super::super::N8N_OCI_REFERENCE).unwrap(),
        key(),
        runner,
        &Ready(true),
        &Probe(true),
        &mut cancel,
    )
    .await
    .unwrap()
}
async fn fixture() -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, IntegrationJob) {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(State::default()));
    let mut runner = Runner(state.clone());
    let job = installed(home.path(), &mut runner).await;
    state.lock().unwrap().calls.clear();
    (home, runner, state, job)
}

#[tokio::test]
async fn healthy_repair_is_no_docker_mutation_and_preserves_persisted_source_ready() {
    let (home, mut runner, state, source) = fixture().await;
    let source_before = serde_json::to_vec(&source).unwrap();
    let repaired =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap();
    let persisted = super::super::IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    let persisted_source = persisted
        .iter()
        .find(|job| job.job_id == source.job_id)
        .unwrap();

    assert_eq!(repaired.state, JobState::Ready);
    assert_eq!(persisted_source.state, JobState::Ready);
    assert_eq!(serde_json::to_vec(persisted_source).unwrap(), source_before);
    assert!(!state.lock().unwrap().calls.iter().any(|call| {
        call == "create" || call.starts_with("start:") || call.starts_with("remove:")
    }));
}
#[tokio::test]
async fn stopped_exact_id_starts_once_with_real_stopped_port_shape() {
    let (home, mut r, s, _) = fixture().await;
    s.lock().unwrap().running = false;
    let old = s.lock().unwrap().container.clone().unwrap().id;
    repair_managed_at_with(home.path(), key(), &mut r, &Ready(true), &Probe(true))
        .await
        .unwrap();
    let calls = s.lock().unwrap().calls.clone();
    assert_eq!(
        calls
            .iter()
            .filter(|c| *c == &format!("start:{old}"))
            .count(),
        1
    );
    assert!(!calls.iter().any(|c| c == "create"));
}
#[tokio::test]
async fn missing_exact_and_name_recreates_same_volume_and_source_key() {
    let (home, mut runner, state, source) = fixture().await;
    state.lock().unwrap().container = None;
    repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
        .await
        .unwrap();
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let recreated_id = state.lock().unwrap().container.clone().unwrap().id;

    assert_eq!(binding.volume, super::super::DEFAULT_VOLUME);
    assert_eq!(binding.job_id, source.job_id.as_str());
    assert_eq!(recreated_id, format!("{:064x}", 2));
    assert_eq!(binding.container_id.as_deref(), Some(recreated_id.as_str()));
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| *call == "create")
            .count(),
        1
    );
}

#[tokio::test]
async fn uncertain_create_never_effects_twice_or_adopts() {
    let (home, mut runner, state, _source) = fixture().await;
    state.lock().unwrap().container = None;
    state.lock().unwrap().unknown_create = true;

    assert!(
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .is_err()
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| *call == "create")
            .count(),
        1
    );
    assert!(
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .is_err()
    );
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| *call == "create")
            .count(),
        1
    );
}
#[tokio::test]
async fn readiness_failure_does_not_ready_repair_or_lose_binding_or_key() {
    let (home, mut runner, _state, _source) = fixture().await;
    let binding_path = home.path().join("n8n-managed-runtime.v2.json");
    let credentials_path = home.path().join("credentials.yaml");
    let binding_before = std::fs::read(&binding_path).unwrap();
    let credentials_before = std::fs::read(&credentials_path).unwrap();

    assert!(
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(false))
            .await
            .is_err()
    );

    assert_eq!(std::fs::read(&binding_path).unwrap(), binding_before);
    assert_eq!(
        std::fs::read(&credentials_path).unwrap(),
        credentials_before
    );
    let jobs = super::super::IntegrationJobService::read_only_snapshot(home.path()).unwrap();
    assert!(
        !jobs
            .iter()
            .any(|job| job.operation == JobOperation::Repair && job.state == JobState::Ready)
    );
}

#[tokio::test]
async fn exact_image_port_and_volume_conflicts_refuse_before_start_or_create() {
    for conflict in ["image", "port", "volume"] {
        let (home, mut runner, state, _source) = fixture().await;
        let binding_before =
            std::fs::read(home.path().join("n8n-managed-runtime.v2.json")).unwrap();
        let credentials_before = std::fs::read(home.path().join("credentials.yaml")).unwrap();
        {
            let mut state = state.lock().unwrap();
            let container = state.container.as_mut().unwrap();
            match conflict {
                "image" => container.image = "sha256:foreign".into(),
                "port" => container.host_port = 9876,
                "volume" => container.volume = "foreign-volume".into(),
                _ => unreachable!(),
            }
        }

        assert!(
            repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
                .await
                .is_err(),
            "{conflict}"
        );
        let state = state.lock().unwrap();
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call == "create" || call.starts_with("start:")),
            "{conflict}"
        );
        drop(state);
        assert_eq!(
            std::fs::read(home.path().join("n8n-managed-runtime.v2.json")).unwrap(),
            binding_before,
            "{conflict}"
        );
        assert_eq!(
            std::fs::read(home.path().join("credentials.yaml")).unwrap(),
            credentials_before,
            "{conflict}"
        );
    }
}

#[tokio::test]
async fn binding_commit_cas_recovers_with_old_or_already_new_binding_without_redispatch() {
    for (recovery_state, already_committed) in [
        (JobState::Queued, false),
        (JobState::Queued, true),
        (JobState::Running, false),
        (JobState::Running, true),
        (JobState::Validating, false),
        (JobState::Validating, true),
        (JobState::Configuring, false),
        (JobState::Configuring, true),
    ] {
        let (home, mut runner, state, _source) = fixture().await;
        let service = super::super::super::open_n8n_job_service(home.path()).unwrap();
        let (old_binding, source) = source_ready(&service, home.path()).unwrap();
        let queued = enqueue_repair(&service, &old_binding, &source, 1).unwrap();
        let repair = match recovery_state {
            JobState::Queued => queued,
            JobState::Running => service
                .start(&queued.job_id, queued.state_revision, "crash-before-validation")
                .unwrap(),
            JobState::Validating => {
                let running = service
                    .start(&queued.job_id, queued.state_revision, "crash-before-validation")
                    .unwrap();
                service
                    .begin_validation(
                        &running.job_id,
                        running.state_revision,
                        "crash-before-configuration",
                    )
                    .unwrap()
            }
            JobState::Configuring => {
                let running = service
                    .start(&queued.job_id, queued.state_revision, "crash-before-validation")
                    .unwrap();
                let validating = service
                    .begin_validation(
                        &running.job_id,
                        running.state_revision,
                        "crash-before-configuration",
                    )
                    .unwrap();
                service
                    .begin_configuration(
                        &validating.job_id,
                        validating.state_revision,
                        "crash-before-ready",
                    )
                    .unwrap()
            }
            _ => unreachable!(),
        };
        let next = expected_recreated_binding(
            &RepairCustody {
                schema_version: 1,
                phase: RepairPhase::BindingCommitDispatched,
                repair_job_id: repair.job_id.as_str().into(),
                repair_manifest_sha256: repair.manifest_sha256.as_str().into(),
                generation: 1,
                source_install_job_id: source.job_id.as_str().into(),
                source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
                action: Some("recreated".into()),
                old_container_id: old_binding.container_id.clone().unwrap(),
                new_container_id: Some("d".repeat(64)),
                old_binding: old_binding.clone(),
                new_binding: None,
                old_binding_bytes: super::super::read_binding_bytes(home.path())
                    .unwrap()
                    .unwrap(),
                new_binding_bytes: None,
            },
            "d".repeat(64),
        );
        let custody = RepairCustody {
            schema_version: 1,
            phase: RepairPhase::BindingCommitDispatched,
            repair_job_id: repair.job_id.as_str().into(),
            repair_manifest_sha256: repair.manifest_sha256.as_str().into(),
            generation: 1,
            source_install_job_id: source.job_id.as_str().into(),
            source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
            action: Some("recreated".into()),
            old_container_id: old_binding.container_id.clone().unwrap(),
            new_container_id: Some("d".repeat(64)),
            old_binding: old_binding.clone(),
            new_binding: Some(next.clone()),
            old_binding_bytes: super::super::read_binding_bytes(home.path())
                .unwrap()
                .unwrap(),
            new_binding_bytes: Some(serde_json::to_vec(&next).unwrap()),
        };
        state.lock().unwrap().container = Some(observed(
            "d".repeat(64),
            source.job_id.as_str(),
            old_binding.host_port,
            old_binding.volume.clone(),
        ));
        state.lock().unwrap().running = true;
        if already_committed {
            super::super::write_binding(home.path(), &next).unwrap();
        }
        write_custody(home.path(), &custody).unwrap();

        let ready =
            repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
                .await
                .unwrap();
        assert_eq!(ready.state, JobState::Ready);
        assert_eq!(
            super::super::read_binding(home.path()).unwrap().unwrap(),
            next
        );
        assert!(
            !state
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| call == "create" || call.starts_with("start:"))
        );
    }
}

#[tokio::test]
async fn bootstrap_volume_owner_labels_allow_repair_and_foreign_or_missing_labels_block_effects() {
    for labels_valid in [true, false] {
        let (home, mut runner, state, source) = fixture().await;
        let mut binding = super::super::read_binding(home.path()).unwrap().unwrap();
        binding.bootstrap_volume_owner_job_id = Some(source.job_id.as_str().into());
        super::super::write_binding(home.path(), &binding).unwrap();
        if labels_valid {
            state.lock().unwrap().volume_present = true;
            state.lock().unwrap().volume_labels = std::collections::BTreeMap::from([
                (
                    super::super::MANAGED_LABEL_KEY.into(),
                    super::super::MANAGED_LABEL_VALUE.into(),
                ),
                ("io.neoth.n8n-job".into(), source.job_id.as_str().into()),
                (
                    "io.neoth.n8n-bootstrap".into(),
                    super::super::super::managed_bootstrap::BOOTSTRAP_SCHEMA.into(),
                ),
            ]);
        }
        let result =
            repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
                .await;
        if labels_valid {
            assert_eq!(result.unwrap().state, JobState::Ready);
            let persisted =
                super::super::IntegrationJobService::read_only_snapshot(home.path()).unwrap();
            assert!(
                persisted
                    .iter()
                    .any(|job| job.job_id == source.job_id && job.state == JobState::Ready)
            );
        } else {
            assert!(result.is_err());
            assert!(
                !state
                    .lock()
                    .unwrap()
                    .calls
                    .iter()
                    .any(|call| call == "create" || call.starts_with("start:"))
            );
        }
    }
}

#[tokio::test]
async fn unwitnessed_create_never_adopts_a_later_matching_named_container() {
    let (home, mut runner, state, source) = fixture().await;
    let old_id = state.lock().unwrap().container.clone().unwrap().id;
    state.lock().unwrap().container = None;
    state.lock().unwrap().unknown_create = true;

    assert!(
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .is_err()
    );
    state.lock().unwrap().container = Some(observed(
        "d".repeat(64),
        source.job_id.as_str(),
        5678,
        super::super::DEFAULT_VOLUME.into(),
    ));
    state.lock().unwrap().running = true;
    assert!(
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .is_err()
    );

    let state = state.lock().unwrap();
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|call| call.as_str() == "create")
            .count(),
        1
    );
    assert!(!state.calls.iter().any(|call| call.starts_with("start:")));
    assert_ne!(old_id, "d".repeat(64));
}

#[tokio::test]
async fn completed_repair_revalidates_a_later_stopped_runtime_instead_of_replaying_ready() {
    let (home, mut runner, state, _source) = fixture().await;
    let first = repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
        .await
        .unwrap();
    assert_eq!(first.state, JobState::Ready);
    state.lock().unwrap().running = false;
    let old_id = state.lock().unwrap().container.clone().unwrap().id;

    let second =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap();
    assert_eq!(second.state, JobState::Ready);
    assert!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == &format!("start:{old_id}"))
    );
}

#[tokio::test]
async fn malformed_repair_sidecar_blocks_uninstall_before_any_docker_effect() {
    let (home, mut runner, state, _source) = fixture().await;
    std::fs::write(home.path().join("n8n-managed-repair.v1.json"), b"not-json").unwrap();

    assert!(
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .is_err()
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == "create"
                || call.starts_with("start:")
                || call.starts_with("remove:"))
    );
}

#[tokio::test]
async fn completed_uninstall_sidecar_with_live_binding_blocks_repair_before_recreate() {
    let (home, mut runner, state, source) = bootstrap_fixture().await;
    let binding_bytes = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    assert_eq!(uninstall.state, JobState::Ready);
    assert!(state.lock().unwrap().container.is_none());
    let completion: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            home.path()
                .join(format!("n8n-uninstall-{}.receipt.json", uninstall.job_id)),
        )
        .unwrap(),
    )
    .unwrap();
    // Replay the real publication boundary: Ready and its completion receipt
    // exist, while the exact pre-finalizer binding and custody remain on disk.
    std::fs::write(
        home.path().join("n8n-managed-runtime.v2.json"),
        &binding_bytes,
    )
    .unwrap();
    let sidecar = serde_json::json!({
        "schema_version": 1,
        "phase": "completed",
        "uninstall_job_id": uninstall.job_id.as_str(),
        "uninstall_manifest_sha256": uninstall.manifest_sha256.as_str(),
        "source_install_job_id": source.job_id.as_str(),
        "source_install_manifest_sha256": source.manifest_sha256.as_str(),
        "container_id": binding.container_id.as_deref().unwrap(),
        "image": binding.image,
        "host_port": binding.host_port,
        "volume": binding.volume,
        "cleanup_disposition": completion["cleanup_disposition"],
    });
    let custody_path = home.path().join("n8n-managed-uninstall.v1.json");
    std::fs::write(&custody_path, serde_json::to_vec(&sidecar).unwrap()).unwrap();
    state.lock().unwrap().calls.clear();

    let failure =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("n8n_repair_conflicting_custody")
    );
    assert_eq!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        binding_bytes
    );
    assert_no_effect_after_setup(&state);
    let reconciled =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    assert_eq!(reconciled.job_id, uninstall.job_id);
    assert!(super::super::read_binding(home.path()).unwrap().is_none());
    assert!(!custody_path.exists());
    assert_no_effect_after_setup(&state);
}

async fn bootstrap_fixture() -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, IntegrationJob) {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(State::default()));
    let mut runner = Runner(state.clone());
    let (_sender, mut cancel) = tokio::sync::oneshot::channel();
    let source = super::super::install_managed_at_with(
        home.path(),
        super::super::ManagedN8nRequest::new_with_volume(
            5678,
            super::super::N8N_OCI_REFERENCE,
            "neoth_n8n_bootstrap_repair_test".into(),
        )
        .unwrap(),
        key(),
        &mut runner,
        &Ready(true),
        &Probe(true),
        &mut cancel,
    )
    .await
    .unwrap();
    super::super::mark_bootstrap_volume_owner_for_test(home.path(), source.job_id.as_str())
        .unwrap();
    state.lock().unwrap().volume_labels = std::collections::BTreeMap::from([
        (
            super::super::MANAGED_LABEL_KEY.into(),
            super::super::MANAGED_LABEL_VALUE.into(),
        ),
        ("io.neoth.n8n-job".into(), source.job_id.as_str().into()),
        (
            "io.neoth.n8n-bootstrap".into(),
            super::super::super::managed_bootstrap::BOOTSTRAP_SCHEMA.into(),
        ),
    ]);
    state.lock().unwrap().volume_present = true;
    state.lock().unwrap().calls.clear();
    (home, runner, state, source)
}

fn assert_no_effect_after_setup(state: &Arc<Mutex<State>>) {
    assert!(!state.lock().unwrap().calls.iter().any(|call| {
        call == "create"
            || call.starts_with("start:")
            || call.starts_with("remove:")
            || call.starts_with("remove_volume:")
    }));
}

fn completed_sidecar_for_nonready_repair(
    repair: &IntegrationJob,
    source: &IntegrationJob,
    binding: &super::super::RuntimeBinding,
    binding_bytes: Vec<u8>,
) -> RepairCustody {
    RepairCustody {
        schema_version: 1,
        phase: RepairPhase::Completed,
        repair_job_id: repair.job_id.as_str().into(),
        repair_manifest_sha256: repair.manifest_sha256.as_str().into(),
        generation: 1,
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        action: Some("healthy".into()),
        old_container_id: binding.container_id.clone().unwrap(),
        new_container_id: None,
        old_binding: binding.clone(),
        new_binding: None,
        old_binding_bytes: binding_bytes,
        new_binding_bytes: None,
    }
}

#[tokio::test]
async fn pending_start_and_create_repair_custody_block_uninstall_before_effects() {
    for phase in [
        RepairPhase::StartDispatched,
        RepairPhase::RecreateDispatched,
    ] {
        let (home, mut runner, state, _source) = fixture().await;
        let completed =
            repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
                .await
                .unwrap();
        let mut custody = read_custody(home.path()).unwrap().unwrap();
        assert_eq!(completed.state, JobState::Ready);
        custody.phase = phase;
        write_custody(home.path(), &custody).unwrap();
        state.lock().unwrap().calls.clear();

        let failure =
            super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
                .await
                .unwrap_err();
        assert!(
            failure
                .to_string()
                .contains("n8n_uninstall_repair_custody_pending")
        );
        assert_no_effect_after_setup(&state);
    }
}

#[tokio::test]
async fn peer_operation_lock_reports_busy_without_repair_or_uninstall_effects() {
    let (home, mut runner, state, _source) = fixture().await;
    let lock = crate::util::locked_file::try_lock_file_once(
        &super::super::operation_lock_path(home.path()),
        "n8n repair peer test",
    )
    .unwrap()
    .unwrap();
    state.lock().unwrap().calls.clear();
    let repair =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap_err();
    assert!(repair.to_string().contains("n8n_managed_operation_busy"));
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap_err();
    assert!(uninstall.to_string().contains("n8n_managed_operation_busy"));
    assert_no_effect_after_setup(&state);
    drop(lock);
}

#[tokio::test]
async fn completed_sidecar_with_queued_or_running_repair_job_blocks_uninstall_and_purge() {
    let (home, mut runner, state, _source) = fixture().await;
    let service = super::super::super::open_n8n_job_service(home.path()).unwrap();
    let (binding, source) = source_ready(&service, home.path()).unwrap();
    let repair = enqueue_repair(&service, &binding, &source, 1).unwrap();
    write_custody(
        home.path(),
        &completed_sidecar_for_nonready_repair(
            &repair,
            &source,
            &binding,
            super::super::read_binding_bytes(home.path())
                .unwrap()
                .unwrap(),
        ),
    )
    .unwrap();
    state.lock().unwrap().calls.clear();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap_err();
    assert!(
        uninstall
            .to_string()
            .contains("n8n_uninstall_repair_custody_pending")
    );
    assert_no_effect_after_setup(&state);

    let (home, mut runner, state, source) = bootstrap_fixture().await;
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let binding_bytes = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let service = super::super::super::open_n8n_job_service(home.path()).unwrap();
    let repair = enqueue_repair(&service, &binding, &source, 1).unwrap();
    let running = service
        .start(
            &repair.job_id,
            repair.state_revision,
            "crash-before-mark-ready",
        )
        .unwrap();
    write_custody(
        home.path(),
        &completed_sidecar_for_nonready_repair(&running, &source, &binding, binding_bytes),
    )
    .unwrap();
    let plan =
        super::super::super::managed_purge::prepare_purge_at(home.path(), &uninstall.job_id)
            .unwrap();
    state.lock().unwrap().calls.clear();
    let purge = super::super::super::managed_purge::purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap_err();
    assert!(
        purge
            .to_string()
            .contains("n8n_purge_repair_custody_pending")
    );
    assert_no_effect_after_setup(&state);
}

#[tokio::test]
async fn pending_and_malformed_repair_custody_block_purge_before_volume_effects() {
    for phase in [
        Some(RepairPhase::StartDispatched),
        Some(RepairPhase::CreateIdWitnessed),
        None,
    ] {
        let (home, mut runner, state, _source) = bootstrap_fixture().await;
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap();
        let saved = read_custody(home.path()).unwrap().unwrap();
        let uninstall =
            super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
                .await
                .unwrap();
        if let Some(phase) = phase {
            let mut pending = saved;
            pending.phase = phase;
            write_custody(home.path(), &pending).unwrap();
        } else {
            std::fs::write(home.path().join("n8n-managed-repair.v1.json"), b"not-json").unwrap();
        }
        let plan =
            super::super::super::managed_purge::prepare_purge_at(home.path(), &uninstall.job_id)
                .unwrap();
        state.lock().unwrap().calls.clear();

        let failure = super::super::super::managed_purge::purge_retained_volume_at_with(
            home.path(),
            &uninstall.job_id,
            &plan.confirmation,
            &mut runner,
        )
        .await
        .unwrap_err();
        assert!(
            failure
                .to_string()
                .contains("n8n_purge_repair_custody_pending")
        );
        assert_no_effect_after_setup(&state);
    }
}

#[tokio::test]
async fn repair_uninstall_and_purge_complete_with_retained_owner_provenance() {
    let (home, mut runner, state, source) = bootstrap_fixture().await;
    let repair =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap();
    assert_eq!(repair.state, JobState::Ready);
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let plan =
        super::super::super::managed_purge::prepare_purge_at(home.path(), &uninstall.job_id)
            .unwrap();
    let purged = super::super::super::managed_purge::purge_retained_volume_at_with(
        home.path(),
        &uninstall.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(purged.state, JobState::Ready);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.starts_with("remove_volume:"))
            .count(),
        1
    );
    assert_eq!(source.operation, JobOperation::Install);
}

#[tokio::test]
async fn completed_repair_uninstall_reentry_returns_the_same_ready_uninstall_without_new_effect() {
    let (home, mut runner, state, _source) = bootstrap_fixture().await;
    repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
        .await
        .unwrap();
    let first =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let calls_before = state.lock().unwrap().calls.len();
    let second =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();

    assert_eq!(second.job_id, first.job_id);
    assert_eq!(state.lock().unwrap().calls.len(), calls_before);
}

#[tokio::test]
async fn retained_install_repair_uninstall_reinstall_and_repair_preserves_original_owner() {
    let (home, mut runner, state, source) = bootstrap_fixture().await;
    repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
        .await
        .unwrap();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let (_sender, mut cancel) = tokio::sync::oneshot::channel();
    let reinstalled = super::super::install_retained_at_with(
        home.path(),
        &uninstall.job_id,
        key(),
        &mut runner,
        &Ready(true),
        &Probe(true),
        &mut cancel,
    )
    .await
    .unwrap();
    state.lock().unwrap().calls.clear();
    let repaired =
        repair_managed_at_with(home.path(), key(), &mut runner, &Ready(true), &Probe(true))
            .await
            .unwrap();
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    assert_eq!(repaired.state, JobState::Ready);
    assert_eq!(binding.volume, "neoth_n8n_bootstrap_repair_test");
    assert_eq!(
        binding
            .retained_reinstall
            .unwrap()
            .volume_owner_install_job_id,
        source.job_id.as_str()
    );
    assert_ne!(reinstalled.job_id, source.job_id);
    assert_no_effect_after_setup(&state);
}
