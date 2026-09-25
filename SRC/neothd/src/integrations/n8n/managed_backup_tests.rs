//! Behavioural custody tests for stopped managed n8n backups.

use super::*;
use crate::{installers::n8n::N8N_OCI_REFERENCE, secret::SecretString};
use sha2::Digest as _;
use std::{
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

fn initialize(home: &Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap();
}
fn command_receipt() -> super::super::ManagedCommandReceipt {
    super::super::ManagedCommandReceipt {
        succeeded: true,
        output_sha256: "a".repeat(64),
    }
}
fn observed(id: String, job: &str, volume: String) -> super::super::ObservedContainer {
    super::super::ObservedContainer {
        id,
        image: N8N_OCI_REFERENCE.into(),
        managed: super::super::MANAGED_LABEL_VALUE.into(),
        job: job.into(),
        host_ip: "127.0.0.1".into(),
        host_port: 5678,
        volume,
        mount_destination: "/home/node/.n8n".into(),
    }
}

#[derive(Clone, Copy, Default)]
enum ArchiveResult {
    #[default]
    Good,
    ErrorAfterEffect,
    BadReceipt,
}
#[derive(Default)]
struct State {
    container: Option<super::super::ObservedContainer>,
    running: bool,
    volume: Option<super::super::ObservedVolume>,
    calls: Vec<String>,
    next_id: u64,
    stop_error: bool,
    start_error: bool,
    archive: ArchiveResult,
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
        s.calls.push(format!("inspect:{id}"));
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
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("volume:{name}"));
        Ok(s.volume
            .clone()
            .filter(|v| v.name == name)
            .map(super::super::InspectVolumeOutcome::Found)
            .unwrap_or(super::super::InspectVolumeOutcome::Absent))
    }
    async fn create(
        &mut self,
        argv: &[String],
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let job = argv
            .windows(2)
            .find(|p| p[0] == "--label" && p[1].starts_with("io.neoth.n8n-job="))
            .ok_or("missing_job")?[1]
            .trim_start_matches("io.neoth.n8n-job=")
            .to_owned();
        let volume = argv
            .windows(2)
            .find(|p| p[0] == "-v")
            .and_then(|p| p[1].split(':').next())
            .ok_or("missing_volume")?
            .to_owned();
        let mut s = self.0.lock().unwrap();
        s.calls.push("create".into());
        s.next_id += 1;
        let id = format!("{:064x}", s.next_id);
        s.container = Some(observed(id, &job, volume.clone()));
        s.running = true;
        s.volume = Some(super::super::ObservedVolume {
            name: volume,
            labels: Default::default(),
        });
        Ok(command_receipt())
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
            .map(|c| c.id.clone());
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
        if !s.container.as_ref().is_some_and(|c| c.id == id) {
            return Err("wrong_start");
        }
        s.running = true;
        if s.start_error {
            Err("start_receipt_lost")
        } else {
            Ok(command_receipt())
        }
    }
    async fn stop_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("stop:{id}"));
        if !s.container.as_ref().is_some_and(|c| c.id == id) {
            return Err("wrong_stop");
        }
        s.running = false;
        if s.stop_error {
            Err("stop_receipt_lost")
        } else {
            Ok(command_receipt())
        }
    }
    async fn archive_exact_n8n_dir_to_private_file(
        &mut self,
        id: &str,
        destination: &Path,
        _: u64,
    ) -> Result<super::super::ManagedArchiveReceipt, &'static str> {
        let outcome = {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("archive:{id}"));
            s.archive
        };
        let bytes = b"real-private-n8n-sqlite-archive";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|_| "archive_destination_exists")?;
        file.write_all(bytes).map_err(|_| "archive_write_failed")?;
        file.sync_all().map_err(|_| "archive_write_failed")?;
        match outcome {
            ArchiveResult::Good => Ok(super::super::ManagedArchiveReceipt {
                archive_sha256: hex::encode(sha2::Sha256::digest(bytes)),
                archive_bytes: bytes.len() as u64,
            }),
            ArchiveResult::ErrorAfterEffect => Err("archive_receipt_lost"),
            ArchiveResult::BadReceipt => Ok(super::super::ManagedArchiveReceipt {
                archive_sha256: "0".repeat(64),
                archive_bytes: bytes.len() as u64 + 1,
            }),
        }
    }
    async fn remove(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        self.0.lock().unwrap().calls.push(format!("remove:{id}"));
        Ok(command_receipt())
    }
}
struct Ready;
#[async_trait::async_trait]
impl super::super::ManagedReadiness for Ready {
    async fn health(&self, _: u16) -> bool {
        true
    }
}
struct Probe;
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
        _: &SecretString,
    ) -> Result<super::super::N8nProbeReceipt, super::super::N8nProbeError> {
        super::super::parse_workflows_response(
            endpoint.clone(),
            200,
            br#"{"data":[],"nextCursor":null}"#,
        )
    }
}
async fn fixture() -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, IntegrationJob) {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(State::default()));
    let mut runner = Runner(state.clone());
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let source = super::super::install_managed_at_with(
        home.path(),
        super::super::ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(),
        SecretString::from("backup-test-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    state.lock().unwrap().calls.clear();
    (home, runner, state, source)
}
fn calls(state: &Arc<Mutex<State>>, prefix: &str) -> usize {
    state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c.starts_with(prefix))
        .count()
}
fn jobs(home: &Path) -> Vec<IntegrationJob> {
    IntegrationJobService::read_only_snapshot(home).unwrap()
}

#[tokio::test]
async fn running_source_backup_stops_archives_restores_and_publishes_exact_receipt() {
    let (home, mut runner, state, source) = fixture().await;
    let before = serde_json::to_vec(&source).unwrap();
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(backup.state, JobState::Ready);
    assert_eq!(calls(&state, "stop:"), 1);
    assert_eq!(calls(&state, "archive:"), 1);
    assert_eq!(calls(&state, "start:"), 1);
    assert_eq!(calls(&state, "create"), 0);
    assert_eq!(calls(&state, "remove:"), 0);
    assert!(state.lock().unwrap().running);
    assert_eq!(
        serde_json::to_vec(
            jobs(home.path())
                .iter()
                .find(|j| j.job_id == source.job_id)
                .unwrap()
        )
        .unwrap(),
        before
    );
    let receipt = completed_receipt_at(home.path(), &backup).unwrap().unwrap();
    let archive = archive_path(home.path(), backup.job_id.as_str()).unwrap();
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        b"real-private-n8n-sqlite-archive"
    );
    assert_eq!(
        hex::encode(sha2::Sha256::digest(std::fs::read(&archive).unwrap())),
        receipt.archive_sha256
    );
    assert_eq!(
        std::fs::metadata(archive).unwrap().len(),
        receipt.archive_bytes
    );
    assert!(!custody_path(home.path()).exists());
}

#[tokio::test]
async fn stopped_source_backup_has_no_stop_or_start_effect() {
    let (home, mut runner, state, _) = fixture().await;
    state.lock().unwrap().running = false;
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(backup.state, JobState::Ready);
    assert_eq!(calls(&state, "stop:"), 0);
    assert_eq!(calls(&state, "start:"), 0);
    assert_eq!(calls(&state, "archive:"), 1);
    assert!(!state.lock().unwrap().running);
    let receipt = completed_receipt_at(home.path(), &backup).unwrap().unwrap();
    assert!(!receipt.original_running_state && !receipt.restored_running_state);
}

#[tokio::test]
async fn copy_dispatch_crash_restores_source_without_second_copy_after_reopen() {
    let (home, mut runner, state, source) = fixture().await;
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let service = open_backup_service(home.path()).unwrap();
    let generation = next_generation(home.path()).unwrap();
    let queued = enqueue_backup(&service, &binding, &source, generation).unwrap();
    let _active = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let archive = ensure_private_backup_dir(home.path())
        .unwrap()
        .join(format!("{}.tar", queued.job_id));
    let custody = BackupCustody {
        schema_version: 1,
        phase: BackupPhase::CopyDispatched,
        backup_job_id: queued.job_id.as_str().into(),
        backup_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        generation,
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        volume: binding.volume.clone(),
        was_running: true,
        restoration_dispatched: false,
        archive_path: archive.to_string_lossy().into_owned(),
        archive_sha256: None,
        archive_bytes: None,
    };
    create_custody(home.path(), &custody).unwrap();
    state.lock().unwrap().running = false;
    drop(service);
    drop(runner);
    let mut reopened = Runner(state.clone());
    let failed = backup_managed_at_with(home.path(), &mut reopened)
        .await
        .unwrap();
    assert_eq!(calls(&state, "archive:"), 0);
    assert_eq!(calls(&state, "start:"), 1);
    assert!(state.lock().unwrap().running);
    assert_eq!(failed.job_id, queued.job_id);
    assert_eq!(failed.state, JobState::Failed);
    assert!(reject_pending_backup(home.path()).is_ok());
    let fresh = backup_managed_at_with(home.path(), &mut reopened)
        .await
        .unwrap();
    assert_eq!(fresh.state, JobState::Ready);
    assert_ne!(fresh.job_id, failed.job_id);
    assert_eq!(calls(&state, "archive:"), 1);
}

#[tokio::test]
async fn uncertain_stop_and_start_receipts_are_observed_once_then_complete_ready() {
    let (home, mut runner, state, _) = fixture().await;
    state.lock().unwrap().stop_error = true;
    let ready = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "stop:"), 1);
    assert_eq!(calls(&state, "archive:"), 1);
    assert_eq!(calls(&state, "start:"), 1);
    assert!(state.lock().unwrap().running);
    let (home, mut runner, state, _) = fixture().await;
    state.lock().unwrap().start_error = true;
    let ready = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "archive:"), 1);
    assert_eq!(calls(&state, "start:"), 1);
    assert!(state.lock().unwrap().running);
}

#[tokio::test]
async fn archive_receipt_error_restores_source_and_cannot_publish_ready() {
    let (home, mut runner, state, _) = fixture().await;
    state.lock().unwrap().archive = ArchiveResult::ErrorAfterEffect;
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert!(state.lock().unwrap().running);
    assert_eq!(calls(&state, "start:"), 1);
    assert_eq!(backup.state, JobState::Failed);
    assert_eq!(completed_receipt_at(home.path(), &backup).unwrap(), None);
    assert!(reject_pending_backup(home.path()).is_ok());
    let (home, mut runner, state, _) = fixture().await;
    state.lock().unwrap().archive = ArchiveResult::BadReceipt;
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert!(state.lock().unwrap().running);
    assert_eq!(calls(&state, "start:"), 1);
    assert_eq!(backup.state, JobState::Failed);
    assert_eq!(completed_receipt_at(home.path(), &backup).unwrap(), None);
}

#[tokio::test]
async fn completed_receipt_rehash_rejects_tampering_after_custody_retirement() {
    let (home, mut runner, _, _) = fixture().await;
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let path = receipt_path(home.path(), backup.job_id.as_str());
    let mut receipt: BackupReceiptView =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    receipt.archive_bytes += 1;
    std::fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_eq!(
        completed_receipt_at(home.path(), &backup),
        Err("n8n_backup_archive_mismatch")
    );
}

#[tokio::test]
async fn completed_receipt_rejects_foreign_source_and_stale_manifest_fields() {
    let (home, mut runner, _, _) = fixture().await;
    let backup = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let path = receipt_path(home.path(), backup.job_id.as_str());
    let original: BackupReceiptView =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut foreign = original.clone();
    foreign.source_install_job_id = "foreign-source".into();
    std::fs::write(&path, serde_json::to_vec(&foreign).unwrap()).unwrap();
    assert!(completed_receipt_at(home.path(), &backup).is_err());
    let mut stale = original;
    stale.backup_manifest_sha256 = "0".repeat(64);
    std::fs::write(path, serde_json::to_vec(&stale).unwrap()).unwrap();
    assert_eq!(
        completed_receipt_at(home.path(), &backup),
        Err("n8n_backup_receipt_mismatch")
    );
}

#[tokio::test]
async fn sequential_backups_retain_historical_first_receipt() {
    let (home, mut runner, state, _) = fixture().await;
    let first = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let first_receipt = completed_receipt_at(home.path(), &first).unwrap().unwrap();
    state.lock().unwrap().running = false;
    let second = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_ne!(first.job_id, second.job_id);
    assert_eq!(
        completed_receipt_at(home.path(), &first).unwrap().unwrap(),
        first_receipt
    );
    assert_eq!(
        completed_receipt_at(home.path(), &second)
            .unwrap()
            .unwrap()
            .generation,
        first_receipt.generation + 1
    );
    assert!(
        !completed_receipt_at(home.path(), &second)
            .unwrap()
            .unwrap()
            .original_running_state
    );
    let mut changed_binding = super::super::read_binding(home.path()).unwrap().unwrap();
    changed_binding.host_port = 6200;
    super::super::write_binding(home.path(), &changed_binding).unwrap();
    assert_eq!(
        completed_receipt_at(home.path(), &first).unwrap().unwrap(),
        first_receipt
    );
}

#[tokio::test]
async fn completed_custody_and_prepublished_receipt_finalize_ready_after_reopen() {
    let (home, mut runner, state, source) = fixture().await;
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let service = open_backup_service(home.path()).unwrap();
    let generation = next_generation(home.path()).unwrap();
    let queued = enqueue_backup(&service, &binding, &source, generation).unwrap();
    let active = service
        .start(&queued.job_id, queued.state_revision, STEPS[0])
        .unwrap();
    let archive_dir = ensure_private_backup_dir(home.path()).unwrap();
    let archive = archive_dir.join(format!("{}.tar", queued.job_id));
    let bytes = b"prepublished-before-ready";
    std::fs::write(&archive, bytes).unwrap();
    let digest = hex::encode(sha2::Sha256::digest(bytes));
    let custody = BackupCustody {
        schema_version: 1,
        phase: BackupPhase::Completed,
        backup_job_id: queued.job_id.as_str().into(),
        backup_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        generation,
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        volume: binding.volume.clone(),
        was_running: true,
        restoration_dispatched: true,
        archive_path: archive.to_string_lossy().into_owned(),
        archive_sha256: Some(digest.clone()),
        archive_bytes: Some(bytes.len() as u64),
    };
    create_custody(home.path(), &custody).unwrap();
    write_receipt(
        home.path(),
        &BackupReceiptView {
            schema_version: 1,
            backup_job_id: custody.backup_job_id.clone(),
            backup_manifest_sha256: custody.backup_manifest_sha256.clone(),
            source_install_job_id: custody.source_install_job_id.clone(),
            source_pinned_image: custody.image.clone(),
            source_container_id: custody.container_id.clone(),
            volume_name: custody.volume.clone(),
            generation,
            archive_sha256: digest,
            archive_bytes: bytes.len() as u64,
            original_running_state: true,
            restored_running_state: true,
        },
    )
    .unwrap();
    assert!(active.state.is_active());
    drop(service);
    drop(runner);
    let mut reopened = Runner(state.clone());
    let ready = backup_managed_at_with(home.path(), &mut reopened)
        .await
        .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(calls(&state, "archive:"), 0);
    assert!(!custody_path(home.path()).exists());
}

#[tokio::test]
async fn malformed_custody_and_final_destination_collision_leave_no_active_or_source_effect() {
    let (home, mut runner, state, _) = fixture().await;
    std::fs::write(custody_path(home.path()), b"malformed").unwrap();
    assert!(
        backup_managed_at_with(home.path(), &mut runner)
            .await
            .is_err()
    );
    assert!(
        super::super::managed_repair::repair_managed_at_with(
            home.path(),
            SecretString::from("backup-test-key"),
            &mut runner,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(calls(&state, "stop:"), 0);
    assert_eq!(calls(&state, "archive:"), 0);
    assert_eq!(calls(&state, "create"), 0);
    assert_eq!(calls(&state, "remove:"), 0);
    assert!(reject_pending_backup(home.path()).is_err());
    let (home, mut runner, state, source) = fixture().await;
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let service = open_backup_service(home.path()).unwrap();
    let generation = next_generation(home.path()).unwrap();
    let queued = enqueue_backup(&service, &binding, &source, generation).unwrap();
    let foreign = BackupCustody {
        schema_version: 1,
        phase: BackupPhase::IntentPersisted,
        backup_job_id: queued.job_id.as_str().into(),
        backup_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: "f".repeat(64),
        generation,
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        volume: binding.volume.clone(),
        was_running: false,
        restoration_dispatched: false,
        archive_path: archive_path(home.path(), queued.job_id.as_str())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        archive_sha256: None,
        archive_bytes: None,
    };
    create_custody(home.path(), &foreign).unwrap();
    drop(service);
    assert!(
        backup_managed_at_with(home.path(), &mut runner)
            .await
            .is_err()
    );
    assert_eq!(calls(&state, "stop:"), 0);
    assert_eq!(calls(&state, "archive:"), 0);
    assert_eq!(calls(&state, "create"), 0);
    assert_eq!(calls(&state, "remove:"), 0);
    let (home, mut runner, state, source) = fixture().await;
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    let service = open_backup_service(home.path()).unwrap();
    let generation = next_generation(home.path()).unwrap();
    let queued = enqueue_backup(&service, &binding, &source, generation).unwrap();
    let dir = ensure_private_backup_dir(home.path()).unwrap();
    let archive = dir.join(format!("{}.tar", queued.job_id));
    std::fs::write(&archive, b"foreign").unwrap();
    let custody = BackupCustody {
        schema_version: 1,
        phase: BackupPhase::IntentPersisted,
        backup_job_id: queued.job_id.as_str().into(),
        backup_manifest_sha256: queued.manifest_sha256.as_str().into(),
        source_install_job_id: source.job_id.as_str().into(),
        source_install_manifest_sha256: source.manifest_sha256.as_str().into(),
        generation,
        container_id: binding.container_id.clone().unwrap(),
        image: binding.image.clone(),
        volume: binding.volume.clone(),
        was_running: false,
        restoration_dispatched: false,
        archive_path: archive.to_string_lossy().into_owned(),
        archive_sha256: None,
        archive_bytes: None,
    };
    create_custody(home.path(), &custody).unwrap();
    drop(service);
    let failed = backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(calls(&state, "stop:"), 0);
    assert_eq!(calls(&state, "archive:"), 0);
    assert_eq!(calls(&state, "start:"), 0);
    assert_eq!(calls(&state, "create"), 0);
    assert_eq!(calls(&state, "remove:"), 0);
    assert!(!custody_path(home.path()).exists());
}
