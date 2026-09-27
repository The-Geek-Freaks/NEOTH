//! Stateful rollback coordinator regressions. The source chain comes from the
//! real managed Install -> Backup -> Restore test fixture; this fake owns only
//! rollback's exact rename/create/remove effects.
use super::*;
use crate::{
    integrations::{
        jobs::RestartValidator,
        n8n::{N8nApiProbe, N8nProbeError, N8nProbeReceipt},
        state::JobState,
    },
    secret::SecretString,
};
use sha2::Digest;
use std::sync::{Arc, Mutex};

fn receipt() -> super::super::ManagedCommandReceipt {
    super::super::ManagedCommandReceipt {
        succeeded: true,
        output_sha256: "a".repeat(64),
    }
}
#[derive(Clone, Copy, Default)]
enum CreateMode {
    #[default]
    Normal,
    LostId,
}
struct State {
    old: super::super::ObservedContainer,
    old_name: String,
    old_running: bool,
    restore_volume: super::super::ObservedVolume,
    new: Option<super::super::ObservedContainer>,
    new_running: bool,
    calls: Vec<String>,
    create: CreateMode,
    rename_error_after_effect: bool,
    foreign_live: bool,
    remove_error_after_effect: bool,
    restore_volume_removed: bool,
    next_create: u64,
}
struct Runner(Arc<Mutex<State>>);
impl Runner {
    fn calls(&self, prefix: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|x| x.starts_with(prefix))
            .count()
    }
}
fn named(s: &State, name: &str) -> Option<super::super::ObservedContainer> {
    if name == super::super::MANAGED_CONTAINER_NAME && s.foreign_live {
        let mut x = s.old.clone();
        x.id = "f".repeat(64);
        Some(x)
    } else if s.old_name == name {
        Some(s.old.clone())
    } else if name == super::super::MANAGED_CONTAINER_NAME {
        s.new.clone()
    } else {
        None
    }
}
#[async_trait::async_trait]
impl super::super::ManagedDockerRunner for Runner {
    async fn inspect_named(&mut self) -> Result<super::super::InspectOutcome, &'static str> {
        self.inspect_name(super::super::MANAGED_CONTAINER_NAME)
            .await
    }
    async fn inspect_name(
        &mut self,
        name: &str,
    ) -> Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("name:{name}"));
        Ok(named(&s, name)
            .map(super::super::InspectOutcome::Found)
            .unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn inspect_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("exact:{id}"));
        Ok(if s.old.id == id {
            super::super::InspectOutcome::Found(s.old.clone())
        } else {
            s.new
                .clone()
                .filter(|x| x.id == id)
                .map(super::super::InspectOutcome::Found)
                .unwrap_or(super::super::InspectOutcome::Absent)
        })
    }
    async fn running_exact(&mut self, id: &str) -> Result<bool, &'static str> {
        let s = self.0.lock().unwrap();
        Ok((s.old.id == id && s.old_running)
            || (s.new.as_ref().is_some_and(|x| x.id == id) && s.new_running))
    }
    async fn inspect_volume(
        &mut self,
        name: &str,
    ) -> Result<super::super::InspectVolumeOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        Ok((s.restore_volume.name == name && !s.restore_volume_removed)
            .then(|| super::super::InspectVolumeOutcome::Found(s.restore_volume.clone()))
            .unwrap_or(super::super::InspectVolumeOutcome::Absent))
    }
    async fn create(
        &mut self,
        argv: &[String],
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        Ok(self.create_with_exact_id(argv).await?.command)
    }
    async fn create_with_exact_id(
        &mut self,
        argv: &[String],
    ) -> Result<super::super::ManagedCreateReceipt, &'static str> {
        let job = argv
            .windows(2)
            .find(|x| x[0] == "--label" && x[1].starts_with("io.neoth.n8n-job="))
            .ok_or("job")?[1]
            .trim_start_matches("io.neoth.n8n-job=")
            .to_owned();
        let volume = argv.windows(2).find(|x| x[0] == "-v").ok_or("volume")?[1]
            .split(':')
            .next()
            .ok_or("volume")?
            .to_owned();
        let image = argv.last().cloned().ok_or("image")?;
        let mut s = self.0.lock().unwrap();
        s.calls.push("create".into());
        s.next_create += 1;
        let id = format!("{:064x}", s.next_create + 1);
        s.new = Some(super::super::ObservedContainer {
            id: id.clone(),
            image,
            managed: super::super::MANAGED_LABEL_VALUE.into(),
            job,
            host_ip: "127.0.0.1".into(),
            host_port: s.old.host_port,
            volume,
            mount_destination: "/home/node/.n8n".into(),
        });
        s.new_running = true;
        Ok(super::super::ManagedCreateReceipt {
            command: receipt(),
            container_id: matches!(s.create, CreateMode::Normal).then_some(id),
        })
    }
    async fn stop_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("stop:{id}"));
        if s.old.id == id {
            s.old_running = false
        } else if s.new.as_ref().is_some_and(|x| x.id == id) {
            s.new_running = false
        } else {
            return Err("stop");
        };
        Ok(receipt())
    }
    async fn start_exact(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("start:{id}"));
        if s.old.id == id {
            s.old_running = true
        } else if s.new.as_ref().is_some_and(|x| x.id == id) {
            s.new_running = true
        } else {
            return Err("start");
        };
        Ok(receipt())
    }
    async fn archive_exact_n8n_dir_to_private_file(
        &mut self,
        _: &str,
        path: &std::path::Path,
        _: u64,
    ) -> Result<super::super::ManagedArchiveReceipt, &'static str> {
        let bytes = b"rollback-backup";
        std::fs::write(path, bytes).map_err(|_| "archive")?;
        Ok(super::super::ManagedArchiveReceipt {
            archive_sha256: hex::encode(sha2::Sha256::digest(bytes)),
            archive_bytes: bytes.len() as u64,
        })
    }
    async fn rename_exact(
        &mut self,
        id: &str,
        dest: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if s.old.id != id {
            return Err("rename");
        };
        s.calls.push(format!("rename:{id}:{dest}"));
        s.old_name = dest.into();
        if s.rename_error_after_effect {
            return Err("lost");
        };
        Ok(receipt())
    }
    async fn remove(
        &mut self,
        id: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if !s.new.as_ref().is_some_and(|x| x.id == id) {
            return Err("remove");
        };
        s.calls.push(format!("remove:{id}"));
        s.new = None;
        s.new_running = false;
        if s.remove_error_after_effect {
            Err("remove-receipt-lost")
        } else {
            Ok(receipt())
        }
    }
    async fn remove_volume(
        &mut self,
        name: &str,
    ) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if s.restore_volume.name != name || s.restore_volume_removed {
            return Err("volume");
        }
        s.calls.push(format!("remove-volume:{name}"));
        s.restore_volume_removed = true;
        Ok(receipt())
    }
}
struct Probe {
    failures: Arc<Mutex<u8>>,
}
impl Probe {
    fn ok() -> Self {
        Self {
            failures: Arc::new(Mutex::new(0)),
        }
    }
    fn fail_once() -> Self {
        Self {
            failures: Arc::new(Mutex::new(1)),
        }
    }
}
#[async_trait::async_trait]
impl N8nApiProbe for Probe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> Result<(), N8nProbeError> {
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            Err(N8nProbeError::Transport)
        } else {
            Ok(())
        }
    }
    async fn authenticated_probe(
        &self,
        e: &crate::config::LoopbackHttpEndpoint,
        _: &SecretString,
    ) -> Result<N8nProbeReceipt, N8nProbeError> {
        crate::integrations::n8n::parse_workflows_response(
            e.clone(),
            200,
            br#"{"data":[],"nextCursor":null}"#,
        )
    }
}
async fn fixture() -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, JobId) {
    let (home, old, restore_volume, restore) =
        super::super::managed_restore::tests::rollback_fixture().await;
    let state = Arc::new(Mutex::new(State {
        old,
        old_name: super::super::MANAGED_CONTAINER_NAME.into(),
        old_running: true,
        restore_volume,
        new: None,
        new_running: false,
        calls: vec![],
        create: CreateMode::Normal,
        rename_error_after_effect: false,
        foreign_live: false,
        remove_error_after_effect: false,
        restore_volume_removed: false,
        next_create: 0,
    }));
    (home, Runner(state.clone()), state, restore.job_id)
}
struct Readiness {
    false_calls: Arc<Mutex<u32>>,
}
#[async_trait::async_trait]
impl super::super::ManagedReadiness for Readiness {
    async fn health(&self, _: u16) -> bool {
        let mut n = self.false_calls.lock().unwrap();
        if *n > 0 {
            *n -= 1;
            false
        } else {
            true
        }
    }
}

#[tokio::test]
async fn ready_success_keeps_same_old_id_and_reentry_has_no_effect() {
    let (home, mut runner, state, restore) = fixture().await;
    let old = state.lock().unwrap().old.id.clone();
    let before = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let ready = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    let endpoint = crate::config::LoopbackHttpEndpoint::parse(format!(
        "http://127.0.0.1:{}",
        state.lock().unwrap().old.host_port
    ))
    .unwrap();
    assert_eq!(
        ready
            .evidence_contract
            .as_ref()
            .unwrap()
            .authenticated_probe_sha256(),
        &super::super::expected_authenticated_probe_sha256(&endpoint)
    );
    let r = completed_receipt_at(home.path(), &ready).unwrap().unwrap();
    assert_eq!(r.retained_source_container_id, old);
    assert_eq!(state.lock().unwrap().old_name, r.retained_source_name);
    assert_eq!(runner.calls("rename:"), 1);
    assert_eq!(runner.calls("create"), 1);
    assert_ne!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        before
    );
    let calls = state.lock().unwrap().calls.len();
    let replay = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    assert_eq!(replay.job_id, ready.job_id);
    assert_eq!(state.lock().unwrap().calls.len(), calls);
    let path = receipt_path(home.path(), ready.job_id.as_str());
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["evidence_sha256"] = "0".repeat(64).into();
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        completed_receipt_at(home.path(), &ready),
        Err("n8n_rollback_receipt_mismatch")
    )
}
#[tokio::test]
async fn rollback_active_runtime_produces_backup_v2_bound_to_rollback() {
    let (home, mut runner, _, restore) = fixture().await;
    let rollback = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    let backup = super::super::managed_backup::backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    let receipt = super::super::managed_backup::completed_receipt_at(home.path(), &backup)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.schema_version, 2);
    assert_eq!(
        receipt.source_job_id.as_deref(),
        Some(rollback.job_id.as_str())
    );
    assert_eq!(
        receipt.source_manifest_sha256.as_deref(),
        Some(rollback.manifest_sha256.as_str())
    );
    assert_eq!(receipt.source_operation.as_deref(), Some("rollback"));
    let path = home
        .path()
        .join(format!("n8n-backup-{}.receipt.json", backup.job_id));
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["source_operation"] = "install".into();
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        super::super::managed_backup::completed_receipt_at(home.path(), &backup),
        Err("n8n_backup_receipt_mismatch")
    )
}
#[tokio::test]
async fn lost_create_id_holds_without_replay_or_adoption() {
    let (home, mut runner, state, restore) = fixture().await;
    state.lock().unwrap().create = CreateMode::LostId;
    assert!(
        rollback_managed_at_with(
            home.path(),
            &restore,
            SecretString::from("historical-key"),
            &mut runner,
            &Probe::ok()
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("create"), 1);
    assert_eq!(runner.calls("rename:"), 1);
    assert!(read(home.path()).unwrap().is_some());
    assert!(
        rollback_managed_at_with(
            home.path(),
            &restore,
            SecretString::from("historical-key"),
            &mut runner,
            &Probe::ok()
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("create"), 1)
}
#[tokio::test]
async fn rename_receipt_loss_is_observed_without_second_rename() {
    let (home, mut runner, state, restore) = fixture().await;
    state.lock().unwrap().rename_error_after_effect = true;
    let ready = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    assert_eq!(runner.calls("rename:"), 1)
}
#[tokio::test]
async fn foreign_identity_blocks_before_rename() {
    let (home, mut runner, state, restore) = fixture().await;
    state.lock().unwrap().foreign_live = true;
    assert!(
        rollback_managed_at_with(
            home.path(),
            &restore,
            SecretString::from("historical-key"),
            &mut runner,
            &Probe::ok()
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("rename:"), 0);
    assert_eq!(runner.calls("create"), 0)
}
#[tokio::test]
async fn known_publish_failure_restores_same_id_and_exact_binding() {
    let (home, mut runner, state, restore) = fixture().await;
    let old = state.lock().unwrap().old.id.clone();
    let before = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let failed = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::fail_once(),
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    let s = state.lock().unwrap();
    assert_eq!(s.old.id, old);
    assert_eq!(s.old_name, super::super::MANAGED_CONTAINER_NAME);
    assert!(s.old_running);
    assert!(s.new.is_none());
    drop(s);
    assert_eq!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(runner.calls("remove:"), 1)
}
#[tokio::test]
async fn failed_compensated_reentry_retires_only_custody() {
    let (home, mut runner, state, restore) = fixture().await;
    let raw = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let old = state.lock().unwrap().old.clone();
    let failed = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::fail_once(),
    )
    .await
    .unwrap();
    let restored = super::super::managed_restore::completed_receipt_at(
        home.path(),
        &IntegrationJobService::read_only_snapshot(home.path())
            .unwrap()
            .into_iter()
            .find(|job| job.job_id == restore)
            .unwrap(),
    )
    .unwrap()
    .unwrap();
    let c = Custody {
        schema_version: 1,
        phase: Phase::Compensated,
        rollback_job_id: failed.job_id.as_str().into(),
        rollback_manifest_sha256: failed.manifest_sha256.as_str().into(),
        restore_job_id: restored.restore_job_id,
        restore_manifest_sha256: restored.restore_manifest_sha256,
        backup_job_id: restored.backup_job_id,
        backup_manifest_sha256: restored.backup_manifest_sha256,
        image: restored.source_pinned_image,
        restore_volume: restored.restore_volume,
        old_container_id: old.id,
        old_image: old.image,
        old_volume: old.volume,
        host_port: old.host_port,
        old_was_running: true,
        retired_name: retired_container_name(failed.job_id.as_str()).unwrap(),
        original_binding_sha256: sha256(&raw),
        original_binding: raw,
        new_container_id: Some("2".repeat(64)),
    };
    create(home.path(), &c).unwrap();
    let calls = state.lock().unwrap().calls.len();
    let replay = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    assert_eq!(replay.job_id, failed.job_id);
    assert_eq!(replay.state, JobState::Failed);
    assert_eq!(state.lock().unwrap().calls.len(), calls);
    assert!(read(home.path()).unwrap().is_none())
}
#[tokio::test]
async fn remove_receipt_loss_is_observed_without_duplicate_compensation_remove() {
    let (home, mut runner, state, restore) = fixture().await;
    state.lock().unwrap().remove_error_after_effect = true;
    let failed = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::fail_once(),
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(runner.calls("remove:"), 1);
    assert!(state.lock().unwrap().new.is_none())
}
#[tokio::test(start_paused = true)]
async fn new_runtime_readiness_timeout_compensates_same_old_id_without_create_replay() {
    let (home, mut runner, state, restore) = fixture().await;
    let old = state.lock().unwrap().old.id.clone();
    let readiness = Readiness {
        false_calls: Arc::new(Mutex::new(225)),
    };
    let failed = rollback_managed_at_with_readiness(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
        &readiness,
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(state.lock().unwrap().old.id, old);
    assert!(state.lock().unwrap().old_running);
    assert!(state.lock().unwrap().new.is_none());
    assert_eq!(runner.calls("create"), 1);
    assert_eq!(runner.calls("remove:"), 1)
}
#[tokio::test]
async fn originally_stopped_source_stays_stopped_after_prepublication_failure() {
    let (home, mut runner, state, restore) = fixture().await;
    state.lock().unwrap().old_running = false;
    let failed = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::fail_once(),
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert!(!state.lock().unwrap().old_running);
    assert_eq!(runner.calls("start:"), 0);
    assert_eq!(runner.calls("stop:"), 0);
    assert!(state.lock().unwrap().new.is_none())
}
#[test]
fn restart_validator_holds_uncertain_dispatch() {
    let home = tempfile::tempdir().unwrap();
    let service = open(home.path()).unwrap();
    let m = sha256_parts(&["rollback-test"]);
    let job = service
        .enqueue(crate::integrations::jobs::EnqueueIntegrationJob {
            capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID)
                .unwrap(),
            operation: JobOperation::Rollback,
            release_version: "1.4.0".into(),
            manifest_sha256: m.clone(),
            evidence_contract: JobEvidenceContract::verified(
                m,
                sha256_parts(&["a"]),
                sha256_parts(&["b"]),
                sha256_parts(&STEPS),
            ),
            requested_by: JobRequester::Cli,
            total_steps: 4,
            bytes_total: None,
        })
        .unwrap()
        .job;
    let c = Custody {
        schema_version: 1,
        phase: Phase::RenameDispatched,
        rollback_job_id: job.job_id.as_str().into(),
        rollback_manifest_sha256: job.manifest_sha256.as_str().into(),
        restore_job_id: "018f0f02-2222-7222-8222-222222222222".into(),
        restore_manifest_sha256: "b".repeat(64),
        backup_job_id: "018f0f02-3333-7333-8333-333333333333".into(),
        backup_manifest_sha256: "c".repeat(64),
        image: format!("docker.io/n8nio/n8n@sha256:{}", "d".repeat(64)),
        restore_volume: "neoth_n8n_018f0f022222722282222222222222".into(),
        old_container_id: "e".repeat(64),
        old_image: format!("docker.io/n8nio/n8n@sha256:{}", "f".repeat(64)),
        old_volume: "neoth_n8n_data".into(),
        host_port: 5678,
        old_was_running: true,
        retired_name: retired_container_name(job.job_id.as_str()).unwrap(),
        original_binding_sha256: sha256(b"binding"),
        original_binding: b"binding".to_vec(),
        new_container_id: None,
    };
    create(home.path(), &c).unwrap();
    assert!(matches!(
        RollbackRestartValidator {
            home: home.path().to_owned()
        }
        .validate(&job),
        crate::integrations::state::RestartDecision::Hold { .. }
    ))
}

#[tokio::test]
async fn rollback_restore_volume_uninstall_reinstall_and_purge_preserve_retired_source() {
    let (home, mut runner, state, restore) = fixture().await;
    let rollback = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    let old = state.lock().unwrap().old.id.clone();
    let old_name = state.lock().unwrap().old_name.clone();
    let restore_volume = state.lock().unwrap().restore_volume.name.clone();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    assert_eq!(runner.calls(&format!("remove:{}", "2".repeat(64))), 1);
    assert_eq!(state.lock().unwrap().old.id, old);
    assert_eq!(state.lock().unwrap().old_name, old_name);
    assert!(!state.lock().unwrap().restore_volume_removed);
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let reinstalled = super::super::install_retained_at_with(
        home.path(),
        &uninstall.job_id,
        SecretString::from("historical-key"),
        &mut runner,
        &Readiness {
            false_calls: Arc::new(Mutex::new(0)),
        },
        &Probe::ok(),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_ne!(reinstalled.job_id, rollback.job_id);
    assert_eq!(
        state.lock().unwrap().new.as_ref().unwrap().volume,
        restore_volume
    );
    let first_reinstall_id = state.lock().unwrap().new.as_ref().unwrap().id.clone();
    assert_eq!(state.lock().unwrap().old.id, old);
    let uninstall_again =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let reinstalled_again = super::super::install_retained_at_with(
        home.path(),
        &uninstall_again.job_id,
        SecretString::from("historical-key"),
        &mut runner,
        &Readiness {
            false_calls: Arc::new(Mutex::new(0)),
        },
        &Probe::ok(),
        &mut cancel,
    )
    .await
    .unwrap();
    assert_ne!(reinstalled_again.job_id, reinstalled.job_id);
    let second_reinstall_id = state.lock().unwrap().new.as_ref().unwrap().id.clone();
    assert_ne!(second_reinstall_id, first_reinstall_id);
    assert_eq!(
        state.lock().unwrap().new.as_ref().unwrap().volume,
        restore_volume
    );
    assert_eq!(state.lock().unwrap().old.id, old);
    let uninstall_third =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let plan =
        super::super::super::managed_purge::prepare_purge_at(home.path(), &uninstall_third.job_id)
            .unwrap();
    assert_eq!(
        plan.confirmation,
        format!(
            "PURGE N8N RESTORE VOLUME {} {}",
            uninstall_third.job_id, restore_volume
        )
    );
    let before_wrong = state.lock().unwrap().calls.len();
    assert!(
        super::super::super::managed_purge::purge_retained_volume_at_with(
            home.path(),
            &uninstall_third.job_id,
            "PURGE N8N RESTORE VOLUME wrong",
            &mut runner,
        )
        .await
        .is_err()
    );
    assert_eq!(state.lock().unwrap().calls.len(), before_wrong);
    super::super::super::managed_purge::purge_retained_volume_at_with(
        home.path(),
        &uninstall_third.job_id,
        &plan.confirmation,
        &mut runner,
    )
    .await
    .unwrap();
    assert_eq!(runner.calls(&format!("remove-volume:{restore_volume}")), 1);
    assert_eq!(state.lock().unwrap().old.id, old);
    assert_eq!(state.lock().unwrap().old_name, old_name);
}

#[tokio::test]
async fn tampered_restore_volume_uninstall_receipt_has_no_reinstall_or_purge_effect() {
    let (home, mut runner, state, restore) = fixture().await;
    let _ = rollback_managed_at_with(
        home.path(),
        &restore,
        SecretString::from("historical-key"),
        &mut runner,
        &Probe::ok(),
    )
    .await
    .unwrap();
    let uninstall =
        super::super::managed_uninstall::uninstall_managed_at_with(home.path(), &mut runner)
            .await
            .unwrap();
    let path = home
        .path()
        .join(format!("n8n-uninstall-{}.receipt.json", uninstall.job_id));
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["rollback_restore"]["restore_volume"] = "neoth_n8n_foreign".into();
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    let before = state.lock().unwrap().calls.len();
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    assert!(
        super::super::install_retained_at_with(
            home.path(),
            &uninstall.job_id,
            SecretString::from("historical-key"),
            &mut runner,
            &Readiness {
                false_calls: Arc::new(Mutex::new(0))
            },
            &Probe::ok(),
            &mut cancel,
        )
        .await
        .is_err()
    );
    assert!(
        super::super::super::managed_purge::prepare_purge_at(home.path(), &uninstall.job_id)
            .is_err()
    );
    assert_eq!(state.lock().unwrap().calls.len(), before);
    assert!(!state.lock().unwrap().restore_volume_removed);
}
