//! Lifecycle regressions for isolated managed n8n restore custody.
//!
//! These use a real temporary job database and the production backup path.
//! The runner is deliberately stateful so assertions cover observed effects,
//! not coordinator implementation details.

use super::*;
use super::super::ManagedDockerRunner;
use crate::{
    installers::n8n::N8N_OCI_REFERENCE,
    integrations::{
        n8n::{
            managed_runtime::{
                managed_backup::{backup_managed_at_with, completed_verified_archive_at},
                managed_restore_candidate::{InspectRestoreCandidateOutcome, ObservedRestoreCandidate, RestoreCandidateContentReceipt, RestoreCandidateSpec},
            },
            N8nApiProbe, N8nProbeError, N8nProbeReceipt,
        },
        state::JobId,
    },
    secret::SecretString,
};
use sha2::Digest;
use std::{collections::BTreeMap, path::Path, sync::{Arc, Mutex}};

fn receipt() -> super::super::ManagedCommandReceipt {
    super::super::ManagedCommandReceipt { succeeded: true, output_sha256: "a".repeat(64) }
}
fn original(id: String, job: &str, volume: String) -> super::super::ObservedContainer {
    super::super::ObservedContainer {
        id, image: N8N_OCI_REFERENCE.into(), managed: super::super::MANAGED_LABEL_VALUE.into(),
        job: job.into(), host_ip: "127.0.0.1".into(), host_port: 5678, volume,
        mount_destination: "/home/node/.n8n".into(),
    }
}
fn content_receipt(workflow_count: u32, credential_count: u32, credential_decryption_proven: bool) -> RestoreCandidateContentReceipt {
    let canonical = format!(
        "{{\"workflow_count\":{workflow_count},\"credential_count\":{credential_count},\"credential_decryption_proven\":{credential_decryption_proven}}}"
    );
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"neoth-n8n-restore-content-v1\0");
    hasher.update(canonical.as_bytes());
    RestoreCandidateContentReceipt {
        workflow_count, credential_count, credential_decryption_proven,
        evidence_sha256: hex::encode(hasher.finalize()),
    }
}

#[derive(Clone, Copy, Default)]
enum Extract { #[default] Good, ReceiptMismatch, ErrorAfterEffect }
#[derive(Clone, Copy, Default)]
enum Content { #[default] Nonempty, Empty, Lost }
#[derive(Default)]
struct State {
    original: Option<super::super::ObservedContainer>, original_running: bool,
    volume: Option<super::super::ObservedVolume>, candidate: Option<ObservedRestoreCandidate>,
    calls: Vec<String>, next: u64, extract: Extract, content: Content,
    candidate_identity_wrong: bool, remove_error_after_effect: bool,
}
struct Runner(Arc<Mutex<State>>);
impl Runner {
    fn calls(&self, prefix: &str) -> usize { self.0.lock().unwrap().calls.iter().filter(|x| x.starts_with(prefix)).count() }
}

#[async_trait::async_trait]
impl super::super::ManagedDockerRunner for Runner {
    async fn inspect_named(&mut self) -> Result<super::super::InspectOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(s.original.clone().map(super::super::InspectOutcome::Found).unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn inspect_exact(&mut self, id: &str) -> Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("live-inspect:{id}"));
        Ok(s.original.clone().filter(|x| x.id == id).map(super::super::InspectOutcome::Found).unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn running_exact(&mut self, id: &str) -> Result<bool, &'static str> {
        let s = self.0.lock().unwrap(); Ok(s.original.as_ref().is_some_and(|x| x.id == id) && s.original_running)
    }
    async fn inspect_volume(&mut self, name: &str) -> Result<super::super::InspectVolumeOutcome, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("volume-inspect:{name}"));
        Ok(s.volume.clone().filter(|x| x.name == name).map(super::super::InspectVolumeOutcome::Found).unwrap_or(super::super::InspectVolumeOutcome::Absent))
    }
    async fn remove_volume(&mut self, name: &str) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("volume-remove:{name}"));
        if s.volume.as_ref().is_some_and(|x| x.name == name) { s.volume = None; }
        Ok(receipt())
    }
    async fn create(&mut self, argv: &[String]) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let job = argv.windows(2).find(|x| x[0] == "--label" && x[1].starts_with("io.neoth.n8n-job=")).ok_or("missing_job")?[1].trim_start_matches("io.neoth.n8n-job=").to_owned();
        let volume = argv.windows(2).find(|x| x[0] == "-v").and_then(|x| x[1].split(':').next()).ok_or("missing_volume")?.to_owned();
        let mut s = self.0.lock().unwrap(); s.calls.push("live-create".into()); s.next += 1;
        s.original = Some(original(format!("{:064x}", s.next), &job, volume)); s.original_running = true; Ok(receipt())
    }
    async fn create_with_exact_id(&mut self, argv: &[String]) -> Result<super::super::ManagedCreateReceipt, &'static str> {
        self.create(argv).await?;
        Ok(super::super::ManagedCreateReceipt { command: receipt(), container_id: self.0.lock().unwrap().original.as_ref().map(|x| x.id.clone()) })
    }
    async fn start_exact(&mut self, id: &str) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if s.original.as_ref().is_some_and(|x| x.id == id) { s.calls.push(format!("live-start:{id}")); s.original_running = true; return Ok(receipt()); }
        if s.candidate.as_ref().is_some_and(|x| x.id == id) {
            s.calls.push(format!("candidate-start:{id}"));
            s.candidate.as_mut().expect("identity checked").running = true;
            return Ok(receipt());
        }
        Err("wrong_start")
    }
    async fn stop_exact(&mut self, id: &str) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if s.original.as_ref().is_some_and(|x| x.id == id) { s.calls.push(format!("live-stop:{id}")); s.original_running = false; return Ok(receipt()); }
        Err("wrong_stop")
    }
    async fn archive_exact_n8n_dir_to_private_file(&mut self, _: &str, destination: &Path, _: u64) -> Result<super::super::ManagedArchiveReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push("backup-archive".into()); drop(s);
        let bytes = b"ready-backup-private-archive"; std::fs::write(destination, bytes).map_err(|_| "archive_write")?;
        Ok(super::super::ManagedArchiveReceipt { archive_sha256: hex::encode(sha2::Sha256::digest(bytes)), archive_bytes: bytes.len() as u64 })
    }
    async fn create_restore_volume_exact(&mut self, job: &JobId) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut labels = BTreeMap::new(); labels.insert(super::super::MANAGED_LABEL_KEY.into(), super::super::MANAGED_LABEL_VALUE.into()); labels.insert("io.neoth.n8n-restore".into(), job.as_str().into()); labels.insert("io.neoth.n8n-restore-schema".into(), "1".into());
        let mut s = self.0.lock().unwrap(); s.calls.push("restore-volume-create".into()); s.volume = Some(super::super::ObservedVolume { name: super::super::managed_restore_candidate::restore_volume_name(job), labels }); Ok(receipt())
    }
    async fn create_restore_candidate_exact(&mut self, spec: RestoreCandidateSpec<'_>) -> Result<super::super::ManagedCreateReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push("candidate-create".into()); s.next += 1;
        let id = format!("{:064x}", s.next); let volume = super::super::managed_restore_candidate::restore_volume_name(spec.restore_job_id);
        let restore_job_id = if s.candidate_identity_wrong { "123e4567-e89b-12d3-a456-426614174001".into() } else { spec.restore_job_id.as_str().into() };
        s.candidate = Some(ObservedRestoreCandidate { id: id.clone(), running: false, image: spec.image.into(), restore_job_id, volume, volume_source: "/private/volume".into(), network_mode: "none".into(), tmpfs_options: "rw,noexec,nosuid,nodev,size=67108864".into() });
        Ok(super::super::ManagedCreateReceipt { command: receipt(), container_id: Some(id) })
    }
    async fn inspect_restore_candidate_exact(&mut self, id: &str) -> Result<InspectRestoreCandidateOutcome, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("candidate-inspect:{id}")); Ok(s.candidate.clone().filter(|x| x.id == id).map(InspectRestoreCandidateOutcome::Found).unwrap_or(InspectRestoreCandidateOutcome::Absent))
    }
    async fn extract_private_archive_to_exact_container(&mut self, _: &Path, digest: &str, bytes: u64, id: &str) -> Result<super::super::ManagedArchiveReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("extract:{id}"));
        match s.extract { Extract::Good => Ok(super::super::ManagedArchiveReceipt { archive_sha256: digest.into(), archive_bytes: bytes }), Extract::ReceiptMismatch => Ok(super::super::ManagedArchiveReceipt { archive_sha256: "0".repeat(64), archive_bytes: bytes + 1 }), Extract::ErrorAfterEffect => Err("extract_receipt_lost") }
    }
    async fn validate_restore_candidate_content_exact(&mut self, id: &str) -> Result<RestoreCandidateContentReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("content:{id}")); match s.content {
            Content::Nonempty => Ok(content_receipt(2, 1, true)),
            Content::Empty => Ok(content_receipt(2, 0, false)),
            Content::Lost => Err("content_receipt_lost"),
        }
    }
    async fn remove(&mut self, id: &str) -> Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap(); s.calls.push(format!("candidate-remove:{id}"));
        if s.candidate.as_ref().is_some_and(|x| x.id == id) { s.candidate = None; if s.remove_error_after_effect { return Err("remove_receipt_lost"); } }
        Ok(receipt())
    }
}

struct Ready;
#[async_trait::async_trait] impl super::super::ManagedReadiness for Ready { async fn health(&self, _: u16) -> bool { true } }
struct Probe;
#[async_trait::async_trait] impl N8nApiProbe for Probe {
    async fn negative_control(&self, _: &crate::config::LoopbackHttpEndpoint) -> Result<(), N8nProbeError> { Ok(()) }
    async fn authenticated_probe(&self, endpoint: &crate::config::LoopbackHttpEndpoint, _: &SecretString) -> Result<N8nProbeReceipt, N8nProbeError> { crate::integrations::n8n::parse_workflows_response(endpoint.clone(), 200, br#"{"data":[],"nextCursor":null}"#) }
}
fn initialize(home: &Path) { std::fs::write(home.join("freedom.yaml"), serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap()).unwrap(); }
async fn fixture() -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, IntegrationJob) {
    let home = tempfile::tempdir().unwrap(); initialize(home.path()); let state = Arc::new(Mutex::new(State::default())); let mut runner = Runner(state.clone());
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    super::super::install_managed_at_with(home.path(), super::super::ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(), SecretString::from("restore-test-key"), &mut runner, &Ready, &Probe, &mut cancel).await.unwrap();
    let backup = backup_managed_at_with(home.path(), &mut runner).await.unwrap();
    state.lock().unwrap().calls.clear(); (home, runner, state, backup)
}

#[tokio::test]
async fn ready_backup_restores_nonempty_content_to_exact_candidate_then_retires_it() {
    let (home, mut runner, state, backup) = fixture().await;
    let restored = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(restored.state, JobState::Ready);
    let receipt = completed_receipt_at(home.path(), &restored).unwrap().unwrap();
    assert!(receipt.candidate_only); assert_eq!(receipt.workflow_count, 2); assert_eq!(receipt.credential_count, 1); assert!(receipt.credential_decryption_proven);
    assert_eq!(runner.calls("restore-volume-create"), 1); assert_eq!(runner.calls("candidate-create"), 1); assert_eq!(runner.calls("extract:"), 1); assert_eq!(runner.calls("candidate-remove:"), 1);
    assert!(state.lock().unwrap().candidate.is_none()); assert!(state.lock().unwrap().volume.is_some());
    assert_eq!(runner.calls("live-inspect:"), 0, "restore must never select a live managed container"); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn zero_credentials_never_claims_decryption_even_when_restore_is_ready() {
    let (home, mut runner, _, backup) = fixture().await; runner.0.lock().unwrap().content = Content::Empty;
    let restored = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    let receipt = completed_receipt_at(home.path(), &restored).unwrap().unwrap();
    assert_eq!(restored.state, JobState::Ready); assert_eq!(receipt.credential_count, 0); assert!(!receipt.credential_decryption_proven);
}

#[tokio::test]
async fn extract_digest_receipt_mismatch_fails_and_removes_only_owned_candidate_and_volume() {
    let (home, mut runner, state, backup) = fixture().await; runner.0.lock().unwrap().extract = Extract::ReceiptMismatch;
    let failed = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(failed.state, JobState::Failed); assert_eq!(runner.calls("extract:"), 1); assert_eq!(runner.calls("candidate-remove:"), 1); assert_eq!(runner.calls("volume-remove:"), 1);
    assert!(state.lock().unwrap().candidate.is_none()); assert!(state.lock().unwrap().volume.is_none()); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn wrong_candidate_identity_stops_before_extract_or_removal() {
    let (home, mut runner, _, backup) = fixture().await; runner.0.lock().unwrap().candidate_identity_wrong = true;
    assert!(restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.is_err());
    assert_eq!(runner.calls("extract:"), 0); assert_eq!(runner.calls("candidate-remove:"), 0); assert_eq!(runner.calls("volume-remove:"), 0); assert!(sidecar(home.path()).exists());
}

#[tokio::test]
async fn lost_extract_receipt_is_not_replayed_and_cleanup_retires_custody() {
    let (home, mut runner, state, backup) = fixture().await; runner.0.lock().unwrap().extract = Extract::ErrorAfterEffect;
    let failed = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(failed.state, JobState::Failed); assert_eq!(runner.calls("extract:"), 1); assert_eq!(runner.calls("candidate-remove:"), 1); assert_eq!(runner.calls("volume-remove:"), 1);
    assert!(state.lock().unwrap().candidate.is_none()); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn lost_content_receipt_compensates_without_replaying_extract() {
    let (home, mut runner, state, backup) = fixture().await; runner.0.lock().unwrap().content = Content::Lost;
    let failed = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(failed.state, JobState::Failed); assert_eq!(runner.calls("extract:"), 1); assert_eq!(runner.calls("content:"), 1); assert_eq!(runner.calls("candidate-remove:"), 1); assert_eq!(runner.calls("volume-remove:"), 1);
    assert!(state.lock().unwrap().candidate.is_none()); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn remove_receipt_loss_is_observed_once_without_second_dispatch() {
    let (home, mut runner, state, backup) = fixture().await; runner.0.lock().unwrap().remove_error_after_effect = true;
    let ready = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(ready.state, JobState::Ready); assert_eq!(runner.calls("candidate-remove:"), 1); assert!(state.lock().unwrap().candidate.is_none());
}

#[tokio::test]
async fn ready_custody_reentry_does_not_enqueue_or_repeat_external_effects() {
    let (home, mut runner, _, backup) = fixture().await;
    let first = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap();
    let receipt = completed_receipt_at(home.path(), &first).unwrap().unwrap();
    let custody = new_custody(&verified, &first);
    let completed = Custody {
        phase: Phase::Completed, candidate_id: Some(receipt.candidate_container_id),
        content: Some(content_receipt(receipt.workflow_count, receipt.credential_count, receipt.credential_decryption_proven)),
        ..custody
    };
    create(home.path(), &completed).unwrap();
    let before = runner.0.lock().unwrap().calls.len(); let replay = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(replay.job_id, first.job_id); assert_eq!(replay.state, JobState::Ready); assert_eq!(runner.0.lock().unwrap().calls.len(), before); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn persisted_extract_dispatch_recovers_by_cleanup_without_a_second_extract() {
    let (home, mut runner, state, backup) = fixture().await;
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap();
    let service = open(home.path()).unwrap();
    let queued = service.enqueue(crate::integrations::jobs::EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(), operation: JobOperation::Restore, release_version: "1.4.0".into(), manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified), requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None }).unwrap().job;
    let active = service.start(&queued.job_id, queued.state_revision, STEPS[0]).unwrap();
    let active = service.begin_validation(&active.job_id, active.state_revision, STEPS[0]).unwrap();
    let _active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[0]).unwrap();
    runner.create_restore_volume_exact(&queued.job_id).await.unwrap();
    let candidate = runner.create_restore_candidate_exact(RestoreCandidateSpec { restore_job_id: &queued.job_id, image: &verified.receipt.source_pinned_image }).await.unwrap();
    let custody = Custody { phase: Phase::ExtractDispatched, candidate_id: candidate.container_id, ..new_custody(&verified, &queued) };
    create(home.path(), &custody).unwrap(); drop(service); state.lock().unwrap().calls.clear();
    let failed = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    assert_eq!(failed.state, JobState::Failed); assert_eq!(runner.calls("extract:"), 0); assert_eq!(runner.calls("candidate-create"), 0);
    assert_eq!(runner.calls("candidate-remove:"), 1); assert_eq!(runner.calls("volume-remove:"), 1);
    assert!(state.lock().unwrap().candidate.is_none()); assert!(!sidecar(home.path()).exists());
}

#[tokio::test]
async fn candidate_dispatch_without_exact_id_holds_recovery_without_name_discovery() {
    let (home, mut runner, _, backup) = fixture().await;
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap();
    let service = open(home.path()).unwrap();
    let queued = service.enqueue(crate::integrations::jobs::EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(), operation: JobOperation::Restore, release_version: "1.4.0".into(), manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified), requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None }).unwrap().job;
    let active = service.start(&queued.job_id, queued.state_revision, STEPS[0]).unwrap();
    let active = service.begin_validation(&active.job_id, active.state_revision, STEPS[0]).unwrap();
    let _active = service.begin_configuration(&active.job_id, active.state_revision, STEPS[0]).unwrap();
    let custody = Custody { phase: Phase::CandidateDispatched, ..new_custody(&verified, &queued) };
    create(home.path(), &custody).unwrap(); drop(service);
    assert!(restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.is_err());
    assert_eq!(runner.calls("candidate-inspect:"), 0); assert_eq!(runner.calls("candidate-create"), 0); assert_eq!(runner.calls("candidate-remove:"), 0);
    assert!(sidecar(home.path()).exists());
}

#[tokio::test]
async fn custody_bound_to_one_backup_rejects_a_different_requested_backup() {
    let (home, mut runner, _, backup) = fixture().await;
    let second = backup_managed_at_with(home.path(), &mut runner).await.unwrap();
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap(); let service = open(home.path()).unwrap();
    let queued = service.enqueue(crate::integrations::jobs::EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(), operation: JobOperation::Restore, release_version: "1.4.0".into(), manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified), requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None }).unwrap().job;
    create(home.path(), &new_custody(&verified, &queued)).unwrap(); drop(service);
    assert!(restore_managed_at_with(home.path(), &second.job_id, &mut runner).await.is_err()); assert_eq!(runner.calls("restore-volume-create"), 0);
}

#[tokio::test]
async fn corrupted_custody_and_completion_receipt_are_rejected_before_new_effects() {
    let (home, mut runner, _, backup) = fixture().await; std::fs::write(sidecar(home.path()), b"not-json").unwrap();
    assert!(restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.is_err()); assert_eq!(runner.calls("restore-volume-create"), 0);
    std::fs::remove_file(sidecar(home.path())).unwrap(); let ready = restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.unwrap();
    let path = receipt_path(home.path(), ready.job_id.as_str()); let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(); value["candidate_container_id"] = "not-an-id".into(); std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(completed_receipt_at(home.path(), &ready), Err("n8n_restore_receipt_mismatch"));
}

#[tokio::test]
async fn custody_manifest_tampering_is_rejected_before_candidate_creation() {
    let (home, mut runner, _, backup) = fixture().await;
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap();
    let service = open(home.path()).unwrap();
    let queued = service.enqueue(crate::integrations::jobs::EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(), operation: JobOperation::Restore, release_version: "1.4.0".into(), manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified), requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None }).unwrap().job;
    let tampered = Custody { backup_manifest_sha256: "f".repeat(64), ..new_custody(&verified, &queued) }; create(home.path(), &tampered).unwrap(); drop(service);
    assert!(restore_managed_at_with(home.path(), &backup.job_id, &mut runner).await.is_err());
    assert_eq!(runner.calls("restore-volume-create"), 0); assert_eq!(runner.calls("candidate-create"), 0);
}

#[tokio::test]
async fn pending_restore_custody_fences_backup_before_it_can_stop_or_archive_live_state() {
    let (home, mut runner, _, backup) = fixture().await;
    let verified = completed_verified_archive_at(home.path(), &backup).unwrap().unwrap();
    let service = open(home.path()).unwrap();
    let queued = service.enqueue(crate::integrations::jobs::EnqueueIntegrationJob { capability_id: crate::integrations::catalog::CapabilityId::parse(N8N_CAPABILITY_ID).unwrap(), operation: JobOperation::Restore, release_version: "1.4.0".into(), manifest_sha256: manifest(&verified), evidence_contract: contract(manifest(&verified), &verified), requested_by: JobRequester::Cli, total_steps: STEPS.len() as u32, bytes_total: None }).unwrap().job;
    create(home.path(), &new_custody(&verified, &queued)).unwrap(); drop(service);
    assert!(backup_managed_at_with(home.path(), &mut runner).await.is_err());
    assert_eq!(runner.calls("live-stop:"), 0); assert_eq!(runner.calls("backup-archive"), 0);
}
