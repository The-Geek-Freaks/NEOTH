//! Behavioural regressions for the managed Update custody transaction.
//!
//! The fixture starts with the real Install coordinator and calls the real
//! Update coordinator with checked-in OCI registry fixtures.

use super::*;
use crate::{
    installers::n8n::N8N_OCI_REFERENCE,
    integrations::n8n::{
        N8nApiProbe, N8nProbeError, N8nProbeReceipt,
        managed_runtime::{
            managed_update_candidate::{
                InspectUpdateSeedOutcome, InspectUpdateServerCandidateOutcome, ObservedUpdateSeed,
                ObservedUpdateServerCandidate, UpdateSeedSpec, UpdateServerCandidateSpec,
                UpdateVolumeSpec,
            },
            managed_update_content::UpdateContentFingerprint,
        },
        managed_update_target::{
            DockerImageObservation, RegistryObject, RegistryTargetReader, UpdateTargetDockerRunner,
        },
    },
    secret::SecretString,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use sha2::Digest;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

fn receipt() -> super::super::ManagedCommandReceipt {
    super::super::ManagedCommandReceipt {
        succeeded: true,
        output_sha256: "a".repeat(64),
    }
}
fn id(n: u64) -> String {
    format!("{n:064x}")
}
fn fingerprint() -> UpdateContentFingerprint {
    UpdateContentFingerprint {
        workflow_count: 2,
        credential_count: 1,
        content_sha256: "b".repeat(64),
    }
}

#[derive(Default)]
struct State {
    source: Option<super::super::ObservedContainer>,
    source_name: String,
    source_running: bool,
    live: Option<super::super::ObservedContainer>,
    live_running: bool,
    volumes: BTreeMap<String, super::super::ObservedVolume>,
    seed: Option<ObservedUpdateSeed>,
    candidate: Option<ObservedUpdateServerCandidate>,
    calls: Vec<String>,
    next: u64,
    content_mismatch: bool,
    archive_receipt_lost: bool,
    extract_receipt_lost: bool,
    lost_candidate_id: bool,
    candidate_remove_unknown: bool,
    candidate_remove_dispatched: bool,
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
fn observed(
    container_id: String,
    image: String,
    job: String,
    port: u16,
    volume: String,
) -> super::super::ObservedContainer {
    super::super::ObservedContainer {
        id: container_id,
        image,
        managed: super::super::MANAGED_LABEL_VALUE.into(),
        job,
        host_ip: "127.0.0.1".into(),
        host_port: port,
        volume,
        mount_destination: "/home/node/.n8n".into(),
    }
}
fn named(s: &State, name: &str) -> Option<super::super::ObservedContainer> {
    if s.source_name == name {
        s.source.clone()
    } else if name == super::super::MANAGED_CONTAINER_NAME {
        s.live.clone()
    } else {
        None
    }
}

#[async_trait]
impl super::super::ManagedDockerRunner for Runner {
    async fn inspect_named(
        &mut self,
    ) -> std::result::Result<super::super::InspectOutcome, &'static str> {
        self.inspect_name(super::super::MANAGED_CONTAINER_NAME)
            .await
    }
    async fn inspect_name(
        &mut self,
        name: &str,
    ) -> std::result::Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("name:{name}"));
        Ok(named(&s, name)
            .map(super::super::InspectOutcome::Found)
            .unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn inspect_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<super::super::InspectOutcome, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("exact:{wanted}"));
        Ok(s.source
            .clone()
            .filter(|x| x.id == wanted)
            .or_else(|| s.live.clone().filter(|x| x.id == wanted))
            .map(super::super::InspectOutcome::Found)
            .unwrap_or(super::super::InspectOutcome::Absent))
    }
    async fn running_exact(&mut self, wanted: &str) -> std::result::Result<bool, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(
            s.source.as_ref().is_some_and(|x| x.id == wanted) && s.source_running
                || s.live.as_ref().is_some_and(|x| x.id == wanted) && s.live_running
                || s.seed.as_ref().is_some_and(|x| x.id == wanted && x.running)
                || s.candidate
                    .as_ref()
                    .is_some_and(|x| x.id == wanted && x.running),
        )
    }
    async fn inspect_volume(
        &mut self,
        name: &str,
    ) -> std::result::Result<super::super::InspectVolumeOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        Ok(s.volumes
            .get(name)
            .cloned()
            .map(super::super::InspectVolumeOutcome::Found)
            .unwrap_or(super::super::InspectVolumeOutcome::Absent))
    }
    async fn create(
        &mut self,
        argv: &[String],
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
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
        s.next += 1;
        let container = observed(id(s.next), image, job, 5678, volume.clone());
        if s.source.is_none() {
            s.source_name = super::super::MANAGED_CONTAINER_NAME.into();
            s.source = Some(container);
            s.source_running = true;
            s.volumes.insert(
                volume.clone(),
                super::super::ObservedVolume {
                    name: volume,
                    labels: BTreeMap::new(),
                },
            );
        } else {
            s.calls.push("live-create".into());
            s.live = Some(container);
            s.live_running = true;
        }
        Ok(receipt())
    }
    async fn create_with_exact_id(
        &mut self,
        argv: &[String],
    ) -> std::result::Result<super::super::ManagedCreateReceipt, &'static str> {
        self.create(argv).await?;
        Ok(super::super::ManagedCreateReceipt {
            command: receipt(),
            container_id: self.0.lock().unwrap().live.as_ref().map(|x| x.id.clone()),
        })
    }
    async fn stop_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("stop:{wanted}"));
        if s.source.as_ref().is_some_and(|x| x.id == wanted) {
            s.source_running = false
        } else if s.live.as_ref().is_some_and(|x| x.id == wanted) {
            s.live_running = false
        } else {
            return Err("stop");
        };
        Ok(receipt())
    }
    async fn start_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("start:{wanted}"));
        if s.source.as_ref().is_some_and(|x| x.id == wanted) {
            s.source_running = true
        } else if s.live.as_ref().is_some_and(|x| x.id == wanted) {
            s.live_running = true
        } else if let Some(x) = s.seed.as_mut().filter(|x| x.id == wanted) {
            x.running = true
        } else if let Some(x) = s.candidate.as_mut().filter(|x| x.id == wanted) {
            x.running = true
        } else {
            return Err("start");
        };
        Ok(receipt())
    }
    async fn rename_exact(
        &mut self,
        wanted: &str,
        dest: &str,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        if s.source.as_ref().is_some_and(|x| x.id == wanted) {
            s.calls.push(format!("rename:{wanted}:{dest}"));
            s.source_name = dest.into();
            Ok(receipt())
        } else {
            Err("rename")
        }
    }
    async fn archive_exact_n8n_dir_to_private_file(
        &mut self,
        wanted: &str,
        path: &Path,
        _: u64,
    ) -> std::result::Result<super::super::ManagedArchiveReceipt, &'static str> {
        let lost = {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("archive:{wanted}"));
            s.archive_receipt_lost
        };
        let bytes = b"private-source-archive";
        std::fs::write(path, bytes).map_err(|_| "archive")?;
        if lost {
            return Err("archive-receipt-lost");
        }
        Ok(super::super::ManagedArchiveReceipt {
            archive_sha256: hex::encode(sha2::Sha256::digest(bytes)),
            archive_bytes: bytes.len() as u64,
        })
    }
    async fn extract_private_archive_to_exact_container(
        &mut self,
        _: &Path,
        digest: &str,
        bytes: u64,
        wanted: &str,
    ) -> std::result::Result<super::super::ManagedArchiveReceipt, &'static str> {
        let lost = {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("extract:{wanted}"));
            s.extract_receipt_lost
        };
        if lost {
            return Err("extract-receipt-lost");
        }
        Ok(super::super::ManagedArchiveReceipt {
            archive_sha256: digest.into(),
            archive_bytes: bytes,
        })
    }
    async fn create_update_volume_exact(
        &mut self,
        spec: UpdateVolumeSpec<'_>,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut labels = BTreeMap::new();
        labels.insert(
            super::super::MANAGED_LABEL_KEY.into(),
            super::super::MANAGED_LABEL_VALUE.into(),
        );
        labels.insert(
            "io.neoth.n8n-update".into(),
            spec.update_job_id.as_str().into(),
        );
        labels.insert("io.neoth.n8n-update-schema".into(), "1".into());
        let mut s = self.0.lock().unwrap();
        let name = super::super::managed_update_candidate::update_volume_name(spec.update_job_id);
        s.calls.push("volume-create".into());
        s.volumes
            .insert(name.clone(), super::super::ObservedVolume { name, labels });
        Ok(receipt())
    }
    async fn inspect_update_volume_exact(
        &mut self,
        job: &crate::integrations::state::JobId,
    ) -> std::result::Result<super::super::InspectVolumeOutcome, &'static str> {
        self.inspect_volume(&super::super::managed_update_candidate::update_volume_name(
            job,
        ))
        .await
    }
    async fn remove_volume(
        &mut self,
        name: &str,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("remove-volume:{name}"));
        if s.volumes.remove(name).is_some() {
            Ok(receipt())
        } else {
            Err("missing-volume")
        }
    }
    async fn create_update_seed_exact(
        &mut self,
        spec: UpdateSeedSpec<'_>,
    ) -> std::result::Result<super::super::ManagedCreateReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.next += 1;
        let x = ObservedUpdateSeed {
            id: id(s.next),
            running: false,
            image: spec.image.into(),
            update_job_id: spec.update_job_id.as_str().into(),
            volume: spec.volume.into(),
            volume_source: "/private/update".into(),
        };
        s.calls.push("seed-create".into());
        let container_id = Some(x.id.clone());
        s.seed = Some(x);
        Ok(super::super::ManagedCreateReceipt {
            command: receipt(),
            container_id,
        })
    }
    async fn inspect_update_seed_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<InspectUpdateSeedOutcome, &'static str> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .seed
            .clone()
            .filter(|x| x.id == wanted)
            .map(InspectUpdateSeedOutcome::Found)
            .unwrap_or(InspectUpdateSeedOutcome::Absent))
    }
    async fn create_update_server_candidate_exact(
        &mut self,
        spec: UpdateServerCandidateSpec<'_>,
    ) -> std::result::Result<super::super::ManagedCreateReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push("candidate-create".into());
        s.next += 1;
        let x = ObservedUpdateServerCandidate {
            id: id(s.next),
            running: false,
            image: spec.image.into(),
            update_job_id: spec.update_job_id.as_str().into(),
            volume: spec.volume.into(),
            volume_source: "/private/update".into(),
        };
        let result = (!s.lost_candidate_id).then(|| x.id.clone());
        s.candidate = Some(x);
        Ok(super::super::ManagedCreateReceipt {
            command: receipt(),
            container_id: result,
        })
    }
    async fn inspect_update_server_candidate_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<InspectUpdateServerCandidateOutcome, &'static str> {
        let s = self.0.lock().unwrap();
        if s.candidate_remove_unknown && s.candidate_remove_dispatched {
            return Ok(InspectUpdateServerCandidateOutcome::Unknown);
        }
        Ok(s.candidate
            .clone()
            .filter(|x| x.id == wanted)
            .map(InspectUpdateServerCandidateOutcome::Found)
            .unwrap_or(InspectUpdateServerCandidateOutcome::Absent))
    }
    async fn fingerprint_update_candidate_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<UpdateContentFingerprint, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("fingerprint:{wanted}"));
        let f = fingerprint();
        if s.candidate.as_ref().is_some_and(|x| x.id == wanted) && s.content_mismatch {
            Ok(UpdateContentFingerprint {
                content_sha256: "c".repeat(64),
                ..f
            })
        } else {
            Ok(f)
        }
    }
    async fn update_candidate_ready_exact(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<bool, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("candidate-ready:{wanted}"));
        Ok(s.candidate
            .as_ref()
            .is_some_and(|x| x.id == wanted && x.running))
    }
    async fn remove(
        &mut self,
        wanted: &str,
    ) -> std::result::Result<super::super::ManagedCommandReceipt, &'static str> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(format!("remove:{wanted}"));
        if s.seed.as_ref().is_some_and(|x| x.id == wanted) {
            s.seed = None
        } else if s.candidate.as_ref().is_some_and(|x| x.id == wanted) {
            s.candidate_remove_dispatched = true;
            if !s.candidate_remove_unknown {
                s.candidate = None
            }
        } else if s.live.as_ref().is_some_and(|x| x.id == wanted) {
            s.live = None;
            s.live_running = false
        } else {
            return Err("remove");
        };
        Ok(receipt())
    }
}

#[async_trait]
impl UpdateTargetDockerRunner for Runner {
    async fn pull_exact_target(&mut self, platform: &str, image: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .calls
            .push(format!("target-pull:{platform}:{image}"));
        Ok(())
    }
    async fn inspect_pulled_target(&mut self, image: &str) -> Result<DockerImageObservation> {
        self.0
            .lock()
            .unwrap()
            .calls
            .push(format!("target-inspect:{image}"));
        Ok(DockerImageObservation {
            id: "sha256:f3bf0d098792d61b470ac74b110e3a32d5c5d1e4920ae2b78215ad41a599824a".into(),
            repo_digests: vec![
                "n8nio/n8n@sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34"
                    .into(),
            ],
            os: "linux".into(),
            architecture: "amd64".into(),
        })
    }
}
struct Reader;
#[async_trait]
impl RegistryTargetReader for Reader {
    async fn read(&self, object: RegistryObject) -> Result<Vec<u8>> {
        match object {
            RegistryObject::Manifest(
                "sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34",
            ) => Ok(include_bytes!("fixtures/update/index-2.40.7.json").to_vec()),
            RegistryObject::Manifest(
                "sha256:599d68c7b6fb18b5ac1e7cd013a2e72c886ec1c807b9d436d56e90da32c664ac",
            ) => Ok(include_bytes!("fixtures/update/amd64-2.40.7.json").to_vec()),
            _ => Err(anyhow!("unexpected target fixture object")),
        }
    }
}
struct Ready;
#[async_trait]
impl super::super::ManagedReadiness for Ready {
    async fn health(&self, _: u16) -> bool {
        true
    }
}
struct Probe;
#[async_trait]
impl N8nApiProbe for Probe {
    async fn negative_control(
        &self,
        _: &crate::config::LoopbackHttpEndpoint,
    ) -> std::result::Result<(), N8nProbeError> {
        Ok(())
    }
    async fn authenticated_probe(
        &self,
        e: &crate::config::LoopbackHttpEndpoint,
        _: &SecretString,
    ) -> std::result::Result<N8nProbeReceipt, N8nProbeError> {
        crate::integrations::n8n::parse_workflows_response(
            e.clone(),
            200,
            br#"{"data":[],"nextCursor":null}"#,
        )
    }
}

fn initialize(home: &Path) {
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
    )
    .unwrap()
}
async fn fixture(running: bool) -> (tempfile::TempDir, Runner, Arc<Mutex<State>>, IntegrationJob) {
    let home = tempfile::tempdir().unwrap();
    initialize(home.path());
    let state = Arc::new(Mutex::new(State::default()));
    let mut runner = Runner(state.clone());
    let (_tx, mut cancel) = tokio::sync::oneshot::channel();
    let source = super::super::install_managed_at_with(
        home.path(),
        super::super::ManagedN8nRequest::new(5678, N8N_OCI_REFERENCE).unwrap(),
        SecretString::from("update-key"),
        &mut runner,
        &Ready,
        &Probe,
        &mut cancel,
    )
    .await
    .unwrap();
    state.lock().unwrap().source_running = running;
    state.lock().unwrap().calls.clear();
    (home, runner, state, source)
}

#[tokio::test]
async fn update_ready_preserves_source_custody_and_is_idempotent() {
    let (home, mut runner, state, _source) = fixture(true).await;
    let before = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();

    let ready = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    let binding = super::super::read_binding(home.path()).unwrap().unwrap();
    assert_eq!(binding.schema_version, 4);
    assert_eq!(binding.job_id, ready.job_id.as_str());

    let receipt = completed_receipt_at(home.path(), &ready).unwrap().unwrap();
    let (fingerprints, candidates, live_creates, baseline, candidate, ready_check, migrated) = {
        let s = state.lock().unwrap();
        assert_eq!(receipt.source_container_id, s.source.as_ref().unwrap().id);
        assert_eq!(s.source_name, receipt.retained_source_name);
        assert!(!s.source_running);
        (
            s.calls
                .iter()
                .filter(|x| x.starts_with("fingerprint:"))
                .count(),
            s.calls.iter().filter(|x| *x == "candidate-create").count(),
            s.calls.iter().filter(|x| *x == "live-create").count(),
            s.calls
                .iter()
                .position(|x| x.starts_with("fingerprint:"))
                .unwrap(),
            s.calls
                .iter()
                .position(|x| x == "candidate-create")
                .unwrap(),
            s.calls
                .iter()
                .position(|x| x.starts_with("candidate-ready:"))
                .unwrap(),
            s.calls
                .iter()
                .rposition(|x| x.starts_with("fingerprint:"))
                .unwrap(),
        )
    };
    assert_eq!(fingerprints, 2);
    assert_eq!(candidates, 1);
    assert_eq!(live_creates, 1);
    assert!(baseline < candidate && ready_check < migrated);
    assert_ne!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        before
    );

    let calls = state.lock().unwrap().calls.len();
    let replay = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(replay.job_id, ready.job_id);
    assert_eq!(state.lock().unwrap().calls.len(), calls);
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/arm64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(state.lock().unwrap().calls.len(), calls);
    let path = receipt_path(home.path(), ready.job_id.as_str());
    let mut damaged = read_receipt(home.path(), ready.job_id.as_str())
        .unwrap()
        .unwrap();
    damaged.migrated_content_sha256 = "0".repeat(64);
    std::fs::write(path, serde_json::to_vec(&damaged).unwrap()).unwrap();
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(state.lock().unwrap().calls.len(), calls);
}

#[tokio::test]
async fn stopped_source_remains_stopped_after_ready_update() {
    let (home, mut runner, state, _source) = fixture(false).await;
    let ready = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(ready.state, JobState::Ready);
    let s = state.lock().unwrap();
    assert!(!s.source_running);
    assert_eq!(s.calls.iter().filter(|x| x.starts_with("stop:")).count(), 0);
    assert_eq!(
        s.calls
            .iter()
            .filter(|x| x.starts_with("start:") && x.contains(&s.source.as_ref().unwrap().id))
            .count(),
        0
    )
}

#[tokio::test]
async fn ready_update_is_a_valid_source_for_the_real_backup_coordinator() {
    let (home, mut runner, _state, _source) = fixture(true).await;
    let update = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(update.state, JobState::Ready);

    let backup = super::super::managed_backup::backup_managed_at_with(home.path(), &mut runner)
        .await
        .unwrap();
    assert_eq!(backup.state, JobState::Ready);
    let receipt = super::super::managed_backup::completed_receipt_at(home.path(), &backup)
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.source_job_id.as_deref(),
        Some(update.job_id.as_str())
    );
    assert_eq!(receipt.source_operation.as_deref(), Some("update"));
}

#[tokio::test]
async fn known_content_mismatch_compensates_running_source_to_exact_prior_binding() {
    let (home, mut runner, state, _source) = fixture(true).await;
    let before = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    let source_volume = super::super::read_binding(home.path())
        .unwrap()
        .unwrap()
        .volume;
    state.lock().unwrap().content_mismatch = true;

    let failed = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        before
    );
    let s = state.lock().unwrap();
    assert_eq!(s.source_name, super::super::MANAGED_CONTAINER_NAME);
    assert!(s.source_running);
    assert!(s.live.is_none());
    assert!(s.candidate.is_none());
    assert!(s.volumes.contains_key(&source_volume));
    assert!(
        !s.volumes
            .keys()
            .any(|name| name.starts_with("neoth_n8n_update_"))
    );
    assert_eq!(
        s.calls
            .iter()
            .filter(|x| x.starts_with("live-create"))
            .count(),
        0
    );
}

#[tokio::test]
async fn known_content_mismatch_preserves_a_previously_stopped_source() {
    let (home, mut runner, state, _source) = fixture(false).await;
    let before = super::super::read_binding_bytes(home.path())
        .unwrap()
        .unwrap();
    state.lock().unwrap().content_mismatch = true;

    let failed = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(
        super::super::read_binding_bytes(home.path())
            .unwrap()
            .unwrap(),
        before
    );
    let s = state.lock().unwrap();
    assert_eq!(s.source_name, super::super::MANAGED_CONTAINER_NAME);
    assert!(!s.source_running);
    assert!(s.live.is_none());
}

#[tokio::test]
async fn lost_archive_receipt_is_held_and_reentry_never_rearchives_source() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().archive_receipt_lost = true;

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("archive:"), 1);
    assert_eq!(runner.calls("candidate-create"), 0);
    assert!(read(home.path()).unwrap().is_some());

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("archive:"), 1);
    assert_eq!(runner.calls("candidate-create"), 0);
}

#[tokio::test]
async fn lost_extract_receipt_is_held_and_reentry_never_reextracts_or_creates_target() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().extract_receipt_lost = true;

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("extract:"), 1);
    assert_eq!(runner.calls("candidate-create"), 0);
    assert_eq!(runner.calls("live-create"), 0);

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("extract:"), 1);
    assert_eq!(runner.calls("candidate-create"), 0);
    assert_eq!(runner.calls("live-create"), 0);
}

#[tokio::test]
async fn source_tuple_image_mismatch_blocks_before_source_mutation() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().source.as_mut().unwrap().image =
        format!("docker.io/n8nio/n8n@sha256:{}", "e".repeat(64));

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("stop:"), 0);
    assert_eq!(runner.calls("archive:"), 0);
    assert_eq!(runner.calls("volume-create"), 0);
    assert_eq!(runner.calls("candidate-create"), 0);
}

#[tokio::test]
async fn compensation_candidate_remove_unknown_holds_then_observed_absence_finalizes_failed() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().content_mismatch = true;
    state.lock().unwrap().candidate_remove_unknown = true;

    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    let candidate_id = state.lock().unwrap().candidate.as_ref().unwrap().id.clone();
    assert_eq!(runner.calls(&format!("remove:{candidate_id}")), 1);
    assert!(read(home.path()).unwrap().is_some());

    {
        let mut s = state.lock().unwrap();
        s.candidate = None;
        s.candidate_remove_unknown = false;
    }
    let failed = update_managed_at_with(
        home.path(),
        "n8n-2.40.7",
        "linux/amd64",
        SecretString::from("update-key"),
        &mut runner,
        &Reader,
        &Ready,
        &Probe,
    )
    .await
    .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(runner.calls(&format!("remove:{candidate_id}")), 1);
    assert!(read(home.path()).unwrap().is_none());
}

#[tokio::test]
async fn ambiguous_candidate_removal_holds_after_one_remove_without_live_create() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().candidate_remove_unknown = true;
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    let candidate_id = state.lock().unwrap().candidate.as_ref().unwrap().id.clone();
    assert_eq!(runner.calls(&format!("remove:{candidate_id}")), 1);
    assert_eq!(runner.calls("live-create"), 0);
    assert_eq!(runner.calls("rename:"), 0);
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls(&format!("remove:{candidate_id}")), 1);
    assert_eq!(runner.calls("live-create"), 0)
}

#[tokio::test]
async fn invalid_persisted_content_proof_holds_before_recovery_effects() {
    for mutation in 0..4 {
        let (home, mut runner, state, _source) = fixture(true).await;
        state.lock().unwrap().candidate_remove_unknown = true;
        assert!(
            update_managed_at_with(
                home.path(),
                "n8n-2.40.7",
                "linux/amd64",
                SecretString::from("update-key"),
                &mut runner,
                &Reader,
                &Ready,
                &Probe
            )
            .await
            .is_err()
        );
        let mut custody = read(home.path()).unwrap().unwrap();
        assert_eq!(custody.phase, Phase::CandidateRemoveDispatched);
        match mutation {
            0 => custody.baseline_content_sha256 = None,
            1 => custody.migrated_content_sha256 = Some("f".repeat(64)),
            2 => custody.migrated_workflow_count = None,
            _ => custody.migrated_credential_count = Some(100),
        }
        write(home.path(), &custody).unwrap();
        let before = state.lock().unwrap().calls.clone();
        assert!(
            update_managed_at_with(
                home.path(),
                "n8n-2.40.7",
                "linux/amd64",
                SecretString::from("update-key"),
                &mut runner,
                &Reader,
                &Ready,
                &Probe
            )
            .await
            .is_err()
        );
        assert_eq!(state.lock().unwrap().calls, before);
        assert!(read(home.path()).unwrap().is_some());
    }
}

#[tokio::test]
async fn lost_candidate_id_does_not_retry_create_on_reentry() {
    let (home, mut runner, state, _source) = fixture(true).await;
    state.lock().unwrap().lost_candidate_id = true;
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("candidate-create"), 1);
    assert!(
        update_managed_at_with(
            home.path(),
            "n8n-2.40.7",
            "linux/amd64",
            SecretString::from("update-key"),
            &mut runner,
            &Reader,
            &Ready,
            &Probe
        )
        .await
        .is_err()
    );
    assert_eq!(runner.calls("candidate-create"), 1);
    assert_eq!(runner.calls("live-create"), 0)
}
