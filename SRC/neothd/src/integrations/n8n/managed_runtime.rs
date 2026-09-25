//! Managed n8n Docker lifecycle.  This module owns only containers whose
//! private durable binding names the exact container id, job, image, port and
//! volume.  API-key custody remains in the existing adoption transaction.

use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command as SyncCommand, Stdio},
    time::{Duration, Instant},
};

use super::{
    HttpN8nApiProbe, IntegrationJob, IntegrationJobService, JobEvidenceContract, JobFailure,
    JobOperation, JobRequester, N8N_CAPABILITY_ID, N8nApiProbe,
    expected_authenticated_probe_sha256, sha256_parts,
};
use crate::integrations::{catalog::CapabilityId, jobs::EnqueueIntegrationJob};
use crate::{
    config::LoopbackHttpEndpoint, installers::n8n::N8N_OCI_REFERENCE, secret::SecretString,
};
use serde::{Deserialize, Serialize};

#[path = "managed_backup.rs"]
pub(crate) mod managed_backup;
#[path = "managed_repair.rs"]
pub(crate) mod managed_repair;
#[path = "managed_uninstall.rs"]
pub(crate) mod managed_uninstall;
#[path = "managed_restore_candidate.rs"]
pub(crate) mod managed_restore_candidate;
#[path = "managed_restore.rs"]
pub(crate) mod managed_restore;
#[path = "managed_restore_io.rs"]
mod managed_restore_io;
#[path = "managed_restore_content.rs"]
mod managed_restore_content;

pub(crate) const MANAGED_CONTAINER_NAME: &str = "neoth-n8n";
pub(crate) const MANAGED_LABEL_KEY: &str = "io.neoth.managed";
pub(crate) const MANAGED_LABEL_VALUE: &str = "n8n";
pub(crate) const DEFAULT_VOLUME: &str = "neoth_n8n_data";
const BINDING_FILE: &str = "n8n-managed-runtime.v2.json";
const OPERATION_LOCK_FILE: &str = "n8n-managed-runtime.operation.lock";
// Match the existing adoption evidence plan so the extracted custody publisher
// can complete this same durable job without a second exclusive job.
const STEPS: [&str; 4] = [
    "validate-loopback-endpoint",
    "authenticated-precommit-probe",
    "publish-config-and-secret",
    "authenticated-postcommit-probe",
];
const DEADLINE: Duration = Duration::from_secs(45);

pub(super) fn is_managed_job(job: &IntegrationJob) -> bool {
    // `release_version` is persisted through the strict public semver gate;
    // the manifest binds the v4 runtime semantics and exact request details.
    job.capability_id.as_str() == N8N_CAPABILITY_ID && job.release_version == "1.4.0"
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedN8nRequest {
    port: u16,
    image: &'static str,
    volume: String,
    prepared_job: Option<IntegrationJob>,
    retained_reinstall: Option<RetainedReinstallSource>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedReinstallSource {
    pub uninstall_job_id: String,
    pub uninstall_manifest_sha256: String,
    pub source_install_job_id: String,
    pub source_install_manifest_sha256: String,
    pub bootstrap_volume: bool,
    /// The bootstrap install that created and labelled this volume.  This is
    /// deliberately distinct from `source_install_job_id`: a reinstall chain
    /// changes the latter but must never change the volume's label owner.
    #[serde(default)]
    pub volume_owner_install_job_id: String,
}
impl ManagedN8nRequest {
    pub(crate) fn new(port: u16, image: &'static str) -> Result<Self, &'static str> {
        if port == 0 || image != N8N_OCI_REFERENCE || !image.contains("@sha256:") {
            Err("managed n8n requires reviewed immutable OCI and nonzero loopback port")
        } else {
            Ok(Self {
                port,
                image,
                volume: DEFAULT_VOLUME.into(),
                prepared_job: None,
                retained_reinstall: None,
            })
        }
    }
    /// Bootstrap owns a fresh, job-namespaced volume.  Ordinary stdin-key
    /// installation deliberately retains the historical volume name.
    pub(crate) fn new_with_volume(
        port: u16,
        image: &'static str,
        volume: String,
    ) -> Result<Self, &'static str> {
        let mut request = Self::new(port, image)?;
        if !valid_volume_name(&volume) {
            return Err("managed n8n requires a validated named volume");
        }
        request.volume = volume;
        Ok(request)
    }
    pub(crate) fn volume(&self) -> &str {
        &self.volume
    }
    pub(crate) fn retained_reinstall_source(&self) -> Option<&RetainedReinstallSource> {
        self.retained_reinstall.as_ref()
    }
    /// Only the bootstrap coordinator may supply a job it created before its
    /// first Docker mutation.  The runtime consumes it exactly once.
    pub(crate) fn with_prepared_job(mut self, job: IntegrationJob) -> Self {
        self.prepared_job = Some(job);
        self
    }
    pub(crate) fn with_retained_reinstall(mut self, source: RetainedReinstallSource) -> Self {
        self.retained_reinstall = Some(source);
        self
    }
    pub(crate) fn endpoint(&self) -> LoopbackHttpEndpoint {
        LoopbackHttpEndpoint::parse(format!("http://127.0.0.1:{}", self.port))
            .expect("validated port")
    }
    pub(crate) fn create_command(&self, job: &str) -> Vec<String> {
        vec![
            "docker".into(),
            "run".into(),
            "-d".into(),
            "--name".into(),
            MANAGED_CONTAINER_NAME.into(),
            "--label".into(),
            format!("{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE}"),
            "--label".into(),
            format!("io.neoth.n8n-job={job}"),
            "-p".into(),
            format!("127.0.0.1:{}:5678", self.port),
            "-v".into(),
            format!("{}:/home/node/.n8n", self.volume),
            "--restart".into(),
            "unless-stopped".into(),
            self.image.into(),
        ]
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedCommandReceipt {
    pub succeeded: bool,
    pub output_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedCreateReceipt {
    pub command: ManagedCommandReceipt,
    /// Exact 64-hex id printed by a successful Docker create response. A
    /// missing value is deliberately ambiguous and cannot authorize adoption.
    pub container_id: Option<String>,
}
/// Receipt for an opaque, NEOTH-owned archive. Archive bytes are never
/// converted to text or attached to command output: the durable backup
/// custody binds only this size and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedArchiveReceipt {
    pub archive_sha256: String,
    pub archive_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedContainer {
    pub id: String,
    pub image: String,
    pub managed: String,
    pub job: String,
    pub host_ip: String,
    pub host_port: u16,
    pub volume: String,
    pub mount_destination: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InspectOutcome {
    Absent,
    Found(ObservedContainer),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedVolume {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InspectVolumeOutcome {
    Absent,
    Found(ObservedVolume),
    Unknown,
}

#[derive(Deserialize)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Config")]
    config: DockerConfig,
    #[serde(rename = "NetworkSettings")]
    network_settings: DockerNetworkSettings,
    #[serde(rename = "HostConfig")]
    host_config: DockerHostConfig,
    #[serde(rename = "Mounts")]
    mounts: Vec<DockerMount>,
}
#[derive(Deserialize)]
struct DockerConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
}
#[derive(Deserialize)]
struct DockerNetworkSettings {
    #[serde(rename = "Ports")]
    ports: BTreeMap<String, Option<Vec<DockerPortBinding>>>,
}
#[derive(Deserialize)]
struct DockerHostConfig {
    #[serde(rename = "PortBindings")]
    port_bindings: BTreeMap<String, Option<Vec<DockerPortBinding>>>,
}
#[derive(Deserialize, Clone, PartialEq, Eq)]
struct DockerPortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}
#[derive(Deserialize)]
struct DockerMount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Destination")]
    destination: String,
}
#[derive(Deserialize)]
struct DockerVolume {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
}
#[async_trait]
pub(crate) trait ManagedDockerRunner: Send {
    /// `inspect_named` is only discovery.  Destruction is always followed by
    /// `inspect_exact`, so a renamed/recreated container cannot prove absence.
    async fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str>;
    async fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str>;
    /// State is deliberately separate from identity inspection so existing
    /// test runners stay conservative until a repair test opts in.
    async fn running_exact(&mut self, _id: &str) -> Result<bool, &'static str> {
        Err("n8n_managed_running_state_unavailable")
    }
    async fn inspect_volume(&mut self, name: &str) -> Result<InspectVolumeOutcome, &'static str>;
    async fn remove_volume(&mut self, _name: &str) -> Result<ManagedCommandReceipt, &'static str> {
        Err("n8n_volume_remove_unavailable")
    }
    async fn create(&mut self, argv: &[String]) -> Result<ManagedCommandReceipt, &'static str>;
    async fn create_with_exact_id(
        &mut self,
        argv: &[String],
    ) -> Result<ManagedCreateReceipt, &'static str> {
        Ok(ManagedCreateReceipt {
            command: self.create(argv).await?,
            container_id: None,
        })
    }
    /// Starting is deliberately an exact-id operation. Existing test runners
    /// do not acquire a new mutator merely by implementing this lifecycle.
    async fn start_exact(&mut self, _id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        Err("n8n_managed_start_unavailable")
    }
    /// Stop is kept separate from removal so the backup coordinator can
    /// durably record the stop effect before asking Docker to perform it.
    async fn stop_exact(&mut self, _id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        Err("n8n_managed_stop_unavailable")
    }
    /// Copy the managed `.n8n` directory as an opaque tar stream into a
    /// private, no-clobber NEOTH file. Implementors must never return its
    /// bytes through stdout, errors, or a command receipt.
    async fn archive_exact_n8n_dir_to_private_file(
        &mut self,
        _id: &str,
        _destination: &Path,
        _max_bytes: u64,
    ) -> Result<ManagedArchiveReceipt, &'static str> {
        Err("n8n_managed_archive_unavailable")
    }
    /// Copy a verified private archive into one exact, stopped restore
    /// candidate. The archive remains opaque to the runner interface.
    async fn extract_private_archive_to_exact_container(
        &mut self,
        _archive: &Path,
        _expected_sha256: &str,
        _expected_bytes: u64,
        _id: &str,
    ) -> Result<ManagedArchiveReceipt, &'static str> {
        Err("n8n_restore_archive_unavailable")
    }
    async fn create_restore_volume_exact(
        &mut self,
        _job: &crate::integrations::state::JobId,
    ) -> Result<ManagedCommandReceipt, &'static str> {
        Err("n8n_restore_candidate_unavailable")
    }
    async fn inspect_restore_candidate_exact(
        &mut self,
        _id: &str,
    ) -> Result<managed_restore_candidate::InspectRestoreCandidateOutcome, &'static str> {
        Err("n8n_restore_candidate_unavailable")
    }
    async fn create_restore_candidate_exact(
        &mut self,
        _spec: managed_restore_candidate::RestoreCandidateSpec<'_>,
    ) -> Result<ManagedCreateReceipt, &'static str> {
        Err("n8n_restore_candidate_unavailable")
    }
    async fn validate_restore_candidate_content_exact(
        &mut self,
        id: &str,
    ) -> Result<managed_restore_candidate::RestoreCandidateContentReceipt, &'static str> {
        managed_restore_content::validate_content_exact(id).await
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum RuntimePhase {
    CreateIntent,
    Bound,
    Ready,
    AbsentVerified,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeBinding {
    pub(super) schema_version: u8,
    pub(super) phase: RuntimePhase,
    pub(super) job_id: String,
    pub(super) manifest_sha256: String,
    pub(super) container_name: String,
    pub(super) container_id: Option<String>,
    pub(super) image: String,
    pub(super) host_port: u16,
    pub(super) volume: String,
    #[serde(default)]
    pub(super) retained_reinstall: Option<RetainedReinstallSource>,
    /// Present only for a first-owner bootstrap runtime. Reinstall bindings
    /// carry this same immutable owner through `retained_reinstall` instead.
    #[serde(default)]
    pub(super) bootstrap_volume_owner_job_id: Option<String>,
}
fn binding_path(home: &Path) -> PathBuf {
    home.join(BINDING_FILE)
}
pub(super) fn operation_lock_path(home: &Path) -> PathBuf {
    home.join(OPERATION_LOCK_FILE)
}
pub(super) fn read_binding(home: &Path) -> Result<Option<RuntimeBinding>, &'static str> {
    let path = binding_path(home);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("n8n_runtime_binding_read_failed"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 {
        return Err("n8n_runtime_binding_invalid");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("n8n_runtime_binding_invalid");
        }
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "n8n_runtime_binding_read_failed")?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "n8n_runtime_binding_read_failed")?;
    if bytes.len() > 16 * 1024 {
        return Err("n8n_runtime_binding_invalid");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "n8n_runtime_binding_invalid")
}
/// Return the validated on-disk bytes so a sibling transaction can perform an
/// exact pre/post publication comparison without inventing a lossy JSON
/// canonicalization rule.
pub(super) fn read_binding_bytes(home: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    if read_binding(home)?.is_none() {
        return Ok(None);
    }
    std::fs::read(binding_path(home))
        .map(Some)
        .map_err(|_| "n8n_runtime_binding_read_failed")
}
pub(crate) fn has_runtime_binding(home: &Path) -> Result<bool, &'static str> {
    Ok(read_binding(home)?.is_some())
}
/// Bootstrap records the final exact ID only after the existing runtime has
/// persisted its own binding.  No caller gets the wider private binding.
pub(crate) fn bound_container_id(home: &Path) -> Result<Option<String>, &'static str> {
    Ok(read_binding(home)?.and_then(|binding| binding.container_id))
}
pub(super) fn write_binding(home: &Path, value: &RuntimeBinding) -> Result<(), &'static str> {
    crate::util::atomic_write::atomic_write_private(
        &binding_path(home),
        &serde_json::to_vec(value).map_err(|_| "n8n_runtime_binding_serialize_failed")?,
    )
    .map_err(|_| "n8n_runtime_binding_write_failed")
}
#[cfg(test)]
pub(super) fn mark_bootstrap_volume_owner_for_test(
    home: &Path,
    owner_job_id: &str,
) -> Result<(), &'static str> {
    let mut binding = read_binding(home)?.ok_or("n8n_runtime_binding_missing")?;
    binding.bootstrap_volume_owner_job_id = Some(owner_job_id.into());
    write_binding(home, &binding)
}
fn remove_binding(home: &Path) -> Result<(), &'static str> {
    let path = binding_path(home);
    if path.exists() {
        crate::util::atomic_write::durable_remove_file(&path)
            .map_err(|_| "n8n_runtime_binding_remove_failed")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreateIntentWrite {
    Persisted,
    Uncertain,
}

/// A failed create-new call is ambiguous: its durable rename may have won
/// before the reported error.  The caller must keep its Queued job recoverable
/// and must not start Docker on this path.
fn persist_create_intent_with<F>(
    home: &Path,
    binding: &RuntimeBinding,
    writer: F,
) -> Result<CreateIntentWrite, &'static str>
where
    F: FnOnce(&Path, &[u8]) -> Result<(), &'static str>,
{
    let bytes = serde_json::to_vec(binding).map_err(|_| "n8n_runtime_binding_serialize_failed")?;
    Ok(if writer(&binding_path(home), &bytes).is_ok() {
        CreateIntentWrite::Persisted
    } else {
        CreateIntentWrite::Uncertain
    })
}

fn persist_create_intent(
    home: &Path,
    binding: &RuntimeBinding,
) -> Result<CreateIntentWrite, &'static str> {
    persist_create_intent_with(home, binding, |path, bytes| {
        crate::util::atomic_write::write_private_create_new_durable(path, bytes)
            .map_err(|_| "n8n_runtime_binding_write_failed")
    })
}

pub(super) fn validate_existing_identity(
    observed: &ObservedContainer,
    binding: Option<&RuntimeBinding>,
    request: &ManagedN8nRequest,
    job: &IntegrationJob,
) -> Result<(), &'static str> {
    let Some(binding) = binding else {
        return Err("n8n_preexisting_container_without_durable_custody");
    };
    let id_matches = match binding.phase {
        RuntimePhase::CreateIntent => binding.container_id.is_none(),
        _ => binding.container_id.as_deref() == Some(observed.id.as_str()),
    };
    if !valid_container_id(&observed.id)
        || binding.schema_version != 2
        || binding.job_id != job.job_id.as_str()
        || binding.manifest_sha256 != job.manifest_sha256.as_str()
        || binding.container_name != MANAGED_CONTAINER_NAME
        || !id_matches
        || observed.job != binding.job_id
        || observed.image != request.image
        || observed.managed != MANAGED_LABEL_VALUE
        || observed.host_ip != "127.0.0.1"
        || observed.host_port != request.port
        || observed.volume != request.volume
        || observed.mount_destination != "/home/node/.n8n"
        || binding.image != request.image
        || binding.host_port != request.port
        || binding.volume != request.volume
    {
        Err("n8n_preexisting_container_unowned_or_mismatch")
    } else {
        Ok(())
    }
}

#[async_trait]
pub(crate) trait ManagedReadiness: Send + Sync {
    async fn health(&self, port: u16) -> bool;
}
pub(super) struct ProductionReadiness;
#[async_trait]
impl ManagedReadiness for ProductionReadiness {
    async fn health(&self, port: u16) -> bool {
        matches!(
            crate::installers::n8n::probe_n8n_readiness_endpoint(port).await,
            crate::installers::n8n::N8nProbeOutcome::Reachable
        )
    }
}
pub(crate) fn enqueue_prepared(
    service: &IntegrationJobService,
    request: &ManagedN8nRequest,
) -> anyhow::Result<IntegrationJob> {
    let endpoint = request.endpoint();
    let manifest = managed_manifest(request);
    let contract = JobEvidenceContract::verified(
        manifest.clone(),
        sha256_parts(&[
            endpoint.origin(),
            MANAGED_LABEL_KEY,
            MANAGED_LABEL_VALUE,
            request.volume(),
        ]),
        expected_authenticated_probe_sha256(&endpoint),
        sha256_parts(&STEPS),
    );
    Ok(service
        .enqueue(EnqueueIntegrationJob {
            capability_id: CapabilityId::parse(N8N_CAPABILITY_ID).expect("static capability"),
            operation: JobOperation::Install,
            release_version: "1.4.0".into(),
            manifest_sha256: manifest,
            evidence_contract: contract,
            requested_by: JobRequester::Cli,
            total_steps: STEPS.len() as u32,
            bytes_total: None,
        })?
        .job)
}

pub(super) fn managed_manifest(request: &ManagedN8nRequest) -> super::Sha256Digest {
    let port = request.port.to_string();
    let mut parts = vec![
        "n8n-managed-runtime-v4",
        request.image,
        MANAGED_CONTAINER_NAME,
        &port,
        request.volume(),
    ];
    if let Some(source) = &request.retained_reinstall {
        parts.extend([
            "n8n-managed-retained-reinstall-v1",
            source.uninstall_job_id.as_str(),
            source.uninstall_manifest_sha256.as_str(),
            source.source_install_job_id.as_str(),
            source.source_install_manifest_sha256.as_str(),
            source.volume_owner_install_job_id.as_str(),
        ]);
    }
    sha256_parts(&parts)
}
fn fail(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    code: &'static str,
) -> anyhow::Result<IntegrationJob> {
    Ok(service.fail(&job.job_id, job.state_revision, JobFailure::new(code, "The managed n8n runtime did not reach authenticated readiness; retry is safe after repair.").expect("static failure"))?)
}
pub(super) fn validate_binding(
    binding: &RuntimeBinding,
    job: &IntegrationJob,
) -> Result<ManagedN8nRequest, &'static str> {
    let mut request = ManagedN8nRequest::new_with_volume(
        binding.host_port,
        N8N_OCI_REFERENCE,
        binding.volume.clone(),
    )?;
    if let Some(source) = binding.retained_reinstall.clone() {
        request = request.with_retained_reinstall(source);
    }
    let expected = managed_manifest(&request);
    let retained_owner_matches = match binding.retained_reinstall.as_ref() {
        None => true,
        Some(source) => {
            source.bootstrap_volume
                && source.volume_owner_install_job_id
                    == binding
                        .bootstrap_volume_owner_job_id
                        .clone()
                        .unwrap_or_default()
                && valid_retained_reinstall_source(source)
        }
    };
    let bootstrap_owner_matches = match (
        &binding.retained_reinstall,
        &binding.bootstrap_volume_owner_job_id,
    ) {
        (Some(_), Some(_)) => retained_owner_matches,
        (Some(_), None) => false,
        (None, Some(owner)) => owner == &binding.job_id && binding.volume != DEFAULT_VOLUME,
        (None, None) => true,
    };
    if !is_managed_job(job)
        || binding.schema_version != 2
        || binding.job_id != job.job_id.as_str()
        || binding.manifest_sha256 != job.manifest_sha256.as_str()
        || job.manifest_sha256 != expected
        || binding.container_name != MANAGED_CONTAINER_NAME
        || binding.image != request.image
        || binding.volume != request.volume
        || !bootstrap_owner_matches
        || binding
            .container_id
            .as_ref()
            .is_some_and(|id| !valid_container_id(id))
        || (binding.phase == RuntimePhase::CreateIntent && binding.container_id.is_some())
        || (matches!(binding.phase, RuntimePhase::Bound | RuntimePhase::Ready)
            && binding.container_id.is_none())
    {
        return Err("n8n_managed_custody_mismatch");
    }
    Ok(request)
}

pub(crate) fn valid_manifest_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_retained_reinstall_source(source: &RetainedReinstallSource) -> bool {
    source.bootstrap_volume
        && super::JobId::parse(source.uninstall_job_id.clone()).is_ok()
        && valid_manifest_sha256(&source.uninstall_manifest_sha256)
        && super::JobId::parse(source.source_install_job_id.clone()).is_ok()
        && valid_manifest_sha256(&source.source_install_manifest_sha256)
        && super::JobId::parse(source.volume_owner_install_job_id.clone()).is_ok()
}

pub(crate) fn valid_container_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_volume_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn absent_digest(binding: &RuntimeBinding) -> super::Sha256Digest {
    sha256_parts(&[
        "n8n-managed-container-absent",
        binding.container_id.as_deref().unwrap_or("not-created"),
        &binding.job_id,
        &binding.manifest_sha256,
    ])
}

fn terminal_after_absence(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    home: &Path,
    binding: &RuntimeBinding,
    code: &'static str,
    cancelling: bool,
    custody_may_exist: bool,
) -> anyhow::Result<IntegrationJob> {
    validate_binding(binding, job).map_err(anyhow::Error::msg)?;
    if binding.phase != RuntimePhase::AbsentVerified {
        anyhow::bail!("n8n_managed_absence_unproven");
    }
    let mut current = service
        .get(&job.job_id)?
        .ok_or_else(|| anyhow::anyhow!("n8n_managed_job_missing"))?;
    if cancelling && !current.cancel_requested {
        current = service.request_cancel(&current.job_id, current.state_revision)?;
    }
    if super::rollback_adoption_if_prepared(home, &current.job_id, custody_may_exist).is_err() {
        // Keep the active job and its absence custody until compensation is
        // proven. Both terms are fixed redacted codes for caller diagnosis.
        anyhow::bail!("{code}:adoption_cleanup_failed");
    }
    let terminal = if current.state == super::JobState::Cancelled {
        current
    } else if current.cancel_requested {
        let contract = current
            .evidence_contract
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("n8n_managed_contract_missing"))?;
        let evidence = crate::integrations::state::CancellationEvidence::verified(
            current.job_id.clone(),
            current.manifest_sha256.clone(),
            contract.step_plan_sha256().clone(),
            current.state_revision,
            absent_digest(binding),
            sha256_parts(&["n8n-custody-rolled-back"]),
        );
        service.acknowledge_cancel(&current.job_id, current.state_revision, evidence)?
    } else {
        fail(service, &current, code)?
    };
    // Only a durable terminal authorizes forgetting process custody.
    let _ = finalize_terminal_custody(home, &terminal);
    Ok(terminal)
}

async fn cleanup_and_fail<R: ManagedDockerRunner>(
    service: &IntegrationJobService,
    job: &IntegrationJob,
    runner: &mut R,
    home: &Path,
    id: &str,
    code: &'static str,
    custody_may_exist: bool,
) -> anyhow::Result<IntegrationJob> {
    let mut current = service
        .get(&job.job_id)?
        .ok_or_else(|| anyhow::anyhow!("n8n_managed_job_missing"))?;
    let cancelling = code == "n8n_managed_cancelled" || current.cancel_requested;
    if cancelling && !current.cancel_requested {
        current = service.request_cancel(&current.job_id, current.state_revision)?;
    }
    let mut binding = read_binding(home)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("n8n_managed_custody_missing"))?;
    let request = validate_binding(&binding, &current).map_err(anyhow::Error::msg)?;
    if binding.container_id.as_deref() != Some(id) || binding.phase == RuntimePhase::Ready {
        anyhow::bail!("n8n_managed_custody_mismatch");
    }
    match runner.inspect_exact(id).await.map_err(anyhow::Error::msg)? {
        InspectOutcome::Absent => {}
        InspectOutcome::Found(found) => {
            validate_existing_identity(&found, Some(&binding), &request, &current)
                .map_err(anyhow::Error::msg)?;
            // A transport error after removal may still have applied the effect.
            // The follow-up exact inspection, not the exit code, proves absence.
            let _ = runner.remove(id).await;
            if !matches!(runner.inspect_exact(id).await, Ok(InspectOutcome::Absent)) {
                anyhow::bail!("n8n_managed_cleanup_failed");
            }
        }
        InspectOutcome::Unknown => anyhow::bail!("n8n_managed_cleanup_failed"),
    }
    binding.phase = RuntimePhase::AbsentVerified;
    write_binding(home, &binding).map_err(anyhow::Error::msg)?;
    terminal_after_absence(
        service,
        &current,
        home,
        &binding,
        code,
        cancelling,
        custody_may_exist,
    )
}

fn cancellation_observed(cancel: &mut tokio::sync::oneshot::Receiver<()>) -> bool {
    !matches!(
        cancel.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::integrations) async fn install_managed_at_with<
    R: ManagedDockerRunner,
    H: ManagedReadiness,
    P: N8nApiProbe + ?Sized,
>(
    home: &Path,
    request: ManagedN8nRequest,
    api_key: SecretString,
    runner: &mut R,
    readiness: &H,
    probe: &P,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    super::ensure_initialized_home_for_new_managed_install(home)?;
    managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    let service = super::open_n8n_job_service(home)?;
    install_managed_in_service_with(
        &service, home, request, api_key, runner, readiness, probe, cancel,
    )
    .await
}

async fn verify_retained_volume<R: ManagedDockerRunner>(
    runner: &mut R,
    request: &ManagedN8nRequest,
) -> anyhow::Result<()> {
    let source = request
        .retained_reinstall
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("n8n_retained_reinstall_source_missing"))?;
    let found = match runner
        .inspect_volume(request.volume())
        .await
        .map_err(anyhow::Error::msg)?
    {
        InspectVolumeOutcome::Found(found) if found.name == request.volume() => found,
        InspectVolumeOutcome::Absent => anyhow::bail!("n8n_retained_volume_absent"),
        InspectVolumeOutcome::Unknown => anyhow::bail!("n8n_retained_volume_unknown"),
        InspectVolumeOutcome::Found(_) => anyhow::bail!("n8n_retained_volume_foreign"),
    };
    if !valid_retained_reinstall_source(source)
        || found.labels.get(MANAGED_LABEL_KEY).map(String::as_str) != Some(MANAGED_LABEL_VALUE)
        || found.labels.get("io.neoth.n8n-job").map(String::as_str)
            != Some(source.volume_owner_install_job_id.as_str())
        || found
            .labels
            .get("io.neoth.n8n-bootstrap")
            .map(String::as_str)
            != Some(super::managed_bootstrap::BOOTSTRAP_SCHEMA)
    {
        anyhow::bail!("n8n_retained_volume_foreign");
    }
    Ok(())
}

/// Repair reuses the exact persisted binding but must still prove that a
/// retained/bootstrap volume has not been swapped before it starts or creates
/// a process. Ordinary legacy managed volumes had no owner labels, so they
/// retain the existing name-only ownership rule.
pub(super) async fn verify_runtime_volume_owner<R: ManagedDockerRunner>(
    runner: &mut R,
    binding: &RuntimeBinding,
) -> Result<(), &'static str> {
    let found = match runner.inspect_volume(&binding.volume).await? {
        InspectVolumeOutcome::Found(found) if found.name == binding.volume => found,
        InspectVolumeOutcome::Absent => return Err("n8n_repair_volume_absent"),
        _ => return Err("n8n_repair_volume_unknown"),
    };
    let expected_owner = binding
        .retained_reinstall
        .as_ref()
        .map(|source| source.volume_owner_install_job_id.as_str())
        .or(binding.bootstrap_volume_owner_job_id.as_deref());
    if let Some(owner) = expected_owner
        && (found.labels.get(MANAGED_LABEL_KEY).map(String::as_str) != Some(MANAGED_LABEL_VALUE)
            || found.labels.get("io.neoth.n8n-job").map(String::as_str) != Some(owner)
            || found
                .labels
                .get("io.neoth.n8n-bootstrap")
                .map(String::as_str)
                != Some(super::managed_bootstrap::BOOTSTRAP_SCHEMA))
    {
        return Err("n8n_repair_volume_owner_mismatch");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::integrations) async fn install_retained_at_with<
    R: ManagedDockerRunner,
    H: ManagedReadiness,
    P: N8nApiProbe + ?Sized,
>(
    home: &Path,
    uninstall_id: &super::JobId,
    api_key: SecretString,
    runner: &mut R,
    readiness: &H,
    probe: &P,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    super::ensure_initialized_home_for_new_managed_install(home)?;
    managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    let service = super::open_n8n_job_service(home)?;
    if read_binding(home).map_err(anyhow::Error::msg)?.is_some() {
        anyhow::bail!("n8n_retained_reinstall_already_active");
    }
    let request =
        managed_uninstall::retained_reinstall_request_in_service(&service, home, uninstall_id)
            .map_err(anyhow::Error::msg)?;
    verify_retained_volume(runner, &request).await?;
    install_managed_in_service_with(
        &service, home, request, api_key, runner, readiness, probe, cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn install_managed_in_service_with<
    R: ManagedDockerRunner,
    H: ManagedReadiness,
    P: N8nApiProbe + ?Sized,
>(
    service: &IntegrationJobService,
    home: &Path,
    mut request: ManagedN8nRequest,
    api_key: SecretString,
    runner: &mut R,
    readiness: &H,
    probe: &P,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    if read_binding(home).map_err(anyhow::Error::msg)?.is_some() {
        anyhow::bail!("n8n_managed_instance_already_owned");
    }
    let prepared_bootstrap_owner = request
        .prepared_job
        .as_ref()
        .map(|job| job.job_id.as_str().to_owned());
    let queued = match request.prepared_job.take() {
        Some(job) => {
            let expected = enqueue_prepared(service, &request)?;
            // `enqueue` is idempotent by its immutable manifest.  It returns
            // the existing row, never a second job, and lets us bind the
            // caller-provided durable ID to the current request.
            if expected.job_id != job.job_id || expected.manifest_sha256 != job.manifest_sha256 {
                anyhow::bail!("n8n_managed_prepared_job_mismatch");
            }
            job
        }
        None => enqueue_prepared(service, &request)?,
    };
    let bootstrap_volume_owner_job_id = match (
        prepared_bootstrap_owner,
        request.retained_reinstall.as_ref(),
    ) {
        (Some(owner), None) if owner == queued.job_id.as_str() => Some(owner),
        (Some(_), None) => anyhow::bail!("n8n_managed_prepared_job_mismatch"),
        (None, Some(source)) if valid_retained_reinstall_source(source) => {
            Some(source.volume_owner_install_job_id.clone())
        }
        (None, Some(_)) => anyhow::bail!("n8n_retained_reinstall_source_invalid"),
        (Some(_), Some(_)) => anyhow::bail!("n8n_retained_reinstall_source_invalid"),
        (None, None) => None,
    };
    let mut binding = RuntimeBinding {
        schema_version: 2,
        phase: RuntimePhase::CreateIntent,
        job_id: queued.job_id.as_str().into(),
        manifest_sha256: queued.manifest_sha256.as_str().into(),
        container_name: MANAGED_CONTAINER_NAME.into(),
        container_id: None,
        image: request.image.into(),
        host_port: request.port,
        volume: request.volume.clone(),
        retained_reinstall: request.retained_reinstall.clone(),
        bootstrap_volume_owner_job_id,
    };
    if persist_create_intent(home, &binding).map_err(anyhow::Error::msg)?
        == CreateIntentWrite::Uncertain
    {
        // The private write may already be durable. Keep this Queued job
        // active: startup recovery can safely turn a matching Queued intent
        // into AbsentVerified without consulting Docker, while malformed or
        // foreign custody remains fail-closed in the validator.
        return Ok(queued);
    }
    if cancellation_observed(cancel) {
        binding.phase = RuntimePhase::AbsentVerified;
        write_binding(home, &binding).map_err(anyhow::Error::msg)?;
        return terminal_after_absence(
            service,
            &queued,
            home,
            &binding,
            "n8n_managed_cancelled",
            true,
            false,
        );
    }
    // Bootstrap starts its one durable job before its first Docker mutation.
    // Ordinary stdin-key install still transitions the freshly queued job here.
    let running = if queued.state == super::JobState::Running {
        queued
    } else if queued.state == super::JobState::Queued {
        service.start(&queued.job_id, queued.state_revision, STEPS[0])?
    } else {
        anyhow::bail!("n8n_managed_prepared_job_not_active");
    };
    match runner.inspect_named().await.map_err(anyhow::Error::msg)? {
        InspectOutcome::Absent => {}
        InspectOutcome::Found(_) => {
            // This new job has not issued create; a same-name process is foreign.
            binding.phase = RuntimePhase::AbsentVerified;
            write_binding(home, &binding).map_err(anyhow::Error::msg)?;
            return terminal_after_absence(
                service,
                &running,
                home,
                &binding,
                "n8n_preexisting_container_unowned_or_mismatch",
                false,
                false,
            );
        }
        InspectOutcome::Unknown => anyhow::bail!("n8n_container_inspect_unknown"),
    }
    let create_result = runner
        .create(&request.create_command(running.job_id.as_str()))
        .await;
    let found = match runner.inspect_named().await.map_err(anyhow::Error::msg)? {
        InspectOutcome::Found(found) => found,
        InspectOutcome::Absent
            if matches!(
                create_result,
                Ok(ManagedCommandReceipt {
                    succeeded: false,
                    ..
                })
            ) =>
        {
            binding.phase = RuntimePhase::AbsentVerified;
            write_binding(home, &binding).map_err(anyhow::Error::msg)?;
            return terminal_after_absence(
                service,
                &running,
                home,
                &binding,
                "n8n_managed_container_create_failed",
                false,
                false,
            );
        }
        _ => anyhow::bail!("n8n_managed_container_identity_ambiguous"),
    };
    validate_existing_identity(&found, Some(&binding), &request, &running)
        .map_err(anyhow::Error::msg)?;
    binding.container_id = Some(found.id.clone());
    binding.phase = RuntimePhase::Bound;
    write_binding(home, &binding).map_err(anyhow::Error::msg)?;
    let id = found.id;
    let deadline = Instant::now() + DEADLINE;
    loop {
        if cancellation_observed(cancel) {
            return cleanup_and_fail(
                service,
                &running,
                runner,
                home,
                &id,
                "n8n_managed_cancelled",
                false,
            )
            .await;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let healthy = tokio::select! {
            biased;
            _ = &mut *cancel => return cleanup_and_fail(
                service,
                &running,
                runner,
                home,
                &id,
                "n8n_managed_cancelled",
                false,
            )
            .await,
            result = tokio::time::timeout(remaining, readiness.health(request.port)) => result.unwrap_or(false),
        };
        if healthy {
            break;
        }
        if Instant::now() >= deadline {
            return cleanup_and_fail(
                service,
                &running,
                runner,
                home,
                &id,
                "n8n_loopback_health_timeout",
                false,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ready_job = match super::publish_adoption_in_job_with_cancel(
        service,
        &running,
        home,
        request.endpoint(),
        api_key,
        probe,
        cancel,
    )
    .await
    {
        Ok(ready) => ready,
        Err(error) => {
            return cleanup_and_fail(
                service,
                &running,
                runner,
                home,
                &id,
                if error.cancelled {
                    "n8n_managed_cancelled"
                } else {
                    error.code
                },
                error.custody_may_exist,
            )
            .await;
        }
    };
    // If this private update fails, durable Ready + exact Bound custody permit
    // the next adapter open to finish it, without removing a Ready container.
    let _ = reconcile_ready_custody(home, &ready_job);
    let _ = crate::config::credentials::Credentials::finish_n8n_adoption_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        ready_job.job_id.as_str(),
    );
    Ok(ready_job)
}

pub(crate) async fn install_managed_at(
    home: &Path,
    request: ManagedN8nRequest,
    api_key: SecretString,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    install_managed_at_with(
        home,
        request,
        api_key,
        &mut DockerManagedRunner,
        &ProductionReadiness,
        &HttpN8nApiProbe,
        cancel,
    )
    .await
}

pub(crate) async fn install_retained_at(
    home: &Path,
    uninstall_id: &super::JobId,
    api_key: SecretString,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    install_retained_at_with(
        home,
        uninstall_id,
        api_key,
        &mut DockerManagedRunner,
        &ProductionReadiness,
        &HttpN8nApiProbe,
        cancel,
    )
    .await
}

pub(crate) async fn install_prepared_managed_in_service(
    service: &IntegrationJobService,
    home: &Path,
    request: ManagedN8nRequest,
    api_key: SecretString,
    cancel: &mut tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<IntegrationJob> {
    managed_restore::reject_pending_restore(home).map_err(anyhow::Error::msg)?;
    install_managed_in_service_with(
        service,
        home,
        request,
        api_key,
        &mut DockerManagedRunner,
        &ProductionReadiness,
        &HttpN8nApiProbe,
        cancel,
    )
    .await
}

pub(super) trait ManagedRecoveryRunner {
    fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str>;
    fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str>;
    fn remove(&mut self, id: &str) -> Result<bool, &'static str>;
}

struct ProductionRecovery;
impl ManagedRecoveryRunner for ProductionRecovery {
    fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        sync_inspect_named()
    }
    fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        sync_inspect_exact(id)
    }
    fn remove(&mut self, id: &str) -> Result<bool, &'static str> {
        sync_docker_ok(&["docker", "rm", "-f", id])
    }
}

pub(super) fn recover_interrupted_with<R: ManagedRecoveryRunner>(
    home: &Path,
    job: &IntegrationJob,
    runner: &mut R,
) -> Result<super::Sha256Digest, &'static str> {
    let Some(mut binding) = read_binding(home)? else {
        // Queued is durable before the create intent; no process command can
        // precede Running. A missing Running binding remains unproven.
        return if job.state == super::JobState::Queued && is_managed_job(job) {
            Ok(sha256_parts(&[
                "n8n-managed-queued-before-intent",
                job.job_id.as_str(),
                job.manifest_sha256.as_str(),
            ]))
        } else {
            Err("n8n_managed_custody_missing")
        };
    };
    let request = validate_binding(&binding, job)?;
    if binding.phase == RuntimePhase::Ready {
        return Err("n8n_managed_ready_runtime_active");
    }
    if binding.phase == RuntimePhase::AbsentVerified {
        return Ok(absent_digest(&binding));
    }
    if binding.phase == RuntimePhase::CreateIntent && job.state == super::JobState::Queued {
        // Docker is invoked only after `service.start`, so a valid persisted
        // intent tied to the still-Queued job proves no process can exist.
        binding.phase = RuntimePhase::AbsentVerified;
        write_binding(home, &binding)?;
        return Ok(absent_digest(&binding));
    }
    if binding.phase == RuntimePhase::CreateIntent {
        match runner.inspect_named()? {
            InspectOutcome::Absent => {
                binding.phase = RuntimePhase::AbsentVerified;
                write_binding(home, &binding)?;
                return Ok(absent_digest(&binding));
            }
            InspectOutcome::Found(found) => {
                validate_existing_identity(&found, Some(&binding), &request, job)?;
                binding.container_id = Some(found.id);
                binding.phase = RuntimePhase::Bound;
                write_binding(home, &binding)?;
            }
            InspectOutcome::Unknown => return Err("n8n_managed_cleanup_failed"),
        }
    }
    let id = binding
        .container_id
        .as_deref()
        .ok_or("n8n_managed_custody_unbound")?;
    match runner.inspect_exact(id)? {
        InspectOutcome::Absent => {}
        InspectOutcome::Found(found) => {
            validate_existing_identity(&found, Some(&binding), &request, job)?;
            let _ = runner.remove(id);
            if !matches!(runner.inspect_exact(id)?, InspectOutcome::Absent) {
                return Err("n8n_managed_cleanup_failed");
            }
        }
        InspectOutcome::Unknown => return Err("n8n_managed_cleanup_failed"),
    }
    binding.phase = RuntimePhase::AbsentVerified;
    write_binding(home, &binding)?;
    Ok(absent_digest(&binding))
}

pub(crate) fn recover_interrupted(
    home: &Path,
    job: &IntegrationJob,
) -> Result<super::Sha256Digest, &'static str> {
    recover_interrupted_with(home, job, &mut ProductionRecovery)
}

pub(crate) fn finalize_terminal_custody(
    home: &Path,
    job: &IntegrationJob,
) -> Result<(), &'static str> {
    let Some(binding) = read_binding(home)? else {
        return Ok(());
    };
    validate_binding(&binding, job)?;
    if binding.phase != RuntimePhase::AbsentVerified
        || !matches!(
            job.state,
            super::JobState::Failed | super::JobState::Cancelled
        )
    {
        return Err("n8n_managed_custody_finalize_mismatch");
    }
    remove_binding(home)
}

pub(crate) fn reconcile_ready_custody(
    home: &Path,
    job: &IntegrationJob,
) -> Result<(), &'static str> {
    let Some(mut binding) = read_binding(home)? else {
        return Err("n8n_managed_custody_missing");
    };
    validate_binding(&binding, job)?;
    if job.state != super::JobState::Ready
        || !matches!(binding.phase, RuntimePhase::Bound | RuntimePhase::Ready)
    {
        return Err("n8n_managed_ready_custody_mismatch");
    }
    if binding.phase == RuntimePhase::Bound {
        binding.phase = RuntimePhase::Ready;
        write_binding(home, &binding)?;
    }
    Ok(())
}

/// Prove that the currently retained runtime custody belongs to this exact
/// Ready managed-install job and still exposes the configured loopback origin.
/// Historical Ready rows are deliberately insufficient: import is allowed only
/// while the current runtime sidecar retains the exact managed binding.
pub(crate) fn ready_binding_matches(
    home: &Path,
    job: &IntegrationJob,
    endpoint: &LoopbackHttpEndpoint,
) -> Result<bool, &'static str> {
    let Some(binding) = read_binding(home)? else {
        return Ok(false);
    };
    let request = validate_binding(&binding, job)?;
    Ok(job.state == super::JobState::Ready
        && binding.phase == RuntimePhase::Ready
        && request.endpoint() == *endpoint)
}

fn sync_docker_ok(argv: &[&str]) -> Result<bool, &'static str> {
    let args = argv
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    Ok(run_docker_sync(&args)?.succeeded)
}

fn sync_inspect_exact(id: &str) -> Result<InspectOutcome, &'static str> {
    let listed = docker_list_sync(&format!("id={id}"))?;
    let ids: Vec<_> = listed.lines().filter(|line| !line.is_empty()).collect();
    if ids.is_empty() {
        return Ok(InspectOutcome::Absent);
    }
    if ids.len() != 1 || ids[0] != id {
        return Ok(InspectOutcome::Unknown);
    }
    match docker_inspect_sync(id)? {
        Some(found) if found.id == id => Ok(InspectOutcome::Found(found)),
        _ => Ok(InspectOutcome::Unknown),
    }
}

pub(crate) fn sync_inspect_named() -> Result<InspectOutcome, &'static str> {
    let listed = docker_list_sync(&format!("name=^/{MANAGED_CONTAINER_NAME}$"))?;
    let ids: Vec<_> = listed.lines().filter(|line| !line.is_empty()).collect();
    if ids.is_empty() {
        return Ok(InspectOutcome::Absent);
    }
    if ids.len() != 1 {
        return Ok(InspectOutcome::Unknown);
    }
    match docker_inspect_sync(ids[0])? {
        Some(found) => Ok(InspectOutcome::Found(found)),
        None => Ok(InspectOutcome::Unknown),
    }
}

const DOCKER_OUTPUT_LIMIT: usize = 8192;
// Request only the identity fields consumed below. The full inspect document
// includes large runtime and environment metadata unrelated to ownership.
const DOCKER_IDENTITY_FORMAT: &str = r#"[{"Id":{{json .Id}},"Config":{"Image":{{json .Config.Image}},"Labels":{"io.neoth.managed":{{json (index .Config.Labels "io.neoth.managed")}},"io.neoth.n8n-job":{{json (index .Config.Labels "io.neoth.n8n-job")}}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},"HostConfig":{"PortBindings":{{json .HostConfig.PortBindings}}},"Mounts":{{json .Mounts}}}]"#;

fn inspect_command(target: &str) -> Vec<String> {
    vec![
        "docker".into(),
        "container".into(),
        "inspect".into(),
        "--format".into(),
        DOCKER_IDENTITY_FORMAT.into(),
        target.into(),
    ]
}

fn local_docker_host() -> &'static str {
    #[cfg(windows)]
    {
        "npipe:////./pipe/docker_engine"
    }
    #[cfg(not(windows))]
    {
        "unix:///var/run/docker.sock"
    }
}

struct DockerCommandResult {
    succeeded: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    overflow: bool,
}

fn drain_limited<R: Read>(mut reader: R) -> Result<(Vec<u8>, bool), &'static str> {
    let mut retained = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| "n8n_docker_capture_failed")?;
        if count == 0 {
            return Ok((retained, overflow));
        }
        let remaining = DOCKER_OUTPUT_LIMIT.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
        overflow |= count > remaining;
    }
}

fn run_docker_sync(argv: &[String]) -> Result<DockerCommandResult, &'static str> {
    let (program, args) = argv.split_first().ok_or("n8n_empty_docker_command")?;
    let mut child = SyncCommand::new(program)
        .arg("--host")
        .arg(local_docker_host())
        .args(args)
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "n8n_docker_spawn_failed")?;
    let stdout = child.stdout.take().ok_or("n8n_docker_capture_failed")?;
    let stderr = child.stderr.take().ok_or("n8n_docker_capture_failed")?;
    let out_thread = std::thread::spawn(move || drain_limited(stdout));
    let err_thread = std::thread::spawn(move || drain_limited(stderr));
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err("n8n_docker_wait_failed");
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err("n8n_docker_timeout");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let (stdout, out_overflow) = out_thread
        .join()
        .map_err(|_| "n8n_docker_capture_failed")??;
    let (stderr, err_overflow) = err_thread
        .join()
        .map_err(|_| "n8n_docker_capture_failed")??;
    Ok(DockerCommandResult {
        succeeded: status.success(),
        stdout,
        stderr,
        overflow: out_overflow || err_overflow,
    })
}

fn docker_list_sync(filter: &str) -> Result<String, &'static str> {
    let result = run_docker_sync(&[
        "docker".into(),
        "container".into(),
        "ls".into(),
        "-a".into(),
        "--no-trunc".into(),
        "--filter".into(),
        filter.into(),
        "--format".into(),
        "{{.ID}}".into(),
    ])?;
    if !result.succeeded || result.overflow {
        return Err("n8n_docker_inspect_unknown");
    }
    String::from_utf8(result.stdout).map_err(|_| "n8n_docker_non_utf8")
}

fn docker_inspect_sync(id: &str) -> Result<Option<ObservedContainer>, &'static str> {
    let result = run_docker_sync(&inspect_command(id))?;
    if !result.succeeded || result.overflow {
        return Ok(None);
    }
    parse_observed_json(&result.stdout).map(Some).or(Ok(None))
}

fn private_archive_staging_path(destination: &Path) -> Result<PathBuf, &'static str> {
    let parent = destination
        .parent()
        .ok_or("n8n_backup_archive_destination_invalid")?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| "n8n_backup_archive_parent_invalid")?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err("n8n_backup_archive_parent_invalid");
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or("n8n_backup_archive_destination_invalid")?;
    Ok(parent.join(format!(".{name}.n8n-archive-staging")))
}

pub(crate) fn preflight_private_archive_destination(
    destination: &Path,
) -> Result<(), &'static str> {
    // A final path that already exists is knowable before the irreversible
    // Docker copy dispatch. `hard_link` remains the no-clobber protection for
    // a path created after this preflight.
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("n8n_backup_archive_destination_exists"),
        Err(_) => Err("n8n_backup_archive_destination_invalid"),
    }
}

fn open_private_archive_staging(destination: &Path) -> Result<(PathBuf, File), &'static str> {
    let staging = private_archive_staging_path(destination)?;
    preflight_private_archive_destination(destination)?;
    #[cfg(windows)]
    let file = crate::wal::win_native::create_private_file_new(&staging)
        .map_err(|_| "n8n_backup_archive_staging_create_failed")?;
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(&file)
        .map_err(|_| "n8n_backup_archive_staging_create_failed")?;
    #[cfg(not(windows))]
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options
            .open(&staging)
            .map_err(|_| "n8n_backup_archive_staging_create_failed")?
    };
    Ok((staging, file))
}

struct ArchiveTee<R> {
    source: R,
    destination: File,
    hasher: sha2::Sha256,
    archive_bytes: u64,
    max_bytes: u64,
    stream_error: Option<&'static str>,
}

impl<R: Read> ArchiveTee<R> {
    fn finish(self) -> Result<ManagedArchiveReceipt, &'static str> {
        use sha2::Digest;
        self.destination
            .sync_all()
            .map_err(|_| "n8n_backup_archive_sync_failed")?;
        Ok(ManagedArchiveReceipt {
            archive_sha256: format!("{:x}", self.hasher.finalize()),
            archive_bytes: self.archive_bytes,
        })
    }
}

impl<R: Read> Read for ArchiveTee<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = match self.source.read(buffer) {
            Ok(count) => count,
            Err(error) => {
                self.stream_error = Some("n8n_backup_archive_stream_read_failed");
                return Err(error);
            }
        };
        let count_u64 = match u64::try_from(count) {
            Ok(count) => count,
            Err(_) => {
                self.stream_error = Some("n8n_backup_archive_size_invalid");
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        };
        let next_bytes = match self.archive_bytes.checked_add(count_u64) {
            Some(next_bytes) => next_bytes,
            None => {
                self.stream_error = Some("n8n_backup_archive_limit_exceeded");
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
        };
        if next_bytes > self.max_bytes {
            self.stream_error = Some("n8n_backup_archive_limit_exceeded");
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        if count != 0 {
            if let Err(error) = self.destination.write_all(&buffer[..count]) {
                self.stream_error = Some("n8n_backup_archive_stream_write_failed");
                return Err(error);
            }
            use sha2::Digest;
            self.hasher.update(&buffer[..count]);
            self.archive_bytes = next_bytes;
        }
        Ok(count)
    }
}

fn archive_member_path_is_safe(path: &Path, entry_type: tar::EntryType) -> bool {
    let mut saw_normal = false;
    let mut saw_current_directory = false;
    for component in path.components() {
        match component {
            Component::CurDir => saw_current_directory = true,
            Component::Normal(_) => saw_normal = true,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return false,
        }
    }
    saw_normal || (saw_current_directory && entry_type.is_dir())
}

fn drain_archive_padding<R: Read>(tee: &mut ArchiveTee<R>) -> Result<(), &'static str> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = tee
            .read(&mut buffer)
            .map_err(|_| tee.stream_error.unwrap_or("n8n_backup_archive_tar_invalid"))?;
        if count == 0 {
            return Ok(());
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err("n8n_backup_archive_trailing_data");
        }
    }
}

fn stream_private_archive<R: Read>(
    source: R,
    destination: File,
    max_bytes: u64,
) -> Result<ManagedArchiveReceipt, &'static str> {
    if max_bytes == 0 {
        return Err("n8n_backup_archive_limit_invalid");
    }
    use sha2::Digest;
    let tee = ArchiveTee {
        source,
        destination,
        hasher: sha2::Sha256::new(),
        archive_bytes: 0,
        max_bytes,
        stream_error: None,
    };
    let mut archive = tar::Archive::new(tee);
    let validation = (|| -> Result<(), &'static str> {
        let entries = archive
            .entries()
            .map_err(|_| "n8n_backup_archive_tar_invalid")?;
        for entry in entries {
            let mut entry = entry.map_err(|_| "n8n_backup_archive_tar_invalid")?;
            let entry_type = entry.header().entry_type();
            // Docker preserves links by default. A complete managed SQLite
            // backup must not silently turn an outside-volume link into an
            // apparently complete archive, so this slice accepts regular
            // files and directories only.
            if !entry_type.is_file() && !entry_type.is_dir() {
                return Err("n8n_backup_archive_unsafe_member");
            }
            let path = entry
                .path()
                .map_err(|_| "n8n_backup_archive_unsafe_member")?;
            if !archive_member_path_is_safe(&path, entry_type) {
                return Err("n8n_backup_archive_unsafe_member");
            }
            std::io::copy(&mut entry, &mut std::io::sink())
                .map_err(|_| "n8n_backup_archive_tar_invalid")?;
        }
        Ok(())
    })();
    let mut tee = archive.into_inner();
    validation.map_err(|error| tee.stream_error.unwrap_or(error))?;
    drain_archive_padding(&mut tee)?;
    tee.finish()
}

fn publish_private_archive_no_clobber(
    staging: &Path,
    destination: &Path,
) -> Result<(), &'static str> {
    // `hard_link` has create-new semantics: unlike rename it cannot replace a
    // concurrently created destination. The archive remains at its private
    // staging name if publication cannot be proven.
    std::fs::hard_link(staging, destination).map_err(|_| "n8n_backup_archive_publish_failed")?;
    crate::util::atomic_write::sync_parent_directory_required(destination)
        .map_err(|_| "n8n_backup_archive_parent_sync_failed")?;
    std::fs::remove_file(staging).map_err(|_| "n8n_backup_archive_staging_cleanup_failed")?;
    crate::util::atomic_write::sync_parent_directory_required(destination)
        .map_err(|_| "n8n_backup_archive_parent_sync_failed")?;
    Ok(())
}

fn archive_exact_n8n_dir_sync(
    id: &str,
    destination: &Path,
    max_bytes: u64,
) -> Result<ManagedArchiveReceipt, &'static str> {
    if !valid_container_id(id) {
        return Err("n8n_managed_archive_invalid_id");
    }
    if max_bytes == 0 {
        return Err("n8n_backup_archive_limit_invalid");
    }
    let (staging, file) = open_private_archive_staging(destination)?;
    let mut child = SyncCommand::new("docker")
        .arg("--host")
        .arg(local_docker_host())
        .args(["cp", &format!("{id}:/home/node/.n8n/."), "-"])
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "n8n_docker_spawn_failed")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("n8n_backup_archive_capture_failed")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("n8n_backup_archive_capture_failed")?;
    let (archive_tx, archive_rx) = std::sync::mpsc::sync_channel(1);
    let archive_thread = std::thread::spawn(move || {
        let _ = archive_tx.send(stream_private_archive(stdout, file, max_bytes));
    });
    let stderr_thread = std::thread::spawn(move || drain_limited(stderr));
    let deadline = Instant::now() + DEADLINE;
    let mut archive_result = None;
    let status = loop {
        if archive_result.is_none() {
            match archive_rx.try_recv() {
                Ok(result) => {
                    if result.is_err() {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = archive_thread.join();
                        let _ = stderr_thread.join();
                        return result;
                    }
                    archive_result = Some(result);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = archive_thread.join();
                    let _ = stderr_thread.join();
                    return Err("n8n_backup_archive_capture_failed");
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = archive_thread.join();
                let _ = stderr_thread.join();
                return Err("n8n_docker_wait_failed");
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = archive_thread.join();
                let _ = stderr_thread.join();
                return Err("n8n_docker_timeout");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let archive = archive_result.unwrap_or_else(|| {
        archive_rx
            .recv()
            .unwrap_or(Err("n8n_backup_archive_capture_failed"))
    })?;
    archive_thread
        .join()
        .map_err(|_| "n8n_backup_archive_capture_failed")?;
    let (_, stderr_overflow) = stderr_thread
        .join()
        .map_err(|_| "n8n_backup_archive_capture_failed")??;
    if stderr_overflow {
        return Err("n8n_backup_archive_stderr_limit");
    }
    if !status.success() {
        return Err("n8n_backup_archive_command_failed");
    }
    publish_private_archive_no_clobber(&staging, destination)?;
    Ok(archive)
}

pub(crate) struct DockerManagedRunner;
async fn docker(argv: &[String]) -> Result<(bool, String, ManagedCommandReceipt), &'static str> {
    let arguments = argv.to_vec();
    let result = tokio::task::spawn_blocking(move || run_docker_sync(&arguments))
        .await
        .map_err(|_| "n8n_docker_wait_failed")??;
    if result.overflow {
        return Err("n8n_docker_output_limit");
    }
    let stdout = String::from_utf8(result.stdout).map_err(|_| "n8n_docker_non_utf8")?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&result.stderr);
    Ok((
        result.succeeded,
        stdout,
        ManagedCommandReceipt {
            succeeded: result.succeeded,
            output_sha256: format!("{:x}", hasher.finalize()),
        },
    ))
}
fn parse_observed_json(data: &[u8]) -> Result<ObservedContainer, &'static str> {
    let mut rows: Vec<DockerInspect> =
        serde_json::from_slice(data).map_err(|_| "n8n_container_inspect_invalid")?;
    if rows.len() != 1 {
        return Err("n8n_container_inspect_invalid");
    }
    let row = rows.pop().expect("length checked");
    let labels = row.config.labels.ok_or("n8n_container_inspect_invalid")?;
    let managed = labels
        .get(MANAGED_LABEL_KEY)
        .cloned()
        .ok_or("n8n_container_inspect_invalid")?;
    let job = labels
        .get("io.neoth.n8n-job")
        .cloned()
        .ok_or("n8n_container_inspect_invalid")?;
    // Runtime port data is empty for a stopped container. HostConfig is the
    // durable declaration; when runtime data exists it must agree exactly.
    if row.host_config.port_bindings.len() != 1 {
        return Err("n8n_container_inspect_invalid");
    }
    let bindings = row
        .host_config
        .port_bindings
        .get("5678/tcp")
        .and_then(Option::as_ref)
        .ok_or("n8n_container_inspect_invalid")?;
    if bindings.len() != 1 || row.mounts.len() != 1 {
        return Err("n8n_container_inspect_invalid");
    }
    if !row.network_settings.ports.is_empty()
        && row.network_settings.ports != row.host_config.port_bindings
    {
        return Err("n8n_container_inspect_invalid");
    }
    let binding = &bindings[0];
    let host_port = binding
        .host_port
        .parse()
        .map_err(|_| "n8n_container_inspect_invalid")?;
    let mount = &row.mounts[0];
    let volume = mount
        .name
        .as_deref()
        .ok_or("n8n_container_inspect_invalid")?;
    if mount.kind != "volume"
        || !valid_volume_name(volume)
        || mount.destination != "/home/node/.n8n"
    {
        return Err("n8n_container_inspect_invalid");
    }
    Ok(ObservedContainer {
        id: row.id,
        image: row.config.image,
        managed,
        job,
        host_ip: binding.host_ip.clone(),
        host_port,
        volume: volume.into(),
        mount_destination: mount.destination.clone(),
    })
}

async fn inspect_target(target: &str) -> Result<InspectOutcome, &'static str> {
    let (ok, data, _) = docker(&inspect_command(target)).await?;
    if !ok {
        return Ok(InspectOutcome::Unknown);
    }
    parse_observed_json(data.as_bytes())
        .map(InspectOutcome::Found)
        .or(Ok(InspectOutcome::Unknown))
}

async fn inspect_volume_target(name: &str) -> Result<InspectVolumeOutcome, &'static str> {
    if !valid_volume_name(name) {
        return Ok(InspectVolumeOutcome::Unknown);
    }
    let (listed_ok, names, _) = docker(&[
        "docker".into(),
        "volume".into(),
        "ls".into(),
        "--filter".into(),
        format!("name=^{}$", name.replace('.', r"\.")),
        "--format".into(),
        "{{.Name}}".into(),
    ])
    .await?;
    if !listed_ok {
        return Ok(InspectVolumeOutcome::Unknown);
    }
    if let Err(outcome) = volume_listing_matches(name, &names) {
        return Ok(outcome);
    }
    let (ok, data, _) = docker(&[
        "docker".into(),
        "volume".into(),
        "inspect".into(),
        name.into(),
    ])
    .await?;
    if !ok {
        return Ok(InspectVolumeOutcome::Unknown);
    }
    let mut rows: Vec<DockerVolume> =
        serde_json::from_str(&data).map_err(|_| "n8n_volume_inspect_invalid")?;
    if rows.len() != 1 {
        return Ok(InspectVolumeOutcome::Unknown);
    }
    let row = rows.pop().expect("length checked");
    if row.name != name {
        return Ok(InspectVolumeOutcome::Unknown);
    }
    Ok(InspectVolumeOutcome::Found(ObservedVolume {
        name: row.name,
        labels: row.labels.unwrap_or_default(),
    }))
}

fn volume_listing_matches(name: &str, output: &str) -> Result<(), InspectVolumeOutcome> {
    let names: Vec<_> = output
        .lines()
        .filter(|candidate| !candidate.is_empty())
        .collect();
    match names.as_slice() {
        [] => Err(InspectVolumeOutcome::Absent),
        [candidate] if *candidate == name => Ok(()),
        _ => Err(InspectVolumeOutcome::Unknown),
    }
}

#[async_trait]
impl ManagedDockerRunner for DockerManagedRunner {
    async fn inspect_named(&mut self) -> Result<InspectOutcome, &'static str> {
        let (ok, ids, _) = docker(&[
            "docker".into(),
            "container".into(),
            "ls".into(),
            "-a".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("name=^/{MANAGED_CONTAINER_NAME}$"),
            "--format".into(),
            "{{.ID}}".into(),
        ])
        .await?;
        if !ok {
            return Ok(InspectOutcome::Unknown);
        }
        let ids: Vec<_> = ids.lines().filter(|id| !id.is_empty()).collect();
        if ids.is_empty() {
            return Ok(InspectOutcome::Absent);
        }
        if ids.len() != 1 {
            return Ok(InspectOutcome::Unknown);
        }
        match inspect_target(ids[0]).await? {
            InspectOutcome::Found(found) => Ok(InspectOutcome::Found(found)),
            _ => Ok(InspectOutcome::Unknown),
        }
    }
    async fn inspect_exact(&mut self, id: &str) -> Result<InspectOutcome, &'static str> {
        let (ok, ids, _) = docker(&[
            "docker".into(),
            "container".into(),
            "ls".into(),
            "-a".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("id={id}"),
            "--format".into(),
            "{{.ID}}".into(),
        ])
        .await?;
        if !ok {
            return Ok(InspectOutcome::Unknown);
        }
        let ids: Vec<_> = ids
            .lines()
            .filter(|candidate| !candidate.is_empty())
            .collect();
        if ids.is_empty() {
            return Ok(InspectOutcome::Absent);
        }
        if ids.len() != 1 || ids[0] != id {
            return Ok(InspectOutcome::Unknown);
        }
        match inspect_target(id).await? {
            InspectOutcome::Found(found) if found.id == id => Ok(InspectOutcome::Found(found)),
            _ => Ok(InspectOutcome::Unknown),
        }
    }
    async fn running_exact(&mut self, id: &str) -> Result<bool, &'static str> {
        if !valid_container_id(id) {
            return Err("n8n_managed_running_state_invalid_id");
        }
        let (ok, stdout, _) = docker(&[
            "docker".into(),
            "inspect".into(),
            "--format".into(),
            "{{.State.Running}}".into(),
            id.into(),
        ])
        .await?;
        match (ok, stdout.trim()) {
            (true, "true") => Ok(true),
            (true, "false") => Ok(false),
            _ => Err("n8n_managed_running_state_unknown"),
        }
    }
    async fn inspect_volume(&mut self, name: &str) -> Result<InspectVolumeOutcome, &'static str> {
        inspect_volume_target(name).await
    }
    async fn remove_volume(&mut self, name: &str) -> Result<ManagedCommandReceipt, &'static str> {
        if !valid_volume_name(name) {
            return Err("n8n_volume_remove_invalid_name");
        }
        let (_, _, receipt) =
            docker(&["docker".into(), "volume".into(), "rm".into(), name.into()]).await?;
        Ok(receipt)
    }
    async fn create(&mut self, argv: &[String]) -> Result<ManagedCommandReceipt, &'static str> {
        let (_, _, receipt) = docker(argv).await?;
        Ok(receipt)
    }
    async fn create_with_exact_id(
        &mut self,
        argv: &[String],
    ) -> Result<ManagedCreateReceipt, &'static str> {
        let (_, stdout, command) = docker(argv).await?;
        let candidate = stdout.trim();
        Ok(ManagedCreateReceipt {
            command,
            container_id: valid_container_id(candidate).then(|| candidate.to_owned()),
        })
    }
    async fn start_exact(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        if !valid_container_id(id) {
            return Err("n8n_managed_start_invalid_id");
        }
        let (_, _, receipt) = docker(&[
            "docker".into(),
            "container".into(),
            "start".into(),
            id.into(),
        ])
        .await?;
        Ok(receipt)
    }
    async fn stop_exact(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        if !valid_container_id(id) {
            return Err("n8n_managed_stop_invalid_id");
        }
        let (_, _, receipt) = docker(&[
            "docker".into(),
            "container".into(),
            "stop".into(),
            id.into(),
        ])
        .await?;
        Ok(receipt)
    }
    async fn archive_exact_n8n_dir_to_private_file(
        &mut self,
        id: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<ManagedArchiveReceipt, &'static str> {
        let id = id.to_owned();
        let destination = destination.to_owned();
        tokio::task::spawn_blocking(move || {
            archive_exact_n8n_dir_sync(&id, &destination, max_bytes)
        })
        .await
        .map_err(|_| "n8n_docker_wait_failed")?
    }
    async fn extract_private_archive_to_exact_container(
        &mut self,
        archive: &Path,
        expected_sha256: &str,
        expected_bytes: u64,
        id: &str,
    ) -> Result<ManagedArchiveReceipt, &'static str> {
        managed_restore_io::extract_private_archive_to_exact_container(
            archive,
            expected_sha256,
            expected_bytes,
            id,
        )
        .await
    }
    async fn create_restore_volume_exact(
        &mut self,
        job: &crate::integrations::state::JobId,
    ) -> Result<ManagedCommandReceipt, &'static str> {
        let (_, _, receipt) = docker(&managed_restore_candidate::restore_volume_command(job)).await?;
        if !receipt.succeeded {
            return Err("n8n_restore_volume_create_command_failed");
        }
        Ok(receipt)
    }
    async fn inspect_restore_candidate_exact(
        &mut self,
        id: &str,
    ) -> Result<managed_restore_candidate::InspectRestoreCandidateOutcome, &'static str> {
        if !valid_container_id(id) {
            return Err("n8n_restore_candidate_invalid_id");
        }
        let (listed, ids, _) = docker(&[
            "docker".into(),
            "container".into(),
            "ls".into(),
            "-a".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("id={id}"),
            "--format".into(),
            "{{.ID}}".into(),
        ])
        .await?;
        if !listed {
            return Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Unknown);
        }
        let rows: Vec<_> = ids.lines().filter(|value| !value.is_empty()).collect();
        if rows.is_empty() {
            return Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Absent);
        }
        if rows.len() != 1 || rows[0] != id {
            return Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Unknown);
        }
        let (inspected, body, _) = docker(&[
            "docker".into(),
            "container".into(),
            "inspect".into(),
            "--format".into(),
            managed_restore_candidate::CANDIDATE_INSPECT_FORMAT.into(),
            id.into(),
        ])
        .await?;
        if !inspected {
            return Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Unknown);
        }
        match managed_restore_candidate::parse_observed_restore_candidate_json(body.as_bytes()) {
            Ok(found) if found.id == id => {
                Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Found(found))
            }
            _ => Ok(managed_restore_candidate::InspectRestoreCandidateOutcome::Unknown),
        }
    }
    async fn create_restore_candidate_exact(
        &mut self,
        spec: managed_restore_candidate::RestoreCandidateSpec<'_>,
    ) -> Result<ManagedCreateReceipt, &'static str> {
        let command = managed_restore_candidate::restore_candidate_command(spec)?;
        let (_, stdout, receipt) = docker(&command).await?;
        if !receipt.succeeded {
            return Err("n8n_restore_candidate_create_command_failed");
        }
        let id = stdout.trim();
        Ok(ManagedCreateReceipt {
            command: receipt,
            container_id: valid_container_id(id).then(|| id.to_owned()),
        })
    }
    async fn remove(&mut self, id: &str) -> Result<ManagedCommandReceipt, &'static str> {
        let (_, _, receipt) =
            docker(&["docker".into(), "rm".into(), "-f".into(), id.into()]).await?;
        Ok(receipt)
    }
}

#[cfg(test)]
#[path = "managed_runtime_tests.rs"]
mod tests;

#[cfg(test)]
mod docker_adapter_tests {
    use super::*;
    use std::io::Cursor;

    fn regular_tar_bytes() -> Vec<u8> {
        let payload = b"opaque\0tar\xff";
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o600);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "database.sqlite", &payload[..])
                .expect("regular tar entry");
            builder.finish().expect("tar finish");
        }
        bytes
    }

    fn symlink_tar_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o600);
            builder
                .append_link(
                    &mut header,
                    "external.sqlite",
                    "/outside-volume/database.sqlite",
                )
                .expect("symlink tar entry");
            builder.finish().expect("tar finish");
        }
        bytes
    }

    fn root_directory_tar_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut root = tar::Header::new_gnu();
            root.set_entry_type(tar::EntryType::Directory);
            root.set_size(0);
            root.set_mode(0o700);
            root.set_path(".").expect("root path");
            root.set_cksum();
            builder
                .append(&root, std::io::empty())
                .expect("root tar entry");
            let payload = b"sqlite";
            let mut file = tar::Header::new_gnu();
            file.set_size(payload.len() as u64);
            file.set_mode(0o600);
            file.set_cksum();
            builder
                .append_data(&mut file, "database.sqlite", &payload[..])
                .expect("regular tar entry");
            builder.finish().expect("tar finish");
        }
        bytes
    }

    fn inspect(network_ports: &str, host_bindings: &str) -> Vec<u8> {
        format!(r#"[{{
          "Id":"exact-container-id",
          "Config":{{"Image":"{image}","Labels":{{"io.neoth.managed":"n8n","io.neoth.n8n-job":"job-1"}}}},
          "NetworkSettings":{{"Ports":{network_ports}}},
          "HostConfig":{{"PortBindings":{host_bindings}}},
          "Mounts":[{{"Type":"volume","Name":"neoth_n8n_data","Destination":"/home/node/.n8n"}}]
        }}]"#, image = N8N_OCI_REFERENCE).into_bytes()
    }

    #[test]
    fn stopped_container_uses_host_config_port_binding_for_exact_identity() {
        let bytes = inspect(
            "{}",
            r#"{"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5678"}]}"#,
        );
        let found = parse_observed_json(&bytes).expect("stopped owned container is inspectable");
        assert_eq!(found.host_ip, "127.0.0.1");
        assert_eq!(found.host_port, 5678);
    }

    #[test]
    fn running_network_binding_must_match_durable_host_config() {
        let ports = r#"{"5678/tcp":[{"HostIp":"0.0.0.0","HostPort":"5678"}]}"#;
        let host = r#"{"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5678"}]}"#;
        assert!(parse_observed_json(&inspect(ports, host)).is_err());
    }

    #[test]
    fn extra_host_port_is_rejected_before_ownership_is_granted() {
        let host = r#"{"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5678"}],"443/tcp":[{"HostIp":"127.0.0.1","HostPort":"443"}]}"#;
        assert!(parse_observed_json(&inspect("{}", host)).is_err());
    }

    #[test]
    fn extra_mount_is_rejected_before_ownership_is_granted() {
        let bytes = String::from_utf8(inspect(
            "{}",
            r#"{"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5678"}]}"#,
        ))
        .expect("test JSON");
        let bytes = bytes.replace(
            r#""Mounts":[{"Type":"volume","Name":"neoth_n8n_data","Destination":"/home/node/.n8n"}]"#,
            r#""Mounts":[{"Type":"volume","Name":"neoth_n8n_data","Destination":"/home/node/.n8n"},{"Type":"volume","Name":"other","Destination":"/tmp/other"}]"#,
        );
        assert!(parse_observed_json(bytes.as_bytes()).is_err());
    }

    #[test]
    fn private_archive_stream_counts_and_hashes_opaque_bytes() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, file) = open_private_archive_staging(&destination).expect("private staging");
        let bytes = regular_tar_bytes();
        let receipt = stream_private_archive(Cursor::new(bytes.clone()), file, 64 * 1024)
            .expect("bounded stream");
        use sha2::Digest;
        let expected_sha256 = format!("{:x}", sha2::Sha256::digest(&bytes));
        assert_eq!(receipt.archive_bytes, bytes.len() as u64);
        assert_eq!(receipt.archive_sha256, expected_sha256);
        assert_eq!(std::fs::read(staging).expect("staging bytes"), bytes);
    }

    #[test]
    fn private_archive_stream_refuses_cap_before_unbounded_write() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, file) = open_private_archive_staging(&destination).expect("private staging");
        assert_eq!(
            stream_private_archive(Cursor::new(regular_tar_bytes()), file, 9),
            Err("n8n_backup_archive_limit_exceeded")
        );
        assert!(
            staging.exists(),
            "untrusted staging remains private for recovery"
        );
        assert!(!destination.exists(), "over-cap stream is never published");
    }

    #[test]
    fn private_archive_stream_refuses_symlinked_outside_volume_data() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, file) = open_private_archive_staging(&destination).expect("private staging");
        assert_eq!(
            stream_private_archive(Cursor::new(symlink_tar_bytes()), file, 64 * 1024),
            Err("n8n_backup_archive_unsafe_member")
        );
        assert!(
            staging.exists(),
            "unsafe archive stays untrusted and unpublished"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn private_archive_stream_accepts_docker_style_current_directory_root() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, file) = open_private_archive_staging(&destination).expect("private staging");
        let bytes = root_directory_tar_bytes();
        let receipt = stream_private_archive(Cursor::new(bytes.clone()), file, 64 * 1024)
            .expect("current directory root is a safe directory member");
        assert_eq!(receipt.archive_bytes, bytes.len() as u64);
        assert_eq!(std::fs::read(staging).expect("staging bytes"), bytes);
    }

    #[test]
    fn private_archive_stream_rejects_nonzero_data_after_tar_end() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, file) = open_private_archive_staging(&destination).expect("private staging");
        let mut bytes = regular_tar_bytes();
        bytes.extend_from_slice(b"unexpected-second-stream");
        assert_eq!(
            stream_private_archive(Cursor::new(bytes), file, 64 * 1024),
            Err("n8n_backup_archive_trailing_data")
        );
        assert!(
            staging.exists(),
            "unsafe trailing data is retained only as staging"
        );
        assert!(!destination.exists());
    }

    #[test]
    fn private_archive_publish_never_replaces_existing_destination() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        let (staging, mut file) =
            open_private_archive_staging(&destination).expect("private staging");
        file.write_all(b"new archive").expect("staging write");
        file.sync_all().expect("staging sync");
        drop(file);
        std::fs::write(&destination, b"preexisting").expect("racing destination");
        assert_eq!(
            publish_private_archive_no_clobber(&staging, &destination),
            Err("n8n_backup_archive_publish_failed")
        );
        assert_eq!(
            std::fs::read(&destination).expect("existing bytes"),
            b"preexisting"
        );
        assert!(staging.exists(), "failed publish retains private staging");
    }

    #[test]
    fn archive_rejects_non_exact_container_id_before_private_file_creation() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        assert_eq!(
            archive_exact_n8n_dir_sync("not-an-exact-id", &destination, 64),
            Err("n8n_managed_archive_invalid_id")
        );
        assert!(!destination.exists());
        assert!(!home.path().join(".backup.tar.n8n-archive-staging").exists());
    }

    #[test]
    fn archive_rejects_known_destination_collision_before_staging_or_docker() {
        let home = tempfile::tempdir().expect("temporary archive parent");
        let destination = home.path().join("backup.tar");
        std::fs::write(&destination, b"existing archive").expect("existing destination");
        assert_eq!(
            archive_exact_n8n_dir_sync(&"a".repeat(64), &destination, 64),
            Err("n8n_backup_archive_destination_exists")
        );
        assert_eq!(
            std::fs::read(&destination).expect("existing bytes"),
            b"existing archive"
        );
        assert!(
            !home.path().join(".backup.tar.n8n-archive-staging").exists(),
            "known destination collision creates no staging file before Docker dispatch"
        );
    }
}
