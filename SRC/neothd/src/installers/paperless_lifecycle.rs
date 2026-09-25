//! Managed Paperless install lifecycle.
//!
//! An install receipt is emitted only after one local Docker engine, the
//! rendered Compose root, and the authenticated loopback API have remained
//! bound to the same owned instance for the whole operation.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

#[path = "paperless_operation_lock.rs"]
mod paperless_operation_lock;

#[cfg(windows)]
use crate::connectors::local_import::{
    ApprovedImportFile, ApprovedImportRoot, approve_import_root, hold_approved_import_file,
};
use crate::{
    config::{SecretsBackend, credentials::Credentials},
    installers::{
        paperless_bootstrap::{self, BootstrapAdmin},
        paperless_readiness::probe_configured_paperless_at,
        paperless_staging::{self, OwnedPaperlessRoot, PaperlessStagingStatus},
    },
    secret::SecretString,
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const READINESS_DEADLINE: Duration = Duration::from_secs(45);
const READINESS_RETRY: Duration = Duration::from_secs(1);
const OUTPUT_LIMIT: usize = 32 * 1024;
const ENV_LIMIT: usize = 16 * 1024;
const PAPERLESS_INTERPOLATION_ENV: [&str; 7] = [
    "PAPERLESS_SECRET_KEY",
    "PAPERLESS_DB_NAME",
    "PAPERLESS_DB_USER",
    "PAPERLESS_DB_PASSWORD",
    "PAPERLESS_ADMIN_USER",
    "PAPERLESS_ADMIN_PASSWORD",
    "PAPERLESS_BIND_PORT",
];
const COMPOSE_CONFIGURATION_ENV: [&str; 16] = [
    "COMPOSE_ANSI",
    "COMPOSE_BAKE",
    "COMPOSE_COMPATIBILITY",
    "COMPOSE_CONVERT_WINDOWS_PATHS",
    "COMPOSE_DISABLE_ENV_FILE",
    "COMPOSE_ENV_FILES",
    "COMPOSE_EXPERIMENTAL",
    "COMPOSE_FILE",
    "COMPOSE_IGNORE_ORPHANS",
    "COMPOSE_MENU",
    "COMPOSE_PARALLEL_LIMIT",
    "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_PROFILES",
    "COMPOSE_PROGRESS",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_STATUS_STDOUT",
];
const OS_LAUNCH_ENV: [&str; 13] = [
    "APPDATA",
    "HOME",
    "LOCALAPPDATA",
    "LOGNAME",
    "PATH",
    "PATHEXT",
    "SHELL",
    "SystemRoot",
    "TMP",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "WINDIR",
];
const RECEIPT_NAME: &str = ".neoth-paperless-lifecycle-receipt.v1.json";
const RECEIPT_DIR: &str = "state";
const UNINSTALL_RECEIPT_NAME: &str = ".neoth-paperless-uninstall-custody.v1.json";
const RECEIPT_READ_LIMIT: usize = 64 * 1024;
const OPERATIONS_LOCK_NAME: &str = ".neoth-paperless-operations.lock";
const RECEIPT_BYTES: &str =
    include_str!("../../../../docs/verification/paperless-oci-v3.2.1/recursive-blob-receipt.json");
const IMAGE_INSPECT_TEMPLATE: &str = r#"{{printf "{\"Id\":%q,\"RepoDigests\":%s,\"Os\":%q,\"Architecture\":%q}" .Id (json .RepoDigests) .Os .Architecture}}"#;
const CONTAINER_INSPECT_TEMPLATE: &str = r#"{{printf "{\"Id\":%q,\"Image\":%q,\"State\":{\"Running\":%t},\"Config\":{\"Labels\":%s},\"NetworkSettings\":{\"Ports\":%s},\"Mounts\":%s}" .Id .Image .State.Running (json .Config.Labels) (json .NetworkSettings.Ports) (json .Mounts)}}"#;
const VOLUME_INSPECT_TEMPLATE: &str =
    r#"{{printf "{\"Name\":%q,\"Labels\":%s}" .Name (json .Labels)}}"#;
const VOLUME_LIST_TEMPLATE: &str = "{{.Name}}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    NotPrepared,
    UnownedOrMismatch,
    LegacyStateMigrationRequired,
    Credentials,
    Receipt,
    LaunchBinding,
    Engine(&'static str),
    Command(&'static str),
    Image(&'static str),
    Container(&'static str),
    Readiness,
    Bootstrap(&'static str),
    Io,
}
impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPrepared => "paperless_not_prepared",
            Self::UnownedOrMismatch => "paperless_unowned_or_mismatch",
            Self::LegacyStateMigrationRequired => "paperless_legacy_state_migration_required",
            Self::Credentials => "paperless_loopback_credentials_required",
            Self::Receipt => "paperless_provenance_receipt_invalid",
            Self::LaunchBinding => "paperless_compose_external_launch_unavailable",
            Self::Engine(x)
            | Self::Command(x)
            | Self::Image(x)
            | Self::Container(x)
            | Self::Bootstrap(x) => x,
            Self::Readiness => "paperless_authenticated_readiness_failed",
            Self::Io => "paperless_lifecycle_io_error",
        })
    }
}
impl std::error::Error for LifecycleError {}

#[derive(Debug, Clone, Serialize)]
pub struct PaperlessLifecycleReceipt {
    pub schema_version: u8,
    pub operation: &'static str,
    pub contract_id: &'static str,
    pub project: String,
    pub loopback_port: u16,
    pub images: Vec<VerifiedImage>,
    pub containers: Vec<VerifiedContainer>,
    pub volumes: Vec<VerifiedVolume>,
    pub authenticated_api_ready: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct StoredPaperlessInstallReceipt {
    schema_version: u8,
    operation: String,
    contract_id: String,
    project: String,
    loopback_port: u16,
    images: Vec<StoredVerifiedImage>,
    containers: Vec<StoredVerifiedContainer>,
    volumes: Vec<StoredVerifiedVolume>,
    authenticated_api_ready: bool,
}
#[derive(Debug, Clone, Deserialize)]
struct StoredVerifiedImage {
    service: String,
    reference: String,
    repo_digest: String,
    config_id: String,
    os: String,
    architecture: String,
}
#[derive(Debug, Clone, Deserialize)]
struct StoredVerifiedContainer {
    service: String,
    id: String,
    image_id: String,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct StoredVerifiedVolume {
    logical_name: String,
    name: String,
    project: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaperlessUninstallPhase {
    Prepared,
    RemoveDispatched,
    ContainersRemoved,
    Complete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperlessUninstallReceipt {
    pub schema_version: u8,
    pub operation: String,
    pub project: String,
    pub phase: PaperlessUninstallPhase,
    pub containers: Vec<PaperlessUninstallContainer>,
    pub retained_volumes: Vec<String>,
    pub network_retained: bool,
    #[serde(default)]
    pub original_container_ids: Vec<String>,
    #[serde(default)]
    pub dispatched_id: Option<String>,
    #[serde(default)]
    pub install_receipt_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperlessUninstallContainer {
    pub service: String,
    pub id: String,
    pub removed: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedImage {
    pub service: &'static str,
    pub reference: &'static str,
    pub repo_digest: String,
    pub config_id: String,
    pub os: String,
    pub architecture: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedContainer {
    pub service: &'static str,
    pub id: String,
    pub image_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedVolume {
    pub logical_name: &'static str,
    pub name: String,
    pub project: String,
}

#[derive(Deserialize)]
struct AdmissionReceipt {
    artifact_blob_bytes_verified: bool,
    selectors: Vec<Selector>,
}
#[derive(Deserialize)]
struct Selector {
    name: String,
    index: Index,
    platforms: BTreeMap<String, Platform>,
}
#[derive(Deserialize)]
struct Index {
    digest: String,
}
#[derive(Deserialize)]
struct Platform {
    config: Config,
}
#[derive(Deserialize)]
struct Config {
    digest: String,
}
#[derive(Deserialize)]
struct DockerImage {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Vec<String>,
    #[serde(rename = "Os")]
    os: String,
    #[serde(rename = "Architecture")]
    architecture: String,
}
#[derive(Deserialize)]
struct DockerServer {
    #[serde(rename = "Os")]
    os: String,
    #[serde(rename = "Arch")]
    architecture: String,
}
#[derive(Deserialize)]
struct DockerContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Config")]
    config: ContainerConfig,
    #[serde(rename = "State")]
    state: ContainerState,
    #[serde(rename = "NetworkSettings")]
    network: NetworkSettings,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<DockerMount>,
}
#[derive(Deserialize)]
struct DockerMount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Destination")]
    destination: String,
}
#[derive(Deserialize)]
struct ContainerState {
    #[serde(rename = "Running")]
    running: bool,
}
#[derive(Deserialize)]
struct ContainerConfig {
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Ports", default)]
    ports: BTreeMap<String, Option<Vec<PortBinding>>>,
}
#[derive(Deserialize)]
struct PortBinding {
    #[serde(rename = "HostIp")]
    host_ip: String,
    #[serde(rename = "HostPort")]
    host_port: String,
}
#[derive(Deserialize)]
struct DockerVolume {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
}

#[async_trait]
pub trait ComposeExecutor: Send {
    async fn run(&mut self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError>;
}
#[async_trait]
trait RetainedComposeExecutor: ComposeExecutor {
    async fn run_retained(
        &mut self,
        argv: &[String],
        root: &OwnedPaperlessRoot,
        binding: &EnvBinding,
    ) -> Result<CommandOutput, LifecycleError>;
}
pub struct DockerExecutor;
#[async_trait]
trait ReadinessVerifier: Send + Sync {
    async fn ready(&self, home: &Path, credentials: &Credentials) -> bool;
}
struct ConfiguredReadiness;
#[async_trait]
impl ReadinessVerifier for ConfiguredReadiness {
    async fn ready(&self, home: &Path, credentials: &Credentials) -> bool {
        probe_configured_paperless_at(home, credentials)
            .await
            .authenticated_api_ready
    }
}
#[async_trait]
impl ComposeExecutor for DockerExecutor {
    async fn run(&mut self, argv: &[String], cwd: &Path) -> Result<CommandOutput, LifecycleError> {
        let (program, args) = argv
            .split_first()
            .ok_or(LifecycleError::Command("paperless_empty_command"))?;
        let mut command = configured_docker_command(program, args, cwd);
        let mut child = command
            .spawn()
            .map_err(|_| LifecycleError::Command("paperless_command_spawn_failed"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(LifecycleError::Command("paperless_command_capture_failed"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(LifecycleError::Command("paperless_command_capture_failed"))?;
        tokio::time::timeout(COMMAND_TIMEOUT, async move {
            let (stdout, stderr, status) = tokio::join!(
                read_bounded(&mut stdout),
                read_bounded(&mut stderr),
                child.wait()
            );
            let stdout = stdout?;
            let _ = stderr?;
            if !status
                .map_err(|_| LifecycleError::Command("paperless_command_wait_failed"))?
                .success()
            {
                return Err(LifecycleError::Command("paperless_command_failed"));
            }
            String::from_utf8(stdout)
                .map(|stdout| CommandOutput { stdout })
                .map_err(|_| LifecycleError::Command("paperless_command_non_utf8"))
        })
        .await
        .map_err(|_| LifecycleError::Command("paperless_command_timeout"))?
    }
}
#[async_trait]
impl RetainedComposeExecutor for DockerExecutor {
    async fn run_retained(
        &mut self,
        argv: &[String],
        root: &OwnedPaperlessRoot,
        binding: &EnvBinding,
    ) -> Result<CommandOutput, LifecycleError> {
        self.run_retained_owned(argv, root, binding).await
    }
}

impl DockerExecutor {
    async fn run_retained_owned(
        &mut self,
        argv: &[String],
        root: &OwnedPaperlessRoot,
        binding: &EnvBinding,
    ) -> Result<CommandOutput, LifecycleError> {
        let (program, args) = argv
            .split_first()
            .ok_or(LifecycleError::Command("paperless_empty_command"))?;
        let mut command = configured_docker_command(program, args, &root.display);
        for (name, value) in compose_environment(binding)? {
            command.env(name, value);
        }
        let mut child =
            crate::updater::process_containment::ContainedChild::spawn_in_retained_directory(
                command,
                &root.root,
                &root.display,
                paperless_staging::expected_compose_bytes(),
                OUTPUT_LIMIT,
            )
            .await
            .map_err(|_| LifecycleError::Command("paperless_command_spawn_failed"))?;
        let output = child
            .wait_until(std::time::Instant::now() + COMMAND_TIMEOUT)
            .await
            .map_err(|_| LifecycleError::Command("paperless_command_timeout"))?;
        if !output.status.success() {
            return Err(LifecycleError::Command("paperless_command_failed"));
        }
        String::from_utf8(output.stdout)
            .map(|stdout| CommandOutput { stdout })
            .map_err(|_| LifecycleError::Command("paperless_command_non_utf8"))
    }
}

fn configured_docker_command(program: &str, args: &[String], cwd: &Path) -> Command {
    let mut command = Command::new(program);
    command.args(args).current_dir(cwd).env_clear();
    for name in OS_LAUNCH_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_DEFAULT_PLATFORM");
    for name in PAPERLESS_INTERPOLATION_ENV {
        command.env_remove(name);
    }
    for name in COMPOSE_CONFIGURATION_ENV {
        command.env_remove(name);
    }
    command
        .env("COMPOSE_DISABLE_ENV_FILE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}
async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, LifecycleError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|_| LifecycleError::Command("paperless_command_capture_failed"))?;
        if n == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(n) > OUTPUT_LIMIT {
            return Err(LifecycleError::Command("paperless_command_output_limit"));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

pub async fn install_at(
    home: &Path,
    credentials: &Credentials,
) -> Result<PaperlessLifecycleReceipt, LifecycleError> {
    install_at_with_readiness(home, credentials, &mut DockerExecutor, &ConfiguredReadiness).await
}
pub async fn install_at_with<E: ComposeExecutor>(
    home: &Path,
    credentials: &Credentials,
    _executor: &mut E,
) -> Result<PaperlessLifecycleReceipt, LifecycleError> {
    let _ = (home, credentials);
    Err(LifecycleError::LaunchBinding)
}
async fn install_at_with_readiness<E: RetainedComposeExecutor, R: ReadinessVerifier>(
    home: &Path,
    credentials: &Credentials,
    executor: &mut E,
    readiness: &R,
) -> Result<PaperlessLifecycleReceipt, LifecycleError> {
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    match paperless_staging::inspect_at(&root_path).status {
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared => {}
        PaperlessStagingStatus::NotPrepared => return Err(LifecycleError::NotPrepared),
        PaperlessStagingStatus::UnownedOrMismatch => return Err(LifecycleError::UnownedOrMismatch),
    }
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let binding = read_binding(&owned)?;
    reject_legacy_state(&owned)?;
    compose_environment(&binding)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _operation_lock =
        paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
            .map_err(map_operation_lock_error)?;
    if let Some(custody) = read_uninstall_receipt(&owned)?
        && custody.phase != PaperlessUninstallPhase::Complete
    {
        return Err(LifecycleError::Command("paperless_uninstall_in_progress"));
    }
    let bootstrap_backend = valid_token(credentials.paperless_token.as_ref())
        .is_none()
        .then(|| configured_backend(home))
        .transpose()?;
    let expected = expected_images()?;
    let project = project_name(&root_path);
    let engine = select_local_engine(executor, &owned).await?;
    preflight_existing_volumes(executor, &engine, &project, &owned, &binding).await?;
    for image in &expected {
        ensure_stage(&owned, &binding)?;
        executor
            .run(&engine.docker("pull", &[image.reference]), &root_path)
            .await?;
        ensure_stage(&owned, &binding)?;
    }
    let mut verified = Vec::with_capacity(expected.len());
    for image in &expected {
        ensure_stage(&owned, &binding)?;
        let result = executor
            .run(
                &engine.docker(
                    "image",
                    &[
                        "inspect",
                        image.reference,
                        "--format",
                        IMAGE_INSPECT_TEMPLATE,
                    ],
                ),
                &root_path,
            )
            .await?;
        ensure_stage(&owned, &binding)?;
        verified.push(verify_image(image, &engine.platform, &result.stdout)?);
    }
    ensure_stage(&owned, &binding)?;
    executor
        .run_retained(
            &engine.compose(&project, &["up", "-d", "--no-build", "--pull", "never"]),
            &owned,
            &binding,
        )
        .await?;
    ensure_stage(&owned, &binding)?;
    let mut containers = Vec::with_capacity(verified.len());
    for image in &verified {
        ensure_stage(&owned, &binding)?;
        let raw_id = executor
            .run_retained(
                &engine.compose(&project, &["ps", "-q", image.service]),
                &owned,
                &binding,
            )
            .await?
            .stdout;
        let id = exact_identifier(&raw_id)
            .ok_or(LifecycleError::Container("paperless_container_id_missing"))?;
        ensure_stage(&owned, &binding)?;
        let result = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root_path,
            )
            .await?;
        ensure_stage(&owned, &binding)?;
        let observed = verify_container(image, &project, binding.port, &result.stdout)?;
        if observed.id != id {
            return Err(LifecycleError::Container("paperless_container_id_changed"));
        }
        containers.push(observed);
    }
    let volumes = inspect_owned_volumes(executor, &engine, &project, &owned, &binding).await?;
    let effective = match valid_token(credentials.paperless_token.as_ref()) {
        Some(token) => token.clone(),
        None => {
            let token = obtain_bootstrap_token(&owned, &binding).await?;
            ensure_stage(&owned, &binding)?;
            paperless_bootstrap::persist_bootstrap_at(
                home,
                bootstrap_backend.ok_or(LifecycleError::Bootstrap(
                    "paperless_bootstrap_config_invalid",
                ))?,
                credentials.paperless_url.as_deref(),
                &binding.origin,
                &token,
            )
            .map_err(LifecycleError::Bootstrap)?;
            token
        }
    };
    let mut readiness_credentials = credentials.clone();
    readiness_credentials.paperless_url = Some(binding.origin.clone());
    readiness_credentials.paperless_token = Some(effective);
    wait_for_readiness(home, &readiness_credentials, readiness, &owned, &binding).await?;
    for container in &containers {
        ensure_stage(&owned, &binding)?;
        let result = executor
            .run(
                &engine.docker(
                    "container",
                    &[
                        "inspect",
                        &container.id,
                        "--format",
                        CONTAINER_INSPECT_TEMPLATE,
                    ],
                ),
                &root_path,
            )
            .await?;
        ensure_stage(&owned, &binding)?;
        let image = verified
            .iter()
            .find(|image| image.service == container.service)
            .ok_or(LifecycleError::Container(
                "paperless_container_service_missing",
            ))?;
        let observed = verify_container(image, &project, binding.port, &result.stdout)?;
        if observed.id != container.id {
            return Err(LifecycleError::Container("paperless_container_id_changed"));
        }
    }
    let final_volumes =
        inspect_owned_volumes(executor, &engine, &project, &owned, &binding).await?;
    if final_volumes != volumes {
        return Err(LifecycleError::Container(
            "paperless_volume_changed_after_readiness",
        ));
    }
    ensure_stage(&owned, &binding)?;
    let receipt = PaperlessLifecycleReceipt {
        schema_version: 1,
        operation: "install",
        contract_id: paperless_staging::OCI_CONTRACT_ID,
        project,
        loopback_port: binding.port,
        images: verified,
        containers,
        volumes,
        authenticated_api_ready: true,
    };
    write_receipt(&owned, &receipt)?;
    Ok(receipt)
}

/// Read the durable safe-uninstall custody without selecting Docker, probing
/// Paperless, acquiring a launch lease, or mutating the staged root.
pub fn uninstall_status_at(
    home: &Path,
) -> Result<Option<PaperlessUninstallReceipt>, LifecycleError> {
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    match paperless_staging::inspect_at(&root_path).status {
        PaperlessStagingStatus::NotPrepared => Ok(None),
        PaperlessStagingStatus::UnownedOrMismatch => Err(LifecycleError::UnownedOrMismatch),
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared => {
            let owned = paperless_staging::open_owned_root_at(&root_path)
                .map_err(|_| LifecycleError::UnownedOrMismatch)?;
            read_uninstall_receipt(&owned)
        }
    }
}
/// Remove only the exact container IDs recorded by the original successful
/// install receipt. Data volumes, staged files, credentials, and networks are
/// deliberately retained; destructive purge is a separate confirmed operation.
pub async fn uninstall_at(
    home: &Path,
    credentials: &Credentials,
) -> Result<PaperlessUninstallReceipt, LifecycleError> {
    uninstall_at_with(home, credentials, &mut DockerExecutor).await
}

pub async fn uninstall_at_with<E: ComposeExecutor>(
    home: &Path,
    credentials: &Credentials,
    executor: &mut E,
) -> Result<PaperlessUninstallReceipt, LifecycleError> {
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    match paperless_staging::inspect_at(&root_path).status {
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared => {}
        PaperlessStagingStatus::NotPrepared => return Err(LifecycleError::NotPrepared),
        PaperlessStagingStatus::UnownedOrMismatch => return Err(LifecycleError::UnownedOrMismatch),
    }
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let binding = read_binding(&owned)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _operation_lock =
        paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
            .map_err(map_operation_lock_error)?;
    let (installed_bytes, installed) = read_install_receipt_with_bytes(&owned)?;
    validate_install_receipt(&installed, &root_path)?;
    let install_receipt_sha256 = format!("{:x}", Sha256::digest(&installed_bytes));
    let mut custody =
        read_uninstall_receipt(&owned)?.unwrap_or_else(|| PaperlessUninstallReceipt {
            schema_version: 1,
            operation: "paperless.safe_uninstall".to_owned(),
            project: installed.project.clone(),
            phase: PaperlessUninstallPhase::Prepared,
            containers: installed
                .containers
                .iter()
                .map(|container| PaperlessUninstallContainer {
                    service: container.service.clone(),
                    id: container.id.clone(),
                    removed: false,
                })
                .collect(),
            retained_volumes: Vec::new(),
            network_retained: true,
            original_container_ids: installed
                .containers
                .iter()
                .map(|container| container.id.clone())
                .collect(),
            dispatched_id: None,
            install_receipt_sha256: install_receipt_sha256.clone(),
        });
    let installed_ids: Vec<String> = installed
        .containers
        .iter()
        .map(|container| container.id.clone())
        .collect();
    validate_uninstall_custody(&custody)?;
    if custody.project != installed.project {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    let custody_pairs: std::collections::BTreeSet<_> = custody
        .containers
        .iter()
        .map(|container| (&container.service, &container.id))
        .collect();
    let installed_pairs: std::collections::BTreeSet<_> = installed
        .containers
        .iter()
        .map(|container| (&container.service, &container.id))
        .collect();
    let generation_changed = custody.install_receipt_sha256 != install_receipt_sha256
        || custody.original_container_ids != installed_ids;
    if !generation_changed && custody_pairs != installed_pairs {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    if generation_changed {
        if custody.phase != PaperlessUninstallPhase::Complete
            || custody.install_receipt_sha256 == install_receipt_sha256
            || custody
                .original_container_ids
                .iter()
                .any(|id| installed_ids.contains(id))
        {
            return Err(LifecycleError::UnownedOrMismatch);
        }
        custody = PaperlessUninstallReceipt {
            schema_version: 1,
            operation: "paperless.safe_uninstall".to_owned(),
            project: installed.project.clone(),
            phase: PaperlessUninstallPhase::Prepared,
            containers: installed
                .containers
                .iter()
                .map(|container| PaperlessUninstallContainer {
                    service: container.service.clone(),
                    id: container.id.clone(),
                    removed: false,
                })
                .collect(),
            retained_volumes: Vec::new(),
            network_retained: true,
            original_container_ids: installed_ids.clone(),
            dispatched_id: None,
            install_receipt_sha256: install_receipt_sha256.clone(),
        };
    }
    if custody.operation != "paperless.safe_uninstall"
        || custody.project != installed.project
        || custody.install_receipt_sha256 != install_receipt_sha256
        || custody.original_container_ids != installed_ids
        || custody.containers.len() != installed.containers.len()
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    if custody.phase == PaperlessUninstallPhase::Complete {
        return Ok(custody);
    }
    let engine = select_local_engine(executor, &owned).await?;
    let retained =
        inspect_owned_volumes(executor, &engine, &installed.project, &owned, &binding).await?;
    if retained.len() != paperless_staging::PAPERLESS_VOLUMES.len() {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    for index in 0..custody.containers.len() {
        let item = custody.containers[index].clone();
        let original = installed
            .containers
            .iter()
            .find(|container| container.service == item.service && container.id == item.id)
            .ok_or(LifecycleError::UnownedOrMismatch)?;
        if !exact_container_id(&item.id) {
            return Err(LifecycleError::UnownedOrMismatch);
        }
        if item.removed {
            continue;
        }
        let present =
            exact_container_present(executor, &engine, &item.id, &owned, &binding).await?;
        if custody.phase == PaperlessUninstallPhase::RemoveDispatched {
            if custody.dispatched_id.as_deref() != Some(item.id.as_str()) {
                return Err(LifecycleError::UnownedOrMismatch);
            }
            // A previous dispatch is never repeated. Only observed absence can advance it.
            if !present {
                custody.containers[index].removed = true;
                custody.phase = PaperlessUninstallPhase::Prepared;
                custody.dispatched_id = None;
                write_uninstall_receipt(&owned, &custody)?;
                continue;
            }
            return Err(LifecycleError::Command(
                "paperless_uninstall_remove_outcome_ambiguous",
            ));
        }
        if !present {
            return Err(LifecycleError::Container(
                "paperless_uninstall_original_container_missing",
            ));
        }
        let raw = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &item.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root_path,
            )
            .await?;
        ensure_stage(&owned, &binding)?;
        verify_original_container(
            original,
            &installed.project,
            installed.loopback_port,
            &raw.stdout,
        )?;
        custody.phase = PaperlessUninstallPhase::RemoveDispatched;
        custody.dispatched_id = Some(item.id.clone());
        write_uninstall_receipt(&owned, &custody)?;
        executor
            .run(&engine.docker("rm", &["-f", &item.id]), &root_path)
            .await?;
        ensure_stage(&owned, &binding)?;
        if exact_container_present(executor, &engine, &item.id, &owned, &binding).await? {
            return Err(LifecycleError::Command(
                "paperless_uninstall_remove_outcome_ambiguous",
            ));
        }
        custody.containers[index].removed = true;
        custody.phase = PaperlessUninstallPhase::Prepared;
        custody.dispatched_id = None;
        write_uninstall_receipt(&owned, &custody)?;
    }
    if custody
        .containers
        .iter()
        .any(|container| !container.removed)
    {
        return Err(LifecycleError::Command("paperless_uninstall_incomplete"));
    }
    custody.phase = PaperlessUninstallPhase::ContainersRemoved;
    custody.retained_volumes = retained.into_iter().map(|volume| volume.name).collect();
    write_uninstall_receipt(&owned, &custody)?;
    let final_volumes =
        inspect_owned_volumes(executor, &engine, &installed.project, &owned, &binding).await?;
    if final_volumes
        .iter()
        .map(|volume| &volume.name)
        .collect::<Vec<_>>()
        != custody.retained_volumes.iter().collect::<Vec<_>>()
    {
        return Err(LifecycleError::Container(
            "paperless_uninstall_volume_changed",
        ));
    }
    custody.phase = PaperlessUninstallPhase::Complete;
    write_uninstall_receipt(&owned, &custody)?;
    Ok(custody)
}
fn lifecycle_state_dir(root: &OwnedPaperlessRoot) -> Result<cap_std::fs::Dir, LifecycleError> {
    crate::skills::store::open_real_child_dir(
        &root.root,
        OsStr::new(RECEIPT_DIR),
        &root.display.join(RECEIPT_DIR),
    )
    .map_err(|_| LifecycleError::UnownedOrMismatch)
}
fn map_operation_lock_error(
    error: paperless_operation_lock::PaperlessOperationLockError,
) -> LifecycleError {
    match error {
        paperless_operation_lock::PaperlessOperationLockError::Busy => {
            LifecycleError::Command("paperless_operation_in_progress")
        }
        paperless_operation_lock::PaperlessOperationLockError::Unsafe => {
            LifecycleError::UnownedOrMismatch
        }
        paperless_operation_lock::PaperlessOperationLockError::Io => LifecycleError::Io,
    }
}
fn read_install_receipt_with_bytes(
    root: &OwnedPaperlessRoot,
) -> Result<(Vec<u8>, StoredPaperlessInstallReceipt), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(RECEIPT_NAME),
        &root.display.join(RECEIPT_DIR).join(RECEIPT_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let receipt = serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    Ok((bytes, receipt))
}
fn read_uninstall_receipt(
    root: &OwnedPaperlessRoot,
) -> Result<Option<PaperlessUninstallReceipt>, LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(UNINSTALL_RECEIPT_NAME),
        &root.display.join(RECEIPT_DIR).join(UNINSTALL_RECEIPT_NAME),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => {
            let receipt: PaperlessUninstallReceipt =
                serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
            validate_uninstall_custody(&receipt)?;
            if receipt.project != project_name(&root.display) {
                return Err(LifecycleError::UnownedOrMismatch);
            }
            Ok(Some(receipt))
        }
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn write_uninstall_receipt(
    root: &OwnedPaperlessRoot,
    receipt: &PaperlessUninstallReceipt,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(UNINSTALL_RECEIPT_NAME),
        &root.display.join(RECEIPT_DIR).join(UNINSTALL_RECEIPT_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn validate_install_receipt(
    receipt: &StoredPaperlessInstallReceipt,
    root: &Path,
) -> Result<(), LifecycleError> {
    if receipt.schema_version != 1
        || receipt.operation != "install"
        || receipt.contract_id != paperless_staging::OCI_CONTRACT_ID
        || !receipt.authenticated_api_ready
        || receipt.project != project_name(root)
        || receipt.images.len() != expected_images()?.len()
        || receipt.containers.len() != expected_images()?.len()
        || receipt.volumes.len() != paperless_staging::PAPERLESS_VOLUMES.len()
    {
        return Err(LifecycleError::Receipt);
    }
    for expected in expected_images()? {
        let image = receipt
            .images
            .iter()
            .find(|image| image.service == expected.service)
            .ok_or(LifecycleError::Receipt)?;
        if image.reference != expected.reference
            || image.repo_digest != expected.repo_digest
            || image.config_id.is_empty()
            || image.os.is_empty()
            || image.architecture.is_empty()
        {
            return Err(LifecycleError::Receipt);
        }
        let container = receipt
            .containers
            .iter()
            .find(|container| container.service == expected.service)
            .ok_or(LifecycleError::Receipt)?;
        if !exact_container_id(&container.id) || container.image_id != image.config_id {
            return Err(LifecycleError::Receipt);
        }
    }
    for expected in paperless_staging::PAPERLESS_VOLUMES {
        let volume = receipt
            .volumes
            .iter()
            .find(|volume| volume.logical_name == expected.logical_name)
            .ok_or(LifecycleError::Receipt)?;
        if volume.name != volume_name(&receipt.project, expected.logical_name)
            || volume.project != receipt.project
        {
            return Err(LifecycleError::Receipt);
        }
    }
    Ok(())
}
fn validate_uninstall_custody(custody: &PaperlessUninstallReceipt) -> Result<(), LifecycleError> {
    if custody.schema_version != 1
        || custody.operation != "paperless.safe_uninstall"
        || custody.project.is_empty()
        || custody.install_receipt_sha256.len() != 64
        || !custody
            .install_receipt_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !custody.network_retained
        || custody.original_container_ids.len() != custody.containers.len()
        || custody.containers.is_empty()
    {
        return Err(LifecycleError::Receipt);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut services = std::collections::BTreeSet::new();
    for container in &custody.containers {
        if !exact_container_id(&container.id)
            || !ids.insert(container.id.as_str())
            || !services.insert(container.service.as_str())
            || !custody
                .original_container_ids
                .iter()
                .any(|id| id == &container.id)
        {
            return Err(LifecycleError::Receipt);
        }
    }
    if custody
        .original_container_ids
        .iter()
        .any(|id| !exact_container_id(id))
        || custody
            .original_container_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != custody.original_container_ids.len()
    {
        return Err(LifecycleError::Receipt);
    }
    let expected_services: std::collections::BTreeSet<_> = expected_images()?
        .into_iter()
        .map(|image| image.service)
        .collect();
    if services.len() != expected_services.len()
        || !services
            .iter()
            .all(|service| expected_services.contains(service))
    {
        return Err(LifecycleError::Receipt);
    }
    match custody.phase {
        PaperlessUninstallPhase::Prepared => {
            if custody.dispatched_id.is_some() {
                return Err(LifecycleError::Receipt);
            }
        }
        PaperlessUninstallPhase::RemoveDispatched => {
            if custody.dispatched_id.as_ref().is_none_or(|id| {
                !exact_container_id(id)
                    || !custody
                        .containers
                        .iter()
                        .any(|container| !container.removed && &container.id == id)
            }) {
                return Err(LifecycleError::Receipt);
            }
        }
        PaperlessUninstallPhase::ContainersRemoved => {
            if custody.dispatched_id.is_some()
                || custody
                    .containers
                    .iter()
                    .any(|container| !container.removed)
            {
                return Err(LifecycleError::Receipt);
            }
        }
        PaperlessUninstallPhase::Complete => {
            if custody.dispatched_id.is_some()
                || custody
                    .containers
                    .iter()
                    .any(|container| !container.removed)
                || custody.retained_volumes.len() != paperless_staging::PAPERLESS_VOLUMES.len()
            {
                return Err(LifecycleError::Receipt);
            }
            for volume in paperless_staging::PAPERLESS_VOLUMES {
                if !custody
                    .retained_volumes
                    .iter()
                    .any(|name| name == &volume_name(&custody.project, volume.logical_name))
                {
                    return Err(LifecycleError::Receipt);
                }
            }
        }
    }
    Ok(())
}
fn exact_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
async fn exact_container_present<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    id: &str,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<bool, LifecycleError> {
    ensure_stage(root, binding)?;
    let listed = executor
        .run(
            &engine.docker(
                "container",
                &[
                    "ls",
                    "--all",
                    "--filter",
                    &format!("id={id}"),
                    "--no-trunc",
                    "--format",
                    "{{.ID}}",
                ],
            ),
            &root.display,
        )
        .await?;
    ensure_stage(root, binding)?;
    let output = listed.stdout.trim();
    if output.is_empty() {
        Ok(false)
    } else if output == id {
        Ok(true)
    } else {
        Err(LifecycleError::UnownedOrMismatch)
    }
}
fn verify_original_container(
    expected: &StoredVerifiedContainer,
    project: &str,
    port: u16,
    raw: &str,
) -> Result<(), LifecycleError> {
    let actual: DockerContainer = serde_json::from_str(raw)
        .map_err(|_| LifecycleError::Container("paperless_container_inspect_invalid"))?;
    if actual.id != expected.id
        || actual.image != expected.image_id
        || actual.config.labels.get("com.docker.compose.project") != Some(&project.to_owned())
        || actual.config.labels.get("com.docker.compose.service") != Some(&expected.service)
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    if expected.service == "webserver"
        && !actual
            .network
            .ports
            .get("8000/tcp")
            .and_then(|entry| entry.as_ref())
            .is_some_and(|entries| {
                entries.len() == 1
                    && entries[0].host_ip == "127.0.0.1"
                    && entries[0].host_port == port.to_string()
            })
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    let expected_mounts: Vec<_> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .filter(|volume| volume.service == expected.service)
        .collect();
    if actual.mounts.len() != expected_mounts.len()
        || expected_mounts.iter().any(|volume| {
            !actual.mounts.iter().any(|mount| {
                mount.kind == "volume"
                    && mount.name == volume_name(project, volume.logical_name)
                    && mount.destination == volume.destination
            })
        })
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    Ok(())
}
struct Engine {
    endpoint: String,
    platform: String,
}
impl Engine {
    fn prefix(&self) -> Vec<String> {
        vec![
            "docker".to_owned(),
            "--host".to_owned(),
            self.endpoint.clone(),
        ]
    }
    fn docker(&self, first: &str, rest: &[&str]) -> Vec<String> {
        self.prefix()
            .into_iter()
            .chain(std::iter::once(first.to_owned()))
            .chain(rest.iter().map(|part| (*part).to_owned()))
            .collect()
    }
    fn compose(&self, project: &str, tail: &[&str]) -> Vec<String> {
        self.docker("compose", &["--project-name", project, "-f", "-"])
            .into_iter()
            .chain(tail.iter().map(|part| (*part).to_owned()))
            .collect()
    }
}
async fn select_local_engine<E: ComposeExecutor>(
    executor: &mut E,
    root: &OwnedPaperlessRoot,
) -> Result<Engine, LifecycleError> {
    if std::env::var_os("DOCKER_HOST").is_some() {
        return Err(LifecycleError::Engine(
            "paperless_docker_host_override_rejected",
        ));
    }
    ensure_bound(root)?;
    let context = exact_identifier(
        &executor
            .run(
                &["docker".into(), "context".into(), "show".into()],
                &root.display,
            )
            .await?
            .stdout,
    )
    .ok_or(LifecycleError::Engine("paperless_docker_context_invalid"))?;
    ensure_bound(root)?;
    let endpoint = executor
        .run(
            &[
                "docker".into(),
                "context".into(),
                "inspect".into(),
                context.clone(),
                "--format".into(),
                "{{json .Endpoints.docker.Host}}".into(),
            ],
            &root.display,
        )
        .await?
        .stdout;
    ensure_bound(root)?;
    let endpoint: String = serde_json::from_str(endpoint.trim())
        .map_err(|_| LifecycleError::Engine("paperless_docker_context_endpoint_invalid"))?;
    if !local_docker_endpoint(&endpoint) {
        return Err(LifecycleError::Engine(
            "paperless_remote_docker_context_rejected",
        ));
    }
    let engine = Engine {
        endpoint,
        platform: String::new(),
    };
    let raw = executor
        .run(
            &engine.docker("version", &["--format", "{{json .Server}}"]),
            &root.display,
        )
        .await?
        .stdout;
    ensure_bound(root)?;
    let server: DockerServer = serde_json::from_str(raw.trim())
        .map_err(|_| LifecycleError::Engine("paperless_docker_engine_invalid"))?;
    if server.os != "linux" || !matches!(server.architecture.as_str(), "amd64" | "arm64") {
        return Err(LifecycleError::Engine(
            "paperless_docker_engine_platform_rejected",
        ));
    }
    Ok(Engine {
        platform: format!("{}/{}", server.os, server.architecture),
        ..engine
    })
}

struct EnvBinding {
    port: u16,
    origin: String,
    env: Zeroizing<Vec<u8>>,
}
fn read_binding(root: &OwnedPaperlessRoot) -> Result<EnvBinding, LifecycleError> {
    ensure_bound(root)?;
    let env = Zeroizing::new(
        crate::skills::store::read_regular_file_bounded(
            &root.root,
            OsStr::new("paperless.env"),
            &root.display.join("paperless.env"),
            ENV_LIMIT,
        )
        .map_err(|_| LifecycleError::UnownedOrMismatch)?,
    );
    let port = dotenv_port(env.as_slice())?;
    Ok(EnvBinding {
        port,
        origin: format!("http://127.0.0.1:{port}"),
        env,
    })
}
fn dotenv_port(env: &[u8]) -> Result<u16, LifecycleError> {
    let mut values = paperless_bootstrap::parse_dotenv_values(env, &["PAPERLESS_BIND_PORT"])
        .map_err(|_| LifecycleError::Credentials)?;
    values
        .remove("PAPERLESS_BIND_PORT")
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(LifecycleError::Credentials)
}
fn compose_environment(binding: &EnvBinding) -> Result<Vec<(String, String)>, LifecycleError> {
    let mut values = paperless_bootstrap::parse_dotenv_values(
        binding.env.as_slice(),
        &PAPERLESS_INTERPOLATION_ENV,
    )
    .map_err(|_| LifecycleError::Credentials)?;
    PAPERLESS_INTERPOLATION_ENV
        .iter()
        .map(|name| {
            values
                .remove(name)
                .filter(|value| !value.is_empty())
                .map(|value| ((*name).to_owned(), value.to_string()))
                .ok_or(LifecycleError::Credentials)
        })
        .collect()
}
fn ensure_stage(root: &OwnedPaperlessRoot, expected: &EnvBinding) -> Result<(), LifecycleError> {
    let observed = read_binding(root)?;
    if observed.port == expected.port && observed.env.as_slice() == expected.env.as_slice() {
        Ok(())
    } else {
        Err(LifecycleError::UnownedOrMismatch)
    }
}
fn validate_credentials_origin(
    credentials: &Credentials,
    origin: &str,
) -> Result<(), LifecycleError> {
    match credentials.paperless_url.as_deref() {
        None => Ok(()),
        Some(value) if value == origin => Ok(()),
        _ => Err(LifecycleError::Credentials),
    }
}
fn valid_token(token: Option<&SecretString>) -> Option<&SecretString> {
    token.filter(|token| !token.expose_secret().is_empty() && token.expose_secret().len() <= 4096)
}
fn configured_backend(home: &Path) -> Result<SecretsBackend, LifecycleError> {
    crate::config::load_optional_runtime_config_pair_from_path(&home.join("freedom.yaml"))
        .map(|(config, _)| {
            config
                .map(|config| config.secrets_backend)
                .unwrap_or(SecretsBackend::File)
        })
        .map_err(|_| LifecycleError::Bootstrap("paperless_bootstrap_config_invalid"))
}
async fn wait_for_readiness<R: ReadinessVerifier>(
    home: &Path,
    credentials: &Credentials,
    readiness: &R,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<(), LifecycleError> {
    let deadline = tokio::time::Instant::now() + READINESS_DEADLINE;
    loop {
        ensure_stage(root, binding)?;
        if readiness.ready(home, credentials).await {
            ensure_stage(root, binding)?;
            return Ok(());
        }
        ensure_stage(root, binding)?;
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(LifecycleError::Readiness);
        }
        tokio::time::sleep_until(std::cmp::min(deadline, now + READINESS_RETRY)).await;
    }
}
async fn obtain_bootstrap_token(
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<SecretString, LifecycleError> {
    let deadline = tokio::time::Instant::now() + READINESS_DEADLINE;
    loop {
        ensure_stage(root, binding)?;
        let admin = BootstrapAdmin::from_env_bytes(binding.env.as_slice())
            .map_err(LifecycleError::Bootstrap)?;
        match paperless_bootstrap::obtain_token(&binding.origin, &admin).await {
            Ok(token) => {
                ensure_stage(root, binding)?;
                return Ok(token);
            }
            Err("paperless_bootstrap_transport" | "paperless_bootstrap_timeout")
                if tokio::time::Instant::now() < deadline =>
            {
                ensure_stage(root, binding)?;
                tokio::time::sleep_until(std::cmp::min(
                    deadline,
                    tokio::time::Instant::now() + READINESS_RETRY,
                ))
                .await;
            }
            Err(error) => return Err(LifecycleError::Bootstrap(error)),
        }
    }
}
fn exact_identifier(raw: &str) -> Option<String> {
    let value = raw.strip_suffix('\n').unwrap_or(raw);
    (!value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_whitespace))
        .then(|| value.to_owned())
}
fn project_name(root: &Path) -> String {
    let digest = Sha256::digest(root.as_os_str().to_string_lossy().as_bytes());
    format!("neoth-paperless-{}", hex::encode(digest)[..12].to_owned())
}
struct ExpectedImage {
    service: &'static str,
    reference: &'static str,
    repo_digest: &'static str,
    configs: BTreeMap<String, String>,
}
fn expected_images() -> Result<Vec<ExpectedImage>, LifecycleError> {
    let receipt: AdmissionReceipt =
        serde_json::from_str(RECEIPT_BYTES).map_err(|_| LifecycleError::Receipt)?;
    if !receipt.artifact_blob_bytes_verified {
        return Err(LifecycleError::Receipt);
    }
    [
        ("paperless", "webserver", paperless_staging::PAPERLESS_IMAGE),
        ("valkey", "broker", paperless_staging::VALKEY_IMAGE),
        ("postgres", "db", paperless_staging::POSTGRES_IMAGE),
    ]
    .into_iter()
    .map(|(name, service, reference)| {
        let selector = receipt
            .selectors
            .iter()
            .find(|selector| selector.name == name && reference.ends_with(&selector.index.digest))
            .ok_or(LifecycleError::Receipt)?;
        let configs = selector
            .platforms
            .iter()
            .map(|(platform, detail)| (platform.clone(), detail.config.digest.clone()))
            .collect();
        Ok(ExpectedImage {
            service,
            reference,
            repo_digest: reference,
            configs,
        })
    })
    .collect()
}
fn verify_image(
    expected: &ExpectedImage,
    target_platform: &str,
    raw: &str,
) -> Result<VerifiedImage, LifecycleError> {
    let actual: DockerImage = serde_json::from_str(raw)
        .map_err(|_| LifecycleError::Image("paperless_image_inspect_invalid"))?;
    if !actual
        .repo_digests
        .iter()
        .any(|digest| digest == expected.repo_digest)
    {
        return Err(LifecycleError::Image(
            "paperless_image_repo_digest_mismatch",
        ));
    }
    let platform = format!("{}/{}", actual.os, actual.architecture);
    if platform != target_platform {
        return Err(LifecycleError::Image(
            "paperless_image_engine_platform_mismatch",
        ));
    }
    let config = expected
        .configs
        .get(&platform)
        .ok_or(LifecycleError::Image("paperless_image_platform_unadmitted"))?;
    if actual.id != *config {
        return Err(LifecycleError::Image("paperless_image_config_id_mismatch"));
    }
    Ok(VerifiedImage {
        service: expected.service,
        reference: expected.reference,
        repo_digest: expected.repo_digest.to_owned(),
        config_id: actual.id,
        os: actual.os,
        architecture: actual.architecture,
    })
}
fn verify_container(
    image: &VerifiedImage,
    project: &str,
    port: u16,
    raw: &str,
) -> Result<VerifiedContainer, LifecycleError> {
    let actual: DockerContainer = serde_json::from_str(raw)
        .map_err(|_| LifecycleError::Container("paperless_container_inspect_invalid"))?;
    if exact_identifier(&actual.id).as_deref() != Some(actual.id.as_str())
        || !actual.state.running
        || actual.image != image.config_id
    {
        return Err(LifecycleError::Container(
            "paperless_container_image_mismatch",
        ));
    }
    if actual.config.labels.get("com.docker.compose.project") != Some(&project.to_owned())
        || actual.config.labels.get("com.docker.compose.service") != Some(&image.service.to_owned())
    {
        return Err(LifecycleError::Container(
            "paperless_container_compose_labels_mismatch",
        ));
    }
    if image.service == "webserver"
        && !actual
            .network
            .ports
            .get("8000/tcp")
            .and_then(|binding| binding.as_ref())
            .is_some_and(|bindings| {
                bindings.len() == 1
                    && bindings[0].host_ip == "127.0.0.1"
                    && bindings[0].host_port == port.to_string()
            })
    {
        return Err(LifecycleError::Container(
            "paperless_loopback_port_mismatch",
        ));
    }
    let expected_mounts: Vec<_> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .filter(|volume| volume.service == image.service)
        .collect();
    if actual.mounts.len() != expected_mounts.len()
        || expected_mounts.iter().any(|expected| {
            !actual.mounts.iter().any(|mount| {
                mount.kind == "volume"
                    && mount.name == volume_name(project, expected.logical_name)
                    && mount.destination == expected.destination
            })
        })
    {
        return Err(LifecycleError::Container(
            "paperless_container_volume_mount_mismatch",
        ));
    }
    Ok(VerifiedContainer {
        service: image.service,
        id: actual.id,
        image_id: actual.image,
    })
}
fn volume_name(project: &str, logical_name: &str) -> String {
    format!("{project}_{logical_name}")
}
fn listed_expected_volume(raw: &str, expected_name: &str) -> Result<bool, LifecycleError> {
    if raw.is_empty() {
        return Ok(false);
    }
    let listed = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .ok_or(LifecycleError::UnownedOrMismatch)?;
    (listed == expected_name)
        .then_some(true)
        .ok_or(LifecycleError::UnownedOrMismatch)
}
async fn preflight_existing_volumes<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    project: &str,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<(), LifecycleError> {
    for expected in paperless_staging::PAPERLESS_VOLUMES {
        ensure_stage(root, binding)?;
        let expected_name = volume_name(project, expected.logical_name);
        let listed = executor
            .run(
                &engine.docker(
                    "volume",
                    &[
                        "ls",
                        "--filter",
                        &format!("name={expected_name}"),
                        "--format",
                        VOLUME_LIST_TEMPLATE,
                    ],
                ),
                &root.display,
            )
            .await?;
        ensure_stage(root, binding)?;
        if listed_expected_volume(&listed.stdout, &expected_name)? {
            let inspected = executor
                .run(
                    &engine.docker(
                        "volume",
                        &[
                            "inspect",
                            &expected_name,
                            "--format",
                            VOLUME_INSPECT_TEMPLATE,
                        ],
                    ),
                    &root.display,
                )
                .await?;
            ensure_stage(root, binding)?;
            verify_volume(expected, project, &inspected.stdout)
                .map_err(|_| LifecycleError::UnownedOrMismatch)?;
        }
    }
    Ok(())
}
async fn inspect_owned_volumes<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    project: &str,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<Vec<VerifiedVolume>, LifecycleError> {
    let mut volumes = Vec::with_capacity(paperless_staging::PAPERLESS_VOLUMES.len());
    for expected in paperless_staging::PAPERLESS_VOLUMES {
        ensure_stage(root, binding)?;
        let expected_name = volume_name(project, expected.logical_name);
        let inspected = executor
            .run(
                &engine.docker(
                    "volume",
                    &[
                        "inspect",
                        &expected_name,
                        "--format",
                        VOLUME_INSPECT_TEMPLATE,
                    ],
                ),
                &root.display,
            )
            .await?;
        ensure_stage(root, binding)?;
        volumes.push(verify_volume(expected, project, &inspected.stdout)?);
    }
    Ok(volumes)
}
fn verify_volume(
    expected: paperless_staging::PaperlessVolumeSpec,
    project: &str,
    raw: &str,
) -> Result<VerifiedVolume, LifecycleError> {
    let actual: DockerVolume = serde_json::from_str(raw)
        .map_err(|_| LifecycleError::Container("paperless_volume_inspect_invalid"))?;
    let expected_name = volume_name(project, expected.logical_name);
    if actual.name != expected_name
        || actual.labels.get("com.docker.compose.project") != Some(&project.to_owned())
        || actual.labels.get("com.docker.compose.volume") != Some(&expected.logical_name.to_owned())
    {
        return Err(LifecycleError::Container(
            "paperless_volume_ownership_mismatch",
        ));
    }
    Ok(VerifiedVolume {
        logical_name: expected.logical_name,
        name: actual.name,
        project: project.to_owned(),
    })
}
fn local_docker_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("npipe:////./pipe/")
        || endpoint.starts_with("unix:///") && !endpoint.contains("..") && !endpoint.contains('\\')
}
fn reject_legacy_state(root: &OwnedPaperlessRoot) -> Result<(), LifecycleError> {
    let mut has_state = false;
    for entry in root.root.entries().map_err(|_| LifecycleError::Io)? {
        let entry = entry.map_err(|_| LifecycleError::Io)?;
        if entry.file_name() == OsStr::new("state") {
            has_state = true;
            break;
        }
    }
    if !has_state {
        return Ok(());
    }
    let state = crate::skills::store::open_real_child_dir(
        &root.root,
        OsStr::new("state"),
        &root.display.join("state"),
    )
    .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    for entry in state.entries().map_err(|_| LifecycleError::Io)? {
        let entry = entry.map_err(|_| LifecycleError::Io)?;
        let name = entry.file_name();
        if !matches!(
            name.to_str(),
            Some("data" | "media" | "valkey" | "postgres")
        ) {
            continue;
        }
        let legacy = crate::skills::store::open_real_child_dir(
            &state,
            &name,
            &root.display.join("state").join(&name),
        )
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
        if legacy
            .entries()
            .map_err(|_| LifecycleError::Io)?
            .next()
            .transpose()
            .map_err(|_| LifecycleError::Io)?
            .is_some()
        {
            return Err(LifecycleError::LegacyStateMigrationRequired);
        }
    }
    Ok(())
}
#[cfg(windows)]
struct WindowsLaunchGuard {
    _root: ApprovedImportRoot,
    _state: ApprovedImportRoot,
    _compose: ApprovedImportFile,
    _env: ApprovedImportFile,
}
#[cfg(windows)]
fn acquire_launch_guard(
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<WindowsLaunchGuard, LifecycleError> {
    ensure_bound(root)?;
    root.root
        .create_dir("state")
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|_| LifecycleError::LaunchBinding)?;
    let root_guard =
        approve_import_root(&root.display).map_err(|_| LifecycleError::LaunchBinding)?;
    let compose = hold_approved_import_file(&root_guard, Path::new("compose.yaml"), ENV_LIMIT)
        .map_err(|_| LifecycleError::LaunchBinding)?;
    let env = hold_approved_import_file(&root_guard, Path::new("paperless.env"), ENV_LIMIT)
        .map_err(|_| LifecycleError::LaunchBinding)?;
    if compose.bytes() != paperless_staging::expected_compose_bytes()
        || env.bytes() != binding.env.as_slice()
    {
        return Err(LifecycleError::LaunchBinding);
    }
    let state_path = root.display.join("state");
    let state = approve_import_root(&state_path).map_err(|_| LifecycleError::LaunchBinding)?;
    ensure_stage(root, binding)?;
    Ok(WindowsLaunchGuard {
        _root: root_guard,
        _state: state,
        _compose: compose,
        _env: env,
    })
}
#[cfg(not(windows))]
struct UnixLaunchGuard {
    _root: cap_std::fs::Dir,
    _compose: Vec<u8>,
    _env: Vec<u8>,
}

#[cfg(not(windows))]
fn acquire_launch_guard(
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<UnixLaunchGuard, LifecycleError> {
    ensure_stage(root, binding)?;
    let compose = crate::skills::store::read_regular_file_bounded(
        &root.root,
        OsStr::new("compose.yaml"),
        &root.display.join("compose.yaml"),
        ENV_LIMIT,
    )
    .map_err(|_| LifecycleError::LaunchBinding)?;
    let env = crate::skills::store::read_regular_file_bounded(
        &root.root,
        OsStr::new("paperless.env"),
        &root.display.join("paperless.env"),
        ENV_LIMIT,
    )
    .map_err(|_| LifecycleError::LaunchBinding)?;
    if compose != paperless_staging::expected_compose_bytes() || env != binding.env.as_slice() {
        return Err(LifecycleError::LaunchBinding);
    }
    root.root
        .create_dir("state")
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|_| LifecycleError::LaunchBinding)?;
    Ok(UnixLaunchGuard {
        _root: root
            .root
            .try_clone()
            .map_err(|_| LifecycleError::LaunchBinding)?,
        _compose: compose,
        _env: env,
    })
}
fn ensure_bound(root: &OwnedPaperlessRoot) -> Result<(), LifecycleError> {
    if paperless_staging::still_exactly_owned(root).map_err(|_| LifecycleError::Io)? {
        Ok(())
    } else {
        Err(LifecycleError::UnownedOrMismatch)
    }
}
fn write_receipt(
    root: &OwnedPaperlessRoot,
    receipt: &PaperlessLifecycleReceipt,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let state_display = root.display.join(RECEIPT_DIR);
    let state = crate::skills::store::open_real_child_dir(
        &root.root,
        OsStr::new(RECEIPT_DIR),
        &state_display,
    )
    .map_err(|_| LifecycleError::Io)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(RECEIPT_NAME),
        &state_display.join(RECEIPT_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
pub fn lifecycle_receipt_path(home: &Path) -> PathBuf {
    crate::config::InstancePaths::for_home(home)
        .paperless_root
        .join(RECEIPT_DIR)
        .join(RECEIPT_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn parses_only_a_single_literal_env_port() {
        assert_eq!(dotenv_port(b"PAPERLESS_BIND_PORT=18000\n").unwrap(), 18000);
        assert!(dotenv_port(b"PAPERLESS_BIND_PORT=18000\nPAPERLESS_BIND_PORT=18001\n").is_err());
        assert!(dotenv_port(b"PAPERLESS_BIND_PORT=${PORT}\n").is_err());
    }
    #[test]
    fn compose_environment_matches_bootstrap_dotenv_literals() {
        for (admin, expected_user, expected_password) in [
            (
                b"PAPERLESS_ADMIN_USER='operator # literal'\nPAPERLESS_ADMIN_PASSWORD='secret # literal'\n"
                    .as_slice(),
                "operator # literal",
                "secret # literal",
            ),
            (
                b"PAPERLESS_ADMIN_USER=\"operator\\tname\"\nPAPERLESS_ADMIN_PASSWORD=\"secret\\\"value\"\n"
                    .as_slice(),
                "operator\tname",
                "secret\"value",
            ),
            (
                b"PAPERLESS_ADMIN_USER=operator # comment\nPAPERLESS_ADMIN_PASSWORD=secret # comment\n"
                    .as_slice(),
                "operator",
                "secret",
            ),
        ] {
            let mut env = b"PAPERLESS_SECRET_KEY=secret-key\nPAPERLESS_DB_NAME=paperless\nPAPERLESS_DB_USER=paperless\nPAPERLESS_DB_PASSWORD=database-secret\n".to_vec();
            env.extend_from_slice(admin);
            env.extend_from_slice(b"PAPERLESS_BIND_PORT=18000\n");
            let binding = EnvBinding {
                port: 18000,
                origin: "http://127.0.0.1:18000".to_owned(),
                env: Zeroizing::new(env),
            };
            let environment = compose_environment(&binding).unwrap();
            let value = |name: &str| -> &str {
                environment
                    .iter()
                    .find_map(|(key, value)| (key == name).then_some(value.as_str()))
                    .unwrap()
            };
            assert_eq!(value("PAPERLESS_ADMIN_USER"), expected_user);
            assert_eq!(value("PAPERLESS_ADMIN_PASSWORD"), expected_password);
            let bootstrap = paperless_bootstrap::parse_dotenv_values(
                binding.env.as_slice(),
                &["PAPERLESS_ADMIN_USER", "PAPERLESS_ADMIN_PASSWORD"],
            )
            .unwrap();
            assert_eq!(bootstrap["PAPERLESS_ADMIN_USER"].as_str(), expected_user);
            assert_eq!(bootstrap["PAPERLESS_ADMIN_PASSWORD"].as_str(), expected_password);
        }
    }
    #[test]
    fn exact_identifier_rejects_multiple_or_spaced_container_ids() {
        assert_eq!(
            exact_identifier("container-id\n").as_deref(),
            Some("container-id")
        );
        assert!(exact_identifier("one\ntwo\n").is_none());
        assert!(exact_identifier("one two").is_none());
    }
    #[test]
    fn compose_never_pulls_and_uses_pinned_engine_endpoint() {
        let engine = Engine {
            endpoint: "npipe:////./pipe/docker_engine".into(),
            platform: "linux/amd64".into(),
        };
        let command = engine.compose(
            "neoth-paperless-test",
            &["up", "-d", "--no-build", "--pull", "never"],
        );
        assert!(
            command
                .windows(2)
                .any(|pair| pair[0] == "--host" && pair[1] == "npipe:////./pipe/docker_engine")
        );
        assert!(
            command
                .windows(2)
                .any(|pair| pair[0] == "--pull" && pair[1] == "never")
        );
        assert!(
            command
                .windows(2)
                .any(|pair| pair[0] == "-f" && pair[1] == "-")
        );
        assert!(!command.iter().any(|part| part == "--env-file"));
    }
    #[test]
    fn receipt_matches_all_pinned_indexes_and_contains_config_proof() {
        let images = expected_images().unwrap();
        assert_eq!(images.len(), 3);
        assert!(images.iter().all(|image| !image.configs.is_empty()));
    }
    #[test]
    fn container_validation_rejects_stopped_and_mixed_bindings() {
        let image = VerifiedImage {
            service: "webserver",
            reference: "x",
            repo_digest: "x".into(),
            config_id: "sha256:config".into(),
            os: "linux".into(),
            architecture: "amd64".into(),
        };
        let stopped = r#"{"Id":"id","Image":"sha256:config","State":{"Running":false},"Config":{"Labels":{"com.docker.compose.project":"project","com.docker.compose.service":"webserver"}},"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"18000"}]}}}"#;
        let mixed = r#"{"Id":"id","Image":"sha256:config","State":{"Running":true},"Config":{"Labels":{"com.docker.compose.project":"project","com.docker.compose.service":"webserver"}},"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"18000"},{"HostIp":"0.0.0.0","HostPort":"18000"}]}}}"#;
        assert!(verify_container(&image, "project", 18000, stopped).is_err());
        assert!(verify_container(&image, "project", 18000, mixed).is_err());
    }
    #[test]
    fn volume_validation_requires_exact_name_and_compose_labels() {
        let expected = paperless_staging::PAPERLESS_VOLUMES[0];
        let name = volume_name("project", expected.logical_name);
        let good = format!(
            r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"project","com.docker.compose.volume":"{}"}}}}"#,
            expected.logical_name
        );
        assert!(verify_volume(expected, "project", &good).is_ok());
        for invalid in [
            format!(
                r#"{{"Name":"foreign","Labels":{{"com.docker.compose.project":"project","com.docker.compose.volume":"{}"}}}}"#,
                expected.logical_name
            ),
            format!(
                r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"other","com.docker.compose.volume":"{}"}}}}"#,
                expected.logical_name
            ),
            format!(
                r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"project","com.docker.compose.volume":"other"}}}}"#
            ),
            "not-json".to_owned(),
        ] {
            assert!(verify_volume(expected, "project", &invalid).is_err());
        }
    }
    #[test]
    fn container_validation_rejects_missing_wrong_and_extra_volume_mounts() {
        let image = VerifiedImage {
            service: "webserver",
            reference: "x",
            repo_digest: "x".into(),
            config_id: "sha256:config".into(),
            os: "linux".into(),
            architecture: "amd64".into(),
        };
        let valid_mounts = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .filter(|volume| volume.service == image.service)
            .map(|volume| {
                format!(
                    r#"{{"Type":"volume","Name":"project_{}","Destination":"{}"}}"#,
                    volume.logical_name, volume.destination
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            paperless_staging::PAPERLESS_VOLUMES
                .iter()
                .filter(|volume| volume.service == image.service)
                .count(),
            4
        );
        let inspect = |mounts: &str| {
            format!(
                r#"{{"Id":"id","Image":"sha256:config","State":{{"Running":true}},"Config":{{"Labels":{{"com.docker.compose.project":"project","com.docker.compose.service":"webserver"}}}},"NetworkSettings":{{"Ports":{{"8000/tcp":[{{"HostIp":"127.0.0.1","HostPort":"18000"}}]}}}},"Mounts":[{mounts}]}}"#
            )
        };
        assert!(verify_container(&image, "project", 18000, &inspect(&valid_mounts)).is_ok());
        assert!(verify_container(&image, "project", 18000, &inspect("")).is_err());
        assert!(
            verify_container(
                &image,
                "project",
                18000,
                &inspect(&valid_mounts.replacen("project_paperless_data", "foreign", 1)),
            )
            .is_err()
        );
        assert!(
            verify_container(
                &image,
                "project",
                18000,
                &inspect(&format!(
                    r#"{valid_mounts},{{"Type":"volume","Name":"anonymous-image-volume","Destination":"/usr/src/paperless/consume"}}"#
                )),
            )
            .is_err()
        );
        assert!(
            verify_container(
                &image,
                "project",
                18000,
                &inspect(&format!(
                    r#"{valid_mounts},{{"Type":"volume","Name":"extra","Destination":"/extra"}}"#
                )),
            )
            .is_err()
        );
    }
    #[test]
    fn volume_listing_accepts_only_one_exact_name() {
        assert!(!listed_expected_volume("", "owned").unwrap());
        assert!(listed_expected_volume("owned\n", "owned").unwrap());
        assert!(listed_expected_volume("owned\r\n", "owned").unwrap());
        assert!(listed_expected_volume("owned\nowned\n", "owned").is_err());
        assert!(listed_expected_volume("foreign\n", "owned").is_err());
    }
    #[test]
    fn image_verification_uses_engine_platform_not_windows_host() {
        let image = expected_images().unwrap().into_iter().next().unwrap();
        let config = image.configs.get("linux/amd64").unwrap();
        let raw = format!(
            r#"{{"Id":"{config}","RepoDigests":["{}"],"Os":"linux","Architecture":"amd64"}}"#,
            image.repo_digest
        );
        assert!(verify_image(&image, "linux/amd64", &raw).is_ok());
        assert!(matches!(
            verify_image(&image, "linux/arm64", &raw),
            Err(LifecycleError::Image(
                "paperless_image_engine_platform_mismatch"
            ))
        ));
    }
    #[test]
    fn docker_command_uses_a_sterile_compose_environment() {
        let command =
            configured_docker_command("docker", &["compose".into()], Path::new("C:/paperless"));
        // After env_clear(), env_remove() need not retain an explicit removal
        // entry. Inspect the configured values instead of requiring tombstones.
        let configured: std::collections::BTreeMap<_, _> = command
            .as_std()
            .get_envs()
            .filter_map(|(name, value)| {
                value.map(|value| (name.to_string_lossy().into_owned(), value.to_os_string()))
            })
            .collect();
        for name in ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_DEFAULT_PLATFORM"]
            .into_iter()
            .chain(PAPERLESS_INTERPOLATION_ENV)
            .chain(
                COMPOSE_CONFIGURATION_ENV
                    .into_iter()
                    .filter(|name| *name != "COMPOSE_DISABLE_ENV_FILE"),
            )
        {
            assert!(
                !configured.contains_key(name),
                "unexpected configured {name}"
            );
        }
        for name in configured.keys() {
            assert!(OS_LAUNCH_ENV.contains(&name.as_str()) || name == "COMPOSE_DISABLE_ENV_FILE");
        }
        assert_eq!(configured.get("PATH"), std::env::var_os("PATH").as_ref());
        assert_eq!(
            configured
                .get("COMPOSE_DISABLE_ENV_FILE")
                .map(|value| value.to_string_lossy()),
            Some("1".into())
        );
    }

    #[derive(Default)]
    pub(super) struct FakeExecutor {
        commands: Vec<Vec<String>>,
        remote: bool,
        exact_container_ids: bool,
        uninstall_test_container_seed: u8,
        container_inspects: Option<std::sync::Arc<AtomicUsize>>,
        volume_list_response: Option<String>,
        volume_inspect_responses: std::collections::VecDeque<String>,
        retained_compose_inputs: Vec<Vec<u8>>,
    }
    #[async_trait]
    impl ComposeExecutor for FakeExecutor {
        async fn run(
            &mut self,
            argv: &[String],
            cwd: &Path,
        ) -> Result<CommandOutput, LifecycleError> {
            self.commands.push(argv.to_vec());
            if argv
                .windows(2)
                .any(|pair| pair[0] == "context" && pair[1] == "show")
            {
                return Ok(CommandOutput {
                    stdout: "desktop-linux\n".into(),
                });
            }
            if argv
                .windows(2)
                .any(|pair| pair[0] == "context" && pair[1] == "inspect")
            {
                return Ok(CommandOutput {
                    stdout: if self.remote {
                        "\"tcp://remote.example:2376\"".into()
                    } else {
                        "\"npipe:////./pipe/docker_engine\"".into()
                    },
                });
            }
            if argv.iter().any(|part| part == "version") {
                return Ok(CommandOutput {
                    stdout: r#"{"Os":"linux","Arch":"amd64"}"#.into(),
                });
            }
            if argv.iter().any(|part| part == "image") {
                let reference = argv
                    .iter()
                    .skip_while(|part| *part != "inspect")
                    .nth(1)
                    .ok_or(LifecycleError::Command("fake_image"))?;
                let image = expected_images()?
                    .into_iter()
                    .find(|image| image.reference == reference)
                    .ok_or(LifecycleError::Receipt)?;
                let config = image
                    .configs
                    .get("linux/amd64")
                    .ok_or(LifecycleError::Receipt)?;
                return Ok(CommandOutput {
                    stdout: format!(
                        r#"{{"Id":"{config}","RepoDigests":["{}"],"Os":"linux","Architecture":"amd64"}}"#,
                        image.repo_digest
                    ),
                });
            }
            if argv.iter().any(|part| part == "volume") {
                if argv.iter().any(|part| part == "ls") {
                    return Ok(CommandOutput {
                        stdout: self.volume_list_response.clone().unwrap_or_default(),
                    });
                }
                let name = argv
                    .iter()
                    .skip_while(|part| *part != "inspect")
                    .nth(1)
                    .ok_or(LifecycleError::Command("fake_volume"))?;
                let logical_name = paperless_staging::PAPERLESS_VOLUMES
                    .iter()
                    .find(|volume| name.ends_with(volume.logical_name))
                    .ok_or(LifecycleError::Container("fake_volume"))?;
                return Ok(CommandOutput {
                    stdout: self.volume_inspect_responses.pop_front().unwrap_or_else(|| format!(
                        r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"{}","com.docker.compose.volume":"{}"}}}}"#,
                        project_name(cwd), logical_name.logical_name
                    )),
                });
            }
            if argv.iter().any(|part| part == "ps") {
                let service = argv.last().ok_or(LifecycleError::Command("fake_ps"))?;
                return Ok(CommandOutput {
                    stdout: if self.exact_container_ids {
                        format!(
                            "{}\n",
                            uninstall_test_container_id(
                                service,
                                self.uninstall_test_container_seed
                            )?
                        )
                    } else {
                        format!("{service}-container\n")
                    },
                });
            }
            if argv.iter().any(|part| part == "container") {
                if let Some(inspects) = &self.container_inspects {
                    inspects.fetch_add(1, Ordering::SeqCst);
                }
                let id = argv
                    .iter()
                    .skip_while(|part| *part != "inspect")
                    .nth(1)
                    .ok_or(LifecycleError::Command("fake_container"))?;
                let service = if self.exact_container_ids {
                    uninstall_test_container_service(id)?
                } else {
                    id.strip_suffix("-container")
                        .ok_or(LifecycleError::Container("fake_container"))?
                };
                let image = expected_images()?
                    .into_iter()
                    .find(|image| image.service == service)
                    .ok_or(LifecycleError::Receipt)?;
                let config = image
                    .configs
                    .get("linux/amd64")
                    .ok_or(LifecycleError::Receipt)?;
                let port = dotenv_port(
                    &std::fs::read(cwd.join("paperless.env")).map_err(|_| LifecycleError::Io)?,
                )?;
                let ports = if service == "webserver" {
                    format!(r#"{{"8000/tcp":[{{"HostIp":"127.0.0.1","HostPort":"{port}"}}]}}"#)
                } else {
                    "{}".into()
                };
                let mounts = paperless_staging::PAPERLESS_VOLUMES
                    .iter()
                    .filter(|volume| volume.service == service)
                    .map(|volume| {
                        format!(
                            r#"{{"Type":"volume","Name":"{}","Destination":"{}"}}"#,
                            volume_name(&project_name(cwd), volume.logical_name),
                            volume.destination
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                return Ok(CommandOutput {
                    stdout: format!(
                        r#"{{"Id":"{id}","Image":"{config}","State":{{"Running":true}},"Config":{{"Labels":{{"com.docker.compose.project":"{}","com.docker.compose.service":"{service}"}}}},"NetworkSettings":{{"Ports":{ports}}},"Mounts":[{mounts}]}}"#,
                        project_name(cwd)
                    ),
                });
            }
            Ok(CommandOutput {
                stdout: String::new(),
            })
        }
    }

    #[async_trait]
    impl RetainedComposeExecutor for FakeExecutor {
        async fn run_retained(
            &mut self,
            argv: &[String],
            root: &OwnedPaperlessRoot,
            binding: &EnvBinding,
        ) -> Result<CommandOutput, LifecycleError> {
            compose_environment(binding)?;
            self.retained_compose_inputs
                .push(paperless_staging::expected_compose_bytes().to_vec());
            self.run(argv, &root.display).await
        }
    }
    struct EventuallyReady(AtomicUsize);
    #[async_trait]
    impl ReadinessVerifier for EventuallyReady {
        async fn ready(&self, _home: &Path, _credentials: &Credentials) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst) >= 1
        }
    }
    fn prepare_staging_or_panic(root: &Path) {
        paperless_staging::prepare_at(root).unwrap_or_else(|error| {
            panic!(
                "paperless staging failed: {error:?}; diagnostic={:?}",
                paperless_staging::last_prepare_io_diagnostic_for_test()
            )
        });
    }
    pub(super) fn staged_home() -> (tempfile::TempDir, Credentials) {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("paperless");
        prepare_staging_or_panic(&root);
        std::fs::write(root.join("paperless.env"), b"PAPERLESS_SECRET_KEY=secret-key\nPAPERLESS_DB_NAME=paperless\nPAPERLESS_DB_USER=paperless\nPAPERLESS_DB_PASSWORD=secret\nPAPERLESS_ADMIN_USER=operator\nPAPERLESS_ADMIN_PASSWORD=secret\nPAPERLESS_BIND_PORT=18000\n").unwrap();
        std::fs::create_dir(root.join("state")).unwrap();
        let mut credentials = Credentials::default();
        credentials.paperless_url = Some("http://127.0.0.1:18000".into());
        credentials.paperless_token = Some(SecretString::from("existing-token"));
        (home, credentials)
    }
    pub(super) async fn installed_home_for_uninstall_test()
    -> (tempfile::TempDir, Credentials, Vec<u8>) {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor {
            exact_container_ids: true,
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap();
        let receipt = std::fs::read(lifecycle_receipt_path(home.path())).unwrap();
        (home, credentials, receipt)
    }
    fn uninstall_test_container_id(service: &str, seed: u8) -> Result<String, LifecycleError> {
        let digit = match (seed, service) {
            (0, "webserver") => 'a',
            (0, "broker") => 'b',
            (0, "db") => 'c',
            (1, "webserver") => 'd',
            (1, "broker") => 'e',
            (1, "db") => 'f',
            _ => return Err(LifecycleError::Container("fake_container")),
        };
        Ok(digit.to_string().repeat(64))
    }
    fn uninstall_test_container_service(id: &str) -> Result<&'static str, LifecycleError> {
        match id.as_bytes().first().copied() {
            Some(b'a') | Some(b'd') => Ok("webserver"),
            Some(b'b') | Some(b'e') => Ok("broker"),
            Some(b'c') | Some(b'f') => Ok("db"),
            _ => Err(LifecycleError::Container("fake_container")),
        }
    }
    pub(super) async fn reinstall_for_uninstall_test(
        home: &Path,
        credentials: &Credentials,
    ) -> Result<PaperlessLifecycleReceipt, LifecycleError> {
        let mut executor = FakeExecutor {
            exact_container_ids: true,
            uninstall_test_container_seed: 1,
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        install_at_with_readiness(home, credentials, &mut executor, &ready).await
    }
    #[test]
    fn empty_or_absent_legacy_state_is_allowed() {
        let (home, _) = staged_home();
        let root_path = crate::config::InstancePaths::for_home(home.path()).paperless_root;
        let owned = paperless_staging::open_owned_root_at(&root_path).unwrap();
        assert!(reject_legacy_state(&owned).is_ok());
        std::fs::create_dir(root_path.join("state").join("data")).unwrap();
        let owned = paperless_staging::open_owned_root_at(&root_path).unwrap();
        assert!(reject_legacy_state(&owned).is_ok());
    }
    #[tokio::test]
    async fn nonempty_legacy_state_aborts_before_docker_mutation() {
        let (home, credentials) = staged_home();
        let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
        let legacy = root.join("state").join("data");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::write(legacy.join("retained"), b"legacy-data").unwrap();
        let mut executor = FakeExecutor::default();
        let ready = EventuallyReady(AtomicUsize::new(0));
        assert!(matches!(
            install_at_with_readiness(home.path(), &credentials, &mut executor, &ready).await,
            Err(LifecycleError::LegacyStateMigrationRequired)
        ));
        assert!(executor.commands.is_empty());
        assert!(!lifecycle_receipt_path(home.path()).exists());
    }
    #[tokio::test]
    async fn public_executor_entrypoint_refuses_unretained_launches() {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor::default();
        assert!(matches!(
            install_at_with(home.path(), &credentials, &mut executor).await,
            Err(LifecycleError::LaunchBinding)
        ));
        assert!(executor.commands.is_empty());
    }
    #[cfg(not(windows))]
    #[tokio::test]
    async fn unix_dispatcher_uses_retained_compose_inputs_and_records_volumes() {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor::default();
        let ready = EventuallyReady(AtomicUsize::new(0));
        let receipt = install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap();
        assert_eq!(
            receipt.volumes.len(),
            paperless_staging::PAPERLESS_VOLUMES.len()
        );
        assert!(
            executor
                .commands
                .iter()
                .any(|command| command.iter().any(|part| part == "compose"))
        );
        assert!(!executor.retained_compose_inputs.is_empty());
        assert!(
            executor
                .retained_compose_inputs
                .iter()
                .all(|input| input.as_slice() == paperless_staging::expected_compose_bytes())
        );
        for command in executor
            .commands
            .iter()
            .filter(|command| command.iter().any(|part| part == "compose"))
        {
            assert!(
                command
                    .windows(2)
                    .any(|pair| pair[0] == "-f" && pair[1] == "-")
            );
            assert!(!command.iter().any(|part| part == "--env-file"));
        }
    }
    #[tokio::test]
    async fn preexisting_unowned_volume_aborts_before_compose_up() {
        let (home, credentials) = staged_home();
        let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
        let project = project_name(&root);
        let expected = paperless_staging::PAPERLESS_VOLUMES[0];
        let name = volume_name(&project, expected.logical_name);
        let mut executor = FakeExecutor {
            volume_list_response: Some(format!("{name}\n")),
            volume_inspect_responses: std::collections::VecDeque::from([format!(
                r#"{{"Name":"{name}","Labels":{{"com.docker.compose.project":"foreign","com.docker.compose.volume":"{}"}}}}"#,
                expected.logical_name
            )]),
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        assert!(matches!(
            install_at_with_readiness(home.path(), &credentials, &mut executor, &ready).await,
            Err(LifecycleError::UnownedOrMismatch)
        ));
        assert!(
            !executor
                .commands
                .iter()
                .any(|command| command.iter().any(|part| part == "compose"))
        );
        assert!(!lifecycle_receipt_path(home.path()).exists());
    }
    #[tokio::test]
    async fn post_readiness_volume_mismatch_suppresses_receipt() {
        let (home, credentials) = staged_home();
        let root = crate::config::InstancePaths::for_home(home.path()).paperless_root;
        let project = project_name(&root);
        let mut responses = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .map(|volume| format!(
                r#"{{"Name":"{}","Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.volume":"{}"}}}}"#,
                volume_name(&project, volume.logical_name), volume.logical_name
            ))
            .collect::<std::collections::VecDeque<_>>();
        let first = paperless_staging::PAPERLESS_VOLUMES[0];
        responses.push_back(format!(
            r#"{{"Name":"{}","Labels":{{"com.docker.compose.project":"foreign","com.docker.compose.volume":"{}"}}}}"#,
            volume_name(&project, first.logical_name), first.logical_name
        ));
        let mut executor = FakeExecutor {
            volume_inspect_responses: responses,
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        assert!(matches!(
            install_at_with_readiness(home.path(), &credentials, &mut executor, &ready).await,
            Err(LifecycleError::Container(
                "paperless_volume_ownership_mismatch"
            ))
        ));
        assert!(!lifecycle_receipt_path(home.path()).exists());
    }
    #[cfg(not(windows))]
    #[tokio::test]
    async fn launch_binding_gate_prevents_remote_engine_selection_and_receipt() {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor {
            remote: true,
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        let error = install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            LifecycleError::Engine("paperless_remote_docker_context_rejected")
        ));
        assert!(!executor.commands.is_empty());
        assert!(!lifecycle_receipt_path(home.path()).exists());
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_guarded_dispatcher_keeps_existing_token_and_binds_full_install() {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor::default();
        let ready = EventuallyReady(AtomicUsize::new(0));
        let receipt = install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap();
        assert_eq!(receipt.images.len(), 3);
        assert_eq!(receipt.containers.len(), 3);
        assert!(lifecycle_receipt_path(home.path()).is_file());
        assert!(
            executor
                .commands
                .iter()
                .any(|command| command.iter().any(|part| part == "pull"))
        );
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_guarded_dispatcher_rejects_remote_engine_before_pull() {
        let (home, credentials) = staged_home();
        let mut executor = FakeExecutor {
            remote: true,
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        let error = install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            LifecycleError::Engine("paperless_remote_docker_context_rejected")
        ));
        assert!(
            !executor
                .commands
                .iter()
                .any(|command| command.iter().any(|part| part == "pull"))
        );
        assert!(!lifecycle_receipt_path(home.path()).exists());
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_guarded_dispatcher_bootstraps_missing_token_after_verified_containers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let inspections = std::sync::Arc::new(AtomicUsize::new(0));
        let server_inspections = inspections.clone();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), async { let (mut stream, _) = listener.accept().await.unwrap(); let mut request = Vec::new(); let header_end = loop { let mut chunk = [0; 512]; let count = stream.read(&mut chunk).await.unwrap(); assert!(count > 0); request.extend_from_slice(&chunk[..count]); if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") { break end + 4; } }; let headers = std::str::from_utf8(&request[..header_end]).unwrap(); let length = headers.lines().find_map(|line| line.strip_prefix("content-length:").or_else(|| line.strip_prefix("Content-Length:")).and_then(|value| value.trim().parse::<usize>().ok())).unwrap(); while request.len().saturating_sub(header_end) < length { let mut chunk = [0; 512]; let count = stream.read(&mut chunk).await.unwrap(); assert!(count > 0); request.extend_from_slice(&chunk[..count]); } assert!(std::str::from_utf8(&request[header_end..]).unwrap().contains("username=operator")); assert_eq!(server_inspections.load(Ordering::SeqCst), 3); let body = br#"{"token":"boot-token"}"#; let header = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()); stream.write_all(header.as_bytes()).await.unwrap(); stream.write_all(body).await.unwrap(); }).await.unwrap();
        });
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("paperless");
        prepare_staging_or_panic(&root);
        std::fs::write(root.join("paperless.env"), format!("PAPERLESS_SECRET_KEY=secret-key\nPAPERLESS_DB_NAME=paperless\nPAPERLESS_DB_USER=paperless\nPAPERLESS_DB_PASSWORD=secret\nPAPERLESS_ADMIN_USER=operator\nPAPERLESS_ADMIN_PASSWORD=secret\nPAPERLESS_BIND_PORT={port}\n")).unwrap();
        std::fs::create_dir(root.join("state")).unwrap();
        let mut credentials = Credentials::default();
        credentials.paperless_url = Some(format!("http://127.0.0.1:{port}"));
        let mut executor = FakeExecutor {
            container_inspects: Some(inspections),
            ..Default::default()
        };
        let ready = EventuallyReady(AtomicUsize::new(0));
        let receipt = install_at_with_readiness(home.path(), &credentials, &mut executor, &ready)
            .await
            .unwrap();
        task.await.unwrap();
        assert!(receipt.authenticated_api_ready);
        let persisted =
            Credentials::load_or_default(&home.path().join("credentials.yaml")).unwrap();
        assert_eq!(
            persisted.paperless_token.unwrap().expose_secret(),
            "boot-token"
        );
    }
    #[test]
    fn safe_uninstall_accepts_only_exact_64_hex_container_ids() {
        assert!(exact_container_id(&"a".repeat(64)));
        assert!(exact_container_id(&"A".repeat(64)));
        assert!(!exact_container_id("webserver-container"));
        assert!(!exact_container_id(&"a".repeat(63)));
        assert!(!exact_container_id(&("a".repeat(63) + "-")));
    }
}

#[cfg(test)]
use tests::staged_home as staged_paperless_home_for_test;

#[cfg(test)]
use tests::installed_home_for_uninstall_test;

#[cfg(test)]
use tests::reinstall_for_uninstall_test;

#[cfg(test)]
#[path = "paperless_uninstall_tests.rs"]
mod paperless_uninstall_tests;
