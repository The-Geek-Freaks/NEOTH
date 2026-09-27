//! Lifecycle-neutral, compiled-catalog preflight for a future managed n8n Update.
//!
//! This is deliberately not an updater.  It proves the admitted OCI index,
//! selected child manifest, and Docker materialized config without creating
//! containers, volumes, jobs, bindings, or configuration. It may download the
//! admitted immutable image into the operator-selected Docker engine.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const REGISTRY_TOKEN_URL: &str =
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:n8nio/n8n:pull";
const REGISTRY_MANIFEST_BASE: &str = "https://registry-1.docker.io/v2/n8nio/n8n/manifests/";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const MAX_REGISTRY_BYTES: usize = 512 * 1024;
const MAX_COMMAND_BYTES: usize = 128 * 1024;
const PULL_TIMEOUT: Duration = Duration::from_secs(300);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct PlatformEntry {
    os: &'static str,
    architecture: &'static str,
    child_manifest_digest: &'static str,
}

#[derive(Clone, Copy)]
struct UpdateTargetCatalogEntry {
    selector: &'static str,
    version: &'static str,
    runtime_image: &'static str,
    repo_digest: &'static str,
    index_digest: &'static str,
    catalog_evidence_sha256: &'static str,
    platforms: &'static [PlatformEntry],
}

const N8N_2407_PLATFORMS: &[PlatformEntry] = &[
    PlatformEntry {
        os: "linux",
        architecture: "amd64",
        child_manifest_digest: "sha256:599d68c7b6fb18b5ac1e7cd013a2e72c886ec1c807b9d436d56e90da32c664ac",
    },
    PlatformEntry {
        os: "linux",
        architecture: "arm64",
        child_manifest_digest: "sha256:7215c2cb5c7093041d094f4e1afb1a4be50486962c590d8df6182031c283b2bb",
    },
];

const N8N_UPDATE_TARGETS: &[UpdateTargetCatalogEntry] = &[UpdateTargetCatalogEntry {
    selector: "n8n-2.40.7",
    version: "2.40.7",
    runtime_image: "docker.io/n8nio/n8n@sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34",
    repo_digest: "n8nio/n8n@sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34",
    index_digest: "sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34",
    catalog_evidence_sha256: "a3c804dbdb2cc45cb0fdaa6a40be49522dc7811123c46eec51883032ad60fb02",
    platforms: N8N_2407_PLATFORMS,
}];

/// Non-secret evidence returned by the read-only CLI preflight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TargetPreflightReceiptView {
    pub selector: String,
    pub version: String,
    pub platform: String,
    pub runtime_image: String,
    pub index_digest: String,
    pub child_manifest_digest: String,
    pub config_digest: String,
    pub catalog_evidence_sha256: String,
}

/// Compiled admission authority for a managed Update.  This deliberately has
/// no receipt path or local-preflight field: callers can obtain it only from
/// the immutable catalog compiled into this binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedUpdateTarget {
    pub selector: String,
    pub version: String,
    pub runtime_image: String,
    pub repo_digest: String,
    pub index_digest: String,
    pub catalog_evidence_sha256: String,
    pub platforms: Vec<AdmittedUpdatePlatform>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedUpdatePlatform {
    pub os: String,
    pub architecture: String,
    pub child_manifest_digest: String,
}

/// Engine-local proof produced only after the selected managed Docker engine
/// has pulled and inspected the compiled target.  It is evidence for a job,
/// never an input to admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetImageProof {
    pub selector: String,
    pub version: String,
    pub platform: String,
    pub runtime_image: String,
    pub repo_digest: String,
    pub index_digest: String,
    pub child_manifest_digest: String,
    pub config_digest: String,
    pub catalog_evidence_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistryObject {
    Manifest(&'static str),
}

#[async_trait]
pub(crate) trait RegistryTargetReader: Send + Sync {
    /// Returns bounded raw bytes only. Implementations must not attach raw
    /// bodies, headers, or bearer tokens to errors.
    async fn read(&self, object: RegistryObject) -> Result<Vec<u8>>;
}

#[async_trait]
pub(crate) trait UpdateTargetDockerRunner: Send {
    async fn pull_exact_target(&mut self, platform: &str, image: &str) -> Result<()>;
    async fn inspect_pulled_target(&mut self, image: &str) -> Result<DockerImageObservation>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DockerImageObservation {
    pub id: String,
    pub repo_digests: Vec<String>,
    pub os: String,
    pub architecture: String,
}

/// Production entrypoint. The platform must be explicit (`linux/amd64` or
/// `linux/arm64`); the CLI owns any platform default policy.
pub(crate) async fn verify_update_target(
    selector: &str,
    platform: &str,
) -> Result<TargetPreflightReceiptView> {
    let reader = DockerHubRegistryTargetReader::new()?;
    let mut docker = LocalUpdateTargetDockerRunner;
    verify_update_target_with(selector, platform, &reader, &mut docker).await
}

pub(crate) async fn verify_update_target_with<
    R: RegistryTargetReader,
    D: UpdateTargetDockerRunner,
>(
    selector: &str,
    platform: &str,
    reader: &R,
    docker: &mut D,
) -> Result<TargetPreflightReceiptView> {
    let target = resolve_admitted_target(selector)?;
    let proof = prove_admitted_target_with(&target, platform, reader, docker).await?;
    Ok(TargetPreflightReceiptView {
        selector: proof.selector,
        version: proof.version,
        platform: proof.platform,
        runtime_image: proof.runtime_image,
        index_digest: proof.index_digest,
        child_manifest_digest: proof.child_manifest_digest,
        config_digest: proof.config_digest,
        catalog_evidence_sha256: proof.catalog_evidence_sha256,
    })
}

/// Resolve one immutable, compiled catalog target.  A `TargetPreflightReceiptView`
/// is intentionally not accepted here; a standalone preflight has no authority
/// over the engine that owns the managed runtime.
pub(crate) fn resolve_admitted_target(selector: &str) -> Result<AdmittedUpdateTarget> {
    let entry = resolve_target(selector)?;
    Ok(AdmittedUpdateTarget {
        selector: entry.selector.into(),
        version: entry.version.into(),
        runtime_image: entry.runtime_image.into(),
        repo_digest: entry.repo_digest.into(),
        index_digest: entry.index_digest.into(),
        catalog_evidence_sha256: entry.catalog_evidence_sha256.into(),
        platforms: entry
            .platforms
            .iter()
            .map(|platform| AdmittedUpdatePlatform {
                os: platform.os.into(),
                architecture: platform.architecture.into(),
                child_manifest_digest: platform.child_manifest_digest.into(),
            })
            .collect(),
    })
}

pub(crate) async fn prove_admitted_target_with<R: RegistryTargetReader, D: UpdateTargetDockerRunner>(
    target: &AdmittedUpdateTarget,
    platform: &str,
    reader: &R,
    docker: &mut D,
) -> Result<TargetImageProof> {
    // Re-resolve the catalog tuple before using it.  This rejects values that
    // merely resemble an admitted target but were reconstructed from a file.
    let catalog = resolve_target(&target.selector)?;
    if target != &resolve_admitted_target(catalog.selector)? {
        return Err(anyhow!("n8n_update_target_admission_mismatch"));
    }
    let platform_entry = target_platform(catalog, platform)?;
    let index_raw =
        bounded_registry_read(reader, RegistryObject::Manifest(catalog.index_digest)).await?;
    let child_descriptor = verify_index(&index_raw, catalog, platform_entry)?;
    let child_raw = bounded_registry_read(
        reader,
        RegistryObject::Manifest(platform_entry.child_manifest_digest),
    )
    .await?;
    let config_digest = verify_child_manifest(&child_raw, platform_entry, child_descriptor.size)?;

    docker
        .pull_exact_target(platform, catalog.runtime_image)
        .await
        .map_err(|_| anyhow!("n8n_update_target_docker_pull_failed"))?;
    let observed = docker
        .inspect_pulled_target(catalog.runtime_image)
        .await
        .map_err(|_| anyhow!("n8n_update_target_docker_inspect_failed"))?;
    verify_pulled_target(&observed, catalog, platform_entry, &config_digest)?;

    Ok(TargetImageProof {
        selector: catalog.selector.into(),
        version: catalog.version.into(),
        platform: platform.into(),
        runtime_image: catalog.runtime_image.into(),
        repo_digest: catalog.repo_digest.into(),
        index_digest: catalog.index_digest.into(),
        child_manifest_digest: platform_entry.child_manifest_digest.into(),
        config_digest,
        catalog_evidence_sha256: catalog.catalog_evidence_sha256.into(),
    })
}

// Kept private for the catalog fixture suite.  Production Update never calls
// this compatibility helper: it must first pass through
// `resolve_admitted_target` above.
#[cfg(test)]
async fn verify_target_with<R: RegistryTargetReader, D: UpdateTargetDockerRunner>(
    target: &UpdateTargetCatalogEntry,
    platform: &str,
    reader: &R,
    docker: &mut D,
) -> Result<TargetPreflightReceiptView> {
    let platform_entry = target_platform(target, platform)?;
    let index_raw = bounded_registry_read(reader, RegistryObject::Manifest(target.index_digest)).await?;
    let child_descriptor = verify_index(&index_raw, target, platform_entry)?;
    let child_raw = bounded_registry_read(reader, RegistryObject::Manifest(platform_entry.child_manifest_digest)).await?;
    let config_digest = verify_child_manifest(&child_raw, platform_entry, child_descriptor.size)?;
    docker.pull_exact_target(platform, target.runtime_image).await.map_err(|_| anyhow!("n8n_update_target_docker_pull_failed"))?;
    let observed = docker.inspect_pulled_target(target.runtime_image).await.map_err(|_| anyhow!("n8n_update_target_docker_inspect_failed"))?;
    verify_pulled_target(&observed, target, platform_entry, &config_digest)?;
    Ok(TargetPreflightReceiptView { selector: target.selector.into(), version: target.version.into(), platform: platform.into(), runtime_image: target.runtime_image.into(), index_digest: target.index_digest.into(), child_manifest_digest: platform_entry.child_manifest_digest.into(), config_digest, catalog_evidence_sha256: target.catalog_evidence_sha256.into() })
}

fn resolve_target(selector: &str) -> Result<&'static UpdateTargetCatalogEntry> {
    N8N_UPDATE_TARGETS
        .iter()
        .find(|entry| entry.selector == selector)
        .ok_or_else(|| anyhow!("n8n_update_target_selector_not_admitted"))
}

fn target_platform(
    target: &UpdateTargetCatalogEntry,
    platform: &str,
) -> Result<&'static PlatformEntry> {
    let (os, architecture) = platform
        .split_once('/')
        .ok_or_else(|| anyhow!("n8n_update_target_platform_not_supported"))?;
    target
        .platforms
        .iter()
        .find(|entry| entry.os == os && entry.architecture == architecture)
        .ok_or_else(|| anyhow!("n8n_update_target_platform_not_supported"))
}

async fn bounded_registry_read<R: RegistryTargetReader>(
    reader: &R,
    object: RegistryObject,
) -> Result<Vec<u8>> {
    let bytes = reader
        .read(object)
        .await
        .map_err(|_| anyhow!("n8n_update_target_registry_read_failed"))?;
    if bytes.is_empty() || bytes.len() > MAX_REGISTRY_BYTES {
        return Err(anyhow!("n8n_update_target_registry_response_invalid"));
    }
    Ok(bytes)
}

fn verify_index(
    raw: &[u8],
    target: &UpdateTargetCatalogEntry,
    selected: &PlatformEntry,
) -> Result<OciDescriptor> {
    require_digest(
        raw,
        target.index_digest,
        "n8n_update_target_index_digest_mismatch",
    )?;
    let index: OciIndex =
        serde_json::from_slice(raw).map_err(|_| anyhow!("n8n_update_target_index_invalid"))?;
    if index.schema_version != 2
        || index.media_type != OCI_INDEX_MEDIA_TYPE
        || index.manifests.len() != target.platforms.len()
    {
        return Err(anyhow!("n8n_update_target_index_shape_invalid"));
    }
    for expected in target.platforms {
        let found = index
            .manifests
            .iter()
            .filter(|descriptor| {
                descriptor.platform.as_ref().is_some_and(|platform| {
                    platform.os == expected.os && platform.architecture == expected.architecture
                })
            })
            .collect::<Vec<_>>();
        if found.len() != 1
            || found[0].digest != expected.child_manifest_digest
            || found[0].size <= 0
            || !is_manifest_media_type(&found[0].media_type)
        {
            return Err(anyhow!("n8n_update_target_index_descriptor_invalid"));
        }
    }
    index
        .manifests
        .into_iter()
        .find(|descriptor| {
            descriptor.platform.as_ref().is_some_and(|platform| {
                platform.os == selected.os && platform.architecture == selected.architecture
            })
        })
        .ok_or_else(|| anyhow!("n8n_update_target_index_descriptor_invalid"))
}

fn verify_child_manifest(
    raw: &[u8],
    expected: &PlatformEntry,
    descriptor_size: i64,
) -> Result<String> {
    require_digest(
        raw,
        expected.child_manifest_digest,
        "n8n_update_target_child_digest_mismatch",
    )?;
    let child: OciManifest =
        serde_json::from_slice(raw).map_err(|_| anyhow!("n8n_update_target_child_invalid"))?;
    if descriptor_size != raw.len() as i64
        || child.schema_version != 2
        || !is_manifest_media_type(&child.media_type)
        || child.config.size <= 0
        || child.config.media_type != OCI_CONFIG_MEDIA_TYPE
        || !valid_sha256_digest(&child.config.digest)
    {
        return Err(anyhow!("n8n_update_target_child_shape_invalid"));
    }
    Ok(child.config.digest)
}

fn verify_pulled_target(
    observed: &DockerImageObservation,
    target: &UpdateTargetCatalogEntry,
    platform: &PlatformEntry,
    config_digest: &str,
) -> Result<()> {
    if observed.id != config_digest {
        return Err(anyhow!("n8n_update_target_docker_config_digest_mismatch"));
    }
    if observed.os != platform.os || observed.architecture != platform.architecture {
        return Err(anyhow!("n8n_update_target_docker_platform_mismatch"));
    }
    if !observed.repo_digests.iter().any(|candidate| {
        normalized_repo_digest(candidate) == normalized_repo_digest(target.repo_digest)
    }) {
        return Err(anyhow!("n8n_update_target_docker_repo_digest_mismatch"));
    }
    Ok(())
}

fn normalized_repo_digest(value: &str) -> &str {
    value
        .strip_prefix("docker.io/")
        .or_else(|| value.strip_prefix("index.docker.io/"))
        .unwrap_or(value)
}

fn require_digest(raw: &[u8], expected: &str, error: &'static str) -> Result<()> {
    let actual = format!("sha256:{:x}", Sha256::digest(raw));
    if actual != expected {
        return Err(anyhow!(error));
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_manifest_media_type(value: &str) -> bool {
    value == OCI_MANIFEST_MEDIA_TYPE || value == DOCKER_MANIFEST_MEDIA_TYPE
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciIndex {
    schema_version: u32,
    media_type: String,
    manifests: Vec<OciDescriptor>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone)]
struct OciDescriptor {
    media_type: String,
    digest: String,
    size: i64,
    platform: Option<OciPlatform>,
}
#[derive(Clone, Deserialize)]
struct OciPlatform {
    os: String,
    architecture: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciManifest {
    schema_version: u32,
    media_type: String,
    config: OciDescriptor,
}

pub(crate) struct DockerHubRegistryTargetReader {
    client: reqwest::Client,
}
impl DockerHubRegistryTargetReader {
    pub(crate) fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| anyhow!("n8n_update_target_registry_client_unavailable"))?;
        Ok(Self { client })
    }
    async fn token(&self) -> Result<String> {
        let bytes = self.request(REGISTRY_TOKEN_URL, None, None).await?;
        parse_docker_hub_token(&bytes)
    }
    async fn request(
        &self,
        url: &str,
        bearer: Option<&str>,
        accept: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut request = self.client.get(url);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if let Some(value) = accept {
            request = request.header(reqwest::header::ACCEPT, value);
        }
        let response = request
            .send()
            .await
            .map_err(|_| anyhow!("n8n_update_target_registry_unavailable"))?;
        if !response.status().is_success() {
            return Err(anyhow!("n8n_update_target_registry_rejected"));
        }
        if response
            .content_length()
            .is_some_and(|length| length as usize > MAX_REGISTRY_BYTES)
        {
            return Err(anyhow!("n8n_update_target_registry_response_invalid"));
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| anyhow!("n8n_update_target_registry_unavailable"))?;
            if bytes.len().saturating_add(chunk.len()) > MAX_REGISTRY_BYTES {
                return Err(anyhow!("n8n_update_target_registry_response_invalid"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err(anyhow!("n8n_update_target_registry_response_invalid"));
        }
        Ok(bytes)
    }
}
#[derive(Deserialize)]
struct DockerHubToken {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    issued_at: Option<String>,
}

fn parse_docker_hub_token(bytes: &[u8]) -> Result<String> {
    let envelope: DockerHubToken = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("n8n_update_target_registry_token_invalid"))?;
    let token = envelope
        .token
        .or(envelope.access_token)
        .ok_or_else(|| anyhow!("n8n_update_target_registry_token_invalid"))?;
    if token.is_empty() || token.len() > 4096 {
        return Err(anyhow!("n8n_update_target_registry_token_invalid"));
    }
    let _ = (envelope.expires_in, envelope.issued_at);
    Ok(token)
}
#[async_trait]
impl RegistryTargetReader for DockerHubRegistryTargetReader {
    async fn read(&self, object: RegistryObject) -> Result<Vec<u8>> {
        match object {
            RegistryObject::Manifest(digest) => {
                if !valid_sha256_digest(digest) {
                    return Err(anyhow!("n8n_update_target_registry_digest_invalid"));
                }
                let token = self.token().await?;
                let url = format!("{REGISTRY_MANIFEST_BASE}{digest}");
                self.request(&url, Some(&token), Some("application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")).await
            }
        }
    }
}

struct LocalUpdateTargetDockerRunner;
#[async_trait]
impl UpdateTargetDockerRunner for LocalUpdateTargetDockerRunner {
    async fn pull_exact_target(&mut self, platform: &str, image: &str) -> Result<()> {
        if target_platform(resolve_target("n8n-2.40.7")?, platform).is_err()
            || image != N8N_UPDATE_TARGETS[0].runtime_image
        {
            return Err(anyhow!("n8n_update_target_docker_input_invalid"));
        }
        run_docker(&["pull", "--platform", platform, image], PULL_TIMEOUT)
            .await
            .map(|_| ())
    }
    async fn inspect_pulled_target(&mut self, image: &str) -> Result<DockerImageObservation> {
        if image != N8N_UPDATE_TARGETS[0].runtime_image {
            return Err(anyhow!("n8n_update_target_docker_input_invalid"));
        }
        let output = run_docker(&["image", "inspect", image], INSPECT_TIMEOUT).await?;
        parse_docker_image_observation(&output)
    }
}
#[derive(Deserialize)]
struct DockerImageInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoDigests")]
    repo_digests: Vec<String>,
    #[serde(rename = "Os")]
    os: String,
    #[serde(rename = "Architecture")]
    architecture: String,
}

/// Shared by the managed-engine adapter.  The command runner remains bound to
/// the caller; this parser cannot select an ambient Docker context.
pub(crate) fn parse_docker_image_observation(data: &[u8]) -> Result<DockerImageObservation> {
    let images: Vec<DockerImageInspect> = serde_json::from_slice(data)
        .map_err(|_| anyhow!("n8n_update_target_docker_inspect_invalid"))?;
    if images.len() != 1 { return Err(anyhow!("n8n_update_target_docker_inspect_invalid")); }
    let image = images.into_iter().next().expect("one checked image");
    Ok(DockerImageObservation { id: image.id, repo_digests: image.repo_digests, os: image.os, architecture: image.architecture })
}

async fn run_docker(args: &[&str], deadline: Duration) -> Result<Vec<u8>> {
    let mut command = Command::new("docker");
    command
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| anyhow!("n8n_update_target_docker_unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("n8n_update_target_docker_unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("n8n_update_target_docker_unavailable"))?;
    timeout(deadline, async {
        let (outcome, stdout, stderr) =
            tokio::join!(child.wait(), read_capped(stdout), read_capped(stderr));
        let status = outcome.map_err(|_| anyhow!("n8n_update_target_docker_unavailable"))?;
        let stdout = stdout?;
        stderr?;
        if !status.success() {
            return Err(anyhow!("n8n_update_target_docker_rejected"));
        }
        Ok(stdout)
    })
    .await
    .map_err(|_| anyhow!("n8n_update_target_docker_timeout"))?
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(mut reader: R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| anyhow!("n8n_update_target_docker_unavailable"))?;
        if count == 0 {
            return Ok(bytes);
        }

        if bytes.len().saturating_add(count) > MAX_COMMAND_BYTES {
            return Err(anyhow!("n8n_update_target_docker_output_too_large"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
#[path = "managed_update_target_tests.rs"]
mod tests;
