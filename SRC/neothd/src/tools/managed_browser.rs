//! Managed-browser policy, reviewed installation and capability-bound resolution.
//!
//! A caller supplies both the NEOTH home and the requested platform. Installation
//! authorizes only the exact reviewed archive; resolution walks every managed
//! component through retained no-follow directory capabilities. This module has
//! no browser launcher, ambient browser discovery, HOME, registry or PATH lookup.
//!
//! The immutable generation layout is:
//!
//!     <home>/managed-browser/generations/<platform>-<version>-<archive-sha256>/
//!         .neoth-managed-browser-generation.json
//!         chrome-headless-shell-<platform>/<reviewed executable>
//!
//! The resolver never turns a verified path into launch authority. It retains
//! the capability and object bindings required for a downstream contained
//! launcher to revalidate immediately before its own final OS-specific launch.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail, ensure};
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};

use crate::skills::store::{
    BoundChildObject, BoundDirectory, BoundDirectoryChild, open_absolute_bound_directory,
    open_bound_real_child_dir, open_bound_regular_file, open_or_create_private_child_dir,
    remove_bound_real_directory_tree, rename_child, sync_parent_directory,
    atomic_write_private_child_create_new, cap_metadata_is_link_like,
};
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpSurface,
};

pub const MANAGED_BROWSER_DIR: &str = "managed-browser";
pub const GENERATIONS_DIR: &str = "generations";
pub const GENERATION_MARKER: &str = ".neoth-managed-browser-generation.json";
const MANIFEST_SCHEMA: &str = "neoth.managed_browser.cft_manifest.v1";
const MARKER_SCHEMA: &str = "neoth.managed_browser.generation.v1";
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS: usize = 10_000;

const REVIEWED_MANIFEST_BYTES: &str =
    include_str!("../../../../docs/verification/managed-browser-cft154.json");

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ManagedBrowserConfig {
    /// Default-off artifact policy. Resolution and installation require opt-in;
    /// rendered fetching still requires its separate runtime authority.
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedBrowserPlatform {
    Win64,
    Linux64,
    MacX64,
    MacArm64,
}

impl ManagedBrowserPlatform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Win64 => "win64",
            Self::Linux64 => "linux64",
            Self::MacX64 => "mac-x64",
            Self::MacArm64 => "mac-arm64",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
struct ReviewedManifest {
    schema: String,
    product: String,
    version: String,
    revision: String,
    provenance: ManifestProvenance,
    targets: Vec<ReviewedTarget>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct ManifestProvenance {
    hosted_run: u64,
    source_head: String,
    receipt_sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct ReviewedTarget {
    platform: String,
    archive_bytes: u64,
    archive_sha256: String,
    expected_executable: String,
    expected_executable_bytes: u64,
    expected_executable_sha256: String,
    url: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct GenerationMarker {
    schema: String,
    platform: String,
    version: String,
    revision: String,
    archive_sha256: String,
    executable_sha256: String,
    executable_bytes: u64,
}

/// A verified browser executable plus the retained no-follow namespace and
/// identity bindings that authorize a later contained launcher to revalidate
/// the same object. It deliberately offers no launch method.
pub struct ResolvedManagedBrowser {
    executable: PathBuf,
    platform: ManagedBrowserPlatform,
    version: String,
    revision: String,
    archive_sha256: String,
    binding: RuntimeBinding,
}

impl fmt::Debug for ResolvedManagedBrowser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedManagedBrowser")
            .field("executable", &self.executable)
            .field("platform", &self.platform)
            .field("version", &self.version)
            .field("revision", &self.revision)
            .field("archive_sha256", &self.archive_sha256)
            .finish_non_exhaustive()
    }
}

impl ResolvedManagedBrowser {
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub const fn platform(&self) -> ManagedBrowserPlatform {
        self.platform
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    /// Revalidate the exact no-follow namespace and regular-file identity
    /// retained during resolution. A downstream contained launcher must call
    /// this immediately before its final launch preparation and must refuse
    /// when it fails; this resolver does not claim to make a later OS launch
    /// race-free by itself.
    pub fn revalidate_for_launch(&self) -> Result<()> {
        self.binding.revalidate()
    }
}

struct RuntimeBinding {
    home: BoundDirectory,
    managed_root: Dir,
    managed_root_binding: BoundDirectoryChild,
    generations: Dir,
    generations_binding: BoundDirectoryChild,
    generation: Dir,
    generation_binding: BoundDirectoryChild,
    executable_parent: Dir,
    executable_parent_binding: BoundDirectoryChild,
    executable_binding: BoundChildObject,
    managed_root_name: OsString,
    generations_name: OsString,
    generation_name: OsString,
    executable_parent_name: OsString,
    executable_name: OsString,
    managed_root_display: PathBuf,
    generations_display: PathBuf,
    generation_display: PathBuf,
    executable_parent_display: PathBuf,
    executable_display: PathBuf,
}

impl RuntimeBinding {
    fn revalidate(&self) -> Result<()> {
        ensure!(
            self.managed_root_binding.matches_directory_child(
                &self.home.dir,
                &self.managed_root_name,
                &self.managed_root_display,
            )?,
            "managed-browser root changed after resolution"
        );
        ensure!(
            self.generations_binding.matches_directory_child(
                &self.managed_root,
                &self.generations_name,
                &self.generations_display,
            )?,
            "managed-browser generations changed after resolution"
        );
        ensure!(
            self.generation_binding.matches_directory_child(
                &self.generations,
                &self.generation_name,
                &self.generation_display,
            )?,
            "managed-browser generation changed after resolution"
        );
        ensure!(
            self.executable_parent_binding.matches_directory_child(
                &self.generation,
                &self.executable_parent_name,
                &self.executable_parent_display,
            )?,
            "managed-browser executable parent changed after resolution"
        );
        ensure!(
            self.executable_binding
                .matches_regular_file_child_readonly(
                    &self.executable_parent,
                    &self.executable_name,
                    &self.executable_display,
                )?,
            "managed-browser executable changed after resolution"
        );
        Ok(())
    }
}

/// Pure explicit-home resolver for the compiled-in reviewed CFT manifest.
pub struct ManagedBrowserRuntimeResolver<'a> {
    home: &'a Path,
    platform: ManagedBrowserPlatform,
    config: &'a ManagedBrowserConfig,
}

impl<'a> ManagedBrowserRuntimeResolver<'a> {
    pub fn new(
        home: &'a Path,
        platform: ManagedBrowserPlatform,
        config: &'a ManagedBrowserConfig,
    ) -> Self {
        Self {
            home,
            platform,
            config,
        }
    }

    pub fn resolve(&self) -> Result<ResolvedManagedBrowser> {
        ensure!(
            self.config.enabled,
            "managed browser is disabled by configuration"
        );
        let manifest = reviewed_manifest()?;
        resolve_from_manifest(self.home, self.platform, &manifest)
    }
}

fn reviewed_manifest() -> Result<ReviewedManifest> {
    parse_reviewed_manifest(REVIEWED_MANIFEST_BYTES)
}

fn parse_reviewed_manifest(bytes: &str) -> Result<ReviewedManifest> {
    let manifest: ReviewedManifest =
        serde_json::from_str(bytes).context("parse compiled-in managed-browser manifest")?;
    ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "managed-browser manifest schema is unsupported"
    );
    ensure!(
        manifest.product == "chrome-headless-shell",
        "managed-browser manifest product is unsupported"
    );
    ensure!(
        !manifest.version.is_empty(),
        "managed-browser manifest has no version"
    );
    ensure!(
        !manifest.revision.is_empty(),
        "managed-browser manifest has no revision"
    );
    ensure!(
        manifest.provenance.hosted_run > 0
            && is_sha256(&manifest.provenance.receipt_sha256)
            && is_git_sha(&manifest.provenance.source_head),
        "managed-browser manifest provenance is malformed"
    );
    ensure!(
        manifest.targets.len() == 4,
        "managed-browser manifest must declare exactly four reviewed targets"
    );

    let mut seen = std::collections::BTreeSet::new();
    for target in &manifest.targets {
        ensure!(
            matches!(
                target.platform.as_str(),
                "win64" | "linux64" | "mac-x64" | "mac-arm64"
            ) && seen.insert(target.platform.as_str()),
            "managed-browser manifest has duplicate or unsupported platform"
        );
        ensure!(
            is_sha256(&target.archive_sha256) && is_sha256(&target.expected_executable_sha256),
            "managed-browser manifest digest is malformed for {}",
            target.platform
        );
        ensure!(
            target.archive_bytes > 0 && target.archive_bytes <= MAX_ARCHIVE_BYTES,
            "managed-browser manifest archive byte length is malformed for {}",
            target.platform
        );
        ensure!(
            target.expected_executable_bytes > 0
                && is_fixed_executable_path(&target.expected_executable),
            "managed-browser manifest executable path is malformed for {}",
            target.platform
        );
        let exact_url = expected_archive_url(&manifest.version, &target.platform);
        ensure!(
            target.url == exact_url,
            "managed-browser manifest archive URL is not the exact reviewed CFT target for {}",
            target.platform
        );
    }
    Ok(manifest)
}

fn resolve_from_manifest(
    home_path: &Path,
    platform: ManagedBrowserPlatform,
    manifest: &ReviewedManifest,
) -> Result<ResolvedManagedBrowser> {
    let target = manifest
        .targets
        .iter()
        .find(|target| target.platform == platform.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "managed-browser platform {} is not admitted",
                platform.as_str()
            )
        })?;
    let home = open_absolute_bound_directory(home_path, false, "managed-browser explicit home")?
        .ok_or_else(|| anyhow::anyhow!("managed-browser explicit home is missing"))?;

    let managed_root_name = OsString::from(MANAGED_BROWSER_DIR);
    let managed_root_display = home.physical_display_path.join(&managed_root_name);
    let (managed_root, managed_root_binding) =
        open_bound_real_child_dir(&home.dir, &managed_root_name, &managed_root_display)?;

    let generations_name = OsString::from(GENERATIONS_DIR);
    let generations_display = managed_root_display.join(&generations_name);
    let (generations, generations_binding) =
        open_bound_real_child_dir(&managed_root, &generations_name, &generations_display)?;

    let generation_name = OsString::from(format!(
        "{}-{}-{}",
        target.platform, manifest.version, target.archive_sha256
    ));
    ensure!(
        is_safe_component(&generation_name.to_string_lossy()),
        "managed-browser generation name is unsafe"
    );
    let generation_display = generations_display.join(&generation_name);
    let (generation, generation_binding) =
        open_bound_real_child_dir(&generations, &generation_name, &generation_display)?;

    let marker_name = OsString::from(GENERATION_MARKER);
    let marker_display = generation_display.join(&marker_name);
    let (mut marker_file, _marker_binding) =
        open_bound_regular_file(&generation, &marker_name, &marker_display)?;
    let marker_bytes = read_bounded(&mut marker_file, 4096, "managed-browser marker")?;
    let marker: GenerationMarker =
        serde_json::from_slice(&marker_bytes).context("parse managed-browser generation marker")?;
    ensure!(
        marker.schema == MARKER_SCHEMA
            && marker.platform == target.platform
            && marker.version == manifest.version
            && marker.revision == manifest.revision
            && marker.archive_sha256 == target.archive_sha256
            && marker.executable_sha256 == target.expected_executable_sha256
            && marker.executable_bytes == target.expected_executable_bytes,
        "managed-browser generation marker does not bind the reviewed target"
    );

    let (executable_parent_component, executable_component) =
        fixed_executable_components(&target.expected_executable)?;
    let executable_parent_name = executable_parent_component.to_os_string();
    let executable_parent_display = generation_display.join(&executable_parent_name);
    let (executable_parent, executable_parent_binding) = open_bound_real_child_dir(
        &generation,
        &executable_parent_name,
        &executable_parent_display,
    )?;
    let executable_name = executable_component.to_os_string();
    let executable_display = executable_parent_display.join(&executable_name);
    let (mut executable_file, executable_binding) =
        open_bound_regular_file(&executable_parent, &executable_name, &executable_display)?;
    let digest = hash_regular_file_exact(
        &mut executable_file,
        target.expected_executable_bytes,
        "managed-browser executable",
    )?;
    ensure!(
        digest == target.expected_executable_sha256,
        "managed-browser executable digest does not match reviewed target"
    );

    let binding = RuntimeBinding {
        home,
        managed_root,
        managed_root_binding,
        generations,
        generations_binding,
        generation,
        generation_binding,
        executable_parent,
        executable_parent_binding,
        executable_binding,
        managed_root_name,
        generations_name,
        generation_name,
        executable_parent_name,
        executable_name,
        managed_root_display,
        generations_display,
        generation_display,
        executable_parent_display,
        executable_display: executable_display.clone(),
    };
    binding.revalidate()?;

    Ok(ResolvedManagedBrowser {
        executable: executable_display,
        platform,
        version: manifest.version.clone(),
        revision: manifest.revision.clone(),
        archive_sha256: target.archive_sha256.clone(),
        binding,
    })
}

/// Result of a single exact reviewed-artifact installation attempt. Neither
/// variant starts a browser or creates CDP/egress authority.
pub enum ManagedBrowserInstallResult {
    VerifiedExisting(ResolvedManagedBrowser),
    Installed(ResolvedManagedBrowser),
}

impl ManagedBrowserInstallResult {
    pub fn resolved(&self) -> &ResolvedManagedBrowser {
        match self {
            Self::VerifiedExisting(resolved) | Self::Installed(resolved) => resolved,
        }
    }

    pub const fn installed(&self) -> bool {
        matches!(self, Self::Installed(_))
    }
}

/// Install one compiled-in reviewed CFT target. The caller supplies the
/// explicit home, platform, mandatory external-HTTP authorizer, and a
/// cancellation flag. There is deliberately no ambient-home, PATH, registry,
/// browser-launch, or automatic-update path here.
pub async fn install_reviewed_managed_browser(
    home: &Path,
    platform: ManagedBrowserPlatform,
    config: &ManagedBrowserConfig,
    http: &ExternalHttpAuthorizer,
    cancelled: &AtomicBool,
) -> Result<ManagedBrowserInstallResult> {
    ensure!(config.enabled, "managed browser is disabled by configuration");
    ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");

    let manifest = reviewed_manifest()?;
    if let Ok(resolved) = resolve_from_manifest(home, platform, &manifest) {
        return Ok(ManagedBrowserInstallResult::VerifiedExisting(resolved));
    }
    let target = manifest
        .targets
        .iter()
        .find(|target| target.platform == platform.as_str())
        .context("managed-browser platform is not admitted")?;

    let archive = download_reviewed_archive(target, http, cancelled).await?;
    ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
    install_archive_from_manifest(home, platform, &manifest, target, &archive, cancelled)
}

fn install_archive_from_manifest(
    home: &Path,
    platform: ManagedBrowserPlatform,
    manifest: &ReviewedManifest,
    target: &ReviewedTarget,
    archive: &[u8],
    cancelled: &AtomicBool,
) -> Result<ManagedBrowserInstallResult> {
    ensure!(
        u64::try_from(archive.len()).context("managed-browser archive length does not fit u64")?
            == target.archive_bytes,
        "managed-browser archive byte length does not match reviewed target"
    );
    ensure!(
        hex::encode(Sha256::digest(archive)) == target.archive_sha256,
        "managed-browser archive digest does not match reviewed target"
    );
    if let Ok(resolved) = resolve_from_manifest(home, platform, manifest) {
        return Ok(ManagedBrowserInstallResult::VerifiedExisting(resolved));
    }
    install_verified_archive(home, platform, manifest, target, archive, cancelled)
        .map(ManagedBrowserInstallResult::Installed)
}

async fn download_reviewed_archive(
    target: &ReviewedTarget,
    http: &ExternalHttpAuthorizer,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    download_reviewed_archive_at(
        &target.url,
        target.archive_bytes,
        &target.archive_sha256,
        http,
        cancelled,
    )
    .await
}

async fn download_reviewed_archive_at(
    url: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    http: &ExternalHttpAuthorizer,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let request = ExternalHttpRequest::get(url, ExternalHttpSurface::ManagedBrowserInstall);
    let permitted_request = request.clone();
    let url = url.to_owned();
    let expected_bytes = expected_bytes;
    let expected_sha256 = expected_sha256.to_owned();
    http.execute(request, move |permit| async move {
        permit.require(&permitted_request)?;
        ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
        let client = crate::providers::http_client::build_client_no_redirect()
            .context("build no-redirect managed-browser HTTP client")?;
        let mut response = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("download reviewed managed-browser archive {url}"))?;
        ensure!(
            !response.status().is_redirection(),
            "managed-browser archive returned an unexpected redirect"
        );
        ensure!(
            response.status().is_success(),
            "managed-browser archive returned HTTP {}",
            response.status()
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length == expected_bytes,
                "managed-browser archive Content-Length does not match reviewed target"
            );
        }

        let mut archive = Vec::new();
        let mut digest = Sha256::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read managed-browser archive stream")?
        {
            ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
            let total = u64::try_from(archive.len())
                .context("managed-browser archive length does not fit u64")?
                .checked_add(u64::try_from(chunk.len()).context("archive chunk length does not fit u64")?)
                .context("managed-browser archive length overflow")?;
            ensure!(
                total <= expected_bytes,
                "managed-browser archive exceeds reviewed byte length"
            );
            digest.update(&chunk);
            archive.extend_from_slice(&chunk);
        }
        ensure!(
            u64::try_from(archive.len()).context("managed-browser archive length does not fit u64")?
                == expected_bytes,
            "managed-browser archive byte length does not match reviewed target"
        );
        ensure!(
            hex::encode(digest.finalize()) == expected_sha256,
            "managed-browser archive digest does not match reviewed target"
        );
        Ok(archive)
    })
    .await
}

fn install_verified_archive(
    home_path: &Path,
    platform: ManagedBrowserPlatform,
    manifest: &ReviewedManifest,
    target: &ReviewedTarget,
    archive: &[u8],
    cancelled: &AtomicBool,
) -> Result<ResolvedManagedBrowser> {
    ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
    let home = open_absolute_bound_directory(home_path, false, "managed-browser explicit home")?
        .context("managed-browser explicit home is missing")?;
    let managed_display = home.physical_display_path.join(MANAGED_BROWSER_DIR);
    let managed = open_or_create_private_child_dir(&home.dir, OsStr::new(MANAGED_BROWSER_DIR), &managed_display)?;
    let generations_display = managed_display.join(GENERATIONS_DIR);
    let generations = open_or_create_private_child_dir(
        &managed,
        OsStr::new(GENERATIONS_DIR),
        &generations_display,
    )?;
    let generation_name = format!("{}-{}-{}", target.platform, manifest.version, target.archive_sha256);
    ensure!(is_safe_component(&generation_name), "managed-browser generation name is unsafe");
    let stage_name = OsString::from(format!(".stage-{}", uuid::Uuid::now_v7().simple()));
    let stage_display = generations_display.join(&stage_name);
    let (stage, stage_binding) = create_private_stage(&generations, &stage_name, &stage_display)?;

    let mut published = false;
    let install = (|| {
        revalidate_stage(&stage_binding, &generations, &stage_name, &stage_display)?;
        extract_reviewed_zip(&stage, &stage_display, target, archive, cancelled)?;
        ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
        revalidate_stage(&stage_binding, &generations, &stage_name, &stage_display)?;
        write_generation_marker(&stage, &stage_display, manifest, target)?;
        ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
        revalidate_stage(&stage_binding, &generations, &stage_name, &stage_display)?;
        drop(stage);
        let generation_display = generations_display.join(&generation_name);
        rename_child(
            &generations,
            &stage_name,
            &generations,
            OsStr::new(&generation_name),
            false,
            &stage_display,
            &generation_display,
        )?;
        published = true;
        confirm_published_stage_identity(
            &stage_binding,
            &generations,
            OsStr::new(&generation_name),
            &generation_display,
        )?;
        let _ = sync_parent_directory(&generations, &generations_display)?;
        resolve_from_manifest(home_path, platform, manifest)
    })();
    if install.is_err() && !published {
        // The stage name is freshly allocated and only this operation may
        // remove it. Cleanup is bounded and capability-relative; an ambiguous
        // cleanup failure remains visible to the operator.
        if let Err(cleanup) = remove_bound_real_directory_tree(
            &generations,
            &stage_name,
            &stage_display,
            stage_binding.identity_token(),
        ) {
            return Err(install.err().expect("checked error").context(format!(
                "managed-browser stage cleanup also failed: {cleanup}"
            )));
        }
    }
    install
}

fn create_private_stage(parent: &Dir, name: &OsStr, display: &Path) -> Result<(Dir, BoundDirectoryChild)> {
    let created: std::io::Result<()> = {
        #[cfg(unix)]
        {
            use cap_std::fs::{DirBuilder, DirBuilderExt as _};
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            parent.create_dir_with(name, &builder)
        }
        #[cfg(not(unix))]
        {
            parent.create_dir(name)
        }
    };
    created.with_context(|| format!("create managed-browser private stage {}", display.display()))?;
    let (stage, binding) = open_bound_real_child_dir(parent, name, display)?;
    let metadata = stage.dir_metadata().context("inspect managed-browser stage")?;
    ensure!(metadata.is_dir() && !cap_metadata_is_link_like(&metadata), "managed-browser stage is not a real directory");
    let _ = sync_parent_directory(parent, display.parent().unwrap_or(display))?;
    Ok((stage, binding))
}

fn extract_reviewed_zip(
    stage: &Dir,
    stage_display: &Path,
    target: &ReviewedTarget,
    archive_bytes: &[u8],
    cancelled: &AtomicBool,
) -> Result<()> {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    let expected_root = fixed_executable_components(&target.expected_executable)?.0;
    let expected_root = expected_root.to_string_lossy().into_owned();
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes)).context("open reviewed managed-browser ZIP")?;
    ensure!(archive.len() <= MAX_ARCHIVE_MEMBERS, "managed-browser ZIP has too many members");
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
        let entry = archive.by_index(index).context("read managed-browser ZIP member")?;
        let raw = std::str::from_utf8(entry.name_raw()).context("managed-browser ZIP member name is not UTF-8")?;
        let components = safe_zip_components(raw)?;
        ensure!(components.first().is_some_and(|component| component == &expected_root), "managed-browser ZIP has unexpected top-level root");
        let key = components.join("/").to_ascii_lowercase();
        ensure!(seen.insert(key), "managed-browser ZIP has duplicate or case-colliding member");
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            let expected_kind = if entry.is_dir() { 0o040_000 } else { 0o100_000 };
            ensure!(kind == 0 || kind == expected_kind, "managed-browser ZIP contains symlink or special member");
        }
        if !entry.is_dir() {
            ensure!(entry.size() <= MAX_ARCHIVE_MEMBER_BYTES, "managed-browser ZIP member exceeds byte limit");
            total = total.checked_add(entry.size()).context("managed-browser ZIP byte count overflow")?;
            ensure!(total <= MAX_UNCOMPRESSED_BYTES, "managed-browser ZIP exceeds uncompressed byte limit");
        }
    }
    drop(archive);

    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes)).context("reopen reviewed managed-browser ZIP")?;
    for index in 0..archive.len() {
        ensure!(!cancelled.load(Ordering::Acquire), "managed-browser install cancelled");
        let mut entry = archive.by_index(index).context("read managed-browser ZIP member")?;
        let raw = std::str::from_utf8(entry.name_raw()).context("managed-browser ZIP member name is not UTF-8")?;
        let components = safe_zip_components(raw)?;
        if entry.is_dir() {
            let _ = ensure_stage_directory(stage, stage_display, &components)?;
            continue;
        }
        let file_name = OsString::from(components.last().context("managed-browser ZIP member has no file name")?);
        let parent = ensure_stage_directory(stage, stage_display, &components[..components.len() - 1])?;
        let file_display = stage_display.join(components.join("/"));
        let (mut output, _) = crate::skills::store::create_private_regular_file_child_create_new(
            &parent,
            &file_name,
            &file_display,
        )?;
        let declared_size = entry.size();
        copy_zip_member_exact(&mut entry, &mut output, declared_size, &file_display)?;
    }
    verify_staged_executable(stage, stage_display, target)
}

fn safe_zip_components(raw: &str) -> Result<Vec<&str>> {
    ensure!(
        !raw.is_empty() && !raw.starts_with('/') && !raw.starts_with('\\') && !raw.contains('\\'),
        "managed-browser ZIP member path is absolute or uses a Windows separator"
    );
    let path = Path::new(raw);
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => result.push(value.to_str().context("managed-browser ZIP member component is not UTF-8")?),
            _ => bail!("managed-browser ZIP member path is unsafe"),
        }
    }
    ensure!(!result.is_empty(), "managed-browser ZIP member path is empty");
    Ok(result)
}

fn ensure_stage_directory(stage: &Dir, display: &Path, components: &[&str]) -> Result<Dir> {
    let mut current = stage.try_clone().context("clone managed-browser stage capability")?;
    let mut current_display = display.to_path_buf();
    for component in components {
        current_display.push(component);
        current = open_or_create_private_child_dir(&current, OsStr::new(component), &current_display)?;
    }
    Ok(current)
}

fn copy_zip_member_exact(
    input: &mut impl Read,
    output: &mut cap_std::fs::File,
    expected: u64,
    display: &Path,
) -> Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).with_context(|| format!("read ZIP member {}", display.display()))?;
        if read == 0 { break; }
        total = total.checked_add(read as u64).context("managed-browser ZIP member length overflow")?;
        ensure!(total <= expected, "managed-browser ZIP member exceeds declared length");
        output.write_all(&buffer[..read]).with_context(|| format!("write ZIP member {}", display.display()))?;
    }
    ensure!(total == expected, "managed-browser ZIP member length differs from declared length");
    output.sync_all().with_context(|| format!("sync ZIP member {}", display.display()))
}

fn verify_staged_executable(stage: &Dir, stage_display: &Path, target: &ReviewedTarget) -> Result<()> {
    let (parent_component, executable_component) = fixed_executable_components(&target.expected_executable)?;
    let parent_display = stage_display.join(parent_component);
    let (parent, _) = open_bound_real_child_dir(stage, parent_component, &parent_display)?;
    let executable_display = parent_display.join(executable_component);
    let (mut executable, _) = open_bound_regular_file(&parent, executable_component, &executable_display)?;
    let digest = hash_regular_file_exact(&mut executable, target.expected_executable_bytes, "staged managed-browser executable")?;
    ensure!(digest == target.expected_executable_sha256, "staged managed-browser executable digest does not match reviewed target");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        executable
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .context("grant owner execute to verified managed-browser executable")?;
        ensure!(
            executable
                .metadata()
                .context("inspect verified managed-browser executable permissions")?
                .permissions()
                .mode()
                & 0o777
                == 0o700,
            "verified managed-browser executable is not owner-executable and private"
        );
        executable.sync_all().context("sync verified managed-browser executable permissions")?;
    }
    Ok(())
}

fn write_generation_marker(
    stage: &Dir,
    stage_display: &Path,
    manifest: &ReviewedManifest,
    target: &ReviewedTarget,
) -> Result<()> {
    let marker = GenerationMarker {
        schema: MARKER_SCHEMA.to_owned(),
        platform: target.platform.clone(),
        version: manifest.version.clone(),
        revision: manifest.revision.clone(),
        archive_sha256: target.archive_sha256.clone(),
        executable_sha256: target.expected_executable_sha256.clone(),
        executable_bytes: target.expected_executable_bytes,
    };
    let marker_bytes = serde_json::to_vec(&marker).context("serialize managed-browser generation marker")?;
    atomic_write_private_child_create_new(
        stage,
        OsStr::new(GENERATION_MARKER),
        &stage_display.join(GENERATION_MARKER),
        &marker_bytes,
    )
}

fn revalidate_stage(
    binding: &BoundDirectoryChild,
    generations: &Dir,
    stage_name: &OsStr,
    stage_display: &Path,
) -> Result<()> {
    ensure!(
        binding.matches_directory_child(generations, stage_name, stage_display)?,
        "managed-browser stage changed before publication"
    );
    Ok(())
}

fn confirm_published_stage_identity(
    stage_binding: &BoundDirectoryChild,
    generations: &Dir,
    generation_name: &OsStr,
    generation_display: &Path,
) -> Result<()> {
    let (_, published_binding) =
        open_bound_real_child_dir(generations, generation_name, generation_display)?;
    ensure!(
        published_binding.identity_token() == stage_binding.identity_token(),
        "managed-browser published generation identity does not match staged generation"
    );
    Ok(())
}

fn expected_archive_url(version: &str, platform: &str) -> String {
    format!(
        "https://storage.googleapis.com/chrome-for-testing-public/{version}/{platform}/chrome-headless-shell-{platform}.zip"
    )
}

fn fixed_executable_components(relative: &str) -> Result<(&OsStr, &OsStr)> {
    let components = Path::new(relative).components().collect::<Vec<_>>();
    let [Component::Normal(parent), Component::Normal(file)] = components.as_slice() else {
        bail!("managed-browser executable path must be exactly two normal components");
    };
    Ok((parent, file))
}

fn is_fixed_executable_path(path: &str) -> bool {
    fixed_executable_components(path).is_ok()
}

fn read_bounded(file: &mut cap_std::fs::File, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "{label} exceeds byte limit"
    );
    Ok(bytes)
}

fn hash_regular_file_exact(
    file: &mut cap_std::fs::File,
    expected_bytes: u64,
    label: &str,
) -> Result<String> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} byte count overflow"))?;
        ensure!(
            total <= expected_bytes,
            "{label} exceeds reviewed byte length"
        );
        digest.update(&buffer[..read]);
    }
    ensure!(
        total == expected_bytes,
        "{label} byte length does not match reviewed target"
    );
    Ok(hex::encode(digest.finalize()))
}

fn is_safe_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.contains('/')
        && !component.contains('\\')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MANIFEST: &str = r#"{
      "schema":"neoth.managed_browser.cft_manifest.v1",
      "product":"chrome-headless-shell",
      "version":"test-1",
      "revision":"test-r",
      "provenance":{"hosted_run":1,"source_head":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
      "targets":[
        {"platform":"win64","archive_bytes":123,"archive_sha256":"1111111111111111111111111111111111111111111111111111111111111111","expected_executable":"shell/browser.exe","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/win64/chrome-headless-shell-win64.zip"},
        {"platform":"linux64","archive_bytes":123,"archive_sha256":"2222222222222222222222222222222222222222222222222222222222222222","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/linux64/chrome-headless-shell-linux64.zip"},
        {"platform":"mac-x64","archive_bytes":123,"archive_sha256":"3333333333333333333333333333333333333333333333333333333333333333","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/mac-x64/chrome-headless-shell-mac-x64.zip"},
        {"platform":"mac-arm64","archive_bytes":123,"archive_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/mac-arm64/chrome-headless-shell-mac-arm64.zip"}
      ]
    }"#;

    fn fixture_manifest() -> ReviewedManifest {
        parse_reviewed_manifest(TEST_MANIFEST).unwrap()
    }

    fn fixture_home() -> tempfile::TempDir {
        let canonical_temp = std::env::temp_dir()
            .canonicalize()
            .expect("canonicalize fixture temp root");
        tempfile::Builder::new()
            .prefix("neoth-managed-browser-")
            .tempdir_in(canonical_temp)
            .expect("create canonical fixture home")
    }

    fn fixture_generation(home: &Path, manifest: &ReviewedManifest) -> PathBuf {
        let target = &manifest.targets[0];
        let generation = home
            .join(MANAGED_BROWSER_DIR)
            .join(GENERATIONS_DIR)
            .join(format!(
                "{}-{}-{}",
                target.platform, manifest.version, target.archive_sha256
            ));
        std::fs::create_dir_all(generation.join("shell")).unwrap();
        std::fs::write(
            generation.join("shell").join("browser.exe"),
            [1_u8, 2, 3, 4],
        )
        .unwrap();
        std::fs::write(
            generation.join(GENERATION_MARKER),
            r#"{"schema":"neoth.managed_browser.generation.v1","platform":"win64","version":"test-1","revision":"test-r","archive_sha256":"1111111111111111111111111111111111111111111111111111111111111111","executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","executable_bytes":4}"#,
        )
        .unwrap();
        generation
    }

    #[test]
    fn config_defaults_disabled() {
        assert!(!ManagedBrowserConfig::default().enabled);
    }

    #[test]
    fn forged_manifest_and_nonexact_target_url_are_rejected() {
        assert!(parse_reviewed_manifest(TEST_MANIFEST.replace("test-1", "").as_str()).is_err());
        assert!(
            parse_reviewed_manifest(TEST_MANIFEST.replace("111111", "nothex").as_str()).is_err()
        );
        assert!(parse_reviewed_manifest(
            TEST_MANIFEST.replace(
                "https://storage.googleapis.com/chrome-for-testing-public/test-1/win64/chrome-headless-shell-win64.zip",
                "https://storage.googleapis.com/chrome-for-testing-public/test-1/win64/other.zip",
            ).as_str()
        ).is_err());
    }

    #[test]
    fn disabled_policy_refuses_before_home_inspection() {
        let config = ManagedBrowserConfig::default();
        let missing_home = Path::new("managed-browser-test-missing-home");
        let error = ManagedBrowserRuntimeResolver::new(
            missing_home,
            ManagedBrowserPlatform::Win64,
            &config,
        )
        .resolve()
        .unwrap_err();
        assert!(error.to_string().contains("disabled"));
    }

    #[test]
    fn missing_generation_fails_closed_without_ambient_fallback() {
        let home = fixture_home();
        let manifest = fixture_manifest();
        let error = resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest)
            .unwrap_err();
        assert!(error.to_string().contains("managed-browser root"));
    }

    #[test]
    fn exact_marker_and_executable_resolve_and_revalidate() {
        let home = fixture_home();
        let manifest = fixture_manifest();
        let generation = fixture_generation(home.path(), &manifest);
        let resolved = resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest)
            .expect("exact immutable fixture resolves");
        assert_eq!(
            resolved.executable(),
            generation.join("shell").join("browser.exe")
        );
        resolved
            .revalidate_for_launch()
            .expect("retained fixture binding remains current");
    }

    #[test]
    fn forged_marker_digest_and_path_are_rejected() {
        let home = fixture_home();
        let manifest = fixture_manifest();
        let generation = fixture_generation(home.path(), &manifest);
        std::fs::write(
            generation.join(GENERATION_MARKER),
            r#"{"schema":"neoth.managed_browser.generation.v1","platform":"win64","version":"test-1","revision":"test-r","archive_sha256":"1111111111111111111111111111111111111111111111111111111111111111","executable_sha256":"0000000000000000000000000000000000000000000000000000000000000000","executable_bytes":4}"#,
        )
        .unwrap();
        assert!(
            resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest).is_err()
        );

        let malicious = TEST_MANIFEST.replace("shell/browser.exe", "../ambient-browser.exe");
        assert!(parse_reviewed_manifest(&malicious).is_err());
    }

    fn zip_fixture(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write as _};

        let mut bytes = Vec::new();
        let cursor = Cursor::new(&mut bytes);
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, body) in members {
            writer
                .start_file::<_, ()>(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
        bytes
    }

    fn reviewed_archive_fixture() -> (ReviewedManifest, Vec<u8>) {
        let archive = zip_fixture(&[
            ("shell/browser.exe", &[1_u8, 2, 3, 4]),
            ("shell/runtime.dat", b"fixture runtime"),
        ]);
        let mut manifest = fixture_manifest();
        manifest.targets[0].archive_bytes = archive.len() as u64;
        manifest.targets[0].archive_sha256 = hex::encode(Sha256::digest(&archive));
        (manifest, archive)
    }

    #[tokio::test]
    async fn disabled_or_precancelled_install_creates_no_stage_or_network_route() {
        let home = fixture_home();
        let disabled = ManagedBrowserConfig::default();
        assert!(install_reviewed_managed_browser(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &disabled,
            &ExternalHttpAuthorizer::test_allow(),
            &AtomicBool::new(false),
        )
        .await
        .is_err());
        assert!(!home.path().join(MANAGED_BROWSER_DIR).exists());

        let enabled = ManagedBrowserConfig { enabled: true };
        let cancelled = AtomicBool::new(true);
        assert!(install_reviewed_managed_browser(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &enabled,
            &ExternalHttpAuthorizer::test_allow(),
            &cancelled,
        )
        .await
        .is_err());
        assert!(!home.path().join(MANAGED_BROWSER_DIR).exists());
    }

    #[tokio::test]
    async fn denied_authorizer_creates_no_stage_before_transport() {
        let home = fixture_home();
        let denied = ExternalHttpAuthorizer::test_policy(
            crate::permissions::AutonomyPolicySnapshot::test_level(
                crate::permissions::AutonomyLevel::Strict,
            ),
            crate::permissions::ConfirmStrategy::FailClosed,
        );
        assert!(install_reviewed_managed_browser(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &ManagedBrowserConfig { enabled: true },
            &denied,
            &AtomicBool::new(false),
        )
        .await
        .is_err());
        assert!(!home.path().join(MANAGED_BROWSER_DIR).exists());
    }

    #[test]
    fn controlled_install_publishes_marker_resolves_and_is_idempotent() {
        let home = fixture_home();
        let (manifest, archive) = reviewed_archive_fixture();
        let cancelled = AtomicBool::new(false);
        let first = install_archive_from_manifest(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &manifest,
            &manifest.targets[0],
            &archive,
            &cancelled,
        )
        .expect("controlled archive publishes a complete W333 generation");
        assert!(first.installed());
        assert!(first.resolved().executable().is_file());
        let second = install_archive_from_manifest(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &manifest,
            &manifest.targets[0],
            &archive,
            &cancelled,
        )
        .expect("matching verified generation is returned without replacement");
        assert!(!second.installed());
    }

    #[test]
    fn wrong_verified_archive_length_or_digest_creates_no_stage() {
        for wrong_digest in [false, true] {
            let home = fixture_home();
            let (mut manifest, archive) = reviewed_archive_fixture();
            if wrong_digest {
                manifest.targets[0].archive_sha256 = "0".repeat(64);
            } else {
                manifest.targets[0].archive_bytes += 1;
            }
            assert!(install_archive_from_manifest(
                home.path(),
                ManagedBrowserPlatform::Win64,
                &manifest,
                &manifest.targets[0],
                &archive,
                &AtomicBool::new(false),
            )
            .is_err());
            assert!(
                !home.path().join(MANAGED_BROWSER_DIR).exists(),
                "archive verification must fail before stage creation"
            );
        }
    }

    #[test]
    fn existing_invalid_generation_is_never_replaced_on_collision() {
        let home = fixture_home();
        let (manifest, archive) = reviewed_archive_fixture();
        let target = &manifest.targets[0];
        let generation = home
            .path()
            .join(MANAGED_BROWSER_DIR)
            .join(GENERATIONS_DIR)
            .join(format!("{}-{}-{}", target.platform, manifest.version, target.archive_sha256));
        std::fs::create_dir_all(&generation).unwrap();
        std::fs::write(generation.join("foreign-kept"), b"must survive").unwrap();
        assert!(install_archive_from_manifest(
            home.path(),
            ManagedBrowserPlatform::Win64,
            &manifest,
            target,
            &archive,
            &AtomicBool::new(false),
        )
        .is_err());
        assert_eq!(std::fs::read(generation.join("foreign-kept")).unwrap(), b"must survive");
    }

    #[test]
    fn replaced_stage_binding_refuses_cleanup_without_deleting_foreign_tree() {
        let home = fixture_home();
        let generations_path = home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR);
        std::fs::create_dir_all(&generations_path).unwrap();
        let home_binding = open_absolute_bound_directory(home.path(), false, "test home").unwrap().unwrap();
        let managed = open_bound_real_child_dir(&home_binding.dir, OsStr::new(MANAGED_BROWSER_DIR), &home.path().join(MANAGED_BROWSER_DIR)).unwrap().0;
        let generations = open_bound_real_child_dir(&managed, OsStr::new(GENERATIONS_DIR), &generations_path).unwrap().0;
        let name = OsStr::new(".stage-test");
        let display = generations_path.join(".stage-test");
        let (stage, binding) = create_private_stage(&generations, name, &display).unwrap();
        drop(stage);
        let retained_name = OsStr::new(".stage-retained-test");
        let retained_display = generations_path.join(retained_name);
        rename_child(
            &generations,
            name,
            &generations,
            retained_name,
            false,
            &display,
            &retained_display,
        )
        .unwrap();
        std::fs::create_dir(&display).unwrap();
        std::fs::write(display.join("foreign-kept"), b"must survive").unwrap();
        assert!(revalidate_stage(&binding, &generations, name, &display).is_err());
        assert!(remove_bound_real_directory_tree(&generations, name, &display, binding.identity_token()).is_err());
        assert_eq!(std::fs::read(display.join("foreign-kept")).unwrap(), b"must survive");
    }

    #[test]
    fn replaced_published_generation_fails_identity_confirmation_without_cleanup() {
        let home = fixture_home();
        let generations_path = home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR);
        std::fs::create_dir_all(&generations_path).unwrap();
        let home_binding = open_absolute_bound_directory(home.path(), false, "test home").unwrap().unwrap();
        let managed = open_bound_real_child_dir(&home_binding.dir, OsStr::new(MANAGED_BROWSER_DIR), &home.path().join(MANAGED_BROWSER_DIR)).unwrap().0;
        let generations = open_bound_real_child_dir(&managed, OsStr::new(GENERATIONS_DIR), &generations_path).unwrap().0;
        let stage_name = OsStr::new(".stage-test");
        let stage_display = generations_path.join(".stage-test");
        let (stage, binding) = create_private_stage(&generations, stage_name, &stage_display).unwrap();
        drop(stage);
        let generation_name = OsStr::new("published-generation");
        let generation_display = generations_path.join(generation_name);
        rename_child(
            &generations,
            stage_name,
            &generations,
            generation_name,
            false,
            &stage_display,
            &generation_display,
        )
        .unwrap();
        let retained_name = OsStr::new("published-generation-retained");
        let retained_display = generations_path.join(retained_name);
        rename_child(
            &generations,
            generation_name,
            &generations,
            retained_name,
            false,
            &generation_display,
            &retained_display,
        )
        .unwrap();
        std::fs::create_dir(&generation_display).unwrap();
        std::fs::write(generation_display.join("foreign-kept"), b"must survive").unwrap();
        assert!(confirm_published_stage_identity(&binding, &generations, generation_name, &generation_display).is_err());
        assert_eq!(std::fs::read(generation_display.join("foreign-kept")).unwrap(), b"must survive");
    }

    #[tokio::test]
    async fn controlled_http_fixture_streams_exact_archive_and_refuses_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let archive = zip_fixture(&[("shell/browser.exe", &[1_u8, 2, 3, 4])]);
        let expected = hex::encode(Sha256::digest(&archive));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/archive.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.clone()))
            .mount(&server)
            .await;
        let cancelled = AtomicBool::new(false);
        let downloaded = download_reviewed_archive_at(
            &format!("{}/archive.zip", server.uri()),
            archive.len() as u64,
            &expected,
            &ExternalHttpAuthorizer::test_allow(),
            &cancelled,
        )
        .await
        .expect("controlled transport satisfies permit, stream, and digest checks");
        assert_eq!(downloaded, archive);

        let redirect = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", server.uri()))
            .mount(&redirect)
            .await;
        assert!(download_reviewed_archive_at(
            &redirect.uri(),
            archive.len() as u64,
            &expected,
            &ExternalHttpAuthorizer::test_allow(),
            &cancelled,
        )
        .await
        .is_err());
    }

    #[test]
    fn controlled_zip_fixture_extracts_only_the_expected_root_and_executable() {
        let home = fixture_home();
        let manifest = fixture_manifest();
        let target = &manifest.targets[0];
        let archive = zip_fixture(&[
            ("shell/browser.exe", &[1_u8, 2, 3, 4]),
            ("shell/runtime.dat", b"fixture runtime"),
        ]);
        std::fs::create_dir_all(home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR)).unwrap();
        let bound = open_absolute_bound_directory(home.path(), false, "test home")
            .unwrap()
            .unwrap();
        let managed = open_bound_real_child_dir(
            &bound.dir,
            OsStr::new(MANAGED_BROWSER_DIR),
            &home.path().join(MANAGED_BROWSER_DIR),
        )
        .unwrap()
        .0;
        let generations = open_bound_real_child_dir(
            &managed,
            OsStr::new(GENERATIONS_DIR),
            &home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR),
        )
        .unwrap()
        .0;
        let stage_name = OsStr::new(".stage-test");
        let stage_display = home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR).join(".stage-test");
        let (stage, _) = create_private_stage(&generations, stage_name, &stage_display).unwrap();
        let cancelled = AtomicBool::new(false);
        extract_reviewed_zip(
            &stage,
            &stage_display,
            target,
            &archive,
            &cancelled,
        )
        .expect("controlled archive is extracted through capability-relative handles");
        assert_eq!(std::fs::read(stage_display.join("shell/browser.exe")).unwrap(), [1, 2, 3, 4]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(stage_display.join("shell/browser.exe"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "the verified Unix executable must retain only owner execute permission"
            );
        }
    }

    #[test]
    fn controlled_zip_fixture_rejects_escape_and_case_collision_before_write() {
        let manifest = fixture_manifest();
        let target = &manifest.targets[0];
        let cases = [
            zip_fixture(&[("../shell/browser.exe", &[1_u8, 2, 3, 4])]),
            zip_fixture(&[
                ("shell/browser.exe", &[1_u8, 2, 3, 4]),
                ("shell/BROWSER.exe", b"collision"),
            ]),
        ];
        for archive in cases {
            let home = fixture_home();
            std::fs::create_dir_all(home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR)).unwrap();
            let bound = open_absolute_bound_directory(home.path(), false, "test home").unwrap().unwrap();
            let managed = open_bound_real_child_dir(&bound.dir, OsStr::new(MANAGED_BROWSER_DIR), &home.path().join(MANAGED_BROWSER_DIR)).unwrap().0;
            let generations = open_bound_real_child_dir(&managed, OsStr::new(GENERATIONS_DIR), &home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR)).unwrap().0;
            let stage_name = OsStr::new(".stage-test");
            let stage_display = home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR).join(".stage-test");
            let (stage, _) = create_private_stage(&generations, stage_name, &stage_display).unwrap();
            assert!(extract_reviewed_zip(&stage, &stage_display, target, &archive, &AtomicBool::new(false)).is_err());
        }
    }

    #[test]
    fn controlled_zip_fixture_rejects_excessive_member_inventory() {
        use std::io::{Cursor, Write as _};

        let mut archive = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(Cursor::new(&mut archive));
            for index in 0..=MAX_ARCHIVE_MEMBERS {
                writer
                    .start_file::<_, ()>(
                        format!("shell/member-{index}"),
                        zip::write::SimpleFileOptions::default(),
                    )
                    .unwrap();
                writer.write_all(b"x").unwrap();
            }
            writer.finish().unwrap();
        }
        let home = fixture_home();
        std::fs::create_dir_all(home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR)).unwrap();
        let manifest = fixture_manifest();
        let bound = open_absolute_bound_directory(home.path(), false, "test home").unwrap().unwrap();
        let managed = open_bound_real_child_dir(&bound.dir, OsStr::new(MANAGED_BROWSER_DIR), &home.path().join(MANAGED_BROWSER_DIR)).unwrap().0;
        let generations = open_bound_real_child_dir(&managed, OsStr::new(GENERATIONS_DIR), &home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR)).unwrap().0;
        let stage_name = OsStr::new(".stage-test");
        let stage_display = home.path().join(MANAGED_BROWSER_DIR).join(GENERATIONS_DIR).join(".stage-test");
        let (stage, _) = create_private_stage(&generations, stage_name, &stage_display).unwrap();
        assert!(extract_reviewed_zip(&stage, &stage_display, &manifest.targets[0], &archive, &AtomicBool::new(false)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn retained_binding_detects_executable_replacement_and_symlink_parent() {
        use std::os::unix::fs::symlink;

        let home = fixture_home();
        let manifest = fixture_manifest();
        let generation = fixture_generation(home.path(), &manifest);
        let resolved = resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest)
            .expect("fixture resolves before deterministic replacement");
        let replacement = generation.join("shell").join("replacement");
        std::fs::write(&replacement, [1_u8, 2, 3, 4]).unwrap();
        std::fs::rename(&replacement, generation.join("shell").join("browser.exe")).unwrap();
        assert!(
            resolved.revalidate_for_launch().is_err(),
            "replacement after resolve must invalidate retained identity"
        );

        let hostile = fixture_home();
        let link_home = fixture_home();
        symlink(hostile.path(), link_home.path().join(MANAGED_BROWSER_DIR)).unwrap();
        assert!(
            resolve_from_manifest(link_home.path(), ManagedBrowserPlatform::Win64, &manifest)
                .is_err(),
            "no-follow capability walk must reject a symlink managed root"
        );
    }
}
