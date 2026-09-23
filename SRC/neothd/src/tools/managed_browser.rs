//! Managed-browser policy and capability-bound local runtime resolution.
//!
//! This module has no downloader, browser launcher, network client, ambient
//! browser discovery, HOME lookup, registry lookup, or PATH lookup. A caller
//! supplies both the NEOTH home and the requested platform. Resolution walks
//! every managed component through retained no-follow directory capabilities.
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
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};

use crate::skills::store::{
    BoundChildObject, BoundDirectory, BoundDirectoryChild, open_absolute_bound_directory,
    open_bound_real_child_dir, open_bound_regular_file,
};

pub const MANAGED_BROWSER_DIR: &str = "managed-browser";
pub const GENERATIONS_DIR: &str = "generations";
pub const GENERATION_MARKER: &str = ".neoth-managed-browser-generation.json";
const MANIFEST_SCHEMA: &str = "neoth.managed_browser.cft_manifest.v1";
const MARKER_SCHEMA: &str = "neoth.managed_browser.generation.v1";

const REVIEWED_MANIFEST_BYTES: &str =
    include_str!("../../../../docs/verification/managed-browser-cft154.json");

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ManagedBrowserConfig {
    /// Default-off policy gate. A manifest/generation is inert until a typed
    /// rendered-fetch caller enables its separate runtime route.
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
            self.executable_binding.matches_regular_file_child_readonly(
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
        ensure!(self.config.enabled, "managed browser is disabled by configuration");
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
    ensure!(manifest.schema == MANIFEST_SCHEMA, "managed-browser manifest schema is unsupported");
    ensure!(
        manifest.product == "chrome-headless-shell",
        "managed-browser manifest product is unsupported"
    );
    ensure!(!manifest.version.is_empty(), "managed-browser manifest has no version");
    ensure!(!manifest.revision.is_empty(), "managed-browser manifest has no revision");
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
            matches!(target.platform.as_str(), "win64" | "linux64" | "mac-x64" | "mac-arm64")
                && seen.insert(target.platform.as_str()),
            "managed-browser manifest has duplicate or unsupported platform"
        );
        ensure!(
            is_sha256(&target.archive_sha256) && is_sha256(&target.expected_executable_sha256),
            "managed-browser manifest digest is malformed for {}",
            target.platform
        );
        ensure!(
            target.expected_executable_bytes > 0 && is_fixed_executable_path(&target.expected_executable),
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
        .ok_or_else(|| anyhow::anyhow!("managed-browser platform {} is not admitted", platform.as_str()))?;
    let home = open_absolute_bound_directory(home_path, false, "managed-browser explicit home")?
        .ok_or_else(|| anyhow::anyhow!("managed-browser explicit home is missing"))?;

    let managed_root_name = OsString::from(MANAGED_BROWSER_DIR);
    let managed_root_display = home.physical_display_path.join(&managed_root_name);
    let (managed_root, managed_root_binding) = open_bound_real_child_dir(
        &home.dir,
        &managed_root_name,
        &managed_root_display,
    )?;

    let generations_name = OsString::from(GENERATIONS_DIR);
    let generations_display = managed_root_display.join(&generations_name);
    let (generations, generations_binding) = open_bound_real_child_dir(
        &managed_root,
        &generations_name,
        &generations_display,
    )?;

    let generation_name = OsString::from(format!(
        "{}-{}-{}",
        target.platform, manifest.version, target.archive_sha256
    ));
    ensure!(
        is_safe_component(&generation_name.to_string_lossy()),
        "managed-browser generation name is unsafe"
    );
    let generation_display = generations_display.join(&generation_name);
    let (generation, generation_binding) = open_bound_real_child_dir(
        &generations,
        &generation_name,
        &generation_display,
    )?;

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

fn read_bounded(
    file: &mut cap_std::fs::File,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    ensure!(bytes.len() as u64 <= max_bytes, "{label} exceeds byte limit");
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
        let read = file.read(&mut buffer).with_context(|| format!("read {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} byte count overflow"))?;
        ensure!(total <= expected_bytes, "{label} exceeds reviewed byte length");
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
        {"platform":"win64","archive_sha256":"1111111111111111111111111111111111111111111111111111111111111111","expected_executable":"shell/browser.exe","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/win64/chrome-headless-shell-win64.zip"},
        {"platform":"linux64","archive_sha256":"2222222222222222222222222222222222222222222222222222222222222222","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/linux64/chrome-headless-shell-linux64.zip"},
        {"platform":"mac-x64","archive_sha256":"3333333333333333333333333333333333333333333333333333333333333333","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/mac-x64/chrome-headless-shell-mac-x64.zip"},
        {"platform":"mac-arm64","archive_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_executable":"shell/browser","expected_executable_bytes":4,"expected_executable_sha256":"9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a","url":"https://storage.googleapis.com/chrome-for-testing-public/test-1/mac-arm64/chrome-headless-shell-mac-arm64.zip"}
      ]
    }"#;

    fn fixture_manifest() -> ReviewedManifest {
        parse_reviewed_manifest(TEST_MANIFEST).unwrap()
    }

    fn fixture_generation(home: &Path, manifest: &ReviewedManifest) -> PathBuf {
        let target = &manifest.targets[0];
        let generation = home
            .join(MANAGED_BROWSER_DIR)
            .join(GENERATIONS_DIR)
            .join(format!("{}-{}-{}", target.platform, manifest.version, target.archive_sha256));
        std::fs::create_dir_all(generation.join("shell")).unwrap();
        std::fs::write(generation.join("shell").join("browser.exe"), [1_u8, 2, 3, 4]).unwrap();
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
        assert!(parse_reviewed_manifest(TEST_MANIFEST.replace("111111", "nothex").as_str()).is_err());
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
        let home = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest();
        let error = resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest)
            .unwrap_err();
        assert!(error.to_string().contains("managed-browser root"));
    }

    #[test]
    fn exact_marker_and_executable_resolve_and_revalidate() {
        let home = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest();
        let generation = fixture_generation(home.path(), &manifest);
        let resolved = resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest)
            .expect("exact immutable fixture resolves");
        assert_eq!(resolved.executable(), generation.join("shell").join("browser.exe"));
        resolved
            .revalidate_for_launch()
            .expect("retained fixture binding remains current");
    }

    #[test]
    fn forged_marker_digest_and_path_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest();
        let generation = fixture_generation(home.path(), &manifest);
        std::fs::write(
            generation.join(GENERATION_MARKER),
            r#"{"schema":"neoth.managed_browser.generation.v1","platform":"win64","version":"test-1","revision":"test-r","archive_sha256":"1111111111111111111111111111111111111111111111111111111111111111","executable_sha256":"0000000000000000000000000000000000000000000000000000000000000000","executable_bytes":4}"#,
        )
        .unwrap();
        assert!(resolve_from_manifest(home.path(), ManagedBrowserPlatform::Win64, &manifest).is_err());

        let malicious = TEST_MANIFEST.replace("shell/browser.exe", "../ambient-browser.exe");
        assert!(parse_reviewed_manifest(&malicious).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn retained_binding_detects_executable_replacement_and_symlink_parent() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
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

        let hostile = tempfile::tempdir().unwrap();
        let link_home = tempfile::tempdir().unwrap();
        symlink(hostile.path(), link_home.path().join(MANAGED_BROWSER_DIR)).unwrap();
        assert!(
            resolve_from_manifest(link_home.path(), ManagedBrowserPlatform::Win64, &manifest).is_err(),
            "no-follow capability walk must reject a symlink managed root"
        );
    }
}
