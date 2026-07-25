//! Closed portable-release bundle policy shared by bootstrap and self-update.
//!
//! Authentication and archive extraction are outer trust boundaries.  This
//! module validates the extracted root again, derives the only legal payload
//! from the compiled target, verifies the release-bound self-knowledge tree,
//! and hands a fixed member plan to the crash-safe install transaction.  No
//! caller can add, omit, rename, or reorder package-owned members.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::install_transaction::{
    AllowedTarget, CommitReceipt, InstallTransaction, PreparedMember, RecoveryOutcome,
};
use crate::wiki::release_snapshot::VerifiedReleaseSnapshot;

const SELF_KNOWLEDGE: &str = "self-knowledge";
pub(crate) const PORTABLE_SUPPORT_DIR: &str = "neoth-support";
pub const PORTABLE_OWNERSHIP_MARKER: &str = ".neoth-portable-install.json";
const PORTABLE_MARKER_OWNER: &str = "neoth_portable_release";
const PORTABLE_MARKER_SCHEMA_VERSION: u32 = 2;
const MAX_PORTABLE_MARKER_BYTES: u64 = 16 * 1024;
const MAX_BUNDLE_DESCENDANTS: usize = 100_001;
const MAX_BUNDLE_DEPTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PortableOwnershipMarker {
    schema_version: u32,
    owner: String,
    install_root: String,
    release_version: String,
    profile: String,
    support_dir: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BundleMemberKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BundleMemberSpec {
    name: &'static str,
    kind: BundleMemberKind,
    executable: bool,
}

impl BundleMemberSpec {
    const fn file(name: &'static str) -> Self {
        Self {
            name,
            kind: BundleMemberKind::File,
            executable: false,
        }
    }

    const fn executable(name: &'static str) -> Self {
        Self {
            name,
            kind: BundleMemberKind::File,
            executable: true,
        }
    }

    const fn directory(name: &'static str) -> Self {
        Self {
            name,
            kind: BundleMemberKind::Directory,
            executable: false,
        }
    }
}

/// Exact profile compiled into this target.  Only musl is intentionally
/// headless; every other portable release is the complete desktop bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableBundleProfile {
    Desktop,
    HeadlessMusl,
}

/// Trusted destination layouts for the one exact source bundle profile.
/// Callers select a packaging shape, never a free-form source/target map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseInstallLayout {
    /// Bootstrap/cargo-style portable directory: every package-owned member is
    /// installed directly below this directory.
    Portable(PathBuf),
    /// Native Linux package layout rooted at `/usr`.
    LinuxSystem,
    /// Signed `NEOTH.app/Contents` layout. The path is validated before use.
    MacApp(PathBuf),
}

/// A signed macOS app cannot be safely updated by replacing files inside
/// `Contents`: doing so invalidates `_CodeSignature/CodeResources`. The caller
/// must hand off to the notarized PKG/full-app replacement path instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMacPackageRequired {
    pub app_contents: PathBuf,
}

impl std::fmt::Display for SignedMacPackageRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "signed macOS NEOTH.app requires a notarized PKG or complete signed-app replacement; refusing to mutate {} because that would invalidate its code signature",
            self.app_contents.display()
        )
    }
}

impl std::error::Error for SignedMacPackageRequired {}

/// Files owned by dpkg/rpm must be updated through that package manager. A
/// per-member transaction would leave its version, checksums, and ownership
/// database describing files that are no longer installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLinuxPackageRequired {
    pub package_root: PathBuf,
}

impl std::fmt::Display for NativeLinuxPackageRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native Linux NEOTH installation requires an authenticated DEB/RPM update through the system package manager; refusing to replace package-owned files below {}",
            self.package_root.display()
        )
    }
}

impl std::error::Error for NativeLinuxPackageRequired {}

/// A registered Inno installation must be updated by its signed Setup asset.
/// Mutating its files directly would bypass CloseApplications, the uninstaller
/// inventory, Authenticode policy, and Windows repair semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedWindowsSetupRequired {
    pub install_dir: PathBuf,
    pub reason: String,
}

impl std::fmt::Display for SignedWindowsSetupRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "signed Windows Setup.exe handoff required for {}: {}",
            self.install_dir.display(),
            self.reason
        )
    }
}

impl std::error::Error for SignedWindowsSetupRequired {}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum InnoInstallRecord {
    Missing,
    Location(String),
    Malformed(String),
}

impl ReleaseInstallLayout {
    /// Derive the only supported layout from an installed, real `neoth`
    /// executable. This is the normal self-update entrypoint.
    pub fn derive_from_executable(executable: impl AsRef<Path>) -> Result<Self> {
        let requested = executable.as_ref();
        // Native macOS packages intentionally expose /usr/local/bin symlinks
        // into NEOTH.app. Resolve that packaging-owned launcher first, then
        // validate the real target and derive only from its canonical shape.
        let executable = fs::canonicalize(requested).with_context(|| {
            format!("canonicalize installed executable {}", requested.display())
        })?;
        let metadata = fs::symlink_metadata(&executable)
            .with_context(|| format!("inspect installed executable {}", executable.display()))?;
        if metadata_is_link_like(&metadata) || !metadata.is_file() {
            anyhow::bail!(
                "installed executable must be a regular non-link file: {}",
                executable.display()
            );
        }
        if executable.file_name().and_then(|name| name.to_str()) != Some(core_binary_name()) {
            anyhow::bail!(
                "release layout must be derived from the neoth entrypoint: {}",
                executable.display()
            );
        }
        let install_dir = executable
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed executable has no parent directory"))?;

        #[cfg(windows)]
        require_windows_portable_ownership(install_dir)?;

        #[cfg(target_os = "macos")]
        if install_dir.file_name().and_then(|name| name.to_str()) == Some("MacOS") {
            let contents = install_dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("macOS executable has no Contents directory"))?;
            validate_mac_contents(contents)?;
            return Err(SignedMacPackageRequired {
                app_contents: contents.to_path_buf(),
            }
            .into());
        }

        #[cfg(target_os = "linux")]
        if install_dir == Path::new("/usr/bin") {
            let portable_snapshot = install_dir.join(PORTABLE_SUPPORT_DIR).join(SELF_KNOWLEDGE);
            let package_snapshot = Path::new("/usr/share/neoth").join(SELF_KNOWLEDGE);
            let portable_exists = portable_snapshot.exists();
            let package_exists = package_snapshot.exists();
            return match (portable_exists, package_exists) {
                (true, false) => Ok(Self::Portable(install_dir.to_path_buf())),
                (false, true) => Err(NativeLinuxPackageRequired {
                    package_root: PathBuf::from("/usr"),
                }
                .into()),
                (true, true) => anyhow::bail!(
                    "ambiguous /usr/bin installation has both portable and package self-knowledge"
                ),
                (false, false) => anyhow::bail!(
                    "cannot derive /usr/bin release layout without an installed self-knowledge baseline"
                ),
            };
        }

        validate_existing_portable_marker(install_dir, PortableBundleProfile::current())?;
        Ok(Self::Portable(install_dir.to_path_buf()))
    }

    fn transaction_root(&self) -> Result<PathBuf> {
        match self {
            Self::Portable(root) => Ok(root.clone()),
            Self::LinuxSystem => Err(NativeLinuxPackageRequired {
                package_root: PathBuf::from("/usr"),
            }
            .into()),
            Self::MacApp(contents) => {
                validate_mac_contents(contents)?;
                Err(SignedMacPackageRequired {
                    app_contents: contents.clone(),
                }
                .into())
            }
        }
    }

    fn target_for(&self, spec: BundleMemberSpec) -> Result<PathBuf> {
        match self {
            Self::Portable(root) => {
                if spec.executable || spec.name == PORTABLE_OWNERSHIP_MARKER {
                    Ok(root.join(spec.name))
                } else {
                    Ok(root.join(PORTABLE_SUPPORT_DIR).join(spec.name))
                }
            }
            Self::LinuxSystem => {
                if spec.executable {
                    Ok(Path::new("/usr/bin").join(spec.name))
                } else if spec.kind == BundleMemberKind::Directory {
                    Ok(Path::new("/usr/share/neoth").join(spec.name))
                } else if is_example(spec.name) {
                    Ok(Path::new("/usr/share/doc/neoth/examples").join(spec.name))
                } else {
                    Ok(Path::new("/usr/share/doc/neoth").join(spec.name))
                }
            }
            Self::MacApp(contents) => {
                validate_mac_contents(contents)?;
                let _ = spec;
                Err(SignedMacPackageRequired {
                    app_contents: contents.clone(),
                }
                .into())
            }
        }
    }

    fn absent_target(&self, name: &'static str) -> Result<PathBuf> {
        self.target_for(BundleMemberSpec::executable(name))
    }
}

impl PortableBundleProfile {
    pub const fn current() -> Self {
        if cfg!(target_env = "musl") {
            Self::HeadlessMusl
        } else {
            Self::Desktop
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::HeadlessMusl => "headless_musl",
        }
    }
}

/// Result returned after the native journal reaches its durable commit state.
#[derive(Debug)]
pub struct ReleaseBundleCommit {
    pub profile: PortableBundleProfile,
    pub receipt: CommitReceipt,
}

/// Recover the one portable transaction that can own the running public or
/// compatibility entrypoint. The installation root is always derived from the
/// canonical executable; callers cannot supply a destination or member list.
/// Native package layouts do not carry the portable marker and are therefore
/// left to their package manager's recovery semantics.
pub fn recover_running_portable_transaction() -> Result<RecoveryOutcome> {
    let executable = std::env::current_exe().context("locate running NEOTH executable")?;
    recover_portable_transaction_for_executable(&executable)
}

fn recover_portable_transaction_for_executable(executable: &Path) -> Result<RecoveryOutcome> {
    let executable = fs::canonicalize(executable)
        .with_context(|| format!("canonicalize running executable {}", executable.display()))?;
    let metadata = fs::symlink_metadata(&executable)
        .with_context(|| format!("inspect running executable {}", executable.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_file() {
        anyhow::bail!(
            "running NEOTH executable must be a regular non-link file: {}",
            executable.display()
        );
    }
    let name = executable.file_name().and_then(|name| name.to_str());
    if name != Some(core_binary_name()) && name != Some(compat_binary_name()) {
        anyhow::bail!(
            "portable recovery is restricted to the real neoth/neothd entrypoints: {}",
            executable.display()
        );
    }
    let install_root = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("running NEOTH executable has no installation root"))?;
    let marker = install_root.join(PORTABLE_OWNERSHIP_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecoveryOutcome::Clean);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspect portable ownership marker {}", marker.display())
            });
        }
    }

    #[cfg(windows)]
    require_windows_portable_ownership(install_root)?;
    let profile = PortableBundleProfile::current();
    validate_existing_portable_marker(install_root, profile)?;
    let layout = ReleaseInstallLayout::Portable(install_root.to_path_buf());
    let specs = bundle_member_specs(profile);
    let transaction =
        InstallTransaction::new(install_root, allowed_targets(profile, &layout, &specs)?)
            .context("bind pending portable transaction to the running installation")?;
    let outcome = transaction
        .recover()
        .context("recover pending portable installation transaction")?;
    validate_existing_portable_marker(install_root, profile)
        .context("validate portable ownership after transaction recovery")?;
    Ok(outcome)
}

/// Validate and atomically install one exact portable release root.
///
/// `expected_version` is the target release, without a leading `v`.  The
/// bootstrap helper additionally binds this value to its own compiled package
/// version before calling here; self-update intentionally validates a newer
/// target version with the same policy.
pub fn apply_portable_release_bundle(
    bundle_root: impl AsRef<Path>,
    install_root: impl AsRef<Path>,
    expected_version: &str,
) -> Result<ReleaseBundleCommit> {
    apply_release_bundle(
        bundle_root,
        ReleaseInstallLayout::Portable(install_root.as_ref().to_path_buf()),
        expected_version,
    )
}

/// Validate and atomically install an exact source bundle into a trusted
/// portable layout. Native Linux packages and signed macOS apps fail closed:
/// those installation types require their platform package transaction.
pub fn apply_release_bundle(
    bundle_root: impl AsRef<Path>,
    layout: ReleaseInstallLayout,
    expected_version: &str,
) -> Result<ReleaseBundleCommit> {
    let expected_version = validate_expected_version(expected_version)?;
    let bundle_root = bundle_root.as_ref();
    let profile = PortableBundleProfile::current();
    let specs = bundle_member_specs(profile);
    // Fail before archive inspection so signed apps and package-manager-owned
    // Linux files are never treated as partially mutable bundles, even when
    // the caller supplies a bad archive.
    let transaction_root = layout.transaction_root()?;
    // GOLD-R3-12a: before the markerless-first-install guard, roll back THIS
    // root's own journaled crashed install partial so a crash mid-first-install
    // self-heals on retry instead of quarantining. Keyed strictly on the
    // deterministic journal sidecar for this exact root — a foreign/prior install
    // carries no NEOTH journal, so recovery is a no-op for it and the guard below
    // still quarantines it. recover() rolls back a non-committed journal (or
    // finishes a committed one) under its own lock, then the guard runs on the
    // cleaned root, so a foreign NEOTH-owned collision that is NOT part of the
    // rolled-back journal STILL quarantines. The brief unlocked window before the
    // real apply transaction is fail-closed by that transaction's
    // revalidate_after_lock (a raced root re-appearance/swap bails retryably,
    // never a clobber).
    recover_crashed_portable_partial(&transaction_root, profile, &layout, &specs)?;
    validate_existing_portable_marker(&transaction_root, profile)?;

    validate_bundle_root_shape(bundle_root, &specs)?;
    VerifiedReleaseSnapshot::open_for_update(
        bundle_root.join(SELF_KNOWLEDGE),
        &expected_version.to_string(),
    )
    .context("verify release bundle self-knowledge")?;

    let (marker_stage, marker_source) =
        prepare_portable_marker(&transaction_root, &expected_version.to_string(), profile)?;

    let allowed = allowed_targets(profile, &layout, &specs)?;
    let transaction = InstallTransaction::new(&transaction_root, allowed)
        .context("prepare portable release install transaction")?;
    let prepared = prepared_members(profile, bundle_root, &layout, &specs, &marker_source)?;
    let receipt = transaction
        .apply(&prepared)
        .context("apply portable release install transaction")?;
    drop(marker_stage);
    Ok(ReleaseBundleCommit { profile, receipt })
}

fn allowed_targets(
    profile: PortableBundleProfile,
    layout: &ReleaseInstallLayout,
    specs: &[BundleMemberSpec],
) -> Result<Vec<AllowedTarget>> {
    let mut allowed = specs
        .iter()
        .map(|spec| {
            let target = layout.target_for(*spec)?;
            match spec.kind {
                BundleMemberKind::File => Ok(AllowedTarget::file(target)),
                BundleMemberKind::Directory => Ok(AllowedTarget::directory(target)),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if profile == PortableBundleProfile::HeadlessMusl {
        allowed.extend([
            AllowedTarget::file(layout.absent_target(gui_binary_name())?),
            AllowedTarget::file(layout.absent_target(keet_binary_name())?),
        ]);
    }
    allowed.push(AllowedTarget::file(
        layout.target_for(BundleMemberSpec::file(PORTABLE_OWNERSHIP_MARKER))?,
    ));
    Ok(allowed)
}

fn prepared_members(
    profile: PortableBundleProfile,
    bundle_root: &Path,
    layout: &ReleaseInstallLayout,
    specs: &[BundleMemberSpec],
    marker_source: &Path,
) -> Result<Vec<PreparedMember>> {
    let (commit_point, companions) = specs
        .split_last()
        .expect("portable release profile always has a core commit point");
    let mut prepared = companions
        .iter()
        .map(|spec| {
            let source = bundle_root.join(spec.name);
            let target = layout.target_for(*spec)?;
            match spec.kind {
                BundleMemberKind::File => Ok(PreparedMember::file(source, target)),
                BundleMemberKind::Directory => Ok(PreparedMember::directory(source, target)),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if profile == PortableBundleProfile::HeadlessMusl {
        prepared.extend([
            PreparedMember::absent_file(layout.absent_target(gui_binary_name())?),
            PreparedMember::absent_file(layout.absent_target(keet_binary_name())?),
        ]);
    }
    prepared.push(PreparedMember::file(
        marker_source,
        layout.target_for(BundleMemberSpec::file(PORTABLE_OWNERSHIP_MARKER))?,
    ));
    prepared.push(PreparedMember::file(
        bundle_root.join(commit_point.name),
        layout.target_for(*commit_point)?,
    ));
    Ok(prepared)
}

fn is_example(name: &str) -> bool {
    matches!(
        name,
        "freedom.yaml.example" | "import-manifest.example.yaml"
    )
}

fn portable_marker_error(root: &Path, reason: impl Into<String>) -> anyhow::Error {
    let reason = reason.into();
    #[cfg(windows)]
    {
        SignedWindowsSetupRequired {
            install_dir: root.to_path_buf(),
            reason,
        }
        .into()
    }
    #[cfg(not(windows))]
    {
        anyhow::anyhow!(
            "portable installation ownership at {} is invalid: {reason}",
            root.display()
        )
    }
}

/// GOLD-R3-12a: roll back this install root's OWN journaled crashed install
/// partial before the markerless-first-install guard runs, so a crash mid first
/// install self-heals on retry instead of quarantining. Gated on a real
/// (non-link) journal file for this exact root: a foreign/prior install carries
/// no NEOTH journal, so this is a no-op for it and the guard still quarantines
/// it. Reuses the transaction's hardened `recover()` (acquire lock → revalidate
/// → roll back a non-committed journal / finish a committed one).
fn recover_crashed_portable_partial(
    transaction_root: &Path,
    profile: PortableBundleProfile,
    layout: &ReleaseInstallLayout,
    specs: &[BundleMemberSpec],
) -> Result<()> {
    let allowed = allowed_targets(profile, layout, specs)?;
    // If a coordinator cannot be constructed for this root (e.g. an invalid or
    // reparse-point ancestor), there is no recoverable NEOTH partial here — no
    // install ever committed through such a root. Return without masking the
    // condition: the markerless guard and marker-preparation path below reject
    // the root with their specific diagnostic instead of a recovery-flavored
    // wrapper (and the real apply transaction re-raises the same construction
    // error), so nothing is silently skipped.
    let Ok(transaction) = InstallTransaction::new(transaction_root, allowed) else {
        return Ok(());
    };
    // symlink_metadata (not Path::exists, which follows links) so a symlinked
    // journal path counts as "no recoverable journal" here and is diagnosed by
    // the ownership guard rather than followed by recover().
    let journal_is_real_file = fs::symlink_metadata(transaction.journal_path())
        .map(|metadata| metadata.is_file() && !metadata_is_link_like(&metadata))
        .unwrap_or(false);
    if journal_is_real_file {
        transaction
            .recover()
            .context("recover a crashed portable install partial before the ownership guard")?;
    }
    Ok(())
}

fn validate_existing_portable_marker(
    install_root: &Path,
    profile: PortableBundleProfile,
) -> Result<()> {
    use std::io::Read as _;

    let marker_path = install_root.join(PORTABLE_OWNERSHIP_MARKER);
    let metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(windows)]
            if windows_default_inno_collision(install_root)? && directory_is_nonempty(install_root)?
            {
                return Err(portable_marker_error(
                    install_root,
                    "the Inno default directory is non-empty but has neither a valid portable ownership marker nor a registered Inno owner",
                ));
            }
            if let Some(collision) = markerless_portable_target_collision(install_root)? {
                return Err(portable_marker_error(
                    install_root,
                    format!(
                        "markerless first install found an existing NEOTH-owned target at {}; move or uninstall that legacy target, or choose another install directory, then retry (unrelated files may remain)",
                        collision.display()
                    ),
                ));
            }
            return Ok(());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect portable marker {}", marker_path.display()));
        }
    };
    if metadata_is_link_like(&metadata)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PORTABLE_MARKER_BYTES
    {
        return Err(portable_marker_error(
            install_root,
            "portable ownership marker is not a bounded regular non-link file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&marker_path)
        .with_context(|| format!("open portable marker {}", marker_path.display()))?
        .take(MAX_PORTABLE_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read portable ownership marker")?;
    if bytes.len() as u64 > MAX_PORTABLE_MARKER_BYTES {
        return Err(portable_marker_error(
            install_root,
            "portable ownership marker exceeds its size ceiling",
        ));
    }
    let marker: PortableOwnershipMarker = serde_json::from_slice(&bytes).map_err(|error| {
        portable_marker_error(
            install_root,
            format!("portable ownership marker is malformed: {error}"),
        )
    })?;
    let resolved_root = resolved_install_root(install_root)?;
    let marker_root = marker_root_identity(&marker.install_root)?;
    let marker_version_valid = matches!(
        semver::Version::parse(&marker.release_version),
        Ok(version) if version.to_string() == marker.release_version
    );
    if marker.schema_version != PORTABLE_MARKER_SCHEMA_VERSION
        || marker.owner != PORTABLE_MARKER_OWNER
        || marker.profile != profile.as_str()
        || marker.support_dir != PORTABLE_SUPPORT_DIR
        || !marker_version_valid
        || marker_root != marker_root_identity(&display_marker_root(&resolved_root))?
    {
        return Err(portable_marker_error(
            install_root,
            "portable ownership marker identity does not match this installation",
        ));
    }
    Ok(())
}

fn prepare_portable_marker(
    install_root: &Path,
    release_version: &str,
    profile: PortableBundleProfile,
) -> Result<(tempfile::TempDir, PathBuf)> {
    use std::io::Write as _;

    let resolved_root = resolved_install_root(install_root)?;
    let marker = PortableOwnershipMarker {
        schema_version: PORTABLE_MARKER_SCHEMA_VERSION,
        owner: PORTABLE_MARKER_OWNER.to_string(),
        install_root: display_marker_root(&resolved_root),
        release_version: release_version.to_string(),
        profile: profile.as_str().to_string(),
        support_dir: PORTABLE_SUPPORT_DIR.to_string(),
    };
    // GOLD-R3-12: stage inside the nearest EXISTING ancestor of the resolved
    // install root — the same link-free, same-volume anchor the install
    // transaction locks and journals in — rather than inside the resolved root
    // itself. On a first install the resolved root does not exist yet, so
    // `tempdir_in(resolved_root)` fails with NotFound; its nearest existing
    // ancestor is already canonical + validated by `resolved_install_root`,
    // so it also avoids the macOS `/var` -> `/private/var` reparse rejection.
    let stage_anchor = super::install_transaction::nearest_existing_path(&resolved_root)?;
    let stage = tempfile::Builder::new()
        .prefix(".neoth-portable-owner-")
        .tempdir_in(stage_anchor)
        .context("create private portable-marker stage")?;
    let source = stage.path().join(PORTABLE_OWNERSHIP_MARKER);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .context("create staged portable ownership marker")?;
    let mut body = serde_json::to_vec_pretty(&marker)?;
    body.push(b'\n');
    file.write_all(&body)?;
    file.sync_all()?;
    Ok((stage, source))
}

#[cfg(test)]
pub(crate) fn write_test_portable_ownership_marker(install_root: &Path) -> Result<()> {
    let (_stage, source) = prepare_portable_marker(
        install_root,
        env!("CARGO_PKG_VERSION"),
        PortableBundleProfile::current(),
    )?;
    fs::copy(&source, install_root.join(PORTABLE_OWNERSHIP_MARKER))
        .context("install portable ownership marker for test fixture")?;
    Ok(())
}

/// Detect only paths owned by the portable layout. Generic README/license or
/// `self-knowledge` names in a shared binary directory are deliberately not
/// package targets anymore and must remain untouched.
fn markerless_portable_target_collision(install_root: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(install_root) {
        Ok(metadata) => {
            if metadata_is_link_like(&metadata) || !metadata.is_dir() {
                anyhow::bail!(
                    "portable installation root must be a real directory: {}",
                    install_root.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect install root {}", install_root.display()));
        }
    }

    let candidates = [
        core_binary_name(),
        compat_binary_name(),
        migrate_binary_name(),
        relay_binary_name(),
        gui_binary_name(),
        keet_binary_name(),
        PORTABLE_SUPPORT_DIR,
    ];
    for name in candidates {
        let path = install_root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect portable target {}", path.display()));
            }
        }
    }
    Ok(None)
}

fn resolved_install_root(requested: &Path) -> Result<PathBuf> {
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for portable installation")?
            .join(requested)
    };
    for component in absolute.components() {
        if matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        ) {
            anyhow::bail!("portable installation root must be lexically normalized");
        }
    }

    let mut cursor = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if metadata_is_link_like(&metadata) || !metadata.is_dir() {
                    anyhow::bail!(
                        "portable installation ancestor is not a real directory: {}",
                        cursor.display()
                    );
                }
                let mut resolved = fs::canonicalize(cursor).with_context(|| {
                    format!(
                        "canonicalize portable install ancestor {}",
                        cursor.display()
                    )
                })?;
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    anyhow::anyhow!("portable installation root has no existing ancestor")
                })?;
                missing.push(name.to_os_string());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("portable installation root has no parent"))?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect portable install ancestor {}", cursor.display())
                });
            }
        }
    }
}

fn display_marker_root(root: &Path) -> String {
    let rendered = root.to_string_lossy();
    #[cfg(windows)]
    let rendered = rendered.strip_prefix(r"\\?\").unwrap_or(&rendered);
    rendered.trim_end_matches(['/', '\\']).to_string()
}

fn marker_root_identity(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.contains('\0') {
        anyhow::bail!("portable marker install_root is empty or contains NUL");
    }
    #[cfg(windows)]
    {
        let without_prefix = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        Ok(without_prefix
            .replace('/', r"\")
            .trim_end_matches('\\')
            .to_lowercase())
    }
    #[cfg(not(windows))]
    {
        Ok(raw.trim_end_matches('/').to_string())
    }
}

#[cfg(windows)]
fn directory_is_nonempty(root: &Path) -> Result<bool> {
    match fs::read_dir(root) {
        Ok(mut entries) => Ok(entries.next().transpose()?.is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read install root {}", root.display())),
    }
}

#[cfg(windows)]
fn windows_default_inno_collision(root: &Path) -> Result<bool> {
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
        return Ok(false);
    };
    let default = PathBuf::from(local_app_data).join("Programs").join("NEOTH");
    Ok(
        marker_root_identity(&display_marker_root(&resolved_install_root(root)?))?
            == marker_root_identity(&display_marker_root(&resolved_install_root(&default)?))?,
    )
}

#[cfg(any(windows, test))]
fn classify_inno_records(
    install_dir: &Path,
    user: InnoInstallRecord,
    machine: InnoInstallRecord,
) -> Result<()> {
    let typed = |reason: String| -> anyhow::Error {
        SignedWindowsSetupRequired {
            install_dir: install_dir.to_path_buf(),
            reason,
        }
        .into()
    };
    if let InnoInstallRecord::Malformed(reason) = &user {
        return Err(typed(format!("malformed per-user Inno record: {reason}")));
    }
    if let InnoInstallRecord::Malformed(reason) = &machine {
        return Err(typed(format!("malformed machine Inno record: {reason}")));
    }
    match (user, machine) {
        (InnoInstallRecord::Location(_), InnoInstallRecord::Location(_)) => Err(typed(
            "both per-user and machine Inno registrations exist; uninstall one copy before updating"
                .to_string(),
        )),
        (InnoInstallRecord::Location(location), InnoInstallRecord::Missing) => {
            let installed = marker_root_identity(&display_marker_root(install_dir))?;
            let relation = if marker_root_identity(&location)? == installed {
                "matches the running executable"
            } else {
                "does not match the running executable"
            };
            Err(typed(format!(
                "per-user Inno InstallLocation {location:?} {relation}"
            )))
        }
        (InnoInstallRecord::Missing, InnoInstallRecord::Location(location)) => {
            let installed = marker_root_identity(&display_marker_root(install_dir))?;
            let relation = if marker_root_identity(&location)? == installed {
                "matches the running executable"
            } else {
                "does not match the running executable"
            };
            Err(typed(format!(
                "machine Inno InstallLocation {location:?} {relation}"
            )))
        }
        (InnoInstallRecord::Missing, InnoInstallRecord::Missing) => Ok(()),
        (InnoInstallRecord::Malformed(_), _) | (_, InnoInstallRecord::Malformed(_)) => {
            unreachable!("malformed records returned above")
        }
    }
}

#[cfg(windows)]
fn require_windows_portable_ownership(install_dir: &Path) -> Result<()> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    classify_inno_records(
        install_dir,
        read_inno_install_location(HKEY_CURRENT_USER),
        read_inno_install_location(HKEY_LOCAL_MACHINE),
    )
}

#[cfg(windows)]
fn read_inno_install_location(
    root: windows_sys::Win32::System::Registry::HKEY,
) -> InnoInstallRecord {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, KEY_QUERY_VALUE, REG_SZ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };

    const UNINSTALL_KEY: &str = concat!(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
        "TheGeekFreaks.NEOTH.BF6060F4-B75D-4E9A-BEB6-7EC8CB94A3C1_is1"
    );
    let key_name = UNINSTALL_KEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let value_name = "InstallLocation\0".encode_utf16().collect::<Vec<_>>();
    let mut key: HKEY = std::ptr::null_mut();
    let open = unsafe { RegOpenKeyExW(root, key_name.as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
    if matches!(open, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
        return InnoInstallRecord::Missing;
    }
    if open != ERROR_SUCCESS {
        return InnoInstallRecord::Malformed(format!("cannot open uninstall key: Win32 {open}"));
    }

    let result = (|| {
        let mut value_type = 0_u32;
        let mut byte_count = 0_u32;
        let query_size = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut byte_count,
            )
        };
        if !matches!(query_size, ERROR_SUCCESS | ERROR_MORE_DATA) {
            return Err(format!(
                "InstallLocation is missing or unreadable: Win32 {query_size}"
            ));
        }
        if value_type != REG_SZ
            || byte_count < 2
            || !byte_count.is_multiple_of(2)
            || byte_count as u64 > MAX_PORTABLE_MARKER_BYTES
        {
            return Err("InstallLocation is not a bounded REG_SZ".to_string());
        }
        let mut buffer = vec![0_u16; byte_count as usize / 2];
        let mut actual_bytes = byte_count;
        let query = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut value_type,
                buffer.as_mut_ptr().cast(),
                &mut actual_bytes,
            )
        };
        if query != ERROR_SUCCESS
            || value_type != REG_SZ
            || actual_bytes != byte_count
            || buffer.last() != Some(&0)
        {
            return Err(format!(
                "InstallLocation changed while reading: Win32 {query}"
            ));
        }
        buffer.pop();
        if buffer.contains(&0) {
            return Err("InstallLocation contains an embedded NUL".to_string());
        }
        let raw = String::from_utf16(&buffer)
            .map_err(|error| format!("InstallLocation is invalid UTF-16: {error}"))?;
        if raw.is_empty() || raw.trim() != raw {
            return Err("InstallLocation is empty or has surrounding whitespace".to_string());
        }
        let path = PathBuf::from(&raw);
        if !path.is_absolute() {
            return Err("InstallLocation is not absolute".to_string());
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("InstallLocation cannot be canonicalized: {error}"))?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("InstallLocation cannot be inspected: {error}"))?;
        if metadata_is_link_like(&metadata) || !metadata.is_dir() {
            return Err("InstallLocation is not a real directory".to_string());
        }
        Ok(display_marker_root(&canonical))
    })();
    unsafe {
        RegCloseKey(key);
    }
    match result {
        Ok(location) => InnoInstallRecord::Location(location),
        Err(reason) => InnoInstallRecord::Malformed(reason),
    }
}

fn validate_mac_contents(contents: &Path) -> Result<()> {
    if contents.file_name().and_then(|name| name.to_str()) != Some("Contents")
        || contents
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("NEOTH.app")
    {
        anyhow::bail!(
            "macOS release layout must be the exact NEOTH.app/Contents tree: {}",
            contents.display()
        );
    }
    Ok(())
}

/// Bind the hidden bootstrap command to the `neoth` executable inside the
/// validated bundle.  This prevents an older or unrelated binary from being
/// used as an unreviewed transaction-policy interpreter.
pub fn require_running_bundle_helper(bundle_root: impl AsRef<Path>) -> Result<()> {
    let bundle_root = bundle_root.as_ref();
    let expected = fs::canonicalize(bundle_root.join(core_binary_name())).with_context(|| {
        format!(
            "canonicalize release helper {}",
            bundle_root.join(core_binary_name()).display()
        )
    })?;
    let current = std::env::current_exe()
        .context("locate running release helper")?
        .canonicalize()
        .context("canonicalize running release helper")?;
    if current != expected {
        anyhow::bail!(
            "bundle transaction must run the verified helper from the bundle root: {} != {}",
            current.display(),
            expected.display()
        );
    }
    Ok(())
}

fn validate_expected_version(raw: &str) -> Result<semver::Version> {
    if raw.starts_with('v') {
        anyhow::bail!("expected version must not include the release-tag 'v' prefix");
    }
    let version = semver::Version::parse(raw).context("parse expected release version")?;
    if version.to_string() != raw {
        anyhow::bail!("expected version must use canonical SemVer: {raw}");
    }
    Ok(version)
}

fn validate_bundle_root_shape(root: &Path, specs: &[BundleMemberSpec]) -> Result<()> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect release bundle root {}", root.display()))?;
    if metadata_is_link_like(&root_metadata) || !root_metadata.is_dir() {
        anyhow::bail!(
            "release bundle root must be a non-link directory: {}",
            root.display()
        );
    }

    let expected = specs
        .iter()
        .map(|spec| (spec.name, *spec))
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("read release bundle root {}", root.display()))?
    {
        let entry = entry.context("read release bundle entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("release bundle contains a non-UTF-8 entry"))?;
        if !actual.insert(name.clone()) {
            anyhow::bail!("release bundle contains duplicate entry {name:?}");
        }
        let Some(spec) = expected.get(name.as_str()) else {
            anyhow::bail!("release bundle contains unexpected entry {name:?}");
        };
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect release bundle entry {}", path.display()))?;
        if metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "release bundle entry must not be a symlink/reparse point: {}",
                path.display()
            );
        }
        match spec.kind {
            BundleMemberKind::File if metadata.is_file() => {
                if metadata.len() == 0 {
                    anyhow::bail!("release bundle file is empty: {}", path.display());
                }
                require_executable_if_needed(&path, *spec, &metadata)?;
            }
            BundleMemberKind::Directory if metadata.is_dir() => {
                reject_link_like_descendants(&path)?;
            }
            BundleMemberKind::File => anyhow::bail!(
                "release bundle member must be a regular file: {}",
                path.display()
            ),
            BundleMemberKind::Directory => anyhow::bail!(
                "release bundle member must be a regular directory: {}",
                path.display()
            ),
        }
    }

    let expected_names = expected.keys().copied().collect::<BTreeSet<_>>();
    let actual_names = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        let missing = expected_names
            .difference(&actual_names)
            .copied()
            .collect::<Vec<_>>();
        anyhow::bail!("release bundle is missing required entries: {missing:?}");
    }
    Ok(())
}

fn reject_link_like_descendants(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut inspected = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("read release bundle directory {}", directory.display()))?
        {
            let entry = entry.context("read release bundle descendant")?;
            let path = entry.path();
            inspected = inspected.saturating_add(1);
            if inspected > MAX_BUNDLE_DESCENDANTS {
                anyhow::bail!("release bundle directory contains too many descendants");
            }
            let depth = path
                .strip_prefix(root)
                .context("release bundle walk escaped its directory root")?
                .components()
                .count();
            if depth > MAX_BUNDLE_DEPTH {
                anyhow::bail!("release bundle directory exceeds the depth safety ceiling");
            }
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect release bundle descendant {}", path.display()))?;
            if metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "release bundle descendant must not be a symlink/reparse point: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() {
                anyhow::bail!(
                    "release bundle descendant must be a regular file or directory: {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_executable_if_needed(
    path: &Path,
    spec: BundleMemberSpec,
    metadata: &fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if spec.executable && metadata.permissions().mode() & 0o111 == 0 {
        anyhow::bail!(
            "release bundle executable has no execute bit: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_executable_if_needed(
    _path: &Path,
    _spec: BundleMemberSpec,
    _metadata: &fs::Metadata,
) -> Result<()> {
    Ok(())
}

fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn bundle_member_specs(profile: PortableBundleProfile) -> Vec<BundleMemberSpec> {
    let mut specs = vec![
        BundleMemberSpec::executable(compat_binary_name()),
        BundleMemberSpec::executable(migrate_binary_name()),
        BundleMemberSpec::executable(relay_binary_name()),
    ];
    if profile == PortableBundleProfile::Desktop {
        specs.push(BundleMemberSpec::executable(gui_binary_name()));
        specs.push(BundleMemberSpec::executable(keet_binary_name()));
    }
    specs.extend([
        BundleMemberSpec::file("README.md"),
        BundleMemberSpec::file("LICENSE-MIT"),
        BundleMemberSpec::file("LICENSE-APACHE"),
        BundleMemberSpec::file("THIRD_PARTY_LICENSES"),
        BundleMemberSpec::file("freedom.yaml.example"),
        BundleMemberSpec::file("import-manifest.example.yaml"),
        BundleMemberSpec::directory(SELF_KNOWLEDGE),
        // Public entrypoint is always the final commit point.
        BundleMemberSpec::executable(core_binary_name()),
    ]);
    specs
}

const fn core_binary_name() -> &'static str {
    if cfg!(windows) { "neoth.exe" } else { "neoth" }
}

const fn compat_binary_name() -> &'static str {
    if cfg!(windows) {
        "neothd.exe"
    } else {
        "neothd"
    }
}

const fn gui_binary_name() -> &'static str {
    if cfg!(windows) {
        "neothd-gui.exe"
    } else {
        "neothd-gui"
    }
}

const fn migrate_binary_name() -> &'static str {
    if cfg!(windows) {
        "neoth-migrate.exe"
    } else {
        "neoth-migrate"
    }
}

const fn relay_binary_name() -> &'static str {
    if cfg!(windows) {
        "neoth-relay.exe"
    } else {
        "neoth-relay"
    }
}

const fn keet_binary_name() -> &'static str {
    if cfg!(windows) {
        "neoth-keet-bridge.exe"
    } else {
        "neoth-keet-bridge"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_shape(root: &Path, profile: PortableBundleProfile) {
        for spec in bundle_member_specs(profile) {
            let path = root.join(spec.name);
            match spec.kind {
                BundleMemberKind::File => {
                    fs::write(&path, b"fixture").unwrap();
                    #[cfg(unix)]
                    if spec.executable {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                    }
                }
                BundleMemberKind::Directory => {
                    fs::create_dir(&path).unwrap();
                    fs::write(path.join("payload"), b"fixture").unwrap();
                }
            }
        }
    }

    #[test]
    fn desktop_profile_is_closed_and_core_is_last() {
        let specs = bundle_member_specs(PortableBundleProfile::Desktop);
        assert_eq!(specs.last().unwrap().name, core_binary_name());
        assert!(
            !specs
                .iter()
                .any(|spec| spec.name == PORTABLE_OWNERSHIP_MARKER),
            "the ownership marker is generated locally and must never be trusted from the archive"
        );
        assert!(specs.iter().any(|spec| spec.name == gui_binary_name()));
        assert!(specs.iter().any(|spec| spec.name == keet_binary_name()));
        for name in [
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "THIRD_PARTY_LICENSES",
            "freedom.yaml.example",
            "import-manifest.example.yaml",
            SELF_KNOWLEDGE,
        ] {
            assert!(specs.iter().any(|spec| spec.name == name), "missing {name}");
        }
    }

    #[test]
    fn musl_profile_excludes_desktop_only_companions() {
        let specs = bundle_member_specs(PortableBundleProfile::HeadlessMusl);
        assert_eq!(specs.last().unwrap().name, core_binary_name());
        assert!(!specs.iter().any(|spec| spec.name == gui_binary_name()));
        assert!(!specs.iter().any(|spec| spec.name == keet_binary_name()));

        let prepared = prepared_members(
            PortableBundleProfile::HeadlessMusl,
            Path::new("bundle"),
            &ReleaseInstallLayout::Portable(PathBuf::from("installed")),
            &specs,
            Path::new("marker-source"),
        )
        .unwrap();
        assert_eq!(
            prepared.last().unwrap().target(),
            Path::new("installed").join(core_binary_name()),
            "neoth must remain the final commit point"
        );
        for forbidden in [gui_binary_name(), keet_binary_name()] {
            let member = prepared
                .iter()
                .find(|member| member.target() == Path::new("installed").join(forbidden))
                .expect("musl plan removes stale desktop companion");
            assert!(member.source().is_none(), "stale companion must be absent");
        }

        let allowed = allowed_targets(
            PortableBundleProfile::HeadlessMusl,
            &ReleaseInstallLayout::Portable(PathBuf::from("installed")),
            &specs,
        )
        .unwrap();
        for forbidden in [gui_binary_name(), keet_binary_name()] {
            assert!(allowed.iter().any(|target| {
                target.path() == Path::new("installed").join(forbidden)
                    && target.kind() == super::super::install_transaction::MemberKind::File
            }));
        }
    }

    #[test]
    fn linux_package_targets_are_derived_from_names_not_caller_maps() {
        let support = BundleMemberSpec::file("README.md");
        let example = BundleMemberSpec::file("freedom.yaml.example");
        let snapshot = BundleMemberSpec::directory(SELF_KNOWLEDGE);
        let binary = BundleMemberSpec::executable(core_binary_name());

        let linux = ReleaseInstallLayout::LinuxSystem;
        assert_eq!(
            linux.target_for(binary).unwrap(),
            Path::new("/usr/bin").join(core_binary_name())
        );
        assert_eq!(
            linux.target_for(support).unwrap(),
            PathBuf::from("/usr/share/doc/neoth/README.md")
        );
        assert_eq!(
            linux.target_for(example).unwrap(),
            PathBuf::from("/usr/share/doc/neoth/examples/freedom.yaml.example")
        );
        assert_eq!(
            linux.target_for(snapshot).unwrap(),
            PathBuf::from("/usr/share/neoth/self-knowledge")
        );
    }

    #[test]
    fn package_owned_layouts_refuse_member_transactions_before_archive_access() {
        let linux_error = apply_release_bundle(
            Path::new("archive-is-never-opened"),
            ReleaseInstallLayout::LinuxSystem,
            "1.0.0",
        )
        .unwrap_err();
        assert!(
            linux_error
                .downcast_ref::<NativeLinuxPackageRequired>()
                .is_some(),
            "unexpected Linux error: {linux_error:#}"
        );

        let mac_error = apply_release_bundle(
            Path::new("archive-is-never-opened"),
            ReleaseInstallLayout::MacApp(PathBuf::from("/Applications/NEOTH.app/Contents")),
            "1.0.0",
        )
        .unwrap_err();
        assert!(
            mac_error
                .downcast_ref::<SignedMacPackageRequired>()
                .is_some(),
            "unexpected macOS error: {mac_error:#}"
        );
    }

    #[test]
    fn portable_marker_is_generated_inside_the_release_transaction() {
        let fixture = crate::test_env::canonical_tempdir().unwrap();
        let bundle = fixture.path().join("bundle");
        let install = fixture.path().join("installed");
        fs::create_dir_all(&bundle).unwrap();
        fs::create_dir_all(&install).unwrap();
        exact_shape(&bundle, PortableBundleProfile::current());
        fs::remove_dir_all(bundle.join(SELF_KNOWLEDGE)).unwrap();
        crate::wiki::release_snapshot::write_test_snapshot(
            &bundle.join(SELF_KNOWLEDGE),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        let committed =
            apply_portable_release_bundle(&bundle, &install, env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(
            committed.receipt.members,
            bundle_member_specs(PortableBundleProfile::current()).len() + 1
        );
        let marker: PortableOwnershipMarker =
            serde_json::from_slice(&fs::read(install.join(PORTABLE_OWNERSHIP_MARKER)).unwrap())
                .unwrap();
        assert_eq!(marker.schema_version, PORTABLE_MARKER_SCHEMA_VERSION);
        assert_eq!(marker.owner, PORTABLE_MARKER_OWNER);
        assert_eq!(marker.release_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(marker.profile, PortableBundleProfile::current().as_str());
        assert_eq!(marker.support_dir, PORTABLE_SUPPORT_DIR);
        assert_eq!(
            marker_root_identity(&marker.install_root).unwrap(),
            marker_root_identity(&display_marker_root(&fs::canonicalize(&install).unwrap()))
                .unwrap()
        );
        validate_existing_portable_marker(&install, PortableBundleProfile::current()).unwrap();
        assert!(
            install
                .join(PORTABLE_SUPPORT_DIR)
                .join("README.md")
                .is_file()
        );
        assert!(
            install
                .join(PORTABLE_SUPPORT_DIR)
                .join(SELF_KNOWLEDGE)
                .is_dir()
        );
        assert!(!install.join("README.md").exists());
        assert!(!install.join(SELF_KNOWLEDGE).exists());
    }

    #[test]
    fn portable_bundle_installs_into_an_absent_root() {
        // GOLD-R3-12: a first portable install must work when the final install
        // root does not exist yet. The ownership marker stages in the nearest
        // existing ancestor (not the absent root), and the transaction creates
        // the root and commits every member. Space + non-ASCII in the missing
        // leaf exercises path handling on the create path.
        let fixture = crate::test_env::canonical_tempdir().unwrap();
        let bundle = fixture.path().join("bundle");
        let install = fixture.path().join("nëoth inst");
        fs::create_dir_all(&bundle).unwrap();
        exact_shape(&bundle, PortableBundleProfile::current());
        fs::remove_dir_all(bundle.join(SELF_KNOWLEDGE)).unwrap();
        crate::wiki::release_snapshot::write_test_snapshot(
            &bundle.join(SELF_KNOWLEDGE),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert!(
            !install.exists(),
            "precondition: install root must be absent"
        );

        let committed =
            apply_portable_release_bundle(&bundle, &install, env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(
            committed.receipt.members,
            bundle_member_specs(PortableBundleProfile::current()).len() + 1
        );
        assert!(
            install.is_dir(),
            "the transaction must create the previously absent install root"
        );
        assert!(
            install.join(PORTABLE_OWNERSHIP_MARKER).is_file(),
            "ownership marker must be committed into the newly created root"
        );
        validate_existing_portable_marker(&install, PortableBundleProfile::current()).unwrap();
        assert!(
            install
                .join(PORTABLE_SUPPORT_DIR)
                .join(SELF_KNOWLEDGE)
                .is_dir()
        );
    }

    #[cfg(unix)]
    #[test]
    fn portable_bundle_rejects_symlinked_ancestor_on_absent_root() {
        // GOLD-R3-12: a first install whose absent destination sits under a
        // SYMLINKED ancestor must be rejected — the resolved-root ancestor walk
        // requires a real, link-free chain, so a fresh install cannot be
        // redirected through a symlink into a foreign volume/location.
        let fixture = crate::test_env::canonical_tempdir().unwrap();
        let bundle = fixture.path().join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        exact_shape(&bundle, PortableBundleProfile::current());
        fs::remove_dir_all(bundle.join(SELF_KNOWLEDGE)).unwrap();
        crate::wiki::release_snapshot::write_test_snapshot(
            &bundle.join(SELF_KNOWLEDGE),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        let real_parent = fixture.path().join("real-parent");
        fs::create_dir_all(&real_parent).unwrap();
        let link_parent = fixture.path().join("link-parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        // Absent leaf under the symlinked ancestor.
        let install = link_parent.join("inst");
        assert!(!install.exists());

        let err = apply_portable_release_bundle(&bundle, &install, env!("CARGO_PKG_VERSION"))
            .expect_err("install through a symlinked ancestor must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ancestor"),
            "expected a link-free-ancestor rejection, got: {msg}"
        );
        // Nothing was created through the link.
        assert!(!real_parent.join("inst").exists());
    }

    #[cfg(windows)]
    #[test]
    fn portable_bundle_rejects_junction_ancestor_on_absent_root() {
        // GOLD-R3-12: the Windows analog of the symlink-ancestor rejection. A
        // first install whose absent destination sits under a DIRECTORY JUNCTION
        // (a reparse point) must be rejected — the resolved-root ancestor walk
        // requires a real, reparse-free chain. `metadata_is_link_like` catches a
        // junction via FILE_ATTRIBUTE_REPARSE_POINT even though Rust does not
        // classify it as a symlink. Junctions (`mklink /J`) need no admin/dev
        // mode, so they are the realistic Windows redirect surface.
        let fixture = crate::test_env::canonical_tempdir().unwrap();
        let bundle = fixture.path().join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        exact_shape(&bundle, PortableBundleProfile::current());
        fs::remove_dir_all(bundle.join(SELF_KNOWLEDGE)).unwrap();
        crate::wiki::release_snapshot::write_test_snapshot(
            &bundle.join(SELF_KNOWLEDGE),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        let real_parent = fixture.path().join("real-parent");
        fs::create_dir_all(&real_parent).unwrap();
        let junction = fixture.path().join("junction-parent");
        // `mklink /J <link> <target>` — a directory junction, no privilege needed.
        let status = std::process::Command::new("cmd")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&real_parent)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mklink /J");
        assert!(status.success(), "mklink /J must create the test junction");

        // Absent leaf under the junctioned ancestor.
        let install = junction.join("inst");
        assert!(!install.exists());

        let err = apply_portable_release_bundle(&bundle, &install, env!("CARGO_PKG_VERSION"))
            .expect_err("install through a junction ancestor must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ancestor"),
            "expected a reparse-free-ancestor rejection, got: {msg}"
        );
        // Nothing was created through the junction.
        assert!(!real_parent.join("inst").exists());
    }

    #[test]
    fn portable_absent_root_hard_crash_self_heals_on_retry() {
        // GOLD-R3-12a regression: a hard child-process crash at StageReady(0)
        // during the first portable install (absent install root) must NOT leave
        // a committed-but-partial install, and a retry must SELF-HEAL — recover
        // its own crashed partial and commit a complete, valid install — rather
        // than quarantining the operator out of their own crashed first install.
        //
        // Behavior: the crash creates the install directory and NEOTH-owned
        // subdirectories but never commits the ownership marker. On retry,
        // apply_release_bundle now runs recover_crashed_portable_partial BEFORE
        // the markerless-first-install guard: recover() rolls back this root's own
        // journaled crashed partial, the guard then sees a cleaned root, and the
        // install commits. A foreign/prior install carries no NEOTH journal, so it
        // is untouched by recovery and still quarantined by the guard (covered by
        // markerless_shared_root_preserves_generic_collisions_but_blocks_neoth_targets).
        //
        // The killpoint mechanism lives in install_transaction::tests::crash_child_entry.
        // We dispatch to a "portable-absent-root" / "apply" arm added there, which
        // sets TEST_HOOK and calls apply_portable_release_bundle. NEOTH_INSTALL_STATE_DIR
        // pins default_transaction_anchor() to our temp dir so the journal does not
        // bleed into LOCALAPPDATA/HOME.
        let fixture = crate::test_env::canonical_tempdir().unwrap();
        let bundle = fixture.path().join("bundle");
        let install = fixture.path().join("install");

        fs::create_dir_all(&bundle).unwrap();
        exact_shape(&bundle, PortableBundleProfile::current());
        fs::remove_dir_all(bundle.join(SELF_KNOWLEDGE)).unwrap();
        crate::wiki::release_snapshot::write_test_snapshot(
            &bundle.join(SELF_KNOWLEDGE),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert!(
            !install.exists(),
            "precondition: install root must be absent"
        );

        // env-var name constants mirror install_transaction::tests (same string values).
        const CHILD_ROOT: &str = "NEOTH_INSTALL_TXN_TEST_ROOT";
        const CHILD_FIXTURE: &str = "NEOTH_INSTALL_TXN_TEST_FIXTURE";
        const CHILD_MODE: &str = "NEOTH_INSTALL_TXN_TEST_MODE";
        const CHILD_HOOK: &str = "NEOTH_INSTALL_TXN_TEST_HOOK";

        // Phase 1 — crash mid-apply.
        // StageReady(0) fires after directories are created and the first member
        // is staged, but BEFORE any file is renamed into its final target.
        // serde_json serialises HookPoint::StageReady(0) as {"StageReady":0}.
        let crash_status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("crash_child_entry")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, fixture.path())
            .env(CHILD_FIXTURE, "portable-absent-root")
            .env(CHILD_MODE, "apply")
            .env(CHILD_HOOK, "{\"StageReady\":0}")
            .env("NEOTH_INSTALL_STATE_DIR", fixture.path())
            .status()
            .unwrap();
        assert_eq!(
            crash_status.code(),
            Some(86),
            "child must exit at the StageReady(0) killpoint"
        );

        // Post-crash: the ownership marker must not exist.
        // The marker is the final commit artefact; its absence proves the install
        // was never partially committed (only staged, then crashed).
        assert!(
            !install.join(PORTABLE_OWNERSHIP_MARKER).exists(),
            "ownership marker must not exist after a StageReady(0) crash — \
             the install must not be in a committed-but-partial state"
        );

        // Phase 2 — retry over the crashed partial must SELF-HEAL.
        // The "apply-recover" mode clears TEST_HOOK so no killpoint fires, then
        // re-runs apply_portable_release_bundle. The child encodes the outcome:
        //    0 = self-healed (retry recovered the partial and committed cleanly)
        //   70 = quarantined (pre-R3-12a behavior — a regression now)
        let recover_status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("crash_child_entry")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, fixture.path())
            .env(CHILD_FIXTURE, "portable-absent-root")
            .env(CHILD_MODE, "apply-recover")
            .env(CHILD_HOOK, "\"DirectoriesReady\"") // valid JSON; cleared by the arm
            .env("NEOTH_INSTALL_STATE_DIR", fixture.path())
            .status()
            .unwrap();

        // GOLD-R3-12a: the retry must recover its own journaled crashed partial
        // and commit a complete, valid install — not quarantine the operator.
        assert_eq!(
            recover_status.code(),
            Some(0),
            "retry over the crashed first-install partial must self-heal (exit 0), \
             recovering the journaled partial and committing cleanly"
        );
        assert!(
            install.join(PORTABLE_OWNERSHIP_MARKER).is_file(),
            "a self-healed retry must commit a valid ownership marker"
        );
        validate_existing_portable_marker(&install, PortableBundleProfile::current())
            .expect("self-healed marker must be valid");
    }

    #[test]
    fn markerless_shared_root_preserves_generic_collisions_but_blocks_neoth_targets() {
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("shared-bin");
        fs::create_dir(&install).unwrap();
        for name in [
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "THIRD_PARTY_LICENSES",
            "freedom.yaml.example",
            "import-manifest.example.yaml",
        ] {
            fs::write(install.join(name), format!("foreign sentinel: {name}")).unwrap();
        }
        fs::create_dir(install.join(SELF_KNOWLEDGE)).unwrap();
        fs::write(
            install.join(SELF_KNOWLEDGE).join("sentinel"),
            b"foreign self knowledge",
        )
        .unwrap();

        validate_existing_portable_marker(&install, PortableBundleProfile::current()).unwrap();
        assert!(
            markerless_portable_target_collision(&install)
                .unwrap()
                .is_none()
        );

        for name in [core_binary_name(), PORTABLE_SUPPORT_DIR] {
            let path = install.join(name);
            if name == PORTABLE_SUPPORT_DIR {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"foreign binary").unwrap();
            }
            let error =
                validate_existing_portable_marker(&install, PortableBundleProfile::current())
                    .unwrap_err();
            assert!(
                error.to_string().contains("markerless first install"),
                "unexpected collision error: {error:#}"
            );
            if path.is_dir() {
                fs::remove_dir(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
        }

        for name in [
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "THIRD_PARTY_LICENSES",
            "freedom.yaml.example",
            "import-manifest.example.yaml",
        ] {
            assert_eq!(
                fs::read_to_string(install.join(name)).unwrap(),
                format!("foreign sentinel: {name}")
            );
        }
        assert_eq!(
            fs::read(install.join(SELF_KNOWLEDGE).join("sentinel")).unwrap(),
            b"foreign self knowledge"
        );
    }

    #[test]
    fn portable_marker_rejects_unknown_fields_and_wrong_identity() {
        let fixture = tempfile::tempdir().unwrap();
        let install = fixture.path().join("installed");
        fs::create_dir(&install).unwrap();
        let (_stage, source) = prepare_portable_marker(
            &install,
            env!("CARGO_PKG_VERSION"),
            PortableBundleProfile::current(),
        )
        .unwrap();
        let marker_path = install.join(PORTABLE_OWNERSHIP_MARKER);
        fs::copy(&source, &marker_path).unwrap();
        validate_existing_portable_marker(&install, PortableBundleProfile::current()).unwrap();

        let mut marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
        marker["unexpected"] = serde_json::json!(true);
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        assert!(
            validate_existing_portable_marker(&install, PortableBundleProfile::current()).is_err()
        );

        marker.as_object_mut().unwrap().remove("unexpected");
        marker["install_root"] = serde_json::json!(fixture.path().join("elsewhere"));
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        assert!(
            validate_existing_portable_marker(&install, PortableBundleProfile::current()).is_err()
        );
    }

    #[test]
    fn inno_registration_classifier_never_treats_setup_as_portable() {
        let install = Path::new("installed");
        assert!(
            classify_inno_records(
                install,
                InnoInstallRecord::Missing,
                InnoInstallRecord::Missing,
            )
            .is_ok()
        );

        for (user, machine, reason) in [
            (
                InnoInstallRecord::Location("installed".to_string()),
                InnoInstallRecord::Missing,
                "per-user",
            ),
            (
                InnoInstallRecord::Missing,
                InnoInstallRecord::Location("installed".to_string()),
                "machine",
            ),
            (
                InnoInstallRecord::Location("elsewhere".to_string()),
                InnoInstallRecord::Missing,
                "does not match",
            ),
            (
                InnoInstallRecord::Location("installed".to_string()),
                InnoInstallRecord::Location("installed".to_string()),
                "both",
            ),
            (
                InnoInstallRecord::Malformed("bad value".to_string()),
                InnoInstallRecord::Missing,
                "malformed",
            ),
        ] {
            let error = classify_inno_records(install, user, machine).unwrap_err();
            assert!(
                error.downcast_ref::<SignedWindowsSetupRequired>().is_some(),
                "unexpected error type: {error:#}"
            );
            assert!(
                error.to_string().contains(reason),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn exact_shape_rejects_missing_and_unexpected_members() {
        let fixture = tempfile::tempdir().unwrap();
        exact_shape(fixture.path(), PortableBundleProfile::Desktop);
        validate_bundle_root_shape(
            fixture.path(),
            &bundle_member_specs(PortableBundleProfile::Desktop),
        )
        .unwrap();

        fs::remove_file(fixture.path().join("README.md")).unwrap();
        assert!(
            validate_bundle_root_shape(
                fixture.path(),
                &bundle_member_specs(PortableBundleProfile::Desktop)
            )
            .unwrap_err()
            .to_string()
            .contains("missing required entries")
        );
        fs::write(fixture.path().join("README.md"), b"fixture").unwrap();
        fs::write(fixture.path().join("unexpected"), b"fixture").unwrap();
        assert!(
            validate_bundle_root_shape(
                fixture.path(),
                &bundle_member_specs(PortableBundleProfile::Desktop)
            )
            .unwrap_err()
            .to_string()
            .contains("unexpected entry")
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_shape_rejects_symlinked_members_and_descendants() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().unwrap();
        exact_shape(fixture.path(), PortableBundleProfile::Desktop);
        let license = fixture.path().join("LICENSE-MIT");
        fs::remove_file(&license).unwrap();
        symlink("LICENSE-APACHE", &license).unwrap();
        assert!(
            validate_bundle_root_shape(
                fixture.path(),
                &bundle_member_specs(PortableBundleProfile::Desktop)
            )
            .is_err()
        );

        fs::remove_file(&license).unwrap();
        fs::write(&license, b"fixture").unwrap();
        symlink(
            fixture.path().join("README.md"),
            fixture.path().join(SELF_KNOWLEDGE).join("link"),
        )
        .unwrap();
        assert!(
            validate_bundle_root_shape(
                fixture.path(),
                &bundle_member_specs(PortableBundleProfile::Desktop)
            )
            .is_err()
        );
    }

    #[test]
    fn expected_version_is_canonical_and_unprefixed() {
        assert_eq!(
            validate_expected_version("1.0.0").unwrap().to_string(),
            "1.0.0"
        );
        assert!(validate_expected_version("v1.0.0").is_err());
        assert!(validate_expected_version("01.0.0").is_err());
    }
}
