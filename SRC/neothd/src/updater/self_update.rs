//! Signed, integrity-checked self-update via GitHub Releases.
//!
//! The module resolves the host archive, bounds every download and extraction,
//! verifies SHA-256 plus minisign policy, stages unattended updates, and applies
//! operator-approved updates through the same closed, journaled release-bundle
//! transaction used by bootstrap. Portable installations update every
//! package-owned member as one version-locked unit. Native package-manager and
//! signed-app layouts fail closed and require their platform installer.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::ReleaseChannel;

/// One GitHub Release as returned by
/// `/repos/{owner}/{repo}/releases/latest`. We only care about the
/// fields the operator-facing summary uses; the rest of the response
/// is ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct LatestRelease {
    /// e.g. `"v0.2.0"`. Leading `v` is stripped by [`parse_semver`].
    pub tag_name: String,
    /// Human-readable page operators click through to.
    pub html_url: String,
    /// ISO-8601 timestamp. Surfaced in the summary; not parsed.
    #[serde(default)]
    pub published_at: String,
    /// Attached binary artefacts from cargo-dist's release-args
    /// pipeline. Empty when the release was published without
    /// attached binaries (Phase-1 v0.1.0 release, for example).
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

/// One file attached to a GitHub Release. cargo-dist names the
/// tarball after `<binary>-<target-triple>.<format>` and uploads
/// a paired `<asset>.sha256` companion for integrity checks.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    /// File name as it lands on disk after download
    /// (e.g. `"neoth-x86_64-pc-windows-msvc.zip"`).
    pub name: String,
    /// Direct download URL — caller `GET`s it to fetch the bytes.
    pub browser_download_url: String,
    /// Reported file size in bytes. Set to 0 by GitHub when the
    /// upload is still in progress; the download path treats that
    /// as "unknown, accept any size".
    #[serde(default)]
    pub size: u64,
}

/// Result the CLI surfaces. `needs_update == true` triggers the
/// "newer version available" banner in the table renderer.
#[derive(Debug, Clone)]
pub struct UpdateCheck {
    pub current: String,
    pub latest: String,
    pub needs_update: bool,
    pub release_url: String,
    pub published_at: String,
}

/// Compile-time version of the running daemon. Pinned at env!-time
/// so the binary always knows its own identity.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn parse_semver_version(s: &str) -> Result<semver::Version> {
    let trimmed = s.trim();
    let normalized = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    semver::Version::parse(normalized).with_context(|| format!("invalid semantic version {s:?}"))
}

/// Parse a semver string into its core `(major, minor, patch)` components.
/// Accepts one leading `v`/`V`; pre-release and build metadata are validated by
/// the SemVer parser and remain available to [`version_is_newer`].
pub fn parse_semver(s: &str) -> Result<(u32, u32, u32)> {
    let version = parse_semver_version(s)?;
    Ok((
        u32::try_from(version.major).context("semver major exceeds u32")?,
        u32::try_from(version.minor).context("semver minor exceeds u32")?,
        u32::try_from(version.patch).context("semver patch exceeds u32")?,
    ))
}

/// Returns true when `latest` strictly compares greater than `current` under
/// full SemVer precedence. In particular, `1.0.0` is newer than
/// `1.0.0-beta.4`; build metadata does not affect precedence. Unparseable input
/// surfaces as `Err`, never a silent "already current" result.
pub fn version_is_newer(latest: &str, current: &str) -> Result<bool> {
    let l = parse_semver_version(latest)?;
    let c = parse_semver_version(current)?;
    Ok(l.cmp_precedence(&c).is_gt())
}

fn prerelease_is_rc(version: &semver::Version) -> bool {
    version.pre.as_str().split(['.', '-']).any(|part| {
        let part = part.to_ascii_lowercase();
        part == "rc"
            || part.strip_prefix("rc").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
    })
}

fn prerelease_is_nightly(version: &semver::Version) -> bool {
    version.pre.as_str().split(['.', '-']).any(|part| {
        let part = part.to_ascii_lowercase();
        part == "nightly"
            || part.strip_prefix("nightly").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
    })
}

fn version_matches_channel(version: &semver::Version, channel: ReleaseChannel) -> bool {
    match channel {
        ReleaseChannel::Stable => version.pre.is_empty(),
        ReleaseChannel::Rc => version.pre.is_empty() || prerelease_is_rc(version),
        ReleaseChannel::Nightly => {
            version.pre.is_empty() || prerelease_is_rc(version) || prerelease_is_nightly(version)
        }
    }
}

/// Validate one release tag against a ring. Used by the staged fast-path so a
/// pending RC/nightly cannot bypass a later switch back to stable.
pub fn release_tag_matches_channel(tag: &str, channel: ReleaseChannel) -> bool {
    parse_semver_version(tag)
        .map(|version| version_matches_channel(&version, channel))
        .unwrap_or(false)
}

/// Strict GitHub release-feed slug validation shared by config loading, CLI
/// overrides, network probes, and staged provenance records.
pub fn owner_repo_is_valid(owner_repo: &str) -> bool {
    let Some((owner, repo)) = owner_repo.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && owner.len() <= 39
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !repo.is_empty()
        && repo.len() <= 100
        && repo != "."
        && repo != ".."
        && !repo.contains('/')
        && repo
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_owner_repo(owner_repo: &str) -> Result<()> {
    if owner_repo_is_valid(owner_repo) {
        Ok(())
    } else {
        anyhow::bail!(
            "invalid GitHub release repository {owner_repo:?}; expected an owner/repo slug"
        )
    }
}

/// Build one anonymous GitHub API GET for the public release feed.
///
/// The runtime updater deliberately has no credential input. NEOTH releases
/// are public, so accepting `GITHUB_TOKEN` would widen the secret-handling
/// surface without changing which signed artifacts the updater may install.
fn github_api_get(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client
        .get(url)
        .header("Accept", "application/vnd.github+json")
}

/// Pick the highest SemVer release admitted by the configured ring. Invalid
/// tags are ignored instead of accidentally becoming an update candidate.
/// GitHub returns newest-first; equal-precedence builds retain that first row.
pub fn select_release_for_channel(
    releases: Vec<LatestRelease>,
    channel: ReleaseChannel,
) -> Option<LatestRelease> {
    let mut selected: Option<(semver::Version, LatestRelease)> = None;
    for release in releases {
        let Ok(version) = parse_semver_version(&release.tag_name) else {
            continue;
        };
        if !version_matches_channel(&version, channel) {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(best, _)| version.cmp_precedence(best).is_gt())
        {
            selected = Some((version, release));
        }
    }
    selected.map(|(_, release)| release)
}

/// Fetch the latest release from GitHub. `owner_repo` is the
/// `owner/repo` slug, e.g. `"The-Geek-Freaks/NEOTH"`.
///
/// User-Agent is required by GitHub; we pin
/// `"NEOTH/{version} (update-check)"` so a server-side audit can
/// distinguish update-check traffic from other reqwest callers.
pub async fn fetch_latest_release(owner_repo: &str) -> Result<LatestRelease> {
    validate_owner_repo(owner_repo)?;
    let url = format!("https://api.github.com/repos/{owner_repo}/releases/latest");
    let ua = format!("NEOTH/{} (update-check)", current_version());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .build()
        .context("build update-check reqwest client")?;
    let resp = github_api_get(&client, &url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "GitHub release check failed: HTTP {} — {}",
            status,
            match status.as_u16() {
                403 => "rate-limited (wait for the public API window to reset, then retry)",
                404 => "repo has no published releases yet",
                _ => "see GitHub status page",
            },
        );
    }
    let release: LatestRelease = resp.json().await.context("parse GitHub release JSON")?;
    Ok(release)
}

/// Resolve the newest release admitted by `channel`.
///
/// Stable uses GitHub's canonical `/releases/latest` endpoint. Wider rings use
/// the newest 100 published releases and choose the highest matching SemVer:
/// `rc` admits stable + RC tags (including `gold-rc1`), while `nightly` admits
/// stable, RC, and nightly-tagged SemVer releases. Alpha/beta tags are excluded
/// because no configured ring claims them.
pub async fn fetch_release_for_channel(
    owner_repo: &str,
    channel: ReleaseChannel,
) -> Result<LatestRelease> {
    if channel == ReleaseChannel::Stable {
        let release = fetch_latest_release(owner_repo).await?;
        if release_tag_matches_channel(&release.tag_name, channel) {
            return Ok(release);
        }
        anyhow::bail!(
            "repo {owner_repo} latest release tag {:?} is not a final SemVer release admitted by channel stable",
            release.tag_name
        );
    }

    validate_owner_repo(owner_repo)?;

    let url = format!("https://api.github.com/repos/{owner_repo}/releases?per_page=100");
    let ua = format!("NEOTH/{} (update-check)", current_version());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .build()
        .context("build update-check reqwest client")?;
    let resp = github_api_get(&client, &url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "GitHub {} release check failed: HTTP {} — {}",
            channel,
            status,
            match status.as_u16() {
                403 => "rate-limited (wait for the public API window to reset, then retry)",
                404 => "repo has no published releases yet",
                _ => "see GitHub status page",
            },
        );
    }
    let releases: Vec<LatestRelease> = resp
        .json()
        .await
        .context("parse GitHub releases-list JSON")?;
    select_release_for_channel(releases, channel).ok_or_else(|| {
        anyhow::anyhow!(
            "repo {owner_repo} has no valid SemVer release admitted by channel {channel}"
        )
    })
}

/// Top-level update check. Wraps `fetch_latest_release` + version
/// comparison into one operator-facing call. The CLI renders the
/// `UpdateCheck` in table form; `--output json` re-emits the same
/// shape via serde.
pub async fn check_for_update(owner_repo: &str) -> Result<UpdateCheck> {
    check_for_update_channel(owner_repo, ReleaseChannel::Stable).await
}

/// Channel-aware update check used by daemon policy and `neoth update --self`.
pub async fn check_for_update_channel(
    owner_repo: &str,
    channel: ReleaseChannel,
) -> Result<UpdateCheck> {
    let release = fetch_release_for_channel(owner_repo, channel).await?;
    let needs = version_is_newer(&release.tag_name, current_version())?;
    Ok(UpdateCheck {
        current: current_version().to_string(),
        latest: release.tag_name,
        needs_update: needs,
        release_url: release.html_url,
        published_at: release.published_at,
    })
}

// Asset naming and resolution stay pure so release-workflow drift is caught by
// unit tests before the networked stage/apply paths run.

/// Archive format the release workflow emits per host platform.
///
/// Pinned to what `.github/workflows/release.yml` actually produces:
///   - Windows: `.zip` (7-Zip, NestedInstallerType: portable for winget)
///   - Linux:   `.tar.gz` (`tar -czf`)
///   - macOS:   `.tar.gz` (`tar -czf`)
///
/// `TarXz` is kept in the enum + the extractor stays compiled — a future
/// workflow flip to `.tar.xz` (smaller for larger releases) only needs
/// flipping the per-target arm in [`archive_format_for_target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    TarXz,
    TarGz,
}

impl ArchiveFormat {
    /// Filename extension — leading dot included so a caller can
    /// append directly: `format!("{}{}", asset_stem, fmt.extension())`.
    pub fn extension(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => ".zip",
            ArchiveFormat::TarXz => ".tar.xz",
            ArchiveFormat::TarGz => ".tar.gz",
        }
    }
}

/// Pick the canonical archive format for a target triple. Aligned to the
/// **release workflow's actual output** — unix targets get `.tar.gz`
/// because that is what `tar -czf` in `release.yml` produces (Session 28f
/// reconciliation; pre-fix the code expected `.tar.xz` and the asset
/// locator silently missed every release). Falls back to `TarGz` for
/// unknown targets — the safest universal choice; the matcher + extractor
/// dispatch on this single source of truth so the want_ext and the chosen
/// extractor can never disagree.
pub fn archive_format_for_target(target: &str) -> ArchiveFormat {
    if target.contains("windows") {
        ArchiveFormat::Zip
    } else {
        // linux / darwin / anything else (universal-safe fallback) — all
        // share the workflow's `tar -czf` `.tar.gz` output.
        ArchiveFormat::TarGz
    }
}

/// Detect the host's Rust target triple at runtime. cargo-dist's
/// tarball naming convention uses these strings verbatim, so the
/// asset-locator must produce the exact same form.
///
/// Composed from `std::env::consts::{OS, ARCH}` — Rust does not
/// expose `TARGET` at runtime by default. Compile-time cfg disambiguates the
/// Linux libc so a musl build can never select a glibc release archive.
///
/// Returns `None` for hosts we don't have a cargo-dist mapping
/// for; the caller falls back to the manual-install path.
pub fn host_target_triple() -> Option<&'static str> {
    use std::env::consts::{ARCH, OS};
    match (OS, ARCH) {
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Some("aarch64-pc-windows-msvc"),
        ("linux", "x86_64") if cfg!(target_env = "musl") => Some("x86_64-unknown-linux-musl"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

/// Exact platform set emitted by `.github/workflows/release.yml`.
pub const SUPPORTED_RELEASE_TARGETS: [&str; 7] = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

pub fn release_target_is_supported(target: &str) -> bool {
    SUPPORTED_RELEASE_TARGETS.contains(&target)
}

/// Resolve an operator override or the native host target, rejecting anything
/// outside the exact release workflow matrix before network/download work.
pub fn resolve_release_target(configured: Option<&str>) -> Result<&str> {
    let target = match configured {
        Some(target) => target.trim(),
        None => host_target_triple().ok_or_else(|| {
            anyhow::anyhow!(
                "host target triple is not in the cargo-dist matrix; supported targets: {}",
                SUPPORTED_RELEASE_TARGETS.join(", ")
            )
        })?,
    };
    if !release_target_is_supported(target) {
        anyhow::bail!(
            "unsupported release target {target:?}; expected one of {}",
            SUPPORTED_RELEASE_TARGETS.join(", ")
        );
    }
    Ok(target)
}

/// Build the canonical asset filename for a binary + release tag + target,
/// matching the release workflow's `<binary>-<tag>-<target>.<archive>` shape.
/// Examples:
///
///   neoth-v1.0.0-x86_64-pc-windows-msvc.zip
///   neoth-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
///   neoth-v1.0.0-aarch64-apple-darwin.tar.gz
///
/// The tag is part of the identity so a stale signed archive attached to a
/// newer release cannot satisfy the update decision by target alone.
pub fn expected_asset_name(binary: &str, tag: &str, target: &str) -> String {
    let fmt = archive_format_for_target(target);
    format!("{binary}-{tag}-{target}{ext}", ext = fmt.extension())
}

/// SHA-256 companion filename for an asset. cargo-dist uploads
/// one of these next to every binary tarball; we use it to
/// verify the download integrity before extracting + installing.
pub fn sha256_companion_name(asset_name: &str) -> String {
    format!("{asset_name}.sha256")
}

/// MV-01b #2 — the minisign signature companion name for an asset
/// (`<asset>.minisig`), matching what the CI signing step uploads.
pub fn minisig_companion_name(asset_name: &str) -> String {
    format!("{asset_name}.minisig")
}

/// Locate the `<asset>.minisig` signature companion for the binary asset.
/// `None` when the release predates signing (manual path warns,
/// unattended path bails).
pub fn find_minisig_companion<'a>(
    assets: &'a [ReleaseAsset],
    binary_asset: &ReleaseAsset,
) -> Option<&'a ReleaseAsset> {
    let want = minisig_companion_name(&binary_asset.name);
    assets.iter().find(|a| a.name == want)
}

/// Locate the matching cargo-dist asset in a release. Returns
/// `None` when no asset matches the target — common when the
/// release was published before the target was added to the
/// cargo-dist matrix.
///
/// Matching is exact across binary, tag, target, and archive format.
pub fn find_matching_asset<'a>(
    assets: &'a [ReleaseAsset],
    binary: &str,
    tag: &str,
    target: &str,
) -> Option<&'a ReleaseAsset> {
    let expected = expected_asset_name(binary, tag, target);
    assets.iter().find(|asset| asset.name == expected)
}

/// Locate the SHA-256 companion asset for a given binary asset.
/// `None` when the release didn't publish a companion. Every stage/apply caller
/// MUST refuse in that case (no checksum =
/// no integrity = treat as untrusted).
pub fn find_sha256_companion<'a>(
    assets: &'a [ReleaseAsset],
    binary_asset: &ReleaseAsset,
) -> Option<&'a ReleaseAsset> {
    let want = sha256_companion_name(&binary_asset.name);
    assets.iter().find(|a| a.name == want)
}

/// Operator-facing decision shape consumed by stage, apply, and dry-run paths.
#[derive(Debug, Clone)]
pub struct UpdateAssets<'a> {
    pub target: &'a str,
    pub binary: &'a ReleaseAsset,
    pub sha256: Option<&'a ReleaseAsset>,
    /// MV-01b #2 — the `.minisig` signature companion, when published.
    pub signature: Option<&'a ReleaseAsset>,
}

/// Closed archive-extraction ceilings. Authentication proves who supplied an
/// archive; these bounds and path rules prove what it is allowed to create.
const MAX_RELEASE_BUNDLE_MEMBER_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RELEASE_BUNDLE_UNPACKED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RELEASE_TAR_STREAM_BYTES: u64 = MAX_RELEASE_BUNDLE_UNPACKED_BYTES + 128 * 1024 * 1024;
const MAX_RELEASE_BUNDLE_MEMBERS: usize = 100_128;
const MAX_RELEASE_BUNDLE_DEPTH: usize = 64;
const MAX_RELEASE_MEMBER_NAME_BYTES: usize = 32 * 1024;

/// Download ceilings for the signed release payload and its small companions.
/// The archive contains all shipped binaries and can legitimately be large, but
/// an unbounded chunked response must never be allowed to exhaust daemon memory.
const MAX_RELEASE_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_PENDING_JSON_BYTES: usize = 64 * 1024;

/// A file-backed `Write` that errors once more than `limit` bytes are written.
/// XZ is decoded into the private extraction directory instead of allocating a
/// decompressed archive in memory.
struct LimitedFileWriter<'a> {
    file: &'a mut std::fs::File,
    written: u64,
    limit: u64,
}

impl std::io::Write for LimitedFileWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::other("decompressed archive size overflow"))?;
        if next > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed archive exceeds size cap (decompression-bomb guard)",
            ));
        }
        let count = std::io::Write::write(self.file, data)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.file)
    }
}

#[derive(Debug)]
struct ArchiveLedger<'a> {
    expected_root: &'a str,
    exact_names: BTreeSet<String>,
    casefold_names: BTreeSet<String>,
    members: usize,
    unpacked_bytes: u64,
}

impl<'a> ArchiveLedger<'a> {
    fn new(expected_root: &'a str) -> Self {
        Self {
            expected_root,
            exact_names: BTreeSet::new(),
            casefold_names: BTreeSet::new(),
            members: 0,
            unpacked_bytes: 0,
        }
    }

    fn register(&mut self, raw_name: &str, is_directory: bool, size: u64) -> Result<PathBuf> {
        if raw_name.len() > MAX_RELEASE_MEMBER_NAME_BYTES {
            anyhow::bail!("release archive member name exceeds the safety ceiling");
        }
        if raw_name.contains(['\\', '\0']) || raw_name.starts_with('/') {
            anyhow::bail!("unsafe release archive member name: {raw_name:?}");
        }
        if !is_directory && raw_name.ends_with('/') {
            anyhow::bail!("regular archive member has a directory name: {raw_name:?}");
        }
        if is_directory && size != 0 {
            anyhow::bail!("archive directory has a non-zero body: {raw_name:?}");
        }
        let normalized = if is_directory {
            raw_name.strip_suffix('/').unwrap_or(raw_name)
        } else {
            raw_name
        };
        let components = normalized.split('/').collect::<Vec<_>>();
        if components.is_empty()
            || components[0] != self.expected_root
            || components.len().saturating_sub(1) > MAX_RELEASE_BUNDLE_DEPTH
        {
            anyhow::bail!(
                "release archive member is outside exact root {:?}: {raw_name:?}",
                self.expected_root
            );
        }
        for component in &components {
            validate_archive_component(component, raw_name)?;
        }

        let exact = components.join("/");
        if !self.exact_names.insert(exact.clone()) {
            anyhow::bail!("duplicate release archive member: {exact:?}");
        }
        let casefold = exact
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if !self.casefold_names.insert(casefold) {
            anyhow::bail!("case-colliding release archive member: {exact:?}");
        }
        self.members = self
            .members
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("release archive member count overflow"))?;
        if self.members > MAX_RELEASE_BUNDLE_MEMBERS {
            anyhow::bail!(
                "release archive exceeds the {MAX_RELEASE_BUNDLE_MEMBERS}-member safety ceiling"
            );
        }
        if size > MAX_RELEASE_BUNDLE_MEMBER_BYTES {
            anyhow::bail!(
                "release archive member exceeds the {MAX_RELEASE_BUNDLE_MEMBER_BYTES}-byte safety ceiling: {exact:?}"
            );
        }
        self.unpacked_bytes = self
            .unpacked_bytes
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("release archive byte count overflow"))?;
        if self.unpacked_bytes > MAX_RELEASE_BUNDLE_UNPACKED_BYTES {
            anyhow::bail!("release archive exceeds the unpacked-byte safety ceiling");
        }

        Ok(components.iter().collect())
    }
}

fn validate_archive_component(component: &str, raw_name: &str) -> Result<()> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.len() > 255
        || component.ends_with([' ', '.'])
        || component.contains(':')
        || component.chars().any(char::is_control)
    {
        anyhow::bail!("unsafe release archive member name: {raw_name:?}");
    }
    let device_stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    let reserved = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || device_stem
            .strip_prefix("COM")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
        || device_stem
            .strip_prefix("LPT")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"));
    if reserved {
        anyhow::bail!("Windows-reserved release archive member: {raw_name:?}");
    }
    Ok(())
}

fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn ensure_private_directory(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            anyhow::bail!("validated archive path became non-relative");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if !metadata_is_link_like(&metadata) && metadata.is_dir() => {}
            Ok(_) => anyhow::bail!(
                "release extraction path is not a real directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).with_context(|| {
                    format!("create private release directory {}", current.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect private release directory {}", current.display())
                });
            }
        }
    }
    Ok(current)
}

fn create_archive_output(root: &Path, relative: &Path) -> Result<std::fs::File> {
    let parent = relative
        .parent()
        .ok_or_else(|| anyhow::anyhow!("release archive file has no parent"))?;
    ensure_private_directory(root, parent)?;
    let destination = root.join(relative);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .with_context(|| format!("create staged release member {}", destination.display()))
}

fn copy_archive_file(
    input: &mut impl std::io::Read,
    output: &mut std::fs::File,
    declared_size: u64,
    relative: &Path,
) -> Result<()> {
    let written = std::io::copy(&mut std::io::Read::take(input, declared_size + 1), output)
        .with_context(|| format!("extract release member {}", relative.display()))?;
    if written != declared_size {
        anyhow::bail!(
            "release archive member size mismatch for {}: declared {declared_size}, extracted {written}",
            relative.display()
        );
    }
    output
        .sync_all()
        .with_context(|| format!("sync staged release member {}", relative.display()))?;
    set_staged_permissions(&root_member_name(relative), output)?;
    Ok(())
}

fn root_member_name(relative: &Path) -> String {
    relative
        .components()
        .nth(1)
        .and_then(|component| component.as_os_str().to_str())
        .unwrap_or_default()
        .to_string()
}

fn set_staged_permissions(root_member: &str, file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let executable = matches!(
            root_member,
            "neoth"
                | "neothd"
                | "neothd-gui"
                | "neoth-migrate"
                | "neoth-relay"
                | "neoth-keet-bridge"
        );
        file.set_permissions(std::fs::Permissions::from_mode(if executable {
            0o755
        } else {
            0o644
        }))?;
    }
    #[cfg(not(unix))]
    let _ = (root_member, file);
    Ok(())
}

fn extract_zip_release_bundle(
    archive_bytes: &[u8],
    stage_root: &Path,
    expected_root: &str,
) -> Result<PathBuf> {
    use std::io::Cursor;

    let mut archive =
        zip::ZipArchive::new(Cursor::new(archive_bytes)).context("open ZIP archive")?;
    let mut ledger = ArchiveLedger::new(expected_root);
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read ZIP entry")?;
        let raw_name = std::str::from_utf8(entry.name_raw())
            .context("ZIP member name is not valid UTF-8")?
            .to_string();
        let is_directory = entry.is_dir();
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            let expected_kind = if is_directory { 0o040_000 } else { 0o100_000 };
            if kind != 0 && kind != expected_kind {
                anyhow::bail!("ZIP member is a symlink or special file: {raw_name:?}");
            }
        }
        let relative = ledger.register(&raw_name, is_directory, entry.size())?;
        if is_directory {
            ensure_private_directory(stage_root, &relative)?;
        } else {
            let declared_size = entry.size();
            let mut output = create_archive_output(stage_root, &relative)?;
            copy_archive_file(&mut entry, &mut output, declared_size, &relative)?;
        }
    }
    require_extracted_root(stage_root, expected_root)
}

fn extract_tar_release_bundle<R: std::io::Read>(
    reader: R,
    stage_root: &Path,
    expected_root: &str,
) -> Result<PathBuf> {
    let mut archive = tar::Archive::new(reader);
    let mut ledger = ArchiveLedger::new(expected_root);
    for entry in archive.entries().context("iterate tar entries")? {
        let mut entry = entry.context("read tar entry")?;
        let raw_name = std::str::from_utf8(entry.path_bytes().as_ref())
            .context("tar member name is not valid UTF-8")?
            .to_string();
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() {
            anyhow::bail!("tar member is a link or special file: {raw_name:?}");
        }
        let is_directory = entry_type.is_dir();
        let declared_size = entry.size();
        let relative = ledger.register(&raw_name, is_directory, declared_size)?;
        if is_directory {
            ensure_private_directory(stage_root, &relative)?;
        } else {
            let mut output = create_archive_output(stage_root, &relative)?;
            copy_archive_file(&mut entry, &mut output, declared_size, &relative)?;
        }
    }
    require_extracted_root(stage_root, expected_root)
}

fn require_extracted_root(stage_root: &Path, expected_root: &str) -> Result<PathBuf> {
    let bundle_root = stage_root.join(expected_root);
    let metadata = std::fs::symlink_metadata(&bundle_root)
        .with_context(|| format!("release archive is missing exact root {expected_root:?}"))?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        anyhow::bail!("release archive root is not a real directory");
    }
    Ok(bundle_root)
}

fn extract_release_bundle(
    archive_bytes: &[u8],
    format: ArchiveFormat,
    stage_root: &Path,
    expected_root: &str,
) -> Result<PathBuf> {
    match format {
        ArchiveFormat::Zip => extract_zip_release_bundle(archive_bytes, stage_root, expected_root),
        ArchiveFormat::TarGz => {
            let decoder = flate2::read::GzDecoder::new(archive_bytes);
            extract_tar_release_bundle(
                std::io::Read::take(decoder, MAX_RELEASE_TAR_STREAM_BYTES + 1),
                stage_root,
                expected_root,
            )
            .context("extract gzip release bundle")
        }
        ArchiveFormat::TarXz => {
            use std::io::{Cursor, Seek as _, SeekFrom, Write as _};

            let raw_tar_path = stage_root.join(".release-bundle.tar");
            let mut raw_tar = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&raw_tar_path)
                .context("create bounded XZ staging file")?;
            {
                let mut writer = LimitedFileWriter {
                    file: &mut raw_tar,
                    written: 0,
                    limit: MAX_RELEASE_TAR_STREAM_BYTES,
                };
                lzma_rs::xz_decompress(&mut Cursor::new(archive_bytes), &mut writer)
                    .context("decompress bounded XZ release bundle")?;
                writer.flush()?;
            }
            raw_tar.seek(SeekFrom::Start(0))?;
            let result = extract_tar_release_bundle(raw_tar, stage_root, expected_root)
                .context("extract XZ release bundle");
            let _ = std::fs::remove_file(raw_tar_path);
            result
        }
    }
}

fn expected_archive_root(release_version: &str, target_triple: &str) -> Result<String> {
    if release_version.trim() != release_version {
        anyhow::bail!("release version contains surrounding whitespace");
    }
    parse_semver_version(release_version)?;
    if !release_target_is_supported(target_triple) {
        anyhow::bail!("unsupported release target {target_triple:?}");
    }
    Ok(format!("neoth-{release_version}-{target_triple}"))
}

/// Pick the host-appropriate binary filename. On Windows the release binary
/// carries a `.exe` suffix; on Unix it is bare.
fn binary_filename_for_host(binary: &str) -> String {
    if std::env::consts::EXE_SUFFIX.is_empty() {
        binary.to_string()
    } else {
        format!("{binary}{}", std::env::consts::EXE_SUFFIX)
    }
}

/// Parse a cargo-dist `.sha256` companion file body. The
/// canonical shape is `<hex-64>  <filename>` (two spaces),
/// matching `sha256sum -b` output. Some publishers emit just
/// the 64-char hex digest on its own line; both forms are
/// accepted. Any line with fewer than 64 hex chars is rejected
/// so a truncated download surfaces as an error instead of a
/// "passes verify because the digest matches itself" footgun.
///
/// Returns the lowercase hex digest. Caller passes this to
/// [`verify_sha256_bytes`] alongside the downloaded asset
/// content.
pub fn parse_sha256_companion(text: &str) -> Result<String> {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("sha256 companion is empty"))?;
    let digest = line
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("sha256 companion has no digest field"))?;
    if digest.len() != 64 {
        anyhow::bail!(
            "sha256 companion digest must be 64 hex chars; got {} chars",
            digest.len()
        );
    }
    if !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("sha256 companion contains non-hex characters");
    }
    Ok(digest.to_ascii_lowercase())
}

/// Compute SHA-256 of `bytes` and compare against the expected
/// lowercase hex digest. Returns `Ok(())` on match; `Err` with
/// an operator-readable diagnostic on mismatch (includes BOTH
/// digests so a copy-paste-mismatch is debuggable, but never
/// the underlying bytes).
///
/// Comparison runs on the hex strings — sha2's digest is
/// already constant-time-safe at the hash level, so the
/// equality check on the hex form is appropriate (the input
/// bytes are public-released-binary, not a secret).
pub fn verify_sha256_bytes(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hasher.finalize();
    let actual_hex = hex_encode(&actual);
    let expected = expected_hex.to_ascii_lowercase();
    if actual_hex != expected {
        anyhow::bail!("sha256 mismatch: expected {expected}, got {actual_hex}");
    }
    Ok(())
}

/// Lowercase hex encoding without an extra dep. Sha256 always
/// produces 32 bytes → 64 hex chars.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Outcome of a successful `apply_update`. The caller surfaces
/// the restart hint to the operator (chat output / WAL frame /
/// neoth doctor banner).
#[derive(Debug, Clone)]
pub struct UpdateApplied {
    pub from_version: String,
    pub to_version: String,
    /// Durable native transaction identifier. Interrupted commits are
    /// recovered automatically from the transaction journal on the next run;
    /// there is no operator-facing backup file to retain or restore manually.
    pub transaction_id: String,
    pub automatic_crash_recovery: bool,
    pub restart_required: bool,
    /// SHA-256 hex of the verified release archive (the value from the
    /// `.sha256` companion that `apply_downloaded` checked the bytes
    /// against). Surfaced into the `0xD2` audit frame so a reviewer can
    /// prove exactly which artifact was installed. MV-01b audit
    /// enrichment (senior-dev panel 2026-05-29).
    pub archive_sha256: String,
    /// Exact `browser_download_url` the archive was fetched from. Lets an
    /// auditor catch a fork-repo swap that the version fields alone
    /// wouldn't reveal.
    pub download_url: String,
    /// MV-01b #2 — minisign signature outcome
    /// ([`crate::updater::sig_verify::SigStatus::as_str`]): `verified`,
    /// `unsigned_allowed`, or `no_pinned_key`. Recorded in the `0xD2`
    /// audit frame.
    pub signature_status: String,
}

/// Windows cannot replace the executable that is currently running. Portable
/// installs therefore hand the already-authenticated archive to the target
/// release helper, which waits for this CLI process and records the real
/// transaction result after it commits. A scheduled handoff is deliberately
/// not reported as `UpdateApplied` and never emits the applied WAL event early.
#[derive(Debug, Clone)]
pub struct UpdateHandoffScheduled {
    pub from_version: String,
    pub to_version: String,
    pub operation_id: String,
    pub receipt_path: PathBuf,
    pub restart_required: bool,
}

#[derive(Debug, Clone)]
pub enum UpdateApplyOutcome {
    Applied(UpdateApplied),
    HandoffScheduled(UpdateHandoffScheduled),
}

struct PreparedDownloadedBundle {
    stage: tempfile::TempDir,
    bundle_root: PathBuf,
    layout: super::release_bundle::ReleaseInstallLayout,
    canonical_version: String,
}

#[cfg(windows)]
fn create_release_staging_directory() -> Result<tempfile::TempDir> {
    require_non_elevated_windows_portable_update("create release staging")?;
    let namespace = windows_handoff_staging_namespace()?;
    let stage = tempfile::Builder::new()
        .prefix(WINDOWS_HANDOFF_STAGE_PREFIX)
        .tempdir_in(&namespace)
        .context("create private Windows release extraction directory")?;
    crate::wal::win_native::set_private_current_user_directory_dacl(stage.path()).with_context(
        || {
            format!(
                "protect private Windows release extraction directory {}",
                stage.path().display()
            )
        },
    )?;
    crate::wal::win_native::verify_private_directory_dacl(stage.path()).with_context(|| {
        format!(
            "verify private Windows release extraction directory {}",
            stage.path().display()
        )
    })?;
    Ok(stage)
}

#[cfg(not(windows))]
fn create_release_staging_directory() -> Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix(".neoth-self-update-")
        .tempdir()
        .context("create private release extraction directory")
}

/// Apply one authenticated release archive through the shared closed bundle
/// policy and crash-safe transaction. The archive is fully extracted into a
/// private directory before package-owned state is inspected or mutated.
pub fn apply_downloaded_bundle(
    asset_bytes: &[u8],
    companion_text: &str,
    format: ArchiveFormat,
    install_dir: &Path,
    expected_release_version: &str,
    target_triple: &str,
) -> Result<super::release_bundle::ReleaseBundleCommit> {
    let prepared = prepare_downloaded_bundle(
        asset_bytes,
        companion_text,
        format,
        install_dir,
        expected_release_version,
        target_triple,
    )?;
    apply_prepared_downloaded_bundle(prepared)
}

fn prepare_downloaded_bundle(
    asset_bytes: &[u8],
    companion_text: &str,
    format: ArchiveFormat,
    install_dir: &Path,
    expected_release_version: &str,
    target_triple: &str,
) -> Result<PreparedDownloadedBundle> {
    let expected = parse_sha256_companion(companion_text).context("parse sha256 companion")?;
    verify_sha256_bytes(asset_bytes, &expected).context("verify asset sha256")?;
    let host_target = host_target_triple()
        .ok_or_else(|| anyhow::anyhow!("self-update is unsupported on this host architecture"))?;
    if target_triple != host_target {
        anyhow::bail!(
            "self-update target {target_triple:?} does not match running host {host_target:?}; cross-target archives cannot replace the running installation"
        );
    }

    let expected_root = expected_archive_root(expected_release_version, target_triple)?;
    let stage = create_release_staging_directory()?;
    let bundle_root = extract_release_bundle(asset_bytes, format, stage.path(), &expected_root)
        .context("safely extract authenticated release bundle")?;

    let installed_executable = install_dir.join(binary_filename_for_host("neoth"));
    let layout =
        super::release_bundle::ReleaseInstallLayout::derive_from_executable(&installed_executable)
            .context("derive trusted installed release layout")?;
    let canonical_version = parse_semver_version(expected_release_version)?.to_string();
    Ok(PreparedDownloadedBundle {
        stage,
        bundle_root,
        layout,
        canonical_version,
    })
}

fn apply_prepared_downloaded_bundle(
    prepared: PreparedDownloadedBundle,
) -> Result<super::release_bundle::ReleaseBundleCommit> {
    let commit = super::release_bundle::apply_release_bundle(
        &prepared.bundle_root,
        prepared.layout,
        &prepared.canonical_version,
    )
    .context("apply authenticated release bundle")?;
    drop(prepared.stage);
    Ok(commit)
}

#[cfg_attr(not(windows), allow(dead_code))]
enum BundleApplyOutcome {
    Committed(super::release_bundle::ReleaseBundleCommit),
    HandoffScheduled {
        operation_id: String,
        receipt_path: PathBuf,
    },
}

#[cfg_attr(not(windows), allow(dead_code))]
struct HandoffAudit<'a> {
    from_version: &'a str,
    release_tag: &'a str,
    source_repo: &'a str,
    channel: ReleaseChannel,
    download_url: &'a str,
}

struct DownloadedBundleUpdateRequest<'a> {
    asset_bytes: &'a [u8],
    companion_text: &'a str,
    signature_text: Option<&'a str>,
    format: ArchiveFormat,
    install_dir: &'a Path,
    expected_release_version: &'a str,
    target_triple: &'a str,
    asset_name: &'a str,
    audit: HandoffAudit<'a>,
}

fn apply_downloaded_bundle_for_update(
    request: DownloadedBundleUpdateRequest<'_>,
) -> Result<BundleApplyOutcome> {
    let DownloadedBundleUpdateRequest {
        asset_bytes,
        companion_text,
        signature_text,
        format,
        install_dir,
        expected_release_version,
        target_triple,
        asset_name,
        audit,
    } = request;
    let prepared = prepare_downloaded_bundle(
        asset_bytes,
        companion_text,
        format,
        install_dir,
        expected_release_version,
        target_triple,
    )?;

    #[cfg(windows)]
    if running_from_install_root(install_dir)? {
        return schedule_windows_bundle_handoff(
            prepared,
            asset_bytes,
            companion_text,
            signature_text,
            target_triple,
            asset_name,
            audit,
        );
    }

    #[cfg(not(windows))]
    let _ = (signature_text, target_triple, asset_name, audit);

    apply_prepared_downloaded_bundle(prepared).map(BundleApplyOutcome::Committed)
}

#[cfg(windows)]
const WINDOWS_HANDOFF_SCHEMA_VERSION: u32 = 1;
#[cfg(windows)]
const WINDOWS_HANDOFF_REQUEST: &str = "handoff.json";
#[cfg(windows)]
const WINDOWS_HANDOFF_ARCHIVE: &str = "handoff.asset";
#[cfg(windows)]
const WINDOWS_HANDOFF_CHECKSUM: &str = "handoff.sha256";
#[cfg(windows)]
const WINDOWS_HANDOFF_SIGNATURE: &str = "handoff.minisig";
#[cfg(windows)]
const WINDOWS_HANDOFF_RECEIPTS: &str = "update-handoffs";
#[cfg(windows)]
const WINDOWS_HANDOFF_STAGING: &str = "update-handoff-staging";
#[cfg(windows)]
const WINDOWS_HANDOFF_STAGE_PREFIX: &str = ".neoth-self-update-";

#[cfg(windows)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsHandoffRequest {
    schema_version: u32,
    operation_id: String,
    install_root: PathBuf,
    expected_version: String,
    release_tag: String,
    target_triple: String,
    from_version: String,
    source_repo: String,
    channel: ReleaseChannel,
    download_url: String,
    daemon_pid: Option<u32>,
    supervisor_enabled: bool,
}

#[cfg(windows)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsHandoffReceipt {
    schema_version: u32,
    operation_id: String,
    status: String,
    from_version: String,
    to_version: String,
    request_sha256: String,
    stage_root: PathBuf,
    install_root: PathBuf,
    transaction_id: Option<String>,
    members: Option<usize>,
    automatic_crash_recovery: bool,
    error: Option<String>,
}

#[cfg(windows)]
pub(crate) struct CompletedWindowsHandoff {
    pub applied: UpdateApplied,
    pub operation_id: String,
    pub install_root: PathBuf,
    pub request_sha256: String,
    pub source_repo: String,
    pub channel: ReleaseChannel,
    pub target_triple: String,
}

#[cfg(windows)]
fn running_from_install_root(install_root: &Path) -> Result<bool> {
    let current = std::env::current_exe()
        .context("locate running self-update executable")?
        .canonicalize()
        .context("canonicalize running self-update executable")?;
    let installed = install_root
        .join(binary_filename_for_host("neoth"))
        .canonicalize()
        .context("canonicalize installed neoth executable")?;
    Ok(current == installed)
}

#[cfg(windows)]
fn validate_handoff_operation_id(operation_id: &str) -> Result<()> {
    if operation_id.len() != 32
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("Windows update handoff id must be 32 lowercase hex characters");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_handoff_request_sha256(request_sha256: &str) -> Result<()> {
    if request_sha256.len() != 64
        || !request_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("Windows update request SHA-256 must be 64 lowercase hex characters");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_handoff_request_binding(bytes: &[u8], expected_sha256: &str) -> Result<()> {
    validate_handoff_request_sha256(expected_sha256)?;
    if hex_encode(&Sha256::digest(bytes)) != expected_sha256 {
        anyhow::bail!("Windows handoff request SHA-256 binding does not match");
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_private_windows_handoff_directory(path: &Path, label: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create {label} directory {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} directory {}", path.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        anyhow::bail!(
            "{label} directory is not a real directory: {}",
            path.display()
        );
    }
    crate::wal::win_native::set_private_current_user_directory_dacl(path)
        .with_context(|| format!("protect {label} directory {}", path.display()))?;
    crate::wal::win_native::verify_private_directory_dacl(path)
        .with_context(|| format!("verify {label} directory {}", path.display()))?;
    std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize {label} directory {}", path.display()))
}

#[cfg(all(windows, test))]
fn windows_handoff_state_home() -> PathBuf {
    std::env::temp_dir().join(format!("neoth-test-update-handoffs-{}", std::process::id()))
}

#[cfg(all(windows, not(test)))]
fn windows_handoff_state_home() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home()
}

#[cfg(windows)]
fn windows_handoff_staging_namespace() -> Result<PathBuf> {
    ensure_private_windows_handoff_directory(
        &windows_handoff_state_home().join(WINDOWS_HANDOFF_STAGING),
        "Windows update staging",
    )
}

#[cfg(windows)]
fn handoff_receipt_path(operation_id: &str) -> Result<PathBuf> {
    validate_handoff_operation_id(operation_id)?;
    let directory = ensure_private_windows_handoff_directory(
        &windows_handoff_state_home().join(WINDOWS_HANDOFF_RECEIPTS),
        "Windows update receipt",
    )?;
    Ok(directory.join(format!("{operation_id}.json")))
}

#[cfg(windows)]
fn write_new_synced(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    use std::io::Write as _;

    let mut file = crate::wal::win_native::create_private_file_new(path)
        .with_context(|| format!("create Windows handoff {label} {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write Windows handoff {label}"))?;
    file.sync_all()
        .with_context(|| format!("flush Windows handoff {label}"))?;
    Ok(())
}

#[cfg(windows)]
fn schedule_windows_bundle_handoff(
    prepared: PreparedDownloadedBundle,
    asset_bytes: &[u8],
    companion_text: &str,
    signature_text: Option<&str>,
    target_triple: &str,
    asset_name: &str,
    audit: HandoffAudit<'_>,
) -> Result<BundleApplyOutcome> {
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    if asset_name != expected_asset_name("neoth", audit.release_tag, target_triple) {
        anyhow::bail!("Windows handoff asset name does not match the exact release target");
    }
    let signature_text = signature_text
        .ok_or_else(|| anyhow::anyhow!("Windows handoff requires a release signature"))?;
    let signature_status = crate::updater::sig_verify::check_signature_for_file(
        asset_bytes,
        Some(signature_text),
        true,
        Some(asset_name),
    )
    .context("Windows handoff requires a verified release signature")?;
    if signature_status != crate::updater::sig_verify::SigStatus::Verified {
        anyhow::bail!("Windows handoff requires a verified release signature");
    }

    let operation_id = uuid::Uuid::new_v4().simple().to_string();
    let receipt_path = handoff_receipt_path(&operation_id)?;
    if receipt_path.exists() {
        anyhow::bail!(
            "Windows update receipt slot already exists: {}",
            receipt_path.display()
        );
    }
    let install_root = match &prepared.layout {
        super::release_bundle::ReleaseInstallLayout::Portable(root) => root.clone(),
        _ => anyhow::bail!("Windows PID handoff is only valid for portable installations"),
    };
    let config = crate::config::FreedomConfig::load_from_default_path_or_default()
        .context("load supervisor policy for Windows update handoff")?;
    let daemon_pid =
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile())
            .context("inspect running daemon before Windows update handoff")?;
    let request = WindowsHandoffRequest {
        schema_version: WINDOWS_HANDOFF_SCHEMA_VERSION,
        operation_id: operation_id.clone(),
        install_root,
        expected_version: prepared.canonical_version.clone(),
        release_tag: audit.release_tag.to_string(),
        target_triple: target_triple.to_string(),
        from_version: audit.from_version.to_string(),
        source_repo: audit.source_repo.to_string(),
        channel: audit.channel,
        download_url: audit.download_url.to_string(),
        daemon_pid,
        supervisor_enabled: config.supervisor.enabled,
    };

    let stage_root = prepared
        .bundle_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows handoff bundle has no staging parent"))?;
    let request_path = stage_root.join(WINDOWS_HANDOFF_REQUEST);
    let archive_path = stage_root.join(WINDOWS_HANDOFF_ARCHIVE);
    let checksum_path = stage_root.join(WINDOWS_HANDOFF_CHECKSUM);
    let signature_path = stage_root.join(WINDOWS_HANDOFF_SIGNATURE);
    let mut request_bytes = serde_json::to_vec_pretty(&request)?;
    request_bytes.push(b'\n');
    let request_sha256 = hex_encode(&Sha256::digest(&request_bytes));
    write_new_synced(&request_path, &request_bytes, "request")?;
    write_new_synced(&archive_path, asset_bytes, "archive")?;
    write_new_synced(&checksum_path, companion_text.as_bytes(), "checksum")?;
    write_new_synced(&signature_path, signature_text.as_bytes(), "signature")?;

    let helper = prepared.bundle_root.join(binary_filename_for_host("neoth"));
    let mut child = Command::new(&helper)
        .arg("--output")
        .arg("json")
        .arg("internal")
        .arg("bundle-transaction")
        .arg("handoff")
        .arg("--bundle-root")
        .arg(&prepared.bundle_root)
        .arg("--request")
        .arg(&request_path)
        .arg("--request-sha256")
        .arg(&request_sha256)
        .arg("--wait-pid")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("start target release helper {}", helper.display()))?;

    if daemon_pid.is_some()
        && let Err(error) = crate::daemon::supervisor::request_restart(
            &crate::config::FreedomConfig::default_neoth_home(),
        )
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("request graceful daemon stop for Windows update handoff");
    }

    let _persistent_stage = prepared.stage.keep();
    Ok(BundleApplyOutcome::HandoffScheduled {
        operation_id,
        receipt_path,
    })
}

#[cfg(windows)]
fn read_windows_handoff_request(
    bundle_root: &Path,
    request_path: &Path,
    expected_sha256: Option<&str>,
) -> Result<(WindowsHandoffRequest, PathBuf)> {
    let bundle_root = std::fs::canonicalize(bundle_root).with_context(|| {
        format!(
            "canonicalize Windows handoff bundle {}",
            bundle_root.display()
        )
    })?;
    let stage_root = bundle_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows handoff bundle has no staging parent"))?
        .to_path_buf();
    let namespace_root = stage_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows handoff stage has no trusted namespace"))?;
    let bytes = read_exact_private_windows_file_bounded(
        namespace_root,
        request_path,
        &stage_root.join(WINDOWS_HANDOFF_REQUEST),
        MAX_PENDING_JSON_BYTES,
        "Windows handoff request",
    )?;
    if let Some(expected_sha256) = expected_sha256 {
        validate_windows_handoff_request_binding(&bytes, expected_sha256)?;
    }
    let request: WindowsHandoffRequest =
        serde_json::from_slice(&bytes).context("parse Windows handoff request")?;
    validate_handoff_operation_id(&request.operation_id)?;
    if request.schema_version != WINDOWS_HANDOFF_SCHEMA_VERSION
        || request.expected_version != env!("CARGO_PKG_VERSION")
        || parse_semver_version(&request.expected_version)?.to_string() != request.expected_version
        || parse_semver_version(&request.release_tag)?.to_string() != request.expected_version
        || parse_semver_version(&request.from_version).is_err()
        || !owner_repo_is_valid(&request.source_repo)
        || host_target_triple() != Some(request.target_triple.as_str())
    {
        anyhow::bail!("Windows handoff request identity is invalid for this release helper");
    }
    let expected_asset = expected_asset_name("neoth", &request.release_tag, &request.target_triple);
    if !request
        .download_url
        .ends_with(&format!("/{expected_asset}"))
    {
        anyhow::bail!("Windows handoff download URL is not bound to the expected asset");
    }
    Ok((request, stage_root))
}

#[cfg(windows)]
fn wait_for_windows_process(pid: u32, timeout_ms: u32, label: &str) -> Result<()> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    if pid == 0 || pid == std::process::id() {
        anyhow::bail!("invalid {label} pid {pid} for Windows update handoff");
    }
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(());
        }
        anyhow::bail!("open {label} pid {pid} for update handoff: Win32 {error}");
    }
    let wait = unsafe { WaitForSingleObject(handle, timeout_ms) };
    let close_ok = unsafe { CloseHandle(handle) };
    if close_ok == 0 {
        anyhow::bail!("close {label} process handle after update wait");
    }
    match wait {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => {
            anyhow::bail!("timed out waiting for {label} pid {pid} to exit before Windows update")
        }
        WAIT_FAILED => anyhow::bail!("wait for {label} pid {pid} failed"),
        other => anyhow::bail!("unexpected Windows wait result {other} for {label} pid {pid}"),
    }
}

#[cfg(windows)]
fn stop_windows_supervisor_task() {
    let outcome = std::process::Command::new("schtasks.exe")
        .args(["/end", "/tn", crate::daemon::supervisor::WINDOWS_TASK_NAME])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if let Err(error) = outcome {
        warn!(%error, "could not ask Task Scheduler to stop the NEOTH supervisor before update");
    }
}

#[cfg(windows)]
fn restore_windows_runtime(request: &WindowsHandoffRequest) -> Result<()> {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    if request.supervisor_enabled {
        let output = std::process::Command::new("schtasks.exe")
            .args(["/run", "/tn", crate::daemon::supervisor::WINDOWS_TASK_NAME])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .context("restart NEOTH Task Scheduler supervisor after update")?;
        if !output.status.success() {
            anyhow::bail!(
                "restart NEOTH Task Scheduler supervisor failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    } else if request.daemon_pid.is_some() {
        std::process::Command::new(request.install_root.join(binary_filename_for_host("neoth")))
            .arg("serve")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .context("restart unsupervised NEOTH daemon after Windows update")?;
    }
    Ok(())
}

#[cfg(windows)]
fn write_windows_handoff_receipt(
    request: &WindowsHandoffRequest,
    request_sha256: &str,
    stage_root: &Path,
    transaction_id: Option<&str>,
    members: Option<usize>,
    error: Option<&str>,
) -> Result<()> {
    validate_handoff_request_sha256(request_sha256)?;
    let canonical_stage = std::fs::canonicalize(stage_root).with_context(|| {
        format!(
            "canonicalize Windows handoff stage for receipt {}",
            stage_root.display()
        )
    })?;
    let canonical_install = std::fs::canonicalize(&request.install_root).with_context(|| {
        format!(
            "canonicalize Windows handoff install root for receipt {}",
            request.install_root.display()
        )
    })?;
    let receipt = WindowsHandoffReceipt {
        schema_version: WINDOWS_HANDOFF_SCHEMA_VERSION,
        operation_id: request.operation_id.clone(),
        status: if error.is_some() {
            "failed".to_string()
        } else {
            "committed".to_string()
        },
        from_version: request.from_version.clone(),
        to_version: request.expected_version.clone(),
        request_sha256: request_sha256.to_string(),
        stage_root: canonical_stage,
        install_root: canonical_install,
        transaction_id: transaction_id.map(str::to_string),
        members,
        automatic_crash_recovery: true,
        error: error.map(str::to_string),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)?;
    bytes.push(b'\n');
    let path = handoff_receipt_path(&request.operation_id)?;
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("write Windows update receipt {}", path.display()))
}

#[cfg(windows)]
fn run_windows_bundle_handoff_inner(
    request: &WindowsHandoffRequest,
    stage_root: &Path,
    wait_pid: u32,
) -> Result<(super::release_bundle::ReleaseBundleCommit, String)> {
    wait_for_windows_process(wait_pid, 300_000, "parent updater")?;
    if let Some(daemon_pid) = request.daemon_pid {
        wait_for_windows_process(daemon_pid, 120_000, "NEOTH daemon")?;
    }
    if request.supervisor_enabled {
        // The Windows supervisor loop would otherwise relaunch the old image
        // three seconds after the daemon drains and re-lock neoth.exe.
        stop_windows_supervisor_task();
    }

    let archive_path = stage_root.join(WINDOWS_HANDOFF_ARCHIVE);
    let checksum_path = stage_root.join(WINDOWS_HANDOFF_CHECKSUM);
    let signature_path = stage_root.join(WINDOWS_HANDOFF_SIGNATURE);
    let namespace_root = stage_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows handoff stage has no trusted namespace"))?;
    let asset_bytes = read_private_windows_file_bounded(
        namespace_root,
        &archive_path,
        MAX_RELEASE_ARCHIVE_BYTES,
        "Windows handoff archive",
    )?;
    let companion_text = String::from_utf8(read_private_windows_file_bounded(
        namespace_root,
        &checksum_path,
        MAX_CHECKSUM_BYTES,
        "Windows handoff checksum",
    )?)
    .context("Windows handoff checksum is not UTF-8")?;
    let signature_text = String::from_utf8(read_private_windows_file_bounded(
        namespace_root,
        &signature_path,
        MAX_SIGNATURE_BYTES,
        "Windows handoff signature",
    )?)
    .context("Windows handoff signature is not UTF-8")?;
    let archive_sha256 = parse_sha256_companion(&companion_text)
        .context("parse Windows handoff checksum before commit")?;
    verify_sha256_bytes(&asset_bytes, &archive_sha256)
        .context("re-verify Windows handoff checksum after parent exit")?;
    let asset_name = expected_asset_name("neoth", &request.release_tag, &request.target_triple);
    let signature_status = crate::updater::sig_verify::check_signature_for_file(
        &asset_bytes,
        Some(&signature_text),
        true,
        Some(&asset_name),
    )
    .context("re-verify Windows handoff release signature after parent exit")?;
    if signature_status != crate::updater::sig_verify::SigStatus::Verified {
        anyhow::bail!("Windows handoff release signature is not verified");
    }
    let commit = apply_downloaded_bundle(
        &asset_bytes,
        &companion_text,
        archive_format_for_target(&request.target_triple),
        &request.install_root,
        &request.expected_version,
        &request.target_triple,
    )?;
    Ok((commit, archive_sha256))
}

#[cfg(windows)]
pub(crate) fn run_windows_bundle_handoff(
    bundle_root: &Path,
    request_path: &Path,
    request_sha256: &str,
    wait_pid: u32,
) -> Result<CompletedWindowsHandoff> {
    require_non_elevated_windows_portable_update("run release handoff")?;
    super::release_bundle::require_running_bundle_helper(bundle_root)?;
    let (request, stage_root) =
        read_windows_handoff_request(bundle_root, request_path, Some(request_sha256))?;
    let apply_result = run_windows_bundle_handoff_inner(&request, &stage_root, wait_pid);
    let restore_result = restore_windows_runtime(&request);

    match apply_result {
        Ok((commit, archive_sha256)) => {
            let restore_warning = restore_result.err().map(|error| format!("{error:#}"));
            if let Some(error) = &restore_warning {
                warn!(%error, "Windows update committed but the previous runtime could not be restarted");
            }
            write_windows_handoff_receipt(
                &request,
                request_sha256,
                &stage_root,
                Some(&commit.receipt.transaction_id),
                Some(commit.receipt.members),
                None,
            )?;
            Ok(CompletedWindowsHandoff {
                applied: UpdateApplied {
                    from_version: request.from_version.clone(),
                    to_version: request.expected_version.clone(),
                    transaction_id: commit.receipt.transaction_id,
                    automatic_crash_recovery: true,
                    restart_required: true,
                    // Bound to the exact bytes verified before the commit.
                    // Never re-read mutable staging state after installation.
                    archive_sha256,
                    download_url: request.download_url.clone(),
                    signature_status: "verified".to_string(),
                },
                operation_id: request.operation_id.clone(),
                install_root: request.install_root.clone(),
                request_sha256: request_sha256.to_string(),
                source_repo: request.source_repo.clone(),
                channel: request.channel,
                target_triple: request.target_triple.clone(),
            })
        }
        Err(error) => {
            let message = match restore_result {
                Ok(()) => format!("{error:#}"),
                Err(restore_error) => {
                    format!("{error:#}; restoring the prior runtime also failed: {restore_error:#}")
                }
            };
            if let Err(receipt_error) = write_windows_handoff_receipt(
                &request,
                request_sha256,
                &stage_root,
                None,
                None,
                Some(&message),
            ) {
                return Err(error.context(format!(
                    "Windows update failed and its failure receipt could not be written: {receipt_error:#}"
                )));
            }
            Err(error.context("detached Windows release transaction failed"))
        }
    }
}

#[cfg(windows)]
pub(crate) fn spawn_windows_handoff_cleanup(completed: &CompletedWindowsHandoff) -> Result<()> {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    std::process::Command::new(
        completed
            .install_root
            .join(binary_filename_for_host("neoth")),
    )
    .arg("--output")
    .arg("json")
    .arg("internal")
    .arg("bundle-transaction")
    .arg("cleanup-handoff")
    .arg("--operation-id")
    .arg(&completed.operation_id)
    .arg("--request-sha256")
    .arg(&completed.request_sha256)
    .arg("--wait-pid")
    .arg(std::process::id().to_string())
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
    .spawn()
    .context("start installed cleanup helper for Windows update handoff")?;
    Ok(())
}

#[cfg(windows)]
fn validate_committed_windows_handoff_receipt(
    receipt: &WindowsHandoffReceipt,
    operation_id: &str,
    request_sha256: &str,
) -> Result<()> {
    if receipt.schema_version != WINDOWS_HANDOFF_SCHEMA_VERSION
        || receipt.operation_id != operation_id
        || receipt.request_sha256 != request_sha256
        || receipt.status != "committed"
        || receipt.to_version != env!("CARGO_PKG_VERSION")
        || parse_semver_version(&receipt.from_version).is_err()
        || receipt.transaction_id.as_deref().is_none_or(str::is_empty)
        || receipt.members.is_none_or(|members| members == 0)
        || !receipt.automatic_crash_recovery
        || receipt.error.is_some()
    {
        anyhow::bail!("Windows handoff receipt is not an exact committed cleanup authority");
    }
    Ok(())
}

#[cfg(windows)]
fn read_committed_windows_handoff_receipt(
    operation_id: &str,
    request_sha256: &str,
) -> Result<WindowsHandoffReceipt> {
    validate_handoff_operation_id(operation_id)?;
    validate_handoff_request_sha256(request_sha256)?;
    let path = handoff_receipt_path(operation_id)?;
    let trusted_root = windows_handoff_state_home();
    let bytes = read_private_windows_file_bounded(
        &trusted_root,
        &path,
        MAX_PENDING_JSON_BYTES,
        "Windows handoff receipt",
    )?;
    let receipt: WindowsHandoffReceipt =
        serde_json::from_slice(&bytes).context("parse Windows handoff receipt")?;
    validate_committed_windows_handoff_receipt(&receipt, operation_id, request_sha256)?;
    Ok(receipt)
}

#[cfg(windows)]
fn validate_windows_cleanup_namespace(
    receipt: &WindowsHandoffReceipt,
    namespace: &Path,
) -> Result<()> {
    if receipt.stage_root.parent() != Some(namespace)
        || !receipt
            .stage_root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(WINDOWS_HANDOFF_STAGE_PREFIX))
    {
        anyhow::bail!("Windows handoff receipt stage is outside the private staging namespace");
    }
    if !receipt.stage_root.is_absolute() || !receipt.install_root.is_absolute() {
        anyhow::bail!("Windows handoff receipt paths are not canonical absolute paths");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_cleanup_tree(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspect Windows handoff cleanup tree {}", root.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        anyhow::bail!(
            "Windows handoff cleanup root is not a real directory: {}",
            root.display()
        );
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("read Windows handoff tree {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "Windows handoff cleanup tree contains a reparse point: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() {
                anyhow::bail!(
                    "Windows handoff cleanup tree contains a special file: {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn remove_windows_cleanup_tree(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspect Windows cleanup artifact {}", root.display()))?;
    if metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "refusing to remove Windows reparse point {}",
            root.display()
        );
    }
    if metadata.is_file() {
        std::fs::remove_file(root)
            .with_context(|| format!("remove Windows cleanup file {}", root.display()))?;
        return Ok(());
    }
    if !metadata.is_dir() {
        anyhow::bail!("refusing to remove Windows special file {}", root.display());
    }
    let mut entries = std::fs::read_dir(root)
        .with_context(|| format!("read Windows cleanup directory {}", root.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        remove_windows_cleanup_tree(&entry.path())?;
    }
    std::fs::remove_dir(root)
        .with_context(|| format!("remove Windows cleanup directory {}", root.display()))
}

#[cfg(windows)]
fn windows_process_is_elevated() -> Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this guard owns one successful OpenProcessToken
                // handle and closes it exactly once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    let mut raw_token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns the caller pseudo-handle and
    // `raw_token` is a valid out-pointer for one TOKEN_QUERY handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("open current process token for Windows handoff cleanup");
    }
    let token = TokenHandle(raw_token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: `elevation` is writable for the declared TOKEN_ELEVATION size,
    // and `returned` is a valid out-pointer for the byte count.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("inspect current process elevation for Windows handoff cleanup");
    }
    if returned < std::mem::size_of::<TOKEN_ELEVATION>() as u32 {
        anyhow::bail!("Windows returned an undersized token elevation record");
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
fn require_non_elevated_windows_portable_update(operation: &str) -> Result<()> {
    #[cfg(test)]
    let elevated = false;
    #[cfg(not(test))]
    let elevated = windows_process_is_elevated()?;

    validate_windows_portable_update_elevation(elevated, operation)
}

#[cfg(windows)]
fn validate_windows_portable_update_elevation(elevated: bool, operation: &str) -> Result<()> {
    if elevated {
        anyhow::bail!(
            "Windows portable self-update refuses to {operation} with an elevated process token; use the signed native installer for machine-wide updates"
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn cleanup_windows_handoff(
    operation_id: &str,
    request_sha256: &str,
    wait_pid: u32,
) -> Result<()> {
    // Portable staging, helper launch, and cleanup intentionally have no more
    // authority than the user who owns the private staging namespace. This
    // makes a same-user replacement race unable to become an elevated deputy.
    require_non_elevated_windows_portable_update("clean release handoff staging")?;
    let receipt = read_committed_windows_handoff_receipt(operation_id, request_sha256)?;
    let namespace = windows_handoff_staging_namespace()?;
    validate_windows_cleanup_namespace(&receipt, &namespace)?;
    let cleanup_root = namespace.join(format!(".cleanup-{operation_id}"));
    let stage_exists = receipt.stage_root.try_exists()?;
    let cleanup_exists = cleanup_root.try_exists()?;
    if stage_exists && cleanup_exists {
        anyhow::bail!("Windows handoff has both live and cleanup staging roots");
    }
    if !stage_exists && !cleanup_exists {
        return Ok(());
    }
    let active_root = if stage_exists {
        let canonical = std::fs::canonicalize(&receipt.stage_root)?;
        if canonical != receipt.stage_root {
            anyhow::bail!("Windows handoff stage identity changed after commit");
        }
        receipt.stage_root.clone()
    } else {
        let canonical = std::fs::canonicalize(&cleanup_root)?;
        if canonical != cleanup_root {
            anyhow::bail!("Windows handoff cleanup identity is not canonical");
        }
        cleanup_root.clone()
    };
    validate_windows_cleanup_tree(&active_root)?;
    crate::wal::win_native::verify_private_directory_dacl(&active_root).with_context(|| {
        format!(
            "verify private Windows handoff cleanup root {}",
            active_root.display()
        )
    })?;

    let is_staged = active_root == receipt.stage_root;
    if is_staged {
        let request_path = active_root.join(WINDOWS_HANDOFF_REQUEST);
        let (request, canonical_active_root) = read_windows_handoff_request(
            &active_root.join(expected_archive_root(
                env!("CARGO_PKG_VERSION"),
                host_target_triple().ok_or_else(|| anyhow::anyhow!("unsupported cleanup host"))?,
            )?),
            &request_path,
            Some(request_sha256),
        )?;
        let canonical_install = std::fs::canonicalize(&request.install_root)?;
        if canonical_active_root != active_root
            || request.operation_id != operation_id
            || canonical_install != receipt.install_root
        {
            anyhow::bail!("Windows handoff cleanup identity does not match its committed receipt");
        }
    }
    let current = std::env::current_exe()
        .context("locate installed Windows cleanup helper")?
        .canonicalize()
        .context("canonicalize installed Windows cleanup helper")?;
    let expected = receipt
        .install_root
        .join(binary_filename_for_host("neoth"))
        .canonicalize()
        .context("canonicalize installed neoth for handoff cleanup")?;
    if current != expected {
        anyhow::bail!("Windows handoff cleanup must run the installed neoth executable");
    }
    wait_for_windows_process(wait_pid, 300_000, "release helper")?;

    if is_staged {
        let (_, revalidated_root) = read_windows_handoff_request(
            &active_root.join(expected_archive_root(
                env!("CARGO_PKG_VERSION"),
                host_target_triple().ok_or_else(|| anyhow::anyhow!("unsupported cleanup host"))?,
            )?),
            &active_root.join(WINDOWS_HANDOFF_REQUEST),
            Some(request_sha256),
        )?;
        if revalidated_root != active_root {
            anyhow::bail!("Windows handoff cleanup root changed while waiting for the helper");
        }
    }
    validate_windows_cleanup_tree(&active_root)?;
    let quarantined = if is_staged {
        if cleanup_root.try_exists()? {
            anyhow::bail!("Windows handoff cleanup quarantine already exists");
        }
        std::fs::rename(&active_root, &cleanup_root).with_context(|| {
            format!(
                "quarantine completed Windows handoff {}",
                active_root.display()
            )
        })?;
        cleanup_root
    } else {
        active_root
    };
    validate_windows_cleanup_tree(&quarantined)?;
    remove_windows_cleanup_tree(&quarantined)
}

async fn fetch_bytes_bounded(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("fetch {label}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte download cap");
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read {label} response body"))?
    {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("{label} response length overflow"))?;
        if next_len > max_bytes {
            anyhow::bail!("{label} exceeds the {max_bytes}-byte download cap");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn fetch_text_bounded(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    let bytes = fetch_bytes_bounded(client, url, max_bytes, label).await?;
    String::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8"))
}

/// Network-driven update flow. Wraps the shared bundle transaction with
/// HTTP fetches against the release's `browser_download_url`
/// fields. Returns [`UpdateApplyOutcome::Applied`] after a synchronous commit,
/// or [`UpdateApplyOutcome::HandoffScheduled`] when a running Windows portable
/// executable must finish through the detached target helper. Errors leave the
/// daemon's existing binary untouched (the
/// extraction tempdir cleans up; installed state mutates only after every
/// archive and layout preflight succeeds).
pub async fn apply_update(
    release: &LatestRelease,
    source_repo: &str,
    channel: ReleaseChannel,
    target_triple: &str,
    binary: &str,
    install_dir: &Path,
    require_signature: bool,
) -> Result<UpdateApplyOutcome> {
    validate_owner_repo(source_repo)?;
    if binary != "neoth" {
        anyhow::bail!(
            "release-bundle self-update supports only the public `neoth` entrypoint, not {binary:?}"
        );
    }
    let assets = resolve_update_assets(release, target_triple, binary)?;
    let companion = assets.sha256.ok_or_else(|| {
        anyhow::anyhow!(
            "release {} published the binary asset but no \
             `.sha256` companion — refusing to apply (no integrity \
             guarantee). Install manually from {}",
            release.tag_name,
            release.html_url
        )
    })?;

    let ua = format!("NEOTH/{} (self-update)", current_version());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .build()
        .context("build self-update reqwest client")?;

    let companion_text = fetch_text_bounded(
        &client,
        &companion.browser_download_url,
        MAX_CHECKSUM_BYTES,
        "sha256 companion",
    )
    .await?;

    let asset_bytes = fetch_bytes_bounded(
        &client,
        &assets.binary.browser_download_url,
        MAX_RELEASE_ARCHIVE_BYTES,
        "binary release archive",
    )
    .await?;

    // MV-01b #2 — minisign signature verification BEFORE the swap. Fetch
    // the `.minisig` companion (if published) then gate on it. `require`
    // is the two-tier rule: the unattended daemon path passes `true`
    // (any non-verified outcome bails); the manual operator path passes
    // `false` (missing sig / unprovisioned key warns + proceeds, but a
    // present-but-invalid sig still bails). Runs before bundle application so
    // a failed verify never reaches the native transaction.
    let signature_text = match assets.signature {
        Some(sig_asset) => Some(
            fetch_text_bounded(
                &client,
                &sig_asset.browser_download_url,
                MAX_SIGNATURE_BYTES,
                "minisig companion",
            )
            .await?,
        ),
        None => None,
    };
    let sig_status = crate::updater::sig_verify::check_signature_for_file(
        &asset_bytes,
        signature_text.as_deref(),
        require_signature,
        Some(&assets.binary.name),
    )
    .context("self-update signature gate")?;
    match sig_status {
        crate::updater::sig_verify::SigStatus::Verified => {
            info!("self-update: release signature verified");
        }
        other => {
            warn!(
                status = other.as_str(),
                "self-update: proceeding without a verified signature (manual path); \
                 unattended updates would refuse this release"
            );
        }
    }

    let format = archive_format_for_target(target_triple);
    let download_url = assets.binary.browser_download_url.clone();
    let bundle_outcome = apply_downloaded_bundle_for_update(DownloadedBundleUpdateRequest {
        asset_bytes: &asset_bytes,
        companion_text: &companion_text,
        signature_text: signature_text.as_deref(),
        format,
        install_dir,
        expected_release_version: &release.tag_name,
        target_triple,
        asset_name: &assets.binary.name,
        audit: HandoffAudit {
            from_version: current_version(),
            release_tag: &release.tag_name,
            source_repo,
            channel,
            download_url: &download_url,
        },
    })?;
    // apply_downloaded_bundle already parsed + verified the companion, so this
    // re-parse cannot fail at this point; default to empty rather than
    // unwrap to keep a successful apply from ever panicking on audit.
    let archive_sha256 = parse_sha256_companion(&companion_text).unwrap_or_default();

    match bundle_outcome {
        BundleApplyOutcome::Committed(commit) => Ok(UpdateApplyOutcome::Applied(UpdateApplied {
            from_version: current_version().to_string(),
            to_version: release.tag_name.clone(),
            transaction_id: commit.receipt.transaction_id,
            automatic_crash_recovery: true,
            restart_required: true,
            archive_sha256,
            download_url,
            signature_status: sig_status.as_str().to_string(),
        })),
        BundleApplyOutcome::HandoffScheduled {
            operation_id,
            receipt_path,
        } => Ok(UpdateApplyOutcome::HandoffScheduled(
            UpdateHandoffScheduled {
                from_version: current_version().to_string(),
                to_version: parse_semver_version(&release.tag_name)?.to_string(),
                operation_id,
                receipt_path,
                restart_required: true,
            },
        )),
    }
}

/// MV-01b prereq #5 — the staged-pending record written next to the
/// staged archive (`<stage_dir>/pending.json`). The unattended daemon
/// task downloads + verifies + writes this; the manual `neoth update
/// --self --apply` reads it to skip the re-download when the staged
/// archive's SHA-256 still matches.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PendingUpdate {
    pub to_version: String,
    /// GitHub `owner/repo` feed that supplied the artifact. Empty only when
    /// reading a legacy record, which callers must treat as a policy mismatch.
    #[serde(default)]
    pub source_repo: String,
    /// Release ring that selected this artifact. Defaults to stable when
    /// reading pending records written before channel wiring landed.
    #[serde(default)]
    pub channel: ReleaseChannel,
    pub archive_sha256: String,
    pub download_url: String,
    pub signature_status: String,
    /// Absolute path of the staged archive on disk.
    pub staged_archive: String,
    /// GR-043 — absolute path of the staged `.minisig` signature companion on
    /// disk (when one was published + staged). `apply_from_staged` RE-VERIFIES
    /// the minisign signature against the pinned key from THIS file at apply
    /// time, so a staged archive swapped on disk (or planted by an attacker with
    /// write access to the stage dir + a forged `signature_status:"verified"`)
    /// can't bypass the SEC-10 signature gate. `None` when no companion exists.
    #[serde(default)]
    pub staged_signature: Option<String>,
    pub target_triple: String,
    pub staged_ts_unix: i64,
}

/// A staged artifact may be reused only under the currently selected release
/// feed, target, and channel. Legacy records have no `source_repo` and fail
/// this check, forcing a fresh authenticated download.
pub fn pending_matches_policy(
    pending: &PendingUpdate,
    owner_repo: &str,
    channel: ReleaseChannel,
    target_triple: &str,
) -> bool {
    pending.source_repo == owner_repo
        && pending.target_triple == target_triple
        && release_tag_matches_channel(&pending.to_version, channel)
}

/// `<stage_dir>/pending.json`.
pub fn pending_json_path(stage_dir: &Path) -> PathBuf {
    stage_dir.join("pending.json")
}

/// Read a staged-pending record, if one exists + parses. `None` when no
/// update is staged (the common case).
pub fn read_pending(stage_dir: &Path) -> Option<PendingUpdate> {
    let trusted_root = stage_dir.parent()?;
    let body = read_file_bounded(
        trusted_root,
        &pending_json_path(stage_dir),
        MAX_PENDING_JSON_BYTES,
        "pending update record",
    )
    .ok()?;
    serde_json::from_slice(&body).ok()
}

// TRUST BOUNDARY (review finding): this initial root open resolves an
// ABSOLUTE path, so ancestor components of the canonicalized trusted root
// are followed by the kernel without per-component no-follow enforcement.
// Ancestors of NEOTH_HOME / the staging root (e.g. C:\Users) are treated
// as part of the system trust domain — replacing them requires privileges
// beyond the attacker model here. Every component BELOW the root IS opened
// relative to the preceding directory handle with no-follow semantics.
// FILE_FLAG_OPEN_REPARSE_POINT ensures the handle points at the reparse
// point itself; File::metadata() (GetFileInformationByHandle) then reports
// FILE_ATTRIBUTE_REPARSE_POINT, which metadata_is_link_like checks. Do not
// replace metadata() with GetFileAttributesExW — that follows the link.
fn open_directory_nofollow(path: &Path, label: &str) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let directory = options.open(path).with_context(|| {
        format!(
            "open {label} parent directory without following links {}",
            path.display()
        )
    })?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspect opened {label} parent directory {}", path.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        anyhow::bail!(
            "opened {label} parent is not a real non-link directory: {}",
            path.display()
        );
    }
    Ok(directory)
}

#[cfg(windows)]
#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[cfg(windows)]
#[repr(C)]
struct NtObjectAttributes {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *const NtUnicodeString,
    attributes: u32,
    security_descriptor: *const std::ffi::c_void,
    security_quality_of_service: *const std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
union NtIoStatusValue {
    status: i32,
    pointer: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct NtIoStatusBlock {
    value: NtIoStatusValue,
    information: usize,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        object_attributes: *const NtObjectAttributes,
        io_status_block: *mut NtIoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
}

fn open_relative_nofollow(
    parent: &std::fs::File,
    component: &std::ffi::OsStr,
    path: &Path,
    label: &str,
    directory: bool,
) -> Result<std::fs::File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};

        let component = std::ffi::CString::new(component.as_bytes())
            .with_context(|| format!("{label} path component contains NUL"))?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory {
                libc::O_DIRECTORY
            } else {
                // FIFOs and device-like leaves must not block before the
                // descriptor-bound regular-file check below can reject them.
                libc::O_NONBLOCK
            };
        // SAFETY: parent owns a live directory descriptor and component is
        // one NUL-terminated relative path component. No slash or parent
        // traversal reaches openat.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "open {label} path component without following links {}",
                    path.display()
                )
            });
        }
        // SAFETY: successful openat returned a new owned descriptor.
        unsafe { std::fs::File::from_raw_fd(fd) }
    };

    #[cfg(windows)]
    let file = {
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};

        const OBJ_CASE_INSENSITIVE: u32 = 0x40;
        const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const FILE_GENERIC_READ: u32 = 0x0012_0089;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_SHARE_ALL: u32 = 0x0000_0007;
        const FILE_OPEN: u32 = 0x0000_0001;
        const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
        const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
        const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
        const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        let wide = component.encode_wide().collect::<Vec<_>>();
        let byte_length = wide
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| anyhow::anyhow!("{label} path component is too long"))?;
        let name = NtUnicodeString {
            length: byte_length,
            maximum_length: byte_length,
            buffer: wide.as_ptr().cast_mut(),
        };
        let attributes = NtObjectAttributes {
            length: {
                const _: () = assert!(
                    std::mem::size_of::<NtObjectAttributes>() <= u32::MAX as usize,
                    "NtObjectAttributes must fit the NT ULONG length field"
                );
                std::mem::size_of::<NtObjectAttributes>() as u32
            },
            root_directory: parent.as_raw_handle(),
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: std::ptr::null(),
            security_quality_of_service: std::ptr::null(),
        };
        let mut io_status = NtIoStatusBlock {
            value: NtIoStatusValue {
                pointer: std::ptr::null_mut(),
            },
            information: 0,
        };
        let mut handle = std::ptr::null_mut();
        let desired_access = if directory {
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        } else {
            FILE_GENERIC_READ
        };
        let create_options = FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_REPARSE_POINT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        // SAFETY: the FFI structures have the documented NT layout, their
        // backing buffers remain live for the call, and parent is live.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &attributes,
                &mut io_status,
                std::ptr::null(),
                0,
                FILE_SHARE_ALL,
                FILE_OPEN,
                create_options,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 || handle.is_null() {
            anyhow::bail!(
                "open {label} path component without following reparse points {}: NTSTATUS {status:#010x}",
                path.display()
            );
        }
        // SAFETY: successful NtCreateFile returned a new owned handle.
        unsafe { std::fs::File::from_raw_handle(handle) }
    };

    #[cfg(not(any(unix, windows)))]
    let file = {
        let _ = (parent, component, path, directory);
        anyhow::bail!("{label} descriptor-relative path traversal is unsupported");
    };

    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened {label} {}", path.display()))?;
    let valid_kind = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if metadata_is_link_like(&metadata) || !valid_kind {
        anyhow::bail!(
            "opened {label} path component is not a real non-link {}: {}",
            if directory { "directory" } else { "file" },
            path.display()
        );
    }
    Ok(file)
}

fn verify_open_file_identity(
    opened: &std::fs::File,
    namespace: &std::fs::File,
    path: &Path,
    label: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let opened = opened
            .metadata()
            .with_context(|| format!("inspect opened {label} {}", path.display()))?;
        let namespace = namespace
            .metadata()
            .with_context(|| format!("inspect current {label} slot {}", path.display()))?;
        if opened.dev() != namespace.dev()
            || opened.ino() != namespace.ino()
            || opened.nlink() != 1
            || namespace.nlink() != 1
        {
            anyhow::bail!(
                "{label} is hard-linked or its path changed while open: {}",
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        let opened = windows_open_object_identity(opened, label)?;
        let namespace = windows_open_object_identity(namespace, label)?;
        // `opened != namespace` also detects an nlink discrepancy between the
        // two GetFileInformationByHandle calls (hard link added in the race
        // window) because nNumberOfLinks is part of the compared tuple.
        // Combined with `opened.1 != 1` this proves BOTH sides read nlink == 1
        // — do not weaken this condition to identity-only.
        if opened != namespace || opened.1 != 1 {
            anyhow::bail!(
                "{label} is hard-linked or its path changed while open: {}",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (opened, namespace);
        anyhow::bail!("{label} opened-handle identity verification is unsupported");
    }
    Ok(())
}

#[cfg(windows)]
fn windows_open_object_identity(file: &std::fs::File, label: &str) -> Result<((u32, u64), u32)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a valid kernel handle and `information` is writable
    // storage for the exact Win32 output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) }
        == 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("query opened {label} object identity"));
    }
    // SAFETY: the successful Win32 call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((
        (information.dwVolumeSerialNumber, index),
        information.nNumberOfLinks,
    ))
}

fn verify_open_relative_path_identity(
    file: &std::fs::File,
    parent: &std::fs::File,
    leaf: &std::ffi::OsStr,
    path: &Path,
    label: &str,
) -> Result<()> {
    let namespace = open_relative_nofollow(parent, leaf, path, label, false)?;
    verify_open_file_identity(file, &namespace, path, label)
}

fn read_opened_file_bounded(
    mut file: std::fs::File,
    path: &Path,
    parent: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
    label: &str,
    require_private_file: bool,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let max_bytes_u64 = u64::try_from(max_bytes).context("file size cap exceeds u64")?;
    let read_limit = max_bytes_u64
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("file size cap overflow"))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect opened {label} {}", path.display()))?;
    if before.len() > max_bytes_u64 {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte size cap");
    }
    #[cfg(windows)]
    if require_private_file {
        crate::wal::win_native::verify_private_file_handle(&file)
            .with_context(|| format!("verify private DACL on opened {label} {}", path.display()))?;
    }
    #[cfg(unix)]
    if require_private_file {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            before.permissions().mode() & 0o077 == 0,
            "opened {label} is not private (group/other permission bits are set): {}",
            path.display()
        );
    }
    #[cfg(not(any(windows, unix)))]
    let _ = require_private_file;
    verify_open_relative_path_identity(&file, parent, leaf, path, label)?;

    let capacity = usize::try_from(before.len()).context("opened file length exceeds usize")?;
    let mut body = Vec::with_capacity(capacity);
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut body)
        .with_context(|| format!("read opened {label} {}", path.display()))?;
    if body.len() > max_bytes {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte size cap");
    }

    let after = file
        .metadata()
        .with_context(|| format!("reinspect opened {label} {}", path.display()))?;
    if after.len() != before.len() || u64::try_from(body.len())? != before.len() {
        anyhow::bail!("{label} changed size while it was being read");
    }
    #[cfg(windows)]
    if require_private_file {
        crate::wal::win_native::verify_private_file_handle(&file).with_context(|| {
            format!("reverify private DACL on opened {label} {}", path.display())
        })?;
    }
    #[cfg(unix)]
    if require_private_file {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            after.permissions().mode() & 0o077 == 0,
            "opened {label} lost its private permissions while being read: {}",
            path.display()
        );
    }
    verify_open_relative_path_identity(&file, parent, leaf, path, label)?;
    Ok(body)
}

fn relative_namespace_components(
    trusted_root: &Path,
    canonical_root: &Path,
    path: &Path,
    label: &str,
) -> Result<Vec<std::ffi::OsString>> {
    let relative = path
        .strip_prefix(trusted_root)
        .or_else(|_| path.strip_prefix(canonical_root))
        .with_context(|| {
            format!(
                "{label} is outside trusted namespace {}: {}",
                trusted_root.display(),
                path.display()
            )
        })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            anyhow::bail!("{label} contains a non-relative namespace component");
        };
        components.push(component.to_os_string());
    }
    if components.is_empty() {
        anyhow::bail!("{label} does not name a file below its trusted namespace");
    }
    Ok(components)
}

fn read_file_bounded_with_policy(
    trusted_root: &Path,
    path: &Path,
    expected_path: Option<&Path>,
    max_bytes: usize,
    label: &str,
    require_private_file: bool,
) -> Result<Vec<u8>> {
    // A configured NEOTH_HOME may itself be a deliberate symlink or junction.
    // Resolve that explicitly trusted boundary once, bind its directory
    // handle, then traverse every untrusted remainder relative to the prior
    // handle. No absolute lookup below the root can follow an earlier alias.
    let canonical_root = std::fs::canonicalize(trusted_root).with_context(|| {
        format!(
            "canonicalize trusted {label} namespace {}",
            trusted_root.display()
        )
    })?;
    let mut components = relative_namespace_components(trusted_root, &canonical_root, path, label)
        .with_context(|| {
            expected_path.map_or_else(
                || format!("{label} is outside its trusted namespace"),
                |expected_path| {
                    format!(
                        "{label} is outside its exact file slot: {}",
                        expected_path.display()
                    )
                },
            )
        })?;
    if let Some(expected_path) = expected_path {
        let expected_components =
            relative_namespace_components(trusted_root, &canonical_root, expected_path, label)
                .with_context(|| {
                    format!(
                        "{label} is outside its exact file slot: {}",
                        expected_path.display()
                    )
                })?;
        if components != expected_components {
            anyhow::bail!(
                "{label} is outside its exact file slot: {}",
                expected_path.display()
            );
        }
    }

    let leaf = components
        .pop()
        .expect("relative namespace components are non-empty");
    let mut parent = open_directory_nofollow(&canonical_root, label)?;
    let mut display_path = canonical_root;
    for component in components {
        display_path.push(&component);
        parent = open_relative_nofollow(&parent, &component, &display_path, label, true)?;
    }
    display_path.push(&leaf);
    let file = open_relative_nofollow(&parent, &leaf, &display_path, label, false)?;
    read_opened_file_bounded(
        file,
        path,
        &parent,
        &leaf,
        max_bytes,
        label,
        require_private_file,
    )
}

fn read_file_bounded(
    trusted_root: &Path,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    read_file_bounded_with_policy(trusted_root, path, None, max_bytes, label, false)
}

/// Read one private control file below a caller-owned trusted root while
/// binding every descendant lookup to no-follow directory/file handles. This
/// is shared with detached background jobs so their prompt-bearing payload is
/// never read through a symlink/reparse swap or an unbounded special file.
pub(crate) fn read_private_control_file_bounded(
    trusted_root: &Path,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    read_file_bounded_with_policy(trusted_root, path, None, max_bytes, label, true)
}

#[cfg(windows)]
fn read_private_windows_file_bounded(
    trusted_root: &Path,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    read_file_bounded_with_policy(trusted_root, path, None, max_bytes, label, true)
}

#[cfg(windows)]
fn read_exact_private_windows_file_bounded(
    trusted_root: &Path,
    path: &Path,
    expected_path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    read_file_bounded_with_policy(
        trusted_root,
        path,
        Some(expected_path),
        max_bytes,
        label,
        true,
    )
}

fn read_validated_staged_file_bounded(
    stage_dir: &Path,
    recorded_path: &str,
    expected_name: &str,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let expected_leaf = Path::new(expected_name);
    if expected_leaf.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        anyhow::bail!("invalid staged {label} filename {expected_name:?}");
    }
    let recorded = PathBuf::from(recorded_path);
    let trusted_root = stage_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("staged {label} directory has no trusted namespace"))?;
    read_file_bounded_with_policy(
        trusted_root,
        &recorded,
        Some(&stage_dir.join(expected_name)),
        max_bytes,
        &format!("staged {label}"),
        false,
    )
    .with_context(|| {
        format!(
            "staged {label} path failed exact stage slot validation: {}",
            stage_dir.join(expected_name).display()
        )
    })
}

/// Apply an ALREADY-STAGED update — skips the network entirely. The staging
/// task downloaded + sha256 + minisig-verified this archive; here we RE-VERIFY
/// **both** the minisign signature (authenticity, GR-043) AND the SHA-256
/// (integrity) before any swap — the staged file, its `.minisig`, and the
/// recorded `pending.json` could all have been touched on disk after staging,
/// so neither the recorded `signature_status` nor a stale check is trusted.
/// Returns the same [`UpdateApplied`] envelope a fresh `apply_update` would.
/// F55 — a tamper-suspect failure of the staged fast-path: the staged
/// artifact's minisign signature or SHA-256 did not verify at apply time.
/// Distinct from an I/O error so the caller can REFUSE (clear the artifact +
/// audit) instead of silently downloading a fresh copy. `?` converts it into
/// `anyhow::Error`; the caller recovers the class via `downcast_ref`.
#[derive(Debug)]
pub struct IntegrityViolation(pub String);

impl std::fmt::Display for IntegrityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IntegrityViolation {}

pub fn apply_from_staged(
    pending: &PendingUpdate,
    stage_dir: &Path,
    install_dir: &Path,
    require_signature: bool,
) -> Result<UpdateApplyOutcome> {
    parse_semver_version(&pending.to_version).map_err(|error| {
        IntegrityViolation(format!("invalid staged release version: {error:#}"))
    })?;
    validate_owner_repo(&pending.source_repo)
        .map_err(|error| IntegrityViolation(format!("invalid staged release source: {error:#}")))?;
    if !release_tag_matches_channel(&pending.to_version, pending.channel) {
        return Err(IntegrityViolation(format!(
            "staged release version {:?} is outside its recorded {} channel",
            pending.to_version,
            pending.channel.as_str()
        ))
        .into());
    }
    if !release_target_is_supported(&pending.target_triple) {
        return Err(IntegrityViolation(format!(
            "unsupported staged release target {:?}",
            pending.target_triple
        ))
        .into());
    }
    let expected_asset = expected_asset_name("neoth", &pending.to_version, &pending.target_triple);
    if !pending
        .download_url
        .ends_with(&format!("/{expected_asset}"))
    {
        return Err(IntegrityViolation(format!(
            "staged download URL is not bound to expected asset {expected_asset:?}"
        ))
        .into());
    }
    let bytes = read_validated_staged_file_bounded(
        stage_dir,
        &pending.staged_archive,
        &expected_asset,
        "archive",
        MAX_RELEASE_ARCHIVE_BYTES,
    )
    .map_err(|error| IntegrityViolation(format!("staged archive read: {error:#}")))?;
    // GR-043 — RE-VERIFY AUTHENTICITY at apply time against the in-binary pinned
    // key. The recorded `signature_status` is attacker-controllable (anyone who
    // can write the stage dir writes pending.json), so trusting it would let a
    // planted archive + a forged `"verified"` record bypass the SEC-10 gate.
    // Re-running the real minisign check over the staged bytes + the staged
    // `.minisig` closes that: an attacker can't forge a signature without the
    // private key, and a swapped archive won't verify against the staged sig.
    let signature_text = match pending.staged_signature.as_deref() {
        Some(sig_path) => {
            let expected_signature = minisig_companion_name(&expected_asset);
            let signature_bytes = read_validated_staged_file_bounded(
                stage_dir,
                sig_path,
                &expected_signature,
                "minisig",
                MAX_SIGNATURE_BYTES,
            )
            .map_err(|error| IntegrityViolation(format!("staged minisig read: {error:#}")))?;
            Some(String::from_utf8(signature_bytes).map_err(|error| {
                IntegrityViolation(format!("staged minisig is not UTF-8: {error}"))
            })?)
        }
        None => None,
    };
    let sig_status = crate::updater::sig_verify::check_signature_for_file(
        &bytes,
        signature_text.as_deref(),
        require_signature,
        Some(&expected_asset),
    )
    .map_err(|e| {
        IntegrityViolation(format!(
            "staged self-update signature gate (apply time): {e:#}"
        ))
    })?;
    // F55 — re-verify integrity (SHA-256) against the recorded hash BEFORE any
    // swap, mapped to the typed `IntegrityViolation` so the caller can tell a
    // tamper-suspect failure apart from a benign I/O error and REFUSE (clear +
    // audit) rather than silently downloading a fresh copy. The shared bundle
    // path re-checks internally too (defence in depth); this typed check fires
    // first so the failure is classifiable.
    verify_sha256_bytes(&bytes, &pending.archive_sha256)
        .map_err(|e| IntegrityViolation(format!("staged sha256 verify failed: {e:#}")))?;
    let companion_text = format!("{}  staged\n", pending.archive_sha256);
    let format = archive_format_for_target(&pending.target_triple);
    let bundle_outcome = apply_downloaded_bundle_for_update(DownloadedBundleUpdateRequest {
        asset_bytes: &bytes,
        companion_text: &companion_text,
        signature_text: signature_text.as_deref(),
        format,
        install_dir,
        expected_release_version: &pending.to_version,
        target_triple: &pending.target_triple,
        asset_name: &expected_asset,
        audit: HandoffAudit {
            from_version: current_version(),
            release_tag: &pending.to_version,
            source_repo: &pending.source_repo,
            channel: pending.channel,
            download_url: &pending.download_url,
        },
    })
    .context("apply staged archive")?;
    match bundle_outcome {
        BundleApplyOutcome::Committed(commit) => Ok(UpdateApplyOutcome::Applied(UpdateApplied {
            from_version: current_version().to_string(),
            to_version: pending.to_version.clone(),
            transaction_id: commit.receipt.transaction_id,
            automatic_crash_recovery: true,
            restart_required: true,
            archive_sha256: pending.archive_sha256.clone(),
            download_url: pending.download_url.clone(),
            signature_status: sig_status.as_str().to_string(),
        })),
        BundleApplyOutcome::HandoffScheduled {
            operation_id,
            receipt_path,
        } => Ok(UpdateApplyOutcome::HandoffScheduled(
            UpdateHandoffScheduled {
                from_version: current_version().to_string(),
                to_version: parse_semver_version(&pending.to_version)?.to_string(),
                operation_id,
                receipt_path,
                restart_required: true,
            },
        )),
    }
}

/// Remove the staged archive + `pending.json` after a successful apply.
/// Best-effort — a leftover staged file is harmless (re-validated next time).
pub fn clear_staged(stage_dir: &Path, pending: &PendingUpdate) {
    // `pending.json` is operator-writable and therefore untrusted. Never delete
    // the recorded arbitrary path; derive the only safe stage children from a
    // validated version + release target.
    if parse_semver_version(&pending.to_version).is_ok()
        && release_target_is_supported(&pending.target_triple)
    {
        let asset = expected_asset_name("neoth", &pending.to_version, &pending.target_triple);
        let _ = std::fs::remove_file(stage_dir.join(&asset));
        let _ = std::fs::remove_file(stage_dir.join(minisig_companion_name(&asset)));
    }
    let _ = std::fs::remove_file(pending_json_path(stage_dir));
}

fn ensure_private_stage_directory(stage_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(stage_dir)
            .with_context(|| format!("create private stage dir {}", stage_dir.display()))?;

        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(stage_dir)
            .with_context(|| format!("open private stage dir {}", stage_dir.display()))?;
        directory
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict stage dir {} to mode 0700", stage_dir.display()))?;
        let mode = directory
            .metadata()
            .with_context(|| format!("verify private stage dir {}", stage_dir.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o700 {
            anyhow::bail!(
                "stage dir {} has mode {mode:04o}; expected 0700",
                stage_dir.display()
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(stage_dir)
            .with_context(|| format!("create stage dir {}", stage_dir.display()))?;
        let metadata = std::fs::symlink_metadata(stage_dir)
            .with_context(|| format!("verify stage dir {}", stage_dir.display()))?;
        if metadata_is_link_like(&metadata) || !metadata.is_dir() {
            anyhow::bail!(
                "stage path is not a real directory: {}",
                stage_dir.display()
            );
        }
        Ok(())
    }
}

/// MV-01b #5 — STAGE (do NOT swap) a newer release: fetch the archive +
/// `.sha256` + `.minisig`, verify both (signature gated by
/// `require_signature`), write the raw archive into `stage_dir`, and
/// drop a `pending.json` record. Returns the [`PendingUpdate`].
///
/// Deliberately stops before extraction and the native bundle transaction — the
/// `Action::SelfBinaryReplace` permission gate is Confirm-always, so the
/// unattended daemon path may only stage; the actual swap stays
/// operator-initiated (`neoth update --self --apply`). Senior-dev panel
/// 2026-05-29.
///
/// NOTE: shares the fetch+verify shape with [`apply_update`]; kept
/// separate (not yet extracted) so the swap path stays untouched.
pub async fn stage_update(
    release: &LatestRelease,
    owner_repo: &str,
    channel: ReleaseChannel,
    target_triple: &str,
    binary: &str,
    stage_dir: &Path,
    require_signature: bool,
    now_unix: i64,
) -> Result<PendingUpdate> {
    validate_owner_repo(owner_repo)?;
    let assets = resolve_update_assets(release, target_triple, binary)?;
    let companion = assets.sha256.ok_or_else(|| {
        anyhow::anyhow!(
            "release {} has no `.sha256` companion — refusing to stage \
             (no integrity guarantee)",
            release.tag_name
        )
    })?;

    let ua = format!("NEOTH/{} (self-update-stage)", current_version());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .build()
        .context("build stage reqwest client")?;

    let companion_text = fetch_text_bounded(
        &client,
        &companion.browser_download_url,
        MAX_CHECKSUM_BYTES,
        "sha256 companion",
    )
    .await?;

    let asset_bytes = fetch_bytes_bounded(
        &client,
        &assets.binary.browser_download_url,
        MAX_RELEASE_ARCHIVE_BYTES,
        "binary release archive",
    )
    .await?;

    // Integrity check (SHA-256) then authenticity (minisig). require=true
    // for the unattended path → any non-verified outcome bails before the
    // archive is written to the staging dir.
    let expected = parse_sha256_companion(&companion_text).context("parse sha256 companion")?;
    verify_sha256_bytes(&asset_bytes, &expected).context("verify staged asset sha256")?;

    let signature_text = match assets.signature {
        Some(sig_asset) => Some(
            fetch_text_bounded(
                &client,
                &sig_asset.browser_download_url,
                MAX_SIGNATURE_BYTES,
                "minisig companion",
            )
            .await?,
        ),
        None => None,
    };
    let sig_status = crate::updater::sig_verify::check_signature_for_file(
        &asset_bytes,
        signature_text.as_deref(),
        require_signature,
        Some(&assets.binary.name),
    )
    .context("staged self-update signature gate")?;

    ensure_private_stage_directory(stage_dir)?;
    let staged_archive = stage_dir.join(&assets.binary.name);
    crate::util::atomic_write::atomic_write_private(&staged_archive, &asset_bytes)
        .with_context(|| format!("write staged archive {}", staged_archive.display()))?;

    // GR-043 — persist the `.minisig` next to the staged archive so
    // `apply_from_staged` can RE-VERIFY authenticity offline at apply time
    // (against the in-binary pinned key), not just trust the recorded status.
    let staged_signature = match signature_text.as_deref() {
        Some(sig) => {
            let sig_path = stage_dir.join(minisig_companion_name(&assets.binary.name));
            crate::util::atomic_write::atomic_write_private(&sig_path, sig.as_bytes())
                .with_context(|| format!("write staged minisig {}", sig_path.display()))?;
            Some(sig_path.display().to_string())
        }
        None => None,
    };

    let pending = PendingUpdate {
        to_version: release.tag_name.clone(),
        source_repo: owner_repo.to_string(),
        channel,
        archive_sha256: expected,
        download_url: assets.binary.browser_download_url.clone(),
        signature_status: sig_status.as_str().to_string(),
        staged_archive: staged_archive.display().to_string(),
        staged_signature,
        target_triple: target_triple.to_string(),
        staged_ts_unix: now_unix,
    };
    let pending_path = pending_json_path(stage_dir);
    let body = serde_json::to_vec_pretty(&pending).context("serialise pending.json")?;
    crate::util::atomic_write::atomic_write_private(&pending_path, &body)
        .with_context(|| format!("write {}", pending_path.display()))?;

    Ok(pending)
}

/// Resolve every asset needed to stage or apply an update.
/// Returns `Err` with an operator-readable diagnostic when:
///
///   - the host's target triple isn't in our cargo-dist mapping,
///   - the release has no asset matching the target,
///   - the release published the binary but no SHA-256 companion
///     (the function still returns `Ok` here — see field type;
///     callers decide whether to bail).
pub fn resolve_update_assets<'a>(
    release: &'a LatestRelease,
    target: &'a str,
    binary: &str,
) -> Result<UpdateAssets<'a>> {
    parse_semver_version(&release.tag_name).context("release tag is not valid SemVer")?;
    if !release_target_is_supported(target) {
        anyhow::bail!(
            "unsupported release target {target:?}; expected one of {}",
            SUPPORTED_RELEASE_TARGETS.join(", ")
        );
    }
    let asset = find_matching_asset(&release.assets, binary, &release.tag_name, target)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no release asset matches target {target}; \
             expected {} — re-run with a cargo-dist target this \
             release was built for, or update manually from {}",
                expected_asset_name(binary, &release.tag_name, target),
                release.html_url
            )
        })?;
    let sha256 = find_sha256_companion(&release.assets, asset);
    let signature = find_minisig_companion(&release.assets, asset);
    Ok(UpdateAssets {
        target,
        binary: asset,
        sha256,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_semver_strips_leading_v() {
        assert_eq!(parse_semver("v0.1.0").unwrap(), (0, 1, 0));
        assert_eq!(parse_semver("V2.3.4").unwrap(), (2, 3, 4));
        assert_eq!(parse_semver("0.1.0").unwrap(), (0, 1, 0));
    }

    #[test]
    fn parse_semver_validates_pre_release_and_build_metadata() {
        assert_eq!(parse_semver("0.2.0-rc1").unwrap(), (0, 2, 0));
        assert_eq!(parse_semver("1.0.0+sha.deadbeef").unwrap(), (1, 0, 0));
        assert_eq!(parse_semver("v0.5.0-alpha.2+build.1").unwrap(), (0, 5, 0));
    }

    #[test]
    fn parse_semver_rejects_two_component_string() {
        // `1.0` is not semver. Surface as Err so the operator gets a
        // diagnostic instead of a silent zero-patch default.
        assert!(parse_semver("1.0").is_err());
        assert!(parse_semver("just-a-tag").is_err());
        assert!(parse_semver("").is_err());
    }

    #[test]
    fn version_is_newer_returns_true_for_strict_increase() {
        assert!(version_is_newer("0.2.0", "0.1.0").unwrap());
        assert!(version_is_newer("v0.1.1", "v0.1.0").unwrap());
        assert!(version_is_newer("1.0.0", "0.99.99").unwrap());
    }

    #[test]
    fn version_is_newer_returns_false_for_equal_versions() {
        // Operator is already on latest — no banner, no nag.
        assert!(!version_is_newer("0.1.0", "0.1.0").unwrap());
        assert!(!version_is_newer("v0.1.0", "0.1.0").unwrap());
        assert!(!version_is_newer("1.0.0+build.2", "1.0.0+build.1").unwrap());
    }

    #[test]
    fn version_is_newer_honors_prerelease_precedence() {
        assert!(version_is_newer("1.0.0", "1.0.0-beta.4").unwrap());
        assert!(version_is_newer("1.0.0-rc.1", "1.0.0-beta.4").unwrap());
        assert!(!version_is_newer("1.0.0-beta.4", "1.0.0").unwrap());
        assert!(!version_is_newer("1.0.0-beta.3", "1.0.0-beta.4").unwrap());
    }

    #[test]
    fn version_is_newer_returns_false_for_downgrade() {
        // Latest GitHub release is older than the daemon — operator
        // is ahead (likely an operator-built local). Never nag.
        assert!(!version_is_newer("0.0.9", "0.1.0").unwrap());
        assert!(!version_is_newer("v0.1.0", "0.2.0").unwrap());
    }

    #[test]
    fn version_is_newer_compares_minor_when_major_equal() {
        // Defends against lexicographic-sort bugs: "0.10.0" must be
        // newer than "0.9.0" (numeric, not string compare).
        assert!(version_is_newer("0.10.0", "0.9.0").unwrap());
        assert!(version_is_newer("0.10.0", "0.9.99").unwrap());
    }

    #[test]
    fn version_is_newer_compares_patch_when_minor_equal() {
        assert!(version_is_newer("0.1.10", "0.1.9").unwrap());
        assert!(!version_is_newer("0.1.9", "0.1.10").unwrap());
    }

    #[test]
    fn version_is_newer_bails_on_unparseable_input() {
        // Garbage inputs surface as Err so the CLI shows a clear
        // diagnostic. Returning false would silently mask a broken
        // release tag.
        assert!(version_is_newer("broken-tag", "0.1.0").is_err());
        assert!(version_is_newer("0.1.0", "broken-tag").is_err());
    }

    #[test]
    fn current_version_matches_cargo_package_metadata() {
        // Pin that env! resolves at compile time — a future toolchain
        // change that flips this to runtime would break update checks.
        assert!(!current_version().is_empty());
        assert!(parse_semver(current_version()).is_ok());
    }

    fn release(tag: &str) -> LatestRelease {
        LatestRelease {
            tag_name: tag.into(),
            html_url: format!("https://example.test/releases/{tag}"),
            published_at: String::new(),
            assets: Vec::new(),
        }
    }

    #[test]
    fn stable_channel_excludes_every_prerelease() {
        let selected = select_release_for_channel(
            vec![
                release("v1.2.0-nightly.20260714"),
                release("v1.1.0-gold-rc1"),
                release("v1.0.1"),
            ],
            ReleaseChannel::Stable,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.0.1");
    }

    #[test]
    fn rc_channel_accepts_gold_rc_and_stable_but_not_nightly() {
        let selected = select_release_for_channel(
            vec![
                release("v1.2.0-nightly.20260714"),
                release("v1.1.0-gold-rc1"),
                release("v1.0.1"),
            ],
            ReleaseChannel::Rc,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.1.0-gold-rc1");
    }

    #[test]
    fn nightly_channel_accepts_nightly_but_excludes_unclaimed_beta() {
        let selected = select_release_for_channel(
            vec![
                release("v1.3.0-beta.1"),
                release("v1.2.0-nightly.20260714"),
                release("v1.1.0-rc.2"),
                release("v1.0.1"),
            ],
            ReleaseChannel::Nightly,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.2.0-nightly.20260714");
    }

    #[test]
    fn channel_selection_skips_invalid_tags_and_keeps_newest_equal_precedence() {
        let selected = select_release_for_channel(
            vec![
                release("not-semver"),
                release("v1.0.0+new"),
                release("v1.0.0+old"),
            ],
            ReleaseChannel::Stable,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.0.0+new");
    }

    #[test]
    fn github_release_repo_slug_is_strict() {
        assert!(owner_repo_is_valid("The-Geek-Freaks/NEOTH"));
        assert!(owner_repo_is_valid("owner/repo.name_v2"));
        for invalid in [
            "owner",
            "/repo",
            "owner/",
            "-owner/repo",
            "owner-/repo",
            "owner/repo/releases",
            "owner/repo?ref=main",
            "owner /repo",
        ] {
            assert!(!owner_repo_is_valid(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn github_api_request_is_anonymous_and_pins_accept_header() {
        let client = reqwest::Client::new();
        let request = github_api_get(
            &client,
            "https://api.github.com/repos/owner/repo/releases/latest",
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers().get(reqwest::header::ACCEPT).unwrap(),
            "application/vnd.github+json"
        );
        assert!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none()
        );
    }

    #[test]
    fn staged_tag_must_match_current_channel() {
        assert!(!release_tag_matches_channel(
            "v1.1.0-rc.1",
            ReleaseChannel::Stable
        ));
        assert!(release_tag_matches_channel(
            "v1.1.0-rc.1",
            ReleaseChannel::Rc
        ));
        assert!(release_tag_matches_channel(
            "v1.1.0-nightly.1",
            ReleaseChannel::Nightly
        ));
    }

    #[test]
    fn target_resolution_accepts_matrix_override_and_rejects_unknown() {
        assert_eq!(
            resolve_release_target(Some(" x86_64-unknown-linux-musl ")).unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert!(resolve_release_target(Some("riscv64gc-unknown-linux-gnu")).is_err());
    }

    // ── Asset-locator coverage ───────────────────────────────────────

    fn fake_asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!(
                "https://github.com/owner/repo/releases/download/v0.2.0/{name}"
            ),
            size: 1234,
        }
    }

    fn fake_release(assets: Vec<ReleaseAsset>) -> LatestRelease {
        LatestRelease {
            tag_name: "v0.2.0".to_string(),
            html_url: "https://github.com/owner/repo/releases/tag/v0.2.0".to_string(),
            published_at: "2026-05-21T00:00:00Z".to_string(),
            assets,
        }
    }

    #[test]
    fn archive_format_picks_zip_for_windows() {
        assert_eq!(
            archive_format_for_target("x86_64-pc-windows-msvc"),
            ArchiveFormat::Zip
        );
        assert_eq!(
            archive_format_for_target("aarch64-pc-windows-msvc"),
            ArchiveFormat::Zip
        );
    }

    #[test]
    fn archive_format_picks_tar_gz_for_unix() {
        // Session 28f reconciliation: aligned to the release workflow's
        // actual output (`tar -czf` → `.tar.gz`). Pre-fix this pinned
        // `TarXz` and the asset locator silently missed every release.
        assert_eq!(
            archive_format_for_target("x86_64-unknown-linux-gnu"),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            archive_format_for_target("aarch64-apple-darwin"),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            archive_format_for_target("x86_64-apple-darwin"),
            ArchiveFormat::TarGz
        );
    }

    #[test]
    fn archive_format_falls_back_to_tar_gz_for_unknown() {
        // Truly unknown OS (no `linux` / `darwin` / `windows`
        // substring) — safest universal fallback so the extractor
        // always has SOMETHING to try.
        assert_eq!(
            archive_format_for_target("riscv64gc-unknown-freebsd"),
            ArchiveFormat::TarGz
        );
        assert_eq!(archive_format_for_target(""), ArchiveFormat::TarGz);
        assert_eq!(
            archive_format_for_target("wasm32-unknown-unknown"),
            ArchiveFormat::TarGz
        );
    }

    #[test]
    fn archive_format_extension_includes_leading_dot() {
        assert_eq!(ArchiveFormat::Zip.extension(), ".zip");
        assert_eq!(ArchiveFormat::TarXz.extension(), ".tar.xz");
        assert_eq!(ArchiveFormat::TarGz.extension(), ".tar.gz");
    }

    #[test]
    fn host_target_triple_returns_some_for_common_hosts() {
        // The test runner host is one of the supported targets.
        // Pin that the function returns Some on whatever the test
        // is running on, AND that the string matches our cargo-dist
        // matrix.
        let host = host_target_triple();
        assert!(
            host.is_some(),
            "test host must be a cargo-dist-mapped target"
        );
        let h = host.unwrap();
        assert!(
            h.contains("windows") || h.contains("linux") || h.contains("darwin"),
            "unexpected host triple: {h}"
        );
    }

    #[test]
    fn expected_asset_name_follows_cargo_dist_convention() {
        // Pin the canonical naming so a release-yaml change is
        // caught here, not at first download.
        assert_eq!(
            expected_asset_name("neoth", "v1.0.0", "x86_64-pc-windows-msvc"),
            "neoth-v1.0.0-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            expected_asset_name("neoth", "v1.0.0", "x86_64-unknown-linux-gnu"),
            "neoth-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            expected_asset_name("neoth", "v1.0.0", "aarch64-apple-darwin"),
            "neoth-v1.0.0-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn sha256_companion_just_appends_sha256_extension() {
        assert_eq!(
            sha256_companion_name("neoth-x86_64-pc-windows-msvc.zip"),
            "neoth-x86_64-pc-windows-msvc.zip.sha256"
        );
        assert_eq!(
            sha256_companion_name("neoth-x86_64-unknown-linux-gnu.tar.gz"),
            "neoth-x86_64-unknown-linux-gnu.tar.gz.sha256"
        );
    }

    #[test]
    fn find_matching_asset_picks_correct_target() {
        let assets = vec![
            fake_asset("neoth-v1.0.0-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz"),
            fake_asset("neoth-aarch64-apple-darwin.tar.gz"),
        ];
        let m = find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-pc-windows-msvc")
            .expect("must locate windows asset");
        assert_eq!(m.name, "neoth-v1.0.0-x86_64-pc-windows-msvc.zip");
    }

    #[test]
    fn find_matching_asset_rejects_other_binary_for_same_target() {
        let assets = vec![
            fake_asset("neothd-v1.0.0-x86_64-pc-windows-msvc.zip"),
            fake_asset("other-v1.0.0-x86_64-pc-windows-msvc.zip"),
        ];
        assert!(
            find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-pc-windows-msvc").is_none(),
            "target matching alone must not select a different executable"
        );
    }

    #[test]
    fn find_matching_asset_rejects_wrong_extension_for_target() {
        // A `.zip` named for a Linux target is rejected — operator
        // error or upload mix-up. The apply path must surface "no match"
        // here.
        let assets = vec![fake_asset("neoth-v1.0.0-x86_64-unknown-linux-gnu.zip")];
        assert!(
            find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-unknown-linux-gnu").is_none()
        );
    }

    #[test]
    fn find_matching_asset_none_when_empty() {
        let assets: Vec<ReleaseAsset> = vec![];
        assert!(
            find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-pc-windows-msvc").is_none()
        );
    }

    #[test]
    fn find_matching_asset_none_for_target_not_in_release() {
        // Release published only the Linux build; Windows host
        // asks for an asset → None, caller falls back to manual.
        let assets = vec![fake_asset("neoth-v1.0.0-x86_64-unknown-linux-gnu.tar.gz")];
        assert!(
            find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-pc-windows-msvc").is_none()
        );
    }

    #[test]
    fn find_matching_asset_rejects_stale_version_for_same_target() {
        let assets = vec![fake_asset("neoth-v0.9.0-x86_64-pc-windows-msvc.zip")];
        assert!(
            find_matching_asset(&assets, "neoth", "v1.0.0", "x86_64-pc-windows-msvc").is_none(),
            "release tag must be bound to the selected archive"
        );
    }

    #[test]
    fn find_sha256_companion_pairs_with_binary() {
        let bin = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz");
        let companion = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz.sha256");
        let assets = vec![bin.clone(), companion];
        let found = find_sha256_companion(&assets, &bin).expect("companion must match");
        assert!(found.name.ends_with(".sha256"));
    }

    #[test]
    fn find_sha256_companion_none_when_missing() {
        // Release without checksum — every apply caller MUST refuse
        // to apply. Pin that the locator surfaces None so the
        // refusal path is reachable.
        let bin = fake_asset("neoth-x86_64-pc-windows-msvc.zip");
        let assets = vec![bin.clone()];
        assert!(find_sha256_companion(&assets, &bin).is_none());
    }

    #[tokio::test]
    async fn apply_from_staged_installs_without_network() {
        // Stage a zip on disk + a matching pending.json, then apply it
        // via the no-network fast-path. Mirrors the apply_downloaded test
        // but through the staged-apply helper. The fixture binary name
        // must match what `apply_from_staged` extracts internally
        // (`"neoth"` — the public self-updated Cargo binary).
        let want = binary_filename_for_host("neoth");
        let target = host_target_triple().expect("test host is in the release matrix");
        let archive_bytes =
            make_release_bundle_with_snapshot(&[(&want, b"staged-daemon")], "v9.9.9", target);
        let mut hasher = Sha256::new();
        hasher.update(&archive_bytes);
        let digest = hex_encode(&hasher.finalize());

        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let asset_name = expected_asset_name("neoth", "v9.9.9", target);
        let staged_archive = stage_dir.join(&asset_name);
        std::fs::write(&staged_archive, &archive_bytes).unwrap();

        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(&want), b"old-daemon").unwrap();
        crate::updater::release_bundle::write_test_portable_ownership_marker(&install_dir).unwrap();
        let overlay = dir
            .path()
            .join("operator-vault/User Overlays/operator-notes.md");
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"operator-owned; never replace").unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: digest,
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(),
            staged_archive: staged_archive.display().to_string(),
            staged_signature: None,
            target_triple: target.into(),
            staged_ts_unix: 1_700_000_000,
        };
        // pending.json round-trips through disk.
        let pj = pending_json_path(&stage_dir);
        std::fs::write(&pj, serde_json::to_vec(&pending).unwrap()).unwrap();
        assert_eq!(read_pending(&stage_dir).as_ref(), Some(&pending));

        // require_signature=false (operator --allow-unsigned): with no pinned
        // key in test builds the gate returns NoPinnedKey, so the offline
        // install mechanics still run.
        let outcome =
            apply_from_staged(&pending, &stage_dir, &install_dir, false).expect("staged apply");
        let UpdateApplyOutcome::Applied(outcome) = outcome else {
            panic!("test installation is not the running Windows executable");
        };
        assert_eq!(outcome.to_version, "v9.9.9");
        assert_eq!(outcome.signature_status, "no_pinned_key");
        assert_eq!(
            std::fs::read(install_dir.join(&want)).unwrap(),
            b"staged-daemon"
        );
        crate::wiki::release_snapshot::VerifiedReleaseSnapshot::open_for_update(
            install_dir
                .join(crate::updater::release_bundle::PORTABLE_SUPPORT_DIR)
                .join("self-knowledge"),
            "v9.9.9",
        )
        .expect("installed snapshot remains release-valid");
        assert_eq!(
            std::fs::read(&overlay).unwrap(),
            b"operator-owned; never replace",
            "self-update must not mutate User Overlays"
        );

        clear_staged(&stage_dir, &pending);
        assert!(!staged_archive.exists(), "staged archive removed");
        assert!(read_pending(&stage_dir).is_none(), "pending.json removed");
    }

    #[tokio::test]
    async fn apply_from_staged_refuses_tampered_archive() {
        // The staged file was modified after staging — the SHA re-check
        // inside apply_from_staged must refuse before any swap. Fixture
        // matches the production binary name `"neoth"`.
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"good");
        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let asset_name = expected_asset_name("neoth", "v9.9.9", "x86_64-pc-windows-msvc");
        let staged_archive = stage_dir.join(&asset_name);
        std::fs::write(&staged_archive, &zip_bytes).unwrap();
        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: "0".repeat(64), // wrong hash → tamper-detect
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(),
            staged_archive: staged_archive.display().to_string(),
            staged_signature: None,
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 0,
        };
        // require_signature=false so the signature gate passes (NoPinnedKey) and
        // the SHA-256 re-check is the refusal point under test.
        let err = apply_from_staged(&pending, &stage_dir, &install_dir, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("sha256 mismatch"),
            "tampered staged archive must fail SHA re-check: {err:#}"
        );
        // F55 — must surface as a typed IntegrityViolation so the caller REFUSES
        // (clear + 0xDE audit) instead of silently falling back to a download.
        assert!(
            err.downcast_ref::<IntegrityViolation>().is_some(),
            "tamper must be a typed IntegrityViolation: {err:#}"
        );
    }

    #[tokio::test]
    async fn apply_from_staged_refuses_when_signature_required_but_unverifiable() {
        // GR-043 — the staged fast-path must enforce the SEC-10 signature gate
        // at APPLY time, not just trust the recorded `signature_status`. With
        // require_signature=true and no verifiable signature (test builds have
        // no pinned key), apply_from_staged must REFUSE before any swap — even
        // though the pending record claims `signature_status:"verified"` and the
        // SHA-256 matches (an attacker who can write the stage dir controls
        // both).
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"attacker-binary");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());

        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let asset_name = expected_asset_name("neoth", "v9.9.9", "x86_64-pc-windows-msvc");
        let staged_archive = stage_dir.join(&asset_name);
        std::fs::write(&staged_archive, &zip_bytes).unwrap();
        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(&want), b"original").unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: digest, // matches the planted archive
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(), // forged claim
            staged_archive: staged_archive.display().to_string(),
            staged_signature: None, // no real signature → can't be verified
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 0,
        };
        let err = apply_from_staged(&pending, &stage_dir, &install_dir, true).unwrap_err();
        assert!(
            format!("{err:#}").contains("signature gate") || format!("{err:#}").contains("pinned"),
            "a required-but-unverifiable staged apply must be refused: {err:#}"
        );
        // F55 — typed so the caller refuses (no silent fresh-download fallback).
        assert!(
            err.downcast_ref::<IntegrityViolation>().is_some(),
            "required-but-unverifiable staged apply must be a typed IntegrityViolation: {err:#}"
        );
        // The on-disk binary must be UNTOUCHED — no swap happened.
        assert_eq!(
            std::fs::read(install_dir.join(&want)).unwrap(),
            b"original",
            "no binary swap may occur when the signature gate refuses"
        );
    }

    #[test]
    fn staged_apply_rejects_recorded_path_outside_exact_stage_slot() {
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"signed-shape");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());
        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        let outside_dir = dir.path().join("outside");
        std::fs::create_dir_all(&stage_dir).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        let asset_name = expected_asset_name("neoth", "v9.9.9", "x86_64-pc-windows-msvc");
        std::fs::write(stage_dir.join(&asset_name), &zip_bytes).unwrap();
        let outside = outside_dir.join(&asset_name);
        std::fs::write(&outside, &zip_bytes).unwrap();
        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(&want), b"original").unwrap();
        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: digest,
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(),
            staged_archive: outside.display().to_string(),
            staged_signature: None,
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 0,
        };

        let error = apply_from_staged(&pending, &stage_dir, &install_dir, false).unwrap_err();
        assert!(error.downcast_ref::<IntegrityViolation>().is_some());
        assert!(format!("{error:#}").contains("exact stage slot"));
        assert_eq!(std::fs::read(install_dir.join(want)).unwrap(), b"original");
    }

    #[test]
    fn clear_staged_never_deletes_untrusted_recorded_path() {
        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let asset_name = expected_asset_name("neoth", "v9.9.9", "x86_64-pc-windows-msvc");
        let expected = stage_dir.join(&asset_name);
        let outside = dir.path().join("operator-data.txt");
        std::fs::write(&expected, b"staged").unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        std::fs::write(pending_json_path(&stage_dir), b"{}").unwrap();
        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: "0".repeat(64),
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(),
            staged_archive: outside.display().to_string(),
            staged_signature: Some(outside.display().to_string()),
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 0,
        };

        clear_staged(&stage_dir, &pending);
        assert_eq!(std::fs::read(outside).unwrap(), b"keep");
        assert!(!expected.exists());
        assert!(!pending_json_path(&stage_dir).exists());
    }

    #[test]
    fn read_pending_rejects_oversized_record() {
        let dir = tempdir().unwrap();
        std::fs::write(
            pending_json_path(dir.path()),
            vec![b' '; MAX_PENDING_JSON_BYTES + 1],
        )
        .unwrap();
        assert!(read_pending(dir.path()).is_none());
    }

    #[test]
    fn bounded_reader_uses_one_regular_single_link_identity() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("artifact.bin");
        std::fs::write(&file, b"bound artifact").unwrap();
        assert_eq!(
            read_file_bounded(dir.path(), &file, 64, "test artifact").unwrap(),
            b"bound artifact"
        );

        let alias = dir.path().join("artifact-hardlink.bin");
        std::fs::hard_link(&file, &alias).unwrap();
        let error = read_file_bounded(dir.path(), &file, 64, "test artifact").unwrap_err();
        assert!(
            format!("{error:#}").contains("hard-linked"),
            "a multiply-linked staged input must fail closed: {error:#}"
        );
    }

    #[test]
    fn exact_bounded_reader_does_not_read_an_outside_same_named_file() {
        let dir = tempdir().unwrap();
        let stage = dir.path().join("stage");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let expected = stage.join("artifact.bin");
        let supplied = outside.join("artifact.bin");
        std::fs::write(&expected, b"expected").unwrap();
        std::fs::write(&supplied, b"outside secret").unwrap();

        let error = read_file_bounded_with_policy(
            dir.path(),
            &supplied,
            Some(&expected),
            64,
            "test exact artifact",
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("exact file slot"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_refuses_a_symlink_at_open_time() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.bin");
        let link = dir.path().join("artifact.bin");
        std::fs::write(&target, b"do not follow").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_file_bounded(dir.path(), &link, 64, "test artifact").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_fifo_without_blocking_before_type_check() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempdir().unwrap();
        let fifo = dir.path().join("artifact.fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_name is a live NUL-terminated path and mode is valid.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let root = dir.path().to_path_buf();
        let fifo_for_reader = fifo.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = read_file_bounded(&root, &fifo_for_reader, 64, "test FIFO artifact");
            sender.send(result).unwrap();
        });

        match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => {
                assert!(result.is_err(), "FIFO must fail the regular-file gate");
                reader.join().unwrap();
            }
            Err(error) => {
                // Unblock an implementation that regressed to a blocking FIFO
                // open before failing the test; do not strand a test thread.
                let writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                drop(writer);
                reader.join().unwrap();
                panic!("FIFO open blocked before the file-type check: {error}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_refuses_a_preexisting_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_stage = dir.path().join("real-stage");
        let linked_stage = dir.path().join("linked-stage");
        std::fs::create_dir(&real_stage).unwrap();
        std::fs::write(real_stage.join("artifact.bin"), b"do not follow parent").unwrap();
        symlink(&real_stage, &linked_stage).unwrap();

        assert!(
            read_file_bounded(
                dir.path(),
                &linked_stage.join("artifact.bin"),
                64,
                "test staged artifact",
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_refuses_a_symlinked_earlier_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_ancestor = dir.path().join("real-ancestor");
        let linked_ancestor = dir.path().join("linked-ancestor");
        let nested_stage = real_ancestor.join("nested/stage");
        std::fs::create_dir_all(&nested_stage).unwrap();
        std::fs::write(nested_stage.join("artifact.bin"), b"do not follow ancestor").unwrap();
        symlink(&real_ancestor, &linked_ancestor).unwrap();

        assert!(
            read_file_bounded(
                dir.path(),
                &linked_ancestor.join("nested/stage/artifact.bin"),
                64,
                "test nested staged artifact",
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_binds_a_symlinked_trusted_root_once() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let linked_home = dir.path().join("linked-home");
        std::fs::create_dir_all(real_home.join("staged")).unwrap();
        std::fs::write(real_home.join("staged/artifact.bin"), b"trusted root").unwrap();
        symlink(&real_home, &linked_home).unwrap();

        assert_eq!(
            read_file_bounded(
                &linked_home,
                &linked_home.join("staged/artifact.bin"),
                64,
                "test symlinked home artifact",
            )
            .unwrap(),
            b"trusted root"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_bounded_reader_binds_dacl_and_reparse_policy_to_handle() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let dir = tempdir().unwrap();
        crate::wal::win_native::set_private_current_user_directory_dacl(dir.path()).unwrap();
        let file = dir.path().join("handoff.asset");
        write_new_synced(&file, b"authenticated archive", "test archive").unwrap();
        assert_eq!(
            read_exact_private_windows_file_bounded(
                dir.path(),
                &file,
                &file,
                64,
                "Windows test handoff archive",
            )
            .unwrap(),
            b"authenticated archive"
        );

        let link = dir.path().join("handoff-link.asset");
        match symlink_file(&file, &link) {
            Ok(()) => assert!(
                read_private_windows_file_bounded(
                    dir.path(),
                    &link,
                    64,
                    "Windows test handoff link",
                )
                .is_err()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows handoff reparse fixture: {error}"),
        }

        let real_stage = dir.path().join("real-stage");
        let linked_stage = dir.path().join("linked-stage");
        std::fs::create_dir(&real_stage).unwrap();
        std::fs::write(real_stage.join("artifact.bin"), b"do not follow parent").unwrap();
        match symlink_dir(&real_stage, &linked_stage) {
            Ok(()) => assert!(
                read_file_bounded(
                    dir.path(),
                    &linked_stage.join("artifact.bin"),
                    64,
                    "Windows test staged parent",
                )
                .is_err()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows handoff parent reparse fixture: {error}"),
        }

        let real_ancestor = dir.path().join("real-ancestor");
        let linked_ancestor = dir.path().join("linked-ancestor");
        let nested_stage = real_ancestor.join("nested/stage");
        std::fs::create_dir_all(&nested_stage).unwrap();
        std::fs::write(nested_stage.join("artifact.bin"), b"do not follow ancestor").unwrap();
        match symlink_dir(&real_ancestor, &linked_ancestor) {
            Ok(()) => assert!(
                read_file_bounded(
                    dir.path(),
                    &linked_ancestor.join("nested/stage/artifact.bin"),
                    64,
                    "Windows test nested staged ancestor",
                )
                .is_err()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows handoff ancestor reparse fixture: {error}"),
        }
    }

    #[test]
    fn pending_update_round_trips_via_json() {
        let p = PendingUpdate {
            to_version: "v0.3.0".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: "a".repeat(64),
            download_url: "https://example.com/neoth.tar.gz".into(),
            signature_status: "verified".into(),
            staged_archive: "/home/user/.neoth/staged/neoth.tar.gz".into(),
            staged_signature: Some("/home/user/.neoth/staged/neoth.tar.gz.minisig".into()),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            staged_ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PendingUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        // GR-043 — an old pending.json without the field still parses (serde
        // default → None), so a staged record from before the fix stays
        // readable (and then fails closed when a signature is required).
        let legacy = r#"{"to_version":"v1","archive_sha256":"00","download_url":"u","signature_status":"verified","staged_archive":"/a","target_triple":"t","staged_ts_unix":0}"#;
        let parsed: PendingUpdate = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.staged_signature, None);
        assert_eq!(parsed.source_repo, "");
        assert_eq!(parsed.channel, ReleaseChannel::Stable);
    }

    #[test]
    fn staged_policy_binds_repo_target_and_release_ring() {
        let pending = PendingUpdate {
            to_version: "v1.1.0-rc.1".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Rc,
            archive_sha256: "a".repeat(64),
            download_url: "https://example.com/neoth.tar.gz".into(),
            signature_status: "verified".into(),
            staged_archive: "/tmp/neoth.tar.gz".into(),
            staged_signature: None,
            target_triple: "x86_64-unknown-linux-gnu".into(),
            staged_ts_unix: 0,
        };

        assert!(pending_matches_policy(
            &pending,
            "The-Geek-Freaks/NEOTH",
            ReleaseChannel::Rc,
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!pending_matches_policy(
            &pending,
            "example/fork",
            ReleaseChannel::Rc,
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!pending_matches_policy(
            &pending,
            "The-Geek-Freaks/NEOTH",
            ReleaseChannel::Stable,
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!pending_matches_policy(
            &pending,
            "The-Geek-Freaks/NEOTH",
            ReleaseChannel::Rc,
            "aarch64-unknown-linux-gnu"
        ));
    }

    #[test]
    fn pending_json_path_is_under_stage_dir() {
        let p = pending_json_path(Path::new("/home/user/.neoth/staged"));
        assert!(p.ends_with("pending.json"));
    }

    #[cfg(unix)]
    #[test]
    fn stage_directory_is_private_with_permissive_umask_and_repairs_existing_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD_ROOT: &str = "NEOTH_STAGE_MODE_TEST_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            // SAFETY: this branch runs in a dedicated child process, so changing
            // its process-global umask cannot race any other test.
            unsafe {
                libc::umask(0);
            }

            let fresh = PathBuf::from(&root).join("fresh");
            ensure_private_stage_directory(&fresh).unwrap();
            assert_eq!(
                std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
                0o700
            );

            let existing = PathBuf::from(root).join("existing");
            std::fs::create_dir(&existing).unwrap();
            std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
            ensure_private_stage_directory(&existing).unwrap();
            assert_eq!(
                std::fs::metadata(existing).unwrap().permissions().mode() & 0o777,
                0o700
            );
            return;
        }

        let root = tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("stage_directory_is_private_with_permissive_umask_and_repairs_existing_mode")
            .arg("--nocapture")
            .env(CHILD_ROOT, root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated umask regression failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn find_minisig_companion_pairs_with_binary() {
        // MV-01b #2: the `<asset>.minisig` companion is located the same
        // way as the .sha256 one.
        let bin = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz");
        let sig = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz.minisig");
        let assets = vec![bin.clone(), sig];
        let found = find_minisig_companion(&assets, &bin).expect("minisig must match");
        assert!(found.name.ends_with(".minisig"));
    }

    #[test]
    fn find_minisig_companion_none_for_pre_signing_release() {
        // Releases published before signing was enabled have no .minisig.
        // resolve_update_assets surfaces None → manual path warns,
        // unattended path bails (sig_verify gate).
        let bin = fake_asset("neoth-x86_64-pc-windows-msvc.zip");
        let assets = vec![bin.clone()];
        assert!(find_minisig_companion(&assets, &bin).is_none());
    }

    #[test]
    fn resolve_update_assets_returns_bundle_for_supported_host() {
        let assets = vec![
            fake_asset("neoth-v0.2.0-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-v0.2.0-x86_64-pc-windows-msvc.zip.sha256"),
        ];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-pc-windows-msvc", "neoth").unwrap();
        assert_eq!(
            resolved.binary.name,
            "neoth-v0.2.0-x86_64-pc-windows-msvc.zip"
        );
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_errors_when_target_unmatched() {
        let release = fake_release(vec![fake_asset(
            "neoth-v0.2.0-x86_64-unknown-linux-gnu.tar.gz",
        )]);
        let err = resolve_update_assets(&release, "x86_64-pc-windows-msvc", "neoth")
            .unwrap_err()
            .to_string();
        // Error must name the expected filename so operators see
        // the cargo-dist convention they should publish under.
        assert!(
            err.contains("neoth-v0.2.0-x86_64-pc-windows-msvc.zip"),
            "diagnostic must name expected filename; got: {err}"
        );
        // Plus the html_url for the manual fallback.
        assert!(err.contains("releases/tag/v0.2.0"));
    }

    #[test]
    fn resolve_update_assets_returns_some_sha256_when_published() {
        let assets = vec![
            fake_asset("neoth-v0.2.0-x86_64-apple-darwin.tar.gz"),
            fake_asset("neoth-v0.2.0-x86_64-apple-darwin.tar.gz.sha256"),
        ];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_returns_none_sha256_when_companion_missing() {
        // The apply path inspects this directly; if None,
        // refuse the update.
        let assets = vec![fake_asset("neoth-v0.2.0-x86_64-apple-darwin.tar.gz")];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_none());
    }

    // ── SHA-256 verification coverage ───────────────────────────────

    const ZERO_BYTES_DIGEST: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parse_sha256_companion_accepts_sha256sum_b_format() {
        let body = format!("{ZERO_BYTES_DIGEST}  neoth-x86_64-pc-windows-msvc.zip\n");
        let parsed = parse_sha256_companion(&body).unwrap();
        assert_eq!(parsed, ZERO_BYTES_DIGEST);
    }

    #[test]
    fn parse_sha256_companion_accepts_bare_digest() {
        let parsed = parse_sha256_companion(ZERO_BYTES_DIGEST).unwrap();
        assert_eq!(parsed, ZERO_BYTES_DIGEST);
    }

    #[test]
    fn parse_sha256_companion_lowercases_upper_hex() {
        let parsed = parse_sha256_companion(&ZERO_BYTES_DIGEST.to_ascii_uppercase()).unwrap();
        // Returned digest must be lowercase so the compare in
        // verify_sha256_bytes is normalised.
        assert_eq!(parsed, ZERO_BYTES_DIGEST);
    }

    #[test]
    fn parse_sha256_companion_skips_leading_blank_lines() {
        let body = format!("\n\n  \n{ZERO_BYTES_DIGEST}  asset.zip\n");
        let parsed = parse_sha256_companion(&body).unwrap();
        assert_eq!(parsed, ZERO_BYTES_DIGEST);
    }

    #[test]
    fn parse_sha256_companion_rejects_truncated_digest() {
        // 63 chars — one short. Catches a truncated upload that
        // would otherwise self-verify.
        let truncated = &ZERO_BYTES_DIGEST[..63];
        let err = parse_sha256_companion(truncated).unwrap_err().to_string();
        assert!(
            err.contains("64"),
            "diagnostic must name expected length: {err}"
        );
    }

    #[test]
    fn parse_sha256_companion_rejects_non_hex_chars() {
        // Letter `z` is not a hex digit.
        let bad = format!("z{}  asset.zip", &ZERO_BYTES_DIGEST[1..]);
        assert!(parse_sha256_companion(&bad).is_err());
    }

    #[test]
    fn parse_sha256_companion_rejects_empty_input() {
        assert!(parse_sha256_companion("").is_err());
        assert!(parse_sha256_companion("\n\n\n").is_err());
    }

    #[test]
    fn verify_sha256_bytes_accepts_matching_digest() {
        // Empty bytes hash to the well-known zero-length SHA-256.
        verify_sha256_bytes(b"", ZERO_BYTES_DIGEST).unwrap();
    }

    #[test]
    fn verify_sha256_bytes_accepts_uppercase_expected_hex() {
        // The asset companion may carry uppercase; normalise.
        verify_sha256_bytes(b"", &ZERO_BYTES_DIGEST.to_ascii_uppercase()).unwrap();
    }

    #[test]
    fn verify_sha256_bytes_rejects_mismatch_with_both_digests_in_message() {
        // A diagnostic that names BOTH digests lets the operator
        // tell "wrong file" from "modified file" at a glance.
        let err = verify_sha256_bytes(b"different content", ZERO_BYTES_DIGEST)
            .unwrap_err()
            .to_string();
        assert!(err.contains(ZERO_BYTES_DIGEST), "must name expected: {err}");
        assert!(
            err.contains("sha256 mismatch"),
            "must label as mismatch: {err}"
        );
    }

    #[test]
    fn verify_sha256_bytes_round_trips_known_text() {
        // SHA-256 of "abc" (NIST test vector).
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        verify_sha256_bytes(b"abc", expected).unwrap();
    }

    #[test]
    fn hex_encode_produces_lowercase_64_chars_for_32_input_bytes() {
        let bytes: Vec<u8> = (0..32u8).collect();
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 64);
        assert_eq!(&hex[..4], "0001");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // Closed release-archive and native-transaction coverage.

    fn make_zip_with_member(name: &str, body: &[u8]) -> Vec<u8> {
        make_zip_with_members(&[(name, body, None)])
    }

    fn make_zip_with_members(members: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
        use std::io::{Cursor, Write as _};

        let mut out = Vec::new();
        {
            let cursor = Cursor::new(&mut out);
            let mut writer = zip::ZipWriter::new(cursor);
            for (name, body, unix_mode) in members {
                let mut options = zip::write::SimpleFileOptions::default();
                if let Some(mode) = unix_mode {
                    options = options.unix_permissions(*mode);
                }
                if unix_mode.is_some_and(|mode| mode & 0o170_000 == 0o120_000) {
                    writer
                        .add_symlink::<_, _, ()>(*name, std::str::from_utf8(body).unwrap(), options)
                        .unwrap();
                    continue;
                }
                writer.start_file::<_, ()>(*name, options).unwrap();
                writer.write_all(body).unwrap();
            }
            writer.finish().unwrap();
        }
        out
    }

    fn collect_snapshot_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
        let mut entries = std::fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                collect_snapshot_files(root, &path, files);
            } else {
                files.push(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }

    fn release_files(
        overrides: &[(&str, &[u8])],
        release_version: &str,
        target: &str,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        for binary in ["neothd", "neoth-migrate", "neoth-relay"] {
            files.insert(
                binary_filename_for_host(binary),
                format!("new-{binary}").into_bytes(),
            );
        }
        if !target.contains("musl") {
            for binary in ["neothd-gui", "neoth-keet-bridge"] {
                files.insert(
                    binary_filename_for_host(binary),
                    format!("new-{binary}").into_bytes(),
                );
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
            files.insert(name.to_string(), format!("fixture-{name}").into_bytes());
        }
        files.insert(binary_filename_for_host("neoth"), b"new-neoth".to_vec());

        let fixture = tempdir().unwrap();
        let snapshot = fixture.path().join("self-knowledge");
        let canonical_version = parse_semver_version(release_version).unwrap().to_string();
        crate::wiki::release_snapshot::write_test_snapshot(&snapshot, &canonical_version).unwrap();
        let mut snapshot_files = Vec::new();
        collect_snapshot_files(&snapshot, &snapshot, &mut snapshot_files);
        for relative in snapshot_files {
            let portable = relative
                .components()
                .map(|component| component.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            files.insert(
                format!("self-knowledge/{portable}"),
                std::fs::read(snapshot.join(relative)).unwrap(),
            );
        }
        for (name, body) in overrides {
            files.insert((*name).to_string(), body.to_vec());
        }
        files
    }

    fn encode_release_files(
        files: &std::collections::BTreeMap<String, Vec<u8>>,
        release_version: &str,
        target: &str,
    ) -> Vec<u8> {
        let root = expected_archive_root(release_version, target).unwrap();
        match archive_format_for_target(target) {
            ArchiveFormat::Zip => {
                use std::io::{Cursor, Write as _};

                let mut out = Vec::new();
                {
                    let cursor = Cursor::new(&mut out);
                    let mut writer = zip::ZipWriter::new(cursor);
                    for (name, body) in files {
                        writer
                            .start_file::<_, ()>(
                                format!("{root}/{name}"),
                                zip::write::SimpleFileOptions::default(),
                            )
                            .unwrap();
                        writer.write_all(body).unwrap();
                    }
                    writer.finish().unwrap();
                }
                out
            }
            ArchiveFormat::TarGz => {
                use flate2::Compression;
                use flate2::write::GzEncoder;
                use std::io::Write as _;

                let mut tar_bytes = Vec::new();
                {
                    let mut builder = tar::Builder::new(&mut tar_bytes);
                    for (name, body) in files {
                        let mut header = tar::Header::new_gnu();
                        header.set_path(format!("{root}/{name}")).unwrap();
                        header.set_size(body.len() as u64);
                        header.set_mode(if name.starts_with("neoth") {
                            0o755
                        } else {
                            0o644
                        });
                        header.set_cksum();
                        builder.append(&header, body.as_slice()).unwrap();
                    }
                    builder.finish().unwrap();
                }
                let mut out = Vec::new();
                let mut gzip = GzEncoder::new(&mut out, Compression::default());
                gzip.write_all(&tar_bytes).unwrap();
                gzip.finish().unwrap();
                out
            }
            ArchiveFormat::TarXz => unreachable!("release matrix does not emit XZ"),
        }
    }

    fn make_release_bundle_with_snapshot(
        overrides: &[(&str, &[u8])],
        release_version: &str,
        target: &str,
    ) -> Vec<u8> {
        encode_release_files(
            &release_files(overrides, release_version, target),
            release_version,
            target,
        )
    }

    #[test]
    fn archive_ledger_rejects_unsafe_names_collisions_and_oversize() {
        let root = "neoth-v9.9.9-x86_64-pc-windows-msvc";
        for bad in [
            format!("{root}/../escape"),
            format!("../{root}/escape"),
            format!("{root}/CON.txt"),
            format!("{root}/trailing."),
            format!("{root}//empty"),
        ] {
            let mut ledger = ArchiveLedger::new(root);
            assert!(ledger.register(&bad, false, 1).is_err(), "{bad:?} passed");
        }

        let mut collision = ArchiveLedger::new(root);
        collision
            .register(&format!("{root}/README.md"), false, 1)
            .unwrap();
        assert!(
            collision
                .register(&format!("{root}/readme.md"), false, 1)
                .is_err()
        );
        let mut oversized = ArchiveLedger::new(root);
        assert!(
            oversized
                .register(
                    &format!("{root}/neoth.exe"),
                    false,
                    MAX_RELEASE_BUNDLE_MEMBER_BYTES + 1,
                )
                .is_err()
        );
    }

    #[test]
    fn zip_extractor_rejects_wrong_root_duplicates_and_links() {
        let root = "neoth-v9.9.9-x86_64-pc-windows-msvc";
        let fixture = tempdir().unwrap();
        assert!(
            extract_zip_release_bundle(
                &make_zip_with_member("other-root/neoth.exe", b"x"),
                fixture.path(),
                root,
            )
            .is_err()
        );

        let fixture = tempdir().unwrap();
        // zip 6 rejects byte-identical duplicate names in ZipWriter itself.
        // Distinct spellings that collide under our cross-platform case-folded
        // ledger still exercise the extractor's duplicate-target boundary.
        let upper = format!("{root}/README.md");
        let lower = format!("{root}/readme.md");
        let collision =
            make_zip_with_members(&[(upper.as_str(), b"a", None), (lower.as_str(), b"b", None)]);
        assert!(extract_zip_release_bundle(&collision, fixture.path(), root).is_err());

        let fixture = tempdir().unwrap();
        let link = format!("{root}/self-knowledge/link");
        let symlink = make_zip_with_members(&[(link.as_str(), b"target", Some(0o120777))]);
        assert!(extract_zip_release_bundle(&symlink, fixture.path(), root).is_err());
    }

    #[test]
    fn tar_extractor_rejects_hardlinks_before_writing_payload() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write as _;

        let root = "neoth-v9.9.9-x86_64-unknown-linux-gnu";
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{root}/neoth")).unwrap();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name(format!("{root}/neothd")).unwrap();
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }
        let mut archive = Vec::new();
        let mut gzip = GzEncoder::new(&mut archive, Compression::default());
        gzip.write_all(&tar_bytes).unwrap();
        gzip.finish().unwrap();

        let fixture = tempdir().unwrap();
        let error = extract_release_bundle(&archive, ArchiveFormat::TarGz, fixture.path(), root)
            .unwrap_err();
        assert!(format!("{error:#}").contains("link or special"));
        assert!(!fixture.path().join(root).join("neoth").exists());
    }

    #[test]
    fn downloaded_bundle_updates_full_portable_profile_and_preserves_user_state() {
        let target = host_target_triple().expect("test host is in the release matrix");
        let core_name = binary_filename_for_host("neoth");
        let archive = make_release_bundle_with_snapshot(
            &[(core_name.as_str(), b"new-core")],
            "v9.9.9",
            target,
        );
        let digest = hex_encode(&Sha256::digest(&archive));
        let install = tempdir().unwrap();
        let core = install.path().join(&core_name);
        std::fs::write(&core, b"old-core").unwrap();
        crate::updater::release_bundle::write_test_portable_ownership_marker(install.path())
            .unwrap();
        let config = install.path().join("freedom.yaml");
        std::fs::write(&config, b"operator: keep").unwrap();
        let overlay = install.path().join("vault/User Overlays/operator.md");
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"keep-overlay").unwrap();

        let commit = apply_downloaded_bundle(
            &archive,
            &digest,
            archive_format_for_target(target),
            install.path(),
            "v9.9.9",
            target,
        )
        .unwrap();

        assert!(!commit.receipt.transaction_id.is_empty());
        assert_eq!(std::fs::read(&core).unwrap(), b"new-core");
        let executable_names = [
            binary_filename_for_host("neoth"),
            binary_filename_for_host("neothd"),
            binary_filename_for_host("neothd-gui"),
            binary_filename_for_host("neoth-migrate"),
            binary_filename_for_host("neoth-relay"),
            binary_filename_for_host("neoth-keet-bridge"),
        ];
        for name in release_files(&[], "v9.9.9", target).keys() {
            let top = name.split('/').next().unwrap();
            let target = if executable_names.iter().any(|binary| binary == top) {
                install.path().join(top)
            } else {
                install
                    .path()
                    .join(crate::updater::release_bundle::PORTABLE_SUPPORT_DIR)
                    .join(top)
            };
            assert!(
                target.exists(),
                "installed member missing: {}",
                target.display()
            );
        }
        crate::wiki::release_snapshot::VerifiedReleaseSnapshot::open_for_update(
            install
                .path()
                .join(crate::updater::release_bundle::PORTABLE_SUPPORT_DIR)
                .join("self-knowledge"),
            "9.9.9",
        )
        .unwrap();
        assert_eq!(std::fs::read(config).unwrap(), b"operator: keep");
        assert_eq!(std::fs::read(overlay).unwrap(), b"keep-overlay");
    }

    #[test]
    fn downloaded_bundle_rejects_bad_bundle_before_mutation() {
        let target = host_target_triple().expect("test host is in the release matrix");
        let install = tempdir().unwrap();
        let core = install.path().join(binary_filename_for_host("neoth"));
        std::fs::write(&core, b"old-core").unwrap();
        crate::updater::release_bundle::write_test_portable_ownership_marker(install.path())
            .unwrap();

        let mut files = release_files(&[], "v9.9.9", target);
        files.remove("README.md");
        let missing = encode_release_files(&files, "v9.9.9", target);
        let error = apply_downloaded_bundle(
            &missing,
            &hex_encode(&Sha256::digest(&missing)),
            archive_format_for_target(target),
            install.path(),
            "v9.9.9",
            target,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("missing required"));
        assert_eq!(std::fs::read(&core).unwrap(), b"old-core");

        let invalid = make_release_bundle_with_snapshot(
            &[("self-knowledge/manifest.json", b"{}")],
            "v9.9.9",
            target,
        );
        assert!(
            apply_downloaded_bundle(
                &invalid,
                &hex_encode(&Sha256::digest(&invalid)),
                archive_format_for_target(target),
                install.path(),
                "v9.9.9",
                target,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(core).unwrap(), b"old-core");
    }

    #[cfg(windows)]
    fn committed_handoff_receipt(
        stage_root: PathBuf,
        install_root: PathBuf,
        request_sha256: &str,
    ) -> WindowsHandoffReceipt {
        WindowsHandoffReceipt {
            schema_version: WINDOWS_HANDOFF_SCHEMA_VERSION,
            operation_id: "0123456789abcdef0123456789abcdef".to_string(),
            status: "committed".to_string(),
            from_version: "0.9.0".to_string(),
            to_version: env!("CARGO_PKG_VERSION").to_string(),
            request_sha256: request_sha256.to_string(),
            stage_root,
            install_root,
            transaction_id: Some("txn-1".to_string()),
            members: Some(1),
            automatic_crash_recovery: true,
            error: None,
        }
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_receipt_rejects_arbitrary_stage_and_preserves_sentinel() {
        let fixture = tempdir().unwrap();
        let namespace = fixture.path().join("private-namespace");
        let outside = fixture
            .path()
            .join(format!("{WINDOWS_HANDOFF_STAGE_PREFIX}attacker"));
        std::fs::create_dir_all(&namespace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("do-not-delete.txt");
        std::fs::write(&sentinel, b"operator-owned").unwrap();
        let request_sha256 = "a".repeat(64);
        let receipt =
            committed_handoff_receipt(outside, fixture.path().join("install"), &request_sha256);

        validate_committed_windows_handoff_receipt(
            &receipt,
            "0123456789abcdef0123456789abcdef",
            &request_sha256,
        )
        .unwrap();
        assert!(validate_windows_cleanup_namespace(&receipt, &namespace).is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"operator-owned");
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_receipt_requires_exact_hash_and_committed_state() {
        let fixture = tempdir().unwrap();
        let request_sha256 = "a".repeat(64);
        let mut receipt = committed_handoff_receipt(
            fixture
                .path()
                .join(format!("{WINDOWS_HANDOFF_STAGE_PREFIX}fixture")),
            fixture.path().join("install"),
            &request_sha256,
        );
        assert!(
            validate_committed_windows_handoff_receipt(
                &receipt,
                "0123456789abcdef0123456789abcdef",
                &"b".repeat(64),
            )
            .is_err()
        );
        receipt.status = "failed".to_string();
        assert!(
            validate_committed_windows_handoff_receipt(
                &receipt,
                "0123456789abcdef0123456789abcdef",
                &request_sha256,
            )
            .is_err()
        );
        assert!(validate_handoff_request_sha256(&"A".repeat(64)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn handoff_request_binding_rejects_noncanonical_hash_before_apply() {
        let bytes = br#"{"schema_version":1}"#;
        let digest = hex_encode(&Sha256::digest(bytes));
        validate_windows_handoff_request_binding(bytes, &digest).unwrap();
        assert!(
            validate_windows_handoff_request_binding(bytes, &digest.to_ascii_uppercase()).is_err()
        );
        assert!(validate_windows_handoff_request_binding(bytes, "abc").is_err());
        assert!(validate_windows_handoff_request_binding(bytes, &"0".repeat(64)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn quarantined_cleanup_resumes_after_request_was_already_removed() {
        let fixture = tempdir().unwrap();
        let cleanup = fixture
            .path()
            .join(".cleanup-0123456789abcdef0123456789abcdef");
        let nested = cleanup.join("partially-removed");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("remaining.bin"), b"remaining").unwrap();

        validate_windows_cleanup_tree(&cleanup).unwrap();
        remove_windows_cleanup_tree(&cleanup).unwrap();
        assert!(!cleanup.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_can_query_process_elevation() {
        windows_process_is_elevated().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn portable_update_policy_rejects_elevated_tokens_deterministically() {
        validate_windows_portable_update_elevation(false, "test staging").unwrap();
        let error = validate_windows_portable_update_elevation(true, "test staging").unwrap_err();
        assert!(format!("{error:#}").contains("signed native installer"));
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_tree_refuses_reparse_descendants_when_supported() {
        use std::os::windows::fs::symlink_file;

        let fixture = tempdir().unwrap();
        let root = fixture.path().join("stage");
        let outside = fixture.path().join("outside.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        let link = root.join("link.txt");
        match symlink_file(&outside, &link) {
            Ok(()) => {
                assert!(validate_windows_cleanup_tree(&root).is_err());
                assert_eq!(std::fs::read(outside).unwrap(), b"outside");
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows reparse fixture: {error}"),
        }
    }
}
