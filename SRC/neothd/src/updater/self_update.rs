//! Signed, integrity-checked self-update via GitHub Releases.
//!
//! The module resolves the host archive, bounds every download and extraction,
//! verifies SHA-256 plus minisign policy, stages unattended updates, and applies
//! operator-approved updates with backups. Release installations are updated as
//! one version-locked bundle: installed companion binaries are preflighted and
//! replaced before `neoth`, with reverse-order rollback on a partial failure.
//! Source-only installations keep their existing footprint.

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
    Ok(l > c)
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

/// Read the optional GitHub API token without ever logging or serializing it.
/// A configured non-Unicode value is rejected instead of silently falling back
/// to the anonymous rate limit while claiming authentication is active.
fn github_api_token() -> Result<Option<String>> {
    match std::env::var("GITHUB_TOKEN") {
        Ok(token) if token.trim().is_empty() => Ok(None),
        Ok(token) => Ok(Some(token.trim().to_string())),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("GITHUB_TOKEN is not valid Unicode")
        }
    }
}

/// Build one GitHub API GET. The optional bearer token raises the API rate
/// limit and supports private release feeds; it is sent only to the fixed
/// `api.github.com` URL assembled by the validated owner/repo call sites.
fn github_api_get(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = client
        .get(url)
        .header("Accept", "application/vnd.github+json");
    match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
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
        if selected.as_ref().is_none_or(|(best, _)| version > *best) {
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
    let token = github_api_token()?;
    let resp = github_api_get(&client, &url, token.as_deref())
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "GitHub release check failed: HTTP {} — {}",
            status,
            match status.as_u16() {
                403 => "rate-limited (set GITHUB_TOKEN env var to raise the limit)",
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
    let token = github_api_token()?;
    let resp = github_api_get(&client, &url, token.as_deref())
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
                403 => "rate-limited (set GITHUB_TOKEN env var to raise the limit)",
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
/// expose `TARGET` at runtime by default. Build-time injection
/// via `build.rs` would be more accurate (could disambiguate
/// `gnu` vs `msvc` on Windows, or `musl` vs `gnu` on Linux), but
/// cargo-dist's default release matrix matches our composed form
/// well enough for the common cases. Operator with an unusual
/// host overrides via `freedom.yaml::auto_update.target_triple`.
///
/// Returns `None` for hosts we don't have a cargo-dist mapping
/// for; the caller falls back to the manual-install path.
pub fn host_target_triple() -> Option<&'static str> {
    use std::env::consts::{ARCH, OS};
    match (OS, ARCH) {
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Some("aarch64-pc-windows-msvc"),
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

/// Extract a cargo-dist archive's `<binary>` member to `out_dir`.
/// Returns the full path of the extracted file.
///
/// The archive's tarball contains the binary at one of two
/// canonical locations:
///   - top-level: `neoth.exe` / `neoth`
///   - inside a target-named subdir: `neoth-x86_64-pc-windows-msvc/neoth.exe`
///
/// Both shapes are accepted. Anything else is rejected because
/// we have no way to know which member is the binary.
///
/// `binary` is the base name (e.g. `"neoth"`). The function adds
/// `.exe` on Windows automatically.
/// Hard ceiling on the size of any single extracted archive member /
/// decompressed tarball (GOLD-SEC-11 / A-29). The real `neothd` binary is
/// tens of MiB; 1 GiB is generous headroom while refusing a decompression
/// bomb (a tiny crafted archive that expands to many GiB). The SHA-256 /
/// minisig checks bind the bytes to the companion but say nothing about
/// decompressed size — this cap is the missing guard.
const MAX_EXTRACT_BYTES: u64 = 1024 * 1024 * 1024;

/// Download ceilings for the signed release payload and its small companions.
/// The archive contains all shipped binaries and can legitimately be large, but
/// an unbounded chunked response must never be allowed to exhaust daemon memory.
const MAX_RELEASE_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_PENDING_JSON_BYTES: usize = 64 * 1024;

/// A `Write` that errors once more than `limit` bytes are written. Bounds
/// the streaming xz output where there is no `Read::take` to cap.
struct LimitedWriter {
    buf: Vec<u8>,
    limit: u64,
}

impl std::io::Write for LimitedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() as u64 + data.len() as u64 > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed archive exceeds size cap (decompression-bomb guard)",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn extract_zip_binary(zip_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::{Cursor, Read};
    let reader = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open zip archive")?;
    let want = binary_filename_for_host(binary);
    let mut chosen: Option<usize> = None;
    for i in 0..archive.len() {
        let entry = archive.by_index(i).context("read zip entry")?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name();
        if name.ends_with(&format!("/{want}")) || name == want {
            chosen = Some(i);
            break;
        }
    }
    let index =
        chosen.ok_or_else(|| anyhow::anyhow!("zip archive missing expected member `{want}`"))?;
    let mut entry = archive
        .by_index(index)
        .context("re-open chosen zip entry")?;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create out_dir {}", out_dir.display()))?;
    let dest = out_dir.join(&want);
    let mut out =
        std::fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
    let written = std::io::copy(&mut (&mut entry).take(MAX_EXTRACT_BYTES + 1), &mut out)
        .context("copy zip body to disk")?;
    if written > MAX_EXTRACT_BYTES {
        let _ = std::fs::remove_file(&dest);
        anyhow::bail!(
            "zip member `{want}` exceeds the {MAX_EXTRACT_BYTES}-byte extraction cap (decompression-bomb guard)"
        );
    }
    set_executable_permissions(&dest)?;
    Ok(dest)
}

/// Extract a `.tar.xz` archive's `<binary>` member to `out_dir`.
/// Pure-Rust pipeline: lzma-rs decompresses xz → tar reads the
/// resulting tarball. No system liblzma linkage.
pub fn extract_tar_xz_binary(tar_xz_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::Cursor;
    let mut writer = LimitedWriter {
        buf: Vec::with_capacity(tar_xz_bytes.len().saturating_mul(3).min(64 * 1024 * 1024)),
        limit: MAX_EXTRACT_BYTES,
    };
    let mut reader = Cursor::new(tar_xz_bytes);
    lzma_rs::xz_decompress(&mut reader, &mut writer)
        .context("xz decompress tarball (or size cap exceeded — decompression-bomb guard)")?;
    extract_tar_binary_from_bytes(&writer.buf, out_dir, binary)
}

/// Extract a `.tar.gz` archive. Mirrors [`extract_tar_xz_binary`]
/// but pipes through flate2 instead of lzma-rs.
pub fn extract_tar_gz_binary(tar_gz_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut gz = GzDecoder::new(tar_gz_bytes);
    let mut decompressed: Vec<u8> = Vec::new();
    let n = gz
        .by_ref()
        .take(MAX_EXTRACT_BYTES + 1)
        .read_to_end(&mut decompressed)
        .context("gz decompress tarball")?;
    if n as u64 > MAX_EXTRACT_BYTES {
        anyhow::bail!(
            "gz tarball exceeds the {MAX_EXTRACT_BYTES}-byte extraction cap (decompression-bomb guard)"
        );
    }
    extract_tar_binary_from_bytes(&decompressed, out_dir, binary)
}

/// Walk a raw tar byte stream looking for the binary member.
/// Shared between the xz + gz paths.
fn extract_tar_binary_from_bytes(raw_tar: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::{Cursor, Read};
    let want = binary_filename_for_host(binary);
    let mut archive = tar::Archive::new(Cursor::new(raw_tar));
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create out_dir {}", out_dir.display()))?;
    let dest = out_dir.join(&want);
    for entry in archive.entries().context("iterate tar entries")? {
        let mut entry = entry.context("read tar entry")?;
        let path_in_tar = entry.path().context("read tar entry path")?.into_owned();
        let name = path_in_tar
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name == want && entry.header().entry_type().is_file() {
            let mut out = std::fs::File::create(&dest)
                .with_context(|| format!("create {}", dest.display()))?;
            let written = std::io::copy(&mut (&mut entry).take(MAX_EXTRACT_BYTES + 1), &mut out)
                .context("copy tar body to disk")?;
            if written > MAX_EXTRACT_BYTES {
                let _ = std::fs::remove_file(&dest);
                anyhow::bail!(
                    "tar member `{want}` exceeds the {MAX_EXTRACT_BYTES}-byte extraction cap (decompression-bomb guard)"
                );
            }
            set_executable_permissions(&dest)?;
            return Ok(dest);
        }
    }
    anyhow::bail!("tar archive missing expected member `{want}`")
}

/// Archive extraction writes a fresh file rather than preserving tar metadata.
/// Restore executable mode explicitly so a successful Unix self-update cannot
/// replace `neoth` with a non-runnable `0644` file.
fn set_executable_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(path)
            .with_context(|| format!("read permissions for {}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("mark {} executable", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Pick the host-appropriate binary filename. On Windows the
/// cargo-dist binary carries a `.exe` suffix; on Unix it's bare.
fn binary_filename_for_host(binary: &str) -> String {
    if std::env::consts::EXE_SUFFIX.is_empty() {
        binary.to_string()
    } else {
        format!("{binary}{}", std::env::consts::EXE_SUFFIX)
    }
}

/// Atomic rename of `new_path` onto `target_path`.
///
/// Strategy:
///   1. Move existing `target_path` → `<target>.bak.<unix_ms>` so
///      a rollback is one rename away.
///   2. Rename `new_path` → `target_path`.
///   3. Best-effort delete the `.bak` only on Unix; Windows keeps
///      the `.bak` since the running daemon may still have a
///      handle to it (the OS releases the handle on next start,
///      and `neoth update --self --gc-backups` can sweep later).
///
/// Both renames are `std::fs::rename`, which on POSIX is atomic
/// inside the same filesystem and on Windows uses
/// `ReplaceFileW` semantics via the std impl. Caller MUST ensure
/// `new_path` lives on the same volume as `target_path`
/// (e.g. by using a tempdir under the target's parent).
pub fn atomic_replace_binary(new_path: &Path, target_path: &Path) -> Result<PathBuf> {
    let now_ms = crate::time::now_unix_ms_u128();
    let bak_path = backup_path_for(target_path, now_ms);
    if target_path.exists() {
        std::fs::rename(target_path, &bak_path).with_context(|| {
            format!("rename {} → {}", target_path.display(), bak_path.display())
        })?;
    }
    if let Err(e) = std::fs::rename(new_path, target_path) {
        // Best-effort rollback: put the original back before
        // surfacing the error.
        if bak_path.exists() {
            let _ = std::fs::rename(&bak_path, target_path);
        }
        return Err(anyhow::anyhow!(
            "rename {} → {} failed: {e}",
            new_path.display(),
            target_path.display()
        ));
    }
    Ok(bak_path)
}

/// Compute the rollback path for `target` at timestamp `now_ms`.
/// Pure — used by [`atomic_replace_binary`] + the test suite.
pub fn backup_path_for(target: &Path, now_ms: u128) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(&format!(".bak.{now_ms}"));
    target.with_file_name(name)
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
    pub backup_path: PathBuf,
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

/// Pure-bytes-in orchestrator. Network-free so the unit suite
/// can exercise the full apply path without HTTP mocking.
///
/// Steps:
///   1. parse the SHA-256 companion text
///   2. verify `asset_bytes` against it
///   3. select the extractor by archive format
///   4. extract the binary into a tmpdir living under
///      `install_dir.parent()` so the rename is same-volume
///   5. atomic-replace onto `install_dir.join(<binary>)`
fn extract_archive_binary(
    asset_bytes: &[u8],
    format: ArchiveFormat,
    stage_dir: &Path,
    binary: &str,
) -> Result<PathBuf> {
    match format {
        ArchiveFormat::Zip => extract_zip_binary(asset_bytes, stage_dir, binary),
        ArchiveFormat::TarXz => extract_tar_xz_binary(asset_bytes, stage_dir, binary),
        ArchiveFormat::TarGz => extract_tar_gz_binary(asset_bytes, stage_dir, binary),
    }
}

pub fn apply_downloaded(
    asset_bytes: &[u8],
    companion_text: &str,
    format: ArchiveFormat,
    binary: &str,
    install_dir: &Path,
) -> Result<PathBuf> {
    let expected = parse_sha256_companion(companion_text).context("parse sha256 companion")?;
    verify_sha256_bytes(asset_bytes, &expected).context("verify asset sha256")?;

    // Stage the extracted binary in a tempdir that lives next to
    // the install dir so the final rename is same-volume (atomic
    // on POSIX, ReplaceFileW-semantics on Windows).
    let stage_parent = install_dir.parent().unwrap_or(install_dir);
    let stage = tempfile::tempdir_in(stage_parent)
        .with_context(|| format!("stage tempdir under {}", stage_parent.display()))?;

    let extracted = extract_archive_binary(asset_bytes, format, stage.path(), binary)?;

    let target = install_dir.join(binary_filename_for_host(binary));
    let backup = atomic_replace_binary(&extracted, &target)?;
    // tempdir drops here; the extracted file already moved out
    // via atomic_replace_binary, so the directory is empty +
    // safe to clean.
    Ok(backup)
}

/// Release archives are a version-locked bundle. Preserve a source-only
/// installation's footprint, but whenever one of the shipped companions is
/// installed beside `neoth`, update it from the same verified archive too.
/// The public binary is replaced last and acts as the transaction commit point.
const SELF_UPDATE_COMPANIONS: [&str; 5] = [
    "neothd",
    "neothd-gui",
    "neoth-migrate",
    "neoth-relay",
    "neoth-keet-bridge",
];

#[derive(Debug)]
struct StagedBundleMember {
    binary: String,
    staged_path: PathBuf,
    target_path: PathBuf,
}

#[derive(Debug)]
struct AppliedBundleMember {
    target_path: PathBuf,
    backup_path: PathBuf,
    had_original: bool,
}

fn installed_bundle_members(primary: &str, install_dir: &Path) -> Vec<String> {
    if primary != "neoth" {
        return vec![primary.to_string()];
    }

    let mut members = SELF_UPDATE_COMPANIONS
        .iter()
        .filter(|binary| install_dir.join(binary_filename_for_host(binary)).exists())
        .map(|binary| (*binary).to_string())
        .collect::<Vec<_>>();
    // Replace the process-owning binary last. If any earlier member fails, the
    // currently running version remains the visible bundle version.
    members.push(primary.to_string());
    members
}

/// Apply the verified release archive to every NEOTH binary currently present
/// in the installation. All required members are extracted before the first
/// target is touched. If a later replacement fails, already-replaced
/// companions are rolled back in reverse order.
pub fn apply_downloaded_bundle(
    asset_bytes: &[u8],
    companion_text: &str,
    format: ArchiveFormat,
    primary: &str,
    install_dir: &Path,
) -> Result<PathBuf> {
    let expected = parse_sha256_companion(companion_text).context("parse sha256 companion")?;
    verify_sha256_bytes(asset_bytes, &expected).context("verify asset sha256")?;

    let stage_parent = install_dir.parent().unwrap_or(install_dir);
    let stage = tempfile::tempdir_in(stage_parent)
        .with_context(|| format!("stage bundle tempdir under {}", stage_parent.display()))?;
    let members = installed_bundle_members(primary, install_dir);
    let mut staged = Vec::with_capacity(members.len());

    // Complete preflight: every installed companion must exist in the exact
    // archive before any on-disk executable is moved.
    for binary in members {
        let target_path = install_dir.join(binary_filename_for_host(&binary));
        if target_path.exists() && !target_path.is_file() {
            anyhow::bail!(
                "self-update target {} exists but is not a regular file",
                target_path.display()
            );
        }
        let staged_path = extract_archive_binary(asset_bytes, format, stage.path(), &binary)
            .with_context(|| {
                format!(
                    "release bundle is missing installed component `{binary}`; no files were changed"
                )
            })?;
        staged.push(StagedBundleMember {
            binary,
            staged_path,
            target_path,
        });
    }

    replace_staged_bundle_with(&staged, primary, atomic_replace_binary)
}

fn replace_staged_bundle_with<F>(
    staged: &[StagedBundleMember],
    primary: &str,
    mut replace: F,
) -> Result<PathBuf>
where
    F: FnMut(&Path, &Path) -> Result<PathBuf>,
{
    let mut applied = Vec::with_capacity(staged.len());
    let mut primary_backup = None;

    for member in staged {
        let had_original = member.target_path.exists();
        match replace(&member.staged_path, &member.target_path) {
            Ok(backup_path) => {
                if member.binary == primary {
                    primary_backup = Some(backup_path.clone());
                } else {
                    info!(
                        component = %member.binary,
                        backup = %backup_path.display(),
                        "self-update: installed companion from version-locked release bundle"
                    );
                }
                applied.push(AppliedBundleMember {
                    target_path: member.target_path.clone(),
                    backup_path,
                    had_original,
                });
            }
            Err(error) => {
                let rollback = rollback_applied_bundle(&applied);
                return match rollback {
                    Ok(()) => Err(error.context(format!(
                        "replace release-bundle component `{}` failed; earlier replacements were rolled back",
                        member.binary
                    ))),
                    Err(rollback_error) => Err(error.context(format!(
                        "replace release-bundle component `{}` failed; rollback was incomplete: {rollback_error:#}",
                        member.binary
                    ))),
                };
            }
        }
    }

    primary_backup.ok_or_else(|| {
        anyhow::anyhow!("release-bundle apply did not include primary binary `{primary}`")
    })
}

fn rollback_applied_bundle(applied: &[AppliedBundleMember]) -> Result<()> {
    let mut failures = Vec::new();
    for member in applied.iter().rev() {
        let mut displaced = member.target_path.clone();
        let displaced_name = format!(
            "{}.failed-update-rollback.{}",
            member
                .target_path
                .file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default(),
            crate::time::now_unix_ms_u128()
        );
        displaced.set_file_name(displaced_name);

        if member.target_path.exists()
            && let Err(error) = std::fs::rename(&member.target_path, &displaced)
        {
            failures.push(format!(
                "move new {} aside: {error}",
                member.target_path.display()
            ));
            continue;
        }

        let mut prior_state_restored = !member.had_original;
        if member.had_original {
            if !member.backup_path.exists() {
                failures.push(format!(
                    "backup {} disappeared",
                    member.backup_path.display()
                ));
            } else if let Err(error) = std::fs::rename(&member.backup_path, &member.target_path) {
                failures.push(format!("restore {}: {error}", member.target_path.display()));
            } else {
                prior_state_restored = true;
            }
        }

        if prior_state_restored && displaced.exists() {
            if let Err(error) = std::fs::remove_file(&displaced) {
                warn!(
                    path = %displaced.display(),
                    error = %error,
                    "self-update rollback restored the prior target but could not remove the displaced candidate"
                );
            }
        } else if displaced.exists() {
            warn!(
                path = %displaced.display(),
                "self-update rollback could not restore the prior target; retained the displaced candidate for manual recovery"
            );
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
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

/// Network-driven update flow. Wraps [`apply_downloaded_bundle`] with
/// HTTP fetches against the release's `browser_download_url`
/// fields. Returns Ok with the [`UpdateApplied`] envelope on
/// success, Err with a diagnostic when any step fails — the
/// daemon's existing binary is left untouched on failure (the
/// staging tempdir cleans up; `target` only mutates after the
/// final atomic_replace succeeds).
pub async fn apply_update(
    release: &LatestRelease,
    target_triple: &str,
    binary: &str,
    install_dir: &Path,
    require_signature: bool,
) -> Result<UpdateApplied> {
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
    // present-but-invalid sig still bails). Runs before apply_downloaded
    // so a failed verify never reaches `atomic_replace_binary`.
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
    let backup =
        apply_downloaded_bundle(&asset_bytes, &companion_text, format, binary, install_dir)?;
    // apply_downloaded_bundle already parsed + verified the companion, so this
    // re-parse cannot fail at this point; default to empty rather than
    // unwrap to keep a successful apply from ever panicking on audit.
    let archive_sha256 = parse_sha256_companion(&companion_text).unwrap_or_default();

    Ok(UpdateApplied {
        from_version: current_version().to_string(),
        to_version: release.tag_name.clone(),
        backup_path: backup,
        restart_required: true,
        archive_sha256,
        download_url,
        signature_status: sig_status.as_str().to_string(),
    })
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
    let body = read_file_bounded(
        &pending_json_path(stage_dir),
        MAX_PENDING_JSON_BYTES,
        "pending update record",
    )
    .ok()?;
    serde_json::from_slice(&body).ok()
}

fn read_file_bounded(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file =
        std::fs::File::open(path).with_context(|| format!("open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes as u64 {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte size cap");
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("read {label} {}", path.display()))?;
    if body.len() > max_bytes {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte size cap");
    }
    Ok(body)
}

fn validated_staged_path(
    stage_dir: &Path,
    recorded_path: &str,
    expected_name: &str,
    label: &str,
) -> Result<PathBuf> {
    let expected_leaf = Path::new(expected_name);
    if expected_leaf.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        anyhow::bail!("invalid staged {label} filename {expected_name:?}");
    }
    let recorded = PathBuf::from(recorded_path);
    if std::fs::symlink_metadata(&recorded)
        .with_context(|| format!("inspect staged {label} {}", recorded.display()))?
        .file_type()
        .is_symlink()
    {
        anyhow::bail!("staged {label} must not be a symlink");
    }
    let canonical_stage = std::fs::canonicalize(stage_dir)
        .with_context(|| format!("canonicalize stage dir {}", stage_dir.display()))?;
    let canonical_recorded = std::fs::canonicalize(&recorded)
        .with_context(|| format!("canonicalize staged {label} {}", recorded.display()))?;
    let canonical_expected = std::fs::canonicalize(stage_dir.join(expected_name))
        .with_context(|| format!("canonicalize expected staged {label} {expected_name}"))?;
    if canonical_recorded != canonical_expected
        || canonical_recorded.parent() != Some(canonical_stage.as_path())
    {
        anyhow::bail!(
            "staged {label} path {} is outside the exact stage slot {}",
            recorded.display(),
            stage_dir.join(expected_name).display()
        );
    }
    Ok(canonical_recorded)
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
) -> Result<UpdateApplied> {
    parse_semver_version(&pending.to_version).map_err(|error| {
        IntegrityViolation(format!("invalid staged release version: {error:#}"))
    })?;
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
    let archive = validated_staged_path(
        stage_dir,
        &pending.staged_archive,
        &expected_asset,
        "archive",
    )
    .map_err(|error| IntegrityViolation(format!("staged archive path: {error:#}")))?;
    let bytes = read_file_bounded(&archive, MAX_RELEASE_ARCHIVE_BYTES, "staged archive")
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
            let signature_path =
                validated_staged_path(stage_dir, sig_path, &expected_signature, "minisig")
                    .map_err(|error| {
                        IntegrityViolation(format!("staged minisig path: {error:#}"))
                    })?;
            let signature_bytes =
                read_file_bounded(&signature_path, MAX_SIGNATURE_BYTES, "staged minisig").map_err(
                    |error| IntegrityViolation(format!("staged minisig read: {error:#}")),
                )?;
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
    // audit) rather than silently downloading a fresh copy. `apply_downloaded`
    // re-checks internally too (defence in depth); this typed pre-check fires
    // first so the failure is classifiable.
    verify_sha256_bytes(&bytes, &pending.archive_sha256)
        .map_err(|e| IntegrityViolation(format!("staged sha256 verify failed: {e:#}")))?;
    let companion_text = format!("{}  staged\n", pending.archive_sha256);
    let format = archive_format_for_target(&pending.target_triple);
    // Update every installed release companion from the exact same verified
    // archive. A source-only core installation remains core-only.
    let backup = apply_downloaded_bundle(&bytes, &companion_text, format, "neoth", install_dir)
        .context("apply staged archive")?;
    Ok(UpdateApplied {
        from_version: current_version().to_string(),
        to_version: pending.to_version.clone(),
        backup_path: backup,
        restart_required: true,
        archive_sha256: pending.archive_sha256.clone(),
        download_url: pending.download_url.clone(),
        signature_status: sig_status.as_str().to_string(),
    })
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

/// MV-01b #5 — STAGE (do NOT swap) a newer release: fetch the archive +
/// `.sha256` + `.minisig`, verify both (signature gated by
/// `require_signature`), write the raw archive into `stage_dir`, and
/// drop a `pending.json` record. Returns the [`PendingUpdate`].
///
/// Deliberately stops BEFORE extract/`atomic_replace_binary` — the
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

    std::fs::create_dir_all(stage_dir)
        .with_context(|| format!("create stage dir {}", stage_dir.display()))?;
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
    fn github_api_request_wires_optional_token_without_network_io() {
        let client = reqwest::Client::new();
        let authenticated = github_api_get(
            &client,
            "https://api.github.com/repos/owner/repo/releases/latest",
            Some("test-token"),
        )
        .build()
        .unwrap();
        assert_eq!(
            authenticated
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer test-token"
        );
        assert_eq!(
            authenticated
                .headers()
                .get(reqwest::header::ACCEPT)
                .unwrap(),
            "application/vnd.github+json"
        );

        let anonymous = github_api_get(
            &client,
            "https://api.github.com/repos/owner/repo/releases/latest",
            None,
        )
        .build()
        .unwrap();
        assert!(
            anonymous
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
        let zip_bytes = make_zip_with_member(&want, b"staged-daemon");
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
        std::fs::write(install_dir.join(&want), b"old-daemon").unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            source_repo: "The-Geek-Freaks/NEOTH".into(),
            channel: ReleaseChannel::Stable,
            archive_sha256: digest,
            download_url: format!("https://example.com/{asset_name}"),
            signature_status: "verified".into(),
            staged_archive: staged_archive.display().to_string(),
            staged_signature: None,
            target_triple: "x86_64-pc-windows-msvc".into(),
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
        assert_eq!(outcome.to_version, "v9.9.9");
        assert_eq!(outcome.signature_status, "no_pinned_key");
        assert_eq!(
            std::fs::read(install_dir.join(&want)).unwrap(),
            b"staged-daemon"
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

    // ── Extractor + atomic-replace coverage ─────────────────────────

    /// Build an in-memory ZIP archive containing one member with
    /// the requested name + body.
    fn make_zip_with_member(name: &str, body: &[u8]) -> Vec<u8> {
        make_zip_with_members(&[(name, body)])
    }

    fn make_zip_with_members(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Cursor;
        use std::io::Write;
        let mut out: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut out);
            let mut writer = zip::ZipWriter::new(cursor);
            for (name, body) in members {
                writer
                    .start_file::<_, ()>(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(body).unwrap();
            }
            writer.finish().unwrap();
        }
        out
    }

    /// Build an in-memory `.tar.gz` archive containing one
    /// member with the requested name + body.
    fn make_tar_gz_with_member(name: &str, body: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let mut tb = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tb.append(&header, body).unwrap();
            tb.finish().unwrap();
        }
        let mut out: Vec<u8> = Vec::new();
        let mut gz = GzEncoder::new(&mut out, Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap();
        out
    }

    #[test]
    fn extract_zip_binary_finds_top_level_member() {
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"daemon-bytes-go-here");
        let dir = tempdir().unwrap();
        let dest = extract_zip_binary(&zip_bytes, dir.path(), "neoth").unwrap();
        assert_eq!(dest, dir.path().join(&want));
        let written = std::fs::read(&dest).unwrap();
        assert_eq!(written, b"daemon-bytes-go-here");
    }

    #[cfg(unix)]
    #[test]
    fn extracted_binary_is_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;

        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"daemon");
        let dir = tempdir().unwrap();
        let dest = extract_zip_binary(&zip_bytes, dir.path(), "neoth").unwrap();
        assert_ne!(
            std::fs::metadata(dest).unwrap().permissions().mode() & 0o111,
            0,
            "self-updated binary must remain runnable"
        );
    }

    #[test]
    fn extract_zip_binary_finds_nested_member() {
        // cargo-dist tarballs nest the binary under a target-
        // named subdir. Mirror that shape.
        let want = binary_filename_for_host("neoth");
        let nested_name = format!("neoth-x86_64-pc-windows-msvc/{want}");
        let zip_bytes = make_zip_with_member(&nested_name, b"nested-bytes");
        let dir = tempdir().unwrap();
        let dest = extract_zip_binary(&zip_bytes, dir.path(), "neoth").unwrap();
        // The output filename strips the subdir — we always
        // land the binary directly under out_dir.
        assert_eq!(dest, dir.path().join(&want));
        assert_eq!(std::fs::read(&dest).unwrap(), b"nested-bytes");
    }

    #[test]
    fn extract_zip_binary_errors_when_member_missing() {
        let zip_bytes = make_zip_with_member("README.md", b"only a readme");
        let dir = tempdir().unwrap();
        let err = extract_zip_binary(&zip_bytes, dir.path(), "neoth")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing"),
            "diagnostic must say missing: {err}"
        );
    }

    #[test]
    fn extract_tar_gz_binary_round_trips() {
        let want = binary_filename_for_host("neoth");
        let tar_gz = make_tar_gz_with_member(&want, b"gz-bytes");
        let dir = tempdir().unwrap();
        let dest = extract_tar_gz_binary(&tar_gz, dir.path(), "neoth").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"gz-bytes");
    }

    #[test]
    fn extract_tar_gz_binary_finds_nested_member() {
        let want = binary_filename_for_host("neoth");
        let nested = format!("neoth-x86_64-unknown-linux-gnu/{want}");
        let tar_gz = make_tar_gz_with_member(&nested, b"nested-gz");
        let dir = tempdir().unwrap();
        let dest = extract_tar_gz_binary(&tar_gz, dir.path(), "neoth").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"nested-gz");
    }

    #[test]
    fn extract_tar_gz_binary_errors_when_member_missing() {
        let tar_gz = make_tar_gz_with_member("LICENSE", b"only license");
        let dir = tempdir().unwrap();
        assert!(extract_tar_gz_binary(&tar_gz, dir.path(), "neoth").is_err());
    }

    #[test]
    fn binary_filename_for_host_carries_exe_suffix_on_windows() {
        let name = binary_filename_for_host("neoth");
        if std::env::consts::EXE_SUFFIX.is_empty() {
            assert_eq!(name, "neoth");
        } else {
            assert!(name.ends_with(std::env::consts::EXE_SUFFIX));
            assert!(name.starts_with("neoth"));
        }
    }

    #[test]
    fn backup_path_for_appends_unix_ms_suffix() {
        let bak = backup_path_for(Path::new("/usr/local/bin/neoth"), 1_716_000_000_000);
        assert_eq!(bak, PathBuf::from("/usr/local/bin/neoth.bak.1716000000000"));
    }

    #[test]
    fn backup_path_for_handles_relative_target() {
        let bak = backup_path_for(Path::new("neoth.exe"), 7);
        assert_eq!(bak, PathBuf::from("neoth.exe.bak.7"));
    }

    #[test]
    fn atomic_replace_binary_moves_new_into_place_and_backs_up_old() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("neoth.bin");
        let new_path = dir.path().join("neoth.new");
        std::fs::write(&target, b"old-daemon").unwrap();
        std::fs::write(&new_path, b"new-daemon").unwrap();

        let bak = atomic_replace_binary(&new_path, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new-daemon");
        assert!(bak.exists(), "backup must exist at {}", bak.display());
        assert_eq!(std::fs::read(&bak).unwrap(), b"old-daemon");
        assert!(!new_path.exists(), "new_path must be renamed away");
    }

    // ── Downloaded-archive apply coverage ───────────────────────────

    #[test]
    fn apply_downloaded_replaces_binary_when_archive_and_digest_match() {
        // Build a zip containing the host's binary name, take its
        // SHA-256, run the full apply_downloaded path, assert the
        // target file ends up with the expected bytes.
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"shiny-new-daemon");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());
        let companion_text = format!("{digest}  neoth.zip\n");

        let dir = tempdir().unwrap();
        let target = dir.path().join(&want);
        std::fs::write(&target, b"old-daemon").unwrap();

        let backup = apply_downloaded(
            &zip_bytes,
            &companion_text,
            ArchiveFormat::Zip,
            "neoth",
            dir.path(),
        )
        .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"shiny-new-daemon");
        assert!(
            backup.exists(),
            "old binary preserved at {}",
            backup.display()
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"old-daemon");
    }

    #[test]
    fn apply_downloaded_bundle_updates_every_installed_component() {
        let binaries: [(&str, &[u8], &[u8]); 6] = [
            ("neothd", b"new-compat", b"old-compat"),
            ("neothd-gui", b"new-gui", b"old-gui"),
            ("neoth-migrate", b"new-migrate", b"old-migrate"),
            ("neoth-relay", b"new-relay", b"old-relay"),
            ("neoth-keet-bridge", b"new-keet", b"old-keet"),
            ("neoth", b"new-core", b"old-core"),
        ];
        let names = binaries
            .iter()
            .map(|(binary, _, _)| binary_filename_for_host(binary))
            .collect::<Vec<_>>();
        let members = names
            .iter()
            .zip(binaries.iter())
            .map(|(name, (_, new_body, _))| (name.as_str(), *new_body))
            .collect::<Vec<_>>();
        let zip_bytes = make_zip_with_members(&members);
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());

        let dir = tempdir().unwrap();
        for (name, (_, _, old_body)) in names.iter().zip(binaries.iter()) {
            std::fs::write(dir.path().join(name), *old_body).unwrap();
        }

        let primary_backup =
            apply_downloaded_bundle(&zip_bytes, &digest, ArchiveFormat::Zip, "neoth", dir.path())
                .unwrap();

        for (name, (_, new_body, _)) in names.iter().zip(binaries.iter()) {
            assert_eq!(std::fs::read(dir.path().join(name)).unwrap(), *new_body);
        }
        assert_eq!(std::fs::read(primary_backup).unwrap(), b"old-core");
    }

    #[test]
    fn apply_downloaded_bundle_preflights_all_members_before_mutating() {
        let core = binary_filename_for_host("neoth");
        let gui = binary_filename_for_host("neothd-gui");
        let zip_bytes = make_zip_with_member(&core, b"new-core");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());

        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(&core), b"old-core").unwrap();
        std::fs::write(dir.path().join(&gui), b"old-gui").unwrap();

        let error =
            apply_downloaded_bundle(&zip_bytes, &digest, ArchiveFormat::Zip, "neoth", dir.path())
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("neothd-gui"),
            "missing installed companion must be named"
        );
        assert_eq!(std::fs::read(dir.path().join(core)).unwrap(), b"old-core");
        assert_eq!(std::fs::read(dir.path().join(gui)).unwrap(), b"old-gui");
    }

    #[test]
    fn bundle_replace_rolls_back_prior_component_on_late_failure() {
        let dir = tempdir().unwrap();
        let compat_target = dir.path().join(binary_filename_for_host("neothd"));
        let core_target = dir.path().join(binary_filename_for_host("neoth"));
        let compat_staged = dir.path().join("compat.new");
        let core_staged = dir.path().join("core.new");
        std::fs::write(&compat_target, b"old-compat").unwrap();
        std::fs::write(&core_target, b"old-core").unwrap();
        std::fs::write(&compat_staged, b"new-compat").unwrap();
        std::fs::write(&core_staged, b"new-core").unwrap();
        let staged = vec![
            StagedBundleMember {
                binary: "neothd".into(),
                staged_path: compat_staged,
                target_path: compat_target.clone(),
            },
            StagedBundleMember {
                binary: "neoth".into(),
                staged_path: core_staged,
                target_path: core_target.clone(),
            },
        ];
        let mut calls = 0;
        let error = replace_staged_bundle_with(&staged, "neoth", |new_path, target_path| {
            calls += 1;
            if calls == 2 {
                anyhow::bail!("injected primary replacement failure");
            }
            atomic_replace_binary(new_path, target_path)
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("rolled back"));
        assert_eq!(std::fs::read(compat_target).unwrap(), b"old-compat");
        assert_eq!(std::fs::read(core_target).unwrap(), b"old-core");
    }

    #[test]
    fn apply_downloaded_refuses_when_sha256_mismatches() {
        let want = binary_filename_for_host("neoth");
        let zip_bytes = make_zip_with_member(&want, b"good-payload");
        // Wrong digest — payload changed somewhere in transit.
        let bogus_digest = "0".repeat(64);
        let companion_text = format!("{bogus_digest}  neoth.zip\n");

        let dir = tempdir().unwrap();
        let target = dir.path().join(&want);
        std::fs::write(&target, b"unchanged-daemon").unwrap();

        let err = apply_downloaded(
            &zip_bytes,
            &companion_text,
            ArchiveFormat::Zip,
            "neoth",
            dir.path(),
        )
        .unwrap_err();
        // anyhow Display shows only the top-level context; the
        // full chain ({:#}) carries the underlying "sha256
        // mismatch" diagnostic.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("sha256 mismatch"),
            "full error chain must label mismatch: {chain}"
        );

        // Target file MUST be untouched on verify failure — a
        // sha256-failing update never gets close to the binary.
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged-daemon");
    }

    #[test]
    fn apply_downloaded_works_for_tar_gz_format() {
        // Pin the same end-to-end shape for the Linux/macOS path
        // via tar.gz (tar.xz would also work but lzma-rs writers
        // aren't part of the crate; xz round-trip is exercised
        // implicitly via real release tarballs).
        let want = binary_filename_for_host("neoth");
        let tar_gz = make_tar_gz_with_member(&want, b"unix-daemon");
        let mut hasher = Sha256::new();
        hasher.update(&tar_gz);
        let digest = hex_encode(&hasher.finalize());
        let companion_text = digest.clone();

        let dir = tempdir().unwrap();
        let target = dir.path().join(&want);

        let backup = apply_downloaded(
            &tar_gz,
            &companion_text,
            ArchiveFormat::TarGz,
            "neoth",
            dir.path(),
        )
        .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"unix-daemon");
        // First install — no prior file to back up.
        assert!(!backup.exists());
    }

    #[test]
    fn atomic_replace_binary_works_when_target_does_not_exist_yet() {
        // First-install path — no prior binary to back up.
        let dir = tempdir().unwrap();
        let target = dir.path().join("neoth.bin");
        let new_path = dir.path().join("neoth.new");
        std::fs::write(&new_path, b"fresh-install").unwrap();

        let bak = atomic_replace_binary(&new_path, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"fresh-install");
        // bak path is the expected name even though no file was
        // moved there.
        assert!(bak.to_string_lossy().contains(".bak."));
        assert!(!bak.exists(), "no backup file when target was missing");
    }
}
