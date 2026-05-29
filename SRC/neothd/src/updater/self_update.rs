//! V03-09 — daemon self-update check via GitHub Releases API.
//!
//! The parent `updater` module covers operator-installed CLIs
//! (claude-cli, antigravity-cli, codex). This sub-module is the
//! deferred-V2 counterpart for the daemon binary itself.
//!
//! Phase 1 (this commit, 2026-05-20): the *check* path only.
//! `neoth update --check` calls GitHub's `releases/latest` endpoint
//! and reports whether a newer version is published. The actual
//! download + replace dance (Phase 2) lands once the binary
//! distribution channel settles — for now the operator clicks the
//! published release URL and installs manually.
//!
//! Pure-logic helpers (semver parse, version-is-newer compare) live
//! here too so unit tests can exercise the comparison without
//! touching the network.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

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

/// Parse a semver string into `(major, minor, patch)`. Accepts a
/// leading `v`/`V` (GitHub release tags conventionally start with
/// it). Pre-release / build metadata after `-` or `+` is ignored —
/// comparison runs on the major.minor.patch triple only.
pub fn parse_semver(s: &str) -> Result<(u32, u32, u32)> {
    let trimmed = s.trim().trim_start_matches(['v', 'V']);
    let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("expected major.minor.patch, got {s:?}");
    }
    let major: u32 = parts[0]
        .parse()
        .with_context(|| format!("major component {s:?}"))?;
    let minor: u32 = parts[1]
        .parse()
        .with_context(|| format!("minor component {s:?}"))?;
    let patch: u32 = parts[2]
        .parse()
        .with_context(|| format!("patch component {s:?}"))?;
    Ok((major, minor, patch))
}

/// Returns true when `latest` strictly compares greater than
/// `current` on the (major, minor, patch) triple. Equal versions
/// return false — the operator is already on the latest. Unparseable
/// inputs surface as `Err`, NOT as false (silent miss).
pub fn version_is_newer(latest: &str, current: &str) -> Result<bool> {
    let l = parse_semver(latest)?;
    let c = parse_semver(current)?;
    Ok(l > c)
}

/// Fetch the latest release from GitHub. `owner_repo` is the
/// `owner/repo` slug, e.g. `"The-Geek-Freaks/NEOTH"`.
///
/// User-Agent is required by GitHub; we pin
/// `"NEOTH/{version} (update-check)"` so a server-side audit can
/// distinguish update-check traffic from other reqwest callers.
pub async fn fetch_latest_release(owner_repo: &str) -> Result<LatestRelease> {
    let url = format!("https://api.github.com/repos/{owner_repo}/releases/latest");
    let ua = format!("NEOTH/{} (update-check)", current_version());
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .build()
        .context("build update-check reqwest client")?;
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
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

/// Top-level update check. Wraps `fetch_latest_release` + version
/// comparison into one operator-facing call. The CLI renders the
/// `UpdateCheck` in table form; `--output json` re-emits the same
/// shape via serde.
pub async fn check_for_update(owner_repo: &str) -> Result<UpdateCheck> {
    let release = fetch_latest_release(owner_repo).await?;
    let needs = version_is_newer(&release.tag_name, current_version()).unwrap_or(false);
    Ok(UpdateCheck {
        current: current_version().to_string(),
        latest: release.tag_name,
        needs_update: needs,
        release_url: release.html_url,
        published_at: release.published_at,
    })
}

// ── Phase 2a (2026-05-21): asset-locator layer for download+apply ──
//
// Phase 1 (2026-05-20) shipped the *check* path: the operator runs
// `neoth update --self` and the daemon reports whether a newer
// release exists. Operators still apply the update by clicking the
// `html_url` and running the installer manually.
//
// Phase 2a (this commit) closes the asset-location half of the
// download+apply dance. Pure-logic helpers — no IO. Given a target
// triple + a `LatestRelease`, the helpers tell the caller:
//
//   - which asset to download (`find_matching_asset`)
//   - what URL it lives at (`browser_download_url` on the matched asset)
//   - which archive format it uses (`archive_format_for_target`)
//   - what the expected SHA-256 companion file is named
//     (`sha256_companion_name`)
//
// The remaining Phase 2b ships the IO half: streaming the asset
// to a temp file, verifying the SHA-256 against the companion,
// extracting the inner binary, atomic-renaming onto the running
// daemon path. That commit needs the operator-facing
// `freedom.yaml::auto_update.{auto_apply,channel}` knobs Codex
// flagged in the Round-3 review.

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

/// Build the canonical asset filename for a binary + target, matching
/// the format the release workflow produces. The base shape is
/// `<binary>-<target>.<archive>`. Examples:
///
///   neothd-x86_64-pc-windows-msvc.zip
///   neothd-x86_64-unknown-linux-gnu.tar.gz
///   neothd-aarch64-apple-darwin.tar.gz
///
/// Used only in the error message of `resolve_update_assets` — the live
/// match path goes through [`find_matching_asset`], which is tolerant of
/// version prefixes (so `neothd-v0.2.1-<target>.tar.gz` matches too).
pub fn expected_asset_name(binary: &str, target: &str) -> String {
    let fmt = archive_format_for_target(target);
    format!("{binary}-{target}{ext}", ext = fmt.extension())
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
/// Match strategy: exact substring on the target triple, then
/// exact extension match against
/// [`archive_format_for_target`]. Both gates must pass; a
/// `.zip` named for a Linux target is rejected (operator error
/// or upload mix-up).
pub fn find_matching_asset<'a>(
    assets: &'a [ReleaseAsset],
    target: &str,
) -> Option<&'a ReleaseAsset> {
    let want_ext = archive_format_for_target(target).extension();
    assets
        .iter()
        .find(|a| a.name.contains(target) && a.name.ends_with(want_ext))
}

/// Locate the SHA-256 companion asset for a given binary asset.
/// `None` when the release didn't publish a companion — Phase 2b
/// MUST refuse to apply an update in that case (no checksum =
/// no integrity = treat as untrusted).
pub fn find_sha256_companion<'a>(
    assets: &'a [ReleaseAsset],
    binary_asset: &ReleaseAsset,
) -> Option<&'a ReleaseAsset> {
    let want = sha256_companion_name(&binary_asset.name);
    assets.iter().find(|a| a.name == want)
}

/// Operator-facing decision shape for the asset-locator pass.
/// Phase 2b's `apply_update` consumes this; the CLI's
/// `neoth update --self --dry-run` (also Phase 2b) renders it.
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
pub fn extract_zip_binary(zip_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::Cursor;
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
    std::io::copy(&mut entry, &mut out).context("copy zip body to disk")?;
    Ok(dest)
}

/// Extract a `.tar.xz` archive's `<binary>` member to `out_dir`.
/// Pure-Rust pipeline: lzma-rs decompresses xz → tar reads the
/// resulting tarball. No system liblzma linkage.
pub fn extract_tar_xz_binary(tar_xz_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::Cursor;
    let mut decompressed: Vec<u8> = Vec::with_capacity(tar_xz_bytes.len() * 3);
    let mut reader = Cursor::new(tar_xz_bytes);
    lzma_rs::xz_decompress(&mut reader, &mut decompressed).context("xz decompress tarball")?;
    extract_tar_binary_from_bytes(&decompressed, out_dir, binary)
}

/// Extract a `.tar.gz` archive. Mirrors [`extract_tar_xz_binary`]
/// but pipes through flate2 instead of lzma-rs.
pub fn extract_tar_gz_binary(tar_gz_bytes: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut gz = GzDecoder::new(tar_gz_bytes);
    let mut decompressed: Vec<u8> = Vec::with_capacity(tar_gz_bytes.len() * 3);
    gz.read_to_end(&mut decompressed)
        .context("gz decompress tarball")?;
    extract_tar_binary_from_bytes(&decompressed, out_dir, binary)
}

/// Walk a raw tar byte stream looking for the binary member.
/// Shared between the xz + gz paths.
fn extract_tar_binary_from_bytes(raw_tar: &[u8], out_dir: &Path, binary: &str) -> Result<PathBuf> {
    use std::io::Cursor;
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
        if name == want {
            let mut out = std::fs::File::create(&dest)
                .with_context(|| format!("create {}", dest.display()))?;
            std::io::copy(&mut entry, &mut out).context("copy tar body to disk")?;
            return Ok(dest);
        }
    }
    anyhow::bail!("tar archive missing expected member `{want}`")
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
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
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

    let extracted = match format {
        ArchiveFormat::Zip => extract_zip_binary(asset_bytes, stage.path(), binary)?,
        ArchiveFormat::TarXz => extract_tar_xz_binary(asset_bytes, stage.path(), binary)?,
        ArchiveFormat::TarGz => extract_tar_gz_binary(asset_bytes, stage.path(), binary)?,
    };

    let target = install_dir.join(binary_filename_for_host(binary));
    let backup = atomic_replace_binary(&extracted, &target)?;
    // tempdir drops here; the extracted file already moved out
    // via atomic_replace_binary, so the directory is empty +
    // safe to clean.
    Ok(backup)
}

/// Network-driven update flow. Wraps `apply_downloaded` with
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

    let companion_text = client
        .get(&companion.browser_download_url)
        .send()
        .await
        .with_context(|| format!("GET {}", companion.browser_download_url))?
        .error_for_status()
        .context("fetch sha256 companion")?
        .text()
        .await
        .context("read sha256 companion body")?;

    let asset_bytes = client
        .get(&assets.binary.browser_download_url)
        .send()
        .await
        .with_context(|| format!("GET {}", assets.binary.browser_download_url))?
        .error_for_status()
        .context("fetch binary asset")?
        .bytes()
        .await
        .context("read binary asset body")?;

    // MV-01b #2 — minisign signature verification BEFORE the swap. Fetch
    // the `.minisig` companion (if published) then gate on it. `require`
    // is the two-tier rule: the unattended daemon path passes `true`
    // (any non-verified outcome bails); the manual operator path passes
    // `false` (missing sig / unprovisioned key warns + proceeds, but a
    // present-but-invalid sig still bails). Runs before apply_downloaded
    // so a failed verify never reaches `atomic_replace_binary`.
    let signature_text = match assets.signature {
        Some(sig_asset) => Some(
            client
                .get(&sig_asset.browser_download_url)
                .send()
                .await
                .with_context(|| format!("GET {}", sig_asset.browser_download_url))?
                .error_for_status()
                .context("fetch minisig companion")?
                .text()
                .await
                .context("read minisig companion body")?,
        ),
        None => None,
    };
    let sig_status = crate::updater::sig_verify::check_signature(
        &asset_bytes,
        signature_text.as_deref(),
        require_signature,
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
    let backup = apply_downloaded(&asset_bytes, &companion_text, format, binary, install_dir)?;
    // apply_downloaded already parsed + verified the companion, so this
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
    pub archive_sha256: String,
    pub download_url: String,
    pub signature_status: String,
    /// Absolute path of the staged archive on disk.
    pub staged_archive: String,
    pub target_triple: String,
    pub staged_ts_unix: i64,
}

/// `<stage_dir>/pending.json`.
pub fn pending_json_path(stage_dir: &Path) -> PathBuf {
    stage_dir.join("pending.json")
}

/// Read a staged-pending record, if one exists + parses. `None` when no
/// update is staged (the common case).
pub fn read_pending(stage_dir: &Path) -> Option<PendingUpdate> {
    let body = std::fs::read(pending_json_path(stage_dir)).ok()?;
    serde_json::from_slice(&body).ok()
}

/// Apply an ALREADY-STAGED update — skips the network entirely. The
/// staging task downloaded + sha256 + minisig-verified this archive; here
/// we RE-VERIFY the SHA-256 (the staged file could have been touched on
/// disk) then extract + atomic-replace. Returns the same [`UpdateApplied`]
/// envelope a fresh `apply_update` would.
pub fn apply_from_staged(pending: &PendingUpdate, install_dir: &Path) -> Result<UpdateApplied> {
    let archive = PathBuf::from(&pending.staged_archive);
    let bytes = std::fs::read(&archive)
        .with_context(|| format!("read staged archive {}", archive.display()))?;
    // Re-verify integrity against the recorded hash before any swap.
    let companion_text = format!("{}  staged\n", pending.archive_sha256);
    let format = archive_format_for_target(&pending.target_triple);
    // `neothd` is the on-disk binary + the archive member basename (Cargo
    // package name `neothd`; release workflow packs `neothd`/`neothd.exe`).
    // Pre-Session-28f this was the wrong string `"neoth"` — the
    // staged-apply fast-path would have failed at extraction looking for a
    // `neoth` member that doesn't exist.
    let backup = apply_downloaded(&bytes, &companion_text, format, "neothd", install_dir)
        .context("apply staged archive")?;
    Ok(UpdateApplied {
        from_version: current_version().to_string(),
        to_version: pending.to_version.clone(),
        backup_path: backup,
        restart_required: true,
        archive_sha256: pending.archive_sha256.clone(),
        download_url: pending.download_url.clone(),
        signature_status: pending.signature_status.clone(),
    })
}

/// Remove the staged archive + `pending.json` after a successful apply.
/// Best-effort — a leftover staged file is harmless (re-validated next time).
pub fn clear_staged(stage_dir: &Path, pending: &PendingUpdate) {
    let _ = std::fs::remove_file(&pending.staged_archive);
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
    target_triple: &str,
    binary: &str,
    stage_dir: &Path,
    require_signature: bool,
    now_unix: i64,
) -> Result<PendingUpdate> {
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

    let companion_text = client
        .get(&companion.browser_download_url)
        .send()
        .await
        .with_context(|| format!("GET {}", companion.browser_download_url))?
        .error_for_status()
        .context("fetch sha256 companion")?
        .text()
        .await
        .context("read sha256 companion body")?;

    let asset_bytes = client
        .get(&assets.binary.browser_download_url)
        .send()
        .await
        .with_context(|| format!("GET {}", assets.binary.browser_download_url))?
        .error_for_status()
        .context("fetch binary asset")?
        .bytes()
        .await
        .context("read binary asset body")?;

    // Integrity check (SHA-256) then authenticity (minisig). require=true
    // for the unattended path → any non-verified outcome bails before the
    // archive is written to the staging dir.
    let expected = parse_sha256_companion(&companion_text).context("parse sha256 companion")?;
    verify_sha256_bytes(&asset_bytes, &expected).context("verify staged asset sha256")?;

    let signature_text = match assets.signature {
        Some(sig_asset) => Some(
            client
                .get(&sig_asset.browser_download_url)
                .send()
                .await
                .with_context(|| format!("GET {}", sig_asset.browser_download_url))?
                .error_for_status()
                .context("fetch minisig companion")?
                .text()
                .await
                .context("read minisig companion body")?,
        ),
        None => None,
    };
    let sig_status = crate::updater::sig_verify::check_signature(
        &asset_bytes,
        signature_text.as_deref(),
        require_signature,
    )
    .context("staged self-update signature gate")?;

    std::fs::create_dir_all(stage_dir)
        .with_context(|| format!("create stage dir {}", stage_dir.display()))?;
    let staged_archive = stage_dir.join(&assets.binary.name);
    std::fs::write(&staged_archive, &asset_bytes)
        .with_context(|| format!("write staged archive {}", staged_archive.display()))?;

    let pending = PendingUpdate {
        to_version: release.tag_name.clone(),
        archive_sha256: expected,
        download_url: assets.binary.browser_download_url.clone(),
        signature_status: sig_status.as_str().to_string(),
        staged_archive: staged_archive.display().to_string(),
        target_triple: target_triple.to_string(),
        staged_ts_unix: now_unix,
    };
    let pending_path = pending_json_path(stage_dir);
    let body = serde_json::to_vec_pretty(&pending).context("serialise pending.json")?;
    std::fs::write(&pending_path, &body)
        .with_context(|| format!("write {}", pending_path.display()))?;

    Ok(pending)
}

/// Resolve every asset Phase 2b needs to run `apply_update`.
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
    let asset = find_matching_asset(&release.assets, target).ok_or_else(|| {
        anyhow::anyhow!(
            "no release asset matches target {target}; \
             expected {} — re-run with a cargo-dist target this \
             release was built for, or update manually from {}",
            expected_asset_name(binary, target),
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
    fn parse_semver_strips_pre_release_and_build_metadata() {
        // Release candidates / nightly builds compare on core triple.
        // `0.2.0-rc1` vs `0.1.5` still reports needs_update because
        // the core 0.2.0 > 0.1.5.
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

    // ── Phase 2a asset-locator coverage ──────────────────────────────

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
            expected_asset_name("neoth", "x86_64-pc-windows-msvc"),
            "neoth-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            expected_asset_name("neoth", "x86_64-unknown-linux-gnu"),
            "neoth-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            expected_asset_name("neoth", "aarch64-apple-darwin"),
            "neoth-aarch64-apple-darwin.tar.gz"
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
            fake_asset("neoth-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz"),
            fake_asset("neoth-aarch64-apple-darwin.tar.gz"),
        ];
        let m = find_matching_asset(&assets, "x86_64-pc-windows-msvc")
            .expect("must locate windows asset");
        assert_eq!(m.name, "neoth-x86_64-pc-windows-msvc.zip");
    }

    #[test]
    fn find_matching_asset_rejects_wrong_extension_for_target() {
        // A `.zip` named for a Linux target is rejected — operator
        // error or upload mix-up. Phase 2b would crash trying to
        // pkzip-extract a tar.xz; better to surface "no match"
        // here.
        let assets = vec![fake_asset("neoth-x86_64-unknown-linux-gnu.zip")];
        assert!(find_matching_asset(&assets, "x86_64-unknown-linux-gnu").is_none());
    }

    #[test]
    fn find_matching_asset_none_when_empty() {
        let assets: Vec<ReleaseAsset> = vec![];
        assert!(find_matching_asset(&assets, "x86_64-pc-windows-msvc").is_none());
    }

    #[test]
    fn find_matching_asset_none_for_target_not_in_release() {
        // Release published only the Linux build; Windows host
        // asks for an asset → None, caller falls back to manual.
        let assets = vec![fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz")];
        assert!(find_matching_asset(&assets, "x86_64-pc-windows-msvc").is_none());
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
        // Release without checksum — caller (Phase 2b) MUST refuse
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
        // (`"neothd"` — the real Cargo binary).
        let want = binary_filename_for_host("neothd");
        let zip_bytes = make_zip_with_member(&want, b"staged-daemon");
        let mut hasher = Sha256::new();
        hasher.update(&zip_bytes);
        let digest = hex_encode(&hasher.finalize());

        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let staged_archive = stage_dir.join("neoth.zip");
        std::fs::write(&staged_archive, &zip_bytes).unwrap();

        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join(&want), b"old-daemon").unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            archive_sha256: digest,
            download_url: "https://example.com/neoth.zip".into(),
            signature_status: "verified".into(),
            staged_archive: staged_archive.display().to_string(),
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 1_700_000_000,
        };
        // pending.json round-trips through disk.
        let pj = pending_json_path(&stage_dir);
        std::fs::write(&pj, serde_json::to_vec(&pending).unwrap()).unwrap();
        assert_eq!(read_pending(&stage_dir).as_ref(), Some(&pending));

        let outcome = apply_from_staged(&pending, &install_dir).expect("staged apply");
        assert_eq!(outcome.to_version, "v9.9.9");
        assert_eq!(outcome.signature_status, "verified");
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
        // matches the production binary name `"neothd"`.
        let want = binary_filename_for_host("neothd");
        let zip_bytes = make_zip_with_member(&want, b"good");
        let dir = tempdir().unwrap();
        let stage_dir = dir.path().join("staged");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let staged_archive = stage_dir.join("neoth.zip");
        std::fs::write(&staged_archive, &zip_bytes).unwrap();
        let install_dir = dir.path().join("bin");
        std::fs::create_dir_all(&install_dir).unwrap();

        let pending = PendingUpdate {
            to_version: "v9.9.9".into(),
            archive_sha256: "0".repeat(64), // wrong hash → tamper-detect
            download_url: "x".into(),
            signature_status: "verified".into(),
            staged_archive: staged_archive.display().to_string(),
            target_triple: "x86_64-pc-windows-msvc".into(),
            staged_ts_unix: 0,
        };
        let err = apply_from_staged(&pending, &install_dir).unwrap_err();
        assert!(
            format!("{err:#}").contains("sha256 mismatch"),
            "tampered staged archive must fail SHA re-check: {err:#}"
        );
    }

    #[test]
    fn pending_update_round_trips_via_json() {
        let p = PendingUpdate {
            to_version: "v0.3.0".into(),
            archive_sha256: "a".repeat(64),
            download_url: "https://example.com/neoth.tar.gz".into(),
            signature_status: "verified".into(),
            staged_archive: "/home/alex/.neoth/staged/neoth.tar.gz".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            staged_ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PendingUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn pending_json_path_is_under_stage_dir() {
        let p = pending_json_path(Path::new("/home/alex/.neoth/staged"));
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
            fake_asset("neoth-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-x86_64-pc-windows-msvc.zip.sha256"),
        ];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-pc-windows-msvc", "neoth").unwrap();
        assert_eq!(resolved.binary.name, "neoth-x86_64-pc-windows-msvc.zip");
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_errors_when_target_unmatched() {
        let release = fake_release(vec![fake_asset("neoth-x86_64-unknown-linux-gnu.tar.gz")]);
        let err = resolve_update_assets(&release, "x86_64-pc-windows-msvc", "neoth")
            .unwrap_err()
            .to_string();
        // Error must name the expected filename so operators see
        // the cargo-dist convention they should publish under.
        assert!(
            err.contains("neoth-x86_64-pc-windows-msvc.zip"),
            "diagnostic must name expected filename; got: {err}"
        );
        // Plus the html_url for the manual fallback.
        assert!(err.contains("releases/tag/v0.2.0"));
    }

    #[test]
    fn resolve_update_assets_returns_some_sha256_when_published() {
        let assets = vec![
            fake_asset("neoth-x86_64-apple-darwin.tar.gz"),
            fake_asset("neoth-x86_64-apple-darwin.tar.gz.sha256"),
        ];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_returns_none_sha256_when_companion_missing() {
        // Phase 2b's apply path inspects this directly; if None,
        // refuse the update.
        let assets = vec![fake_asset("neoth-x86_64-apple-darwin.tar.gz")];
        let release = fake_release(assets);
        let resolved = resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_none());
    }

    // ── Phase 2a sha256 verify coverage ─────────────────────────────

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

    // ── Phase 2b extractor + atomic-replace coverage ────────────────

    /// Build an in-memory ZIP archive containing one member with
    /// the requested name + body.
    fn make_zip_with_member(name: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Cursor;
        use std::io::Write;
        let mut out: Vec<u8> = Vec::new();
        {
            let cursor = Cursor::new(&mut out);
            let mut writer = zip::ZipWriter::new(cursor);
            writer
                .start_file::<_, ()>(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body).unwrap();
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

    // ── Phase 2b apply_downloaded orchestrator coverage ────────────

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
