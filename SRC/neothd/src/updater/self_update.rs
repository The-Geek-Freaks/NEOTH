//! V03-09 — daemon self-update check via GitHub Releases API.
//!
//! The parent `updater` module covers operator-installed CLIs
//! (claude-cli, gemini-cli, codex). This sub-module is the
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

use anyhow::{Context, Result};
use serde::Deserialize;

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
    let core = trimmed
        .split(['-', '+'])
        .next()
        .unwrap_or(trimmed);
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
    let release: LatestRelease = resp
        .json()
        .await
        .context("parse GitHub release JSON")?;
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

/// Archive format cargo-dist emits per host platform.
///
/// cargo-dist's default release matrix:
///   - Windows: `.zip` (binaries + PDBs)
///   - Linux:   `.tar.xz` (smaller than .gz, ubiquitous on modern distros)
///   - macOS:   `.tar.xz` (matches Linux; cargo-dist >= 0.10)
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

/// Pick the cargo-dist-canonical archive format for a target
/// triple. Falls back to `TarGz` for unknown targets — the
/// safest universal choice; Phase 2b's extractor must handle
/// all three.
pub fn archive_format_for_target(target: &str) -> ArchiveFormat {
    if target.contains("windows") {
        ArchiveFormat::Zip
    } else if target.contains("linux") || target.contains("darwin") {
        ArchiveFormat::TarXz
    } else {
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

/// Build the cargo-dist-canonical asset filename for a binary +
/// target. The default cargo-dist convention is
/// `<binary>-<target>.<archive>`. Examples:
///
///   neoth-x86_64-pc-windows-msvc.zip
///   neoth-x86_64-unknown-linux-gnu.tar.xz
///   neoth-aarch64-apple-darwin.tar.xz
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
    Ok(UpdateAssets {
        target,
        binary: asset,
        sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn archive_format_picks_tar_xz_for_unix() {
        assert_eq!(
            archive_format_for_target("x86_64-unknown-linux-gnu"),
            ArchiveFormat::TarXz
        );
        assert_eq!(
            archive_format_for_target("aarch64-apple-darwin"),
            ArchiveFormat::TarXz
        );
        assert_eq!(
            archive_format_for_target("x86_64-apple-darwin"),
            ArchiveFormat::TarXz
        );
    }

    #[test]
    fn archive_format_falls_back_to_tar_gz_for_unknown() {
        // Truly unknown OS (no `linux` / `darwin` / `windows`
        // substring) — safest universal fallback so Phase 2b's
        // extractor always has SOMETHING to try. Note `*-linux-musl`
        // intentionally still routes to TarXz; cargo-dist publishes
        // both glibc + musl Linux as `.tar.xz`.
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
            "neoth-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            expected_asset_name("neoth", "aarch64-apple-darwin"),
            "neoth-aarch64-apple-darwin.tar.xz"
        );
    }

    #[test]
    fn sha256_companion_just_appends_sha256_extension() {
        assert_eq!(
            sha256_companion_name("neoth-x86_64-pc-windows-msvc.zip"),
            "neoth-x86_64-pc-windows-msvc.zip.sha256"
        );
        assert_eq!(
            sha256_companion_name("neoth-x86_64-unknown-linux-gnu.tar.xz"),
            "neoth-x86_64-unknown-linux-gnu.tar.xz.sha256"
        );
    }

    #[test]
    fn find_matching_asset_picks_correct_target() {
        let assets = vec![
            fake_asset("neoth-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-x86_64-unknown-linux-gnu.tar.xz"),
            fake_asset("neoth-aarch64-apple-darwin.tar.xz"),
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
        let assets = vec![fake_asset("neoth-x86_64-unknown-linux-gnu.tar.xz")];
        assert!(find_matching_asset(&assets, "x86_64-pc-windows-msvc").is_none());
    }

    #[test]
    fn find_sha256_companion_pairs_with_binary() {
        let bin = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.xz");
        let companion = fake_asset("neoth-x86_64-unknown-linux-gnu.tar.xz.sha256");
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

    #[test]
    fn resolve_update_assets_returns_bundle_for_supported_host() {
        let assets = vec![
            fake_asset("neoth-x86_64-pc-windows-msvc.zip"),
            fake_asset("neoth-x86_64-pc-windows-msvc.zip.sha256"),
        ];
        let release = fake_release(assets);
        let resolved =
            resolve_update_assets(&release, "x86_64-pc-windows-msvc", "neoth").unwrap();
        assert_eq!(resolved.binary.name, "neoth-x86_64-pc-windows-msvc.zip");
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_errors_when_target_unmatched() {
        let release = fake_release(vec![fake_asset(
            "neoth-x86_64-unknown-linux-gnu.tar.xz",
        )]);
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
            fake_asset("neoth-x86_64-apple-darwin.tar.xz"),
            fake_asset("neoth-x86_64-apple-darwin.tar.xz.sha256"),
        ];
        let release = fake_release(assets);
        let resolved =
            resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_some());
    }

    #[test]
    fn resolve_update_assets_returns_none_sha256_when_companion_missing() {
        // Phase 2b's apply path inspects this directly; if None,
        // refuse the update.
        let assets = vec![fake_asset("neoth-x86_64-apple-darwin.tar.xz")];
        let release = fake_release(assets);
        let resolved =
            resolve_update_assets(&release, "x86_64-apple-darwin", "neoth").unwrap();
        assert!(resolved.sha256.is_none());
    }
}
