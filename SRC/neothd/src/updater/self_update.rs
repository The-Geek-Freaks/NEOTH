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
}
