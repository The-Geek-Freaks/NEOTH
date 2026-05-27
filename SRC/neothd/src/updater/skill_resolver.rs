//! U-02b (Session 26): resolve "latest version" for an operator-
//! installed skill or plugin via its declared `source` URL.
//!
//! Today only one scheme is supported: `git+https://<host>/<owner>/
//! <repo>`. The resolver shells out to `git ls-remote --tags <url>`
//! and returns the highest-sorting semver tag (Cargo's
//! `Version::parse` lookalike — semver dotted u32 triples plus an
//! optional pre-release suffix; we ignore pre-releases).
//!
//! ## Design picked (per Session 26 hand-off)
//!
//! Two options were on the table:
//!   1. **Per-skill `source` field** in `SkillManifest` + git
//!      ls-remote --tags probe. Battle-tested pattern (cargo, npm
//!      submodules, pyproject deps). Resolver lives in this module.
//!   2. **Community registry** at `skills.neoth.dev/v1/skill/<id>`.
//!      Requires a NEOTH-operated HTTPS endpoint + signature
//!      story.
//!
//! Alex picked option 1 for the v0.3 ship: smaller surface, no new
//! NEOTH-operated infrastructure, operators already understand
//! GitHub-as-registry from npm/cargo. The community-registry path
//! lands as a second scheme (`registry+https://…`) when an
//! operator-facing reason to maintain it surfaces.
//!
//! ## Scheme parser
//!
//! `git+https://github.com/<owner>/<repo>` → `https://github.com/
//! <owner>/<repo>` (the `git+` prefix flags Git semantics for the
//! resolver but is not part of the URL handed to `git ls-remote`).
//! Unknown schemes (anything not `git+https://` or `git+http://`)
//! return a structured Err so the cron audit chain captures
//! "operator misconfigured the source" instead of silently
//! failing.

use std::process::Stdio;
use std::time::Duration;

use tracing::debug;

/// Timeout for the `git ls-remote` subprocess. 5s is well above any
/// reasonable upstream response; longer than that means the operator's
/// network is broken or the host is dead, and we'd rather surface a
/// timeout error in the audit frame than block the updater cron.
pub const RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve the latest published version tag for a `source` URI.
/// Returns the tag verbatim (e.g. `"v1.2.3"`); the caller decides
/// whether to strip the leading `v` for comparison against the
/// skill manifest's `version: "1.2.3"` field.
pub async fn resolve_latest_version(source: &str) -> Result<String, String> {
    let url = parse_git_source(source)?;
    debug!(source, url, "resolving latest version via git ls-remote");

    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("ls-remote")
        .arg("--tags")
        .arg(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let fut = cmd.output();
    let out = match tokio::time::timeout(RESOLVER_TIMEOUT, fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("spawn git ls-remote {url}: {e}")),
        Err(_) => {
            return Err(format!(
                "git ls-remote {url} timed out after {}s",
                RESOLVER_TIMEOUT.as_secs(),
            ));
        }
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let trimmed = stderr.trim();
        return Err(format!(
            "git ls-remote {url} exit {:?}: {}",
            out.status.code(),
            if trimmed.is_empty() {
                "no stderr output"
            } else {
                trimmed
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let tags = parse_ls_remote_tags(&stdout);
    pick_highest_semver_tag(&tags).ok_or_else(|| {
        if tags.is_empty() {
            format!("git ls-remote {url} returned no tags")
        } else {
            format!(
                "git ls-remote {url} returned {} tags but none were semver-shaped",
                tags.len()
            )
        }
    })
}

/// Strip the `git+` prefix from a `source` URI + reject schemes the
/// resolver doesn't support. Pure-fn — tests exercise this without
/// touching the process layer.
pub fn parse_git_source(source: &str) -> Result<String, String> {
    let url = source.strip_prefix("git+").ok_or_else(|| {
        format!("source scheme not supported (expected `git+https://…`): {source}")
    })?;
    if !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("ssh://")) {
        return Err(format!(
            "source scheme not supported (expected git+{{https,http,ssh}}://): {source}"
        ));
    }
    Ok(url.to_string())
}

/// Parse `git ls-remote --tags <url>` output into a deduplicated
/// list of tag names. Each line is `<sha>\trefs/tags/<name>` and
/// peeled annotated tags carry the `^{}` suffix that we strip.
pub fn parse_ls_remote_tags(stdout: &str) -> Vec<String> {
    let mut tags: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let (_sha, refname) = line.split_once('\t')?;
            let tag = refname.strip_prefix("refs/tags/")?;
            // Annotated tags emit two lines — `refs/tags/v1.0.0` and
            // `refs/tags/v1.0.0^{}`. Both refer to the same release;
            // dedup by stripping the peel suffix.
            let tag = tag.strip_suffix("^{}").unwrap_or(tag);
            Some(tag.to_string())
        })
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// Pick the highest semver-shaped tag from a list. `Some(tag)` on
/// success; `None` when no tag parses as a `MAJOR.MINOR.PATCH`
/// triple. Pre-release-suffixed tags (`1.0.0-rc1`, `2.0.0-beta`) are
/// intentionally ignored — the updater probes stable releases only,
/// per Cargo's default `^1.0.0` semantics.
pub fn pick_highest_semver_tag(tags: &[String]) -> Option<String> {
    let mut best: Option<(SemverTriple, &String)> = None;
    for tag in tags {
        let Some(triple) = parse_semver_triple(tag) else {
            continue;
        };
        match &best {
            Some((prev, _)) if prev >= &triple => {}
            _ => best = Some((triple, tag)),
        }
    }
    best.map(|(_, tag)| tag.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemverTriple {
    major: u32,
    minor: u32,
    patch: u32,
}

fn parse_semver_triple(tag: &str) -> Option<SemverTriple> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    // Reject pre-release / build suffixes — `1.0.0-rc1` shouldn't
    // outrank `1.0.0` if the operator ever ships a real release.
    if stripped.contains('-') || stripped.contains('+') {
        return None;
    }
    let mut parts = stripped.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None; // Anything past patch is non-semver.
    }
    Some(SemverTriple {
        major,
        minor,
        patch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_git_source_accepts_https() {
        let url = parse_git_source("git+https://github.com/owner/repo").unwrap();
        assert_eq!(url, "https://github.com/owner/repo");
    }

    #[test]
    fn parse_git_source_accepts_ssh() {
        let url = parse_git_source("git+ssh://git@github.com/owner/repo").unwrap();
        assert_eq!(url, "ssh://git@github.com/owner/repo");
    }

    #[test]
    fn parse_git_source_rejects_missing_prefix() {
        let err = parse_git_source("https://github.com/owner/repo").unwrap_err();
        assert!(err.contains("expected `git+"));
    }

    #[test]
    fn parse_git_source_rejects_unknown_inner_scheme() {
        let err = parse_git_source("git+ftp://example.com").unwrap_err();
        assert!(err.contains("expected git+"));
    }

    #[test]
    fn parse_ls_remote_picks_tag_names() {
        let raw = "\
abc123\trefs/tags/v1.0.0\n\
def456\trefs/tags/v1.0.0^{}\n\
789xyz\trefs/tags/v2.1.3\n\
000000\trefs/heads/main\n";
        let tags = parse_ls_remote_tags(raw);
        // Annotated peel `^{}` deduped to the same v1.0.0.
        assert_eq!(tags, vec!["v1.0.0".to_string(), "v2.1.3".to_string()]);
    }

    #[test]
    fn parse_ls_remote_empty_input_returns_empty() {
        assert!(parse_ls_remote_tags("").is_empty());
    }

    #[test]
    fn parse_semver_strips_v_prefix() {
        assert_eq!(
            parse_semver_triple("v1.2.3"),
            Some(SemverTriple {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(
            parse_semver_triple("1.2.3"),
            Some(SemverTriple {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
    }

    #[test]
    fn parse_semver_rejects_prerelease() {
        assert!(parse_semver_triple("1.0.0-rc1").is_none());
        assert!(parse_semver_triple("1.0.0+meta").is_none());
    }

    #[test]
    fn parse_semver_rejects_non_triple() {
        assert!(parse_semver_triple("v1.0").is_none());
        assert!(parse_semver_triple("1.2.3.4").is_none());
        assert!(parse_semver_triple("not-a-version").is_none());
    }

    #[test]
    fn pick_highest_orders_numerically_not_lexicographically() {
        // Lex sort would put "v10.0.0" < "v2.0.0" because '1' < '2'.
        // The numeric comparator must put v10.0.0 ABOVE v2.0.0.
        let tags = vec![
            "v2.0.0".to_string(),
            "v10.0.0".to_string(),
            "v1.5.7".to_string(),
        ];
        assert_eq!(pick_highest_semver_tag(&tags), Some("v10.0.0".to_string()));
    }

    #[test]
    fn pick_highest_skips_non_semver_tags() {
        let tags = vec![
            "release-alpha".to_string(),
            "v1.0.0".to_string(),
            "stable".to_string(),
        ];
        assert_eq!(pick_highest_semver_tag(&tags), Some("v1.0.0".to_string()));
    }

    #[test]
    fn pick_highest_no_semver_tags_returns_none() {
        let tags = vec!["release-alpha".to_string(), "stable".to_string()];
        assert!(pick_highest_semver_tag(&tags).is_none());
    }

    #[tokio::test]
    async fn resolve_latest_returns_err_on_bad_scheme() {
        let err = resolve_latest_version("not-a-url").await.unwrap_err();
        assert!(err.contains("expected `git+"));
    }

    #[tokio::test]
    async fn resolve_latest_returns_err_on_unreachable_host() {
        // RFC2606 `.invalid` TLD reserved for examples — guaranteed
        // to never resolve. `git ls-remote` returns non-zero. Note:
        // tests run with kill_on_drop so the subprocess gets cleaned
        // up immediately when the test future is dropped.
        let err = resolve_latest_version("git+https://nonexistent-host.invalid/owner/repo")
            .await
            .unwrap_err();
        // Either non-zero exit ("not found") or a spawn error if git
        // isn't installed — both are valid signals the resolver
        // surfaces faithfully.
        assert!(err.contains("ls-remote") || err.contains("spawn"));
    }
}
