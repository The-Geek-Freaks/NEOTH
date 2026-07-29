//! U-02b (Session 26): resolve "latest version" for an operator-
//! installed skill or plugin via its declared `source` URL.
//!
//! Today only one scheme is supported: `git+https://<approved-forge>/<owner>/
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
//! Option 1 was chosen for the v0.3 ship: smaller surface, no new
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
//! Unknown or unauthenticated schemes (anything except `git+https://`)
//! return a structured Err so the cron audit chain captures
//! "operator misconfigured the source" instead of silently
//! failing. v1 deliberately limits hosts to established public forges;
//! self-hosted sources require a future explicit operator host policy.

use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};
use tracing::debug;

const APPROVED_GIT_HOSTS: &[&str] = &["github.com", "gitlab.com", "codeberg.org"];
const MAX_GIT_SOURCE_BYTES: usize = 2048;
const MAX_GIT_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;
const MAX_GIT_VERSION_BYTES: usize = 256;
const MAX_PINNED_GIT_ADDRESSES: usize = 16;
const MIN_DNS_PIN_GIT_VERSION: (u32, u32, u32) = (2, 37, 0);

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
    let parsed = parse_git_source_url(source)?;
    let host = parsed
        .host_str()
        .expect("approved git source parser always returns a host")
        .to_string();
    let url = parsed.as_str().to_string();

    let isolated_cwd = tempfile::Builder::new()
        .prefix("neoth-git-probe-")
        .tempdir()
        .map_err(|_| "create isolated git probe directory".to_string())?;
    ensure_git_supports_dns_pinning(isolated_cwd.path()).await?;
    let addresses = tokio::time::timeout(
        RESOLVER_TIMEOUT,
        resolve_public_git_addresses(host.as_str()),
    )
    .await
    .map_err(|_| "approved git source DNS resolution timed out".to_string())??;
    let dns_pin = curlopt_resolve_value(host.as_str(), &addresses);
    debug!(
        forge = %host,
        pinned_addresses = addresses.len(),
        "resolving latest version via DNS-pinned hardened git ls-remote"
    );

    let mut cmd = hardened_git_command(&url, &dns_pin, isolated_cwd.path());
    let mut child = cmd
        .spawn()
        .map_err(|_| "spawn hardened git ls-remote probe".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "capture git probe stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "capture git probe stderr".to_string())?;
    let stdout_task = tokio::spawn(capture_bounded(stdout, MAX_GIT_STDOUT_BYTES));
    let stderr_task = tokio::spawn(capture_bounded(stderr, MAX_GIT_STDERR_BYTES));

    let status = match tokio::time::timeout(RESOLVER_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            let _ = child.kill().await;
            return Err("wait for hardened git ls-remote probe".to_string());
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!(
                "git ls-remote timed out after {}s",
                RESOLVER_TIMEOUT.as_secs()
            ));
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|_| "git stdout capture task failed".to_string())?
        .map_err(|_| "read git stdout".to_string())?;
    let stderr = stderr_task
        .await
        .map_err(|_| "git stderr capture task failed".to_string())?
        .map_err(|_| "read git stderr".to_string())?;

    if !status.success() {
        return Err(format!(
            "git ls-remote exited with code {:?} (stderr {} bytes{})",
            status.code(),
            stderr.total_bytes,
            if stderr.truncated { ", truncated" } else { "" }
        ));
    }
    if stdout.truncated {
        return Err(format!(
            "git ls-remote output exceeds the {MAX_GIT_STDOUT_BYTES}-byte limit"
        ));
    }

    let stdout = std::str::from_utf8(&stdout.bytes)
        .map_err(|_| "git ls-remote returned non-UTF-8 output".to_string())?;
    let tags = parse_ls_remote_tags(stdout);
    pick_highest_semver_tag(&tags).ok_or_else(|| {
        if tags.is_empty() {
            "git ls-remote returned no tags".to_string()
        } else {
            format!(
                "git ls-remote returned {} tags but none were semver-shaped",
                tags.len()
            )
        }
    })
}

fn hardened_git_command(url: &str, dns_pin: &str, cwd: &Path) -> tokio::process::Command {
    let mut cmd = hardened_git_process(cwd);
    cmd.arg("-c")
        .arg("credential.helper=")
        .arg("-c")
        .arg("credential.interactive=false")
        .arg("-c")
        .arg("core.askPass=")
        .arg("-c")
        .arg("http.followRedirects=false")
        .arg("-c")
        .arg("http.sslVerify=true")
        .arg("-c")
        .arg("http.proxy=")
        .arg("-c")
        .arg("http.extraHeader=")
        .arg("-c")
        .arg("http.maxRequests=1")
        .arg("-c")
        .arg(format!("http.curloptResolve={dns_pin}"))
        .arg("ls-remote")
        .arg("--tags")
        .arg("--refs")
        .arg("--end-of-options")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// Resolve an approved forge exactly once and retain the validated addresses
/// that Git will connect to. Passing the same set through
/// `http.curloptResolve` closes the classic check-then-re-resolve hole: a DNS
/// answer cannot be public during validation and private when libcurl dials.
async fn resolve_public_git_addresses(host: &str) -> Result<Vec<IpAddr>, String> {
    let resolved = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| "approved git source DNS resolution failed".to_string())?;
    validate_public_git_addresses(resolved.map(|address| address.ip()))
}

fn validate_public_git_addresses(
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<IpAddr>, String> {
    let mut unique = std::collections::BTreeSet::new();
    for address in addresses {
        if !is_globally_routable_git_address(address) {
            return Err(
                "approved git source resolved to a non-public or reserved address".to_string(),
            );
        }
        unique.insert(address);
        if unique.len() > MAX_PINNED_GIT_ADDRESSES {
            return Err(format!(
                "approved git source exceeds the {MAX_PINNED_GIT_ADDRESSES}-address DNS limit"
            ));
        }
    }
    if unique.is_empty() {
        return Err("approved git source DNS resolved zero addresses".to_string());
    }
    Ok(unique.into_iter().collect())
}

/// Conservative IANA special-purpose filter for the Git transport. Stable Rust
/// does not yet expose `IpAddr::is_global`, so keep the small transport-local
/// predicate explicit. Approved public forges do not need any of these ranges;
/// rejecting a future ambiguous allocation is safer than letting updater DNS
/// reach a local or reserved network.
fn is_globally_routable_git_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            !(a == 0
                || address.is_private()
                || (a == 100 && b & 0xc0 == 0x40)
                || address.is_loopback()
                || address.is_link_local()
                || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
                // Deprecated 6to4 Relay Anycast. A resolver must not use a
                // transition address to escape the public-destination check.
                || (a == 192 && b == 88 && c == 99)
                || address.is_documentation()
                || (a == 198 && b & 0xfe == 18)
                || a >= 224)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            let numeric = u128::from_be_bytes(address.octets());
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                // Deprecated IPv4-compatible and IPv4-mapped forms. A normal
                // A record arrives as `IpAddr::V4`, so no legitimate forge
                // resolution needs either alias form.
                || matches!(segments, [0, 0, 0, 0, 0, 0 | 0xffff, _, _])
                // Well-known NAT64 (`64:ff9b::/96`). Even though the prefix is
                // globally routed on some networks, its final 32 bits can
                // encode loopback, link-local or RFC-1918 IPv4 destinations.
                || matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, _, _])
                // IPv4-IPv6 translation local-use prefix (`64:ff9b:1::/48`).
                || matches!(segments, [0x64, 0xff9b, 1, _, _, _, _, _])
                // Discard-only (`100::/64`).
                || matches!(segments, [0x100, 0, 0, 0, _, _, _, _])
                // Dummy IPv6 prefix (`100:0:0:1::/64`).
                || matches!(segments, [0x100, 0, 0, 1, _, _, _, _])
                // IETF protocol assignments (`2001::/23`) except the small
                // set explicitly recorded as globally reachable by IANA.
                || (matches!(segments, [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                    && !(numeric == 0x2001_0001_0000_0000_0000_0000_0000_0001
                        || numeric == 0x2001_0001_0000_0000_0000_0000_0000_0002
                        || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
                        || matches!(segments, [0x2001, 4, 0x112, _, _, _, _, _])
                        || matches!(segments, [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3f).contains(&b))))
                || matches!(segments, [0x2002, _, _, _, _, _, _, _])
                || matches!(segments, [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..])
                || matches!(segments, [0x5f00, ..]))
        }
    }
}

fn curlopt_resolve_value(host: &str, addresses: &[IpAddr]) -> String {
    let addresses = addresses
        .iter()
        .map(|address| match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        })
        .collect::<Vec<_>>()
        .join(",");
    // The plain form is a permanent entry for this short-lived Git process.
    // Avoid the optional `+` prefix so Git builds linked against older libcurl
    // releases do not reject an otherwise supported pinned address list.
    format!("{host}:443:{addresses}")
}

/// Git only gained `http.curloptResolve` in 2.37. An older binary silently
/// ignores unknown config keys, which would look successful while reopening
/// DNS rebinding. Verify the capability before the network subprocess.
async fn ensure_git_supports_dns_pinning(cwd: &Path) -> Result<(), String> {
    let mut command = hardened_git_process(cwd);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| "spawn Git version capability check".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "capture Git version capability output".to_string())?;
    let stdout_task = tokio::spawn(capture_bounded(stdout, MAX_GIT_VERSION_BYTES));
    let status = match tokio::time::timeout(RESOLVER_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            return Err("wait for Git version capability check".to_string());
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            return Err("Git version capability check timed out".to_string());
        }
    };
    let output = stdout_task
        .await
        .map_err(|_| "Git version capture task failed".to_string())?
        .map_err(|_| "read Git version capability output".to_string())?;
    if !status.success() || output.truncated {
        return Err("Git version capability check failed".to_string());
    }
    let text = std::str::from_utf8(&output.bytes)
        .map_err(|_| "Git version capability output is not UTF-8".to_string())?;
    let version = parse_git_version(text)
        .ok_or_else(|| "Git version capability output is invalid".to_string())?;
    if version < MIN_DNS_PIN_GIT_VERSION {
        return Err(format!(
            "Git {}.{}.{} or newer is required for DNS-pinned Skill source probes",
            MIN_DNS_PIN_GIT_VERSION.0, MIN_DNS_PIN_GIT_VERSION.1, MIN_DNS_PIN_GIT_VERSION.2
        ));
    }
    Ok(())
}

fn parse_git_version(output: &str) -> Option<(u32, u32, u32)> {
    let numeric = output
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = numeric.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

/// Construct the process boundary shared by every Git probe. In addition to
/// clearing system/global config, cap repository discovery at the exact empty
/// probe directory. Otherwise a same-user `.git/config` in an ancestor of the
/// platform temp directory can still inject `url.*.insteadOf`, proxy, or TLS
/// settings before `ls-remote` runs.
fn hardened_git_process(cwd: &Path) -> tokio::process::Command {
    // Git stops before inspecting a ceiling directory itself. The private
    // probe directory is a fresh, non-repository child, so its parent is the
    // correct ceiling: Git may inspect `cwd`, but can never load `.git/config`
    // from the environment-selected temp parent or any higher ancestor.
    let discovery_ceiling = cwd.parent().unwrap_or(cwd);
    let mut cmd = tokio::process::Command::new("git");
    cmd.env_clear();
    preserve_minimal_process_environment(&mut cmd);
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_CEILING_DIRECTORIES", discovery_ceiling)
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .current_dir(cwd);
    cmd
}

/// Strip the `git+` prefix from a `source` URI + reject schemes the
/// resolver doesn't support. Pure-fn — tests exercise this without
/// touching the process layer.
pub fn parse_git_source(source: &str) -> Result<String, String> {
    parse_git_source_url(source).map(|url| url.to_string())
}

fn parse_git_source_url(source: &str) -> Result<url::Url, String> {
    if source.len() > MAX_GIT_SOURCE_BYTES {
        return Err(format!(
            "git source exceeds the {MAX_GIT_SOURCE_BYTES}-byte limit"
        ));
    }
    if source.chars().any(char::is_control) {
        return Err("git source contains control characters".to_string());
    }
    let raw = source
        .strip_prefix("git+")
        .ok_or_else(|| "source scheme not supported (expected `git+https://…`)".to_string())?;
    let parsed = url::Url::parse(raw).map_err(|_| "git source URL is invalid".to_string())?;
    if parsed.scheme() != "https" {
        return Err("source scheme not supported (expected `git+https://…`)".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("git source must not contain userinfo".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("git source must not contain a query or fragment".to_string());
    }
    if parsed.port().is_some_and(|port| port != 443) {
        return Err("git source must use the default HTTPS port".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "git source URL has no host".to_string())?;
    if !APPROVED_GIT_HOSTS
        .iter()
        .any(|approved| host.eq_ignore_ascii_case(approved))
    {
        return Err("git source host is not an approved public forge".to_string());
    }
    if parsed
        .path_segments()
        .is_none_or(|segments| segments.filter(|segment| !segment.is_empty()).count() < 2)
    {
        return Err("git source must identify an owner and repository".to_string());
    }
    Ok(parsed)
}

fn preserve_minimal_process_environment(command: &mut tokio::process::Command) {
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(windows)]
fn null_device() -> &'static OsStr {
    OsStr::new("NUL")
}

#[cfg(not(windows))]
fn null_device() -> &'static OsStr {
    OsStr::new("/dev/null")
}

struct CapturedStream {
    bytes: Vec<u8>,
    total_bytes: usize,
    truncated: bool,
}

async fn capture_bounded<R>(mut reader: R, limit: usize) -> std::io::Result<CapturedStream>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut total_bytes = 0usize;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(read);
        if bytes.len() < limit {
            let keep = (limit - bytes.len()).min(read);
            bytes.extend_from_slice(&buffer[..keep]);
        }
    }
    Ok(CapturedStream {
        bytes,
        total_bytes,
        truncated: total_bytes > limit,
    })
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
    fn parse_git_source_accepts_each_approved_public_forge() {
        for host in APPROVED_GIT_HOSTS {
            let source = format!("git+https://{host}/owner/repo");
            let parsed = parse_git_source(&source).unwrap();
            assert_eq!(parsed, format!("https://{host}/owner/repo"));
        }
    }

    #[test]
    fn parse_git_source_rejects_ssh() {
        let err = parse_git_source("git+ssh://git@github.com/owner/repo").unwrap_err();
        assert!(err.contains("expected `git+https://"));
    }

    #[test]
    fn parse_git_source_rejects_plaintext_http() {
        let err = parse_git_source("git+http://github.com/owner/repo").unwrap_err();
        assert!(err.contains("expected `git+https://"));
    }

    #[test]
    fn parse_git_source_rejects_unapproved_or_non_global_hosts() {
        for source in [
            "git+https://localhost/owner/repo",
            "git+https://127.0.0.1/owner/repo",
            "git+https://10.0.0.1/owner/repo",
            "git+https://github.com.evil.example/owner/repo",
            "git+https://sub.github.com/owner/repo",
            "git+https://example.com/owner/repo",
        ] {
            let err = parse_git_source(source).unwrap_err();
            assert!(err.contains("not an approved public forge"));
            assert!(!err.contains(source), "errors must not echo source URLs");
        }
    }

    #[test]
    fn parse_git_source_rejects_credentials_query_fragment_and_custom_port() {
        for source in [
            "git+https://user:super-secret@github.com/owner/repo",
            "git+https://github.com/owner/repo?token=super-secret",
            "git+https://github.com/owner/repo#super-secret",
            "git+https://github.com:8443/owner/repo",
        ] {
            let err = parse_git_source(source).unwrap_err();
            assert!(!err.contains("super-secret"));
            assert!(!err.contains(source), "errors must not echo source URLs");
        }
    }

    #[test]
    fn parse_git_source_rejects_control_characters_and_incomplete_paths() {
        let err = parse_git_source("git+https://github.com/owner/repo\nsecret").unwrap_err();
        assert!(err.contains("control characters"));
        assert!(!err.contains("secret"));
        assert!(parse_git_source("git+https://github.com/owner").is_err());
        assert!(parse_git_source("git+https://github.com/").is_err());
        let oversized = format!("git+https://github.com/owner/{}", "x".repeat(2048));
        assert!(
            parse_git_source(&oversized)
                .unwrap_err()
                .contains("byte limit")
        );
    }

    #[test]
    fn hardened_git_command_disables_credentials_redirects_and_prompts() {
        let cwd = tempfile::tempdir().unwrap();
        let dns_pin = "github.com:443:192.30.255.112,[2606:50c0:8000::154]";
        let command = hardened_git_command("https://github.com/owner/repo", dns_pin, cwd.path());
        let command = command.as_std();
        let args: Vec<String> = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        for required in [
            "credential.helper=",
            "credential.interactive=false",
            "core.askPass=",
            "http.followRedirects=false",
            "http.sslVerify=true",
            "http.proxy=",
            "http.extraHeader=",
            "http.curloptResolve=github.com:443:192.30.255.112,[2606:50c0:8000::154]",
            "--end-of-options",
        ] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }
        let env: std::collections::HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect();
        assert_eq!(
            env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            env.get("GCM_INTERACTIVE").map(String::as_str),
            Some("Never")
        );
        assert_eq!(
            env.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
            Some("https")
        );
        assert_eq!(
            env.get("GIT_DISCOVERY_ACROSS_FILESYSTEM")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(
            env.get("GIT_CEILING_DIRECTORIES").map(String::as_str),
            Some(cwd.path().parent().unwrap().to_string_lossy().as_ref())
        );
        assert_eq!(command.get_current_dir(), Some(cwd.path()));
    }

    #[test]
    fn git_address_policy_rejects_every_local_alias_and_reserved_family() {
        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let address = address.parse::<IpAddr>().unwrap();
            assert!(
                !is_globally_routable_git_address(address),
                "{address} must not be eligible for a Git source pin"
            );
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "192.0.0.9",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            let address = address.parse::<IpAddr>().unwrap();
            assert!(
                is_globally_routable_git_address(address),
                "{address} must remain eligible for a Git source pin"
            );
        }
    }

    #[test]
    fn validated_git_addresses_are_unique_bounded_and_deterministic() {
        let addresses = validate_public_git_addresses([
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(
            addresses,
            vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]
        );
        assert!(
            validate_public_git_addresses(["127.0.0.1".parse().unwrap()])
                .unwrap_err()
                .contains("non-public or reserved")
        );
        let too_many = (1..=MAX_PINNED_GIT_ADDRESSES + 1)
            .map(|last| IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, last as u8)));
        assert!(
            validate_public_git_addresses(too_many)
                .unwrap_err()
                .contains("DNS limit")
        );
    }

    #[test]
    fn curlopt_resolve_pin_formats_ipv4_and_ipv6_without_dns_relookup() {
        let addresses = [
            "192.30.255.112".parse().unwrap(),
            "2606:50c0:8000::154".parse().unwrap(),
        ];
        assert_eq!(
            curlopt_resolve_value("github.com", &addresses),
            "github.com:443:192.30.255.112,[2606:50c0:8000::154]"
        );
    }

    #[test]
    fn git_version_parser_accepts_vendor_suffixes_and_enforces_pin_floor() {
        assert_eq!(
            parse_git_version("git version 2.49.0.windows.1\n"),
            Some((2, 49, 0))
        );
        assert_eq!(
            parse_git_version("git version 2.39.5 (Apple Git-154)\n"),
            Some((2, 39, 5))
        );
        assert!(parse_git_version("git version unknown").is_none());
        assert!((2, 36, 9) < MIN_DNS_PIN_GIT_VERSION);
        assert!((2, 37, 0) >= MIN_DNS_PIN_GIT_VERSION);
    }

    #[tokio::test]
    async fn hardened_git_process_does_not_discover_poisoned_ancestor_repository() {
        let ancestor = tempfile::tempdir().unwrap();
        let git_dir = ancestor.path().join(".git");
        std::fs::create_dir_all(git_dir.join("objects")).unwrap();
        std::fs::create_dir_all(git_dir.join("refs").join("heads")).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[core]\n  repositoryformatversion = 0\n  bare = false\n\
             [url \"https://attacker.invalid/\"]\n  insteadOf = https://github.com/\n",
        )
        .unwrap();
        let cwd = ancestor.path().join("probe");
        std::fs::create_dir(&cwd).unwrap();

        // If Git is unavailable the production resolver cannot run either;
        // keep this platform regression portable while still exercising the
        // real discovery behavior everywhere Git is installed.
        let available = std::process::Command::new("git")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(available, Ok(status) if status.success()) {
            return;
        }

        let ordinary = std::process::Command::new("git")
            .current_dir(&cwd)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .unwrap();
        assert!(
            ordinary.status.success(),
            "fixture ancestor must be discoverable"
        );

        let mut hardened = hardened_git_process(&cwd);
        let output = hardened
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .await
            .unwrap();
        assert!(
            !output.status.success(),
            "hardened Git must not discover an ancestor repository"
        );
    }

    #[test]
    fn parse_git_source_rejects_missing_prefix() {
        let err = parse_git_source("https://github.com/owner/repo").unwrap_err();
        assert!(err.contains("expected `git+"));
    }

    #[test]
    fn parse_git_source_rejects_unknown_inner_scheme() {
        let err = parse_git_source("git+ftp://example.com").unwrap_err();
        assert!(err.contains("git+https"));
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
        // Unapproved hosts are rejected before DNS or subprocess execution.
        let err = resolve_latest_version("git+https://nonexistent-host.invalid/owner/repo")
            .await
            .unwrap_err();
        assert!(err.contains("not an approved public forge"));
        assert!(!err.contains("nonexistent-host"));
    }

    #[tokio::test]
    async fn capture_bounded_drains_but_caps_retained_output() {
        use tokio::io::AsyncWriteExt as _;

        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            writer.write_all(&vec![b'x'; 4096]).await.unwrap();
        });
        let captured = capture_bounded(reader, 128).await.unwrap();
        write.await.unwrap();

        assert_eq!(captured.bytes.len(), 128);
        assert_eq!(captured.total_bytes, 4096);
        assert!(captured.truncated);
    }
}
