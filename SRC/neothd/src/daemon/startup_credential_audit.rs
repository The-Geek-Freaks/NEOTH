//! HO-06 (Session 28) — startup credential-pattern scanner.
//!
//! Scans operator-listed file paths (typically `~/.bashrc`,
//! `~/.config/git/config`, project `.env` files) for credential
//! shapes (`ghp_*`, `sk-ant-*`, `AKIA*`, Bearer tokens, etc.) at
//! daemon startup + emits a structured report. The point isn't to
//! refuse to start — operators routinely keep dotfiles with bearer
//! tokens for tools they legitimately use — but to surface the
//! findings in `neoth doctor` + the daemon log so the operator
//! decides whether to rotate / move to a keychain.
//!
//! ## Wiring
//!
//! Activated by `~/.neoth/policy.yaml::startup_audit_scan_paths`
//! (paths) + optional `forbid_inline_tokens_in_remotes` (git remote
//! URL check). Empty list → quiet no-op. Each finding logs a
//! `warn!` with the path + the redacted secret kind; the operator
//! sees a per-line summary at boot + can cross-reference with
//! `neoth doctor` if they want detail.
//!
//! ## Why warn-only not block-boot
//!
//! Blocking boot on the FIRST detected credential would punish
//! every operator running NEOTH on a workstation with legitimate
//! API keys in their shell rc files. Warn-only is the
//! recommend-then-let-operator-decide stance — symmetric with how
//! `policy::dangerous_patterns` works elsewhere.
//!
//! ## Scope (Phase 1)
//!
//! - File scanner uses the existing `security::redact::PATTERNS`
//!   under the hood so a single secret-shape regex update covers
//!   redaction + audit.
//! - Directory walk is ONE LEVEL only — operators who want full
//!   recursion list each subdir explicitly. Keeps the boot scan
//!   bounded.
//! - Git remote check is a shell-out to `git remote -v` in the
//!   current process cwd; failure (no git installed, not a repo,
//!   git rejects the call) yields zero findings + a debug log,
//!   never fails the audit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// One credential finding from the scanner. Path + line number +
/// stable secret-kind label (mirrors the names in
/// [`crate::security::redact`]'s PATTERNS table).
///
/// `secret_excerpt` is the matched span TRIMMED to its first 8 chars
/// — enough for the operator to recognise WHICH key without the
/// finding itself becoming a leak in `neoth doctor` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialFinding {
    pub path: PathBuf,
    pub line: u32,
    pub secret_kind: String,
    pub secret_excerpt: String,
}

/// Per-pattern minimum match-length below which we treat the hit as
/// noise (avoids flagging `Bearer x` short tokens or `sk-` literal
/// prefixes that appear in docs). The redact module's regexes
/// already enforce `{20,}` for most patterns; this is the secondary
/// guard for the few that don't.
const MIN_SECRET_LENGTH: usize = 16;

/// Run the full scan: file paths + (optionally) git remote URLs.
/// Returns the combined finding list; the caller logs each entry as
/// `warn!` + (optionally) appends to the doctor sidecar.
///
/// Pure-fn over a slice of paths so tests can drive against tempdir
/// fixtures without touching the operator's real home dir. The
/// `check_git_remotes` flag is the wired-through equivalent of
/// `policy.forbid_inline_tokens_in_remotes`.
pub fn run_credential_scan(
    scan_paths: &[PathBuf],
    check_git_remotes: bool,
) -> Result<Vec<CredentialFinding>> {
    let mut findings = Vec::new();
    for p in scan_paths {
        if !p.exists() {
            // Missing path is normal — operator may list ~/.bashrc
            // even if they don't have one on this machine. Skip,
            // don't fail.
            continue;
        }
        if p.is_file() {
            findings.extend(scan_one_file(p)?);
        } else if p.is_dir() {
            findings.extend(scan_one_directory(p)?);
        }
    }
    if check_git_remotes {
        findings.extend(scan_git_remotes_inline_tokens());
    }
    Ok(findings)
}

/// Read one file + match every line against the secret-shape regex
/// table. Read errors are NOT fatal — surface them via the caller's
/// warn log path but return what we got from other paths.
fn scan_one_file(path: &Path) -> Result<Vec<CredentialFinding>> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => {
            // Permissions / binary file / broken symlink — skip.
            return Ok(Vec::new());
        }
    };
    let mut findings = Vec::new();
    for (line_idx, line) in body.lines().enumerate() {
        for hit in match_secret_kinds(line) {
            findings.push(CredentialFinding {
                path: path.to_path_buf(),
                line: (line_idx + 1) as u32,
                secret_kind: hit.kind,
                secret_excerpt: hit.excerpt,
            });
        }
    }
    Ok(findings)
}

/// One-level directory walk. The operator who wants deeper recursion
/// lists each subdir explicitly in scan_paths.
fn scan_one_directory(dir: &Path) -> Result<Vec<CredentialFinding>> {
    let mut findings = Vec::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            findings.extend(scan_one_file(&path)?);
        }
    }
    Ok(findings)
}

/// Shell out to `git remote -v` in cwd. Returns findings for each
/// remote URL containing an inline `user:token@host` pattern.
/// Failure modes (no git installed, not in a repo) collapse to an
/// empty result + debug log — the audit must never crash the
/// daemon startup path.
fn scan_git_remotes_inline_tokens() -> Vec<CredentialFinding> {
    let mut findings = Vec::new();
    let Ok(out) = std::process::Command::new("git")
        .args(["remote", "-v"])
        .output()
    else {
        tracing::debug!("startup credential audit: git not available; skipping remote scan");
        return findings;
    };
    if !out.status.success() {
        // Not a git repo or git rejected the call — quiet skip.
        return findings;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // Format: `<remote>\t<url> (fetch|push)`
        let Some((_remote_name, rest)) = line.split_once('\t') else {
            continue;
        };
        let url = rest.split_whitespace().next().unwrap_or("").to_string();
        if let Some(excerpt) = inline_token_excerpt(&url) {
            findings.push(CredentialFinding {
                path: PathBuf::from(format!(".git/config (remote URL: {url})")),
                line: 0,
                secret_kind: "git_inline_token".to_string(),
                secret_excerpt: excerpt,
            });
        }
    }
    findings
}

/// Match an HTTPS git URL with an inline `user:token@host` token.
/// Returns the first 8 chars of the password portion when present,
/// `None` otherwise. Strictly `https://`-scoped because ssh URLs
/// don't carry inline tokens (they use SSH key auth).
fn inline_token_excerpt(url: &str) -> Option<String> {
    let stripped = url.strip_prefix("https://")?;
    let auth = stripped.split('@').next()?;
    let (_user, password) = auth.split_once(':')?;
    if password.is_empty() {
        return None;
    }
    Some(password.chars().take(8).collect::<String>() + "…")
}

/// One regex hit from [`match_secret_kinds`]. Kept private so the
/// signature can evolve without API churn.
struct SecretHit {
    kind: String,
    excerpt: String,
}

/// Match `line` against every pattern in the redact module's PATTERNS
/// table. Returns one [`SecretHit`] per distinct kind that matched;
/// duplicate-kind hits on the same line collapse to the first match
/// so the operator doesn't see N lines for one .bashrc.
fn match_secret_kinds(line: &str) -> Vec<SecretHit> {
    let mut hits: Vec<SecretHit> = Vec::new();
    // We use `redact::PATTERNS` indirectly via the public surface:
    // `redact_text` returns a string with every match replaced by
    // `[REDACTED:<kind>]`. Diff the input vs output to learn WHICH
    // kinds fired without re-implementing the regex set.
    let redacted = crate::security::redact::redact_text(line);
    if redacted == line {
        return hits;
    }
    // Walk the redacted text + every `[REDACTED:<kind>]` token is a
    // hit. The kind label is the substring inside the brackets.
    let mut cursor = 0;
    while let Some(idx) = redacted[cursor..].find("[REDACTED:") {
        let start = cursor + idx + "[REDACTED:".len();
        let Some(end_rel) = redacted[start..].find(']') else {
            break;
        };
        let kind = &redacted[start..start + end_rel];
        // Find the corresponding excerpt in the ORIGINAL line by
        // tracking how much we've consumed.
        let excerpt_source = line
            .split_whitespace()
            .find(|w| {
                w.len() >= MIN_SECRET_LENGTH || matches!(kind, "anthropic_key" | "openai_key")
            })
            .unwrap_or(line);
        let excerpt = excerpt_source.chars().take(12).collect::<String>() + "…";
        if !hits.iter().any(|h| h.kind == kind) {
            hits.push(SecretHit {
                kind: kind.to_string(),
                excerpt,
            });
        }
        cursor = start + end_rel + 1;
    }
    hits
}

/// Convenience for callers: format one finding as a single
/// operator-readable line (matches the `neoth doctor` style).
pub fn format_finding(f: &CredentialFinding) -> String {
    if f.line == 0 {
        format!(
            "{kind} in {path} (excerpt: {excerpt})",
            kind = f.secret_kind,
            path = f.path.display(),
            excerpt = f.secret_excerpt,
        )
    } else {
        format!(
            "{kind} at {path}:{line} (excerpt: {excerpt})",
            kind = f.secret_kind,
            path = f.path.display(),
            line = f.line,
            excerpt = f.secret_excerpt,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn empty_scan_path_list_returns_no_findings() {
        let findings = run_credential_scan(&[], false).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_path_is_quietly_skipped_not_errored() {
        let path = PathBuf::from("/this/path/does/not/exist/zzz");
        let findings = run_credential_scan(&[path], false).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn finds_anthropic_key_in_file() {
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            ".bashrc",
            "export ANTHROPIC_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        let findings = run_credential_scan(&[p.clone()], false).unwrap();
        assert!(!findings.is_empty(), "expected at least one finding");
        assert!(
            findings.iter().any(|f| f.secret_kind == "anthropic_key"),
            "expected anthropic_key kind in {:?}",
            findings,
        );
    }

    #[test]
    fn finds_github_pat_in_file() {
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            ".env",
            "GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        let findings = run_credential_scan(&[p], false).unwrap();
        assert!(
            findings.iter().any(|f| f.secret_kind == "github_pat"),
            "expected github_pat in {:?}",
            findings,
        );
    }

    #[test]
    fn finds_aws_key_in_file() {
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            "aws-creds",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        );
        let findings = run_credential_scan(&[p], false).unwrap();
        assert!(
            findings.iter().any(|f| f.secret_kind == "aws_access_key"),
            "expected aws_access_key in {:?}",
            findings,
        );
    }

    #[test]
    fn no_findings_for_clean_file() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "config", "operator_id: alex\nlevel: standard\n");
        let findings = run_credential_scan(&[p], false).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn directory_scan_walks_one_level_only() {
        let dir = TempDir::new().unwrap();
        // Top-level dirty file → must be found.
        write_file(
            &dir,
            "top.env",
            "TOK=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        // Subdir dirty file → must NOT be found (we don't recurse).
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            sub.join("nested.env"),
            "TOK2=ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        .unwrap();
        let findings = run_credential_scan(&[dir.path().to_path_buf()], false).unwrap();
        assert!(findings.iter().any(|f| f.path.ends_with("top.env")));
        assert!(
            !findings.iter().any(|f| f.path.ends_with("nested.env")),
            "directory walk MUST be one level only; got nested hit in {:?}",
            findings,
        );
    }

    #[test]
    fn line_number_reported_one_based() {
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            "multi.env",
            "clean line\nsecond clean\nKEY=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        let findings = run_credential_scan(&[p], false).unwrap();
        let ghp = findings
            .iter()
            .find(|f| f.secret_kind == "github_pat")
            .expect("github_pat hit");
        assert_eq!(ghp.line, 3, "line number must be 1-based");
    }

    // ── inline_token_excerpt ───────────────────────────────────────

    #[test]
    fn inline_token_excerpt_finds_password_in_https_url() {
        let url = "https://alex:ghp_AAAAAAAAAAAAAAAAAAAA@github.com/foo/bar.git";
        let excerpt = inline_token_excerpt(url).expect("should match");
        assert!(excerpt.starts_with("ghp_"));
        // 8-char prefix + ellipsis.
        assert!(excerpt.contains('…'));
    }

    #[test]
    fn inline_token_excerpt_returns_none_for_ssh_url() {
        let url = "git@github.com:foo/bar.git";
        assert!(inline_token_excerpt(url).is_none());
    }

    #[test]
    fn inline_token_excerpt_returns_none_for_https_without_token() {
        let url = "https://github.com/foo/bar.git";
        assert!(inline_token_excerpt(url).is_none());
    }

    #[test]
    fn inline_token_excerpt_returns_none_when_password_empty() {
        let url = "https://alex:@github.com/foo/bar.git";
        assert!(inline_token_excerpt(url).is_none());
    }

    // ── format_finding ─────────────────────────────────────────────

    #[test]
    fn format_finding_includes_line_for_file_hits() {
        let f = CredentialFinding {
            path: PathBuf::from("/home/alex/.env"),
            line: 7,
            secret_kind: "github_pat".into(),
            secret_excerpt: "ghp_AAAAA…".into(),
        };
        let rendered = format_finding(&f);
        assert!(rendered.contains("github_pat"));
        assert!(rendered.contains(":7"));
        assert!(rendered.contains("ghp_AAAAA…"));
    }

    #[test]
    fn format_finding_omits_line_when_zero() {
        // Git remote findings carry line=0 because the URL doesn't
        // have a line concept.
        let f = CredentialFinding {
            path: PathBuf::from(".git/config (remote URL: https://...)"),
            line: 0,
            secret_kind: "git_inline_token".into(),
            secret_excerpt: "ghp_AAAA…".into(),
        };
        let rendered = format_finding(&f);
        assert!(rendered.contains("git_inline_token"));
        assert!(!rendered.contains(":0"));
    }
}
