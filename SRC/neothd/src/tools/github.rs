//! GitHub CLI shim (A-3 + A-4).
//!
//! Wraps the operator's existing `gh` CLI (already installed via
//! `installers/mod.rs`) so NEOTH can list/create issues, list/view
//! PRs, and post inline comments without owning a full Octocrab client.
//! `gh` carries the operator's auth; NEOTH never touches the token.
//!
//! Why shell out instead of using octocrab: `gh` is already configured
//! on the operator's machine with their OAuth scopes, GHE host, and
//! enterprise SSO. Re-implementing all of that in Rust would duplicate
//! months of GitHub-side work for marginal gain. Subprocess + `--json`
//! flags give structured output without parser drift.

use anyhow::{Context, Result};
use std::process::Command;

/// Locate the `gh` binary. `$PATH` lookup with the standard Windows
/// `.exe` suffix handling — operators on linux/macOS hit the bare
/// `gh` name. Returns `None` when the binary isn't installed; CLI
/// callers turn that into an actionable "run `neoth update --apply`
/// or install gh manually" message.
pub fn locate_gh() -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) { "gh.exe" } else { "gh" };
    std::env::var_os("PATH")?
        .to_str()
        .map(|s| s.to_string())?
        .split(if cfg!(windows) { ';' } else { ':' })
        .map(|dir| std::path::Path::new(dir).join(exe))
        .find(|p| p.exists())
}

/// Run `gh <args>` + return parsed stdout. Errors propagate the gh
/// exit code + stderr so the operator sees the actual GitHub error
/// message, not "subprocess failed".
/// Validate an `owner/repo` slug before it reaches `gh --repo` (GOLD-SEC-23
/// / A-85). Only `[A-Za-z0-9._-]` segments separated by exactly one `/` —
/// so an operator/LLM-supplied value can't smuggle a `gh` flag (e.g.
/// `--json` / `-X`) or an argument-injection token.
fn validate_repo(repo: &str) -> Result<()> {
    let segs: Vec<&str> = repo.split('/').collect();
    let seg_ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if segs.len() != 2 || !seg_ok(segs[0]) || !seg_ok(segs[1]) {
        anyhow::bail!("github: invalid repo {repo:?} (expected owner/name using [A-Za-z0-9._-])");
    }
    Ok(())
}

/// Validate an issue/PR `--state` against gh's allowed set (GOLD-SEC-23 / A-85).
fn validate_state(state: &str) -> Result<()> {
    if !matches!(state, "open" | "closed" | "merged" | "all") {
        anyhow::bail!("github: invalid state {state:?} (expected open|closed|merged|all)");
    }
    Ok(())
}

fn run_gh(args: &[&str]) -> Result<String> {
    let bin = locate_gh().ok_or_else(|| {
        anyhow::anyhow!(
            "github: `gh` CLI not on PATH. \
             Run `neoth update --apply` to install, or set up gh manually \
             from https://cli.github.com/."
        )
    })?;
    let output = Command::new(bin)
        .args(args)
        .output()
        .context("spawn gh subprocess")?;
    if !output.status.success() {
        anyhow::bail!(
            "gh exit {} — {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Issue {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author: GhAuthor,
    pub url: String,
    #[serde(default)]
    pub labels: Vec<GhLabel>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GhAuthor {
    pub login: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GhLabel {
    pub name: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author: GhAuthor,
    pub url: String,
    #[serde(rename = "headRefName")]
    pub head: String,
    #[serde(rename = "baseRefName")]
    pub base: String,
    #[serde(default)]
    pub draft: bool,
}

/// `gh issue list --repo <repo> --json ...`
pub fn list_issues(repo: Option<&str>, state: Option<&str>, limit: usize) -> Result<Vec<Issue>> {
    let limit_s = limit.clamp(1, 100).to_string();
    let mut args: Vec<&str> = vec!["issue", "list"];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    if let Some(s) = state {
        validate_state(s)?;
        args.push("--state");
        args.push(s);
    }
    args.push("--limit");
    args.push(&limit_s);
    args.push("--json");
    args.push("number,title,state,author,url,labels");
    let json = run_gh(&args)?;
    serde_json::from_str(&json).context("decode `gh issue list` json")
}

/// `gh issue create --repo <repo> --title <title> --body <body>`.
/// Returns the created issue's URL on success.
pub fn create_issue(repo: Option<&str>, title: &str, body: &str) -> Result<String> {
    if title.trim().is_empty() {
        anyhow::bail!("github: issue title must not be empty");
    }
    let mut args: Vec<&str> = vec!["issue", "create"];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    args.push("--title");
    args.push(title);
    args.push("--body");
    args.push(body);
    let stdout = run_gh(&args)?;
    // gh prints the URL on the first non-empty line.
    let url = stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("gh issue create returned no URL"))?
        .trim()
        .to_string();
    Ok(url)
}

/// `gh pr create --title <title> --body <body> [--base <base>] [--repo <repo>]
/// [--draft]`. Uses the current branch as the PR head (gh's default). Returns
/// the created PR's URL on success. Consumer: `neoth github pr-create` + the
/// `git_pr_create` skill (GOLD-ADAPT-GITPR-01/02).
pub fn create_pr(
    repo: Option<&str>,
    title: &str,
    body: &str,
    base: Option<&str>,
    draft: bool,
) -> Result<String> {
    if title.trim().is_empty() {
        anyhow::bail!("github: PR title must not be empty");
    }
    let mut args: Vec<&str> = vec!["pr", "create"];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    args.push("--title");
    args.push(title);
    args.push("--body");
    args.push(body);
    if let Some(b) = base {
        args.push("--base");
        args.push(b);
    }
    if draft {
        args.push("--draft");
    }
    let stdout = run_gh(&args)?;
    // gh prints the URL on the first non-empty line.
    let url = stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("gh pr create returned no URL"))?
        .trim()
        .to_string();
    Ok(url)
}

/// `gh pr list --repo <repo> --json ...`
pub fn list_prs(repo: Option<&str>, state: Option<&str>, limit: usize) -> Result<Vec<PullRequest>> {
    let limit_s = limit.clamp(1, 100).to_string();
    let mut args: Vec<&str> = vec!["pr", "list"];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    if let Some(s) = state {
        validate_state(s)?;
        args.push("--state");
        args.push(s);
    }
    args.push("--limit");
    args.push(&limit_s);
    args.push("--json");
    args.push("number,title,state,author,url,headRefName,baseRefName,draft");
    let json = run_gh(&args)?;
    serde_json::from_str(&json).context("decode `gh pr list` json")
}

/// `gh pr view <number> --json ...` — fetch a single PR's full body
/// for review. Returns the raw JSON to keep the schema flexible.
pub fn view_pr(repo: Option<&str>, number: u64) -> Result<serde_json::Value> {
    let number_s = number.to_string();
    let mut args: Vec<&str> = vec!["pr", "view", &number_s];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    args.push("--json");
    args.push("number,title,body,author,url,state,headRefName,baseRefName,reviews,commits,additions,deletions");
    let json = run_gh(&args)?;
    serde_json::from_str(&json).context("decode `gh pr view` json")
}

/// `gh pr review <number> --comment --body <text>` — post a single
/// PR-level review comment. Operator opts into "approve" / "request
/// changes" via the `verdict` parameter.
pub fn review_pr(
    repo: Option<&str>,
    number: u64,
    verdict: ReviewVerdict,
    body: &str,
) -> Result<()> {
    if body.trim().is_empty() {
        anyhow::bail!("github: review body must not be empty");
    }
    let number_s = number.to_string();
    let mut args: Vec<&str> = vec!["pr", "review", &number_s];
    if let Some(r) = repo {
        validate_repo(r)?;
        args.push("--repo");
        args.push(r);
    }
    args.push(verdict.flag());
    args.push("--body");
    args.push(body);
    let _ = run_gh(&args)?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum ReviewVerdict {
    Comment,
    Approve,
    RequestChanges,
}

impl ReviewVerdict {
    fn flag(self) -> &'static str {
        match self {
            ReviewVerdict::Comment => "--comment",
            ReviewVerdict::Approve => "--approve",
            ReviewVerdict::RequestChanges => "--request-changes",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "comment" => Some(Self::Comment),
            "approve" => Some(Self::Approve),
            "request-changes" | "changes" | "block" => Some(Self::RequestChanges),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_gh_returns_some_or_none() {
        // Smoke: never panics regardless of whether gh is installed.
        let _ = locate_gh();
    }

    #[test]
    fn create_issue_rejects_empty_title() {
        let err = create_issue(None, "", "body").unwrap_err();
        assert!(err.to_string().contains("title must not be empty"));
    }

    #[test]
    fn review_pr_rejects_empty_body() {
        let err = review_pr(None, 1, ReviewVerdict::Comment, "").unwrap_err();
        assert!(err.to_string().contains("review body"));
    }

    #[test]
    fn review_verdict_parses_known_labels() {
        assert!(matches!(
            ReviewVerdict::parse("comment"),
            Some(ReviewVerdict::Comment)
        ));
        assert!(matches!(
            ReviewVerdict::parse("approve"),
            Some(ReviewVerdict::Approve)
        ));
        assert!(matches!(
            ReviewVerdict::parse("changes"),
            Some(ReviewVerdict::RequestChanges)
        ));
        assert!(ReviewVerdict::parse("yolo").is_none());
    }

    #[test]
    fn review_verdict_flag_matches_gh_cli_surface() {
        assert_eq!(ReviewVerdict::Comment.flag(), "--comment");
        assert_eq!(ReviewVerdict::Approve.flag(), "--approve");
        assert_eq!(ReviewVerdict::RequestChanges.flag(), "--request-changes");
    }

    // ── CDX-04: gh-CLI JSON-shape drift guards ────────────────────────────
    //
    // This module shells out to `gh --json ...` rather than hitting the
    // GitHub REST API directly, so wiremock doesn't apply. The drift
    // risk is the `gh` CLI's --json output format. These fixtures pin
    // realistic `gh issue list` / `gh pr list` / `gh pr view` shapes
    // against the local `Issue` + `PullRequest` deserializers so an
    // upstream rename (e.g. `headRefName` → `head_ref_name`) trips here
    // before it ships.

    #[test]
    fn issue_deserializes_realistic_gh_json_list_entry() {
        let json = r#"{
            "number": 142,
            "title": "Crash on empty config",
            "state": "OPEN",
            "author": {"login": "alice"},
            "url": "https://github.com/owner/repo/issues/142",
            "labels": [{"name": "bug"}, {"name": "needs-triage"}]
        }"#;
        let issue: Issue = serde_json::from_str(json).expect("issue decode");
        assert_eq!(issue.number, 142);
        assert_eq!(issue.title, "Crash on empty config");
        assert_eq!(issue.state, "OPEN");
        assert_eq!(issue.author.login, "alice");
        assert_eq!(issue.labels.len(), 2);
        assert_eq!(issue.labels[0].name, "bug");
    }

    #[test]
    fn issue_decodes_when_labels_absent() {
        // `gh issue list` omits `labels` when none are set — the
        // `#[serde(default)]` keeps the decoder honest.
        let json = r#"{
            "number": 1,
            "title": "x",
            "state": "OPEN",
            "author": {"login": "bob"},
            "url": "https://github.com/x/y/issues/1"
        }"#;
        let issue: Issue = serde_json::from_str(json).unwrap();
        assert!(issue.labels.is_empty());
    }

    #[test]
    fn pull_request_deserializes_headref_and_baseref_renames() {
        // `gh pr view --json` returns headRefName / baseRefName in
        // camelCase. The serde renames are load-bearing; this test
        // pins them.
        let json = r#"{
            "number": 7,
            "title": "feat: webhook listener",
            "state": "OPEN",
            "author": {"login": "carol"},
            "url": "https://github.com/owner/repo/pull/7",
            "headRefName": "feat/webhook",
            "baseRefName": "main",
            "draft": false
        }"#;
        let pr: PullRequest = serde_json::from_str(json).expect("pr decode");
        assert_eq!(pr.number, 7);
        assert_eq!(pr.head, "feat/webhook");
        assert_eq!(pr.base, "main");
        assert!(!pr.draft);
    }

    #[test]
    fn pull_request_draft_defaults_to_false_when_missing() {
        // Some gh versions omit `draft` for non-draft PRs.
        let json = r#"{
            "number": 8,
            "title": "x",
            "state": "MERGED",
            "author": {"login": "d"},
            "url": "https://github.com/o/r/pull/8",
            "headRefName": "branch",
            "baseRefName": "main"
        }"#;
        let pr: PullRequest = serde_json::from_str(json).unwrap();
        assert!(!pr.draft);
    }

    #[test]
    fn issue_list_array_round_trips_through_serde() {
        // `gh issue list --json ...` returns a JSON array. The CLI
        // path serde::from_str's the whole array; pinning the shape
        // here catches an array-of-objects vs object-with-array drift.
        let json = r#"[
            {
                "number": 1,
                "title": "first",
                "state": "OPEN",
                "author": {"login": "x"},
                "url": "u1",
                "labels": []
            },
            {
                "number": 2,
                "title": "second",
                "state": "CLOSED",
                "author": {"login": "y"},
                "url": "u2",
                "labels": [{"name": "wontfix"}]
            }
        ]"#;
        let issues: Vec<Issue> = serde_json::from_str(json).unwrap();
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].title, "first");
        assert_eq!(issues[1].labels[0].name, "wontfix");
    }

    #[test]
    fn validate_repo_accepts_owner_name_rejects_injection() {
        // GOLD-SEC-23 / A-85
        assert!(validate_repo("The-Geek-Freaks/NEOTH").is_ok());
        assert!(validate_repo("owner.with.dots/repo_name").is_ok());
        assert!(validate_repo("--json").is_err()); // flag smuggling
        assert!(validate_repo("owner/repo/extra").is_err()); // too many segments
        assert!(validate_repo("owner only").is_err()); // space / no slash
        assert!(validate_repo("/repo").is_err()); // empty owner
        assert!(validate_repo("owner/").is_err()); // empty name
        assert!(validate_repo("a;b/c").is_err()); // stray punctuation
    }

    #[test]
    fn validate_state_allowlist_only() {
        for ok in ["open", "closed", "merged", "all"] {
            assert!(validate_state(ok).is_ok(), "{ok}");
        }
        assert!(validate_state("--limit").is_err());
        assert!(validate_state("OPEN").is_err()); // case-sensitive (gh expects lowercase)
        assert!(validate_state("").is_err());
    }
}
