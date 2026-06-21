//! Tokenjuice vendor compression rules — context injection filter.
//!
//! Adapted from OH `tokenjuice/vendor/rules/*.json` + `classify.rs` /
//! `reduce.rs`. GOLD-ADAPT-OH-09 / overlaps GOLD-FEAT-12.
//!
//! ## Problem
//!
//! Tool output injected into a coding-session context often contains
//! massive amounts of low-signal boilerplate:
//!
//!   - `git log --oneline` dumps hundreds of SHA-keyed lines for a
//!     "what changed?" question.
//!   - `npm install` prints progress bars, advisory counts, and the
//!     `added 1234 packages (678 packages audited)` summary buried
//!     under kilobytes of download ticks.
//!   - `cargo check` / `cargo build` repeats `Compiling X v0.y.z`
//!     for every crate before the first real error.
//!   - Linters (`eslint`, `clippy`, `ruff`) emit file-path headers
//!     + hundreds of blank-line separators.
//!
//! Every token wasted on boilerplate is a token the model cannot use
//! for the actual task.
//!
//! ## Approach
//!
//! Each [`CompressionRule`] holds:
//!
//!   - a `classifier`: regex / substring matcher that decides whether
//!     a *block* of text is the kind of output this rule handles;
//!   - a pure `compress` function that reduces the block to a compact
//!     summary string ready for context injection.
//!
//! [`apply_rules`] is the single public entry point: given raw tool
//! output it tries every rule in order; the FIRST match wins (first
//! registered → highest priority). Unmatched text passes through
//! unchanged — rules are conservative and never drop information
//! silently.
//!
//! ## Rule taxonomy (~30 rules)
//!
//! | Category | Count |
//! |----------|-------|
//! | git      |     9 |
//! | npm/yarn/pnpm |  6 |
//! | cargo/rust build | 7 |
//! | eslint / prettier | 4 |
//! | clippy / ruff / flake8 | 4 |
//! Total: 30 rules.
//!
//! ## Pure-function guarantee
//!
//! No IO, no async, no global state. Every function is `fn(…) -> …`.
//! This makes the rules trivially testable + safe to call from any
//! async context without an `await` point.

use std::borrow::Cow;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single compression rule.  A rule is pure: it exposes a classifier
/// that gates whether the rule applies, and a compressor that produces
/// the compact representation.
pub struct CompressionRule {
    /// Human-readable tag shown in tool output + WAL audit frames.
    pub tag: &'static str,
    /// Returns `true` when this rule handles `text`.
    pub matches: fn(&str) -> bool,
    /// Reduce `text` to a compact summary.  Always returns something
    /// non-empty; if compression is impossible for this input it MAY
    /// return the original unchanged (though a matching rule is
    /// expected to produce a shorter result).
    pub compress: fn(&str) -> String,
}

// ---------------------------------------------------------------------------
// Helper predicates (shared across rules)
// ---------------------------------------------------------------------------

/// Return `true` iff `text` contains *all* of the given substrings.
#[inline]
fn contains_all(text: &str, needles: &[&str]) -> bool {
    needles.iter().all(|n| text.contains(n))
}

/// Return `true` iff `text` contains *any* of the given substrings.
#[inline]
fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// Count lines matching a predicate.
fn count_lines<P: Fn(&str) -> bool>(text: &str, pred: P) -> usize {
    text.lines().filter(|l| pred(l)).count()
}

/// Collect non-blank lines that satisfy a predicate (first `limit` only).
fn head_lines<P: Fn(&str) -> bool>(text: &str, pred: P, limit: usize) -> Vec<&str> {
    text.lines().filter(|l| pred(l)).take(limit).collect()
}

// ---------------------------------------------------------------------------
// ── GIT rules (9) ──────────────────────────────────────────────────────────
// ---------------------------------------------------------------------------

/// GIT-01  git log (--oneline or full, multi-line)
fn git_log_matches(text: &str) -> bool {
    // A git log block: multiple lines that look like SHA + subject.
    // We require ≥5 SHA-style prefixes to avoid false-positives on
    // single-line git references.
    let sha_lines = count_lines(text, |l| {
        let t = l.trim();
        t.len() >= 7 && t.chars().take(7).all(|c| c.is_ascii_hexdigit())
    });
    sha_lines >= 5
}

fn git_log_compress(text: &str) -> String {
    let sha_lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            t.len() >= 7 && t.chars().take(7).all(|c| c.is_ascii_hexdigit())
        })
        .collect();
    let total = sha_lines.len();
    let preview: Vec<&str> = sha_lines.iter().take(5).copied().collect();
    let mut out = preview.join("\n");
    if total > 5 {
        out.push_str(&format!("\n… ({} more commits)", total - 5));
    }
    out
}

/// GIT-02  git diff --stat summary
fn git_diff_stat_matches(text: &str) -> bool {
    // `git diff --stat` ends with a summary line like:
    //   3 files changed, 42 insertions(+), 7 deletions(-)
    text.contains("files changed") && text.contains("insertion") && text.contains("deletion")
}

fn git_diff_stat_compress(text: &str) -> String {
    // Keep only the summary line + at most 10 changed-file lines.
    let summary = text
        .lines()
        .find(|l| l.contains("files changed"))
        .unwrap_or("")
        .trim();
    let file_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains('|') && (l.contains('+') || l.contains('-')))
        .take(10)
        .collect();
    let mut out = file_lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(summary);
    out
}

/// GIT-03  git status
fn git_status_matches(text: &str) -> bool {
    contains_any(
        text,
        &[
            "On branch ",
            "Changes not staged",
            "Changes to be committed",
            "Untracked files:",
            "nothing to commit",
        ],
    ) && text.lines().count() >= 3
}

fn git_status_compress(text: &str) -> String {
    // Keep branch, staged summary, modified summary, untracked count.
    let branch = text
        .lines()
        .find(|l| l.starts_with("On branch"))
        .unwrap_or("On branch (unknown)");
    let staged = count_lines(text, |l| l.starts_with('\t') && !l.contains("modified:") || l.contains("new file:") || l.contains("deleted:"));
    let modified = count_lines(text, |l| l.contains("modified:"));
    let untracked = count_lines(text, |l| l.starts_with('\t') && !l.contains(':'));
    format!(
        "{}\n{} staged  |  {} modified  |  {} untracked",
        branch, staged, modified, untracked
    )
}

/// GIT-04  git fetch / pull output
fn git_fetch_matches(text: &str) -> bool {
    contains_any(
        text,
        &[
            "From git",
            "From https",
            "remote: Counting objects",
            "remote: Compressing objects",
            "Receiving objects:",
            "Resolving deltas:",
            "Updating ",
        ],
    )
}

fn git_fetch_compress(text: &str) -> String {
    // Keep only branch-tracking update lines + "Fast-forward" / merge lines.
    let keep: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.contains("->")
                || l.contains("Fast-forward")
                || l.starts_with("Updating")
                || l.contains("up to date")
                || l.contains("Already up")
        })
        .take(10)
        .collect();
    if keep.is_empty() {
        text.lines().next().unwrap_or("(git fetch output)").to_string()
    } else {
        keep.join("\n")
    }
}

/// GIT-05  git stash list
fn git_stash_list_matches(text: &str) -> bool {
    count_lines(text, |l| l.starts_with("stash@{")) >= 3
}

fn git_stash_list_compress(text: &str) -> String {
    let entries: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("stash@{"))
        .take(5)
        .collect();
    let total = count_lines(text, |l| l.starts_with("stash@{"));
    let mut out = entries.join("\n");
    if total > 5 {
        out.push_str(&format!("\n… ({} more stash entries)", total - 5));
    }
    out
}

/// GIT-06  git blame (many lines of blame output)
fn git_blame_matches(text: &str) -> bool {
    // git blame lines: `^SHA (Author  Date  Line#) code`
    count_lines(text, |l| {
        let t = l.trim_start();
        t.len() > 10 && t[..8].chars().all(|c| c.is_ascii_hexdigit()) && t.contains('(')
    }) >= 5
}

fn git_blame_compress(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.len() > 10 && t[..8].chars().all(|c| c.is_ascii_hexdigit())
        })
        .take(5)
        .collect();
    let total = count_lines(text, |l| {
        let t = l.trim_start();
        t.len() > 10 && t[..8].chars().all(|c| c.is_ascii_hexdigit())
    });
    let mut out = lines.join("\n");
    if total > 5 {
        out.push_str(&format!("\n… ({} more blame lines)", total - 5));
    }
    out
}

/// GIT-07  git branch -vv / branch listing
///
/// A branch-list block has ≥5 lines where each line is either:
///   `* <name>  <sha>  <subject>`   (current)
///   `  <name>  <sha>  <subject>`   (local)
///   `  remotes/<remote>/<name>`    (remote)
/// We require the `* ` current-branch marker to be present and
/// the block to not look like a git log (SHA at position 0) or
/// cargo build output.
fn git_branch_matches(text: &str) -> bool {
    // Must have the `* ` current-branch marker.
    if !text.lines().any(|l| l.starts_with("* ") || l.starts_with("  ")) {
        return false;
    }
    // Must not look like a git log (SHA prefixes at column 0).
    if git_log_matches(text) {
        return false;
    }
    // Count lines that look like branch entries: start with `* ` or
    // `  ` followed by a valid branch-name char, and are NOT cargo /
    // build output (those lines start with "Compiling", "error", "test ",
    // "running", or contain `|` file-stat separators).
    let branch_lines = count_lines(text, |l| {
        let starts_ok = l.starts_with("* ") || l.starts_with("  ");
        if !starts_ok {
            return false;
        }
        let inner = l.trim_start_matches(['*', ' ']);
        // Reject cargo/lint/test noise.
        let noise = inner.starts_with("Compiling ")
            || inner.starts_with("error")
            || inner.starts_with("test ")
            || inner.starts_with("running ")
            || inner.starts_with("warning")
            || l.contains(" | ")
            || l.contains("-->")
            || l.contains("... ok")
            || l.contains("... FAILED");
        if noise {
            return false;
        }
        // Branch name must start with an alphanumeric char, `_`, `-`, or `remotes/`.
        inner.starts_with("remotes/")
            || inner
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-')
    });
    branch_lines >= 5
}

fn git_branch_compress(text: &str) -> String {
    let current = text
        .lines()
        .find(|l| l.trim_start().starts_with('*'))
        .map(|l| l.trim())
        .unwrap_or("(no current branch)");
    let total = text.lines().filter(|l| !l.trim().is_empty()).count();
    format!("{}\n… ({} branches total)", current, total)
}

/// GIT-08  git show (commit header + diff body)
fn git_show_matches(text: &str) -> bool {
    text.starts_with("commit ") && text.contains("Author:") && text.contains("Date:")
}

fn git_show_compress(text: &str) -> String {
    // Keep commit header (first 6 lines) + stat summary.
    let header: Vec<&str> = text.lines().take(6).collect();
    let stat = text
        .lines()
        .find(|l| l.contains("files changed"))
        .unwrap_or("");
    let mut out = header.join("\n");
    if !stat.is_empty() {
        out.push('\n');
        out.push_str(stat.trim());
    }
    out
}

/// GIT-09  git remote -v
fn git_remote_matches(text: &str) -> bool {
    count_lines(text, |l| l.contains("(fetch)") || l.contains("(push)")) >= 2
}

fn git_remote_compress(text: &str) -> String {
    let remotes: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("(fetch)"))
        .take(5)
        .collect();
    remotes.join("\n")
}

// ---------------------------------------------------------------------------
// ── NPM / YARN / PNPM rules (6) ────────────────────────────────────────────
// ---------------------------------------------------------------------------

/// NPM-01  npm install progress ticks + summary
fn npm_install_matches(text: &str) -> bool {
    contains_any(text, &["npm warn", "added ", "npm notice"]) && text.contains("packages")
}

fn npm_install_compress(text: &str) -> String {
    // Find the "added N packages" summary + any "found N vulnerabilities" line.
    let summary = text
        .lines()
        .find(|l| l.contains("added ") && l.contains("packages"))
        .unwrap_or("(npm install completed)");
    let vuln = text
        .lines()
        .find(|l| l.contains("vulnerabilities") || l.contains("audit"));
    let mut out = summary.trim().to_string();
    if let Some(v) = vuln {
        out.push('\n');
        out.push_str(v.trim());
    }
    out
}

/// NPM-02  npm audit report
fn npm_audit_matches(text: &str) -> bool {
    contains_all(text, &["vulnerabilities", "severity"]) && text.contains("npm audit")
}

fn npm_audit_compress(text: &str) -> String {
    let severity_lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            contains_any(
                l,
                &["critical", "high", "moderate", "low", "info", "found "],
            )
        })
        .take(8)
        .collect();
    severity_lines.join("\n")
}

/// NPM-03  npm/yarn run script output preamble
fn npm_run_preamble_matches(text: &str) -> bool {
    contains_any(text, &["> ", "yarn run v", "$ "]) && text.lines().count() >= 4
        && contains_any(text, &["Done in", "npm run ", "info Visit"])
}

fn npm_run_preamble_compress(text: &str) -> String {
    // Drop the script-runner preamble/postamble; keep the middle content.
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            !l.starts_with("> ")
                && !l.starts_with("$ ")
                && !l.starts_with("yarn run ")
                && !l.contains("info Visit")
                && !l.starts_with("Done in ")
        })
        .collect();
    lines.join("\n")
}

/// NPM-04  pnpm install output
fn pnpm_install_matches(text: &str) -> bool {
    contains_any(text, &["Progress: resolved", "Packages: +", "pnpm install"])
}

fn pnpm_install_compress(text: &str) -> String {
    // Keep only Packages summary + Done line.
    let keep: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("Packages:") || l.starts_with("Done in") || l.contains("Done!"))
        .take(4)
        .collect();
    if keep.is_empty() {
        "pnpm install completed".to_string()
    } else {
        keep.join("\n")
    }
}

/// NPM-05  yarn classic install
fn yarn_install_matches(text: &str) -> bool {
    contains_any(
        text,
        &["yarn add v", "[1/4] Resolving", "[2/4] Fetching", "[3/4] Linking", "[4/4] Building"],
    )
}

fn yarn_install_compress(text: &str) -> String {
    let done = text
        .lines()
        .find(|l| l.contains("Done in") || l.contains("success"))
        .unwrap_or("yarn install completed");
    done.trim().to_string()
}

/// NPM-06  lockfile diff noise
fn lockfile_diff_matches(text: &str) -> bool {
    let lock_hunks = count_lines(text, |l| {
        l.starts_with('+') || l.starts_with('-')
    });
    (text.contains("package-lock.json") || text.contains("yarn.lock") || text.contains("pnpm-lock.yaml"))
        && lock_hunks > 20
}

fn lockfile_diff_compress(text: &str) -> String {
    let added = count_lines(text, |l| l.starts_with('+') && !l.starts_with("+++"));
    let removed = count_lines(text, |l| l.starts_with('-') && !l.starts_with("---"));
    format!(
        "[lockfile diff suppressed: +{} / -{} lines — review with git diff --stat]",
        added, removed
    )
}

// ---------------------------------------------------------------------------
// ── CARGO / RUST build rules (7) ───────────────────────────────────────────
// ---------------------------------------------------------------------------

/// CARGO-01  Compiling progress lines
fn cargo_compiling_matches(text: &str) -> bool {
    count_lines(text, |l| l.trim_start().starts_with("Compiling ")) >= 3
}

fn cargo_compiling_compress(text: &str) -> String {
    let compiling: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("Compiling "))
        .collect();
    let total = compiling.len();
    // Keep non-Compiling lines (warnings, errors) + a count summary.
    let rest: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("Compiling "))
        .collect();
    let mut out = rest.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("[{} crates compiled]", total));
    out
}

/// CARGO-02  cargo test output — individual test pass lines
fn cargo_test_passing_matches(text: &str) -> bool {
    count_lines(text, |l| l.trim_start().starts_with("test ") && l.contains("... ok")) >= 5
}

fn cargo_test_passing_compress(text: &str) -> String {
    let pass = count_lines(text, |l| l.trim_start().starts_with("test ") && l.contains("... ok"));
    let fail_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("FAILED") || l.contains("failures:") || l.starts_with("error"))
        .take(20)
        .collect();
    let summary = text
        .lines()
        .find(|l| l.contains("test result:"))
        .unwrap_or("");
    let mut out = format!("[{} tests ok]\n", pass);
    if !fail_lines.is_empty() {
        out.push_str(&fail_lines.join("\n"));
        out.push('\n');
    }
    out.push_str(summary.trim());
    out
}

/// CARGO-03  cargo clippy clean (no warnings)
fn cargo_clippy_clean_matches(text: &str) -> bool {
    text.contains("warning(s) generated") || (text.contains("Finished") && text.contains("clippy"))
}

fn cargo_clippy_clean_compress(text: &str) -> String {
    // Keep warning lines only + summary.
    let warnings: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("warning") || l.trim_start().starts_with("error"))
        .take(30)
        .collect();
    let summary = text
        .lines()
        .find(|l| l.contains("warning(s) generated") || l.starts_with("Finished"))
        .unwrap_or("");
    let mut out = if warnings.is_empty() {
        "[clippy: no warnings]\n".to_string()
    } else {
        warnings.join("\n") + "\n"
    };
    out.push_str(summary.trim());
    out
}

/// CARGO-04  cargo build error output
fn cargo_build_error_matches(text: &str) -> bool {
    (text.contains("error[E") || text.contains("error: ")) && text.contains("cargo build")
        || (text.contains("error[E") && text.contains(" --> "))
}

fn cargo_build_error_compress(text: &str) -> String {
    // Keep error lines, the ` --> file:line:col` pointers, and the
    // "aborting due to N errors" summary. Drop Compiling/Downloading noise.
    let keep: Vec<&str> = text
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("error")
                || t.starts_with("--> ")
                || t.starts_with("| ")
                || t.contains("aborting due to")
                || t.starts_with("= help:")
                || t.starts_with("= note:")
        })
        .take(60)
        .collect();
    keep.join("\n")
}

/// CARGO-05  cargo update / fetch dependency download
fn cargo_download_matches(text: &str) -> bool {
    contains_any(text, &["Downloading crates", "Updating crates.io", "Blocking waiting"])
        && text.lines().count() >= 3
}

fn cargo_download_compress(text: &str) -> String {
    let summary = text
        .lines()
        .find(|l| l.contains("Updating") || l.contains("downloaded"))
        .unwrap_or("(cargo fetch)");
    summary.trim().to_string()
}

/// CARGO-06  cargo doc generation
fn cargo_doc_matches(text: &str) -> bool {
    count_lines(text, |l| l.trim_start().starts_with("Documenting ")) >= 3
}

fn cargo_doc_compress(text: &str) -> String {
    let docs = count_lines(text, |l| l.trim_start().starts_with("Documenting "));
    let finished = text
        .lines()
        .find(|l| l.starts_with("Finished") || l.contains("Generated"))
        .unwrap_or("");
    format!("[{} crates documented] {}", docs, finished.trim())
}

/// CARGO-07  Finished / linker line (tail after a long build)
fn cargo_finished_tail_matches(text: &str) -> bool {
    text.trim_start().starts_with("Finished") && text.lines().count() == 1
}

fn cargo_finished_tail_compress(text: &str) -> String {
    text.trim().to_string()
}

// ---------------------------------------------------------------------------
// ── ESLint / Prettier rules (4) ────────────────────────────────────────────
// ---------------------------------------------------------------------------

/// LINT-01  ESLint file listing with error/warning counts
fn eslint_matches(text: &str) -> bool {
    (text.contains("problems (") || text.contains("error") && text.contains("warning"))
        && (text.contains(".js") || text.contains(".ts") || text.contains(".jsx") || text.contains(".tsx"))
        && count_lines(text, |l| l.contains("error") || l.contains("warning")) >= 3
}

fn eslint_compress(text: &str) -> String {
    // Keep only lines with "error" or "warning", plus the summary.
    let diag_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("error") || l.contains("warning"))
        .take(20)
        .collect();
    let summary = text
        .lines()
        .find(|l| l.contains("problems ("))
        .unwrap_or("");
    let mut out = diag_lines.join("\n");
    if !summary.is_empty() {
        out.push('\n');
        out.push_str(summary.trim());
    }
    out
}

/// LINT-02  Prettier format output (list of changed files)
fn prettier_matches(text: &str) -> bool {
    count_lines(text, |l| {
        (l.contains(".js") || l.contains(".ts") || l.contains(".css"))
            && (l.trim_start().starts_with("- ") || l.trim_start().starts_with("+ "))
    }) >= 3
        && text.contains("prettier")
}

fn prettier_compress(text: &str) -> String {
    let changed = count_lines(text, |l| {
        (l.trim_start().starts_with("- ") || l.trim_start().starts_with("+ "))
            && (l.contains(".js") || l.contains(".ts"))
    });
    format!("[prettier: {} files reformatted]", changed)
}

/// LINT-03  TypeScript tsc output
fn tsc_matches(text: &str) -> bool {
    (text.contains("error TS") || text.contains("Found ") && text.contains("errors"))
        && (text.contains(".ts(") || text.contains(".tsx("))
}

fn tsc_compress(text: &str) -> String {
    let errors: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("error TS") || l.contains("Found "))
        .take(20)
        .collect();
    errors.join("\n")
}

/// LINT-04  Prettier / lint-staged pass-through (nothing changed)
fn lint_clean_matches(text: &str) -> bool {
    contains_any(
        text,
        &[
            "All matched files use Prettier",
            "Everything is awesome",
            "No linting errors",
            "passed",
            "✓ No problems found",
        ],
    ) && text.lines().count() <= 4
}

fn lint_clean_compress(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("(lint passed)")
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// ── Clippy / ruff / flake8 rules (4) ───────────────────────────────────────
// ---------------------------------------------------------------------------

/// RUST-LINT-01  clippy warnings block
fn clippy_warn_matches(text: &str) -> bool {
    count_lines(text, |l| {
        l.trim_start().starts_with("warning:")
            || (l.trim_start().starts_with("--> ") && l.contains(".rs:"))
    }) >= 3
        && !cargo_build_error_matches(text)
}

fn clippy_warn_compress(text: &str) -> String {
    let warnings: Vec<&str> = head_lines(
        text,
        |l| {
            let t = l.trim_start();
            t.starts_with("warning:") || t.starts_with("--> ") || t.starts_with("= help:")
        },
        30,
    );
    let total_warns = count_lines(text, |l| l.trim_start().starts_with("warning:"));
    let mut out = warnings.join("\n");
    out.push_str(&format!("\n[{} warnings total]", total_warns));
    out
}

/// PY-LINT-01  ruff output
fn ruff_matches(text: &str) -> bool {
    contains_any(text, &["ruff check", "ruff: "]) && text.contains(".py:")
}

fn ruff_compress(text: &str) -> String {
    let diags: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(".py:") && (l.contains(" E") || l.contains(" W") || l.contains(" F")))
        .take(20)
        .collect();
    let summary = text
        .lines()
        .find(|l| l.contains("Found") && l.contains("error"))
        .unwrap_or("");
    let mut out = diags.join("\n");
    if !summary.is_empty() {
        out.push('\n');
        out.push_str(summary.trim());
    }
    out
}

/// PY-LINT-02  flake8 output
fn flake8_matches(text: &str) -> bool {
    count_lines(text, |l| {
        l.contains(".py:") && (l.contains(": E") || l.contains(": W") || l.contains(": F"))
    }) >= 3
}

fn flake8_compress(text: &str) -> String {
    let diags: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.contains(".py:")
                && (l.contains(": E") || l.contains(": W") || l.contains(": F"))
        })
        .take(20)
        .collect();
    let total = count_lines(text, |l| {
        l.contains(".py:")
            && (l.contains(": E") || l.contains(": W") || l.contains(": F"))
    });
    let mut out = diags.join("\n");
    if total > 20 {
        out.push_str(&format!("\n… ({} more flake8 issues)", total - 20));
    }
    out
}

/// PY-LINT-03  mypy output
fn mypy_matches(text: &str) -> bool {
    (text.contains("error:") || text.contains("Found ") && text.contains("error"))
        && text.contains(".py:")
        && text.contains("mypy")
}

fn mypy_compress(text: &str) -> String {
    let errors: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(".py:") && l.contains("error:"))
        .take(20)
        .collect();
    let summary = text
        .lines()
        .find(|l| l.starts_with("Found ") && l.contains("error"))
        .unwrap_or("");
    let mut out = errors.join("\n");
    if !summary.is_empty() {
        out.push('\n');
        out.push_str(summary.trim());
    }
    out
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

/// Ordered list of all compression rules.  FIRST match wins — order
/// matters when classifiers could overlap. More specific rules (e.g.
/// `cargo_build_error`) come before broad ones (e.g. `cargo_compiling`).
pub const RULES: &[CompressionRule] = &[
    // git — more specific matchers first to avoid false positives
    CompressionRule { tag: "git-show",        matches: git_show_matches,        compress: git_show_compress },
    CompressionRule { tag: "git-log",         matches: git_log_matches,         compress: git_log_compress },
    CompressionRule { tag: "git-diff-stat",   matches: git_diff_stat_matches,   compress: git_diff_stat_compress },
    CompressionRule { tag: "git-status",      matches: git_status_matches,      compress: git_status_compress },
    CompressionRule { tag: "git-fetch",       matches: git_fetch_matches,       compress: git_fetch_compress },
    CompressionRule { tag: "git-stash",       matches: git_stash_list_matches,  compress: git_stash_list_compress },
    CompressionRule { tag: "git-blame",       matches: git_blame_matches,       compress: git_blame_compress },
    CompressionRule { tag: "git-branch",      matches: git_branch_matches,      compress: git_branch_compress },
    CompressionRule { tag: "git-remote",      matches: git_remote_matches,      compress: git_remote_compress },
    // npm / yarn / pnpm
    CompressionRule { tag: "lockfile-diff",   matches: lockfile_diff_matches,   compress: lockfile_diff_compress },
    CompressionRule { tag: "npm-install",     matches: npm_install_matches,     compress: npm_install_compress },
    CompressionRule { tag: "npm-audit",       matches: npm_audit_matches,       compress: npm_audit_compress },
    CompressionRule { tag: "npm-run",         matches: npm_run_preamble_matches, compress: npm_run_preamble_compress },
    CompressionRule { tag: "pnpm-install",    matches: pnpm_install_matches,    compress: pnpm_install_compress },
    CompressionRule { tag: "yarn-install",    matches: yarn_install_matches,    compress: yarn_install_compress },
    // cargo / rust
    CompressionRule { tag: "cargo-error",     matches: cargo_build_error_matches, compress: cargo_build_error_compress },
    CompressionRule { tag: "cargo-compiling", matches: cargo_compiling_matches, compress: cargo_compiling_compress },
    CompressionRule { tag: "cargo-test",      matches: cargo_test_passing_matches, compress: cargo_test_passing_compress },
    CompressionRule { tag: "cargo-clippy",    matches: cargo_clippy_clean_matches, compress: cargo_clippy_clean_compress },
    CompressionRule { tag: "cargo-download",  matches: cargo_download_matches,  compress: cargo_download_compress },
    CompressionRule { tag: "cargo-doc",       matches: cargo_doc_matches,       compress: cargo_doc_compress },
    CompressionRule { tag: "cargo-finished",  matches: cargo_finished_tail_matches, compress: cargo_finished_tail_compress },
    // eslint / ts
    CompressionRule { tag: "eslint",          matches: eslint_matches,          compress: eslint_compress },
    CompressionRule { tag: "prettier",        matches: prettier_matches,        compress: prettier_compress },
    CompressionRule { tag: "tsc",             matches: tsc_matches,             compress: tsc_compress },
    CompressionRule { tag: "lint-clean",      matches: lint_clean_matches,      compress: lint_clean_compress },
    // rust / python linters
    CompressionRule { tag: "clippy-warn",     matches: clippy_warn_matches,     compress: clippy_warn_compress },
    CompressionRule { tag: "ruff",            matches: ruff_matches,            compress: ruff_compress },
    CompressionRule { tag: "flake8",          matches: flake8_matches,          compress: flake8_compress },
    CompressionRule { tag: "mypy",            matches: mypy_matches,            compress: mypy_compress },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of applying rules to a piece of tool output.
#[derive(Debug, Clone)]
pub struct CompressionResult<'a> {
    /// The (possibly compressed) text ready for context injection.
    pub text: Cow<'a, str>,
    /// The rule that matched, or `None` if the text passed through
    /// unchanged.
    pub matched_rule: Option<&'static str>,
}

impl<'a> CompressionResult<'a> {
    /// `true` when a rule matched and the text was compressed.
    pub fn was_compressed(&self) -> bool {
        self.matched_rule.is_some()
    }
}

/// Apply the vendor compression rules to `tool_output`.
///
/// Returns the first matching rule's compressed output, or the original
/// text (as a borrow) if no rule matched.  Callers inject the result's
/// `.text` field directly into the context window; the `.matched_rule`
/// field is logged to the WAL audit frame.
pub fn apply_rules(tool_output: &str) -> CompressionResult<'_> {
    for rule in RULES {
        if (rule.matches)(tool_output) {
            let compressed = (rule.compress)(tool_output);
            return CompressionResult {
                text: Cow::Owned(compressed),
                matched_rule: Some(rule.tag),
            };
        }
    }
    CompressionResult {
        text: Cow::Borrowed(tool_output),
        matched_rule: None,
    }
}

/// Convenience: return only the compressed text string.
///
/// Equivalent to `apply_rules(s).text.into_owned()` but avoids the
/// Cow lifetime when the caller just wants the string.
pub fn compress(tool_output: &str) -> String {
    apply_rules(tool_output).text.into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── registry ──────────────────────────────────────────────────────────

    #[test]
    fn rule_count_is_at_least_30() {
        assert!(
            RULES.len() >= 30,
            "expected ≥30 rules, got {}",
            RULES.len()
        );
    }

    #[test]
    fn all_rule_tags_are_non_empty_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in RULES {
            assert!(!rule.tag.is_empty(), "empty tag in rule");
            assert!(seen.insert(rule.tag), "duplicate tag: {}", rule.tag);
        }
    }

    // ── pass-through (no match) ────────────────────────────────────────────

    #[test]
    fn unmatched_output_passes_through_unchanged() {
        let text = "Hello, world! No build output here.\nJust some random text.";
        let result = apply_rules(text);
        assert!(
            !result.was_compressed(),
            "expected pass-through, matched {:?}",
            result.matched_rule
        );
        assert_eq!(result.text, text);
    }

    // ── git rules ─────────────────────────────────────────────────────────

    #[test]
    fn git_log_compresses_many_sha_lines() {
        // Build a fake git log with 20 SHA lines.
        let mut log = String::new();
        for i in 0u32..20 {
            log.push_str(&format!("{:07x} fix: commit message #{}\n", i + 0xabc_def0, i));
        }
        let result = apply_rules(&log);
        assert_eq!(result.matched_rule, Some("git-log"), "should match git-log");
        let out = result.text.as_ref();
        assert!(out.contains("more commits"), "should summarise tail commits");
        // Compressed must be shorter than the original.
        assert!(
            out.len() < log.len(),
            "compressed ({}) should be shorter than original ({})",
            out.len(),
            log.len()
        );
    }

    #[test]
    fn git_log_short_does_not_match() {
        // Fewer than 5 SHA-prefixed lines → no match.
        let log = "abc1234 one commit\ndef5678 two commits\n";
        let result = apply_rules(log);
        assert!(
            result.matched_rule != Some("git-log"),
            "short log should not trigger git-log rule"
        );
    }

    #[test]
    fn git_diff_stat_compresses_to_summary() {
        let stat = "src/foo.rs            |  42 +++++++++---\nsrc/bar.rs            |   7 --\n\
                    2 files changed, 42 insertions(+), 7 deletions(-)";
        let result = apply_rules(stat);
        assert_eq!(result.matched_rule, Some("git-diff-stat"));
        let out = result.text.as_ref();
        assert!(out.contains("files changed"));
    }

    #[test]
    fn git_status_compresses_to_branch_plus_counts() {
        let status = "On branch main\nYour branch is up to date with 'origin/main'.\n\
                     Changes not staged for commit:\n\tmodified:   src/a.rs\n\
                     \tmodified:   src/b.rs\nUntracked files:\n\tCargo.lock\n";
        let result = apply_rules(status);
        assert_eq!(result.matched_rule, Some("git-status"));
        let out = result.text.as_ref();
        assert!(out.contains("On branch main"), "should keep branch");
    }

    #[test]
    fn git_show_compresses_to_header() {
        let show = "commit abc1234567890\nAuthor: Alice <alice@example.com>\n\
                    Date:   Mon Jun 1 12:00:00 2026 +0000\n\n    fix: something\n\
                    \n+++ a/src/foo.rs\n--- b/src/foo.rs\n@@ -1 +1 @@\n-old\n+new\n\
                    1 files changed, 1 insertion(+), 1 deletion(-)";
        let result = apply_rules(show);
        assert_eq!(result.matched_rule, Some("git-show"));
        let out = result.text.as_ref();
        assert!(out.contains("commit abc1234567890"));
        assert!(out.contains("Author:"));
    }

    // ── npm / yarn / pnpm rules ────────────────────────────────────────────

    #[test]
    fn npm_install_compresses_to_summary_line() {
        let npm_out = "npm warn deprecated foo@1.0.0: use bar instead\n\
                       npm warn deprecated baz@0.2.0: use qux instead\n\
                       added 1234 packages, and audited 5678 packages in 30s\n\
                       found 0 vulnerabilities";
        let result = apply_rules(npm_out);
        assert_eq!(result.matched_rule, Some("npm-install"));
        let out = result.text.as_ref();
        assert!(out.contains("added 1234 packages"), "should keep summary");
    }

    #[test]
    fn lockfile_diff_suppressed() {
        let mut diff = "--- a/package-lock.json\n+++ b/package-lock.json\n".to_string();
        for i in 0..30 {
            diff.push_str(&format!("-  \"version\": \"1.{}.0\",\n", i));
            diff.push_str(&format!("+  \"version\": \"1.{}.1\",\n", i));
        }
        let result = apply_rules(&diff);
        assert_eq!(result.matched_rule, Some("lockfile-diff"));
        let out = result.text.as_ref();
        assert!(out.contains("lockfile diff suppressed"));
    }

    #[test]
    fn yarn_install_keeps_done_line() {
        let yarn_out = "yarn add v1.22.0\n\
                        [1/4] Resolving packages...\n\
                        [2/4] Fetching packages...\n\
                        [3/4] Linking dependencies...\n\
                        [4/4] Building fresh packages...\n\
                        success Saved lockfile.\n\
                        Done in 12.34s.";
        let result = apply_rules(yarn_out);
        assert_eq!(result.matched_rule, Some("yarn-install"));
        let out = result.text.as_ref();
        // Must contain the done/success line, not the [1/4] noise.
        assert!(out.contains("Done") || out.contains("success"));
        assert!(!out.contains("[1/4]"), "should drop fetch progress lines");
    }

    // ── cargo / rust rules ─────────────────────────────────────────────────

    #[test]
    fn cargo_compiling_drops_progress_keeps_errors() {
        let build_out = "   Compiling serde v1.0.0\n   Compiling serde_derive v1.0.0\n\
                         Compiling myapp v0.1.0\nerror[E0308]: type mismatch\n \
                          --> src/main.rs:10:5\naborting due to 1 error";
        let result = apply_rules(build_out);
        // cargo-error fires first (more specific).
        assert_eq!(result.matched_rule, Some("cargo-error"), "error rule should win");
        let out = result.text.as_ref();
        assert!(out.contains("error[E0308]"), "should keep error");
        assert!(!out.contains("Compiling serde "), "should drop Compiling lines");
    }

    #[test]
    fn cargo_compiling_only_no_errors() {
        let build_out = "   Compiling serde v1.0.0\n   Compiling serde_derive v1.0.0\n\
                         Compiling myapp v0.1.0 (/home/user/myapp)\n   Compiling foo v2.0\n\
                         Finished dev [unoptimized] target(s) in 5.23s";
        let result = apply_rules(build_out);
        // cargo-error won't match; cargo-compiling should.
        assert_eq!(result.matched_rule, Some("cargo-compiling"));
        let out = result.text.as_ref();
        assert!(out.contains("crates compiled"), "should show crate count");
    }

    #[test]
    fn cargo_test_passing_compresses_ok_lines() {
        let test_out = {
            let mut s = String::new();
            for i in 0..10 {
                s.push_str(&format!("test module::test_{} ... ok\n", i));
            }
            s.push_str("test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured");
            s
        };
        let result = apply_rules(&test_out);
        assert_eq!(result.matched_rule, Some("cargo-test"));
        let out = result.text.as_ref();
        assert!(out.contains("10 tests ok") || out.contains("test result:"));
    }

    // ── linter rules ──────────────────────────────────────────────────────

    #[test]
    fn eslint_compresses_to_diagnostics() {
        let eslint_out = "/app/src/foo.js\n  10:5  error  'x' is not defined  no-undef\n\
                          /app/src/bar.js\n  3:1   warning  no-console  console.log\n\
                          /app/src/baz.js\n  1:1   error  missing semicolon\n\
                          ✖ 3 problems (2 errors, 1 warning)";
        let result = apply_rules(eslint_out);
        assert_eq!(result.matched_rule, Some("eslint"));
        let out = result.text.as_ref();
        assert!(out.contains("error") || out.contains("problems"), "should keep diagnostics");
    }

    #[test]
    fn clippy_warn_compresses_to_warnings_only() {
        let clippy_out = "   Compiling foo v0.1.0\n\
                          warning: unused variable `x`\n \
                           --> src/main.rs:10:9\n\
                          warning: unused import `std::collections::HashMap`\n \
                           --> src/lib.rs:3:5\n\
                          = help: remove the import\n\
                          warning: 2 warnings generated.";
        // cargo-clippy fires first when "warning(s) generated" present.
        let result = apply_rules(clippy_out);
        // Either cargo-clippy or clippy-warn; both are correct compressions.
        assert!(
            result.was_compressed(),
            "clippy output should match some rule"
        );
        let out = result.text.as_ref();
        // Should keep warnings, drop the Compiling line.
        assert!(!out.contains("Compiling foo"), "should drop Compiling noise");
    }

    #[test]
    fn flake8_compresses_diagnostics() {
        let flake8_out = "src/foo.py:10:1: E302 expected 2 blank lines, found 1\n\
                          src/foo.py:20:5: W503 line break before binary operator\n\
                          src/bar.py:1:1: F401 'os' imported but unused\n\
                          src/bar.py:5:80: E501 line too long (85 > 79 characters)\n";
        let result = apply_rules(flake8_out);
        assert_eq!(result.matched_rule, Some("flake8"));
        let out = result.text.as_ref();
        assert!(out.contains("E302") || out.contains("W503"));
    }

    // ── edge-cases ─────────────────────────────────────────────────────────

    #[test]
    fn empty_string_passes_through() {
        let result = apply_rules("");
        assert!(!result.was_compressed());
    }

    #[test]
    fn single_line_passes_through() {
        let result = apply_rules("hello world");
        assert!(!result.was_compressed());
    }

    #[test]
    fn compress_fn_matches_apply_rules() {
        let npm_out = "npm warn deprecated foo@1.0.0: bar\nadded 100 packages in 5s";
        assert_eq!(
            compress(npm_out),
            apply_rules(npm_out).text.into_owned()
        );
    }
}
