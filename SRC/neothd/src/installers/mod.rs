//! CLI auto-installer for the three first-class LLM front-ends.
//!
//! Operator requirement: `neoth init` provisions claude-cli, gemini-cli and
//! codex from inside the wizard. Operator never opens npm or a terminal.
//! See `memory/neoth_cli_installers.md`.
//!
//! Architecture: each CLI is described by a `CliKind` constant carrying
//! npm package name + binary name + login command. Common probe / install /
//! login logic lives in the helpers below; everything else is per-CLI data.
//!
//! Out of scope here (deferred):
//! - Auto-installing Node + npm itself. Operator must have npm on PATH.
//! - Updating an already-installed CLI. We probe, report, move on.
//! - Sandboxing the npm install — global npm is the standard pattern.

use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

/// One of the three CLIs NEOTH knows how to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CliKind {
    /// Display name for log messages and the wizard.
    pub display: &'static str,
    /// PATH-resolvable binary name (without `.cmd`/`.exe`).
    pub binary: &'static str,
    /// npm package to install globally.
    pub npm_package: &'static str,
    /// Optional login command. `None` means env-var auth only (codex with
    /// OPENAI_API_KEY). `Some(args)` triggers `<binary> <args...>` interactively.
    pub login_args: Option<&'static [&'static str]>,
}

pub const CLAUDE: CliKind = CliKind {
    display: "Claude Code (Anthropic)",
    binary: "claude",
    npm_package: "@anthropic-ai/claude-code",
    login_args: Some(&["/login"]),
};

pub const GEMINI: CliKind = CliKind {
    display: "Gemini CLI (Google)",
    binary: "gemini",
    npm_package: "@google/gemini-cli",
    login_args: Some(&["auth", "login"]),
};

pub const CODEX: CliKind = CliKind {
    display: "Codex CLI (OpenAI)",
    binary: "codex",
    npm_package: "@openai/codex",
    login_args: Some(&["login"]),
};

/// Iteration helper for the wizard.
pub const ALL: &[CliKind] = &[CLAUDE, GEMINI, CODEX];

/// Probe `npm --version`. Returns the version string on success, None when
/// npm is missing or returns non-zero.
pub async fn npm_version() -> Option<String> {
    cli_version_async("npm").await
}

/// Probe `<binary> --version`. Wraps through `cmd /C` on Windows so npm
/// shims (`claude.cmd`, `gemini.cmd`, `codex.cmd`) work the same way as
/// proper `.exe` binaries.
pub async fn cli_version_async(binary: &str) -> Option<String> {
    let result = spawn_cli(binary, &["--version"])
        .ok()?
        .wait_with_output()
        .await
        .ok()?;
    if !result.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&result.stdout).trim().to_string())
}

/// Install `kind.npm_package` via `npm install -g`. Streams npm's stderr to
/// the wizard's tracing output so the operator sees download progress.
pub async fn install_kind(kind: CliKind) -> Result<()> {
    info!(
        package = kind.npm_package,
        display = kind.display,
        "running `npm install -g {}`",
        kind.npm_package
    );
    let mut child = spawn_cli("npm", &["install", "-g", kind.npm_package])
        .with_context(|| format!("spawn npm install -g {}", kind.npm_package))?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("await npm install {}", kind.npm_package))?;
    if !status.success() {
        anyhow::bail!(
            "npm install -g {} failed (exit {:?}). Is npm reachable + writable? \
             You may need elevated privileges, or `npm config set prefix ~/.npm-global` \
             and PATH adjustments.",
            kind.npm_package,
            status.code()
        );
    }
    info!(package = kind.npm_package, "install ok");
    Ok(())
}

/// Run the CLI's login command interactively. Inherits operator stdin/stdout/stderr
/// so OAuth browser prompts appear in the wizard's terminal. Returns Ok even if
/// the login subprocess exits non-zero — the operator may legitimately abort.
pub async fn login_kind(kind: CliKind) -> Result<()> {
    let Some(args) = kind.login_args else {
        info!(
            display = kind.display,
            "no login command — env-var auth assumed"
        );
        return Ok(());
    };
    info!(
        display = kind.display,
        "starting login: {} {:?}", kind.binary, args
    );
    let status = spawn_cli_inherit(kind.binary, args)?
        .wait()
        .await
        .with_context(|| format!("await {} login", kind.display))?;
    if !status.success() {
        warn!(
            display = kind.display,
            code = status.code(),
            "login subprocess exited non-zero; operator may have aborted"
        );
    }
    Ok(())
}

/// Spawn a CLI with stdout/stderr piped (for version probing + install).
/// On Windows wraps through `cmd /C` so npm shell-script shims work.
fn spawn_cli(binary: &str, args: &[&str]) -> std::io::Result<tokio::process::Child> {
    let mut cmd = build_cmd(binary, args);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Spawn a CLI inheriting parent stdio (for interactive login).
fn spawn_cli_inherit(binary: &str, args: &[&str]) -> Result<tokio::process::Child> {
    build_cmd(binary, args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn `{binary}` interactively"))
}

pub(crate) fn build_cmd(binary: &str, args: &[&str]) -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = Command::new(binary);
        for a in args {
            cmd.arg(a);
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_clis_have_distinct_binaries() {
        let binaries: Vec<&str> = ALL.iter().map(|c| c.binary).collect();
        assert_eq!(binaries.len(), 3);
        assert!(binaries.contains(&"claude"));
        assert!(binaries.contains(&"gemini"));
        assert!(binaries.contains(&"codex"));
    }

    #[test]
    fn npm_package_format_is_scoped() {
        // All three vendors publish under their own npm scope. If any of these
        // suddenly becomes unscoped, the install pattern needs review.
        assert!(CLAUDE.npm_package.starts_with("@"));
        assert!(GEMINI.npm_package.starts_with("@"));
        assert!(CODEX.npm_package.starts_with("@"));
    }

    #[tokio::test]
    async fn npm_version_returns_some_or_none() {
        // Smoke test: probe doesn't panic on either outcome. Real value
        // depends on whether the test machine has node installed.
        let v = npm_version().await;
        if let Some(version) = v {
            // Looks like a version: at least one digit somewhere.
            assert!(version.chars().any(|c| c.is_ascii_digit()));
        }
    }
}
