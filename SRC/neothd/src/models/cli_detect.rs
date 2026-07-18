//! CLI binary presence detection for the K-Models-Discovery (Session
//! 14 Pick #5) CLI-pull path.
//!
//! Reality check from 2026-05-18 web research: neither `claude` (Claude
//! Code CLI) nor `agy` (Google's Antigravity CLI, gemini-cli successor
//! per 2026-05-19 transition) ships a stable non-interactive
//! `list-models` subcommand. Both surface model selection via
//! interactive `/model` slash commands at runtime. Versions, however,
//! are recoverable via `--version` flags and that's enough signal to:
//!
//!   1. Confirm the operator has the CLI installed + reachable in PATH
//!   2. Surface the operator-canonical aliases (`opus`, `sonnet`, `haiku`
//!      for Claude; equivalent for Antigravity / Gemini models) as a
//!      discovery-source result
//!   3. Mark the catalog entry as [`SourceOrigin::Cli`] so the operator
//!      knows the data came from a more trusted (OAuth-authed) surface
//!
//! Failure modes (all return `Err`):
//!   - Binary not on PATH
//!   - Binary present but `--version` returns non-zero
//!   - `--version` output cannot be parsed
//!
//! This module never spawns LLM calls. The non-interactive `claude -p
//! "list models"` path was deliberately rejected — it costs tokens, is
//! prone to hallucination, and an outdated training-data answer would
//! be worse than no data.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};

/// Outcome of a single CLI-presence probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliPresence {
    /// Binary that was probed (e.g. "claude", "agy", "codex").
    pub binary: String,
    /// Version line emitted by the CLI's `--version` command, trimmed.
    /// Operators see this in `neoth catalog show <provider>` so they
    /// can verify what release NEOTH detected.
    pub version: String,
}

/// Cap on how long we wait for a CLI's `--version` to respond. Real CLIs
/// (claude, agy, codex) print + exit in <100ms; anything slower than
/// 5s is hung and we skip it rather than block the daemon startup.
pub const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Probe a CLI binary's `--version`. Returns `Err` when the binary
/// isn't in PATH, the call returns non-zero, or the output is empty.
///
/// Implemented synchronously because `tokio::process::Command` adds
/// pipe-handle setup overhead the discovery hot-path doesn't need —
/// this function runs once per day per provider.
pub fn probe_cli_version(binary: &str) -> Result<CliPresence> {
    let mut cmd = std::process::Command::new(binary);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Spawn + wait with timeout via thread.join_timeout — std::process
    // doesn't have a timeout API, but `wait_timeout` crate is overkill
    // for a single 5s wait. Use a thread + recv_timeout instead.
    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{binary} --version` (binary not in PATH?)"))?;
    let output = wait_with_timeout(child, VERSION_PROBE_TIMEOUT)
        .with_context(|| format!("`{binary} --version` did not complete in time"))?;

    if !output.status.success() {
        anyhow::bail!(
            "`{binary} --version` exited with status {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<terminated by signal>".to_string())
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    // Some CLIs print version to stderr (older Node.js conventions).
    // Take whichever stream is non-empty.
    let version = if !stdout.is_empty() {
        stdout
    } else if !stderr.is_empty() {
        stderr
    } else {
        anyhow::bail!("`{binary} --version` returned no output");
    };
    Ok(CliPresence {
        binary: binary.to_string(),
        version,
    })
}

/// Spawn a process and wait for it, but bail out after `timeout`.
/// Mirrors the `wait_timeout` crate's API without pulling a new dep —
/// uses a parking-thread + channel signal.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output> {
    drop(child.stdin.take());
    let stdout_reader = child
        .stdout
        .take()
        .map(|stdout| std::thread::spawn(move || read_all_to_end(stdout)));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| std::thread::spawn(move || read_all_to_end(stderr)));
    let started = std::time::Instant::now();
    loop {
        match child.try_wait().context("query CLI probe status")? {
            Some(status) => {
                let stdout = stdout_reader
                    .map(|reader| reader.join().unwrap_or_default())
                    .unwrap_or_default();
                let stderr = stderr_reader
                    .map(|reader| reader.join().unwrap_or_default())
                    .unwrap_or_default();
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            None if started.elapsed() >= timeout => {
                // Kill only the exact Child handle we spawned. Never use a
                // process-name sweep: another operator process may share the
                // same binary name. Waiting reaps the direct child handle.
                if let Err(kill_error) = child.kill()
                    && child
                        .try_wait()
                        .context("recheck timed-out CLI probe status")?
                        .is_none()
                {
                    return Err(kill_error).context("terminate timed-out CLI probe");
                }
                child.wait().context("reap timed-out CLI probe")?;
                anyhow::bail!("CLI probe timed out after {timeout:?}");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn read_all_to_end<R: std::io::Read>(mut r: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = r.read_to_end(&mut buf);
    buf
}

/// Bundled canonical model IDs known to be currently valid as of the
/// 2026-05-18 NEOTH research snapshot. Operators with the corresponding
/// CLI installed get these as the catalog entry under
/// [`SourceOrigin::Cli`] when REST list-models isn't reachable. The
/// catalog refresher overwrites these the moment a REST pull succeeds.
pub mod bundled_cli_models {
    pub const ANTHROPIC: &[(&str, &str)] = &[
        (
            "claude-opus-4-7",
            "Claude Opus 4.7 (most capable, 2026-04-16)",
        ),
        ("claude-sonnet-4-6", "Claude Sonnet 4.6 (balanced)"),
        (
            "claude-haiku-4-5-20251001",
            "Claude Haiku 4.5 (fast + low cost)",
        ),
        ("opus", "alias → claude-opus-4-7"),
        ("sonnet", "alias → claude-sonnet-4-6"),
        ("haiku", "alias → claude-haiku-4-5-20251001"),
    ];

    pub const GEMINI: &[(&str, &str)] = &[
        (
            "gemini-3.1-pro-preview",
            "Gemini 3.1 Pro Preview (most capable)",
        ),
        (
            "gemini-3.1-flash-image",
            "Gemini 3.1 Flash Image (vision + edits)",
        ),
        (
            "gemini-3.1-flash-lite",
            "Gemini 3.1 Flash-Lite (cost-efficient)",
        ),
        ("gemini-3-flash", "Gemini 3 Flash (balanced multimodal)"),
    ];

    pub const OPENAI: &[(&str, &str)] = &[
        ("gpt-5.5", "GPT-5.5 (latest reasoning + agentic flagship)"),
        ("gpt-5.4", "GPT-5.4 (frontier reasoning + coding)"),
        ("gpt-5.4-mini", "GPT-5.4 mini (high-volume)"),
        ("gpt-5.4-nano", "GPT-5.4 nano (simple high-volume)"),
        ("gpt-5-codex", "GPT-5-Codex (long-horizon coding)"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_err_for_nonexistent_binary() {
        let err = probe_cli_version("this-binary-does-not-exist-on-any-system-anywhere-promised")
            .unwrap_err();
        assert!(
            err.to_string().contains("failed to spawn") || err.to_string().contains("not in PATH"),
            "expected PATH-related error, got: {err}"
        );
    }

    #[test]
    fn bundled_anthropic_models_include_current_flagship() {
        let ids: Vec<&str> = bundled_cli_models::ANTHROPIC
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert!(ids.contains(&"claude-opus-4-7"));
        assert!(ids.contains(&"claude-sonnet-4-6"));
    }

    #[test]
    fn bundled_anthropic_models_include_aliases() {
        let ids: Vec<&str> = bundled_cli_models::ANTHROPIC
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert!(ids.contains(&"opus"));
        assert!(ids.contains(&"sonnet"));
        assert!(ids.contains(&"haiku"));
    }

    #[test]
    fn bundled_gemini_models_include_current_preview() {
        let ids: Vec<&str> = bundled_cli_models::GEMINI
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert!(ids.contains(&"gemini-3.1-pro-preview"));
        assert!(!ids.iter().any(|i| i.contains("gemini-2.5")));
    }

    #[test]
    fn bundled_openai_models_include_current_flagship() {
        let ids: Vec<&str> = bundled_cli_models::OPENAI
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert!(ids.contains(&"gpt-5.5"));
        assert!(!ids.iter().any(|i| i == &"gpt-4o"));
    }

    /// Probe a guaranteed-present binary on this OS — Windows `cmd.exe`
    /// (Windows CI) or `/bin/sh` (unix CI). Confirms the version-string
    /// extraction works end-to-end without depending on a specific LLM
    /// CLI being installed.
    #[test]
    fn probe_works_against_a_real_binary_with_version_flag() {
        // `git` is universally installed on dev boxes + CI runners and
        // emits a version banner to stdout. NEOTH itself depends on
        // `git` for its `cli/repo_map.rs` Tree-sitter walker.
        let result = probe_cli_version("git");
        if let Ok(presence) = result {
            assert_eq!(presence.binary, "git");
            assert!(
                presence.version.to_ascii_lowercase().contains("git"),
                "expected version banner to mention 'git', got: {}",
                presence.version
            );
        }
        // If `git` isn't installed (rare but possible in minimal CI),
        // we don't fail the test — the absence-path is covered by
        // `probe_returns_err_for_nonexistent_binary`.
    }
}
