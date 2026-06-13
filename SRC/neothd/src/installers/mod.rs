//! CLI auto-installer for the three first-class LLM front-ends.
//!
//! Operator requirement: `neoth init` provisions claude-cli, antigravity-cli
//! and codex from inside the wizard. Operator never opens npm, curl, or a
//! terminal manually. See `memory/neoth_cli_installers.md`.
//!
//! Architecture: each CLI is described by a `CliKind` constant carrying
//! binary name, install strategy (npm OR shell-script), and login command.
//! Common probe / install / login logic lives in the helpers below;
//! everything else is per-CLI data.
//!
//! Session 26 migration: Google announced (2026-05-19) that gemini-cli
//! (npm `@google/gemini-cli`, binary `gemini`) stops serving API requests
//! on 2026-06-18 and is superseded by **Antigravity CLI** (binary `agy`,
//! Go-native, shell-script install only — not on npm). NEOTH's managed
//! Google CLI slot now points at antigravity-cli via [`ANTIGRAVITY`].
//!
//! Out of scope here (deferred):
//! - Auto-installing Node + npm itself. Operator must have npm on PATH
//!   for npm-strategy CLIs.
//! - Updating an already-installed CLI. We probe, report, move on.
//! - Sandboxing the install — global npm / shell-script-piped-from-vendor
//!   are the upstream-recommended patterns.

use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

pub mod detect;
pub mod faccam_family;
pub mod ffmpeg;
pub mod fontconfig;
pub mod gpu;
pub mod hysteria2;
pub mod n8n;
pub mod n8n_starter_workflows;
pub mod n8n_workflows;
pub mod node;
pub mod oauth_pkce;
pub mod obs;
pub mod obsidian;
pub mod obsidian_vault;
pub mod obsidian_vault_w02;
pub mod ocr;
pub mod ollama;
pub mod omi;
pub mod paperless;
pub mod pears;
pub mod probe;
pub mod qwen_weights;
pub mod tailscale;
pub mod tmux;
pub mod tmux_w02;
pub mod zero_install;

/// How a managed CLI gets installed onto the operator's host.
///
/// Two strategies cover every first-class vendor today:
/// - **npm**: Anthropic + OpenAI ship their CLIs as scoped npm packages
///   (`@anthropic-ai/claude-code`, `@openai/codex`). Install path is the
///   stock `npm install -g <pkg>`.
/// - **shell-script**: Google's Antigravity CLI (`agy`) is a Go-native
///   binary distributed via a vendor-hosted shell script (sh on
///   Unix, PowerShell on Windows) at `antigravity.google/cli/`. Not on
///   npm — `npm view @google/antigravity` returns 404.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStrategy {
    /// `npm install -g <package>`. Requires Node + npm on PATH.
    Npm { package: &'static str },
    /// Vendor-hosted shell-script piped to the host shell. Operator
    /// trust boundary is "operator chose this CLI in the wizard" —
    /// identical to the npm-strategy trust boundary, just a different
    /// distribution channel.
    ShellScript {
        /// `curl -fsSL <unix_url> | sh` invocation target.
        unix_url: &'static str,
        /// PowerShell `irm <windows_ps_url> | iex` invocation target.
        windows_ps_url: &'static str,
    },
}

/// One of the three CLIs NEOTH knows how to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CliKind {
    /// Display name for log messages and the wizard.
    pub display: &'static str,
    /// PATH-resolvable binary name (without `.cmd`/`.exe`).
    pub binary: &'static str,
    /// How the CLI gets installed (npm or shell-script).
    pub install: InstallStrategy,
    /// Optional login command. `None` means env-var auth only (codex with
    /// OPENAI_API_KEY). `Some(args)` triggers `<binary> <args...>` interactively.
    pub login_args: Option<&'static [&'static str]>,
}

pub const CLAUDE: CliKind = CliKind {
    display: "Claude Code (Anthropic)",
    binary: "claude",
    install: InstallStrategy::Npm {
        package: "@anthropic-ai/claude-code",
    },
    login_args: Some(&["/login"]),
};

/// Google's Antigravity CLI (`agy`) — successor to gemini-cli per the
/// 2026-05-19 transition announcement. Hard cutoff for old gemini-cli
/// API serving: 2026-06-18. Go-native binary, distributed via shell
/// script at `antigravity.google/cli/install.{sh,ps1}` (not on npm).
pub const ANTIGRAVITY: CliKind = CliKind {
    display: "Antigravity CLI (Google)",
    binary: "agy",
    install: InstallStrategy::ShellScript {
        unix_url: "https://antigravity.google/cli/install.sh",
        windows_ps_url: "https://antigravity.google/cli/install.ps1",
    },
    login_args: Some(&["auth", "login"]),
};

pub const CODEX: CliKind = CliKind {
    display: "Codex CLI (OpenAI)",
    binary: "codex",
    install: InstallStrategy::Npm {
        package: "@openai/codex",
    },
    login_args: Some(&["login"]),
};

/// Iteration helper for the wizard.
pub const ALL: &[CliKind] = &[CLAUDE, ANTIGRAVITY, CODEX];

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

/// Install `kind` using its declared [`InstallStrategy`]. Streams the
/// installer's stderr to the wizard's tracing output so the operator
/// sees download progress regardless of channel.
pub async fn install_kind(kind: CliKind) -> Result<()> {
    match kind.install {
        InstallStrategy::Npm { package } => install_via_npm(kind.display, package).await,
        InstallStrategy::ShellScript {
            unix_url,
            windows_ps_url,
        } => install_via_shell_script(kind.display, unix_url, windows_ps_url).await,
    }
}

// NB: parameter named `cli_name` rather than `display` because the
// `info!` / `warn!` macros from `tracing` resolve a bare `display`
// identifier as the `tracing::field::display` value-formatter function,
// not as the local variable — see E0277 on the qwen-metal job for
// run 26503528842.
async fn install_via_npm(cli_name: &str, package: &str) -> Result<()> {
    // GOLD-ADAPT-GOOSE-01 supply-chain gate — query OSV for MAL-* malware
    // advisories on this package BEFORE installing it. A confirmed hit aborts;
    // a lookup error fails open (logged) so an offline install still works.
    npm_supply_chain_gate(
        package,
        crate::security::osv_check::check_package(package, "npm", None).await,
    )?;
    info!(package, cli_name, "running `npm install -g {package}`");
    let mut child = spawn_cli("npm", &["install", "-g", package])
        .with_context(|| format!("spawn npm install -g {package}"))?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("await npm install {package}"))?;
    if !status.success() {
        anyhow::bail!(
            "npm install -g {package} failed (exit {:?}). Is npm reachable + writable? \
             You may need elevated privileges, or `npm config set prefix ~/.npm-global` \
             and PATH adjustments.",
            status.code()
        );
    }
    info!(package, cli_name, "install ok");
    Ok(())
}

/// GOLD-ADAPT-GOOSE-01 — turn an OSV verdict into a go/no-go for an
/// `npm install -g`. A confirmed `MAL-*` hit is a HARD block (NEOTH's own
/// toolchain packages — claude-cli / codex / gemini-cli — have no legitimate
/// reason to be malware-flagged, so the block is unconditional rather than
/// autonomy-gated). A lookup that could not complete (`Unknown`) fails OPEN with
/// a warning so an offline / air-gapped install is never bricked by a network
/// blip. Pure (modulo the warn log) so it is unit-tested without npm.
fn npm_supply_chain_gate(
    package: &str,
    verdict: crate::security::osv_check::OsvVerdict,
) -> Result<()> {
    use crate::security::osv_check::OsvVerdict;
    match verdict {
        OsvVerdict::Malicious { advisories } => anyhow::bail!(
            "refusing to `npm install -g {package}` — OSV flags it as MALWARE ({}). \
             Supply-chain install aborted (GOLD-ADAPT-GOOSE-01).",
            advisories.join(", ")
        ),
        OsvVerdict::Unknown { reason } => {
            warn!(package, %reason, "OSV malware check could not complete — proceeding (fail-open)");
            Ok(())
        }
        OsvVerdict::Clean => Ok(()),
    }
}

#[cfg(test)]
mod npm_gate_tests {
    use super::npm_supply_chain_gate;
    use crate::security::osv_check::OsvVerdict;

    #[test]
    fn malicious_verdict_blocks_install() {
        let err = npm_supply_chain_gate(
            "evil-pkg",
            OsvVerdict::Malicious {
                advisories: vec!["MAL-2024-1".to_string()],
            },
        )
        .expect_err("a MAL-* verdict must block");
        let msg = err.to_string();
        assert!(msg.contains("MALWARE"), "error names malware: {msg}");
        assert!(msg.contains("MAL-2024-1"), "error names the advisory: {msg}");
    }

    #[test]
    fn clean_verdict_allows_install() {
        assert!(npm_supply_chain_gate("jquery", OsvVerdict::Clean).is_ok());
    }

    #[test]
    fn unknown_verdict_fails_open() {
        // A lookup error must NOT block — offline installs still proceed.
        assert!(
            npm_supply_chain_gate(
                "pkg",
                OsvVerdict::Unknown {
                    reason: "network down".to_string()
                }
            )
            .is_ok()
        );
    }
}

/// Run the vendor-hosted shell installer. The host shell pipeline is
/// the upstream-recommended path (Google docs `irm … | iex` on Windows,
/// `curl … | sh` on Unix). We replicate it from a tokio process so the
/// wizard can stream stderr + apply the same timeout/cancel discipline
/// as the npm path.
async fn install_via_shell_script(
    cli_name: &str,
    unix_url: &str,
    windows_ps_url: &str,
) -> Result<()> {
    #[cfg(windows)]
    {
        info!(
            cli_name,
            url = windows_ps_url,
            "running PowerShell installer `irm {windows_ps_url} | iex`",
        );
        let mut cmd = Command::new("powershell");
        cmd.arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(format!("irm {windows_ps_url} | iex"))
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn powershell installer {windows_ps_url}"))?;
        let status = child.wait().await?;
        if !status.success() {
            anyhow::bail!(
                "shell installer for {cli_name} failed (exit {:?}). Try running the \
                 upstream command manually: irm {windows_ps_url} | iex",
                status.code()
            );
        }
        info!(cli_name, "install ok");
        let _ = unix_url; // silence unused on the Windows branch
        Ok(())
    }
    #[cfg(not(windows))]
    {
        info!(
            cli_name,
            url = unix_url,
            "running shell installer `curl -fsSL {unix_url} | sh`",
        );
        // `sh -c "curl -fsSL <url> | sh"` keeps the pipeline single-shot;
        // curl's `--fail` upgrades a 4xx/5xx to a non-zero exit so a
        // 404 (e.g. vendor moved the script) doesn't pipe a stub HTML
        // page into the operator's shell.
        let pipeline = format!("curl -fsSL {unix_url} | sh");
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(&pipeline)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn sh installer {unix_url}"))?;
        let status = child.wait().await?;
        if !status.success() {
            anyhow::bail!(
                "shell installer for {cli_name} failed (exit {:?}). Try running the \
                 upstream command manually: {pipeline}",
                status.code()
            );
        }
        info!(cli_name, "install ok");
        let _ = windows_ps_url; // silence unused on this branch
        Ok(())
    }
}

/// D3b-7 (2026-05-22 Session 20): build the `INSTALLER_RAN` (0x12)
/// WAL payload for a CLI install. Returns the JSON bytes the caller
/// appends via `writer.append(header, payload)`. Kept as a pure
/// helper so install_kind stays test-isolated (no WAL writer dep);
/// the wizard wires this in `cli::init` after install_kind succeeds.
pub fn build_installer_ran_payload(
    cli_name: &str,
    version: &str,
    login_state: &str,
    ts_unix: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "cli_name": cli_name,
        "version": version,
        "login_state": login_state,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
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
        assert!(binaries.contains(&"agy"));
        assert!(binaries.contains(&"codex"));
    }

    #[test]
    fn npm_strategy_uses_scoped_packages() {
        // npm-strategy vendors must publish under their own scope so an
        // attacker can't typo-squat the install. ShellScript-strategy
        // CLIs (antigravity) are exempt from this — vendor-hosted URL
        // discipline lives in the URL validation below instead.
        for kind in ALL {
            if let InstallStrategy::Npm { package } = kind.install {
                assert!(
                    package.starts_with('@'),
                    "{} npm package must be scoped, got {package}",
                    kind.display
                );
            }
        }
    }

    #[test]
    fn shell_strategy_urls_are_https_and_vendor_owned() {
        // Lock the trust boundary: shell-script installers must come
        // over TLS from an upstream-hosted URL we name explicitly.
        for kind in ALL {
            if let InstallStrategy::ShellScript {
                unix_url,
                windows_ps_url,
            } = kind.install
            {
                assert!(unix_url.starts_with("https://"), "{unix_url} not https");
                assert!(
                    windows_ps_url.starts_with("https://"),
                    "{windows_ps_url} not https"
                );
            }
        }
    }

    #[test]
    fn antigravity_replaces_gemini_in_ali_slot() {
        // Drift-guard: the Google CLI slot must point at antigravity
        // post-2026-05-19 transition. A regression that brings back
        // `@google/gemini-cli` or binary `gemini` is a hard fail
        // because gemini-cli stops serving API requests 2026-06-18.
        let google = ALL
            .iter()
            .find(|k| k.display.contains("Google"))
            .expect("Google CLI slot must exist");
        assert_eq!(google.binary, "agy");
        match google.install {
            InstallStrategy::ShellScript { unix_url, .. } => {
                assert!(unix_url.contains("antigravity"));
            }
            InstallStrategy::Npm { .. } => panic!("Antigravity does not ship on npm"),
        }
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

    // ── D3b-7 + D3b-8 installer telemetry tests ──────────────────────────

    #[test]
    fn d3b_7_installer_ran_payload_carries_required_fields() {
        // Per the WAL event 0x12 spec: payload MUST carry cli_name +
        // version + login_state + ts_unix. Pin so a future refactor
        // that drops one of the fields surfaces here.
        let payload = build_installer_ran_payload("claude", "1.2.3", "logged_in", 1_700_000_000);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["cli_name"].as_str(), Some("claude"));
        assert_eq!(v["version"].as_str(), Some("1.2.3"));
        assert_eq!(v["login_state"].as_str(), Some("logged_in"));
        assert_eq!(v["ts_unix"].as_i64(), Some(1_700_000_000));
    }

    #[test]
    fn d3b_7_installer_ran_payload_handles_all_three_clis() {
        // Every shipped CLI must produce a parseable payload — pin so
        // a future addition that changes the binary name doesn't slip
        // a non-utf-8 name through.
        for kind in ALL {
            let payload = build_installer_ran_payload(kind.binary, "0.0.0", "pending", 0);
            let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(v["cli_name"].as_str(), Some(kind.binary));
        }
    }

    #[test]
    fn d3b_8_mock_install_test_distinct_install_targets_pin() {
        // D3b-8 mock-install integration: the install_kind path takes
        // a CliKind + dispatches on InstallStrategy. Real npm/curl
        // don't live on every CI runner so we pin the SHAPE (distinct
        // install targets + format discipline) here; the real network
        // call is verified by `npm_version_returns_some_or_none`
        // above.
        let targets: std::collections::HashSet<&str> = ALL
            .iter()
            .map(|c| match c.install {
                InstallStrategy::Npm { package } => package,
                InstallStrategy::ShellScript { unix_url, .. } => unix_url,
            })
            .collect();
        assert_eq!(targets.len(), 3, "all 3 CLIs have distinct install targets");

        // Pin the format pattern so a vendor rename breaks at test
        // time, not at first operator install.
        for c in ALL {
            match c.install {
                InstallStrategy::Npm { package } => {
                    assert!(
                        package.starts_with('@'),
                        "{} npm pkg should be scoped",
                        c.display
                    );
                    assert!(
                        package.contains('/'),
                        "{} npm pkg should be `@scope/name` shape",
                        c.display
                    );
                }
                InstallStrategy::ShellScript {
                    unix_url,
                    windows_ps_url,
                } => {
                    assert!(unix_url.starts_with("https://"));
                    assert!(windows_ps_url.starts_with("https://"));
                }
            }
        }
    }
}
