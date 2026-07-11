//! GOLD-ADAPT-CBM-01 — codebase-memory-mcp installer primitive.
//!
//! codebase-memory-mcp (CBM) is a zero-dependency C binary that indexes any
//! codebase into a persistent knowledge graph and exposes it as a stdio MCP
//! server. The wizard offers it as an optional code-intelligence rail.
//!
//! Install paths mirror [`super::ollama`]: a platform-selected `InstallPath`
//! enum with `install_command()`, `display_command()`, `consent_text()`, and
//! `for_host()`.
//!
//! Distribution channels confirmed from README (v0.8.1):
//!   - macOS / Linux : `curl -fsSL <install.sh> | bash`
//!   - Windows       : `winget install DeusData.CodebaseMemoryMcp`
//!   - Also available on Homebrew, Scoop, Chocolatey, AUR, npm, PyPI, go install
//!     (operator may choose any; wizard uses the canonical per-platform path).

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Official one-line installer published by DeusData for macOS / Linux.
/// Source: <https://github.com/DeusData/codebase-memory-mcp/blob/main/install.sh>
// neoth: verified present in repo tree (v0.8.1 shallow clone 2026-06-19).
// Confirm URL still resolves before each NEOTH release that ships this installer.
pub const CBM_INSTALL_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh";

/// Releases page the wizard shows for manual / unsupported-platform installs.
pub const CBM_DOWNLOAD_URL: &str =
    "https://github.com/DeusData/codebase-memory-mcp/releases/latest";

/// `winget` package identifier for Windows installs.
// neoth: "Available on: npm, PyPI, Homebrew, Scoop, Winget, Chocolatey, AUR,
// go install" confirmed in README. Winget package id format follows
// DeusData.<ProductName> convention; exact id NOT verified against winget-pkgs
// index (repo tree search is a flat root-level listing, not deep).
// Confirm `winget search codebase-memory-mcp` before shipping.
pub const CBM_WINGET_ID: &str = "DeusData.CodebaseMemoryMcp";

/// Installation method for `codebase-memory-mcp` on a given platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `curl -fsSL <install.sh> | bash` — official macOS / Linux installer.
    UpstreamScript,
    /// `winget install DeusData.CodebaseMemoryMcp` — Microsoft-managed pkg mgr.
    Winget,
    /// `brew install codebase-memory-mcp` — macOS Homebrew.
    Brew,
    /// Manual download from [`CBM_DOWNLOAD_URL`].
    Manual,
}

impl InstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamScript => "upstream_script",
            Self::Winget => "winget",
            Self::Brew => "brew",
            Self::Manual => "manual",
        }
    }

    /// The argv the wizard hands to the host shell to install CBM.
    /// Returns an empty `Vec` for [`Self::Manual`] — caller must fall back to
    /// displaying [`CBM_DOWNLOAD_URL`].
    pub fn install_command(self) -> Vec<String> {
        match self {
            Self::UpstreamScript => vec![
                "sh".into(),
                "-c".into(),
                format!("curl -fsSL {CBM_INSTALL_SCRIPT_URL} | bash"),
            ],
            Self::Winget => vec![
                "winget".into(),
                "install".into(),
                CBM_WINGET_ID.into(),
            ],
            Self::Brew => vec![
                "brew".into(),
                "install".into(),
                "codebase-memory-mcp".into(),
            ],
            Self::Manual => Vec::new(),
        }
    }

    /// Human-readable shell command shown at the operator consent prompt.
    /// Spells out the full command so the operator understands exactly what
    /// will execute (a `curl | bash` pipe makes the trust boundary explicit).
    pub fn display_command(self) -> String {
        match self {
            Self::UpstreamScript => {
                format!("curl -fsSL {CBM_INSTALL_SCRIPT_URL} | bash")
            }
            Self::Winget => format!("winget install {CBM_WINGET_ID}"),
            Self::Brew => "brew install codebase-memory-mcp".to_string(),
            Self::Manual => format!("manual download from {CBM_DOWNLOAD_URL}"),
        }
    }

    /// Operator-facing consent text shown before the wizard runs the install
    /// command. Must make explicit that the operator is authorising a
    /// third-party binary that reads and indexes local source trees.
    pub fn consent_text(self) -> String {
        let cmd = self.display_command();
        format!(
            "NEOTH is about to run:\n\
             \n\
             \t{cmd}\n\
             \n\
             This will download and install codebase-memory-mcp, a THIRD-PARTY \
             binary published by DeusData (https://github.com/DeusData/codebase-memory-mcp).\n\
             \n\
             The binary INDEXES LOCAL SOURCE TREES and writes to your agent \
             configuration files. All processing is local — your code never \
             leaves your machine. Every release binary is signed, checksummed, \
             and scanned by 70+ antivirus engines.\n\
             \n\
             Review the source before proceeding: https://github.com/DeusData/codebase-memory-mcp\n\
             \n\
             Proceed? [y/N]"
        )
    }

    /// Platform-canonical install path for the current compile target.
    pub const fn for_host() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Winget
        }
        #[cfg(target_os = "macos")]
        {
            Self::Brew
        }
        #[cfg(target_os = "linux")]
        {
            Self::UpstreamScript
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Self::Manual
        }
    }
}

/// GOLD-ADAPT-CBM-02 — run the install argv, streaming the child's stdout/stderr
/// to the operator's terminal. Errors on an empty argv (the `Manual` path) or a
/// non-zero exit. Mirrors `installers::ollama::run_command`.
pub async fn run_command(argv: &[String]) -> anyhow::Result<()> {
    let (prog, rest) = argv.split_first().context("empty command")?;
    let status = tokio::process::Command::new(prog)
        .args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("spawn `{}`", argv.join(" ")))?;
    if !status.success() {
        anyhow::bail!("`{}` failed (exit {:?})", argv.join(" "), status.code());
    }
    Ok(())
}

/// GOLD-ADAPT-CBM-02 — install codebase-memory-mcp for this host via the
/// platform [`InstallPath`]. The `Manual` platform has no automatic command →
/// returns an error pointing at the releases page. The CALLER (the wizard step)
/// shows [`InstallPath::consent_text`] and gets explicit operator consent BEFORE
/// invoking this (a `curl | bash` / `winget install` runs a third-party binary).
pub async fn install_for_host() -> anyhow::Result<()> {
    let cmd = InstallPath::for_host().install_command();
    if cmd.is_empty() {
        anyhow::bail!(
            "no automatic codebase-memory-mcp installer for this platform — \
             download from {CBM_DOWNLOAD_URL}"
        );
    }
    run_command(&cmd).await
}

/// GOLD-ADAPT-CBM-02 — true when `codebase-memory-mcp` (`.exe` on Windows) is on
/// PATH. Pure PATH scan, no subprocess — mirrors `cli::computer_use::is_installed`.
/// This is the "verify the stdio command exists" half of CBM-02: don't register a
/// stdio MCP server whose `command` can't actually be spawned.
pub fn is_installed() -> bool {
    let exe = if cfg!(target_os = "windows") {
        "codebase-memory-mcp.exe"
    } else {
        "codebase-memory-mcp"
    };
    exe_on_path(exe, std::env::var_os("PATH"))
}

/// Testable core of [`is_installed`]: true iff `exe` is a file in any dir of
/// `path_var`. Split out so the PATH-scan can be unit-tested with a synthetic
/// PATH (the real `PATH` env is not deterministic in CI).
fn exe_on_path(exe: &str, path_var: Option<std::ffi::OsString>) -> bool {
    path_var
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(exe).is_file()))
        .unwrap_or(false)
}

/// GOLD-ADAPT-CBM-02 — verify the CBM binary is on PATH, then register its
/// hardened MCP-server entry in `mcp_servers.yaml` and enable it. Idempotent:
/// re-enables an existing `codebase-memory` entry, else pushes
/// [`crate::mcp::config::cbm_recommended_config`] (imported read-only — no edit
/// to mcp/config.rs). Returns `Ok(false)` WITHOUT writing when the binary is not
/// installed (a stdio server with an unspawnable command is worse than none).
/// Mirrors the load/push/atomic-write pattern in `cli::computer_use::set_enabled`.
pub fn auto_register() -> anyhow::Result<bool> {
    if !is_installed() {
        return Ok(false);
    }
    use crate::mcp::config::{McpServers, cbm_recommended_config};
    let path = McpServers::default_path();
    McpServers::update_at(&path, |servers| {
        let mut recommended = cbm_recommended_config();
        recommended.enabled = true;
        if let Some(existing) = servers.servers.iter_mut().find(|s| s.id == recommended.id) {
            existing.enabled = true;
        } else {
            servers.servers.push(recommended);
        }
        Ok(true)
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_command_bails_on_empty_argv() {
        assert!(run_command(&[]).await.is_err());
    }

    #[test]
    fn exe_on_path_detects_presence_absence_and_no_path() {
        // GOLD-ADAPT-CBM-02 — the binary-verify half. Synthetic PATH so the
        // assertion is deterministic regardless of the host's real PATH.
        let tmp = tempfile::tempdir().unwrap();
        let exe = if cfg!(target_os = "windows") {
            "cbm-probe.exe"
        } else {
            "cbm-probe"
        };
        std::fs::write(tmp.path().join(exe), b"x").unwrap();
        let path_var = std::env::join_paths([tmp.path()]).unwrap();
        assert!(
            exe_on_path(exe, Some(path_var.clone())),
            "must find an exe present in a PATH dir"
        );
        assert!(
            !exe_on_path("cbm-definitely-absent", Some(path_var)),
            "must not find an absent exe"
        );
        assert!(!exe_on_path(exe, None), "no PATH set => not found");
    }

    #[test]
    fn as_str_variants_are_stable() {
        assert_eq!(InstallPath::UpstreamScript.as_str(), "upstream_script");
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn winget_command_uses_correct_package_id() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd[0], "winget");
        assert_eq!(cmd[1], "install");
        assert_eq!(cmd[2], CBM_WINGET_ID);
        // Pin the exact id so a rename surfaces here.
        assert_eq!(cmd[2], "DeusData.CodebaseMemoryMcp");
    }

    #[test]
    fn brew_command_installs_correct_formula() {
        let cmd = InstallPath::Brew.install_command();
        assert_eq!(cmd[0], "brew");
        assert_eq!(cmd[1], "install");
        assert_eq!(cmd[2], "codebase-memory-mcp");
    }

    #[test]
    fn upstream_script_pipes_curl_to_bash() {
        let cmd = InstallPath::UpstreamScript.install_command();
        assert_eq!(cmd[0], "sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("curl"));
        assert!(cmd[2].contains(CBM_INSTALL_SCRIPT_URL));
        assert!(cmd[2].contains("| bash"));
    }

    #[test]
    fn manual_returns_empty_command() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn install_script_url_is_official_github_raw() {
        assert!(CBM_INSTALL_SCRIPT_URL.starts_with(
            "https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/"
        ));
    }

    #[test]
    fn consent_text_mentions_third_party_and_indexing() {
        for path in [
            InstallPath::UpstreamScript,
            InstallPath::Winget,
            InstallPath::Brew,
            InstallPath::Manual,
        ] {
            let text = path.consent_text();
            assert!(
                text.contains("THIRD-PARTY"),
                "{path:?}: missing THIRD-PARTY notice"
            );
            assert!(
                text.contains("INDEXES LOCAL SOURCE TREES"),
                "{path:?}: missing indexing disclosure"
            );
        }
    }
}
