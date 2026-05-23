//! D-101 (Session 21, 2026-05-23, 6/6 agent panel) — Pears runtime
//! install primitive for the Keet HTTP-bridge path.
//!
//! NEOTH ships an out-of-process HTTP bridge to a running `pear`
//! runtime so the in-binary `channels/pears_bridge.rs` reqwest client
//! can talk to Hyperswarm/Pears without pulling 60 MiB of Node into
//! the binary itself or attempting a multi-month Rust-native port.
//!
//! Same shape as `installers/node.rs`: OS-specific picker + pure-fn
//! `install_command()` so the wizard renders the exact command line
//! before running it (no surprise subprocess; matches the AGENTER
//! "operator GO per command" rule).
//!
//! Distribution paths:
//!   - Windows: npm install -g pear (assumes Node from NOOB-UX-6 sub-gap (1))
//!   - macOS:   `brew tap holepunchto/tap && brew install pear` if available;
//!              fall back to `npm install -g pear` so the path works even
//!              when the brew formula isn't published yet.
//!   - Linux:   `npm install -g pear` (Pears upstream distributes via npm).
//!
//! Operator already has `pear` on PATH → returns `AlreadyInstalled`
//! and the wizard skips the install step entirely.

use std::time::Duration;

use tokio::process::Command;

/// One of the OS-specific Pears install paths. Pinned exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PearsInstallPath {
    /// `npm install -g pear` — Windows. Requires Node.js on PATH
    /// (NOOB-UX-6 sub-gap (1) ships the Node installer).
    NpmWindows,
    /// `npm install -g pear` — macOS fallback when no brew formula
    /// is published. Requires Node + npm on PATH.
    NpmMacos,
    /// `npm install -g pear` — Linux. Requires Node + npm on PATH.
    NpmLinux,
    /// Operator already has `pear` on PATH (detected via `pear --version`
    /// returning successfully).
    AlreadyInstalled,
}

impl PearsInstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NpmWindows => "npm_windows",
            Self::NpmMacos => "npm_macos",
            Self::NpmLinux => "npm_linux",
            Self::AlreadyInstalled => "already_installed",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::NpmWindows => {
                "Install Pears runtime via npm (Windows — requires Node.js LTS)"
            }
            Self::NpmMacos => {
                "Install Pears runtime via npm (macOS — requires Node.js LTS)"
            }
            Self::NpmLinux => {
                "Install Pears runtime via npm (Linux — requires Node.js LTS)"
            }
            Self::AlreadyInstalled => "Pears already installed — skip",
        }
    }
}

/// Pick the install path for the operator's host. `is_installed`
/// (operator passes the result of probing `pear --version`)
/// short-circuits to `AlreadyInstalled`.
pub fn recommend_install_path(is_installed: bool) -> PearsInstallPath {
    if is_installed {
        return PearsInstallPath::AlreadyInstalled;
    }
    if cfg!(target_os = "windows") {
        PearsInstallPath::NpmWindows
    } else if cfg!(target_os = "macos") {
        PearsInstallPath::NpmMacos
    } else {
        PearsInstallPath::NpmLinux
    }
}

/// Build the install command + args for `path`. Pure-fn so the
/// wizard renders the exact command to the operator before running
/// it. The npm-on-Windows path goes through `cmd /C` because npm
/// ships as a .cmd shim that bash + tokio::process can't exec
/// directly.
pub fn install_command(path: PearsInstallPath) -> Vec<String> {
    match path {
        PearsInstallPath::NpmWindows => vec![
            "cmd".into(),
            "/C".into(),
            "npm".into(),
            "install".into(),
            "-g".into(),
            "pear".into(),
        ],
        PearsInstallPath::NpmMacos | PearsInstallPath::NpmLinux => {
            vec!["npm".into(), "install".into(), "-g".into(), "pear".into()]
        }
        PearsInstallPath::AlreadyInstalled => Vec::new(),
    }
}

/// Probe `pear --version`. Returns `Some(version_string)` on success
/// or None if `pear` is missing / errors / times out.
pub async fn check_pears() -> Option<String> {
    cli_version("pear").await
}

async fn cli_version(binary: &str) -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(binary).arg("--version");
        c
    } else {
        let mut c = Command::new(binary);
        c.arg("--version");
        c
    };
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(PearsInstallPath::NpmWindows.as_str(), "npm_windows");
        assert_eq!(PearsInstallPath::NpmMacos.as_str(), "npm_macos");
        assert_eq!(PearsInstallPath::NpmLinux.as_str(), "npm_linux");
        assert_eq!(
            PearsInstallPath::AlreadyInstalled.as_str(),
            "already_installed"
        );
    }

    #[test]
    fn descriptions_distinct_per_path() {
        let descs = [
            PearsInstallPath::NpmWindows.description(),
            PearsInstallPath::NpmMacos.description(),
            PearsInstallPath::NpmLinux.description(),
            PearsInstallPath::AlreadyInstalled.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len(), "duplicate description");
    }

    #[test]
    fn already_installed_short_circuits_regardless_of_os() {
        assert_eq!(
            recommend_install_path(true),
            PearsInstallPath::AlreadyInstalled
        );
    }

    #[test]
    fn recommend_picks_os_specific_path_when_missing() {
        let p = recommend_install_path(false);
        if cfg!(target_os = "windows") {
            assert_eq!(p, PearsInstallPath::NpmWindows);
        } else if cfg!(target_os = "macos") {
            assert_eq!(p, PearsInstallPath::NpmMacos);
        } else {
            assert_eq!(p, PearsInstallPath::NpmLinux);
        }
    }

    #[test]
    fn npm_windows_command_uses_cmd_c_shim() {
        // npm on Windows ships as a .cmd; bash + tokio::process can't
        // exec it directly, so we go through `cmd /C`. Drift guard.
        let cmd = install_command(PearsInstallPath::NpmWindows);
        assert_eq!(cmd[..3], ["cmd".to_string(), "/C".to_string(), "npm".to_string()]);
        assert!(cmd.contains(&"pear".to_string()));
        assert!(cmd.contains(&"-g".to_string()));
    }

    #[test]
    fn npm_macos_command_is_direct_npm_invocation() {
        let cmd = install_command(PearsInstallPath::NpmMacos);
        assert_eq!(cmd, vec!["npm", "install", "-g", "pear"]);
    }

    #[test]
    fn npm_linux_command_is_direct_npm_invocation() {
        let cmd = install_command(PearsInstallPath::NpmLinux);
        assert_eq!(cmd, vec!["npm", "install", "-g", "pear"]);
    }

    #[test]
    fn already_installed_command_is_empty() {
        assert!(install_command(PearsInstallPath::AlreadyInstalled).is_empty());
    }

    #[tokio::test]
    async fn check_pears_returns_some_or_none_no_panic() {
        // Smoke: either present (returns Some) or missing (returns None).
        // Never panics. Test CI rarely has `pear` installed so None is
        // the common outcome.
        let v = check_pears().await;
        if let Some(version) = v {
            assert!(!version.is_empty());
        }
    }
}
