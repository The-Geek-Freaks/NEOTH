//! NOOB-UX-6 sub-gap (1) — Node + npm install picker primitive.
//!
//! NEOTH's wizard auto-installs `claude-cli` + `gemini-cli` + `codex`
//! via `npm install -g` per `[[neoth-cli-installers]]` memory rule.
//! That assumes `node` + `npm` are on PATH — the pre-flight bails
//! with "install Node first" if not. NOOB-UX-6 closes that gap with
//! the OS-specific Node install path picker (same shape as
//! `installers/obs.rs` / `installers/obsidian.rs` / `installers/
//! tmux.rs`).
//!
//! Windows: `winget install OpenJS.NodeJS.LTS`
//! macOS: `brew install node@22` (LTS line)
//! Linux: NodeSource distro repo hint (apt / dnf / pacman / zypper).
//! No silent `sudo apt install` — operator runs the package-manager
//! command themselves per the AGENTER "operator GO per command" rule.

use std::time::Duration;

use tokio::process::Command;

/// One of the OS-specific Node install paths. Pinned exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeInstallPath {
    /// `winget install --exact --id OpenJS.NodeJS.LTS`
    WingetWindows,
    /// `brew install node@22` — pinned at the LTS major. Operators
    /// who want bleeding-edge override the version themselves.
    BrewMacos,
    /// Linux distro hint — apt / dnf / pacman / zypper + NodeSource
    /// URL pointer. Operator runs sudo themselves.
    PackageManagerLinux,
    /// Operator already has Node + npm installed (detected via
    /// `node --version` + `npm --version` both succeeding).
    AlreadyInstalled,
}

impl NodeInstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WingetWindows => "winget_windows",
            Self::BrewMacos => "brew_macos",
            Self::PackageManagerLinux => "package_manager_linux",
            Self::AlreadyInstalled => "already_installed",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::WingetWindows => "Install Node.js LTS via winget (Windows 10+)",
            Self::BrewMacos => "Install Node.js LTS via Homebrew (node@22 — macOS)",
            Self::PackageManagerLinux => {
                "Install Node.js LTS via your distro package manager (apt / dnf / pacman / zypper) — see nodesource.com for the official distro repo setup"
            }
            Self::AlreadyInstalled => "Node + npm already installed — skip",
        }
    }
}

/// Pick the install path for the operator's host. `is_installed`
/// (operator passes the result of probing both `node --version` AND
/// `npm --version`) short-circuits to `AlreadyInstalled`.
pub fn recommend_install_path(is_installed: bool) -> NodeInstallPath {
    if is_installed {
        return NodeInstallPath::AlreadyInstalled;
    }
    if cfg!(target_os = "windows") {
        NodeInstallPath::WingetWindows
    } else if cfg!(target_os = "macos") {
        NodeInstallPath::BrewMacos
    } else {
        NodeInstallPath::PackageManagerLinux
    }
}

/// Build the install command + args for `path`. Pure-fn so the
/// wizard renders the exact command to the operator before running
/// (no surprise subprocess).
pub fn install_command(path: NodeInstallPath) -> Vec<String> {
    match path {
        NodeInstallPath::WingetWindows => vec![
            "winget".into(),
            "install".into(),
            "--exact".into(),
            "--id".into(),
            "OpenJS.NodeJS.LTS".into(),
            "--accept-source-agreements".into(),
            "--accept-package-agreements".into(),
        ],
        NodeInstallPath::BrewMacos => {
            vec!["brew".into(), "install".into(), "node@22".into()]
        }
        NodeInstallPath::PackageManagerLinux => vec![
            "echo".into(),
            "Operator: install Node.js LTS — \
             Ubuntu/Debian → use NodeSource (https://github.com/nodesource/distributions), \
             Fedora → `sudo dnf install nodejs`, \
             Arch → `sudo pacman -S nodejs npm`, \
             openSUSE → `sudo zypper install nodejs22`. \
             Verify with `node --version && npm --version`."
                .into(),
        ],
        NodeInstallPath::AlreadyInstalled => Vec::new(),
    }
}

/// Probe BOTH `node --version` AND `npm --version`. Returns
/// `Some((node_ver, npm_ver))` when both respond, else None. Both
/// must succeed because the wizard's downstream `npm install -g`
/// path can't progress with just one of them.
pub async fn check_node_and_npm() -> Option<(String, String)> {
    let node = cli_version("node").await?;
    let npm = cli_version("npm").await?;
    Some((node, npm))
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
        assert_eq!(NodeInstallPath::WingetWindows.as_str(), "winget_windows");
        assert_eq!(NodeInstallPath::BrewMacos.as_str(), "brew_macos");
        assert_eq!(
            NodeInstallPath::PackageManagerLinux.as_str(),
            "package_manager_linux"
        );
        assert_eq!(
            NodeInstallPath::AlreadyInstalled.as_str(),
            "already_installed"
        );
    }

    #[test]
    fn descriptions_distinct_per_path() {
        let descs = [
            NodeInstallPath::WingetWindows.description(),
            NodeInstallPath::BrewMacos.description(),
            NodeInstallPath::PackageManagerLinux.description(),
            NodeInstallPath::AlreadyInstalled.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len(), "duplicate description");
    }

    #[test]
    fn already_installed_short_circuits_regardless_of_os() {
        assert_eq!(
            recommend_install_path(true),
            NodeInstallPath::AlreadyInstalled
        );
    }

    #[test]
    fn recommend_picks_os_specific_path_when_missing() {
        let p = recommend_install_path(false);
        if cfg!(target_os = "windows") {
            assert_eq!(p, NodeInstallPath::WingetWindows);
        } else if cfg!(target_os = "macos") {
            assert_eq!(p, NodeInstallPath::BrewMacos);
        } else {
            assert_eq!(p, NodeInstallPath::PackageManagerLinux);
        }
    }

    #[test]
    fn winget_command_pins_lts_id_and_silent_flags() {
        let cmd = install_command(NodeInstallPath::WingetWindows);
        assert!(cmd.contains(&"OpenJS.NodeJS.LTS".to_string()));
        assert!(cmd.contains(&"--accept-source-agreements".to_string()));
        assert!(cmd.contains(&"--accept-package-agreements".to_string()));
    }

    #[test]
    fn brew_command_pins_lts_major() {
        // Drift guard — operator-facing LTS line. Renaming silently
        // would shift onto whatever brew's "node" default is at
        // brew-update time, which has historically jumped a major.
        let cmd = install_command(NodeInstallPath::BrewMacos);
        assert_eq!(cmd, vec!["brew", "install", "node@22"]);
    }

    #[test]
    fn linux_command_is_distro_hint_no_silent_sudo() {
        let cmd = install_command(NodeInstallPath::PackageManagerLinux);
        assert!(!cmd.is_empty());
        let joined = cmd.join(" ").to_lowercase();
        assert!(joined.contains("nodesource"));
        assert!(joined.contains("apt") || joined.contains("debian"));
        assert!(joined.contains("dnf"));
        assert!(joined.contains("pacman"));
    }

    #[test]
    fn already_installed_command_is_empty() {
        assert!(install_command(NodeInstallPath::AlreadyInstalled).is_empty());
    }

    #[tokio::test]
    async fn check_node_and_npm_returns_some_or_none_no_panic() {
        // Smoke: either both present (returns Some) or one missing
        // (returns None). Never panics.
        let v = check_node_and_npm().await;
        if let Some((node, npm)) = v {
            assert!(node.chars().any(|c| c.is_ascii_digit()));
            assert!(npm.chars().any(|c| c.is_ascii_digit()));
        }
    }
}
