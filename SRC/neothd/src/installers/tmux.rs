//! NOOB-UX-6.a — tmux installer primitive.
//!
//! `tmux` is mandatory for the claude-cli warm-session backend per
//! `[[neoth-claude-cli-tmux-mandatory]]` memory rule. Today's
//! wizard surface bails out with "install tmux first" if it's
//! missing — this module closes that gap with the OS-specific
//! install path picker (similar shape to `installers/obs.rs` and
//! `installers/obsidian.rs`).
//!
//! Windows: tmux is Unix-only — the picker surfaces `NotApplicable`
//! and the wizard skips the install offer entirely. Windows
//! operators use the subprocess backend (`claude --print`); the
//! wizard already routes them via `ClaudeBackend::Subprocess`.
//!
//! Linux: package manager hint (apt / dnf / pacman / zypper). No
//! silent `sudo apt install` per the AGENTER hard rule "no
//! destructive auto-action without operator GO per command".
//!
//! macOS: `brew install tmux` (when Homebrew detected). Falls back
//! to operator-hint when Homebrew is missing.

use std::time::Duration;

use tokio::process::Command;

/// One of the OS-specific tmux install paths. Pinned exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TmuxInstallPath {
    /// `brew install tmux` — macOS with Homebrew.
    BrewMacos,
    /// `apt install tmux` / `dnf install tmux` / `pacman -S tmux`
    /// — Linux distro-detect hint, operator runs sudo themselves.
    PackageManagerLinux,
    /// Windows — tmux is Unix-only; wizard skips the install
    /// offer + the operator uses the subprocess backend.
    NotApplicable,
    /// Operator already has tmux installed (detected via `tmux -V`).
    AlreadyInstalled,
}

impl TmuxInstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BrewMacos => "brew_macos",
            Self::PackageManagerLinux => "package_manager_linux",
            Self::NotApplicable => "not_applicable",
            Self::AlreadyInstalled => "already_installed",
        }
    }

    /// Operator-facing one-line description shown in the wizard.
    pub fn description(self) -> &'static str {
        match self {
            Self::BrewMacos => "Install tmux via Homebrew (macOS)",
            Self::PackageManagerLinux => {
                "Install tmux via your distro package manager (apt / dnf / pacman / zypper)"
            }
            Self::NotApplicable => {
                "tmux is Unix-only — Windows operators use the subprocess backend (claude --print)"
            }
            Self::AlreadyInstalled => "tmux already installed on this host — skip",
        }
    }
}

/// Pick the install path for the operator's host. `is_installed`
/// short-circuits when tmux is already detected; Windows always
/// returns `NotApplicable` regardless.
pub fn recommend_install_path(is_installed: bool) -> TmuxInstallPath {
    if cfg!(target_os = "windows") {
        return TmuxInstallPath::NotApplicable;
    }
    if is_installed {
        return TmuxInstallPath::AlreadyInstalled;
    }
    if cfg!(target_os = "macos") {
        TmuxInstallPath::BrewMacos
    } else {
        TmuxInstallPath::PackageManagerLinux
    }
}

/// Build the install command + args for `path`. Linux returns a
/// hint vec because the actual command varies per distro; macOS
/// returns the brew invocation; Windows + AlreadyInstalled return
/// empty.
pub fn install_command(path: TmuxInstallPath) -> Vec<String> {
    match path {
        TmuxInstallPath::BrewMacos => {
            vec!["brew".into(), "install".into(), "tmux".into()]
        }
        TmuxInstallPath::PackageManagerLinux => vec![
            "echo".into(),
            "Operator: install tmux via your distro package manager: \
             Ubuntu/Debian → `sudo apt install tmux`, \
             Fedora → `sudo dnf install tmux`, \
             Arch → `sudo pacman -S tmux`, \
             openSUSE → `sudo zypper install tmux`."
                .into(),
        ],
        TmuxInstallPath::NotApplicable | TmuxInstallPath::AlreadyInstalled => Vec::new(),
    }
}

/// Probe `tmux -V`. Returns Some(version) on success. None on
/// Windows + when tmux missing on PATH.
pub async fn check_tmux_version() -> Option<String> {
    if cfg!(target_os = "windows") {
        return None;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("tmux")
            .arg("-V")
            .stdin(std::process::Stdio::null())
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
        assert_eq!(TmuxInstallPath::BrewMacos.as_str(), "brew_macos");
        assert_eq!(
            TmuxInstallPath::PackageManagerLinux.as_str(),
            "package_manager_linux"
        );
        assert_eq!(TmuxInstallPath::NotApplicable.as_str(), "not_applicable");
        assert_eq!(
            TmuxInstallPath::AlreadyInstalled.as_str(),
            "already_installed"
        );
    }

    #[test]
    fn descriptions_distinct_per_path() {
        let descs = [
            TmuxInstallPath::BrewMacos.description(),
            TmuxInstallPath::PackageManagerLinux.description(),
            TmuxInstallPath::NotApplicable.description(),
            TmuxInstallPath::AlreadyInstalled.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len(), "duplicate description");
    }

    #[test]
    fn windows_always_returns_not_applicable() {
        // Drift guard — tmux is Unix-only. A future refactor that
        // routed Windows operators into a tmux install would silently
        // break per [[neoth-claude-cli-tmux-mandatory]] hard rule.
        if cfg!(target_os = "windows") {
            assert_eq!(
                recommend_install_path(false),
                TmuxInstallPath::NotApplicable
            );
            // Even with is_installed=true, Windows stays NotApplicable
            // (tmux on Windows would be MSYS2 / WSL — neither matches
            // the warm-session protocol).
            assert_eq!(recommend_install_path(true), TmuxInstallPath::NotApplicable);
        }
    }

    #[test]
    fn unix_already_installed_short_circuits() {
        if !cfg!(target_os = "windows") {
            assert_eq!(
                recommend_install_path(true),
                TmuxInstallPath::AlreadyInstalled
            );
        }
    }

    #[test]
    fn recommend_picks_os_specific_path_when_not_installed() {
        let p = recommend_install_path(false);
        if cfg!(target_os = "macos") {
            assert_eq!(p, TmuxInstallPath::BrewMacos);
        } else if cfg!(target_os = "windows") {
            assert_eq!(p, TmuxInstallPath::NotApplicable);
        } else {
            assert_eq!(p, TmuxInstallPath::PackageManagerLinux);
        }
    }

    #[test]
    fn brew_command_is_plain_install() {
        let cmd = install_command(TmuxInstallPath::BrewMacos);
        assert_eq!(cmd, vec!["brew", "install", "tmux"]);
    }

    #[test]
    fn linux_command_is_distro_hint_no_silent_sudo() {
        // Drift guard — never silently sudo apt install. Operator
        // must run the package-manager command themselves so they
        // see WHICH package landed.
        let cmd = install_command(TmuxInstallPath::PackageManagerLinux);
        assert!(!cmd.is_empty());
        let joined = cmd.join(" ").to_lowercase();
        assert!(joined.contains("apt"));
        assert!(joined.contains("dnf"));
        assert!(joined.contains("pacman"));
        assert!(joined.contains("zypper"));
    }

    #[test]
    fn windows_and_already_installed_commands_are_empty() {
        assert!(install_command(TmuxInstallPath::NotApplicable).is_empty());
        assert!(install_command(TmuxInstallPath::AlreadyInstalled).is_empty());
    }

    #[tokio::test]
    async fn check_tmux_version_returns_some_or_none_no_panic() {
        let v = check_tmux_version().await;
        if cfg!(target_os = "windows") {
            assert!(v.is_none(), "Windows must report no tmux regardless");
        } else if let Some(s) = v {
            // tmux -V prints something like "tmux 3.4" — must contain a digit.
            assert!(s.to_lowercase().contains("tmux") || s.chars().any(|c| c.is_ascii_digit()));
        }
    }
}
