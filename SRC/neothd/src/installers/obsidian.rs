//! O-1 — Obsidian installer primitive.
//!
//! NEOTH ships an Obsidian-as-archive-brain integration: every
//! noteworthy WAL event materialises into the operator's vault as
//! a daily-note markdown row, and Obsidian-side edits flow back
//! into the WAL via the indexer (see O-5). The wizard step picks
//! the right install path for the operator's OS:
//!
//!   - Windows: `winget install Obsidian.Obsidian`
//!   - macOS:   `brew install --cask obsidian`
//!   - Linux:   direct AppImage download
//!
//! All probes are async + non-blocking. Install commands are
//! returned as `Vec<String>` so the wizard renders the exact
//! command to the operator before running (no surprise spawn —
//! honours the "operator GO per command" rule).



/// One of three OS-specific install paths. Pinned exhaustively
/// per Linux/macOS/Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObsidianInstallPath {
    /// `winget install Obsidian.Obsidian`
    WingetWindows,
    /// `brew install --cask obsidian`
    BrewMacos,
    /// Direct AppImage download — operator runs `chmod +x` + launches.
    AppImageLinux,
    /// Operator has Obsidian installed via a path NEOTH doesn't
    /// know how to verify; surface "already installed" + skip.
    AlreadyInstalled,
}

impl ObsidianInstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WingetWindows => "winget_windows",
            Self::BrewMacos => "brew_macos",
            Self::AppImageLinux => "appimage_linux",
            Self::AlreadyInstalled => "already_installed",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::WingetWindows => "Install via winget (Windows 10+)",
            Self::BrewMacos => "Install via Homebrew (macOS)",
            Self::AppImageLinux => "Download AppImage (Linux)",
            Self::AlreadyInstalled => "Obsidian already installed on this host — skip",
        }
    }
}

/// Pick the install path for the operator's current host.
/// `obsidian_already_installed` short-circuits — we surface
/// "already installed" instead of suggesting a re-install.
pub fn recommend_install_path(obsidian_already_installed: bool) -> ObsidianInstallPath {
    if obsidian_already_installed {
        return ObsidianInstallPath::AlreadyInstalled;
    }
    if cfg!(target_os = "windows") {
        ObsidianInstallPath::WingetWindows
    } else if cfg!(target_os = "macos") {
        ObsidianInstallPath::BrewMacos
    } else {
        ObsidianInstallPath::AppImageLinux
    }
}

/// Build the install command + args for `path`. Pure-fn so the
/// wizard renders the exact command before running. AppImage path
/// returns the canonical download URL — wizard does the actual
/// HTTPS download + chmod via a separate step.
pub fn install_command(path: ObsidianInstallPath) -> Vec<String> {
    match path {
        ObsidianInstallPath::WingetWindows => vec![
            "winget".into(),
            "install".into(),
            "--exact".into(),
            "--id".into(),
            "Obsidian.Obsidian".into(),
            "--accept-source-agreements".into(),
            "--accept-package-agreements".into(),
        ],
        ObsidianInstallPath::BrewMacos => vec![
            "brew".into(),
            "install".into(),
            "--cask".into(),
            "obsidian".into(),
        ],
        ObsidianInstallPath::AppImageLinux => vec![
            "echo".into(),
            "Operator: download AppImage from https://obsidian.md/download \
             (Linux x64), `chmod +x Obsidian-*.AppImage`, then run."
                .into(),
        ],
        ObsidianInstallPath::AlreadyInstalled => Vec::new(),
    }
}

/// Probe for an existing Obsidian install. Checks the three
/// canonical paths per-OS; returns true on any match. Cheap
/// (~5ms) — file_exists checks only, no subprocess.
pub fn detect_obsidian_install() -> bool {
    let candidates = canonical_obsidian_paths();
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

/// Operator-facing list of canonical install paths NEOTH knows
/// how to detect. Exposed for the doctor surface so an operator
/// who installed Obsidian to a non-standard path can see WHY the
/// detector didn't find it.
pub fn canonical_obsidian_paths() -> Vec<String> {
    let mut paths = Vec::new();
    if cfg!(target_os = "windows") {
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            paths.push(
                std::path::Path::new(&local_app)
                    .join("Programs")
                    .join("Obsidian")
                    .join("Obsidian.exe")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            paths.push(
                std::path::Path::new(&program_files)
                    .join("Obsidian")
                    .join("Obsidian.exe")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    } else if cfg!(target_os = "macos") {
        paths.push("/Applications/Obsidian.app/Contents/MacOS/Obsidian".into());
    } else {
        // Linux: AppImage typically lives in ~/Applications.
        if let Some(home) = std::env::var_os("HOME") {
            paths.push(
                std::path::Path::new(&home)
                    .join("Applications")
                    .join("Obsidian.AppImage")
                    .to_string_lossy()
                    .into_owned(),
            );
            paths.push("/usr/bin/obsidian".into());
            paths.push("/snap/bin/obsidian".into());
        }
    }
    paths
}

/// Probe `winget --version` on Windows. Returns Some(version)
/// when winget is available, None on non-Windows or missing.
pub async fn check_winget_available() -> Option<String> {
    if !cfg!(target_os = "windows") {
        return None;
    }
    crate::installers::probe::cli_version("winget").await
}

/// Probe `brew --version` on macOS. Returns Some(version) on
/// success; None on non-macOS or missing brew.
pub async fn check_brew_available() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    crate::installers::probe::cli_version("brew").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(
            ObsidianInstallPath::WingetWindows.as_str(),
            "winget_windows"
        );
        assert_eq!(ObsidianInstallPath::BrewMacos.as_str(), "brew_macos");
        assert_eq!(
            ObsidianInstallPath::AppImageLinux.as_str(),
            "appimage_linux"
        );
        assert_eq!(
            ObsidianInstallPath::AlreadyInstalled.as_str(),
            "already_installed"
        );
    }

    #[test]
    fn install_path_descriptions_distinct() {
        let descs = [
            ObsidianInstallPath::WingetWindows.description(),
            ObsidianInstallPath::BrewMacos.description(),
            ObsidianInstallPath::AppImageLinux.description(),
            ObsidianInstallPath::AlreadyInstalled.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len(), "duplicate description");
    }

    #[test]
    fn recommend_short_circuits_when_already_installed() {
        let p = recommend_install_path(true);
        assert_eq!(p, ObsidianInstallPath::AlreadyInstalled);
    }

    #[test]
    fn recommend_picks_os_specific_path() {
        let p = recommend_install_path(false);
        if cfg!(target_os = "windows") {
            assert_eq!(p, ObsidianInstallPath::WingetWindows);
        } else if cfg!(target_os = "macos") {
            assert_eq!(p, ObsidianInstallPath::BrewMacos);
        } else {
            assert_eq!(p, ObsidianInstallPath::AppImageLinux);
        }
    }

    #[test]
    fn winget_command_includes_silent_agreement_flags() {
        let cmd = install_command(ObsidianInstallPath::WingetWindows);
        assert!(cmd.contains(&"winget".to_string()));
        assert!(cmd.contains(&"install".to_string()));
        assert!(cmd.contains(&"Obsidian.Obsidian".to_string()));
        // Silent install — operator already agreed in the wizard.
        assert!(cmd.contains(&"--accept-source-agreements".to_string()));
        assert!(cmd.contains(&"--accept-package-agreements".to_string()));
    }

    #[test]
    fn brew_command_uses_cask() {
        let cmd = install_command(ObsidianInstallPath::BrewMacos);
        assert_eq!(cmd, vec!["brew", "install", "--cask", "obsidian"]);
    }

    #[test]
    fn appimage_command_is_operator_hint_not_silent_download() {
        // Linux path is hint-only — we never silently download
        // an AppImage. Operator must run the chmod + first-launch
        // themselves so they see WHERE the AppImage landed.
        let cmd = install_command(ObsidianInstallPath::AppImageLinux);
        assert!(!cmd.is_empty());
        assert!(cmd.iter().any(|s| s.contains("obsidian.md/download")));
    }

    #[test]
    fn already_installed_command_is_empty() {
        let cmd = install_command(ObsidianInstallPath::AlreadyInstalled);
        assert!(cmd.is_empty());
    }

    #[test]
    fn canonical_paths_returns_non_empty_for_known_os() {
        let paths = canonical_obsidian_paths();
        // On macOS we always have /Applications; on Linux + Windows
        // we depend on env vars — if HOME/LOCALAPPDATA are set we
        // get paths, otherwise empty is acceptable.
        if cfg!(target_os = "macos") {
            assert!(!paths.is_empty());
        }
    }

    #[test]
    fn detect_does_not_panic_on_empty_filesystem() {
        // Smoke — must not panic regardless of host state.
        let _ = detect_obsidian_install();
    }

    #[tokio::test]
    async fn winget_probe_returns_some_or_none_no_panic() {
        let v = check_winget_available().await;
        if cfg!(target_os = "windows") {
            // On Windows we may or may not have winget; either way no panic.
            if let Some(s) = v {
                assert!(s.chars().any(|c| c.is_ascii_digit()));
            }
        } else {
            assert!(v.is_none(), "non-Windows must report no winget");
        }
    }

    #[tokio::test]
    async fn brew_probe_returns_some_or_none_no_panic() {
        let v = check_brew_available().await;
        if cfg!(target_os = "macos") {
            if let Some(s) = v {
                assert!(
                    s.to_lowercase().contains("homebrew") || s.chars().any(|c| c.is_ascii_digit())
                );
            }
        } else {
            assert!(v.is_none(), "non-macOS must report no brew");
        }
    }
}
