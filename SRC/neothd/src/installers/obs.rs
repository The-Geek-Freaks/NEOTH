//! FC-3 — OBS Studio installer primitive.
//!
//! Per R-A6 research (Session 21), OBS Virtual Camera is the picked
//! cross-platform "FacCam equivalent": only candidate with a real IPC
//! automation surface (obs-websocket v5 built-in since OBS 28),
//! genuinely cross-platform Linux+Windows+macOS, GPLv2 + no
//! phone-home, AI-blur plugin ecosystem available for silent install.
//!
//! This module ships the installer-path primitive (similar to the
//! `installers/obsidian.rs` shape). The runtime adapter that drives
//! OBS via the WebSocket lives separately in `plugins/obs_facecam.rs`
//! when FC-3 implementation lands.

/// Default obs-websocket port (since OBS 28). Pinned drift-guarded —
/// operators copy-pasting from OBS docs expect this match.
pub const DEFAULT_OBS_WEBSOCKET_PORT: u16 = 4455;

/// One of three OS-specific install paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObsInstallPath {
    /// `winget install -e --id OBSProject.OBSStudio`
    WingetWindows,
    /// `brew install --cask obs`
    BrewMacos,
    /// `apt install obs-studio` / `dnf install obs-studio` /
    /// `pacman -S obs-studio` — distro-detect at wizard time.
    PackageManagerLinux,
    /// Operator already has OBS installed somewhere NEOTH can detect.
    AlreadyInstalled,
}

impl ObsInstallPath {
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
            Self::WingetWindows => "Install OBS Studio via winget (Windows 10+)",
            Self::BrewMacos => "Install OBS Studio via Homebrew (macOS)",
            Self::PackageManagerLinux => {
                "Install OBS Studio via your distro package manager (apt / dnf / pacman)"
            }
            Self::AlreadyInstalled => "OBS Studio already installed on this host — skip",
        }
    }
}

/// Pick the install path for the operator's host. `already` short-
/// circuits when OBS is already detected.
pub fn recommend_install_path(obs_already_installed: bool) -> ObsInstallPath {
    if obs_already_installed {
        return ObsInstallPath::AlreadyInstalled;
    }
    if cfg!(target_os = "windows") {
        ObsInstallPath::WingetWindows
    } else if cfg!(target_os = "macos") {
        ObsInstallPath::BrewMacos
    } else {
        ObsInstallPath::PackageManagerLinux
    }
}

/// Build the install command + args for `path`. Linux returns a
/// hint string because the actual command varies per distro
/// (apt / dnf / pacman / zypper) — wizard runs distro detect first.
pub fn install_command(path: ObsInstallPath) -> Vec<String> {
    match path {
        ObsInstallPath::WingetWindows => vec![
            "winget".into(),
            "install".into(),
            "--exact".into(),
            "--id".into(),
            "OBSProject.OBSStudio".into(),
            "--accept-source-agreements".into(),
            "--accept-package-agreements".into(),
        ],
        ObsInstallPath::BrewMacos => {
            vec![
                "brew".into(),
                "install".into(),
                "--cask".into(),
                "obs".into(),
            ]
        }
        ObsInstallPath::PackageManagerLinux => vec![
            "echo".into(),
            "Operator: install OBS Studio via your distro package manager: \
             Ubuntu/Debian → `sudo apt install obs-studio`, \
             Fedora → `sudo dnf install obs-studio`, \
             Arch → `sudo pacman -S obs-studio`. \
             OBS bundles obs-websocket since v28."
                .into(),
        ],
        ObsInstallPath::AlreadyInstalled => Vec::new(),
    }
}

/// Probe for an existing OBS install across canonical paths.
pub fn detect_obs_install() -> bool {
    canonical_obs_paths()
        .iter()
        .any(|p| std::path::Path::new(p).exists())
}

/// Operator-facing list of canonical install paths. Exposed for the
/// doctor surface so an operator who installed OBS to a non-standard
/// location can see WHY NEOTH's detector didn't find it.
pub fn canonical_obs_paths() -> Vec<String> {
    let mut paths = Vec::new();
    if cfg!(target_os = "windows") {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            paths.push(
                std::path::Path::new(&program_files)
                    .join("obs-studio")
                    .join("bin")
                    .join("64bit")
                    .join("obs64.exe")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    } else if cfg!(target_os = "macos") {
        paths.push("/Applications/OBS.app/Contents/MacOS/OBS".into());
    } else {
        // Linux: canonical binary locations across distros.
        paths.push("/usr/bin/obs".into());
        paths.push("/usr/local/bin/obs".into());
        paths.push("/snap/bin/obs".into());
        paths.push("/var/lib/flatpak/exports/bin/com.obsproject.Studio".into());
    }
    paths
}

/// Probe `obs --version`. Returns Some(version) on success.
/// Cross-platform — OBS supports `--version` on all 3 OSs.
pub async fn check_obs_version() -> Option<String> {
    crate::installers::probe::cli_version("obs").await
}

// GOLD-SEC-23 / GR-145 — `obs_headless_launch_args(port, password)` was REMOVED.
// It was UNWIRED (referenced only by its own tests) and a footgun: it placed
// `--websocket_password <pw>` on the OBS argv, which is visible to every other
// user on the host via `ps` / Task Manager / `/proc/<pid>/cmdline` — guarded
// only by a "do not wire this verbatim" doc comment, not by the type system.
//
// When OBS control is actually built, the password MUST be delivered OUT-OF-BAND
// — write the obs-websocket plugin config
// (`…/plugin_config/obs-websocket/config.json`, mode 0600) and launch WITHOUT a
// password flag — and only THEN build the safe `--websocket_port` / tray / vcam
// args, with a real consumer. A safe-by-construction launch-args helper is
// re-added at that point; an argv-password one never is.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_websocket_port_pinned() {
        // Drift guard — obs-websocket v5 docs document 4455 as canonical.
        // A rename here orphans operator copy-paste from OBS docs.
        assert_eq!(DEFAULT_OBS_WEBSOCKET_PORT, 4455);
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(ObsInstallPath::WingetWindows.as_str(), "winget_windows");
        assert_eq!(ObsInstallPath::BrewMacos.as_str(), "brew_macos");
        assert_eq!(
            ObsInstallPath::PackageManagerLinux.as_str(),
            "package_manager_linux"
        );
        assert_eq!(
            ObsInstallPath::AlreadyInstalled.as_str(),
            "already_installed"
        );
    }

    #[test]
    fn install_path_descriptions_distinct() {
        let descs = [
            ObsInstallPath::WingetWindows.description(),
            ObsInstallPath::BrewMacos.description(),
            ObsInstallPath::PackageManagerLinux.description(),
            ObsInstallPath::AlreadyInstalled.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len(), "duplicate description");
    }

    #[test]
    fn recommend_short_circuits_when_already_installed() {
        assert_eq!(
            recommend_install_path(true),
            ObsInstallPath::AlreadyInstalled
        );
    }

    #[test]
    fn recommend_picks_os_specific_path() {
        let p = recommend_install_path(false);
        if cfg!(target_os = "windows") {
            assert_eq!(p, ObsInstallPath::WingetWindows);
        } else if cfg!(target_os = "macos") {
            assert_eq!(p, ObsInstallPath::BrewMacos);
        } else {
            assert_eq!(p, ObsInstallPath::PackageManagerLinux);
        }
    }

    #[test]
    fn winget_command_uses_canonical_id_and_silent_flags() {
        let cmd = install_command(ObsInstallPath::WingetWindows);
        assert!(cmd.contains(&"winget".to_string()));
        assert!(cmd.contains(&"OBSProject.OBSStudio".to_string()));
        assert!(cmd.contains(&"--accept-source-agreements".to_string()));
        assert!(cmd.contains(&"--accept-package-agreements".to_string()));
    }

    #[test]
    fn brew_command_uses_cask() {
        let cmd = install_command(ObsInstallPath::BrewMacos);
        assert_eq!(cmd, vec!["brew", "install", "--cask", "obs"]);
    }

    #[test]
    fn linux_command_is_distro_hint_not_silent_install() {
        // Linux path is hint-only — we never silently sudo apt
        // install. Operator must run the package-manager command
        // themselves so they see WHICH package landed.
        let cmd = install_command(ObsInstallPath::PackageManagerLinux);
        assert!(!cmd.is_empty());
        let joined = cmd.join(" ").to_lowercase();
        assert!(joined.contains("apt"));
        assert!(joined.contains("dnf"));
        assert!(joined.contains("pacman"));
    }

    #[test]
    fn already_installed_command_is_empty() {
        assert!(install_command(ObsInstallPath::AlreadyInstalled).is_empty());
    }

    #[test]
    fn canonical_paths_returns_something_for_known_os() {
        let paths = canonical_obs_paths();
        if cfg!(target_os = "macos") {
            assert!(!paths.is_empty(), "macOS must have /Applications path");
        } else if cfg!(target_os = "linux") {
            assert!(!paths.is_empty(), "Linux must have /usr/bin/obs path");
        }
        // Windows depends on $ProgramFiles being set.
    }

    #[test]
    fn detect_does_not_panic_on_empty_filesystem() {
        let _ = detect_obs_install();
    }

    // GOLD-SEC-23 / GR-145 — the obs_headless_launch_args tests were removed with
    // the dead argv-password helper (a launch arg builder that leaked the
    // websocket password via the command line).

    #[tokio::test]
    async fn check_obs_version_returns_some_or_none_no_panic() {
        let v = check_obs_version().await;
        if let Some(s) = v {
            // OBS --version prints something like "OBS Studio - 32.1.2"
            // — must contain a digit.
            assert!(s.chars().any(|c| c.is_ascii_digit()));
        }
    }
}
