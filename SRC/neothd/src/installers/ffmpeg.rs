//! W-02 — ffmpeg installer primitive.
//!
//! ffmpeg is required for MM-01/MM-02 (audio/video pipelines).
//! No daemon to run — just a binary that must be on PATH. The
//! wizard probes via `ffmpeg -version`, recommends an install
//! path per OS, and renders the command for operator GO/STOP.
//!
//! ## Why no `InstallStrategy::ManualBinary`-style enum
//!
//! ffmpeg ships through OS package managers everywhere we
//! target (winget on Windows, brew on macOS, apt/dnf/pacman on
//! Linux). No "Docker container" variant — ffmpeg is a CLI tool,
//! not a service.

use tokio::process::Command;

use serde::{Deserialize, Serialize};

/// Project home URL the wizard renders when no package manager
/// path applies. Pinned constant so wizard re-renders survive
/// upstream docs reorganisation.
pub const FFMPEG_DOWNLOAD_URL: &str = "https://ffmpeg.org/download.html";

/// Per-OS install command. Pinned exhaustively — adding a new OS
/// path needs operator-facing wizard UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `winget install ffmpeg`. Microsoft-managed package mgr;
    /// pre-installed on Win11.
    Winget,
    /// `choco install ffmpeg-full`. Operator-installed
    /// Chocolatey; fallback when winget isn't available.
    Choco,
    /// `brew install ffmpeg`. macOS Homebrew.
    Brew,
    /// `sudo apt install -y ffmpeg`. Debian/Ubuntu.
    Apt,
    /// `sudo dnf install -y ffmpeg`. Fedora/RHEL.
    Dnf,
    /// `sudo pacman -S --noconfirm ffmpeg`. Arch / Manjaro.
    Pacman,
    /// Operator builds from source — wizard renders
    /// [`FFMPEG_DOWNLOAD_URL`].
    Manual,
}

impl InstallPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Winget => "winget",
            Self::Choco => "choco",
            Self::Brew => "brew",
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Manual => "manual",
        }
    }

    /// Build the install argv. Empty for `Manual` (operator
    /// follows the URL).
    pub fn install_command(self) -> Vec<String> {
        match self {
            Self::Winget => vec!["winget".into(), "install".into(), "ffmpeg".into()],
            Self::Choco => vec![
                "choco".into(),
                "install".into(),
                "-y".into(),
                "ffmpeg-full".into(),
            ],
            Self::Brew => vec!["brew".into(), "install".into(), "ffmpeg".into()],
            Self::Apt => vec![
                "sudo".into(),
                "apt".into(),
                "install".into(),
                "-y".into(),
                "ffmpeg".into(),
            ],
            Self::Dnf => vec![
                "sudo".into(),
                "dnf".into(),
                "install".into(),
                "-y".into(),
                "ffmpeg".into(),
            ],
            Self::Pacman => vec![
                "sudo".into(),
                "pacman".into(),
                "-S".into(),
                "--noconfirm".into(),
                "ffmpeg".into(),
            ],
            Self::Manual => Vec::new(),
        }
    }

    /// Pick a default install path for the current target. Pure
    /// const-fn lookup. Operator overrides via `--via` in the
    /// wizard install step.
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
            // Picking apt as the modal Linux operator. Operators
            // on dnf/pacman override via the wizard.
            Self::Apt
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Self::Manual
        }
    }
}

/// Probe `ffmpeg -version`. Returns the first line on success.
pub async fn check_ffmpeg_available() -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg("ffmpeg").arg("-version");
        c
    } else {
        let mut c = Command::new("ffmpeg");
        c.arg("-version");
        c
    };
    let output = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_url_is_official_ffmpeg_https() {
        assert!(FFMPEG_DOWNLOAD_URL.starts_with("https://ffmpeg.org/"));
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Choco.as_str(), "choco");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Apt.as_str(), "apt");
        assert_eq!(InstallPath::Dnf.as_str(), "dnf");
        assert_eq!(InstallPath::Pacman.as_str(), "pacman");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn winget_command_shape() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd, vec!["winget", "install", "ffmpeg"]);
    }

    #[test]
    fn choco_command_uses_full_variant_with_yes_flag() {
        let cmd = InstallPath::Choco.install_command();
        assert_eq!(cmd, vec!["choco", "install", "-y", "ffmpeg-full"]);
    }

    #[test]
    fn brew_command_shape() {
        assert_eq!(
            InstallPath::Brew.install_command(),
            vec!["brew", "install", "ffmpeg"],
        );
    }

    #[test]
    fn apt_command_uses_sudo_and_yes() {
        let cmd = InstallPath::Apt.install_command();
        assert!(cmd.contains(&"sudo".to_string()));
        assert!(cmd.contains(&"-y".to_string()));
        assert!(cmd.contains(&"ffmpeg".to_string()));
    }

    #[test]
    fn dnf_command_uses_sudo_and_yes() {
        let cmd = InstallPath::Dnf.install_command();
        assert!(cmd.starts_with(&["sudo".to_string(), "dnf".to_string()]));
        assert!(cmd.contains(&"-y".to_string()));
    }

    #[test]
    fn pacman_command_uses_noconfirm() {
        let cmd = InstallPath::Pacman.install_command();
        assert!(cmd.contains(&"--noconfirm".to_string()));
    }

    #[test]
    fn manual_install_command_is_empty() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn for_host_returns_platform_appropriate() {
        let pick = InstallPath::for_host();
        #[cfg(target_os = "windows")]
        assert_eq!(pick, InstallPath::Winget);
        #[cfg(target_os = "macos")]
        assert_eq!(pick, InstallPath::Brew);
        #[cfg(target_os = "linux")]
        assert_eq!(pick, InstallPath::Apt);
    }

    #[test]
    fn install_path_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&InstallPath::Pacman).unwrap(),
            "\"pacman\"",
        );
    }

    #[tokio::test]
    async fn check_ffmpeg_available_returns_option() {
        // Live probe — gracefully None on hosts without ffmpeg
        // on PATH; gracefully Some(...) on hosts that have it.
        // Either outcome validates the surface; we just assert
        // no panic.
        let _ = check_ffmpeg_available().await;
    }
}
