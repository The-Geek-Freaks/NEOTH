//! W-02 — Hysteria2 installer primitive.
//!
//! Hysteria2 is the privacy-first VPN option the W-03 wizard
//! recommends for operators who picked `privacy_first: true`.
//! Censorship-resistant UDP-based transport; standalone binary
//! (no daemon needed beyond the operator's own running instance).

use serde::{Deserialize, Serialize};
use tokio::process::Command;

pub const HYSTERIA2_DOWNLOAD_URL: &str =
    "https://v2.hysteria.network/docs/getting-started/Installation/";
pub const HYSTERIA2_INSTALL_SCRIPT_URL: &str = "https://get.hy2.sh/";

/// Default Hysteria2 server-side UDP port. Pinned so the wizard's
/// firewall-rule hints stay consistent.
pub const DEFAULT_HYSTERIA2_PORT: u16 = 36_712;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `bash <(curl -fsSL https://get.hy2.sh/)` — official Linux/
    /// macOS installer.
    UpstreamScript,
    /// `winget install apernet.hysteria` — Microsoft pkg mgr.
    Winget,
    /// `brew install hysteria` — macOS Homebrew alternative.
    Brew,
    /// Manual binary download from GitHub releases linked off the
    /// upstream docs.
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

    pub fn install_command(self) -> Vec<String> {
        match self {
            Self::UpstreamScript => vec![
                "bash".into(),
                "-c".into(),
                format!("curl -fsSL {HYSTERIA2_INSTALL_SCRIPT_URL} | bash"),
            ],
            Self::Winget => vec!["winget".into(), "install".into(), "apernet.hysteria".into()],
            Self::Brew => vec!["brew".into(), "install".into(), "hysteria".into()],
            Self::Manual => Vec::new(),
        }
    }

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

pub async fn check_hysteria2_available() -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg("hysteria").arg("version");
        c
    } else {
        let mut c = Command::new("hysteria");
        c.arg("version");
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
        .find(|l| l.to_lowercase().contains("version") || !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_pinned() {
        assert_eq!(DEFAULT_HYSTERIA2_PORT, 36_712);
    }

    #[test]
    fn urls_are_official_https() {
        assert!(HYSTERIA2_DOWNLOAD_URL.starts_with("https://"));
        assert!(HYSTERIA2_INSTALL_SCRIPT_URL.starts_with("https://"));
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(InstallPath::UpstreamScript.as_str(), "upstream_script");
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn upstream_script_pipes_curl_to_bash() {
        let cmd = InstallPath::UpstreamScript.install_command();
        assert_eq!(cmd[0], "bash");
        assert!(cmd[2].contains(HYSTERIA2_INSTALL_SCRIPT_URL));
        assert!(cmd[2].contains("| bash"));
    }

    #[test]
    fn winget_uses_canonical_apernet_package() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd, vec!["winget", "install", "apernet.hysteria"]);
    }

    #[test]
    fn brew_command_shape() {
        assert_eq!(
            InstallPath::Brew.install_command(),
            vec!["brew", "install", "hysteria"],
        );
    }

    #[test]
    fn manual_command_is_empty() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&InstallPath::UpstreamScript).unwrap(),
            "\"upstream_script\"",
        );
    }

    #[tokio::test]
    async fn check_hysteria2_available_returns_option_gracefully() {
        let _ = check_hysteria2_available().await;
    }

    #[test]
    fn for_host_returns_platform_appropriate() {
        let pick = InstallPath::for_host();
        #[cfg(target_os = "windows")]
        assert_eq!(pick, InstallPath::Winget);
        #[cfg(target_os = "macos")]
        assert_eq!(pick, InstallPath::Brew);
        #[cfg(target_os = "linux")]
        assert_eq!(pick, InstallPath::UpstreamScript);
    }
}
