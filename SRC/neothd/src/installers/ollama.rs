//! W-02 — ollama installer primitive.
//!
//! Ollama is the optional local-model runtime NEOTH wizard offers
//! when the operator's GPU/RAM can host one. Same pattern as
//! [`super::n8n`] + [`super::paperless`]: probe binary + endpoint,
//! recommend install path, render commands for operator GO/STOP.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

/// Default Ollama HTTP port. Pinned — operators copy/pasting from
/// upstream docs hit the canonical value.
pub const DEFAULT_OLLAMA_PORT: u16 = 11_434;

/// Upstream install docs URL the wizard renders for unsupported
/// platforms / manual installs.
pub const OLLAMA_DOWNLOAD_URL: &str = "https://ollama.com/download";

/// One-line install script Ollama publishes for Linux/macOS.
pub const OLLAMA_INSTALL_SCRIPT_URL: &str = "https://ollama.com/install.sh";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `curl -fsSL https://ollama.com/install.sh | sh` — official
    /// Linux/macOS installer.
    UpstreamScript,
    /// `winget install Ollama.Ollama` — Microsoft-managed pkg mgr.
    Winget,
    /// `brew install ollama` — macOS Homebrew alternative.
    Brew,
    /// Manual download from [`OLLAMA_DOWNLOAD_URL`].
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
                "sh".into(),
                "-c".into(),
                format!("curl -fsSL {OLLAMA_INSTALL_SCRIPT_URL} | sh"),
            ],
            Self::Winget => vec!["winget".into(), "install".into(), "Ollama.Ollama".into()],
            Self::Brew => vec!["brew".into(), "install".into(), "ollama".into()],
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

pub async fn check_ollama_available() -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg("ollama").arg("--version");
        c
    } else {
        let mut c = Command::new("ollama");
        c.arg("--version");
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
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Reachable,
    PortClosed,
    Timeout,
}

impl ProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::PortClosed => "port_closed",
            Self::Timeout => "timeout",
        }
    }
}

pub async fn probe_endpoint(port: u16) -> ProbeOutcome {
    use tokio::net::TcpStream;
    let addr = format!("127.0.0.1:{port}");
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => ProbeOutcome::Reachable,
        Ok(Err(_)) => ProbeOutcome::PortClosed,
        Err(_) => ProbeOutcome::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_pinned() {
        assert_eq!(DEFAULT_OLLAMA_PORT, 11_434);
    }

    #[test]
    fn urls_are_official_https() {
        assert!(OLLAMA_DOWNLOAD_URL.starts_with("https://ollama.com/"));
        assert!(OLLAMA_INSTALL_SCRIPT_URL.starts_with("https://ollama.com/"));
        assert!(OLLAMA_INSTALL_SCRIPT_URL.ends_with(".sh"));
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(InstallPath::UpstreamScript.as_str(), "upstream_script");
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn upstream_script_command_pipes_curl_to_sh() {
        let cmd = InstallPath::UpstreamScript.install_command();
        assert_eq!(cmd[0], "sh");
        assert_eq!(cmd[1], "-c");
        assert!(cmd[2].contains("curl"));
        assert!(cmd[2].contains(OLLAMA_INSTALL_SCRIPT_URL));
        assert!(cmd[2].contains("| sh"));
    }

    #[test]
    fn winget_command_uses_canonical_package_id() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd, vec!["winget", "install", "Ollama.Ollama"]);
    }

    #[test]
    fn brew_command_shape() {
        assert_eq!(
            InstallPath::Brew.install_command(),
            vec!["brew", "install", "ollama"],
        );
    }

    #[test]
    fn manual_install_command_is_empty() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn probe_outcome_as_str_pinned() {
        assert_eq!(ProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(ProbeOutcome::PortClosed.as_str(), "port_closed");
        assert_eq!(ProbeOutcome::Timeout.as_str(), "timeout");
    }

    #[tokio::test]
    async fn probe_unbound_port_returns_closed_or_timeout() {
        // High random port unlikely to be bound.
        let outcome = probe_endpoint(58_421).await;
        assert!(matches!(
            outcome,
            ProbeOutcome::PortClosed | ProbeOutcome::Timeout
        ));
    }

    #[tokio::test]
    async fn check_ollama_available_returns_option_gracefully() {
        let _ = check_ollama_available().await;
    }

    #[test]
    fn snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&InstallPath::UpstreamScript).unwrap(),
            "\"upstream_script\"",
        );
    }
}
