//! W-02 — Tailscale installer primitive.
//!
//! Tailscale is one of two VPN options the W-03 wizard recommends
//! (the other is Hysteria2 for privacy-first operators). Same
//! pattern as ffmpeg/ollama: probe binary + login state, render
//! install command for operator GO/STOP.

use serde::{Deserialize, Serialize};
use tokio::process::Command;

pub const TAILSCALE_DOWNLOAD_URL: &str = "https://tailscale.com/download";
pub const TAILSCALE_INSTALL_SCRIPT_URL: &str = "https://tailscale.com/install.sh";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPath {
    /// `curl -fsSL https://tailscale.com/install.sh | sh` —
    /// official Linux installer.
    UpstreamScript,
    /// `winget install Tailscale.Tailscale`.
    Winget,
    /// `brew install tailscale`.
    Brew,
    /// Manual download from [`TAILSCALE_DOWNLOAD_URL`].
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
                format!("curl -fsSL {TAILSCALE_INSTALL_SCRIPT_URL} | sh"),
            ],
            Self::Winget => vec![
                "winget".into(),
                "install".into(),
                "Tailscale.Tailscale".into(),
            ],
            Self::Brew => vec!["brew".into(), "install".into(), "tailscale".into()],
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

pub async fn check_tailscale_available() -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg("tailscale").arg("version");
        c
    } else {
        let mut c = Command::new("tailscale");
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
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// `tailscale status --json` returns a JSON envelope including a
/// `BackendState` field. We parse that to surface "Running" vs
/// "NeedsLogin" / "Stopped" / "NoState" to the operator without
/// having to parse the whole graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    Running,
    NeedsLogin,
    Stopped,
    NoState,
    /// Parsed an unrecognised state — surface verbatim to the operator.
    Unknown(String),
}

impl BackendState {
    pub fn from_status_json(json: &str) -> Self {
        let v: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return Self::Unknown("invalid_json".to_string()),
        };
        match v.get("BackendState").and_then(|x| x.as_str()) {
            Some("Running") => Self::Running,
            Some("NeedsLogin") => Self::NeedsLogin,
            Some("Stopped") => Self::Stopped,
            Some("NoState") => Self::NoState,
            Some(other) => Self::Unknown(other.to_string()),
            None => Self::Unknown("missing_field".to_string()),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::NeedsLogin => "needs_login",
            Self::Stopped => "stopped",
            Self::NoState => "no_state",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_official_https() {
        assert!(TAILSCALE_DOWNLOAD_URL.starts_with("https://tailscale.com/"));
        assert!(TAILSCALE_INSTALL_SCRIPT_URL.starts_with("https://tailscale.com/"));
    }

    #[test]
    fn install_path_as_str_pinned() {
        assert_eq!(InstallPath::UpstreamScript.as_str(), "upstream_script");
        assert_eq!(InstallPath::Winget.as_str(), "winget");
        assert_eq!(InstallPath::Brew.as_str(), "brew");
        assert_eq!(InstallPath::Manual.as_str(), "manual");
    }

    #[test]
    fn upstream_script_pipes_curl_to_sh() {
        let cmd = InstallPath::UpstreamScript.install_command();
        assert_eq!(cmd[0], "sh");
        assert!(cmd[2].contains("tailscale.com/install.sh"));
        assert!(cmd[2].contains("| sh"));
    }

    #[test]
    fn winget_uses_canonical_package_id() {
        let cmd = InstallPath::Winget.install_command();
        assert_eq!(cmd, vec!["winget", "install", "Tailscale.Tailscale"]);
    }

    #[test]
    fn brew_command_shape() {
        assert_eq!(
            InstallPath::Brew.install_command(),
            vec!["brew", "install", "tailscale"],
        );
    }

    #[test]
    fn manual_command_is_empty() {
        assert!(InstallPath::Manual.install_command().is_empty());
    }

    #[test]
    fn backend_state_running_from_json() {
        let json = r#"{"BackendState":"Running","Self":{"ID":"xyz"}}"#;
        assert_eq!(BackendState::from_status_json(json), BackendState::Running);
    }

    #[test]
    fn backend_state_needs_login_from_json() {
        let json = r#"{"BackendState":"NeedsLogin"}"#;
        assert_eq!(
            BackendState::from_status_json(json),
            BackendState::NeedsLogin
        );
    }

    #[test]
    fn backend_state_stopped_and_no_state() {
        assert_eq!(
            BackendState::from_status_json(r#"{"BackendState":"Stopped"}"#),
            BackendState::Stopped,
        );
        assert_eq!(
            BackendState::from_status_json(r#"{"BackendState":"NoState"}"#),
            BackendState::NoState,
        );
    }

    #[test]
    fn backend_state_unknown_surfaces_verbatim() {
        let s = BackendState::from_status_json(r#"{"BackendState":"WhoKnows"}"#);
        match s {
            BackendState::Unknown(payload) => assert_eq!(payload, "WhoKnows"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn backend_state_missing_field_returns_unknown() {
        let s = BackendState::from_status_json(r#"{"Self":{}}"#);
        match s {
            BackendState::Unknown(p) => assert_eq!(p, "missing_field"),
            other => panic!("expected Unknown(missing_field), got {other:?}"),
        }
    }

    #[test]
    fn backend_state_malformed_json_returns_unknown_invalid() {
        let s = BackendState::from_status_json("not json");
        match s {
            BackendState::Unknown(p) => assert_eq!(p, "invalid_json"),
            other => panic!("expected Unknown(invalid_json), got {other:?}"),
        }
    }

    #[test]
    fn backend_state_as_str_pinned() {
        assert_eq!(BackendState::Running.as_str(), "running");
        assert_eq!(BackendState::NeedsLogin.as_str(), "needs_login");
        assert_eq!(BackendState::Stopped.as_str(), "stopped");
        assert_eq!(BackendState::NoState.as_str(), "no_state");
        assert_eq!(BackendState::Unknown("x".into()).as_str(), "unknown");
    }

    #[tokio::test]
    async fn check_tailscale_available_returns_option_gracefully() {
        let _ = check_tailscale_available().await;
    }
}
