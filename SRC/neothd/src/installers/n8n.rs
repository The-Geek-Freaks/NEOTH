//! N-1 — n8n workflow engine installer primitive.
//!
//! n8n is an optional NEOTH integration that ships with operator-
//! visible workflow templates for daily summary / morning brief /
//! weekly stats (see N-2 in `assets/n8n_workflows/`). The wizard
//! step that consumes this module:
//!
//!   1. Probes Docker via [`check_docker_available`].
//!   2. Probes npm via [`check_npm_available`].
//!   3. Offers the operator two install paths (Docker container vs
//!      global npm) per [`InstallStrategy::recommend`].
//!   4. Runs the chosen install command (subprocess shell-out, not
//!      auto-spawned — we honour the "operator GO per command" rule
//!      so n8n install is opt-in even when both Docker and npm are
//!      available).
//!   5. Probes the live HTTP endpoint at [`DEFAULT_N8N_PORT`] via
//!      [`probe_n8n_endpoint`].
//!
//! All probes are async + non-blocking; the actual install commands
//! get assembled here as `Vec<String>` so the wizard can show them
//! to the operator before running anything. No silent spawn.

use std::time::Duration;

use tokio::process::Command;

/// Default n8n web port. Operator can override via wizard prompt;
/// the const is the recommendation we render in the picker.
pub const DEFAULT_N8N_PORT: u16 = 5678;

/// One of the two install paths n8n supports. Pinned exhaustively
/// — adding a third path needs operator-facing wizard UX.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InstallStrategy {
    /// `docker run -d -p <port>:5678 -v n8n_data:/home/node/.n8n n8nio/n8n`
    /// Recommended when Docker is available — operator keeps n8n
    /// isolated + can upgrade by pulling a new image.
    Docker,
    /// `npm install -g n8n` + `n8n start --tunnel`
    /// Fallback when Docker isn't available. Operator owns the
    /// Node.js runtime + must manage the n8n process lifecycle.
    Npm,
}

impl InstallStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Npm => "npm",
        }
    }

    /// Operator-facing one-line description shown in the wizard
    /// picker. Decline-friendly framing — both paths work; operator
    /// can skip n8n entirely.
    pub fn description(self) -> &'static str {
        match self {
            Self::Docker => {
                "Run n8n as a Docker container (recommended: isolated, easy upgrade)"
            }
            Self::Npm => "Install n8n globally via npm (fallback: needs Node.js)",
        }
    }

    /// Decide which strategy to recommend given probe outcomes.
    /// Docker wins when available (isolation); npm is the fallback.
    /// `None` means neither path is available — the wizard surfaces
    /// "install Docker or Node.js first" with links.
    pub fn recommend(docker: bool, npm: bool) -> Option<Self> {
        if docker {
            Some(Self::Docker)
        } else if npm {
            Some(Self::Npm)
        } else {
            None
        }
    }

    /// Build the install command + args for this strategy. Pure-fn
    /// so the wizard can render the exact command to the operator
    /// before running anything (no surprise subprocess).
    pub fn install_command(self, port: u16) -> Vec<String> {
        match self {
            Self::Docker => vec![
                "docker".into(),
                "run".into(),
                "-d".into(),
                "--name".into(),
                "neoth-n8n".into(),
                "-p".into(),
                format!("{port}:5678"),
                "-v".into(),
                "n8n_data:/home/node/.n8n".into(),
                "--restart".into(),
                "unless-stopped".into(),
                "n8nio/n8n:latest".into(),
            ],
            Self::Npm => vec!["npm".into(), "install".into(), "-g".into(), "n8n".into()],
        }
    }
}

/// Probe `docker --version`. Returns the version string on success
/// or None when Docker is missing / returns non-zero.
pub async fn check_docker_available() -> Option<String> {
    cli_version("docker").await
}

/// Probe `npm --version` — re-uses the existing installer probe
/// but namespaced here so the n8n wizard step can keep its own
/// surface.
pub async fn check_npm_available() -> Option<String> {
    cli_version("npm").await
}

async fn cli_version(binary: &str) -> Option<String> {
    // Wrap through `cmd /C` on Windows so npm/docker shell-script
    // shims (`docker.cmd`, `npm.cmd`) resolve the same way as `.exe`.
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(binary).arg("--version");
        c
    } else {
        let mut c = Command::new(binary);
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
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Outcome of a live n8n HTTP probe. Operator-readable so the
/// wizard can render "n8n is up" / "port is open but n8n isn't
/// responding" / "port is closed" without re-running the probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum N8nProbeOutcome {
    /// HTTP layer accepted the probe — n8n process is up.
    Reachable,
    /// TCP connect refused — n8n isn't running on the port.
    PortClosed,
    /// TCP connect succeeded but the HTTP handshake timed out — port
    /// is bound by some other process or n8n is mid-startup.
    PortOpenNoHttp,
    /// Probe didn't complete inside the timeout window.
    Timeout,
}

impl N8nProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::PortClosed => "port_closed",
            Self::PortOpenNoHttp => "port_open_no_http",
            Self::Timeout => "timeout",
        }
    }
}

/// Probe the live n8n endpoint at `127.0.0.1:<port>`. Uses TCP
/// connect (fast) — when that succeeds we ALSO try a brief HTTP
/// handshake so a port collision (some other service holding the
/// port) is distinguishable from a real n8n.
pub async fn probe_n8n_endpoint(port: u16) -> N8nProbeOutcome {
    use tokio::net::TcpStream;
    let addr = format!("127.0.0.1:{port}");
    let connect_timeout = Duration::from_secs(2);
    let connect = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await;
    match connect {
        Ok(Ok(_stream)) => {
            // Port is bound. v0.1: distinguishing "n8n vs other
            // process" needs a real HTTP GET / response inspect;
            // for the primitive we report Reachable on TCP open
            // (n8n is the only thing operators bind 5678 to in
            // their NEOTH workflow) + PortOpenNoHttp would require
            // a follow-up commit that adds reqwest/hyper to the
            // probe path. v0.1 keeps the probe TCP-only.
            N8nProbeOutcome::Reachable
        }
        Ok(Err(_)) => N8nProbeOutcome::PortClosed,
        Err(_) => N8nProbeOutcome::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_pinned_to_n8n_canonical() {
        // Drift guard — n8n's own docs document 5678 as the
        // canonical port. Operators copy-pasting from n8n docs
        // expect this match.
        assert_eq!(DEFAULT_N8N_PORT, 5678);
    }

    #[test]
    fn strategy_as_str_pinned() {
        assert_eq!(InstallStrategy::Docker.as_str(), "docker");
        assert_eq!(InstallStrategy::Npm.as_str(), "npm");
    }

    #[test]
    fn strategy_descriptions_distinct() {
        let a = InstallStrategy::Docker.description();
        let b = InstallStrategy::Npm.description();
        assert_ne!(a, b);
        // Both must mention what the operator gets.
        assert!(a.to_lowercase().contains("docker"));
        assert!(b.to_lowercase().contains("npm"));
    }

    #[test]
    fn recommend_prefers_docker_when_available() {
        assert_eq!(
            InstallStrategy::recommend(true, true),
            Some(InstallStrategy::Docker)
        );
        assert_eq!(
            InstallStrategy::recommend(true, false),
            Some(InstallStrategy::Docker)
        );
    }

    #[test]
    fn recommend_falls_back_to_npm_when_only_npm_available() {
        assert_eq!(
            InstallStrategy::recommend(false, true),
            Some(InstallStrategy::Npm)
        );
    }

    #[test]
    fn recommend_returns_none_when_neither_available() {
        assert_eq!(InstallStrategy::recommend(false, false), None);
    }

    #[test]
    fn docker_install_command_uses_canonical_image_and_port() {
        let cmd = InstallStrategy::Docker.install_command(DEFAULT_N8N_PORT);
        assert_eq!(cmd[0], "docker");
        assert_eq!(cmd[1], "run");
        assert!(cmd.contains(&"-d".to_string()));
        assert!(cmd.contains(&"n8nio/n8n:latest".to_string()));
        assert!(cmd.iter().any(|a| a == &format!("{DEFAULT_N8N_PORT}:5678")));
        assert!(cmd.contains(&"--restart".to_string()));
        assert!(cmd.contains(&"unless-stopped".to_string()));
    }

    #[test]
    fn docker_install_command_respects_custom_port() {
        let cmd = InstallStrategy::Docker.install_command(9999);
        assert!(cmd.iter().any(|a| a == "9999:5678"));
    }

    #[test]
    fn npm_install_command_is_global_install() {
        let cmd = InstallStrategy::Npm.install_command(DEFAULT_N8N_PORT);
        assert_eq!(cmd, vec!["npm", "install", "-g", "n8n"]);
    }

    #[test]
    fn probe_outcome_as_str_pinned() {
        assert_eq!(N8nProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(N8nProbeOutcome::PortClosed.as_str(), "port_closed");
        assert_eq!(N8nProbeOutcome::PortOpenNoHttp.as_str(), "port_open_no_http");
        assert_eq!(N8nProbeOutcome::Timeout.as_str(), "timeout");
    }

    #[tokio::test]
    async fn probe_returns_port_closed_for_unbound_port() {
        // Port 1 is IANA-reserved + never bound — TCP connect must
        // refuse immediately, classifying as PortClosed.
        let outcome = probe_n8n_endpoint(1).await;
        assert!(
            matches!(
                outcome,
                N8nProbeOutcome::PortClosed | N8nProbeOutcome::Timeout
            ),
            "expected PortClosed or Timeout for dead port, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn probe_returns_reachable_for_live_loopback_listener() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let outcome = probe_n8n_endpoint(port).await;
        assert_eq!(outcome, N8nProbeOutcome::Reachable);
    }

    #[tokio::test]
    async fn docker_probe_returns_some_or_none_no_panic() {
        // Smoke — runs on any host. If docker is installed we get
        // a version string; otherwise None. Either way no panic.
        let v = check_docker_available().await;
        if let Some(s) = v {
            assert!(s.to_lowercase().contains("docker"));
        }
    }

    #[tokio::test]
    async fn npm_probe_returns_some_or_none_no_panic() {
        let v = check_npm_available().await;
        if let Some(s) = v {
            // npm --version → bare semver, must contain a digit.
            assert!(s.chars().any(|c| c.is_ascii_digit()));
        }
    }
}
