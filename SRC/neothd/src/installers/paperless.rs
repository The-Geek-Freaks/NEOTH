//! PL-01 — paperless-ngx installer primitive.
//!
//! paperless-ngx is an optional NEOTH integration: a self-hosted
//! document management server that ingests scanned PDFs / images,
//! runs OCR via tesseract, and exposes a REST API NEOTH consumes
//! (see PL-02 OCR ingest → Obsidian + SC-16 paperless typed
//! wrapper). This module mirrors the [`super::n8n`] surface:
//!
//!   1. Probe Docker via [`check_docker_available`].
//!   2. Probe docker-compose via [`check_docker_compose_available`]
//!      (modern Docker bundles `docker compose`; older standalone
//!      `docker-compose` also works — we accept either).
//!   3. Recommend an install strategy via [`InstallStrategy::recommend`].
//!   4. Render the install command sequence as `Vec<String>` so the
//!      wizard SHOWS it to the operator before running anything.
//!      No silent spawn — honours the "operator GO per command" rule.
//!   5. Probe the live HTTP endpoint via [`probe_paperless_endpoint`].
//!
//! ## Why Docker-only for the primitive
//!
//! paperless-ngx upstream packages itself as a multi-container
//! application (paperless + redis + postgres + tika + gotenberg).
//! The bare-metal install path requires the operator to install
//! tesseract + redis + postgres + python venv themselves — out of
//! scope for "would a non-technical user on a fresh Win11 laptop reach the
//! wizard?". When Docker is unavailable, the wizard prints the
//! upstream install URL + tells the operator we'll auto-detect
//! once they have it running.

use std::time::Duration;

use tokio::process::Command;

/// Default paperless-ngx web port. Operator can override via wizard;
/// the const is the recommendation we render in the picker.
pub const DEFAULT_PAPERLESS_PORT: u16 = 8000;

/// URL of the upstream installer docs the wizard renders when Docker
/// isn't available. Public so the CLI + GUI surfaces share the same
/// link (one source of truth — broken-link audits stay simple).
pub const PAPERLESS_UPSTREAM_DOCS_URL: &str = "https://docs.paperless-ngx.com/setup/#installation";

/// Canonical compose-file URL operators curl to bootstrap. Pinned
/// so a wizard re-render survives upstream-docs URL changes.
pub const PAPERLESS_COMPOSE_BOOTSTRAP_URL: &str = "https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/main/docker/compose/docker-compose.postgres.yml";

/// One of the install paths paperless-ngx supports. Pinned
/// exhaustively — adding a third path needs wizard UX.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InstallStrategy {
    /// `docker compose -f docker-compose.postgres.yml up -d` after
    /// curling the upstream compose file. Recommended when Docker +
    /// compose are available — upstream-supported, easy upgrades
    /// via `docker compose pull && docker compose up -d`.
    DockerCompose,
    /// `docker-compose -f ... up -d` for older Docker installs that
    /// shipped the standalone `docker-compose` binary instead of
    /// `docker compose` subcommand. Same behaviour, different CLI.
    DockerComposeLegacy,
}

impl InstallStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DockerCompose => "docker_compose",
            Self::DockerComposeLegacy => "docker_compose_legacy",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::DockerCompose => {
                "Run paperless-ngx via `docker compose` (recommended: modern Docker)"
            }
            Self::DockerComposeLegacy => {
                "Run paperless-ngx via legacy `docker-compose` binary (older Docker installs)"
            }
        }
    }

    /// Decide which strategy to recommend given probe outcomes.
    /// Modern `docker compose` wins when available; legacy is the
    /// fallback. `None` means neither is available — wizard renders
    /// [`PAPERLESS_UPSTREAM_DOCS_URL`] and stops.
    pub fn recommend(docker_compose: bool, docker_compose_legacy: bool) -> Option<Self> {
        if docker_compose {
            Some(Self::DockerCompose)
        } else if docker_compose_legacy {
            Some(Self::DockerComposeLegacy)
        } else {
            None
        }
    }

    /// Build the install command sequence. Three steps: download
    /// compose file via curl, then `up -d`, then operator-facing
    /// success line. The wizard renders each line + asks GO/STOP
    /// between download and `up`.
    pub fn install_commands(self, work_dir: &str) -> Vec<Vec<String>> {
        let compose_file = format!("{work_dir}/docker-compose.yml");
        match self {
            Self::DockerCompose => vec![
                vec![
                    "curl".into(),
                    "-fsSL".into(),
                    PAPERLESS_COMPOSE_BOOTSTRAP_URL.into(),
                    "-o".into(),
                    compose_file.clone(),
                ],
                vec![
                    "docker".into(),
                    "compose".into(),
                    "-f".into(),
                    compose_file,
                    "up".into(),
                    "-d".into(),
                ],
            ],
            Self::DockerComposeLegacy => vec![
                vec![
                    "curl".into(),
                    "-fsSL".into(),
                    PAPERLESS_COMPOSE_BOOTSTRAP_URL.into(),
                    "-o".into(),
                    compose_file.clone(),
                ],
                vec![
                    "docker-compose".into(),
                    "-f".into(),
                    compose_file,
                    "up".into(),
                    "-d".into(),
                ],
            ],
        }
    }
}

/// Probe `docker --version`. Returns the version string on success
/// or None when Docker is missing.
pub async fn check_docker_available() -> Option<String> {
    cli_version_args("docker", &["--version"]).await
}

/// Probe `docker compose version` — modern Docker bundles compose as
/// a subcommand, not a standalone binary. Returns version string on
/// success.
pub async fn check_docker_compose_available() -> Option<String> {
    cli_version_args("docker", &["compose", "version"]).await
}

/// Probe legacy `docker-compose --version` — older Docker installs.
pub async fn check_docker_compose_legacy_available() -> Option<String> {
    cli_version_args("docker-compose", &["--version"]).await
}

async fn cli_version_args(binary: &str, args: &[&str]) -> Option<String> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(binary);
        for a in args {
            c.arg(a);
        }
        c
    } else {
        let mut c = Command::new(binary);
        for a in args {
            c.arg(a);
        }
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

/// Outcome of a live paperless-ngx HTTP probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaperlessProbeOutcome {
    /// TCP layer accepted the probe — paperless is up on the port.
    Reachable,
    /// TCP connect refused — paperless isn't running on the port.
    PortClosed,
    /// Probe didn't complete inside the timeout window.
    Timeout,
}

impl PaperlessProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::PortClosed => "port_closed",
            Self::Timeout => "timeout",
        }
    }
}

/// Probe the live paperless-ngx endpoint at `127.0.0.1:<port>`.
/// TCP-only probe — distinguishing "real paperless vs other process
/// on the port" would need a real HTTP GET which adds a reqwest
/// dependency to the primitive. v0.1 stays TCP-only; the wizard
/// asks the operator to confirm via browser when probe says
/// `Reachable`.
pub async fn probe_paperless_endpoint(port: u16) -> PaperlessProbeOutcome {
    use tokio::net::TcpStream;
    let addr = format!("127.0.0.1:{port}");
    let connect_timeout = Duration::from_secs(2);
    match tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => PaperlessProbeOutcome::Reachable,
        Ok(Err(_)) => PaperlessProbeOutcome::PortClosed,
        Err(_) => PaperlessProbeOutcome::Timeout,
    }
}

/// Wizard-facing summary of an install scan. Single struct so the
/// CLI + GUI render identical data without duplicating field logic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaperlessScan {
    pub docker_version: Option<String>,
    pub docker_compose_version: Option<String>,
    pub docker_compose_legacy_version: Option<String>,
    pub probe: PaperlessProbeOutcome,
    pub recommended_strategy: Option<InstallStrategy>,
}

impl PaperlessScan {
    /// True when paperless is already reachable — wizard skips the
    /// install step + jumps straight to API-token entry.
    pub fn already_running(&self) -> bool {
        self.probe == PaperlessProbeOutcome::Reachable
    }

    /// True when an install path exists. False = wizard renders the
    /// upstream docs URL + stops.
    pub fn can_install(&self) -> bool {
        self.recommended_strategy.is_some()
    }
}

/// Run the full scan in one call — probe both compose flavours +
/// live endpoint in parallel, return the [`PaperlessScan`].
pub async fn scan(port: u16) -> PaperlessScan {
    let (docker, modern, legacy, probe) = tokio::join!(
        check_docker_available(),
        check_docker_compose_available(),
        check_docker_compose_legacy_available(),
        probe_paperless_endpoint(port),
    );
    let recommended_strategy = InstallStrategy::recommend(modern.is_some(), legacy.is_some());
    PaperlessScan {
        docker_version: docker,
        docker_compose_version: modern,
        docker_compose_legacy_version: legacy,
        probe,
        recommended_strategy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_pinned_to_paperless_canonical() {
        // Drift guard — paperless-ngx default web port. Operators
        // copy-pasting from upstream docs must hit the same value.
        assert_eq!(DEFAULT_PAPERLESS_PORT, 8000);
    }

    #[test]
    fn upstream_docs_url_points_at_paperless_ngx() {
        assert!(PAPERLESS_UPSTREAM_DOCS_URL.contains("paperless-ngx"));
        assert!(PAPERLESS_UPSTREAM_DOCS_URL.starts_with("https://"));
    }

    #[test]
    fn compose_bootstrap_url_is_https_and_yml() {
        assert!(PAPERLESS_COMPOSE_BOOTSTRAP_URL.starts_with("https://"));
        assert!(PAPERLESS_COMPOSE_BOOTSTRAP_URL.ends_with(".yml"));
    }

    #[test]
    fn strategy_as_str_pinned_for_audit() {
        assert_eq!(InstallStrategy::DockerCompose.as_str(), "docker_compose");
        assert_eq!(
            InstallStrategy::DockerComposeLegacy.as_str(),
            "docker_compose_legacy"
        );
    }

    #[test]
    fn recommend_prefers_modern_over_legacy() {
        assert_eq!(
            InstallStrategy::recommend(true, true),
            Some(InstallStrategy::DockerCompose)
        );
        assert_eq!(
            InstallStrategy::recommend(true, false),
            Some(InstallStrategy::DockerCompose)
        );
    }

    #[test]
    fn recommend_falls_back_to_legacy_when_modern_absent() {
        assert_eq!(
            InstallStrategy::recommend(false, true),
            Some(InstallStrategy::DockerComposeLegacy)
        );
    }

    #[test]
    fn recommend_none_when_no_compose_available() {
        assert_eq!(InstallStrategy::recommend(false, false), None);
    }

    #[test]
    fn install_commands_modern_curls_then_compose_up() {
        let cmds = InstallStrategy::DockerCompose.install_commands("/tmp/paperless");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0][0], "curl");
        assert!(cmds[0].contains(&PAPERLESS_COMPOSE_BOOTSTRAP_URL.to_string()));
        assert_eq!(cmds[1][0], "docker");
        assert_eq!(cmds[1][1], "compose");
        assert!(cmds[1].iter().any(|a| a == "up"));
        assert!(cmds[1].iter().any(|a| a == "-d"));
    }

    #[test]
    fn install_commands_legacy_uses_hyphenated_binary() {
        let cmds = InstallStrategy::DockerComposeLegacy.install_commands("/tmp/paperless");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1][0], "docker-compose");
        assert!(cmds[1].iter().any(|a| a == "up"));
    }

    #[test]
    fn install_commands_embed_work_dir_in_compose_path() {
        let cmds = InstallStrategy::DockerCompose.install_commands("/custom/paperless-dir");
        assert!(
            cmds[0]
                .iter()
                .any(|a| a == "/custom/paperless-dir/docker-compose.yml")
        );
        assert!(
            cmds[1]
                .iter()
                .any(|a| a == "/custom/paperless-dir/docker-compose.yml")
        );
    }

    #[test]
    fn probe_outcome_as_str_pinned() {
        assert_eq!(PaperlessProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(PaperlessProbeOutcome::PortClosed.as_str(), "port_closed");
        assert_eq!(PaperlessProbeOutcome::Timeout.as_str(), "timeout");
    }

    #[tokio::test]
    async fn probe_closed_port_returns_port_closed() {
        // Pick a high random port unlikely to be bound.
        let outcome = probe_paperless_endpoint(58_237).await;
        assert!(matches!(
            outcome,
            PaperlessProbeOutcome::PortClosed | PaperlessProbeOutcome::Timeout
        ));
    }

    #[test]
    fn scan_struct_already_running_reflects_probe_reachable() {
        let s = PaperlessScan {
            docker_version: Some("Docker version 25.0.0".into()),
            docker_compose_version: Some("Docker Compose version v2.24.0".into()),
            docker_compose_legacy_version: None,
            probe: PaperlessProbeOutcome::Reachable,
            recommended_strategy: Some(InstallStrategy::DockerCompose),
        };
        assert!(s.already_running());
        assert!(s.can_install());
    }

    #[test]
    fn scan_can_install_false_when_no_strategy() {
        let s = PaperlessScan {
            docker_version: None,
            docker_compose_version: None,
            docker_compose_legacy_version: None,
            probe: PaperlessProbeOutcome::PortClosed,
            recommended_strategy: None,
        };
        assert!(!s.can_install());
        assert!(!s.already_running());
    }

    #[test]
    fn description_strings_are_operator_readable() {
        let modern = InstallStrategy::DockerCompose.description();
        let legacy = InstallStrategy::DockerComposeLegacy.description();
        assert!(modern.contains("paperless") || modern.contains("Docker"));
        assert!(legacy.contains("legacy") || legacy.contains("older"));
    }
}
