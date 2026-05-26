//! W-05 — install_step + W-05a PkgManagerHandle trait.
//!
//! Shared install-fallback substrate the wizard's step-5
//! (W-05), the self-updater (U-01), and the CLI-version
//! updater (U-03) all consume. Each pkg-manager impls
//! [`PkgManagerHandle`] so the fallback chain
//! (`winget→choco` on Windows, `apt→dnf→pacman→brew` on
//! Linux/macOS) is one routing surface.
//!
//! ## What ships here
//!
//! - [`PkgManagerHandle`] async trait — `install(pkg)` +
//!   `upgrade(pkg)`.
//! - 6 pure-data + command-formatter handles: Winget, Choco,
//!   Apt, Dnf, Pacman, Brew. Each builds the exact argv the
//!   subprocess would spawn — testable without spawning.
//! - [`FallbackChain`] — operator-config-driven ordered list of
//!   handles; the orchestrator tries each until one succeeds.
//! - [`dry_run_install_commands`] — pure-fn render path for the
//!   wizard's GO/STOP prompt before any subprocess fires.
//! - [`build_installer_ran_payload`] — bridges back into the
//!   W-08 `InstallerRanPayload` so the WAL emit-site never
//!   reaches into per-handle internals.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::wal::payloads_w08::InstallerRanPayload;

/// Outcome of one install/upgrade attempt by a single handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Subprocess exited 0; package now installed/upgraded.
    Success,
    /// Subprocess exited non-zero; surface stderr for the
    /// fallback decision.
    NonZeroExit { code: i32, stderr_tail: String },
    /// Subprocess failed to spawn (binary missing on PATH,
    /// permission denied). Fallback chain consumes this as
    /// "skip this handle, try the next".
    SpawnFailed { reason: String },
    /// Operator passed `dry_run=true` — handle returned without
    /// firing anything. Wizard treats this as a clean exit + no
    /// fallback needed.
    DryRun,
}

impl InstallOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::DryRun)
    }

    pub fn snake_case_tag(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NonZeroExit { .. } => "non_zero_exit",
            Self::SpawnFailed { .. } => "spawn_failed",
            Self::DryRun => "dry_run",
        }
    }
}

/// Common interface every pkg-manager backend implements.
#[async_trait]
pub trait PkgManagerHandle: Send + Sync {
    /// Stable identifier — matches the W-08 InstallerRanPayload
    /// `pkg_mgr` field (`"winget"` / `"choco"` / `"apt"` / …).
    fn kind(&self) -> PkgManagerKind;

    /// Build the install argv. Pure-fn — caller renders to
    /// operator for GO/STOP before invoking.
    fn install_argv(&self, package: &str) -> Vec<String>;

    /// Build the upgrade argv.
    fn upgrade_argv(&self, package: &str) -> Vec<String>;

    /// Run the install. `dry_run=true` short-circuits + returns
    /// `InstallOutcome::DryRun`.
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome;

    /// Run the upgrade.
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome;
}

/// Stable identifier per pkg-manager. Matches the
/// `InstallerRanPayload::pkg_mgr` wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PkgManagerKind {
    Winget,
    Choco,
    Apt,
    Dnf,
    Pacman,
    Brew,
    /// Operator did the install manually — no pkg-mgr fired.
    /// Used by the WAL emit-site when the wizard falls off the
    /// chain entirely.
    Manual,
}

impl PkgManagerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Winget => "winget",
            Self::Choco => "choco",
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Brew => "brew",
            Self::Manual => "manual",
        }
    }
}

// ── per-handle impls (argv-only — actual `install`/`upgrade`
// async fns spawn subprocess via tokio::process::Command + the
// shared `run_argv` helper below) ───────────────────────────────

/// `winget install --silent --id <pkg>` (Microsoft pkg-mgr).
pub struct WingetHandle;

#[async_trait]
impl PkgManagerHandle for WingetHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Winget
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec![
            "winget".into(),
            "install".into(),
            "--silent".into(),
            "--id".into(),
            package.into(),
        ]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec![
            "winget".into(),
            "upgrade".into(),
            "--silent".into(),
            "--id".into(),
            package.into(),
        ]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// `choco install -y <pkg>` / `choco upgrade -y <pkg>`.
pub struct ChocoHandle;

#[async_trait]
impl PkgManagerHandle for ChocoHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Choco
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec![
            "choco".into(),
            "install".into(),
            "-y".into(),
            package.into(),
        ]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec![
            "choco".into(),
            "upgrade".into(),
            "-y".into(),
            package.into(),
        ]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// `sudo apt install -y <pkg>` / `sudo apt upgrade -y <pkg>`.
pub struct AptHandle;

#[async_trait]
impl PkgManagerHandle for AptHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Apt
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "apt".into(),
            "install".into(),
            "-y".into(),
            package.into(),
        ]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "apt".into(),
            "install".into(),
            "--only-upgrade".into(),
            "-y".into(),
            package.into(),
        ]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// `sudo dnf install -y <pkg>` / `sudo dnf upgrade -y <pkg>`.
pub struct DnfHandle;

#[async_trait]
impl PkgManagerHandle for DnfHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Dnf
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "dnf".into(),
            "install".into(),
            "-y".into(),
            package.into(),
        ]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "dnf".into(),
            "upgrade".into(),
            "-y".into(),
            package.into(),
        ]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// `sudo pacman -S --noconfirm <pkg>` / `sudo pacman -Syu
/// --noconfirm <pkg>`.
pub struct PacmanHandle;

#[async_trait]
impl PkgManagerHandle for PacmanHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Pacman
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "pacman".into(),
            "-S".into(),
            "--noconfirm".into(),
            package.into(),
        ]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec![
            "sudo".into(),
            "pacman".into(),
            "-Syu".into(),
            "--noconfirm".into(),
            package.into(),
        ]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// `brew install <pkg>` / `brew upgrade <pkg>`.
pub struct BrewHandle;

#[async_trait]
impl PkgManagerHandle for BrewHandle {
    fn kind(&self) -> PkgManagerKind {
        PkgManagerKind::Brew
    }
    fn install_argv(&self, package: &str) -> Vec<String> {
        vec!["brew".into(), "install".into(), package.into()]
    }
    fn upgrade_argv(&self, package: &str) -> Vec<String> {
        vec!["brew".into(), "upgrade".into(), package.into()]
    }
    async fn install(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.install_argv(package)).await
    }
    async fn upgrade(&self, package: &str, dry_run: bool) -> InstallOutcome {
        if dry_run {
            return InstallOutcome::DryRun;
        }
        run_argv(&self.upgrade_argv(package)).await
    }
}

/// Run an argv via tokio::process. Captures stderr tail (last 1024
/// bytes) so the fallback decision sees the actual error message
/// when a handle fails.
async fn run_argv(argv: &[String]) -> InstallOutcome {
    if argv.is_empty() {
        return InstallOutcome::SpawnFailed {
            reason: "empty argv".to_string(),
        };
    }
    let mut cmd = tokio::process::Command::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return InstallOutcome::SpawnFailed {
                reason: format!("{e}"),
            };
        }
    };
    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            return InstallOutcome::SpawnFailed {
                reason: format!("wait: {e}"),
            };
        }
    };
    if output.status.success() {
        return InstallOutcome::Success;
    }
    let stderr_tail = String::from_utf8_lossy(&output.stderr)
        .chars()
        .rev()
        .take(1024)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    InstallOutcome::NonZeroExit {
        code: output.status.code().unwrap_or(-1),
        stderr_tail,
    }
}

/// Operator-config-driven ordered list of handles to try.
pub struct FallbackChain {
    handles: Vec<Box<dyn PkgManagerHandle>>,
}

impl FallbackChain {
    pub fn new(handles: Vec<Box<dyn PkgManagerHandle>>) -> Self {
        Self { handles }
    }

    /// Build the canonical chain for the current host:
    ///   - Windows: Winget → Choco
    ///   - macOS:   Brew
    ///   - Linux:   Apt → Dnf → Pacman
    /// (Linux distro-specific resolution lands in W-05 phase 2 —
    /// caller can pre-narrow via [`Self::new`] using
    /// `installers::tmux_w02::LinuxDistro` if they've already
    /// classified.)
    pub fn for_host() -> Self {
        let handles: Vec<Box<dyn PkgManagerHandle>> = if cfg!(target_os = "windows") {
            vec![Box::new(WingetHandle), Box::new(ChocoHandle)]
        } else if cfg!(target_os = "macos") {
            vec![Box::new(BrewHandle)]
        } else if cfg!(target_os = "linux") {
            vec![
                Box::new(AptHandle),
                Box::new(DnfHandle),
                Box::new(PacmanHandle),
            ]
        } else {
            Vec::new()
        };
        Self { handles }
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub fn kinds(&self) -> Vec<PkgManagerKind> {
        self.handles.iter().map(|h| h.kind()).collect()
    }

    /// Run `install` across the chain. Returns the first handle
    /// that returned `is_success()` along with its outcome, or
    /// the last outcome if every handle failed.
    pub async fn install(&self, package: &str, dry_run: bool) -> ChainResult {
        let mut tried = Vec::new();
        let mut last: Option<InstallOutcome> = None;
        for h in &self.handles {
            let kind = h.kind();
            let outcome = h.install(package, dry_run).await;
            let success = outcome.is_success();
            tried.push((kind, outcome.clone()));
            last = Some(outcome);
            if success {
                return ChainResult {
                    winning_kind: Some(kind),
                    tried,
                    outcome: last.unwrap(),
                };
            }
        }
        ChainResult {
            winning_kind: None,
            tried,
            outcome: last.unwrap_or(InstallOutcome::SpawnFailed {
                reason: "empty chain".to_string(),
            }),
        }
    }
}

/// Aggregate of a chain-traversal attempt. Wizard logs the
/// full `tried` list to the WAL so the operator audit shows
/// every handle that was consulted.
#[derive(Debug, Clone)]
pub struct ChainResult {
    pub winning_kind: Option<PkgManagerKind>,
    pub tried: Vec<(PkgManagerKind, InstallOutcome)>,
    pub outcome: InstallOutcome,
}

impl ChainResult {
    pub fn is_success(&self) -> bool {
        self.winning_kind.is_some()
    }
}

/// Render every handle's install argv for the wizard's GO/STOP
/// preview screen. Pure-fn.
pub fn dry_run_install_commands(
    chain: &FallbackChain,
    package: &str,
) -> Vec<(PkgManagerKind, Vec<String>)> {
    chain
        .handles
        .iter()
        .map(|h| (h.kind(), h.install_argv(package)))
        .collect()
}

/// Build the W-08 `InstallerRanPayload` from a chain result.
/// Used by the WAL emit-site so `0x12 INSTALLER_RAN` carries
/// the right `pkg_mgr` + `dry_run` + `wizard_step` + `cli_name`
/// fields.
pub fn build_installer_ran_payload(
    cli_name: impl Into<String>,
    version: impl Into<String>,
    login_state: impl Into<String>,
    ts_unix: u64,
    wizard_step: impl Into<String>,
    chain_result: &ChainResult,
) -> InstallerRanPayload {
    let pkg_mgr = chain_result
        .winning_kind
        .map(|k| k.as_str().to_string())
        .unwrap_or_else(|| PkgManagerKind::Manual.as_str().to_string());
    let dry_run = matches!(chain_result.outcome, InstallOutcome::DryRun);
    InstallerRanPayload {
        cli_name: cli_name.into(),
        version: version.into(),
        login_state: login_state.into(),
        ts_unix,
        dry_run,
        wizard_step: wizard_step.into(),
        pkg_mgr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn kind_as_str_pinned() {
        assert_eq!(PkgManagerKind::Winget.as_str(), "winget");
        assert_eq!(PkgManagerKind::Choco.as_str(), "choco");
        assert_eq!(PkgManagerKind::Apt.as_str(), "apt");
        assert_eq!(PkgManagerKind::Dnf.as_str(), "dnf");
        assert_eq!(PkgManagerKind::Pacman.as_str(), "pacman");
        assert_eq!(PkgManagerKind::Brew.as_str(), "brew");
        assert_eq!(PkgManagerKind::Manual.as_str(), "manual");
    }

    #[test]
    fn outcome_snake_case_tag_pinned() {
        assert_eq!(InstallOutcome::Success.snake_case_tag(), "success");
        assert_eq!(InstallOutcome::DryRun.snake_case_tag(), "dry_run");
        assert_eq!(
            InstallOutcome::NonZeroExit {
                code: 1,
                stderr_tail: "x".into()
            }
            .snake_case_tag(),
            "non_zero_exit",
        );
        assert_eq!(
            InstallOutcome::SpawnFailed { reason: "x".into() }.snake_case_tag(),
            "spawn_failed",
        );
    }

    #[test]
    fn outcome_is_success_correct() {
        assert!(InstallOutcome::Success.is_success());
        assert!(InstallOutcome::DryRun.is_success());
        assert!(
            !InstallOutcome::NonZeroExit {
                code: 1,
                stderr_tail: "x".into()
            }
            .is_success()
        );
        assert!(!InstallOutcome::SpawnFailed { reason: "x".into() }.is_success());
    }

    #[test]
    fn kind_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&PkgManagerKind::Apt).unwrap(),
            "\"apt\"",
        );
    }

    // ── per-handle argv ───────────────────────────────────────────

    #[test]
    fn winget_install_argv_uses_silent_and_id() {
        let argv = WingetHandle.install_argv("Ollama.Ollama");
        assert_eq!(
            argv,
            vec!["winget", "install", "--silent", "--id", "Ollama.Ollama"]
        );
    }

    #[test]
    fn winget_upgrade_argv() {
        let argv = WingetHandle.upgrade_argv("Ollama.Ollama");
        assert!(argv.contains(&"upgrade".to_string()));
        assert!(argv.contains(&"Ollama.Ollama".to_string()));
    }

    #[test]
    fn choco_install_and_upgrade_use_y_flag() {
        let install = ChocoHandle.install_argv("ffmpeg");
        let upgrade = ChocoHandle.upgrade_argv("ffmpeg");
        assert!(install.contains(&"-y".to_string()));
        assert!(upgrade.contains(&"-y".to_string()));
    }

    #[test]
    fn apt_argv_uses_sudo_and_y() {
        let install = AptHandle.install_argv("ffmpeg");
        assert_eq!(install[0], "sudo");
        assert_eq!(install[1], "apt");
        assert!(install.contains(&"-y".to_string()));
    }

    #[test]
    fn apt_upgrade_uses_only_upgrade_flag() {
        let upgrade = AptHandle.upgrade_argv("ffmpeg");
        assert!(upgrade.contains(&"--only-upgrade".to_string()));
    }

    #[test]
    fn dnf_argv_uses_sudo_and_y() {
        assert_eq!(
            DnfHandle.install_argv("ffmpeg"),
            vec!["sudo", "dnf", "install", "-y", "ffmpeg"]
        );
        assert_eq!(
            DnfHandle.upgrade_argv("ffmpeg"),
            vec!["sudo", "dnf", "upgrade", "-y", "ffmpeg"]
        );
    }

    #[test]
    fn pacman_argv_uses_noconfirm() {
        let install = PacmanHandle.install_argv("ffmpeg");
        assert!(install.contains(&"--noconfirm".to_string()));
        assert!(install.contains(&"-S".to_string()));
        let upgrade = PacmanHandle.upgrade_argv("ffmpeg");
        assert!(upgrade.contains(&"-Syu".to_string()));
    }

    #[test]
    fn brew_argv_shape() {
        assert_eq!(
            BrewHandle.install_argv("ffmpeg"),
            vec!["brew", "install", "ffmpeg"]
        );
        assert_eq!(
            BrewHandle.upgrade_argv("ffmpeg"),
            vec!["brew", "upgrade", "ffmpeg"]
        );
    }

    // ── dry-run paths ─────────────────────────────────────────────

    #[tokio::test]
    async fn each_handle_dry_run_returns_dry_run() {
        for h in chain_handles_for_test() {
            let outcome = h.install("anything", true).await;
            assert_eq!(outcome, InstallOutcome::DryRun);
            let outcome = h.upgrade("anything", true).await;
            assert_eq!(outcome, InstallOutcome::DryRun);
        }
    }

    fn chain_handles_for_test() -> Vec<Box<dyn PkgManagerHandle>> {
        vec![
            Box::new(WingetHandle),
            Box::new(ChocoHandle),
            Box::new(AptHandle),
            Box::new(DnfHandle),
            Box::new(PacmanHandle),
            Box::new(BrewHandle),
        ]
    }

    // ── for_host ──────────────────────────────────────────────────

    #[test]
    fn for_host_chain_matches_target_os() {
        let chain = FallbackChain::for_host();
        let kinds = chain.kinds();
        #[cfg(target_os = "windows")]
        assert_eq!(kinds, vec![PkgManagerKind::Winget, PkgManagerKind::Choco]);
        #[cfg(target_os = "macos")]
        assert_eq!(kinds, vec![PkgManagerKind::Brew]);
        #[cfg(target_os = "linux")]
        assert_eq!(
            kinds,
            vec![
                PkgManagerKind::Apt,
                PkgManagerKind::Dnf,
                PkgManagerKind::Pacman
            ],
        );
    }

    #[test]
    fn for_host_chain_non_empty_on_supported_oses() {
        let chain = FallbackChain::for_host();
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        assert!(!chain.is_empty());
    }

    // ── fallback chain dry-run E2E ────────────────────────────────

    #[tokio::test]
    async fn chain_install_dry_run_short_circuits_on_first_handle() {
        let chain = FallbackChain::new(vec![Box::new(WingetHandle), Box::new(ChocoHandle)]);
        let result = chain.install("Test.Package", true).await;
        assert!(result.is_success());
        assert_eq!(result.winning_kind, Some(PkgManagerKind::Winget));
        // Only one handle was tried — first dry-run hit.
        assert_eq!(result.tried.len(), 1);
        assert_eq!(result.tried[0].0, PkgManagerKind::Winget);
        assert_eq!(result.tried[0].1, InstallOutcome::DryRun);
    }

    #[tokio::test]
    async fn chain_install_real_run_falls_through_when_first_handle_spawn_fails() {
        // Construct a chain that's guaranteed to spawn-fail (binary
        // not on PATH for any of these on most hosts), followed by
        // a dry-run handle that succeeds. The chain returns the
        // dry-run as the winner.
        // For the spawn-fail handle, we use a synthetic one that
        // returns SpawnFailed unconditionally.
        struct AlwaysSpawnFail;
        #[async_trait]
        impl PkgManagerHandle for AlwaysSpawnFail {
            fn kind(&self) -> PkgManagerKind {
                PkgManagerKind::Manual
            }
            fn install_argv(&self, _package: &str) -> Vec<String> {
                Vec::new()
            }
            fn upgrade_argv(&self, _package: &str) -> Vec<String> {
                Vec::new()
            }
            async fn install(&self, _: &str, _: bool) -> InstallOutcome {
                InstallOutcome::SpawnFailed {
                    reason: "synthetic".into(),
                }
            }
            async fn upgrade(&self, _: &str, _: bool) -> InstallOutcome {
                InstallOutcome::SpawnFailed {
                    reason: "synthetic".into(),
                }
            }
        }
        let chain = FallbackChain::new(vec![Box::new(AlwaysSpawnFail), Box::new(WingetHandle)]);
        // Use dry_run=true so the second handle (Winget) returns
        // DryRun, which is_success() recognises.
        let result = chain.install("anything", true).await;
        assert!(result.is_success());
        assert_eq!(result.winning_kind, Some(PkgManagerKind::Winget));
        assert_eq!(result.tried.len(), 2);
        assert_eq!(result.tried[0].0, PkgManagerKind::Manual);
        assert_eq!(result.tried[1].0, PkgManagerKind::Winget);
    }

    #[tokio::test]
    async fn chain_install_all_fail_returns_failure() {
        struct AlwaysSpawnFail;
        #[async_trait]
        impl PkgManagerHandle for AlwaysSpawnFail {
            fn kind(&self) -> PkgManagerKind {
                PkgManagerKind::Manual
            }
            fn install_argv(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn upgrade_argv(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            async fn install(&self, _: &str, _: bool) -> InstallOutcome {
                InstallOutcome::SpawnFailed {
                    reason: "synthetic".into(),
                }
            }
            async fn upgrade(&self, _: &str, _: bool) -> InstallOutcome {
                InstallOutcome::SpawnFailed {
                    reason: "synthetic".into(),
                }
            }
        }
        let chain = FallbackChain::new(vec![Box::new(AlwaysSpawnFail), Box::new(AlwaysSpawnFail)]);
        let result = chain.install("anything", false).await;
        assert!(!result.is_success());
        assert_eq!(result.winning_kind, None);
        assert_eq!(result.tried.len(), 2);
    }

    // ── dry_run_install_commands renderer ─────────────────────────

    #[test]
    fn dry_run_renders_all_handles_in_chain_order() {
        let chain = FallbackChain::new(vec![Box::new(AptHandle), Box::new(DnfHandle)]);
        let rendered = dry_run_install_commands(&chain, "ffmpeg");
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0].0, PkgManagerKind::Apt);
        assert!(rendered[0].1.contains(&"apt".to_string()));
        assert_eq!(rendered[1].0, PkgManagerKind::Dnf);
        assert!(rendered[1].1.contains(&"dnf".to_string()));
    }

    // ── build_installer_ran_payload ───────────────────────────────

    #[test]
    fn payload_winning_kind_lands_in_pkg_mgr_field() {
        let chain_result = ChainResult {
            winning_kind: Some(PkgManagerKind::Brew),
            tried: vec![(PkgManagerKind::Brew, InstallOutcome::Success)],
            outcome: InstallOutcome::Success,
        };
        let payload = build_installer_ran_payload(
            "ffmpeg",
            "6.1.1",
            "n/a",
            1_700_000_000,
            "step5_cli_picker",
            &chain_result,
        );
        assert_eq!(payload.pkg_mgr, "brew");
        assert_eq!(payload.cli_name, "ffmpeg");
        assert_eq!(payload.wizard_step, "step5_cli_picker");
        assert!(!payload.dry_run);
    }

    #[test]
    fn payload_dry_run_set_when_chain_outcome_is_dry_run() {
        let chain_result = ChainResult {
            winning_kind: Some(PkgManagerKind::Winget),
            tried: vec![(PkgManagerKind::Winget, InstallOutcome::DryRun)],
            outcome: InstallOutcome::DryRun,
        };
        let payload = build_installer_ran_payload(
            "tailscale",
            "1.60.0",
            "logged_in",
            1_700_000_000,
            "step5_vpn",
            &chain_result,
        );
        assert!(payload.dry_run);
        assert_eq!(payload.pkg_mgr, "winget");
    }

    #[test]
    fn payload_no_winning_handle_falls_back_to_manual_pkg_mgr() {
        let chain_result = ChainResult {
            winning_kind: None,
            tried: vec![(
                PkgManagerKind::Winget,
                InstallOutcome::SpawnFailed {
                    reason: "not on PATH".into(),
                },
            )],
            outcome: InstallOutcome::SpawnFailed {
                reason: "not on PATH".into(),
            },
        };
        let payload = build_installer_ran_payload(
            "obsidian",
            "1.5.0",
            "n/a",
            1_700_000_000,
            "step5_vault",
            &chain_result,
        );
        assert_eq!(payload.pkg_mgr, "manual");
        assert!(!payload.dry_run);
    }
}
