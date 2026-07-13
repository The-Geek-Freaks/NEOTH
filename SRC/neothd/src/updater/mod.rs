//! Auto-update for NEOTH-managed components.
//!
//! Per [[neoth-arch-extensions]] R-6: every CLI / binary / plugin NEOTH
//! installs must be auto-updatable. Operator never runs `npm update` or
//! chases version drift manually.
//!
//! V1 scope: npm-installed CLIs (claude-cli, gemini-cli, codex). Each has
//! - `installed_version()` → ask the binary itself (e.g. `claude --version`)
//! - `latest_version()` → query the npm registry via `npm view <pkg> version`
//! - `apply()` → `npm install -g <pkg>@latest`
//!
//! V2 (deferred): obsidian, hysteria, keet bridge, neothd self-update.
//! The trait + reporting machinery is laid out so a v2 implementor only adds
//! a new variant to `Component`.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// V03-09 daemon self-update check (2026-05-20). Lives next to the
// CLI auto-update logic — same `updater` module, separate file so
// the GitHub-Releases-API path doesn't entangle with the npm-aware
// installer path.
pub mod pipeline;
pub mod probes;
pub mod self_update;
/// MAR-02 — in-process minisign keypair generation + release signing (the
/// DAU-friendly `neoth release keygen`/`sign`; no external `minisign` binary).
pub mod sig_keygen;
pub mod sig_verify;
pub mod skill_resolver;

#[cfg_attr(not(test), allow(unused_imports))]
use crate::installers::{ALL as ALL_INSTALLERS, build_cmd};

/// What we update. One discriminant per managed component. Adding a non-npm
/// component (Obsidian, Hysteria, …) is "new variant + match arm in the four
/// functions below", nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    ClaudeCli,
    /// Antigravity CLI (`agy`) — replaces the retired gemini-cli per
    /// Google's 2026-05-19 transition. Serde alias `gemini_cli` keeps
    /// historical WAL frames + freedom.yaml snapshots that pre-date the
    /// migration readable; outbound serialization always emits
    /// `antigravity_cli`.
    #[serde(alias = "gemini_cli")]
    AntigravityCli,
    Codex,
}

impl Component {
    pub const ALL: &'static [Component] = &[
        Component::ClaudeCli,
        Component::AntigravityCli,
        Component::Codex,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Component::ClaudeCli => "claude_cli",
            Component::AntigravityCli => "antigravity_cli",
            Component::Codex => "codex",
        }
    }

    /// npm package name when the CLI ships via npm. `None` for CLIs
    /// distributed via vendor-hosted shell installers (today only
    /// Antigravity CLI — Google's Go binary that does not publish to
    /// npm at all).
    pub fn npm_package(self) -> Option<&'static str> {
        match self {
            Component::ClaudeCli => Some("@anthropic-ai/claude-code"),
            Component::AntigravityCli => None,
            Component::Codex => Some("@openai/codex"),
        }
    }

    pub fn binary(self) -> &'static str {
        match self {
            Component::ClaudeCli => "claude",
            Component::AntigravityCli => "agy",
            Component::Codex => "codex",
        }
    }
}

/// One row in an update report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub component: Component,
    pub installed: Option<String>,
    pub latest: Option<String>,
    pub update_available: bool,
    /// Empty before `apply`. After: "applied" / "noop" / one-line error string.
    pub applied: Option<String>,
}

/// Probe `<binary> --version` and return the first whitespace-delimited token
/// that contains at least one digit. None on missing binary or zero output.
async fn binary_version(binary: &str) -> Option<String> {
    let out = build_cmd(binary, &["--version"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;

    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace()
        .find(|tok| tok.chars().any(|c| c.is_ascii_digit()))
        .map(|tok| tok.trim_matches(|c: char| c == 'v' || c == 'V').to_string())
}

/// `npm view <package> version` to learn the latest published version.
/// 4s timeout so a flaky registry does not stall the wizard.
async fn npm_latest_version(npm_package: &str) -> Option<String> {
    let fut = build_cmd("npm", &["view", npm_package, "version"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();

    let out = tokio::time::timeout(Duration::from_secs(4), fut)
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Probe one component. Cheap: at most two short subprocesses.
pub async fn check_one(component: Component) -> UpdateStatus {
    let installed = binary_version(component.binary()).await;
    // Components without an npm channel (Antigravity ships via shell
    // script only) skip the registry probe — the operator's self-update
    // path is the vendor installer re-run, surfaced through the doctor
    // flow instead.
    let latest = match component.npm_package() {
        Some(pkg) => npm_latest_version(pkg).await,
        None => None,
    };

    let update_available = match (&installed, &latest) {
        (Some(i), Some(l)) => i != l,
        // If we don't have the binary at all, "not installed" is not "update
        // available" — operator should run the installer first, not the updater.
        // Same for shell-script-only CLIs where `latest` is intentionally None.
        _ => false,
    };

    UpdateStatus {
        component,
        installed,
        latest,
        update_available,
        applied: None,
    }
}

/// Probe all known components in parallel.
pub async fn check_all() -> Vec<UpdateStatus> {
    let futures = Component::ALL.iter().map(|c| check_one(*c));
    futures_util::future::join_all(futures).await
}

/// Run the component's auto-update path. For npm-distributed CLIs this
/// is `npm install -g <pkg>@latest`; for vendor-shell-script CLIs (today
/// only Antigravity) we re-run the matching upstream installer through
/// the [`installers`] dispatcher. Honours the same cmd-wrapper
/// indirection the `installers` module uses on Windows.
fn installer_kind(component: Component) -> crate::installers::CliKind {
    match component {
        Component::ClaudeCli => crate::installers::CLAUDE,
        Component::AntigravityCli => crate::installers::ANTIGRAVITY,
        Component::Codex => crate::installers::CODEX,
    }
}

fn install_plan(
    component: Component,
    security_policy: &crate::config::SecurityPolicy,
) -> (
    crate::installers::CliKind,
    crate::security::osv_check::SeverityLevel,
) {
    (
        installer_kind(component),
        security_policy.dep_vuln_threshold,
    )
}

pub async fn apply_one(
    component: Component,
    security_policy: &crate::config::SecurityPolicy,
) -> Result<()> {
    // Route every update through the canonical installer. This keeps npm and
    // vendor-script updates on the same supply-chain path and makes the
    // operator's live dependency-severity policy mandatory at the type level.
    let (kind, dep_vuln_threshold) = install_plan(component, security_policy);
    info!(
        component = component.name(),
        display = kind.display,
        "updating through policy-bound installer"
    );
    crate::installers::install_kind(kind, dep_vuln_threshold).await
}

/// Convenience: probe all + apply each component flagged `update_available`.
/// Returns the post-apply statuses so the CLI can render a result table.
pub async fn check_and_apply_all(
    security_policy: &crate::config::SecurityPolicy,
) -> Vec<UpdateStatus> {
    let mut report = check_all().await;
    for row in report.iter_mut() {
        if !row.update_available {
            row.applied = Some("noop".to_string());
            continue;
        }
        match apply_one(row.component, security_policy).await {
            Ok(()) => {
                row.applied = Some("applied".to_string());
                // Re-read installed version so the printed table reflects reality.
                if let Some(new) = binary_version(row.component.binary()).await {
                    row.installed = Some(new);
                }
                if let (Some(i), Some(l)) = (&row.installed, &row.latest) {
                    row.update_available = i != l;
                }
            }
            Err(e) => {
                warn!(component = row.component.name(), error = %e, "update failed");
                row.applied = Some(format!("error: {e}"));
            }
        }
    }
    report
}

/// Sanity check used by tests: every `installers::CliKind` has a matching
/// `Component`. If installers add a new CLI, this drives a fail-loud reminder
/// to wire it into the updater.
#[cfg(test)]
pub(crate) fn coverage_check() -> Result<()> {
    for kind in ALL_INSTALLERS {
        let mapped = Component::ALL.iter().any(|c| c.binary() == kind.binary);
        if !mapped {
            anyhow::bail!(
                "installer {} has no matching Component variant",
                kind.binary
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_table_has_three_entries() {
        assert_eq!(Component::ALL.len(), 3);
    }

    #[test]
    fn npm_package_is_scoped_or_none() {
        // npm-strategy CLIs must use a scoped package; shell-script
        // CLIs (Antigravity) opt out via `None` and verify their
        // install URLs separately in `installers::tests`.
        for c in Component::ALL {
            match c.npm_package() {
                Some(pkg) => assert!(
                    pkg.starts_with('@'),
                    "{c:?} npm_package must be scoped, got {pkg}"
                ),
                None => {
                    // The only shell-script CLI today is Antigravity.
                    // A future shell-script entry would land here too,
                    // adding another branch is intentional and tracked.
                    assert!(
                        matches!(c, Component::AntigravityCli),
                        "only AntigravityCli has no npm_package, got {c:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn binary_and_install_target_are_distinct_per_component() {
        let mut bins = std::collections::HashSet::new();
        let mut targets = std::collections::HashSet::new();
        for c in Component::ALL {
            assert!(bins.insert(c.binary()), "duplicate binary {}", c.binary());
            // For npm components compare the package; for shell-script
            // ones use the component name as a stand-in so the set has
            // distinct entries without claiming an npm slot.
            let key = c.npm_package().unwrap_or_else(|| c.name());
            assert!(targets.insert(key), "duplicate install target {key}");
        }
    }

    #[test]
    fn antigravity_replaces_gemini_cli_in_component_table() {
        // Drift-guard for the 2026-05-19 transition. If a refactor
        // brings back `gemini` as the binary or `@google/gemini-cli`
        // as the npm package, gemini-cli stops serving 2026-06-18 so
        // operators ship broken.
        let google = Component::ALL
            .iter()
            .copied()
            .find(|c| matches!(c, Component::AntigravityCli))
            .expect("AntigravityCli variant present");
        assert_eq!(google.binary(), "agy");
        assert_eq!(google.name(), "antigravity_cli");
        assert!(google.npm_package().is_none());
    }

    #[test]
    fn gemini_cli_serde_alias_still_loads_old_payloads() {
        // Old WAL frames + freedom.yaml snapshots stored
        // `"component":"gemini_cli"` before the rename. Verify the
        // alias keeps them readable. Outbound serialization always
        // emits the new name.
        let parsed: Component = serde_json::from_str("\"gemini_cli\"").unwrap();
        assert!(matches!(parsed, Component::AntigravityCli));
        let serialised = serde_json::to_string(&Component::AntigravityCli).unwrap();
        assert_eq!(serialised, "\"antigravity_cli\"");
    }

    #[test]
    fn updater_covers_every_installer() {
        coverage_check().unwrap();
    }

    #[test]
    fn updater_install_plan_preserves_operator_severity_policy() {
        let policy = crate::config::SecurityPolicy {
            dep_vuln_threshold: crate::security::osv_check::SeverityLevel::Critical,
            ..Default::default()
        };
        for component in Component::ALL {
            let (kind, threshold) = install_plan(*component, &policy);
            assert_eq!(kind.binary, component.binary());
            assert_eq!(
                threshold,
                crate::security::osv_check::SeverityLevel::Critical,
                "updater must not replace the operator policy with a hardcoded default"
            );
        }
    }

    #[tokio::test]
    async fn binary_version_returns_none_for_missing_binary() {
        assert!(
            binary_version("definitely-not-a-real-binary-xyz")
                .await
                .is_none()
        );
    }
}
