//! U-01 + U-03 probe builders — bridges the existing
//! `self_update::check_for_update` (GitHub Releases) +
//! `check_all` (npm CLI versions) probes into the
//! `ComponentSpec` shape the U-04 cron loop consumes.
//!
//! The cron loop's builder signature is sync `Fn() -> Vec<ComponentSpec>`
//! because it runs on `tokio::task::spawn_blocking`. Each probe
//! here exposes both async + sync wrappers:
//!
//!   - `*_specs_async()` for callers in async contexts (tests,
//!     ad-hoc CLI subcommands).
//!   - `*_specs_blocking()` for the cron-builder closure — uses
//!     `tokio::runtime::Handle::current().block_on()` to drive
//!     the async probe from the blocking thread.
//!
//! Failure modes are encoded in the `ComponentSpec.latest_version
//! : Result<String, String>` field: a network error becomes
//! `Err("github probe: <msg>")` which `compute_outcome` turns
//! into `ComponentStatus::Failed`. The cron loop still emits the
//! audit frame so operators see "yes, the cron ran; yes, it
//! tried; here's why it didn't have a latest_version answer".

use crate::updater::pipeline::{ComponentSpec, GateDecision, cli_version_specs, neoth_self_specs};
use crate::updater::self_update::{check_for_update, current_version};

/// Canonical owner/repo for the `neothd` binary lookup.
pub const NEOTH_OWNER_REPO: &str = "The-Geek-Freaks/NEOTH";

// ── U-01 neoth_self ──────────────────────────────────────────────────────────

/// Probe `neothd` self-version. Returns a single-component spec
/// list ready for `run_updater_pass(UpdaterTaskKind::NeothSelf, …)`.
pub async fn neoth_self_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    let current = current_version().to_string();
    let latest = match check_for_update(NEOTH_OWNER_REPO).await {
        Ok(c) => Ok(c.latest),
        Err(e) => Err(format!("github probe: {e}")),
    };
    neoth_self_specs(current, latest, gate)
}

/// Sync wrapper for the U-04 cron-builder closure. Calls
/// `block_on` on the current tokio runtime — safe because the
/// closure runs on `spawn_blocking` (no nested-runtime issue).
pub fn neoth_self_specs_blocking(gate: GateDecision) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(neoth_self_specs_async(gate)),
        Err(_) => Vec::new(),
    }
}

// ── U-03 cli_version ─────────────────────────────────────────────────────────

/// Probe every CLI we manage (`claude-cli`, `gemini-cli`, `codex`)
/// and project into a spec list for
/// `run_updater_pass(UpdaterTaskKind::CliVersion, …)`. CLIs that
/// aren't installed produce no spec entry (matches
/// `pipeline::cli_version_specs`'s `Option`-skip contract).
pub async fn cli_version_specs_async(gate: GateDecision) -> Vec<ComponentSpec> {
    use crate::updater::Component;
    let statuses = crate::updater::check_all().await;
    let mut by_kind: std::collections::HashMap<Component, &crate::updater::UpdateStatus> =
        std::collections::HashMap::new();
    for s in &statuses {
        by_kind.insert(s.component, s);
    }
    let to_pair = |c: Component| -> Option<(String, Result<String, String>)> {
        let s = by_kind.get(&c)?;
        let installed = s.installed.clone()?;
        let latest = s
            .latest
            .clone()
            .map(Ok)
            .unwrap_or_else(|| Err(format!("npm view {} version: failed", c.npm_package())));
        Some((installed, latest))
    };
    cli_version_specs(
        to_pair(Component::ClaudeCli),
        to_pair(Component::Codex),
        to_pair(Component::GeminiCli),
        &gate,
    )
}

/// Sync wrapper for the U-04 cron-builder closure.
pub fn cli_version_specs_blocking(gate: GateDecision) -> Vec<ComponentSpec> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(cli_version_specs_async(gate)),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::pipeline::GateDecision;

    #[tokio::test]
    async fn neoth_self_probe_returns_single_spec_with_current_version() {
        // Network call goes out; the assertion only pins the
        // spec shape, not the upstream response. A network
        // failure surfaces as `latest_version: Err(...)` —
        // still a valid single-spec list.
        let specs = neoth_self_specs_async(GateDecision::Allow).await;
        assert_eq!(specs.len(), 1, "neoth_self probe yields exactly one spec");
        assert_eq!(specs[0].name, "neothd");
        assert_eq!(specs[0].current_version, current_version());
    }

    #[test]
    fn neoth_self_blocking_outside_runtime_returns_empty() {
        // No tokio runtime in this test → Handle::try_current()
        // fails → empty vec (no panic).
        let specs = neoth_self_specs_blocking(GateDecision::Allow);
        assert!(specs.is_empty());
    }

    #[tokio::test]
    async fn cli_version_probe_yields_spec_only_for_installed_clis() {
        // CI runners don't have claude/codex/gemini installed by
        // default, so the expected result is an empty vec. When
        // operator has them installed, each installed CLI
        // produces exactly one spec.
        let specs = cli_version_specs_async(GateDecision::Allow).await;
        for s in &specs {
            assert!(
                matches!(s.name.as_str(), "claude-cli" | "codex" | "gemini-cli",),
                "unexpected component name in cli_version probe: {}",
                s.name,
            );
        }
    }

    #[test]
    fn cli_version_blocking_outside_runtime_returns_empty() {
        let specs = cli_version_specs_blocking(GateDecision::Allow);
        assert!(specs.is_empty());
    }
}
