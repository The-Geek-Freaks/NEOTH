//! U-01 + U-02 + U-03 — updater pipeline implementations.
//!
//! Each updater builds an [`UpdaterTaskResultPayload`] from a
//! list of [`ComponentOutcome`]s. The cron consumer emits the
//! payload as a `0x45 UPDATER_TASK_RESULT` WAL frame; the
//! `neoth updater status` CLI renders it via U-04's
//! `render_updater_status`.
//!
//! ## Why one pipeline module
//!
//! All three updaters share the same shape: "for each component,
//! probe current version → query upstream → decide upgrade vs
//! skip → emit ComponentOutcome." The only thing that varies is
//! WHICH components + WHICH probe/install mechanism. Separating
//! them into three impls would duplicate the orchestration loop;
//! one module + three configurations keeps the shape obvious.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::wal::payloads_u04::{
    ComponentOutcome, UpdaterPassIdentity, UpdaterTaskKind, UpdaterTaskResultPayload,
};

/// One component spec — name + current version + how to discover
/// the latest version. Pure-data so tests construct directly.
pub struct ComponentSpec {
    pub name: String,
    pub current_version: String,
    pub latest_version: Result<String, String>,
    pub gate_decision: GateDecision,
}

/// Gate decision the updater consults before each component
/// upgrade. Mirrors operator's `freedom.yaml::updater.*` flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// Operator has opted-in to upgrade this component.
    Allow,
    /// Operator's `freedom.yaml` flag blocks the upgrade; we still
    /// run the check + emit `SkippedByGate` with the reason.
    Deny { reason: String },
}

/// Run one updater pass — synchronous over a pre-built component
/// list. Network probes happen upstream (caller has already
/// resolved `latest_version` for each component).
pub fn run_updater_pass(
    task_kind: UpdaterTaskKind,
    components: Vec<ComponentSpec>,
) -> UpdaterTaskResultPayload {
    let started = Instant::now();
    let ts_unix = crate::time::now_unix_secs();

    let outcomes: Vec<ComponentOutcome> = components
        .into_iter()
        .map(|c| compute_outcome(&c))
        .collect();

    UpdaterTaskResultPayload {
        // The pure pipeline does not own the durable FIRED append. Its daemon
        // caller replaces this legacy marker with the pass identity created
        // before FIRED is written.
        identity: UpdaterPassIdentity::legacy(),
        task_kind,
        ts_unix,
        duration_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        components: outcomes,
    }
}

/// Pure-fn outcome computation from one ComponentSpec.
pub fn compute_outcome(spec: &ComponentSpec) -> ComponentOutcome {
    // Gate decision short-circuits BEFORE the version check —
    // operator's policy "no upgrades right now" is a stronger
    // signal than "you're already current".
    if let GateDecision::Deny { reason } = &spec.gate_decision {
        return ComponentOutcome::skipped_by_gate(
            spec.name.clone(),
            spec.current_version.clone(),
            reason.clone(),
        );
    }

    match &spec.latest_version {
        Err(e) => {
            ComponentOutcome::failed(spec.name.clone(), spec.current_version.clone(), e.clone())
        }
        Ok(latest) if *latest == spec.current_version => {
            ComponentOutcome::up_to_date(spec.name.clone(), spec.current_version.clone())
        }
        Ok(latest) => ComponentOutcome::upgraded(
            spec.name.clone(),
            spec.current_version.clone(),
            latest.clone(),
        ),
    }
}

/// U-01: build the spec list for the public `neoth` binary self-update
/// pass. Today's single-component pass — future extensions add
/// `neoth-plugin-sdk`, `neothd-gui`.
pub fn neoth_self_specs(
    current_version: impl Into<String>,
    latest_version: Result<String, String>,
    gate: GateDecision,
) -> Vec<ComponentSpec> {
    vec![ComponentSpec {
        name: "neoth".to_string(),
        current_version: current_version.into(),
        latest_version,
        gate_decision: gate,
    }]
}

/// U-02: build the spec list for the skills + plugins re-resolve
/// pass. Caller iterates the operator's installed skills /
/// plugins + supplies (name, current, latest, gate) per item.
pub fn skill_plugin_specs(
    installed: Vec<(String, String, Result<String, String>, GateDecision)>,
) -> Vec<ComponentSpec> {
    installed
        .into_iter()
        .map(|(name, current, latest, gate)| ComponentSpec {
            name,
            current_version: current,
            latest_version: latest,
            gate_decision: gate,
        })
        .collect()
}

/// U-03: build the spec list for the detected-CLI version pass.
/// Pinned set: claude-cli, codex, antigravity-cli. Caller resolves
/// each component's current+latest via the per-CLI probe in
/// installer-specific post-update work. The third argument is
/// still named `antigravity` post-2026-05-19 transition (was `gemini`
/// when Google shipped gemini-cli via npm).
pub fn cli_version_specs(
    claude: Option<(String, Result<String, String>)>,
    codex: Option<(String, Result<String, String>)>,
    antigravity: Option<(String, Result<String, String>)>,
    gate: &GateDecision,
) -> Vec<ComponentSpec> {
    let mut out = Vec::new();
    for (name, pair) in [
        ("claude-cli", claude),
        ("codex", codex),
        ("antigravity-cli", antigravity),
    ] {
        if let Some((current, latest)) = pair {
            out.push(ComponentSpec {
                name: name.to_string(),
                current_version: current,
                latest_version: latest,
                gate_decision: gate.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::payloads_u04::ComponentStatus;

    fn spec(name: &str, current: &str, latest: Result<&str, &str>) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            current_version: current.to_string(),
            latest_version: latest.map(|s| s.to_string()).map_err(|s| s.to_string()),
            gate_decision: GateDecision::Allow,
        }
    }

    // ── compute_outcome ───────────────────────────────────────────

    #[test]
    fn outcome_up_to_date_when_versions_equal() {
        let s = spec("a", "1.0.0", Ok("1.0.0"));
        let o = compute_outcome(&s);
        assert_eq!(o.status, ComponentStatus::UpToDate);
        assert_eq!(o.prior_version, "1.0.0");
        assert!(o.new_version.is_none());
    }

    #[test]
    fn outcome_upgraded_when_latest_differs() {
        let s = spec("a", "1.0.0", Ok("1.1.0"));
        let o = compute_outcome(&s);
        assert_eq!(o.status, ComponentStatus::Upgraded);
        assert_eq!(o.prior_version, "1.0.0");
        assert_eq!(o.new_version.as_deref(), Some("1.1.0"));
    }

    #[test]
    fn outcome_failed_when_latest_lookup_errors() {
        let s = spec("a", "1.0.0", Err("npm registry 503"));
        let o = compute_outcome(&s);
        assert_eq!(o.status, ComponentStatus::Failed);
        assert!(o.new_version.is_none());
        assert_eq!(o.note, "npm registry 503");
    }

    #[test]
    fn outcome_skipped_when_gate_denies_even_when_upgrade_available() {
        let mut s = spec("a", "1.0.0", Ok("1.1.0"));
        s.gate_decision = GateDecision::Deny {
            reason: "freedom.yaml: updater.allow_huggingface_downloads=false".to_string(),
        };
        let o = compute_outcome(&s);
        assert_eq!(o.status, ComponentStatus::SkippedByGate);
        assert!(o.note.contains("allow_huggingface_downloads"));
        // Gate decision short-circuits BEFORE the version check —
        // operator sees "we did the right thing" even when upgrade
        // was available.
        assert!(o.new_version.is_none());
    }

    #[test]
    fn outcome_gate_denied_overrides_failed_lookup() {
        // Drift guard: when both gate denies AND lookup failed,
        // the gate decision wins (operator policy first).
        let mut s = spec("a", "1.0.0", Err("network down"));
        s.gate_decision = GateDecision::Deny {
            reason: "operator policy".to_string(),
        };
        let o = compute_outcome(&s);
        assert_eq!(o.status, ComponentStatus::SkippedByGate);
    }

    // ── run_updater_pass ──────────────────────────────────────────

    #[test]
    fn pass_with_empty_components_returns_empty_payload() {
        let r = run_updater_pass(UpdaterTaskKind::NeothSelf, Vec::new());
        assert_eq!(r.task_kind, UpdaterTaskKind::NeothSelf);
        assert!(r.components.is_empty());
        assert!(r.is_uneventful());
    }

    #[test]
    fn pass_aggregates_mixed_outcomes() {
        let components = vec![
            spec("a", "1.0", Ok("1.0")),   // up to date
            spec("b", "1.0", Ok("1.1")),   // upgraded
            spec("c", "1.0", Err("boom")), // failed
        ];
        let r = run_updater_pass(UpdaterTaskKind::CliVersions, components);
        assert_eq!(r.up_to_date_count(), 1);
        assert_eq!(r.upgraded_count(), 1);
        assert_eq!(r.failed_count(), 1);
        assert_eq!(r.task_kind, UpdaterTaskKind::CliVersions);
        // ts_unix populated (best-effort SystemTime; just assert
        // non-zero on hosts with a clock).
        assert!(r.ts_unix > 0);
    }

    #[test]
    fn pass_duration_ms_recorded() {
        let r = run_updater_pass(
            UpdaterTaskKind::NeothSelf,
            vec![spec("a", "1.0", Ok("1.0"))],
        );
        // No assertion on the actual value — just confirm the
        // field exists + parses as u32.
        let _: u32 = r.duration_ms;
    }

    // ── builders ──────────────────────────────────────────────────

    #[test]
    fn neoth_self_specs_emits_neoth_component() {
        let specs = neoth_self_specs("0.3.0", Ok("0.3.1".to_string()), GateDecision::Allow);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "neoth");
        assert_eq!(specs[0].current_version, "0.3.0");
    }

    #[test]
    fn skill_plugin_specs_aggregates_installed_list() {
        let installed = vec![
            (
                "skill_a".to_string(),
                "1.0".to_string(),
                Ok("1.1".to_string()),
                GateDecision::Allow,
            ),
            (
                "plugin_b".to_string(),
                "0.5".to_string(),
                Err("network".to_string()),
                GateDecision::Allow,
            ),
        ];
        let specs = skill_plugin_specs(installed);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "skill_a");
        assert_eq!(specs[1].name, "plugin_b");
    }

    #[test]
    fn cli_version_specs_skips_absent_clis() {
        let specs = cli_version_specs(
            Some(("1.2.3".to_string(), Ok("1.3.0".to_string()))),
            None, // codex absent
            Some(("0.1.0".to_string(), Err("npm 503".to_string()))),
            &GateDecision::Allow,
        );
        assert_eq!(specs.len(), 2);
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"claude-cli"));
        assert!(names.contains(&"antigravity-cli"));
        assert!(!names.contains(&"codex"));
    }

    #[test]
    fn cli_version_specs_applies_gate_to_all_clis_uniformly() {
        let gate = GateDecision::Deny {
            reason: "global skip".into(),
        };
        let specs = cli_version_specs(
            Some(("1".into(), Ok("2".into()))),
            Some(("1".into(), Ok("2".into()))),
            Some(("1".into(), Ok("2".into()))),
            &gate,
        );
        for s in &specs {
            assert!(matches!(s.gate_decision, GateDecision::Deny { .. }));
        }
    }

    // ── E2E: U-01 + U-02 + U-03 round-trip ────────────────────────

    #[test]
    fn u01_full_self_update_pass_produces_clean_payload() {
        // Operator runs `neoth updater check` for U-01 — neoth is
        // current.
        let specs = neoth_self_specs("0.3.0", Ok("0.3.0".to_string()), GateDecision::Allow);
        let r = run_updater_pass(UpdaterTaskKind::NeothSelf, specs);
        assert!(r.is_uneventful());
        assert_eq!(r.up_to_date_count(), 1);
    }

    #[test]
    fn u02_skill_plugin_pass_reports_upgrade_when_one_skill_lags() {
        let installed = vec![
            (
                "verification".into(),
                "1.0".into(),
                Ok("1.1".into()),
                GateDecision::Allow,
            ),
            (
                "council_dispatch".into(),
                "0.5".into(),
                Ok("0.5".into()),
                GateDecision::Allow,
            ),
        ];
        let specs = skill_plugin_specs(installed);
        let r = run_updater_pass(UpdaterTaskKind::SkillPlugin, specs);
        assert_eq!(r.upgraded_count(), 1);
        assert_eq!(r.up_to_date_count(), 1);
    }

    #[test]
    fn u03_cli_pass_partition_per_status() {
        let specs = cli_version_specs(
            Some(("1.2.3".into(), Ok("1.2.3".into()))), // up to date
            Some(("0.4.0".into(), Ok("0.5.0".into()))), // upgraded
            Some(("0.1.0".into(), Err("npm 503".into()))), // failed
            &GateDecision::Allow,
        );
        let r = run_updater_pass(UpdaterTaskKind::CliVersions, specs);
        assert_eq!(r.up_to_date_count(), 1);
        assert_eq!(r.upgraded_count(), 1);
        assert_eq!(r.failed_count(), 1);
    }
}
