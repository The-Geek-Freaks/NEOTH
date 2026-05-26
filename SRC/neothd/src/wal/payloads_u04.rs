//! U-04 — typed payloads for the `0x44 UPDATER_TASK_FIRED` +
//! `0x45 UPDATER_TASK_RESULT` WAL frames + the readable
//! `neoth updater status` aggregator.
//!
//! Same shape discipline as W-08: typed structs that serialise
//! to a stable JSON wire-form so audit consumers grep on pinned
//! field names. The cron tick emit-site builds one
//! [`UpdaterTaskFiredPayload`] + one [`UpdaterTaskResultPayload`]
//! per pass.

use serde::{Deserialize, Serialize};

/// Which updater task fired. Pinned exhaustively — adding a new
/// task class needs a payload-schema-version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdaterTaskKind {
    /// U-01: `neothd` binary self-update check.
    NeothSelf,
    /// U-02: skills + plugins re-resolve.
    SkillPlugin,
    /// U-03: detected CLI environment (claude / codex / gemini)
    /// version check.
    CliVersions,
}

impl UpdaterTaskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeothSelf => "neoth_self",
            Self::SkillPlugin => "skill_plugin",
            Self::CliVersions => "cli_versions",
        }
    }
}

/// Outcome per component in a U-01/U-02/U-03 pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// Component is already at the latest version. No action taken.
    UpToDate,
    /// Component was upgraded. `new_version` populated.
    Upgraded,
    /// Component check or upgrade failed. Recorded for the
    /// operator audit — failures don't halt other components.
    Failed,
    /// Operator policy gated the upgrade (e.g.
    /// `freedom.yaml::updater.allow_huggingface_downloads=false`
    /// blocking a model bump). Surfaced separately from `Failed`
    /// so the operator can audit "we did the right thing" without
    /// noise.
    SkippedByGate,
}

impl ComponentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::Upgraded => "upgraded",
            Self::Failed => "failed",
            Self::SkippedByGate => "skipped_by_gate",
        }
    }
}

/// One component's per-pass outcome. `prior_version` always
/// populated (the check ran); `new_version` populated only when
/// `status == Upgraded`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentOutcome {
    pub name: String,
    pub prior_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,
    pub status: ComponentStatus,
    /// Optional human-readable note. For `Failed`, contains the
    /// stderr tail; for `SkippedByGate`, the policy reason; for
    /// `UpToDate` / `Upgraded`, empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl ComponentOutcome {
    pub fn up_to_date(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            prior_version: version.into(),
            new_version: None,
            status: ComponentStatus::UpToDate,
            note: String::new(),
        }
    }

    pub fn upgraded(
        name: impl Into<String>,
        prior: impl Into<String>,
        new: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prior_version: prior.into(),
            new_version: Some(new.into()),
            status: ComponentStatus::Upgraded,
            note: String::new(),
        }
    }

    pub fn failed(
        name: impl Into<String>,
        prior: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prior_version: prior.into(),
            new_version: None,
            status: ComponentStatus::Failed,
            note: note.into(),
        }
    }

    pub fn skipped_by_gate(
        name: impl Into<String>,
        prior: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prior_version: prior.into(),
            new_version: None,
            status: ComponentStatus::SkippedByGate,
            note: reason.into(),
        }
    }
}

/// `0x44 UPDATER_TASK_FIRED` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterTaskFiredPayload {
    pub task_kind: UpdaterTaskKind,
    pub ts_unix: u64,
}

/// `0x45 UPDATER_TASK_RESULT` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterTaskResultPayload {
    pub task_kind: UpdaterTaskKind,
    pub ts_unix: u64,
    pub duration_ms: u32,
    pub components: Vec<ComponentOutcome>,
}

impl UpdaterTaskResultPayload {
    pub fn upgraded_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::Upgraded)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::Failed)
            .count()
    }

    pub fn up_to_date_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::UpToDate)
            .count()
    }

    pub fn skipped_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::SkippedByGate)
            .count()
    }

    /// True when no upgrade succeeded AND nothing failed — pure
    /// "all current" pass. The operator-facing CLI uses this to
    /// decide between the green "everything current" line vs the
    /// detailed table.
    pub fn is_uneventful(&self) -> bool {
        self.upgraded_count() == 0 && self.failed_count() == 0 && self.skipped_count() == 0
    }
}

/// Operator-facing status renderer for `neoth updater status`.
/// Pure-fn over a slice of recent UpdaterTaskResultPayload (the
/// CLI side reads the WAL + filters by event_type then feeds the
/// payloads in). Returns a plain-text table the CLI prints
/// verbatim.
pub fn render_updater_status(results: &[UpdaterTaskResultPayload]) -> String {
    if results.is_empty() {
        return "neoth updater status — no updater pass on record yet.\n\
                Run `neoth updater check` to bootstrap.\n"
            .to_string();
    }
    let mut out = String::new();
    out.push_str("neoth updater status\n");
    out.push_str("====================\n");
    for r in results {
        out.push_str(&format!(
            "\n[{}] ts={} duration={}ms\n",
            r.task_kind.as_str(),
            r.ts_unix,
            r.duration_ms,
        ));
        if r.is_uneventful() {
            out.push_str(&format!(
                "  all {} components up to date\n",
                r.up_to_date_count()
            ));
            continue;
        }
        for c in &r.components {
            let symbol = match c.status {
                ComponentStatus::UpToDate => "·",
                ComponentStatus::Upgraded => "↑",
                ComponentStatus::Failed => "✗",
                ComponentStatus::SkippedByGate => "⊘",
            };
            match &c.new_version {
                Some(new) => out.push_str(&format!(
                    "  {symbol} {name} {prior} → {new} [{status}]\n",
                    name = c.name,
                    prior = c.prior_version,
                    status = c.status.as_str(),
                )),
                None => out.push_str(&format!(
                    "  {symbol} {name} {prior} [{status}]\n",
                    name = c.name,
                    prior = c.prior_version,
                    status = c.status.as_str(),
                )),
            }
            if !c.note.is_empty() {
                out.push_str(&format!("      note: {}\n", c.note));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_with_components(
        kind: UpdaterTaskKind,
        ts: u64,
        components: Vec<ComponentOutcome>,
    ) -> UpdaterTaskResultPayload {
        UpdaterTaskResultPayload {
            task_kind: kind,
            ts_unix: ts,
            duration_ms: 1234,
            components,
        }
    }

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn task_kind_as_str_pinned() {
        assert_eq!(UpdaterTaskKind::NeothSelf.as_str(), "neoth_self");
        assert_eq!(UpdaterTaskKind::SkillPlugin.as_str(), "skill_plugin");
        assert_eq!(UpdaterTaskKind::CliVersions.as_str(), "cli_versions");
    }

    #[test]
    fn task_kind_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&UpdaterTaskKind::NeothSelf).unwrap(),
            "\"neoth_self\"",
        );
    }

    #[test]
    fn component_status_as_str_pinned() {
        assert_eq!(ComponentStatus::UpToDate.as_str(), "up_to_date");
        assert_eq!(ComponentStatus::Upgraded.as_str(), "upgraded");
        assert_eq!(ComponentStatus::Failed.as_str(), "failed");
        assert_eq!(ComponentStatus::SkippedByGate.as_str(), "skipped_by_gate");
    }

    #[test]
    fn component_status_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&ComponentStatus::SkippedByGate).unwrap(),
            "\"skipped_by_gate\"",
        );
    }

    // ── ComponentOutcome constructors ─────────────────────────────

    #[test]
    fn up_to_date_constructor_no_new_version_no_note() {
        let c = ComponentOutcome::up_to_date("claude-cli", "1.2.3");
        assert_eq!(c.status, ComponentStatus::UpToDate);
        assert!(c.new_version.is_none());
        assert!(c.note.is_empty());
    }

    #[test]
    fn upgraded_constructor_has_new_version() {
        let c = ComponentOutcome::upgraded("claude-cli", "1.2.3", "1.3.0");
        assert_eq!(c.status, ComponentStatus::Upgraded);
        assert_eq!(c.new_version.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn failed_constructor_captures_note() {
        let c = ComponentOutcome::failed("claude-cli", "1.2.3", "npm registry 503");
        assert_eq!(c.status, ComponentStatus::Failed);
        assert!(c.new_version.is_none());
        assert_eq!(c.note, "npm registry 503");
    }

    #[test]
    fn skipped_by_gate_constructor_captures_reason() {
        let c = ComponentOutcome::skipped_by_gate(
            "qwen-7b",
            "1.0",
            "freedom.yaml::updater.allow_huggingface_downloads=false",
        );
        assert_eq!(c.status, ComponentStatus::SkippedByGate);
        assert!(c.note.contains("allow_huggingface"));
    }

    // ── counters ──────────────────────────────────────────────────

    #[test]
    fn result_counters_partition_components() {
        let r = result_with_components(
            UpdaterTaskKind::CliVersions,
            100,
            vec![
                ComponentOutcome::up_to_date("a", "1.0"),
                ComponentOutcome::up_to_date("b", "2.0"),
                ComponentOutcome::upgraded("c", "1.0", "1.1"),
                ComponentOutcome::failed("d", "0.5", "network down"),
                ComponentOutcome::skipped_by_gate("e", "1.0", "policy"),
            ],
        );
        assert_eq!(r.up_to_date_count(), 2);
        assert_eq!(r.upgraded_count(), 1);
        assert_eq!(r.failed_count(), 1);
        assert_eq!(r.skipped_count(), 1);
        assert!(!r.is_uneventful());
    }

    #[test]
    fn result_uneventful_when_all_up_to_date() {
        let r = result_with_components(
            UpdaterTaskKind::NeothSelf,
            100,
            vec![
                ComponentOutcome::up_to_date("a", "1.0"),
                ComponentOutcome::up_to_date("b", "1.0"),
            ],
        );
        assert!(r.is_uneventful());
    }

    #[test]
    fn result_uneventful_when_empty() {
        let r = result_with_components(UpdaterTaskKind::NeothSelf, 100, Vec::new());
        assert!(r.is_uneventful());
    }

    // ── render_updater_status ─────────────────────────────────────

    #[test]
    fn render_empty_results_shows_friendly_bootstrap_message() {
        let s = render_updater_status(&[]);
        assert!(s.contains("no updater pass"));
        assert!(s.contains("neoth updater check"));
    }

    #[test]
    fn render_uneventful_shows_short_summary() {
        let r = result_with_components(
            UpdaterTaskKind::NeothSelf,
            100,
            vec![
                ComponentOutcome::up_to_date("neothd", "0.3.0"),
                ComponentOutcome::up_to_date("neoth-plugin-sdk", "0.3.0"),
            ],
        );
        let s = render_updater_status(&[r]);
        assert!(s.contains("[neoth_self]"));
        assert!(s.contains("all 2 components up to date"));
    }

    #[test]
    fn render_detailed_table_when_eventful() {
        let r = result_with_components(
            UpdaterTaskKind::CliVersions,
            100,
            vec![
                ComponentOutcome::up_to_date("claude-cli", "1.2.3"),
                ComponentOutcome::upgraded("codex", "0.4.0", "0.5.0"),
                ComponentOutcome::failed("gemini-cli", "0.1.0", "npm 503"),
            ],
        );
        let s = render_updater_status(&[r]);
        assert!(s.contains("[cli_versions]"));
        // up-to-date line.
        assert!(s.contains("· claude-cli 1.2.3"));
        // upgraded line with arrow.
        assert!(s.contains("↑ codex 0.4.0 → 0.5.0"));
        // failed line with note.
        assert!(s.contains("✗ gemini-cli 0.1.0"));
        assert!(s.contains("note: npm 503"));
    }

    #[test]
    fn render_multiple_results_separates_by_header() {
        let a = result_with_components(
            UpdaterTaskKind::NeothSelf,
            100,
            vec![ComponentOutcome::up_to_date("neothd", "0.3.0")],
        );
        let b = result_with_components(
            UpdaterTaskKind::CliVersions,
            200,
            vec![ComponentOutcome::upgraded("claude-cli", "1.2.3", "1.3.0")],
        );
        let s = render_updater_status(&[a, b]);
        assert!(s.contains("[neoth_self] ts=100"));
        assert!(s.contains("[cli_versions] ts=200"));
        assert!(s.contains("↑ claude-cli 1.2.3 → 1.3.0"));
    }

    // ── serde wire form ───────────────────────────────────────────

    #[test]
    fn fired_payload_serialises_snake_case_audit_keys() {
        let p = UpdaterTaskFiredPayload {
            task_kind: UpdaterTaskKind::CliVersions,
            ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"task_kind\":\"cli_versions\""));
        assert!(json.contains("\"ts_unix\":1700000000"));
    }

    #[test]
    fn result_payload_serialises_audit_keys() {
        let r = UpdaterTaskResultPayload {
            task_kind: UpdaterTaskKind::SkillPlugin,
            ts_unix: 100,
            duration_ms: 250,
            components: vec![ComponentOutcome::upgraded("skill_a", "1.0", "1.1")],
        };
        let json = serde_json::to_string(&r).unwrap();
        for k in [
            "task_kind",
            "ts_unix",
            "duration_ms",
            "components",
            "name",
            "prior_version",
            "new_version",
            "status",
        ] {
            assert!(json.contains(&format!("\"{k}\"")), "missing key {k}");
        }
        assert!(json.contains("\"task_kind\":\"skill_plugin\""));
        assert!(json.contains("\"status\":\"upgraded\""));
    }

    #[test]
    fn result_payload_omits_empty_new_version_and_note() {
        let r = UpdaterTaskResultPayload {
            task_kind: UpdaterTaskKind::NeothSelf,
            ts_unix: 0,
            duration_ms: 0,
            components: vec![ComponentOutcome::up_to_date("a", "1.0")],
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"new_version\""));
        assert!(!json.contains("\"note\""));
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = result_with_components(
            UpdaterTaskKind::CliVersions,
            42,
            vec![
                ComponentOutcome::up_to_date("a", "1.0"),
                ComponentOutcome::upgraded("b", "1.0", "1.1"),
                ComponentOutcome::failed("c", "1.0", "boom"),
            ],
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: UpdaterTaskResultPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
