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

/// Current wire schema for recurring updater pass correlation.
///
/// Schema v1 is the historical payload without a pass identity. Serde defaults
/// missing identity fields to that legacy shape so old WAL segments remain
/// readable, but consumers must not guess a FIRED/RESULT pairing for them.
pub const UPDATER_PASS_SCHEMA_VERSION: u16 = 2;

const fn legacy_schema_version() -> u16 {
    1
}

/// Concrete recurring lane that owns a pass. This is more precise than
/// [`UpdaterTaskKind`]: probe/apply and probe/stage lanes intentionally share
/// the historical task kind, but must never share an audit identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdaterPassLane {
    NeothSelfProbe,
    CliVersionProbe,
    SkillPluginProbe,
    CliAutoApply,
    SelfStage,
}

impl UpdaterPassLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeothSelfProbe => "neoth_self_probe",
            Self::CliVersionProbe => "cli_version_probe",
            Self::SkillPluginProbe => "skill_plugin_probe",
            Self::CliAutoApply => "cli_auto_apply",
            Self::SelfStage => "self_stage",
        }
    }

    pub fn task_kind(self) -> UpdaterTaskKind {
        match self {
            Self::NeothSelfProbe | Self::SelfStage => UpdaterTaskKind::NeothSelf,
            Self::CliVersionProbe | Self::CliAutoApply => UpdaterTaskKind::CliVersions,
            Self::SkillPluginProbe => UpdaterTaskKind::SkillPlugin,
        }
    }
}

/// Shared FIRED/RESULT correlation fields.
///
/// The struct is flattened into both payloads so the stable wire keys remain
/// top-level. A legacy payload deserializes as schema v1 with no identity and
/// is therefore explicitly uncorrelatable rather than heuristically paired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterPassIdentity {
    #[serde(default = "legacy_schema_version")]
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<UpdaterPassLane>,
}

impl UpdaterPassIdentity {
    /// Construct a new schema-v2 identity before FIRED is appended. The exact
    /// same value must then be copied into its terminal RESULT.
    pub fn new(lane: UpdaterPassLane, accepted_epoch: u64) -> Self {
        Self {
            schema_version: UPDATER_PASS_SCHEMA_VERSION,
            pass_id: Some(uuid::Uuid::now_v7().to_string()),
            accepted_epoch: Some(accepted_epoch),
            lane: Some(lane),
        }
    }

    /// Historical/synthetic result with no durable FIRED correlation.
    pub const fn legacy() -> Self {
        Self {
            schema_version: 1,
            pass_id: None,
            accepted_epoch: None,
            lane: None,
        }
    }

    /// Return the stable pass id only when every schema-v2 correlation field is
    /// present and the id is a canonical UUID. Unknown future schemas are kept
    /// readable but deliberately treated as indeterminate.
    pub fn correlatable_pass_id(&self) -> Option<&str> {
        if self.schema_version != UPDATER_PASS_SCHEMA_VERSION
            || self.accepted_epoch.is_none()
            || self.lane.is_none()
        {
            return None;
        }
        let pass_id = self.pass_id.as_deref()?;
        let parsed = uuid::Uuid::parse_str(pass_id).ok()?;
        (parsed.to_string() == pass_id).then_some(pass_id)
    }

    pub fn correlatable_pass_id_for(&self, task_kind: UpdaterTaskKind) -> Option<&str> {
        let pass_id = self.correlatable_pass_id()?;
        (self.lane?.task_kind() == task_kind).then_some(pass_id)
    }
}

/// Which updater task fired. Pinned exhaustively — adding a new
/// task class needs a payload-schema-version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdaterTaskKind {
    /// U-01: `neothd` binary self-update check.
    NeothSelf,
    /// U-02: skills + plugins re-resolve.
    SkillPlugin,
    /// U-03: detected CLI environment (claude / codex / antigravity)
    /// version check. Historical frames may carry `gemini-cli` as a
    /// component name — Component's serde alias maps it to the new
    /// AntigravityCli variant.
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
    /// A probe found a newer release, but no mutation was attempted.
    /// `new_version` is the available release.
    UpdateAvailable,
    /// A verified update was downloaded and staged, but the installed
    /// component is still at `prior_version` until the operator applies it.
    /// `new_version` is the staged release.
    Staged,
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
            Self::UpdateAvailable => "update_available",
            Self::Staged => "staged",
            Self::Failed => "failed",
            Self::SkippedByGate => "skipped_by_gate",
        }
    }
}

/// One component's per-pass outcome. `prior_version` always
/// populated (the check ran); `new_version` populated only when
/// `status == Upgraded`, `status == UpdateAvailable`, or `status == Staged`.
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

    pub fn staged(
        name: impl Into<String>,
        prior: impl Into<String>,
        staged: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prior_version: prior.into(),
            new_version: Some(staged.into()),
            status: ComponentStatus::Staged,
            note: "verified artifact staged; operator apply is pending".to_string(),
        }
    }

    pub fn update_available(
        name: impl Into<String>,
        current: impl Into<String>,
        available: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prior_version: current.into(),
            new_version: Some(available.into()),
            status: ComponentStatus::UpdateAvailable,
            note: "newer release is available".to_string(),
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
    #[serde(flatten)]
    pub identity: UpdaterPassIdentity,
    pub task_kind: UpdaterTaskKind,
    pub ts_unix: u64,
}

/// `0x45 UPDATER_TASK_RESULT` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterTaskResultPayload {
    #[serde(flatten)]
    pub identity: UpdaterPassIdentity,
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

    pub fn staged_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::Staged)
            .count()
    }

    pub fn update_available_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == ComponentStatus::UpdateAvailable)
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
        self.upgraded_count() == 0
            && self.staged_count() == 0
            && self.update_available_count() == 0
            && self.failed_count() == 0
            && self.skipped_count() == 0
    }
}

/// Legacy result-only renderer retained for synthetic consumers and wire-form
/// regression tests. Production `neoth updater status` uses the FIRED/RESULT
/// state machine in `cli::updater`; result-only rendering cannot prove a pass
/// completed.
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
                ComponentStatus::UpdateAvailable => "!",
                ComponentStatus::Staged => "↓",
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
            identity: UpdaterPassIdentity::legacy(),
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
        assert_eq!(
            ComponentStatus::UpdateAvailable.as_str(),
            "update_available"
        );
        assert_eq!(ComponentStatus::Staged.as_str(), "staged");
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
    fn available_and_staged_constructors_do_not_claim_installation() {
        let available = ComponentOutcome::update_available("neoth", "1.0.0", "1.1.0");
        assert_eq!(available.status, ComponentStatus::UpdateAvailable);
        assert_eq!(available.new_version.as_deref(), Some("1.1.0"));
        let staged = ComponentOutcome::staged("neoth", "1.0.0", "1.1.0");
        assert_eq!(staged.status, ComponentStatus::Staged);
        assert_eq!(staged.new_version.as_deref(), Some("1.1.0"));
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
                ComponentOutcome::update_available("c2", "1.0", "1.2"),
                ComponentOutcome::staged("c3", "1.0", "1.2"),
                ComponentOutcome::failed("d", "0.5", "network down"),
                ComponentOutcome::skipped_by_gate("e", "1.0", "policy"),
            ],
        );
        assert_eq!(r.up_to_date_count(), 2);
        assert_eq!(r.upgraded_count(), 1);
        assert_eq!(r.update_available_count(), 1);
        assert_eq!(r.staged_count(), 1);
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
                ComponentOutcome::failed(
                    "antigravity-cli",
                    "0.1.0",
                    "shell-script update path not reachable",
                ),
            ],
        );
        let s = render_updater_status(&[r]);
        assert!(s.contains("[cli_versions]"));
        // up-to-date line.
        assert!(s.contains("· claude-cli 1.2.3"));
        // upgraded line with arrow.
        assert!(s.contains("↑ codex 0.4.0 → 0.5.0"));
        // failed line with note.
        assert!(s.contains("✗ antigravity-cli 0.1.0"));
        assert!(s.contains("note: shell-script update path not reachable"));
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
            identity: UpdaterPassIdentity::new(UpdaterPassLane::CliVersionProbe, 7),
            task_kind: UpdaterTaskKind::CliVersions,
            ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"task_kind\":\"cli_versions\""));
        assert!(json.contains("\"ts_unix\":1700000000"));
        assert!(json.contains("\"schema_version\":2"));
        assert!(json.contains("\"accepted_epoch\":7"));
        assert!(json.contains("\"lane\":\"cli_version_probe\""));
        assert!(json.contains("\"pass_id\":"));
    }

    #[test]
    fn result_payload_serialises_audit_keys() {
        let r = UpdaterTaskResultPayload {
            identity: UpdaterPassIdentity::new(UpdaterPassLane::SkillPluginProbe, 7),
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
            identity: UpdaterPassIdentity::legacy(),
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

    #[test]
    fn fired_and_result_share_the_exact_versioned_pass_identity() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 42);
        let fired = UpdaterTaskFiredPayload {
            identity: identity.clone(),
            task_kind: UpdaterTaskKind::NeothSelf,
            ts_unix: 100,
        };
        let result = UpdaterTaskResultPayload {
            identity: identity.clone(),
            task_kind: UpdaterTaskKind::NeothSelf,
            ts_unix: 101,
            duration_ms: 1,
            components: vec![],
        };
        let fired_json = serde_json::to_value(fired).unwrap();
        let result_json = serde_json::to_value(result).unwrap();
        for key in ["schema_version", "pass_id", "accepted_epoch", "lane"] {
            assert_eq!(fired_json[key], result_json[key], "mismatched key {key}");
        }
        assert!(identity.correlatable_pass_id().is_some());
    }

    #[test]
    fn legacy_payloads_decode_as_explicitly_uncorrelatable_schema_v1() {
        let fired: UpdaterTaskFiredPayload =
            serde_json::from_str(r#"{"task_kind":"cli_versions","ts_unix":1}"#).unwrap();
        let result: UpdaterTaskResultPayload = serde_json::from_str(
            r#"{"task_kind":"cli_versions","ts_unix":2,"duration_ms":3,"components":[]}"#,
        )
        .unwrap();
        assert_eq!(fired.identity, UpdaterPassIdentity::legacy());
        assert_eq!(result.identity, UpdaterPassIdentity::legacy());
        assert!(fired.identity.correlatable_pass_id().is_none());
        assert!(result.identity.correlatable_pass_id().is_none());
    }
}
