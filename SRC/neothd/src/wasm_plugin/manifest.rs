//! `plugin.toml` manifest — V10-04 plugin authoring contract.
//!
//! Every operator-loadable WASM plugin ships as a directory under
//! `~/.neoth/plugins/<id>/` with:
//!
//! ```text
//! ~/.neoth/plugins/<id>/
//!   plugin.toml      — this manifest
//!   plugin.wasm      — compiled module (loaded by wasm_plugin::engine)
//!   README.md        — operator-facing description (optional)
//! ```
//!
//! The manifest carries the metadata NEOTH needs BEFORE compiling the
//! `.wasm`:
//!
//!   - **`id`** — globally unique snake_case identifier. Used as the
//!     directory name + the WAL `plugin_id` field.
//!   - **`name`** — display name for `neoth plugins list`.
//!   - **`version`** — semver, validated at load time.
//!   - **`requested_permissions`** — the highest [`PermissionLevel`] the
//!     plugin claims to need. NEOTH issues a token at most this level
//!     after the operator's `FreedomGrant` lands; the plugin cannot
//!     forge a higher one.
//!   - **`hook_stages`** — which pipeline stages the plugin wants to
//!     observe. Loaded by the hook dispatcher; unknown stages reject
//!     the manifest with an actionable error.
//!   - **`fuel_budget_override`** — optional per-call fuel override.
//!     Capped at 10× the default — a misconfigured plugin can't claim
//!     unlimited compute.
//!   - **`memory_limit_bytes`** — optional per-instance memory cap.
//!     Capped at 256 MiB.
//!
//! Compiled regardless of the `wasm-plugin-host` feature so non-wasm
//! builds can still parse a manifest for diagnostic surfaces (`neoth
//! doctor --explain plugin-<id>`).

use serde::{Deserialize, Serialize};

/// Maximum allowed `fuel_budget_override` — 10M fuel ≈ 500M wasm ops
/// ≈ 5-20s of pure CPU. Above this the plugin should be redesigned to
/// batch its work, not granted more fuel.
pub const MAX_FUEL_BUDGET: u64 = 10_000_000;

/// Maximum allowed `memory_limit_bytes` — 256 MiB. Hard cap so a
/// manifest can't claim a gigabyte and DoS the daemon.
pub const MAX_MEMORY_LIMIT_BYTES: usize = 256 * 1024 * 1024;

/// Permission level a plugin requested at load time.
/// Mirrors `neoth_plugin_sdk::permission::PermissionLevel` variants
/// but lives here as a serde-friendly enum so the manifest parses
/// cleanly without depending on the SDK's sealed-trait machinery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedPermission {
    #[default]
    None,
    ReadOnly,
    Write,
    Execute,
    Dangerous,
}

impl RequestedPermission {
    /// Operator-readable label for the consent prompt + audit log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadOnly => "read_only",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Dangerous => "dangerous",
        }
    }
}

/// Pipeline stage a hook plugin declares it observes (the `hook_stages`
/// vocabulary in `plugin.toml`).
///
/// COR-27 (PAT-002): the stages that overlap with the daemon's
/// [`crate::hooks::stages::HookStage`] MUST use the same serde wire form, or a
/// plugin declaring a stage can never be matched to the dispatcher stage it
/// means. The provider stages previously serialized as `pre_provider` /
/// `post_provider` here but `pre_provider_call` / `post_provider_call` in the
/// dispatcher — a silent divergence. They are now `PreProviderCall` /
/// `PostProviderCall` (the canonical wire form), each with a `#[serde(alias)]`
/// so manifests written against the old short form still parse. Use
/// [`HookStage::to_hook_stage`] to bridge to the dispatcher enum; stages with
/// no dispatcher counterpart map to `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HookStage {
    /// Before the provider request — dispatcher `PreProviderCall`. Old
    /// manifests that wrote `pre_provider` still parse via the alias.
    #[serde(alias = "pre_provider")]
    PreProviderCall,
    /// After the provider reply — dispatcher `PostProviderCall`. Old
    /// manifests that wrote `post_provider` still parse via the alias.
    #[serde(alias = "post_provider")]
    PostProviderCall,
    /// Before the reply is sent to the channel — dispatcher `PreEgress`.
    PreChannelSend,
    /// After a channel message is received. No dispatcher counterpart yet.
    PostChannelReceive,
    /// A recall query ran. No dispatcher counterpart (internal pass).
    OnRecallQuery,
    /// A memory consolidation pass ran. No dispatcher counterpart.
    OnConsolidationPass,
}

impl HookStage {
    /// Bridge a plugin-declared stage to the daemon dispatcher's
    /// [`crate::hooks::stages::HookStage`]. Returns `None` for stages with no
    /// dispatcher counterpart (`PostChannelReceive`, `OnRecallQuery`,
    /// `OnConsolidationPass`) so a caller skips them rather than mis-firing.
    ///
    /// COR-27: this is the conversion the eventual manifest→`HookDef` dispatch
    /// wiring uses to register a plugin's hooks at the correct stage; before
    /// the wire forms were unified there was no way to map between the enums.
    /// The match is exhaustive (the enum is only `#[non_exhaustive]` to
    /// downstream crates) so a new variant forces an explicit decision here.
    pub fn to_hook_stage(self) -> Option<crate::hooks::stages::HookStage> {
        use crate::hooks::stages::HookStage as H;
        match self {
            Self::PreProviderCall => Some(H::PreProviderCall),
            Self::PostProviderCall => Some(H::PostProviderCall),
            Self::PreChannelSend => Some(H::PreEgress),
            Self::PostChannelReceive | Self::OnRecallQuery | Self::OnConsolidationPass => None,
        }
    }
}

/// Parsed `plugin.toml`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub requested_permissions: RequestedPermission,
    #[serde(default)]
    pub hook_stages: Vec<HookStage>,
    #[serde(default)]
    pub fuel_budget_override: Option<u64>,
    #[serde(default)]
    pub memory_limit_bytes: Option<usize>,
    /// U-02b parity (Session 27): upstream source URI the updater
    /// probes for the latest published version. Same scheme as the
    /// sibling `SkillManifest::source` — `git+https://github.com/
    /// <owner>/<repo>` is the only form supported today; the resolver
    /// shells out to `git ls-remote --tags <url>` and picks the
    /// highest-sorting semver tag. `None` opts the plugin out of
    /// auto-update probes (operator manually pulls + replaces).
    #[serde(default)]
    pub source: Option<String>,
}

/// Errors that block a manifest from loading. Operator sees these in
/// `neoth plugins list` + the WAL `PLUGIN_REJECTED` (0xC3) frame.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum ManifestError {
    #[error("plugin id must be snake_case, got: {got:?}")]
    InvalidId { got: String },
    #[error("plugin version must be semver-shaped, got: {got:?}")]
    InvalidVersion { got: String },
    #[error("fuel_budget_override {got} exceeds MAX_FUEL_BUDGET ({MAX_FUEL_BUDGET})")]
    FuelBudgetTooHigh { got: u64 },
    #[error("memory_limit_bytes {got} exceeds MAX_MEMORY_LIMIT_BYTES ({MAX_MEMORY_LIMIT_BYTES})")]
    MemoryLimitTooHigh { got: usize },
    #[error("TOML parse error: {0}")]
    Parse(String),
}

/// Parse `plugin.toml` bytes into a validated `PluginManifest`.
/// Validates id-shape + version-shape + budget caps; rejects anything
/// that would let a plugin escape its sandbox bounds at load time
/// instead of at run time.
pub fn parse_manifest(toml_bytes: &[u8]) -> Result<PluginManifest, ManifestError> {
    let raw = std::str::from_utf8(toml_bytes)
        .map_err(|e| ManifestError::Parse(format!("non-utf8 plugin.toml: {e}")))?;
    let manifest: PluginManifest =
        toml::from_str(raw).map_err(|e| ManifestError::Parse(e.to_string()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Post-parse validation. Pulled out so callers that construct a
/// manifest programmatically (tests, future GUI editor) can validate
/// without going through TOML.
pub fn validate_manifest(m: &PluginManifest) -> Result<(), ManifestError> {
    if !is_snake_case_id(&m.id) {
        return Err(ManifestError::InvalidId { got: m.id.clone() });
    }
    if !is_semver_shape(&m.version) {
        return Err(ManifestError::InvalidVersion {
            got: m.version.clone(),
        });
    }
    if let Some(fuel) = m.fuel_budget_override {
        if fuel > MAX_FUEL_BUDGET {
            return Err(ManifestError::FuelBudgetTooHigh { got: fuel });
        }
    }
    if let Some(mem) = m.memory_limit_bytes {
        if mem > MAX_MEMORY_LIMIT_BYTES {
            return Err(ManifestError::MemoryLimitTooHigh { got: mem });
        }
    }
    Ok(())
}

fn is_snake_case_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

fn is_semver_shape(s: &str) -> bool {
    // Light shape check — not a full semver parser. Three dot-separated
    // numeric components, optional `-pre` suffix. Catches typos
    // ("0.1" / "0.1.0.0" / "vee 0.1.0") without dragging in the `semver`
    // crate just for load-time validation.
    let main = s.split('-').next().unwrap_or(s);
    let parts: Vec<&str> = main.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_manifest() -> PluginManifest {
        PluginManifest {
            id: "indexer_v1".into(),
            name: "Indexer".into(),
            version: "0.1.0".into(),
            description: None,
            requested_permissions: RequestedPermission::ReadOnly,
            hook_stages: vec![HookStage::OnRecallQuery],
            fuel_budget_override: None,
            memory_limit_bytes: None,
            source: None,
        }
    }

    #[test]
    fn parse_minimal_manifest_succeeds() {
        let toml = br#"
            id = "indexer_v1"
            name = "Indexer"
            version = "0.1.0"
        "#;
        let m = parse_manifest(toml).expect("minimal manifest must parse");
        assert_eq!(m.id, "indexer_v1");
        assert_eq!(m.requested_permissions, RequestedPermission::None);
        assert!(m.hook_stages.is_empty());
    }

    #[test]
    fn parse_full_manifest_with_stages_and_caps() {
        let toml = br#"
            id = "recall_rerank"
            name = "Recall Re-ranker"
            version = "0.2.1"
            description = "Re-ranks recall hits by recency"
            requested_permissions = "write"
            hook_stages = ["on_recall_query", "on_consolidation_pass"]
            fuel_budget_override = 2000000
            memory_limit_bytes = 33554432
        "#;
        let m = parse_manifest(toml).expect("full manifest must parse");
        assert_eq!(m.requested_permissions, RequestedPermission::Write);
        assert_eq!(m.hook_stages.len(), 2);
        assert_eq!(m.fuel_budget_override, Some(2_000_000));
    }

    #[test]
    fn invalid_id_rejected() {
        let mut m = good_manifest();
        m.id = "Indexer-V1".into();
        let err = validate_manifest(&m).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidId { .. }));
    }

    #[test]
    fn id_starting_with_digit_rejected() {
        let mut m = good_manifest();
        m.id = "1plugin".into();
        assert!(matches!(
            validate_manifest(&m).unwrap_err(),
            ManifestError::InvalidId { .. }
        ));
    }

    #[test]
    fn invalid_version_rejected() {
        let mut m = good_manifest();
        m.version = "0.1".into();
        let err = validate_manifest(&m).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidVersion { .. }));
    }

    #[test]
    fn semver_with_pre_release_accepted() {
        let mut m = good_manifest();
        m.version = "1.0.0-alpha".into();
        assert!(validate_manifest(&m).is_ok());
    }

    #[test]
    fn fuel_budget_above_cap_rejected() {
        let mut m = good_manifest();
        m.fuel_budget_override = Some(MAX_FUEL_BUDGET + 1);
        assert!(matches!(
            validate_manifest(&m).unwrap_err(),
            ManifestError::FuelBudgetTooHigh { .. }
        ));
    }

    #[test]
    fn memory_limit_above_cap_rejected() {
        let mut m = good_manifest();
        m.memory_limit_bytes = Some(MAX_MEMORY_LIMIT_BYTES + 1);
        assert!(matches!(
            validate_manifest(&m).unwrap_err(),
            ManifestError::MemoryLimitTooHigh { .. }
        ));
    }

    #[test]
    fn requested_permission_serialises_snake_case() {
        let m = PluginManifest {
            requested_permissions: RequestedPermission::Execute,
            ..good_manifest()
        };
        let toml_str = toml::to_string(&m).unwrap();
        assert!(
            toml_str.contains("requested_permissions = \"execute\""),
            "toml must serialise as snake_case: {toml_str}"
        );
    }

    #[test]
    fn requested_permission_default_is_none() {
        let r: RequestedPermission = Default::default();
        assert_eq!(r, RequestedPermission::None);
    }

    #[test]
    fn hook_stage_serialises_snake_case() {
        let m = PluginManifest {
            hook_stages: vec![HookStage::PreChannelSend, HookStage::OnConsolidationPass],
            ..good_manifest()
        };
        let toml_str = toml::to_string(&m).unwrap();
        assert!(toml_str.contains("pre_channel_send"));
        assert!(toml_str.contains("on_consolidation_pass"));
    }

    #[test]
    fn manifest_caps_are_pinned() {
        // Pin the literals so a future "let's bump it" lands as a
        // deliberate decision, not a silent ratchet.
        assert_eq!(MAX_FUEL_BUDGET, 10_000_000);
        assert_eq!(MAX_MEMORY_LIMIT_BYTES, 256 * 1024 * 1024);
    }

    #[test]
    fn non_utf8_bytes_rejected() {
        let bytes = b"\xff\xfe not utf8";
        let err = parse_manifest(bytes).unwrap_err();
        assert!(matches!(err, ManifestError::Parse(_)));
    }

    #[test]
    fn pre_provider_alias_parses_to_canonical_and_serialises_canonical() {
        // COR-27: a manifest written against the OLD short wire form still
        // parses (serde alias), and serialises back as the canonical form that
        // matches the dispatcher's wire form.
        let toml = br#"
            id = "auditor"
            name = "Auditor"
            version = "0.1.0"
            hook_stages = ["pre_provider", "post_provider"]
        "#;
        let m = parse_manifest(toml).expect("alias manifest must parse");
        assert_eq!(
            m.hook_stages,
            vec![HookStage::PreProviderCall, HookStage::PostProviderCall]
        );
        let serialized = toml::to_string(&m).unwrap();
        assert!(
            serialized.contains("pre_provider_call"),
            "must serialise canonical: {serialized}"
        );
        assert!(serialized.contains("post_provider_call"));
        // The old short form must not be the OUTPUT wire form anymore.
        assert!(!serialized.contains("\"pre_provider\""));
    }

    #[test]
    fn to_hook_stage_bridges_overlapping_stages_to_the_dispatcher() {
        use crate::hooks::stages::HookStage as H;
        // The provider stages a plugin declares now resolve to the dispatcher
        // stage they mean — impossible while the wire forms diverged (PAT-002).
        assert_eq!(
            HookStage::PreProviderCall.to_hook_stage(),
            Some(H::PreProviderCall)
        );
        assert_eq!(
            HookStage::PostProviderCall.to_hook_stage(),
            Some(H::PostProviderCall)
        );
        assert_eq!(HookStage::PreChannelSend.to_hook_stage(), Some(H::PreEgress));
        // Manifest-only vocabulary with no dispatcher counterpart → None.
        assert_eq!(HookStage::PostChannelReceive.to_hook_stage(), None);
        assert_eq!(HookStage::OnRecallQuery.to_hook_stage(), None);
        assert_eq!(HookStage::OnConsolidationPass.to_hook_stage(), None);
    }
}
