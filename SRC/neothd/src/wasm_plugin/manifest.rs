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

/// Maximum allowed `ui_surface.title` length in bytes (UTF-8). Keeps the
/// GUI tab label sane and prevents the plugin directory (attacker-controlled)
/// from injecting arbitrarily long strings into the GUI.
pub const MAX_UI_SURFACE_TITLE_LEN: usize = 80;

/// DES-12 — the GUI surface a plugin may declare. Only `WalFeed` is accepted;
/// any other `kind` fails TOML parse via the `#[serde(tag = "kind")]`
/// exhaustive enum (no unknown-variant passthrough), which is the safe
/// default: a plugin cannot gain a new surface type by naming an unknown kind.
///
/// # Security posture
/// - `kind = "wal_feed"` is read-only: the GUI only polls existing WAL frames
///   written by the daemon's own hostcall path. The plugin cannot push
///   arbitrary HTML, execute commands, or read files via this surface.
/// - `title` is bounded at [`MAX_UI_SURFACE_TITLE_LEN`] bytes and must be
///   valid UTF-8 (TOML guarantees this). The GUI is responsible for HTML-
///   escaping the title for display; this layer caps the length only.
/// - Old manifests that omit `[ui_surface]` parse fine as `None` via the
///   `#[serde(default)]` on [`PluginManifest::ui_surface`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PluginUiSurface {
    /// Render a live feed of the plugin's WAL events (0xC4 frames) in a
    /// GUI tab. `title` is the tab label shown to the operator.
    WalFeed { title: String },
}

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
/// so manifests written against the old short form still parse. This is
/// advisory/display metadata only — see the GOLD-COR-27 note below on why a
/// plugin's declared stages are NOT auto-registered into the daemon dispatcher.
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

// GOLD-COR-27 / GR-035 — the `to_hook_stage()` manifest→dispatcher bridge was
// REMOVED as dead code. It had zero non-test callers: a plugin's declared
// `hook_stages` is NOT auto-registered into the daemon's hook dispatcher.
//
// That is a DELIBERATE security posture, not an oversight. Auto-wiring a loaded
// plugin's WASM `invoke` as a `PreProviderCall` / `PreEgress` hook would let any
// installed plugin intercept (and block) every provider call + outbound message
// from a manifest declaration alone. Plugin participation in a hook stage is
// instead wired EXPLICITLY by the operator via a `HookDef` TOML action
// (serve.rs hook setup) — the same operator-controlled gate every other hook
// goes through. `hook_stages` stays as advisory/display metadata (surfaced by
// `neoth plugins`) so the operator sees which stages a plugin is designed for
// before wiring it. If manifest→HookDef auto-registration is ever built, it
// needs its own consent model — re-introduce the enum bridge WITH that consumer.

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
    /// DES-12 — optional GUI surface declaration. When `Some`, the GUI
    /// renders an extra tab for this plugin. Old manifests that omit this
    /// key parse as `None` (backward-compatible). Only `WalFeed` is
    /// accepted — a manifest with any other `kind` fails to parse, which
    /// is the safe default (no unknown surface types silently accepted).
    #[serde(default)]
    pub ui_surface: Option<PluginUiSurface>,
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
    #[error(
        "ui_surface.title length {got} bytes exceeds MAX_UI_SURFACE_TITLE_LEN \
         ({MAX_UI_SURFACE_TITLE_LEN})"
    )]
    UiSurfaceTitleTooLong { got: usize },
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
    // DES-12: cap ui_surface title so an attacker-controlled manifest
    // directory cannot inject an arbitrarily long string into the GUI.
    if let Some(PluginUiSurface::WalFeed { title }) = &m.ui_surface {
        if title.len() > MAX_UI_SURFACE_TITLE_LEN {
            return Err(ManifestError::UiSurfaceTitleTooLong { got: title.len() });
        }
    }
    Ok(())
}

/// Canonical plugin-id shape check: non-empty, `[a-z0-9_]` only, not starting
/// with `_` or a digit. This is the single source of truth for what a valid
/// installed plugin directory name looks like — reused by `neoth plugin
/// remove` to reject path-traversal ids (`../`, absolute paths, separators)
/// before they reach a filesystem join.
pub(crate) fn is_snake_case_id(s: &str) -> bool {
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
            ui_surface: None,
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

    // GOLD-COR-27 / GR-035 — the to_hook_stage bridge + its test were removed
    // (dead code; plugin hook_stages are advisory metadata, not auto-registered).

    // ── DES-12: PluginUiSurface ──────────────────────────────────────────────

    #[test]
    fn ui_surface_wal_feed_parses_and_round_trips() {
        // A manifest with [ui_surface] kind = "wal_feed" must parse and
        // validate cleanly; the title must survive a TOML round-trip.
        let toml = br#"
            id = "live_feed"
            name = "Live Feed"
            version = "0.1.0"
            [ui_surface]
            kind = "wal_feed"
            title = "My Plugin Events"
        "#;
        let m = parse_manifest(toml).expect("wal_feed ui_surface must parse");
        assert!(
            matches!(&m.ui_surface, Some(PluginUiSurface::WalFeed { title }) if title == "My Plugin Events")
        );
        // Validate must accept it.
        validate_manifest(&m).expect("valid wal_feed ui_surface");
    }

    #[test]
    fn ui_surface_unknown_kind_rejected_by_parse() {
        // A manifest with an unknown kind (e.g. "exec") must fail to parse
        // because the serde tag enum is exhaustive — no unknown variant
        // passthrough. This is the primary security gate for DES-12.
        let toml = br#"
            id = "bad_plugin"
            name = "Bad"
            version = "0.1.0"
            [ui_surface]
            kind = "exec"
            title = "Should not load"
        "#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(
            matches!(err, ManifestError::Parse(_)),
            "unknown ui_surface kind must fail as a parse error, got: {err:?}"
        );
    }

    #[test]
    fn ui_surface_overlong_title_rejected_by_validate() {
        // A title longer than MAX_UI_SURFACE_TITLE_LEN bytes is rejected
        // by validate_manifest to prevent large strings entering the GUI.
        let mut m = good_manifest();
        m.ui_surface = Some(PluginUiSurface::WalFeed {
            title: "x".repeat(MAX_UI_SURFACE_TITLE_LEN + 1),
        });
        let err = validate_manifest(&m).unwrap_err();
        assert!(
            matches!(err, ManifestError::UiSurfaceTitleTooLong { .. }),
            "overlong title must be rejected, got: {err:?}"
        );
    }

    #[test]
    fn ui_surface_none_for_old_manifests() {
        // Old manifests without [ui_surface] must parse as None — backward
        // compatible.
        let toml = br#"
            id = "indexer_v1"
            name = "Indexer"
            version = "0.1.0"
        "#;
        let m = parse_manifest(toml).expect("old manifest must parse");
        assert!(m.ui_surface.is_none(), "no ui_surface key => None");
    }
}
