//! GU-03 — persona-adaptive settings-panel visibility (the rule engine).
//!
//! Pure Rust, ZERO Slint dependency, so the entire "which settings panels show
//! at which complexity level" rule set is unit-testable without a display —
//! matching the established test-seam pattern in `main.rs` (`shape_chat_output`,
//! `shape_usage_summary`, `validate_operator_id`, …). The `.slint` side binds
//! `in property <bool> show_*` to the fields of [`PanelVisibility`], which
//! `main.rs` populates from the operator's complexity level on startup.
//!
//! The complexity level is the SAME signal the wizard computes
//! (`neothd::wizard::recommend::operator_complexity_level` → W-03a). The type is
//! MIRRORED here (same `minimal`/`standard`/`full` wire form) rather than
//! depended-on, keeping the GUI crate decoupled from the daemon — the same
//! pattern as the `MinimalFreedomYaml` / `CodingSessionJson` mirrors in main.rs.

/// Mirror of `neothd::wizard::recommend::ComplexityLevel`.
/// Serde/string wire form: `"minimal"` | `"standard"` | `"full"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplexityLevel {
    /// Beginner — only the panels a first-run operator needs.
    Minimal,
    /// Intermediate — the common panels expanded; advanced present but collapsed.
    #[default]
    Standard,
    /// Advanced — everything visible + advanced sub-sections expanded.
    Full,
}

impl ComplexityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ComplexityLevel::Minimal => "minimal",
            ComplexityLevel::Standard => "standard",
            ComplexityLevel::Full => "full",
        }
    }
}

/// Which settings tabs are visible + which advanced sub-sections are expanded.
/// Every field is independently queryable so a test can pin one panel's
/// decision without coupling to the whole set. (`chat` is the always-present
/// main surface and is intentionally NOT gated.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelVisibility {
    pub show_hemispheres: bool,
    pub show_channels: bool,
    pub show_skills: bool,
    pub show_plugins: bool,
    pub show_memory: bool,
    pub show_privacy: bool,
    pub show_cluster: bool,
    pub show_config: bool,
    pub show_code_sessions: bool,
    /// Advanced sub-section expansion within a tab (the header shows, the inner
    /// detail is collapsed until the operator opens it / is at Full).
    pub expand_cluster_advanced: bool,
    pub expand_config_advanced: bool,
}

/// GU-03 entry point — the single source of truth for panel-collapse rules.
///
/// - **Minimal** (beginner): hide everything except the panels a first-run
///   operator genuinely needs — channels (to connect Telegram), privacy (the
///   autonomy level is beginner-critical), config (provider choice). No
///   clustering / plugins / skills / memory internals / code sessions.
/// - **Standard** (intermediate): all common panels visible; advanced tabs
///   (cluster, config) present but their advanced sub-sections collapsed; no
///   plugins (a power-user surface).
/// - **Full** (advanced): everything visible + advanced sub-sections expanded.
pub fn panels_for(level: ComplexityLevel) -> PanelVisibility {
    match level {
        ComplexityLevel::Minimal => PanelVisibility {
            show_hemispheres: false,
            show_channels: true,
            show_skills: false,
            show_plugins: false,
            show_memory: false,
            show_privacy: true,
            show_cluster: false,
            show_config: true,
            show_code_sessions: false,
            expand_cluster_advanced: false,
            expand_config_advanced: false,
        },
        ComplexityLevel::Standard => PanelVisibility {
            show_hemispheres: true,
            show_channels: true,
            show_skills: true,
            show_plugins: false,
            show_memory: true,
            show_privacy: true,
            show_cluster: true,
            show_config: true,
            show_code_sessions: true,
            expand_cluster_advanced: false,
            expand_config_advanced: false,
        },
        ComplexityLevel::Full => PanelVisibility {
            show_hemispheres: true,
            show_channels: true,
            show_skills: true,
            show_plugins: true,
            show_memory: true,
            show_privacy: true,
            show_cluster: true,
            show_config: true,
            show_code_sessions: true,
            expand_cluster_advanced: true,
            expand_config_advanced: true,
        },
    }
}

/// Parse the complexity string the wizard persists. Unknown / missing → the
/// safe non-overwhelming default (`Standard`).
pub fn parse_complexity_level(s: &str) -> ComplexityLevel {
    match s.trim().to_ascii_lowercase().as_str() {
        "minimal" => ComplexityLevel::Minimal,
        "full" => ComplexityLevel::Full,
        _ => ComplexityLevel::Standard,
    }
}

/// Read the operator's complexity level from `~/.neoth/wizard_state_v2.yaml`
/// (the `complexity_level` top-level key the v2 wizard persists — W-03a). This
/// is the REAL adaptive signal: the GUI binds panel visibility to whatever the
/// wizard decided for this operator. Fallback `Standard` when the file/field is
/// absent (a pre-v2 wizard state, or the operator hasn't run the v2 wizard) —
/// the safe non-overwhelming default.
///
/// Reads the YAML with a minimal struct rather than depending on the daemon
/// crate (the GUI stays decoupled — same pattern as `MinimalFreedomYaml`).
pub fn read_complexity_level(home: &std::path::Path) -> ComplexityLevel {
    let path = home.join("wizard_state_v2.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ComplexityLevel::Standard;
    };
    #[derive(serde::Deserialize)]
    struct MinimalWizardState {
        #[serde(default)]
        complexity_level: Option<String>,
    }
    match serde_yaml::from_str::<MinimalWizardState>(&text) {
        Ok(m) => m
            .complexity_level
            .as_deref()
            .map(parse_complexity_level)
            .unwrap_or_default(),
        Err(_) => ComplexityLevel::Standard,
    }
}

// ── GR-10 — Safety Rails panel (parse `neoth security safe-mode --json`) ──────

/// One safety rail as reported by `neoth security safe-mode --json`. The GUI
/// `SafeRailRow` Slint struct is built from this in `main.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRail {
    pub name: String,
    pub engaged: bool,
    pub detail: String,
}

/// The parsed safe-mode snapshot: every rail + the engaged/total counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SafeModeSnapshot {
    pub rails: Vec<SafeRail>,
    pub engaged_count: i32,
    pub total: i32,
}

/// Parse the JSON emitted by `neoth security safe-mode --json`
/// (`{rails:[{name,engaged,detail}], engaged_count, total}`). PURE + robust: a
/// missing/malformed payload yields an EMPTY snapshot so the panel renders a
/// "no data" state rather than crashing the GUI. The counts are derived from
/// the rails when the top-level fields are absent (forward-compatible).
pub fn parse_safe_mode(json: &str) -> SafeModeSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return SafeModeSnapshot::default();
    };
    let rails: Vec<SafeRail> = v
        .get("rails")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let name = r.get("name")?.as_str()?.to_string();
                    let engaged = r.get("engaged").and_then(|e| e.as_bool()).unwrap_or(false);
                    let detail = r
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(SafeRail {
                        name,
                        engaged,
                        detail,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let engaged_count = v
        .get("engaged_count")
        .and_then(|c| c.as_i64())
        .unwrap_or_else(|| rails.iter().filter(|r| r.engaged).count() as i64)
        as i32;
    let total = v
        .get("total")
        .and_then(|t| t.as_i64())
        .unwrap_or(rails.len() as i64) as i32;
    SafeModeSnapshot {
        rails,
        engaged_count,
        total,
    }
}

// ── GU-01 hemispheres panel (parse `neoth hemispheres show --output json`) ───

/// One role→provider binding for the Hemispheres panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HemisphereBinding {
    pub role: String,     // "left" | "right" | "cerebellum"
    pub provider: String, // canonical id, or "(unset)" when no provider bound
    pub model: String,    // "" when the binding uses the provider default
    pub has_key: bool,
}

/// Parsed hemisphere topology snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HemispheresSnapshot {
    pub mode: String, // "single" | "custom" | "triplet"
    pub bindings: Vec<HemisphereBinding>,
}

/// Parse `neoth hemispheres show --output json`. PURE + robust (malformed →
/// empty). A null `provider` renders as `(unset)`; a null `model` as empty.
pub fn parse_hemispheres(json: &str) -> HemispheresSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return HemispheresSnapshot::default();
    };
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let bindings = v
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let role = r.get("role")?.as_str()?.to_string();
                    let provider = r
                        .get("provider")
                        .and_then(|p| p.as_str())
                        .unwrap_or("(unset)")
                        .to_string();
                    let model = r
                        .get("model")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    let has_key = r.get("has_key").and_then(|k| k.as_bool()).unwrap_or(false);
                    Some(HemisphereBinding {
                        role,
                        provider,
                        model,
                        has_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    HemispheresSnapshot { mode, bindings }
}

// ── GU-01 skills panel (parse `neoth skills --list --output json`) ───────────

/// One installed skill for the Skills panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillSummary {
    pub id: String,
    pub description: String,
    pub enabled: bool,
    /// Trigger keywords joined with ", " for display.
    pub keywords: String,
}

/// Parse `neoth skills --list --output json` (a JSON array of SkillManifest).
/// PURE + robust (malformed → empty). A skill missing `enabled` defaults to
/// `true` (matching the daemon's `#[serde(default = "default_true")]`).
pub fn parse_skills(json: &str) -> Vec<SkillSummary> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let id = s.get("id")?.as_str()?.to_string();
            let description = s
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let enabled = s.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
            let keywords = s
                .get("trigger_keywords")
                .and_then(|k| k.as_array())
                .map(|kw| {
                    kw.iter()
                        .filter_map(|w| w.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Some(SkillSummary {
                id,
                description,
                enabled,
                keywords,
            })
        })
        .collect()
}

// ── GU-01 plugins panel (parse `neoth plugin list --output json`) ────────────

/// One discovered plugin for the Plugins panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginSummary {
    pub id: String,
    pub name: String,
    pub activation: String, // "enabled" | "pending" | "disabled" | …
}

/// Parse `neoth plugin list --output json` (array of `{id,name,activation}`).
/// PURE + robust (malformed/non-array → empty; id-less entries skipped).
pub fn parse_plugins(json: &str) -> Vec<PluginSummary> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|p| {
            let id = p.get("id")?.as_str()?.to_string();
            let name = p
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let activation = p
                .get("activation")
                .and_then(|a| a.as_str())
                .unwrap_or("unknown")
                .to_string();
            Some(PluginSummary {
                id,
                name,
                activation,
            })
        })
        .collect()
}

// ── GU-01 memory panel (parse `neoth memory --size --output json`) ───────────

/// One memory block (source + path + byte size) for the Memory panel. The
/// `--size` shape deliberately carries NO content — only metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryBlockInfo {
    pub source: String, // "global" | "project" | "rule" | "memory"
    pub path: String,
    pub bytes: i64,
}

/// Parsed memory snapshot: total bytes + per-block sizes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemorySnapshot {
    pub total_bytes: i64,
    pub blocks: Vec<MemoryBlockInfo>,
}

/// Parse `neoth memory --size --output json`
/// (`{total_bytes, blocks:[{source,path,bytes}]}`). PURE + robust (malformed →
/// empty; total derived from the blocks when absent).
pub fn parse_memory_size(json: &str) -> MemorySnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return MemorySnapshot::default();
    };
    let blocks: Vec<MemoryBlockInfo> = v
        .get("blocks")
        .and_then(|b| b.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    let source = b
                        .get("source")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let path = b.get("path")?.as_str()?.to_string();
                    let bytes = b.get("bytes").and_then(|n| n.as_i64()).unwrap_or(0);
                    Some(MemoryBlockInfo {
                        source,
                        path,
                        bytes,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let total_bytes = v
        .get("total_bytes")
        .and_then(|t| t.as_i64())
        .unwrap_or_else(|| blocks.iter().map(|b| b.bytes).sum());
    MemorySnapshot {
        total_bytes,
        blocks,
    }
}

// ── GU-01 channels panel (credentials.yaml token PRESENCE, never the value) ──

/// One channel's connection state for the Channels panel. ONLY the connected
/// bool is derived — a secret token is NEVER read into this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    pub name: String,
    pub connected: bool,
}

/// Derive per-channel connection state from the PRESENCE of credential fields
/// in a `credentials.yaml` string. PURE + secret-safe: it deserialises each
/// token into an `Option<String>` only to test `is_some() && !is_empty()`, and
/// emits ONLY the boolean — token values never leave this function. A malformed
/// file yields "all disconnected" (never panics, never partial-leaks).
pub fn channel_status_from_credentials_yaml(yaml: &str) -> Vec<ChannelStatus> {
    #[derive(serde::Deserialize, Default)]
    struct MinimalCreds {
        telegram_token: Option<String>,
        whatsapp_token: Option<String>,
        slack_bot_token: Option<String>,
        keet_seed_phrase: Option<String>,
        pears_bearer_token: Option<String>,
    }
    let creds: MinimalCreds = serde_yaml::from_str(yaml).unwrap_or_default();
    let present = |o: &Option<String>| o.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    vec![
        ChannelStatus {
            name: "telegram".into(),
            connected: present(&creds.telegram_token),
        },
        ChannelStatus {
            name: "whatsapp".into(),
            connected: present(&creds.whatsapp_token),
        },
        ChannelStatus {
            name: "slack".into(),
            connected: present(&creds.slack_bot_token),
        },
        ChannelStatus {
            name: "keet".into(),
            connected: present(&creds.keet_seed_phrase),
        },
        ChannelStatus {
            name: "pears".into(),
            connected: present(&creds.pears_bearer_token),
        },
    ]
}

/// Read `<neoth_home>/credentials.yaml` + derive channel connection state. A
/// missing file yields "all disconnected". The fs read is the only impurity;
/// the logic is the unit-tested [`channel_status_from_credentials_yaml`].
pub fn read_channel_status(neoth_home: &std::path::Path) -> Vec<ChannelStatus> {
    let path = neoth_home.join("credentials.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_default();
    channel_status_from_credentials_yaml(&yaml)
}

// ── SPEC-05 preset selector (parse `neoth preset list --json`) ───────────────

/// One saved preset for the selector.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresetEntry {
    pub name: String,
    pub active: bool,
}

/// Parse `neoth preset list --json` (`{presets:[{name,active}], active}`).
/// PURE + robust (malformed → empty; name-less entries skipped).
pub fn parse_presets(json: &str) -> Vec<PresetEntry> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    v.get("presets")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let name = p.get("name")?.as_str()?.to_string();
                    let active = p.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                    Some(PresetEntry { name, active })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── SPEC-06 hemisphere switcher (parse `neoth provider list --output json`) ──

/// Extract the IMPLEMENTED provider ids from `neoth provider list --output json`
/// (`[{id, description, implemented}]`) — the options for the per-role provider
/// picker. PURE + robust (malformed → empty; stub/unimplemented providers
/// excluded so the operator can't bind a role to a non-functional adapter).
/// This is a fixed adapter set, NOT a model whitelist — it stays
/// model-version-agnostic (the model id is a separate free-form field).
pub fn parse_provider_ids(json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter(|p| p.get("implemented").and_then(|i| i.as_bool()).unwrap_or(true))
        .filter_map(|p| p.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse ────────────────────────────────────────────────────────────
    #[test]
    fn parse_known_and_unknown() {
        assert_eq!(parse_complexity_level("minimal"), ComplexityLevel::Minimal);
        assert_eq!(parse_complexity_level("  FULL "), ComplexityLevel::Full);
        assert_eq!(parse_complexity_level("standard"), ComplexityLevel::Standard);
        assert_eq!(parse_complexity_level(""), ComplexityLevel::Standard);
        assert_eq!(parse_complexity_level("garbage"), ComplexityLevel::Standard);
    }

    #[test]
    fn default_is_standard() {
        assert_eq!(ComplexityLevel::default(), ComplexityLevel::Standard);
    }

    // ── Minimal: the beginner-safe set ─────────────────────────────────────
    #[test]
    fn minimal_shows_only_beginner_essentials() {
        let p = panels_for(ComplexityLevel::Minimal);
        // Shown: the 3 a beginner needs.
        assert!(p.show_channels, "beginner needs channels to connect Telegram");
        assert!(p.show_privacy, "autonomy level is beginner-critical");
        assert!(p.show_config, "provider choice is beginner-critical");
        // Hidden: everything advanced.
        assert!(!p.show_hemispheres);
        assert!(!p.show_skills);
        assert!(!p.show_plugins);
        assert!(!p.show_memory);
        assert!(!p.show_cluster);
        assert!(!p.show_code_sessions);
        assert!(!p.expand_cluster_advanced);
        assert!(!p.expand_config_advanced);
    }

    // ── Standard: common expanded, advanced collapsed ──────────────────────
    #[test]
    fn standard_shows_common_hides_plugins_collapses_advanced() {
        let p = panels_for(ComplexityLevel::Standard);
        assert!(p.show_hemispheres);
        assert!(p.show_channels);
        assert!(p.show_skills);
        assert!(p.show_memory);
        assert!(p.show_privacy);
        assert!(p.show_cluster);
        assert!(p.show_config);
        assert!(p.show_code_sessions);
        // Plugins is a power-user surface — hidden until Full.
        assert!(!p.show_plugins);
        // Advanced sub-sections collapsed at Standard.
        assert!(!p.expand_cluster_advanced);
        assert!(!p.expand_config_advanced);
    }

    // ── Full: everything ───────────────────────────────────────────────────
    #[test]
    fn full_shows_everything_and_expands_advanced() {
        let p = panels_for(ComplexityLevel::Full);
        assert!(p.show_hemispheres);
        assert!(p.show_channels);
        assert!(p.show_skills);
        assert!(p.show_plugins);
        assert!(p.show_memory);
        assert!(p.show_privacy);
        assert!(p.show_cluster);
        assert!(p.show_config);
        assert!(p.show_code_sessions);
        assert!(p.expand_cluster_advanced);
        assert!(p.expand_config_advanced);
    }

    // ── monotonicity: a higher level never hides what a lower level shows ──
    #[test]
    fn visibility_is_monotonic_across_levels() {
        let m = panels_for(ComplexityLevel::Minimal);
        let s = panels_for(ComplexityLevel::Standard);
        let f = panels_for(ComplexityLevel::Full);
        let fields = |p: &PanelVisibility| {
            [
                p.show_hemispheres,
                p.show_channels,
                p.show_skills,
                p.show_plugins,
                p.show_memory,
                p.show_privacy,
                p.show_cluster,
                p.show_config,
                p.show_code_sessions,
            ]
        };
        let (mf, sf, ff) = (fields(&m), fields(&s), fields(&f));
        for i in 0..mf.len() {
            assert!(!mf[i] || sf[i], "Standard hides a panel Minimal showed (idx {i})");
            assert!(!sf[i] || ff[i], "Full hides a panel Standard showed (idx {i})");
        }
    }

    #[test]
    fn privacy_and_config_visible_at_every_level() {
        // The two safety-critical panels (autonomy + provider) are never hidden.
        for lvl in [
            ComplexityLevel::Minimal,
            ComplexityLevel::Standard,
            ComplexityLevel::Full,
        ] {
            let p = panels_for(lvl);
            assert!(p.show_privacy, "{} must show privacy", lvl.as_str());
            assert!(p.show_config, "{} must show config", lvl.as_str());
        }
    }

    #[test]
    fn read_complexity_from_wizard_state_yaml() {
        let dir = tempfile::tempdir().unwrap();
        // Absent file ⇒ safe default.
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Standard);
        // Top-level complexity_level key (the v2 wizard flattens it there).
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "operator_id: alice\ncomplexity_level: full\nprivacy_first: true\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Full);
        // Missing field amid other keys ⇒ default.
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "operator_id: bob\nautonomy: standard\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Standard);
        // Minimal persona round-trips.
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "complexity_level: minimal\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Minimal);
    }

    #[test]
    fn round_trips_through_string() {
        for lvl in [
            ComplexityLevel::Minimal,
            ComplexityLevel::Standard,
            ComplexityLevel::Full,
        ] {
            assert_eq!(parse_complexity_level(lvl.as_str()), lvl);
        }
    }

    // ── GR-10 parse_safe_mode ────────────────────────────────────────────────

    #[test]
    fn parse_safe_mode_full_payload() {
        let json = r#"{
            "rails": [
                {"name": "autonomy_gate", "engaged": true, "detail": "strict"},
                {"name": "email_llm_tiebreak", "engaged": false, "detail": "off"}
            ],
            "engaged_count": 1,
            "total": 2
        }"#;
        let s = parse_safe_mode(json);
        assert_eq!(s.rails.len(), 2);
        assert_eq!(s.rails[0].name, "autonomy_gate");
        assert!(s.rails[0].engaged);
        assert_eq!(s.rails[0].detail, "strict");
        assert!(!s.rails[1].engaged);
        assert_eq!(s.engaged_count, 1);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn parse_safe_mode_derives_counts_when_absent() {
        // Forward-compat: missing engaged_count/total derive from the rails.
        let json = r#"{"rails":[
            {"name":"a","engaged":true,"detail":""},
            {"name":"b","engaged":true,"detail":""},
            {"name":"c","engaged":false}
        ]}"#;
        let s = parse_safe_mode(json);
        assert_eq!(s.engaged_count, 2, "derived from engaged rails");
        assert_eq!(s.total, 3, "derived from rail count");
        assert_eq!(s.rails[2].detail, "", "missing detail defaults empty");
    }

    #[test]
    fn parse_safe_mode_malformed_is_empty_not_panic() {
        assert_eq!(parse_safe_mode("not json"), SafeModeSnapshot::default());
        assert_eq!(parse_safe_mode(""), SafeModeSnapshot::default());
        // A rail missing its required `name` is skipped, not fatal.
        let s = parse_safe_mode(r#"{"rails":[{"engaged":true},{"name":"ok","engaged":false}]}"#);
        assert_eq!(s.rails.len(), 1);
        assert_eq!(s.rails[0].name, "ok");
    }

    // ── GU-01 parse_hemispheres ───────────────────────────────────────────────

    #[test]
    fn parse_hemispheres_full() {
        let json = r#"{
            "mode": "triplet",
            "single_provider_fallback": "ClaudeCli",
            "roles": [
                {"role":"left","provider":"claude_cli","model":"sonnet","endpoint":null,"has_key":true},
                {"role":"right","provider":"openai_api","model":null,"endpoint":null,"has_key":false},
                {"role":"cerebellum","provider":null,"model":null,"endpoint":null,"has_key":false}
            ]
        }"#;
        let s = parse_hemispheres(json);
        assert_eq!(s.mode, "triplet");
        assert_eq!(s.bindings.len(), 3);
        assert_eq!(s.bindings[0].role, "left");
        assert_eq!(s.bindings[0].provider, "claude_cli");
        assert_eq!(s.bindings[0].model, "sonnet");
        assert!(s.bindings[0].has_key);
        assert_eq!(s.bindings[1].model, "", "null model -> empty");
        assert_eq!(s.bindings[2].provider, "(unset)", "null provider -> (unset)");
    }

    #[test]
    fn parse_hemispheres_malformed_is_empty() {
        assert_eq!(parse_hemispheres("nope"), HemispheresSnapshot::default());
        // role-less entry skipped.
        let s = parse_hemispheres(r#"{"mode":"single","roles":[{"provider":"x"},{"role":"left","provider":"y"}]}"#);
        assert_eq!(s.bindings.len(), 1);
        assert_eq!(s.bindings[0].role, "left");
    }

    // ── GU-01 parse_skills ────────────────────────────────────────────────────

    #[test]
    fn parse_skills_array_with_keywords() {
        let json = r#"[
            {"id":"verification","description":"verify before done","trigger_keywords":["verify","check"],"enabled":true},
            {"id":"research","description":"deep research","trigger_keywords":[]}
        ]"#;
        let rows = parse_skills(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "verification");
        assert_eq!(rows[0].keywords, "verify, check");
        assert!(rows[0].enabled);
        assert!(rows[1].enabled, "missing enabled defaults true");
        assert_eq!(rows[1].keywords, "");
    }

    #[test]
    fn parse_skills_malformed_and_non_array_is_empty() {
        assert!(parse_skills("nope").is_empty());
        assert!(parse_skills(r#"{"id":"x"}"#).is_empty(), "object, not array -> empty");
        // id-less entry skipped.
        let rows = parse_skills(r#"[{"description":"no id"},{"id":"ok"}]"#);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "ok");
    }

    // ── GU-01 parse_plugins ───────────────────────────────────────────────────

    #[test]
    fn parse_plugins_array() {
        let json = r#"[
            {"id":"faccam","name":"FacCam","activation":"enabled"},
            {"id":"x","activation":"pending"}
        ]"#;
        let rows = parse_plugins(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "faccam");
        assert_eq!(rows[0].name, "FacCam");
        assert_eq!(rows[0].activation, "enabled");
        assert_eq!(rows[1].name, "", "missing name -> empty");
        assert_eq!(rows[1].activation, "pending");
    }

    #[test]
    fn parse_plugins_malformed_is_empty() {
        assert!(parse_plugins("nope").is_empty());
        assert!(parse_plugins(r#"{"id":"x"}"#).is_empty(), "object not array");
        assert_eq!(parse_plugins(r#"[{"name":"no id"},{"id":"ok"}]"#).len(), 1);
    }

    // ── GU-01 parse_memory_size ───────────────────────────────────────────────

    #[test]
    fn parse_memory_size_full() {
        let json = r#"{"total_bytes":300,"blocks":[
            {"source":"global","path":"/a/CLAUDE.md","bytes":100},
            {"source":"memory","path":"/b/MEMORY.md","bytes":200}
        ]}"#;
        let s = parse_memory_size(json);
        assert_eq!(s.total_bytes, 300);
        assert_eq!(s.blocks.len(), 2);
        assert_eq!(s.blocks[0].source, "global");
        assert_eq!(s.blocks[1].bytes, 200);
    }

    #[test]
    fn parse_memory_size_derives_total_and_skips_pathless() {
        let s = parse_memory_size(r#"{"blocks":[{"source":"x","path":"/p","bytes":5},{"source":"y","bytes":9}]}"#);
        assert_eq!(s.blocks.len(), 1, "path-less block skipped");
        assert_eq!(s.total_bytes, 5, "derived from present blocks");
        assert_eq!(parse_memory_size("nope"), MemorySnapshot::default());
    }

    // ── GU-01 channel status (secret-safe) ────────────────────────────────────

    #[test]
    fn channel_status_reads_presence_not_values() {
        let yaml = "telegram_token: \"123:abc\"\nslack_bot_token: \"xoxb-x\"\n";
        let rows = channel_status_from_credentials_yaml(yaml);
        let by = |n: &str| rows.iter().find(|c| c.name == n).unwrap().connected;
        assert!(by("telegram"));
        assert!(by("slack"));
        assert!(!by("whatsapp"), "absent -> disconnected");
        assert!(!by("keet"));
        // The connected bool is all that's exposed — no token value in the struct.
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn channel_status_empty_token_is_disconnected_and_malformed_is_all_off() {
        let rows = channel_status_from_credentials_yaml("telegram_token: \"  \"\n");
        assert!(!rows.iter().find(|c| c.name == "telegram").unwrap().connected,
            "whitespace-only token -> disconnected");
        // Malformed YAML -> all disconnected, never a panic.
        let all = channel_status_from_credentials_yaml("%%% not yaml %%%");
        assert!(all.iter().all(|c| !c.connected));
    }

    #[test]
    fn read_channel_status_missing_file_is_all_off() {
        let dir = tempfile::tempdir().unwrap();
        let rows = read_channel_status(dir.path());
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().all(|c| !c.connected));
    }

    // ── SPEC-05 parse_presets ─────────────────────────────────────────────────

    #[test]
    fn parse_presets_marks_active() {
        let json = r#"{"presets":[{"name":"frugal","active":false},{"name":"weekend","active":true}],"active":"weekend"}"#;
        let rows = parse_presets(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "frugal");
        assert!(!rows[0].active);
        assert_eq!(rows[1].name, "weekend");
        assert!(rows[1].active);
    }

    #[test]
    fn parse_presets_malformed_and_nameless_skipped() {
        assert!(parse_presets("nope").is_empty());
        assert!(parse_presets(r#"{"presets":[]}"#).is_empty());
        let rows = parse_presets(r#"{"presets":[{"active":true},{"name":"ok"}]}"#);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "ok");
    }

    // ── SPEC-06 parse_provider_ids ────────────────────────────────────────────

    #[test]
    fn parse_provider_ids_keeps_implemented_only() {
        let json = r#"[
            {"id":"claude_cli","description":"x","implemented":true},
            {"id":"aws_bedrock","description":"y","implemented":false},
            {"id":"openai_api","description":"z","implemented":true}
        ]"#;
        let ids = parse_provider_ids(json);
        assert_eq!(ids, vec!["claude_cli", "openai_api"], "stub provider excluded");
    }

    #[test]
    fn parse_provider_ids_malformed_and_missing_flag() {
        assert!(parse_provider_ids("nope").is_empty());
        assert!(parse_provider_ids(r#"{"id":"x"}"#).is_empty(), "object not array");
        // Missing `implemented` defaults to included (forward-compat).
        let ids = parse_provider_ids(r#"[{"id":"a"},{"description":"no id"}]"#);
        assert_eq!(ids, vec!["a"]);
    }
}
