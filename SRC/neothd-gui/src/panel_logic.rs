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
}
