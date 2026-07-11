//! tweakcc-style operator customisation — Phase 32 R-20.
//!
//! Loads `~/.neoth/tweaks.toml` and exposes a typed `Tweaks` struct that
//! the daemon consults before rendering any UI surface or building the
//! per-turn system prompt. Inspired by `tweakcc::settings.json` (Phase 33d
//! Q-7), but TOML to stay consistent with the rest of NEOTH's config
//! surface.
//!
//! ## Schema
//!
//! ```toml
//! # ~/.neoth/tweaks.toml
//! statusline   = "neoth • {operator} • {model}"
//! color_theme  = "dark"           # light | dark | auto
//! model_default = "claude-opus-4-7"
//! persona_override = "concise, no chitchat"
//!
//! [[prompts]]
//! id          = "morning-greet"
//! description = "Morning greeting prefix"
//! prompt      = "Good morning, {operator}. Start with: "
//! ```
//!
//! Missing file → defaults. Bad TOML → loud error (operator typo'd; better
//! to fail-fast than silently load defaults).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::FreedomConfig;

/// Top-level tweaks file shape.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Tweaks {
    /// Status-line template. `{operator}`, `{model}`, `{autonomy}` are
    /// substituted at render time. Empty → use NEOTH's built-in default.
    pub statusline: Option<String>,
    /// Color theme name. Accepted values: `light` | `dark` | `auto`.
    pub color_theme: Option<String>,
    /// Default model override. Wins over `freedom.yaml::provider_model`
    /// for interactive sessions.
    pub model_default: Option<String>,
    /// Free-form persona-tone hint. Prepended to the operator-md system
    /// prompt at per-turn assembly time.
    pub persona_override: Option<String>,
    /// Named reusable prompt snippets, mirrors `tweakcc::prompts[]`.
    pub prompts: Vec<PromptSnippet>,
    /// HO-05 (R-21): GUI/TUI appearance + layout knobs. Parsed here so a
    /// `[theme]` block in `tweaks.toml` round-trips; the Slint GUI +
    /// statusline consume these when rendering (Workstream P). All
    /// optional — `None` means "use NEOTH's built-in default".
    #[serde(default)]
    pub theme: ThemeConfig,
}

/// HO-05 (R-21) `[theme]` block — ~18 appearance/layout keys the GUI +
/// statusline read at render time. Every field optional so partial
/// `tweaks.toml` overrides only what the operator set; unknown keys are
/// ignored by serde so a newer GUI can add keys without breaking older
/// configs. Colours are free-form strings (`"#ff00aa"` / named) validated
/// at render time, not here.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ThemeConfig {
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub foreground_color: Option<String>,
    pub font_family: Option<String>,
    pub font_size_pt: Option<u8>,
    pub sidebar_width_px: Option<u32>,
    pub border_radius_px: Option<u32>,
    pub compact_mode: Option<bool>,
    pub show_token_count: Option<bool>,
    pub show_model_badge: Option<bool>,
    /// `"rounded"` | `"square"` | `"minimal"` — chat bubble shape.
    pub chat_bubble_style: Option<String>,
    pub icon_set: Option<String>,
    /// `"none"` | `"reduced"` | `"full"` — respects reduce-motion prefs.
    pub animation_speed: Option<String>,
    pub scrollbar_style: Option<String>,
    pub input_height_lines: Option<u8>,
    pub panel_opacity: Option<f32>,
    pub header_hidden: Option<bool>,
    pub sidebar_collapsed: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PromptSnippet {
    pub id: String,
    pub description: String,
    pub prompt: String,
}

impl Tweaks {
    /// `~/.neoth/tweaks.toml`.
    pub fn default_path() -> PathBuf {
        FreedomConfig::default_neoth_home().join("tweaks.toml")
    }

    /// Missing file → defaults. Bad TOML → error so the operator sees the
    /// failure at startup, not as silent fallback.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read tweaks at {}", path.display()))?;
        let t: Self =
            toml::from_str(&body).with_context(|| format!("parse TOML at {}", path.display()))?;
        Ok(t)
    }

    /// Convenience: load from the default path.
    pub fn load() -> Result<Self> {
        Self::load_or_default(&Self::default_path())
    }

    /// Look up a prompt snippet by id.
    pub fn snippet(&self, id: &str) -> Option<&PromptSnippet> {
        self.prompts.iter().find(|p| p.id == id)
    }

    /// Render the statusline with substitutions filled in.
    pub fn render_statusline(
        &self,
        operator: Option<&str>,
        model: Option<&str>,
        autonomy: Option<&str>,
    ) -> String {
        let template = self
            .statusline
            .clone()
            .unwrap_or_else(|| "neoth • {operator} • {model} • {autonomy}".to_string());
        template
            .replace("{operator}", operator.unwrap_or("operator"))
            .replace("{model}", model.unwrap_or("unset"))
            .replace("{autonomy}", autonomy.unwrap_or("standard"))
    }
}

/// Which layer in the model-selection priority chain resolved the effective model.
///
/// Walk order (highest → lowest priority):
/// `Dispatch` → `Skill` → `Cli` → `Tweaks` → `Freedom` → `ProviderDefault`.
/// Recorded in WAL frames so operators can audit what drove each model decision.
/// Never contains secrets (model identifiers are configuration, not credentials).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSource {
    /// A Dispatch agent or council decision selected the model.
    Dispatch,
    /// A skill manifest declared a `model:` field.
    Skill,
    /// Operator passed `--model` on the CLI.
    Cli,
    /// `model_default` in `tweaks.toml` wins.
    Tweaks,
    /// `provider_model` in `freedom.yaml` wins.
    Freedom,
    /// No override; the provider selects the model itself.
    ProviderDefault,
}

impl ModelSource {
    /// Static label used in WAL payloads and diagnostics. No allocation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ModelSource::Dispatch => "dispatch",
            ModelSource::Skill => "skill",
            ModelSource::Cli => "cli",
            ModelSource::Tweaks => "tweaks",
            ModelSource::Freedom => "freedom",
            ModelSource::ProviderDefault => "provider_default",
        }
    }
}

/// Resolve the effective model from the priority chain.
///
/// Pure — no I/O, no side effects, trivially unit-testable. Walk the chain
/// in priority order and return the first `Some` value together with its
/// [`ModelSource`] tag, or `(None, ModelSource::ProviderDefault)` when all
/// inputs are `None`.
///
/// Priority: `dispatch` > `skill` > `cli` > `tweaks_default` > `freedom`
/// > provider default.
pub fn resolve_effective_model<'a>(
    dispatch: Option<&'a str>,
    skill: Option<&'a str>,
    cli: Option<&'a str>,
    tweaks_default: Option<&'a str>,
    freedom: Option<&'a str>,
) -> (Option<&'a str>, ModelSource) {
    if let Some(m) = dispatch {
        return (Some(m), ModelSource::Dispatch);
    }
    if let Some(m) = skill {
        return (Some(m), ModelSource::Skill);
    }
    if let Some(m) = cli {
        return (Some(m), ModelSource::Cli);
    }
    if let Some(m) = tweaks_default {
        return (Some(m), ModelSource::Tweaks);
    }
    if let Some(m) = freedom {
        return (Some(m), ModelSource::Freedom);
    }
    (None, ModelSource::ProviderDefault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempdir().unwrap();
        let t = Tweaks::load_or_default(&dir.path().join("absent.toml")).unwrap();
        assert!(t.statusline.is_none());
        assert!(t.prompts.is_empty());
    }

    #[test]
    fn parses_full_tweaks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        std::fs::write(
            &path,
            r#"
statusline = "n • {operator}"
color_theme = "dark"
model_default = "opus"
persona_override = "blunt"

[[prompts]]
id = "morning"
description = "Morning prefix"
prompt = "Guten Morgen."

[[prompts]]
id = "shipping"
description = "Ship-it prefix"
prompt = "Ship it. Reasoning first, then code."
"#,
        )
        .unwrap();
        let t = Tweaks::load_or_default(&path).unwrap();
        assert_eq!(t.statusline.as_deref(), Some("n • {operator}"));
        assert_eq!(t.color_theme.as_deref(), Some("dark"));
        assert_eq!(t.prompts.len(), 2);
        assert!(t.snippet("morning").is_some());
        assert!(t.snippet("ghost").is_none());
    }

    #[test]
    fn parses_theme_block_with_partial_overrides() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        std::fs::write(
            &path,
            r##"
statusline = "n"

[theme]
accent_color = "#ff00aa"
font_size_pt = 14
compact_mode = true
animation_speed = "reduced"
"##,
        )
        .unwrap();
        let t = Tweaks::load_or_default(&path).unwrap();
        assert_eq!(t.theme.accent_color.as_deref(), Some("#ff00aa"));
        assert_eq!(t.theme.font_size_pt, Some(14));
        assert_eq!(t.theme.compact_mode, Some(true));
        assert_eq!(t.theme.animation_speed.as_deref(), Some("reduced"));
        // Keys the operator didn't set stay None (partial override).
        assert!(t.theme.sidebar_width_px.is_none());
        assert!(t.theme.header_hidden.is_none());
    }

    #[test]
    fn theme_defaults_to_all_none_when_block_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, "statusline = \"x\"").unwrap();
        let t = Tweaks::load_or_default(&path).unwrap();
        assert!(t.theme.accent_color.is_none());
        assert!(t.theme.compact_mode.is_none());
    }

    #[test]
    fn renders_statusline_with_substitutions() {
        let t = Tweaks {
            statusline: Some("[{operator}/{model}/{autonomy}]".into()),
            ..Default::default()
        };
        assert_eq!(
            t.render_statusline(Some("sam"), Some("opus"), Some("standard")),
            "[sam/opus/standard]",
        );
    }

    #[test]
    fn renders_default_statusline_when_unset() {
        let t = Tweaks::default();
        let s = t.render_statusline(Some("sam"), Some("opus"), Some("strict"));
        assert!(s.contains("sam"));
        assert!(s.contains("opus"));
        assert!(s.contains("strict"));
    }

    #[test]
    fn missing_substitutions_use_safe_defaults() {
        let t = Tweaks::default();
        let s = t.render_statusline(None, None, None);
        assert!(s.contains("operator"));
        assert!(s.contains("unset"));
        assert!(s.contains("standard"));
    }

    #[test]
    fn bad_toml_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is = not [valid").unwrap();
        assert!(Tweaks::load_or_default(&path).is_err());
    }

    #[test]
    fn empty_prompts_array_is_fine() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, "statusline = \"x\"").unwrap();
        let t = Tweaks::load_or_default(&path).unwrap();
        assert!(t.prompts.is_empty());
    }

    // ── B22 — resolve_effective_model precedence table ────────────────────

    #[test]
    fn resolve_model_full_precedence_table() {
        // dispatch wins over everything
        let (m, src) =
            resolve_effective_model(Some("d"), Some("s"), Some("c"), Some("t"), Some("f"));
        assert_eq!(m, Some("d"));
        assert_eq!(src, ModelSource::Dispatch);

        // skill wins when no dispatch
        let (m, src) =
            resolve_effective_model(None, Some("s"), Some("c"), Some("t"), Some("f"));
        assert_eq!(m, Some("s"));
        assert_eq!(src, ModelSource::Skill);

        // cli wins over tweaks and freedom
        let (m, src) = resolve_effective_model(None, None, Some("c"), Some("t"), Some("f"));
        assert_eq!(m, Some("c"));
        assert_eq!(src, ModelSource::Cli);

        // tweaks wins over freedom
        let (m, src) = resolve_effective_model(None, None, None, Some("t"), Some("f"));
        assert_eq!(m, Some("t"));
        assert_eq!(src, ModelSource::Tweaks);

        // freedom wins when only freedom present
        let (m, src) = resolve_effective_model(None, None, None, None, Some("f"));
        assert_eq!(m, Some("f"));
        assert_eq!(src, ModelSource::Freedom);

        // all None → ProviderDefault
        let (m, src) = resolve_effective_model(None, None, None, None, None);
        assert_eq!(m, None);
        assert_eq!(src, ModelSource::ProviderDefault);
    }

    #[test]
    fn resolve_model_no_override_is_provider_default() {
        let (m, src) = resolve_effective_model(None, None, None, None, None);
        assert!(m.is_none());
        assert_eq!(src, ModelSource::ProviderDefault);
    }

    #[test]
    fn resolve_model_tweaks_alone_beats_freedom() {
        let (m, src) =
            resolve_effective_model(None, None, None, Some("claude-opus-4-7"), Some("sonnet"));
        assert_eq!(m, Some("claude-opus-4-7"));
        assert_eq!(src, ModelSource::Tweaks);
    }

    #[test]
    fn model_source_as_str_roundtrips() {
        assert_eq!(ModelSource::Dispatch.as_str(), "dispatch");
        assert_eq!(ModelSource::Skill.as_str(), "skill");
        assert_eq!(ModelSource::Cli.as_str(), "cli");
        assert_eq!(ModelSource::Tweaks.as_str(), "tweaks");
        assert_eq!(ModelSource::Freedom.as_str(), "freedom");
        assert_eq!(ModelSource::ProviderDefault.as_str(), "provider_default");
    }

    // ── B22 production-wiring invariants ─────────────────────────────────────
    // These tests verify the scenarios that the bug-fixes in cli/chat.rs depend
    // on: when dispatch_provider calls resolve_effective_model with a pre-folded
    // override_model (dispatch+skill winner) as the `dispatch` param, the result
    // must match what the 6-tier chain would have produced inline.

    #[test]
    fn resolve_model_prefold_dispatch_skill_beats_all_lower_tiers() {
        // In dispatch_provider, override_model carries the pre-folded dispatch+skill
        // winner and is passed as the `dispatch` parameter.  It must win over cli,
        // tweaks, and freedom so PROVIDER_REQUEST WAL, model_used, and error
        // usage_log all record the correct model when a skill/dispatch override won.
        let (m, src) = resolve_effective_model(
            Some("skill-or-dispatch-model"),
            None, // already folded into dispatch param by the caller
            Some("cli-model"),
            Some("tweaks-model"),
            Some("freedom-model"),
        );
        assert_eq!(m, Some("skill-or-dispatch-model"));
        assert_eq!(src, ModelSource::Dispatch);
    }

    #[test]
    fn resolve_model_no_override_falls_through_to_cli() {
        // When neither dispatch nor skill resolved a model (override_model = None),
        // the cli flag must win — matching the behaviour of the old inline chain.
        let (m, src) = resolve_effective_model(None, None, Some("my-cli"), None, None);
        assert_eq!(m, Some("my-cli"));
        assert_eq!(src, ModelSource::Cli);
    }

    #[test]
    fn resolve_model_tweaks_beats_freedom_when_no_higher_tier() {
        // Confirms the tweaks tier wins over freedom when cli/dispatch/skill are absent
        // (regression guard for the token-cap + error-log sites that use effective_model).
        let (m, src) = resolve_effective_model(None, None, None, Some("tweaks-opus"), Some("freedom-sonnet"));
        assert_eq!(m, Some("tweaks-opus"));
        assert_eq!(src, ModelSource::Tweaks);
    }

    #[test]
    fn resolve_model_all_none_gives_unknown_sentinel() {
        // When ALL tiers are absent the resolved model is None — callers unwrap to
        // "unknown".  Verifies that the streaming model_used fallback path matches.
        let (m, src) = resolve_effective_model(None, None, None, None, None);
        assert!(m.is_none(), "should be None when all tiers absent");
        assert_eq!(src, ModelSource::ProviderDefault);
    }

    #[test]
    fn invalid_toml_error_includes_path_context() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "model_default = [broken").unwrap();
        let err = Tweaks::load_or_default(&path).unwrap_err();
        let msg = format!("{err:#}");
        // load_or_default adds "parse TOML at <path>" context — operator must
        // be able to find the offending file from the error message.
        assert!(
            msg.contains("parse TOML") || msg.contains("bad.toml"),
            "expected path context in error, got: {msg}"
        );
    }
}
