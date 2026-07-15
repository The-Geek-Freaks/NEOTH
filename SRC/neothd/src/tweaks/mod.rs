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

/// HO-05 (R-21) `[theme]` block — appearance/layout keys the GUI +
/// statusline read at render time. Every field optional so partial
/// `tweaks.toml` overrides only what the operator set. Unknown keys fail
/// loudly: a retained configuration value may never parse and then disappear.
/// Colours use `#RGB`, `#RRGGBB`, or `#RRGGBBAA` and are validated before use.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
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
    /// `"none"` | `"reduced"` | `"full"` — respects reduce-motion prefs.
    pub animation_speed: Option<String>,
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

// ── B23 — THEME-TWEAKS-RUNTIME ───────────────────────────────────────────────

/// Which layer in the theme-precedence chain provided the effective value.
///
/// Walk order (highest → lowest priority):
/// `Dotfile` (persisted `.gui-theme`/`.gui-density`) → `Tweaks` (`[theme]` block)
/// → `BuiltIn` (hard-coded NEOTH defaults).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeSource {
    /// Value came from a persisted dotfile (`.gui-theme` / `.gui-density`).
    Dotfile,
    /// Value came from the `[theme]` block in `tweaks.toml`.
    Tweaks,
    /// Value is the NEOTH built-in default (no operator override).
    BuiltIn,
}

impl ThemeSource {
    /// Static label used in diagnostics and the `tweaks show` renderer.
    pub fn as_str(&self) -> &'static str {
        match self {
            ThemeSource::Dotfile => "dotfile",
            ThemeSource::Tweaks => "tweaks",
            ThemeSource::BuiltIn => "built_in",
        }
    }
}

impl Default for ThemeSource {
    fn default() -> Self {
        ThemeSource::BuiltIn
    }
}

/// Support matrix: each field name paired with its status string.
///
/// Status strings:
/// - `"active/<sink-name>"` — wired to a named Slint property or TUI surface.
/// Every entry is active. Fields without an honest production sink are removed
/// from the schema instead of being accepted and ignored.
///
/// Every field that appears in `ThemeConfig` PLUS `color_theme` and `statusline`
/// (top-level `Tweaks` fields that belong to the theme surface) is listed here.
/// Silent parse-and-ignore is forbidden: any field that is set but not `active`
/// must appear in `EffectiveGuiTheme::unsupported_keys`.
pub const THEME_SUPPORT_MATRIX: &[(&str, &str)] = &[
    // ── top-level Tweaks fields that touch the theme surface ───────────────
    ("color_theme", "active/Theme.dark"),
    ("statusline", "active/cli-chat.stderr"),
    // ── [theme] block ──────────────────────────────────────────────────────
    ("compact_mode", "active/Theme.density-mode"),
    ("font_family", "active/Theme.font-sans-override"),
    ("font_size_pt", "active/Theme.font-size-override"),
    ("sidebar_width_px", "active/Theme.sidebar-w-override"),
    ("input_height_lines", "active/Theme.input-height-override"),
    ("panel_opacity", "active/Theme.panel-opacity"),
    ("accent_color", "active/Theme.accent-color-override"),
    ("background_color", "active/Theme.background-color-override"),
    ("foreground_color", "active/Theme.foreground-color-override"),
    ("border_radius_px", "active/Theme.border-radius-override"),
    ("show_token_count", "active/Theme.show-token-count"),
    ("show_model_badge", "active/ChatMessage.model-badge"),
    ("chat_bubble_style", "active/Theme.chat-bubble-style"),
    ("animation_speed", "active/Theme.animation-mode"),
    ("header_hidden", "active/Theme.header-hidden"),
    ("sidebar_collapsed", "active/Theme.sidebar-collapsed"),
];

/// Resolved effective GUI theme values with per-field source attribution.
///
/// Computed once before first paint (pure, no I/O). Consumed by the Slint GUI
/// bootstrap in `neothd-gui` and by `neoth tweaks show`.
#[derive(Clone, Debug, Serialize)]
pub struct EffectiveGuiTheme {
    /// `true` = dark mode (NEOTH default).
    pub dark: bool,
    /// Which precedence layer resolved `dark`.
    pub dark_source: ThemeSource,
    /// Density mode: 0=compact  1=normal  2=spacious.
    pub density_mode: i32,
    /// Which precedence layer resolved `density_mode`.
    pub density_source: ThemeSource,
    /// Font family override — maps to `Theme.font-sans-override`.
    pub font_family: Option<String>,
    /// Font size in points — converted to `Theme.font-size-override` pixels.
    pub font_size_pt: Option<u8>,
    /// Sidebar width in pixels — maps to `Theme.sidebar-w-override`.
    pub sidebar_width_px: Option<u32>,
    /// Input-area height in lines — converted to `Theme.input-height-override`.
    pub input_height_lines: Option<u8>,
    /// Panel opacity (0.0–1.0), mapped to `Theme.panel-opacity`.
    pub panel_opacity: Option<f32>,
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub foreground_color: Option<String>,
    pub border_radius_px: Option<u32>,
    pub show_token_count: bool,
    pub show_model_badge: bool,
    pub chat_bubble_style: String,
    pub animation_speed: String,
    pub header_hidden: bool,
    pub sidebar_collapsed: bool,
    /// Field names rejected by validation before reaching a sink.
    pub unsupported_keys: Vec<String>,
    /// Human-readable diagnostics: invalid values, dotfile fall-through, etc.
    pub diagnostics: Vec<String>,
}

impl Default for EffectiveGuiTheme {
    fn default() -> Self {
        Self {
            dark: true,
            dark_source: ThemeSource::BuiltIn,
            density_mode: 1,
            density_source: ThemeSource::BuiltIn,
            font_family: None,
            font_size_pt: None,
            sidebar_width_px: None,
            input_height_lines: None,
            panel_opacity: None,
            accent_color: None,
            background_color: None,
            foreground_color: None,
            border_radius_px: None,
            show_token_count: true,
            show_model_badge: false,
            chat_bubble_style: "rounded".to_string(),
            animation_speed: "full".to_string(),
            header_hidden: false,
            sidebar_collapsed: false,
            unsupported_keys: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

/// Resolve the effective GUI theme from the precedence chain.
///
/// Pure — no I/O, no side effects, trivially unit-testable.
///
/// **Precedence:** valid dotfile > tweaks baseline > built-in default.
/// Invalid dotfile values fall through WITH a diagnostic instead of
/// silently to `dark`/`normal`.
///
/// # Parameters
/// - `tweaks` — parsed `tweaks.toml`, or `Tweaks::default()` when missing.
/// - `dotfile_theme` — trimmed content of `~/.neoth/.gui-theme`, or `None`.
/// - `dotfile_density` — parsed density (0/1/2) from `~/.neoth/.gui-density`,
///   or `None` when the file is absent/unparseable.
pub fn resolve_effective_gui_theme(
    tweaks: &Tweaks,
    dotfile_theme: Option<&str>,
    dotfile_density: Option<i32>,
) -> EffectiveGuiTheme {
    let mut e = EffectiveGuiTheme::default();

    // ── color_theme / dark ────────────────────────────────────────────────
    match dotfile_theme {
        Some("dark") => {
            e.dark = true;
            e.dark_source = ThemeSource::Dotfile;
        }
        Some("light") => {
            e.dark = false;
            e.dark_source = ThemeSource::Dotfile;
        }
        Some(s) => {
            // Non-empty but unrecognised → fall through with diagnostic.
            e.diagnostics.push(format!(
                "invalid dotfile theme '{s}'; falling through to tweaks color_theme"
            ));
            resolve_dark_from_tweaks(tweaks, &mut e);
        }
        None => {
            resolve_dark_from_tweaks(tweaks, &mut e);
        }
    }

    // ── density_mode / compact_mode ───────────────────────────────────────
    match dotfile_density {
        Some(v) if (0..=2).contains(&v) => {
            e.density_mode = v;
            e.density_source = ThemeSource::Dotfile;
        }
        Some(v) => {
            e.diagnostics.push(format!(
                "invalid dotfile density {v}; falling through to tweaks compact_mode"
            ));
            resolve_density_from_tweaks(tweaks, &mut e);
        }
        None => {
            resolve_density_from_tweaks(tweaks, &mut e);
        }
    }

    // ── scalar overrides ──────────────────────────────────────────────────
    e.font_family = tweaks.theme.font_family.as_ref().and_then(|value| {
        if value.trim().is_empty() {
            reject_theme_value(&mut e, "font_family", "must not be empty");
            None
        } else {
            Some(value.clone())
        }
    });
    e.font_size_pt = tweaks.theme.font_size_pt.and_then(|value| {
        if value == 0 {
            reject_theme_value(&mut e, "font_size_pt", "must be greater than zero");
            None
        } else {
            Some(value)
        }
    });
    e.sidebar_width_px = tweaks.theme.sidebar_width_px.and_then(|value| {
        if value == 0 {
            reject_theme_value(&mut e, "sidebar_width_px", "must be greater than zero");
            None
        } else {
            Some(value)
        }
    });
    e.input_height_lines = tweaks.theme.input_height_lines.and_then(|value| {
        if value == 0 {
            reject_theme_value(&mut e, "input_height_lines", "must be greater than zero");
            None
        } else {
            Some(value)
        }
    });

    // ── panel_opacity ─────────────────────────────────────────────────────
    if let Some(v) = tweaks.theme.panel_opacity {
        if v.is_finite() && (0.0..=1.0).contains(&v) {
            e.panel_opacity = Some(v);
        } else {
            reject_theme_value(
                &mut e,
                "panel_opacity",
                &format!("{v} is not finite or outside 0.0..=1.0"),
            );
        }
    }

    // ── palette + shape + visibility + motion ─────────────────────────────
    e.accent_color = validate_color_override(&mut e, "accent_color", &tweaks.theme.accent_color);
    e.background_color =
        validate_color_override(&mut e, "background_color", &tweaks.theme.background_color);
    e.foreground_color =
        validate_color_override(&mut e, "foreground_color", &tweaks.theme.foreground_color);
    e.border_radius_px = tweaks.theme.border_radius_px.and_then(|value| {
        if value == 0 {
            reject_theme_value(&mut e, "border_radius_px", "must be at least 1px");
            None
        } else {
            Some(value)
        }
    });
    e.show_token_count = tweaks.theme.show_token_count.unwrap_or(true);
    e.show_model_badge = tweaks.theme.show_model_badge.unwrap_or(false);
    if let Some(value) = tweaks.theme.chat_bubble_style.as_deref() {
        if matches!(value, "rounded" | "square" | "minimal") {
            e.chat_bubble_style = value.to_string();
        } else {
            reject_theme_value(
                &mut e,
                "chat_bubble_style",
                "must be rounded, square, or minimal",
            );
        }
    }
    if let Some(value) = tweaks.theme.animation_speed.as_deref() {
        if matches!(value, "none" | "reduced" | "full") {
            e.animation_speed = value.to_string();
        } else {
            reject_theme_value(&mut e, "animation_speed", "must be none, reduced, or full");
        }
    }
    e.header_hidden = tweaks.theme.header_hidden.unwrap_or(false);
    e.sidebar_collapsed = tweaks.theme.sidebar_collapsed.unwrap_or(false);

    e
}

fn reject_theme_value(e: &mut EffectiveGuiTheme, key: &str, reason: &str) {
    e.unsupported_keys.push(key.to_string());
    e.diagnostics.push(format!(
        "'{key}' rejected before its runtime sink: {reason}"
    ));
}

fn validate_color_override(
    e: &mut EffectiveGuiTheme,
    key: &str,
    value: &Option<String>,
) -> Option<String> {
    let value = value.as_ref()?;
    let hex = value.strip_prefix('#').unwrap_or("");
    if matches!(hex.len(), 3 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(value.clone())
    } else {
        reject_theme_value(e, key, "must use #RGB, #RRGGBB, or #RRGGBBAA");
        None
    }
}

/// Resolve `dark` from `tweaks.color_theme`, falling back to built-in dark.
fn resolve_dark_from_tweaks(tweaks: &Tweaks, e: &mut EffectiveGuiTheme) {
    match tweaks.color_theme.as_deref() {
        Some("light") => {
            e.dark = false;
            e.dark_source = ThemeSource::Tweaks;
        }
        Some("dark") | Some("auto") => {
            e.dark = true;
            e.dark_source = ThemeSource::Tweaks;
        }
        Some(other) => {
            e.diagnostics.push(format!(
                "color_theme '{other}' is not a valid value (light|dark|auto); using built-in dark"
            ));
            e.dark = true;
            e.dark_source = ThemeSource::BuiltIn;
        }
        None => {
            e.dark = true;
            e.dark_source = ThemeSource::BuiltIn;
        }
    }
}

/// Resolve `density_mode` from `tweaks.theme.compact_mode`, falling back to 1 (normal).
fn resolve_density_from_tweaks(tweaks: &Tweaks, e: &mut EffectiveGuiTheme) {
    match tweaks.theme.compact_mode {
        Some(true) => {
            e.density_mode = 0;
            e.density_source = ThemeSource::Tweaks;
        }
        Some(false) => {
            e.density_mode = 1;
            e.density_source = ThemeSource::Tweaks;
        }
        None => {
            e.density_mode = 1;
            e.density_source = ThemeSource::BuiltIn;
        }
    }
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
    fn removed_no_sink_theme_fields_fail_loud() {
        for field in ["icon_set", "scrollbar_style"] {
            let body = format!("[theme]\n{field} = \"legacy\"\n");
            assert!(
                toml::from_str::<Tweaks>(&body).is_err(),
                "removed field {field} must not parse and disappear"
            );
        }
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
        let (m, src) = resolve_effective_model(None, Some("s"), Some("c"), Some("t"), Some("f"));
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
        let (m, src) = resolve_effective_model(
            None,
            None,
            None,
            Some("tweaks-opus"),
            Some("freedom-sonnet"),
        );
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

    // ── B23 — resolve_effective_gui_theme ─────────────────────────────────

    #[test]
    fn b23_dotfile_dark_beats_tweaks_light() {
        let t = Tweaks {
            color_theme: Some("light".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, Some("dark"), None);
        assert!(e.dark, "dotfile dark must win over tweaks light");
        assert_eq!(e.dark_source, ThemeSource::Dotfile);
    }

    #[test]
    fn b23_dotfile_light_beats_tweaks_dark() {
        let t = Tweaks {
            color_theme: Some("dark".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, Some("light"), None);
        assert!(!e.dark, "dotfile light must win over tweaks dark");
        assert_eq!(e.dark_source, ThemeSource::Dotfile);
    }

    #[test]
    fn b23_invalid_dotfile_theme_falls_through_with_diagnostic() {
        let t = Tweaks {
            color_theme: Some("dark".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, Some("solarized"), None);
        assert!(e.dark, "should fall through to tweaks dark");
        assert_eq!(e.dark_source, ThemeSource::Tweaks);
        assert!(
            e.diagnostics.iter().any(|d| d.contains("solarized")),
            "diagnostic must name the invalid value"
        );
    }

    #[test]
    fn b23_tweaks_light_beats_builtin_dark() {
        let t = Tweaks {
            color_theme: Some("light".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(!e.dark);
        assert_eq!(e.dark_source, ThemeSource::Tweaks);
    }

    #[test]
    fn b23_auto_color_theme_resolves_to_dark() {
        let t = Tweaks {
            color_theme: Some("auto".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(e.dark, "auto must resolve to dark");
        assert_eq!(e.dark_source, ThemeSource::Tweaks);
    }

    #[test]
    fn b23_invalid_tweaks_color_theme_falls_to_builtin_dark_with_diagnostic() {
        let t = Tweaks {
            color_theme: Some("matrix".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(e.dark);
        assert_eq!(e.dark_source, ThemeSource::BuiltIn);
        assert!(e.diagnostics.iter().any(|d| d.contains("matrix")));
    }

    #[test]
    fn b23_builtin_defaults_to_dark_normal_when_all_absent() {
        let t = Tweaks::default();
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(e.dark);
        assert_eq!(e.dark_source, ThemeSource::BuiltIn);
        assert_eq!(e.density_mode, 1);
        assert_eq!(e.density_source, ThemeSource::BuiltIn);
        assert!(e.unsupported_keys.is_empty());
        assert!(e.diagnostics.is_empty());
    }

    #[test]
    fn b23_dotfile_density_beats_compact_mode_tweaks() {
        let mut t = Tweaks::default();
        t.theme.compact_mode = Some(true); // would give density=0
        let e = resolve_effective_gui_theme(&t, None, Some(2)); // dotfile=spacious
        assert_eq!(e.density_mode, 2);
        assert_eq!(e.density_source, ThemeSource::Dotfile);
    }

    #[test]
    fn b23_compact_mode_true_gives_density_0() {
        let mut t = Tweaks::default();
        t.theme.compact_mode = Some(true);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.density_mode, 0);
        assert_eq!(e.density_source, ThemeSource::Tweaks);
    }

    #[test]
    fn b23_compact_mode_false_gives_density_1() {
        let mut t = Tweaks::default();
        t.theme.compact_mode = Some(false);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.density_mode, 1);
        assert_eq!(e.density_source, ThemeSource::Tweaks);
    }

    #[test]
    fn b23_invalid_dotfile_density_falls_through_with_diagnostic() {
        let t = Tweaks::default();
        let e = resolve_effective_gui_theme(&t, None, Some(99));
        assert_eq!(e.density_mode, 1, "should fall to built-in normal");
        assert!(
            e.diagnostics
                .iter()
                .any(|d| d.contains("density") && d.contains("99"))
        );
    }

    #[test]
    fn b23_font_family_passthrough() {
        let mut t = Tweaks::default();
        t.theme.font_family = Some("JetBrains Mono".into());
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.font_family.as_deref(), Some("JetBrains Mono"));
    }

    #[test]
    fn b23_font_size_pt_passthrough() {
        let mut t = Tweaks::default();
        t.theme.font_size_pt = Some(16);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.font_size_pt, Some(16));
    }

    #[test]
    fn b23_sidebar_width_px_passthrough() {
        let mut t = Tweaks::default();
        t.theme.sidebar_width_px = Some(320);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.sidebar_width_px, Some(320));
    }

    #[test]
    fn b23_input_height_lines_passthrough() {
        let mut t = Tweaks::default();
        t.theme.input_height_lines = Some(5);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.input_height_lines, Some(5));
    }

    #[test]
    fn b23_panel_opacity_valid_passthrough() {
        let mut t = Tweaks::default();
        t.theme.panel_opacity = Some(0.8);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert_eq!(e.panel_opacity, Some(0.8));
        assert!(!e.unsupported_keys.contains(&"panel_opacity".to_string()));
    }

    #[test]
    fn b23_panel_opacity_nonfinite_rejected_with_diagnostic() {
        let mut t = Tweaks::default();
        t.theme.panel_opacity = Some(f32::INFINITY);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(e.panel_opacity.is_none());
        assert!(e.unsupported_keys.contains(&"panel_opacity".to_string()));
        assert!(e.diagnostics.iter().any(|d| d.contains("panel_opacity")));
    }

    #[test]
    fn b23_panel_opacity_out_of_range_rejected() {
        let mut t = Tweaks::default();
        t.theme.panel_opacity = Some(1.5);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(e.panel_opacity.is_none());
        assert!(e.unsupported_keys.contains(&"panel_opacity".to_string()));
        assert!(
            e.diagnostics
                .iter()
                .any(|d| d.contains("panel_opacity") && d.contains("1.5"))
        );
    }

    #[test]
    fn b23_panel_opacity_zero_and_one_are_valid_boundaries() {
        let mut t = Tweaks::default();
        t.theme.panel_opacity = Some(0.0);
        assert_eq!(
            resolve_effective_gui_theme(&t, None, None).panel_opacity,
            Some(0.0)
        );
        t.theme.panel_opacity = Some(1.0);
        assert_eq!(
            resolve_effective_gui_theme(&t, None, None).panel_opacity,
            Some(1.0)
        );
    }

    #[test]
    fn b23_invalid_active_values_are_rejected_with_diagnostics() {
        let mut t = Tweaks::default();
        t.theme.accent_color = Some("not-a-color".into());
        t.theme.animation_speed = Some("turbo".into());
        t.theme.chat_bubble_style = Some("cloud".into());
        let e = resolve_effective_gui_theme(&t, None, None);
        for key in &["accent_color", "animation_speed", "chat_bubble_style"] {
            assert!(
                e.unsupported_keys.contains(&(*key).to_string()),
                "missing from unsupported_keys: {key}"
            );
            assert!(
                e.diagnostics.iter().any(|d| d.contains(key)),
                "no diagnostic for: {key}"
            );
        }
    }

    #[test]
    fn b23_all_retained_theme_fields_resolve_to_runtime_values() {
        let mut t = Tweaks::default();
        t.theme.accent_color = Some("#123".into());
        t.theme.background_color = Some("#112233".into());
        t.theme.foreground_color = Some("#112233ff".into());
        t.theme.border_radius_px = Some(4);
        t.theme.show_token_count = Some(true);
        t.theme.show_model_badge = Some(true);
        t.theme.chat_bubble_style = Some("minimal".into());
        t.theme.animation_speed = Some("reduced".into());
        t.theme.header_hidden = Some(true);
        t.theme.sidebar_collapsed = Some(true);
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(
            e.unsupported_keys.is_empty(),
            "all retained fields have sinks"
        );
        assert_eq!(e.accent_color.as_deref(), Some("#123"));
        assert_eq!(e.background_color.as_deref(), Some("#112233"));
        assert_eq!(e.foreground_color.as_deref(), Some("#112233ff"));
        assert_eq!(e.border_radius_px, Some(4));
        assert!(e.show_token_count);
        assert!(e.show_model_badge);
        assert_eq!(e.chat_bubble_style, "minimal");
        assert_eq!(e.animation_speed, "reduced");
        assert!(e.header_hidden);
        assert!(e.sidebar_collapsed);
    }

    #[test]
    fn b23_statusline_is_an_active_cli_sink() {
        let t = Tweaks {
            statusline: Some("neoth • {operator}".into()),
            ..Default::default()
        };
        let e = resolve_effective_gui_theme(&t, None, None);
        assert!(!e.unsupported_keys.contains(&"statusline".to_string()));
        assert!(!e.diagnostics.iter().any(|d| d.contains("statusline")));
    }

    #[test]
    fn b23_complete_non_default_fixture_changes_all_supported_fields() {
        let mut t = Tweaks {
            color_theme: Some("light".into()),
            statusline: Some("s".into()),
            ..Default::default()
        };
        t.theme.compact_mode = Some(true);
        t.theme.font_family = Some("Inter".into());
        t.theme.font_size_pt = Some(14);
        t.theme.sidebar_width_px = Some(300);
        t.theme.input_height_lines = Some(4);
        // Dotfile wins for color and density
        let e = resolve_effective_gui_theme(&t, Some("dark"), Some(1));
        assert!(e.dark);
        assert_eq!(e.dark_source, ThemeSource::Dotfile);
        assert_eq!(e.density_mode, 1);
        assert_eq!(e.density_source, ThemeSource::Dotfile);
        assert_eq!(e.font_family.as_deref(), Some("Inter"));
        assert_eq!(e.font_size_pt, Some(14));
        assert_eq!(e.sidebar_width_px, Some(300));
        assert_eq!(e.input_height_lines, Some(4));
    }

    #[test]
    fn b23_support_matrix_covers_all_16_retained_theme_fields_plus_color_and_statusline() {
        let keys: Vec<&str> = THEME_SUPPORT_MATRIX.iter().map(|(k, _)| *k).collect();
        // All retained ThemeConfig fields. icon_set and scrollbar_style were
        // removed because Slint has no honest application-wide sink for them.
        for field in &[
            "accent_color",
            "background_color",
            "foreground_color",
            "font_family",
            "font_size_pt",
            "sidebar_width_px",
            "border_radius_px",
            "compact_mode",
            "show_token_count",
            "show_model_badge",
            "chat_bubble_style",
            "animation_speed",
            "input_height_lines",
            "panel_opacity",
            "header_hidden",
            "sidebar_collapsed",
        ] {
            assert!(
                keys.contains(field),
                "support matrix missing ThemeConfig field: {field}"
            );
        }
        // Top-level theme-surface fields
        assert!(
            keys.contains(&"color_theme"),
            "support matrix missing top-level: color_theme"
        );
        assert!(
            keys.contains(&"statusline"),
            "support matrix missing top-level: statusline"
        );
    }

    #[test]
    fn b23_support_matrix_active_fields_named_correctly() {
        let active: Vec<&str> = THEME_SUPPORT_MATRIX
            .iter()
            .filter(|(_, s)| s.starts_with("active/"))
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(active.len(), THEME_SUPPORT_MATRIX.len());
        assert_eq!(
            active.len(),
            18,
            "16 theme fields + color_theme + statusline"
        );
    }

    #[test]
    fn b23_missing_dotfile_theme_with_no_tweaks_gives_builtin_dark() {
        let e = resolve_effective_gui_theme(&Tweaks::default(), None, None);
        assert!(e.dark);
        assert_eq!(e.dark_source, ThemeSource::BuiltIn);
        assert_eq!(e.density_mode, 1);
        assert!(e.unsupported_keys.is_empty());
        assert!(e.diagnostics.is_empty());
    }
}
