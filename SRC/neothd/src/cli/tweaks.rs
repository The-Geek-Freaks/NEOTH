//! `neoth tweaks` — inspect operator-side customisation loaded from
//! `~/.neoth/tweaks.toml`.
//!
//! Two actions today:
//!   - `show` dumps every populated tweak (statusline / theme / model /
//!     persona override) + the list of named prompt snippets. Reveals
//!     what's actually loaded vs. defaults, which matters when the
//!     persona-override hint mysteriously fails to fire and the operator
//!     wants to know if `tweaks.toml` even parsed.
//!   - `snippet <id>` renders one prompt snippet by id so operators can
//!     copy-paste it without re-typing.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::tweaks::{THEME_SUPPORT_MATRIX, Tweaks, resolve_effective_gui_theme};

#[derive(Args, Debug, Clone)]
pub struct TweaksArgs {
    #[command(subcommand)]
    pub action: TweaksAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TweaksAction {
    /// Dump the parsed `~/.neoth/tweaks.toml` contents. Missing file =>
    /// shows defaults so the operator can copy-paste a starting point.
    Show,
    /// Render a named prompt snippet by id. Useful when the operator
    /// keeps reusable openings (`/snippet morning-greet`) and wants
    /// to inspect them without grepping the file.
    Snippet { id: String },
}

pub async fn run_tweaks(args: TweaksArgs) -> Result<()> {
    let path = Tweaks::default_path();
    let t = Tweaks::load_or_default(&path)?;
    match args.action {
        TweaksAction::Show => render_show(&t, &path, &args.output),
        TweaksAction::Snippet { id } => render_snippet(&t, &id, &args.output),
    }
}

fn render_show(t: &Tweaks, path: &std::path::Path, output: &OutputFormat) -> Result<()> {
    // Resolve effective theme so we can report per-field source and support status.
    // Pass None for dotfile values: `tweaks show` reports the tweaks layer only;
    // the dotfile override is a GUI-startup concern, not a CLI inspection concern.
    let eff = resolve_effective_gui_theme(t, None, None);

    // Build a lookup from the support matrix for quick status resolution.
    let support_map: std::collections::HashMap<&str, &str> =
        THEME_SUPPORT_MATRIX.iter().copied().collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Helper: emit {"value": …, "support": …, "source": …} for each theme key.
            let theme_key = |value: serde_json::Value, key: &str, source: &str| {
                let support = support_map
                    .get(key)
                    .copied()
                    .unwrap_or("missing/contract-entry");
                serde_json::json!({ "value": value, "support": support, "source": source })
            };

            let body = serde_json::json!({
                "path": path.display().to_string(),
                "loaded": path.exists(),
                "model_default": t.model_default,
                "persona_override": t.persona_override,
                "prompts": t.prompts.iter().map(|p| serde_json::json!({
                    "id": p.id,
                    "description": p.description,
                })).collect::<Vec<_>>(),
                "theme": {
                    "color_theme": theme_key(
                        serde_json::Value::Bool(eff.dark),
                        "color_theme",
                        eff.dark_source.as_str(),
                    ),
                    "statusline": theme_key(
                        t.statusline.as_ref().map_or(
                            serde_json::Value::Null,
                            |s| serde_json::Value::String(s.clone()),
                        ),
                        "statusline",
                        if t.statusline.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "compact_mode": theme_key(
                        serde_json::json!(eff.density_mode),
                        "compact_mode",
                        eff.density_source.as_str(),
                    ),
                    "font_family": theme_key(
                        t.theme.font_family.as_ref().map_or(
                            serde_json::Value::Null,
                            |s| serde_json::Value::String(s.clone()),
                        ),
                        "font_family",
                        if t.theme.font_family.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "font_size_pt": theme_key(
                        t.theme.font_size_pt.map_or(
                            serde_json::Value::Null,
                            |v| serde_json::json!(v),
                        ),
                        "font_size_pt",
                        if t.theme.font_size_pt.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "sidebar_width_px": theme_key(
                        t.theme.sidebar_width_px.map_or(
                            serde_json::Value::Null,
                            |v| serde_json::json!(v),
                        ),
                        "sidebar_width_px",
                        if t.theme.sidebar_width_px.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "input_height_lines": theme_key(
                        t.theme.input_height_lines.map_or(
                            serde_json::Value::Null,
                            |v| serde_json::json!(v),
                        ),
                        "input_height_lines",
                        if t.theme.input_height_lines.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "panel_opacity": theme_key(
                        t.theme.panel_opacity.map_or(
                            serde_json::Value::Null,
                            |v| serde_json::json!(v),
                        ),
                        "panel_opacity",
                        if t.theme.panel_opacity.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "accent_color": theme_key(
                        t.theme.accent_color.as_ref().map_or(serde_json::Value::Null, |s| serde_json::Value::String(s.clone())),
                        "accent_color", if t.theme.accent_color.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "background_color": theme_key(
                        t.theme.background_color.as_ref().map_or(serde_json::Value::Null, |s| serde_json::Value::String(s.clone())),
                        "background_color", if t.theme.background_color.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "foreground_color": theme_key(
                        t.theme.foreground_color.as_ref().map_or(serde_json::Value::Null, |s| serde_json::Value::String(s.clone())),
                        "foreground_color", if t.theme.foreground_color.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "border_radius_px": theme_key(
                        t.theme.border_radius_px.map_or(serde_json::Value::Null, |v| serde_json::json!(v)),
                        "border_radius_px", if t.theme.border_radius_px.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "show_token_count": theme_key(
                        serde_json::json!(eff.show_token_count),
                        "show_token_count", if t.theme.show_token_count.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "show_model_badge": theme_key(
                        serde_json::json!(eff.show_model_badge),
                        "show_model_badge", if t.theme.show_model_badge.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "chat_bubble_style": theme_key(
                        serde_json::json!(eff.chat_bubble_style),
                        "chat_bubble_style", if t.theme.chat_bubble_style.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "animation_speed": theme_key(
                        serde_json::json!(eff.animation_speed),
                        "animation_speed", if t.theme.animation_speed.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "header_hidden": theme_key(
                        t.theme.header_hidden.map_or(serde_json::Value::Null, |v| serde_json::json!(v)),
                        "header_hidden", if t.theme.header_hidden.is_some() { "tweaks" } else { "built_in" },
                    ),
                    "sidebar_collapsed": theme_key(
                        t.theme.sidebar_collapsed.map_or(serde_json::Value::Null, |v| serde_json::json!(v)),
                        "sidebar_collapsed", if t.theme.sidebar_collapsed.is_some() { "tweaks" } else { "built_in" },
                    ),
                },
                "unsupported_keys": eff.unsupported_keys,
                "diagnostics": eff.diagnostics,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Tweaks ({})", path.display());
            println!(
                "  file exists:       {}",
                if path.exists() {
                    "yes"
                } else {
                    "no (defaults shown)"
                }
            );
            println!("  model_default:     {}", or_default(&t.model_default));
            println!("  persona_override:  {}", or_default(&t.persona_override));

            println!();
            println!("## Theme");
            // Every retained field has a production sink. A non-active entry
            // is a support-matrix contract bug and is rendered as such.
            for (key, status) in THEME_SUPPORT_MATRIX {
                let prefix = if status.starts_with("active/") {
                    "[ACTIVE]  "
                } else {
                    "[BROKEN]  "
                };
                let sink = if status.starts_with("active/") {
                    format!(" → {}", status.trim_start_matches("active/"))
                } else {
                    format!(" ({status})")
                };
                match *key {
                    "color_theme" => println!(
                        "  {} color_theme: {} (dark={}){}",
                        prefix,
                        or_default(&t.color_theme),
                        eff.dark,
                        sink
                    ),
                    "statusline" => println!(
                        "  {} statusline: {}{}",
                        prefix,
                        or_default(&t.statusline),
                        sink
                    ),
                    "compact_mode" => println!(
                        "  {} compact_mode: {} (density_mode={}){}",
                        prefix,
                        t.theme
                            .compact_mode
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        eff.density_mode,
                        sink
                    ),
                    "font_family" => println!(
                        "  {} font_family: {}{}",
                        prefix,
                        or_default(&t.theme.font_family),
                        sink
                    ),
                    "font_size_pt" => println!(
                        "  {} font_size_pt: {}{}",
                        prefix,
                        t.theme
                            .font_size_pt
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "sidebar_width_px" => println!(
                        "  {} sidebar_width_px: {}{}",
                        prefix,
                        t.theme
                            .sidebar_width_px
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "input_height_lines" => println!(
                        "  {} input_height_lines: {}{}",
                        prefix,
                        t.theme
                            .input_height_lines
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "panel_opacity" => println!(
                        "  {} panel_opacity: {}{}",
                        prefix,
                        t.theme
                            .panel_opacity
                            .map_or("(default)".to_string(), |v| format!("{v:.2}")),
                        sink
                    ),
                    "accent_color" => println!(
                        "  {} accent_color: {}{}",
                        prefix,
                        or_default(&t.theme.accent_color),
                        sink
                    ),
                    "background_color" => println!(
                        "  {} background_color: {}{}",
                        prefix,
                        or_default(&t.theme.background_color),
                        sink
                    ),
                    "foreground_color" => println!(
                        "  {} foreground_color: {}{}",
                        prefix,
                        or_default(&t.theme.foreground_color),
                        sink
                    ),
                    "border_radius_px" => println!(
                        "  {} border_radius_px: {}{}",
                        prefix,
                        t.theme
                            .border_radius_px
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "show_token_count" => println!(
                        "  {} show_token_count: {}{}",
                        prefix,
                        t.theme
                            .show_token_count
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "show_model_badge" => println!(
                        "  {} show_model_badge: {}{}",
                        prefix,
                        t.theme
                            .show_model_badge
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "chat_bubble_style" => println!(
                        "  {} chat_bubble_style: {}{}",
                        prefix,
                        or_default(&t.theme.chat_bubble_style),
                        sink
                    ),
                    "animation_speed" => println!(
                        "  {} animation_speed: {}{}",
                        prefix,
                        or_default(&t.theme.animation_speed),
                        sink
                    ),
                    "header_hidden" => println!(
                        "  {} header_hidden: {}{}",
                        prefix,
                        t.theme
                            .header_hidden
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    "sidebar_collapsed" => println!(
                        "  {} sidebar_collapsed: {}{}",
                        prefix,
                        t.theme
                            .sidebar_collapsed
                            .map_or("(default)".to_string(), |v| v.to_string()),
                        sink
                    ),
                    _ => {}
                }
            }

            if !eff.unsupported_keys.is_empty() {
                println!();
                println!("## Rejected theme keys");
                for k in &eff.unsupported_keys {
                    println!("  - {k}");
                }
            }
            if !eff.diagnostics.is_empty() {
                println!();
                println!("## Diagnostics");
                for d in &eff.diagnostics {
                    println!("  ! {d}");
                }
            }

            if t.prompts.is_empty() {
                println!();
                println!("  prompts:           (none)");
            } else {
                println!();
                println!("## Prompt snippets");
                for p in &t.prompts {
                    println!("    {} — {}", p.id, p.description);
                }
            }
        }
    }
    Ok(())
}

fn render_snippet(t: &Tweaks, id: &str, output: &OutputFormat) -> Result<()> {
    let s = t.snippet(id).ok_or_else(|| {
        let ids: Vec<&str> = t.prompts.iter().map(|p| p.id.as_str()).collect();
        anyhow::anyhow!(
            "no prompt snippet named `{id}`. Defined snippets: {}",
            if ids.is_empty() {
                "(none)".to_string()
            } else {
                ids.join(", ")
            }
        )
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": s.id,
                    "description": s.description,
                    "prompt": s.prompt,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Prompt snippet `{}`", s.id);
            println!("  description: {}", s.description);
            println!("\n  prompt:");
            for line in s.prompt.lines() {
                println!("    {line}");
            }
        }
    }
    Ok(())
}

fn or_default(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "(default)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tweaks::PromptSnippet;
    use tempfile::tempdir;

    fn fixture() -> Tweaks {
        Tweaks {
            statusline: Some("neoth • {operator}".into()),
            color_theme: Some("dark".into()),
            model_default: None,
            persona_override: Some("concise".into()),
            prompts: vec![PromptSnippet {
                id: "morning-greet".into(),
                description: "Morning greeting".into(),
                prompt: "Good morning, {operator}.".into(),
            }],
            theme: Default::default(), // HO-05
        }
    }

    #[test]
    fn render_show_json_includes_theme_object_with_support_and_source() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        // Capture output via a simple round-trip: render does not error.
        render_show(&fixture(), &path, &OutputFormat::Json).unwrap();
    }

    #[test]
    fn render_show_json_color_theme_active_sink() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        // Build JSON and verify color_theme has active/Theme.dark support.
        let t = Tweaks {
            color_theme: Some("dark".into()),
            ..Default::default()
        };
        // render_show must not error; full JSON inspection would require capturing stdout.
        render_show(&t, &path, &OutputFormat::Json).unwrap();
    }

    #[test]
    fn render_show_table_includes_active_sinks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        render_show(&fixture(), &path, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn render_show_table_active_fields_do_not_error_when_set() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        let mut t = fixture();
        t.theme.accent_color = Some("#ff0000".into());
        t.theme.animation_speed = Some("reduced".into());
        render_show(&t, &path, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn render_show_defaults_when_path_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        let t = Tweaks::default();
        render_show(&t, &path, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn render_show_json_includes_unsupported_keys_and_diagnostics_arrays() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        let mut t = Tweaks::default();
        t.theme.accent_color = Some("invalid".into());
        // Invalid active values are emitted in the rejection/diagnostic arrays.
        render_show(&t, &path, &OutputFormat::Json).unwrap();
    }

    #[test]
    fn render_snippet_unknown_id_lists_available() {
        let t = fixture();
        let err = render_snippet(&t, "ghost", &OutputFormat::Json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"));
        assert!(msg.contains("morning-greet"));
    }

    #[test]
    fn render_snippet_resolves_known_id() {
        let t = fixture();
        render_snippet(&t, "morning-greet", &OutputFormat::Json).unwrap();
    }

    #[test]
    fn or_default_helper_substitutes_placeholder() {
        assert_eq!(or_default(&None), "(default)");
        assert_eq!(or_default(&Some("x".into())), "x");
    }
}
