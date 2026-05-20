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
use crate::tweaks::Tweaks;

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
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "path": path.display().to_string(),
                "loaded": path.exists(),
                "statusline": t.statusline,
                "color_theme": t.color_theme,
                "model_default": t.model_default,
                "persona_override": t.persona_override,
                "prompts": t.prompts.iter().map(|p| serde_json::json!({
                    "id": p.id,
                    "description": p.description,
                })).collect::<Vec<_>>(),
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
            println!("  statusline:        {}", or_default(&t.statusline));
            println!("  color_theme:       {}", or_default(&t.color_theme));
            println!("  model_default:     {}", or_default(&t.model_default));
            println!("  persona_override:  {}", or_default(&t.persona_override));
            if t.prompts.is_empty() {
                println!("  prompts:           (none)");
            } else {
                println!("  prompts:");
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
                prompt: "Good morning, Alex.".into(),
            }],
        }
    }

    #[test]
    fn render_show_includes_persona_override() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tweaks.toml");
        render_show(&fixture(), &path, &OutputFormat::Json).unwrap();
    }

    #[test]
    fn render_show_defaults_when_path_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        let t = Tweaks::default();
        render_show(&t, &path, &OutputFormat::Table).unwrap();
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
