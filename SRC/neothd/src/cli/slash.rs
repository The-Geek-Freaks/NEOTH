//! `neoth slash` — operator visibility into the slash-command set.
//!
//! Same shape as `neoth agents`: lists built-ins + operator overrides from
//! `~/.neoth/commands/*.toml` so operators can discover which `/name args`
//! invocations the chat dispatcher will resolve.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::slash::{builtins, schema::SlashCommand};

#[derive(Args, Debug, Clone)]
pub struct SlashArgs {
    #[command(subcommand)]
    pub action: SlashAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SlashAction {
    /// Print every loaded slash command (built-in + operator-defined),
    /// sorted by name.
    List,
    /// Render a single slash command with its prompt template + help text.
    Show { name: String },
}

pub async fn run_slash(args: SlashArgs) -> Result<()> {
    let dir = FreedomConfig::default_neoth_home().join("commands");
    let operator = crate::slash::loader::load_all(&dir)
        .await
        .with_context(|| format!("load slash commands from {}", dir.display()))?;
    let built = builtins::built_in_commands();
    let merged = merge_with_provenance(&built, &operator);

    match args.action {
        SlashAction::List => render_list(&merged, &args.output),
        SlashAction::Show { name } => render_show(&name, &merged, &args.output),
    }
}

#[derive(Debug)]
struct SlashRow<'a> {
    cmd: &'a SlashCommand,
    source: &'static str,
}

fn merge_with_provenance<'a>(
    built: &'a [SlashCommand],
    operator: &'a [SlashCommand],
) -> Vec<SlashRow<'a>> {
    let mut rows: Vec<SlashRow<'a>> = Vec::new();
    let operator_names: std::collections::HashSet<&str> =
        operator.iter().map(|c| c.name.as_str()).collect();
    for c in built {
        if operator_names.contains(c.name.as_str()) {
            continue;
        }
        rows.push(SlashRow {
            cmd: c,
            source: "builtin",
        });
    }
    for c in operator {
        rows.push(SlashRow {
            cmd: c,
            source: "operator",
        });
    }
    rows.sort_by(|a, b| a.cmd.name.cmp(&b.cmd.name));
    rows
}

fn render_list(rows: &[SlashRow<'_>], output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "count": rows.len(),
                "commands": rows.iter().map(|r| serde_json::json!({
                    "name": r.cmd.name,
                    "source": r.source,
                    "description": r.cmd.description,
                    "enabled": r.cmd.enabled,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# Slash commands\n  (none loaded)");
                return Ok(());
            }
            println!("# Slash commands ({})", rows.len());
            for r in rows {
                let status = if r.cmd.enabled { "ON " } else { "OFF" };
                println!(
                    "  {status}  [{:<8}] /{:<16}  {}",
                    r.source, r.cmd.name, r.cmd.description,
                );
            }
            println!("\n  Invoke any of these by typing `/<name> <args>` in a chat message.");
        }
    }
    Ok(())
}

fn render_show(name: &str, rows: &[SlashRow<'_>], output: &OutputFormat) -> Result<()> {
    let row = rows.iter().find(|r| r.cmd.name == name).ok_or_else(|| {
        let available: Vec<&str> = rows.iter().map(|r| r.cmd.name.as_str()).collect();
        anyhow::anyhow!(
            "no slash command named `/{name}`. Available: {}",
            available.join(", ")
        )
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": row.cmd.name,
                    "source": row.source,
                    "description": row.cmd.description,
                    "prompt": row.cmd.prompt,
                    "help": row.cmd.help,
                    "enabled": row.cmd.enabled,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# /{} [{}]", row.cmd.name, row.source);
            println!("  description: {}", row.cmd.description);
            println!("  enabled:     {}", row.cmd.enabled);
            if let Some(h) = &row.cmd.help {
                println!("  help:        {h}");
            }
            println!("\n  prompt template:");
            for line in row.cmd.prompt.lines() {
                println!("    {line}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(name: &str, desc: &str) -> SlashCommand {
        SlashCommand {
            name: name.into(),
            description: desc.into(),
            prompt: format!("prompt for {name}: {{args}}"),
            action: None,
            help: None,
            enabled: true,
        }
    }

    #[test]
    fn merge_promotes_operator_override() {
        let built = vec![fake("recall", "built-in recall")];
        let operator = vec![fake("recall", "operator override")];
        let rows = merge_with_provenance(&built, &operator);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "operator");
        assert_eq!(rows[0].cmd.description, "operator override");
    }

    #[test]
    fn merge_keeps_both_when_names_differ() {
        let built = vec![fake("help", "built-in help")];
        let operator = vec![fake("status", "operator status")];
        let rows = merge_with_provenance(&built, &operator);
        let names: Vec<_> = rows.iter().map(|r| r.cmd.name.clone()).collect();
        assert_eq!(names, vec!["help", "status"]);
    }

    #[test]
    fn render_show_unknown_name_includes_available_list() {
        let built = vec![fake("help", "h")];
        let rows = merge_with_provenance(&built, &[]);
        let err = render_show("ghost", &rows, &OutputFormat::Json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/ghost"));
        assert!(msg.contains("help"));
    }

    #[test]
    fn render_list_empty_does_not_error() {
        render_list(&[], &OutputFormat::Json).unwrap();
        render_list(&[], &OutputFormat::Table).unwrap();
    }

    #[tokio::test]
    async fn run_slash_list_against_real_builtins_succeeds() {
        let args = SlashArgs {
            action: SlashAction::List,
            output: OutputFormat::Json,
        };
        run_slash(args).await.unwrap();
    }
}
