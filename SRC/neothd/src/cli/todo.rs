//! `neoth todo` — TD-01. Operator CLI over the Todoist REST v2 adapter
//! (`tools::todoist`): `list` / `add <content>` / `close <id>`.
//!
//! Token resolution order (first hit wins):
//!   1. `--token <TOKEN>` flag (explicit override)
//!   2. `credentials.yaml::todoist_token` (the configured store)
//!   3. `NEOTH_TODOIST_TOKEN` env var (CI / quick one-off)
//! else a clear error telling the operator where to put it.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::secret::SecretString;
use crate::tools::todoist;

#[derive(Args, Debug, Clone)]
pub struct TodoArgs {
    #[command(subcommand)]
    pub action: TodoAction,
    /// Todoist REST v2 API token. Overrides `credentials.yaml::todoist_token`
    /// and `NEOTH_TODOIST_TOKEN`. Get it from Todoist → Settings →
    /// Integrations → Developer.
    #[arg(long, value_name = "TOKEN", global = true)]
    pub token: Option<String>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TodoAction {
    /// List active (open) tasks.
    List,
    /// Create a task: `neoth todo add "buy milk"`.
    Add {
        /// Task content (the title shown in Todoist).
        content: String,
    },
    /// Close (complete) a task by its Todoist id.
    Close {
        /// Todoist v2 task id (from `neoth todo list`).
        id: String,
    },
}

pub async fn run_todo(args: TodoArgs) -> Result<()> {
    let token = resolve_token(args.token.as_deref())?;
    match &args.action {
        TodoAction::List => {
            let tasks = todoist::list_tasks(&token).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&tasks)?);
                }
                OutputFormat::Table => {
                    if tasks.is_empty() {
                        println!("(no open tasks)");
                        return Ok(());
                    }
                    for t in &tasks {
                        let due = t
                            .due
                            .as_ref()
                            .and_then(|d| d.string.as_deref().or(d.date.as_deref()))
                            .map(|s| format!("  (due {s})"))
                            .unwrap_or_default();
                        println!("{}  {}{}", t.id, t.content, due);
                    }
                }
            }
        }
        TodoAction::Add { content } => {
            let task = todoist::create_task(&token, content).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&task)?);
                }
                OutputFormat::Table => {
                    println!("✓ created #{} — {}", task.id, task.content);
                }
            }
        }
        TodoAction::Close { id } => {
            todoist::close_task(&token, id).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "closed": id, "ok": true }));
                }
                OutputFormat::Table => println!("✓ closed #{id}"),
            }
        }
    }
    Ok(())
}

/// Resolve the Todoist token: `--token` → `credentials.yaml::todoist_token`
/// → `NEOTH_TODOIST_TOKEN`, else a clear error.
fn resolve_token(arg: Option<&str>) -> Result<SecretString> {
    if let Some(t) = arg {
        if !t.is_empty() {
            return Ok(SecretString::from(t));
        }
    }
    // Propagate a corrupt-credentials parse error (load_or_default hard-errors
    // on bad YAML by contract) rather than `unwrap_or_default()`-swallowing it
    // into a misleading "no Todoist token" bail. Mirrors cli::slack.
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;
    if let Some(tok) = creds.todoist_token {
        return Ok(tok);
    }
    if let Ok(env) = std::env::var("NEOTH_TODOIST_TOKEN") {
        if !env.is_empty() {
            return Ok(SecretString::from(env));
        }
    }
    anyhow::bail!(
        "no Todoist token — pass --token <TOKEN>, add `todoist_token` to \
         ~/.neoth/credentials.yaml, or set NEOTH_TODOIST_TOKEN. Get a token from \
         Todoist → Settings → Integrations → Developer."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_token_prefers_explicit_arg() {
        // The explicit --token wins before any creds-file / env lookup, so
        // this is hermetic regardless of the host's ~/.neoth or env.
        let t = resolve_token(Some("arg-token")).expect("arg token");
        assert_eq!(t.expose(), "arg-token");
    }
}
