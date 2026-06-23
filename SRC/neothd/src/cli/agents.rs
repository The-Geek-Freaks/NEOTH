//! `neoth agents` — operator visibility into the sub-agent set.
//!
//! Sub-agents are dispatched via `/agent <name> <body>` in chat. Built-ins
//! live in `sub_agents::builtins::built_in_agents()`; operators override
//! by dropping `~/.neoth/agents/<name>.toml`. Without this CLI, an operator
//! has no way to discover what names they can type. With it:
//!
//! - `neoth agents list` shows every loaded agent grouped by source
//!   (`builtin` / `operator`) with one-line description + model preference
//!   + tool allowlist count.
//! - `neoth agents show <name>` dumps the full system prompt so the
//!   operator sees exactly what behaviour they're invoking.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::sub_agents::{SubAgent, builtins};

#[derive(Args, Debug, Clone)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub action: AgentsAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentsAction {
    /// Print every loaded sub-agent (built-in + operator), sorted by name.
    List,
    /// Dump the full TOML-style record for a single agent including the
    /// system prompt. Useful for reviewing what a name actually does
    /// before typing `/agent <name>`.
    Show { name: String },
}

pub async fn run_agents(args: AgentsArgs) -> Result<()> {
    let agent_dir = FreedomConfig::default_neoth_home().join("agents");
    let operator = crate::sub_agents::load_all(&agent_dir)
        .await
        .with_context(|| format!("load agents from {}", agent_dir.display()))?;
    let built = builtins::built_in_agents();
    // Operator entries override built-ins of the same name. Build a merged
    // view with provenance so `list` can render the source column.
    let merged = merge_with_provenance(&built, &operator);

    match args.action {
        AgentsAction::List => render_list(&merged, &args.output),
        AgentsAction::Show { name } => render_show(&name, &merged, &args.output),
    }
}

#[derive(Debug)]
struct AgentRow<'a> {
    agent: &'a SubAgent,
    source: &'static str,
}

fn merge_with_provenance<'a>(built: &'a [SubAgent], operator: &'a [SubAgent]) -> Vec<AgentRow<'a>> {
    let mut rows: Vec<AgentRow<'a>> = Vec::new();
    let operator_names: std::collections::HashSet<&str> =
        operator.iter().map(|a| a.name.as_str()).collect();
    for a in built {
        if operator_names.contains(a.name.as_str()) {
            // Operator override takes the same name — skip the built-in
            // entry; the operator copy will be added below with source =
            // "operator" so the audit shows what the daemon will run.
            continue;
        }
        rows.push(AgentRow {
            agent: a,
            source: "builtin",
        });
    }
    for a in operator {
        rows.push(AgentRow {
            agent: a,
            source: "operator",
        });
    }
    rows.sort_by(|a, b| a.agent.name.cmp(&b.agent.name));
    rows
}

fn render_list(rows: &[AgentRow<'_>], output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "count": rows.len(),
                "agents": rows.iter().map(|r| serde_json::json!({
                    "name": r.agent.name,
                    "source": r.source,
                    "description": r.agent.description,
                    "model": r.agent.model,
                    "tool_count": r.agent.tools.len(),
                    "enabled": r.agent.enabled,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# Sub-agents\n  (none loaded — built-ins missing? rebuild the binary)");
                return Ok(());
            }
            println!("# Sub-agents ({})", rows.len());
            for r in rows {
                let model = r.agent.model.as_deref().unwrap_or("(default)");
                let status = if r.agent.enabled { "ON " } else { "OFF" };
                println!(
                    "  {status}  [{:<8}] {:<20}  model={:<24} tools={}",
                    r.source,
                    r.agent.name,
                    model,
                    r.agent.tools.len(),
                );
                println!("           {}", r.agent.description);
            }
            println!("\n  Invoke via: /agent <name> <your message>");
        }
    }
    Ok(())
}

fn render_show(name: &str, rows: &[AgentRow<'_>], output: &OutputFormat) -> Result<()> {
    let row = rows.iter().find(|r| r.agent.name == name).ok_or_else(|| {
        let available: Vec<&str> = rows.iter().map(|r| r.agent.name.as_str()).collect();
        anyhow::anyhow!(
            "no sub-agent named `{name}`. Available: {}",
            available.join(", ")
        )
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": row.agent.name,
                    "source": row.source,
                    "description": row.agent.description,
                    "model": row.agent.model,
                    "tools": row.agent.tools,
                    "enabled": row.agent.enabled,
                    "system": row.agent.system,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# {} [{}]", row.agent.name, row.source);
            println!("  description: {}", row.agent.description);
            println!(
                "  model:       {}",
                row.agent.model.as_deref().unwrap_or("(default)")
            );
            println!("  enabled:     {}", row.agent.enabled);
            println!("  tools:       {}", row.agent.tools.join(", "));
            println!("\n  system prompt:");
            for line in row.agent.system.lines() {
                println!("    {line}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(name: &str, desc: &str) -> SubAgent {
        SubAgent {
            name: name.into(),
            description: desc.into(),
            model: None,
            system: format!("system for {name}"),
            tools: vec!["recall".into()],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: false,
            omit_recall: false,
            omit_repo_context: false,
        }
    }

    #[test]
    fn merge_promotes_operator_override() {
        let built = vec![fake("planner", "built-in planner")];
        let operator = vec![fake("planner", "operator override")];
        let rows = merge_with_provenance(&built, &operator);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "operator");
        assert_eq!(rows[0].agent.description, "operator override");
    }

    #[test]
    fn merge_keeps_distinct_names_from_both_sources() {
        let built = vec![fake("planner", "p")];
        let operator = vec![fake("helper", "h")];
        let rows = merge_with_provenance(&built, &operator);
        let names: Vec<_> = rows.iter().map(|r| r.agent.name.clone()).collect();
        assert_eq!(names, vec!["helper", "planner"]);
        // Sorted; helper is operator, planner is builtin
        assert_eq!(rows[0].source, "operator");
        assert_eq!(rows[1].source, "builtin");
    }

    #[test]
    fn render_show_unknown_name_errors_with_available_list() {
        let built = vec![fake("planner", "p")];
        let rows = merge_with_provenance(&built, &[]);
        let err = render_show("ghost", &rows, &OutputFormat::Json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no sub-agent named `ghost`"));
        assert!(msg.contains("planner"));
    }

    #[test]
    fn render_list_empty_does_not_error() {
        render_list(&[], &OutputFormat::Json).unwrap();
        render_list(&[], &OutputFormat::Table).unwrap();
    }

    #[tokio::test]
    async fn run_agents_list_against_real_builtins_succeeds() {
        // Uses the real builtins; only the operator dir is overridden via
        // FreedomConfig::default_neoth_home which we can't redirect from
        // a unit test without exposing more state. The merge path is the
        // load-bearing part and is covered above; this test pings the
        // run_agents entry point to verify it composes.
        let args = AgentsArgs {
            action: AgentsAction::List,
            output: OutputFormat::Json,
        };
        run_agents(args).await.unwrap();
    }
}
