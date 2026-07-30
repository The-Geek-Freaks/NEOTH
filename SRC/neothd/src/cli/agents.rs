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
//! - `neoth agents show <name>` dumps the full system prompt.
//! - `neoth agents run --agent planner --agent critic "..."` executes a
//!   bounded provider-only fan-out, validates every answer through structured
//!   QA, and persists a private run record.
//! - `neoth agents history [run-id]` lists or re-opens those records.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

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
    /// Run 2-8 independent provider-only agents concurrently. Every candidate
    /// receives a typed QA verdict; --retry-failed permits one correction.
    Run {
        /// Agent name. Repeat once per independent perspective/task.
        #[arg(long = "agent", required = true)]
        agents: Vec<String>,
        /// Operator task sent independently to every selected agent.
        prompt: String,
        /// Bound concurrent provider work. Hard-capped at 4.
        #[arg(long, default_value_t = 4)]
        max_concurrent: usize,
        /// Per-agent wall-clock ceiling, including QA and optional retry.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
        /// Permit exactly one corrected answer after a structured QA Fail.
        #[arg(long)]
        retry_failed: bool,
    },
    /// List private run records, or show one by id.
    History {
        run_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

pub async fn run_agents(args: AgentsArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let agent_dir = home.join("agents");
    match args.action {
        action @ AgentsAction::List | action @ AgentsAction::Show { .. } => {
            let operator = crate::sub_agents::load_operator_definitions(&agent_dir)
                .await
                .with_context(|| format!("load agents from {}", agent_dir.display()))?;
            let built = builtins::built_in_agents();
            let merged = merge_with_provenance(&built, &operator);
            match action {
                AgentsAction::List => render_list(&merged, &args.output),
                AgentsAction::Show { name } => render_show(&name, &merged, &args.output),
                _ => unreachable!(),
            }
        }
        AgentsAction::Run {
            agents,
            prompt,
            max_concurrent,
            timeout_secs,
            retry_failed,
        } => {
            run_fan_out(
                &home,
                &agent_dir,
                agents,
                prompt,
                max_concurrent,
                timeout_secs,
                retry_failed,
                &args.output,
            )
            .await
        }
        AgentsAction::History { run_id, limit } => {
            render_history(&home, run_id.as_deref(), limit, &args.output)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_fan_out(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    agent_names: Vec<String>,
    prompt: String,
    max_concurrent: usize,
    timeout_secs: u64,
    retry_failed: bool,
    output: &OutputFormat,
) -> Result<()> {
    use crate::sub_agents::parallel::dispatch_parallel;
    use crate::sub_agents::runtime::{
        MAX_CONCURRENT, MAX_FAN_OUT, MAX_PROMPT_BYTES, ProviderSubAgentWorker, SubAgentRunRecord,
    };
    use crate::sub_agents::schema::{HandoffPriority, SubAgentRequest};

    if !(2..=MAX_FAN_OUT).contains(&agent_names.len()) {
        anyhow::bail!("fan-out requires 2..={MAX_FAN_OUT} --agent values");
    }
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES {
        anyhow::bail!("prompt must contain 1..={MAX_PROMPT_BYTES} bytes");
    }
    if max_concurrent == 0 || max_concurrent > MAX_CONCURRENT {
        anyhow::bail!("--max-concurrent must be 1..={MAX_CONCURRENT}");
    }
    if !(1..=600).contains(&timeout_secs) {
        anyhow::bail!("--timeout-secs must be 1..=600");
    }
    let unique: HashSet<&str> = agent_names.iter().map(String::as_str).collect();
    if unique.len() != agent_names.len() {
        anyhow::bail!("each --agent must be unique; duplicate work is not independent fan-out");
    }

    let loaded = crate::sub_agents::load_all(agent_dir)
        .await
        .with_context(|| format!("load agents from {}", agent_dir.display()))?;
    let mut selected: Vec<SubAgent> = agent_names
        .iter()
        .map(|name| {
            loaded
                .iter()
                .find(|agent| agent.name == *name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no enabled sub-agent named `{name}`"))
        })
        .collect::<Result<_>>()?;

    let neoth_home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let wal_dir = neoth_home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "sub-agents");
    let (writer, writer_join) = crate::wal::writer::spawn_for_home(segment, neoth_home.clone())
        .context("spawn sub-agent audit WAL writer")?;

    let raw_provider =
        crate::providers::fallback_chain_from_config(&config, &neoth_home, Some(writer.clone()))
            .await
            .context("build sub-agent provider")?;
    canonicalize_agent_models(&config, raw_provider.as_ref(), &mut selected)?;
    let default_model = crate::providers::provider_default_wire_model(raw_provider.as_ref());
    let provider = Arc::new(
        crate::providers::cost_authorization::AuthorizedProvider::from_box(
            raw_provider,
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                config.autonomy_policy(),
                Some(writer.clone()),
                config.tokens.max_per_request,
            ),
            default_model,
            "sub_agents.fan_out",
        ),
    );
    let worker = Arc::new(ProviderSubAgentWorker::new(
        provider,
        selected,
        retry_failed,
        writer.clone(),
    ));

    let now_ns = crate::time::now_unix_ns();
    let run_id = format!("run-{now_ns}-{}", std::process::id());
    let requests = agent_names
        .iter()
        .enumerate()
        .map(|(index, name)| SubAgentRequest {
            from: "cli".into(),
            to: name.clone(),
            phase: "fan_out".into(),
            task_id: format!("{run_id}-{index}"),
            priority: HandoffPriority::Normal,
            context: prompt.clone(),
            deliverable: "A complete, self-contained answer within the named agent's role.".into(),
            success_criteria: vec![
                "Addresses the operator task without inventing tool or external-state evidence."
                    .into(),
                "States missing evidence explicitly instead of fabricating it.".into(),
            ],
            evidence_required: vec![],
            ts_unix: crate::time::now_unix_i64(),
        })
        .collect();

    let dispatch = dispatch_parallel(
        worker,
        requests,
        Some(max_concurrent),
        Some(Duration::from_secs(timeout_secs)),
    )
    .await;
    let record_result = dispatch.and_then(|report| {
        let record = SubAgentRunRecord {
            schema_version: 1,
            run_id: run_id.clone(),
            ts_unix: crate::time::now_unix_i64(),
            prompt_hash_xxh3: xxhash_rust::xxh3::xxh3_64(prompt.as_bytes()),
            results: report.results,
        };
        crate::sub_agents::runtime::persist_run(home, &record).map(|path| (record, path))
    });
    drop(writer);
    let _ = writer_join.await;
    let (record, path) = record_result?;
    render_run(&record, &path, output)
}

/// Agent TOML is a second model-selection surface after `freedom.yaml`.
/// Normalize it before the worker is built so both the primary answer and its
/// QA pass carry the exact same global-alias- and adapter-resolved wire model.
fn canonicalize_agent_models(
    config: &FreedomConfig,
    provider: &dyn crate::providers::Provider,
    agents: &mut [SubAgent],
) -> Result<()> {
    for agent in agents {
        if agent.model.is_some() {
            agent.model = Some(crate::providers::resolve_configured_request_model_for_wire(
                config,
                provider,
                agent.model.as_deref(),
            )?);
        }
    }
    Ok(())
}

fn render_run(
    record: &crate::sub_agents::runtime::SubAgentRunRecord,
    path: &std::path::Path,
    output: &OutputFormat,
) -> Result<()> {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!("{}", serde_json::to_string_pretty(record)?);
        return Ok(());
    }
    println!("# Sub-agent run {}", record.run_id);
    for result in &record.results {
        println!(
            "\n## {} — {} ({} attempt{})",
            result.from,
            verdict_name(&result.verdict),
            result.attempts,
            if result.attempts == 1 { "" } else { "s" }
        );
        println!("{}", result.output);
        match &result.verdict {
            crate::council::qa_verdict::QaVerdict::Fail { failures } => {
                for failure in failures {
                    println!("  QA {}: {}", failure.kind, failure.message);
                }
            }
            crate::council::qa_verdict::QaVerdict::Blocked { reason } => {
                println!("  QA blocked: {reason}");
            }
            crate::council::qa_verdict::QaVerdict::Pass { .. } => {}
        }
        for call in &result.provider_calls {
            println!(
                "  {}#{}: {}/{}",
                call.stage, call.attempt, call.provider, call.wire_model
            );
        }
    }
    println!("\nPrivate record: {}", path.display());
    Ok(())
}

fn render_history(
    home: &std::path::Path,
    run_id: Option<&str>,
    limit: usize,
    output: &OutputFormat,
) -> Result<()> {
    if let Some(run_id) = run_id {
        let record = crate::sub_agents::runtime::load_run(home, run_id)?;
        let path = home.join("sub-agent-runs").join(format!("{run_id}.json"));
        return render_run(&record, &path, output);
    }
    let records = crate::sub_agents::runtime::list_runs(home, limit)?;
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        let summaries: Vec<_> = records
            .iter()
            .map(|record| {
                serde_json::json!({
                    "run_id": record.run_id,
                    "ts_unix": record.ts_unix,
                    "prompt_hash_xxh3": record.prompt_hash_xxh3,
                    "results": record.results.len(),
                    "pass": record.results.iter().filter(|r| r.verdict.is_pass()).count(),
                    "fail": record.results.iter().filter(|r| r.verdict.is_retriable()).count(),
                    "blocked": record.results.iter().filter(|r| r.verdict.is_blocked()).count(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&summaries)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("no sub-agent runs recorded");
        return Ok(());
    }
    for record in records {
        let pass = record
            .results
            .iter()
            .filter(|r| r.verdict.is_pass())
            .count();
        let fail = record
            .results
            .iter()
            .filter(|r| r.verdict.is_retriable())
            .count();
        let blocked = record
            .results
            .iter()
            .filter(|r| r.verdict.is_blocked())
            .count();
        println!(
            "{}  agents={} pass={} fail={} blocked={}",
            record.run_id,
            record.results.len(),
            pass,
            fail,
            blocked
        );
    }
    Ok(())
}

fn verdict_name(verdict: &crate::council::qa_verdict::QaVerdict) -> &'static str {
    match verdict {
        crate::council::qa_verdict::QaVerdict::Pass { .. } => "PASS",
        crate::council::qa_verdict::QaVerdict::Fail { .. } => "FAIL",
        crate::council::qa_verdict::QaVerdict::Blocked { .. } => "BLOCKED",
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

    struct AliasProvider;

    #[async_trait::async_trait]
    impl crate::providers::Provider for AliasProvider {
        fn name(&self) -> &'static str {
            "alias_test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("wire:default")
        }

        fn resolve_model_for_wire(&self, requested_model: &str) -> String {
            if requested_model.starts_with("wire:") {
                requested_model.to_owned()
            } else {
                format!("wire:{requested_model}")
            }
        }
    }

    fn fake(name: &str, desc: &str) -> SubAgent {
        SubAgent {
            name: name.into(),
            description: desc.into(),
            model: None,
            system: format!("system for {name}"),
            tools: vec!["recall".into()],
            disallowed_tools: vec![],
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
    fn agent_models_resolve_global_alias_then_provider_wire_identity() {
        let mut config = FreedomConfig::default();
        config
            .models_aliases
            .insert("@agent".into(), "provider-native".into());
        let mut agents = vec![fake("explicit", "e"), fake("default", "d")];
        agents[0].model = Some("@agent".into());

        canonicalize_agent_models(&config, &AliasProvider, &mut agents).unwrap();

        assert_eq!(agents[0].model.as_deref(), Some("wire:provider-native"));
        assert_eq!(
            agents[1].model, None,
            "unset models inherit the wrapper default"
        );
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
