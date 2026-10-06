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
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::sub_agents::{SubAgent, builtins};

#[derive(Clone)]
pub(crate) struct FanOutLeftRoleBinding {
    role: crate::config::inference::HemisphereRole,
    provider: crate::config::inference::InferenceProvider,
    config: Arc<FreedomConfig>,
}

/// Resolve the fixed canonical Left origin before the fan-out opens its WAL.
/// The legacy identity fallback preserves single-provider configurations whose
/// topology leaves the default slot implicit.
pub(crate) fn fan_out_left_role_binding(
    config: Arc<FreedomConfig>,
) -> Result<FanOutLeftRoleBinding> {
    let role = crate::config::inference::HemisphereRole::Left;
    let provider = config
        .inference
        .resolve_role_binding(role)?
        .slot
        .provider
        .or_else(|| config.provider_kind.map(|kind| kind.to_inference()))
        .context("sub-agent Left role has no configured provider identity")?;
    Ok(FanOutLeftRoleBinding {
        role,
        provider,
        config,
    })
}

pub(crate) fn bind_fan_out_left_authorizer(
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    binding: &FanOutLeftRoleBinding,
) -> crate::providers::cost_authorization::ProviderCallAuthorizer {
    authorizer.with_role_dispatch(binding.role, binding.provider, Arc::clone(&binding.config))
}

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
    /// List private run records, show one by id, or export one content-free
    /// unqualified NCT observation with `--nct-baseline`.
    History {
        run_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Export only a content-free, unqualified NCT observation for this
        /// one existing private run. Requires RUN_ID and --output json or jsonl.
        #[arg(long, requires = "run_id")]
        nct_baseline: bool,
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
        AgentsAction::History {
            run_id,
            limit,
            nct_baseline,
        } => render_history(&home, run_id.as_deref(), limit, nct_baseline, &args.output),
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
    run_fan_out_with_provider_factory(
        home,
        agent_dir,
        agent_names,
        prompt,
        max_concurrent,
        timeout_secs,
        retry_failed,
        output,
        |config, home, writer| async move {
            crate::providers::fallback_chain_from_config(&config, &home, Some(writer)).await
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_fan_out_with_provider_factory<F, Fut>(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    agent_names: Vec<String>,
    prompt: String,
    max_concurrent: usize,
    timeout_secs: u64,
    retry_failed: bool,
    output: &OutputFormat,
    provider_factory: F,
) -> Result<()>
where
    F: FnOnce(
            FreedomConfig,
            std::path::PathBuf,
            crate::wal::writer::WalWriterHandle,
        ) -> Fut
        + Send
        + 'static,
    Fut: std::future::Future<Output = Result<Box<dyn crate::providers::Provider>>> + Send + 'static,
{
    use crate::sub_agents::parallel::dispatch_parallel;
    use crate::sub_agents::runtime::{
        MAX_CONCURRENT, MAX_FAN_OUT, MAX_PROMPT_BYTES, ProviderSubAgentWorker, SubAgentRunRecord,
    };
    use crate::sub_agents::schema::{HandoffPriority, SubAgentRequest};

    let home = home.to_path_buf();

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

    let config_path = home.join("freedom.yaml");
    let config = FreedomConfig::load_from_path(&config_path)
        .context("load freedom.yaml — run `neoth init` first")?;
    let left_binding = fan_out_left_role_binding(Arc::new(config.clone()))?;
    let skill_registry_context = fan_out_skill_registry_context(&home, &config_path, &config)
        .await
        .context("capture authority-bound Skill registry for this fan-out run")?;
    // A standalone fan-out can own this home only while no daemon owns its
    // startup lock. Acquire before the first WAL/provider effect and retain the
    // lease until the writer has reached a terminal join on every path.
    let fan_out_lease = crate::daemon::pidfile::acquire_offline_agents_fan_out_interlock(
        &home.join("neothd.pid"),
    )?
    .ok_or_else(|| anyhow::anyhow!(
        "`neoth serve` owns or is acquiring this home — `agents run` cannot construct a concurrent provider or WAL writer; stop the daemon and retry"
    ))?;
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "sub-agents");
    let (writer, writer_completion) =
        crate::wal::writer::spawn_for_home_with_completion(segment, home.clone())
            .context("spawn sub-agent audit WAL writer")?;

    // The supervisor owns both the lease and writer completion. If this CLI
    // future is cancelled, the receiver may disappear but the supervisor still
    // drops every writer owner and boundedly aborts/reaps the real writer before
    // releasing the daemon-startup lock.
    let (mut result_tx, result_rx) = tokio::sync::oneshot::channel::<
        Result<(SubAgentRunRecord, std::path::PathBuf)>,
    >();
    tokio::spawn(async move {
        let _fan_out_lease = fan_out_lease;
        let transaction_result: Result<(SubAgentRunRecord, std::path::PathBuf)> = tokio::select! {
            transaction_result = async {
                let raw_provider =
                    provider_factory(config.clone(), home.clone(), writer.clone())
                        .await
                        .context("build sub-agent provider")?;
                canonicalize_agent_models(&config, raw_provider.as_ref(), &mut selected)?;
                let default_model = crate::providers::provider_default_wire_model(raw_provider.as_ref());
                let authorizer = bind_fan_out_left_authorizer(
                    crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                        config.autonomy_policy(),
                        Some(writer.clone()),
                        config.tokens.max_per_request,
                    ),
                    &left_binding,
                );
                let provider = Arc::new(
                    crate::providers::cost_authorization::AuthorizedProvider::from_box(
                        raw_provider,
                        authorizer,
                        default_model,
                        "sub_agents.fan_out",
                    ),
                );
                let worker = Arc::new(ProviderSubAgentWorker::new(
                    provider,
                    selected,
                    retry_failed,
                    writer.clone(),
                    skill_registry_context,
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
                        deliverable: "A complete, self-contained answer within the named agent's role."
                            .into(),
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
                dispatch.and_then(|report| {
                    let record = SubAgentRunRecord {
                        schema_version: 1,
                        run_id,
                        ts_unix: crate::time::now_unix_i64(),
                        prompt_hash_xxh3: xxhash_rust::xxh3::xxh3_64(prompt.as_bytes()),
                        results: report.results,
                    };
                    crate::sub_agents::runtime::persist_run(home, &record).map(|path| (record, path))
                })
            } => transaction_result,
            _ = result_tx.closed() => Err(anyhow::anyhow!(
                "sub-agent fan-out caller cancelled; abort work before WAL owner cleanup"
            )),
        };
        drop(writer);
        let writer_result = writer_completion
            .wait_bounded(Duration::from_secs(30))
            .await
            .context("finalize sub-agent audit WAL writer");
        let result = match (transaction_result, writer_result) {
            (Ok(record), Ok(())) => Ok(record),
            (Err(transaction_error), Ok(())) => Err(transaction_error),
            (Ok(_), Err(writer_error)) => Err(writer_error),
            (Err(transaction_error), Err(writer_error)) => Err(transaction_error).context(format!(
                "sub-agent fan-out failed and audit WAL finalization also failed: {writer_error:#}"
            )),
        };
        // Make response delivery observe the completed ownership transition:
        // callers cannot receive a terminal result while this lease is held.
        drop(_fan_out_lease);
        let _ = result_tx.send(result);
    });
    let (record, path) = result_rx
        .await
        .context("sub-agent fan-out owner supervisor ended before terminal cleanup")??;
    render_run(&record, &path, output)
}

/// Capture one complete, authority-admitted registry before any fan-out work.
/// The returned typed block is owned by the worker for the life of this run;
/// a later config or authority publication therefore cannot affect retries.
async fn fan_out_skill_registry_context(
    neoth_home: &std::path::Path,
    config_path: &std::path::Path,
    config: &FreedomConfig,
) -> Result<crate::pipeline::RenderedUntrustedContext> {
    let reload = Arc::new(crate::config::reload::ReloadController::new(
        config.clone(),
        config_path.to_path_buf(),
    ));
    let config_epoch = reload.accepted_snapshot().epoch();
    let registry = crate::skills::registry::SkillRegistry::load_with_reload_controller(
        neoth_home.join("skills"),
        Arc::clone(&reload),
    )
    .await
    .context("load exact fan-out Skill registry authority")?;
    let snapshot = registry
        .authority_bound_snapshot_for_epoch(config_epoch)
        .context("acquire authority-bound fan-out Skill snapshot")?;
    let active_files = crate::skills::resolver::active_files_from_env();
    let eval_suppress = config.skills.should_suppress_for_eval();
    crate::skills::resolver::SkillRouteResolver::new(snapshot)
        .retaining(move |_| !eval_suppress)
        .session_registry_context(&active_files)
        .context("render complete fan-out Skill registry context")
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
    nct_baseline: bool,
    output: &OutputFormat,
) -> Result<()> {
    if nct_baseline {
        let run_id = run_id.context("--nct-baseline requires RUN_ID")?;
        if !matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            anyhow::bail!("--nct-baseline requires --output json or --output jsonl");
        }
        let record = crate::sub_agents::runtime::load_run(home, run_id)?;
        return render_nct_baseline_observation(&record, output);
    }
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

#[derive(Serialize)]
struct NctBaselineObservation {
    schema: &'static str,
    purpose: &'static str,
    source_kind: &'static str,
    source_run_id: String,
    source_schema_version: u8,
    source_record_status: &'static str,
    route_qualification_status: &'static str,
    evidence_status: &'static str,
    qualification_status: &'static str,
    request_binding_status: &'static str,
    wal_lifecycle_pairing_status: &'static str,
    config_admission_status: &'static str,
    cost_status: &'static str,
    result_count: usize,
    results: Vec<NctBaselineObservationResult>,
}

#[derive(Serialize)]
struct NctBaselineObservationResult {
    result_index: usize,
    outcome: &'static str,
    attempts: u8,
    provider_leaf_count: usize,
    provider_leaves: Vec<NctBaselineObservationLeaf>,
}

#[derive(Serialize)]
struct NctBaselineObservationLeaf {
    stage: String,
    attempt: u8,
    provider: String,
    wire_model: String,
    measurement_status: &'static str,
    prompt_baseline: Option<NctBaselinePromptBaseline>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NctBaselinePromptBaseline {
    shape: NctBaselinePromptShape,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    completion_latency_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NctBaselinePromptShape {
    prompt_bytes: u64,
    system_bytes: u64,
    context_bytes: u64,
    candidate_bytes: u64,
    qa_failure_bytes: u64,
    repeated_segment_bytes: u64,
    prompt_tokens_upper_bound: u64,
    system_tokens_upper_bound: u64,
    context_tokens_upper_bound: u64,
    candidate_tokens_upper_bound: u64,
    qa_failure_tokens_upper_bound: u64,
    total_request_tokens_upper_bound: u64,
}

fn nct_baseline_observation(
    record: &crate::sub_agents::runtime::SubAgentRunRecord,
) -> Result<NctBaselineObservation> {
    let results = record
        .results
        .iter()
        .enumerate()
        .map(|(result_index, result)| {
            let provider_leaves = result
                .provider_calls
                .iter()
                .map(|call| {
                    let prompt_baseline = call
                        .prompt_baseline
                        .as_ref()
                        .map(|baseline| {
                            serde_json::to_value(baseline)
                                .context("serialize source sub-agent prompt baseline")
                                .and_then(|value| {
                                    serde_json::from_value(value).context(
                                        "validate source sub-agent prompt baseline against NCT whitelist",
                                    )
                                })
                        })
                        .transpose()?;
                    Ok(NctBaselineObservationLeaf {
                        stage: call.stage.clone(),
                        attempt: call.attempt,
                        provider: call.provider.clone(),
                        wire_model: call.wire_model.clone(),
                        measurement_status: if prompt_baseline.is_some() {
                            "present"
                        } else {
                            "missing_in_source_record"
                        },
                        prompt_baseline,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(NctBaselineObservationResult {
                result_index,
                outcome: nct_baseline_outcome(&result.verdict),
                attempts: result.attempts,
                provider_leaf_count: provider_leaves.len(),
                provider_leaves,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NctBaselineObservation {
        schema: "neoth.nct-subagent-observation.v1",
        purpose: "existing_private_subagent_run_content_free_observation",
        source_kind: "private_subagent_run",
        source_run_id: record.run_id.clone(),
        source_schema_version: record.schema_version,
        source_record_status: "validated_existing_private_run",
        route_qualification_status: "unavailable_in_source_record",
        evidence_status: "incomplete_unqualified_observation",
        qualification_status: "not_eligible",
        request_binding_status: "unavailable_in_subagent_run_record",
        wal_lifecycle_pairing_status: "unavailable_in_subagent_run_record",
        config_admission_status: "unavailable_in_subagent_run_record",
        cost_status: "unknown",
        result_count: results.len(),
        results,
    })
}

fn nct_baseline_outcome(verdict: &crate::council::qa_verdict::QaVerdict) -> &'static str {
    match verdict {
        crate::council::qa_verdict::QaVerdict::Pass { .. } => "pass",
        crate::council::qa_verdict::QaVerdict::Fail { .. } => "fail",
        crate::council::qa_verdict::QaVerdict::Blocked { .. } => "blocked",
    }
}

fn render_nct_baseline_observation(
    record: &crate::sub_agents::runtime::SubAgentRunRecord,
    output: &OutputFormat,
) -> Result<()> {
    let observation = nct_baseline_observation(record)?;
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&observation)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&observation)?),
        OutputFormat::Table => {
            anyhow::bail!("--nct-baseline requires --output json or --output jsonl")
        }
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
    use std::path::Path;

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

    struct W2464ControlledProvider {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        blocked_once: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for W2464ControlledProvider {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w2464-controlled-model")
        }

        async fn complete_raw(
            &self,
            request: crate::providers::Request,
            _permit: &crate::providers::ProviderDispatchPermit,
        ) -> Result<crate::providers::Completion> {
            if !self
                .blocked_once
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            let is_qa = request
                .system
                .as_deref()
                .is_some_and(|system| system.contains("strict QA verifier"));
            Ok(crate::providers::Completion {
                text: if is_qa {
                    r#"{"kind":"pass","evidence":["controlled fixture"]}"#.into()
                } else {
                    "controlled fan-out answer".into()
                },
                model: "w2464-controlled-model".into(),
                ..Default::default()
            })
        }
    }
    struct W2464CancellationProvider {
        entered: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for W2464CancellationProvider {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w2464-cancellation-model")
        }

        async fn complete_raw(
            &self,
            _request: crate::providers::Request,
            _permit: &crate::providers::ProviderDispatchPermit,
        ) -> Result<crate::providers::Completion> {
            self.entered.notify_one();
            std::future::pending::<()>().await;
            unreachable!("pending cancellation provider must be cancelled by owner supervisor")
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

    async fn write_installed_skill(home: &Path, id: &str, enabled: bool) {
        let dir = home.join("skills").join(id);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("skill.yaml"),
            format!(
                "id: {id}\ndescription: {id} registry fixture\nsystem_prompt: {id} body\ntrigger_keywords: [{id}]\nenabled: {enabled}\n"
            ),
        )
        .await
        .unwrap();
    }

    fn activate_installed_skill(
        home: &Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
    ) {
        let current =
            crate::skills::installer::inspect_current_install(&home.join("skills"), id).unwrap();
        crate::skills::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            crate::skills::installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
        let decision = crate::skills::authority::SkillAuthorityDecision::new(
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
            crate::skills::authority::SkillAuthorityState::Active,
            None,
        )
        .unwrap();
        crate::skills::authority::publish_installed_authority_decision(home, id, reload, decision)
            .unwrap();
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
    async fn fan_out_registry_admits_only_enabled_skills_and_suppresses_eval() {
        let home = tempfile::tempdir().unwrap();
        let config_path = home.path().join("fan-out-freedom.yaml");
        let config = FreedomConfig::default();
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        write_installed_skill(home.path(), "fan-out-ready", true).await;
        write_installed_skill(home.path(), "fan-out-disabled", true).await;
        crate::skills::authority::initialize_authority_key_for_test(home.path()).unwrap();
        let reload =
            crate::config::reload::ReloadController::new(config.clone(), config_path.clone());
        activate_installed_skill(home.path(), "fan-out-ready", &reload);
        activate_installed_skill(home.path(), "fan-out-disabled", &reload);

        let mut disabled_config = config.clone();
        disabled_config
            .skills
            .disabled
            .push("fan-out-disabled".to_string());
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&disabled_config).unwrap(),
        )
        .unwrap();
        let admitted = fan_out_skill_registry_context(home.path(), &config_path, &disabled_config)
            .await
            .unwrap();
        assert!(admitted.as_str().contains("fan-out-ready"));
        assert!(!admitted.as_str().contains("fan-out-disabled"));

        let mut eval_config = disabled_config;
        eval_config.skills.disabled_for_eval_sessions = true;
        eval_config.skills.eval_session_active = true;
        std::fs::write(&config_path, serde_yaml::to_string(&eval_config).unwrap()).unwrap();
        let suppressed = fan_out_skill_registry_context(home.path(), &config_path, &eval_config)
            .await
            .unwrap();
        assert!(!suppressed.as_str().contains("fan-out-ready"));
        assert!(!suppressed.as_str().contains("fan-out-disabled"));
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

    #[tokio::test]
    async fn w2464_live_daemon_rejects_real_fan_out_before_provider_or_wal() {
        let home = tempfile::tempdir().expect("fan-out home");
        let agent_dir = home.path().join("agents");
        std::fs::create_dir(&agent_dir).expect("agent directory");
        let config = FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::LocalOllama),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize fan-out config"),
        )
        .expect("write fan-out config");
        let daemon = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("live daemon owner");

        let error = run_fan_out(
            home.path(),
            &agent_dir,
            vec!["planner".into(), "critic".into()],
            "bounded fan-out ownership fixture".into(),
            2,
            1,
            false,
            &OutputFormat::Json,
        )
        .await
        .expect_err("live daemon must reject the real fan-out consumer");
        assert!(
            error.to_string().contains("`neoth serve` owns or is acquiring this home"),
            "unexpected owner refusal: {error:#}"
        );
        assert!(
            !home.path().join("wal").exists(),
            "live-owner refusal must happen before any fan-out WAL mutation"
        );
        assert!(
            !home.path().join("sub-agent-runs").exists(),
            "live-owner refusal must happen before fan-out persistence"
        );
        drop(daemon);
    }
    #[tokio::test]
    async fn w2464_offline_real_fan_out_finalizes_writer_before_owner_release() {
        let home = tempfile::tempdir().expect("fan-out home");
        let agent_dir = home.path().join("agents");
        std::fs::create_dir(&agent_dir).expect("agent directory");
        let config = FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::ClaudeCli),
            provider_binary: Some("neoth-w2464-intentionally-missing-provider".into()),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize fan-out config"),
        )
        .expect("write fan-out config");

        let error = run_fan_out(
            home.path(),
            &agent_dir,
            vec!["planner".into(), "critic".into()],
            "bounded fan-out writer-finalization fixture".into(),
            2,
            1,
            false,
            &OutputFormat::Json,
        )
        .await
        .expect_err("missing fixture provider must terminally fail the real fan-out");
        assert!(
            !home.path().join("sub-agent-runs").exists(),
            "failed fan-out must not persist a successful run record: {error:#}"
        );
        assert!(
            home.path().join("wal").exists(),
            "offline fan-out must have opened its real isolated WAL writer"
        );
        let daemon = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("fan-out return must wait for writer join before releasing owner");
        drop(daemon);
    }
    #[tokio::test]
    async fn w2464_controlled_real_fan_out_blocks_daemon_until_terminal_writer_cleanup() {
        let home = tempfile::tempdir().expect("fan-out home");
        let agent_dir = home.path().join("agents");
        std::fs::create_dir(&agent_dir).expect("agent directory");
        let config = FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::LocalOllama),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize controlled config"),
        )
        .expect("write controlled config");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let task_home = home.path().to_path_buf();
        let task_agents = agent_dir.clone();
        let task_entered = Arc::clone(&entered);
        let task_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            let output = OutputFormat::Json;
            run_fan_out_with_provider_factory(
                &task_home,
                &task_agents,
                vec!["planner".into(), "critic".into()],
                "controlled successful fan-out".into(),
                2,
                30,
                false,
                &output,
                move |_, _, _| async move {
                    Ok(Box::new(W2464ControlledProvider {
                        entered: task_entered,
                        release: task_release,
                        blocked_once: std::sync::atomic::AtomicBool::new(false),
                    }) as Box<dyn crate::providers::Provider>)
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("real fan-out must reach controlled provider before contender probe");

        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("daemon::pidfile::tests::w2464_agents_fan_out_interlock_child_daemon_start")
            .env("NEOTH_W2464_AGENTS_FAN_OUT_PIDFILE", home.path().join("neothd.pid"))
            .output()
            .expect("cross-process daemon contender");
        assert!(
            child.status.success(),
            "running fan-out must retain its real lease; stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        release.notify_waiters();
        task.await
            .expect("controlled real fan-out task join")
            .expect("controlled real fan-out success");
        assert!(
            home.path().join("sub-agent-runs").exists(),
            "successful controlled fan-out must persist its run only after dispatch"
        );
        let daemon = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid"))
            .expect("daemon may acquire only after terminal writer cleanup");
        drop(daemon);
    }
    #[tokio::test]
    async fn w2464_cancelled_real_fan_out_retains_lease_until_retained_writer_clone_releases() {
        let home = tempfile::tempdir().expect("fan-out home");
        let agent_dir = home.path().join("agents");
        std::fs::create_dir(&agent_dir).expect("agent directory");
        let config = FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::LocalOllama),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize cancellation config"),
        )
        .expect("write cancellation config");
        let entered = Arc::new(tokio::sync::Notify::new());
        let task_entered = Arc::clone(&entered);
        let (writer_tx, writer_rx) = tokio::sync::oneshot::channel();
        let task_home = home.path().to_path_buf();
        let task_agents = agent_dir.clone();
        let task = tokio::spawn(async move {
            let output = OutputFormat::Json;
            run_fan_out_with_provider_factory(
                &task_home,
                &task_agents,
                vec!["planner".into(), "critic".into()],
                "controlled cancellation fan-out".into(),
                2,
                30,
                false,
                &output,
                move |_, _, writer| {
                    writer_tx
                        .send(writer)
                        .expect("hand real writer clone to cancellation fixture");
                    async move {
                        Ok(Box::new(W2464CancellationProvider {
                            entered: task_entered,
                        }) as Box<dyn crate::providers::Provider>)
                    }
                },
            )
            .await
        });
        let retained_writer = tokio::time::timeout(Duration::from_secs(5), writer_rx)
            .await
            .expect("factory must receive real writer clone")
            .expect("factory must retain real writer clone");
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("real fan-out must reach cancellation provider");
        task.abort();
        let _ = task.await;

        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("daemon::pidfile::tests::w2464_agents_fan_out_interlock_child_daemon_start")
            .env("NEOTH_W2464_AGENTS_FAN_OUT_PIDFILE", home.path().join("neothd.pid"))
            .output()
            .expect("cross-process contender after caller cancellation");
        assert!(
            child.status.success(),
            "retained writer clone must keep the actual fan-out lease through caller cancellation; stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        drop(retained_writer);
        let pidfile = home.path().join("neothd.pid");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match crate::daemon::pidfile::acquire(&pidfile) {
                    Ok(daemon) => {
                        drop(daemon);
                        break;
                    }
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("writer completion must release daemon startup only after retained clone drops");
    }
    fn write_nct_observation_source_run(home: &Path, run_id: &str) {
        let dir = home.join("sub-agent-runs");
        std::fs::create_dir_all(&dir).unwrap();
        let record = r#"{
  "schema_version": 1,
  "run_id": "run-nct-observation",
  "ts_unix": 1700000000,
  "prompt_hash_xxh3": 99,
  "results": [{
    "from": "private-agent-name",
    "to": "private-recipient",
    "task_id": "NCT_PRIVATE_TASK_ID",
    "verdict": {"kind": "pass", "evidence": ["NCT_PRIVATE_QA_EVIDENCE"]},
    "evidence": ["NCT_PRIVATE_RESULT_EVIDENCE"],
    "output": "NCT_PRIVATE_OUTPUT_AND_PROVIDER_ERROR",
    "provider_calls": [
      {
        "stage": "primary", "attempt": 1, "provider": "openai_api", "wire_model": "wire-model-v1",
        "input_tokens": 0, "output_tokens": null,
        "prompt_baseline": {
          "shape": {
            "prompt_bytes": 11, "system_bytes": 22, "context_bytes": 33,
            "candidate_bytes": 0, "qa_failure_bytes": 0, "repeated_segment_bytes": 0,
            "prompt_tokens_upper_bound": 11, "system_tokens_upper_bound": 22,
            "context_tokens_upper_bound": 33, "candidate_tokens_upper_bound": 0,
            "qa_failure_tokens_upper_bound": 0, "total_request_tokens_upper_bound": 33
          },
          "input_tokens": 0, "output_tokens": null,
          "cache_creation_tokens": 0, "cache_read_tokens": null, "completion_latency_ms": 0
        }
      },
      {
        "stage": "qa", "attempt": 1, "provider": "openai_api", "wire_model": "wire-model-v1",
        "input_tokens": 4, "output_tokens": 2,
        "prompt_baseline": {
          "shape": {
            "prompt_bytes": 44, "system_bytes": 55, "context_bytes": 33,
            "candidate_bytes": 10, "qa_failure_bytes": 0, "repeated_segment_bytes": 43,
            "prompt_tokens_upper_bound": 44, "system_tokens_upper_bound": 55,
            "context_tokens_upper_bound": 33, "candidate_tokens_upper_bound": 10,
            "qa_failure_tokens_upper_bound": 0, "total_request_tokens_upper_bound": 99
          },
          "input_tokens": 4, "output_tokens": 2,
          "cache_creation_tokens": null, "cache_read_tokens": 0, "completion_latency_ms": 7
        }
      },
      {
        "stage": "primary", "attempt": 2, "provider": "openai_api", "wire_model": "wire-model-v1",
        "input_tokens": null, "output_tokens": null, "prompt_baseline": null
      }
    ],
    "attempts": 2,
    "next_agent": "NCT_PRIVATE_NEXT_AGENT",
    "ts_unix": 1700000001
  }]
}"#;
        let record = record.replace("run-nct-observation", run_id);
        std::fs::write(dir.join(format!("{run_id}.json")), record).unwrap();
    }

    #[test]
    fn nct_baseline_flag_requires_a_history_run_id_at_clap_boundary() {
        use clap::Parser;

        let error = <crate::cli::Cli as Parser>::try_parse_from([
            "neoth",
            "--output",
            "json",
            "agents",
            "history",
            "--nct-baseline",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("--nct-baseline"));
    }

    #[test]
    fn nct_baseline_projection_uses_validated_private_run_and_excludes_private_content() {
        let home = tempfile::tempdir().unwrap();
        let run_id = "run-nct-observation";
        write_nct_observation_source_run(home.path(), run_id);

        let record = crate::sub_agents::runtime::load_run(home.path(), run_id).unwrap();
        let observation = nct_baseline_observation(&record).unwrap();
        let serialized = serde_json::to_string(&observation).unwrap();

        assert_eq!(observation.source_run_id, run_id);
        assert_eq!(
            observation.route_qualification_status,
            "unavailable_in_source_record"
        );
        assert_eq!(
            observation.evidence_status,
            "incomplete_unqualified_observation"
        );
        assert_eq!(observation.qualification_status, "not_eligible");
        assert_eq!(observation.cost_status, "unknown");
        let leaves = &observation.results[0].provider_leaves;
        assert_eq!(leaves.len(), 3);
        assert_eq!(
            leaves
                .iter()
                .map(|leaf| leaf.stage.as_str())
                .collect::<Vec<_>>(),
            vec!["primary", "qa", "primary"]
        );
        assert_eq!(
            leaves.iter().map(|leaf| leaf.attempt).collect::<Vec<_>>(),
            vec![1, 1, 2]
        );
        let primary = leaves[0].prompt_baseline.as_ref().unwrap();
        assert_eq!(primary.input_tokens, Some(0));
        assert_eq!(primary.output_tokens, None);
        assert_eq!(primary.cache_creation_tokens, Some(0));
        assert_eq!(primary.cache_read_tokens, None);
        assert_eq!(primary.completion_latency_ms, 0);
        assert_eq!(leaves[2].measurement_status, "missing_in_source_record");
        assert!(leaves[2].prompt_baseline.is_none());
        for private_fragment in [
            "NCT_PRIVATE_TASK_ID",
            "NCT_PRIVATE_QA_EVIDENCE",
            "NCT_PRIVATE_RESULT_EVIDENCE",
            "NCT_PRIVATE_OUTPUT_AND_PROVIDER_ERROR",
            "NCT_PRIVATE_NEXT_AGENT",
            "private-agent-name",
            "private-recipient",
            "prompt_hash_xxh3",
        ] {
            assert!(
                !serialized.contains(private_fragment),
                "leaked {private_fragment}"
            );
        }
    }

    #[test]
    fn nct_baseline_rejects_table_before_private_run_read_and_uses_history_renderer_path() {
        let missing = tempfile::tempdir().unwrap();
        let error = render_history(
            missing.path(),
            Some("run-missing"),
            20,
            true,
            &OutputFormat::Table,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--output json or --output jsonl")
        );

        let home = tempfile::tempdir().unwrap();
        let run_id = "run-nct-render";
        write_nct_observation_source_run(home.path(), run_id);
        render_history(home.path(), Some(run_id), 20, true, &OutputFormat::Json).unwrap();
    }
}
