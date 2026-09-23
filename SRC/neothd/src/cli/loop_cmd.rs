//! `neoth loop` — GOLD-LOOP-02/04/07: the standalone CLI surface of the
//! GOLD-LOOP-01 loop engine.
//!
//! `neoth chat --loop` (the chat-embedded entry point) stays untouched —
//! this command drives the same `loop_engine::run_loop` directly with its
//! own provider/MCP/WAL plumbing, plus the run-history reader over the
//! `~/.neoth/loops/` records the engine already writes.
//!
//! Autonomy: `--level l1|l2|l3` maps through [`LoopAutonomyLevel`]
//! (L1=Standard, L2=Elevated, L3=Full); L3 refuses to run without
//! `--budget` (GOLD-LOOP-05 gate — the most autonomous mode must carry a
//! hard tool-call cap).

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use tracing::warn;

use crate::cli::OutputFormat;
use crate::config::inference::HemisphereRole;
use crate::config::FreedomConfig;
use crate::loop_engine::{LoopAutonomyLevel, LoopRunRecord};

#[derive(Args, Debug, Clone)]
pub struct LoopArgs {
    #[command(subcommand)]
    pub action: LoopAction,

    /// Populated from the global `--output` flag by `cli::run`.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LoopAction {
    /// Run a multi-round autonomous loop on a prompt.
    Run(LoopRunArgs),
    /// List past loop runs (from `~/.neoth/loops/`).
    History,
    /// Show one loop-run record by id (unique prefix accepted).
    Show {
        /// The loop id (or a unique prefix of it) as shown by `history`.
        id: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct LoopRunArgs {
    /// The task prompt the loop iterates on.
    #[arg(value_name = "PROMPT")]
    pub prompt: String,

    /// Max outer rounds (default: freedom.yaml `loop.max_rounds`).
    #[arg(long, short = 'n')]
    pub iterations: Option<u32>,

    /// Structural stop criterion (repeatable) — the stop verifier gates
    /// convergence on these at L2+.
    #[arg(long)]
    pub until: Vec<String>,

    /// Enable the self-reflect critique/refine pass each round (L2+).
    #[arg(long)]
    pub critique: bool,

    /// Cumulative tool-call budget across all rounds (MANDATORY at l3).
    #[arg(long)]
    pub budget: Option<u64>,

    /// Loop autonomy level: l1 (bounded iterate), l2 (verifier + refine),
    /// l3 (full — requires --budget). Default: the session autonomy.
    #[arg(long)]
    pub level: Option<String>,
}

pub async fn run_loop_cmd(args: LoopArgs) -> Result<()> {
    let loops_dir = FreedomConfig::default_neoth_home().join("loops");
    match args.action {
        LoopAction::History => {
            print!(
                "{}",
                render_history(&load_records(&loops_dir)?, args.output)?
            );
            Ok(())
        }
        LoopAction::Show { id } => {
            let records = load_records(&loops_dir)?;
            let matches: Vec<&LoopRunRecord> = records
                .iter()
                .filter(|r| r.loop_id.starts_with(&id))
                .collect();
            match matches.as_slice() {
                [one] => {
                    print!("{}", render_record(one, args.output)?);
                    Ok(())
                }
                [] => anyhow::bail!(
                    "no loop run matches `{id}` — `neoth loop history` lists known ids"
                ),
                many => anyhow::bail!(
                    "`{id}` is ambiguous — {} runs match (give more of the id)",
                    many.len()
                ),
            }
        }
        LoopAction::Run(run) => run_loop_run(run, args.output).await,
    }
}

async fn run_loop_run(args: LoopRunArgs, output: OutputFormat) -> Result<()> {
    if args.prompt.trim().is_empty() {
        anyhow::bail!("neoth loop run: prompt is empty — nothing to iterate on");
    }
    let neoth_home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;

    // GOLD-LOOP-04 — named ladder; GOLD-LOOP-05 — L3 requires a budget.
    let level = match args.level.as_deref() {
        Some(s) => Some(
            LoopAutonomyLevel::parse(s)
                .ok_or_else(|| anyhow::anyhow!("--level `{s}` is not one of l1 / l2 / l3"))?,
        ),
        None => None,
    };
    let budget = args.budget.or(config.loop_config.tool_call_budget);
    if let Some(level) = level {
        level
            .validate_budget(budget)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    let autonomy = level
        .map(LoopAutonomyLevel::to_autonomy_level)
        .unwrap_or(config.autonomy);

    let loop_cfg = crate::loop_engine::engine::LoopConfig {
        min_rounds: 1,
        max_rounds: args
            .iterations
            .unwrap_or(config.loop_config.max_rounds)
            .max(1),
        until: args.until,
        tool_call_budget: budget,
        autonomy,
        refine_enabled: args.critique || config.loop_config.refine_enabled,
        neoth_home: neoth_home.clone(),
    };

    // Single-writer guard: a running daemon owns the WAL segment — a second
    // appender from this process could interleave frame bytes (open_segment
    // is create+append, no exclusivity lock). This NEW command refuses
    // loudly instead of inheriting the dual-writer exposure.
    let pidfile = neoth_home.join("neothd.pid");
    if let Ok(Some(pid)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        anyhow::bail!(
            "neoth serve (pid {pid}) is running and owns the WAL segment — run \
             loops through the daemon (a `loop: true` skill via a channel, or \
             `neoth chat --loop`), or stop the daemon first"
        );
    }

    // Same plumbing trio as the chat path: fallback-chain provider, the
    // operator's MCP server set, and a home-bound standalone WAL writer.
    let provider = crate::providers::fallback_chain_from_config(&config, &neoth_home, None)
        .await
        .context("resolve provider chain")?;
    let mcp_path = neoth_home.join("mcp_servers.yaml");
    let servers = crate::mcp::config::McpServers::load_from(&mcp_path)
        .with_context(|| format!("load MCP server config {}", mcp_path.display()))?;
    let wal_dir = neoth_home.join("wal");
    let segment_path = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "loop");
    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
    }
    let (writer, writer_join) =
        crate::wal::writer::spawn_for_home(segment_path, neoth_home.clone())
            .context("spawn WAL writer")?;
    let provider_policy =
        crate::permissions::AutonomyPolicySnapshot::new(autonomy, &config.custom_autonomy);
    let left_provider = standalone_loop_left_provider(&config)?;
    let provider_call_authorizer =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            provider_policy,
            Some(writer.clone()),
            config.tokens.max_per_request,
        );
    let provider_call_authorizer =
        bind_standalone_loop_left_authorizer(provider_call_authorizer, &config, left_provider);

    let req = match standalone_loop_enriched_request(&config, &neoth_home, &writer, &args.prompt)
        .await
    {
        Ok(request) => request,
        Err(error) => {
            drop(writer);
            return match writer_join.await {
                Ok(()) => Err(error),
                Err(join_error) => Err(error.context(format!(
                    "standalone loop Skill setup failed and WAL writer join also failed: {join_error}"
                ))),
            };
        }
    };
    let elicitation = if config.elicitation.enabled {
        crate::cli::elicitation::ElicitationHandler::Cli
    } else {
        crate::cli::elicitation::ElicitationHandler::Disabled
    };
    let tool_scope = crate::mcp::McpToolScope::default();

    eprintln!(
        "loop: rounds≤{} autonomy={} budget={} critique={}",
        loop_cfg.max_rounds,
        loop_cfg.autonomy.as_str(),
        loop_cfg
            .tool_call_budget
            .map(|b| b.to_string())
            .unwrap_or_else(|| "none".into()),
        loop_cfg.refine_enabled,
    );
    let result = crate::loop_engine::run_loop(
        &loop_cfg,
        provider.as_ref(),
        req,
        &servers,
        &writer,
        &config,
        provider_call_authorizer,
        None,
        &tool_scope,
        &elicitation,
        None,
    )
    .await;

    if let Ok(record) = result.as_ref() {
        crate::cli::chat::emit_terminal_goal_outcome(
            &writer,
            // This standalone command never admitted a chat/channel turn.
            None,
            record.goal_outcome,
            record.goal_hash.as_deref(),
            "loop_cmd",
        )
        .await;
    }
    drop(writer);
    let _ = writer_join.await;

    let record = result?;
    print!("{}", render_record(&record, output)?);
    Ok(())
}

/// `fallback_chain_from_config` above starts from the canonical Left role.
/// The generic loop engine has no role origin, so retain that caller-selected
/// identity in its authorizer rather than teaching the engine to infer one.
fn standalone_loop_left_provider(
    config: &FreedomConfig,
) -> Result<crate::config::inference::InferenceProvider> {
    config
        .inference
        .slot_for(HemisphereRole::Left)
        .provider
        .or_else(|| config.provider_kind.map(|kind| kind.to_inference()))
        .ok_or_else(|| anyhow::anyhow!("standalone loop Left fallback chain has no configured provider identity"))
}

fn bind_standalone_loop_left_authorizer(
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    config: &FreedomConfig,
    left_provider: crate::config::inference::InferenceProvider,
) -> crate::providers::cost_authorization::ProviderCallAuthorizer {
    authorizer.with_role_dispatch(
        HemisphereRole::Left,
        left_provider,
        std::sync::Arc::new(config.clone()),
    )
}

/// Build the one request a standalone loop may reuse for all of its rounds.
/// This owns the session-start Skill publication boundary: callers cannot
/// rebuild a registry inside the engine's round/retry path.
async fn standalone_loop_enriched_request(
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
    prompt: &str,
) -> Result<crate::providers::Request> {
    // A standalone loop is an authenticated local-operator session too. Load
    // one compound config/authority Skill snapshot and render its filtered
    // inventory before the first provider request. `run_loop` clones this
    // request for later rounds, so retries and rounds retain these exact bytes
    // rather than observing a newer registry generation.
    let skills_dir = neoth_home.join("skills");
    let reload = std::sync::Arc::new(crate::config::reload::ReloadController::new(
        config.clone(),
        neoth_home.join("freedom.yaml"),
    ));
    let config_epoch = reload.accepted_snapshot().epoch();
    let registry = crate::skills::SkillRegistry::load_with_reload_controller(
        &skills_dir,
        std::sync::Arc::clone(&reload),
    )
    .await
    .with_context(|| format!("load loop skill registry from {}", skills_dir.display()))?;
    let skill_snapshot = registry
        .authority_bound_snapshot_for_epoch(config_epoch)
        .context("acquire authority-bound standalone loop Skill snapshot")?;
    let raw_installed_skills = skill_snapshot.skills();
    let mut blocked_skill_ids = std::collections::BTreeSet::<String>::new();
    if !config.skills.pinned_hashes.is_empty() {
        let verdicts = crate::skills::versioning::check_pinned_hashes(
            raw_installed_skills
                .iter()
                .map(|skill| (skill.id(), skill.content_hash.as_str())),
            &config.skills.pinned_hashes,
        );
        for (skill, verdict) in raw_installed_skills.iter().zip(verdicts.iter()) {
            if matches!(
                verdict.verdict,
                crate::skills::versioning::PinnedHashOutcome::Mismatch
            ) {
                blocked_skill_ids.insert(skill.id().to_owned());
                let payload = serde_json::to_vec(&serde_json::json!({
                    "skill_id": verdict.skill_id,
                    "content_hash": verdict.actual_hash,
                    "expected_hash": verdict.expected_hash,
                    "reason": crate::skills::versioning::SkillSkipReason::HashMismatch.as_str(),
                    "ts_unix": crate::time::now_unix_secs(),
                }))
                .unwrap_or_default();
                let header = crate::wal::make_header(
                    crate::wal::events::EVENT_TYPE_SKILL_INJECT_SKIPPED,
                    &payload,
                );
                if let Err(error) = writer.append(header, payload).await {
                    warn!(
                        skill = %verdict.skill_id,
                        error = %error,
                        "SKILL_INJECT_SKIPPED (hash_mismatch) emit failed (non-fatal)"
                    );
                }
            }
        }
    }
    let eval_suppress = config.skills.should_suppress_for_eval();
    if eval_suppress {
        for skill in raw_installed_skills
            .iter()
            .filter(|skill| skill.manifest.enabled && !blocked_skill_ids.contains(skill.id()))
        {
            let payload = serde_json::to_vec(&serde_json::json!({
                "skill_id": skill.id(),
                "content_hash": skill.content_hash,
                "reason": crate::skills::versioning::SkillSkipReason::EvalSession.as_str(),
                "ts_unix": crate::time::now_unix_secs(),
            }))
            .unwrap_or_default();
            let header = crate::wal::make_header(
                crate::wal::events::EVENT_TYPE_SKILL_INJECT_SKIPPED,
                &payload,
            );
            if let Err(error) = writer.append(header, payload).await {
                warn!(
                    skill = skill.id(),
                    error = %error,
                    "SKILL_INJECT_SKIPPED (eval_session) emit failed (non-fatal)"
                );
            }
        }
    }
    let active_files = crate::skills::resolver::active_files_from_env();
    let skill_registry_context = crate::skills::resolver::SkillRouteResolver::new(skill_snapshot)
        .retaining(|skill| !eval_suppress && !blocked_skill_ids.contains(skill.id()))
        .session_registry_context(&active_files)
        .context("render standalone loop session-start Skill registry context")?;
    let enriched = crate::pipeline::build_enriched_request(crate::pipeline::EnrichmentInputs {
        prompt,
        operator_sovereignty: Some(
            crate::security::operator_sovereignty::OperatorSovereigntyPrompt::local_interactive(),
        ),
        operator_context: None,
        preset_addendum: None,
        explicit_system: None,
        repo_context_block: None,
        attachment_contexts: None,
        skill_system_prompt: None,
        skill_registry_context: Some(&skill_registry_context),
        used_skill_id: None,
        mcp_catalogue: None,
        persona_override: None,
        moral_core: None,
        identity_anchor: None,
        identity_locked: false,
        current_goal: None,
        communication_profile: None,
    });
    Ok(crate::providers::Request {
        prompt: enriched.prompt,
        system: enriched.system,
        ..Default::default()
    })
}

/// Load every LoopRunRecord in `loops_dir`, newest first. Unreadable or
/// non-record JSON files are skipped with a note on stderr (a corrupt
/// record must not hide the readable history).
fn load_records(loops_dir: &std::path::Path) -> Result<Vec<LoopRunRecord>> {
    let mut records: Vec<LoopRunRecord> = Vec::new();
    let entries = match std::fs::read_dir(loops_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(records),
        Err(e) => {
            return Err(e).with_context(|| format!("read {}", loops_dir.display()));
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|b| serde_json::from_slice::<LoopRunRecord>(&b).map_err(Into::into))
        {
            Ok(r) => records.push(r),
            Err(e) => eprintln!("(skipping unreadable record {}: {e})", path.display()),
        }
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.ts_start));
    Ok(records)
}

fn render_history(records: &[LoopRunRecord], output: OutputFormat) -> Result<String> {
    Ok(match output {
        OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(records)?),
        OutputFormat::Jsonl => {
            let mut s = String::new();
            for r in records {
                s.push_str(&serde_json::to_string(r)?);
                s.push('\n');
            }
            s
        }
        OutputFormat::Table => {
            if records.is_empty() {
                return Ok("(no loop runs recorded — `neoth loop run \"<prompt>\"`)\n".into());
            }
            let mut s = format!(
                "{:<20} {:>6} {:<16} {:>10} {:>10}\n",
                "LOOP ID", "ROUNDS", "STOP", "TOOL CALLS", "SECS"
            );
            for r in records {
                s.push_str(&format!(
                    "{:<20} {:>6} {:<16} {:>10} {:>10}\n",
                    truncate_id(&r.loop_id, 20),
                    r.rounds_run,
                    r.stop_reason.as_str(),
                    r.total_tool_calls
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "-".into()),
                    (r.ts_end - r.ts_start).max(0),
                ));
            }
            s
        }
    })
}

fn render_record(record: &LoopRunRecord, output: OutputFormat) -> Result<String> {
    Ok(match output {
        OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(record)?),
        OutputFormat::Jsonl => format!("{}\n", serde_json::to_string(record)?),
        OutputFormat::Table => {
            let mut s = String::new();
            s.push_str(&format!("# loop {}\n", record.loop_id));
            s.push_str(&format!(
                "#   rounds={} stop={} tool_calls={} duration={}s\n",
                record.rounds_run,
                record.stop_reason.as_str(),
                record
                    .total_tool_calls
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into()),
                (record.ts_end - record.ts_start).max(0),
            ));
            for round in &record.per_round {
                s.push_str(&format!(
                    "#   round {}: iterations={} ok={} failed={}{}\n",
                    round.round_num,
                    round.iterations,
                    round.successful_calls,
                    round.failed_calls,
                    if round.refine_fired { " (refined)" } else { "" },
                ));
            }
            s.push('\n');
            s.push_str(&record.final_text);
            if !record.final_text.ends_with('\n') {
                s.push('\n');
            }
            s
        }
    })
}

fn truncate_id(id: &str, max: usize) -> String {
    // char-boundary-safe (ids are ASCII today; stay safe anyway).
    id.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loop_engine::engine::{LoopRound, StopReason};
    use crate::config::inference::InferenceProvider;
    use crate::config::role_policy::{RolePolicyConfig, RolePolicyRule};
    use crate::providers::cost_authorization::{AuthorizedProvider, ProviderCallAuthorizer};
    use crate::providers::{CompletionIdentity, ProviderDispatchPermit};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct W302LoopLeaf {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for W302LoopLeaf {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w302-loop-allowed")
        }

        async fn complete_raw(
            &self,
            _request: crate::providers::Request,
            _permit: &ProviderDispatchPermit,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion {
                text: "loop round output".to_owned(),
                identity: CompletionIdentity::default(),
                model: "w302-loop-allowed".to_owned(),
                ..Default::default()
            })
        }
    }

    struct W302QuotaLeaf {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for W302QuotaLeaf {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w302-loop-allowed")
        }

        async fn complete_raw(
            &self,
            _request: crate::providers::Request,
            _permit: &ProviderDispatchPermit,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::Error::new(crate::providers::quota::QuotaError {
                provider: self.name(),
                retry_after: None,
                body: "W302 synthetic 429".to_owned(),
            }))
        }
    }

    fn w302_loop_config(policy_model: &str) -> FreedomConfig {
        let mut config = FreedomConfig::default();
        config.inference.default_slot.provider = Some(InferenceProvider::OpenAi);
        config.inference.default_slot.model = Some(policy_model.to_owned());
        config.inference.role_policy = Some(RolePolicyConfig {
            rules: vec![RolePolicyRule {
                role: HemisphereRole::Left,
                provider: InferenceProvider::OpenAi,
                model: Some(policy_model.to_owned()),
            }],
        });
        config
    }

    fn w302_loop_provider_requests(segment: &std::path::Path) -> usize {
        let bytes = std::fs::read(segment).expect("read W302 loop WAL");
        let mut count = 0;
        crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST {
                let payload: serde_json::Value =
                    serde_json::from_slice(frame.payload).expect("decode W302 loop request");
                assert_eq!(payload["hemisphere_role"], "left");
                assert_eq!(payload["hemisphere_provider"], "openai_api");
                count += 1;
            }
            Ok(())
        })
        .expect("scan W302 loop WAL");
        count
    }

    struct StandaloneRequestRecordingProvider {
        requests: Arc<Mutex<Vec<crate::providers::Request>>>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for StandaloneRequestRecordingProvider {
        fn name(&self) -> &'static str {
            "standalone_loop_registry_test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("test-model")
        }

        async fn complete(
            &self,
            request: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.requests.lock().unwrap().push(request);
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: "loop round output".into(),
                identity: Default::default(),
                model: "test-model".into(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    async fn loop_request_for_test(
        home: &std::path::Path,
        config: &FreedomConfig,
    ) -> crate::providers::Request {
        let (writer, join) = crate::wal::writer::spawn(home.join("loop-registry-test.wal"))
            .expect("test WAL writer");
        let request = standalone_loop_enriched_request(config, home, &writer, "test loop prompt")
            .await
            .expect("standalone loop request");
        drop(writer);
        join.await.expect("test WAL writer join");
        request
    }

    fn registry_skill_ids(request: &crate::providers::Request) -> Vec<String> {
        let system = request.system.as_deref().expect("registry system layer");
        let envelopes: Vec<serde_json::Value> = system
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| {
                value["source_id"]
                    .as_str()
                    .is_some_and(|source| source.starts_with("skills:registry:"))
            })
            .collect();
        assert_eq!(envelopes.len(), 1, "exactly one registry envelope");
        // Registry JSON is data inside the canonical envelope's JSON string.
        // Decode both layers rather than searching its escaped wire bytes.
        let payload: serde_json::Value =
            serde_json::from_str(envelopes[0]["data"].as_str().expect("registry data string"))
                .expect("registry payload JSON");
        payload["skills"]
            .as_array()
            .expect("complete registry skill array")
            .iter()
            .map(|skill| skill["id"].as_str().expect("Skill id").to_owned())
            .collect()
    }

    fn first_registry_skill_id(request: &crate::providers::Request) -> String {
        registry_skill_ids(request)
            .first()
            .expect("at least one admitted Skill")
            .clone()
    }

    fn record(id: &str, ts_start: i64) -> LoopRunRecord {
        LoopRunRecord {
            loop_id: id.to_string(),
            prompt_hash: "ph".into(),
            rounds_run: 2,
            stop_reason: StopReason::Converged,
            total_tool_calls: Some(7),
            goal_outcome: crate::mcp::dispatch_loop::GoalOutcome::None,
            goal_hash: None,
            per_round: vec![LoopRound {
                round_num: 1,
                iterations: 3,
                hit_cap: false,
                successful_calls: 5,
                failed_calls: 0,
                stop_approved: true,
                refine_fired: false,
                quality_score: 0.75,
                ts_start,
                ts_end: ts_start + 5,
            }],
            final_text: "done".into(),
            ts_start,
            ts_end: ts_start + 10,
        }
    }

    fn write_record(dir: &std::path::Path, r: &LoopRunRecord) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(format!("{}.json", r.loop_id)),
            serde_json::to_vec_pretty(r).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn load_records_missing_dir_is_empty_history() {
        let dir = tempfile::tempdir().unwrap();
        let records = load_records(&dir.path().join("loops")).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn load_records_sorts_newest_first_and_skips_garbage() {
        let dir = tempfile::tempdir().unwrap();
        write_record(dir.path(), &record("older", 100));
        write_record(dir.path(), &record("newer", 200));
        std::fs::write(dir.path().join("junk.json"), b"{not json").unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"ignored").unwrap();
        let records = load_records(dir.path()).unwrap();
        let ids: Vec<&str> = records.iter().map(|r| r.loop_id.as_str()).collect();
        assert_eq!(ids, vec!["newer", "older"]);
    }

    #[test]
    fn render_history_table_lists_runs() {
        let out = render_history(&[record("abc123", 100)], OutputFormat::Table).unwrap();
        assert!(out.contains("LOOP ID"), "{out}");
        assert!(out.contains("abc123"), "{out}");
        assert!(out.contains("converged"), "{out}");
    }

    #[test]
    fn render_history_empty_table_says_so() {
        let out = render_history(&[], OutputFormat::Table).unwrap();
        assert!(out.contains("no loop runs"), "{out}");
    }

    #[test]
    fn render_record_roundtrips_json_and_shows_rounds_in_table() {
        let r = record("xyz", 100);
        let json = render_record(&r, OutputFormat::Json).unwrap();
        let back: LoopRunRecord = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(back.loop_id, "xyz");

        let table = render_record(&r, OutputFormat::Table).unwrap();
        assert!(table.contains("round 1"), "{table}");
        assert!(table.contains("done"), "{table}");
    }

    #[tokio::test]
    async fn w191_loop_request_excludes_pin_rejected_and_eval_suppressed_registry_entries() {
        let home = tempfile::tempdir().unwrap();
        let baseline = loop_request_for_test(home.path(), &FreedomConfig::default()).await;
        let admitted_id = first_registry_skill_id(&baseline);
        assert!(
            registry_skill_ids(&baseline).contains(&admitted_id),
            "the baseline must prove this fixture uses the production registry loader"
        );

        let mut pin_rejected = FreedomConfig::default();
        pin_rejected
            .skills
            .pinned_hashes
            .insert(admitted_id.clone(), "0".repeat(64));
        let pin_request = loop_request_for_test(home.path(), &pin_rejected).await;
        assert!(
            !registry_skill_ids(&pin_request).contains(&admitted_id),
            "pinned Skill {admitted_id} must be absent from registry ids: {:?}",
            registry_skill_ids(&pin_request)
        );

        let mut eval_suppressed = FreedomConfig::default();
        eval_suppressed.skills.disabled_for_eval_sessions = true;
        eval_suppressed.skills.eval_session_active = true;
        let eval_request = loop_request_for_test(home.path(), &eval_suppressed).await;
        assert!(
            !registry_skill_ids(&eval_request).contains(&admitted_id),
            "an eval-suppressed session must expose no Skill registry entry"
        );
    }

    #[tokio::test]
    async fn w191_later_standalone_loop_rebuilds_its_registry_from_fresh_config() {
        let home = tempfile::tempdir().unwrap();
        let baseline = loop_request_for_test(home.path(), &FreedomConfig::default()).await;
        let admitted_id = first_registry_skill_id(&baseline);

        let mut reject_first_generation = FreedomConfig::default();
        reject_first_generation
            .skills
            .pinned_hashes
            .insert(admitted_id.clone(), "0".repeat(64));
        let first = loop_request_for_test(home.path(), &reject_first_generation).await;
        assert!(
            !registry_skill_ids(&first).contains(&admitted_id),
            "the first loop generation rejects the pinned Skill"
        );

        let later = loop_request_for_test(home.path(), &FreedomConfig::default()).await;
        assert!(
            registry_skill_ids(&later).contains(&admitted_id),
            "a later standalone loop must acquire a fresh registry instead of reusing the rejected generation"
        );
    }

    #[tokio::test]
    async fn w191_actual_standalone_request_retains_loaded_registry_through_two_rounds() {
        let home = tempfile::tempdir().unwrap();
        let freedom = FreedomConfig {
            autonomy: crate::permissions::AutonomyLevel::Full,
            ..Default::default()
        };
        let request = loop_request_for_test(home.path(), &freedom).await;
        let registry_id = first_registry_skill_id(&request);
        let initial_system = request.system.clone().expect("loaded registry system");
        assert!(initial_system.contains(&registry_id));

        let (writer, join) =
            crate::wal::writer::spawn(home.path().join("actual-loop-registry.wal")).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let provider = StandaloneRequestRecordingProvider {
            requests: Arc::clone(&requests),
        };
        let loop_config = crate::loop_engine::engine::LoopConfig {
            min_rounds: 2,
            max_rounds: 2,
            until: vec![],
            tool_call_budget: Some(10),
            autonomy: crate::permissions::AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: home.path().to_path_buf(),
        };
        crate::loop_engine::run_loop(
            &loop_config,
            &provider,
            request,
            &crate::mcp::McpServers::default(),
            &writer,
            &freedom,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            None,
            &crate::mcp::McpToolScope::default(),
            &crate::cli::elicitation::ElicitationHandler::Disabled,
            None,
        )
        .await
        .expect("actual standalone request completes two rounds");
        drop(writer);
        join.await.unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].system.as_deref(), Some(initial_system.as_str()));
        assert_eq!(requests[1].system.as_deref(), Some(initial_system.as_str()));
        assert_ne!(requests[0].prompt, requests[1].prompt);
    }

    #[tokio::test]
    async fn w302_standalone_loop_retains_left_binding_for_every_round() {
        let home = tempfile::tempdir().expect("create W302 loop home");
        let segment = home.path().join("w302-loop-rounds.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).expect("spawn W302 loop WAL");
        let config = w302_loop_config("w302-loop-allowed");
        let calls = Arc::new(AtomicUsize::new(0));
        let raw = Arc::new(W302LoopLeaf {
            calls: Arc::clone(&calls),
        });
        let authorizer = bind_standalone_loop_left_authorizer(
            ProviderCallAuthorizer::fail_closed(
                crate::permissions::AutonomyLevel::Full,
                Some(writer.clone()),
                config.tokens.max_per_request,
            ),
            &config,
            standalone_loop_left_provider(&config).expect("configured Left provider"),
        );
        let loop_config = crate::loop_engine::engine::LoopConfig {
            min_rounds: 2,
            max_rounds: 2,
            until: vec![],
            tool_call_budget: Some(10),
            autonomy: crate::permissions::AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: home.path().to_path_buf(),
        };
        crate::loop_engine::run_loop(
            &loop_config,
            raw.as_ref(),
            crate::providers::Request {
                prompt: "W302 loop rounds".to_owned(),
                ..Default::default()
            },
            &crate::mcp::McpServers::default(),
            &writer,
            &config,
            authorizer,
            None,
            &crate::mcp::McpToolScope::default(),
            &crate::cli::elicitation::ElicitationHandler::Disabled,
            None,
        )
        .await
        .expect("two bound standalone loop rounds complete");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(raw);
        drop(writer);
        join.await.expect("drain W302 loop WAL");
        assert_eq!(w302_loop_provider_requests(&segment), 2);
    }

    #[tokio::test]
    async fn w302_standalone_loop_denies_primary_and_429_fallback_before_raw_leaf() {
        let home = tempfile::tempdir().expect("create W302 denied loop home");
        let segment = home.path().join("w302-loop-denied.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).expect("spawn W302 loop WAL");
        let config = w302_loop_config("w302-loop-allowed");

        let denied_primary_calls = Arc::new(AtomicUsize::new(0));
        let denied_primary = AuthorizedProvider::from_arc(
            Arc::new(W302LoopLeaf {
                calls: Arc::clone(&denied_primary_calls),
            }),
            bind_standalone_loop_left_authorizer(
                ProviderCallAuthorizer::fail_closed(
                    crate::permissions::AutonomyLevel::Full,
                    Some(writer.clone()),
                    config.tokens.max_per_request,
                ),
                &w302_loop_config("denied"),
                standalone_loop_left_provider(&config).expect("configured Left provider"),
            ),
            Some("w302-loop-allowed".to_owned()),
            "loop.w302.primary_denied",
        );
        assert!(denied_primary.complete(crate::providers::Request::default()).await.is_err());
        assert_eq!(denied_primary_calls.load(Ordering::SeqCst), 0);
        drop(denied_primary);

        let quota_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let chain = crate::providers::fallback::FallbackProvider::new_with_models_at(
            vec![
                Box::new(W302QuotaLeaf {
                    calls: Arc::clone(&quota_calls),
                }),
                Box::new(W302LoopLeaf {
                    calls: Arc::clone(&fallback_calls),
                }),
            ],
            vec![
                Some("w302-loop-allowed".to_owned()),
                Some("w302-loop-disallowed-fallback".to_owned()),
            ],
            1,
            None,
            home.path().join("w302-quota.json"),
        );
        let fallback = AuthorizedProvider::from_box(
            Box::new(chain),
            bind_standalone_loop_left_authorizer(
                ProviderCallAuthorizer::fail_closed(
                    crate::permissions::AutonomyLevel::Full,
                    Some(writer.clone()),
                    config.tokens.max_per_request,
                ),
                &config,
                standalone_loop_left_provider(&config).expect("configured Left provider"),
            ),
            Some("w302-loop-allowed".to_owned()),
            "loop.w302.fallback_denied",
        );
        assert!(fallback.complete(crate::providers::Request::default()).await.is_err());
        assert_eq!(quota_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
        drop(fallback);
        drop(writer);
        join.await.expect("drain W302 loop WAL");
        assert_eq!(w302_loop_provider_requests(&segment), 1);
    }
}
