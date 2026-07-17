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

use crate::cli::OutputFormat;
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
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(pid)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        anyhow::bail!(
            "neoth serve (pid {pid}) is running and owns the WAL segment — run \
             loops through the daemon (a `loop: true` skill via a channel, or \
             `neoth chat --loop`), or stop the daemon first"
        );
    }

    // Same plumbing trio as the chat path: fallback-chain provider, the
    // operator's MCP server set, a WAL writer on the default segment.
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
    let (writer, writer_join) = crate::wal::spawn(segment_path).context("spawn WAL writer")?;
    let provider_policy =
        crate::permissions::AutonomyPolicySnapshot::new(autonomy, &config.custom_autonomy);
    let provider_call_authorizer =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            provider_policy,
            Some(writer.clone()),
            config.tokens.max_per_request,
        );

    let req = crate::providers::Request {
        prompt: args.prompt,
        ..Default::default()
    };
    let elicitation = if config.elicitation.enabled {
        crate::cli::elicitation::ElicitationHandler::Cli
    } else {
        crate::cli::elicitation::ElicitationHandler::Disabled
    };

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
        &elicitation,
    )
    .await;

    drop(writer);
    let _ = writer_join.await;

    let record = result?;
    print!("{}", render_record(&record, output)?);
    Ok(())
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

    fn record(id: &str, ts_start: i64) -> LoopRunRecord {
        LoopRunRecord {
            loop_id: id.to_string(),
            prompt_hash: "ph".into(),
            rounds_run: 2,
            stop_reason: StopReason::Converged,
            total_tool_calls: Some(7),
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
}
