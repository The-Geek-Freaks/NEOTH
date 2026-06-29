/// GOLD-LOOP-01 — loop engine core.
///
/// `run_loop` wraps `cli::chat::run_mcp_dispatch_loop` with outer rounds,
/// stop-condition verification (`council::stop_verifier`), optional self-
/// reflect refine passes at L2+ autonomy, WAL events (0x7C–0x7F), and a
/// `LoopRunRecord` written atomically to `~/.neoth/loops/<loop_id>.json`.
///
/// # Consumers (wired in this item)
///
/// 1. `cli/chat.rs::run_chat_with` — `--loop` flag path (CLI).
/// 2. `cli/chat.rs::dispatch_council_with_recovery` — strong-dissent auto-
///    invoke when `loop_config.auto_invoke_on_dissent = true`.
/// 3. `cli/serve_pipeline.rs` — channel `use_loop` branch when
///    `loop_config.enabled = true && loop_config.max_rounds > 1`.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::council::stop_verifier::{StopConditionVerifier, StopProposal};
use crate::permissions::AutonomyLevel;
use crate::wal::events::{
    EVENT_TYPE_LOOP_COMPLETED, EVENT_TYPE_LOOP_REFINED, EVENT_TYPE_LOOP_ROUND,
    EVENT_TYPE_LOOP_STARTED,
};
use crate::wal::writer::WalWriterHandle;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Runtime-view of the loop engine configuration. Built from
/// `config::LoopConfig` + optional CLI overrides.
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// Maximum outer rounds. Each round is one full `run_mcp_dispatch_loop`.
    pub max_rounds: u32,
    /// Structural stop criteria passed to `StopConditionVerifier`. Empty means
    /// no structured gate — any round exit is accepted.
    pub until: Vec<String>,
    /// Optional cumulative TOOL-CALL budget across all rounds — an outer safety
    /// gate on how much tool work the loop may do (sum of successful + failed
    /// calls). NOT an LLM-token budget: the inner dispatch loop does not surface
    /// per-round token usage, so this counts tool calls. Named accordingly so the
    /// operator isn't misled. `None` = no cap (bounded only by `max_rounds`).
    pub tool_call_budget: Option<u64>,
    /// Autonomy level — controls whether `StopConditionVerifier` actually
    /// gates the stop or passes through immediately (below Elevated).
    pub autonomy: AutonomyLevel,
    /// When `true` and autonomy >= Elevated, fire a self-reflect refine pass
    /// each round when quality is below threshold.
    pub refine_enabled: bool,
    /// Name of the `FreedomConfig` path for disk writes (neoth home).
    pub neoth_home: PathBuf,
}

impl LoopConfig {
    /// Build a `LoopConfig` from a `config::LoopConfig` + `FreedomConfig`
    /// fields. Called by the chat.rs and serve_pipeline.rs wiring.
    pub fn from_freedom(
        cfg: &crate::config::LoopConfig,
        autonomy: AutonomyLevel,
        until: Vec<String>,
        neoth_home: PathBuf,
    ) -> Self {
        Self {
            max_rounds: cfg.max_rounds,
            until,
            tool_call_budget: cfg.tool_call_budget,
            autonomy,
            refine_enabled: cfg.refine_enabled,
            neoth_home,
        }
    }

    /// Build a minimal `LoopConfig` for the dissent-spike auto-invoke path:
    /// one round, no structured stop criteria, no refine.
    pub fn for_dissent_invoke(
        autonomy: AutonomyLevel,
        neoth_home: PathBuf,
    ) -> Self {
        Self {
            max_rounds: 1,
            until: Vec::new(),
            tool_call_budget: None,
            autonomy,
            refine_enabled: false,
            neoth_home,
        }
    }
}

/// Why the loop stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `StopConditionVerifier` approved the stop (or no criteria were set).
    Converged,
    /// `max_rounds` reached without verifier approval.
    CapHit,
    /// Tool-call budget exceeded (see `LoopConfig::tool_call_budget`).
    BudgetExceeded,
}

impl StopReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Converged => "converged",
            Self::CapHit => "cap_hit",
            Self::BudgetExceeded => "budget_exceeded",
        }
    }
}

/// Record of a single completed round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopRound {
    pub round_num: u32,
    pub iterations: u32,
    pub hit_cap: bool,
    pub successful_calls: u32,
    pub failed_calls: u32,
    pub stop_approved: bool,
    pub refine_fired: bool,
    pub ts_start: i64,
    pub ts_end: i64,
}

/// Full record for one `run_loop` invocation. Written to
/// `~/.neoth/loops/<loop_id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopRunRecord {
    pub loop_id: String,
    pub prompt_hash: String,
    pub rounds_run: u32,
    pub stop_reason: StopReason,
    /// Total tool calls across all rounds (the `tool_call_budget` accumulator).
    /// `serde(alias)` keeps older `total_tokens_used` records readable.
    #[serde(alias = "total_tokens_used")]
    pub total_tool_calls: Option<u64>,
    pub per_round: Vec<LoopRound>,
    pub final_text: String,
    pub ts_start: i64,
    pub ts_end: i64,
}

/// Mutable state threaded through the loop.
pub struct LoopState {
    pub current_round: u32,
    pub accumulated_tool_calls: u64,
    pub stop_verifier: StopConditionVerifier,
}

impl LoopState {
    fn new(config: &LoopConfig) -> Self {
        Self {
            current_round: 0,
            accumulated_tool_calls: 0,
            stop_verifier: StopConditionVerifier::new(config.until.iter().map(|s| s.as_str())),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Generate a loop_id: `loop_<unix_ts>_<pseudo_random>`.
fn new_loop_id() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    // Use the lower bits of the system time as entropy — sufficient for a
    // file-system key; not a security primitive.
    let lo = (ts & 0xFFFF) as u32;
    format!("loop_{ts}_{lo:04X}")
}

/// Emit a WAL frame best-effort (never fails the loop on WAL error).
async fn emit_wal(writer: &WalWriterHandle, event_type: u8, payload: serde_json::Value) {
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, event = event_type, "loop-engine: WAL payload serialise failed");
            return;
        }
    };
    let header = crate::wal::make_header(event_type, &bytes);
    if let Err(e) = writer.append(header, bytes).await {
        warn!(error = %e, event = event_type, "loop-engine: WAL append failed (non-fatal)");
    }
}

/// Write `LoopRunRecord` atomically to `~/.neoth/loops/<loop_id>.json`.
/// Pattern: write to `.tmp` then rename — same as `telemetry/trajectory.rs`.
fn write_run_record(record: &LoopRunRecord, neoth_home: &Path) {
    let loops_dir = neoth_home.join("loops");
    if let Err(e) = std::fs::create_dir_all(&loops_dir) {
        warn!(error = %e, "loop-engine: could not create ~/.neoth/loops/ dir");
        return;
    }
    let path = loops_dir.join(format!("{}.json", record.loop_id));
    let tmp = loops_dir.join(format!("{}.json.tmp", record.loop_id));
    let bytes = match serde_json::to_vec_pretty(record) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "loop-engine: could not serialise LoopRunRecord");
            return;
        }
    };
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        warn!(error = %e, path = ?tmp, "loop-engine: could not write LoopRunRecord tmp");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        warn!(error = %e, path = ?path, "loop-engine: could not rename LoopRunRecord");
    }
}

/// Extract evidence tokens from the final text for the stop verifier.
/// Simple heuristic: split on common sentence terminators and keep
/// unique lowercase tokens ≤ 6 words long.
fn extract_evidence(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|l| l.split(['.', ';', ':', '\n']))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s.split_whitespace().count() <= 8)
        .take(32)
        .collect()
}

// ---------------------------------------------------------------------------
// Core entry point
// ---------------------------------------------------------------------------

/// Run the multi-round loop engine.
///
/// Each round calls `cli::chat::run_mcp_dispatch_loop` via the shared
/// `pub(crate)` helper. After each round the stop verifier judges whether
/// the criteria declared in `config.until` are satisfied; if so the loop
/// exits with `StopReason::Converged`. At L2+ autonomy and when
/// `config.refine_enabled = true`, a self-reflect refine pass fires when
/// quality is below threshold. The loop also respects a tool-call budget
/// (`config.tool_call_budget`) as an outer safety gate.
///
/// Returns `Ok(LoopRunRecord)` on any normal exit (Converged / CapHit /
/// BudgetExceeded). Returns `Err` only when the first round itself fails
/// (so callers get a clean error rather than a record with 0 rounds).
#[allow(clippy::too_many_arguments)]
pub async fn run_loop(
    config: &LoopConfig,
    provider: &dyn crate::providers::Provider,
    mut req: crate::providers::Request,
    servers: &crate::mcp::McpServers,
    writer: &WalWriterHandle,
    freedom: &crate::config::FreedomConfig,
    elicitation: &crate::cli::elicitation::ElicitationHandler,
) -> Result<LoopRunRecord> {
    let loop_id = new_loop_id();
    let prompt_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes())
    );
    let ts_start = now_unix();
    let has_until = !config.until.is_empty();
    // P2 — the stable task prompt. Each round after the first re-bases `req.prompt`
    // on this plus the previous round's output, so the loop actually iterates
    // (refine/extend) instead of re-running the identical prompt every round.
    let base_prompt = req.prompt.clone();

    // --- WAL: LOOP_STARTED ---
    emit_wal(
        writer,
        EVENT_TYPE_LOOP_STARTED,
        serde_json::json!({
            "loop_id": loop_id,
            "prompt_hash": prompt_hash,
            "max_rounds": config.max_rounds,
            "has_until": has_until,
            "ts_unix": ts_start,
        }),
    )
    .await;

    info!(
        loop_id = %loop_id,
        max_rounds = config.max_rounds,
        has_until,
        "loop-engine: starting multi-round loop"
    );

    let mut state = LoopState::new(config);
    let mut per_round: Vec<LoopRound> = Vec::new();
    let mut final_text = String::new();
    let mut stop_reason = StopReason::CapHit;

    // Common dispatch-loop arguments derived from freedom config.
    let rollback = &freedom.rollback;
    let security = &freedom.security;
    let goal_context = crate::mcp::goal_tracker::GoalContext {
        goal: freedom.goal.goal.clone(),
        grind: freedom.goal.grind.clone(),
    };
    let compaction = crate::context::compaction::CompactionPolicy::from_config(
        freedom.compaction.enabled,
        freedom.compaction.progressive,
        freedom.tokens.max_per_request,
        freedom.compaction.threshold_fraction,
    );
    let compression = crate::context::compress::CompressionRuntime::persistent(
        freedom.compression.gate(),
        freedom.compression.thresholds(),
        crate::context::compress::default_ccr_dir(),
    );
    let judge_provider: Option<&dyn crate::providers::Provider> =
        if freedom.goal.judge_enabled && freedom.goal.goal.is_some() {
            Some(provider)
        } else {
            None
        };

    for round_num in 1..=config.max_rounds {
        // Token budget check before each round (except the first — we need
        // at least one round to produce any output).
        if round_num > 1 {
            if let Some(budget) = config.tool_call_budget {
                if state.accumulated_tool_calls >= budget {
                    info!(
                        loop_id = %loop_id,
                        accumulated_tool_calls = state.accumulated_tool_calls,
                        budget,
                        "loop-engine: tool-call budget exceeded — stopping"
                    );
                    stop_reason = StopReason::BudgetExceeded;
                    break;
                }
            }
        }

        state.current_round = round_num;
        let round_ts_start = now_unix();

        info!(
            loop_id = %loop_id,
            round = round_num,
            "loop-engine: starting round"
        );

        let outcome = crate::cli::chat::run_mcp_dispatch_loop(
            provider,
            req.clone(),
            servers,
            config.autonomy,
            writer,
            Some(rollback),
            // No skill allowlist at the loop-engine level; the inner dispatch
            // loop applies skill scoping based on skill matching at call time.
            None,
            freedom.goal.max_turns,
            security,
            None, // no sub-agent denylist at loop level
            goal_context.clone(),
            freedom.hints.enabled,
            compaction,
            compression.clone(),
            judge_provider,
            // GOLD-ADOPT-17 / P4 — elicitation is supplied by the caller:
            // `Cli` on the interactive `neoth chat --loop` TTY (so mid-turn
            // elicitation works in loop mode too), `Disabled` on the headless
            // serve/channel path. No longer hard-wired off.
            elicitation,
        )
        .await?;

        // Accumulate the round's tool-call count (successful + failed). This is a
        // tool-call budget, NOT a token budget — it's an outer safety gate on how
        // much tool work the loop may do, named honestly so the operator isn't
        // misled into thinking `tool_call_budget` counts LLM tokens.
        let round_calls = outcome.successful_calls as u64 + outcome.failed_calls as u64;
        state.accumulated_tool_calls = state.accumulated_tool_calls.saturating_add(round_calls);

        // --- Self-reflect refine pass (L2+ autonomy + refine_enabled) ---
        let mut refine_fired = false;
        let round_text = if config.refine_enabled
            && is_elevated_or_full(config.autonomy)
            && crate::council::self_reflect::should_refine(freedom, 0.0, 0)
        {
            match crate::cli::chat::build_hemisphere_for_loop(
                freedom,
                crate::config::inference::HemisphereRole::Left,
                &req,
            )
            .await
            {
                Ok(hemisphere) => {
                    refine_fired = true;
                    emit_wal(
                        writer,
                        EVENT_TYPE_LOOP_REFINED,
                        serde_json::json!({
                            "loop_id": loop_id,
                            "round": round_num,
                            "ts_unix": now_unix(),
                        }),
                    )
                    .await;
                    let refined = crate::council::self_reflect::refine(
                        &req.prompt,
                        &outcome.final_text,
                        hemisphere.as_ref(),
                    )
                    .await;
                    refined.refined
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        loop_id = %loop_id,
                        round = round_num,
                        "loop-engine: self-reflect skipped — hemisphere rebuild failed"
                    );
                    outcome.final_text.clone()
                }
            }
        } else {
            outcome.final_text.clone()
        };

        // --- Stop condition evaluation ---
        let evidence = extract_evidence(&round_text);
        let proposal = StopProposal {
            agent_message: round_text.clone(),
            claimed_evidence: evidence,
        };
        let judgement = state.stop_verifier.judge(&proposal, config.autonomy);
        let stop_approved = judgement.is_approved();

        let round_ts_end = now_unix();

        // --- WAL: LOOP_ROUND ---
        emit_wal(
            writer,
            EVENT_TYPE_LOOP_ROUND,
            serde_json::json!({
                "loop_id": loop_id,
                "round": round_num,
                "iterations": outcome.iterations,
                "hit_cap": outcome.hit_cap,
                "successful_calls": outcome.successful_calls,
                "failed_calls": outcome.failed_calls,
                "stop_approved": stop_approved,
                "ts_unix": round_ts_end,
            }),
        )
        .await;

        per_round.push(LoopRound {
            round_num,
            iterations: outcome.iterations,
            hit_cap: outcome.hit_cap,
            successful_calls: outcome.successful_calls,
            failed_calls: outcome.failed_calls,
            stop_approved,
            refine_fired,
            ts_start: round_ts_start,
            ts_end: round_ts_end,
        });

        final_text = round_text;

        // P2 — feed this round's output into the NEXT round's request so the
        // loop iterates on its own work (refine/extend/correct) rather than
        // re-running the identical prompt. The original task stays the stable
        // base; only the LATEST output is attached (not compounded every round).
        if round_num < config.max_rounds && !stop_approved {
            req.prompt = format!(
                "{base_prompt}\n\n## Previous round (#{round_num}) produced:\n{final_text}\n\n\
                 ## Now: build on and improve the above toward the task — refine, fill gaps, \
                 or correct mistakes. Do not merely repeat it."
            );
        }

        if stop_approved {
            info!(
                loop_id = %loop_id,
                round = round_num,
                reason = judgement.reason(),
                "loop-engine: stop approved — converged"
            );
            stop_reason = StopReason::Converged;
            break;
        }

        info!(
            loop_id = %loop_id,
            round = round_num,
            reason = judgement.reason(),
            "loop-engine: stop not yet approved — continuing"
        );
    }

    let ts_end = now_unix();
    let rounds_run = per_round.len() as u32;

    // --- WAL: LOOP_COMPLETED ---
    emit_wal(
        writer,
        EVENT_TYPE_LOOP_COMPLETED,
        serde_json::json!({
            "loop_id": loop_id,
            "rounds_run": rounds_run,
            "stop_reason": stop_reason.as_str(),
            "ts_unix": ts_end,
        }),
    )
    .await;

    info!(
        loop_id = %loop_id,
        rounds_run,
        stop_reason = stop_reason.as_str(),
        "loop-engine: completed"
    );

    let record = LoopRunRecord {
        loop_id: loop_id.clone(),
        prompt_hash,
        rounds_run,
        stop_reason,
        total_tool_calls: if state.accumulated_tool_calls > 0 {
            Some(state.accumulated_tool_calls)
        } else {
            None
        },
        per_round,
        final_text,
        ts_start,
        ts_end,
    };

    write_run_record(&record, &config.neoth_home);

    Ok(record)
}

/// True when `autonomy >= Elevated` — mirrors the private helper in
/// `council::stop_verifier` so the loop engine can make the same gate
/// decision without depending on an unexported symbol.
fn is_elevated_or_full(autonomy: AutonomyLevel) -> bool {
    matches!(autonomy, AutonomyLevel::Elevated | AutonomyLevel::Full)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stop_reason_serialises_correctly() {
        assert_eq!(
            serde_json::to_string(&StopReason::Converged).unwrap(),
            "\"converged\""
        );
        assert_eq!(
            serde_json::to_string(&StopReason::CapHit).unwrap(),
            "\"cap_hit\""
        );
        assert_eq!(
            serde_json::to_string(&StopReason::BudgetExceeded).unwrap(),
            "\"budget_exceeded\""
        );
    }

    #[test]
    fn loop_run_record_roundtrips_json() {
        let record = LoopRunRecord {
            loop_id: "loop_12345_ABCD".into(),
            prompt_hash: "deadbeef01234567".into(),
            rounds_run: 2,
            stop_reason: StopReason::Converged,
            total_tool_calls: Some(42),
            per_round: vec![LoopRound {
                round_num: 1,
                iterations: 3,
                hit_cap: false,
                successful_calls: 2,
                failed_calls: 0,
                stop_approved: false,
                refine_fired: false,
                ts_start: 1000,
                ts_end: 1001,
            }],
            final_text: "done".into(),
            ts_start: 999,
            ts_end: 1002,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: LoopRunRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.loop_id, "loop_12345_ABCD");
        assert_eq!(back.rounds_run, 2);
        assert_eq!(back.stop_reason, StopReason::Converged);
        assert_eq!(back.per_round.len(), 1);
    }

    #[test]
    fn write_run_record_creates_file() {
        let dir = TempDir::new().unwrap();
        let record = LoopRunRecord {
            loop_id: "loop_test_0001".into(),
            prompt_hash: "aabbccdd".into(),
            rounds_run: 1,
            stop_reason: StopReason::CapHit,
            total_tool_calls: None,
            per_round: vec![],
            final_text: "hello".into(),
            ts_start: 0,
            ts_end: 1,
        };
        write_run_record(&record, dir.path());
        let path = dir.path().join("loops").join("loop_test_0001.json");
        assert!(path.exists(), "LoopRunRecord file must exist after write");
        let content = std::fs::read_to_string(&path).unwrap();
        let back: LoopRunRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(back.loop_id, "loop_test_0001");
        assert_eq!(back.stop_reason, StopReason::CapHit);
    }

    #[test]
    fn extract_evidence_returns_short_tokens() {
        let text = "all tests pass. build is green. no open tasks.";
        let ev = extract_evidence(text);
        // Each item should be <= 8 words.
        for e in &ev {
            assert!(
                e.split_whitespace().count() <= 8,
                "evidence token too long: {e}"
            );
        }
        assert!(!ev.is_empty());
    }

    #[test]
    fn new_loop_id_is_unique() {
        let a = new_loop_id();
        let b = new_loop_id();
        // May collide in theory (same ms), but format must be correct.
        assert!(a.starts_with("loop_"), "loop_id must start with loop_");
        assert!(b.starts_with("loop_"), "loop_id must start with loop_");
    }

    #[test]
    fn loop_config_from_freedom_copies_fields() {
        let cfg = crate::config::LoopConfig {
            enabled: true,
            max_rounds: 5,
            auto_invoke_on_dissent: true,
            refine_enabled: true,
            tool_call_budget: Some(1000),
        };
        let lc = LoopConfig::from_freedom(
            &cfg,
            AutonomyLevel::Elevated,
            vec!["done".into()],
            PathBuf::from("/tmp/neoth"),
        );
        assert_eq!(lc.max_rounds, 5);
        assert_eq!(lc.tool_call_budget, Some(1000));
        assert!(lc.refine_enabled);
        assert_eq!(lc.until, vec!["done".to_string()]);
    }

    #[test]
    fn loop_config_for_dissent_invoke_is_one_round() {
        let lc = LoopConfig::for_dissent_invoke(
            AutonomyLevel::Standard,
            PathBuf::from("/tmp/neoth"),
        );
        assert_eq!(lc.max_rounds, 1);
        assert!(lc.until.is_empty());
        assert!(!lc.refine_enabled);
    }

    #[test]
    fn is_elevated_or_full_gate() {
        assert!(!is_elevated_or_full(AutonomyLevel::Strict));
        assert!(!is_elevated_or_full(AutonomyLevel::Standard));
        assert!(is_elevated_or_full(AutonomyLevel::Elevated));
        assert!(is_elevated_or_full(AutonomyLevel::Full));
    }

    /// Verifies that the LoopState stop verifier approves an unconstrained stop.
    #[test]
    fn loop_state_no_criteria_always_approves() {
        let cfg = LoopConfig {
            max_rounds: 3,
            until: vec![],
            tool_call_budget: None,
            autonomy: AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: PathBuf::from("/tmp"),
        };
        let state = LoopState::new(&cfg);
        let proposal = StopProposal {
            agent_message: "done".into(),
            claimed_evidence: vec![],
        };
        let j = state.stop_verifier.judge(&proposal, AutonomyLevel::Full);
        assert!(j.is_approved(), "no-criteria verifier must approve any stop");
    }

    /// Verifies that the LoopState stop verifier rejects an unmet criterion.
    #[test]
    fn loop_state_unmet_criterion_rejects() {
        let cfg = LoopConfig {
            max_rounds: 3,
            until: vec!["build green".into()],
            tool_call_budget: None,
            autonomy: AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: PathBuf::from("/tmp"),
        };
        let state = LoopState::new(&cfg);
        let proposal = StopProposal {
            agent_message: "I think I'm done".into(),
            claimed_evidence: vec!["tests pass".into()],
        };
        // "build green" is NOT in the evidence → Rejected.
        let j = state.stop_verifier.judge(&proposal, AutonomyLevel::Full);
        assert!(
            !j.is_approved(),
            "unmet criterion 'build green' must reject the stop"
        );
    }
}
