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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::council::stop_verifier::{StopConditionVerifier, StopProposal};
use crate::mcp::dispatch_loop::{GoalOutcome, LoopOutcome};
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
    /// Minimum outer rounds before normal convergence may stop the loop.
    /// Safety and tool-budget failures remain terminal immediately.
    pub min_rounds: u32,
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
            min_rounds: 1,
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
        tool_call_budget: Option<u64>,
    ) -> Self {
        Self {
            min_rounds: 1,
            max_rounds: 1,
            until: Vec::new(),
            tool_call_budget,
            autonomy,
            refine_enabled: false,
            neoth_home,
        }
    }

    /// Validate invariants at the shared engine boundary so every caller
    /// (chat, channels, standalone CLI, dissent auto-invoke) receives the same
    /// fail-closed safety contract.
    pub fn validate_safety(&self) -> Result<()> {
        if self.max_rounds == 0 {
            anyhow::bail!("loop max_rounds must be at least 1");
        }
        if self.min_rounds == 0 {
            anyhow::bail!("loop min_rounds must be at least 1");
        }
        if self.min_rounds > self.max_rounds {
            anyhow::bail!(
                "loop min_rounds ({}) cannot exceed max_rounds ({})",
                self.min_rounds,
                self.max_rounds
            );
        }
        if self.autonomy == AutonomyLevel::Full
            && self.tool_call_budget.is_none_or(|budget| budget == 0)
        {
            anyhow::bail!(
                "full-autonomy loops require a positive tool_call_budget — uncapped L3 execution is blocked"
            );
        }
        Ok(())
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
    pub fn as_str(&self) -> &'static str {
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
    /// Response-local score used by the refine threshold before any refine
    /// call. Defaults to zero when reading records written by older versions.
    #[serde(default)]
    pub quality_score: f32,
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
    /// Exact aggregated lifecycle outcome for the configured goal. Older
    /// records predate this field and therefore deserialize as `None`.
    #[serde(default)]
    pub goal_outcome: GoalOutcome,
    /// Stable hash of the original, untruncated goal. Provider prompts may use
    /// a bounded copy, but persisted lifecycle correlation never does.
    #[serde(default)]
    pub goal_hash: Option<String>,
    pub per_round: Vec<LoopRound>,
    pub final_text: String,
    pub ts_start: i64,
    pub ts_end: i64,
}

impl LoopRunRecord {
    /// Convert the persisted multi-round envelope to the dispatch surface used
    /// by both CLI chat and channels. Keeping this mapping here prevents either
    /// caller from re-inferring terminal goal state from historical round caps.
    pub fn into_dispatch_outcome(self) -> LoopOutcome {
        let hit_cap = matches!(
            self.stop_reason,
            StopReason::CapHit | StopReason::BudgetExceeded
        );
        let successful_calls = self
            .per_round
            .iter()
            .map(|round| round.successful_calls)
            .sum();
        let failed_calls = self.per_round.iter().map(|round| round.failed_calls).sum();

        LoopOutcome {
            final_text: self.final_text,
            iterations: self.rounds_run,
            hit_cap,
            successful_calls,
            failed_calls,
            tool_call_records: Vec::new(),
            goal_outcome: self.goal_outcome,
            goal_hash: self.goal_hash,
        }
    }
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
    crate::time::now_unix_i64()
}

/// Generate a time-sortable, process-safe loop id.
fn new_loop_id() -> String {
    format!("loop_{}", uuid::Uuid::now_v7().simple())
}

fn aggregate_goal_outcome(
    configured_goal_hash: Option<&str>,
    round_goal_hash: Option<&str>,
    _current: GoalOutcome,
    round: GoalOutcome,
) -> Result<GoalOutcome> {
    if configured_goal_hash != round_goal_hash {
        return Err(crate::mcp::goal_tracker::GoalIntegrityError::HashMismatch.into());
    }
    // The outcome must describe the bytes that can actually become the final
    // response. A historical Met cannot remain sticky after an explicit
    // `--until` rejection causes a later round to replace those judged bytes.
    // Inner caps remain round-local; the final outer cap is applied below.
    Ok(if round == GoalOutcome::Met {
        GoalOutcome::Met
    } else {
        GoalOutcome::None
    })
}

fn finalize_goal_outcome(
    goal_active: bool,
    stop_reason: &StopReason,
    aggregated: GoalOutcome,
) -> GoalOutcome {
    if !goal_active {
        return GoalOutcome::None;
    }
    if aggregated == GoalOutcome::Met {
        return GoalOutcome::Met;
    }
    if matches!(stop_reason, StopReason::CapHit | StopReason::BudgetExceeded) {
        return GoalOutcome::BudgetExhausted;
    }
    aggregated
}

/// Combine the exact-goal lifecycle with the operator's structural stop gate.
/// An inner cap vetoes the round. A proven goal still cannot bypass explicit
/// `--until` criteria or the route's minimum-round invariant; with no criteria
/// the verifier approves by construction.
fn round_stop_approved(
    goal_outcome: GoalOutcome,
    verifier_approved: bool,
    minimum_rounds_met: bool,
) -> bool {
    goal_outcome != GoalOutcome::BudgetExhausted && verifier_approved && minimum_rounds_met
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

/// Score one loop round using the two quality components observable on a
/// single-provider response: provider tier and response-local signals. Council
/// memory/diversity components require competing hemispheres, so their weights
/// are excluded and the remaining 0.75 weight is normalized back to `[0, 1]`.
fn round_quality_score(provider_id: &str, text: &str) -> f32 {
    const OBSERVED_WEIGHT: f32 = 0.40 + 0.35;
    let tier = crate::council::quality_score::provider_tier(provider_id);
    let dynamic = crate::council::quality_score::dynamic_signal_from_text(text);
    ((0.40 * tier + 0.35 * dynamic) / OBSERVED_WEIGHT).clamp(0.0, 1.0)
}

/// Charges the Council's whole-message call budget before every provider leaf
/// reachable through the dissent loop (normal rounds, retries, compaction and
/// goal-judge calls all use this same provider object).
struct CouncilBudgetedLoopProvider<'a> {
    inner: &'a dyn crate::providers::Provider,
    budget: crate::council::BudgetToken,
}

#[async_trait::async_trait]
impl crate::providers::Provider for CouncilBudgetedLoopProvider<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn request_controls(&self) -> crate::providers::ProviderRequestControls {
        self.inner.request_controls()
    }

    fn validate_request_controls(&self, req: &crate::providers::Request) -> Result<()> {
        self.inner.validate_request_controls(req)
    }

    fn default_model(&self) -> Option<&str> {
        self.inner.default_model()
    }

    fn resolve_model_for_wire(&self, requested_model: &str) -> String {
        self.inner.resolve_model_for_wire(requested_model)
    }

    fn output_token_ceiling(&self, req: &crate::providers::Request) -> Option<u32> {
        self.inner.output_token_ceiling(req)
    }

    fn handles_nonstream_quota_backoff(&self) -> bool {
        self.inner.handles_nonstream_quota_backoff()
    }

    fn preserves_inner_response_identity(&self) -> bool {
        true
    }

    async fn complete(
        &self,
        req: crate::providers::Request,
    ) -> Result<crate::providers::Completion> {
        self.budget
            .charge()
            .map_err(|error| anyhow::anyhow!("Council dissent loop {error}"))?;
        crate::providers::cost_authorization::precharged_council_attempt_scope(
            self.budget.clone(),
            self.inner.complete(req),
        )
        .await
    }
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
/// BudgetExceeded). Returns `Err` when a round fails before a truthful record
/// can be produced or when an integrity binding (such as the goal hash)
/// diverges. Callers may only fallback for non-integrity errors.
#[allow(clippy::too_many_arguments)]
pub async fn run_loop(
    config: &LoopConfig,
    provider: &dyn crate::providers::Provider,
    mut req: crate::providers::Request,
    servers: &crate::mcp::McpServers,
    writer: &WalWriterHandle,
    freedom: &crate::config::FreedomConfig,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    council_budget: Option<&crate::council::BudgetToken>,
    tool_scope: &crate::mcp::McpToolScope,
    elicitation: &crate::cli::elicitation::ElicitationHandler,
    // Interactive chat supplies this opaque in-RAM capability so a fresh
    // self-reflect provider leaf cannot bypass the session canary guard.
    session_canary: Option<std::sync::Arc<crate::security::injection_tracker::CanaryToken>>,
) -> Result<LoopRunRecord> {
    config.validate_safety()?;

    // Own the single authorization boundary for the entire loop. Callers must
    // pass their raw/provider-decorator chain (a token cap is fine), never an
    // existing CostAuthorizingProvider/AuthorizedProvider; nested authorization
    // boundaries are deliberately rejected at runtime.
    let authorized_provider = crate::providers::cost_authorization::CostAuthorizingProvider::new(
        provider,
        authorizer.clone(),
        req.model.clone(),
        "loop_provider_round",
    );
    let budgeted_provider = council_budget.map(|budget| CouncilBudgetedLoopProvider {
        inner: &authorized_provider,
        budget: budget.clone(),
    });
    let provider: &dyn crate::providers::Provider = match budgeted_provider.as_ref() {
        Some(provider) => provider,
        None => &authorized_provider,
    };
    let loop_id = new_loop_id();
    let prompt_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes()));
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
    let configured_goal_hash = freedom
        .goal
        .goal
        .as_deref()
        .map(crate::mcp::goal_judge::goal_hash);
    let mut goal_outcome = GoalOutcome::None;
    // This is a per-operator-turn allowance, not a per-round allowance. Every
    // nested MCP loop below borrows the same value so max_rounds cannot
    // multiply paid compaction leaves.
    let mut compaction_budget = crate::mcp::dispatch_loop::CompactionBudget::default();

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
        // Tool-call budget check before every round. The first round is allowed
        // only while positive budget remains; its inner dispatch receives the
        // exact remainder and enforces it before each individual call.
        if let Some(budget) = config.tool_call_budget
            && state.accumulated_tool_calls >= budget
        {
            info!(
                loop_id = %loop_id,
                accumulated_tool_calls = state.accumulated_tool_calls,
                budget,
                "loop-engine: tool-call budget exceeded — stopping"
            );
            stop_reason = StopReason::BudgetExceeded;
            break;
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
            &freedom.autonomy_policy(),
            writer,
            Some(rollback),
            tool_scope,
            freedom.goal.max_turns,
            security,
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
            // GOLD-ADAPT-AWE-CODE-01 — no inbound subject at loop level.
            None,
            // GOLD-ADAPT-HARNESS — operator harness knobs from freedom.yaml.
            &freedom.tools.harness,
            &mut compaction_budget,
            config
                .tool_call_budget
                .map(|budget| budget.saturating_sub(state.accumulated_tool_calls)),
            &config.neoth_home,
        )
        .await?;

        let goal_met_this_round = outcome.goal_outcome == GoalOutcome::Met;
        goal_outcome = aggregate_goal_outcome(
            configured_goal_hash.as_deref(),
            outcome.goal_hash.as_deref(),
            goal_outcome,
            outcome.goal_outcome,
        )?;

        // Accumulate the round's tool-call count (successful + failed). This is a
        // tool-call budget, NOT a token budget — it's an outer safety gate on how
        // much tool work the loop may do, named honestly so the operator isn't
        // misled into thinking `tool_call_budget` counts LLM tokens.
        let round_calls = outcome.successful_calls as u64 + outcome.failed_calls as u64;
        state.accumulated_tool_calls = state.accumulated_tool_calls.saturating_add(round_calls);
        let tool_budget_reached = config
            .tool_call_budget
            .is_some_and(|budget| state.accumulated_tool_calls >= budget);

        // --- Self-reflect refine pass (L2+ autonomy + refine_enabled) ---
        let mut refine_fired = false;
        let quality_score = round_quality_score(provider.name(), &outcome.final_text);
        let round_text = if !goal_met_this_round
            && config.refine_enabled
            && is_elevated_or_full(config.autonomy)
            && crate::council::self_reflect::should_refine(freedom, quality_score, 0)
        {
            match crate::cli::chat::build_hemisphere_for_loop(
                freedom,
                &config.neoth_home,
                crate::config::inference::HemisphereRole::Left,
                &req,
                authorizer.clone(),
                session_canary.clone(),
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
                    let refined = match council_budget {
                        Some(budget) => {
                            crate::council::self_reflect::refine_with_budget(
                                &req.prompt,
                                &outcome.final_text,
                                hemisphere.as_ref(),
                                budget,
                            )
                            .await
                        }
                        None => {
                            crate::council::self_reflect::refine(
                                &req.prompt,
                                &outcome.final_text,
                                hemisphere.as_ref(),
                            )
                            .await
                        }
                    };
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
        let minimum_rounds_met = round_num >= config.min_rounds;
        let stop_approved = round_stop_approved(
            outcome.goal_outcome,
            judgement.is_approved(),
            minimum_rounds_met,
        );

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
                "minimum_rounds": config.min_rounds,
                "minimum_rounds_met": minimum_rounds_met,
                "quality_score": quality_score,
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
            quality_score,
            ts_start: round_ts_start,
            ts_end: round_ts_end,
        });

        final_text = round_text;

        if goal_met_this_round && stop_approved {
            info!(
                loop_id = %loop_id,
                round = round_num,
                "loop-engine: goal and structural stop criteria confirmed — preserving judged response"
            );
            stop_reason = StopReason::Converged;
            break;
        }

        if tool_budget_reached {
            info!(
                loop_id = %loop_id,
                round = round_num,
                accumulated_tool_calls = state.accumulated_tool_calls,
                budget = config.tool_call_budget,
                "loop-engine: tool-call budget reached — stopping before another round"
            );
            stop_reason = StopReason::BudgetExceeded;
            break;
        }

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
    goal_outcome =
        finalize_goal_outcome(configured_goal_hash.is_some(), &stop_reason, goal_outcome);

    // --- WAL: LOOP_COMPLETED ---
    // GOLD-LOOP-05 — the budget-escalation audit rides HERE: the WAL byte
    // space is exhausted (255/256 codes assigned), so a dedicated
    // LOOP_ESCALATED event is impossible AND redundant — a budget exit is
    // grep-able as `stop_reason: "budget_exceeded"` and now carries the
    // numbers a dedicated frame would have carried.
    let mut completed = serde_json::json!({
        "loop_id": loop_id,
        "rounds_run": rounds_run,
        "stop_reason": stop_reason.as_str(),
        "ts_unix": ts_end,
    });
    if matches!(stop_reason, StopReason::BudgetExceeded) {
        completed["accumulated_tool_calls"] = serde_json::json!(state.accumulated_tool_calls);
        completed["budget"] = serde_json::json!(config.tool_call_budget);
    }
    emit_wal(writer, EVENT_TYPE_LOOP_COMPLETED, completed).await;

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
        goal_outcome,
        goal_hash: configured_goal_hash,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct CountingLoopProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for CountingLoopProvider {
        fn name(&self) -> &'static str {
            "loop_budget_test"
        }

        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: "ok".into(),
                identity: crate::providers::CompletionIdentity {
                    provider: "loop_budget_test".into(),
                    wire_model: "test-model".into(),
                    dispatch_route: Vec::new(),
                },
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

    struct FixedLoopProvider {
        calls: Arc<AtomicUsize>,
        text: String,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for FixedLoopProvider {
        fn name(&self) -> &'static str {
            "fixed_loop_test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("test-model")
        }

        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: self.text.clone(),
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

    struct RecordingLoopProvider {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for RecordingLoopProvider {
        fn name(&self) -> &'static str {
            "recording_loop_test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("test-model")
        }

        async fn complete(
            &self,
            req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.prompts.lock().unwrap().push(req.prompt);
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: "round output".into(),
                identity: crate::providers::CompletionIdentity {
                    provider: "recording_loop_test".into(),
                    wire_model: "test-model".into(),
                    dispatch_route: Vec::new(),
                },
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

    #[tokio::test]
    async fn council_loop_provider_cannot_dispatch_past_shared_budget() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingLoopProvider {
            calls: Arc::clone(&calls),
        };
        let budget = crate::council::BudgetToken::new(1);
        let provider = CouncilBudgetedLoopProvider {
            inner: &inner,
            budget: budget.clone(),
        };

        crate::providers::Provider::complete(&provider, crate::providers::Request::default())
            .await
            .unwrap();
        let error =
            crate::providers::Provider::complete(&provider, crate::providers::Request::default())
                .await
                .expect_err("second dissent-loop leaf must be rejected");

        assert!(error.to_string().contains("budget exhausted"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(budget.used(), 1);
        assert!(budget.was_denied());
    }

    #[tokio::test]
    async fn minimum_rounds_defers_empty_until_convergence_and_feeds_next_prompt() {
        let home = TempDir::new().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(home.path().join("minimum-rounds.wal")).unwrap();
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let provider = RecordingLoopProvider {
            prompts: Arc::clone(&prompts),
        };
        let config = LoopConfig {
            min_rounds: 2,
            max_rounds: 2,
            until: vec![],
            tool_call_budget: Some(10),
            autonomy: AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: home.path().to_path_buf(),
        };
        let freedom = crate::config::FreedomConfig {
            autonomy: AutonomyLevel::Full,
            ..Default::default()
        };
        let record = run_loop(
            &config,
            &provider,
            crate::providers::Request {
                prompt: "verify the result".into(),
                model: Some("test-model".into()),
                ..Default::default()
            },
            &crate::mcp::McpServers::default(),
            &writer,
            &freedom,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                AutonomyLevel::Full,
            ),
            None,
            &crate::mcp::McpToolScope::default(),
            &crate::cli::elicitation::ElicitationHandler::Disabled,
            None,
        )
        .await
        .expect("minimum-round loop");
        drop(writer);
        join.await.unwrap();

        assert_eq!(record.rounds_run, 2);
        assert_eq!(record.stop_reason, StopReason::Converged);
        assert!(!record.per_round[0].stop_approved);
        assert!(record.per_round[1].stop_approved);
        let prompts = prompts.lock().unwrap();
        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[0], "verify the result");
        assert!(prompts[1].contains("Previous round (#1) produced"));
        assert!(prompts[1].contains("round output"));
    }

    #[tokio::test]
    async fn outer_loop_propagates_goal_dispatch_unavailable_without_convergence() {
        let home = TempDir::new().unwrap();
        let wal_path = home.path().join("outer-goal-unavailable.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = FixedLoopProvider {
            calls: Arc::clone(&calls),
            text: r#"```mcp-tool-call
{"server":"missing","tool":"read","arguments":{}}
```"#
                .into(),
        };
        let goal = "complete the unavailable outer-loop operation";
        let mut freedom = crate::config::FreedomConfig {
            autonomy: AutonomyLevel::Full,
            ..Default::default()
        };
        freedom.goal.goal = Some(goal.into());
        freedom.goal.judge_enabled = false;
        let config = LoopConfig {
            min_rounds: 1,
            max_rounds: 2,
            until: vec![],
            tool_call_budget: Some(10),
            autonomy: AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: home.path().to_path_buf(),
        };
        let req = crate::providers::Request {
            prompt: "read it".into(),
            model: Some("test-model".into()),
            ..Default::default()
        };

        let error = run_loop(
            &config,
            &provider,
            req,
            &crate::mcp::McpServers::default(),
            &writer,
            &freedom,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                AutonomyLevel::Full,
            ),
            None,
            &crate::mcp::McpToolScope::default(),
            &crate::cli::elicitation::ElicitationHandler::Disabled,
            None,
        )
        .await
        .expect_err("an unavailable goal round must not become outer convergence");
        drop(writer);
        join.await.unwrap();

        assert!(matches!(
            error.downcast_ref::<crate::mcp::goal_tracker::GoalIntegrityError>(),
            Some(crate::mcp::goal_tracker::GoalIntegrityError::DispatchUnavailable)
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the outer loop must not retry or fall through after the typed goal failure"
        );

        let bytes = std::fs::read(wal_path).unwrap();
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut unavailable_hashes = Vec::new();
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_GOAL_JUDGED {
                let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                if payload["kind"] == "unavailable" {
                    unavailable_hashes
                        .push(payload["goal_hash"].as_str().unwrap_or_default().to_owned());
                }
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(
            unavailable_hashes,
            vec![crate::mcp::goal_judge::goal_hash(goal)]
        );
    }

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
            goal_outcome: GoalOutcome::Met,
            goal_hash: Some("0123456789abcdef".into()),
            per_round: vec![LoopRound {
                round_num: 1,
                iterations: 3,
                hit_cap: false,
                successful_calls: 2,
                failed_calls: 0,
                stop_approved: false,
                refine_fired: false,
                quality_score: 0.75,
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
        assert_eq!(back.goal_outcome, GoalOutcome::Met);
        assert_eq!(back.goal_hash.as_deref(), Some("0123456789abcdef"));
        assert_eq!(back.per_round.len(), 1);
    }

    #[test]
    fn later_goal_met_supersedes_an_earlier_inner_cap() {
        let aggregated = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            GoalOutcome::None,
            GoalOutcome::Met,
        )
        .unwrap();
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::CapHit, aggregated),
            GoalOutcome::Met,
            "a historical inner cap must not overwrite a later confirmed goal"
        );

        let outcome = LoopRunRecord {
            loop_id: "loop_goal_met".into(),
            prompt_hash: "deadbeef".into(),
            rounds_run: 2,
            stop_reason: StopReason::Converged,
            total_tool_calls: None,
            goal_outcome: GoalOutcome::Met,
            goal_hash: Some("0123456789abcdef".into()),
            per_round: vec![
                LoopRound {
                    round_num: 1,
                    iterations: 8,
                    hit_cap: true,
                    successful_calls: 1,
                    failed_calls: 0,
                    stop_approved: false,
                    refine_fired: false,
                    quality_score: 0.5,
                    ts_start: 1,
                    ts_end: 2,
                },
                LoopRound {
                    round_num: 2,
                    iterations: 2,
                    hit_cap: false,
                    successful_calls: 0,
                    failed_calls: 0,
                    stop_approved: true,
                    refine_fired: false,
                    quality_score: 1.0,
                    ts_start: 3,
                    ts_end: 4,
                },
            ],
            final_text: "done".into(),
            ts_start: 1,
            ts_end: 4,
        }
        .into_dispatch_outcome();

        assert_eq!(outcome.goal_outcome, GoalOutcome::Met);
        assert!(!outcome.hit_cap);
        assert_eq!(outcome.goal_hash.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn historical_inner_budget_exhaustion_is_not_terminal_after_convergence() {
        let after_inner_cap = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            GoalOutcome::None,
            GoalOutcome::BudgetExhausted,
        )
        .unwrap();
        let after_later_clean_round = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            after_inner_cap,
            GoalOutcome::None,
        )
        .unwrap();
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::Converged, after_later_clean_round,),
            GoalOutcome::None
        );
    }

    #[test]
    fn historical_met_does_not_certify_replaced_final_bytes() {
        let after_met = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            GoalOutcome::None,
            GoalOutcome::Met,
        )
        .unwrap();
        let after_replacement = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            after_met,
            GoalOutcome::None,
        )
        .unwrap();

        assert_eq!(after_replacement, GoalOutcome::None);
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::CapHit, after_replacement),
            GoalOutcome::BudgetExhausted,
            "a later unjudged response must not inherit an earlier Met verdict"
        );
    }

    #[test]
    fn inner_goal_budget_exhaustion_vetoes_only_its_own_round() {
        let verifier_approved = true;
        let first_round = GoalOutcome::BudgetExhausted;
        let first_round_stop_approved = round_stop_approved(first_round, verifier_approved, true);
        assert!(
            !first_round_stop_approved,
            "an empty until-list must not hide inner goal budget exhaustion"
        );

        let after_first_round = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            GoalOutcome::None,
            first_round,
        )
        .unwrap();
        assert_eq!(after_first_round, GoalOutcome::None);
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::CapHit, after_first_round),
            GoalOutcome::BudgetExhausted,
            "outer exhaustion remains terminal when no later round meets the goal"
        );

        let later_round = GoalOutcome::Met;
        let later_round_stop_approved = round_stop_approved(later_round, !verifier_approved, true);
        assert!(
            !later_round_stop_approved,
            "a Met verdict must not bypass explicit structural stop criteria"
        );
        assert!(
            round_stop_approved(later_round, verifier_approved, true),
            "a later Met verdict terminates once the structural gate also approves"
        );
        assert!(
            !round_stop_approved(later_round, verifier_approved, false),
            "a real goal verdict cannot bypass the route's minimum-round invariant"
        );
        let after_later_met = aggregate_goal_outcome(
            Some("0123456789abcdef"),
            Some("0123456789abcdef"),
            after_first_round,
            later_round,
        )
        .unwrap();
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::Converged, after_later_met),
            GoalOutcome::Met
        );
    }

    #[test]
    fn mismatched_inner_goal_hash_is_rejected() {
        let error = aggregate_goal_outcome(
            Some("original"),
            Some("different"),
            GoalOutcome::None,
            GoalOutcome::Met,
        )
        .expect_err("a verdict for another goal must fail closed");
        assert!(matches!(
            error.downcast_ref::<crate::mcp::goal_tracker::GoalIntegrityError>(),
            Some(crate::mcp::goal_tracker::GoalIntegrityError::HashMismatch)
        ));
        assert!(error.to_string().contains("goal hash mismatch"));
    }

    #[test]
    fn final_outer_caps_are_goal_budget_exhaustion() {
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::CapHit, GoalOutcome::None),
            GoalOutcome::BudgetExhausted
        );
        assert_eq!(
            finalize_goal_outcome(true, &StopReason::BudgetExceeded, GoalOutcome::None,),
            GoalOutcome::BudgetExhausted
        );
        assert_eq!(
            finalize_goal_outcome(false, &StopReason::CapHit, GoalOutcome::None),
            GoalOutcome::None
        );
    }

    #[test]
    fn legacy_loop_record_defaults_goal_lifecycle_fields() {
        let legacy = serde_json::json!({
            "loop_id": "legacy",
            "prompt_hash": "deadbeef",
            "rounds_run": 0,
            "stop_reason": "cap_hit",
            "total_tool_calls": null,
            "per_round": [],
            "final_text": "",
            "ts_start": 0,
            "ts_end": 1
        });
        let record: LoopRunRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(record.goal_outcome, GoalOutcome::None);
        assert_eq!(record.goal_hash, None);
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
            goal_outcome: GoalOutcome::BudgetExhausted,
            goal_hash: Some("fedcba9876543210".into()),
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
        let handles = (0..8)
            .map(|_| std::thread::spawn(|| (0..256).map(|_| new_loop_id()).collect::<Vec<_>>()))
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("loop-id worker must not panic"))
            .collect::<Vec<_>>();
        let unique = ids.iter().collect::<std::collections::HashSet<_>>();

        assert!(ids.iter().all(|id| id.starts_with("loop_")));
        assert_eq!(
            unique.len(),
            ids.len(),
            "concurrent loop starts must never share a WAL/file correlation id"
        );
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
        assert_eq!(lc.min_rounds, 1);
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
            None,
        );
        assert_eq!(lc.min_rounds, 1);
        assert_eq!(lc.max_rounds, 1);
        assert!(lc.until.is_empty());
        assert!(!lc.refine_enabled);
    }

    #[test]
    fn shared_entry_rejects_uncapped_or_zero_budget_full_autonomy() {
        for budget in [None, Some(0)] {
            let cfg = LoopConfig {
                min_rounds: 1,
                max_rounds: 1,
                until: vec![],
                tool_call_budget: budget,
                autonomy: AutonomyLevel::Full,
                refine_enabled: false,
                neoth_home: PathBuf::from("/tmp"),
            };
            assert!(cfg.validate_safety().is_err(), "budget={budget:?}");
        }

        let capped = LoopConfig {
            min_rounds: 1,
            max_rounds: 1,
            until: vec![],
            tool_call_budget: Some(1),
            autonomy: AutonomyLevel::Full,
            refine_enabled: false,
            neoth_home: PathBuf::from("/tmp"),
        };
        assert!(capped.validate_safety().is_ok());
    }

    #[test]
    fn shared_entry_rejects_zero_rounds_for_every_caller() {
        let cfg = LoopConfig {
            min_rounds: 1,
            max_rounds: 0,
            until: vec![],
            tool_call_budget: None,
            autonomy: AutonomyLevel::Standard,
            refine_enabled: false,
            neoth_home: PathBuf::from("/tmp"),
        };
        assert!(cfg.validate_safety().is_err());
    }

    #[test]
    fn shared_entry_rejects_invalid_minimum_rounds() {
        for (min_rounds, max_rounds) in [(0, 1), (2, 1)] {
            let cfg = LoopConfig {
                min_rounds,
                max_rounds,
                until: vec![],
                tool_call_budget: None,
                autonomy: AutonomyLevel::Standard,
                refine_enabled: false,
                neoth_home: PathBuf::from("/tmp"),
            };
            assert!(
                cfg.validate_safety().is_err(),
                "min={min_rounds}, max={max_rounds}"
            );
        }
    }

    #[test]
    fn is_elevated_or_full_gate() {
        assert!(!is_elevated_or_full(AutonomyLevel::Strict));
        assert!(!is_elevated_or_full(AutonomyLevel::Standard));
        assert!(is_elevated_or_full(AutonomyLevel::Elevated));
        assert!(is_elevated_or_full(AutonomyLevel::Full));
    }

    #[test]
    fn round_refine_gate_uses_measured_quality_instead_of_constant_zero() {
        let high_quality = format!("{}\n\n- verified\n- complete", "substantive ".repeat(80));
        let high = round_quality_score("claude_cli", &high_quality);
        let low = round_quality_score("claude_cli", "I'm sorry, but I cannot help.");
        assert!(high >= 0.90, "high-quality score was {high}");
        assert!(low < 0.90, "low-quality score was {low}");

        let mut freedom = crate::config::FreedomConfig::default();
        freedom.council.self_reflect_enabled = true;
        freedom.council.refine_threshold = Some(0.90);
        assert!(!crate::council::self_reflect::should_refine(
            &freedom, high, 0
        ));
        assert!(crate::council::self_reflect::should_refine(
            &freedom, low, 0
        ));
    }

    /// Verifies that the LoopState stop verifier approves an unconstrained stop.
    #[test]
    fn loop_state_no_criteria_always_approves() {
        let cfg = LoopConfig {
            min_rounds: 1,
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
        assert!(
            j.is_approved(),
            "no-criteria verifier must approve any stop"
        );
    }

    /// Verifies that the LoopState stop verifier rejects an unmet criterion.
    #[test]
    fn loop_state_unmet_criterion_rejects() {
        let cfg = LoopConfig {
            min_rounds: 1,
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
