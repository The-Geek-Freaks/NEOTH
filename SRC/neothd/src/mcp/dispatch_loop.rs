//! Autonomous MCP tool-call dispatcher loop (CDX-05 closure).
//!
//! Pulls together Step 1 (catalogue injection) + Step 2 (tool-call
//! parsing) + the gate to give chat dispatch real autonomous tool use:
//!
//! 1. Caller issues an initial LLM completion (system prompt already
//!    contains the catalogue from [`super::catalogue::assemble_catalogue`]).
//! 2. [`run_tool_loop`] scans the LLM response for ```mcp-tool-call
//!    blocks via [`super::tool_call_parser::extract_tool_calls`].
//! 3. For each parsed call: lookup the configured server, spawn a
//!    client, dispatch via [`super::gate::invoke_with_audit`] (allowlist
//!    + autonomy + WAL audit all enforced).
//! 4. Tool results + parse errors are rendered as text and threaded
//!    back to the LLM as the next user message.
//! 5. The completion is re-issued. Loop terminates when (a) the LLM
//!    response carries no tool-call fences, (b) the iteration cap is
//!    hit, or (c) every call in a round failed before reaching the
//!    server (no point feeding the LLM nothing-but-errors forever).
//!
//! The function is generic over the completion closure so chat.rs can
//! keep its full request-building logic + this module can unit-test
//! the loop against a mock provider.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use tracing::{error, info, warn};

use crate::mcp::config::McpServers;
use crate::mcp::tool_call_parser::{ParseError, ParsedToolCall, extract_tool_calls};
use crate::permissions::AutonomyLevel;
use crate::wal::writer::WalWriterHandle;

/// Cap on dispatcher iterations. Prevents a model that emits a
/// degenerate tool-call → reply → tool-call loop from burning the
/// operator's spend forever. 5 covers realistic chains (read file →
/// summarise → write reply); operators who need more chain depth lift
/// via [`run_tool_loop_with_cap`].
pub const DEFAULT_MAX_ITERATIONS: u32 = 5;

/// Outcome of one dispatcher run.
#[derive(Debug, Clone)]
pub struct LoopOutcome {
    /// Final assistant response text (the last completion's `text`).
    pub final_text: String,
    /// Number of iterations actually run (1 = no tool calls in initial response).
    pub iterations: u32,
    /// Whether the loop terminated because of the iteration cap.
    pub hit_cap: bool,
    /// Total successful tool invocations across all iterations.
    pub successful_calls: u32,
    /// Total parse errors + dispatch failures across all iterations.
    pub failed_calls: u32,
}

/// Caller-supplied completion driver. Takes the (already-assembled)
/// prompt string for the current iteration + returns the LLM response
/// text. Implementations typically wrap their existing `Provider::complete`
/// call with whatever request-shape building they do upstream.
pub trait CompletionDriver {
    fn complete<'a>(
        &'a mut self,
        prompt: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
}

/// Run the dispatch loop with the default iteration cap.
#[allow(clippy::too_many_arguments)]
pub async fn run_tool_loop<D: CompletionDriver + Send>(
    driver: &mut D,
    initial_prompt: String,
    servers: &McpServers,
    autonomy: AutonomyLevel,
    writer: Option<&WalWriterHandle>,
    rollback_policy: Option<&crate::config::RollbackConfig>,
    skill_allowlist: Option<&[String]>,
    // GOLD-ADOPT-23 P0 — explicit so no caller silently inherits an Allow-only
    // gate (security review Finding 4). Pass `&SecurityPolicy::default()` to
    // accept the secure defaults (deny dangerous, warn egress).
    security_policy: &crate::config::SecurityPolicy,
) -> Result<LoopOutcome> {
    run_tool_loop_with_cap(
        driver,
        initial_prompt,
        servers,
        autonomy,
        writer,
        rollback_policy,
        skill_allowlist,
        DEFAULT_MAX_ITERATIONS,
        security_policy,
        crate::mcp::goal_tracker::GoalContext::empty(),
        true, // GOLD-ADOPT-18 — hints default-on for the convenience wrapper.
        // GOLD-ADOPT-19 — compaction off in the bare wrapper; the chat path
        // builds an explicit policy from freedom.yaml. Keeps the wrapper's
        // (test-only) callers free of surprise summarization calls.
        crate::context::compaction::CompactionPolicy::disabled(),
    )
    .await
}

/// Run the dispatch loop with an explicit iteration cap. Mostly for
/// tests + operators who want to widen the chain.
#[allow(clippy::too_many_arguments)]
pub async fn run_tool_loop_with_cap<D: CompletionDriver + Send>(
    driver: &mut D,
    initial_prompt: String,
    servers: &McpServers,
    autonomy: AutonomyLevel,
    writer: Option<&WalWriterHandle>,
    rollback_policy: Option<&crate::config::RollbackConfig>,
    skill_allowlist: Option<&[String]>,
    max_iterations: u32,
    // GOLD-ADOPT-23 P0 — egress + dangerous-command policy gate.
    security_policy: &crate::config::SecurityPolicy,
    // GOLD-ADOPT-22 — Goal/Grind nudge context (empty = no nudging).
    goal_context: crate::mcp::goal_tracker::GoalContext,
    // GOLD-ADOPT-18 — subdirectory-hint injection toggle (`freedom.yaml::hints.enabled`,
    // default true). `false` disables the tracker entirely (no FS reads).
    hints_enabled: bool,
    // GOLD-ADOPT-19 — auto context-compaction policy. When enabled, the
    // accumulated prompt is LLM-summarized once it crosses the token threshold,
    // before the next completion. `CompactionPolicy::disabled()` = off.
    compaction: crate::context::compaction::CompactionPolicy,
) -> Result<LoopOutcome> {
    let mut prompt = initial_prompt;
    let mut iterations = 0u32;
    let mut hit_cap = false;
    let mut successful_calls = 0u32;
    let mut failed_calls = 0u32;
    let mut current_text;
    // GOLD-ADOPT-20 — stuck-loop guard, accumulated across all rounds of this
    // loop invocation. A blocked call is not dispatched; the LLM sees a notice
    // and (if every call in a round is blocked) the all-failed termination fires.
    let mut repetition_guard = crate::mcp::repetition_guard::ToolRepetitionGuard::with_defaults();
    // GOLD-ADOPT-22 — Goal/Grind tracker: on a clean exit (no tool calls), inject
    // one more nudge instead of stopping, until the goal is checked / the grind
    // is bounded by max_iterations.
    let mut goal_tracker = crate::mcp::goal_tracker::GoalTracker::new(goal_context);
    // GOLD-ADOPT-22 — SmartApprove read-only cache, session-scoped (persists
    // across loop iterations so a server's tool annotations are seeded once).
    // `Some` only when the operator opted in via `security.smart_approve`; the
    // gate auto-approves a Confirm-gated call iff the tool's DECLARED EFFECT
    // metadata marks it read-only. Discarded when the loop returns.
    let mut smart_cache = security_policy
        .smart_approve
        .then(crate::mcp::smart_approve::ReadOnlyCache::new);
    // GOLD-ADOPT-18 — subdirectory-hint tracker (session-scoped, like the
    // guards above). As the agent issues tool calls with path args, the first
    // time it enters a dir under cwd we inject that dir's .neothhints/AGENTS.md
    // once. No-op when no hint files exist (e.g. the channel/daemon cwd).
    let mut hint_tracker =
        hints_enabled.then(crate::mcp::hints::SubdirHintTracker::new);
    let hint_cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    loop {
        iterations += 1;
        // GOLD-ADOPT-19 — compact the accumulated history before the next
        // completion if it crossed the threshold. Iteration 1 is the operator's
        // own prompt (never compact that); only the grown prompt (2+) qualifies.
        if iterations > 1 {
            prompt = compact_if_needed(driver, prompt, &compaction, writer, iterations).await;
        }
        current_text = driver.complete(&prompt).await?;
        let extraction = extract_tool_calls(&current_text);
        if extraction.is_empty() {
            // No tool calls → the model thinks it's done. GOLD-ADOPT-22: if a
            // goal/grind is active and we're under the cap, inject one nudge and
            // keep going; otherwise stop.
            if iterations < max_iterations {
                if let Some(nudge) = goal_tracker.on_clean_exit() {
                    // Visibility (GOLD-ADOPT-22): a grind keeps re-firing — make
                    // sure the operator can see WHY the loop won't stop, and how
                    // to stop it.
                    warn!(
                        iteration = iterations,
                        "goal/grind ACTIVE — injecting a nudge instead of stopping \
                         (clear with `neoth goal off`)"
                    );
                    prompt = format!("{prompt}\n\n{current_text}\n\n{nudge}");
                    continue;
                }
            }
            break;
        }
        if iterations >= max_iterations {
            hit_cap = true;
            warn!(
                iterations,
                "MCP dispatch loop hit iteration cap, returning last response"
            );
            break;
        }
        let mut iteration_had_success = false;
        let mut tool_result_blocks = Vec::new();
        for call in &extraction.calls {
            // GOLD-ADOPT-20 — block runaway repetition BEFORE spawning a server.
            let verdict = repetition_guard.check(call);
            if verdict.is_blocked() {
                failed_calls += 1;
                warn!(
                    server = %call.server,
                    tool = %call.tool,
                    "tool-repetition guard blocked a call (stuck-loop protection)"
                );
                tool_result_blocks.push(format_guard_block(call, &verdict));
                continue;
            }
            // GOLD-ADOPT-23 P0 — scan the call's arguments for outbound egress +
            // dangerous shell patterns, ALWAYS surface them (tracing warn), then
            // apply the operator's risk policy as a deny/confirm GATE.
            let risk = crate::security::inspect_tool_args(&call.arguments);
            if !risk.is_empty() {
                for d in &risk.dangerous {
                    warn!(
                        server = %call.server, tool = %call.tool,
                        rule = d.id, severity = d.severity.as_str(),
                        "dangerous-command pattern in tool call: {}", d.reason
                    );
                }
                for e in &risk.egress {
                    warn!(
                        server = %call.server, tool = %call.tool,
                        kind = %e.kind, domain = %e.domain,
                        "outbound egress destination in tool call"
                    );
                }
                let mut gate = crate::security::risk_gate::evaluate_tool_risk(&risk, security_policy);
                // GOLD-ADOPT-23 P1 — an active operator risk-override lease
                // (`neoth lease grant operator dangerous_command|egress --ttl N`)
                // lifts the block for its TTL window. Checked only on a block
                // (rare), so the lease file isn't read on every call.
                if gate.is_blocked() {
                    let (dangerous_leased, egress_leased, lease_id, expired_present) =
                        check_risk_leases(&risk, security_policy.confirm_high);
                    if dangerous_leased || egress_leased {
                        let lifted = crate::security::risk_gate::apply_risk_leases(
                            &risk,
                            security_policy,
                            dangerous_leased,
                            egress_leased,
                        );
                        if !lifted.is_blocked() {
                            warn!(
                                server = %call.server, tool = %call.tool,
                                lease = lease_id.as_deref().unwrap_or("?"),
                                "risk-gate block LIFTED by active operator risk-confirm lease"
                            );
                            // GR-032 — single-use: spend the covering lease(s)
                            // NOW so this window authorises exactly ONE blocked
                            // call (matching `neoth risk-confirm`'s "the next
                            // blocked tool call proceeds"), not unlimited calls
                            // until the TTL lapses. The audited id is the one
                            // actually consumed.
                            match consume_risk_leases(dangerous_leased, egress_leased) {
                                Ok(consumed) => {
                                    // GOLD-ADOPT-23 point 3 — the confirm window was spent.
                                    emit_risk_gate_wal(
                                        writer,
                                        call,
                                        crate::wal::events::EVENT_TYPE_RISK_CONFIRM_USED,
                                        "lifted_by_lease",
                                        consumed
                                            .as_deref()
                                            .or(lease_id.as_deref())
                                            .unwrap_or("egress"),
                                    )
                                    .await;
                                    gate = lifted; // now Allow — fall through to dispatch.
                                }
                                Err(e) => {
                                    // M3 (2026-06-12) — fail-CLOSED. The single-use
                                    // consumption could NOT be persisted, so the in-memory
                                    // revoke would not survive a restart / a 2nd instance
                                    // (the lease reloads as valid → reusable until TTL).
                                    // Keep the call BLOCKED rather than lift on an un-spent
                                    // lease: `gate` stays its prior blocked value, so the
                                    // block path below denies + audits it normally.
                                    error!(
                                        server = %call.server, tool = %call.tool, error = %e,
                                        "risk-lease single-use consumption could not be persisted — keeping the call BLOCKED (fail-closed); re-run `neoth risk-confirm`"
                                    );
                                }
                            }
                        }
                    } else if expired_present {
                        // GOLD-ADOPT-23 point 3 — a matching risk-confirm lease
                        // existed but lapsed; surface it so the operator knows the
                        // window closed (re-run `neoth risk-confirm`).
                        let rule = risk.dangerous.first().map(|d| d.id).unwrap_or("egress");
                        emit_risk_gate_wal(
                            writer,
                            call,
                            crate::wal::events::EVENT_TYPE_RISK_CONFIRM_EXPIRED,
                            "expired",
                            rule,
                        )
                        .await;
                    }
                }
                if gate.is_blocked() {
                    failed_calls += 1;
                    let (status, reason) = match &gate {
                        crate::security::risk_gate::RiskGate::Deny(r) => ("DENIED", r.as_str()),
                        crate::security::risk_gate::RiskGate::Confirm(r) => {
                            ("CONFIRM_REQUIRED", r.as_str())
                        }
                        crate::security::risk_gate::RiskGate::Allow => unreachable!(),
                    };
                    warn!(
                        server = %call.server, tool = %call.tool, status,
                        "risk policy gate blocked tool call: {reason}"
                    );
                    // GOLD-ADOPT-23 point 4 — DISTINCT audit event per outcome
                    // (RISK_GATE_DENIED / RISK_GATE_CONFIRM_REQUIRED), not the old
                    // single 0xCF-with-verdict-field.
                    let rule = risk.dangerous.first().map(|d| d.id).unwrap_or("egress");
                    let (event_type, verdict) = match &gate {
                        crate::security::risk_gate::RiskGate::Deny(_) => {
                            (crate::wal::events::EVENT_TYPE_RISK_GATE_DENIED, "denied")
                        }
                        crate::security::risk_gate::RiskGate::Confirm(_) => (
                            crate::wal::events::EVENT_TYPE_RISK_GATE_CONFIRM_REQUIRED,
                            "confirm_required",
                        ),
                        crate::security::risk_gate::RiskGate::Allow => unreachable!(),
                    };
                    emit_risk_gate_wal(writer, call, event_type, verdict, rule).await;
                    tool_result_blocks.push(format!(
                        "```mcp-tool-result\n{{\"server\": \"{}\", \"tool\": \"{}\", \"status\": \"{status}\"}}\n{reason}\n```",
                        call.server, call.tool,
                    ));
                    continue;
                }
            }
            match dispatch_one(
                call,
                servers,
                autonomy,
                writer,
                rollback_policy,
                skill_allowlist,
                smart_cache.as_mut(),
            )
            .await
            {
                Ok(rendered) => {
                    successful_calls += 1;
                    iteration_had_success = true;
                    // GR-127 — record the dirs this call touched ONLY after it
                    // passed EVERY gate (repetition + risk + skill-allowlist +
                    // autonomy, all inside dispatch_one) and was actually invoked.
                    // The old code recorded for every parsed call BEFORE the
                    // gates, so a DENIED/blocked call still seeded pending_dirs and
                    // `load_new_hints` below read those dirs' hint files + injected
                    // their content into the next prompt — a side-channel +
                    // injection surface driven by a call the policy refused.
                    if let Some(t) = hint_tracker.as_mut() {
                        t.record_tool_arguments(&call.arguments, &hint_cwd);
                    }
                    tool_result_blocks.push(rendered);
                }
                Err(reason) => {
                    failed_calls += 1;
                    tool_result_blocks.push(format_failure(call, &reason));
                }
            }
        }
        for err in &extraction.errors {
            failed_calls += 1;
            tool_result_blocks.push(format_parse_error(err));
        }
        // Defensive termination: if EVERY call in this iteration failed
        // (no successes), feeding the LLM the same errors next round is
        // unlikely to converge. Break + return the last response so the
        // operator sees what happened.
        if !iteration_had_success && !extraction.calls.is_empty() {
            info!(
                failed = failed_calls,
                "every dispatch in this round failed; terminating loop early",
            );
            break;
        }
        // GOLD-ADOPT-18 — load hints for any newly-entered subdir + audit each.
        let mut hint_blocks: Vec<String> = Vec::new();
        if let Some(t) = hint_tracker.as_mut() {
            let new_hints = t.load_new_hints(&hint_cwd);
            if !new_hints.is_empty() {
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                for h in new_hints {
                    emit_hint_loaded(writer, &h, now_unix).await;
                    hint_blocks.push(h.content);
                }
            }
        }
        prompt = build_next_prompt(&prompt, &current_text, &tool_result_blocks, &hint_blocks);
    }

    Ok(LoopOutcome {
        final_text: current_text,
        iterations,
        hit_cap,
        successful_calls,
        failed_calls,
    })
}

/// GOLD-ADOPT-19 — if `prompt` crossed the compaction threshold, summarize it
/// via one extra `driver.complete` call and return the compacted replacement;
/// otherwise return `prompt` unchanged. Best-effort: a failed summarization
/// keeps the original prompt (the loop proceeds — compaction is an optimization,
/// never a correctness gate). Emits 0x5B START + 0x5C DONE around a real pass.
async fn compact_if_needed<D: CompletionDriver + Send>(
    driver: &mut D,
    prompt: String,
    policy: &crate::context::compaction::CompactionPolicy,
    writer: Option<&WalWriterHandle>,
    iteration: u32,
) -> String {
    if !crate::context::compaction::needs_compaction(&prompt, policy) {
        return prompt;
    }
    let before_tokens = crate::tokens::budget::count_tokens(&prompt);
    emit_compaction_wal(
        writer,
        crate::wal::events::EVENT_TYPE_CONTEXT_COMPACTION_START,
        serde_json::json!({
            "iteration": iteration,
            "prompt_tokens": before_tokens,
            "threshold_tokens": policy.threshold_tokens,
            "ts_unix": now_unix_i64(),
        }),
    )
    .await;

    // GR-120: summarize only the OLDER history and re-attach the most recent
    // exchange verbatim, so the last tool result can never be summarized away
    // (the retention instruction alone was a behavioural hint, not a guarantee).
    let (older, last_exchange) = crate::context::compaction::split_last_exchange(&prompt);
    let summary_prompt = crate::context::compaction::build_compaction_prompt(older);
    match driver.complete(&summary_prompt).await {
        Ok(summary) if !summary.trim().is_empty() => {
            let compacted =
                crate::context::compaction::wrap_summary_with_last_exchange(&summary, last_exchange);
            let after_tokens = crate::tokens::budget::count_tokens(&compacted);
            info!(
                iteration,
                before_tokens, after_tokens, "context compacted (GOLD-ADOPT-19)"
            );
            emit_compaction_wal(
                writer,
                crate::wal::events::EVENT_TYPE_CONTEXT_COMPACTION_DONE,
                serde_json::json!({
                    "iteration": iteration,
                    "before_tokens": before_tokens,
                    "after_tokens": after_tokens,
                    "ts_unix": now_unix_i64(),
                }),
            )
            .await;
            compacted
        }
        Ok(_) => {
            warn!(iteration, "compaction returned empty summary — keeping original prompt");
            prompt
        }
        Err(e) => {
            warn!(iteration, error = %e, "compaction LLM call failed — keeping original prompt");
            prompt
        }
    }
}

/// Append a compaction lifecycle frame (best-effort; a WAL failure must not
/// derail the loop). Shared by START/DONE so the two stay shape-consistent.
async fn emit_compaction_wal(
    writer: Option<&WalWriterHandle>,
    event_type: u8,
    payload: serde_json::Value,
) {
    let Some(w) = writer else { return };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(event_type, &bytes).build();
    if let Err(e) = w.append(header, bytes).await {
        warn!(error = %e, event_type, "compaction WAL append failed");
    }
}

fn now_unix_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_one(
    call: &ParsedToolCall,
    servers: &McpServers,
    autonomy: AutonomyLevel,
    writer: Option<&WalWriterHandle>,
    rollback_policy: Option<&crate::config::RollbackConfig>,
    skill_allowlist: Option<&[String]>,
    smart_approve: Option<&mut crate::mcp::smart_approve::ReadOnlyCache>,
) -> std::result::Result<String, String> {
    let Some(cfg) = servers.get_enabled(&call.server) else {
        return Err(format!(
            "no enabled MCP server `{}` configured. Available: {}",
            call.server,
            list_enabled_ids(servers)
        ));
    };
    // SC-11 — the active skill's tool_allowlist gates BEFORE we even
    // spawn the server (no point starting an MCP subprocess for a tool
    // the matched skill isn't allowed to call). Empty/None ⇒ no
    // restriction; the server-level allowlist still runs inside
    // invoke_with_audit afterwards.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Err(e) = crate::mcp::gate::enforce_skill_allowlist(
        skill_allowlist,
        &call.server,
        &call.tool,
        writer,
        now_unix,
    )
    .await
    {
        return Err(format!("dispatch `{}::{}`: {e}", call.server, call.tool));
    }
    let mut client = crate::mcp::client::McpClient::spawn_with_timeout(
        cfg,
        Duration::from_secs(crate::mcp::client::DEFAULT_REQUEST_TIMEOUT.as_secs()),
    )
    .await
    .map_err(|e| format!("spawn MCP server `{}`: {e}", call.server))?;
    let result = crate::mcp::gate::invoke_with_audit(
        &mut client,
        cfg,
        &call.tool,
        call.arguments.clone(),
        autonomy,
        writer,
        rollback_policy,
        smart_approve,
        now_unix,
    )
    .await
    .map_err(|e| format!("dispatch `{}::{}`: {e}", call.server, call.tool))?;
    Ok(format_success(call, &result))
}

fn format_success(call: &ParsedToolCall, result: &crate::mcp::client::ToolCallResult) -> String {
    let mut body = String::new();
    for c in &result.content {
        match c {
            crate::mcp::client::McpContent::Text { text } => {
                body.push_str(text);
                body.push('\n');
            }
            crate::mcp::client::McpContent::Image { data, mime_type } => {
                body.push_str(&format!(
                    "[image {mime_type}, {} bytes — not rendered]\n",
                    data.len()
                ));
            }
            crate::mcp::client::McpContent::Other => {
                body.push_str("[non-text content omitted]\n");
            }
        }
    }
    let status = if result.is_error { "ERROR" } else { "OK" };
    format!(
        "```mcp-tool-result\n{{\"server\": \"{}\", \"tool\": \"{}\", \"status\": \"{}\"}}\n{}```",
        call.server,
        call.tool,
        status,
        body.trim_end_matches('\n'),
    )
}

fn format_failure(call: &ParsedToolCall, reason: &str) -> String {
    format!(
        "```mcp-tool-result\n{{\"server\": \"{}\", \"tool\": \"{}\", \"status\": \"FAILED\"}}\n{reason}\n```",
        call.server, call.tool,
    )
}

/// GOLD-ADOPT-23 (operator points 3+4) — append a DISTINCT-TYPE risk-gate audit
/// frame. `event_type` is one of `RISK_GATE_DENIED` / `RISK_GATE_CONFIRM_REQUIRED`
/// / `RISK_CONFIRM_USED` / `RISK_CONFIRM_EXPIRED`, so `neoth wal show --type
/// risk_gate_denied` filters precisely (the operator's preference over the old
/// single `0xCF`-with-verdict-field). `verdict` mirrors the outcome in the
/// payload for human readers; `rule` is the dangerous rule id, `egress`, or a
/// lease id. The raw command is NEVER recorded.
async fn emit_risk_gate_wal(
    writer: Option<&WalWriterHandle>,
    call: &ParsedToolCall,
    event_type: u8,
    verdict: &str,
    rule: &str,
) {
    let Some(w) = writer else { return };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = serde_json::to_vec(&serde_json::json!({
        "server": call.server,
        "tool": call.tool,
        "verdict": verdict,
        "rule": rule,
        "ts_unix": ts,
    }))
    .unwrap_or_default();
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = w.append(header, payload).await {
        warn!(error = %e, event_type, "risk-gate audit append failed (audit gap)");
    }
}

/// GOLD-ADOPT-23 (P1 + operator point 3) — check the operator's risk-override
/// leases for the blocking dimensions of `risk`. Returns `(dangerous_leased,
/// egress_leased, first_lease_id, expired_present)` — `expired_present` is true
/// when a matching-scope lease EXISTS but has lapsed (so the dispatch loop can
/// emit `RISK_CONFIRM_EXPIRED` to tell the operator their confirm window closed
/// rather than silently re-blocking). Best-effort: an unreadable lease store
/// fails closed (no override). Only called on a block, so the file isn't read
/// per call.
/// GR-046 — whether a tool-call risk needs the operator's DangerousCommand
/// risk-override lease to lift its block. A Critical dangerous finding always
/// does; a HIGH finding does too ONLY when `confirm_high` is on (it then
/// generates a `Confirm` that `neoth risk-confirm`'s DangerousCommand lease must
/// be able to lift — a High confirm_high block was previously unliftable). Pure
/// → unit-testable.
fn risk_needs_dangerous_lease(risk: &crate::security::ToolCallRisk, confirm_high: bool) -> bool {
    use crate::security::dangerous_command::Severity;
    risk.dangerous
        .iter()
        .any(|d| d.severity == Severity::Critical || (confirm_high && d.severity == Severity::High))
}

fn check_risk_leases(
    risk: &crate::security::ToolCallRisk,
    confirm_high: bool,
) -> (bool, bool, Option<String>, bool) {
    use crate::permissions::lease::{LeaseScope, LeaseStore};
    use crate::security::risk_gate::RISK_LEASE_SUBJECT;

    let home = crate::config::FreedomConfig::default_neoth_home();
    let Ok(store) = LeaseStore::load(&LeaseStore::default_path(&home)) else {
        return (false, false, None, false);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let needs_dangerous = risk_needs_dangerous_lease(risk, confirm_high);
    let needs_egress = !risk.egress.is_empty();
    let mut lease_id = None;
    let dangerous_leased = needs_dangerous
        && match store.find_covering(RISK_LEASE_SUBJECT, &LeaseScope::DangerousCommand, now) {
            Some(l) => {
                lease_id = Some(l.lease_id.clone());
                true
            }
            None => false,
        };
    let egress_leased = needs_egress
        && match store.find_covering(RISK_LEASE_SUBJECT, &LeaseScope::Egress, now) {
            Some(l) => {
                if lease_id.is_none() {
                    lease_id = Some(l.lease_id.clone());
                }
                true
            }
            None => false,
        };
    // A lease for a needed scope that exists but is no longer active.
    let scope_expired = |scope: &LeaseScope| {
        store
            .leases
            .iter()
            .any(|l| l.granted_to == RISK_LEASE_SUBJECT && &l.scope == scope && !l.is_active(now))
    };
    let expired_present = (needs_dangerous && !dangerous_leased && scope_expired(&LeaseScope::DangerousCommand))
        || (needs_egress && !egress_leased && scope_expired(&LeaseScope::Egress));
    (dangerous_leased, egress_leased, lease_id, expired_present)
}

/// GR-032 — make a risk-override confirm SINGLE-USE: remove the active covering
/// lease(s) for the lifted dimension(s) from `leases.json` and persist, so the
/// NEXT blocked call in the (still-unexpired) window re-blocks instead of
/// silently proceeding. Returns one consumed lease id for the audit frame.
/// Best-effort: a save failure is warned (the lease stays reusable until expiry)
/// but never blocks the in-flight, already-authorised call.
fn consume_risk_leases(
    consume_dangerous: bool,
    consume_egress: bool,
) -> anyhow::Result<Option<String>> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    consume_risk_leases_at(&home, consume_dangerous, consume_egress)
}

/// M3 (2026-06-12) — home-injectable core so the single-use persistence + the
/// fail-closed save path are hermetically testable (the wrapper above resolves
/// the real `~/.neoth`). Returns `Err` when the single-use revoke can't be
/// persisted to disk, so the caller keeps the lifted call BLOCKED rather than
/// letting an un-spent lease stay reusable until its TTL lapses.
fn consume_risk_leases_at(
    home: &std::path::Path,
    consume_dangerous: bool,
    consume_egress: bool,
) -> anyhow::Result<Option<String>> {
    use crate::permissions::lease::{LeaseScope, LeaseStore};
    use crate::security::risk_gate::RISK_LEASE_SUBJECT;

    let path = LeaseStore::default_path(home);
    let Ok(mut store) = LeaseStore::load(&path) else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut consumed: Option<String> = None;
    if consume_dangerous {
        if let Some(id) = store
            .find_covering(RISK_LEASE_SUBJECT, &LeaseScope::DangerousCommand, now)
            .map(|l| l.lease_id.clone())
        {
            store.revoke(&id);
            consumed = Some(id);
        }
    }
    if consume_egress {
        if let Some(id) = store
            .find_covering(RISK_LEASE_SUBJECT, &LeaseScope::Egress, now)
            .map(|l| l.lease_id.clone())
        {
            store.revoke(&id);
            consumed.get_or_insert(id);
        }
    }
    if consumed.is_some() {
        store
            .save(&path)
            .map_err(|e| anyhow::anyhow!("persist single-use risk-lease consumption: {e}"))?;
    }
    Ok(consumed)
}

/// GOLD-ADOPT-20 — render a repetition-guard block as an operator-visible
/// tool-result so the LLM sees WHY the call didn't run and changes approach.
fn format_guard_block(
    call: &ParsedToolCall,
    verdict: &crate::mcp::repetition_guard::GuardVerdict,
) -> String {
    use crate::mcp::repetition_guard::GuardVerdict;
    let reason = match verdict {
        GuardVerdict::BlockedConsecutive { count, .. } => format!(
            "repetition guard: this identical call was issued {count} times in a row and was NOT \
             executed. Change your approach — the repeated call is not making progress."
        ),
        GuardVerdict::BlockedCeiling { tool, count } => format!(
            "repetition guard: `{tool}` has been called {count} times this turn (ceiling reached) \
             and was NOT executed. Stop calling it and try a different strategy or finish."
        ),
        GuardVerdict::Allow => "repetition guard: allowed".to_string(),
    };
    format!(
        "```mcp-tool-result\n{{\"server\": \"{}\", \"tool\": \"{}\", \"status\": \"BLOCKED\"}}\n{reason}\n```",
        call.server, call.tool,
    )
}

fn format_parse_error(err: &ParseError) -> String {
    format!(
        "```mcp-tool-result\n{{\"status\": \"PARSE_ERROR\"}}\n{}\nOriginal block: {}\n```",
        err.reason,
        err.raw_block.trim(),
    )
}

fn build_next_prompt(
    prior_prompt: &str,
    assistant_reply: &str,
    tool_blocks: &[String],
    hint_blocks: &[String],
) -> String {
    let mut out = String::with_capacity(
        prior_prompt.len()
            + assistant_reply.len()
            + tool_blocks.iter().map(|b| b.len()).sum::<usize>()
            + hint_blocks.iter().map(|b| b.len()).sum::<usize>()
            + 256,
    );
    out.push_str(prior_prompt);
    out.push_str("\n\n[assistant]\n");
    out.push_str(assistant_reply);
    out.push_str("\n\n[tool results]\n");
    for b in tool_blocks {
        out.push_str(b);
        out.push('\n');
    }
    // GOLD-ADOPT-18 — per-directory conventions the agent just entered.
    if !hint_blocks.is_empty() {
        out.push_str("\n[subdirectory hints — directory-specific conventions]\n");
        for b in hint_blocks {
            out.push_str(b);
            out.push('\n');
        }
    }
    out.push_str(
        "\nContinue. Emit more `mcp-tool-call` blocks if you need to, or finish your reply.",
    );
    out
}

/// GOLD-ADOPT-18 — audit a subdirectory-hint injection (`0x58 HINT_LOADED`).
/// Records the dir + injected byte count only — never the hint body.
async fn emit_hint_loaded(
    writer: Option<&WalWriterHandle>,
    hint: &crate::mcp::hints::LoadedHint,
    now_unix: i64,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::to_vec(&serde_json::json!({
        "dir": hint.dir.display().to_string(),
        "bytes": hint.content.len(),
        "ts_unix": now_unix,
    }))
    .unwrap_or_default();
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_HINT_LOADED, &payload).build();
    if let Err(e) = w.append(header, payload).await {
        warn!(error = %e, "HINT_LOADED append failed");
    }
}

fn list_enabled_ids(servers: &McpServers) -> String {
    let ids: Vec<&str> = servers.enabled().iter().map(|s| s.id.as_str()).collect();
    if ids.is_empty() {
        "(none)".into()
    } else {
        ids.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test driver — fixed-script responder. Each `complete` call
    /// returns the next item from `responses`. Captures every prompt
    /// it saw so tests can assert what was threaded back.
    struct ScriptedDriver {
        responses: Vec<String>,
        cursor: Arc<AtomicUsize>,
        seen_prompts: std::sync::Mutex<Vec<String>>,
    }

    impl ScriptedDriver {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: responses.into_iter().map(String::from).collect(),
                cursor: Arc::new(AtomicUsize::new(0)),
                seen_prompts: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl CompletionDriver for ScriptedDriver {
        fn complete<'a>(
            &'a mut self,
            prompt: &'a str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
            self.seen_prompts.lock().unwrap().push(prompt.to_string());
            let idx = self.cursor.fetch_add(1, Ordering::SeqCst);
            let resp = self
                .responses
                .get(idx)
                .cloned()
                .unwrap_or_else(|| "(no more scripted responses)".to_string());
            Box::pin(async move { Ok(resp) })
        }
    }

    // ── GOLD-ADOPT-19 context compaction ───────────────────────────────────

    #[tokio::test]
    async fn compact_if_needed_summarizes_over_threshold() {
        use crate::context::compaction::{CompactionPolicy, SUMMARY_MARKER};
        let mut driver = ScriptedDriver::new(vec!["did X; pending: fetch Y"]);
        let policy = CompactionPolicy {
            enabled: true,
            threshold_tokens: 1,
            progressive: false,
        };
        let big = "history ".repeat(50);
        let out = compact_if_needed(&mut driver, big, &policy, None, 2).await;
        assert!(out.starts_with(SUMMARY_MARKER), "compacted prompt carries the marker");
        assert!(out.contains("pending: fetch Y"), "summary content is preserved");
        // The driver received the retention-instructed compaction prompt.
        let seen = driver.seen_prompts.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("DENSE SUMMARY:"));
    }

    #[tokio::test]
    async fn compact_if_needed_is_noop_under_threshold() {
        use crate::context::compaction::CompactionPolicy;
        let mut driver = ScriptedDriver::new(vec!["MUST NOT BE CALLED"]);
        let policy = CompactionPolicy {
            enabled: true,
            threshold_tokens: 1_000_000,
            progressive: false,
        };
        let original = "a short prompt".to_string();
        let out = compact_if_needed(&mut driver, original.clone(), &policy, None, 2).await;
        assert_eq!(out, original, "under threshold the prompt is unchanged");
        assert!(
            driver.seen_prompts.lock().unwrap().is_empty(),
            "no LLM call when under threshold"
        );
    }

    #[tokio::test]
    async fn compact_if_needed_keeps_original_on_empty_summary() {
        use crate::context::compaction::CompactionPolicy;
        // An empty/whitespace summary is a failed compaction — keep the original
        // prompt rather than replacing the history with nothing.
        let mut driver = ScriptedDriver::new(vec!["   \n  "]);
        let policy = CompactionPolicy {
            enabled: true,
            threshold_tokens: 1,
            progressive: false,
        };
        let original = "big history ".repeat(50);
        let out = compact_if_needed(&mut driver, original.clone(), &policy, None, 2).await;
        assert_eq!(out, original, "empty summary must not discard the prompt");
    }

    #[test]
    fn guard_block_renders_operator_visible_notice() {
        use crate::mcp::repetition_guard::GuardVerdict;
        let call = ParsedToolCall {
            server: "fs".into(),
            tool: "read".into(),
            arguments: serde_json::json!({"path": "a"}),
        };
        let consec = format_guard_block(
            &call,
            &GuardVerdict::BlockedConsecutive {
                tool: "fs::read".into(),
                count: 4,
            },
        );
        assert!(consec.contains("\"status\": \"BLOCKED\""));
        assert!(consec.contains("4 times in a row"));
        let ceil = format_guard_block(
            &call,
            &GuardVerdict::BlockedCeiling {
                tool: "fs::read".into(),
                count: 26,
            },
        );
        assert!(ceil.contains("ceiling reached"));
        assert!(ceil.contains("26 times"));
    }

    #[tokio::test]
    async fn risk_gate_denies_dangerous_call_before_dispatch() {
        // GOLD-ADOPT-23 P0: a tool call carrying `rm -rf /` is blocked by the
        // default deny policy — it never reaches dispatch (which would fail on
        // the unknown server anyway), and the all-blocked round terminates.
        let reply = r#"I'll clean up.
```mcp-tool-call
{"server": "shell", "tool": "exec", "arguments": {"command": "rm -rf /"}}
```
"#;
        let mut driver = ScriptedDriver::new(vec![reply, "(unreached)"]);
        let servers = McpServers::default();
        let outcome = run_tool_loop_with_cap(
            &mut driver,
            "clean up".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            5,
            &crate::config::SecurityPolicy::default(), // dangerous_commands = Deny
            crate::mcp::goal_tracker::GoalContext::empty(),
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        // The dangerous call is counted as failed (blocked) and the loop stops
        // after the single all-blocked round.
        assert_eq!(outcome.iterations, 1);
        assert_eq!(outcome.successful_calls, 0);
        assert_eq!(outcome.failed_calls, 1);
    }

    // The env lock is held across the await so no concurrent test mutates
    // NEOTH_HOME mid-run (the lease store is read from default_neoth_home).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn active_lease_lifts_dangerous_block_and_audits() {
        use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let prev = std::env::var("NEOTH_HOME").ok();
        unsafe { std::env::set_var("NEOTH_HOME", dir.path()) };

        // Grant an active `dangerous_command` lease to the operator subject.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut store = LeaseStore::default();
        store.grant(CapabilityLease::new(
            crate::security::risk_gate::RISK_LEASE_SUBJECT,
            LeaseScope::DangerousCommand,
            3600,
            now,
        ));
        store.save(&LeaseStore::default_path(dir.path())).unwrap();

        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let reply = r#"```mcp-tool-call
{"server": "shell", "tool": "exec", "arguments": {"command": "rm -rf /"}}
```"#;
        let mut driver = ScriptedDriver::new(vec![reply]);
        let servers = McpServers::default();
        let _ = run_tool_loop_with_cap(
            &mut driver,
            "x".into(),
            &servers,
            AutonomyLevel::Standard,
            Some(&writer),
            None,
            None,
            5,
            &crate::config::SecurityPolicy::default(), // dangerous = Deny
            crate::mcp::goal_tracker::GoalContext::empty(),
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        drop(writer);
        join.await.ok();

        if let Some(v) = prev {
            unsafe { std::env::set_var("NEOTH_HOME", v) };
        } else {
            unsafe { std::env::remove_var("NEOTH_HOME") };
        }

        // GOLD-ADOPT-23 point 3 — the lift must record a distinct
        // RISK_CONFIRM_USED frame (not the generic block).
        let bytes = std::fs::read(&wal_path).unwrap();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut verdict = String::new();
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else { break };
            if f.header.event_type == crate::wal::events::EVENT_TYPE_RISK_CONFIRM_USED {
                let p: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
                verdict = p["verdict"].as_str().unwrap_or("").to_string();
            }
            let t = f.header.total_len as usize;
            if t == 0 { break; }
            cur += t;
        }
        assert_eq!(verdict, "lifted_by_lease", "active lease must lift + audit via RISK_CONFIRM_USED");

        // GR-032 single-use: the lifted lease was CONSUMED — a second blocked
        // call in the same (still-unexpired) window would re-block. The store no
        // longer carries an active dangerous lease for the operator subject.
        let store_after = LeaseStore::load(&LeaseStore::default_path(dir.path())).unwrap();
        assert!(
            store_after
                .find_covering(
                    crate::security::risk_gate::RISK_LEASE_SUBJECT,
                    &LeaseScope::DangerousCommand,
                    now
                )
                .is_none(),
            "single-use: the lifted risk lease must be consumed, not reusable"
        );
    }

    #[test]
    fn confirm_high_makes_a_high_finding_need_the_dangerous_lease() {
        use crate::security::ToolCallRisk;
        use crate::security::dangerous_command::inspect;
        // A HIGH-severity finding (git push --force).
        let high = ToolCallRisk {
            egress: vec![],
            dangerous: inspect("git push --force origin main"),
        };
        assert!(!high.dangerous.is_empty(), "git push --force must be a High finding");
        // GR-046: without confirm_high a High block is NOT liftable via the
        // DangerousCommand lease; WITH confirm_high it IS (so `neoth risk-confirm`
        // can lift the confirm_high block).
        assert!(!risk_needs_dangerous_lease(&high, false));
        assert!(risk_needs_dangerous_lease(&high, true));
        // A Critical finding always needs the lease, regardless of confirm_high.
        let crit = ToolCallRisk {
            egress: vec![],
            dangerous: inspect("rm -rf /"),
        };
        assert!(risk_needs_dangerous_lease(&crit, false));
        assert!(risk_needs_dangerous_lease(&crit, true));
    }

    // Holds the env lock + points NEOTH_HOME at a CLEAN home (no leases) so the
    // lease check finds nothing and this test sees a true `denied` — otherwise
    // it races the lease-lift test's NEOTH_HOME (which carries a live lease).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn risk_gate_block_emits_distinct_denied_wal_frame() {
        // GOLD-ADOPT-23 point 4: a blocked dangerous call appends a DISTINCT
        // RISK_GATE_DENIED audit frame carrying the rule id + verdict, NOT the
        // raw command (operator preference over the old single 0xCF type).
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let prev = std::env::var("NEOTH_HOME").ok();
        unsafe { std::env::set_var("NEOTH_HOME", dir.path()) }; // clean — no leases.json
        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let reply = r#"```mcp-tool-call
{"server": "shell", "tool": "exec", "arguments": {"command": "rm -rf /"}}
```"#;
        let mut driver = ScriptedDriver::new(vec![reply]);
        let servers = McpServers::default();
        let _ = run_tool_loop_with_cap(
            &mut driver,
            "x".into(),
            &servers,
            AutonomyLevel::Standard,
            Some(&writer),
            None,
            None,
            5,
            &crate::config::SecurityPolicy::default(),
            crate::mcp::goal_tracker::GoalContext::empty(),
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        drop(writer);
        join.await.ok();
        if let Some(v) = prev {
            unsafe { std::env::set_var("NEOTH_HOME", v) };
        } else {
            unsafe { std::env::remove_var("NEOTH_HOME") };
        }

        let bytes = std::fs::read(&wal_path).unwrap();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found = false;
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else { break };
            if f.header.event_type == crate::wal::events::EVENT_TYPE_RISK_GATE_DENIED {
                found = true;
                let p: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
                assert_eq!(p["verdict"], "denied");
                assert_eq!(p["rule"], "rm_rf_root");
                // The raw command must NOT be in the audit frame.
                assert!(!p.to_string().contains("rm -rf"), "raw command must not be in WAL");
            }
            let t = f.header.total_len as usize;
            if t == 0 { break; }
            cur += t;
        }
        assert!(found, "a RISK_GATE_DENIED frame must be present");
    }

    #[tokio::test]
    async fn active_grind_keeps_loop_going_past_clean_exit() {
        // GOLD-ADOPT-22: with a grind set, a no-tool-call response does NOT end
        // the loop — a nudge is injected and it runs to the iteration cap.
        let mut driver = ScriptedDriver::new(vec!["done?", "still done?", "really done?"]);
        let servers = McpServers::default();
        let outcome = run_tool_loop_with_cap(
            &mut driver,
            "build it".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            3,
            &crate::config::SecurityPolicy::default(),
            crate::mcp::goal_tracker::GoalContext {
                goal: None,
                grind: Some("ship the feature".into()),
            },
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        // Grind refuses to stop at the first clean exit → runs the full 3 turns
        // (vs stopping at 1 without a grind). The last turn exits via the
        // clean-exit branch once iterations == max, so hit_cap stays false.
        assert_eq!(outcome.iterations, 3);
        // The injected nudge is in the threaded-back prompt.
        let prompts = driver.seen_prompts.lock().unwrap();
        assert!(
            prompts.iter().any(|p| p.contains("goal-nudge")),
            "a grind nudge must be threaded into the prompt"
        );
    }

    #[tokio::test]
    async fn no_goal_stops_at_clean_exit() {
        // The default (no goal/grind) is unchanged: stop at the first clean exit.
        let mut driver = ScriptedDriver::new(vec!["done.", "(unreached)"]);
        let servers = McpServers::default();
        let outcome = run_tool_loop_with_cap(
            &mut driver,
            "hi".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            5,
            &crate::config::SecurityPolicy::default(),
            crate::mcp::goal_tracker::GoalContext::empty(),
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.iterations, 1);
    }

    #[tokio::test]
    async fn loop_terminates_immediately_when_no_tool_calls() {
        let mut driver = ScriptedDriver::new(vec!["plain text reply, no tool calls"]);
        let servers = McpServers::default();
        let outcome = run_tool_loop(
            &mut driver,
            "hi".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            &crate::config::SecurityPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.iterations, 1);
        assert!(!outcome.hit_cap);
        assert_eq!(outcome.successful_calls, 0);
        assert_eq!(outcome.failed_calls, 0);
        assert!(outcome.final_text.contains("plain text reply"));
    }

    #[tokio::test]
    async fn loop_terminates_early_when_every_call_fails_unknown_server() {
        // LLM emits a tool call for a server that doesn't exist. The
        // dispatcher logs FAILED, and since no call succeeded, the loop
        // breaks rather than feeding the LLM nothing-but-errors forever.
        let reply = r#"I'll fetch it.
```mcp-tool-call
{"server": "ghost", "tool": "read", "arguments": {}}
```
"#;
        let mut driver = ScriptedDriver::new(vec![reply, "(this shouldn't be reached)"]);
        let servers = McpServers::default();
        let outcome = run_tool_loop(
            &mut driver,
            "fetch X".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            &crate::config::SecurityPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.iterations, 1,
            "should not re-issue after all-fail round"
        );
        assert_eq!(outcome.successful_calls, 0);
        assert_eq!(outcome.failed_calls, 1);
    }

    #[tokio::test]
    async fn loop_hits_iteration_cap_when_llm_calls_forever() {
        // LLM stuck in a loop — every response carries an unknown
        // tool call. Cap kicks in even though dispatch_one fails.
        // We set cap = 2 so the cap path is exercised before
        // the all-fail early-exit (which fires on the FIRST iteration).
        // Trick: provide a valid-LOOKING call by routing through the
        // failing path but with a different reason each iteration —
        // here all calls fail, so the early-exit (no-success) wins
        // the race. Verify by checking iteration count = 1 + outcome.
        let reply = r#"```mcp-tool-call
{"server": "ghost", "tool": "x"}
```"#;
        let mut driver = ScriptedDriver::new(vec![reply; 10]);
        let servers = McpServers::default();
        let outcome = run_tool_loop_with_cap(
            &mut driver,
            "x".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            5,
            &crate::config::SecurityPolicy::default(),
            crate::mcp::goal_tracker::GoalContext::empty(),
            true,
            crate::context::compaction::CompactionPolicy::disabled(),
        )
        .await
        .unwrap();
        // All-fail early-exit fires on iteration 1 — `hit_cap` stays false.
        assert_eq!(outcome.iterations, 1);
        assert!(!outcome.hit_cap);
        assert_eq!(outcome.failed_calls, 1);
    }

    #[tokio::test]
    async fn loop_records_parse_errors_as_failures() {
        let reply = r#"```mcp-tool-call
{"server": "filesystem", "tool":   broken json
```"#;
        let mut driver = ScriptedDriver::new(vec![reply]);
        let servers = McpServers::default();
        let outcome = run_tool_loop(
            &mut driver,
            "x".into(),
            &servers,
            AutonomyLevel::Standard,
            None,
            None,
            None,
            &crate::config::SecurityPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.successful_calls, 0);
        assert_eq!(outcome.failed_calls, 1);
    }

    #[test]
    fn format_failure_renders_recognisable_tool_result_block() {
        let call = ParsedToolCall {
            server: "filesystem".into(),
            tool: "read_file".into(),
            arguments: serde_json::json!({}),
        };
        let out = format_failure(&call, "permission denied");
        assert!(out.contains("```mcp-tool-result"));
        assert!(out.contains("\"status\": \"FAILED\""));
        assert!(out.contains("permission denied"));
        assert!(out.ends_with("```"));
    }

    #[test]
    fn format_parse_error_keeps_raw_block_for_llm_self_correction() {
        let err = ParseError {
            raw_block: "```mcp-tool-call\n{bad}\n```".into(),
            reason: "JSON parse: expected ident".into(),
        };
        let out = format_parse_error(&err);
        assert!(out.contains("PARSE_ERROR"));
        assert!(out.contains("JSON parse"));
        assert!(out.contains("{bad}"));
    }

    #[test]
    fn build_next_prompt_layers_assistant_reply_and_tool_blocks() {
        let prior = "Initial question.";
        let assistant = "Let me fetch that.";
        let blocks = vec!["```mcp-tool-result\n...result A...```".to_string()];
        let hints = vec!["### Subdirectory hints (/p/sub)\nUse Foo here.".to_string()];
        let out = build_next_prompt(prior, assistant, &blocks, &hints);
        // Prior prompt stays at the top so the LLM sees the full
        // conversation thread; assistant + tool blocks layer on.
        assert!(out.starts_with(prior));
        assert!(out.contains("[assistant]"));
        assert!(out.contains("Let me fetch that."));
        assert!(out.contains("[tool results]"));
        assert!(out.contains("...result A..."));
        // GOLD-ADOPT-18 hint section present when hints are supplied.
        assert!(out.contains("[subdirectory hints"));
        assert!(out.contains("Use Foo here."));
        assert!(out.contains("Continue"));
        // No hint section when none supplied.
        let no_hints = build_next_prompt(prior, assistant, &blocks, &[]);
        assert!(!no_hints.contains("[subdirectory hints"));
    }

    #[test]
    fn default_iteration_cap_is_five() {
        // Pin the budget — operators reading this default see
        // exactly what the cap is without reading the source.
        assert_eq!(DEFAULT_MAX_ITERATIONS, 5);
    }

    #[test]
    fn consume_risk_leases_persists_the_single_use_revoke() {
        // M3: a successful single-use consumption must be DURABLE — the lease is
        // gone from disk afterwards, so a restart / 2nd instance can't re-use it.
        use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};
        use crate::security::risk_gate::RISK_LEASE_SUBJECT;
        let home = tempfile::tempdir().expect("tempdir");
        let path = LeaseStore::default_path(home.path());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut store = LeaseStore::default();
        store.grant(CapabilityLease::new(
            RISK_LEASE_SUBJECT,
            LeaseScope::DangerousCommand,
            3600,
            now,
        ));
        store.save(&path).unwrap();

        let consumed =
            consume_risk_leases_at(home.path(), true, false).expect("save must succeed");
        assert!(consumed.is_some(), "the covering lease was consumed");
        let reloaded = LeaseStore::load(&path).unwrap();
        assert!(
            reloaded.leases.is_empty(),
            "single-use consumption must be persisted to disk"
        );
    }

    #[test]
    fn consume_risk_leases_fails_closed_when_persist_fails() {
        // M3: if the single-use revoke can't be persisted the function must
        // return Err (so the caller keeps the call BLOCKED) instead of silently
        // warning and proceeding — which left the lease reusable until its TTL.
        // Force the atomic save (tmp-write + rename) to fail by occupying its
        // `<path>.json.tmp` write target with a DIRECTORY; `load()` still reads
        // the real `leases.json` so the consume reaches the save step.
        use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};
        use crate::security::risk_gate::RISK_LEASE_SUBJECT;
        let home = tempfile::tempdir().expect("tempdir");
        let path = LeaseStore::default_path(home.path());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut store = LeaseStore::default();
        store.grant(CapabilityLease::new(
            RISK_LEASE_SUBJECT,
            LeaseScope::DangerousCommand,
            3600,
            now,
        ));
        store.save(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).expect("occupy tmp path");

        let result = consume_risk_leases_at(home.path(), true, false);
        assert!(
            result.is_err(),
            "M3: an un-persistable single-use consumption must fail-closed (Err), not warn-and-proceed"
        );
    }
}
