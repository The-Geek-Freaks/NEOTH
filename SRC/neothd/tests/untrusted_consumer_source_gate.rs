//! Source-level release gate for typed untrusted-context adoption.
//!
//! Runtime corpus tests prove the serializer itself. These focused source
//! tripwires pin known production seams and removed signatures; behavioral and
//! type-level tests remain authoritative for equivalent refactors.

const ENRICHED: &str = include_str!("../src/pipeline/enriched_request.rs");
const CATALOGUE: &str = include_str!("../src/mcp/catalogue.rs");
const DISPATCH: &str = include_str!("../src/mcp/dispatch_loop.rs");
const GOAL_JUDGE: &str = include_str!("../src/mcp/goal_judge.rs");
const GOAL_TRACKER: &str = include_str!("../src/mcp/goal_tracker.rs");
const HINTS: &str = include_str!("../src/mcp/hints.rs");
const SLASH: &str = include_str!("../src/slash/schema.rs");
const CRON: &str = include_str!("../src/cron/runner.rs");
const COMPACTION: &str = include_str!("../src/context/compaction.rs");
const LOOP_ENGINE: &str = include_str!("../src/loop_engine/engine.rs");
const CHAT: &str = include_str!("../src/cli/chat.rs");
const LOOP_CMD: &str = include_str!("../src/cli/loop_cmd.rs");
const SERVE_PIPELINE: &str = include_str!("../src/cli/serve_pipeline.rs");
const BUDGET: &str = include_str!("../src/tokens/budget.rs");

#[test]
fn skill_and_slash_arguments_stay_in_the_user_message() {
    assert!(
        !ENRICHED.contains(r#"s.replace("$ARGUMENTS", inputs.prompt.trim())"#),
        "skill arguments must never be copied from Block E into system authority"
    );
    assert!(ENRICHED.contains(r#"s.replace("$ARGUMENTS", CURRENT_OPERATOR_MESSAGE_REFERENCE)"#));
    assert!(
        !SLASH.contains(r#".replace("{args}", args)"#),
        "slash arguments must never be copied into the command system template"
    );
    assert!(SLASH.contains(r#".replace("{args}", CURRENT_USER_MESSAGE_REFERENCE)"#));
}

#[test]
fn mcp_catalogue_cannot_collapse_back_to_a_raw_string_contract() {
    assert!(CATALOGUE.contains("pub struct McpPromptCatalogue"));
    assert!(CATALOGUE.contains("UntrustedContextClass::McpCatalogue"));
    assert!(CATALOGUE.contains("Option<McpPromptCatalogue>"));
    assert!(CATALOGUE.contains("pub const MAX_CATALOGUE_SERVERS"));
    assert!(CATALOGUE.contains("pub const MAX_CATALOGUE_DATA_BYTES"));
    assert!(CATALOGUE.contains("Vec::with_capacity(MAX_CATALOGUE_SERVERS)"));
    assert!(CATALOGUE.contains("for cfg in &servers.servers"));
    assert!(CATALOGUE.contains(".buffered(MAX_CONCURRENT_CATALOGUE_FETCHES)"));
    assert!(ENRICHED.contains("pub mcp_catalogue: Option<&'a McpPromptCatalogue>"));
    assert!(
        !ENRICHED.contains("pub mcp_catalogue: Option<&'a str>"),
        "remote MCP metadata must retain its dedicated type through assembly"
    );
    assert!(
        CRON.contains("catalogue.render_system_block()"),
        "Cron must use the same typed Header plus Envelope renderer"
    );
    assert!(CHAT.contains("let mcp_catalogue: Option<crate::mcp::catalogue::McpPromptCatalogue>"));
    assert!(
        SERVE_PIPELINE.contains(
            "let channel_mcp_catalogue: Option<crate::mcp::catalogue::McpPromptCatalogue>"
        )
    );
    assert!(
        !CRON.contains("catalogue.data().as_str()"),
        "Cron must not append the dynamic catalogue through a parallel raw path"
    );
    assert_eq!(
        ENRICHED.matches("Some(AtomicGroup::McpCatalogue)").count(),
        2,
        "trusted protocol and dynamic catalogue must share one atomic budget group"
    );
    assert!(BUDGET.contains("expand_atomic_removals(items, &mut to_remove)"));
    assert_eq!(
        BUDGET.matches("validate_atomic_groups(items)?").count(),
        3,
        "render plus both public budget enforcers must reject malformed atomic groups"
    );
}

#[test]
fn repo_hints_and_model_replays_require_canonical_types() {
    assert!(ENRICHED.contains("UntrustedContextClass::RepoHint"));
    assert!(HINTS.contains("pub rendered: crate::pipeline::RenderedUntrustedContext"));
    assert!(HINTS.contains("pub source_bytes: u64"));
    assert!(HINTS.contains("pub source_truncated: bool"));
    assert!(HINTS.contains("fn defer_pending("));
    assert!(HINTS.contains("neoth.repo-hint.path.v1"));
    assert!(
        !HINTS.contains("pub content: String"),
        "repository hints must not expose prompt-ready raw strings"
    );
    assert!(
        DISPATCH.contains("tokio::task::spawn_blocking"),
        "repository filesystem reads must not block the async dispatch worker"
    );
    assert!(DISPATCH.contains("assistant_reply: &crate::pipeline::RenderedUntrustedContext"));
    assert!(DISPATCH.contains("hint_blocks: &[crate::pipeline::RenderedUntrustedContext]"));
    assert!(!DISPATCH.contains("assistant_reply: &str"));
    assert!(!DISPATCH.contains("hint_blocks: &[String]"));
    assert!(DISPATCH.contains("const REPOSITORY_HINT_ADAPTER: &str"));
    assert!(DISPATCH.contains("out.push_str(REPOSITORY_HINT_ADAPTER)"));
    assert!(
        DISPATCH.contains("crate::context::compaction::LAST_EXCHANGE_MARKER"),
        "the iteration producer must share its assistant marker with compaction"
    );
    assert!(COMPACTION.contains(
        "pub const LAST_EXCHANGE_MARKER: &str = \"\\n\\n[assistant output — untrusted data]\\n\""
    ));
    assert!(DISPATCH.contains(
        "let leaked_reply = render_model_output(&current_text, iterations, \"leaked-call\")"
    ));
    assert!(DISPATCH.contains(
        "let replayed_reply = render_model_output(&current_text, iterations, \"assistant-reply\")"
    ));
    assert!(
        !DISPATCH.contains("{prompt}\\n\\n{current_text}"),
        "raw model output must not return to any provider prompt"
    );
    assert!(DISPATCH.contains(r#""payload_bytes": payload_bytes"#));
    assert!(DISPATCH.contains(r#""wire_bytes": wire_bytes"#));
    assert!(DISPATCH.contains(r#""source_truncated": hint.source_truncated"#));
}

#[test]
fn goal_judge_requires_typed_model_output_and_an_exact_verdict() {
    assert!(
        GOAL_JUDGE.contains("conversation_summary: &crate::pipeline::RenderedUntrustedContext")
    );
    assert!(!GOAL_JUDGE.contains("conversation_summary: &str"));
    assert!(GOAL_JUDGE.contains(r#"text == "YES""#));
    assert!(GOAL_JUDGE.contains(r#""input_budget_exceeded""#));
    assert!(GOAL_JUDGE.contains(r#""unavailable""#));
    assert!(
        GOAL_JUDGE.contains("if goal.was_truncated()"),
        "the public judge primitive must reject an incomplete goal before provider dispatch"
    );
    assert!(
        !GOAL_JUDGE.contains(r#"starts_with("YES")"#),
        "YES-prefixed prose must not terminate an active goal"
    );
    assert!(DISPATCH.contains("judge_goal_met_with_hash"));
    assert!(DISPATCH.contains("goal_tracker.on_judged_not_met()"));
    assert!(DISPATCH.contains("!goal_tracker.goal_prompt_complete()"));
    assert!(DISPATCH.contains("GoalIntegrityError::PromptIncomplete"));
    assert!(DISPATCH.contains("GoalIntegrityError::DispatchUnavailable"));
    assert!(DISPATCH.contains(r#""input_budget_exceeded""#));
    assert!(DISPATCH.contains(r#""unavailable""#));
    assert!(DISPATCH.contains("goal_hash: goal_tracker.configured_goal_hash().map(str::to_owned)"));
    assert!(GOAL_TRACKER.contains("goal_hash = ctx.goal.as_deref().map"));
    assert!(GOAL_TRACKER.contains("goal_prompt_complete: bool"));
    assert!(GOAL_TRACKER.contains("!self.goal_met && self.goal_prompt_complete"));
    assert!(GOAL_TRACKER.contains("pub enum GoalIntegrityError"));
    assert!(GOAL_TRACKER.contains("HashMismatch"));
    assert!(GOAL_TRACKER.contains("PromptIncomplete"));
    assert!(GOAL_TRACKER.contains("DispatchUnavailable"));
    assert!(CHAT.contains("outcome.goal_hash.as_deref()"));
    assert!(SERVE_PIPELINE.contains("outcome.goal_hash.as_deref()"));
    assert!(LOOP_ENGINE.contains("pub goal_outcome: GoalOutcome"));
    assert!(LOOP_ENGINE.contains("pub goal_hash: Option<String>"));
    assert!(LOOP_ENGINE.contains("GoalIntegrityError::HashMismatch"));
    assert!(
        LOOP_ENGINE.contains("let goal_met_this_round = outcome.goal_outcome == GoalOutcome::Met")
    );
    assert!(
        LOOP_ENGINE.contains("if round == GoalOutcome::Met")
            && !LOOP_ENGINE.contains("current == GoalOutcome::Met ||"),
        "only the response bytes from the current round may retain a Met verdict"
    );
    assert!(LOOP_ENGINE.contains("fn round_stop_approved("));
    assert!(
        LOOP_ENGINE.contains("goal_outcome != GoalOutcome::BudgetExhausted && verifier_approved")
    );
    let compact_loop_engine = LOOP_ENGINE.split_whitespace().collect::<String>();
    assert!(compact_loop_engine.contains(
        "round_stop_approved(outcome.goal_outcome,judgement.is_approved(),minimum_rounds_met,)"
    ));
    assert!(LOOP_ENGINE.contains("if !goal_met_this_round"));
    assert!(
        LOOP_ENGINE.contains("if goal_met_this_round && stop_approved {"),
        "a confirmed goal must not bypass explicit --until criteria"
    );
    assert!(CHAT.contains("Ok(record) => record.into_dispatch_outcome()"));
    assert!(SERVE_PIPELINE.contains("let outcome = record.into_dispatch_outcome()"));
    assert!(
        !CHAT.contains("per_round.iter().any"),
        "historical round caps must not infer a terminal goal outcome"
    );
    assert_eq!(
        SERVE_PIPELINE
            .matches("emit_terminal_goal_outcome(")
            .count(),
        2,
        "direct and multi-round channel paths must share terminal goal WAL handling"
    );
    assert_eq!(
        LOOP_CMD.matches("emit_terminal_goal_outcome(").count(),
        1,
        "standalone loop command must emit the terminal goal lifecycle"
    );
    assert!(
        CHAT.matches("emit_terminal_goal_outcome(").count() >= 3,
        "CLI dispatch and council-dissent loops must share terminal goal WAL handling"
    );
    assert_eq!(
        SERVE_PIPELINE
            .matches("crate::mcp::goal_tracker::GoalIntegrityError")
            .count(),
        3,
        "channel council, loop-engine, and direct-MCP fallback arms must abort on a goal integrity failure"
    );
    assert!(SERVE_PIPELINE.matches("aborting without fallback").count() >= 3);
    assert!(
        SERVE_PIPELINE.contains("channel council goal integrity failure"),
        "the outer channel council caller must not hide a dissent-loop integrity failure"
    );
    assert!(
        CHAT.contains("crate::mcp::goal_tracker::GoalIntegrityError")
            && CHAT.contains("aborting without fallback"),
        "council dissent must not fall back across the shared goal integrity boundary"
    );
}

#[test]
fn untrusted_blocks_cannot_impersonate_trusted_budget_layers() {
    assert!(CHAT.contains("item.block == Block::B && item.content.trim_end() == code_discipline"));
    assert!(CHAT.contains("item.block == Block::B && item.content == protocol"));
    assert!(
        !CHAT.contains(
            "item.block != Block::E && item.content.contains(\"## Core principles (always apply)\")"
        ),
        "untrusted D content must not suppress the trusted code-discipline preamble"
    );
    assert!(
        !CHAT.contains("item.block != Block::E && item.content == protocol"),
        "untrusted D content must not suppress the trusted clarification protocol"
    );
}
