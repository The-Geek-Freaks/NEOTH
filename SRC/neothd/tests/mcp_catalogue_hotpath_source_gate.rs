//! Source tripwire for bounded MCP catalogue prompt assembly.

const CHAT: &str = include_str!("../src/cli/chat.rs");
const SERVE_PIPELINE: &str = include_str!("../src/cli/serve_pipeline.rs");
const CATALOGUE: &str = include_str!("../src/mcp/catalogue.rs");
const LOOP_ENGINE: &str = include_str!("../src/loop_engine/engine.rs");
const SANITIZER: &str = include_str!("../src/mcp/sanitizer.rs");

fn compact_region(source: &str, start: &str, end: &str) -> String {
    let (_, region) = source.split_once(start).expect("start marker must exist");
    let (region, _) = region.split_once(end).expect("end marker must exist");
    region.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn catalogue_prompt_assembly_is_bound_to_the_exact_mcp_route() {
    let chat_catalogue = compact_region(
        CHAT,
        "// ── Route-bound MCP catalogue (CLI path)",
        "let route_cap =",
    );
    let channel_catalogue = compact_region(
        SERVE_PIPELINE,
        "// ── Route-bound MCP catalogue (channel path)",
        "let budgeted =",
    );

    assert!(
        !chat_catalogue.contains(".enabled()"),
        "CLI prompt assembly must delegate empty detection and bounded selection to the catalogue"
    );
    assert!(
        !channel_catalogue.contains(".enabled()"),
        "channel prompt assembly must delegate empty detection and bounded selection to the catalogue"
    );
    assert_eq!(CHAT.matches("assemble_catalogue_for_prompt(").count(), 1);
    assert_eq!(
        SERVE_PIPELINE
            .matches("assemble_catalogue_for_prompt(")
            .count(),
        1
    );
    assert!(
        chat_catalogue
            .find("chat_route.uses_mcp_catalogue()")
            .expect("CLI route guard")
            < chat_catalogue
                .find("assemble_catalogue_for_prompt(")
                .expect("CLI catalogue await"),
        "CLI must prove the exact MCP route before catalogue process I/O"
    );
    assert!(
        channel_catalogue
            .find("channel_route.uses_mcp_catalogue()")
            .expect("channel route guard")
            < channel_catalogue
                .find("assemble_catalogue_for_prompt(")
                .expect("channel catalogue await"),
        "channel must prove the exact MCP route before catalogue process I/O"
    );
    assert!(chat_catalogue.contains("slot.insert(&mutbudget_items,catalogue)"));
    assert!(channel_catalogue.contains("slot.insert(&mutchannel_budget_items,catalogue)"));

    let chat_route = CHAT
        .find("let chat_route = resolve_chat_turn_route(")
        .expect("CLI exact route");
    let chat_assemble = CHAT
        .find("assemble_catalogue_for_prompt(")
        .expect("CLI catalogue await");
    let chat_finalize = CHAT[chat_assemble..]
        .find("finalize_provider_request(")
        .map(|offset| chat_assemble + offset)
        .expect("CLI final budget");
    assert!(chat_route < chat_assemble && chat_assemble < chat_finalize);

    let channel_route = SERVE_PIPELINE
        .find("let channel_route = resolve_channel_turn_route(")
        .expect("channel exact route");
    let channel_assemble = SERVE_PIPELINE
        .find("assemble_catalogue_for_prompt(")
        .expect("channel catalogue await");
    let channel_finalize = SERVE_PIPELINE[channel_assemble..]
        .find("finalize_provider_request(")
        .map(|offset| channel_assemble + offset)
        .expect("channel final budget");
    assert!(channel_route < channel_assemble && channel_assemble < channel_finalize);
}

#[test]
fn dispatch_consumes_the_preselected_route_without_recomputing_admission() {
    let chat_dispatch = compact_region(
        CHAT,
        "async fn dispatch_provider(",
        "async fn run_post_reply_pipelines(",
    );
    assert!(chat_dispatch.contains("route.uses_loop()"));
    assert!(chat_dispatch.contains("route.loop_trigger()"));
    assert!(chat_dispatch.contains("route.uses_mcp_catalogue()"));
    assert!(chat_dispatch.contains("McpServers::default()"));
    assert!(chat_dispatch.contains(".max(loop_trigger.minimum_rounds())"));
    assert!(chat_dispatch.contains("min_rounds:loop_trigger.minimum_rounds()"));
    assert!(!chat_dispatch.contains("autoroute_decision("));
    assert!(!chat_dispatch.contains("try_admit_convene("));

    let channel_after_catalogue = compact_region(
        SERVE_PIPELINE,
        "// ── Route-bound MCP catalogue (channel path)",
        "if !completion.identity.is_bound()",
    );
    assert!(channel_after_catalogue.contains("channel_route.uses_loop()"));
    assert!(channel_after_catalogue.contains("TurnDispatchRoute::McpDispatch"));
    assert!(channel_after_catalogue.contains("McpServers::default()"));
    assert!(channel_after_catalogue.contains("loop_cfg.min_rounds=loop_trigger.minimum_rounds()"));
    assert!(!channel_after_catalogue.contains("autoroute_decision("));
    assert!(!channel_after_catalogue.contains("try_admit_convene("));

    let channel_resolver = compact_region(
        SERVE_PIPELINE,
        "async fn resolve_channel_turn_route(",
        "/// Build the per-channel pipeline handler closure.",
    );
    assert_eq!(channel_resolver.matches("try_admit_convene(").count(), 1);

    let route_selector = compact_region(
        CHAT,
        "pub(crate) fn select_turn_dispatch_route(",
        "/// Stable position where the MCP A/D atomic pair belongs",
    );
    assert!(route_selector.contains("TurnDispatchRoute::RefineLoop"));
    assert!(
        route_selector.contains("autoroute.is_on()&&mcp_catalogue_allowed"),
        "MCP dispatch and catalogue eligibility must stay coupled"
    );

    let prompt_bundle = compact_region(
        CHAT,
        "struct PromptBundle {",
        "/// Typed reason why a non-Council turn must enter the loop engine.",
    );
    assert!(prompt_bundle.contains("skill_loop_trigger:bool"));

    let cli_resolver = compact_region(
        CHAT,
        "async fn resolve_chat_turn_route(",
        "async fn dispatch_provider(",
    );
    assert!(cli_resolver.contains("LoopRouteTrigger::new(skill_loop_trigger"));
    assert!(cli_resolver.contains("args.loop_mode"));
    assert!(cli_resolver.contains("!loop_trigger.is_active()"));

    let channel_skill_route = compact_region(
        SERVE_PIPELINE,
        "let mode_registry =",
        "let channel_persona =",
    );
    assert_eq!(
        channel_skill_route
            .matches("routed_skill_loop_trigger(")
            .count(),
        2,
        "both a mode parent and a directly matched channel skill must preserve loop:true"
    );

    let stop_gate = compact_region(
        LOOP_ENGINE,
        "// --- Stop condition evaluation ---",
        "let round_ts_end =",
    );
    assert!(LOOP_ENGINE.contains("pub min_rounds: u32"));
    assert!(stop_gate.contains("round_num>=config.min_rounds"));
    assert!(stop_gate.contains("minimum_rounds_met"));
}

#[test]
fn catalogue_fetch_has_one_deadline_and_retains_only_compact_results() {
    assert!(CATALOGUE.contains("pub const CATALOGUE_TOTAL_TIMEOUT"));
    assert!(CATALOGUE.contains("timeout_at(deadline, work.next())"));
    assert!(CATALOGUE.contains(".buffered(MAX_CONCURRENT_CATALOGUE_FETCHES)"));
    assert!(
        !compact_region(
            CATALOGUE,
            "async fn collect_catalogue_servers(",
            "async fn fetch_catalogue_server(",
        )
        .contains(".collect::<Vec<"),
        "the deadline-aware fetch loop must not await and retain every server result"
    );

    let retained = compact_region(
        CATALOGUE,
        "pub(crate) struct FetchedServer {",
        "struct CatalogueFetchBatch {",
    );
    assert!(retained.contains("tool_names:Vec<String>"));
    assert!(retained.contains("full_block:String"));
    assert!(
        !retained.contains("SanitizedTool"),
        "cross-server batch state must not retain complete tool/schema trees"
    );
    assert!(CATALOGUE.contains(PARTIAL_MARKER_SOURCE));
}

#[test]
fn raw_schema_is_bounded_before_recursive_clone_and_all_prompt_text_is_redacted() {
    let compact_tool = compact_region(CATALOGUE, "fn compact_tool_entry(", "fn merge_verdicts(");
    let size_gate = compact_tool
        .find("serialized_json_fits(&input_schema,MAX_RAW_TOOL_SCHEMA_BYTES)")
        .expect("raw schema size gate");
    let recursive_clone = compact_tool
        .find("sanitize_schema_descriptions(&input_schema)")
        .expect("bounded recursive sanitizer");
    assert!(
        size_gate < recursive_clone,
        "raw schema byte gate must precede the cloning recursive sanitizer"
    );
    assert!(CATALOGUE.contains("let data = sanitize_tool_output(data);"));
    assert!(SANITIZER.contains("let mut sanitized = sanitize_tool_output(text);"));
}

const PARTIAL_MARKER_SOURCE: &str = "PARTIAL_CATALOGUE_HEADING";
