//! Source tripwires for the GOLD-R3-14 attachment trust boundary.
//!
//! Behavioral tests cover rendering and caps. These assertions keep future
//! refactors from silently returning to the old "prepend file text to the
//! operator prompt" design before the provider-facing tests can notice.

const CHAT: &str = include_str!("../src/cli/chat.rs");
const CHAT_TURN_PIPELINE: &str = include_str!("../src/cli/chat_turn_pipeline.rs");
const ENRICHED_REQUEST: &str = include_str!("../src/pipeline/enriched_request.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("source-gate start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("source-gate end marker");
    &tail[..end]
}

#[test]
fn raw_attachment_prompt_prepend_path_cannot_return() {
    for source in [CHAT, CHAT_TURN_PIPELINE] {
        assert!(!source.contains("fn render_attachments_block("));
        assert!(!source.contains("fn attachment_block("));
        assert!(!source.contains("format!(\"{block}\\n{base}\")"));
    }
    assert!(CHAT.contains("struct ResolvedTurnInput"));
    assert!(CHAT.contains("has_attachments: bool"));

    let resolver = between(
        CHAT,
        "async fn resolve_turn_input(",
        "async fn reject_attachment_ignoring_slash_before_extraction(",
    );
    assert!(resolver.contains("prompt: base"));
    assert!(!resolver.contains("format!("));
}

#[test]
fn attachment_ignoring_slashes_are_rejected_before_extraction() {
    let resolver = between(
        CHAT,
        "async fn resolve_turn_input(",
        "fn attachment_byte_limit(",
    );
    assert!(resolver.contains("reject_attachment_ignoring_slash_before_extraction"));
    assert!(resolver.contains("if name == \"research\""));
    assert!(resolver.contains("command.action.is_some()"));
    assert!(resolver.contains("/{name} does not consume attachments"));
    assert!(resolver.contains("/{name} is a local action and does not consume attachments"));

    let adapter = between(
        CHAT,
        "async fn run_chat_with_consent(",
        "/// The direct adapter's one post-WAL terminal boundary.",
    );
    let adapter_compact = adapter
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let preparation = adapter_compact
        .find("prepare_cli_chat_turn(")
        .expect("adapter preparation");
    let wal = adapter_compact
        .find("spawn_for_home_with_completion(")
        .expect("completion-aware home-bound turn WAL");
    let engine = adapter_compact
        .find("chat_turn_pipeline::run_prepared_chat_turn(")
        .expect("typed turn engine");
    let writer_drop = adapter_compact[engine..]
        .find("drop(writer);")
        .map(|offset| engine + offset)
        .expect("writer drop after typed turn engine");
    let completion = adapter_compact[writer_drop..]
        .find("writer_completion.wait().await")
        .map(|offset| writer_drop + offset)
        .expect("completion-aware writer wait");
    let finalizer = adapter_compact[completion..]
        .find("finish_cli_chat_turn(")
        .map(|offset| completion + offset)
        .expect("post-completion CLI finalizer");
    assert!(
        preparation < wal
            && wal < engine
            && engine < writer_drop
            && writer_drop < completion
            && completion < finalizer,
        "the adapter must prepare input, open a completion-aware WAL, run the typed engine, drop the writer, await completion, and only then finalize presentation"
    );
    assert!(adapter_compact[engine..writer_drop].contains("&writer"));
    assert!(
        adapter_compact.contains("letdrained=writer_completion.wait().await.context("),
        "writer completion errors must retain context before the terminal finalizer decides presentation"
    );

    let preparation = between(
        CHAT,
        "async fn prepare_cli_chat_turn",
        "async fn resolve_turn_input(",
    );
    assert!(
        preparation.contains("resolve_turn_input(&args"),
        "turn preparation must route and reject attachment-ignoring slashes before the adapter opens WAL"
    );

    let engine_start = CHAT_TURN_PIPELINE
        .find("pub(crate) async fn run_prepared_chat_turn(")
        .expect("typed turn engine implementation");
    let engine = &CHAT_TURN_PIPELINE[engine_start..];
    let extract = engine
        .find("extract_attachment_contexts(")
        .expect("attachment extraction");
    let correction = engine
        .find("record_operator_correction(")
        .expect("operator correction persistence");
    assert!(
        extract < correction,
        "a rejected attachment turn must not mutate the learned profile"
    );
    assert!(
        engine[extract..correction].contains("writer.clone()")
            && engine[extract..correction].contains("drop(writer);")
            && engine[extract..correction].contains("return Err(error);"),
        "extraction must use the caller-owned writer and fail before correction persistence"
    );
}

#[test]
fn local_file_ingress_is_no_follow_single_read_and_bounded() {
    let ingress = between(
        CHAT,
        "fn open_attachment_no_follow(",
        "async fn resolve_prompt_base(",
    );
    assert!(ingress.contains("libc::O_NOFOLLOW"));
    assert!(ingress.contains("libc::O_NONBLOCK"));
    assert!(ingress.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(ingress.contains("attachment_metadata_is_link_like"));
    assert!(ingress.contains("MAX_CHAT_ATTACHMENTS"));
    assert!(ingress.contains("MAX_CHAT_ATTACHMENT_AGGREGATE_BYTES"));
    assert!(ingress.contains(".take(attachment.byte_limit.saturating_add(1))"));
    assert!(ingress.contains("bytes.try_reserve_exact(capacity)"));
    assert!(ingress.contains("bytes.try_reserve(read)"));
    assert!(ingress.contains(".checked_add(read)"));
    assert!(!ingress.contains("Vec::with_capacity(capacity)"));
    assert!(!ingress.contains(".read_to_end(&mut bytes)"));
    assert!(ingress.contains("spawn_blocking(move || admit_chat_attachments"));
    assert!(ingress.contains("request-bound cost/consent authorization"));
    assert!(!ingress.contains("let stt_audit ="));
    assert!(ingress.contains("crate::media::Asset::Bytes"));
    assert!(!ingress.contains("read_to_string"));
    assert!(!ingress.contains("crate::media::Asset::Path"));
}

#[test]
fn typed_attachment_batch_reaches_main_agent_and_slash_builders() {
    assert!(
        ENRICHED_REQUEST.contains("pub attachment_contexts: Option<&'a AttachmentContextBatch>")
    );
    assert!(
        ENRICHED_REQUEST
            .contains("budget_item(Block::D, None, attachment.as_str()).with_required_retention()")
    );

    assert!(CHAT.contains("attachment_contexts: attachment_contexts.cloned()"));
    assert!(CHAT.contains("attachment_contexts: layers.attachment_contexts.as_ref()"));
    assert!(CHAT_TURN_PIPELINE.contains("attachment_contexts: attachment_contexts.as_ref()"));

    let custom_slash = between(
        CHAT,
        "if let Some(cmd) = commands.iter().find(|c| c.name == name)",
        "crate::slash::Invocation::Escaped",
    );
    assert!(custom_slash.contains("agent_raw_layers.attachment_contexts.as_ref()"));
    assert!(custom_slash.contains("crate::tokens::budget::Block::D"));
    assert!(custom_slash.contains(".with_required_retention()"));
    assert!(custom_slash.contains("crate::tokens::budget::render_request(&items)"));
}

#[test]
fn attachment_failures_are_operator_errors_not_model_content() {
    let ingress = between(
        CHAT,
        "async fn extract_attachment_contexts(",
        "async fn resolve_prompt_base(",
    );
    assert!(ingress.contains("with_context(||"));
    assert!(ingress.contains("produced no textual content"));
    assert!(!ingress.contains("extraction failed —"));
    assert!(!ingress.contains("unsupported or unreadable —"));
}

#[test]
fn aggregate_source_budget_is_enforced_before_retaining_each_extraction() {
    let ingress = between(
        CHAT,
        "async fn extract_attachment_contexts(",
        "async fn resolve_prompt_base(",
    );
    let limit = ingress
        .find("let max_source_bytes = attachment_limits.max_source_bytes()")
        .expect("canonical attachment source ceiling");
    let account = ingress
        .find("extracted_source_bytes = extracted_source_bytes")
        .expect("incremental source-byte accounting");
    let enforce = ingress
        .find("extracted_source_bytes <= max_source_bytes")
        .expect("incremental source ceiling");
    let retain = ingress
        .find("extracted.push(ExtractedChatAttachment")
        .expect("retained extraction");

    assert!(limit < account && account < enforce && enforce < retain);
}
