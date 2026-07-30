//! Source tripwires for the GOLD-R3-14 attachment trust boundary.
//!
//! Behavioral tests cover rendering and caps. These assertions keep future
//! refactors from silently returning to the old "prepend file text to the
//! operator prompt" design before the provider-facing tests can notice.

const CHAT: &str = include_str!("../src/cli/chat.rs");
const ENRICHED_REQUEST: &str = include_str!("../src/pipeline/enriched_request.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("source-gate start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("source-gate end marker");
    &tail[..end]
}

#[test]
fn raw_attachment_prompt_prepend_path_cannot_return() {
    assert!(!CHAT.contains("fn render_attachments_block("));
    assert!(!CHAT.contains("fn attachment_block("));
    assert!(!CHAT.contains("format!(\"{block}\\n{base}\")"));
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
    assert!(resolver.contains("does not consume attachments"));

    let runner = between(
        CHAT,
        "async fn run_chat_with_consent(",
        "const MAX_CHAT_ATTACHMENTS:",
    );
    let route = runner
        .find("resolve_turn_input(&args")
        .expect("route-first input");
    let wal = runner.find("spawn_for_home(").expect("home-bound turn WAL");
    let extract = runner
        .find("extract_attachment_contexts(")
        .expect("attachment extraction");
    let correction = runner
        .find("record_operator_correction(")
        .expect("operator correction persistence");
    assert!(route < wal && wal < extract);
    assert!(
        extract < correction,
        "a rejected attachment turn must not mutate the learned profile"
    );
    assert!(runner.contains("writer.clone()"));
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
    assert!(CHAT.contains("attachment_contexts: agent_raw_layers.attachment_contexts.as_ref()"));
    assert!(CHAT.contains("attachment_contexts: attachment_contexts.as_ref()"));

    let custom_slash = between(
        CHAT,
        "if let Some(cmd) = commands.iter().find(|c| c.name == name)",
        "crate::slash::Invocation::Escaped",
    );
    assert!(custom_slash.contains("agent_raw_layers.attachment_contexts.as_ref()"));
    assert!(custom_slash.contains("crate::tokens::budget::Block::D"));
    assert!(custom_slash.contains(".with_required_retention()"));
    assert!(custom_slash.contains("crate::tokens::budget::render_request(&items)"));
    assert!(CHAT.contains("WAL writer join failed while refusing /research attachments"));
    assert!(CHAT.contains("WAL writer join failed while refusing local-action attachments"));
    assert!(CHAT.contains("/research does not consume attachments"));
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
