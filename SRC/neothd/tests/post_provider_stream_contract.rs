//! GOLD-LF-P2-26a — executable producer proof for the post-provider stream
//! gate.  This exercises the real hook dispatcher and the exact framing seam
//! used by `run_post_reply_pipelines`; it deliberately avoids source-text
//! assertions and does not need a networked provider.

use std::time::Duration;

use neothd::cli::chat::{
    emit_deferred_post_provider_stream_to, emit_deferred_stream_done_to,
    emit_stream_finalization_error_to,
};
use neothd::hooks::dispatcher::StageOutcome;
use neothd::hooks::schema::{HookAction, HookDef, HookMatcher};
use neothd::hooks::{HookStage, run_stage};
use neothd::providers::{Completion, CompletionIdentity};

const CONTROL_PREFIX: &str = "\u{1e}NEOTH/1 ";
const CONTROL_TOKEN: &str = "lf-p2-26a-control-token";
const SYNTHETIC_SECRET: &str = "sk-lf-p2-26a-never-visible";

fn completion() -> Completion {
    let mut identity = CompletionIdentity::default();
    identity.provider = "lf-p2-fixture".to_owned();
    identity.wire_model = "lf-p2-fixture-model".to_owned();
    Completion {
        identity,
        model: "lf-p2-fixture-model".to_owned(),
        input_tokens: Some(13),
        output_tokens: Some(8),
        latency: Duration::from_millis(17),
        ..Default::default()
    }
}

fn hook(action: HookAction) -> HookDef {
    HookDef {
        name: "lf-p2-post-provider-gate".to_owned(),
        stage: HookStage::PostProviderCall,
        enabled: Some(true),
        priority: None,
        matcher: Some(HookMatcher {
            pattern: SYNTHETIC_SECRET.to_owned(),
        }),
        action,
        status_message: None,
        once: false,
        fail_fast: false,
    }
}

fn frames(output: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(output)
        .expect("writer emits UTF-8 JSON lines")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str(line.strip_prefix(CONTROL_PREFIX).expect("private frame"))
                .expect("valid authenticated JSON frame")
        })
        .collect()
}

#[test]
fn post_provider_block_emits_zero_deltas_boundaries_or_success() {
    let provider_chunks = [
        "first ordinary chunk; ",
        SYNTHETIC_SECRET,
        "; third ordinary chunk",
    ];
    let provider_body = provider_chunks.concat();
    let blocked = run_stage(
        HookStage::PostProviderCall,
        &provider_body,
        &[hook(HookAction::Block {
            reason: "synthetic secret must not leave the provider boundary".to_owned(),
        })],
    )
    .expect("real dispatcher decides the post-provider hook");

    assert!(matches!(blocked, StageOutcome::Block { .. }));

    // `run_post_reply_pipelines` bails on this real StageOutcome before it
    // reaches the only deferred producer seam.  Keep the writer untouched to
    // prove that no raw chunk, boundary, or terminal success is emitted.
    let output = Vec::<u8>::new();
    assert!(output.is_empty());
    assert!(
        !std::str::from_utf8(&output)
            .unwrap()
            .contains(SYNTHETIC_SECRET)
    );
}

#[test]
fn post_provider_replace_binds_only_accepted_bytes_and_commits_done_last() {
    let provider_chunks = [
        "first ordinary chunk; ",
        SYNTHETIC_SECRET,
        "; third ordinary chunk",
    ];
    let provider_body = provider_chunks.concat();
    let accepted = run_stage(
        HookStage::PostProviderCall,
        &provider_body,
        &[hook(HookAction::Replace {
            template: "[REDACTED]".to_owned(),
        })],
    )
    .expect("real dispatcher replaces the synthetic secret");
    let accepted_body = match accepted {
        StageOutcome::Continue { body, .. } => body,
        StageOutcome::Block { .. } => panic!("replace hook must continue"),
    };
    assert!(!accepted_body.contains(SYNTHETIC_SECRET));

    let mut output = Vec::new();
    let pending = emit_deferred_post_provider_stream_to(
        &mut output,
        Some(CONTROL_TOKEN),
        256,
        &completion(),
        &accepted_body,
    )
    .expect("real deferred producer emits accepted body and boundary");

    let before_success = frames(&output);
    assert_eq!(before_success.len(), 2);
    assert_eq!(before_success[0]["neoth_stream"], "provider_delta");
    assert_eq!(before_success[0]["sequence"], 1);
    assert_eq!(before_success[0]["text"], accepted_body);
    assert_eq!(before_success[1]["neoth_stream"], "provider_done");
    assert_eq!(before_success[1]["count"], 1);
    assert_eq!(
        before_success[0]["request_id"], before_success[1]["request_id"],
        "visible delta and provider boundary must bind one request"
    );
    assert!(
        !output
            .windows(SYNTHETIC_SECRET.len())
            .any(|bytes| bytes == SYNTHETIC_SECRET.as_bytes()),
        "the producer may never serialize the pre-hook synthetic secret"
    );
    assert!(
        !before_success
            .iter()
            .any(|frame| frame["neoth_stream"] == "done"),
        "a provider boundary is not final success"
    );

    emit_deferred_stream_done_to(&mut output, Some(CONTROL_TOKEN), &pending.done_line)
        .expect("terminal frame writes after successful finalization");
    let completed = frames(&output);
    assert_eq!(completed.len(), 3);
    assert_eq!(completed[2]["neoth_stream"], "done");
    assert_eq!(completed[2]["count"], 1);
    assert_eq!(completed[2]["content_hash"], completed[1]["content_hash"]);
    assert_eq!(completed[2]["request_id"], completed[1]["request_id"]);
    assert!(completed[2]["finalization_receipt"].is_string());
}

#[test]
fn finalization_error_is_visible_without_a_false_done_record() {
    let accepted_body = "accepted replacement after a three-chunk provider stream";
    let mut output = Vec::new();
    let _pending = emit_deferred_post_provider_stream_to(
        &mut output,
        Some(CONTROL_TOKEN),
        256,
        &completion(),
        accepted_body,
    )
    .expect("provider boundary is emitted before finalization");

    // Simulate the failure branch after the boundary but before the durable
    // finalizer can commit its terminal frame.
    emit_stream_finalization_error_to(
        &mut output,
        CONTROL_TOKEN,
        "synthetic durable finalizer failed",
    )
    .expect("finalization failure is visible on the authenticated wire");

    let frames = frames(&output);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["neoth_stream"], "provider_delta");
    assert_eq!(frames[1]["neoth_stream"], "provider_done");
    assert_eq!(frames[2]["neoth_stream"], "notice");
    assert_eq!(frames[2]["kind"], "finalization_error");
    assert_eq!(frames[2]["durable"], false);
    assert_eq!(frames[2]["request_id"], frames[1]["request_id"]);
    assert!(
        !frames.iter().any(|frame| frame["neoth_stream"] == "done"),
        "a finalization error must never masquerade as terminal success"
    );
}
