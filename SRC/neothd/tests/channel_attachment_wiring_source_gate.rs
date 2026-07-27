//! Source tripwires for the channel half of the GOLD-R3-14 attachment boundary.

const SERVE: &str = include_str!("../src/cli/serve_pipeline.rs");
const ENRICHED: &str = include_str!("../src/pipeline/enriched_request.rs");
const AUDIO: &str = include_str!("../src/media/audio.rs");
const DICTATE: &str = include_str!("../src/cli/dictate.rs");
const DICTATION: &str = include_str!("../src/media/dictation.rs");
const OMI_INGEST: &str = include_str!("../src/daemon/omi_native_ingest.rs");
const RESAMPLER: &str = include_str!("../src/media/resampler.rs");
const STT_PROVIDER: &str = include_str!("../src/media/stt_provider.rs");
const MODEL_MANAGER: &str = include_str!("../src/media/model_manager.rs");
const VIDEO: &str = include_str!("../src/media/video.rs");
const WEB_FETCH: &str = include_str!("../src/tools/web_fetch.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("source-gate start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("source-gate end marker");
    &tail[..end]
}

#[test]
fn channel_caption_and_media_keep_separate_trust_paths() {
    let handler = between(
        SERVE,
        "pub(crate) fn build_pipeline_handler(",
        "/// Run one owned inbound media attachment",
    );
    assert!(handler.contains("take_channel_turn_input(&mut inbound)"));
    assert!(handler.contains("let raw_text = operator_text.as_str()"));
    assert!(handler.contains("prompt: &sanitized_text"));
    assert!(handler.contains("attachment_contexts: channel_attachment_contexts.as_ref()"));
    assert!(!handler.contains("inbound.media.clone()"));
    let after_take = &handler[handler
        .find("take_channel_turn_input(&mut inbound)")
        .unwrap()..];
    assert!(
        !after_take.contains("inbound.text"),
        "post-take learning must use the retained sanitized caption"
    );
    assert!(after_take.contains("channel_learning_signal(&sanitized_text)"));

    let route = handler
        .find("route_with_min_weight(")
        .expect("caption-only skill route");
    let extraction = handler
        .find("handle_media_attachment(")
        .expect("typed media extraction");
    assert!(
        route < extraction,
        "decoder output must not become skill-routing input"
    );
    assert!(handler.contains("/{name} does not consume channel media attachments"));
    assert!(handler.contains("if !has_media"));
}

#[test]
fn channel_media_is_capped_before_single_owner_snapshot() {
    let media = between(
        SERVE,
        "pub(crate) async fn handle_media_attachment(",
        "fn channel_media_asset_kind(",
    );
    let cap = media
        .find("enforce_channel_media_input_limit(asset_kind, data.len())")
        .expect("pre-snapshot cap");
    let snapshot = media
        .find("snapshot_channel_media(data")
        .expect("single-owner snapshot");
    assert!(cap < snapshot);
    assert!(media.contains("let crate::channels::MediaPayload"));
    assert!(media.contains("Asset::Path"));
    assert!(!media.contains("media.data.clone()"));
    assert!(!media.contains("Asset::Bytes"));

    let limits = between(
        SERVE,
        "fn enforce_channel_media_input_limit(",
        "fn ensure_channel_media_stt_is_local(",
    );
    assert!(limits.contains("AssetKind::Audio => crate::media::audio::MAX_AUDIO_BYTES as usize"));
    assert!(limits.contains("AssetKind::Video => 256 * 1024 * 1024"));
}

#[test]
fn channel_attachment_is_required_d_and_delegation_cannot_drop_it() {
    assert!(
        ENRICHED
            .contains("budget_item(Block::D, None, attachment.as_str()).with_required_retention()")
    );
    let delegated = between(SERVE, "fn delegated_system_bundle(", "#[cfg(test)]");
    assert!(delegated.contains("item.block == Block::D"));
    assert!(delegated.contains("item.retention == PromptRetention::Required"));
    assert!(delegated.contains("BlockItem::new(Block::E, current_user_message(prior))"));
}

#[test]
fn channel_cloud_stt_remains_fail_closed_without_request_binding() {
    let guard = between(
        SERVE,
        "fn ensure_channel_media_stt_is_local(",
        "fn channel_media_snapshot_suffix(",
    );
    assert!(guard.contains("config.media.stt.primary.is_local()"));
    assert!(guard.contains("request-bound cost/consent authorization"));

    let media = between(
        SERVE,
        "pub(crate) async fn handle_media_attachment(",
        "fn channel_media_asset_kind(",
    );
    let guard_call = media
        .find("ensure_channel_media_stt_is_local(asset_kind, config)")
        .expect("cloud STT guard");
    let snapshot = media
        .find("snapshot_channel_media(data")
        .expect("media snapshot");
    assert!(
        guard_call < snapshot,
        "cloud rejection must happen before decoder or egress work"
    );
}

#[test]
fn sanitized_transcripts_and_media_errors_stay_behind_policy_boundaries() {
    let handler = between(
        SERVE,
        "pub(crate) fn build_pipeline_handler(",
        "/// Run one owned inbound media attachment",
    );
    assert!(
        !handler.contains("reply_to_inbound("),
        "every handler reply must cross PreEgress, ChannelSend, and CHANNEL_EGRESS WAL"
    );
    let sanitizer = handler
        .find("let Some(report) = sanitize_inbound(")
        .expect("channel sanitizer");
    let transcript = handler
        .find("persist_sanitized_channel_caption(")
        .expect("sanitized transcript persistence");
    assert!(
        sanitizer < transcript,
        "channel captions must not persist before hooks, rate-limit, and sanitizer"
    );
    assert!(!handler[..sanitizer].contains("insert_turn_best_effort("));

    let media_slash = between(
        handler,
        "if has_media",
        "// ── GOLD-ADAPT-GOOSE-03: UUID-reply fast-path",
    );
    assert!(media_slash.contains("release_local_channel_notice("));
    assert!(!media_slash.contains("reply_to_inbound("));

    let media_extract = between(
        handler,
        "let channel_attachment_contexts = match media.take()",
        "let channel_enriched =",
    );
    assert!(media_extract.contains("release_local_channel_notice("));
    assert!(!media_extract.contains("reply_to_inbound("));

    let provider_budget = between(
        handler,
        "let budgeted = match crate::cli::chat::finalize_provider_request(",
        "let crate::cli::chat::BudgetedProviderRequest",
    );
    assert!(provider_budget.contains("release_local_channel_notice("));
    assert!(provider_budget.contains("\"provider-request-budget-error\""));
    assert!(!provider_budget.contains("reply_to_inbound("));
}

#[test]
fn queued_task_ack_reuses_the_ingress_session_and_policy_egress() {
    let handler = between(
        SERVE,
        "pub(crate) fn build_pipeline_handler(",
        "/// Run one owned inbound media attachment",
    );
    let task_ack = between(handler, "let ack = format!(", "// ── K-Wire-3 (Session 23)");
    assert!(task_ack.contains("&ody26_session"));
    assert!(!task_ack.contains("ody26_task_session"));
    assert!(task_ack.contains("release_local_channel_notice("));
    assert!(task_ack.contains("\"task-queued\""));
}

#[test]
fn channel_text_documents_are_bounded_and_images_fail_before_decode() {
    let media = between(
        SERVE,
        "pub(crate) async fn handle_media_attachment(",
        "fn channel_media_asset_kind(",
    );
    let semantic_gate = media
        .find("ensure_channel_media_semantics_available(asset_kind)")
        .expect("semantic image gate");
    let text_extract = media
        .find("extract_channel_text_document(")
        .expect("text document extractor");
    let snapshot = media
        .find("snapshot_channel_media(data")
        .expect("decoder snapshot");
    assert!(semantic_gate < snapshot);
    assert!(text_extract < snapshot);
    assert!(media.contains("asset_kind == AssetKind::Document"));

    let text = between(
        SERVE,
        "fn channel_text_document_format(",
        "fn ensure_channel_media_semantics_available(",
    );
    for mime in ["text/plain", "text/markdown", "text/html"] {
        assert!(
            text.contains(mime),
            "missing bounded channel support for {mime}"
        );
    }
    assert!(text.contains("MAX_CHANNEL_TEXT_CONTEXT_BYTES"));
    assert!(text.contains("crate::tools::web_fetch::strip_html"));
}

#[test]
fn audio_bytes_are_preflighted_then_copied_at_most_once() {
    let async_entry = between(
        AUDIO,
        "pub(crate) async fn extract_with_context(",
        "#[async_trait::async_trait]",
    );
    assert!(async_entry.contains("own_audio_input(asset)?"));
    assert!(!async_entry.contains("asset.clone()"));

    let ownership = between(
        AUDIO,
        "fn own_audio_input(",
        "fn extract_blocking_with_context(",
    );
    let ceiling = ownership
        .find("enforce_audio_byte_ceiling")
        .expect("borrowed byte preflight");
    let copy = ownership
        .find("owned.extend_from_slice(data)")
        .expect("single ownership copy");
    assert!(ceiling < copy);
    assert_eq!(
        ownership.matches("owned.extend_from_slice(data)").count(),
        1
    );
    assert!(!ownership.contains("data.to_vec()"));

    let blocking = between(
        AUDIO,
        "fn extract_blocking_with_context(",
        "fn transcription_model_detail(",
    );
    assert!(!blocking.contains("data.clone()"));
}

#[test]
fn audio_memory_is_globally_serialized_and_all_large_buffers_are_fallible() {
    let async_entry = between(
        AUDIO,
        "pub(crate) async fn extract_with_context(",
        "#[async_trait::async_trait]",
    );
    let permit = async_entry
        .find("acquire_audio_work_permit().await?")
        .expect("global audio worker permit");
    let ownership = async_entry
        .find("own_audio_input(asset)?")
        .expect("owned input snapshot");
    assert!(
        permit < ownership,
        "permit must precede input cloning or reads"
    );
    assert!(AUDIO.contains("const AUDIO_WORKER_CONCURRENCY: usize = 1"));
    assert!(AUDIO.contains("pub(crate) const MAX_AUDIO_BYTES: u64 = 32 * 1024 * 1024"));
    assert!(AUDIO.contains("const MAX_AUDIO_DURATION_SECS: u64 = 10 * 60"));
    assert!(AUDIO.contains("AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES"));
    assert!(AUDIO.contains("reserve_decoded_pcm_growth("));

    for forbidden in [
        "data.to_vec()",
        "let mut bytes = Vec::with_capacity(capacity)",
        "decoded_mono.try_reserve(frame_count)",
        "decoded_mono.try_reserve_exact(frame_count)",
        "let mut out = Vec::with_capacity(out_len)",
    ] {
        assert!(
            !AUDIO.contains(forbidden),
            "audio buffer still has an infallible/geometric allocation: {forbidden}"
        );
    }
    assert!(AUDIO.contains("try_reserve_exact"));
    assert!(RESAMPLER.contains("try_reserve_exact"));
    assert!(!RESAMPLER.contains("Vec::with_capacity"));
    assert!(!RESAMPLER.contains("vec![0.0f32; CHUNK]"));
}

#[test]
fn one_unforgeable_audio_permit_spans_decode_and_every_stt_entry() {
    let extractor = between(
        AUDIO,
        "pub(crate) async fn extract_with_context(",
        "#[async_trait::async_trait]",
    );
    assert!(extractor.contains("let permit = acquire_audio_work_permit().await?"));
    assert!(extractor.contains("own_audio_input(asset)?"));
    assert!(
        extractor.find("acquire_audio_work_permit").unwrap()
            < extractor.find("own_audio_input").unwrap()
    );
    let blocking = between(
        AUDIO,
        "fn extract_blocking_with_context(",
        "fn transcription_model_detail(",
    );
    assert!(blocking.contains("dispatch_pcm_f32_with_audio_permit("));
    assert!(blocking.contains("&permit"));

    let file_decode = between(
        AUDIO,
        "pub(crate) fn decode_file_to_pcm(",
        "struct DecodedAudio",
    );
    assert!(file_decode.contains("_permit: &AudioWorkPermit"));

    let dictate = between(DICTATE, "pub async fn run_dictate(", "#[cfg(test)]");
    let permit = dictate.find("acquire_audio_work_permit()").unwrap();
    let decode = dictate.find("decode_file_to_pcm(&file, &permit)").unwrap();
    let dispatch_scope = dictate
        .find("transcribe_utterance_with_audio_permit(")
        .unwrap();
    assert!(permit < decode && decode < dispatch_scope);
    let drop_writer = dictate.find("drop(writer_for_stt)").unwrap();
    let await_writer = dictate.find("if let Some((writer, join)) = audit").unwrap();
    assert!(
        drop_writer < await_writer,
        "dictate must drop every cloned WAL sender before awaiting shutdown"
    );

    let canonical = between(
        STT_PROVIDER,
        "pub async fn dispatch_pcm_f32(",
        "#[cfg(test)]",
    );
    assert!(canonical.contains("acquire_audio_work_permit()"));
    assert!(canonical.contains("dispatch_pcm_f32_with_audio_permit("));
    assert!(canonical.contains("_permit: &crate::media::audio::AudioWorkPermit"));

    let dictation = between(
        DICTATION,
        "pub(crate) async fn transcribe_utterance_with_audio_permit(",
        "// ── Tests",
    );
    assert!(dictation.contains("permit: &crate::media::audio::AudioWorkPermit"));
    assert!(dictation.contains("dispatch_pcm_f32_with_audio_permit("));
    assert!(dictation.contains("crate::media::stt_provider::dispatch_pcm_f32("));

    let omi_request = between(OMI_INGEST, "async fn handle_request", "fn parse_route(");
    let omi_permit = omi_request.find("acquire_audio_work_permit()").unwrap();
    let omi_body = omi_request.find("read_limited(").unwrap();
    assert!(
        omi_permit < omi_body,
        "OMI must own the audio permit before request-body accumulation"
    );
    assert!(omi_request.contains("REQUEST_BODY_TOTAL_TIMEOUT"));
    let omi_dispatch = between(
        OMI_INGEST,
        "async fn dispatch_event(",
        "async fn start_call(",
    );
    let candidate_clone = omi_dispatch
        .find("let mut candidate = call.clone()")
        .unwrap();
    let required_permit = omi_dispatch
        .find("let audio_permit = audio_permit.as_ref()")
        .unwrap();
    assert!(required_permit < candidate_clone);
    let terminal = between(
        OMI_INGEST,
        "async fn terminalize(",
        "async fn ensure_native_event_open(",
    );
    assert!(terminal.contains("audio_permit: &crate::media::audio::AudioWorkPermit"));
    assert!(!terminal.contains("acquire_audio_work_permit()"));
    assert!(OMI_INGEST.contains("dispatch_pcm_f32_with_audio_permit("));
    assert!(OMI_INGEST.contains("permit: &crate::media::audio::AudioWorkPermit"));
}

#[test]
fn native_omi_retained_pcm_and_chunk_bounds_are_hard_wired() {
    for contract in [
        "const MAX_TRACKS_PER_CALL: usize = 4",
        "const MAX_SAMPLE_RATE_HZ: u32 = 48_000",
        "const MAX_AUDIO_CHUNK_BODY_BYTES: usize = 1024 * 1024",
        "const OMI_RETAINED_PCM_BUDGET_BYTES: usize = 128 * 1024 * 1024",
        "MAX_RETAINED_OMI_PCM_BYTES <= OMI_RETAINED_PCM_BUDGET_BYTES",
        "AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES",
    ] {
        assert!(
            OMI_INGEST.contains(contract),
            "missing native OMI memory contract: {contract}"
        );
    }
    let audio_limit = between(
        OMI_INGEST,
        "const fn body_limit(self, config: &OmiConfig)",
        "fn event_fingerprint(",
    );
    assert!(audio_limit.contains("MAX_AUDIO_CHUNK_BODY_BYTES"));
    assert!(!audio_limit.contains("crate::media::audio::MAX_AUDIO_BYTES"));
    assert!(OMI_INGEST.contains("sample rate must be in 8000..=48000 Hz"));
}

#[test]
fn cloud_stt_has_a_durable_request_bound_replay_transaction() {
    let binding = between(
        STT_PROVIDER,
        "struct CloudSttReplayBinding",
        "fn ensure_private_cloud_stt_replay_root(",
    );
    for field in ["provider:", "effective_model:", "request:", "audio_sha256:"] {
        assert!(
            binding.contains(field),
            "cloud STT replay binding is missing {field}"
        );
    }
    let begin = between(
        STT_PROVIDER,
        "fn begin_cloud_stt_replay(",
        "fn commit_cloud_stt_replay_result(",
    );
    assert!(begin.contains("write_private_create_new_durable("));

    let dispatch = between(
        STT_PROVIDER,
        "pub(crate) async fn transcribe_and_audit(",
        "async fn emit_stt_transcribed(",
    );
    let intent = dispatch
        .find("begin_cloud_stt_replay(paths)")
        .expect("durable pre-egress intent");
    let provider = dispatch
        .find(".transcribe(&permit, &audio, &effective_request)")
        .expect("provider egress");
    let outcome = dispatch
        .find("persist_cloud_stt_replay_outcome(")
        .expect("durable post-provider outcome");
    let audit = dispatch
        .find("emit_stt_transcribed(")
        .expect("0xCC completion audit");
    let result = dispatch
        .find("commit_cloud_stt_replay_result(")
        .expect("durable replay result");
    assert!(intent < provider && provider < outcome && outcome < audit && audit < result);
    assert!(dispatch.contains("tokio::spawn(transaction)"));
    assert!(dispatch.contains("acquire_cloud_stt_audit("));
    assert!(dispatch.contains("mark_cloud_stt_audit_claim("));
    assert!(STT_PROVIDER.contains("CloudSttAuditStage::Claimed"));
    assert!(STT_PROVIDER.contains("refusing a duplicate 0xCC audit"));
    assert!(STT_PROVIDER.contains("lock_file_blocking("));

    let commit = between(
        STT_PROVIDER,
        "fn commit_cloud_stt_replay_result(",
        "/// P0 — transcribe through",
    );
    let result_write = commit
        .find("atomic_write_private(&paths.result")
        .expect("private atomic result write");
    let pending_remove = commit
        .find("durable_remove_file(&paths.pending)")
        .expect("durable pending removal");
    assert!(result_write < pending_remove);
    assert!(commit.contains("durable_remove_file(&paths.outcome)"));
    assert!(commit.contains("CLOUD_STT_REPLAY_RESULT_MAX_BYTES"));
}

#[test]
fn every_encoded_stt_dispatch_and_faster_whisper_child_keeps_its_permits() {
    let encoded = between(
        STT_PROVIDER,
        "pub async fn dispatch_transcription(",
        "pub(crate) async fn dispatch_transcription_with_audio_permit(",
    );
    assert!(encoded.contains("acquire_audio_work_permit()"));
    assert!(encoded.contains("dispatch_transcription_with_audio_permit("));

    let pcm = between(
        STT_PROVIDER,
        "async fn dispatch_pcm_f32_inner(",
        "#[cfg(test)]",
    );
    assert!(pcm.contains("dispatch_transcription_with_audio_permit("));
    assert!(!pcm.contains("dispatch_transcription("));

    let faster = between(
        STT_PROVIDER,
        "async fn run_faster_whisper_child(",
        "#[async_trait]\ntrait LocalWhisperPrefetchExecutor",
    );
    for contract in [
        "tokio::spawn(run_faster_whisper_child_supervised(",
        "process_group(0)",
        "PR_SET_PDEATHSIG",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "CREATE_SUSPENDED",
        "AssignProcessToJobObject",
        "NtResumeProcess",
        "QueryInformationJobObject",
        "TerminateJobObject",
        "prove_tree_empty",
        "SYS_pidfd_open",
        "SYS_close_range",
        "libc::fork()",
        "libc::getpgrp() != libc::getpid()",
        "kill_and_reap_faster_whisper",
        "collect_faster_whisper_stream",
        "close_audio_work_budget",
        "close_private_audio",
    ] {
        assert!(
            faster.contains(contract),
            "missing faster-whisper lifecycle contract: {contract}"
        );
    }
    assert!(
        STT_PROVIDER.contains("crate::util::private_temp::named_file(\".neoth-fw-\", \".wav\")")
    );
    assert!(STT_PROVIDER.contains("Some(permit.clone())"));
    assert!(STT_PROVIDER.contains("Some(model_lock)"));
    assert!(STT_PROVIDER.contains("Some(audio_permit.clone())"));
    assert!(STT_PROVIDER.contains("Some(attempt.cache_guard())"));
    assert!(
        STT_PROVIDER.contains("path.disable_cleanup(true)"),
        "unproved child-tree cleanup must retain the protected WAV instead of deleting it early"
    );
    assert!(STT_PROVIDER.contains("factory.build(kind, permit)"));
    assert!(MODEL_MANAGER.contains("_lease: Arc<ModelCacheLease>"));
    assert!(MODEL_MANAGER.contains("pub(crate) fn cache_guard(&self) -> ModelCacheGuard"));
    assert!(STT_PROVIDER.contains("cleanup_proved: true"));
    let tree_may_exist = faster
        .find("resources.cleanup_proved = false")
        .expect("spawn boundary must arm fail-closed cleanup");
    let spawn = faster
        .find("command.spawn()")
        .expect("faster-whisper child spawn");
    assert!(tree_may_exist < spawn);
    assert!(!faster.contains("&FasterWhisperContainment"));
    assert!(!faster.contains("unsafe impl Sync"));
    assert!(!STT_PROVIDER.contains("tempfile::Builder::new()"));
}

#[test]
fn cloud_stt_response_body_is_streamed_under_a_hard_limit() {
    let reader = between(
        STT_PROVIDER,
        "async fn read_cloud_stt_response_bounded(",
        "// ── OpenAI Whisper API",
    );
    assert!(reader.contains(".content_length()"));
    assert!(reader.contains(".chunk()"));
    assert!(reader.contains("next_len > MAX_CLOUD_STT_RESPONSE_BYTES"));
    assert!(reader.contains("try_reserve_exact"));
    assert!(!STT_PROVIDER.contains(".bytes()\n"));
}

#[test]
fn omi_validates_before_delegating_retry_ownership_to_canonical_stt() {
    let audio = between(
        OMI_INGEST,
        "async fn process_audio(",
        "async fn process_caption(",
    );
    let validation = audio
        .find("let content_type = required_header(")
        .expect("audio request validation");
    let provider = audio
        .find(".transcriber")
        .expect("OMI audio provider egress");
    assert!(validation < provider);
    assert!(!audio.contains("mark_audio_event_pending("));
    assert!(OMI_INGEST.contains("dispatch_pcm_f32_with_audio_permit("));
    assert!(STT_PROVIDER.contains("persist_cloud_stt_replay_outcome("));
    assert!(STT_PROVIDER.contains("CloudSttReplayStart::ResumeAudit"));
}

#[test]
fn html_channel_extraction_uses_one_forward_scan() {
    let stripper = between(WEB_FETCH, "fn strip_html_bounded(", "fn extract_attr<");
    assert!(stripper.contains("while cursor < html.len()"));
    assert!(!stripper.contains("replace_block_open_close"));
    assert!(!stripper.contains("drop_block("));
    assert!(!stripper.contains(".replace("));
    assert!(stripper.contains("if dropped_block.is_some()"));
    assert!(stripper.contains("dropped_block.as_mut()"));
    assert!(WEB_FETCH.contains("strip_html_many_open_tags_remains_linear_at_eight_mib"));
    assert!(WEB_FETCH.contains("strip_html_drops_script_blocks_entirely"));
}

#[test]
fn video_admission_remains_decoupled_from_the_tighter_audio_input_cap() {
    assert!(VIDEO.contains("const MAX_VIDEO_INPUT_BYTES: u64 = 256 * 1024 * 1024"));
    assert!(!VIDEO.contains("MAX_VIDEO_INPUT_BYTES: u64 = audio::MAX_AUDIO_BYTES"));
    assert!(!VIDEO.contains("fn snapshot_private_input("));
    assert!(VIDEO.contains("#[cfg(test)]\nfn write_private_temp_input_with_limit("));
}
