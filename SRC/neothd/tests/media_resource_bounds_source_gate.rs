//! Source tripwires for hostile media resource and temporary-storage bounds.

const WEB_FETCH: &str = include_str!("../src/tools/web_fetch.rs");
const WEB_CACHE: &str = include_str!("../src/tools/web_doc_cache.rs");
const PRIVATE_TEMP: &str = include_str!("../src/util/private_temp.rs");
const WIN_NATIVE: &str = include_str!("../src/wal/win_native.rs");
const SERVE: &str = include_str!("../src/cli/serve_pipeline.rs");
const VIDEO: &str = include_str!("../src/media/video.rs");
const DOCLING: &str = include_str!("../src/media/docling.rs");
const STT_PROVIDER: &str = include_str!("../src/media/stt_provider.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("source-gate start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("source-gate end marker");
    &tail[..end]
}

#[test]
fn web_fetch_streams_under_the_limit_instead_of_collecting_first() {
    let fetch = between(
        WEB_FETCH,
        "async fn fetch_inner(",
        "async fn read_response_body_bounded(",
    );
    assert!(fetch.contains("read_response_body_bounded(&mut resp, &safe_target)"));
    assert!(
        !fetch.contains(".bytes()"),
        "Response::bytes collects an attacker-controlled body before the cap"
    );

    let reader = between(
        WEB_FETCH,
        "async fn read_response_body_bounded(",
        "/// Strip + truncate a raw body",
    );
    assert!(reader.contains(".content_length()"));
    assert!(reader.contains(".chunk()"));
    assert!(reader.contains("next_len > MAX_RESPONSE_BYTES"));
    assert!(reader.contains("try_reserve"));
}

#[test]
fn web_cache_is_bounded_before_and_after_deserialization() {
    let lookup = between(WEB_CACHE, "pub fn lookup(", "/// Persist `doc`");
    assert!(lookup.contains("read_cache_file_bounded(&path)"));
    assert!(lookup.contains("cached_doc_is_valid(&doc, url)"));
    assert!(!lookup.contains("read_to_string"));

    let reader = between(
        WEB_CACHE,
        "fn read_cache_file_bounded(",
        "fn cached_doc_is_valid(",
    );
    assert!(reader.contains("metadata.len() > MAX_CACHE_FILE_BYTES as u64"));
    assert!(reader.contains("next_len > MAX_CACHE_FILE_BYTES"));
    assert!(reader.contains("try_reserve"));

    let validation = between(
        WEB_CACHE,
        "fn cached_doc_is_valid(",
        "/// When the dir holds",
    );
    assert!(validation.contains("doc.raw.len() <= MAX_CACHEABLE_BYTES"));
    assert!(WEB_CACHE.contains("parsed.query_pairs()"));
    assert!(WEB_CACHE.contains("parsed.password().is_some()"));
    assert!(WEB_FETCH.contains("URL userinfo credentials are not accepted"));
    assert!(WEB_CACHE.contains("atomic_write_private(&path, body.as_bytes())"));
}

#[test]
fn html_extraction_caps_output_links_and_allocations() {
    let stripper = between(WEB_FETCH, "fn strip_html_bounded(", "fn extract_attr<");
    assert!(stripper.contains("MAX_HTML_LINK_DEPTH"));
    assert!(stripper.contains("MAX_HTML_LINK_BYTES"));
    assert!(stripper.contains("links.try_reserve(1)"));

    let writer = between(WEB_FETCH, "struct HtmlTextWriter", "#[cfg(test)]");
    assert!(writer.contains("MAX_EXTRACTED_BYTES"));
    assert!(writer.contains("try_reserve"));
    assert!(writer.contains("HTML_TRUNCATION_MARKER"));
}

#[test]
fn sensitive_media_tempfiles_have_private_creation_boundaries() {
    assert!(PRIVATE_TEMP.contains("options.mode(0o600).custom_flags(libc::O_NOFOLLOW)"));
    assert!(PRIVATE_TEMP.contains("create_private_shared_file_new(path)"));
    assert!(PRIVATE_TEMP.contains("create_private_directory_new(path)"));
    assert!(PRIVATE_TEMP.contains("pub(crate) fn close(mut self) -> io::Result<()>"));
    assert!(WIN_NATIVE.contains("FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE"));
    assert!(WIN_NATIVE.contains("CreateDirectoryW(path_w.as_ptr(), &security_attributes)"));

    let snapshot = between(
        SERVE,
        "async fn snapshot_channel_media(",
        "/// Resolve an explicitly delegated channel agent",
    );
    assert!(snapshot.contains("crate::util::private_temp::named_file("));
    assert!(VIDEO.contains("crate::util::private_temp::named_file(prefix, suffix)"));
    assert!(DOCLING.contains("crate::util::private_temp::directory(\".neoth-docling-\")"));
    assert!(
        STT_PROVIDER.contains("crate::util::private_temp::named_file(\".neoth-fw-\", \".wav\")")
    );
}

#[test]
fn channel_audio_admission_matches_the_decoder_ceiling() {
    let limits = between(
        SERVE,
        "fn enforce_channel_media_input_limit(",
        "fn ensure_channel_media_stt_is_local(",
    );
    assert!(limits.contains("AssetKind::Audio => crate::media::audio::MAX_AUDIO_BYTES as usize"));
}

#[test]
fn complete_video_lifecycle_is_owned_past_caller_cancellation() {
    let entry = between(
        VIDEO,
        "pub(crate) async fn extract_with_context(",
        "async fn run_owned_video_pipeline(",
    );
    assert!(entry.contains("tokio::spawn(run_owned_video_pipeline("));
    let supervisor = between(
        VIDEO,
        "async fn run_owned_video_pipeline(",
        "#[async_trait::async_trait]",
    );
    assert!(supervisor.contains("VideoRequestLease::new(permit)"));
    assert!(supervisor.contains("snapshot_owned_private_input_async("));
    assert!(supervisor.contains("audio::AudioExtractor"));
    assert!(supervisor.contains("close_video_temp(temp, \"audio WAV\")"));
    assert!(supervisor.contains("close_video_temp(input_snapshot, \"input snapshot\")"));
    assert!(supervisor.contains("lease.release_after_verified_cleanup()"));
}
