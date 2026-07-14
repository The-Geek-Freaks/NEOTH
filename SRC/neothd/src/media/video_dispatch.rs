//! MM-02b — video analysis dispatch: decode frames → vision synthesis → audit.
//!
//! The real consumer that ties [`FrameDecoder`] + [`MultimodalSynthesizer`]
//! together. Caps the frame count to the provider's documented max, runs the
//! synthesis, and emits a `0xC9 VIDEO_FRAME_SYNTHESIZED` audit frame (metadata
//! only — the prompt is hashed, the frame pixels are NEVER in the WAL).

use super::Asset;
use super::frame_decoder::FrameDecoder;
use super::multimodal_synth::MultimodalSynthesizer;
use super::video_frames::{FrameFormat, MultimodalProvider, MultimodalRequest};
use crate::wal::writer::WalWriterHandle;

/// Build the `0xC9 VIDEO_FRAME_SYNTHESIZED` audit payload. Metadata only: the
/// prompt is xxh3-64 HASHED (never verbatim), pixels never included. PURE.
fn synthesized_payload(
    provider: MultimodalProvider,
    frame_count: usize,
    prompt: &str,
    output_chars: usize,
    now_unix: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "provider": provider.as_str(),
        "frame_count": frame_count,
        "prompt_hash": format!("{:016x}", xxhash_rust::xxh3::xxh3_64(prompt.as_bytes())),
        "output_chars": output_chars,
        "ts_unix": now_unix,
    }))
    .unwrap_or_default()
}

/// Decode `timestamps_ms` (capped to the provider's frame limit) into frames,
/// run the prompt-guided vision synthesis, and audit the call (`0xC9`). Returns
/// the provider's answer text.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_video_analysis(
    decoder: &dyn FrameDecoder,
    synth: &dyn MultimodalSynthesizer,
    asset: &Asset,
    timestamps_ms: &[u64],
    format: FrameFormat,
    prompt: &str,
    max_tokens: u32,
    writer: Option<&WalWriterHandle>,
    media_cfg: &crate::config::MediaConfig,
) -> Result<String, String> {
    // P0 ENFORCEMENT — decoding video frames and shipping them to a cloud vision
    // model uploads imagery from the operator's files. It may only run when the
    // operator opted in (`media.video_frame_upload_enabled`). Every offered
    // synthesizer is cloud-backed, so there is no local exemption.
    if !media_cfg.video_frame_upload_enabled {
        return Err(format!(
            "video frame upload ({}) is disabled — set media.video_frame_upload_enabled: true \
             to decode video frames and send them to a cloud vision model (those frames then \
             LEAVE the device)",
            synth.provider().as_str()
        ));
    }
    // P0 fail-closed pre-flight: under proof-hardline, refuse a CLOUD frame
    // upload that can't be audited.
    crate::media::enforce_cloud_media_audit(
        media_cfg.required_audit_for_cloud_media,
        writer.is_some(),
    )?;
    // Honour the provider's documented per-request frame cap.
    let cap = synth.provider().max_frames_per_request() as usize;
    let chosen: Vec<u64> = timestamps_ms.iter().take(cap).copied().collect();
    if chosen.is_empty() {
        return Err("no frame timestamps to analyse".into());
    }

    let mut frames = Vec::with_capacity(chosen.len());
    for ts in chosen {
        let f = decoder
            .decode_frame(asset, ts, format)
            .await
            .map_err(|e| format!("decode {ts}ms: {e}"))?;
        frames.push(f);
    }
    let frame_count = frames.len();
    let req = MultimodalRequest::new(prompt, frames, max_tokens).map_err(|e| e.to_string())?;

    let answer = synth.synthesize(&req).await?;

    if let Some(w) = writer {
        emit_synthesized(
            w,
            synth.provider(),
            frame_count,
            prompt,
            answer.chars().count(),
        )
        .await;
    }
    Ok(answer)
}

/// Emit the `0xC9` audit frame. Best-effort: a WAL error is logged + dropped
/// (the synthesis already happened; the frame is the audit nicety).
async fn emit_synthesized(
    writer: &WalWriterHandle,
    provider: MultimodalProvider,
    frame_count: usize,
    prompt: &str,
    output_chars: usize,
) {
    let now = crate::time::now_unix_secs();
    let payload = synthesized_payload(provider, frame_count, prompt, output_chars, now);
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED,
        &payload,
    );
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append VIDEO_FRAME_SYNTHESIZED (0xC9) failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::video_frames::Frame;
    use async_trait::async_trait;

    struct MockDecoder {
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl FrameDecoder for MockDecoder {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn decode_frame(
            &self,
            _asset: &Asset,
            ts_ms: u64,
            format: FrameFormat,
        ) -> Result<Frame, crate::media::ExtractionError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Frame {
                ts_ms,
                width: 1,
                height: 1,
                format,
                pixels: vec![1, 2, 3],
            })
        }
    }

    struct MockSynth {
        provider: MultimodalProvider,
        answer: String,
        seen_frames: std::sync::Mutex<usize>,
    }
    #[async_trait]
    impl MultimodalSynthesizer for MockSynth {
        fn provider(&self) -> MultimodalProvider {
            self.provider
        }
        async fn synthesize(&self, request: &MultimodalRequest) -> Result<String, String> {
            *self.seen_frames.lock().unwrap() = request.frames.len();
            Ok(self.answer.clone())
        }
    }

    fn asset() -> Asset {
        Asset::Bytes {
            kind: crate::media::AssetKind::Video,
            mime: "video/mp4".into(),
            data: vec![0u8; 8],
        }
    }

    fn frames_on() -> crate::config::MediaConfig {
        crate::config::MediaConfig {
            video_frame_upload_enabled: true,
            ..Default::default()
        }
    }

    fn test_writer() -> (
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (w, j) = crate::wal::writer::spawn(dir.path().join("vd.wal")).unwrap();
        (w, j, dir)
    }

    fn count_0xc9(seg: &std::path::Path) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut n = 0;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_VIDEO_FRAME_SYNTHESIZED {
                n += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        n
    }

    #[tokio::test]
    async fn dispatch_decodes_synthesises_and_emits_0xc9() {
        let decoder = MockDecoder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let synth = MockSynth {
            provider: MultimodalProvider::AnthropicClaude,
            answer: "a person waves at the camera".into(),
            seen_frames: std::sync::Mutex::new(0),
        };
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("vd.wal");

        let out = dispatch_video_analysis(
            &decoder,
            &synth,
            &asset(),
            &[0, 500, 1000],
            FrameFormat::Jpeg,
            "what happens?",
            256,
            Some(&writer),
            &frames_on(),
        )
        .await
        .unwrap();

        assert_eq!(out, "a person waves at the camera");
        assert_eq!(decoder.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(*synth.seen_frames.lock().unwrap(), 3);

        drop(writer);
        let _ = join.await;
        assert_eq!(count_0xc9(&seg), 1, "exactly one 0xC9 audit frame");
    }

    #[tokio::test]
    async fn dispatch_caps_frames_to_provider_max() {
        // OpenAI's documented cap is 10; feeding 15 timestamps must truncate.
        let decoder = MockDecoder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let synth = MockSynth {
            provider: MultimodalProvider::OpenAiGpt4o,
            answer: "ok".into(),
            seen_frames: std::sync::Mutex::new(0),
        };
        let ts: Vec<u64> = (0..15).map(|i| i * 100).collect();
        let (writer, join, _dir) = test_writer();
        dispatch_video_analysis(
            &decoder,
            &synth,
            &asset(),
            &ts,
            FrameFormat::Jpeg,
            "p",
            64,
            Some(&writer),
            &frames_on(),
        )
        .await
        .unwrap();
        assert_eq!(
            *synth.seen_frames.lock().unwrap(),
            10,
            "must cap at the OpenAI per-request frame limit"
        );
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn dispatch_empty_timestamps_errors() {
        let decoder = MockDecoder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let synth = MockSynth {
            provider: MultimodalProvider::GoogleGemini,
            answer: "x".into(),
            seen_frames: std::sync::Mutex::new(0),
        };
        let err = dispatch_video_analysis(
            &decoder,
            &synth,
            &asset(),
            &[],
            FrameFormat::Jpeg,
            "p",
            64,
            None,
            &frames_on(),
        )
        .await
        .unwrap_err();
        assert!(err.contains("no frame timestamps"));
    }

    #[tokio::test]
    async fn cloud_frame_upload_refused_when_flag_off() {
        // P0 — video_frame_upload_enabled OFF (default): a cloud synth must be
        // refused BEFORE any frame is decoded (no decoder calls, no WAL frame).
        let decoder = MockDecoder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let synth = MockSynth {
            provider: MultimodalProvider::AnthropicClaude,
            answer: "leaked".into(),
            seen_frames: std::sync::Mutex::new(0),
        };
        let off = crate::config::MediaConfig::default();
        let err = dispatch_video_analysis(
            &decoder,
            &synth,
            &asset(),
            &[0, 500],
            FrameFormat::Jpeg,
            "p",
            64,
            None,
            &off,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("video frame upload") && err.contains("LEAVE the device"),
            "got: {err}"
        );
        // Gate fired before decoding — nothing touched the asset.
        assert_eq!(decoder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(*synth.seen_frames.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn cloud_frame_upload_refused_when_required_audit_and_no_writer() {
        // P0 proof-hardline: upload enabled BUT required_audit on + no WAL sink →
        // refuse before decoding (no unprovable cloud upload).
        let decoder = MockDecoder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let synth = MockSynth {
            provider: MultimodalProvider::AnthropicClaude,
            answer: "leaked".into(),
            seen_frames: std::sync::Mutex::new(0),
        };
        let cfg = crate::config::MediaConfig {
            video_frame_upload_enabled: true,
            required_audit_for_cloud_media: true,
            ..Default::default()
        };
        let err = dispatch_video_analysis(
            &decoder,
            &synth,
            &asset(),
            &[0, 500],
            FrameFormat::Jpeg,
            "p",
            64,
            None,
            &cfg,
        )
        .await
        .unwrap_err();
        assert!(err.contains("required_audit_for_cloud_media"), "got: {err}");
        assert_eq!(decoder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn payload_hashes_prompt_and_omits_raw_text() {
        let p = synthesized_payload(
            MultimodalProvider::AnthropicClaude,
            3,
            "secret prompt",
            42,
            1700,
        );
        let v: serde_json::Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["provider"], "anthropic_claude");
        assert_eq!(v["frame_count"], 3);
        assert_eq!(v["output_chars"], 42);
        assert_eq!(v["ts_unix"], 1700);
        assert!(
            !p.windows(6).any(|w| w == b"secret"),
            "raw prompt must not be in the frame"
        );
        assert_eq!(
            v["prompt_hash"],
            format!("{:016x}", xxhash_rust::xxh3::xxh3_64(b"secret prompt"))
        );
    }
}
