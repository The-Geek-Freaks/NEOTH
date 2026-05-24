//! Video backend — R-9 Phase 2.
//!
//! Strategy: spawn `ffmpeg` as a subprocess to extract the audio track,
//! re-encode it to 16 kHz mono WAV, then route the resulting bytes
//! through the [`audio::AudioExtractor`]. Avoids re-implementing
//! container parsing while staying self-contained from NEOTH's
//! perspective — `ffmpeg` is on PATH for any operator who already
//! handles video files, and the wizard's installer step can prompt
//! for it (R-9 Phase 3).
//!
//! Path-vs-bytes:
//!   - `Asset::Path` is handed directly to ffmpeg as `-i <path>`.
//!   - `Asset::Bytes` is written to a temp file first so ffmpeg can
//!     seek freely; some container formats (MP4 moov atoms) don't
//!     stream cleanly via stdin.
//!
//! Future: native demux via `symphonia` once it gains a full MP4 reader
//! + chunked audio extraction without ffmpeg.

use std::path::Path;
use std::process::Stdio;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor, audio};

pub struct VideoExtractor;

#[async_trait::async_trait]
impl MediaExtractor for VideoExtractor {
    fn name(&self) -> &'static str {
        "video"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Video {
            return Err(ExtractionError::Unsupported {
                backend: "video",
                got: asset.kind(),
            });
        }
        // 1. Extract audio track as 16 kHz mono WAV via ffmpeg.
        let wav_bytes = extract_audio_track(asset).await?;
        // 2. Hand the WAV to the audio backend so transcription /
        //    metadata logic stays in one place.
        let audio_asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: wav_bytes,
        };
        let audio_out = audio::AudioExtractor.extract(&audio_asset).await?;
        // Re-tag the metadata so operators can tell the extraction came
        // through the video pipeline (not a bare audio file).
        let mut metadata = audio_out.metadata;

        // M-4 thumbnail extract (Session 23, Workstream H): best-effort
        // first-frame grab via the same ffmpeg subprocess. Surfaces as
        // base64-encoded JPEG bytes in metadata so downstream consumers
        // can persist + display without a second ffmpeg trip. Failure
        // here is non-fatal — the audio extraction already succeeded
        // and that's the primary deliverable.
        let thumbnail = match extract_thumbnail(asset).await {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "video thumbnail extract failed (non-fatal); continuing"
                );
                None
            }
        };

        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "video_pipeline".into(),
                serde_json::json!({
                    "extractor": "video",
                    "audio_via": "ffmpeg-subprocess",
                    "thumbnail_via": if thumbnail.is_some() {
                        "ffmpeg-subprocess"
                    } else {
                        "skipped"
                    },
                }),
            );
            if let Some(bytes) = thumbnail.as_ref() {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                obj.insert(
                    "thumbnail".into(),
                    serde_json::json!({
                        "mime": "image/jpeg",
                        "bytes_base64": b64,
                        "bytes_len": bytes.len(),
                    }),
                );
            }
        }
        Ok(Extraction {
            text: audio_out.text,
            metadata,
        })
    }
}

/// Extract the first frame of a video as a JPEG via the ffmpeg
/// subprocess. Used by the video extraction pipeline to provide a
/// preview operators can render in the UI / messenger reply.
pub(crate) async fn extract_thumbnail(asset: &Asset) -> Result<Vec<u8>, ExtractionError> {
    match asset {
        Asset::Path { path, .. } => run_ffmpeg_thumbnail(path).await,
        Asset::Bytes { data, .. } => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            let mut tmp_path = std::env::temp_dir();
            tmp_path.push(format!("neoth-thumb-{pid}-{nanos}.bin"));
            std::fs::write(&tmp_path, data)
                .map_err(|e| ExtractionError::Io(format!("write temp: {e}")))?;
            let out = run_ffmpeg_thumbnail(&tmp_path).await;
            let _ = std::fs::remove_file(&tmp_path);
            out
        }
    }
}

async fn run_ffmpeg_thumbnail(input: &Path) -> Result<Vec<u8>, ExtractionError> {
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-i")
        .arg(input)
        .arg("-ss")
        .arg("0")
        .arg("-frames:v")
        .arg("1")
        .arg("-f")
        .arg("image2pipe")
        .arg("-vcodec")
        .arg("mjpeg")
        .arg("pipe:1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| {
        if matches!(e.kind(), std::io::ErrorKind::NotFound) {
            ExtractionError::Backend {
                backend: "video",
                reason: "ffmpeg not on PATH (thumbnail extract)".into(),
            }
        } else {
            ExtractionError::Io(format!("spawn ffmpeg (thumbnail): {e}"))
        }
    })?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("ffmpeg thumbnail exit {}: {}", output.status, err.trim()),
        });
    }
    Ok(output.stdout)
}

async fn extract_audio_track(asset: &Asset) -> Result<Vec<u8>, ExtractionError> {
    match asset {
        Asset::Path { path, .. } => run_ffmpeg(path).await,
        Asset::Bytes { data, .. } => {
            // ffmpeg needs a seekable source for many video containers.
            // Hand-roll a temp file (tempfile crate is dev-only); the
            // unique-suffix construction avoids parallel-test collisions.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            let mut tmp_path = std::env::temp_dir();
            tmp_path.push(format!("neoth-video-{pid}-{nanos}.bin"));
            std::fs::write(&tmp_path, data)
                .map_err(|e| ExtractionError::Io(format!("write temp: {e}")))?;
            let out = run_ffmpeg(&tmp_path).await;
            // Best-effort cleanup; tmp dir gets swept by the OS even if
            // we fail to remove.
            let _ = std::fs::remove_file(&tmp_path);
            out
        }
    }
}

async fn run_ffmpeg(input: &Path) -> Result<Vec<u8>, ExtractionError> {
    // Output to stdout so we don't need a second temp file. WAV is the
    // most-robust container for piping; ffmpeg writes a RIFF stream that
    // symphonia decodes cleanly.
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-i")
        .arg(input)
        .arg("-vn") // drop video
        .arg("-ac")
        .arg("1") // mono
        .arg("-ar")
        .arg(audio::TARGET_SAMPLE_RATE.to_string())
        .arg("-f")
        .arg("wav")
        .arg("pipe:1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| {
        // ffmpeg missing → wrap into actionable error so the operator
        // sees "install ffmpeg" not "command not found".
        if matches!(e.kind(), std::io::ErrorKind::NotFound) {
            ExtractionError::Backend {
                backend: "video",
                reason: "ffmpeg binary not found on PATH. Install via your package manager \
                     (apt install ffmpeg / brew install ffmpeg / choco install ffmpeg) \
                     and re-run."
                    .into(),
            }
        } else {
            ExtractionError::Io(format!("spawn ffmpeg: {e}"))
        }
    })?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!(
                "ffmpeg exited with status {}: {}",
                output.status,
                err.trim()
            ),
        });
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn extract_returns_unsupported_for_non_video() {
        let extractor = VideoExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: vec![0u8; 8],
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported {
                backend: "video",
                ..
            }
        ));
    }

    /// Live ffmpeg subprocess test — gated behind `#[ignore]` because the
    /// binary isn't always installed on CI runners. Operators with
    /// ffmpeg on PATH can verify via `cargo test -- --ignored video`.
    #[tokio::test]
    #[ignore = "requires ffmpeg on PATH"]
    async fn run_ffmpeg_errors_when_input_does_not_exist() {
        let r = run_ffmpeg(Path::new("does-not-exist.mp4")).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    #[ignore = "requires ffmpeg on PATH"]
    async fn thumbnail_extract_errors_on_missing_input() {
        let r = run_ffmpeg_thumbnail(Path::new("does-not-exist.mp4")).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn thumbnail_surfaces_missing_ffmpeg_with_helpful_message() {
        let prev = std::env::var("PATH").ok();
        // SAFETY: test-only env mutation; restored before the next
        // assertion to keep the parallel-test race window tiny.
        unsafe {
            std::env::set_var("PATH", "");
        }
        let asset = Asset::Bytes {
            kind: AssetKind::Video,
            mime: "video/mp4".into(),
            data: b"fake".to_vec(),
        };
        let r = extract_thumbnail(&asset).await;
        unsafe {
            match prev {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        match r {
            Err(ExtractionError::Backend {
                backend: "video",
                reason,
            }) if reason.contains("ffmpeg not on PATH") => {}
            other => panic!("expected ffmpeg-missing Backend error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn extract_surfaces_missing_ffmpeg_with_helpful_message() {
        // Override PATH so the spawn fails with NotFound.
        let prev = std::env::var("PATH").ok();
        // SAFETY: test-only env mutation. Cargo runs tests in parallel,
        // so a concurrent test reading PATH for a real subprocess could
        // race here. We restore promptly to keep the window small.
        unsafe {
            std::env::set_var("PATH", "");
        }
        let extractor = VideoExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Video,
            mime: "video/mp4".into(),
            data: b"fake".to_vec(),
        };
        let r = extractor.extract(&asset).await;
        unsafe {
            match prev {
                Some(v) => std::env::set_var("PATH", v),
                None => std::env::remove_var("PATH"),
            }
        }
        // ffmpeg-not-found surfaces as Backend with actionable message.
        match r {
            Err(ExtractionError::Backend {
                backend: "video",
                reason,
            }) if reason.contains("ffmpeg binary not found") => {}
            other => panic!("expected 'ffmpeg not found' Backend error, got: {other:?}"),
        }
    }
}
