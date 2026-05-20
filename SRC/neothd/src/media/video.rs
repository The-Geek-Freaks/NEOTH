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
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "video_pipeline".into(),
                serde_json::json!({
                    "extractor": "video",
                    "audio_via": "ffmpeg-subprocess",
                }),
            );
        }
        Ok(Extraction {
            text: audio_out.text,
            metadata,
        })
    }
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
