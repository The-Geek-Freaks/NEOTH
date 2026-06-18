//! MM-02b — video frame decoder. Extracts a still frame near a timestamp via
//! an `ffmpeg` subprocess, mirroring [`super::video`]'s extraction pattern
//! (PATH-resolved binary, temp-file for byte sources, image2pipe to stdout).
//!
//! ffmpeg is a subprocess — there is no in-process video codec dep. A missing
//! binary maps to an actionable "install ffmpeg" error, not "command not found".

use std::path::Path;
use std::process::Stdio;

use super::video_frames::{Frame, FrameFormat};
use super::{Asset, ExtractionError};

/// Extract a single still frame near a source timestamp.
#[async_trait::async_trait]
pub trait FrameDecoder: Send + Sync {
    fn name(&self) -> &'static str;

    /// Decode the frame nearest `ts_ms` from `asset`, encoded as `format`.
    async fn decode_frame(
        &self,
        asset: &Asset,
        ts_ms: u64,
        format: FrameFormat,
    ) -> Result<Frame, ExtractionError>;
}

/// The ffmpeg `-vcodec` for an image-pipe `format`. `None` = not an encodable
/// still image (e.g. `Rgb24` raw — the vision providers want jpeg/png/webp).
fn vcodec_for_format(format: FrameFormat) -> Option<&'static str> {
    match format {
        FrameFormat::Jpeg => Some("mjpeg"),
        FrameFormat::Png => Some("png"),
        FrameFormat::WebP => Some("webp"),
        FrameFormat::Rgb24 => None,
    }
}

/// Build the ffmpeg arg vector for a single-frame extract at `ts_ms`. PURE +
/// testable. `-ss` BEFORE `-i` is an input seek (fast, keyframe-accurate
/// enough for sampling). Returns `None` for a non-image format.
fn ffmpeg_frame_args(input: &str, ts_ms: u64, format: FrameFormat) -> Option<Vec<String>> {
    let vcodec = vcodec_for_format(format)?;
    // ffmpeg `-ss` takes seconds (fractional) — render ms as S.mmm.
    let seconds = format!("{}.{:03}", ts_ms / 1000, ts_ms % 1000);
    Some(vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-ss".into(),
        seconds,
        "-i".into(),
        input.into(),
        "-frames:v".into(),
        "1".into(),
        "-f".into(),
        "image2pipe".into(),
        "-vcodec".into(),
        vcodec.into(),
        "pipe:1".into(),
    ])
}

/// ffmpeg-backed [`FrameDecoder`].
pub struct FfmpegFrameDecoder;

impl FfmpegFrameDecoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FfmpegFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FrameDecoder for FfmpegFrameDecoder {
    fn name(&self) -> &'static str {
        "ffmpeg"
    }

    async fn decode_frame(
        &self,
        asset: &Asset,
        ts_ms: u64,
        format: FrameFormat,
    ) -> Result<Frame, ExtractionError> {
        match asset {
            Asset::Path { path, .. } => run_ffmpeg_frame(path, ts_ms, format).await,
            Asset::Bytes { data, .. } => {
                // ffmpeg needs a seekable source — hand-roll a temp file (mirror
                // video.rs; the tempfile crate is dev-only). Unique suffix avoids
                // parallel collisions.
                let nanos = crate::time::now_unix_ns_u128();
                let pid = std::process::id();
                let mut tmp_path = std::env::temp_dir();
                tmp_path.push(format!("neoth-framedec-{pid}-{nanos}.bin"));
                std::fs::write(&tmp_path, data)
                    .map_err(|e| ExtractionError::Io(format!("write temp: {e}")))?;
                let out = run_ffmpeg_frame(&tmp_path, ts_ms, format).await;
                let _ = std::fs::remove_file(&tmp_path);
                out
            }
        }
    }
}

async fn run_ffmpeg_frame(
    input: &Path,
    ts_ms: u64,
    format: FrameFormat,
) -> Result<Frame, ExtractionError> {
    let args = ffmpeg_frame_args(&input.to_string_lossy(), ts_ms, format).ok_or_else(|| {
        ExtractionError::Backend {
            backend: "video",
            reason: format!(
                "frame format {} is not an encodable still image",
                format.as_str()
            ),
        }
    })?;
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| {
        if matches!(e.kind(), std::io::ErrorKind::NotFound) {
            ExtractionError::Backend {
                backend: "video",
                reason: "ffmpeg binary not found on PATH. Install via your package manager \
                     (apt install ffmpeg / brew install ffmpeg / choco install ffmpeg) and re-run."
                    .into(),
            }
        } else {
            ExtractionError::Io(format!("spawn ffmpeg (frame): {e}"))
        }
    })?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("ffmpeg frame exit {}: {}", output.status, err.trim()),
        });
    }
    if output.stdout.is_empty() {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("ffmpeg produced no frame at {ts_ms}ms (past end of clip?)"),
        });
    }
    // width/height are unknown without decoding the image; the vision providers
    // read the encoded bytes directly + don't need them. Leave 0/0.
    Ok(Frame {
        ts_ms,
        width: 0,
        height: 0,
        format,
        pixels: output.stdout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcodec_maps_image_formats() {
        assert_eq!(vcodec_for_format(FrameFormat::Jpeg), Some("mjpeg"));
        assert_eq!(vcodec_for_format(FrameFormat::Png), Some("png"));
        assert_eq!(vcodec_for_format(FrameFormat::WebP), Some("webp"));
        assert_eq!(vcodec_for_format(FrameFormat::Rgb24), None);
    }

    #[test]
    fn ffmpeg_args_seek_format_and_pipe() {
        let args = ffmpeg_frame_args("/v.mp4", 2500, FrameFormat::Jpeg).unwrap();
        // -ss seconds rendered as S.mmm, BEFORE -i.
        let ss = args.iter().position(|a| a == "-ss").unwrap();
        assert_eq!(args[ss + 1], "2.500");
        let i = args.iter().position(|a| a == "-i").unwrap();
        assert!(ss < i, "-ss must precede -i (input seek)");
        assert_eq!(args[i + 1], "/v.mp4");
        assert!(args.windows(2).any(|w| w == ["-frames:v", "1"]));
        assert!(args.windows(2).any(|w| w == ["-vcodec", "mjpeg"]));
        assert_eq!(args.last().unwrap(), "pipe:1");
    }

    #[test]
    fn ffmpeg_args_sub_second_ms_padding() {
        let args = ffmpeg_frame_args("/v.mp4", 40, FrameFormat::Png).unwrap();
        let ss = args.iter().position(|a| a == "-ss").unwrap();
        assert_eq!(args[ss + 1], "0.040", "ms must zero-pad to 3 digits");
    }

    #[test]
    fn ffmpeg_args_none_for_raw_format() {
        assert!(ffmpeg_frame_args("/v.mp4", 0, FrameFormat::Rgb24).is_none());
    }
}
