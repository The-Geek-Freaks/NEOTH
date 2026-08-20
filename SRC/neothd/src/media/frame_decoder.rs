//! MM-02b — video frame decoder. Extracts a still frame near a timestamp via
//! an `ffmpeg` subprocess, mirroring [`super::video`]'s extraction pattern
//! (PATH-resolved binary, temp-file for byte sources, image2pipe to stdout).
//!
//! ffmpeg is a subprocess — there is no in-process video codec dep. A missing
//! binary maps to an actionable "install ffmpeg" error, not "command not found".

use std::path::Path;
use super::video::{
    acquire_auxiliary_video_work_permit, poison_video_worker_budget_after_private_cleanup_failure,
    run_auxiliary_ffmpeg_bounded_with_permit, snapshot_video_input_for_auxiliary_ffmpeg,
    AuxiliaryVideoWorkPermit,
};
use super::video_frames::{Frame, FrameFormat, HARD_MAX_FRAMES_PER_REQUEST};
use super::{Asset, ExtractionError};

const PERCEPTUAL_GRID_SIDE: usize = 16;
const PERCEPTUAL_SIGNATURE_BYTES: usize = PERCEPTUAL_GRID_SIDE * PERCEPTUAL_GRID_SIDE;
const FRAME_STDOUT_LIMIT: u64 = 4 * 1024 * 1024;
const PERCEPTUAL_STDOUT_LIMIT: u64 = PERCEPTUAL_SIGNATURE_BYTES as u64;
const FFMPEG_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const FFMPEG_MISSING_BINARY_REASON: &str = "ffmpeg binary not found on PATH. Install via your package manager \
    (apt install ffmpeg / brew install ffmpeg / choco install ffmpeg) and re-run.";

/// One encoded provider frame plus the local pixels used to compare it.
/// Both values must originate from the same immutable video snapshot.
#[derive(Clone)]
pub struct DecodedVideoFrame {
    pub frame: Frame,
    pub grayscale_signature: Option<[u8; PERCEPTUAL_SIGNATURE_BYTES]>,
}

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

    /// Decode the same video timestamp into exactly 16×16 greyscale bytes for
    /// local perceptual comparison. Implementations that cannot prove this
    /// contract return `None`; dispatch then preserves their frames rather
    /// than comparing compressed payload bytes as if they were pixels.
    async fn decode_perceptual_signature(
        &self,
        _asset: &Asset,
        _ts_ms: u64,
    ) -> Result<Option<[u8; PERCEPTUAL_SIGNATURE_BYTES]>, ExtractionError> {
        Ok(None)
    }

    /// Decode one provider frame and its perceptual signature as one operation.
    /// The default keeps legacy implementations source-compatible. Decoders
    /// that use subprocesses can override it to own one immutable input across
    /// both representations and across caller cancellation.
    async fn decode_frame_with_perceptual_signature(
        &self,
        asset: &Asset,
        ts_ms: u64,
        format: FrameFormat,
    ) -> Result<(Frame, Option<[u8; PERCEPTUAL_SIGNATURE_BYTES]>), ExtractionError> {
        let frame = self.decode_frame(asset, ts_ms, format).await?;
        let signature = self.decode_perceptual_signature(asset, ts_ms).await?;
        Ok((frame, signature))
    }

    /// Decode a capped request's timestamps. The default keeps existing
    /// decoders source-compatible; the ffmpeg implementation overrides it to
    /// bind the complete request to one cancellation-safe private snapshot.
    async fn decode_frames_with_perceptual_signatures(
        &self,
        asset: &Asset,
        timestamps_ms: &[u64],
        format: FrameFormat,
    ) -> Result<Vec<DecodedVideoFrame>, ExtractionError> {
        enforce_frame_batch_hard_cap(timestamps_ms.len())?;
        let mut frames = Vec::with_capacity(timestamps_ms.len());
        for &ts_ms in timestamps_ms {
            let (frame, grayscale_signature) = self
                .decode_frame_with_perceptual_signature(asset, ts_ms, format)
                .await?;
            frames.push(DecodedVideoFrame {
                frame,
                grayscale_signature,
            });
        }
        Ok(frames)
    }
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

/// ffmpeg arguments for the bounded local-only perceptual preprocessor.
/// Exactly one 16×16 `gray` frame reaches stdout: 256 bytes, never a provider
/// payload. This is deliberately separate from the encoded still image that
/// the multimodal provider receives.
fn ffmpeg_perceptual_args(input: &str, ts_ms: u64) -> Vec<String> {
    let seconds = format!("{}.{:03}", ts_ms / 1000, ts_ms % 1000);
    vec![
        "-hide_banner".into(),
        "-loglevel".into(),
        "error".into(),
        "-ss".into(),
        seconds,
        "-i".into(),
        input.into(),
        "-frames:v".into(),
        "1".into(),
        "-vf".into(),
        "scale=16:16:flags=area,format=gray".into(),
        "-f".into(),
        "rawvideo".into(),
        "-pix_fmt".into(),
        "gray".into(),
        "pipe:1".into(),
    ]
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
        let (frame, _) = self
            .decode_frame_with_perceptual_signature(asset, ts_ms, format)
            .await?;
        Ok(frame)
    }

    async fn decode_perceptual_signature(
        &self,
        asset: &Asset,
        ts_ms: u64,
    ) -> Result<Option<[u8; PERCEPTUAL_SIGNATURE_BYTES]>, ExtractionError> {
        let (_, signature) = self
            .decode_frame_with_perceptual_signature(asset, ts_ms, FrameFormat::Jpeg)
            .await?;
        Ok(signature)
    }

    async fn decode_frame_with_perceptual_signature(
        &self,
        asset: &Asset,
        ts_ms: u64,
        format: FrameFormat,
    ) -> Result<(Frame, Option<[u8; PERCEPTUAL_SIGNATURE_BYTES]>), ExtractionError> {
        let mut frames = self
            .decode_frames_with_perceptual_signatures(asset, &[ts_ms], format)
            .await?;
        let decoded = frames.pop().ok_or_else(|| ExtractionError::Backend {
            backend: "video",
            reason: "ffmpeg frame-pair supervisor returned no frame".into(),
        })?;
        Ok((decoded.frame, decoded.grayscale_signature))
    }

    async fn decode_frames_with_perceptual_signatures(
        &self,
        asset: &Asset,
        timestamps_ms: &[u64],
        format: FrameFormat,
    ) -> Result<Vec<DecodedVideoFrame>, ExtractionError> {
        // The outer caller may cancel at any await. Move the complete capped
        // batch into its own task so the sole input snapshot survives until
        // every child supervisor has proved termination and it is explicitly
        // removed. No timestamp can reopen the ambient source path.
        enforce_frame_batch_hard_cap(timestamps_ms.len())?;
        let permit = acquire_auxiliary_video_work_permit().await?;
        let asset = asset.clone();
        let timestamps_ms = timestamps_ms.to_vec();
        tokio::spawn(async move {
            let snapshot = snapshot_video_input_for_auxiliary_ffmpeg(&asset).await?;
            let result = async {
                let mut frames = Vec::with_capacity(timestamps_ms.len());
                for ts_ms in timestamps_ms {
                    let frame = run_ffmpeg_frame(snapshot.path(), ts_ms, format, &permit).await?;
                    let grayscale_signature =
                        run_ffmpeg_perceptual(snapshot.path(), ts_ms, &permit).await?;
                    frames.push(DecodedVideoFrame {
                        frame,
                        grayscale_signature: Some(grayscale_signature),
                    });
                }
                Ok::<_, ExtractionError>(frames)
            }
            .await;
            if let Err(error) = snapshot.close() {
                poison_video_worker_budget_after_private_cleanup_failure();
                return Err(ExtractionError::Io(format!(
                    "remove private video frame snapshot: {error}"
                )));
            }
            result
        })
        .await
        .map_err(|error| ExtractionError::Backend {
            backend: "video",
            reason: format!("ffmpeg frame-batch supervisor failed: {error}"),
        })?
    }
}

fn enforce_frame_batch_hard_cap(frame_count: usize) -> Result<(), ExtractionError> {
    if frame_count > HARD_MAX_FRAMES_PER_REQUEST {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!(
                "video frame batch has {frame_count} timestamps; hard cap is {HARD_MAX_FRAMES_PER_REQUEST}"
            ),
        });
    }
    Ok(())
}

async fn run_ffmpeg_frame(
    input: &Path,
    ts_ms: u64,
    format: FrameFormat,
    permit: &AuxiliaryVideoWorkPermit,
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
    cmd.args(&args);
    let pixels = run_auxiliary_ffmpeg_bounded_with_permit(
        cmd,
        "encoded video frame",
        FFMPEG_FRAME_TIMEOUT,
        FRAME_STDOUT_LIMIT,
        FFMPEG_MISSING_BINARY_REASON,
        permit,
    )
    .await?;
    if pixels.is_empty() {
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
        pixels,
    })
}

async fn run_ffmpeg_perceptual(
    input: &Path,
    ts_ms: u64,
    permit: &AuxiliaryVideoWorkPermit,
) -> Result<[u8; PERCEPTUAL_SIGNATURE_BYTES], ExtractionError> {
    let args = ffmpeg_perceptual_args(&input.to_string_lossy(), ts_ms);
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.args(&args);
    let stdout = run_auxiliary_ffmpeg_bounded_with_permit(
        cmd,
        "perceptual video frame",
        FFMPEG_FRAME_TIMEOUT,
        PERCEPTUAL_STDOUT_LIMIT,
        FFMPEG_MISSING_BINARY_REASON,
        permit,
    )
    .await?;
    stdout.try_into().map_err(|bytes: Vec<u8>| {
        ExtractionError::Backend {
            backend: "video",
            reason: format!(
                "ffmpeg perceptual frame at {ts_ms}ms produced {} bytes; \
                 expected {PERCEPTUAL_SIGNATURE_BYTES}",
                bytes.len()
            ),
        }
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

    #[test]
    fn perceptual_ffmpeg_args_emit_one_fixed_greyscale_grid() {
        let args = ffmpeg_perceptual_args("/v.mp4", 2_500);
        assert!(args.windows(2).any(|pair| pair == ["-frames:v", "1"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-vf", "scale=16:16:flags=area,format=gray"]));
        assert!(args.windows(2).any(|pair| pair == ["-f", "rawvideo"]));
        assert!(args.windows(2).any(|pair| pair == ["-pix_fmt", "gray"]));
        assert_eq!(args.last().map(String::as_str), Some("pipe:1"));
        assert_eq!(PERCEPTUAL_SIGNATURE_BYTES, 256);
    }

    #[test]
    fn frame_batch_supervisor_owns_then_verifies_private_snapshot_cleanup() {
        let source = include_str!("frame_decoder.rs");
        let implementation = source
            .find("impl FrameDecoder for FfmpegFrameDecoder")
            .expect("ffmpeg frame decoder implementation");
        let batch = source[implementation..]
            .find("async fn decode_frames_with_perceptual_signatures(")
            .expect("ffmpeg batch override");
        let owned = &source[implementation + batch..];
        let permit = owned
            .find("let permit = acquire_auxiliary_video_work_permit().await?")
            .unwrap();
        let asset_copy = owned.find("let asset = asset.clone()").unwrap();
        let spawn = owned.find("tokio::spawn(async move").unwrap();
        let snapshot = owned
            .find("snapshot_video_input_for_auxiliary_ffmpeg(&asset)")
            .unwrap();
        let loop_start = owned.find("for ts_ms in timestamps_ms").unwrap();
        let encoded = owned.find("run_ffmpeg_frame(snapshot.path()").unwrap();
        let signature = owned
            .find("run_ffmpeg_perceptual(snapshot.path()")
            .unwrap();
        let close = owned.find("snapshot.close()").unwrap();
        let poison = owned
            .find("poison_video_worker_budget_after_private_cleanup_failure()")
            .unwrap();
        assert!(permit < asset_copy && asset_copy < spawn && spawn < snapshot);
        assert!(snapshot < loop_start && loop_start < encoded);
        assert!(encoded < signature);
        assert!(signature < close && close < poison);
    }

}
