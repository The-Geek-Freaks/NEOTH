//! ADOPT31-F1/F3 — real visual-video probe and sampling over one immutable
//! private snapshot. This is intentionally an ingest helper, not a replacement
//! for the established audio/STT video extractor.

use std::time::Duration;

use super::frame_decoder::{DecodedVideoFrame, FfmpegFrameDecoder};
use super::video::{
    AuxiliaryVideoWorkPermit, acquire_auxiliary_video_work_permit,
    poison_video_worker_budget_after_private_cleanup_failure,
    run_auxiliary_ffmpeg_bounded_with_permit_capture_stderr,
    snapshot_video_input_for_auxiliary_ffmpeg,
};
use super::video_frames::{
    FrameFormat, VISUAL_SCENE_CHANGE, plan_observed_video_frame_timestamps,
    scene_change_config,
};
use super::{Asset, ExtractionError};

const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const SCENE_SAMPLE_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_STDOUT_LIMIT: u64 = 256 * 1024;
const FFMPEG_MISSING_BINARY_REASON: &str = "ffmpeg binary not found on PATH. Install via your package manager \
    (apt install ffmpeg / brew install ffmpeg / choco install ffmpeg) and re-run.";
const FFPROBE_MISSING_BINARY_REASON: &str = "ffprobe binary not found on PATH. Install ffmpeg (which provides ffprobe) and re-run.";

/// One fully local decoded batch, with the exact ordered timestamps selected
/// from observed probe/scene evidence. No source path escapes this module.
pub(crate) struct VisualVideoFrameBatch {
    pub timestamps_ms: Vec<u64>,
    #[cfg(all(test, target_os = "linux"))]
    pub scene_timestamps_ms: Vec<u64>,
    pub frames: Vec<DecodedVideoFrame>,
}

struct ObservedFrameTimestamps {
    keyframes_ms: Vec<u64>,
    frames_ms: Vec<u64>,
}

struct VisualVideoSnapshot {
    input: tempfile::NamedTempFile,
    permit: AuxiliaryVideoWorkPermit,
}

impl VisualVideoSnapshot {
    async fn create(asset: &Asset) -> Result<Self, ExtractionError> {
        let permit = acquire_auxiliary_video_work_permit().await?;
        let input = snapshot_video_input_for_auxiliary_ffmpeg(asset).await?;
        Ok(Self { input, permit })
    }

    fn path(&self) -> &std::path::Path {
        self.input.path()
    }

    async fn duration_ms(&self) -> Result<u64, ExtractionError> {
        let mut command = tokio::process::Command::new("ffprobe");
        command.args([
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=nokey=1:noprint_wrappers=1",
        ]);
        command.arg(self.path());
        let output = run_auxiliary_ffmpeg_bounded_with_permit_capture_stderr(
            command,
            "video duration probe",
            PROBE_TIMEOUT,
            PROBE_STDOUT_LIMIT,
            FFPROBE_MISSING_BINARY_REASON,
            &self.permit,
        )
        .await?;
        parse_duration_ms(&output.stdout)
    }

    async fn observed_frame_timestamps_ms(
        &self,
        duration_ms: u64,
    ) -> Result<ObservedFrameTimestamps, ExtractionError> {
        let mut command = tokio::process::Command::new("ffprobe");
        command.args([
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_frames",
            "-show_entries",
            "frame=key_frame,best_effort_timestamp_time",
            "-of",
            "json",
        ]);
        command.arg(self.path());
        let output = run_auxiliary_ffmpeg_bounded_with_permit_capture_stderr(
            command,
            "video keyframe probe",
            PROBE_TIMEOUT,
            PROBE_STDOUT_LIMIT,
            FFPROBE_MISSING_BINARY_REASON,
            &self.permit,
        )
        .await?;
        parse_observed_frame_timestamps_ms(&output.stdout, duration_ms)
    }

    async fn scene_timestamps_ms(&self, duration_ms: u64) -> Result<Vec<u64>, ExtractionError> {
        let mut command = tokio::process::Command::new("ffmpeg");
        command.args([
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "info",
            "-i",
        ]);
        command.arg(self.path());
        let (threshold, _) = scene_change_config(&VISUAL_SCENE_CHANGE).ok_or_else(|| {
            ExtractionError::Backend {
                backend: "video",
                reason: "visual scene-change strategy is not configured".into(),
            }
        })?;
        let scene_filter = format!("select='gt(scene,{threshold:.2})',showinfo");
        command.arg("-vf").arg(scene_filter).args(["-an", "-f", "null", "-"]);
        let output = run_auxiliary_ffmpeg_bounded_with_permit_capture_stderr(
            command,
            "scene-change video sampling",
            SCENE_SAMPLE_TIMEOUT,
            1,
            FFMPEG_MISSING_BINARY_REASON,
            &self.permit,
        )
        .await?;
        parse_scene_timestamps_ms(&output.stderr, duration_ms)
    }

    fn close(self) -> Result<(), ExtractionError> {
        self.input.close().map_err(|error| {
            poison_video_worker_budget_after_private_cleanup_failure();
            ExtractionError::Io(format!("remove private visual video snapshot: {error}"))
        })
    }
}

/// Probe, F1 scene-sample, plan, and decode from the same immutable snapshot.
/// Provider/audit gates belong to the caller and must run before this function.
pub(crate) async fn decode_observed_visual_video_frames(
    asset: &Asset,
    provider_cap: usize,
) -> Result<VisualVideoFrameBatch, ExtractionError> {
    // Caller cancellation must not drop the snapshot while a detached child
    // still owns a path to it. This task retains the permit and snapshot until
    // every probe/decode child has completed and removal is explicitly proven.
    let asset = asset.clone();
    tokio::spawn(async move {
        let snapshot = VisualVideoSnapshot::create(&asset).await?;
        let result = async {
            let duration_ms = snapshot.duration_ms().await?;
            let observed_frames_ms = snapshot.observed_frame_timestamps_ms(duration_ms).await?;
            let scenes_ms = snapshot.scene_timestamps_ms(duration_ms).await?;
            let timestamps_ms = plan_observed_video_frame_timestamps(
                &VISUAL_SCENE_CHANGE,
                duration_ms,
                &observed_frames_ms.keyframes_ms,
                &scenes_ms,
                &observed_frames_ms.frames_ms,
                provider_cap,
            );
            if timestamps_ms.is_empty() {
                return Err(ExtractionError::Backend {
                    backend: "video",
                    reason: "visual video sampling produced no frame timestamps".into(),
                });
            }
            let decoder = FfmpegFrameDecoder::new();
            let frames = decoder
                .decode_snapshot_with_perceptual_signatures(
                    snapshot.path(),
                    &snapshot.permit,
                    &timestamps_ms,
                    FrameFormat::Jpeg,
                )
                .await?;
            Ok(VisualVideoFrameBatch {
                timestamps_ms,
                #[cfg(all(test, target_os = "linux"))]
                scene_timestamps_ms: scenes_ms,
                frames,
            })
        }
        .await;
        snapshot.close()?;
        result
    })
    .await
    .map_err(|error| ExtractionError::Backend {
        backend: "video",
        reason: format!("visual video supervisor failed: {error}"),
    })?
}

fn parse_duration_ms(stdout: &[u8]) -> Result<u64, ExtractionError> {
    let duration = std::str::from_utf8(stdout)
        .map_err(|error| ExtractionError::Backend {
            backend: "video",
            reason: format!("ffprobe duration was not UTF-8: {error}"),
        })?
        .trim()
        .parse::<f64>()
        .map_err(|error| ExtractionError::Backend {
            backend: "video",
            reason: format!("ffprobe did not return a numeric duration: {error}"),
        })?;
    timestamp_seconds_to_ms(duration, "duration")
}

fn parse_observed_frame_timestamps_ms(
    stdout: &[u8],
    duration_ms: u64,
) -> Result<ObservedFrameTimestamps, ExtractionError> {
    #[derive(serde::Deserialize)]
    struct FfprobeFrames {
        frames: Vec<FfprobeFrame>,
    }
    #[derive(serde::Deserialize)]
    struct FfprobeFrame {
        key_frame: u8,
        best_effort_timestamp_time: String,
    }

    let parsed: FfprobeFrames = serde_json::from_slice(stdout).map_err(|error| {
        ExtractionError::Backend {
            backend: "video",
            reason: format!("ffprobe keyframe JSON is malformed or lacks required fields: {error}"),
        }
    })?;
    let mut keyframes_ms = Vec::new();
    let mut frames_ms = Vec::with_capacity(parsed.frames.len());
    for frame in parsed.frames {
        if !matches!(frame.key_frame, 0 | 1) {
            return Err(ExtractionError::Backend {
                backend: "video",
                reason: "ffprobe keyframe flag must be 0 or 1".into(),
            });
        }
        let timestamp_ms = checked_timestamp_ms(
            &frame.best_effort_timestamp_time,
            duration_ms,
            "frame",
        )?;
        frames_ms.push(timestamp_ms);
        if frame.key_frame == 1 {
            keyframes_ms.push(timestamp_ms);
        }
    }
    verify_strict_timestamp_order(&frames_ms, "frame")?;
    verify_strict_timestamp_order(&keyframes_ms, "keyframe")?;
    Ok(ObservedFrameTimestamps {
        keyframes_ms,
        frames_ms,
    })
}

fn parse_scene_timestamps_ms(
    stderr: &[u8],
    duration_ms: u64,
) -> Result<Vec<u64>, ExtractionError> {
    let text = std::str::from_utf8(stderr).map_err(|error| ExtractionError::Backend {
        backend: "video",
        reason: format!("ffmpeg showinfo output was not UTF-8: {error}"),
    })?;
    let mut timestamps = Vec::new();
    for fragment in text.split("pts_time:").skip(1) {
        let value = fragment.split_whitespace().next().unwrap_or_default();
        timestamps.push(checked_timestamp_ms(value, duration_ms, "scene timestamp")?);
    }
    verify_strict_timestamp_order(&timestamps, "scene")?;
    Ok(timestamps)
}

fn checked_timestamp_ms(
    seconds: &str,
    duration_ms: u64,
    label: &str,
) -> Result<u64, ExtractionError> {
    let timestamp = seconds.parse::<f64>().map_err(|error| ExtractionError::Backend {
        backend: "video",
        reason: format!("{label} timestamp is not numeric: {error}"),
    })?;
    let milliseconds = timestamp_seconds_to_ms(timestamp, label)?;
    if milliseconds >= duration_ms {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("{label} timestamp is not before probed video duration"),
        });
    }
    Ok(milliseconds)
}

fn timestamp_seconds_to_ms(seconds: f64, label: &str) -> Result<u64, ExtractionError> {
    let milliseconds = seconds * 1_000.0;
    if !seconds.is_finite()
        || seconds < 0.0
        || !milliseconds.is_finite()
        || milliseconds > u64::MAX as f64
    {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("ffprobe {label} must be finite and non-negative"),
        });
    }
    let milliseconds = milliseconds.round() as u64;
    if milliseconds == 0 && label == "duration" {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: "ffprobe duration must be greater than zero".into(),
        });
    }
    Ok(milliseconds)
}

fn verify_strict_timestamp_order(timestamps: &[u64], label: &str) -> Result<(), ExtractionError> {
    if timestamps.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("ffprobe/ffmpeg {label} timestamps are not strictly ordered"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_requires_a_real_finite_positive_value() {
        assert_eq!(parse_duration_ms(b"12.345\n").unwrap(), 12_345);
        assert!(parse_duration_ms(b"N/A\n").is_err());
        assert!(parse_duration_ms(b"-1\n").is_err());
        assert!(parse_duration_ms(b"0\n").is_err());
    }

    #[test]
    fn keyframe_probe_accepts_codec_side_data_but_requires_frame_fields() {
        let observed = parse_observed_frame_timestamps_ms(
            br#"{
                "frames": [
                    {"key_frame": 0, "best_effort_timestamp_time": "0.000"},
                    {
                        "key_frame": 1,
                        "best_effort_timestamp_time": "1.250",
                        "side_data_list": [{"side_data_type": "H.264 User Data Unregistered SEI message"}]
                    },
                    {"key_frame": 0, "best_effort_timestamp_time": "2.000"},
                    {"key_frame": 1, "best_effort_timestamp_time": "9.999"}
                ]
            }"#,
            10_000,
        )
        .unwrap();
        assert_eq!(observed.keyframes_ms, vec![1_250, 9_999]);
        assert_eq!(observed.frames_ms, vec![0, 1_250, 2_000, 9_999]);
        assert!(parse_observed_frame_timestamps_ms(
            br#"{"frames":[
                {"key_frame":1,"best_effort_timestamp_time":"2.000"},
                {"key_frame":1,"best_effort_timestamp_time":"1.000"}
            ]}"#,
            3_000,
        )
        .is_err());
        assert!(parse_observed_frame_timestamps_ms(br#"{"frames":[{"key_frame":1}]}"#, 3_000)
            .is_err());
    }

    #[test]
    fn showinfo_pts_time_parser_rejects_malformed_or_out_of_range_values() {
        let stderr = b"[Parsed_showinfo_1] pts: 5 pts_time:0.005 foo\n\
            [Parsed_showinfo_1] pts: 10 pts_time:2.500 foo\n";
        assert_eq!(parse_scene_timestamps_ms(stderr, 3_000).unwrap(), vec![5, 2_500]);
        assert!(parse_scene_timestamps_ms(b"pts_time:N/A\n", 3_000).is_err());
        assert!(parse_scene_timestamps_ms(b"pts_time:4.000\n", 3_000).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn hosted_silent_video_runs_probe_scene_decode_and_mock_synthesis() {
        use crate::media::multimodal_synth::MultimodalSynthesizer;
        use crate::media::video_dispatch::dispatch_predecoded_video_analysis;
        use crate::media::video_frames::MultimodalProvider;

        struct MockSynth;
        #[async_trait::async_trait]
        impl MultimodalSynthesizer for MockSynth {
            fn provider(&self) -> MultimodalProvider {
                MultimodalProvider::OpenAiGpt4o
            }

            async fn synthesize(
                &self,
                request: &crate::media::video_frames::MultimodalRequest,
            ) -> Result<String, String> {
                if request.frames.len() < 2
                    || !request
                        .frames
                        .windows(2)
                        .any(|pair| pair[0].pixels != pair[1].pixels)
                {
                    return Err("mock synthesis did not receive distinct scene frames".into());
                }
                Ok("silent visual analysis".into())
            }
        }

        let dir = tempfile::tempdir().expect("create hosted video fixture directory");
        let path = dir.path().join("silent.mp4");
        let status = std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "color=c=black:s=32x32:r=10:d=1,drawbox=x=0:y=0:w=iw:h=ih:color=white:t=fill:enable='gte(t,0.5)'",
                "-an",
                "-c:v",
                "libx264",
                "-g",
                "100",
                "-keyint_min",
                "100",
                "-threads",
                "1",
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&path)
            .status()
            .expect("hosted Linux W174 lane requires ffmpeg");
        assert!(status.success(), "ffmpeg fixture generation must succeed");

        let codec_probe = std::process::Command::new("ffprobe")
            .args(["-v", "error", "-select_streams", "v:0", "-show_frames", "-of", "json"])
            .arg(&path)
            .output()
            .expect("hosted Linux W174 lane requires ffprobe");
        assert!(codec_probe.status.success(), "ffprobe fixture inspection must succeed");
        let codec_json = String::from_utf8(codec_probe.stdout)
            .expect("ffprobe JSON fixture output must be UTF-8");
        assert!(
            codec_json.contains("side_data_list"),
            "libx264 fixture must expose actual codec side-data"
        );
        let actual_codec_observation =
            parse_observed_frame_timestamps_ms(codec_json.as_bytes(), 1_000)
                .expect("structured parser must accept actual codec side-data");
        assert!(!actual_codec_observation.frames_ms.is_empty());

        let asset = Asset::Path {
            kind: crate::media::AssetKind::Video,
            mime: "video/mp4".into(),
            path,
        };
        let batch = decode_observed_visual_video_frames(&asset, 10)
            .await
            .expect("silent video must reach real probe, scene sampling, and decode");
        assert!(
            !batch.scene_timestamps_ms.is_empty(),
            "black-to-white transition must produce real showinfo pts_time evidence"
        );
        assert_eq!(batch.timestamps_ms.len(), 8);
        assert_eq!(batch.frames.len(), 8);
        assert!(batch
            .timestamps_ms
            .iter()
            .all(|timestamp| *timestamp < 1_000));

        let media_cfg = crate::config::MediaConfig {
            video_frame_upload_enabled: true,
            ..Default::default()
        };
        let answer = dispatch_predecoded_video_analysis(
            &MockSynth,
            batch.frames,
            "describe frames",
            64,
            None,
            None,
            &media_cfg,
        )
        .await
        .expect("mock visual synthesis must receive decoded silent-video frames");
        assert_eq!(answer, "silent visual analysis");
    }
}
