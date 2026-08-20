//! Video backend — R-9 Phase 2.
//!
//! Strategy: spawn `ffmpeg` as a subprocess to extract the audio track,
//! re-encode it to 16 kHz mono WAV, then route the bounded WAV snapshot
//! through the [`audio::AudioExtractor`]. Avoids re-implementing
//! container parsing while staying self-contained from NEOTH's
//! perspective — `ffmpeg` is on PATH for any operator who already
//! handles video files, and the wizard's installer step can prompt
//! for it (R-9 Phase 3).
//!
//! Path-vs-bytes:
//!   - Both forms are snapshotted into a private bounded tempfile before
//!     ffmpeg runs. Path assets are opened no-follow and copied from the same
//!     verified regular-file handle so ffmpeg never receives an ambient,
//!     mutable operator path.
//!
//! Future: native demux via `symphonia` once it gains a full MP4 reader
//! + chunked audio extraction without ffmpeg.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor, audio};

const VIDEO_AUDIO_DURATION_SECS: u64 = 10 * 60;
const VIDEO_AUDIO_BYTES_PER_SECOND: u64 =
    audio::TARGET_SAMPLE_RATE as u64 * size_of::<i16>() as u64;
const VIDEO_AUDIO_WAV_HEADER_ALLOWANCE_BYTES: u64 = 64 * 1024;
const AUDIO_MAX_OUTPUT_BYTES: u64 = VIDEO_AUDIO_DURATION_SECS * VIDEO_AUDIO_BYTES_PER_SECOND
    + VIDEO_AUDIO_WAV_HEADER_ALLOWANCE_BYTES;
const AUDIO_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_VIDEO_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const THUMBNAIL_MAX_DIMENSION: u32 = 1280;
const THUMBNAIL_MAX_DURATION_SECS: u64 = 1;
const THUMBNAIL_MAX_FRAMES: u32 = 1;
const THUMBNAIL_MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const THUMBNAIL_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STDERR_BYTES: usize = 16 * 1024;
const CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const VIDEO_WORKER_CONCURRENCY: usize = 1;
const MAX_VIDEO_PATH_UNITS: usize = 32 * 1024;
const _: () = assert!(AUDIO_MAX_OUTPUT_BYTES <= audio::MAX_AUDIO_BYTES);

static VIDEO_WORKER_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(VIDEO_WORKER_CONCURRENCY);
static VIDEO_WORKER_BUDGET_POISONED: AtomicBool = AtomicBool::new(false);

/// Proof that one request owns the process-wide video/ffmpeg budget.
///
/// The lock order is deliberately `video -> audio`: a complete video turn
/// keeps this token while the extracted WAV enters [`audio::AudioExtractor`].
/// Audio code must never call a video entry point while it holds its own
/// permit, otherwise the two single-permit budgets could deadlock.
struct VideoWorkLease {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

#[derive(Clone)]
struct VideoWorkPermit {
    _lease: std::sync::Arc<VideoWorkLease>,
}

/// A caller-owned reservation of the global video worker. Auxiliary ffmpeg
/// batches acquire this before snapshotting untrusted input and retain it until
/// every child and private-file cleanup has completed.
pub(crate) struct AuxiliaryVideoWorkPermit(VideoWorkPermit);

async fn acquire_video_work_permit() -> Result<VideoWorkPermit, ExtractionError> {
    if VIDEO_WORKER_BUDGET_POISONED.load(Ordering::Acquire) {
        return Err(video_budget_poisoned_error());
    }
    let permit = VIDEO_WORKER_BUDGET
        .acquire()
        .await
        .map_err(|_| ExtractionError::Backend {
            backend: "video",
            reason: "global video worker budget is closed".into(),
        })?;
    if VIDEO_WORKER_BUDGET_POISONED.load(Ordering::Acquire) {
        drop(permit);
        return Err(video_budget_poisoned_error());
    }
    Ok(VideoWorkPermit {
        _lease: std::sync::Arc::new(VideoWorkLease { _permit: permit }),
    })
}

pub(crate) async fn acquire_auxiliary_video_work_permit(
) -> Result<AuxiliaryVideoWorkPermit, ExtractionError> {
    Ok(AuxiliaryVideoWorkPermit(acquire_video_work_permit().await?))
}

fn video_budget_poisoned_error() -> ExtractionError {
    ExtractionError::Backend {
        backend: "video",
        reason: "video worker budget is fail-closed because a prior detached request did not prove private-media cleanup".into(),
    }
}

/// Permanently reject further video work after a private-media cleanup failure.
/// A caller that cannot prove its snapshot was removed must never allow a new
/// ffmpeg child to accumulate alongside it.
pub(crate) fn poison_video_worker_budget_after_private_cleanup_failure() {
    VIDEO_WORKER_BUDGET_POISONED.store(true, Ordering::Release);
    VIDEO_WORKER_BUDGET.close();
    tracing::error!("video worker budget closed after private input cleanup failure");
}

enum OwnedVideoInput {
    Bytes(Vec<u8>),
    Path(std::path::PathBuf),
}

fn own_video_input(asset: &Asset) -> Result<OwnedVideoInput, ExtractionError> {
    match asset {
        Asset::Bytes { data, .. } => {
            enforce_video_input_cap(data.len() as u64, MAX_VIDEO_INPUT_BYTES)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(data.len())
                .map_err(|error| ExtractionError::Backend {
                    backend: "video",
                    reason: format!("reserve bounded video input snapshot: {error}"),
                })?;
            owned.extend_from_slice(data);
            Ok(OwnedVideoInput::Bytes(owned))
        }
        Asset::Path { path, .. } => {
            let source = path.as_os_str();
            if source.len() > MAX_VIDEO_PATH_UNITS {
                return Err(ExtractionError::Backend {
                    backend: "video",
                    reason: format!(
                        "video input path exceeds the {MAX_VIDEO_PATH_UNITS}-unit ceiling"
                    ),
                });
            }
            let mut owned = OsString::new();
            owned
                .try_reserve_exact(source.len())
                .map_err(|error| ExtractionError::Backend {
                    backend: "video",
                    reason: format!("reserve bounded video input path: {error}"),
                })?;
            owned.push(source);
            Ok(OwnedVideoInput::Path(owned.into()))
        }
    }
}

struct VideoRequestLease {
    permit: Option<VideoWorkPermit>,
    armed: bool,
}

impl VideoRequestLease {
    fn new(permit: VideoWorkPermit) -> Self {
        Self {
            permit: Some(permit),
            armed: true,
        }
    }

    fn permit(&self) -> &VideoWorkPermit {
        self.permit
            .as_ref()
            .expect("armed video request owns its work permit")
    }

    fn release_after_verified_cleanup(mut self) {
        self.armed = false;
        self.permit.take();
    }
}

impl Drop for VideoRequestLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        VIDEO_WORKER_BUDGET_POISONED.store(true, Ordering::Release);
        if let Some(permit) = self.permit.take() {
            std::mem::forget(permit);
        }
        tracing::error!(
            "video request ended without proving private snapshot cleanup; video budget is now fail-closed"
        );
    }
}

pub struct VideoExtractor;

impl VideoExtractor {
    /// Writer- and policy-aware video extraction. The extracted audio track
    /// must retain the caller's effective STT/download policy and WAL sink.
    pub(crate) async fn extract_with_context(
        &self,
        asset: &Asset,
        media_cfg: &crate::config::MediaConfig,
        updater_cfg: &crate::config::UpdaterConfig,
        neoth_home: &std::path::Path,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Video {
            return Err(ExtractionError::Unsupported {
                backend: "video",
                got: asset.kind(),
            });
        }
        // Acquire before the one bounded ownership copy, then detach the
        // complete request lifecycle. Dropping the caller's JoinHandle does not
        // cancel the supervisor: its video permit, input/WAV snapshots, ffmpeg
        // children and nested audio/STT worker remain owned until explicit
        // cleanup succeeds.
        let video_permit = acquire_video_work_permit().await?;
        let input = own_video_input(asset)?;
        let media_cfg = media_cfg.clone();
        let updater_cfg = updater_cfg.clone();
        let neoth_home = neoth_home.to_path_buf();
        tokio::spawn(run_owned_video_pipeline(
            input,
            video_permit,
            media_cfg,
            updater_cfg,
            neoth_home,
            wal_writer,
        ))
        .await
        .map_err(|error| ExtractionError::Backend {
            backend: "video",
            reason: format!("video supervisor task failed: {error}"),
        })?
    }
}

async fn run_owned_video_pipeline(
    input: OwnedVideoInput,
    permit: VideoWorkPermit,
    media_cfg: crate::config::MediaConfig,
    updater_cfg: crate::config::UpdaterConfig,
    neoth_home: std::path::PathBuf,
    wal_writer: Option<crate::wal::writer::WalWriterHandle>,
) -> Result<Extraction, ExtractionError> {
    let input_snapshot = snapshot_owned_private_input_async(input, ".neoth-video-").await?;
    // Snapshot admission failures happen before any subprocess exists and do
    // not poison the global worker budget. From this point on, however, every
    // exit must prove both child termination and private-file cleanup.
    let lease = VideoRequestLease::new(permit);
    let mut wav_snapshot = None;

    let pipeline_result = async {
        // 1. Extract audio track as 16 kHz mono WAV via ffmpeg. Stdout is
        // streamed under a max+1 cap into a private tempfile.
        wav_snapshot = Some(run_ffmpeg_audio(input_snapshot.path(), lease.permit()).await?);
        let wav_path = wav_snapshot
            .as_ref()
            .expect("successful ffmpeg extraction produced a WAV guard")
            .path()
            .to_path_buf();

        // 2. Keep both snapshot guards and the video lease while the audio
        // backend's detached blocking STT worker reaches its terminal result.
        let audio_asset = Asset::Path {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            path: wav_path,
        };
        let audio_out = audio::AudioExtractor
            .extract_with_context(
                &audio_asset,
                &media_cfg,
                &updater_cfg,
                &neoth_home,
                wal_writer.clone(),
            )
            .await?;
        let mut metadata = audio_out.metadata;

        let thumbnail = match run_ffmpeg_thumbnail(input_snapshot.path(), lease.permit()).await {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                tracing::debug!(
                    error = %error,
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
    .await;

    let wav_cleanup_error = wav_snapshot.and_then(|temp| close_video_temp(temp, "audio WAV").err());
    let input_cleanup_error = close_video_temp(input_snapshot, "input snapshot").err();
    let cleanup_error = wav_cleanup_error.or(input_cleanup_error);

    if let Some(cleanup_error) = cleanup_error {
        return match pipeline_result {
            Ok(_) => Err(cleanup_error),
            Err(pipeline_error) => Err(ExtractionError::Backend {
                backend: "video",
                reason: format!(
                    "video pipeline failed: {pipeline_error}; private cleanup also failed: {cleanup_error}"
                ),
            }),
        };
    }
    lease.release_after_verified_cleanup();
    pipeline_result
}

fn close_video_temp(temp: tempfile::NamedTempFile, label: &str) -> Result<(), ExtractionError> {
    temp.close()
        .map_err(|error| ExtractionError::Io(format!("remove private video {label}: {error}")))
}

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
        let config = crate::config::FreedomConfig::load_from_default_path().map_err(|error| {
            ExtractionError::Backend {
                backend: "video",
                reason: format!("load effective STT config: {error}"),
            }
        })?;
        self.extract_with_context(
            asset,
            &config.media,
            &config.updater,
            &crate::config::FreedomConfig::default_neoth_home(),
            None,
        )
        .await
    }
}

async fn run_ffmpeg_thumbnail(
    input: &Path,
    permit: &VideoWorkPermit,
) -> Result<Vec<u8>, ExtractionError> {
    let mut command = Command::new("ffmpeg");
    command.args(thumbnail_ffmpeg_args(input));
    run_child_bounded(
        command,
        ChildLimits {
            operation: "thumbnail",
            timeout: THUMBNAIL_SUBPROCESS_TIMEOUT,
            max_stdout_bytes: THUMBNAIL_MAX_OUTPUT_BYTES,
            missing_binary_reason: "ffmpeg binary not found on PATH (thumbnail extract)",
        },
        permit,
    )
    .await
}

async fn run_ffmpeg_audio(
    input: &Path,
    permit: &VideoWorkPermit,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    // The ffmpeg-side PCM format is fixed and the Rust-side max+1 writer
    // streams stdout into a private WAV tempfile. Output beyond the downstream
    // 10-minute AudioExtractor contract is rejected, never truncated.
    let mut command = Command::new("ffmpeg");
    command.args(audio_ffmpeg_args(input));
    let output = new_private_temp_output(".neoth-video-audio-", ".wav")?;
    run_child_to_temp_bounded(
        command,
        ChildLimits {
            operation: "audio",
            timeout: AUDIO_SUBPROCESS_TIMEOUT,
            max_stdout_bytes: AUDIO_MAX_OUTPUT_BYTES,
            missing_binary_reason: "ffmpeg binary not found on PATH. Install ffmpeg and re-run.",
        },
        output,
        permit,
    )
    .await
}

async fn snapshot_owned_private_input_async(
    input: OwnedVideoInput,
    prefix: &'static str,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    match input {
        OwnedVideoInput::Bytes(data) => {
            let temp = new_private_temp_input(prefix)?;
            let file = temp
                .as_file()
                .try_clone()
                .map_err(|error| ExtractionError::Io(format!("clone video tempfile: {error}")))?;
            let mut output = tokio::fs::File::from_std(file);
            output
                .write_all(&data)
                .await
                .map_err(|error| ExtractionError::Io(format!("write video tempfile: {error}")))?;
            output
                .flush()
                .await
                .map_err(|error| ExtractionError::Io(format!("flush video tempfile: {error}")))?;
            drop(output);
            Ok(temp)
        }
        OwnedVideoInput::Path(path) => tokio::task::spawn_blocking(move || {
            snapshot_path_with_limit(&path, prefix, MAX_VIDEO_INPUT_BYTES)
        })
        .await
        .map_err(|error| ExtractionError::Backend {
            backend: "video",
            reason: format!("input snapshot task failed: {error}"),
        })?,
    }
}

/// Take one bounded, no-follow private snapshot for auxiliary ffmpeg consumers.
///
/// The returned guard must outlive every child that uses its path. This makes
/// multiple ffmpeg passes observe the same immutable video bytes rather than
/// reopening an ambient path between passes.
pub(crate) async fn snapshot_video_input_for_auxiliary_ffmpeg(
    asset: &Asset,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    snapshot_owned_private_input_async(own_video_input(asset)?, ".neoth-video-frame-").await
}

#[cfg(test)]
fn write_private_temp_input_with_limit(
    data: &[u8],
    prefix: &str,
    max_bytes: u64,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    enforce_video_input_cap(data.len() as u64, max_bytes)?;
    let mut temp = new_private_temp_input(prefix)?;
    temp.as_file_mut()
        .write_all(data)
        .and_then(|()| temp.as_file_mut().flush())
        .map_err(|error| ExtractionError::Io(format!("write video tempfile: {error}")))?;
    Ok(temp)
}

fn snapshot_path_with_limit(
    path: &Path,
    prefix: &str,
    max_bytes: u64,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    let mut input = open_video_input_no_follow(path)
        .map_err(|error| ExtractionError::Io(format!("open video input: {error}")))?;
    let before = input
        .metadata()
        .map_err(|error| ExtractionError::Io(format!("inspect video input: {error}")))?;
    if !before.is_file() || video_metadata_is_link_like(&before) {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: "video input must be a regular non-link file".into(),
        });
    }
    enforce_video_input_cap(before.len(), max_bytes)?;
    let before_modified = before.modified().ok();

    let mut temp = new_private_temp_input(prefix)?;
    let read_cap = max_bytes.saturating_add(1);
    let copied = std::io::copy(&mut Read::take(&mut input, read_cap), temp.as_file_mut())
        .map_err(|error| ExtractionError::Io(format!("snapshot video input: {error}")))?;
    enforce_video_input_cap(copied, max_bytes)?;

    let after = input
        .metadata()
        .map_err(|error| ExtractionError::Io(format!("re-inspect video input: {error}")))?;
    if before.len() != after.len()
        || before_modified != after.modified().ok()
        || copied != before.len()
    {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: "video input changed while it was being snapshotted".into(),
        });
    }
    temp.as_file_mut()
        .flush()
        .map_err(|error| ExtractionError::Io(format!("flush video tempfile: {error}")))?;
    Ok(temp)
}

fn open_video_input_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn video_metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn new_private_temp_input(prefix: &str) -> Result<tempfile::NamedTempFile, ExtractionError> {
    new_private_temp_output(prefix, ".bin")
}

fn new_private_temp_output(
    prefix: &str,
    suffix: &str,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    crate::util::private_temp::named_file(prefix, suffix)
        .map_err(|error| ExtractionError::Io(format!("create private video tempfile: {error}")))
}

fn enforce_video_input_cap(len: u64, max_bytes: u64) -> Result<(), ExtractionError> {
    if len > max_bytes {
        return Err(ExtractionError::Backend {
            backend: "video",
            reason: format!("video input exceeds the {max_bytes}-byte limit"),
        });
    }
    Ok(())
}

fn common_ffmpeg_args(input: &Path) -> Vec<OsString> {
    vec![
        "-hide_banner".into(),
        "-nostdin".into(),
        "-nostats".into(),
        "-loglevel".into(),
        "error".into(),
        "-i".into(),
        input.as_os_str().to_owned(),
    ]
}

fn audio_ffmpeg_args(input: &Path) -> Vec<OsString> {
    let mut args = common_ffmpeg_args(input);
    args.extend([
        "-map".into(),
        "0:a:0".into(),
        "-vn".into(),
        "-ac".into(),
        "1".into(),
        "-ar".into(),
        audio::TARGET_SAMPLE_RATE.to_string().into(),
        "-c:a".into(),
        "pcm_s16le".into(),
        "-threads".into(),
        "1".into(),
        "-f".into(),
        "wav".into(),
        "pipe:1".into(),
    ]);
    args
}

fn thumbnail_ffmpeg_args(input: &Path) -> Vec<OsString> {
    let mut args = vec![
        "-hide_banner".into(),
        "-nostdin".into(),
        "-nostats".into(),
        "-loglevel".into(),
        "error".into(),
        "-ss".into(),
        "0".into(),
        "-i".into(),
        input.as_os_str().to_owned(),
    ];
    args.extend([
        "-map".into(),
        "0:v:0".into(),
        "-an".into(),
        "-t".into(),
        THUMBNAIL_MAX_DURATION_SECS.to_string().into(),
        "-frames:v".into(),
        THUMBNAIL_MAX_FRAMES.to_string().into(),
        "-vf".into(),
        format!(
            "scale='min({THUMBNAIL_MAX_DIMENSION},iw)':\
             'min({THUMBNAIL_MAX_DIMENSION},ih)':force_original_aspect_ratio=decrease"
        )
        .into(),
        "-threads".into(),
        "1".into(),
        "-f".into(),
        "image2pipe".into(),
        "-vcodec".into(),
        "mjpeg".into(),
        "-q:v".into(),
        "3".into(),
        "pipe:1".into(),
    ]);
    args
}

#[derive(Clone, Copy)]
struct ChildLimits {
    operation: &'static str,
    timeout: Duration,
    max_stdout_bytes: u64,
    missing_binary_reason: &'static str,
}

#[derive(Debug)]
struct CappedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

struct CapturedStdout<T> {
    output: T,
    bytes_written: u64,
    truncated: bool,
}

#[derive(Debug)]
enum ChildRunError {
    Stdout(std::io::Error),
    Wait(std::io::Error),
    OutputTooLarge,
}

async fn run_child_bounded(
    command: Command,
    limits: ChildLimits,
    permit: &VideoWorkPermit,
) -> Result<Vec<u8>, ExtractionError> {
    run_child_bounded_with(command, limits, permit.clone(), |stdout, max_bytes| {
        read_max_plus_one(stdout, max_bytes)
    })
    .await
}

/// Run an auxiliary ffmpeg operation through the owned video supervisor.
///
/// Callers outside this module must not create a competing child lifecycle:
/// this retains the process-wide one-worker bound and its fail-closed cleanup
/// rule when a child cannot be proven reaped.
pub(crate) async fn run_auxiliary_ffmpeg_bounded(
    command: Command,
    operation: &'static str,
    timeout: Duration,
    max_stdout_bytes: u64,
    missing_binary_reason: &'static str,
) -> Result<Vec<u8>, ExtractionError> {
    let permit = acquire_auxiliary_video_work_permit().await?;
    run_auxiliary_ffmpeg_bounded_with_permit(
        command,
        operation,
        timeout,
        max_stdout_bytes,
        missing_binary_reason,
        &permit,
    )
    .await
}

/// Run one child under a caller-held auxiliary video reservation. The caller
/// must retain `permit` through every related child and private snapshot.
pub(crate) async fn run_auxiliary_ffmpeg_bounded_with_permit(
    command: Command,
    operation: &'static str,
    timeout: Duration,
    max_stdout_bytes: u64,
    missing_binary_reason: &'static str,
    permit: &AuxiliaryVideoWorkPermit,
) -> Result<Vec<u8>, ExtractionError> {
    run_child_bounded(
        command,
        ChildLimits {
            operation,
            timeout,
            max_stdout_bytes,
            missing_binary_reason,
        },
        &permit.0,
    )
    .await
}

async fn run_child_to_temp_bounded(
    command: Command,
    limits: ChildLimits,
    output: tempfile::NamedTempFile,
    permit: &VideoWorkPermit,
) -> Result<tempfile::NamedTempFile, ExtractionError> {
    run_child_bounded_with(command, limits, permit.clone(), move |stdout, max_bytes| {
        write_max_plus_one_to_temp(stdout, output, max_bytes)
    })
    .await
}

async fn run_child_bounded_with<T, F, Fut>(
    command: Command,
    limits: ChildLimits,
    permit: VideoWorkPermit,
    capture_stdout: F,
) -> Result<T, ExtractionError>
where
    T: Send + 'static,
    F: FnOnce(tokio::process::ChildStdout, u64) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = std::io::Result<CapturedStdout<T>>> + Send + 'static,
{
    tokio::spawn(run_child_supervised(
        command,
        limits,
        permit,
        capture_stdout,
    ))
    .await
    .map_err(|error| ExtractionError::Backend {
        backend: "video",
        reason: format!("ffmpeg supervisor task failed: {error}"),
    })?
}

async fn run_child_supervised<T, F, Fut>(
    mut command: Command,
    limits: ChildLimits,
    _permit: VideoWorkPermit,
    capture_stdout: F,
) -> Result<T, ExtractionError>
where
    F: FnOnce(tokio::process::ChildStdout, u64) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<CapturedStdout<T>>>,
{
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| {
        if matches!(error.kind(), std::io::ErrorKind::NotFound) {
            ExtractionError::Backend {
                backend: "video",
                reason: limits.missing_binary_reason.into(),
            }
        } else {
            ExtractionError::Io(format!(
                "spawn ffmpeg ({} extraction): {error}",
                limits.operation
            ))
        }
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExtractionError::Io("ffmpeg stdout pipe unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExtractionError::Io("ffmpeg stderr pipe unavailable".into()))?;
    let stderr_task = tokio::spawn(drain_to_eof_capped(stderr, MAX_STDERR_BYTES));

    let run_result = tokio::time::timeout(limits.timeout, async {
        let output = capture_stdout(stdout, limits.max_stdout_bytes)
            .await
            .map_err(ChildRunError::Stdout)?;
        if output.truncated {
            return Err(ChildRunError::OutputTooLarge);
        }
        let status = child.wait().await.map_err(ChildRunError::Wait)?;
        Ok((status, output))
    })
    .await;

    match run_result {
        Err(_) => {
            if let Err(error) = terminate_child_fail_closed(&mut child, limits.operation).await {
                stderr_task.abort();
                let _ = stderr_task.await;
                return Err(error);
            }
            let stderr = collect_stderr(stderr_task).await?;
            let detail = sanitized_stderr_detail(&stderr);
            Err(ExtractionError::Backend {
                backend: "video",
                reason: format!(
                    "ffmpeg {} extraction timed out after {}s{}",
                    limits.operation,
                    limits.timeout.as_secs(),
                    detail
                ),
            })
        }
        Ok(Err(ChildRunError::OutputTooLarge)) => {
            if let Err(error) = terminate_child_fail_closed(&mut child, limits.operation).await {
                stderr_task.abort();
                let _ = stderr_task.await;
                return Err(error);
            }
            let _ = collect_stderr(stderr_task).await?;
            Err(ExtractionError::Backend {
                backend: "video",
                reason: format!(
                    "ffmpeg {} output exceeds the {}-byte limit",
                    limits.operation, limits.max_stdout_bytes
                ),
            })
        }
        Ok(Err(ChildRunError::Stdout(error))) => {
            if let Err(cleanup_error) =
                terminate_child_fail_closed(&mut child, limits.operation).await
            {
                stderr_task.abort();
                let _ = stderr_task.await;
                return Err(cleanup_error);
            }
            let _ = collect_stderr(stderr_task).await?;
            Err(ExtractionError::Io(format!(
                "read ffmpeg {} stdout: {error}",
                limits.operation
            )))
        }
        Ok(Err(ChildRunError::Wait(error))) => {
            if let Err(cleanup_error) =
                terminate_child_fail_closed(&mut child, limits.operation).await
            {
                stderr_task.abort();
                let _ = stderr_task.await;
                return Err(cleanup_error);
            }
            let _ = collect_stderr(stderr_task).await?;
            Err(ExtractionError::Io(format!(
                "wait for ffmpeg {} extraction: {error}",
                limits.operation
            )))
        }
        Ok(Ok((status, output))) => {
            let stderr = collect_stderr(stderr_task).await?;
            if !status.success() {
                return Err(ExtractionError::Backend {
                    backend: "video",
                    reason: format!(
                        "ffmpeg {} extraction exited with status {}{}",
                        limits.operation,
                        status,
                        sanitized_stderr_detail(&stderr)
                    ),
                });
            }
            if output.bytes_written == 0 {
                return Err(ExtractionError::Backend {
                    backend: "video",
                    reason: format!("ffmpeg {} extraction produced no output", limits.operation),
                });
            }
            Ok(output.output)
        }
    }
}

async fn terminate_child_fail_closed(
    child: &mut tokio::process::Child,
    operation: &str,
) -> Result<(), ExtractionError> {
    kill_and_reap(child).await.map_err(|error| {
        // A child whose exit cannot be proven must never be followed by a new
        // ffmpeg request. Closing the semaphore wakes queued callers with an
        // error and prevents orphan accumulation even after this lease drops.
        poison_video_worker_budget_after_private_cleanup_failure();
        ExtractionError::Backend {
            backend: "video",
            reason: format!(
                "ffmpeg {operation} cleanup failed; video worker budget closed fail-closed: {error}"
            ),
        }
    })
}

async fn kill_and_reap(child: &mut tokio::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Err(kill_error) = child.start_kill() {
        // The process may have exited between try_wait and start_kill.
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        return Err(kill_error);
    }
    match tokio::time::timeout(CHILD_REAP_TIMEOUT, child.wait()).await {
        Ok(Ok(_status)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "child did not exit and reap within {}s",
                CHILD_REAP_TIMEOUT.as_secs()
            ),
        )),
    }
}

async fn read_max_plus_one<R>(reader: R, max_bytes: u64) -> std::io::Result<CapturedStdout<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut reader = reader.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity((max_bytes.min(64 * 1024)) as usize);
    reader.read_to_end(&mut bytes).await?;
    let truncated = bytes.len() as u64 > max_bytes;
    if truncated {
        bytes.truncate(max_bytes as usize);
    }
    Ok(CapturedStdout {
        bytes_written: bytes.len() as u64,
        output: bytes,
        truncated,
    })
}

async fn write_max_plus_one_to_temp<R>(
    mut reader: R,
    output: tempfile::NamedTempFile,
    max_bytes: u64,
) -> std::io::Result<CapturedStdout<tempfile::NamedTempFile>>
where
    R: AsyncRead + Unpin,
{
    let file = output.as_file().try_clone()?;
    let mut writer = tokio::fs::File::from_std(file);
    let mut bytes_seen = 0u64;
    let mut bytes_written = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let remaining = max_bytes.saturating_add(1).saturating_sub(bytes_seen);
        if remaining == 0 {
            break;
        }
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            std::io::Error::other("buffer-sized ffmpeg read limit does not fit usize")
        })?;
        let read = reader.read(&mut buffer[..read_limit]).await?;
        if read == 0 {
            break;
        }
        bytes_seen = bytes_seen.saturating_add(read as u64);
        let writable = usize::try_from(max_bytes.saturating_sub(bytes_written))
            .unwrap_or(usize::MAX)
            .min(read);
        if writable > 0 {
            writer.write_all(&buffer[..writable]).await?;
            bytes_written = bytes_written.saturating_add(writable as u64);
        }
    }
    writer.flush().await?;
    drop(writer);
    Ok(CapturedStdout {
        output,
        bytes_written,
        truncated: bytes_seen > max_bytes,
    })
}

async fn drain_to_eof_capped<R>(mut reader: R, max_bytes: usize) -> std::io::Result<CappedBytes>
where
    R: AsyncRead + Unpin,
{
    let mut captured = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(captured.len());
        let keep = remaining.min(read);
        captured.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok(CappedBytes {
        bytes: captured,
        truncated,
    })
}

async fn collect_stderr(
    mut task: tokio::task::JoinHandle<std::io::Result<CappedBytes>>,
) -> Result<CappedBytes, ExtractionError> {
    match tokio::time::timeout(CHILD_REAP_TIMEOUT, &mut task).await {
        Ok(result) => result
            .map_err(|error| ExtractionError::Io(format!("join ffmpeg stderr reader: {error}")))?
            .map_err(|error| ExtractionError::Io(format!("read ffmpeg stderr: {error}"))),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(ExtractionError::Io(
                "ffmpeg stderr reader did not close after child exit".into(),
            ))
        }
    }
}

fn sanitized_stderr_detail(stderr: &CappedBytes) -> String {
    let decoded = String::from_utf8_lossy(&stderr.bytes);
    let printable: String = decoded
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let mut compact = printable.split_whitespace().collect::<Vec<_>>().join(" ");
    if stderr.truncated {
        if !compact.is_empty() {
            compact.push(' ');
        }
        compact.push_str("[stderr truncated]");
    }
    if compact.is_empty() {
        String::new()
    } else {
        format!(": {compact}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

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
        let permit = acquire_video_work_permit().await.unwrap();
        let r = run_ffmpeg_audio(Path::new("does-not-exist.mp4"), &permit).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    #[ignore = "requires ffmpeg on PATH"]
    async fn thumbnail_extract_errors_on_missing_input() {
        let permit = acquire_video_work_permit().await.unwrap();
        let r = run_ffmpeg_thumbnail(Path::new("does-not-exist.mp4"), &permit).await;
        assert!(r.is_err());
    }

    #[test]
    fn audio_arguments_do_not_silently_pretruncate_before_rust_caps() {
        let args = audio_ffmpeg_args(Path::new("video with spaces.mp4"))
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(!args.iter().any(|arg| arg == "-t"));
        assert!(!args.iter().any(|arg| arg == "-fs"));
        assert_eq!(value_after(&args, "-map"), "0:a:0");
        assert_eq!(value_after(&args, "-c:a"), "pcm_s16le");
        assert_eq!(
            value_after(&args, "-ar"),
            audio::TARGET_SAMPLE_RATE.to_string()
        );
        assert!(args.iter().any(|arg| arg == "video with spaces.mp4"));
        assert!(args.iter().any(|arg| arg == "-nostdin"));
        assert_eq!(VIDEO_AUDIO_DURATION_SECS, 10 * 60);
        assert_eq!(
            VIDEO_AUDIO_BYTES_PER_SECOND,
            u64::from(audio::TARGET_SAMPLE_RATE) * size_of::<i16>() as u64
        );
        const {
            assert!(AUDIO_MAX_OUTPUT_BYTES <= audio::MAX_AUDIO_BYTES);
        }
    }

    #[test]
    fn thumbnail_arguments_enforce_frame_and_dimension_caps_without_file_truncation() {
        let args = thumbnail_ffmpeg_args(Path::new("clip.mp4"))
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(value_after(&args, "-frames:v"), "1");
        assert_eq!(value_after(&args, "-t"), "1");
        assert!(!args.iter().any(|arg| arg == "-fs"));
        assert_eq!(value_after(&args, "-map"), "0:v:0");
        assert!(value_after(&args, "-vf").contains("min(1280,iw)"));
    }

    #[test]
    fn private_temp_input_is_removed_when_guard_drops() {
        let path = {
            let temp = write_private_temp_input_with_limit(
                b"private video bytes",
                ".neoth-video-test-",
                1024,
            )
            .expect("create private temp input");
            let path = temp.path().to_owned();
            assert!(path.exists());
            assert_eq!(std::fs::read(&path).unwrap(), b"private video bytes");
            path
        };
        assert!(!path.exists(), "NamedTempFile guard must remove its input");
    }

    #[test]
    fn byte_input_rejects_limit_plus_one_before_temp_write() {
        let error = write_private_temp_input_with_limit(b"123456789", ".neoth-video-test-", 8)
            .expect_err("limit+1 byte input must be rejected");
        assert!(error.to_string().contains("8-byte limit"));
    }

    #[test]
    fn path_snapshot_rejects_limit_plus_one() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(source.as_file_mut(), b"123456789").unwrap();
        std::io::Write::flush(source.as_file_mut()).unwrap();

        let error = snapshot_path_with_limit(source.path(), ".neoth-video-test-", 8)
            .expect_err("limit+1 path input must be rejected");
        assert!(error.to_string().contains("8-byte limit"));
    }

    #[test]
    fn path_snapshot_is_stable_and_accepts_exact_limit() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(source.as_file_mut(), b"12345678").unwrap();
        std::io::Write::flush(source.as_file_mut()).unwrap();

        let snapshot = snapshot_path_with_limit(source.path(), ".neoth-video-test-", 8)
            .expect("exact-limit path input should be snapshotted");
        source.as_file_mut().set_len(0).unwrap();
        std::io::Write::write_all(source.as_file_mut(), b"changed!").unwrap();
        std::io::Write::flush(source.as_file_mut()).unwrap();

        assert_eq!(std::fs::read(snapshot.path()).unwrap(), b"12345678");
    }

    #[cfg(unix)]
    #[test]
    fn path_snapshot_rejects_symlink_inputs() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.mp4");
        let link = dir.path().join("linked.mp4");
        std::fs::write(&source, b"video").unwrap();
        symlink(&source, &link).unwrap();

        let error = snapshot_path_with_limit(&link, ".neoth-video-test-", 8)
            .expect_err("video path snapshots must never follow a symlink");
        assert!(
            error.to_string().contains("open video input")
                || error.to_string().contains("regular non-link")
        );
    }

    #[tokio::test]
    async fn stdout_reader_keeps_only_max_plus_one_signal() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"0123456789").await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let captured = read_max_plus_one(reader, 8).await.unwrap();
        writer_task.await.unwrap();
        assert!(captured.truncated);
        assert_eq!(captured.bytes_written, 8);
        assert_eq!(captured.output, b"01234567");
    }

    #[tokio::test]
    async fn audio_stdout_streams_to_a_bounded_private_tempfile() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"0123456789").await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let output = new_private_temp_output(".neoth-video-audio-test-", ".wav").unwrap();
        let path = output.path().to_path_buf();

        let captured = write_max_plus_one_to_temp(reader, output, 8).await.unwrap();
        writer_task.await.unwrap();

        assert!(captured.truncated);
        assert_eq!(captured.bytes_written, 8);
        assert_eq!(std::fs::read(&path).unwrap(), b"01234567");
    }

    #[tokio::test]
    async fn video_worker_budget_serializes_full_ffmpeg_turns() {
        assert_eq!(VIDEO_WORKER_CONCURRENCY, 1);
        let permit = acquire_video_work_permit().await.unwrap();
        assert!(
            VIDEO_WORKER_BUDGET.try_acquire().is_err(),
            "a second video/ffmpeg turn must wait for the first permit"
        );
        drop(permit);
    }

    #[test]
    fn full_video_turn_is_detached_and_keeps_snapshot_cleanup_order() {
        let source = include_str!("video.rs");
        let start = source
            .find("pub(crate) async fn extract_with_context(")
            .expect("video context entry");
        let tail = &source[start..];
        let end = tail
            .find("#[async_trait::async_trait]")
            .expect("end of contextual video implementation");
        let implementation = &tail[..end];
        let supervisor = implementation
            .find("async fn run_owned_video_pipeline(")
            .expect("owned video supervisor");
        let entry = &implementation[..supervisor];
        let owned = &implementation[supervisor..];

        let video_permit = entry.find("acquire_video_work_permit()").unwrap();
        let owned_input = entry.find("own_video_input(asset)").unwrap();
        let detached = entry
            .find("tokio::spawn(run_owned_video_pipeline(")
            .unwrap();
        assert!(video_permit < owned_input && owned_input < detached);

        assert_eq!(
            owned.matches("snapshot_owned_private_input_async(").count(),
            1,
            "one immutable input snapshot must feed the complete video turn"
        );
        let snapshot = owned.find("snapshot_owned_private_input_async(").unwrap();
        let audio_ffmpeg = owned
            .find("run_ffmpeg_audio(input_snapshot.path()")
            .unwrap();
        let audio_backend = owned.find("audio::AudioExtractor").unwrap();
        let thumbnail = owned
            .find("run_ffmpeg_thumbnail(input_snapshot.path()")
            .unwrap();
        let wav_cleanup = owned.find("close_video_temp(temp, \"audio WAV\")").unwrap();
        let input_cleanup = owned
            .find("close_video_temp(input_snapshot, \"input snapshot\")")
            .unwrap();
        let release = owned
            .find("lease.release_after_verified_cleanup()")
            .unwrap();
        assert!(
            snapshot < audio_ffmpeg
                && audio_ffmpeg < audio_backend
                && audio_backend < thumbnail
                && thumbnail < wav_cleanup
                && wav_cleanup < input_cleanup
                && input_cleanup < release
        );
        assert!(owned.contains("let audio_asset = Asset::Path"));
        assert!(!owned.contains("let audio_asset = Asset::Bytes"));
    }

    #[test]
    fn audio_module_never_acquires_the_video_budget() {
        let audio_source = include_str!("audio.rs");
        assert!(
            audio_source.contains("const MAX_AUDIO_DURATION_SECS: u64 = 10 * 60;"),
            "video's visible ffmpeg rejection cap must track AudioExtractor"
        );
        assert!(!audio_source.contains("super::video"));
        assert!(!audio_source.contains("crate::media::video"));
    }

    #[tokio::test]
    async fn stderr_reader_drains_but_retains_only_the_cap() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"0123456789").await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let captured = drain_to_eof_capped(reader, 4).await.unwrap();
        writer_task.await.unwrap();
        assert!(captured.truncated);
        assert_eq!(captured.bytes, b"0123");
    }

    #[test]
    fn stderr_detail_removes_terminal_controls_and_marks_truncation() {
        let detail = sanitized_stderr_detail(&CappedBytes {
            bytes: b"bad\x1b[31m\r\nsecond line".to_vec(),
            truncated: true,
        });

        assert!(!detail.contains('\x1b'));
        assert!(!detail.contains('\r'));
        assert!(!detail.contains('\n'));
        assert_eq!(detail, ": bad [31m second line [stderr truncated]");
    }

    #[test]
    fn bounded_child_timeout_fixture() {
        if std::env::var_os("NEOTH_VIDEO_TIMEOUT_CHILD").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[tokio::test]
    async fn bounded_child_timeout_kills_and_reaps_process() {
        let permit = acquire_video_work_permit().await.unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("bounded_child_timeout_fixture")
            .env("NEOTH_VIDEO_TIMEOUT_CHILD", "1");
        let started = std::time::Instant::now();
        let error = run_child_bounded(
            command,
            ChildLimits {
                operation: "timeout-test",
                timeout: Duration::from_millis(100),
                max_stdout_bytes: 1024,
                missing_binary_reason: "test child unavailable",
            },
            &permit,
        )
        .await
        .expect_err("slow child must be killed at the wall-clock deadline");

        assert!(error.to_string().contains("timed out after"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn kill_and_reap_proves_the_child_is_waited() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("bounded_child_timeout_fixture")
            .env("NEOTH_VIDEO_TIMEOUT_CHILD", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let pid = child.id().expect("spawned child has a process id");

        kill_and_reap(&mut child).await.unwrap();

        assert!(
            child.try_wait().unwrap().is_some(),
            "child {pid} must have an observed exit status"
        );
        assert!(
            child.id().is_none(),
            "reaped child {pid} must no longer expose a live process id"
        );
    }

    fn value_after(args: &[String], flag: &str) -> String {
        let index = args
            .iter()
            .position(|arg| arg == flag)
            .unwrap_or_else(|| panic!("missing ffmpeg flag {flag}"));
        args.get(index + 1)
            .unwrap_or_else(|| panic!("missing ffmpeg value after {flag}"))
            .clone()
    }

    // Sync `#[test]` + block_on so the env lock isn't held across an
    // `.await` (clippy::await_holding_lock under -D warnings).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    #[test]
    fn extract_surfaces_missing_ffmpeg_with_helpful_message() {
        // Override PATH so the spawn fails with NotFound. Hold the
        // crate-wide env lock — PATH is process-global and an empty
        // PATH breaks ANY concurrent subprocess spawn. (The lock
        // serialises against other env tests; the residual race vs
        // arbitrary subprocess-spawning tests is why the duplicate
        // PATH test was already deleted + the live ffmpeg test is
        // `#[ignore]`.)
        let _env = crate::test_env::lock();
        let prev = std::env::var("PATH").ok();
        unsafe {
            std::env::set_var("PATH", "");
        }
        let extractor = VideoExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Video,
            mime: "video/mp4".into(),
            data: b"fake".to_vec(),
        };
        let home = tempfile::tempdir().unwrap();
        let config = crate::config::FreedomConfig::default();
        let r = block_on(extractor.extract_with_context(
            &asset,
            &config.media,
            &config.updater,
            home.path(),
            None,
        ));
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
