//! ADOPT31-F4 — explicit, caption-first URL video ingestion.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use sha2::{Digest as _, Sha256};
use tokio::process::Command;

use super::{Asset, AssetKind, Extraction, ExtractionError, VideoSource};
use crate::permissions::{Action, Gate, PermissionAuditSink};
use crate::wal::writer::WalWriterHandle;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CAPTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_VIDEO_BYTES: u64 = 256 * 1024 * 1024;
const STAGING_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadStage {
    Captions,
    MediaFallback,
}

impl DownloadStage {
    const fn action_name(self) -> &'static str {
        match self {
            Self::Captions => "captions",
            Self::MediaFallback => "media_fallback",
        }
    }

    const fn surface(self) -> &'static str {
        match self {
            Self::Captions => "video_url_yt_dlp_captions",
            Self::MediaFallback => "video_url_yt_dlp_media_fallback",
        }
    }

    const fn gate_intent_domain(self) -> &'static [u8] {
        match self {
            Self::Captions => b"video-url-gate-captions",
            Self::MediaFallback => b"video-url-gate-media-fallback",
        }
    }

    const fn receipt_intent_domain(self) -> &'static [u8] {
        match self {
            Self::Captions => b"video-url-receipt-captions",
            Self::MediaFallback => b"video-url-receipt-media-fallback",
        }
    }
}

pub async fn extract_with_context(
    source: &VideoSource,
    config: &crate::config::FreedomConfig,
    home: &Path,
    writer: &WalWriterHandle,
) -> Result<Extraction, ExtractionError> {
    let VideoSource::Url(raw_url) = source else {
        return Err(ExtractionError::Unsupported {
            backend: "video-url",
            got: AssetKind::Video,
        });
    };
    let url = validate_url(raw_url).map_err(backend)?;
    let binary = crate::installers::yt_dlp::managed_path(home);
    if crate::installers::yt_dlp::check_installed(home)
        .await
        .is_none()
    {
        return Err(backend(
            "pinned managed yt-dlp is not installed; run interactive neoth init",
        ));
    }
    let request_binding = digest_url(url.as_str());

    let mut ops = ProductionCaptionFirst {
        config,
        home,
        writer,
        url: &url,
        binary: &binary,
    };
    caption_first_or_fallback(&mut ops, &request_binding)
        .await
        .map_err(backend)
}

/// Narrow internal seam for the actual caption-first production control flow.
/// Both transports can run only after their matching authorization operation.
trait CaptionFirstOps {
    fn authorize<'a>(&'a mut self, action: &'a str) -> BoxFuture<'a, Result<()>>;
    fn captions<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<String>>>;
    fn fallback<'a>(&'a mut self) -> BoxFuture<'a, Result<Extraction>>;
}

async fn caption_first_or_fallback<O: CaptionFirstOps>(
    ops: &mut O,
    request_binding: &str,
) -> Result<Extraction> {
    ops.authorize("captions").await?;
    match ops.captions().await {
        Ok(Some(text)) => Ok(Extraction {
            text,
            metadata: serde_json::json!({
                "extractor": "yt-dlp-captions",
                "source": "url",
                "yt_dlp_version": crate::installers::yt_dlp::YT_DLP_VERSION,
                "caption_first": true,
                "url_sha256": request_binding,
            }),
        }),
        Ok(None) => {
            ops.authorize("media_fallback").await?;
            ops.fallback().await
        }
        Err(error) => {
            tracing::debug!(%error, "yt-dlp caption retrieval unavailable; considering media fallback");
            ops.authorize("media_fallback").await?;
            ops.fallback().await
        }
    }
}

struct ProductionCaptionFirst<'a> {
    config: &'a crate::config::FreedomConfig,
    home: &'a Path,
    writer: &'a WalWriterHandle,
    url: &'a url::Url,
    binary: &'a Path,
}

impl CaptionFirstOps for ProductionCaptionFirst<'_> {
    fn authorize<'a>(&'a mut self, action: &'a str) -> BoxFuture<'a, Result<()>> {
        let stage = match action {
            "captions" => DownloadStage::Captions,
            "media_fallback" => DownloadStage::MediaFallback,
            _ => {
                return Box::pin(async move {
                    anyhow::bail!("unknown video URL download stage: {action}")
                });
            }
        };
        Box::pin(authorize_and_audit(
            self.config,
            self.writer,
            self.url,
            stage,
        ))
    }

    fn captions<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let dir = tempfile::tempdir().context("create caption staging directory")?;
            run_yt_dlp(self.binary, self.url, dir.path(), true).await?;
            read_caption(dir.path())
        })
    }

    fn fallback<'a>(&'a mut self) -> BoxFuture<'a, Result<Extraction>> {
        Box::pin(async move {
            let dir = tempfile::tempdir().context("create video staging directory")?;
            run_yt_dlp(self.binary, self.url, dir.path(), false).await?;
            let path = downloaded_video(dir.path())?;
            let asset = Asset::Path {
                kind: AssetKind::Video,
                mime: "video/mp4".into(),
                path,
            };
            super::video::VideoExtractor
                .extract_with_context(
                    &asset,
                    &self.config.media,
                    &self.config.updater,
                    self.home,
                    Some(self.writer.clone()),
                    None,
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
    }
}

fn validate_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).context("parse video URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "https" | "http"),
        "video URL must use http or https"
    );
    anyhow::ensure!(url.host_str().is_some(), "video URL must include a host");
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "video URL must not contain credentials"
    );
    anyhow::ensure!(raw.len() <= 8 * 1024, "video URL exceeds 8192-byte limit");
    Ok(url)
}

async fn authorize_and_audit(
    config: &crate::config::FreedomConfig,
    writer: &WalWriterHandle,
    url: &url::Url,
    stage: DownloadStage,
) -> Result<()> {
    let binding = stage_binding(stage, url.as_str());
    let destination = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    let action = Action::ExternalHttpRequest {
        method: "GET".into(),
        destination,
        surface: stage.surface().into(),
        request_id: crate::wal::events::next_intent_id(
            stage.gate_intent_domain(),
            &binding,
            crate::time::now_unix_i64(),
        ),
        request_binding_sha256: binding.clone(),
    };
    Gate::for_policy(config.autonomy_policy())
        .with_confirm(Gate::auto_confirm())
        .check_with_audit_sink(
            &action,
            PermissionAuditSink::Writer(writer),
            true,
            Some(&binding),
        )
        .await
        .context("video URL request-bound egress consent")?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "operation_id": crate::wal::events::next_intent_id(stage.receipt_intent_domain(), &binding, crate::time::now_unix_i64()),
        "request_binding_sha256": binding, "action": stage.action_name(),
        "yt_dlp_version": crate::installers::yt_dlp::YT_DLP_VERSION,
        "ts_unix": crate::time::now_unix_secs(),
    }))?;
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::VideoDownloadConsented as u8)
        .build();
    writer
        .append(header, payload)
        .await
        .context("append VIDEO_DOWNLOAD_CONSENTED before yt-dlp egress")?;
    Ok(())
}

async fn run_yt_dlp(
    binary: &Path,
    url: &url::Url,
    output_dir: &Path,
    captions: bool,
) -> Result<()> {
    let template = output_dir.join("asset.%(ext)s");
    let mut command = Command::new(binary);
    command
        .args(yt_dlp_args(&template, url, captions))
        .current_dir(output_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // yt-dlp's `--max-filesize` is an early upstream-side guard for media;
    // the aggregate tree monitor below is the local authority for both modes.
    let ceiling = if captions {
        MAX_CAPTION_BYTES
    } else {
        MAX_VIDEO_BYTES
    };
    let mut child = command.spawn().context("spawn pinned yt-dlp")?;
    let started = tokio::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().context("poll pinned yt-dlp")? {
            break status;
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            terminate_yt_dlp(&mut child).await;
            anyhow::bail!("yt-dlp timed out");
        }
        if let Err(error) = staging_bytes_at_most(output_dir, ceiling) {
            terminate_yt_dlp(&mut child).await;
            return Err(error.context("yt-dlp staging output exceeded bounded ceiling"));
        }
        tokio::time::sleep(STAGING_POLL_INTERVAL).await;
    };
    staging_bytes_at_most(output_dir, ceiling)
        .context("yt-dlp staging output exceeded bounded ceiling")?;
    anyhow::ensure!(status.success(), "yt-dlp exited unsuccessfully");
    Ok(())
}

fn yt_dlp_args(template: &Path, url: &url::Url, captions: bool) -> Vec<OsString> {
    let mut args = vec![
        "--no-config".into(),
        "--no-playlist".into(),
        "--no-warnings".into(),
        "--restrict-filenames".into(),
        "--output".into(),
        template.as_os_str().to_os_string(),
    ];
    if captions {
        args.extend([
            "--skip-download".into(),
            "--write-subs".into(),
            "--write-auto-subs".into(),
            "--sub-langs".into(),
            "all".into(),
        ]);
    } else {
        args.extend([
            "--max-filesize".into(),
            "256M".into(),
            "--format".into(),
            "best[filesize<256M]/best".into(),
        ]);
    }
    args.push("--".into());
    args.push(url.as_str().into());
    args
}

async fn terminate_yt_dlp(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// Count the whole child-owned staging tree, rejecting before the aggregate
/// budget is exceeded. Symlinks do not contribute and are never followed.
fn staging_bytes_at_most(dir: &Path, ceiling: u64) -> Result<u64> {
    fn visit(dir: &Path, ceiling: u64, total: &mut u64) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                visit(&entry.path(), ceiling, total)?;
            } else if metadata.is_file() {
                *total = total
                    .checked_add(metadata.len())
                    .context("yt-dlp staging size overflow")?;
                anyhow::ensure!(
                    *total <= ceiling,
                    "yt-dlp staging output exceeds {ceiling}-byte ceiling"
                );
            }
        }
        Ok(())
    }

    let mut total = 0;
    visit(dir, ceiling, &mut total)?;
    Ok(total)
}

fn read_caption(dir: &Path) -> Result<Option<String>> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !matches!(
            path.extension().and_then(|v| v.to_str()),
            Some("vtt" | "srt" | "ttml")
        ) {
            continue;
        }
        let metadata = std::fs::metadata(&path)?;
        anyhow::ensure!(
            metadata.len() <= MAX_CAPTION_BYTES,
            "caption output exceeds byte ceiling"
        );
        let text = std::fs::read_to_string(&path).context("read caption UTF-8")?;
        if !text.trim().is_empty() {
            return Ok(Some(text));
        }
    }
    Ok(None)
}

fn downloaded_video(dir: &Path) -> Result<PathBuf> {
    let path = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.is_file()
                && matches!(
                    path.extension()
                        .and_then(|v| v.to_str())
                        .map(str::to_ascii_lowercase)
                        .as_deref(),
                    Some("mp4" | "m4v" | "mov" | "mkv" | "webm" | "avi")
                )
        })
        .context("yt-dlp media fallback produced no video file")?;
    anyhow::ensure!(
        std::fs::metadata(&path)?.len() <= MAX_VIDEO_BYTES,
        "yt-dlp video exceeds byte ceiling"
    );
    Ok(path)
}

/// Privacy-preserving source identifier shared by reports, index rows, and WAL
/// records. The original URL is passed only to the already-authorized yt-dlp
/// process and never persisted by this ingestion surface.
pub fn source_ref(url: &str) -> String {
    format!("video-url:{}", digest_url(url))
}

fn digest_url(url: &str) -> String {
    format!("{:x}", Sha256::digest(url.as_bytes()))
}

/// Bind permission and WAL receipts to the exact URL *and* irreversible stage,
/// without placing the URL in either operator-facing surface.
fn stage_binding(stage: DownloadStage, raw_url: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth/video-url-stage/v1\0");
    digest.update(stage.action_name().as_bytes());
    digest.update([0]);
    digest.update(raw_url.as_bytes());
    format!("{:x}", digest.finalize())
}
fn backend(reason: impl std::fmt::Display) -> ExtractionError {
    ExtractionError::Backend {
        backend: "video-url",
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCaptionFirst {
        caption: Result<Option<String>>,
        denied_action: Option<&'static str>,
        calls: Vec<&'static str>,
    }

    impl CaptionFirstOps for MockCaptionFirst {
        fn authorize<'a>(&'a mut self, action: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.calls.push(if action == "captions" {
                    "authorize:captions"
                } else {
                    "authorize:fallback"
                });
                if self.denied_action == Some(action) {
                    anyhow::bail!("required WAL admission refused for {action}");
                }
                Ok(())
            })
        }

        fn captions<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<String>>> {
            Box::pin(async move {
                self.calls.push("captions");
                match &self.caption {
                    Ok(text) => Ok(text.clone()),
                    Err(error) => Err(anyhow::anyhow!(error.to_string())),
                }
            })
        }

        fn fallback<'a>(&'a mut self) -> BoxFuture<'a, Result<Extraction>> {
            Box::pin(async move {
                self.calls.push("fallback");
                Ok(Extraction {
                    text: "fallback text".into(),
                    metadata: serde_json::json!({"extractor": "fallback"}),
                })
            })
        }
    }
    #[test]
    fn rejects_credential_or_non_http_urls_before_any_process() {
        assert!(validate_url("file:///tmp/a.mp4").is_err());
        assert!(validate_url("https://user:secret@example.test/a").is_err());
        assert!(validate_url("https://example.test/a").is_ok());
    }
    #[test]
    fn url_digest_is_stable_and_never_raw_url() {
        let digest = source_ref("https://example.test/private");
        assert_eq!(digest.len(), "video-url:".len() + 64);
        assert!(!digest.contains("example"));
    }

    #[test]
    fn caption_and_media_stages_have_distinct_private_gate_bindings_and_surfaces() {
        let raw_url = "https://example.test/private-video";
        let captions = stage_binding(DownloadStage::Captions, raw_url);
        let media = stage_binding(DownloadStage::MediaFallback, raw_url);
        assert_ne!(captions, media);
        assert_eq!(captions.len(), 64);
        assert_eq!(media.len(), 64);
        assert!(!captions.contains("example"));
        assert!(!media.contains("example"));
        assert_ne!(
            DownloadStage::Captions.surface(),
            DownloadStage::MediaFallback.surface()
        );
    }

    #[test]
    fn aggregate_caption_staging_ceiling_rejects_many_small_outputs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.vtt"), vec![0; 1024]).unwrap();
        std::fs::write(temp.path().join("b.vtt"), vec![0; 1024]).unwrap();
        assert!(staging_bytes_at_most(temp.path(), 2047).is_err());
    }

    #[test]
    fn media_staging_ceiling_rejects_output_before_consumer_selection() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("asset.mp4"), vec![0; 1025]).unwrap();
        assert!(staging_bytes_at_most(temp.path(), 1024).is_err());
    }

    #[test]
    fn command_args_keep_caption_mode_first_and_url_after_double_dash() {
        let url = validate_url("https://example.test/watch?v=1").unwrap();
        let args = yt_dlp_args(Path::new("out/asset.%(ext)s"), &url, true);
        let args: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(args.contains(&"--skip-download".into()));
        assert!(!args.contains(&"--max-filesize".into()));
        assert_eq!(args[args.len() - 2], "--");
        assert_eq!(args.last().unwrap(), url.as_str());
    }

    #[test]
    fn command_args_use_bounded_media_fallback_after_caption_miss() {
        let url = validate_url("https://example.test/watch?v=1").unwrap();
        let args = yt_dlp_args(Path::new("out/asset.%(ext)s"), &url, false);
        let args: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();
        assert!(args.contains(&"--max-filesize".into()));
        assert!(!args.contains(&"--skip-download".into()));
        assert_eq!(args[args.len() - 2], "--");
    }

    #[tokio::test]
    async fn caption_success_returns_text_without_authorizing_or_calling_fallback() {
        let mut ops = MockCaptionFirst {
            caption: Ok(Some("caption text".into())),
            denied_action: None,
            calls: Vec::new(),
        };
        let binding = "a".repeat(64);
        let extraction = caption_first_or_fallback(&mut ops, &binding).await.unwrap();
        assert_eq!(extraction.text, "caption text");
        assert_eq!(ops.calls, ["authorize:captions", "captions"]);
    }

    #[tokio::test]
    async fn missing_captions_separately_authorizes_then_calls_fallback() {
        let mut ops = MockCaptionFirst {
            caption: Ok(None),
            denied_action: None,
            calls: Vec::new(),
        };
        let binding = "a".repeat(64);
        let extraction = caption_first_or_fallback(&mut ops, &binding).await.unwrap();
        assert_eq!(extraction.text, "fallback text");
        assert_eq!(
            ops.calls,
            [
                "authorize:captions",
                "captions",
                "authorize:fallback",
                "fallback"
            ]
        );
    }

    #[tokio::test]
    async fn denied_caption_authorization_prevents_all_transport() {
        let mut ops = MockCaptionFirst {
            caption: Ok(Some("must not be read".into())),
            denied_action: Some("captions"),
            calls: Vec::new(),
        };
        let binding = "a".repeat(64);
        assert!(caption_first_or_fallback(&mut ops, &binding).await.is_err());
        assert_eq!(ops.calls, ["authorize:captions"]);
    }

    #[tokio::test]
    async fn required_wal_refusal_for_fallback_prevents_fallback_transport() {
        let mut ops = MockCaptionFirst {
            caption: Ok(None),
            denied_action: Some("media_fallback"),
            calls: Vec::new(),
        };
        let binding = "a".repeat(64);
        assert!(caption_first_or_fallback(&mut ops, &binding).await.is_err());
        assert_eq!(
            ops.calls,
            ["authorize:captions", "captions", "authorize:fallback"]
        );
    }
}
