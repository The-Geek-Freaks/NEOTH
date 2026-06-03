//! `neoth ingest <path>` — multimodal asset ingest pipeline.
//!
//! Detect kind from file extension, route to the matching media
//! extractor (PDF / image / audio / video), then persist any produced
//! embedding into `idx_embedding` so similarity search can find it
//! later. Text payloads come along for the ride in the printed report
//! today; persisting them via the WAL writer is the next step (see
//! the "follow-ups" docs in `media/mod.rs`).
//!
//! Why this CLI: vision Phase 2b builds a 512-dim CLIP embedding on
//! every image extraction, but until this command landed the embeddings
//! were marooned in the in-memory metadata JSON — no caller persisted
//! them. `neoth ingest` is the operator-side cursor that runs the full
//! pipeline end-to-end without a channel adapter wired in.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::media::{Asset, AssetKind, MediaExtractor, route_to_first_match};
use crate::memory::{embeddings, store};
use crate::providers::clip_engine;
use crate::wal::events::{EVENT_TYPE_EMBED_PERSISTED, EVENT_TYPE_INGEST_EXTRACTED};
use crate::wal::{make_header, spawn as wal_spawn};

#[derive(Args, Debug, Clone)]
pub struct IngestArgs {
    /// File to ingest. Extension drives the kind:
    /// `.pdf` → pdf, `.png|.jpg|.jpeg|.webp|.gif` → image,
    /// `.wav|.mp3|.flac|.ogg|.m4a` → audio,
    /// `.mp4|.mov|.mkv|.webm` → video,
    /// `.docx|.pptx|.xlsx|.odt|.ods|.odp|.epub|.rtf` → document.
    pub path: PathBuf,

    /// Override the views.db path. Defaults to `~/.neoth/views.db`.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Override the WAL segment path the audit events land in. Defaults
    /// to `~/.neoth/wal/000001.wal` — the same surface `neothd serve`
    /// writes to.
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Skip the embedding persistence pass — useful when running the
    /// pipeline against fixtures in tests or when the operator is just
    /// inspecting the metadata.
    #[arg(long)]
    pub no_persist: bool,

    /// Skip emitting `INGEST_EXTRACTED` / `EMBED_PERSISTED` WAL audit
    /// events. Useful for batch reprocessing where the audit trail is
    /// already known.
    #[arg(long)]
    pub no_audit: bool,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_ingest(args: IngestArgs) -> Result<()> {
    let path = args.path.clone();
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    let kind = detect_kind(&path).ok_or_else(|| {
        anyhow::anyhow!(
            "could not infer asset kind from extension on {} \
             — supported: .pdf .png .jpg .jpeg .webp .gif .wav .mp3 .flac .ogg .m4a \
             .mp4 .mov .mkv .webm .docx .pptx .xlsx .odt .ods .odp .epub .rtf",
            path.display()
        )
    })?;

    let asset = Asset::Path {
        kind,
        mime: mime_hint(kind, &path),
        path: path.clone(),
    };
    let backends = default_backends();
    let extraction = route_to_first_match(&backends, &asset)
        .await
        .map_err(|e| anyhow::anyhow!("extract: {e}"))?;

    let mut persisted = false;
    let mut embedding_dim: Option<usize> = None;
    if !args.no_persist {
        let (rows_written, dim) = persist_embedding_if_any(&args, &extraction)?;
        persisted = rows_written;
        embedding_dim = dim;
    }

    if !args.no_audit {
        emit_audit_events(&args, &extraction, kind, persisted, embedding_dim)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "ingest audit-event emit failed (non-fatal)");
            });
    }

    let report = IngestReport {
        path: path.display().to_string(),
        kind: format!("{kind:?}").to_lowercase(),
        text_bytes: extraction.text.len(),
        text_preview: preview(&extraction.text, 200),
        embed_status: extraction.metadata["embed_status"]
            .as_str()
            .unwrap_or("n/a")
            .to_string(),
        embed_persisted: persisted,
        metadata: extraction.metadata.clone(),
    };

    match args.output {
        OutputFormat::Table => print_table(&report),
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct IngestReport {
    path: String,
    kind: String,
    text_bytes: usize,
    text_preview: String,
    embed_status: String,
    embed_persisted: bool,
    metadata: serde_json::Value,
}

fn print_table(r: &IngestReport) {
    println!("path        : {}", r.path);
    println!("kind        : {}", r.kind);
    println!("text bytes  : {}", r.text_bytes);
    if !r.text_preview.is_empty() {
        println!("preview     : {}", r.text_preview);
    }
    println!("embed status: {}", r.embed_status);
    println!("persisted   : {}", r.embed_persisted);
}

fn preview(s: &str, max: usize) -> String {
    if s.is_empty() {
        return String::new();
    }
    let trimmed: String = s.chars().take(max).collect();
    if s.len() > trimmed.len() {
        format!("{trimmed}…")
    } else {
        trimmed
    }
}

/// Pull the embedding (if any) out of `extraction.metadata.embedding`
/// and write it into `idx_embedding`. Returns `(persisted, dim)` so
/// the audit-event emitter can include the dim in the WAL frame.
fn persist_embedding_if_any(
    args: &IngestArgs,
    extraction: &crate::media::Extraction,
) -> Result<(bool, Option<usize>)> {
    let Some(arr) = extraction.metadata["embedding"].as_array() else {
        return Ok((false, None));
    };
    let mut embedding: Vec<f32> = Vec::with_capacity(arr.len());
    for v in arr {
        match v.as_f64() {
            Some(f) => embedding.push(f as f32),
            None => {
                tracing::warn!(
                    "ingest: metadata.embedding contains a non-numeric entry; skipping persistence"
                );
                return Ok((false, None));
            }
        }
    }
    if embedding.is_empty() {
        return Ok((false, None));
    }
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).context("open views.db")?;
    let source_ref = canonical_source_ref(&args.path);
    // Phase 2b only emits CLIP image embeddings today. When audio or
    // text vectors come online, the `kind` here should follow the
    // emitting extractor's hint rather than a hardcoded "image".
    let kind = match args.path_kind_hint() {
        AssetKind::Image => "image",
        AssetKind::Audio => "audio_segment",
        AssetKind::Video => "video_frame",
        AssetKind::Pdf => "pdf_page",
        AssetKind::Document => "document",
        AssetKind::Other => "asset",
    };
    let model = extraction.metadata["extractor"]
        .as_str()
        .map(|s| match s {
            "vision" => clip_engine::DEFAULT_CLIP_REPO.to_string(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| clip_engine::DEFAULT_CLIP_REPO.to_string());
    let dim = embedding.len();
    embeddings::upsert(&conn, kind, &source_ref, &model, &embedding)
        .context("persist embedding")?;
    Ok((true, Some(dim)))
}

/// Emit `INGEST_EXTRACTED` (always) and `EMBED_PERSISTED` (only when an
/// embedding actually landed) WAL frames. Best-effort: errors here are
/// logged but never abort the ingest path — operators get their
/// extraction report even if the WAL writer can't reach the segment.
///
/// **Concurrency contract**: WAL frames are two writes (header + payload).
/// `O_APPEND` is atomic per-call but not across the pair. If `neothd
/// serve` is already running, its writer task owns the segment; a CLI
/// one-shot writer would race and could produce an interleaved frame.
/// We skip the audit emission (with a warning) in that case rather
/// than risk corrupting the segment — the operator's extraction
/// report still prints, just without the audit row.
async fn emit_audit_events(
    args: &IngestArgs,
    extraction: &crate::media::Extraction,
    asset_kind: AssetKind,
    embedding_persisted: bool,
    embedding_dim: Option<usize>,
) -> Result<()> {
    // Build the frame payloads up front — both the forward path (daemon live)
    // and the one-shot-writer path emit the same bytes.
    let source_ref = canonical_source_ref(&args.path);
    let kind_str = format!("{asset_kind:?}").to_lowercase();
    let model = extraction.metadata["extractor"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let now = now_unix();

    let extracted_payload = serde_json::to_vec(&serde_json::json!({
        "source_ref": source_ref,
        "asset_kind": kind_str,
        "text_bytes": extraction.text.len(),
        "model": model,
        "ts_unix": now,
    }))?;
    let embed_payload = if embedding_persisted {
        Some(serde_json::to_vec(&serde_json::json!({
            "source_kind": match asset_kind {
                AssetKind::Image => "image",
                AssetKind::Audio => "audio_segment",
                AssetKind::Video => "video_frame",
                AssetKind::Pdf => "pdf_page",
                AssetKind::Document => "document",
                AssetKind::Other => "asset",
            },
            "source_ref": source_ref,
            "model": clip_engine::DEFAULT_CLIP_REPO,
            "dim": embedding_dim.unwrap_or(clip_engine::EMBED_DIM),
            "ts_unix": now,
        }))?)
    } else {
        None
    };

    let pidfile = crate::daemon::pidfile::default_pidfile();
    if let Ok(Some(_pid)) = crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        // AUDIT-RPC-01: daemon owns the WAL writer → forward the ingest frames
        // over the loopback channel (0x2C/0x2D allowlisted) instead of silently
        // skipping. Best-effort: an unreachable/disabled listener falls through
        // to no-frame (the asset was still ingested).
        let home = FreedomConfig::default_neoth_home();
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            &home,
            EVENT_TYPE_INGEST_EXTRACTED,
            &extracted_payload,
        )
        .await
        {
            tracing::debug!(error = %e, "ingest 0x2C forward skipped (daemon listener unreachable)");
        }
        if let Some(p) = &embed_payload {
            if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
                &home,
                EVENT_TYPE_EMBED_PERSISTED,
                p,
            )
            .await
            {
                tracing::debug!(error = %e, "ingest 0x2D forward skipped (daemon listener unreachable)");
            }
        }
        return Ok(());
    }

    let segment_path = args
        .wal_segment
        .clone()
        .unwrap_or_else(|| FreedomConfig::default_wal_dir().join("000001.wal"));
    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
    }
    let (writer, writer_join) =
        wal_spawn(segment_path).context("spawn one-shot WAL writer for ingest audit")?;

    let extracted_header = make_header(EVENT_TYPE_INGEST_EXTRACTED, &extracted_payload);
    writer
        .append(extracted_header, extracted_payload)
        .await
        .context("append INGEST_EXTRACTED")?;

    if let Some(p) = embed_payload {
        let embed_header = make_header(EVENT_TYPE_EMBED_PERSISTED, &p);
        writer
            .append(embed_header, p)
            .await
            .context("append EMBED_PERSISTED")?;
    }

    drop(writer);
    writer_join.await.context("wal writer join")?;
    Ok(())
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn canonical_source_ref(p: &std::path::Path) -> String {
    std::fs::canonicalize(p)
        .map(|c| c.display().to_string())
        .unwrap_or_else(|_| p.display().to_string())
}

fn detect_kind(p: &std::path::Path) -> Option<AssetKind> {
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())?;
    Some(match ext.as_str() {
        "pdf" => AssetKind::Pdf,
        "png" | "jpg" | "jpeg" | "webp" | "gif" => AssetKind::Image,
        "wav" | "mp3" | "flac" | "ogg" | "m4a" => AssetKind::Audio,
        "mp4" | "mov" | "mkv" | "webm" => AssetKind::Video,
        "docx" | "pptx" | "xlsx" | "odt" | "ods" | "odp" | "epub" | "rtf" => AssetKind::Document,
        _ => return None,
    })
}

fn mime_hint(kind: AssetKind, p: &std::path::Path) -> String {
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match (kind, ext.as_str()) {
        (AssetKind::Pdf, _) => "application/pdf".into(),
        (AssetKind::Document, "docx") => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into()
        }
        (AssetKind::Document, "pptx") => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation".into()
        }
        (AssetKind::Document, "xlsx") => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".into()
        }
        (AssetKind::Document, "odt") => "application/vnd.oasis.opendocument.text".into(),
        (AssetKind::Document, "ods") => "application/vnd.oasis.opendocument.spreadsheet".into(),
        (AssetKind::Document, "odp") => "application/vnd.oasis.opendocument.presentation".into(),
        (AssetKind::Document, "epub") => "application/epub+zip".into(),
        (AssetKind::Document, "rtf") => "application/rtf".into(),
        (AssetKind::Image, "png") => "image/png".into(),
        (AssetKind::Image, "jpg" | "jpeg") => "image/jpeg".into(),
        (AssetKind::Image, "webp") => "image/webp".into(),
        (AssetKind::Image, "gif") => "image/gif".into(),
        (AssetKind::Audio, "wav") => "audio/wav".into(),
        (AssetKind::Audio, "mp3") => "audio/mpeg".into(),
        (AssetKind::Audio, "flac") => "audio/flac".into(),
        (AssetKind::Audio, "ogg") => "audio/ogg".into(),
        (AssetKind::Audio, "m4a") => "audio/mp4".into(),
        (AssetKind::Video, "mp4" | "m4v") => "video/mp4".into(),
        (AssetKind::Video, "mov") => "video/quicktime".into(),
        (AssetKind::Video, "mkv") => "video/x-matroska".into(),
        (AssetKind::Video, "webm") => "video/webm".into(),
        _ => "application/octet-stream".into(),
    }
}

fn default_backends() -> Vec<Arc<dyn MediaExtractor>> {
    vec![
        Arc::new(crate::media::pdf::PdfExtractor),
        Arc::new(crate::media::document::DocumentExtractor),
        Arc::new(crate::media::vision::VisionExtractor),
        Arc::new(crate::media::audio::AudioExtractor),
        Arc::new(crate::media::video::VideoExtractor),
    ]
}

trait IngestArgsExt {
    fn path_kind_hint(&self) -> AssetKind;
}
impl IngestArgsExt for IngestArgs {
    fn path_kind_hint(&self) -> AssetKind {
        detect_kind(&self.path).unwrap_or(AssetKind::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_kind_returns_image_for_known_extensions() {
        for ext in ["png", "jpg", "jpeg", "webp", "gif"] {
            let p = PathBuf::from(format!("x.{ext}"));
            assert_eq!(detect_kind(&p), Some(AssetKind::Image), "ext: {ext}");
        }
    }

    #[test]
    fn detect_kind_returns_audio_for_known_extensions() {
        for ext in ["wav", "mp3", "flac", "ogg", "m4a"] {
            let p = PathBuf::from(format!("x.{ext}"));
            assert_eq!(detect_kind(&p), Some(AssetKind::Audio));
        }
    }

    #[test]
    fn detect_kind_returns_video_for_known_extensions() {
        for ext in ["mp4", "mov", "mkv", "webm"] {
            let p = PathBuf::from(format!("x.{ext}"));
            assert_eq!(detect_kind(&p), Some(AssetKind::Video));
        }
    }

    #[test]
    fn detect_kind_returns_pdf() {
        let p = PathBuf::from("doc.pdf");
        assert_eq!(detect_kind(&p), Some(AssetKind::Pdf));
    }

    #[test]
    fn detect_kind_uppercase_extension_still_matches() {
        let p = PathBuf::from("PHOTO.JPG");
        assert_eq!(detect_kind(&p), Some(AssetKind::Image));
    }

    #[test]
    fn detect_kind_unknown_returns_none() {
        assert_eq!(detect_kind(&PathBuf::from("x.bin")), None);
        assert_eq!(detect_kind(&PathBuf::from("x")), None);
    }

    #[test]
    fn mime_hint_picks_known_types() {
        assert_eq!(
            mime_hint(AssetKind::Image, &PathBuf::from("x.png")),
            "image/png"
        );
        assert_eq!(
            mime_hint(AssetKind::Audio, &PathBuf::from("x.mp3")),
            "audio/mpeg"
        );
        assert_eq!(
            mime_hint(AssetKind::Video, &PathBuf::from("x.mp4")),
            "video/mp4"
        );
        assert_eq!(
            mime_hint(AssetKind::Pdf, &PathBuf::from("x.pdf")),
            "application/pdf"
        );
    }

    #[test]
    fn preview_truncates_long_text_with_ellipsis() {
        let p = preview("hello world", 5);
        assert_eq!(p, "hello…");
    }

    #[test]
    fn preview_short_text_passes_through() {
        let p = preview("ok", 100);
        assert_eq!(p, "ok");
    }

    #[test]
    fn default_backends_includes_all_modalities() {
        let bs = default_backends();
        let names: Vec<&'static str> = bs.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"pdf"));
        assert!(names.contains(&"vision"));
        assert!(names.contains(&"audio"));
        assert!(names.contains(&"video"));
    }
}
