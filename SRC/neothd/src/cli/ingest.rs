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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::media::{Asset, AssetKind, MediaExtractor, route_to_first_match};
use crate::memory::{
    ctx::{IndexReport, IndexRequest, index_document},
    embeddings, store,
};
use crate::providers::clip_engine;
use crate::wal::events::{EVENT_TYPE_EMBED_PERSISTED, EVENT_TYPE_INGEST_EXTRACTED};
use crate::wal::make_header;

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

    /// Override the WAL segment used for audit events. It must be a canonical
    /// direct child of the selected instance home's `wal` directory and use a
    /// six-digit standalone/rotation suffix. Defaults to a collision-resistant
    /// standalone segment under `~/.neoth/wal`.
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

    /// Skip writing extracted text chunks into the ctx/recall memory store
    /// (`views.db`). Useful when the operator just wants the extraction
    /// report or embedding persistence without indexing the text for recall.
    #[arg(long)]
    pub no_index: bool,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_ingest(args: IngestArgs) -> Result<()> {
    let neoth_home = FreedomConfig::default_neoth_home();
    // Ingest is a zero-friction local surface: a clean machine receives the
    // safe built-in defaults, while a present but malformed operator config
    // still fails closed through the strict load-or-default contract.
    let effective_config = FreedomConfig::load_from_default_path_or_default()?;
    run_ingest_with_context(args, &effective_config, &neoth_home).await
}

async fn run_ingest_with_context(
    args: IngestArgs,
    effective_config: &FreedomConfig,
    neoth_home: &Path,
) -> Result<()> {
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
    let backends = default_backends(&effective_config.media);

    // Audio STT needs the caller's effective policy and a real audit writer.
    // Use an independent segment so a running daemon can keep exclusive
    // ownership of its active segment. `--no-audit` deliberately supplies no
    // sink; proof-hardline cloud STT then refuses before egress.
    let stt_audit_required = !effective_config.media.stt.primary.is_local()
        || effective_config
            .media
            .stt
            .fallback
            .is_some_and(|fallback| !fallback.is_local());
    let stt_audit = if matches!(kind, AssetKind::Audio | AssetKind::Video) && !args.no_audit {
        let wal_dir = neoth_home.join("wal");
        let opened = (|| -> anyhow::Result<_> {
            std::fs::create_dir_all(&wal_dir)?;
            let segment =
                crate::wal::writer::unique_standalone_segment_path(&wal_dir, "ingest-stt");
            Ok(crate::wal::writer::spawn_for_home_with_completion(
                segment,
                neoth_home.to_path_buf(),
            )?)
        })();
        match opened {
            Ok(pair) => Some(pair),
            Err(error) => {
                tracing::warn!(%error, "ingest: STT audit writer unavailable");
                None
            }
        }
    } else {
        None
    };
    let extraction_result = if matches!(kind, AssetKind::Audio | AssetKind::Video) {
        let config = &effective_config;
        match kind {
            AssetKind::Audio => {
                crate::media::audio::AudioExtractor
                    .extract_with_context(
                        &asset,
                        &config.media,
                        &config.updater,
                        neoth_home,
                        stt_audit.as_ref().map(|(writer, _)| writer.clone()),
                    )
                    .await
            }
            AssetKind::Video => {
                crate::media::video::VideoExtractor
                    .extract_with_context(
                        &asset,
                        &config.media,
                        &config.updater,
                        neoth_home,
                        stt_audit.as_ref().map(|(writer, _)| writer.clone()),
                    )
                    .await
            }
            _ => unreachable!("guarded by audio/video match"),
        }
    } else {
        route_to_first_match(&backends, &asset).await
    };
    if let Some((writer, completion)) = stt_audit {
        drop(writer);
        if let Err(error) = completion.wait().await {
            if stt_audit_required {
                return Err(anyhow::anyhow!(
                    "ingest: required cloud STT audit WAL finalization failed: {error}"
                ));
            }
            tracing::warn!(
                %error,
                "ingest: local STT audit WAL finalization failed (non-fatal)"
            );
        }
    }
    let extraction = extraction_result.map_err(|e| anyhow::anyhow!("extract: {e}"))?;

    let mut persisted = false;
    let mut embedding_dim: Option<usize> = None;
    if !args.no_persist {
        let (rows_written, dim) = persist_embedding_if_any(&args, &extraction, neoth_home)?;
        persisted = rows_written;
        embedding_dim = dim;
    }

    if !args.no_audit {
        emit_audit_events(
            &args,
            &extraction,
            kind,
            persisted,
            embedding_dim,
            neoth_home,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "ingest audit-event emit failed (non-fatal)");
        });
    }

    // ── Gap A: write extracted text into the ctx/recall memory store ─────────
    // This is the PRIMARY step that makes `neoth ingest` produce chunked memory
    // entries queryable by `neoth recall` / `neoth ctx`. Best-effort: errors
    // are logged and logged but never abort the ingest (operator still gets the
    // extraction report). Mirrors the pattern in omi_ingest_task + arxiv_ingest_task.
    let chunk_count: Option<usize> = if !args.no_index && !extraction.text.is_empty() {
        let db_path = args
            .db
            .clone()
            .unwrap_or_else(|| neoth_home.join("views.db"));
        match store::open(&db_path) {
            Ok(mut conn) => {
                let req = IndexRequest {
                    label: canonical_source_ref(&path),
                    content: extraction.text.clone(),
                    file_path: Some(path.display().to_string()),
                    content_type: "prose".to_string(),
                    source_category: Some("ingest".to_string()),
                    event_id: None,
                };
                match index_document(&mut conn, &req) {
                    Ok(IndexReport { chunk_count, .. }) => {
                        tracing::debug!(
                            chunks = chunk_count,
                            path = %path.display(),
                            "ingest: indexed into ctx memory store"
                        );
                        Some(chunk_count)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ingest ctx index failed (non-fatal)");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "ingest: could not open views.db for ctx index (non-fatal)");
                None
            }
        }
    } else {
        None
    };

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
        chunk_count,
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
    /// Number of ctx/recall memory chunks written for this document.
    /// `None` when `--no-index` is set or when the extracted text is empty.
    chunk_count: Option<usize>,
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
    match r.chunk_count {
        Some(n) => println!("chunks      : {n}"),
        None => println!("chunks      : (not indexed)"),
    }
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
    neoth_home: &Path,
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
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(|| neoth_home.join("views.db"));
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
    home: &Path,
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

    let pidfile = home.join("neothd.pid");
    if let Some(_pid) = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))?
    {
        // AUDIT-RPC-01: daemon owns the WAL writer → forward the ingest frames
        // over the same-user OS channel (0x2C/0x2D allowlisted) instead of silently
        // skipping. Best-effort: a disabled audit route or unreachable listener
        // falls through to no-frame (the asset was still ingested).
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            EVENT_TYPE_INGEST_EXTRACTED,
            &extracted_payload,
        )
        .await
        {
            tracing::debug!(error = %e, "ingest 0x2C forward skipped (daemon listener unreachable)");
        }
        if let Some(p) = &embed_payload
            && let Err(e) =
                crate::daemon::audit_rpc::try_post_audit_frame(home, EVENT_TYPE_EMBED_PERSISTED, p)
                    .await
        {
            tracing::debug!(error = %e, "ingest 0x2D forward skipped (daemon listener unreachable)");
        }
        return Ok(());
    }

    let segment_path = args.wal_segment.clone().unwrap_or_else(|| {
        crate::wal::writer::unique_standalone_segment_path(&home.join("wal"), "ingest")
    });
    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
    }
    let (writer, writer_completion) =
        crate::wal::writer::spawn_for_home_with_completion(segment_path, home.to_path_buf())
            .context("spawn home-bound one-shot WAL writer for ingest audit")?;

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
    writer_completion
        .wait()
        .await
        .context("finalize one-shot ingest audit WAL writer")?;
    Ok(())
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

fn canonical_source_ref(p: &std::path::Path) -> String {
    std::fs::canonicalize(p)
        .map(|c| c.display().to_string())
        .unwrap_or_else(|_| p.display().to_string())
}

pub(crate) fn detect_kind(p: &std::path::Path) -> Option<AssetKind> {
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

pub(crate) fn mime_hint(kind: AssetKind, p: &std::path::Path) -> String {
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

pub(crate) fn default_backends(
    media_config: &crate::config::MediaConfig,
) -> Vec<Arc<dyn MediaExtractor>> {
    // GOLD-ADAPT-AWE-DOC-01: DoclingExtractor is prepended before the pure-Rust
    // PDF/Document backends. It returns Unsupported (not Backend) when:
    //   - MediaConfig::docling_enabled is false (default), OR
    //   - the `docling` binary is not on PATH.
    // In both cases route_to_first_match falls through to PdfExtractor /
    // DocumentExtractor, so the pipeline is identical to pre-Docling when the
    // flag is off or the binary is absent.
    vec![
        Arc::new(crate::media::docling::DoclingExtractor::new(
            media_config.docling_enabled,
        )),
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
        let bs = default_backends(&crate::config::MediaConfig::default());
        let names: Vec<&'static str> = bs.iter().map(|b| b.name()).collect();
        assert!(
            names.contains(&"docling"),
            "docling must be in backend list"
        );
        assert!(names.contains(&"pdf"));
        assert!(names.contains(&"vision"));
        assert!(names.contains(&"audio"));
        assert!(names.contains(&"video"));
    }

    #[test]
    fn default_backends_has_docling_before_pdf_and_document() {
        let bs = default_backends(&crate::config::MediaConfig::default());
        let names: Vec<&'static str> = bs.iter().map(|b| b.name()).collect();
        let docling_pos = names.iter().position(|&n| n == "docling").unwrap();
        let pdf_pos = names.iter().position(|&n| n == "pdf").unwrap();
        let doc_pos = names.iter().position(|&n| n == "document").unwrap();
        assert!(docling_pos < pdf_pos, "docling must come before pdf");
        assert!(docling_pos < doc_pos, "docling must come before document");
    }

    // ── Gap A integration test ────────────────────────────────────────────────
    // Proves that run_ingest writes extracted text into the ctx memory store
    // (views.db) such that it is queryable by memory::ctx::search.

    /// Minimal DOCX zip fixture: a `word/document.xml` with two paragraphs.
    fn make_docx_fixture() -> Vec<u8> {
        use std::io::Write as _;
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>paragraph alpha content here</w:t></w:r></w:p>
<w:p><w:r><w:t>paragraph beta content here</w:t></w:r></w:p>
</w:body>
</w:document>"#;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file::<_, ()>("word/document.xml", opts).unwrap();
        w.write_all(xml.as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[tokio::test]
    async fn ingest_ctx_indexes_document_chunks() {
        use crate::memory::ctx::search;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let doc_path = dir.path().join("test_doc.docx");
        let db_path = dir.path().join("views.db");
        let wal_path = dir.path().join("test.wal");

        std::fs::write(&doc_path, make_docx_fixture()).unwrap();

        let args = IngestArgs {
            path: doc_path.clone(),
            db: Some(db_path.clone()),
            wal_segment: Some(wal_path),
            no_persist: true,
            no_audit: true,
            no_index: false,
            output: OutputFormat::Json,
        };

        // run_ingest must complete without error.
        run_ingest_with_context(args, &FreedomConfig::default(), dir.path())
            .await
            .expect("run_ingest failed");

        // Open the db and search for content from the fixture.
        let conn = crate::memory::store::open(&db_path).expect("open views.db");
        let hits = search(&conn, "alpha", 10).expect("search failed");
        assert!(
            !hits.is_empty(),
            "expected at least 1 ctx hit for 'alpha' after ingest, got 0"
        );
        assert_eq!(
            hits[0].source_category.as_deref(),
            Some("ingest"),
            "chunk source_category must be 'ingest'"
        );
        // The label must contain the canonical path of the fixture.
        assert!(
            hits[0].label.contains("test_doc.docx"),
            "chunk label must reference the fixture file, got: {}",
            hits[0].label
        );
    }

    #[tokio::test]
    async fn ingest_no_index_skips_ctx_write() {
        use crate::memory::ctx::search;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let doc_path = dir.path().join("skip_doc.docx");
        let db_path = dir.path().join("views_skip.db");
        let wal_path = dir.path().join("skip.wal");

        std::fs::write(&doc_path, make_docx_fixture()).unwrap();

        let args = IngestArgs {
            path: doc_path.clone(),
            db: Some(db_path.clone()),
            wal_segment: Some(wal_path),
            no_persist: true,
            no_audit: true,
            no_index: true, // <── skip indexing
            output: OutputFormat::Json,
        };

        run_ingest_with_context(args, &FreedomConfig::default(), dir.path())
            .await
            .expect("run_ingest failed");

        // views.db should either not exist or be empty (no sources written).
        if db_path.exists() {
            let conn = crate::memory::store::open(&db_path).expect("open views.db");
            let hits = search(&conn, "alpha", 10).expect("search failed");
            assert!(
                hits.is_empty(),
                "--no-index must not write any ctx chunks; got {} hits",
                hits.len()
            );
        }
    }
}
