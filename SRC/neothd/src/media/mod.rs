//! Multimodal pipeline — R-9 (PDF / Vision / Audio / Video).
//!
//! Per `memory/neoth-arch-v2.md` R-9 + the round-3 research synthesis pins.
//! The status column reflects what actually ships today — not the original
//! aspiration. In particular **the audio path is cloud-first**: local STT
//! transcription and local TTS are NOT implemented yet, so any claim of a
//! "full-stack local" audio pipeline would be untrue (GOLD-HON-04 / B-08).
//!
//! | Modality | Tech pin                                                                | Status                                                                                       |
//! |----------|-------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
//! | PDF      | `pdf-extract` text · `pdfium-render` forms (feature `pdf-forms`)         | text extraction shipped (no OCR); form fields behind `pdf-forms`                              |
//! | Vision   | `image` decode · local CLIP embed (candle) · cloud vision synth (MM-02b) | decode + cached-CLIP embed + cloud synth shipped                                              |
//! | Audio    | `symphonia` decode · STT: candle `whisper` local (cache-gated) + cloud REST (MM-01b) · TTS: cloud REST (MM-03b) + planned `piper-rs`/OS-native | decode + **local candle-Whisper STT** (wired; fires once the model artifacts are cached) + cloud STT/TTS REST shipped; local **TTS** still planned |
//! | Video    | ffmpeg decode → vision synth (MM-02b)                                    | frame decode + vision synth shipped                                                           |
//!
//! This module started as a **trait surface**; most paths are now real — cloud
//! STT (MM-01b), cloud TTS (MM-03b), and video decode → vision-synth (MM-02b)
//! ship working REST/ffmpeg backends; PDF text + CLIP image embedding work
//! locally; and **local Whisper STT is wired** (DD-03 / HON-04 — the doc
//! previously said the opposite): `audio.rs`'s `transcribe_if_cached` runs
//! `providers::whisper::WhisperEngine` (candle) once the model artifacts are
//! cached, emitting real transcript text; only when the model is absent does
//! `text` stay empty (status `"model not cached"`). The remaining **local**
//! scaffold is TTS (piper-rs / OS-native speech synthesis) and PDF OCR. The
//! shape is intentional — no module-internal "later we'll generalise" pattern:
//! every backend is its own typed `Asset` consumer + producer.

pub mod audio;
pub mod document;
/// GOLD-ADAPT-HANDY-07 — GPU/accelerator detection + FMA3 guard for the
/// media pipeline (STT backend selection). Probes CPU capability flags
/// (FMA3/AVX2/AVX) and best available accelerator class; `require_fma3`
/// guards against SIGILL on pre-Haswell CPUs.
pub mod hw_probe;
/// MM-02b — ffmpeg-backed video frame decoder (single still near a timestamp).
pub mod frame_decoder;
/// MM-02b — multimodal vision synthesizers (Anthropic / OpenAI / Gemini REST).
pub mod multimodal_synth;
pub mod pdf;
pub mod pdf_forms;
/// GOLD-ADAPT-HANDY-04 — model download manager: SHA-256 verify, resumable
/// `Range` downloads, and atomic tmp→dest rename.
pub mod model_manager;
/// HANDY-01 — band-limited sinc resampler (rubato) for the STT capture path.
pub mod resampler;
pub mod stt_dispatch;
/// GOLD-ADAPT-SPEAKR-02 — Speaker voice-profile re-identification.
/// Cosine-matches a voice embedding against known profiles, updates the
/// winning centroid via a 70/30 EMA, and guards against ambiguous top-2
/// results. Wire into the STT post-processing path when embeddings are
/// available (`media.auto_speaker_labels: true`).
pub mod speaker_profile;
/// HANDY-03 — filler-word removal + stutter collapse for raw STT transcripts.
/// Called as a post-processing hook before transcript text leaves the pipeline.
pub mod stt_postprocess;
/// MM-01b — cloud STT providers (OpenAI Whisper API + Azure Speech) + the
/// `make_stt_provider` factory. REST via `providers::http_client`. Transcript
/// text is never WAL-written (privacy).
pub mod stt_provider;
/// MM-03b — cloud TTS providers (Azure Cognitive Services + ElevenLabs) +
/// the `make_tts_provider` factory. REST via `providers::http_client`.
pub mod tts_cloud;
pub mod tts_dispatch;
pub mod tts_provider;
pub mod video;
/// MM-02b — video analysis dispatch: decode → vision synth → 0xC9 audit.
pub mod video_dispatch;
pub mod video_frames;
pub mod vision;

use anyhow::Result;

/// One typed media asset that flows through the pipeline. Either raw bytes
/// in memory (small attachments, voice notes) or a path reference (large
/// videos, multi-page PDFs that the backend mmap'd directly).
#[derive(Debug, Clone)]
pub enum Asset {
    Bytes {
        kind: AssetKind,
        mime: String,
        data: Vec<u8>,
    },
    Path {
        kind: AssetKind,
        mime: String,
        path: std::path::PathBuf,
    },
}

impl Asset {
    pub fn kind(&self) -> AssetKind {
        match self {
            Asset::Bytes { kind, .. } | Asset::Path { kind, .. } => *kind,
        }
    }
    pub fn mime(&self) -> &str {
        match self {
            Asset::Bytes { mime, .. } | Asset::Path { mime, .. } => mime,
        }
    }
}

/// Coarse classification — drives routing in the multimodal dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    Pdf,
    Image,
    Audio,
    Video,
    /// Office / e-book documents (DOCX, PPTX, XLSX, ODT/ODS/ODP, EPUB,
    /// RTF) routed to [`document::DocumentExtractor`]. PDF stays its own
    /// kind because it has an image-aware extractor.
    Document,
    /// Catch-all for formats NEOTH does not yet route. Operator's inbound
    /// channel adapter sets it; the pipeline returns an `Unsupported`
    /// extraction result.
    Other,
}

/// What every backend produces. Operator pipelines reason over text +
/// metadata; the original asset is preserved separately when needed.
#[derive(Debug, Clone, Default)]
pub struct Extraction {
    /// Free-form text suitable for ingest into the WAL / recall.
    pub text: String,
    /// Backend-specific metadata (page count, audio duration, frame
    /// count, vision tags, …). JSON for round-trip into WAL payloads.
    pub metadata: serde_json::Value,
}

/// The single trait every backend implements. Async because audio + video
/// extraction can dwell on disk IO + subprocess waits.
#[async_trait::async_trait]
pub trait MediaExtractor: Send + Sync {
    /// Stable identifier shown in logs + WAL events: `"pdf"`, `"audio"`, …
    fn name(&self) -> &'static str;

    /// Pull text + metadata out of the asset. Backends that cannot handle
    /// the asset return [`ExtractionError::Unsupported`].
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
    #[error("unsupported asset kind for backend `{backend}` (got {got:?})")]
    Unsupported {
        backend: &'static str,
        got: AssetKind,
    },
    #[error("backend `{backend}` failed: {reason}")]
    Backend {
        backend: &'static str,
        reason: String,
    },
    #[error("io error: {0}")]
    Io(String),
}

/// Dispatch helper: pick the first backend that accepts `asset.kind()`.
pub async fn route_to_first_match(
    backends: &[std::sync::Arc<dyn MediaExtractor>],
    asset: &Asset,
) -> Result<Extraction, ExtractionError> {
    for b in backends {
        match b.extract(asset).await {
            Ok(out) => return Ok(out),
            Err(ExtractionError::Unsupported { .. }) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(ExtractionError::Unsupported {
        backend: "(none)",
        got: asset.kind(),
    })
}

/// P0 — fail-closed audit pre-flight for cloud-media operations. When the
/// operator demands proof (`config::MediaConfig::required_audit_for_cloud_media`)
/// and the audit sink is unavailable, the cloud STT / TTS / Vision / Video call
/// is REFUSED *before* it runs — better no transcription than an unprovable one.
/// PURE so the policy is unit-testable without a WAL.
pub fn enforce_cloud_media_audit(required: bool, audit_available: bool) -> Result<(), String> {
    if required && !audit_available {
        return Err(
            "required_audit_for_cloud_media is on but no WAL audit sink is available — \
             refusing the cloud-media operation (it would run without an audit trail)"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn cloud_media_audit_fails_closed_only_when_required_and_unavailable() {
        // The one refusal case: proof demanded + no sink.
        assert!(enforce_cloud_media_audit(true, false).is_err());
        // required but a sink IS available → proceeds.
        assert!(enforce_cloud_media_audit(true, true).is_ok());
        // not required → always proceeds (best-effort posture).
        assert!(enforce_cloud_media_audit(false, false).is_ok());
        assert!(enforce_cloud_media_audit(false, true).is_ok());
    }

    struct AlwaysUnsupported(&'static str);
    #[async_trait::async_trait]
    impl MediaExtractor for AlwaysUnsupported {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
            Err(ExtractionError::Unsupported {
                backend: self.0,
                got: asset.kind(),
            })
        }
    }

    struct AlwaysPdf;
    #[async_trait::async_trait]
    impl MediaExtractor for AlwaysPdf {
        fn name(&self) -> &'static str {
            "pdf-mock"
        }
        async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
            if asset.kind() != AssetKind::Pdf {
                return Err(ExtractionError::Unsupported {
                    backend: "pdf-mock",
                    got: asset.kind(),
                });
            }
            Ok(Extraction {
                text: "page 1 body".into(),
                metadata: serde_json::json!({"pages": 1}),
            })
        }
    }

    fn fixture_pdf_bytes() -> Asset {
        Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: vec![0x25, 0x50, 0x44, 0x46], // "%PDF"
        }
    }

    #[tokio::test]
    async fn route_returns_first_match() {
        let asset = fixture_pdf_bytes();
        let backends: Vec<Arc<dyn MediaExtractor>> = vec![
            Arc::new(AlwaysUnsupported("a")),
            Arc::new(AlwaysPdf),
            Arc::new(AlwaysUnsupported("c")),
        ];
        let out = route_to_first_match(&backends, &asset).await.unwrap();
        assert_eq!(out.text, "page 1 body");
        assert_eq!(out.metadata["pages"], 1);
    }

    #[tokio::test]
    async fn route_returns_unsupported_when_no_backend_handles() {
        let asset = fixture_pdf_bytes();
        let backends: Vec<Arc<dyn MediaExtractor>> = vec![
            Arc::new(AlwaysUnsupported("a")),
            Arc::new(AlwaysUnsupported("b")),
        ];
        let err = route_to_first_match(&backends, &asset).await.unwrap_err();
        assert!(matches!(err, ExtractionError::Unsupported { .. }));
    }

    #[test]
    fn asset_helpers_return_kind_and_mime() {
        let a = fixture_pdf_bytes();
        assert_eq!(a.kind(), AssetKind::Pdf);
        assert_eq!(a.mime(), "application/pdf");
    }

    #[test]
    fn path_asset_kind_round_trips() {
        let a = Asset::Path {
            kind: AssetKind::Video,
            mime: "video/mp4".into(),
            path: std::path::PathBuf::from("/tmp/x.mp4"),
        };
        assert_eq!(a.kind(), AssetKind::Video);
        assert_eq!(a.mime(), "video/mp4");
    }
}
