//! Multimodal pipeline scaffold — R-9 (PDF / Vision / Audio / Video).
//!
//! Per `memory/neoth-arch-v2.md` R-9 + the round-3 research synthesis pins:
//!
//! | Modality | Tech pin                              | Status v0.1.x          |
//! |----------|---------------------------------------|------------------------|
//! | PDF      | `pdfium-render` (text + form fields)  | scaffold + stubs       |
//! | Vision   | local CLIP via candle → vendor fallback | scaffold + stubs     |
//! | Audio    | `whisper-rs` in + `piper-rs` out      | scaffold + stubs       |
//! | Video    | ffmpeg subprocess for transcript      | scaffold + stubs       |
//!
//! This module ships the **trait surface only**. Concrete implementations
//! land per-modality once the operator's first multimodal use case is
//! concrete. The shape is intentional — no module-internal "later we'll
//! generalise" pattern: every backend is its own typed `Asset` consumer +
//! producer.

pub mod audio;
pub mod pdf;
pub mod pdf_forms;
pub mod stt_dispatch;
pub mod tts_dispatch;
pub mod video;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
