//! PDF backend — R-9 Phase 2.
//!
//! Uses `pdf-extract` (pure Rust) for text extraction. Limitations:
//!   - No form-field reading (PDF AcroForm).
//!   - No OCR (image-only PDFs return empty text).
//!   - No layout preservation — pages become whitespace-separated text.
//!
//! The pdfium-render upgrade lands when an operator hits one of those
//! ceilings; the trait surface stays unchanged.

use std::path::Path;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

pub struct PdfExtractor;

#[async_trait::async_trait]
impl MediaExtractor for PdfExtractor {
    fn name(&self) -> &'static str {
        "pdf"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Pdf {
            return Err(ExtractionError::Unsupported {
                backend: "pdf",
                got: asset.kind(),
            });
        }
        // pdf-extract is sync + CPU-bound; offload to a blocking task so
        // the tokio reactor stays free for other channel pipelines.
        let payload = asset.clone();
        tokio::task::spawn_blocking(move || extract_blocking(&payload))
            .await
            .map_err(|e| ExtractionError::Backend {
                backend: "pdf",
                reason: format!("join error: {e}"),
            })?
    }
}

fn extract_blocking(asset: &Asset) -> Result<Extraction, ExtractionError> {
    let text = match asset {
        Asset::Bytes { data, .. } => {
            pdf_extract::extract_text_from_mem(data).map_err(|e| ExtractionError::Backend {
                backend: "pdf",
                reason: format!("extract_text_from_mem: {e}"),
            })?
        }
        Asset::Path { path, .. } => extract_text_from_path(path)?,
    };
    let stats = compute_stats(&text);
    Ok(Extraction {
        text,
        metadata: serde_json::json!({
            "extractor": "pdf-extract",
            "char_count": stats.chars,
            "word_count": stats.words,
            "line_count": stats.lines,
        }),
    })
}

fn extract_text_from_path(path: &Path) -> Result<String, ExtractionError> {
    pdf_extract::extract_text(path).map_err(|e| ExtractionError::Backend {
        backend: "pdf",
        reason: format!("extract_text({}): {e}", path.display()),
    })
}

struct Stats {
    chars: usize,
    words: usize,
    lines: usize,
}

fn compute_stats(text: &str) -> Stats {
    Stats {
        chars: text.chars().count(),
        words: text.split_whitespace().count(),
        lines: text.lines().count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_stats_counts_basic_text() {
        let s = compute_stats("hello world\nsecond line");
        assert_eq!(s.lines, 2);
        assert_eq!(s.words, 4);
        assert!(s.chars > 0);
    }

    #[test]
    fn compute_stats_handles_empty_text() {
        let s = compute_stats("");
        assert_eq!(s.lines, 0);
        assert_eq!(s.words, 0);
        assert_eq!(s.chars, 0);
    }

    #[tokio::test]
    async fn extract_returns_unsupported_for_non_pdf() {
        let extractor = PdfExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: vec![0x89, b'P', b'N', b'G'],
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported { backend: "pdf", .. }
        ));
    }

    /// Garbage bytes claiming to be a PDF must surface as a `Backend`
    /// error from the underlying parser, never panic.
    #[tokio::test]
    async fn extract_errors_cleanly_on_garbage_pdf_bytes() {
        let extractor = PdfExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"not actually a pdf".to_vec(),
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(
            matches!(err, ExtractionError::Backend { backend: "pdf", .. }),
            "got: {err:?}",
        );
    }
}
