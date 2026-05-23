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

// ── M-1 scaffolding: per-page + metadata + form-field readiness ──
//
// The base `PdfExtractor` returns one whitespace-joined text blob;
// for indexer use-cases that want page-anchored recall ("find the
// router decision on page 3 of the proposal"), callers need
// per-page text. The metadata block surfaces title/author/page-
// count for the operator's `neoth recall --pdf-meta` display.
//
// Form-field reading + write/sign still requires `pdfium-render`
// (C++ FFI dep). M-1b lands those behind a `pdfium` cargo feature
// so non-form operators don't pay the dep weight. The types here
// stay forward-compatible — `PdfMetadata.has_form_fields` is
// pre-declared + defaults to `false` (cannot detect from
// `pdf-extract` alone).

/// Lightweight metadata extracted from a PDF. Free fields default
/// to `None`; `pdf-extract` doesn't expose author/title parsing,
/// so v1 populates page_count only — the other fields stay
/// placeholders until M-1b (`pdfium-render` path) lands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PdfMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub page_count: Option<usize>,
    /// True when the PDF contains AcroForm fields. v1 reports
    /// `false` (we can't detect from text-only extraction);
    /// M-1b flips this based on real pdfium inspection.
    pub has_form_fields: bool,
}

/// One page's extracted text + its 1-indexed page number.
/// `text` may be empty for image-only pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfPage {
    pub page_no: usize,
    pub text: String,
}

/// Split a `pdf-extract` whole-document text blob into per-page
/// entries. The library emits a form-feed character (`\x0C`) on
/// page boundaries — we use that as the splitter. Pages without
/// a form-feed (single-page PDFs) return one entry with the full
/// text. Pages with no text after the split are kept as empty
/// entries so page numbering stays stable for recall anchoring.
pub fn split_into_pages(whole_text: &str) -> Vec<PdfPage> {
    if whole_text.is_empty() {
        return Vec::new();
    }
    whole_text
        .split('\x0c')
        .enumerate()
        .map(|(idx, page_text)| PdfPage {
            page_no: idx + 1,
            text: page_text.to_string(),
        })
        .collect()
}

/// Extract per-page text from a PDF asset. Wraps `extract_blocking`
/// + `split_into_pages` so callers indexing for page-anchored
/// recall ("which page mentions the router config?") consume the
/// shape directly.
pub async fn extract_pages(asset: &Asset) -> Result<Vec<PdfPage>, ExtractionError> {
    let payload = asset.clone();
    let extraction = tokio::task::spawn_blocking(move || extract_blocking(&payload))
        .await
        .map_err(|e| ExtractionError::Backend {
            backend: "pdf",
            reason: format!("join error: {e}"),
        })??;
    Ok(split_into_pages(&extraction.text))
}

/// Build a `PdfMetadata` from an asset. v1 populates `page_count`
/// only (derived from the per-page split — counts form-feed
/// separators). M-1b will surface title/author/has_form_fields
/// via `pdfium-render`.
pub async fn extract_metadata(asset: &Asset) -> Result<PdfMetadata, ExtractionError> {
    let pages = extract_pages(asset).await?;
    Ok(PdfMetadata {
        title: None,
        author: None,
        page_count: Some(pages.len()),
        has_form_fields: false,
    })
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

    // ── M-1 scaffolding tests ─────────────────────────────────────

    #[test]
    fn split_into_pages_empty_text_returns_empty() {
        assert!(split_into_pages("").is_empty());
    }

    #[test]
    fn split_into_pages_no_form_feed_returns_single_page() {
        let pages = split_into_pages("just one page of text");
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].page_no, 1);
        assert_eq!(pages[0].text, "just one page of text");
    }

    #[test]
    fn split_into_pages_form_feed_splits_correctly() {
        // 3 pages separated by form-feed chars (the exact splitter
        // `pdf-extract` emits between pages).
        let body = "page one\x0cpage two body\x0cpage three";
        let pages = split_into_pages(body);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].page_no, 1);
        assert_eq!(pages[0].text, "page one");
        assert_eq!(pages[1].page_no, 2);
        assert_eq!(pages[1].text, "page two body");
        assert_eq!(pages[2].page_no, 3);
        assert_eq!(pages[2].text, "page three");
    }

    #[test]
    fn split_into_pages_preserves_empty_pages_for_stable_numbering() {
        // Image-only middle page emits an empty entry between two
        // text pages. Caller MUST see page_no = 2 for the empty
        // slot so per-page recall anchors stay correct.
        let body = "page one\x0c\x0cpage three";
        let pages = split_into_pages(body);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[1].page_no, 2);
        assert!(
            pages[1].text.is_empty(),
            "empty middle page must stay an empty entry, not be dropped"
        );
        assert_eq!(pages[2].page_no, 3);
    }

    #[test]
    fn pdf_metadata_default_is_empty_placeholders() {
        let m = PdfMetadata::default();
        assert!(m.title.is_none());
        assert!(m.author.is_none());
        assert!(m.page_count.is_none());
        assert!(!m.has_form_fields, "v1 has_form_fields defaults to false (M-1b adds detection)");
    }

    #[test]
    fn pdf_page_struct_round_trip() {
        let p = PdfPage {
            page_no: 7,
            text: "body".into(),
        };
        assert_eq!(p.page_no, 7);
        assert_eq!(p.text, "body");
    }
}
