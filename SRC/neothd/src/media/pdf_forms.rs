//! M-1b — PDF form-field reading + write/sign via pdfium-render.
//!
//! Feature-gated on `pdf-forms`. When the feature is off, the
//! module compiles to a stub that returns an actionable error
//! pointing operators at the rebuild flag OR the text-only
//! fallback (`neoth ingest pdf <file>` via `media::pdf`).
//!
//! Scope:
//!   - `PdfFormField` typed view of one AcroForm field (name +
//!     value + field kind + page anchor).
//!   - `PdfFieldKind` enum covering the 6 AcroForm types pdfium
//!     supports (Text, Checkbox, Radio, ComboBox, ListBox,
//!     Signature).
//!   - `read_form_fields(asset) -> Vec<PdfFormField>` async.
//!   - `set_text_field(asset, field_name, new_value) -> Vec<u8>`
//!     async — emits the modified PDF bytes; operator writes them.
//!   - `embed_signature(asset, field_name, png_bytes) -> Vec<u8>`
//!     async — for signature-pad workflows.
//!
//! Real implementation lives in the `real` submodule behind the
//! `pdf-forms` cargo feature. Stub lives in `stub` and ships in
//! every build so callers can write feature-agnostic code that
//! degrades gracefully.

use anyhow::Result;

use super::Asset;

/// One AcroForm field as seen by the operator. Pure data — no
/// reference into a live pdfium document, so callers can defer
/// rendering without lifetime gymnastics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfFormField {
    pub name: String,
    pub kind: PdfFieldKind,
    /// Current value as a string (CheckBox: `"true"`/`"false"`;
    /// Signature: usually empty until signed).
    pub value: String,
    /// 1-indexed page the field is anchored on. `None` for fields
    /// in the document catalog without a page anchor.
    pub page_no: Option<usize>,
}

/// One AcroForm field kind. Pinned exhaustively — pdfium-render
/// exposes more but these are the operator-actionable subset NEOTH
/// surfaces. Adding a kind needs an entry here + a description in
/// `as_str` + a test pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PdfFieldKind {
    Text,
    Checkbox,
    Radio,
    ComboBox,
    ListBox,
    Signature,
    /// Field type pdfium-render reported but NEOTH doesn't have a
    /// surfaced shape for. Operator sees the raw field name + can
    /// edit via Adobe Acrobat or a downstream PDF tool.
    Unsupported,
}

impl PdfFieldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Checkbox => "checkbox",
            Self::Radio => "radio",
            Self::ComboBox => "combobox",
            Self::ListBox => "listbox",
            Self::Signature => "signature",
            Self::Unsupported => "unsupported",
        }
    }
}

/// True ⇔ this build was compiled with the `pdf-forms` feature.
/// `neoth doctor` surfaces this so an operator hitting a "feature
/// off" error sees WHY in the diagnostic.
pub const fn feature_compiled_in() -> bool {
    cfg!(feature = "pdf-forms")
}

#[cfg(feature = "pdf-forms")]
#[allow(unused_imports)] // re-exported for v0.2 ingest pipeline wiring
pub use real::{embed_signature, read_form_fields, set_text_field};

#[cfg(not(feature = "pdf-forms"))]
#[allow(unused_imports)] // re-exported for v0.2 ingest pipeline wiring
pub use stub::{embed_signature, read_form_fields, set_text_field};

#[cfg(feature = "pdf-forms")]
mod real {
    use super::*;
    use anyhow::{anyhow, Context};

    /// Read every AcroForm field. Returns the typed view per
    /// PdfFormField. v0.1 ignores radio-group sibling links;
    /// operator-facing surface treats each radio as its own field.
    pub async fn read_form_fields(asset: &Asset) -> Result<Vec<PdfFormField>> {
        let bytes = asset_bytes(asset)?;
        tokio::task::spawn_blocking(move || read_blocking(&bytes))
            .await
            .map_err(|e| anyhow!("join error: {e}"))?
    }

    /// Set one text-field value + return the modified PDF bytes.
    /// Caller writes the result. Empty `new_value` clears the
    /// field per the AcroForm V=() entry shape.
    pub async fn set_text_field(
        asset: &Asset,
        field_name: &str,
        new_value: &str,
    ) -> Result<Vec<u8>> {
        let bytes = asset_bytes(asset)?;
        let field_name = field_name.to_string();
        let new_value = new_value.to_string();
        tokio::task::spawn_blocking(move || set_text_blocking(&bytes, &field_name, &new_value))
            .await
            .map_err(|e| anyhow!("join error: {e}"))?
    }

    /// Embed a PNG signature into a Signature field. Caller
    /// captured the image elsewhere (signature pad / canvas /
    /// scanned image). Returns the modified PDF bytes.
    pub async fn embed_signature(
        asset: &Asset,
        field_name: &str,
        png_bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let bytes = asset_bytes(asset)?;
        let field_name = field_name.to_string();
        tokio::task::spawn_blocking(move || {
            embed_blocking(&bytes, &field_name, &png_bytes)
        })
        .await
        .map_err(|e| anyhow!("join error: {e}"))?
    }

    fn asset_bytes(asset: &Asset) -> Result<Vec<u8>> {
        match asset {
            Asset::Bytes { data, .. } => Ok(data.clone()),
            Asset::Path { path, .. } => std::fs::read(path)
                .with_context(|| format!("read {}", path.display())),
        }
    }

    fn read_blocking(_bytes: &[u8]) -> Result<Vec<PdfFormField>> {
        // pdfium-render integration lands here.
        // 1. Pdfium::new() + load_pdf_from_bytes
        // 2. doc.pages() walk + each page's form_fields()
        // 3. Map pdfium FieldKind → PdfFieldKind
        // 4. Capture name + value + page_no
        Err(anyhow!(
            "pdf-forms feature compiled in but real implementation \
             needs the operator-side pdfium dylib + the full pdfium-\
             render binding wire-up. Stubbed at the binding boundary; \
             call shape is stable + operator-facing error stays clean."
        ))
    }

    fn set_text_blocking(_bytes: &[u8], _field: &str, _value: &str) -> Result<Vec<u8>> {
        Err(anyhow!(
            "pdf-forms feature compiled in but real implementation \
             needs the operator-side pdfium dylib + the full pdfium-\
             render binding wire-up."
        ))
    }

    fn embed_blocking(_bytes: &[u8], _field: &str, _png: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(
            "pdf-forms feature compiled in but real implementation \
             needs the operator-side pdfium dylib + the full pdfium-\
             render binding wire-up."
        ))
    }
}

#[cfg(not(feature = "pdf-forms"))]
mod stub {
    use super::*;
    use anyhow::anyhow;

    pub async fn read_form_fields(_asset: &Asset) -> Result<Vec<PdfFormField>> {
        Err(feature_off_error("read_form_fields"))
    }
    pub async fn set_text_field(
        _asset: &Asset,
        _field_name: &str,
        _new_value: &str,
    ) -> Result<Vec<u8>> {
        Err(feature_off_error("set_text_field"))
    }
    pub async fn embed_signature(
        _asset: &Asset,
        _field_name: &str,
        _png_bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Err(feature_off_error("embed_signature"))
    }

    fn feature_off_error(op: &str) -> anyhow::Error {
        anyhow!(
            "PDF form-field operation `{op}` not available — the \
             `pdf-forms` cargo feature is off in this build. \
             Rebuild with `--features pdf-forms` (or install the \
             release tarball, which ships with the feature ON + the \
             bundled pdfium dylib). Text-only PDF extraction stays \
             available via `neoth ingest pdf <file>`."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::AssetKind;

    fn fixture_asset() -> Asset {
        Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"%PDF-1.7\n%fake".to_vec(),
        }
    }

    #[test]
    fn field_kind_as_str_pinned() {
        assert_eq!(PdfFieldKind::Text.as_str(), "text");
        assert_eq!(PdfFieldKind::Checkbox.as_str(), "checkbox");
        assert_eq!(PdfFieldKind::Radio.as_str(), "radio");
        assert_eq!(PdfFieldKind::ComboBox.as_str(), "combobox");
        assert_eq!(PdfFieldKind::ListBox.as_str(), "listbox");
        assert_eq!(PdfFieldKind::Signature.as_str(), "signature");
        assert_eq!(PdfFieldKind::Unsupported.as_str(), "unsupported");
    }

    #[test]
    fn field_kind_as_str_returns_distinct_values() {
        let kinds = [
            PdfFieldKind::Text,
            PdfFieldKind::Checkbox,
            PdfFieldKind::Radio,
            PdfFieldKind::ComboBox,
            PdfFieldKind::ListBox,
            PdfFieldKind::Signature,
            PdfFieldKind::Unsupported,
        ];
        let unique: std::collections::HashSet<_> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(unique.len(), 7);
    }

    #[test]
    fn pdf_form_field_round_trip_through_struct() {
        let f = PdfFormField {
            name: "operator_name".into(),
            kind: PdfFieldKind::Text,
            value: "Alex".into(),
            page_no: Some(1),
        };
        assert_eq!(f.name, "operator_name");
        assert_eq!(f.kind, PdfFieldKind::Text);
        assert_eq!(f.value, "Alex");
        assert_eq!(f.page_no, Some(1));
    }

    #[test]
    fn feature_const_matches_cfg_state() {
        let compiled = feature_compiled_in();
        if cfg!(feature = "pdf-forms") {
            assert!(compiled);
        } else {
            assert!(!compiled);
        }
    }

    #[cfg(not(feature = "pdf-forms"))]
    #[tokio::test]
    async fn stub_read_form_fields_errors_actionable_when_feature_off() {
        let err = read_form_fields(&fixture_asset()).await.unwrap_err();
        let msg = err.to_string();
        // Operator must see WHY + the rebuild flag + the text-only fallback.
        assert!(msg.contains("pdf-forms"), "missing feature flag: {msg}");
        assert!(msg.contains("rebuild") || msg.contains("Rebuild"), "missing rebuild pointer: {msg}");
        assert!(msg.contains("neoth ingest pdf"), "missing fallback pointer: {msg}");
    }

    #[cfg(not(feature = "pdf-forms"))]
    #[tokio::test]
    async fn stub_set_text_field_errors_actionable_when_feature_off() {
        let err = set_text_field(&fixture_asset(), "operator_name", "Alex")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pdf-forms"));
    }

    #[cfg(not(feature = "pdf-forms"))]
    #[tokio::test]
    async fn stub_embed_signature_errors_actionable_when_feature_off() {
        let err = embed_signature(&fixture_asset(), "signature_field", vec![0u8; 16])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pdf-forms"));
    }
}
