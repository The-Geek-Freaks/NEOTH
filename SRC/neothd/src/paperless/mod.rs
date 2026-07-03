//! PL-02 (Session 24) — paperless OCR → Obsidian sync.
//!
//! Sits AFTER [`crate::security::paperless_ingest::ingest_ocr_text`]
//! (SC-16) — that gate produces a sanitized [`PaperlessOcrPayload`].
//! This module renders each payload as one operator-readable
//! markdown note + writes it atomically to
//! `<vault>/<subdir>/Paperless/<doc_id>.md`.
//!
//! ## Why one file per document, not a daily compilation
//!
//! Paperless documents are long-lived: an invoice scanned in May
//! may matter in October. Operators search/edit/tag them
//! individually — one note per doc maps cleanly to the
//! per-document `[[wikilink]]`s downstream notes use to reference
//! the source. The daily compilation pattern (OB-01 dreams)
//! doesn't fit here.
//!
//! ## Atomic write
//!
//! Via the shared [`crate::util::atomic_write::atomic_write`] helper (`.tmp` +
//! fsync + atomic `rename` — no target-remove window; std `rename` replaces in
//! place on Windows too). Same crash-safety shape as
//! `daemon::dreaming::sync_dreams_to_obsidian` +
//! `reflection::sync_reflections_to_obsidian` +
//! `proactive::action_staging::sync_proposals_to_obsidian`.
//!
//! ## Frontmatter discipline
//!
//! `doc_id / ocr_source / raw_input_hash / sanitizer_findings_count
//! / generated_unix` — pinned field order for Dataview queries.
//! `ocr_source` is the snake_case form from `OcrSource::as_str`
//! so audit consumers (memory recall, dreaming) join across the
//! sanitizer event + the obsidian note via the same source tag.

pub mod consult;
/// GOLD-ADAPT-JV-PAPERLESS-01 — quarantine store for emails that fail the
/// content scanner HIGH-severity gate. Atomic JSON writes; CLI list/show.
pub mod quarantine;
pub mod webhook;
pub mod webhook_server;

use std::fs;
use std::path::{Path, PathBuf};

use crate::security::ingress_sanitizer::Finding;
use crate::security::paperless_ingest::PaperlessOcrPayload;

/// Outcome of [`sync_ocr_to_obsidian`]. Parallel to
/// [`crate::daemon::dreaming::DreamSyncOutcome`] so future generic
/// "vault sync" trait can adopt all three (dreams + reflections +
/// paperless) without surface churn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcrSyncOutcome {
    pub doc_id: String,
    pub target_path: PathBuf,
    pub bytes_written: usize,
}

/// PL-02 — render one sanitized OCR payload as an Obsidian
/// markdown note + write atomically to
/// `<vault>/<subdir>/Paperless/<doc_id>.md`.
///
/// `doc_id` SHOULD be filesystem-safe; the function rejects empty
/// or path-traversal-looking ids (`""`, `"."`, `".."`, anything
/// containing `/` or `\`) to keep the target inside the Paperless
/// subdir. Operators see the rejection as an io::Error with kind
/// `InvalidInput`.
///
/// Existing files with the same doc_id are overwritten — the
/// payload is the source of truth; the note is a renderable view.
/// Re-ingesting a corrected OCR replaces the stale version.
pub fn sync_ocr_to_obsidian(
    payload: &PaperlessOcrPayload,
    vault_root: &Path,
    subdir: &str,
) -> std::io::Result<OcrSyncOutcome> {
    let doc_id = payload.document_id.clone();
    if !is_safe_doc_id(&doc_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unsafe doc_id {doc_id:?} — must be non-empty, no path separators, not '.'/'..'"
            ),
        ));
    }

    let dest_dir = vault_root.join(subdir).join("Paperless");
    let final_path = dest_dir.join(format!("{doc_id}.md"));
    let body = render_obsidian_md(payload);

    fs::create_dir_all(&dest_dir)?;
    crate::util::atomic_write::atomic_write(&final_path, body.as_bytes())?;

    Ok(OcrSyncOutcome {
        doc_id,
        target_path: final_path,
        bytes_written: body.len(),
    })
}

/// Render the payload as Obsidian-flavored markdown. Public so a
/// future GUI panel can show the preview without writing to disk.
pub fn render_obsidian_md(payload: &PaperlessOcrPayload) -> String {
    let now_unix = crate::time::now_unix_secs();
    let findings_summary = render_findings_block(&payload.findings);
    let findings_count = payload.findings.len();
    let body_text = payload.body();
    format!(
        "---\n\
         doc_id: \"{doc_id}\"\n\
         ocr_source: \"{source}\"\n\
         raw_input_hash: \"{hash}\"\n\
         sanitizer_findings_count: {fcount}\n\
         ingested_unix: {ts_in}\n\
         generated_unix: {ts_gen}\n\
         ---\n\n\
         # Paperless document {doc_id}\n\n\
         ## Body\n\n\
         {body}\n\n\
         ## Sanitizer findings\n\n\
         {findings}",
        doc_id = escape_yaml_string(&payload.document_id),
        source = payload.source.as_str(),
        hash = escape_yaml_string(&payload.raw_input_hash),
        fcount = findings_count,
        ts_in = payload.ts_unix,
        ts_gen = now_unix,
        body = body_text.trim_end_matches('\n'),
        findings = findings_summary,
    )
}

fn render_findings_block(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "_(no sanitizer findings — body passed clean)_\n".to_string();
    }
    let mut out = String::with_capacity(findings.len() * 64);
    for f in findings {
        let line = match f {
            Finding::OversizeInput { bytes, limit } => {
                format!("- oversize_input: {bytes} bytes (limit {limit})\n")
            }
            Finding::NeededNfkcNormalization => "- needed_nfkc_normalization\n".to_string(),
            Finding::BadControlChar { codepoint, count } => {
                format!("- bad_control_char: U+{codepoint:04X} ×{count}\n")
            }
            Finding::PromptInjectionMarker { pattern } => {
                format!(
                    "- prompt_injection_marker: `{}`\n",
                    pattern.replace('`', "'")
                )
            }
            // GOLD-ADAPT-JV-MODE-01: persona override attempt blocked by identity anchor.
            Finding::PersonaOverrideAttempt { pattern } => {
                format!(
                    "- persona_override_attempt: `{}`\n",
                    pattern.replace('`', "'")
                )
            }
        };
        out.push_str(&line);
    }
    out
}

fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Doc-id allowlist: non-empty, no path separators, not `.` or `..`,
/// no control chars. Liberal otherwise — paperless-ngx ids can be
/// strings like `"INV-2026-001"` or pure integers.
fn is_safe_doc_id(id: &str) -> bool {
    if id.is_empty() || id == "." || id == ".." {
        return false;
    }
    !id.chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
}

/// Render which target path a given doc_id would write to. Useful
/// for dry-run UIs without invoking the writer.
pub fn target_path_for(vault_root: &Path, subdir: &str, doc_id: &str) -> PathBuf {
    vault_root
        .join(subdir)
        .join("Paperless")
        .join(format!("{doc_id}.md"))
}

/// Re-export the source enum so callers don't need a second `use`
/// line just to construct a payload for testing or rendering.
pub use crate::security::paperless_ingest::OcrSource as PaperlessSource;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::paperless_ingest::ingest_ocr_text;

    fn payload(doc_id: &str, raw: &str) -> PaperlessOcrPayload {
        ingest_ocr_text(raw, PaperlessSource::PaperlessNgx, doc_id).expect("sanitizer ok")
    }

    #[test]
    fn render_md_includes_frontmatter_and_body_and_findings_section() {
        let p = payload("doc-42", "Invoice text\nAmount: 42 EUR");
        let md = render_obsidian_md(&p);
        assert!(md.starts_with("---\n"));
        assert!(md.contains("doc_id: \"doc-42\""));
        assert!(md.contains("ocr_source: \"paperless_ngx\""));
        assert!(md.contains("raw_input_hash: \""));
        assert!(md.contains("sanitizer_findings_count: 0"));
        assert!(md.contains("# Paperless document doc-42"));
        assert!(md.contains("## Body"));
        assert!(md.contains("Invoice text"));
        assert!(md.contains("## Sanitizer findings"));
        assert!(md.contains("body passed clean"));
    }

    #[test]
    fn render_md_renders_findings_when_present() {
        // Force a NeededNfkcNormalization finding via fullwidth chars.
        let p = payload("doc-1", "\u{FF41}bc");
        let md = render_obsidian_md(&p);
        assert!(md.contains("needed_nfkc_normalization"));
        assert!(!md.contains("body passed clean"));
    }

    #[test]
    fn render_md_escapes_backtick_in_marker_pattern() {
        // Build a synthetic payload with a hand-crafted finding —
        // bypass ingest_ocr_text because we want the marker text
        // exactly as we wrote it. Serde is the only public path
        // that can set the private `body` field.
        let p: PaperlessOcrPayload = serde_json::from_str(
            r#"{"body":"safe","source":"paperless_ngx","document_id":"doc-x","findings":[{"kind":"prompt_injection_marker","pattern":"with`backtick`"}],"raw_input_hash":"0000","ts_unix":0}"#,
        )
        .unwrap();
        let md = render_obsidian_md(&p);
        // Backticks inside the rendered marker rewrite to single
        // quotes so they don't break the surrounding inline-code span.
        assert!(md.contains("with'backtick'"));
        assert!(!md.contains("with`backtick`"));
    }

    #[test]
    fn sync_writes_md_at_vault_subdir_paperless_doc_id() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("doc-77", "Hello world");
        let outcome = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap();

        let expected = vault
            .path()
            .join("NEOTH")
            .join("Paperless")
            .join("doc-77.md");
        assert_eq!(outcome.target_path, expected);
        assert!(expected.exists());

        let body = std::fs::read_to_string(&expected).unwrap();
        assert!(body.contains("Hello world"));
        assert!(body.contains("doc_id: \"doc-77\""));
    }

    #[test]
    fn sync_bytes_written_matches_file_size() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("doc-1", "x");
        let outcome = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap();
        let on_disk = std::fs::metadata(&outcome.target_path).unwrap().len() as usize;
        assert_eq!(on_disk, outcome.bytes_written);
    }

    #[test]
    fn sync_overwrites_stale_existing_file() {
        let vault = tempfile::tempdir().unwrap();
        let dest_dir = vault.path().join("NEOTH").join("Paperless");
        std::fs::create_dir_all(&dest_dir).unwrap();
        std::fs::write(dest_dir.join("doc-1.md"), "STALE").unwrap();

        let p = payload("doc-1", "fresh content");
        let outcome = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap();

        let body = std::fs::read_to_string(&outcome.target_path).unwrap();
        assert!(!body.contains("STALE"));
        assert!(body.contains("fresh content"));
    }

    #[test]
    fn sync_no_tmp_file_lingers() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("doc-1", "x");
        let outcome = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap();
        let dest_dir = outcome.target_path.parent().unwrap();
        let leftover = dest_dir.join("doc-1.md.tmp");
        assert!(!leftover.exists(), "tmp file leaked: {leftover:?}");
    }

    #[test]
    fn sync_rejects_empty_doc_id() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("", "x");
        let err = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sync_rejects_path_separator_in_doc_id() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("../escape", "x");
        let err = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sync_rejects_dot_doc_id() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload(".", "x");
        let err = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sync_rejects_dotdot_doc_id() {
        let vault = tempfile::tempdir().unwrap();
        let p = payload("..", "x");
        let err = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sync_rejects_backslash_separator_in_doc_id() {
        // Windows-style path separator must be rejected too — vault
        // operators on Windows would hit silent dir traversal otherwise.
        let vault = tempfile::tempdir().unwrap();
        let p = payload("evil\\path", "x");
        let err = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn target_path_for_matches_actual_write_location() {
        let vault = tempfile::tempdir().unwrap();
        let predicted = target_path_for(vault.path(), "NEOTH", "doc-99");

        let p = payload("doc-99", "x");
        let outcome = sync_ocr_to_obsidian(&p, vault.path(), "NEOTH").unwrap();
        assert_eq!(predicted, outcome.target_path);
    }

    #[test]
    fn render_md_yaml_escapes_quote_in_doc_id() {
        // Construct via serde so doc_id can contain unusual chars
        // (the ingest_ocr_text path doesn't reject these — it's
        // sync's job).
        let p: PaperlessOcrPayload = serde_json::from_str(
            r#"{"body":"safe","source":"paperless_ngx","document_id":"weird\"id","findings":[],"raw_input_hash":"0000","ts_unix":0}"#,
        )
        .unwrap();
        let md = render_obsidian_md(&p);
        assert!(md.contains("doc_id: \"weird\\\"id\""), "got {md}");
    }

    #[test]
    fn ocr_source_enum_re_exported_as_paperless_source() {
        // Drift guard: callers can import `paperless::PaperlessSource`
        // instead of digging into `security::paperless_ingest`.
        let s = PaperlessSource::TesseractDirect;
        assert_eq!(s.as_str(), "tesseract_direct");
    }
}
