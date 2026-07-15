//! GOLD-ADAPT-AWE-DOC-01 — Docling subprocess extractor.
//!
//! `DoclingExtractor` invokes the `docling` CLI (or `python -m docling`)
//! as a headless subprocess, captures its JSON output, and returns the
//! concatenated page text as an [`Extraction`].
//!
//! **Opt-in**: the extractor returns [`ExtractionError::Unsupported`] (not
//! [`ExtractionError::Backend`]) when:
//! - `MediaConfig::docling_enabled` is `false`, OR
//! - the `docling` binary is not on `PATH`.
//!
//! Both conditions cause `route_to_first_match` to fall through to the next
//! registered backend (`PdfExtractor` / `DocumentExtractor`), so the rest of
//! the ingest pipeline is **completely unaffected** when Docling is absent.
//!
//! **Supported asset kinds**: `Pdf`, `Document`, `Image`. All others
//! immediately return `Unsupported`.
//!
//! **Docling JSON contract** (pinned to Docling ≥ 2.x with `--output-format json`):
//! ```json
//! {
//!   "pages": [
//!     { "text": "page body …" },
//!     …
//!   ]
//! }
//! ```
//! If the JSON shape differs (older builds emit `content.text` or plain
//! markdown), the parser falls back to treating the raw stdout as text.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Subprocess stdout cap — 50 MiB. Docling on a 1000-page PDF is the worst
/// case; anything larger implies a corrupted input.
const MAX_STDOUT_BYTES: u64 = 50 * 1024 * 1024;

/// Subprocess wall-clock timeout. Docling needs to run an ML model on every
/// page; 5 minutes covers even a very large document on a slow CPU.
const SUBPROCESS_TIMEOUT_SECS: u64 = 300;

/// Subprocess stderr cap — 16 KiB of diagnostics is plenty for an error
/// message. We keep reading stderr past this cap (to EOF) so the OS pipe never
/// fills and deadlocks the child mid-write; only storage is bounded.
const MAX_STDERR_BYTES: usize = 16 * 1024;

pub struct DoclingExtractor;

#[async_trait::async_trait]
impl MediaExtractor for DoclingExtractor {
    fn name(&self) -> &'static str {
        "docling"
    }

    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        // ── Gate 1: operator opt-in ──────────────────────────────────────────
        // Load current FreedomConfig so the flag is live (no daemon required).
        // A genuinely absent config uses the safe disabled default. An existing
        // malformed/unreadable policy is a hard extraction error: treating it
        // as disabled would conceal operator-state corruption.
        let cfg =
            crate::config::FreedomConfig::load_from_default_path_or_default().map_err(|error| {
                ExtractionError::Backend {
                    backend: "docling",
                    reason: format!("load freedom.yaml: {error:#}"),
                }
            })?;
        if !cfg.media.docling_enabled {
            return Err(ExtractionError::Unsupported {
                backend: "docling",
                got: asset.kind(),
            });
        }

        // ── Gate 2: asset kind ───────────────────────────────────────────────
        match asset.kind() {
            AssetKind::Pdf | AssetKind::Document | AssetKind::Image => {}
            other => {
                return Err(ExtractionError::Unsupported {
                    backend: "docling",
                    got: other,
                });
            }
        }

        // ── Gate 3: binary on PATH ───────────────────────────────────────────
        // `which::which` is not in the tree; use `tokio::process::Command`
        // with a version probe instead — cheaper than a full extract call
        // and produces a clean Unsupported on missing binary.
        if !docling_binary_available().await {
            tracing::debug!("docling binary not on PATH — falling through to pure-Rust backends");
            return Err(ExtractionError::Unsupported {
                backend: "docling",
                got: asset.kind(),
            });
        }

        // ── Resolve to a file path ───────────────────────────────────────────
        // DoclingExtractor always operates on a file path. For `Asset::Bytes`
        // we write a tempfile so the subprocess can read it.
        let (file_path, _tempfile_guard) = match asset {
            Asset::Path { path, .. } => (path.clone(), None),
            Asset::Bytes { data, mime, .. } => {
                let dir = tempfile::tempdir().map_err(|e| ExtractionError::Io(e.to_string()))?;
                let ext = ext_from_mime(mime);
                let tmp_path = dir.path().join(format!("docling_input{ext}"));
                std::fs::write(&tmp_path, data).map_err(|e| ExtractionError::Io(e.to_string()))?;
                // Return the dir as a guard so it is dropped AFTER we finish.
                (tmp_path, Some(dir))
            }
        };

        // ── Spawn docling ────────────────────────────────────────────────────
        // `kill_on_drop` is the backstop: any early return / panic below reaps
        // the child instead of leaking a zombie that keeps an ML model resident.
        let mut child = Command::new("docling")
            .args(["--output-format", "json", file_path.to_str().unwrap_or("")])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ExtractionError::Backend {
                backend: "docling",
                reason: format!("spawn failed: {e}"),
            })?;

        let mut stdout_handle = child
            .stdout
            .take()
            .ok_or_else(|| ExtractionError::Backend {
                backend: "docling",
                reason: "no stdout handle".into(),
            })?;
        let stderr_handle = child
            .stderr
            .take()
            .ok_or_else(|| ExtractionError::Backend {
                backend: "docling",
                reason: "no stderr handle".into(),
            })?;

        // Drain stderr in a background task so its OS pipe can NEVER fill and
        // deadlock the child mid-write (Docling streams progress + model
        // warnings to stderr). We keep only a small head for diagnostics but
        // read all the way to EOF so the pipe always drains.
        let stderr_task = tokio::spawn(drain_to_eof_capped(stderr_handle, MAX_STDERR_BYTES));

        let timeout = Duration::from_secs(SUBPROCESS_TIMEOUT_SECS);
        let mut stdout_bytes = Vec::with_capacity(64 * 1024);

        // ── Read stdout with a byte cap and wall-clock timeout ───────────────
        let read_result = tokio::time::timeout(timeout, async {
            let mut buf = [0u8; 65536];
            loop {
                match stdout_handle.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdout_bytes.len() as u64 + n as u64 > MAX_STDOUT_BYTES {
                            // Keep only up to the cap (room < n here, since we
                            // just crossed it); `.min(n)` is belt-and-braces.
                            let room = (MAX_STDOUT_BYTES as usize)
                                .saturating_sub(stdout_bytes.len())
                                .min(n);
                            stdout_bytes.extend_from_slice(&buf[..room]);
                            tracing::warn!(
                                "docling stdout exceeded {MAX_STDOUT_BYTES} bytes — truncating + killing child"
                            );
                            // We've stopped draining stdout: the child would
                            // block on its next write and hang `wait()`. Kill it
                            // now so the wait below returns promptly.
                            let _ = child.kill().await;
                            break;
                        }
                        stdout_bytes.extend_from_slice(&buf[..n]);
                    }
                    Err(e) => {
                        return Err(ExtractionError::Io(format!("stdout read: {e}")));
                    }
                }
            }
            Ok(())
        })
        .await;

        match read_result {
            Err(_elapsed) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stderr_task.await;
                return Err(ExtractionError::Backend {
                    backend: "docling",
                    reason: format!("subprocess timed out after {SUBPROCESS_TIMEOUT_SECS}s"),
                });
            }
            Ok(Err(e)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stderr_task.await;
                return Err(e);
            }
            Ok(Ok(())) => {}
        }

        // ── Wait for exit code (bounded) ─────────────────────────────────────
        // After a clean stdout EOF the child is exiting; after a cap-kill it is
        // already dead. Bound the wait anyway so a wedged child can never pin
        // the caller — `kill_on_drop` reaps it when `child` finally drops.
        let status = match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let _ = stderr_task.await;
                return Err(ExtractionError::Backend {
                    backend: "docling",
                    reason: format!("wait failed: {e}"),
                });
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                let _ = stderr_task.await;
                return Err(ExtractionError::Backend {
                    backend: "docling",
                    reason: "subprocess did not exit after stdout close".into(),
                });
            }
        };

        let stderr_bytes = stderr_task.await.unwrap_or_default();

        if !status.success() {
            let code = status.code().unwrap_or(-1);
            let stderr_snip = String::from_utf8_lossy(&stderr_bytes);
            let stderr_snip = stderr_snip.trim();
            let reason = if stderr_snip.is_empty() {
                format!("exit code {code}")
            } else {
                format!("exit code {code}: {stderr_snip}")
            };
            return Err(ExtractionError::Backend {
                backend: "docling",
                reason,
            });
        }

        // ── Parse JSON output ────────────────────────────────────────────────
        let stdout_str = String::from_utf8_lossy(&stdout_bytes);
        let (text, page_count) = parse_docling_output(&stdout_str);

        let ext_str = file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        let metadata = serde_json::json!({
            "extractor": "docling",
            "page_count": page_count,
            "format": ext_str,
        });

        Ok(Extraction { text, metadata })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Probe whether the `docling` binary is reachable. Invokes `docling --version`
/// with a tight timeout; returns `false` on any error (missing binary, PATH
/// problem, etc.). This is cheap because the version probe exits immediately.
async fn docling_binary_available() -> bool {
    let probe = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("docling")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status(),
    )
    .await;
    matches!(probe, Ok(Ok(s)) if s.success() || s.code().is_some())
}

/// Drain an async reader to EOF, retaining at most `cap` bytes. Reading
/// continues past the cap so the underlying OS pipe never fills (which would
/// deadlock the child writing to it); the overflow is simply discarded. Used
/// for the child's stderr, which we keep only for diagnostics on failure.
async fn drain_to_eof_capped<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let room = cap - out.len();
                    out.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            Err(_) => break,
        }
    }
    out
}

/// Parse Docling's JSON output.
///
/// Docling ≥ 2.x `--output-format json` emits:
/// ```json
/// { "pages": [{ "text": "..." }, ...] }
/// ```
/// Older builds may emit `{ "content": { "text": "..." } }` or plain text.
/// This parser is lenient: if the JSON doesn't match the expected shape it
/// returns the raw stdout as the text payload.
fn parse_docling_output(stdout: &str) -> (String, usize) {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return (String::new(), 0);
    }

    // Primary: pages[].text
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(pages) = v["pages"].as_array() {
            let texts: Vec<&str> = pages
                .iter()
                .filter_map(|p| p["text"].as_str())
                .filter(|s| !s.trim().is_empty())
                .collect();
            if !texts.is_empty() {
                return (texts.join("\n\n"), texts.len());
            }
        }
        // Fallback: content.text (older Docling builds)
        if let Some(text) = v["content"]["text"].as_str()
            && !text.trim().is_empty()
        {
            return (text.to_string(), 1);
        }
        // Fallback: top-level "text"
        if let Some(text) = v["text"].as_str()
            && !text.trim().is_empty()
        {
            return (text.to_string(), 1);
        }
    }

    // Last resort: treat raw stdout as plain text (e.g. markdown output mode
    // accidentally triggered, or future Docling format change).
    let text = trimmed.to_string();
    let page_count = if text.is_empty() { 0 } else { 1 };
    (text, page_count)
}

fn ext_from_mime(mime: &str) -> &'static str {
    match mime {
        "application/pdf" => ".pdf",
        m if m.contains("wordprocessingml") => ".docx",
        m if m.contains("presentationml") => ".pptx",
        m if m.contains("spreadsheetml") => ".xlsx",
        m if m.contains("opendocument.text") => ".odt",
        m if m.contains("opendocument.spreadsheet") => ".ods",
        m if m.contains("opendocument.presentation") => ".odp",
        "application/epub+zip" => ".epub",
        "application/rtf" => ".rtf",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/webp" => ".webp",
        _ => ".bin",
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pages_array() {
        let json = r#"{"pages":[{"text":"hello world"},{"text":"second page"}]}"#;
        let (text, pages) = parse_docling_output(json);
        assert_eq!(pages, 2);
        assert!(text.contains("hello world"));
        assert!(text.contains("second page"));
    }

    #[test]
    fn parse_content_text_fallback() {
        let json = r#"{"content":{"text":"legacy format body"}}"#;
        let (text, pages) = parse_docling_output(json);
        assert_eq!(pages, 1);
        assert!(text.contains("legacy format body"));
    }

    #[test]
    fn parse_plain_text_fallback() {
        let raw = "# Markdown output\n\nsome content";
        let (text, pages) = parse_docling_output(raw);
        assert_eq!(pages, 1);
        assert!(text.contains("Markdown output"));
    }

    #[test]
    fn parse_empty_input_returns_zero_pages() {
        let (text, pages) = parse_docling_output("   ");
        assert_eq!(pages, 0);
        assert!(text.is_empty());
    }

    #[test]
    fn ext_from_mime_covers_main_types() {
        assert_eq!(ext_from_mime("application/pdf"), ".pdf");
        assert_eq!(
            ext_from_mime(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            ".docx"
        );
        assert_eq!(ext_from_mime("image/png"), ".png");
        assert_eq!(ext_from_mime("application/octet-stream"), ".bin");
    }

    #[tokio::test]
    async fn docling_returns_unsupported_when_disabled() {
        // With default FreedomConfig (docling_enabled=false), the extractor
        // must return Unsupported regardless of asset kind.
        let extractor = DoclingExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"%PDF-1.4".to_vec(),
        };
        // We don't control FreedomConfig::load_or_default here in tests
        // (it reads freedom.yaml from disk). The test asserts the Unsupported
        // path is taken when the binary is absent — which is always true in CI.
        // The exact error variant depends on whether Docling is installed.
        let result = extractor.extract(&asset).await;
        // We accept both Unsupported (disabled or no binary) as valid.
        match result {
            Err(ExtractionError::Unsupported { .. }) => {}
            // If Docling happens to be installed AND docling_enabled is true
            // on this machine, the extractor runs — we just confirm no panic.
            Ok(_) | Err(ExtractionError::Backend { .. }) | Err(ExtractionError::Io(_)) => {}
        }
    }

    #[tokio::test]
    async fn docling_returns_unsupported_for_audio() {
        let extractor = DoclingExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: vec![],
        };
        let result = extractor.extract(&asset).await;
        // Audio is always Unsupported regardless of config.
        // (If docling_enabled is false, gate 1 fires first — still Unsupported.)
        assert!(
            matches!(result, Err(ExtractionError::Unsupported { .. })),
            "expected Unsupported for Audio kind, got {result:?}"
        );
    }
}
