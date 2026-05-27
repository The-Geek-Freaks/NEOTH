//! SC-15 (Session 24) — email-specific sanitizer.
//!
//! Every EM-* item (Gmail OAuth ingest, Calendar adapter, draft
//! generation) feeds email bodies + attachment filenames into the
//! memory + LLM surface. Plain
//! [`crate::security::ingress_sanitizer::sanitize`] handles text
//! after the email-specific normalisation is done — but emails
//! arrive with MIME quoting + quoted-reply cascades + attachment
//! filenames operators didn't author. SC-15 ships the
//! pre-processing pipeline that runs BEFORE the generic sanitizer.
//!
//! ## Stages (executed in order)
//!
//! 1. **MIME normalize** — collapse CRLF → LF; strip
//!    Content-Type boundary markers; decode quoted-printable
//!    soft-wraps; strip leading `Content-*:` header carriers.
//! 2. **Quoted-reply strip** — remove the cascading "On <date>,
//!    <name> wrote:" / `>` line-prefix block that doubles a
//!    reply's payload + tricks the model into treating ancient
//!    quoted text as fresh instructions.
//! 3. **Attachment filename sanitization** — defends against
//!    path-traversal + extension hijack like `invoice.pdf.exe`,
//!    `..\..\config.yaml`, and Windows reserved names (CON,
//!    PRN, AUX, NUL, COM1-9, LPT1-9).
//!
//! After SC-15 the caller pipes `EmailSanitized::body` through
//! the standard [`crate::security::ingress_sanitizer::sanitize`]
//! and the filename through [`safe_attachment_filename`] for the
//! storage path.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Hard ceiling on attachment filename length AFTER sanitization.
/// Mirrors NTFS/ext4 limits; longer names get truncated with a
/// hash suffix to preserve uniqueness.
pub const MAX_FILENAME_LEN: usize = 200;

/// Windows reserved device names. The OS treats these specially
/// regardless of file extension — a path called `CON.txt` opens
/// the console device, not a file. Operators on cross-platform
/// systems can hit this trap; we sanitize on every platform.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Suspicious double-extensions that operators encounter in
/// phishing payloads. Surfaced as a finding (caller decides
/// whether to drop or just warn).
const SUSPICIOUS_DOUBLE_EXTS: &[(&str, &str)] = &[
    (".pdf", ".exe"),
    (".pdf", ".scr"),
    (".docx", ".exe"),
    (".xlsx", ".exe"),
    (".jpg", ".exe"),
    (".png", ".exe"),
    (".txt", ".exe"),
    (".pdf", ".bat"),
    (".pdf", ".cmd"),
    (".pdf", ".vbs"),
    (".pdf", ".js"),
];

/// Result of [`sanitize_email_body`]. Caller pipes `body` through
/// the standard ingress_sanitizer afterwards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmailSanitized {
    pub body: String,
    pub findings: Vec<EmailFinding>,
}

/// Per-stage diagnostic. Snake_case wire form for stable JSON
/// output across CLI / GUI / audit consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmailFinding {
    CrlfNormalized {
        count: usize,
    },
    QuotedPrintableSoftWrapDecoded,
    MimeBoundaryStripped,
    ContentHeaderStripped {
        header: String,
    },
    QuotedReplyStripped {
        lines: usize,
    },
    FilenamePathTraversal {
        raw: String,
    },
    FilenameWindowsReserved {
        raw: String,
        base: String,
    },
    FilenameSuspiciousDoubleExt {
        raw: String,
        inner: String,
        outer: String,
    },
    FilenameTruncated {
        from: usize,
        to: usize,
    },
}

/// Pipe an email body through stages 1+2. Returns the cleaned
/// text + diagnostics. Caller passes `result.body` to
/// [`crate::security::ingress_sanitizer::sanitize`] for the
/// generic NFKC + prompt-injection scan.
pub fn sanitize_email_body(input: &str) -> EmailSanitized {
    let mut findings = Vec::new();
    let mut body = input.to_string();

    // ── Stage 1a: CRLF → LF ─────────────────────────────────────
    let crlf_count = body.matches("\r\n").count();
    if crlf_count > 0 {
        body = body.replace("\r\n", "\n");
        findings.push(EmailFinding::CrlfNormalized { count: crlf_count });
    }

    // ── Stage 1b: strip MIME boundary lines ────────────────────
    //
    // Runs BEFORE quoted-printable decode (Stage 1c) on purpose:
    // boundary markers end in `==\n` which would partially match
    // the QP soft-wrap pattern `=\n` and turn `==\n` into `=`,
    // mangling whatever follows. Strip the whole boundary line
    // first; QP decode then sees only operator-typed content.
    let boundary_re = "--===============";
    if body.contains(boundary_re) {
        body = body
            .lines()
            .filter(|line| !line.trim_start().starts_with(boundary_re))
            .collect::<Vec<_>>()
            .join("\n");
        findings.push(EmailFinding::MimeBoundaryStripped);
    }

    // ── Stage 1c: Quoted-printable soft-wrap (=\n at line end) ──
    //
    // Tightened from `replace("=\n", "")` to skip when the `=`
    // is preceded by another `=` — `==\n` is operator-typed
    // text (or a leftover from a malformed boundary that Stage
    // 1b missed), not a QP soft-wrap. Real QP wraps only end in
    // a single `=` at column 75-76.
    if body.contains("=\n") {
        let mut out = String::with_capacity(body.len());
        let bytes = body.as_bytes();
        let mut decoded = false;
        let mut i = 0;
        while i < bytes.len() {
            if i + 1 < bytes.len() && bytes[i] == b'=' && bytes[i + 1] == b'\n' {
                // Check the preceding byte — if it's another `=`,
                // this is NOT a QP soft-wrap; keep both characters.
                let preceded_by_equals = i > 0 && bytes[i - 1] == b'=';
                if !preceded_by_equals {
                    // Skip the `=` + the `\n` (soft-wrap unwrap).
                    i += 2;
                    decoded = true;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        if decoded {
            body = out;
            findings.push(EmailFinding::QuotedPrintableSoftWrapDecoded);
        }
    }

    // ── Stage 1d: strip leading Content-* headers ──────────────
    // MIME parts often begin with `Content-Type:` / `Content-
    // Transfer-Encoding:` / `Content-Disposition:` lines that
    // leak into the body when an upstream parser kept them.
    // Strip from the START of the body; once we hit a non-header
    // line, stop (header block ends at the first blank line).
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_header_block = true;
    for line in body.lines() {
        if in_header_block && line.starts_with("Content-") && line.contains(':') {
            let header_name = line
                .split(':')
                .next()
                .unwrap_or("Content-Unknown")
                .to_string();
            findings.push(EmailFinding::ContentHeaderStripped {
                header: header_name,
            });
            continue;
        }
        if in_header_block && line.trim().is_empty() {
            // First blank line ends the header block — drop it
            // too so the body starts cleanly.
            in_header_block = false;
            continue;
        }
        in_header_block = false;
        new_lines.push(line);
    }
    body = new_lines.join("\n");

    // ── Stage 2: quoted-reply strip ────────────────────────────
    // Two patterns covered:
    //   a) "On <date>, <Name> wrote:" / "Am <Datum> schrieb <Name>:"
    //      followed by ≥1 line starting with `>`
    //   b) Bare `>` line-prefix cascade (forwarded inline)
    //
    // The strip removes the attribution line + every subsequent
    // `>`-prefixed line. Lines AFTER the cascade are kept (some
    // operators add P.S. notes below quoted text).
    let (stripped, quoted_lines) = strip_quoted_reply(&body);
    if quoted_lines > 0 {
        body = stripped;
        findings.push(EmailFinding::QuotedReplyStripped {
            lines: quoted_lines,
        });
    }

    EmailSanitized { body, findings }
}

fn strip_quoted_reply(body: &str) -> (String, usize) {
    // Anchor patterns (case-insensitive prefix match per line).
    let attribution_prefixes = [
        "on ", // "On Mon, May 25..."
        "am ", // "Am Montag, ..."
        "el ", // "El lunes, ..."
        "le ", // "Le lundi, ..."
        "il ", // "Il lunedì, ..."
    ];
    let mut output: Vec<&str> = Vec::new();
    let mut quoted_count = 0;
    let mut in_quote_block = false;

    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let lower = trimmed.to_lowercase();

        // Attribution line followed by `>` cascade — strip both.
        let is_attribution = attribution_prefixes.iter().any(|p| lower.starts_with(p))
            && (lower.contains(" wrote:") || lower.contains(" schrieb") || lower.ends_with(':'));
        let next_starts_with_gt = i + 1 < lines.len() && lines[i + 1].trim_start().starts_with('>');
        if is_attribution && next_starts_with_gt {
            quoted_count += 1; // attribution line
            i += 1;
            in_quote_block = true;
            continue;
        }
        // Bare `>` prefix line in a quote block — strip.
        if trimmed.starts_with('>') {
            quoted_count += 1;
            in_quote_block = true;
            i += 1;
            continue;
        }
        // End of quote block — operator may have notes after.
        if in_quote_block && trimmed.is_empty() {
            // Skip the blank separator too so the operator's text
            // starts at column 0.
            quoted_count += 1;
            i += 1;
            continue;
        }
        in_quote_block = false;
        output.push(line);
        i += 1;
    }
    (output.join("\n"), quoted_count)
}

/// Stage 3 — sanitize ONE attachment filename. Returns
/// `(safe_name, findings)`. The safe name is suitable for use
/// as the basename of a path under the operator's attachment
/// store; the caller still composes the full path.
///
/// Defends against:
/// - Path traversal (`../`, `..\\`, absolute paths)
/// - Windows reserved names (CON, NUL, COM1, etc.)
/// - Suspicious double-extensions (`invoice.pdf.exe`)
/// - Overlong filenames (truncate with hash suffix to preserve
///   uniqueness across truncated collisions)
pub fn safe_attachment_filename(raw: &str) -> (String, Vec<EmailFinding>) {
    let mut findings = Vec::new();

    // Step 1: strip any path component — take basename only.
    // `Path::file_name` on a `\\`-separated string returns the whole
    // string on Unix targets (the path crate honors `/` only there),
    // which lets a crafted email attachment `..\..\Windows\config`
    // slip through the traversal check on a Linux operator's mail
    // pipeline. Pre-split on BOTH separators before handing to Path.
    let pre_basename: &str = raw
        .rsplit(|c: char| c == '/' || c == '\\')
        .next()
        .unwrap_or("");
    // Path::file_name returns None for `..`, `.`, `/`, and `""`. In
    // those cases we keep the previous "" fallback so a literal `..`
    // input still funnels to `untitled` rather than leaking the
    // traversal marker into the output filename.
    let basename = Path::new(pre_basename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let had_path = basename != raw;
    if had_path || raw.contains("..") {
        findings.push(EmailFinding::FilenamePathTraversal {
            raw: raw.to_string(),
        });
    }

    // Step 2: rebase if empty (e.g. raw was "/" or "..").
    let mut name = if basename.is_empty() {
        "untitled".to_string()
    } else {
        basename
    };

    // Step 3: check Windows reserved names. Compare against the
    // stem (part before the last extension) so `CON.txt` flags too.
    let stem = Path::new(&name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        findings.push(EmailFinding::FilenameWindowsReserved {
            raw: raw.to_string(),
            base: stem.clone(),
        });
        name = format!("safe_{name}");
    }

    // Step 4: suspicious double-extension scan.
    let lower = name.to_lowercase();
    for (inner, outer) in SUSPICIOUS_DOUBLE_EXTS {
        if lower.ends_with(outer) && lower.contains(inner) {
            // Verify the inner extension actually appears BEFORE
            // the outer one (not just anywhere in the string).
            let inner_pos = lower.rfind(inner);
            let outer_pos = lower.rfind(outer);
            if let (Some(ip), Some(op)) = (inner_pos, outer_pos) {
                if ip < op {
                    findings.push(EmailFinding::FilenameSuspiciousDoubleExt {
                        raw: raw.to_string(),
                        inner: inner.to_string(),
                        outer: outer.to_string(),
                    });
                    // Rewrite the outer extension to `.bin` so the
                    // operator's mailer + OS don't auto-execute it.
                    name = format!("{}.bin", &name[..name.len() - outer.len()]);
                    break;
                }
            }
        }
    }

    // Step 5: truncate if overlong. Preserve the extension +
    // append a short hash so collisions don't masquerade.
    if name.len() > MAX_FILENAME_LEN {
        let original_len = name.len();
        let ext = Path::new(&name)
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default();
        let hash = format!("_{:08x}", xxhash_rust::xxh3::xxh3_64(name.as_bytes()));
        let budget = MAX_FILENAME_LEN.saturating_sub(hash.len() + ext.len());
        let stem_safe: String = name.chars().take(budget).collect();
        name = format!("{stem_safe}{hash}{ext}");
        findings.push(EmailFinding::FilenameTruncated {
            from: original_len,
            to: name.len(),
        });
    }

    (name, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_email_body: MIME normalize ───────────────────────────

    #[test]
    fn crlf_collapses_to_lf() {
        let r = sanitize_email_body("line1\r\nline2\r\nline3");
        assert_eq!(r.body, "line1\nline2\nline3");
        assert!(matches!(
            r.findings[0],
            EmailFinding::CrlfNormalized { count: 2 },
        ));
    }

    #[test]
    fn quoted_printable_soft_wrap_decoded() {
        // `=\n` at line end is QP's soft-wrap marker; it should be
        // removed so the body reads as the operator typed it.
        let r = sanitize_email_body("hello wo=\nrld");
        assert_eq!(r.body, "hello world");
        assert!(
            r.findings
                .iter()
                .any(|f| matches!(f, EmailFinding::QuotedPrintableSoftWrapDecoded))
        );
    }

    #[test]
    fn mime_boundary_lines_stripped() {
        let raw = "--===============1234==\nfirst part\n--===============1234==\nsecond";
        let r = sanitize_email_body(raw);
        assert!(!r.body.contains("==="), "body: {:?}", r.body);
        assert!(r.body.contains("first part"), "body: {:?}", r.body);
        assert!(r.body.contains("second"), "body: {:?}", r.body);
        assert!(
            r.findings
                .iter()
                .any(|f| matches!(f, EmailFinding::MimeBoundaryStripped))
        );
    }

    #[test]
    fn content_headers_at_start_stripped() {
        let raw = "Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n\nactual body here";
        let r = sanitize_email_body(raw);
        assert_eq!(r.body, "actual body here");
        let header_findings: Vec<_> = r
            .findings
            .iter()
            .filter(|f| matches!(f, EmailFinding::ContentHeaderStripped { .. }))
            .collect();
        assert_eq!(header_findings.len(), 2);
    }

    #[test]
    fn content_header_inside_body_not_stripped() {
        // A `Content-Type:` line in the middle of the body (not the
        // leading header block) is operator text, not a header. Must
        // survive.
        let raw = "first line\n\nContent-Type: i quoted this in my email";
        let r = sanitize_email_body(raw);
        assert!(r.body.contains("Content-Type: i quoted"));
    }

    // ── sanitize_email_body: quoted-reply strip ───────────────────────

    #[test]
    fn english_quoted_reply_block_stripped() {
        let raw = "thanks for the update\n\nOn Mon, May 25 2026, Alex <a@x> wrote:\n> hello\n> how are you\n> i wanted to ask";
        let r = sanitize_email_body(raw);
        assert!(r.body.contains("thanks for the update"));
        assert!(!r.body.contains("hello"));
        assert!(!r.body.contains("how are you"));
        assert!(
            r.findings
                .iter()
                .any(|f| matches!(f, EmailFinding::QuotedReplyStripped { .. }))
        );
    }

    #[test]
    fn german_quoted_reply_block_stripped() {
        let raw = "danke fuer die antwort\n\nAm 25.05.2026 schrieb Alex:\n> hallo\n> bis bald";
        let r = sanitize_email_body(raw);
        assert!(r.body.contains("danke fuer die antwort"));
        assert!(!r.body.contains("hallo"));
        assert!(!r.body.contains("bis bald"));
    }

    #[test]
    fn bare_gt_prefix_cascade_stripped() {
        // No attribution line — just a bare `>` cascade (inline forward).
        let raw = "P.S. forgot to mention\n\n> ancient text\n> more ancient";
        let r = sanitize_email_body(raw);
        assert!(r.body.contains("P.S. forgot"));
        assert!(!r.body.contains("ancient"));
    }

    #[test]
    fn ps_after_quoted_block_survives() {
        // Operator typed a P.S. AFTER the quoted block. The
        // quoted-reply stripper must leave it intact.
        let raw = "Reply text\n\nOn Mon, Alex wrote:\n> old text\n> more\n\nP.S. one more thing";
        let r = sanitize_email_body(raw);
        assert!(r.body.contains("Reply text"));
        assert!(r.body.contains("P.S. one more thing"));
        assert!(!r.body.contains("old text"));
    }

    #[test]
    fn no_quoted_block_produces_no_finding() {
        let r = sanitize_email_body("plain message, no quotes");
        assert_eq!(r.body, "plain message, no quotes");
        assert!(
            !r.findings
                .iter()
                .any(|f| matches!(f, EmailFinding::QuotedReplyStripped { .. }))
        );
    }

    // ── safe_attachment_filename ──────────────────────────────────────

    #[test]
    fn ordinary_filename_passes_through_unchanged() {
        let (n, f) = safe_attachment_filename("invoice.pdf");
        assert_eq!(n, "invoice.pdf");
        assert!(f.is_empty());
    }

    #[test]
    fn path_traversal_stripped_to_basename() {
        let (n, f) = safe_attachment_filename("../../etc/passwd");
        assert_eq!(n, "passwd");
        assert!(
            f.iter()
                .any(|x| matches!(x, EmailFinding::FilenamePathTraversal { .. }))
        );
    }

    #[test]
    fn windows_path_traversal_stripped() {
        let (n, f) = safe_attachment_filename(r"..\..\Windows\config");
        // Path::file_name on a backslash path returns the full
        // string on unix targets; on windows targets it returns
        // "config". Either way it must NOT contain `..`.
        assert!(!n.contains(".."), "got: {n}");
        assert!(
            f.iter()
                .any(|x| matches!(x, EmailFinding::FilenamePathTraversal { .. }))
        );
    }

    #[test]
    fn windows_reserved_name_prefixed_safe() {
        let (n, f) = safe_attachment_filename("CON.txt");
        assert!(n.starts_with("safe_"));
        assert!(
            f.iter()
                .any(|x| matches!(x, EmailFinding::FilenameWindowsReserved { .. }))
        );
    }

    #[test]
    fn windows_reserved_lpt_and_com_caught() {
        for raw in &["COM1", "LPT9", "NUL.dat", "AUX"] {
            let (n, f) = safe_attachment_filename(raw);
            assert!(
                n.starts_with("safe_"),
                "expected safe_ prefix for {raw:?}, got {n:?}",
            );
            assert!(
                f.iter()
                    .any(|x| matches!(x, EmailFinding::FilenameWindowsReserved { .. })),
                "no Windows-reserved finding for {raw:?}",
            );
        }
    }

    #[test]
    fn suspicious_double_extension_rewritten_to_bin() {
        let (n, f) = safe_attachment_filename("invoice.pdf.exe");
        assert!(n.ends_with(".bin"));
        assert!(n.contains(".pdf"));
        assert!(
            f.iter()
                .any(|x| matches!(x, EmailFinding::FilenameSuspiciousDoubleExt { .. }))
        );
    }

    #[test]
    fn benign_single_extension_not_flagged() {
        // `.pdf` alone, `.txt` alone, etc. must NOT trigger the
        // double-ext finding (false-positive guard).
        for raw in &["report.pdf", "notes.txt", "image.png"] {
            let (n, f) = safe_attachment_filename(raw);
            assert_eq!(n, *raw, "name must pass through: {raw}");
            assert!(
                !f.iter()
                    .any(|x| matches!(x, EmailFinding::FilenameSuspiciousDoubleExt { .. })),
                "false-positive double-ext on {raw:?}",
            );
        }
    }

    #[test]
    fn overlong_filename_truncated_with_hash() {
        let long = "a".repeat(MAX_FILENAME_LEN + 100);
        let raw = format!("{long}.pdf");
        let (n, f) = safe_attachment_filename(&raw);
        assert!(n.len() <= MAX_FILENAME_LEN);
        assert!(n.ends_with(".pdf"));
        assert!(n.contains('_'), "truncation must include hash suffix: {n}");
        assert!(
            f.iter()
                .any(|x| matches!(x, EmailFinding::FilenameTruncated { .. }))
        );
    }

    #[test]
    fn empty_filename_becomes_untitled() {
        let (n, _) = safe_attachment_filename("");
        assert_eq!(n, "untitled");
        let (n2, _) = safe_attachment_filename("/");
        assert_eq!(n2, "untitled");
    }

    #[test]
    fn case_insensitive_windows_reserved_match() {
        // `con.txt` (lowercase) is the same trap as `CON.txt`.
        let (n, _) = safe_attachment_filename("con.txt");
        assert!(n.starts_with("safe_"));
    }
}
