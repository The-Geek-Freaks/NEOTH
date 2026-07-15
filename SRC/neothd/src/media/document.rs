//! Office-document backend — PF-03.
//!
//! Reads the common office/e-book formats to plain text for ingest into
//! recall / paperless. PDF stays in [`super::pdf`] (image-aware via
//! `pdf-extract`); this backend covers the rest:
//!
//! | Format            | Ext    | Source                              |
//! |-------------------|--------|-------------------------------------|
//! | Word / OOXML      | `docx` | `word/document.xml`                 |
//! | PowerPoint        | `pptx` | `ppt/slides/slideN.xml` (in order)  |
//! | Excel             | `xlsx` | `xl/sharedStrings.xml`              |
//! | OpenDocument      | `odt` `ods` `odp` | `content.xml`            |
//! | EPUB              | `epub` | every XHTML in the archive (sorted) |
//! | Rich Text         | `rtf`  | control-word stripper (not a zip)   |
//!
//! Strategy: every zip-based format is OOXML/ODF/XHTML XML under the hood,
//! so a single tag-stripper (`xml_body_text`) handles them all — we only
//! vary which archive member(s) we read and which tags map to a line
//! break. Pure Rust, reusing the `zip` crate already in the tree; no new
//! dependency. RTF is the one non-zip format and gets its own
//! control-word stripper.
//!
//! Limitations (first slice — read only):
//!   - XLSX reads shared strings only (cell labels/text), not computed
//!     numeric cells or inline strings.
//!   - No style/layout preservation — output is paragraph-separated text.
//!   - No image OCR inside documents.

use std::io::{Cursor, Read};
use std::path::Path;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Per-member read cap — guards against a zip-bomb member inflating to
/// gigabytes. 64 MiB is comfortably above any real document part.
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
/// Total extracted-text cap handed downstream. Truncated with a marker
/// rather than streamed — recall/ingest reason over a bounded blob.
const MAX_TOTAL_TEXT: usize = 8 * 1024 * 1024;

pub struct DocumentExtractor;

#[async_trait::async_trait]
impl MediaExtractor for DocumentExtractor {
    fn name(&self) -> &'static str {
        "document"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Document {
            return Err(ExtractionError::Unsupported {
                backend: "document",
                got: asset.kind(),
            });
        }
        // Parsing is sync + CPU/IO-bound; keep the reactor free.
        let payload = asset.clone();
        tokio::task::spawn_blocking(move || extract_blocking(&payload))
            .await
            .map_err(|e| ExtractionError::Backend {
                backend: "document",
                reason: format!("join error: {e}"),
            })?
    }
}

/// The document formats this backend understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocFormat {
    Docx,
    Pptx,
    Xlsx,
    Odt,
    Ods,
    Odp,
    Epub,
    Rtf,
}

impl DocFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            DocFormat::Docx => "docx",
            DocFormat::Pptx => "pptx",
            DocFormat::Xlsx => "xlsx",
            DocFormat::Odt => "odt",
            DocFormat::Ods => "ods",
            DocFormat::Odp => "odp",
            DocFormat::Epub => "epub",
            DocFormat::Rtf => "rtf",
        }
    }

    pub fn from_mime(mime: &str) -> Option<Self> {
        // Match on the bare type, ignoring any `; charset=` suffix.
        let bare = mime.split(';').next().unwrap_or(mime).trim();
        Some(match bare {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
                DocFormat::Docx
            }
            "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
                DocFormat::Pptx
            }
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => DocFormat::Xlsx,
            "application/vnd.oasis.opendocument.text" => DocFormat::Odt,
            "application/vnd.oasis.opendocument.spreadsheet" => DocFormat::Ods,
            "application/vnd.oasis.opendocument.presentation" => DocFormat::Odp,
            "application/epub+zip" => DocFormat::Epub,
            "application/rtf" | "text/rtf" => DocFormat::Rtf,
            _ => return None,
        })
    }

    pub fn from_ext(ext: &str) -> Option<Self> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "docx" => DocFormat::Docx,
            "pptx" => DocFormat::Pptx,
            "xlsx" => DocFormat::Xlsx,
            "odt" => DocFormat::Odt,
            "ods" => DocFormat::Ods,
            "odp" => DocFormat::Odp,
            "epub" => DocFormat::Epub,
            "rtf" => DocFormat::Rtf,
            _ => return None,
        })
    }

    fn is_zip(self) -> bool {
        !matches!(self, DocFormat::Rtf)
    }
}

fn extract_blocking(asset: &Asset) -> Result<Extraction, ExtractionError> {
    let fmt = detect_format(asset).ok_or_else(|| ExtractionError::Backend {
        backend: "document",
        reason: "unrecognised document format (mime + extension both unknown)".into(),
    })?;
    let bytes = read_asset_bytes(asset)?;

    let mut text = if fmt.is_zip() {
        extract_zip_text(&bytes, fmt)?
    } else {
        rtf_to_text(&bytes)
    };
    let truncated = text.len() > MAX_TOTAL_TEXT;
    if truncated {
        let safe = crate::util::byte_floor(&text, MAX_TOTAL_TEXT);
        text.truncate(safe);
        text.push_str("\n[NEOTH] …document truncated at extraction cap…");
    }

    let stats = compute_stats(&text);
    Ok(Extraction {
        text,
        metadata: serde_json::json!({
            "extractor": "document",
            "format": fmt.as_str(),
            "char_count": stats.0,
            "word_count": stats.1,
            "line_count": stats.2,
            "truncated": truncated,
        }),
    })
}

/// mime first (the channel layer sets a precise OOXML/ODF mime), then
/// fall back to the path extension for `neoth ingest file.docx`.
fn detect_format(asset: &Asset) -> Option<DocFormat> {
    if let Some(f) = DocFormat::from_mime(asset.mime()) {
        return Some(f);
    }
    if let Asset::Path { path, .. } = asset
        && let Some(ext) = path.extension().and_then(|e| e.to_str())
    {
        return DocFormat::from_ext(ext);
    }
    None
}

fn read_asset_bytes(asset: &Asset) -> Result<Vec<u8>, ExtractionError> {
    match asset {
        Asset::Bytes { data, .. } => Ok(data.clone()),
        Asset::Path { path, .. } => read_path(path),
    }
}

fn read_path(path: &Path) -> Result<Vec<u8>, ExtractionError> {
    std::fs::read(path).map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display())))
}

// ── zip-based extraction ──────────────────────────────────────────────

type Archive = zip::ZipArchive<Cursor<Vec<u8>>>;

fn extract_zip_text(bytes: &[u8], fmt: DocFormat) -> Result<String, ExtractionError> {
    let cursor = Cursor::new(bytes.to_vec());
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::Backend {
        backend: "document",
        reason: format!("open {} archive: {e}", fmt.as_str()),
    })?;

    match fmt {
        DocFormat::Docx => {
            let xml = read_member(&mut archive, "word/document.xml")?
                .ok_or_else(missing("docx", "word/document.xml"))?;
            Ok(xml_body_text(&xml, DOCX_BREAKS))
        }
        DocFormat::Pptx => {
            let mut names = member_names(&archive);
            names.retain(|n| is_slide(n));
            names.sort_by_key(|n| slide_number(n));
            let mut out = String::new();
            for name in names {
                if let Some(xml) = read_member(&mut archive, &name)? {
                    push_section(&mut out, &xml_body_text(&xml, PPTX_BREAKS));
                }
            }
            Ok(out)
        }
        DocFormat::Xlsx => {
            // Shared strings hold the text labels; numeric-only sheets
            // legitimately yield empty text.
            match read_member(&mut archive, "xl/sharedStrings.xml")? {
                Some(xml) => Ok(xml_body_text(&xml, XLSX_BREAKS)),
                None => Ok(String::new()),
            }
        }
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp => {
            let xml = read_member(&mut archive, "content.xml")?
                .ok_or_else(missing(fmt.as_str(), "content.xml"))?;
            Ok(xml_body_text(&xml, ODF_BREAKS))
        }
        DocFormat::Epub => {
            let mut names = member_names(&archive);
            names.retain(|n| is_xhtml(n));
            names.sort();
            let mut out = String::new();
            for name in names {
                if let Some(xml) = read_member(&mut archive, &name)? {
                    push_section(&mut out, &xml_body_text(&xml, HTML_BREAKS));
                }
            }
            Ok(out)
        }
        DocFormat::Rtf => unreachable!("rtf is not zip-based"),
    }
}

fn missing(fmt: &'static str, member: &'static str) -> impl Fn() -> ExtractionError {
    move || ExtractionError::Backend {
        backend: "document",
        reason: format!("{fmt} archive missing expected member `{member}`"),
    }
}

fn member_names(archive: &Archive) -> Vec<String> {
    archive.file_names().map(|s| s.to_string()).collect()
}

fn read_member(archive: &mut Archive, name: &str) -> Result<Option<String>, ExtractionError> {
    match archive.by_name(name) {
        Ok(file) => {
            let mut buf = String::new();
            file.take(MAX_MEMBER_BYTES)
                .read_to_string(&mut buf)
                .map_err(|e| ExtractionError::Backend {
                    backend: "document",
                    reason: format!("read member `{name}`: {e}"),
                })?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(ExtractionError::Backend {
            backend: "document",
            reason: format!("open member `{name}`: {e}"),
        }),
    }
}

fn is_slide(name: &str) -> bool {
    name.starts_with("ppt/slides/slide") && name.ends_with(".xml")
}

/// Pull the slide ordinal out of `ppt/slides/slideN.xml` so `slide10`
/// sorts after `slide2` (lexical sort would invert them).
fn slide_number(name: &str) -> u32 {
    name.rsplit('/')
        .next()
        .unwrap_or(name)
        .trim_start_matches("slide")
        .trim_end_matches(".xml")
        .parse()
        .unwrap_or(u32::MAX)
}

fn is_xhtml(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xhtml") || lower.ends_with(".html") || lower.ends_with(".htm")
}

fn push_section(out: &mut String, section: &str) {
    let section = section.trim();
    if section.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(section);
}

// ── XML → text ────────────────────────────────────────────────────────

/// (literal-tag, replacement) pairs applied *before* the generic
/// tag-strip so paragraph/line boundaries survive as real whitespace.
type Breaks = &'static [(&'static str, &'static str)];

const DOCX_BREAKS: Breaks = &[
    ("</w:p>", "\n"),
    ("<w:br/>", "\n"),
    ("<w:br />", "\n"),
    ("<w:tab/>", "\t"),
    ("<w:tab />", "\t"),
    ("</w:tr>", "\n"),
];
const PPTX_BREAKS: Breaks = &[("</a:p>", "\n"), ("<a:br/>", "\n"), ("<a:br />", "\n")];
const XLSX_BREAKS: Breaks = &[("</si>", "\n")];
const ODF_BREAKS: Breaks = &[
    ("</text:p>", "\n"),
    ("</text:h>", "\n"),
    ("<text:line-break/>", "\n"),
    ("<text:tab/>", "\t"),
    ("</table:table-row>", "\n"),
];
const HTML_BREAKS: Breaks = &[
    ("</p>", "\n"),
    ("<br/>", "\n"),
    ("<br />", "\n"),
    ("<br>", "\n"),
    ("</div>", "\n"),
    ("</li>", "\n"),
    ("</tr>", "\n"),
    ("</h1>", "\n"),
    ("</h2>", "\n"),
    ("</h3>", "\n"),
    ("</h4>", "\n"),
    ("</h5>", "\n"),
    ("</h6>", "\n"),
];

/// Turn a fragment of OOXML/ODF/XHTML into plain text: insert line breaks
/// at structural tags, strip every remaining `<…>` span, decode XML
/// entities in the text nodes, then normalise whitespace. Tag attributes
/// never leak because they live between `<` and `>`.
fn xml_body_text(xml: &str, breaks: Breaks) -> String {
    let mut s = std::borrow::Cow::Borrowed(xml);
    for (lit, rep) in breaks {
        if s.contains(lit) {
            s = std::borrow::Cow::Owned(s.replace(lit, rep));
        }
    }
    let stripped = strip_tags(&s);
    let decoded = decode_entities(&stripped);
    normalize_ws(&decoded)
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some(semi) = s[i..].find(';').map(|rel| i + rel)
            && semi - i <= 12
        {
            let entity = &s[i + 1..semi];
            if let Some(ch) = decode_one_entity(entity) {
                out.push(ch);
                i = semi + 1;
                continue;
            }
        }
        // Not a recognised entity — copy the byte's char.
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn decode_one_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        _ => {
            let num = entity.strip_prefix('#')?;
            let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                num.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

/// Trim trailing space per line and collapse 3+ blank lines to one.
fn normalize_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank_run = 0u32;
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank_run += 1;
            if blank_run <= 1 {
                out.push('\n');
            }
        } else {
            blank_run = 0;
            out.push_str(trimmed);
            out.push('\n');
        }
    }
    out.trim().to_string()
}

// ── RTF ───────────────────────────────────────────────────────────────

/// Groups whose entire content is metadata, not body text. When the
/// first control word inside a `{…}` group is one of these, the whole
/// group is skipped.
const RTF_SKIP_GROUPS: &[&str] = &[
    "fonttbl",
    "colortbl",
    "stylesheet",
    "info",
    "pict",
    "object",
    "themedata",
    "colorschememapping",
    "latentstyles",
    "datastore",
    "operator",
];

/// Strip RTF to plain text. Not a full RTF reader — emits run text,
/// maps `\par`/`\line` to newlines and `\tab` to tabs, decodes `\'xx`
/// (cp1252) and `\uN` unicode escapes, and skips font/color/style
/// metadata groups + any `{\*…}` ignorable destination.
fn rtf_to_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len());
    // Stack of "are we skipping this group?" flags, one per `{` depth.
    let mut skip_stack: Vec<bool> = vec![false];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '{' => {
                let parent = *skip_stack.last().unwrap_or(&false);
                skip_stack.push(parent);
                i += 1;
            }
            '}' => {
                if skip_stack.len() > 1 {
                    skip_stack.pop();
                }
                i += 1;
            }
            '\\' => {
                i = handle_rtf_control(&chars, i, &mut out, &mut skip_stack);
            }
            '\r' | '\n' => {
                // Raw line breaks in RTF source are not body text.
                i += 1;
            }
            _ => {
                if !*skip_stack.last().unwrap_or(&false) {
                    out.push(c);
                }
                i += 1;
            }
        }
    }
    normalize_ws(&out)
}

/// Handle a backslash control starting at `i` (which points at `\`).
/// Returns the index of the next unconsumed char.
fn handle_rtf_control(
    chars: &[char],
    i: usize,
    out: &mut String,
    skip_stack: &mut [bool],
) -> usize {
    let next = chars.get(i + 1).copied();
    let skipping = *skip_stack.last().unwrap_or(&false);
    match next {
        // Escaped literals are always body text.
        Some('\\') | Some('{') | Some('}') => {
            if !skipping {
                out.push(next.unwrap());
            }
            i + 2
        }
        // `\'xx` — hex byte in the current code page (assume cp1252).
        Some('\'') => {
            let h1 = chars.get(i + 2).copied();
            let h2 = chars.get(i + 3).copied();
            if let (Some(a), Some(b)) = (h1, h2)
                && let Ok(byte) = u8::from_str_radix(&format!("{a}{b}"), 16)
            {
                if !skipping {
                    out.push(cp1252_to_char(byte));
                }
                return i + 4;
            }
            i + 2
        }
        // `\*` — ignorable destination; mark this group skipped.
        Some('*') => {
            if let Some(top) = skip_stack.last_mut() {
                *top = true;
            }
            i + 2
        }
        Some(c) if c.is_ascii_alphabetic() => {
            // Read the control word + optional numeric parameter.
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_ascii_alphabetic() {
                j += 1;
            }
            let word: String = chars[i + 1..j].iter().collect();
            // Optional signed numeric parameter.
            let mut param = String::new();
            if j < chars.len() && (chars[j] == '-' || chars[j].is_ascii_digit()) {
                if chars[j] == '-' {
                    param.push('-');
                    j += 1;
                }
                while j < chars.len() && chars[j].is_ascii_digit() {
                    param.push(chars[j]);
                    j += 1;
                }
            }
            // A single trailing space is the delimiter and is consumed.
            if j < chars.len() && chars[j] == ' ' {
                j += 1;
            }

            // If this control word is the first token of the group and
            // names a metadata destination, skip the whole group.
            if RTF_SKIP_GROUPS.contains(&word.as_str()) {
                if let Some(top) = skip_stack.last_mut() {
                    *top = true;
                }
                return j;
            }

            if !skipping {
                apply_rtf_word(&word, &param, out);
            }

            // `\uN` is followed by a fallback char we must discard.
            if word == "u"
                && let Some(&fb) = chars.get(j)
                && fb != '\\'
                && fb != '{'
                && fb != '}'
            {
                j += 1;
            }
            j
        }
        _ => i + 1,
    }
}

fn apply_rtf_word(word: &str, param: &str, out: &mut String) {
    match word {
        "par" | "line" | "sect" => out.push('\n'),
        "tab" => out.push('\t'),
        "u" => {
            if let Ok(code) = param.parse::<i32>() {
                let code = if code < 0 {
                    (code + 65536) as u32
                } else {
                    code as u32
                };
                if let Some(ch) = char::from_u32(code) {
                    out.push(ch);
                }
            }
        }
        _ => {}
    }
}

/// Decode the cp1252-specific bytes (0x80–0x9F) plus latin1 for the
/// rest. Covers smart quotes / dashes that RTF emits via `\'xx`.
fn cp1252_to_char(byte: u8) -> char {
    match byte {
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        other => other as char,
    }
}

fn compute_stats(text: &str) -> (usize, usize, usize) {
    (
        text.chars().count(),
        text.split_whitespace().count(),
        text.lines().count(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(members: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, content) in members {
            w.start_file::<_, ()>(*name, opts).unwrap();
            w.write_all(content.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn doc_asset(mime: &str, data: Vec<u8>) -> Asset {
        Asset::Bytes {
            kind: AssetKind::Document,
            mime: mime.into(),
            data,
        }
    }

    const DOCX_MIME: &str =
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    const PPTX_MIME: &str =
        "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    const XLSX_MIME: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    const EPUB_MIME: &str = "application/epub+zip";

    // ── format detection ──────────────────────────────────────────────

    #[test]
    fn from_mime_covers_all_known_types() {
        assert_eq!(DocFormat::from_mime(DOCX_MIME), Some(DocFormat::Docx));
        assert_eq!(DocFormat::from_mime(PPTX_MIME), Some(DocFormat::Pptx));
        assert_eq!(DocFormat::from_mime(XLSX_MIME), Some(DocFormat::Xlsx));
        assert_eq!(DocFormat::from_mime(EPUB_MIME), Some(DocFormat::Epub));
        assert_eq!(
            DocFormat::from_mime("application/rtf"),
            Some(DocFormat::Rtf)
        );
        assert_eq!(DocFormat::from_mime("text/rtf"), Some(DocFormat::Rtf));
        assert_eq!(DocFormat::from_mime("application/pdf"), None);
    }

    #[test]
    fn from_mime_ignores_charset_suffix() {
        assert_eq!(
            DocFormat::from_mime("application/rtf; charset=utf-8"),
            Some(DocFormat::Rtf)
        );
    }

    #[test]
    fn from_ext_round_trips() {
        for (ext, want) in [
            ("docx", DocFormat::Docx),
            ("PPTX", DocFormat::Pptx),
            ("xlsx", DocFormat::Xlsx),
            ("odt", DocFormat::Odt),
            ("ods", DocFormat::Ods),
            ("odp", DocFormat::Odp),
            ("epub", DocFormat::Epub),
            ("rtf", DocFormat::Rtf),
        ] {
            assert_eq!(DocFormat::from_ext(ext), Some(want), "ext {ext}");
        }
        assert_eq!(DocFormat::from_ext("bin"), None);
    }

    // ── xml helpers ───────────────────────────────────────────────────

    #[test]
    fn strip_tags_removes_markup_keeps_text() {
        assert_eq!(strip_tags("<a href=\"x\">hi</a>there"), "hithere");
    }

    #[test]
    fn decode_entities_handles_named_and_numeric() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_entities("&#65;&#x42;"), "AB");
        assert_eq!(decode_entities("plain"), "plain");
    }

    #[test]
    fn decode_entities_leaves_unknown_amp_alone() {
        assert_eq!(decode_entities("Q&A session"), "Q&A session");
    }

    #[test]
    fn normalize_ws_collapses_blank_runs() {
        assert_eq!(normalize_ws("a\n\n\n\nb"), "a\n\nb");
        assert_eq!(normalize_ws("  x  \n  y  "), "x\ny");
    }

    // ── docx ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn docx_extracts_paragraph_text() {
        let xml = "<?xml version=\"1.0\"?><w:document xmlns:w=\"ns\"><w:body>\
            <w:p><w:r><w:t>Hello</w:t></w:r></w:p>\
            <w:p><w:r><w:t>World &amp; more</w:t></w:r></w:p>\
            </w:body></w:document>";
        let zip = make_zip(&[("word/document.xml", xml)]);
        let out = DocumentExtractor
            .extract(&doc_asset(DOCX_MIME, zip))
            .await
            .unwrap();
        assert_eq!(out.text, "Hello\nWorld & more");
        assert_eq!(out.metadata["format"], "docx");
        assert_eq!(out.metadata["truncated"], false);
    }

    #[tokio::test]
    async fn docx_missing_document_xml_errors() {
        let zip = make_zip(&[("word/other.xml", "<x/>")]);
        let err = DocumentExtractor
            .extract(&doc_asset(DOCX_MIME, zip))
            .await
            .unwrap_err();
        assert!(matches!(err, ExtractionError::Backend { .. }), "{err:?}");
    }

    // ── pptx (slide ordering) ─────────────────────────────────────────

    #[tokio::test]
    async fn pptx_reads_slides_in_numeric_order() {
        let slide = |t: &str| format!("<p:sld><a:p><a:r><a:t>{t}</a:t></a:r></a:p></p:sld>");
        // Insert slide10 before slide2 to prove numeric (not lexical) sort.
        let zip = make_zip(&[
            ("ppt/slides/slide1.xml", &slide("one")),
            ("ppt/slides/slide10.xml", &slide("ten")),
            ("ppt/slides/slide2.xml", &slide("two")),
        ]);
        let out = DocumentExtractor
            .extract(&doc_asset(PPTX_MIME, zip))
            .await
            .unwrap();
        assert_eq!(out.text, "one\n\ntwo\n\nten");
    }

    // ── xlsx ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn xlsx_reads_shared_strings() {
        let xml = "<sst><si><t>Apple</t></si><si><t>Banana</t></si></sst>";
        let zip = make_zip(&[("xl/sharedStrings.xml", xml)]);
        let out = DocumentExtractor
            .extract(&doc_asset(XLSX_MIME, zip))
            .await
            .unwrap();
        assert_eq!(out.text, "Apple\nBanana");
    }

    #[tokio::test]
    async fn xlsx_without_shared_strings_is_empty_not_error() {
        let zip = make_zip(&[("xl/worksheets/sheet1.xml", "<worksheet/>")]);
        let out = DocumentExtractor
            .extract(&doc_asset(XLSX_MIME, zip))
            .await
            .unwrap();
        assert_eq!(out.text, "");
    }

    // ── odt ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn odt_extracts_content_xml() {
        let xml = "<office:document-content><office:body><office:text>\
            <text:p>Para one</text:p><text:p>Para two</text:p>\
            </office:text></office:body></office:document-content>";
        let zip = make_zip(&[("content.xml", xml)]);
        let out = DocumentExtractor
            .extract(&doc_asset("application/vnd.oasis.opendocument.text", zip))
            .await
            .unwrap();
        assert_eq!(out.text, "Para one\nPara two");
    }

    // ── epub ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn epub_concatenates_xhtml_in_order() {
        let ch = |t: &str| format!("<html><body><p>{t}</p></body></html>");
        let zip = make_zip(&[
            ("mimetype", "application/epub+zip"),
            ("OEBPS/ch1.xhtml", &ch("Chapter one")),
            ("OEBPS/ch2.xhtml", &ch("Chapter two")),
            ("META-INF/container.xml", "<container/>"),
        ]);
        let out = DocumentExtractor
            .extract(&doc_asset(EPUB_MIME, zip))
            .await
            .unwrap();
        assert_eq!(out.text, "Chapter one\n\nChapter two");
    }

    // ── rtf ───────────────────────────────────────────────────────────

    #[test]
    fn rtf_strips_control_words_and_metadata() {
        let rtf = r"{\rtf1\ansi\deff0 {\fonttbl{\f0\fnil Arial;}}\f0 Hello\par World\par}";
        assert_eq!(rtf_to_text(rtf.as_bytes()), "Hello\nWorld");
    }

    #[test]
    fn rtf_decodes_hex_and_unicode_escapes() {
        // \'e9 = é (cp1252), \u233? = é via unicode with '?' fallback.
        assert_eq!(rtf_to_text(r"caf\'e9".as_bytes()), "café");
        assert_eq!(rtf_to_text(r"caf\u233?".as_bytes()), "café");
    }

    #[test]
    fn rtf_handles_escaped_braces() {
        assert_eq!(rtf_to_text(r"a\{b\}c".as_bytes()), "a{b}c");
    }

    #[tokio::test]
    async fn rtf_via_extractor_surface() {
        let rtf = r"{\rtf1 Plain text here\par}";
        let out = DocumentExtractor
            .extract(&doc_asset("application/rtf", rtf.as_bytes().to_vec()))
            .await
            .unwrap();
        assert_eq!(out.text, "Plain text here");
        assert_eq!(out.metadata["format"], "rtf");
    }

    // ── error paths ───────────────────────────────────────────────────

    #[tokio::test]
    async fn wrong_kind_returns_unsupported() {
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: vec![0x25, 0x50],
        };
        let err = DocumentExtractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported {
                backend: "document",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unknown_format_errors_cleanly() {
        let asset = doc_asset("application/octet-stream", vec![1, 2, 3]);
        let err = DocumentExtractor.extract(&asset).await.unwrap_err();
        assert!(matches!(err, ExtractionError::Backend { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn corrupt_zip_errors_not_panics() {
        let asset = doc_asset(DOCX_MIME, b"PK\x03\x04 not a real zip".to_vec());
        let err = DocumentExtractor.extract(&asset).await.unwrap_err();
        assert!(matches!(err, ExtractionError::Backend { .. }), "{err:?}");
    }

    #[test]
    fn slide_number_parses_ordinal() {
        assert_eq!(slide_number("ppt/slides/slide7.xml"), 7);
        assert_eq!(slide_number("ppt/slides/slide10.xml"), 10);
    }
}
