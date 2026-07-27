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
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS: usize = 4_096;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_EXPANSION_RATIO: u64 = 200;
/// Total extracted-text cap handed downstream, including the visible
/// truncation marker.
const MAX_TOTAL_TEXT: usize = 8 * 1024 * 1024;
const TRUNCATION_MARKER: &str = "\n[NEOTH] …document truncated at extraction cap…";
const MAX_CONTENT_TEXT: usize = MAX_TOTAL_TEXT - TRUNCATION_MARKER.len();

#[derive(Clone, Copy)]
struct ArchiveLimits {
    members: usize,
    member_bytes: u64,
    uncompressed_bytes: u64,
    expansion_ratio: u64,
}

const ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    members: MAX_ARCHIVE_MEMBERS,
    member_bytes: MAX_MEMBER_BYTES,
    uncompressed_bytes: MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    expansion_ratio: MAX_ARCHIVE_EXPANSION_RATIO,
};

struct ArchiveReadBudget {
    limit: u64,
    remaining: u64,
}

impl ArchiveReadBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            remaining: limit,
        }
    }

    fn consume(&mut self, bytes: u64) -> Result<(), ExtractionError> {
        self.remaining =
            self.remaining
                .checked_sub(bytes)
                .ok_or_else(|| ExtractionError::Backend {
                    backend: "document",
                    reason: format!(
                        "archive member reads exceed the {}-byte aggregate cap",
                        self.limit
                    ),
                })?;
        Ok(())
    }
}

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

    let (mut text, truncated) = if fmt.is_zip() {
        extract_zip_text(&bytes, fmt)?
    } else {
        truncate_owned_text(rtf_to_text(&bytes), MAX_CONTENT_TEXT)
    };
    if truncated {
        text.push_str(TRUNCATION_MARKER);
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
        Asset::Bytes { data, .. } => {
            enforce_document_byte_ceiling(data.len() as u64)?;
            Ok(data.clone())
        }
        Asset::Path { path, .. } => read_path(path),
    }
}

fn read_path(path: &Path) -> Result<Vec<u8>, ExtractionError> {
    let file = std::fs::File::open(path)
        .map_err(|e| ExtractionError::Io(format!("open {}: {e}", path.display())))?;
    let declared_len = file
        .metadata()
        .map_err(|e| ExtractionError::Io(format!("stat {}: {e}", path.display())))?
        .len();
    enforce_document_byte_ceiling(declared_len)?;
    let mut bytes = Vec::with_capacity(declared_len as usize);
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display())))?;
    enforce_document_byte_ceiling(bytes.len() as u64)?;
    Ok(bytes)
}

fn enforce_document_byte_ceiling(len: u64) -> Result<(), ExtractionError> {
    if len > MAX_DOCUMENT_BYTES {
        return Err(ExtractionError::Backend {
            backend: "document",
            reason: format!("input {len} bytes exceeds the {MAX_DOCUMENT_BYTES}-byte cap"),
        });
    }
    Ok(())
}

// ── zip-based extraction ──────────────────────────────────────────────

type Archive = zip::ZipArchive<Cursor<Vec<u8>>>;

fn extract_zip_text(bytes: &[u8], fmt: DocFormat) -> Result<(String, bool), ExtractionError> {
    let cursor = Cursor::new(bytes.to_vec());
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| ExtractionError::Backend {
        backend: "document",
        reason: format!("open {} archive: {e}", fmt.as_str()),
    })?;
    validate_archive(&mut archive, ARCHIVE_LIMITS)?;
    let mut read_budget = ArchiveReadBudget::new(MAX_ARCHIVE_UNCOMPRESSED_BYTES);

    match fmt {
        DocFormat::Docx => {
            let xml = read_member(&mut archive, "word/document.xml", &mut read_budget)?
                .ok_or_else(missing("docx", "word/document.xml"))?;
            Ok(truncate_owned_text(
                xml_body_text(&xml, DOCX_BREAKS),
                MAX_CONTENT_TEXT,
            ))
        }
        DocFormat::Pptx => {
            let mut names = member_names(&archive);
            names.retain(|n| is_slide(n));
            names.sort_by_key(|n| slide_number(n));
            let mut out = String::new();
            let mut truncated = false;
            for name in names {
                if let Some(xml) = read_member(&mut archive, &name, &mut read_budget)?
                    && push_section_bounded(
                        &mut out,
                        &xml_body_text(&xml, PPTX_BREAKS),
                        MAX_CONTENT_TEXT,
                    )
                {
                    truncated = true;
                    break;
                }
            }
            Ok((out, truncated))
        }
        DocFormat::Xlsx => {
            // Shared strings hold the text labels; numeric-only sheets
            // legitimately yield empty text.
            match read_member(&mut archive, "xl/sharedStrings.xml", &mut read_budget)? {
                Some(xml) => Ok(truncate_owned_text(
                    xml_body_text(&xml, XLSX_BREAKS),
                    MAX_CONTENT_TEXT,
                )),
                None => Ok((String::new(), false)),
            }
        }
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp => {
            let xml = read_member(&mut archive, "content.xml", &mut read_budget)?
                .ok_or_else(missing(fmt.as_str(), "content.xml"))?;
            Ok(truncate_owned_text(
                xml_body_text(&xml, ODF_BREAKS),
                MAX_CONTENT_TEXT,
            ))
        }
        DocFormat::Epub => {
            let mut names = member_names(&archive);
            names.retain(|n| is_xhtml(n));
            names.sort();
            let mut out = String::new();
            let mut truncated = false;
            for name in names {
                if let Some(xml) = read_member(&mut archive, &name, &mut read_budget)?
                    && push_section_bounded(
                        &mut out,
                        &xml_body_text(&xml, HTML_BREAKS),
                        MAX_CONTENT_TEXT,
                    )
                {
                    truncated = true;
                    break;
                }
            }
            Ok((out, truncated))
        }
        DocFormat::Rtf => unreachable!("rtf is not zip-based"),
    }
}

fn validate_archive(archive: &mut Archive, limits: ArchiveLimits) -> Result<(), ExtractionError> {
    let member_count = archive.len();
    if member_count > limits.members {
        return Err(ExtractionError::Backend {
            backend: "document",
            reason: format!(
                "archive has {member_count} members, exceeding the {}-member cap",
                limits.members
            ),
        });
    }

    let mut total_uncompressed = 0u64;
    let mut total_compressed = 0u64;
    for index in 0..member_count {
        let file = archive
            .by_index(index)
            .map_err(|e| ExtractionError::Backend {
                backend: "document",
                reason: format!("inspect archive member {index}: {e}"),
            })?;
        let member_size = file.size();
        if member_size > limits.member_bytes {
            return Err(ExtractionError::Backend {
                backend: "document",
                reason: format!(
                    "archive member `{}` declares {member_size} bytes, exceeding the {}-byte cap",
                    file.name(),
                    limits.member_bytes
                ),
            });
        }
        total_uncompressed = total_uncompressed.checked_add(member_size).ok_or_else(|| {
            ExtractionError::Backend {
                backend: "document",
                reason: "archive uncompressed-size sum overflow".into(),
            }
        })?;
        total_compressed = total_compressed
            .checked_add(file.compressed_size())
            .ok_or_else(|| ExtractionError::Backend {
                backend: "document",
                reason: "archive compressed-size sum overflow".into(),
            })?;
    }
    if total_uncompressed > limits.uncompressed_bytes {
        return Err(ExtractionError::Backend {
            backend: "document",
            reason: format!(
                "archive declares {total_uncompressed} uncompressed bytes, exceeding the {}-byte cap",
                limits.uncompressed_bytes
            ),
        });
    }
    if u128::from(total_uncompressed)
        > u128::from(total_compressed.max(1)) * u128::from(limits.expansion_ratio)
    {
        return Err(ExtractionError::Backend {
            backend: "document",
            reason: format!(
                "archive expansion ratio exceeds {}:1 ({total_uncompressed} uncompressed / {total_compressed} compressed bytes)",
                limits.expansion_ratio
            ),
        });
    }
    Ok(())
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

fn read_member(
    archive: &mut Archive,
    name: &str,
    read_budget: &mut ArchiveReadBudget,
) -> Result<Option<String>, ExtractionError> {
    read_member_with_limits(archive, name, MAX_MEMBER_BYTES, read_budget)
}

fn read_member_with_limits(
    archive: &mut Archive,
    name: &str,
    max_bytes: u64,
    read_budget: &mut ArchiveReadBudget,
) -> Result<Option<String>, ExtractionError> {
    match archive.by_name(name) {
        Ok(file) => {
            let actual_limit = max_bytes.min(read_budget.remaining);
            let mut bytes = Vec::with_capacity(file.size().min(actual_limit) as usize);
            file.take(actual_limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| ExtractionError::Backend {
                    backend: "document",
                    reason: format!("read member `{name}`: {e}"),
                })?;
            if bytes.len() as u64 > max_bytes {
                return Err(ExtractionError::Backend {
                    backend: "document",
                    reason: format!(
                        "archive member `{name}` exceeds the {max_bytes}-byte read cap"
                    ),
                });
            }
            if bytes.len() as u64 > read_budget.remaining {
                return Err(ExtractionError::Backend {
                    backend: "document",
                    reason: format!(
                        "archive member reads exceed the {}-byte aggregate cap while reading `{name}`",
                        read_budget.limit
                    ),
                });
            }
            read_budget.consume(bytes.len() as u64)?;
            String::from_utf8(bytes)
                .map(Some)
                .map_err(|e| ExtractionError::Backend {
                    backend: "document",
                    reason: format!("archive member `{name}` is not UTF-8: {e}"),
                })
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

fn push_section_bounded(out: &mut String, section: &str, limit: usize) -> bool {
    let section = section.trim();
    if section.is_empty() {
        return false;
    }
    let separator_len = usize::from(!out.is_empty()) * 2;
    let remaining = limit.saturating_sub(out.len());
    if section.len().saturating_add(separator_len) <= remaining {
        if separator_len != 0 {
            out.push_str("\n\n");
        }
        out.push_str(section);
        return false;
    }
    if remaining <= separator_len {
        return true;
    }
    if separator_len != 0 {
        out.push_str("\n\n");
    }
    let available = limit.saturating_sub(out.len());
    let safe = crate::util::byte_floor(section, available);
    out.push_str(&section[..safe]);
    true
}

fn truncate_owned_text(mut text: String, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text, false);
    }
    let safe = crate::util::byte_floor(&text, limit);
    text.truncate(safe);
    (text, true)
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
        let entity_end = if bytes[i] == b'&' {
            let search_end = i.saturating_add(13).min(bytes.len());
            bytes[i + 1..search_end]
                .iter()
                .position(|byte| *byte == b';')
                .map(|relative| i + 1 + relative)
        } else {
            None
        };
        if let Some(semi) = entity_end {
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

    fn open_zip(bytes: Vec<u8>) -> Archive {
        zip::ZipArchive::new(Cursor::new(bytes)).expect("open test zip")
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
    fn decode_entities_is_linear_for_ampersand_heavy_hostile_text() {
        let input = "&".repeat(256 * 1024);
        let started = std::time::Instant::now();
        assert_eq!(decode_entities(&input), input);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "bounded entity lookahead must stay linear"
        );
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
    fn archive_member_count_is_bounded_before_name_collection() {
        let zip = make_zip(&[("a", ""), ("b", ""), ("c", "")]);
        let mut archive = open_zip(zip);
        let error = validate_archive(
            &mut archive,
            ArchiveLimits {
                members: 2,
                member_bytes: u64::MAX,
                uncompressed_bytes: u64::MAX,
                expansion_ratio: u64::MAX,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ExtractionError::Backend {
                    backend: "document",
                    ref reason
                } if reason.contains("member")
            ),
            "{error:?}"
        );
    }

    #[test]
    fn archive_member_read_uses_limit_plus_one_and_fails() {
        let mut archive = open_zip(make_zip(&[("word/document.xml", "12345")]));
        let mut budget = ArchiveReadBudget::new(100);
        let error =
            read_member_with_limits(&mut archive, "word/document.xml", 4, &mut budget).unwrap_err();
        assert!(
            matches!(
                error,
                ExtractionError::Backend {
                    backend: "document",
                    ref reason
                } if reason.contains("read cap")
            ),
            "{error:?}"
        );
    }

    #[test]
    fn archive_member_reads_share_an_actual_byte_budget() {
        let mut archive = open_zip(make_zip(&[("a", "1234"), ("b", "5678")]));
        let mut budget = ArchiveReadBudget::new(7);
        assert_eq!(
            read_member_with_limits(&mut archive, "a", 10, &mut budget)
                .unwrap()
                .as_deref(),
            Some("1234")
        );
        let error = read_member_with_limits(&mut archive, "b", 10, &mut budget).unwrap_err();
        assert!(
            matches!(
                error,
                ExtractionError::Backend {
                    backend: "document",
                    ref reason
                } if reason.contains("aggregate cap")
            ),
            "{error:?}"
        );
    }

    #[test]
    fn archive_aggregate_and_expansion_ratio_are_bounded() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file::<_, ()>("word/document.xml", options)
            .unwrap();
        writer.write_all(&vec![b'A'; 4_096]).unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut archive = open_zip(bytes);

        let ratio_error = validate_archive(
            &mut archive,
            ArchiveLimits {
                members: 10,
                member_bytes: 8_192,
                uncompressed_bytes: 8_192,
                expansion_ratio: 2,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                ratio_error,
                ExtractionError::Backend {
                    backend: "document",
                    ref reason
                } if reason.contains("expansion ratio")
            ),
            "{ratio_error:?}"
        );

        let mut archive = open_zip(make_zip(&[("a", "1234"), ("b", "5678")]));
        let aggregate_error = validate_archive(
            &mut archive,
            ArchiveLimits {
                members: 10,
                member_bytes: 8,
                uncompressed_bytes: 7,
                expansion_ratio: 10,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                aggregate_error,
                ExtractionError::Backend {
                    backend: "document",
                    ref reason
                } if reason.contains("uncompressed")
            ),
            "{aggregate_error:?}"
        );
    }

    #[test]
    fn bounded_section_append_never_splits_utf8_or_exceeds_limit() {
        let mut out = "abc".to_string();
        assert!(push_section_bounded(&mut out, "ééé", 8));
        assert!(out.is_char_boundary(out.len()));
        assert!(out.len() <= 8);
        assert_eq!(out, "abc\n\né");
    }

    #[test]
    fn document_input_ceiling_is_fail_closed() {
        assert!(enforce_document_byte_ceiling(MAX_DOCUMENT_BYTES).is_ok());
        assert!(enforce_document_byte_ceiling(MAX_DOCUMENT_BYTES + 1).is_err());
    }

    #[test]
    fn slide_number_parses_ordinal() {
        assert_eq!(slide_number("ppt/slides/slide7.xml"), 7);
        assert_eq!(slide_number("ppt/slides/slide10.xml"), 10);
    }
}
