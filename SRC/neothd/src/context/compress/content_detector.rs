//! GOLD-HR-01 — content-type detection for the token-compression pipeline.
//!
//! Native Rust port of headroom's `crates/headroom-core/src/transforms/
//! content_detector.rs` (chopratejas/headroom, Apache-2.0) — the heuristic,
//! regex-only path. The optional `magika` ML detector is deliberately OUT (it
//! needs a model + I/O; NEOTH stays self-contained), so detection here is a
//! pure function of the input string: no model load, no filesystem, no network.
//!
//! It classifies one tool-output block so the [`super::pipeline`] router can
//! dispatch it to the right compressor:
//!
//! - **JsonArray** — a JSON array (→ the structured `smart_crusher`)
//! - **SourceCode** — Python / JS / TS / Go / Rust / Java
//! - **SearchResults** — grep / ripgrep `file:line:content`
//! - **BuildOutput** — compiler / test / lint logs
//! - **GitDiff** — unified-diff format (→ `diff_compressor`)
//! - **Html** — web pages (extraction, not compression)
//! - **PlainText** — generic fallback
//!
//! Regex patterns, dispatch order, confidence formulas and the line-count caps
//! are kept byte-equal with the upstream Rust core so the behaviour stays
//! parity-locked; see GOLD-HR-11 for the upstream-resync checklist.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

/// Content types recognised by the detector. The string tags match the upstream
/// `ContentType` values 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    JsonArray,
    SourceCode,
    SearchResults,
    BuildOutput,
    GitDiff,
    Html,
    PlainText,
}

impl ContentType {
    /// Stable string tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::JsonArray => "json_array",
            ContentType::SourceCode => "source_code",
            ContentType::SearchResults => "search",
            ContentType::BuildOutput => "build",
            ContentType::GitDiff => "diff",
            ContentType::Html => "html",
            ContentType::PlainText => "text",
        }
    }
}

/// Result of [`detect_content_type`]. `metadata` is per-type free-form data
/// (item counts, detected language, match counts, …).
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub content_type: ContentType,
    pub confidence: f64,
    pub metadata: Map<String, Value>,
}

impl DetectionResult {
    fn new(content_type: ContentType, confidence: f64, metadata: Map<String, Value>) -> Self {
        Self {
            content_type,
            confidence,
            metadata,
        }
    }

    fn plain_text(confidence: f64) -> Self {
        Self::new(ContentType::PlainText, confidence, Map::new())
    }
}

// ─── Regex patterns (compiled once, shared) ───────────────────────────

/// `file:line:` (grep -n style) — first column on a non-blank line.
static SEARCH_RESULT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s:]+:\d+:").unwrap());

/// Diff-header detection: `git diff`, merge-commit (`--combined`/`--cc`),
/// regular hunk headers (`@@ -A,B +C,D @@`) and combined-diff hunks (`@@@…@@@`).
static DIFF_HEADER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(diff --git|diff --combined |diff --cc |--- a/|@@\s+-\d+,\d+\s+\+\d+,\d+\s+@@|@@@+\s+-\d+(?:,\d+)?\s+(?:-\d+(?:,\d+)?\s+)+\+\d+(?:,\d+)?\s+@@@+)",
    )
    .unwrap()
});

/// `+`/`-` change lines (not `+++`/`---` headers).
static DIFF_CHANGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[+-][^+-]").unwrap());

// ─── Code patterns by language ─────────────────────────────────────────

struct CodePatterns {
    name: &'static str,
    patterns: Vec<Regex>,
}

static CODE_PATTERNS: LazyLock<Vec<CodePatterns>> = LazyLock::new(|| {
    vec![
        CodePatterns {
            name: "python",
            patterns: vec![
                Regex::new(r"^\s*(def|class|import|from|async def)\s+\w+").unwrap(),
                Regex::new(r"^\s*@\w+").unwrap(),
                Regex::new(r#"^\s*""""#).unwrap(),
                Regex::new(r"^\s*if __name__\s*==").unwrap(),
            ],
        },
        CodePatterns {
            name: "javascript",
            patterns: vec![
                Regex::new(r"^\s*(function|const|let|var|class|import|export)\s+").unwrap(),
                Regex::new(r"^\s*(async\s+function|=>\s*\{)").unwrap(),
                Regex::new(r"^\s*module\.exports").unwrap(),
            ],
        },
        CodePatterns {
            name: "typescript",
            patterns: vec![
                Regex::new(r"^\s*(interface|type|enum|namespace)\s+\w+").unwrap(),
                // Start-anchored to match the upstream `pattern.match(line)`
                // (the regex crate's `is_match` is unanchored by default).
                Regex::new(r"^:\s*(string|number|boolean|any|void)\b").unwrap(),
            ],
        },
        CodePatterns {
            name: "go",
            patterns: vec![
                Regex::new(r"^\s*(func|type|package|import)\s+").unwrap(),
                Regex::new(r"^\s*func\s+\([^)]+\)\s+\w+").unwrap(),
            ],
        },
        CodePatterns {
            name: "rust",
            patterns: vec![
                Regex::new(r"^\s*(fn|struct|enum|impl|mod|use|pub)\s+").unwrap(),
                Regex::new(r"^\s*#\[").unwrap(),
            ],
        },
        CodePatterns {
            name: "java",
            patterns: vec![
                Regex::new(r"^\s*(public|private|protected)\s+(class|interface|enum)").unwrap(),
                Regex::new(r"^\s*@\w+").unwrap(),
                Regex::new(r"^\s*package\s+[\w.]+;").unwrap(),
            ],
        },
    ]
});

// ─── Log / build output patterns ───────────────────────────────────────
//
// Order matters: indices 0–1 (ERROR + WARN families) count as "error" matches
// in `try_detect_log` and add extra confidence.
static LOG_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\b(ERROR|FAIL|FAILED|FATAL|CRITICAL)\b").unwrap(),
        Regex::new(r"(?i)\b(WARN|WARNING)\b").unwrap(),
        Regex::new(r"(?i)\b(INFO|DEBUG|TRACE)\b").unwrap(),
        Regex::new(r"^\s*\d{4}-\d{2}-\d{2}").unwrap(),
        Regex::new(r"^\s*\[\d{2}:\d{2}:\d{2}\]").unwrap(),
        Regex::new(r"^={3,}|^-{3,}").unwrap(),
        Regex::new(r"^\s*PASSED|^\s*FAILED|^\s*SKIPPED").unwrap(),
        Regex::new(r"^npm ERR!|^yarn error|^cargo error").unwrap(),
        Regex::new(r"Traceback \(most recent call last\)").unwrap(),
        Regex::new(r"^\s*at\s+[\w.$]+\(").unwrap(),
    ]
});

// ─── HTML patterns ─────────────────────────────────────────────────────

static HTML_DOCTYPE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*<!doctype\s+html").unwrap());
static HTML_TAG_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<html[\s>]").unwrap());
static HTML_HEAD_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<head[\s>]").unwrap());
static HTML_BODY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<body[\s>]").unwrap());
static HTML_STRUCTURAL_TAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)<(div|span|script|style|link|meta|nav|header|footer|aside|article|section|main)[\s>]",
    )
    .unwrap()
});

// ─── Public entry point ────────────────────────────────────────────────

/// Detect the type of `content` for routing.
///
/// Dispatch order (parity-locked):
/// 1. Empty / whitespace-only → `PlainText` confidence 0.0
/// 2. JSON array (highest priority for the structured crusher)
/// 3. Git diff (≥ 0.7 confidence required)
/// 4. HTML (≥ 0.7 confidence required)
/// 5. Search results (≥ 0.6 confidence required)
/// 6. Build / log output (≥ 0.5 confidence required)
/// 7. Source code (≥ 0.5 confidence required)
/// 8. Fallback → `PlainText` confidence 0.5
pub fn detect_content_type(content: &str) -> DetectionResult {
    if content.is_empty() || content.trim().is_empty() {
        return DetectionResult::plain_text(0.0);
    }

    if let Some(r) = try_detect_json(content) {
        return r;
    }
    if let Some(r) = try_detect_diff(content)
        && r.confidence >= 0.7
    {
        return r;
    }
    if let Some(r) = try_detect_html(content)
        && r.confidence >= 0.7
    {
        return r;
    }
    if let Some(r) = try_detect_search(content)
        && r.confidence >= 0.6
    {
        return r;
    }
    if let Some(r) = try_detect_log(content)
        && r.confidence >= 0.5
    {
        return r;
    }
    if let Some(r) = try_detect_code(content)
        && r.confidence >= 0.5
    {
        return r;
    }
    DetectionResult::plain_text(0.5)
}

/// Quick check: is `content` a JSON array of dictionaries (the format the
/// structured crusher natively handles)?
pub fn is_json_array_of_dicts(content: &str) -> bool {
    let result = detect_content_type(content);
    if result.content_type != ContentType::JsonArray {
        return false;
    }
    result
        .metadata
        .get("is_dict_array")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// ─── Per-type detection helpers ────────────────────────────────────────

fn try_detect_json(content: &str) -> Option<DetectionResult> {
    let trimmed = content.trim();
    if !trimmed.starts_with('[') {
        return None;
    }
    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    let arr = parsed.as_array()?;
    let item_count = arr.len();
    let is_dict_array = !arr.is_empty() && arr.iter().all(|v| v.is_object());
    let confidence = if is_dict_array { 1.0 } else { 0.8 };
    Some(DetectionResult::new(
        ContentType::JsonArray,
        confidence,
        json!({ "item_count": item_count, "is_dict_array": is_dict_array })
            .as_object()
            .cloned()
            .unwrap(),
    ))
}

fn try_detect_diff(content: &str) -> Option<DetectionResult> {
    let mut header_matches: u32 = 0;
    let mut change_matches: u32 = 0;
    for line in content.split('\n').take(500) {
        if DIFF_HEADER_PATTERN.is_match(line) {
            header_matches += 1;
        }
        if DIFF_CHANGE_PATTERN.is_match(line) {
            change_matches += 1;
        }
    }
    if header_matches == 0 {
        return None;
    }
    let confidence =
        (0.5 + (header_matches as f64) * 0.2 + (change_matches as f64) * 0.05).min(1.0);
    Some(DetectionResult::new(
        ContentType::GitDiff,
        confidence,
        json!({ "header_matches": header_matches, "change_lines": change_matches })
            .as_object()
            .cloned()
            .unwrap(),
    ))
}

fn try_detect_html(content: &str) -> Option<DetectionResult> {
    let sample: &str = if content.len() > 3000 {
        let mut cutoff = 3000;
        while !content.is_char_boundary(cutoff) {
            cutoff -= 1;
        }
        &content[..cutoff]
    } else {
        content
    };

    let has_doctype = HTML_DOCTYPE_PATTERN.is_match(sample);
    let has_html_tag = HTML_TAG_PATTERN.is_match(sample);
    let has_head = HTML_HEAD_PATTERN.is_match(sample);
    let has_body = HTML_BODY_PATTERN.is_match(sample);
    let structural_matches = HTML_STRUCTURAL_TAGS.find_iter(sample).count() as u32;

    if !has_doctype && !has_html_tag && structural_matches < 3 {
        return None;
    }

    let mut confidence = 0.0_f64;
    if has_doctype {
        confidence += 0.5;
    }
    if has_html_tag {
        confidence += 0.3;
    }
    if has_head {
        confidence += 0.1;
    }
    if has_body {
        confidence += 0.1;
    }
    confidence += (structural_matches as f64 * 0.03).min(0.3);
    confidence = confidence.min(1.0);

    if confidence < 0.5 {
        return None;
    }
    Some(DetectionResult::new(
        ContentType::Html,
        confidence,
        json!({
            "has_doctype": has_doctype,
            "has_html_tag": has_html_tag,
            "structural_tags": structural_matches,
        })
        .as_object()
        .cloned()
        .unwrap(),
    ))
}

fn try_detect_search(content: &str) -> Option<DetectionResult> {
    let lines: Vec<&str> = content.split('\n').take(100).collect();
    if lines.is_empty() {
        return None;
    }
    let mut matching_lines: u32 = 0;
    for line in &lines {
        if !line.trim().is_empty() && SEARCH_RESULT_PATTERN.is_match(line) {
            matching_lines += 1;
        }
    }
    if matching_lines == 0 {
        return None;
    }
    let non_empty_lines = lines.iter().filter(|l| !l.trim().is_empty()).count() as u32;
    if non_empty_lines == 0 {
        return None;
    }
    let ratio = matching_lines as f64 / non_empty_lines as f64;
    if ratio < 0.3 {
        return None;
    }
    let confidence = (0.4 + ratio * 0.6).min(1.0);
    Some(DetectionResult::new(
        ContentType::SearchResults,
        confidence,
        json!({ "matching_lines": matching_lines, "total_lines": non_empty_lines })
            .as_object()
            .cloned()
            .unwrap(),
    ))
}

fn try_detect_log(content: &str) -> Option<DetectionResult> {
    let lines: Vec<&str> = content.split('\n').take(200).collect();
    if lines.is_empty() {
        return None;
    }
    let mut pattern_matches: u32 = 0;
    let mut error_matches: u32 = 0;
    for line in &lines {
        for (i, pattern) in LOG_PATTERNS.iter().enumerate() {
            if pattern.is_match(line) {
                pattern_matches += 1;
                if i < 2 {
                    error_matches += 1;
                }
                break; // one pattern per line is enough
            }
        }
    }
    if pattern_matches == 0 {
        return None;
    }
    let non_empty_lines = lines.iter().filter(|l| !l.trim().is_empty()).count() as u32;
    if non_empty_lines == 0 {
        return None;
    }
    let ratio = pattern_matches as f64 / non_empty_lines as f64;
    if ratio < 0.1 {
        return None;
    }
    let confidence = (0.3 + ratio * 0.5 + (error_matches as f64) * 0.05).min(1.0);
    Some(DetectionResult::new(
        ContentType::BuildOutput,
        confidence,
        json!({
            "pattern_matches": pattern_matches,
            "error_matches": error_matches,
            "total_lines": non_empty_lines,
        })
        .as_object()
        .cloned()
        .unwrap(),
    ))
}

fn try_detect_code(content: &str) -> Option<DetectionResult> {
    let lines: Vec<&str> = content.split('\n').take(100).collect();
    if lines.is_empty() {
        return None;
    }
    // First-match insertion order + first-on-tie tie-break, mirroring the
    // upstream Python dict + `max()` semantics (Rust's `max_by` returns LAST
    // on ties, so we resolve the tie manually).
    let mut language_scores: Vec<(&'static str, u32)> = Vec::new();

    for line in &lines {
        for cp in CODE_PATTERNS.iter() {
            for pattern in &cp.patterns {
                if pattern.is_match(line) {
                    if let Some(entry) = language_scores.iter_mut().find(|(n, _)| *n == cp.name) {
                        entry.1 += 1;
                    } else {
                        language_scores.push((cp.name, 1));
                    }
                    break;
                }
            }
        }
    }

    if language_scores.is_empty() {
        return None;
    }
    let max_score = language_scores.iter().map(|x| x.1).max().unwrap_or(0);
    let (best_lang, best_score) = *language_scores
        .iter()
        .find(|x| x.1 == max_score)
        .expect("language_scores non-empty");
    if best_score < 3 {
        return None;
    }
    let non_empty_lines = lines.iter().filter(|l| !l.trim().is_empty()).count() as u32;
    let ratio = best_score as f64 / non_empty_lines.max(1) as f64;
    let confidence = (0.4 + ratio * 0.4 + (best_score as f64) * 0.02).min(1.0);
    Some(DetectionResult::new(
        ContentType::SourceCode,
        confidence,
        json!({ "language": best_lang, "pattern_matches": best_score })
            .as_object()
            .cloned()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_plain_text_zero_confidence() {
        let r = detect_content_type("");
        assert_eq!(r.content_type, ContentType::PlainText);
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn whitespace_only_returns_plain_text_zero_confidence() {
        let r = detect_content_type("   \n\t  ");
        assert_eq!(r.content_type, ContentType::PlainText);
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn json_array_of_dicts_high_confidence() {
        let r = detect_content_type(r#"[{"id": 1}, {"id": 2}]"#);
        assert_eq!(r.content_type, ContentType::JsonArray);
        assert_eq!(r.confidence, 1.0);
        assert_eq!(
            r.metadata.get("is_dict_array").unwrap().as_bool(),
            Some(true)
        );
        assert_eq!(r.metadata.get("item_count").unwrap().as_u64(), Some(2));
    }

    #[test]
    fn json_array_of_scalars_lower_confidence() {
        let r = detect_content_type(r#"[1, 2, 3]"#);
        assert_eq!(r.content_type, ContentType::JsonArray);
        assert_eq!(r.confidence, 0.8);
        assert_eq!(
            r.metadata.get("is_dict_array").unwrap().as_bool(),
            Some(false)
        );
    }

    #[test]
    fn json_object_falls_through_to_text() {
        let r = detect_content_type(r#"{"id": 1}"#);
        assert_eq!(r.content_type, ContentType::PlainText);
    }

    #[test]
    fn search_results_detected() {
        let content =
            "src/main.py:42:def process():\nsrc/util.py:13:    return None\nlib/x.py:7:class X:";
        let r = detect_content_type(content);
        assert_eq!(r.content_type, ContentType::SearchResults);
        assert!(r.confidence >= 0.6);
    }

    #[test]
    fn git_diff_detected() {
        let content = "\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,4 @@
 def hello():
-    print('hi')
+    print('hello')
+    print('world')
";
        let r = detect_content_type(content);
        assert_eq!(r.content_type, ContentType::GitDiff);
        assert!(r.confidence >= 0.7);
    }

    #[test]
    fn html_doctype_detected() {
        let content = "\
<!DOCTYPE html>
<html>
<head><title>X</title></head>
<body><div>hi</div></body>
</html>";
        let r = detect_content_type(content);
        assert_eq!(r.content_type, ContentType::Html);
        assert!(r.confidence >= 0.7);
    }

    #[test]
    fn build_output_detected() {
        let content = "\
[INFO] Starting build
[INFO] Compiling 42 sources
[ERROR] Compilation failed
[WARN] Deprecated API
FAILED test_one
PASSED test_two
";
        let r = detect_content_type(content);
        assert_eq!(r.content_type, ContentType::BuildOutput);
        assert!(r.confidence >= 0.5);
    }

    #[test]
    fn rust_code_detected() {
        let content = "\
use std::sync::Arc;

#[derive(Debug)]
pub struct Foo {
    bar: u32,
}

pub fn baz() -> u32 {
    42
}

impl Foo {
    pub fn new() -> Self {
        Self { bar: 0 }
    }
}
";
        let r = detect_content_type(content);
        assert_eq!(r.content_type, ContentType::SourceCode);
        assert_eq!(r.metadata.get("language").unwrap().as_str(), Some("rust"));
    }

    #[test]
    fn fallback_to_plain_text() {
        let r = detect_content_type("Just some random text without any special structure.");
        assert_eq!(r.content_type, ContentType::PlainText);
        assert_eq!(r.confidence, 0.5);
    }

    #[test]
    fn is_json_array_of_dicts_paths() {
        assert!(is_json_array_of_dicts(r#"[{"a": 1}, {"a": 2}]"#));
        assert!(!is_json_array_of_dicts(r#"[1, 2, 3]"#));
        assert!(!is_json_array_of_dicts(r#"{"a": 1}"#));
        assert!(!is_json_array_of_dicts("[]"));
    }

    #[test]
    fn content_type_string_tags_pinned() {
        assert_eq!(ContentType::JsonArray.as_str(), "json_array");
        assert_eq!(ContentType::SourceCode.as_str(), "source_code");
        assert_eq!(ContentType::SearchResults.as_str(), "search");
        assert_eq!(ContentType::BuildOutput.as_str(), "build");
        assert_eq!(ContentType::GitDiff.as_str(), "diff");
        assert_eq!(ContentType::Html.as_str(), "html");
        assert_eq!(ContentType::PlainText.as_str(), "text");
    }
}
