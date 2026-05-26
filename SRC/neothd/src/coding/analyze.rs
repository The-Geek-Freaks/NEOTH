//! UA-01 (Session 24) — consumer for `understand-anything` JSON output.
//!
//! `understand-anything` (Lum1104/understand-anything, MIT) is an
//! external code-analyser CLI that emits a JSON report describing
//! a codebase: per-file functions, classes, dependency edges, an
//! optional natural-language summary. NEOTH treats it as a black
//! box — the operator runs `understand-anything --json out.json`
//! themselves, then `neoth code analyze out.json` to surface the
//! findings.
//!
//! ## Why a tolerant parser, not a pinned schema
//!
//! `understand-anything` evolves outside the NEOTH repo + minor
//! field additions land between releases. A strict schema would
//! force operators to pin a tool version. Every NEOTH field below
//! is `#[serde(default)]` — missing fields produce empty
//! collections + omitted strings, not a parse error. Unknown
//! fields are dropped (default serde behaviour) so a new
//! understand-anything release that adds a `complexity_score`
//! field still parses against this schema.
//!
//! ## What the consumer does
//!
//! 1. Parse the JSON file into [`AnalysisReport`].
//! 2. Compute a [`AnalysisSummary`] with shape stats (file count,
//!    function count, top dependency edges, language histogram).
//! 3. Optionally persist the summary as one structured memory
//!    event so future recall ("what does my repo look like?")
//!    has something to hit — wired via [`render_summary_md`]
//!    which a future `cli/code.rs analyze` subcommand pipes into
//!    the memory layer.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level shape of the understand-anything JSON. Every field is
/// `#[serde(default)]` so missing keys don't break the parse —
/// tolerance is the whole point.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Optional natural-language description of the project, if the
    /// analyser produced one.
    #[serde(default)]
    pub summary: String,
    /// Per-file records.
    #[serde(default)]
    pub files: Vec<FileRecord>,
    /// Dependency edges in `(from, to)` form. May be empty when
    /// the analyser didn't run the dependency pass.
    #[serde(default)]
    pub edges: Vec<DependencyEdge>,
    /// Optional version string of the analyser that produced this
    /// JSON. Surfaced verbatim in the summary so operators know
    /// which tool revision generated the data.
    #[serde(default)]
    pub generator_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    /// Detected language — analyser-dependent string. Empty when
    /// the analyser couldn't classify the file.
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub functions: Vec<FunctionRecord>,
    #[serde(default)]
    pub classes: Vec<ClassRecord>,
    /// File-level line count.
    #[serde(default)]
    pub line_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub name: String,
    #[serde(default)]
    pub line_start: u32,
    #[serde(default)]
    pub line_end: u32,
    #[serde(default)]
    pub doc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassRecord {
    pub name: String,
    #[serde(default)]
    pub line_start: u32,
    #[serde(default)]
    pub line_end: u32,
    #[serde(default)]
    pub doc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    /// Optional edge kind — analyser-dependent ("import" / "call" /
    /// "inherits" / …). Empty falls back to "depends".
    #[serde(default)]
    pub kind: String,
}

/// Aggregated stats derived from an [`AnalysisReport`]. Stable
/// shape — operator-facing UIs lock onto these fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisSummary {
    pub file_count: usize,
    pub function_count: usize,
    pub class_count: usize,
    pub edge_count: usize,
    /// Language histogram sorted by file-count desc, ties broken
    /// alphabetically ascending. Empty-language files (analyser
    /// couldn't classify) are tagged `"<unknown>"`.
    pub language_histogram: Vec<(String, usize)>,
    /// Top dependency targets by inbound edge count. Same sort
    /// rule as `language_histogram`. Capped at 10 entries.
    pub top_dependency_targets: Vec<(String, usize)>,
    /// Files with the largest line counts. Capped at 10 entries,
    /// sorted descending by line count, ties broken alphabetically.
    pub largest_files: Vec<(String, u32)>,
    /// Carried forward verbatim from the analyser.
    pub generator_version: String,
}

const TOP_N: usize = 10;

/// Parse an understand-anything JSON file from disk.
pub fn parse_report_file(path: &Path) -> Result<AnalysisReport> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read analysis report {}", path.display()))?;
    parse_report_str(&body).with_context(|| format!("parse JSON at {}", path.display()))
}

/// Parse from an in-memory string. Tolerant — extra fields drop,
/// missing fields use defaults.
pub fn parse_report_str(body: &str) -> Result<AnalysisReport> {
    let report: AnalysisReport = serde_json::from_str(body).context("decode AnalysisReport")?;
    Ok(report)
}

/// Derive the [`AnalysisSummary`] from a report. Pure function —
/// no I/O. Always succeeds (empty report → all-zero summary).
pub fn summarize(report: &AnalysisReport) -> AnalysisSummary {
    let file_count = report.files.len();
    let function_count: usize = report.files.iter().map(|f| f.functions.len()).sum();
    let class_count: usize = report.files.iter().map(|f| f.classes.len()).sum();
    let edge_count = report.edges.len();

    // Language histogram
    let mut lang_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &report.files {
        let key = if f.language.is_empty() {
            "<unknown>".to_string()
        } else {
            f.language.clone()
        };
        *lang_counts.entry(key).or_insert(0) += 1;
    }
    let mut language_histogram: Vec<(String, usize)> = lang_counts.into_iter().collect();
    language_histogram.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Top dependency targets (in-degree)
    let mut indegree: BTreeMap<String, usize> = BTreeMap::new();
    for e in &report.edges {
        *indegree.entry(e.to.clone()).or_insert(0) += 1;
    }
    let mut top_dependency_targets: Vec<(String, usize)> = indegree.into_iter().collect();
    top_dependency_targets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_dependency_targets.truncate(TOP_N);

    // Largest files
    let mut largest_files: Vec<(String, u32)> = report
        .files
        .iter()
        .map(|f| (f.path.clone(), f.line_count))
        .collect();
    largest_files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    largest_files.truncate(TOP_N);

    AnalysisSummary {
        file_count,
        function_count,
        class_count,
        edge_count,
        language_histogram,
        top_dependency_targets,
        largest_files,
        generator_version: report.generator_version.clone(),
    }
}

/// Render the summary as plain-text markdown for stdout or memory
/// archive. Stable layout — operator UIs and future Dataview
/// queries pin on the section headers.
pub fn render_summary_md(report: &AnalysisReport, summary: &AnalysisSummary) -> String {
    let mut out = String::with_capacity(1024);

    out.push_str("# Codebase analysis\n\n");
    if !summary.generator_version.is_empty() {
        out.push_str(&format!(
            "_Generated by understand-anything `{}`._\n\n",
            summary.generator_version
        ));
    }

    out.push_str("## Shape\n\n");
    out.push_str(&format!("- Files: {}\n", summary.file_count));
    out.push_str(&format!("- Functions: {}\n", summary.function_count));
    out.push_str(&format!("- Classes: {}\n", summary.class_count));
    out.push_str(&format!("- Dependency edges: {}\n\n", summary.edge_count));

    out.push_str("## Languages\n\n");
    if summary.language_histogram.is_empty() {
        out.push_str("_No files in report._\n\n");
    } else {
        for (lang, n) in &summary.language_histogram {
            out.push_str(&format!("- {lang}: {n}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Largest files\n\n");
    if summary.largest_files.is_empty() {
        out.push_str("_No files in report._\n\n");
    } else {
        for (path, lines) in &summary.largest_files {
            out.push_str(&format!("- `{path}` — {lines} lines\n"));
        }
        out.push('\n');
    }

    out.push_str("## Top dependency targets\n\n");
    if summary.top_dependency_targets.is_empty() {
        out.push_str("_No dependency edges in report._\n\n");
    } else {
        for (target, n) in &summary.top_dependency_targets {
            out.push_str(&format!("- `{target}` ← {n}\n"));
        }
        out.push('\n');
    }

    if !report.summary.is_empty() {
        out.push_str("## Analyser narrative\n\n");
        out.push_str(report.summary.trim());
        out.push_str("\n\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with(files: Vec<FileRecord>, edges: Vec<DependencyEdge>) -> AnalysisReport {
        AnalysisReport {
            summary: String::new(),
            files,
            edges,
            generator_version: String::new(),
        }
    }

    fn file(path: &str, language: &str, lines: u32, fn_count: usize) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            language: language.to_string(),
            functions: (0..fn_count)
                .map(|i| FunctionRecord {
                    name: format!("fn_{i}"),
                    ..Default::default()
                })
                .collect(),
            classes: Vec::new(),
            line_count: lines,
        }
    }

    #[test]
    fn parse_empty_object_yields_defaults() {
        let r = parse_report_str("{}").unwrap();
        assert!(r.summary.is_empty());
        assert!(r.files.is_empty());
        assert!(r.edges.is_empty());
        assert!(r.generator_version.is_empty());
    }

    #[test]
    fn parse_ignores_unknown_fields() {
        let json = r#"{"complexity_score": 42, "files": [], "future_field": "x"}"#;
        let r = parse_report_str(json).expect("tolerant parse");
        assert!(r.files.is_empty());
    }

    #[test]
    fn parse_minimal_file_record() {
        let json = r#"{"files":[{"path":"src/main.rs","language":"rust","line_count":120}]}"#;
        let r = parse_report_str(json).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "src/main.rs");
        assert_eq!(r.files[0].language, "rust");
        assert_eq!(r.files[0].line_count, 120);
        assert!(r.files[0].functions.is_empty());
    }

    #[test]
    fn summarize_empty_report_all_zeros() {
        let r = AnalysisReport::default();
        let s = summarize(&r);
        assert_eq!(s.file_count, 0);
        assert_eq!(s.function_count, 0);
        assert_eq!(s.class_count, 0);
        assert_eq!(s.edge_count, 0);
        assert!(s.language_histogram.is_empty());
        assert!(s.largest_files.is_empty());
        assert!(s.top_dependency_targets.is_empty());
    }

    #[test]
    fn summarize_counts_files_functions_classes() {
        let r = report_with(
            vec![
                file("a.rs", "rust", 100, 3),
                file("b.rs", "rust", 50, 1),
                FileRecord {
                    path: "c.py".to_string(),
                    language: "python".to_string(),
                    functions: vec![],
                    classes: vec![ClassRecord {
                        name: "Foo".to_string(),
                        ..Default::default()
                    }],
                    line_count: 10,
                },
            ],
            vec![],
        );
        let s = summarize(&r);
        assert_eq!(s.file_count, 3);
        assert_eq!(s.function_count, 4);
        assert_eq!(s.class_count, 1);
    }

    #[test]
    fn summarize_language_histogram_desc_then_alpha() {
        let r = report_with(
            vec![
                file("a.rs", "rust", 1, 0),
                file("b.rs", "rust", 1, 0),
                file("c.py", "python", 1, 0),
                file("d.go", "go", 1, 0),
            ],
            vec![],
        );
        let s = summarize(&r);
        // rust=2, go=1, python=1; ties (go vs python) alphabetical
        assert_eq!(s.language_histogram[0], ("rust".to_string(), 2));
        assert_eq!(s.language_histogram[1].0, "go");
        assert_eq!(s.language_histogram[2].0, "python");
    }

    #[test]
    fn summarize_unknown_language_tagged() {
        let r = report_with(vec![file("a.bin", "", 1, 0)], vec![]);
        let s = summarize(&r);
        assert_eq!(s.language_histogram[0].0, "<unknown>");
    }

    #[test]
    fn summarize_top_dependency_targets_by_in_degree() {
        let r = report_with(
            vec![],
            vec![
                DependencyEdge {
                    from: "a".into(),
                    to: "core".into(),
                    kind: "import".into(),
                },
                DependencyEdge {
                    from: "b".into(),
                    to: "core".into(),
                    kind: "import".into(),
                },
                DependencyEdge {
                    from: "c".into(),
                    to: "core".into(),
                    kind: "call".into(),
                },
                DependencyEdge {
                    from: "a".into(),
                    to: "util".into(),
                    kind: "import".into(),
                },
            ],
        );
        let s = summarize(&r);
        assert_eq!(s.top_dependency_targets[0], ("core".to_string(), 3));
        assert_eq!(s.top_dependency_targets[1], ("util".to_string(), 1));
    }

    #[test]
    fn summarize_top_dependency_targets_capped_at_10() {
        let edges: Vec<DependencyEdge> = (0..15)
            .map(|i| DependencyEdge {
                from: "x".into(),
                to: format!("dep{i:02}"),
                kind: "import".into(),
            })
            .collect();
        let r = report_with(vec![], edges);
        let s = summarize(&r);
        assert_eq!(s.top_dependency_targets.len(), 10);
    }

    #[test]
    fn summarize_largest_files_desc_with_alpha_tiebreak() {
        let r = report_with(
            vec![
                file("z.rs", "rust", 100, 0),
                file("a.rs", "rust", 100, 0),
                file("m.rs", "rust", 50, 0),
            ],
            vec![],
        );
        let s = summarize(&r);
        // 100 == 100 → a before z
        assert_eq!(s.largest_files[0], ("a.rs".to_string(), 100));
        assert_eq!(s.largest_files[1], ("z.rs".to_string(), 100));
        assert_eq!(s.largest_files[2], ("m.rs".to_string(), 50));
    }

    #[test]
    fn summarize_largest_files_capped_at_10() {
        let files: Vec<FileRecord> = (0..15)
            .map(|i| file(&format!("f{i:02}.rs"), "rust", i, 0))
            .collect();
        let r = report_with(files, vec![]);
        let s = summarize(&r);
        assert_eq!(s.largest_files.len(), 10);
    }

    #[test]
    fn summarize_carries_generator_version_through() {
        let r = AnalysisReport {
            generator_version: "0.7.3".into(),
            ..Default::default()
        };
        let s = summarize(&r);
        assert_eq!(s.generator_version, "0.7.3");
    }

    #[test]
    fn render_summary_md_contains_pinned_section_headers() {
        let r = report_with(vec![file("a.rs", "rust", 100, 1)], vec![]);
        let s = summarize(&r);
        let md = render_summary_md(&r, &s);
        assert!(md.starts_with("# Codebase analysis\n\n"));
        assert!(md.contains("## Shape\n"));
        assert!(md.contains("## Languages\n"));
        assert!(md.contains("## Largest files\n"));
        assert!(md.contains("## Top dependency targets\n"));
    }

    #[test]
    fn render_summary_md_shows_zero_state_message_when_empty() {
        let r = AnalysisReport::default();
        let s = summarize(&r);
        let md = render_summary_md(&r, &s);
        assert!(md.contains("Files: 0"));
        assert!(md.contains("_No files in report._"));
        assert!(md.contains("_No dependency edges in report._"));
    }

    #[test]
    fn render_summary_md_includes_generator_version_line() {
        let r = AnalysisReport {
            generator_version: "0.7.3".into(),
            ..Default::default()
        };
        let s = summarize(&r);
        let md = render_summary_md(&r, &s);
        assert!(md.contains("understand-anything `0.7.3`"));
    }

    #[test]
    fn render_summary_md_includes_analyser_narrative_when_present() {
        let mut r = AnalysisReport::default();
        r.summary = "Repo is a CLI agent system focused on local-first memory.".to_string();
        let s = summarize(&r);
        let md = render_summary_md(&r, &s);
        assert!(md.contains("## Analyser narrative"));
        assert!(md.contains("Repo is a CLI agent system"));
    }

    #[test]
    fn render_summary_md_omits_narrative_section_when_empty() {
        let r = AnalysisReport::default();
        let s = summarize(&r);
        let md = render_summary_md(&r, &s);
        assert!(!md.contains("## Analyser narrative"));
    }

    #[test]
    fn parse_report_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let json = r#"{
            "summary": "ok",
            "files": [{"path": "src/main.rs", "language": "rust", "line_count": 12}],
            "edges": [],
            "generator_version": "0.1.0"
        }"#;
        std::fs::write(&path, json).unwrap();
        let r = parse_report_file(&path).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.summary, "ok");
        assert_eq!(r.generator_version, "0.1.0");
    }

    #[test]
    fn parse_report_file_missing_path_errors() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("nope.json");
        let err = parse_report_file(&bogus).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("read analysis report"));
    }

    #[test]
    fn parse_report_file_invalid_json_errors_with_path_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let err = parse_report_file(&path).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("parse JSON at"), "got {msg}");
    }
}
