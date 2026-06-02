//! Per-source readers — V10-06 Phase-3 dry-run path.
//!
//! Each import-source kind (Markdown / Json / LanceArrow / Sqlite /
//! GitTree / FaissFlat per `RUNBOOK_phase3_cutover.md` Day-62) gets
//! its own reader. Phase 1 (this binary) implements the scan-only
//! variants — count rows, surface sample entries, validate the shape.
//! Phase 2 (V10-06 follow-up) will wire each reader to an
//! `OperatorWalEmitter` that appends WAL frames during `apply`.
//!
//! The list of sources is NOT hardcoded — the operator declares their
//! own prior-AI memory stores in an `import-manifest.yaml` (passed via
//! `--manifest <PATH>`). See `examples/import-manifest.example.yaml`
//! for the schema. The scanners below are generic by [`ImportKind`];
//! only the source LIST is operator-supplied.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};

/// One operator-declared import source — a single row of the
/// `import-manifest.yaml`. The operator points NEOTH at THEIR prior-AI
/// memory; nothing is hardcoded to any one person's machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSource {
    /// Operator-chosen label (appears in the dry-run report).
    pub name: String,
    /// Path to the store. A leading `~/` expands to the operator's
    /// home at runtime; absolute paths pass through.
    pub path: String,
    /// Which reader to dispatch.
    pub kind: ImportKind,
    /// Optional operator hint shown in the dry-run report (e.g.
    /// "~500 files"). Purely informational.
    #[serde(default)]
    pub hint: Option<String>,
}

/// Top-level shape of an `import-manifest.yaml`:
///
/// ```yaml
/// sources:
///   - name: my_vault
///     path: ~/Documents/MyVault
///     kind: markdown
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImportManifest {
    pub sources: Vec<ImportSource>,
}

/// Load + parse an operator import manifest. A missing/unreadable file
/// or malformed YAML is a hard error — the operator asked to import
/// from a manifest, so silently scanning nothing would be a surprise.
pub fn load_manifest(path: &Path) -> anyhow::Result<ImportManifest> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read import manifest at {}", path.display()))?;
    let manifest: ImportManifest = serde_yaml::from_str(&body)
        .with_context(|| format!("parse import manifest YAML at {}", path.display()))?;
    Ok(manifest)
}

/// One row in the dry-run report — what the migrator found at the
/// source's path after `~`-expansion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreScan {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub status: ScanStatus,
    pub row_count: usize,
    /// First N entries the reader saw (best-effort preview). Truncated
    /// to the file path / row id, not the full body, so the dry-run
    /// JSON stays under a few KiB.
    pub sample: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Reader scanned successfully; `row_count` + `sample` populated.
    Ok,
    /// Store path doesn't exist on this operator's machine.
    PathMissing,
    /// Reader not yet implemented in this Phase-1 binary. Operator
    /// sees this in the report and knows to wait for V10-06 follow-up.
    ReaderNotImplemented { reason: String },
    /// Reader hit an unrecoverable error mid-walk (permissions,
    /// corruption). Operator-actionable.
    Error { detail: String },
}

/// Backing format for an import source. Drives which reader the
/// migrator dispatches. The `as_str()` snake_case values ARE the
/// `kind:` field values in the operator's manifest — `#[serde(rename_all
/// = "snake_case")]` keeps the wire form stable across binary upgrades.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    Markdown,
    MarkdownFile,
    JsonDir,
    JsonFile,
    LanceArrow,
    Sqlite,
    GitTree,
    FaissFlat,
}

impl ImportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::MarkdownFile => "markdown_file",
            Self::JsonDir => "json_dir",
            Self::JsonFile => "json_file",
            Self::LanceArrow => "lance_arrow",
            Self::Sqlite => "sqlite",
            Self::GitTree => "git_tree",
            Self::FaissFlat => "faiss_flat",
        }
    }
}

/// Top-level dry-run pass. Walks every operator-declared source,
/// returns a per-source `StoreScan`. Never errors at the aggregate
/// level — the `ScanStatus::Error` variant carries the per-source
/// failure detail.
pub fn scan_all(sources: &[ImportSource], home: &Path) -> Vec<StoreScan> {
    sources.iter().map(|s| scan_one(s, home)).collect()
}

fn scan_one(source: &ImportSource, home: &Path) -> StoreScan {
    let name = source.name.as_str();
    let kind = source.kind;
    let resolved = resolve_path(&source.path, home);
    let path_str = resolved.display().to_string();
    if !resolved.exists() {
        return StoreScan {
            name: name.to_string(),
            path: path_str,
            kind: kind.as_str().to_string(),
            status: ScanStatus::PathMissing,
            row_count: 0,
            sample: vec![],
        };
    }
    match kind {
        ImportKind::Markdown => scan_markdown_dir(name, &resolved, kind),
        ImportKind::MarkdownFile => scan_markdown_file(name, &resolved, kind),
        ImportKind::JsonDir => scan_json_dir(name, &resolved, kind),
        ImportKind::JsonFile => scan_json_file(name, &resolved, kind),
        ImportKind::Sqlite => scan_sqlite(name, &resolved, kind),
        ImportKind::FaissFlat => scan_faiss_flat(name, &resolved, kind),
        ImportKind::LanceArrow => scan_lance_inventory(name, &resolved, kind),
        ImportKind::GitTree => scan_git_inventory(name, &resolved, kind),
    }
}

// ── LanceArrow pure-Rust inventory reader (Pick #35 follow-up) ──────
//
// Pick #35 (Session 16) deferred LanceArrow because real row-reads
// need the `lance` C-dep. Pick #35 follow-up (2026-05-20) ships a
// pure-Rust inventory pass instead: count Lance datasets present
// (each is a directory ending `.lance/` with a `_versions/`
// subdirectory). The operator gets a real `row_count` (= dataset
// count) + sample = dataset names. Real row-reads land when the
// Phase-3 dep block lets us pull `lance`.

fn scan_lance_inventory(name: &str, path: &std::path::Path, kind: ImportKind) -> StoreScan {
    let kind_str = kind.as_str().to_string();
    let path_str = path.display().to_string();
    let mut datasets: Vec<String> = Vec::new();
    let walker = match std::fs::read_dir(path) {
        Ok(w) => w,
        Err(e) => {
            return StoreScan {
                name: name.to_string(),
                path: path_str,
                kind: kind_str,
                status: ScanStatus::Error {
                    detail: format!("read_dir failed: {e}"),
                },
                row_count: 0,
                sample: vec![],
            };
        }
    };
    for entry in walker.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        // A Lance dataset is conventionally `<name>.lance/` with a
        // `_versions/` subdirectory inside. Use the latter as the
        // tell so we don't false-positive on operator-named dirs.
        if p.extension().and_then(|s| s.to_str()) == Some("lance") && p.join("_versions").is_dir() {
            if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                datasets.push(n.to_string());
            }
        }
    }
    datasets.sort();
    let sample: Vec<String> = datasets.iter().take(5).cloned().collect();
    StoreScan {
        name: name.to_string(),
        path: path_str,
        kind: kind_str,
        status: ScanStatus::Ok,
        row_count: datasets.len(),
        sample,
    }
}

// ── GitTree pure-Rust inventory reader (Pick #35 follow-up) ─────────
//
// Same approach as LanceArrow: pure-Rust inventory. A "git tree"
// here is any subdirectory that contains a `.git/HEAD` file. Real
// commit/blob walking lands with the `git2` Phase-3 dep.

fn scan_git_inventory(name: &str, path: &std::path::Path, kind: ImportKind) -> StoreScan {
    let kind_str = kind.as_str().to_string();
    let path_str = path.display().to_string();
    let mut repos: Vec<String> = Vec::new();
    let walker = match std::fs::read_dir(path) {
        Ok(w) => w,
        Err(e) => {
            return StoreScan {
                name: name.to_string(),
                path: path_str,
                kind: kind_str,
                status: ScanStatus::Error {
                    detail: format!("read_dir failed: {e}"),
                },
                row_count: 0,
                sample: vec![],
            };
        }
    };
    for entry in walker.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        if p.join(".git").join("HEAD").is_file() {
            if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                repos.push(n.to_string());
            }
        }
    }
    repos.sort();
    let sample: Vec<String> = repos.iter().take(5).cloned().collect();
    StoreScan {
        name: name.to_string(),
        path: path_str,
        kind: kind_str,
        status: ScanStatus::Ok,
        row_count: repos.len(),
        sample,
    }
}

// ── Sqlite reader (Pick #35) ─────────────────────────────────────────

fn scan_sqlite(name: &str, path: &std::path::Path, kind: ImportKind) -> StoreScan {
    let kind_str = kind.as_str().to_string();
    // If the operator pointed us at a directory, pick the first `.db`
    // file under it. A direct file path is used as-is.
    let actual_db = if path.is_dir() {
        let candidate = std::fs::read_dir(path)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|x| x.to_str()) == Some("db"));
        match candidate {
            Some(c) => c,
            None => {
                return StoreScan {
                    name: name.to_string(),
                    path: path.display().to_string(),
                    kind: kind_str,
                    status: ScanStatus::Error {
                        detail: "directory contains no .db file".into(),
                    },
                    row_count: 0,
                    sample: vec![],
                };
            }
        }
    } else {
        path.to_path_buf()
    };

    let conn = match rusqlite::Connection::open_with_flags(
        &actual_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => {
            return StoreScan {
                name: name.to_string(),
                path: actual_db.display().to_string(),
                kind: kind_str,
                status: ScanStatus::Error {
                    detail: format!("open sqlite: {e}"),
                },
                row_count: 0,
                sample: vec![],
            };
        }
    };

    let table_query = "SELECT name FROM sqlite_master WHERE type='table' \
                       AND name NOT LIKE 'sqlite_%' ORDER BY name";
    let tables: Vec<String> = match conn.prepare(table_query) {
        Ok(mut stmt) => match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                return StoreScan {
                    name: name.to_string(),
                    path: actual_db.display().to_string(),
                    kind: kind_str,
                    status: ScanStatus::Error {
                        detail: format!("iterate tables: {e}"),
                    },
                    row_count: 0,
                    sample: vec![],
                };
            }
        },
        Err(e) => {
            return StoreScan {
                name: name.to_string(),
                path: actual_db.display().to_string(),
                kind: kind_str,
                status: ScanStatus::Error {
                    detail: format!("list tables: {e}"),
                },
                row_count: 0,
                sample: vec![],
            };
        }
    };

    let mut total_rows: usize = 0;
    for table in &tables {
        let q = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
        if let Ok(count) = conn.query_row(&q, [], |row| row.get::<_, i64>(0)) {
            total_rows = total_rows.saturating_add(count.max(0) as usize);
        }
    }

    StoreScan {
        name: name.to_string(),
        path: actual_db.display().to_string(),
        kind: kind_str,
        status: ScanStatus::Ok,
        row_count: total_rows,
        sample: tables.into_iter().take(3).collect(),
    }
}

// ── FaissFlat reader (Pick #35) ──────────────────────────────────────

/// Standard sentence-transformer output dim × 4 bytes per f32.
const QMD_VECTOR_BYTES_ESTIMATE: u64 = 768 * 4;

fn scan_faiss_flat(name: &str, dir: &std::path::Path, kind: ImportKind) -> StoreScan {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return StoreScan {
                name: name.to_string(),
                path: dir.display().to_string(),
                kind: kind.as_str().to_string(),
                status: ScanStatus::Error {
                    detail: format!("read_dir: {e}"),
                },
                row_count: 0,
                sample: vec![],
            };
        }
    };
    let mut total_bytes: u64 = 0;
    let mut bin_files: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("bin")
            && let Ok(meta) = entry.metadata()
        {
            total_bytes = total_bytes.saturating_add(meta.len());
            if bin_files.len() < 3 {
                bin_files.push(p.display().to_string());
            }
        }
    }
    let estimated_vectors = (total_bytes / QMD_VECTOR_BYTES_ESTIMATE) as usize;
    StoreScan {
        name: name.to_string(),
        path: dir.display().to_string(),
        kind: kind.as_str().to_string(),
        status: ScanStatus::Ok,
        row_count: estimated_vectors,
        sample: bin_files,
    }
}

fn resolve_path(template: &str, home: &Path) -> PathBuf {
    if let Some(rest) = template.strip_prefix("~/") {
        home.join(rest)
    } else if template == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(template)
    }
}

fn scan_markdown_dir(name: &str, dir: &Path, kind: ImportKind) -> StoreScan {
    let mut count = 0;
    let mut sample = Vec::new();
    for entry in WalkBuilder::new(dir)
        .standard_filters(true)
        .build()
        .flatten()
    {
        if entry.path().extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        count += 1;
        if sample.len() < 3 {
            sample.push(entry.path().display().to_string());
        }
    }
    StoreScan {
        name: name.to_string(),
        path: dir.display().to_string(),
        kind: kind.as_str().to_string(),
        status: ScanStatus::Ok,
        row_count: count,
        sample,
    }
}

fn scan_markdown_file(name: &str, file: &Path, kind: ImportKind) -> StoreScan {
    match std::fs::read_to_string(file) {
        Ok(text) => {
            // Count the H1/H2 anchors as a rough row proxy. Operators
            // care about "how many sections will turn into recall
            // entries", not raw line count.
            let headings = text
                .lines()
                .filter(|l| l.starts_with("# ") || l.starts_with("## "))
                .count();
            StoreScan {
                name: name.to_string(),
                path: file.display().to_string(),
                kind: kind.as_str().to_string(),
                status: ScanStatus::Ok,
                row_count: headings.max(1),
                sample: text
                    .lines()
                    .filter(|l| l.starts_with("# ") || l.starts_with("## "))
                    .take(3)
                    .map(String::from)
                    .collect(),
            }
        }
        Err(e) => StoreScan {
            name: name.to_string(),
            path: file.display().to_string(),
            kind: kind.as_str().to_string(),
            status: ScanStatus::Error {
                detail: e.to_string(),
            },
            row_count: 0,
            sample: vec![],
        },
    }
}

fn scan_json_dir(name: &str, dir: &Path, kind: ImportKind) -> StoreScan {
    let mut count = 0;
    let mut sample = Vec::new();
    for entry in WalkBuilder::new(dir)
        .standard_filters(true)
        .build()
        .flatten()
    {
        let p = entry.path();
        if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("json" | "ajson")
        ) {
            count += 1;
            if sample.len() < 3 {
                sample.push(p.display().to_string());
            }
        }
    }
    StoreScan {
        name: name.to_string(),
        path: dir.display().to_string(),
        kind: kind.as_str().to_string(),
        status: ScanStatus::Ok,
        row_count: count,
        sample,
    }
}

fn scan_json_file(name: &str, file: &Path, kind: ImportKind) -> StoreScan {
    match std::fs::read_to_string(file) {
        Ok(text) => {
            let row_count = match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(serde_json::Value::Array(arr)) => arr.len(),
                Ok(serde_json::Value::Object(obj)) => obj.len(),
                Ok(_) => 1, // scalar value = 1 row
                Err(_) => 0,
            };
            StoreScan {
                name: name.to_string(),
                path: file.display().to_string(),
                kind: kind.as_str().to_string(),
                status: if row_count > 0 {
                    ScanStatus::Ok
                } else {
                    ScanStatus::Error {
                        detail: "JSON parse failed".into(),
                    }
                },
                row_count,
                sample: vec![],
            }
        }
        Err(e) => StoreScan {
            name: name.to_string(),
            path: file.display().to_string(),
            kind: kind.as_str().to_string(),
            status: ScanStatus::Error {
                detail: e.to_string(),
            },
            row_count: 0,
            sample: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn src(name: &str, path: &str, kind: ImportKind) -> ImportSource {
        ImportSource {
            name: name.to_string(),
            path: path.to_string(),
            kind,
            hint: None,
        }
    }

    #[test]
    fn manifest_parses_sources_with_kind_and_optional_hint() {
        let yaml = "\
sources:
  - name: my_vault
    path: ~/Documents/MyVault
    kind: markdown
    hint: \"~500 files\"
  - name: chat_exports
    path: ~/Downloads/exports
    kind: json_dir
";
        let m: ImportManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.sources.len(), 2);
        assert_eq!(m.sources[0].name, "my_vault");
        assert_eq!(m.sources[0].kind, ImportKind::Markdown);
        assert_eq!(m.sources[0].hint.as_deref(), Some("~500 files"));
        assert_eq!(m.sources[1].kind, ImportKind::JsonDir);
        assert!(m.sources[1].hint.is_none());
    }

    #[test]
    fn manifest_empty_or_missing_sources_is_empty() {
        let m: ImportManifest = serde_yaml::from_str("sources: []").unwrap();
        assert!(m.sources.is_empty());
        let m2: ImportManifest = serde_yaml::from_str("{}").unwrap();
        assert!(m2.sources.is_empty());
    }

    #[test]
    fn load_manifest_round_trips_from_disk() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("import.yaml");
        std::fs::write(
            &p,
            "sources:\n  - name: notes\n    path: ~/notes\n    kind: markdown\n",
        )
        .unwrap();
        let m = load_manifest(&p).unwrap();
        assert_eq!(m.sources.len(), 1);
        assert_eq!(m.sources[0].name, "notes");
    }

    #[test]
    fn load_manifest_errors_on_missing_file() {
        let tmp = tempdir().unwrap();
        assert!(load_manifest(&tmp.path().join("absent.yaml")).is_err());
    }

    #[test]
    fn import_kind_as_str_is_stable_snake_case() {
        // Pin every variant so wire-format compat across binary
        // versions survives. Operator manifests use these `kind:`
        // values verbatim.
        assert_eq!(ImportKind::Markdown.as_str(), "markdown");
        assert_eq!(ImportKind::MarkdownFile.as_str(), "markdown_file");
        assert_eq!(ImportKind::JsonDir.as_str(), "json_dir");
        assert_eq!(ImportKind::JsonFile.as_str(), "json_file");
        assert_eq!(ImportKind::LanceArrow.as_str(), "lance_arrow");
        assert_eq!(ImportKind::Sqlite.as_str(), "sqlite");
        assert_eq!(ImportKind::GitTree.as_str(), "git_tree");
        assert_eq!(ImportKind::FaissFlat.as_str(), "faiss_flat");
    }

    #[test]
    fn import_kind_serde_uses_snake_case_wire_form() {
        // The `kind:` field in the manifest is the snake_case string,
        // not the PascalCase Rust variant — an operator writes
        // `kind: lance_arrow`, never `kind: LanceArrow`.
        assert_eq!(
            serde_yaml::to_string(&ImportKind::LanceArrow)
                .unwrap()
                .trim(),
            "lance_arrow"
        );
        let k: ImportKind = serde_yaml::from_str("json_dir").unwrap();
        assert_eq!(k, ImportKind::JsonDir);
    }

    #[test]
    fn resolve_path_expands_tilde_prefix() {
        let home = std::path::PathBuf::from("/home/op");
        assert_eq!(resolve_path("~/foo", &home), home.join("foo"));
        assert_eq!(resolve_path("~/notes/x", &home), home.join("notes/x"));
    }

    #[test]
    fn resolve_path_passes_absolute_through() {
        let home = std::path::PathBuf::from("/home/op");
        let abs = "/mnt/data/vault";
        assert_eq!(resolve_path(abs, &home), std::path::PathBuf::from(abs));
    }

    #[test]
    fn scan_all_returns_one_entry_per_source_even_when_paths_missing() {
        // Operator-declared sources pointing at non-existent paths →
        // one PathMissing entry each (never silently dropped).
        let tmp = tempdir().unwrap();
        let sources = vec![
            src("a", "~/does-not-exist-a", ImportKind::Markdown),
            src("b", "~/does-not-exist-b", ImportKind::Sqlite),
            src("c", "~/does-not-exist-c", ImportKind::JsonDir),
        ];
        let report = scan_all(&sources, tmp.path());
        assert_eq!(report.len(), 3);
        let missing = report
            .iter()
            .filter(|s| matches!(s.status, ScanStatus::PathMissing))
            .count();
        assert_eq!(missing, 3, "all missing paths report PathMissing");
        // Names carry through from the manifest.
        assert_eq!(report[0].name, "a");
    }

    #[test]
    fn scan_all_empty_sources_is_empty_report() {
        let tmp = tempdir().unwrap();
        assert!(scan_all(&[], tmp.path()).is_empty());
    }

    #[test]
    fn scan_markdown_dir_counts_md_files() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("vault");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.md"), "# heading\nbody").unwrap();
        std::fs::write(dir.join("b.md"), "# other").unwrap();
        std::fs::write(dir.join("ignored.txt"), "skip me").unwrap();
        let scan = scan_markdown_dir("test", &dir, ImportKind::Markdown);
        assert_eq!(scan.row_count, 2);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.name, "test");
    }

    #[test]
    fn scan_markdown_file_counts_headings() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("c.md");
        std::fs::write(&p, "# one\n## two\n## three\nbody").unwrap();
        let scan = scan_markdown_file("test", &p, ImportKind::MarkdownFile);
        assert_eq!(scan.row_count, 3);
        assert_eq!(scan.sample.len(), 3);
    }

    #[test]
    fn scan_json_file_counts_array_length() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("arr.json");
        std::fs::write(&p, "[1, 2, 3, 4, 5]").unwrap();
        let scan = scan_json_file("test", &p, ImportKind::JsonFile);
        assert_eq!(scan.row_count, 5);
    }

    #[test]
    fn scan_json_file_counts_object_keys() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("obj.json");
        std::fs::write(&p, r#"{"a":1,"b":2,"c":3}"#).unwrap();
        let scan = scan_json_file("test", &p, ImportKind::JsonFile);
        assert_eq!(scan.row_count, 3);
    }

    #[test]
    fn scan_json_file_handles_malformed_input() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("bad.json");
        std::fs::write(&p, "not valid json").unwrap();
        let scan = scan_json_file("test", &p, ImportKind::JsonFile);
        assert!(matches!(scan.status, ScanStatus::Error { .. }));
    }

    #[test]
    fn lance_and_git_readers_run_inventory_pass() {
        let tmp = tempdir().unwrap();
        for (sub, kind) in [
            ("lance", ImportKind::LanceArrow),
            ("git", ImportKind::GitTree),
        ] {
            let p = tmp.path().join(sub);
            std::fs::create_dir_all(&p).unwrap();
            let scan = scan_one(&src("test", &p.to_string_lossy(), kind), tmp.path());
            assert!(
                matches!(scan.status, ScanStatus::Ok),
                "{kind:?} reader must run an inventory pass"
            );
            assert_eq!(scan.row_count, 0, "empty {kind:?} dir → zero count");
        }
    }

    // ── Sqlite reader (Pick #35) ──────────────────────────────────────

    #[test]
    fn sqlite_reader_counts_user_tables_and_rows() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("test.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE memories (id INTEGER PRIMARY KEY, text TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memories (text) VALUES ('one'), ('two'), ('three')",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE skills (id INTEGER PRIMARY KEY, name TEXT)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO skills (name) VALUES ('a'), ('b')", [])
            .unwrap();

        let scan = scan_sqlite("test", &db_path, ImportKind::Sqlite);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 5, "3 memories + 2 skills");
        assert!(
            scan.sample.contains(&"memories".to_string()),
            "sample must include user table name; got {:?}",
            scan.sample
        );
        assert!(scan.sample.contains(&"skills".to_string()));
    }

    #[test]
    fn sqlite_reader_handles_directory_with_db_file() {
        let tmp = tempdir().unwrap();
        let db_dir = tmp.path().join("ctx-mode");
        std::fs::create_dir_all(&db_dir).unwrap();
        let db_path = db_dir.join("session.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE chunks (id INTEGER PRIMARY KEY, body TEXT)",
            [],
        )
        .unwrap();
        let scan = scan_sqlite("test", &db_dir, ImportKind::Sqlite);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert!(scan.path.contains("session.db"));
    }

    #[test]
    fn sqlite_reader_errors_on_corrupt_db() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("garbage.db");
        std::fs::write(&db_path, b"not a sqlite file").unwrap();
        let scan = scan_sqlite("test", &db_path, ImportKind::Sqlite);
        assert!(matches!(scan.status, ScanStatus::Error { .. }));
    }

    #[test]
    fn sqlite_reader_skips_sqlite_internal_tables() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("with-internal.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("CREATE TABLE just_one (x INT)", []).unwrap();
        conn.execute("INSERT INTO just_one VALUES (1), (2)", [])
            .unwrap();
        let scan = scan_sqlite("test", &db_path, ImportKind::Sqlite);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 2);
        for s in &scan.sample {
            assert!(
                !s.starts_with("sqlite_"),
                "sqlite_* internal tables must stay hidden; got {s:?}"
            );
        }
    }

    // ── FaissFlat reader (Pick #35) ───────────────────────────────────

    #[test]
    fn faiss_flat_reader_counts_bin_files_and_estimates_vectors() {
        let tmp = tempdir().unwrap();
        let four_vec_bytes = (QMD_VECTOR_BYTES_ESTIMATE * 4) as usize;
        let eight_vec_bytes = (QMD_VECTOR_BYTES_ESTIMATE * 8) as usize;
        std::fs::write(tmp.path().join("a.bin"), vec![0u8; four_vec_bytes]).unwrap();
        std::fs::write(tmp.path().join("b.bin"), vec![0u8; eight_vec_bytes]).unwrap();
        std::fs::write(tmp.path().join("ignored.txt"), b"skip me").unwrap();
        let scan = scan_faiss_flat("test", tmp.path(), ImportKind::FaissFlat);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 12, "4 + 8 estimated vectors");
        assert_eq!(scan.sample.len(), 2, "two .bin files sampled");
    }

    #[test]
    fn faiss_flat_reader_returns_zero_on_empty_dir() {
        let tmp = tempdir().unwrap();
        let scan = scan_faiss_flat("test", tmp.path(), ImportKind::FaissFlat);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 0);
    }

    // ── LanceArrow inventory reader (Pick #35 follow-up) ──────────────

    #[test]
    fn lance_inventory_counts_datasets_with_versions_subdir() {
        let tmp = tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("episodes.lance/_versions")).unwrap();
        std::fs::create_dir_all(tmp.path().join("embeddings.lance/_versions")).unwrap();
        std::fs::create_dir(tmp.path().join("bare.lance")).unwrap(); // no _versions
        std::fs::create_dir(tmp.path().join("misc")).unwrap();
        let scan = scan_lance_inventory("test", tmp.path(), ImportKind::LanceArrow);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 2, "two valid datasets");
        assert_eq!(scan.sample.len(), 2);
        assert!(scan.sample.contains(&"episodes.lance".to_string()));
        assert!(scan.sample.contains(&"embeddings.lance".to_string()));
    }

    #[test]
    fn lance_inventory_returns_zero_on_empty_dir() {
        let tmp = tempdir().unwrap();
        let scan = scan_lance_inventory("test", tmp.path(), ImportKind::LanceArrow);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 0);
        assert!(scan.sample.is_empty());
    }

    #[test]
    fn lance_inventory_sample_caps_at_five() {
        let tmp = tempdir().unwrap();
        for i in 0..7 {
            std::fs::create_dir_all(tmp.path().join(format!("dataset-{i}.lance/_versions")))
                .unwrap();
        }
        let scan = scan_lance_inventory("test", tmp.path(), ImportKind::LanceArrow);
        assert_eq!(scan.row_count, 7);
        assert_eq!(scan.sample.len(), 5, "sample bounded at 5");
    }

    // ── GitTree inventory reader (Pick #35 follow-up) ─────────────────

    #[test]
    fn git_inventory_counts_subdirs_with_dot_git_head() {
        let tmp = tempdir().unwrap();
        for repo in &["alpha", "bravo"] {
            let head = tmp.path().join(repo).join(".git");
            std::fs::create_dir_all(&head).unwrap();
            std::fs::write(head.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        }
        std::fs::create_dir_all(tmp.path().join("incomplete/.git")).unwrap();
        std::fs::create_dir_all(tmp.path().join("not-a-repo")).unwrap();

        let scan = scan_git_inventory("test", tmp.path(), ImportKind::GitTree);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 2, "alpha + bravo only");
        assert!(scan.sample.contains(&"alpha".to_string()));
        assert!(scan.sample.contains(&"bravo".to_string()));
    }

    #[test]
    fn git_inventory_returns_zero_on_empty_dir() {
        let tmp = tempdir().unwrap();
        let scan = scan_git_inventory("test", tmp.path(), ImportKind::GitTree);
        assert!(matches!(scan.status, ScanStatus::Ok));
        assert_eq!(scan.row_count, 0);
    }
}
