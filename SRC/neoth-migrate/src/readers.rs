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

// ── Known source-tag strings (mirror neothd's Source::as_str()) ─────────────
//
// These constants are the EXACT values neothd's `Source::as_str()` returns.
// neoth-migrate bypasses the neothd crate, so we replicate them here as
// string constants. A mismatch silently creates rows with an unrecognised
// source string that recall queries would never match — pin them.

/// Source tag written into `idx_groundtruth.source` for each ImportKind.
/// `hint` on the ImportSource can override for Sqlite kind (which has
/// sub-formats: hermes / openhuman / cq-commons).
fn source_tag_for(src: &ImportSource) -> &'static str {
    match src.kind {
        ImportKind::Sqlite => {
            // Sqlite kind carries multiple sub-formats. The operator declares
            // which one via `hint: hermes | openhuman | cq-commons | veronica`.
            // Fall back to a generic tag so unknown hints still produce a row.
            match src.hint.as_deref().unwrap_or("").trim() {
                "hermes" => "import:hermes",
                "openhuman" => "import:openhuman",
                "cq-commons" | "cq_commons" => "import:openclaw",
                "veronica" => "import:veronica",
                _ => "import:openclaw",
            }
        }
        // Markdown / JSON sources: map by source name conventions first,
        // then fall back to obsidian (the most common markdown import).
        ImportKind::Markdown | ImportKind::MarkdownFile => "import:obsidian",
        ImportKind::JsonFile | ImportKind::JsonDir => "import:session",
        // Lance/Faiss/Git — these callers bail before reaching source_tag_for.
        ImportKind::LanceArrow | ImportKind::FaissFlat | ImportKind::GitTree => "import:openclaw",
    }
}

/// One imported claim — (statement, source_tag, scope) ready for
/// `INSERT OR IGNORE INTO idx_groundtruth`.
///
/// Returns all claims for one `ImportSource`. The `source_tag` strings match
/// `neothd::memory::groundtruth::Source::as_str()` exactly — a mismatch
/// would silently create rows that recall queries never surface.
///
/// Kinds that have no implemented reader (`LanceArrow`, `FaissFlat`,
/// `GitTree`) bail immediately so the caller can log and skip.
pub fn emit_claims(
    src: &ImportSource,
    home: &Path,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let resolved = resolve_path(&src.path, home);
    let tag = source_tag_for(src);
    let scope = src
        .hint
        .as_deref()
        .and_then(|h| {
            // If hint looks like a scope override (`scope:global`, `scope:host:foo`)
            // peel it off; otherwise the hint is a sub-format key (hermes etc.)
            // and we default to "global".
            h.strip_prefix("scope:")
        })
        .unwrap_or("global")
        .to_string();

    match src.kind {
        ImportKind::LanceArrow | ImportKind::FaissFlat | ImportKind::GitTree => {
            anyhow::bail!(
                "emit_claims: reader not implemented for kind {:?} (source '{}'). \
                 This kind supports scan-only. Skip and continue.",
                src.kind,
                src.name
            );
        }

        ImportKind::Sqlite => emit_sqlite_claims(&resolved, tag, &scope),

        ImportKind::MarkdownFile => emit_markdown_file_claims(&resolved, tag, &scope),

        ImportKind::Markdown => emit_markdown_dir_claims(&resolved, tag, &scope),

        ImportKind::JsonFile => emit_json_file_claims(&resolved, tag, &scope),

        ImportKind::JsonDir => emit_json_dir_claims(&resolved, tag, &scope),
    }
}

// ── Sqlite claim emitter ─────────────────────────────────────────────────────

/// Read all text rows from every user table in the Sqlite store.
/// Each non-empty TEXT value becomes a claim with `statement = value`.
/// This is intentionally broad: the dry-run scan already told the
/// operator what tables exist, so apply trusts the manifest opt-in.
fn emit_sqlite_claims(
    path: &Path,
    tag: &'static str,
    scope: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    use anyhow::Context as _;

    // Resolve directory → first .db file (same logic as scan_sqlite).
    let actual_db = if path.is_dir() {
        let candidate = std::fs::read_dir(path)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|x| x.to_str()) == Some("db"));
        candidate.ok_or_else(|| anyhow::anyhow!("directory contains no .db file: {}", path.display()))?
    } else {
        path.to_path_buf()
    };

    let conn = rusqlite::Connection::open_with_flags(
        &actual_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("open sqlite: {}", actual_db.display()))?;

    // Enumerate user tables.
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .context("list tables")?;
        stmt.query_map([], |row| row.get::<_, String>(0))
            .context("query tables")?
            .filter_map(|r| r.ok())
            .collect()
    };

    let mut claims = Vec::new();
    for table in &tables {
        // Find TEXT columns in each table.
        let col_query = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
        let text_cols: Vec<String> = {
            let mut stmt = conn.prepare(&col_query).context("table_info")?;
            stmt.query_map([], |row| {
                let col_type: String = row.get::<_, String>(2).unwrap_or_default();
                let col_name: String = row.get::<_, String>(1)?;
                Ok((col_name, col_type))
            })
            .context("iterate columns")?
            .filter_map(|r| r.ok())
            .filter(|(_, col_type)| {
                let t = col_type.to_uppercase();
                t.contains("TEXT") || t.is_empty() // SQLite affinity: no type → TEXT affinity
            })
            .map(|(name, _)| name)
            .collect()
        };

        if text_cols.is_empty() {
            continue;
        }

        let sel: Vec<String> = text_cols
            .iter()
            .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
            .collect();
        let query = format!(
            "SELECT {} FROM \"{}\"",
            sel.join(", "),
            table.replace('"', "\"\"")
        );
        let mut stmt = conn.prepare(&query).context("prepare data query")?;
        let col_count = sel.len();
        let rows = stmt
            .query_map([], |row| {
                let mut vals = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let v: Option<String> = row.get(i).ok().flatten();
                    vals.push(v);
                }
                Ok(vals)
            })
            .context("query rows")?;

        for row in rows.filter_map(|r| r.ok()) {
            for val in row.into_iter().flatten() {
                let stmt_text = val.trim().to_string();
                if !stmt_text.is_empty() {
                    claims.push((stmt_text, tag.to_string(), scope.to_string()));
                }
            }
        }
    }
    Ok(claims)
}

// ── Markdown claim emitters ───────────────────────────────────────────────────

/// Parse a single Markdown file. Each paragraph (block of non-empty text that
/// is not a heading marker or fence) becomes one claim. Headings become claims
/// too (stripped of leading `#` chars) since they often encode facts in vault
/// style ("Server Cube is at 100.68.210.50").
fn emit_markdown_file_claims(
    path: &Path,
    tag: &'static str,
    scope: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    use anyhow::Context as _;
    use pulldown_cmark::{Event, Parser as MdParser, Tag, TagEnd};

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read markdown file: {}", path.display()))?;

    let mut claims = Vec::new();
    let mut buf = String::new();
    let mut in_code = false;

    for event in MdParser::new(&text) {
        match event {
            Event::Start(Tag::CodeBlock(_)) => {
                in_code = true;
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code = false;
                buf.clear();
            }
            Event::Text(t) | Event::Code(t) if !in_code => {
                buf.push_str(&t);
                buf.push(' ');
            }
            Event::End(TagEnd::Paragraph)
            | Event::End(TagEnd::Heading(_))
            | Event::End(TagEnd::Item)
            | Event::End(TagEnd::BlockQuote(_)) => {
                let stmt = buf.trim().to_string();
                if !stmt.is_empty() && stmt.len() >= 8 {
                    // Skip single-word headings or lone punctuation.
                    claims.push((stmt, tag.to_string(), scope.to_string()));
                }
                buf.clear();
            }
            Event::SoftBreak | Event::HardBreak if !buf.trim().is_empty() => {
                buf.push(' ');
            }
            Event::SoftBreak | Event::HardBreak => {}
            _ => {}
        }
    }

    // Trailing text that never saw a closing tag.
    let stmt = buf.trim().to_string();
    if !stmt.is_empty() && stmt.len() >= 8 {
        claims.push((stmt, tag.to_string(), scope.to_string()));
    }

    Ok(claims)
}

/// Walk a directory tree of Markdown files, emitting claims from each.
fn emit_markdown_dir_claims(
    dir: &Path,
    tag: &'static str,
    scope: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut claims = Vec::new();
    for entry in WalkBuilder::new(dir).standard_filters(true).build().flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        match emit_markdown_file_claims(p, tag, scope) {
            Ok(mut c) => claims.append(&mut c),
            Err(e) => {
                tracing::warn!(path = %p.display(), err = %e, "markdown claim read failed, skipping file");
            }
        }
    }
    Ok(claims)
}

// ── JSON claim emitters ───────────────────────────────────────────────────────

/// Extract claims from a single JSON file.
///
/// Supported shapes:
/// - Array of objects: each object with a `statement`/`text`/`content`/`body`
///   string field becomes one claim.
/// - Array of strings: each string is a claim.
/// - Single object: same field extraction as above.
fn emit_json_file_claims(
    path: &Path,
    tag: &'static str,
    scope: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    use anyhow::Context as _;

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read json file: {}", path.display()))?;
    let val: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parse json: {}", path.display()))?;

    Ok(extract_json_claims(&val, tag, scope))
}

/// Known field names (in priority order) to extract the statement from
/// a JSON object.
const CLAIM_FIELDS: &[&str] = &[
    "statement",
    "text",
    "content",
    "body",
    "message",
    "fact",
    "claim",
    "note",
    "value",
];

fn extract_json_claims(
    val: &serde_json::Value,
    tag: &'static str,
    scope: &str,
) -> Vec<(String, String, String)> {
    let mut claims = Vec::new();
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                match item {
                    serde_json::Value::String(s) => {
                        let stmt = s.trim().to_string();
                        if stmt.len() >= 8 {
                            claims.push((stmt, tag.to_string(), scope.to_string()));
                        }
                    }
                    serde_json::Value::Object(_) => {
                        if let Some(stmt) = pick_claim_field(item) {
                            claims.push((stmt, tag.to_string(), scope.to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }
        serde_json::Value::Object(_) => {
            if let Some(stmt) = pick_claim_field(val) {
                claims.push((stmt, tag.to_string(), scope.to_string()));
            }
        }
        serde_json::Value::String(s) => {
            let stmt = s.trim().to_string();
            if stmt.len() >= 8 {
                claims.push((stmt, tag.to_string(), scope.to_string()));
            }
        }
        _ => {}
    }
    claims
}

fn pick_claim_field(obj: &serde_json::Value) -> Option<String> {
    for &field in CLAIM_FIELDS {
        if let Some(serde_json::Value::String(s)) = obj.get(field) {
            let stmt = s.trim().to_string();
            if stmt.len() >= 8 {
                return Some(stmt);
            }
        }
    }
    None
}

/// Walk a directory of JSON files, emitting claims from each.
fn emit_json_dir_claims(
    dir: &Path,
    tag: &'static str,
    scope: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut claims = Vec::new();
    for entry in WalkBuilder::new(dir).standard_filters(true).build().flatten() {
        let p = entry.path();
        if !matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("json" | "ajson")
        ) {
            continue;
        }
        match emit_json_file_claims(p, tag, scope) {
            Ok(mut c) => claims.append(&mut c),
            Err(e) => {
                tracing::warn!(path = %p.display(), err = %e, "json claim read failed, skipping file");
            }
        }
    }
    Ok(claims)
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

    // ── emit_claims tests ─────────────────────────────────────────────────────

    fn make_src(name: &str, path: &str, kind: ImportKind, hint: Option<&str>) -> ImportSource {
        ImportSource {
            name: name.to_string(),
            path: path.to_string(),
            kind,
            hint: hint.map(String::from),
        }
    }

    #[test]
    fn emit_claims_json_file_array_of_objects() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("facts.json");
        std::fs::write(
            &p,
            r#"[{"statement":"The sky is blue"},{"statement":"Water is wet"}]"#,
        )
        .unwrap();
        let src = make_src("t", &p.to_string_lossy(), ImportKind::JsonFile, None);
        let claims = emit_claims(&src, tmp.path()).unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].0, "The sky is blue");
        assert_eq!(claims[0].1, "import:session");
        assert_eq!(claims[0].2, "global");
    }

    #[test]
    fn emit_claims_json_file_array_of_strings() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("strs.json");
        std::fs::write(&p, r#"["fact one here","fact two here"]"#).unwrap();
        let src = make_src("t", &p.to_string_lossy(), ImportKind::JsonFile, None);
        let claims = emit_claims(&src, tmp.path()).unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].0, "fact one here");
    }

    #[test]
    fn emit_claims_json_file_short_strings_skipped() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("short.json");
        // "ok" is 2 chars < 8 threshold; "long enough fact" is fine
        std::fs::write(&p, r#"["ok","long enough fact here"]"#).unwrap();
        let src = make_src("t", &p.to_string_lossy(), ImportKind::JsonFile, None);
        let claims = emit_claims(&src, tmp.path()).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "long enough fact here");
    }

    #[test]
    fn emit_claims_markdown_file_extracts_paragraphs() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("notes.md");
        std::fs::write(
            &p,
            "# My Heading\n\nThis is a paragraph about something important.\n\nAnother paragraph.\n",
        )
        .unwrap();
        let src = make_src("t", &p.to_string_lossy(), ImportKind::MarkdownFile, None);
        let claims = emit_claims(&src, tmp.path()).unwrap();
        // At minimum the heading and paragraphs should produce claims
        assert!(!claims.is_empty(), "should extract at least one claim");
        assert!(
            claims.iter().any(|(s, _, _)| s.contains("important")),
            "paragraph text must appear in claims; got {claims:?}"
        );
    }

    #[test]
    fn emit_claims_markdown_dir_walks_md_files() {
        let tmp = tempdir().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(
            vault.join("a.md"),
            "# Server facts\n\nThe cube server is at 100.68.210.50.\n",
        )
        .unwrap();
        std::fs::write(vault.join("b.md"), "Short.\n").unwrap(); // too short → 0 claims
        std::fs::write(vault.join("c.txt"), "ignored\n").unwrap(); // wrong ext → skip
        let src = make_src("v", &vault.to_string_lossy(), ImportKind::Markdown, None);
        let claims = emit_claims(&src, tmp.path()).unwrap();
        assert!(!claims.is_empty());
        assert!(claims.iter().any(|(s, _, _)| s.contains("100.68.210.50")));
        assert!(claims.iter().all(|(_, tag, _)| tag == "import:obsidian"));
    }

    #[test]
    fn emit_claims_sqlite_reads_text_columns() {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("mem.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE memories (id INTEGER PRIMARY KEY, text TEXT, score REAL);\
             INSERT INTO memories VALUES (1,'The operator lives in Germany',0.9);\
             INSERT INTO memories VALUES (2,'The assistant must speak German',0.8);",
        )
        .unwrap();
        drop(conn);
        let src = make_src(
            "mem",
            &db_path.to_string_lossy(),
            ImportKind::Sqlite,
            Some("hermes"),
        );
        let claims = emit_claims(&src, tmp.path()).unwrap();
        assert_eq!(claims.len(), 2, "two text rows expected; got {claims:?}");
        assert!(claims.iter().all(|(_, tag, _)| tag == "import:hermes"));
        assert!(claims
            .iter()
            .any(|(s, _, _)| s.contains("operator lives in Germany")));
    }

    #[test]
    fn emit_claims_lance_arrow_bails() {
        let tmp = tempdir().unwrap();
        // LanceArrow, FaissFlat, GitTree must bail — not crash
        for kind in [
            ImportKind::LanceArrow,
            ImportKind::FaissFlat,
            ImportKind::GitTree,
        ] {
            let src = make_src("t", &tmp.path().to_string_lossy(), kind, None);
            let result = emit_claims(&src, tmp.path());
            assert!(result.is_err(), "{kind:?} must return Err");
        }
    }

    #[test]
    fn source_tag_for_sqlite_hint_variants() {
        let mk = |hint: Option<&str>| ImportSource {
            name: "x".into(),
            path: ".".into(),
            kind: ImportKind::Sqlite,
            hint: hint.map(String::from),
        };
        assert_eq!(source_tag_for(&mk(Some("hermes"))), "import:hermes");
        assert_eq!(source_tag_for(&mk(Some("openhuman"))), "import:openhuman");
        assert_eq!(source_tag_for(&mk(Some("cq-commons"))), "import:openclaw");
        assert_eq!(source_tag_for(&mk(Some("veronica"))), "import:veronica");
        assert_eq!(source_tag_for(&mk(None)), "import:openclaw"); // fallback
    }
}
