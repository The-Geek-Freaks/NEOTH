//! Filesystem walker for K-Repo-Map Phase 1 (Session 14 Pick #13).
//!
//! Walks the operator's project root respecting `.gitignore` /
//! `.ignore` / `.neothignore` semantics, classifies each file by
//! language, captures LOC + bytes, returns a structured `RepoMap`.
//!
//! Hard rules:
//!   - **NO file bodies in the map**. Operator privacy: source is read
//!     transiently when symbol extraction is enabled, but the map persists
//!     only paths, counts, hashes, languages, and declaration metadata.
//!   - **Respects existing ignore files**: `.gitignore`,
//!     `.ignore`, plus NEOTH-specific `.neothignore` for "operator
//!     wants this hidden from the LLM context" semantics.
//!   - **Bounded scan**: max files + max bytes cap so a pathological
//!     repo (millions of files) doesn't blow operator's memory.
//!   - **Pure scan, no I/O side effects**: no SQLite writes, no WAL,
//!     no provider calls. The result is in-memory; persistence is
//!     the caller's choice.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use std::{fs::File, io::Read};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::symbols::{Symbol, extract_symbols};

/// Languages NEOTH currently recognises via extension or shebang.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    Python,
    TypeScript,
    JavaScript,
    Go,
    C,
    Cpp,
    Java,
    Kotlin,
    Swift,
    CSharp,
    Ruby,
    PhpLang,
    Shell,
    Lua,
    Markdown,
    Toml,
    Yaml,
    Json,
    Html,
    Css,
    Sql,
    Dockerfile,
    Other,
}

impl Language {
    /// Classify by file extension. Returns [`Language::Other`] for
    /// extensions we don't recognise — Phase 2 widens this list.
    pub fn from_path(path: &Path) -> Self {
        // Special-case Dockerfile / Makefile (no extension).
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower == "dockerfile" || lower.starts_with("dockerfile.") {
                return Language::Dockerfile;
            }
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase());
        match ext.as_deref() {
            Some("rs") => Language::Rust,
            Some("py") | Some("pyi") => Language::Python,
            Some("ts") | Some("tsx") => Language::TypeScript,
            Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => Language::JavaScript,
            Some("go") => Language::Go,
            Some("c") | Some("h") => Language::C,
            Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") | Some("hh") | Some("hxx") => {
                Language::Cpp
            }
            Some("java") => Language::Java,
            Some("kt") | Some("kts") => Language::Kotlin,
            Some("swift") => Language::Swift,
            Some("cs") => Language::CSharp,
            Some("rb") => Language::Ruby,
            Some("php") => Language::PhpLang,
            Some("sh") | Some("bash") | Some("zsh") => Language::Shell,
            Some("lua") => Language::Lua,
            Some("md") | Some("markdown") => Language::Markdown,
            Some("toml") => Language::Toml,
            Some("yaml") | Some("yml") => Language::Yaml,
            Some("json") => Language::Json,
            Some("html") | Some("htm") => Language::Html,
            Some("css") | Some("scss") | Some("sass") => Language::Css,
            Some("sql") => Language::Sql,
            _ => Language::Other,
        }
    }

    /// Operator-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Go => "go",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Java => "java",
            Language::Kotlin => "kotlin",
            Language::Swift => "swift",
            Language::CSharp => "csharp",
            Language::Ruby => "ruby",
            Language::PhpLang => "php",
            Language::Shell => "shell",
            Language::Lua => "lua",
            Language::Markdown => "markdown",
            Language::Toml => "toml",
            Language::Yaml => "yaml",
            Language::Json => "json",
            Language::Html => "html",
            Language::Css => "css",
            Language::Sql => "sql",
            Language::Dockerfile => "dockerfile",
            Language::Other => "other",
        }
    }

    /// True when the language is currently considered "code" (vs
    /// documentation / configuration / markup). Drives the
    /// recall-context prioritisation in Phase 3.
    pub fn is_code(self) -> bool {
        matches!(
            self,
            Language::Rust
                | Language::Python
                | Language::TypeScript
                | Language::JavaScript
                | Language::Go
                | Language::C
                | Language::Cpp
                | Language::Java
                | Language::Kotlin
                | Language::Swift
                | Language::CSharp
                | Language::Ruby
                | Language::PhpLang
                | Language::Shell
                | Language::Lua
                | Language::Sql
        )
    }
}

/// One indexed file. Path is repo-relative so the map stays portable
/// across operator machines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoFile {
    /// Repo-relative path (forward-slash separator on every platform).
    pub path: String,
    /// Classified language.
    pub language: Language,
    /// File size in bytes (UTF-8 bytes, not characters).
    pub bytes: u64,
    /// Newline-counted line count. `0` for empty files.
    pub loc: u64,
    /// SHA-256 hex digest of the file contents. Used by the incremental
    /// re-indexer (CBM-04) to skip files whose content + mtime are
    /// unchanged since the last persist. `#[serde(default)]` keeps
    /// existing JSON serialised maps backward-compatible (v1 had no
    /// hash column).
    #[serde(default)]
    pub sha256: String,
    /// File modification time as nanoseconds since UNIX epoch. Stored
    /// as `u64` in-memory; persisted as `i64` in SQLite (matching the
    /// existing `scanned_at INTEGER` pattern). `0` when the OS returns
    /// an error from `metadata().modified()`.
    #[serde(default)]
    pub mtime_ns: u64,
    /// Extracted top-level declarations. Populated only when the
    /// builder ran with `with_symbols(true)`; empty otherwise so
    /// callers don't have to special-case Phase-1 maps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<Symbol>,
}

/// Operator-facing scan summary. Mirrors what `neoth code-map scan
/// <path>` would render.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub total_files: u64,
    pub total_bytes: u64,
    pub total_loc: u64,
    /// Per-language file counts, ordered by descending count.
    pub by_language: Vec<(Language, u64)>,
    /// Files skipped because they exceeded `max_file_bytes`.
    pub oversize_skipped: u64,
    /// Number of regular entries visited when the scan hit any aggregate work
    /// ceiling (`max_files`, total source bytes, symbols, or metadata text).
    pub truncated_at: Option<u64>,
}

/// Full repo map. Serialisable to `~/.neoth/code_map.json` in Phase 3.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RepoMap {
    /// Root directory the scan started from (absolute, canonicalised).
    pub root: String,
    pub files: Vec<RepoFile>,
    pub report: ScanReport,
}

/// Hard cap on a single file's size. Files above this contribute to
/// `oversize_skipped`. Picked at 2 MiB so the operator's repo can
/// include reasonable-size generated SQL fixtures + minified bundles
/// without ballooning the map.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Hard cap on total files counted. Pathological monorepos with
/// 1M+ files would otherwise blow operator memory. Above this, scan
/// truncates + sets `report.truncated_at`.
pub const DEFAULT_MAX_FILES: u64 = 50_000;
/// Aggregate bytes read by one scan. Files are processed sequentially, but a
/// finite corpus budget prevents a valid-looking 50k × 2MiB tree from turning
/// one persistence command into an unbounded CPU/I/O job.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
/// Maximum declarations retained in one in-memory map before persistence.
pub const DEFAULT_MAX_SYMBOLS: usize = 250_000;
/// Maximum path/hash/declaration text retained in one in-memory map.
pub const DEFAULT_MAX_METADATA_TEXT_BYTES: usize = 32 * 1024 * 1024;

/// Build pipeline for a `RepoMap`. Bounded by file count + byte size.
pub struct RepoMapBuilder {
    root: PathBuf,
    included_relative_paths: Option<Vec<PathBuf>>,
    excluded_relative_paths: Vec<PathBuf>,
    max_file_bytes: u64,
    max_files: u64,
    max_total_bytes: u64,
    max_symbols: usize,
    max_metadata_text_bytes: usize,
    include_hidden: bool,
    with_symbols: bool,
    strict_errors: bool,
}

impl RepoMapBuilder {
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Self {
            root: root.into(),
            included_relative_paths: None,
            excluded_relative_paths: Vec::new(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_symbols: DEFAULT_MAX_SYMBOLS,
            max_metadata_text_bytes: DEFAULT_MAX_METADATA_TEXT_BYTES,
            include_hidden: false,
            with_symbols: false,
            strict_errors: false,
        }
    }

    /// Override the per-file size cap. Default
    /// [`DEFAULT_MAX_FILE_BYTES`].
    pub fn max_file_bytes(mut self, n: u64) -> Self {
        self.max_file_bytes = n;
        self
    }

    /// Override the total-file cap. Default [`DEFAULT_MAX_FILES`].
    pub fn max_files(mut self, n: u64) -> Self {
        self.max_files = n;
        self
    }

    /// Override the aggregate source-byte work cap. Primarily useful for
    /// bounded diagnostics and regression tests.
    pub fn max_total_bytes(mut self, n: u64) -> Self {
        self.max_total_bytes = n;
        self
    }

    /// Override the aggregate retained declaration cap.
    pub fn max_symbols(mut self, n: usize) -> Self {
        self.max_symbols = n;
        self
    }

    /// Override the aggregate retained path/hash/declaration text cap.
    pub fn max_metadata_text_bytes(mut self, n: usize) -> Self {
        self.max_metadata_text_bytes = n;
        self
    }

    /// Include dotfiles + hidden directories. Default `false`
    /// (operator typically wants `.git/`, `target/`, etc. skipped).
    pub fn include_hidden(mut self, b: bool) -> Self {
        self.include_hidden = b;
        self
    }

    /// Enable Phase-2 symbol extraction. When `true`, each
    /// [`RepoFile`] for a recognised code language gets its
    /// top-level declarations populated via
    /// [`super::symbols::extract_symbols`]. Default `false` so the
    /// scan stays I/O-only — symbol extraction re-reads + regex-scans
    /// every code file.
    pub fn with_symbols(mut self, b: bool) -> Self {
        self.with_symbols = b;
        self
    }

    /// Fail the scan when the walker cannot enumerate, stat, or read a file.
    /// Completion-producing snapshots enable this so an I/O omission cannot be
    /// certified as a complete repository map. Interactive partial scans keep
    /// the historical best-effort behaviour unless they opt in.
    pub fn strict_errors(mut self, strict: bool) -> Self {
        self.strict_errors = strict;
        self
    }

    /// Exclude exact repo-relative files or complete repo-relative subtrees.
    ///
    /// Completion-producing callers use this for mutable runtime state that
    /// lives below an otherwise valid source root. Invalid/escaping paths are
    /// rejected by [`scan`](Self::scan); they are never silently ignored.
    pub fn exclude_relative_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.excluded_relative_paths.extend(paths);
        self
    }

    /// Restrict the scan to explicit repo-relative files or subtrees. Ancestor
    /// directories are traversed only to reach an included path. Calling this
    /// with an empty iterator intentionally produces an empty source corpus.
    pub fn include_relative_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.included_relative_paths = Some(paths.into_iter().collect());
        self
    }

    /// Run the scan. Synchronous + sequential — fast enough for
    /// repos up to ~50k files. Phase 2 may switch to parallel walking
    /// via `ignore::WalkBuilder::threads(N)`.
    pub fn scan(self) -> Result<RepoMap> {
        // A raw-path fallback poisons every downstream containment and cache
        // key: the same directory can then be persisted under aliases, or a
        // missing root can masquerade as an empty successful scan. Resolve the
        // canonical physical root once and fail visibly before walking.
        let canonical_root = super::root_identity::CanonicalRepoRoot::discover(&self.root)?;
        let root_canonical = canonical_root.path().to_path_buf();
        let root_str = canonical_root.display().to_owned();
        let included_relative_paths = self
            .included_relative_paths
            .as_deref()
            .map(normalize_relative_scope_paths)
            .transpose()?;
        let excluded_relative_paths =
            normalize_relative_scope_paths(&self.excluded_relative_paths)?;
        if let Some(included_relative_paths) = &included_relative_paths {
            for included in included_relative_paths {
                anyhow::ensure!(
                    !excluded_relative_paths
                        .iter()
                        .any(|excluded| included.starts_with(excluded)),
                    "code-map include {} is contained by an excluded path",
                    included.display()
                );
            }
        }
        let mut files: Vec<RepoFile> = Vec::new();
        let mut report = ScanReport::default();
        let mut by_lang: std::collections::HashMap<Language, u64> =
            std::collections::HashMap::new();
        let mut visited_files: u64 = 0;
        let mut scanned_source_bytes: u64 = 0;
        let mut retained_symbols: usize = 0;
        let mut retained_metadata_text_bytes: usize = root_str.len();

        let mut builder = WalkBuilder::new(&root_canonical);
        builder
            .hidden(!self.include_hidden) // hidden(true) means HIDE hidden files
            .git_ignore(true)
            .git_exclude(true)
            .git_global(true)
            .require_git(false) // honour .gitignore even outside a git repo
            .add_custom_ignore_filename(".neothignore")
            .follow_links(false);

        let generated_root = root_canonical.clone();
        builder.filter_entry(move |entry| {
            let Ok(relative) = entry.path().strip_prefix(&generated_root) else {
                return false;
            };
            let generated = relative
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == "graphify-out");
            let included = included_relative_paths
                .as_ref()
                .is_none_or(|included_paths| {
                    included_paths.iter().any(|included| {
                        relative.starts_with(included) || included.starts_with(relative)
                    })
                });
            !generated
                && included
                && !excluded_relative_paths
                    .iter()
                    .any(|excluded| relative.starts_with(excluded))
        });
        for entry in builder.build() {
            let entry = match entry {
                Ok(e) => e,
                Err(error) if self.strict_errors => {
                    return Err(anyhow::anyhow!(error))
                        .context("walk repository for complete code-map snapshot");
                }
                Err(_) => continue,
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            if visited_files >= self.max_files {
                report.truncated_at = Some(visited_files);
                break;
            }
            // The work bound applies to every regular entry, including files
            // later rejected as oversized. Otherwise a tree containing only
            // oversized files can bypass `max_files` and force an unbounded
            // stat/read walk.
            visited_files += 1;
            let path = entry.path();
            let meta = match path.metadata() {
                Ok(m) => m,
                Err(error) if self.strict_errors => {
                    return Err(error).with_context(|| {
                        format!("read metadata for code-map file {}", path.display())
                    });
                }
                Err(_) => continue,
            };
            if meta.len() > self.max_file_bytes {
                report.oversize_skipped += 1;
                continue;
            }

            // Single bounded read — used for LOC, hash, and (if with_symbols)
            // symbol extraction. The actual byte count is authoritative: a
            // file may grow after metadata or report a synthetic length.
            let raw = match read_file_bounded(path, self.max_file_bytes) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    report.oversize_skipped += 1;
                    continue;
                }
                Err(error) if self.strict_errors => {
                    return Err(error)
                        .with_context(|| format!("read code-map file {}", path.display()));
                }
                Err(_) => continue,
            };
            let bytes = raw.len() as u64;
            let next_source_bytes = scanned_source_bytes
                .checked_add(bytes)
                .context("code-map aggregate source-byte count overflow")?;
            if next_source_bytes > self.max_total_bytes {
                if self.strict_errors {
                    anyhow::bail!(
                        "code-map scan exceeds aggregate {}-byte source budget; refusing a partial completion snapshot",
                        self.max_total_bytes
                    );
                }
                report.truncated_at = Some(visited_files);
                break;
            }
            scanned_source_bytes = next_source_bytes;
            let loc = count_lines_from_bytes(&raw);

            // mtime_ns: nanoseconds since UNIX epoch. Fallback 0 on error
            // (e.g. platforms that don't expose sub-second precision).
            let mtime_ns: u64 = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            // SHA-256 of the raw file bytes — authoritative skip guard.
            let sha256 = {
                let digest = Sha256::digest(&raw);
                format!("{digest:x}")
            };

            let language = Language::from_path(path);
            let rel = path
                .strip_prefix(&root_canonical)
                .with_context(|| {
                    format!(
                        "walked path {} escaped canonical repository root {}",
                        path.display(),
                        root_canonical.display()
                    )
                })?
                .to_string_lossy()
                .replace('\\', "/");

            // Symbol extraction: opt-in, only for code languages. File bytes
            // are already in `raw` — convert to &str without a second read.
            let symbols = if self.with_symbols && language.is_code() {
                let text = String::from_utf8_lossy(&raw);
                extract_symbols(&text, language)
            } else {
                Vec::new()
            };

            let next_symbol_count = retained_symbols
                .checked_add(symbols.len())
                .context("code-map aggregate symbol count overflow")?;
            let mut next_metadata_text_bytes = retained_metadata_text_bytes
                .checked_add(rel.len())
                .and_then(|bytes| bytes.checked_add(sha256.len()))
                .context("code-map aggregate metadata text-byte count overflow")?;
            for symbol in &symbols {
                next_metadata_text_bytes = next_metadata_text_bytes
                    .checked_add(symbol.name.len())
                    .and_then(|bytes| bytes.checked_add(symbol.kind.label().len()))
                    .context("code-map aggregate declaration text-byte count overflow")?;
            }
            if next_symbol_count > self.max_symbols
                || next_metadata_text_bytes > self.max_metadata_text_bytes
            {
                if self.strict_errors {
                    anyhow::bail!(
                        "code-map scan exceeds retained metadata budget (symbols {next_symbol_count}/{}, text bytes {next_metadata_text_bytes}/{}); refusing a partial completion snapshot",
                        self.max_symbols,
                        self.max_metadata_text_bytes
                    );
                }
                report.truncated_at = Some(visited_files);
                break;
            }
            retained_symbols = next_symbol_count;
            retained_metadata_text_bytes = next_metadata_text_bytes;

            files.push(RepoFile {
                path: rel,
                language,
                bytes,
                loc,
                sha256,
                mtime_ns,
                symbols,
            });
            report.total_files += 1;
            report.total_bytes += bytes;
            report.total_loc += loc;
            *by_lang.entry(language).or_insert(0) += 1;
        }

        let mut by_language: Vec<_> = by_lang.into_iter().collect();
        by_language.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.label().cmp(b.0.label())));
        report.by_language = by_language;

        Ok(RepoMap {
            root: root_str,
            files,
            report,
        })
    }
}

pub(crate) fn normalize_relative_scope_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut normalized = Vec::with_capacity(paths.len());
    for path in paths {
        let mut clean = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::Normal(part) => clean.push(part),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_) => anyhow::bail!(
                    "code-map exclusion must be a contained relative path: {}",
                    path.display()
                ),
            }
        }
        anyhow::ensure!(
            !clean.as_os_str().is_empty(),
            "code-map exclusion cannot name the repository root"
        );
        normalized.push(clean);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

pub(crate) fn read_file_bounded(
    path: &Path,
    max_file_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let mut raw = Vec::new();
    file.take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_file_bytes {
        Ok(None)
    } else {
        Ok(Some(raw))
    }
}

/// Count newline characters from already-read bytes. Empty file → 0.
/// Adds 1 for the last line when the file doesn't end with a newline
/// and is non-empty (typical for source code).
fn count_lines_from_bytes(raw: &[u8]) -> u64 {
    let count = raw.iter().filter(|&&b| b == b'\n').count() as u64;
    if !raw.is_empty() && raw.last() != Some(&b'\n') {
        count + 1
    } else {
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn language_from_rust_path() {
        assert_eq!(
            Language::from_path(Path::new("src/main.rs")),
            Language::Rust
        );
    }

    #[test]
    fn language_from_python_path() {
        assert_eq!(Language::from_path(Path::new("app.py")), Language::Python);
        assert_eq!(
            Language::from_path(Path::new("types.pyi")),
            Language::Python
        );
    }

    #[test]
    fn language_from_typescript_path() {
        assert_eq!(
            Language::from_path(Path::new("App.tsx")),
            Language::TypeScript
        );
        assert_eq!(
            Language::from_path(Path::new("util.ts")),
            Language::TypeScript
        );
    }

    #[test]
    fn language_from_dockerfile() {
        assert_eq!(
            Language::from_path(Path::new("Dockerfile")),
            Language::Dockerfile
        );
        assert_eq!(
            Language::from_path(Path::new("Dockerfile.prod")),
            Language::Dockerfile
        );
    }

    #[test]
    fn language_from_unknown_extension() {
        assert_eq!(Language::from_path(Path::new("foo.xyz")), Language::Other);
        assert_eq!(Language::from_path(Path::new("LICENSE")), Language::Other);
    }

    #[test]
    fn language_label_matches_serde() {
        // Drift guard: serde rename_all="lowercase" must match
        // the `label()` output exactly so `neoth code-map scan
        // --output json` produces stable values consumable by
        // operator scripts.
        for lang in [Language::Rust, Language::Python, Language::Go] {
            let json = serde_json::to_value(lang).unwrap();
            let s = json.as_str().unwrap();
            assert_eq!(s, lang.label(), "drift for {lang:?}");
        }
    }

    #[test]
    fn is_code_classifies_source_languages() {
        assert!(Language::Rust.is_code());
        assert!(Language::Python.is_code());
        assert!(Language::Sql.is_code());
        // Documentation / config aren't "code"
        assert!(!Language::Markdown.is_code());
        assert!(!Language::Json.is_code());
        assert!(!Language::Yaml.is_code());
        assert!(!Language::Dockerfile.is_code());
    }

    #[test]
    fn scan_empty_directory_returns_empty_map() {
        let dir = tempdir().unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        assert_eq!(map.report.total_files, 0);
        assert!(map.files.is_empty());
    }

    #[test]
    fn scan_fails_when_root_cannot_be_canonicalized() {
        let root = tempdir().unwrap();
        let missing = root.path().join("does-not-exist");
        let error = RepoMapBuilder::new(&missing).scan().unwrap_err();
        assert!(
            error.to_string().contains("canonicalize repository root"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn scan_finds_files_in_subdirs() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.path().join("README.md"), "# hi\n").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        assert_eq!(map.report.total_files, 2);
        // Paths should be repo-relative + forward-slash normalised.
        let paths: Vec<&str> = map.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"README.md"));
    }

    #[test]
    fn scan_classifies_languages_per_file() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn x() {}\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "def y():\n  pass\n").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let langs: std::collections::HashSet<Language> =
            map.files.iter().map(|f| f.language).collect();
        assert!(langs.contains(&Language::Rust));
        assert!(langs.contains(&Language::Python));
    }

    #[test]
    fn scan_respects_gitignore() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "target/\n*.log\n").unwrap();
        std::fs::create_dir_all(dir.path().join("target/debug")).unwrap();
        std::fs::write(dir.path().join("target/debug/junk.bin"), "x").unwrap();
        std::fs::write(dir.path().join("error.log"), "boom").unwrap();
        std::fs::write(dir.path().join("ok.txt"), "fine").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let paths: Vec<&str> = map.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"ok.txt"));
        assert!(!paths.iter().any(|p| p.contains("target/")));
        assert!(!paths.iter().any(|p| p.ends_with(".log")));
    }

    #[test]
    fn scan_respects_neothignore() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".neothignore"), "secrets.txt\n").unwrap();
        std::fs::write(dir.path().join("secrets.txt"), "shh").unwrap();
        std::fs::write(dir.path().join("public.txt"), "hello").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let paths: Vec<&str> = map.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"public.txt"));
        assert!(!paths.contains(&"secrets.txt"));
    }

    #[test]
    fn scan_applies_explicit_file_and_subtree_exclusions_before_bounds() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("runtime/nested")).unwrap();
        std::fs::write(dir.path().join("source.rs"), "fn source() {}\n").unwrap();
        std::fs::write(dir.path().join("state.json"), "{}\n").unwrap();
        std::fs::write(dir.path().join("runtime/nested/wal.bin"), "mutable").unwrap();

        let map = RepoMapBuilder::new(dir.path())
            .max_files(1)
            .exclude_relative_paths([PathBuf::from("state.json"), PathBuf::from("runtime")])
            .scan()
            .unwrap();

        assert_eq!(map.report.total_files, 1);
        assert_eq!(map.report.truncated_at, None);
        assert_eq!(map.files[0].path, "source.rs");
    }

    #[test]
    fn scan_exact_include_traverses_ancestors_but_omits_siblings() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nested/deeper")).unwrap();
        std::fs::write(
            dir.path().join("nested/deeper/target.rs"),
            "fn target() {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("nested/deeper/sibling.rs"),
            "fn sibling() {}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("root_sibling.rs"), "fn root_sibling() {}\n").unwrap();

        let map = RepoMapBuilder::new(dir.path())
            .include_relative_paths([PathBuf::from("nested/deeper/target.rs")])
            .scan()
            .unwrap();

        assert_eq!(map.report.total_files, 1);
        assert_eq!(map.files[0].path, "nested/deeper/target.rs");
    }

    #[test]
    fn scan_rejects_exclusions_that_escape_the_root() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("source.rs"), "fn source() {}\n").unwrap();

        let error = RepoMapBuilder::new(dir.path())
            .exclude_relative_paths([PathBuf::from("../outside")])
            .scan()
            .unwrap_err();

        assert!(error.to_string().contains("contained relative path"));
    }

    #[test]
    fn scan_rejects_includes_that_escape_the_root() {
        let dir = tempdir().unwrap();
        let error = RepoMapBuilder::new(dir.path())
            .include_relative_paths([PathBuf::from("../outside")])
            .scan()
            .unwrap_err();
        assert!(error.to_string().contains("contained relative path"));
    }

    #[test]
    fn scan_skips_hidden_directories_by_default() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "ref").unwrap();
        std::fs::write(dir.path().join("visible.txt"), "x").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let paths: Vec<&str> = map.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"visible.txt"));
        assert!(!paths.iter().any(|p| p.contains(".git")), "got: {paths:?}");
    }

    #[test]
    fn scan_respects_max_files_cap() {
        let dir = tempdir().unwrap();
        for i in 0..10 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), "x").unwrap();
        }
        let map = RepoMapBuilder::new(dir.path()).max_files(5).scan().unwrap();
        assert!(map.report.total_files <= 5);
        assert!(map.report.truncated_at.is_some());
    }

    #[test]
    fn strict_scan_refuses_aggregate_source_budget_before_completion() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.path().join("b.rs"), "fn b() {}\n").unwrap();

        let error = RepoMapBuilder::new(dir.path())
            .max_total_bytes(12)
            .strict_errors(true)
            .scan()
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("aggregate 12-byte source budget")
        );
    }

    #[test]
    fn strict_scan_refuses_aggregate_symbol_budget_before_completion() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();

        let error = RepoMapBuilder::new(dir.path())
            .with_symbols(true)
            .max_symbols(1)
            .strict_errors(true)
            .scan()
            .unwrap_err();

        assert!(error.to_string().contains("symbols 2/1"));
    }

    #[test]
    fn scan_marks_oversize_files() {
        let dir = tempdir().unwrap();
        let big = vec![b'x'; 1024 * 1024];
        std::fs::write(dir.path().join("big.bin"), &big).unwrap();
        std::fs::write(dir.path().join("small.txt"), "tiny").unwrap();
        let map = RepoMapBuilder::new(dir.path())
            .max_file_bytes(100)
            .scan()
            .unwrap();
        assert_eq!(map.report.oversize_skipped, 1);
        // small.txt still landed.
        assert!(map.files.iter().any(|f| f.path == "small.txt"));
    }

    #[test]
    fn bounded_reader_rejects_file_that_grows_after_metadata() {
        use std::io::Write as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("growing.txt");
        std::fs::write(&path, "x").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        assert_eq!(before.len(), 1);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[b'x'; 32]).unwrap();

        assert!(read_file_bounded(&path, 8).unwrap().is_none());
    }

    #[test]
    fn max_files_bounds_oversize_entries_too() {
        let dir = tempdir().unwrap();
        for index in 0..8 {
            std::fs::write(dir.path().join(format!("oversize-{index}.txt")), "xx").unwrap();
        }

        let map = RepoMapBuilder::new(dir.path())
            .max_files(3)
            .max_file_bytes(1)
            .scan()
            .unwrap();

        assert_eq!(map.report.total_files, 0);
        assert_eq!(map.report.oversize_skipped, 3);
        assert_eq!(map.report.truncated_at, Some(3));
    }

    #[test]
    fn scan_counts_loc_correctly() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("three.txt"), "a\nb\nc\n").unwrap();
        std::fs::write(dir.path().join("no_trailing.txt"), "a\nb\nc").unwrap();
        std::fs::write(dir.path().join("empty.txt"), "").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let three = map.files.iter().find(|f| f.path == "three.txt").unwrap();
        let no_trail = map
            .files
            .iter()
            .find(|f| f.path == "no_trailing.txt")
            .unwrap();
        let empty = map.files.iter().find(|f| f.path == "empty.txt").unwrap();
        assert_eq!(three.loc, 3);
        assert_eq!(no_trail.loc, 3);
        assert_eq!(empty.loc, 0);
    }

    #[test]
    fn scan_aggregates_report() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn x() {}\n").unwrap();
        std::fs::write(dir.path().join("b.rs"), "fn y() {}\n").unwrap();
        std::fs::write(dir.path().join("c.md"), "# heading\n").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        assert_eq!(map.report.total_files, 3);
        let rust_count = map
            .report
            .by_language
            .iter()
            .find(|(l, _)| *l == Language::Rust)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        assert_eq!(rust_count, 2);
    }

    #[test]
    fn paths_use_forward_slashes_on_every_platform() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        std::fs::write(dir.path().join("a/b/c/deep.txt"), "x").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let f = map.files.iter().find(|f| f.path.contains("deep")).unwrap();
        assert!(
            !f.path.contains('\\'),
            "backslash leaked into path: {}",
            f.path
        );
        assert!(f.path.ends_with("a/b/c/deep.txt"), "got: {}", f.path);
    }
}
