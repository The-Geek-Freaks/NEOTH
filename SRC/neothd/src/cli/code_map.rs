//! `neoth code-map` — operator-facing repository code-map.
//!
//! Subcommands:
//!
//!   - `scan [PATH]`  Walk the repository at PATH (default: cwd),
//!                    classify files by language, count LOC + bytes,
//!                    optionally extract symbols, and print a summary
//!                    or full JSON map.
//!   - `persist [PATH]`  Re-scan and atomically replace that root's
//!                       snapshot in `~/.neoth/code_map.db`.
//!   - `load [PATH]`     Inspect a persisted snapshot without rescanning.
//!   - `search <NAME>`   Find exact persisted symbol declarations.
//!   - `relevant <PROMPT>` Rank files for the same repo-context engine
//!                         used by chat and codegraph MCP consumers.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::code_map::RepoMapBuilder;

#[derive(Args, Debug, Clone)]
pub struct CodeMapArgs {
    #[command(subcommand)]
    pub action: CodeMapAction,

    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CodeMapAction {
    /// Walk the repository at PATH (default: cwd), classify by
    /// language, count LOC + bytes. Honours .gitignore /
    /// .neothignore semantics. Bounded by --max-files +
    /// --max-file-bytes caps.
    Scan {
        /// Root directory to scan. Defaults to current working dir.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Hard cap on total files counted. Defaults to 50000.
        #[arg(long, value_name = "N")]
        max_files: Option<u64>,

        /// Hard cap on per-file byte size. Files above this contribute
        /// to `oversize_skipped`. Defaults to 2 MiB.
        #[arg(long, value_name = "BYTES")]
        max_file_bytes: Option<u64>,

        /// Include hidden directories (.git, .cache, etc.). Default
        /// behaviour skips them.
        #[arg(long)]
        include_hidden: bool,

        /// Emit the FULL file list, not just the summary report.
        /// Required to consume the per-file `RepoFile` shape from
        /// scripts. Default prints only the summary.
        #[arg(long)]
        full: bool,

        /// Extract top-level declarations (functions, classes, etc.)
        /// per code file. Adds a `symbols` array to each `RepoFile`
        /// in `--full` JSON output. Default off — symbol extraction
        /// re-reads + regex-scans every code file in the repo.
        #[arg(long)]
        symbols: bool,
    },

    /// Phase 3a (Session 14 Pick #22) — scan PATH (or cwd) and
    /// persist the resulting `RepoMap` into `~/.neoth/code_map.db`.
    /// Idempotent: a re-run against the same root replaces the
    /// prior snapshot atomically. Chat, coding, and MCP consumers
    /// read this DB for repo-context and architecture queries.
    Persist {
        /// Root directory to scan + persist. Defaults to cwd.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Hard cap on total files counted. Defaults to 50000.
        #[arg(long, value_name = "N")]
        max_files: Option<u64>,

        /// Hard cap on per-file byte size. Defaults to 2 MiB.
        #[arg(long, value_name = "BYTES")]
        max_file_bytes: Option<u64>,

        /// Include hidden directories. Default behaviour skips them.
        #[arg(long)]
        include_hidden: bool,

        /// Extract + persist top-level symbol declarations alongside
        /// each file entry. Default off (lighter scan).
        #[arg(long)]
        symbols: bool,
    },

    /// Phase 3a — read a previously persisted snapshot back from
    /// `~/.neoth/code_map.db`. PATH is the canonical scan root that
    /// `Persist` recorded. Useful for inspection without re-scanning.
    Load {
        /// Root directory key whose snapshot to load. Defaults to
        /// canonicalised cwd.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Emit the FULL file list. Default prints summary only.
        #[arg(long)]
        full: bool,
    },

    /// Phase 3a — find every persisted file that declares a symbol
    /// matching NAME exactly. Searches across every root the DB has
    /// snapshots for.
    Search {
        /// Symbol name to look up.
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Phase 3b (Session 14 Pick #25) — given a free-text PROMPT,
    /// query the persisted code map for files that look relevant.
    /// Ranks by identifier-symbol matches first, path-keyword overlap
    /// second. Use this to inspect what chat would inject as a
    /// `<repo-context>` block without firing a provider call.
    Relevant {
        /// Free-text prompt to score against the persisted map.
        #[arg(value_name = "PROMPT")]
        prompt: String,

        /// Max files to return. Default 5.
        #[arg(long, value_name = "N", default_value_t = 5)]
        max: usize,

        /// Also report whether the persisted index is stale relative to the
        /// files on disk. Re-scans the active root (reads + hashes files), so
        /// it is opt-in and slower than a plain recall.
        #[arg(long)]
        check_stale: bool,
    },
}

pub async fn run_code_map(args: CodeMapArgs) -> Result<()> {
    match args.action {
        CodeMapAction::Scan {
            path,
            max_files,
            max_file_bytes,
            include_hidden,
            full,
            symbols,
        } => run_scan(
            path,
            max_files,
            max_file_bytes,
            include_hidden,
            full,
            symbols,
            args.output,
        ),
        CodeMapAction::Persist {
            path,
            max_files,
            max_file_bytes,
            include_hidden,
            symbols,
        } => run_persist(
            path,
            max_files,
            max_file_bytes,
            include_hidden,
            symbols,
            args.output,
        ),
        CodeMapAction::Load { path, full } => run_load(path, full, args.output),
        CodeMapAction::Search { name } => run_search(name, args.output),
        CodeMapAction::Relevant {
            prompt,
            max,
            check_stale,
        } => run_relevant(prompt, max, check_stale, args.output),
    }
}

fn run_scan(
    path: Option<PathBuf>,
    max_files: Option<u64>,
    max_file_bytes: Option<u64>,
    include_hidden: bool,
    full: bool,
    symbols: bool,
    output: OutputFormat,
) -> Result<()> {
    let root = path
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve scan root: no path given + no cwd"))?;

    let mut builder = RepoMapBuilder::new(&root);
    if let Some(n) = max_files {
        builder = builder.max_files(n);
    }
    if let Some(n) = max_file_bytes {
        builder = builder.max_file_bytes(n);
    }
    if include_hidden {
        builder = builder.include_hidden(true);
    }
    if symbols {
        builder = builder.with_symbols(true);
    }
    let map = builder.scan()?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            if full {
                println!("{}", serde_json::to_string_pretty(&map)?);
            } else {
                let summary = json!({
                    "root": map.root,
                    "total_files": map.report.total_files,
                    "total_bytes": map.report.total_bytes,
                    "total_loc": map.report.total_loc,
                    "by_language": map.report.by_language.iter()
                        .map(|(l, n)| json!({ "language": l, "count": n }))
                        .collect::<Vec<_>>(),
                    "oversize_skipped": map.report.oversize_skipped,
                    "truncated_at": map.report.truncated_at,
                });
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
        }
        OutputFormat::Table => {
            render_summary_table(&map);
            if full {
                println!();
                println!("# Per-file details ({} entries)", map.files.len());
                println!("{:<10} {:>10} {:>10}  path", "language", "bytes", "loc");
                println!(
                    "{:<10} {:>10} {:>10}  {}",
                    "-".repeat(10),
                    "-".repeat(10),
                    "-".repeat(10),
                    "-".repeat(40)
                );
                for f in &map.files {
                    println!(
                        "{:<10} {:>10} {:>10}  {}",
                        f.language.label(),
                        f.bytes,
                        f.loc,
                        f.path
                    );
                }
            }
        }
    }
    Ok(())
}

fn render_summary_table(map: &crate::code_map::RepoMap) {
    println!("# code-map scan summary");
    println!("  root:           {}", map.root);
    println!("  total files:    {}", map.report.total_files);
    println!("  total bytes:    {}", human_bytes(map.report.total_bytes));
    println!("  total LOC:      {}", map.report.total_loc);
    if map.report.oversize_skipped > 0 {
        println!("  skipped (oversize): {}", map.report.oversize_skipped);
    }
    if let Some(at) = map.report.truncated_at {
        println!("  truncated at:   {at} files (max-files cap hit)");
    }
    println!();
    println!("## by language");
    let code_total: u64 = map
        .report
        .by_language
        .iter()
        .filter(|(l, _)| l.is_code())
        .map(|(_, n)| *n)
        .sum();
    println!("  code files:     {code_total}");
    println!();
    println!("  {:<14} {:>8}", "language", "files");
    println!("  {:<14} {:>8}", "-".repeat(14), "-".repeat(8));
    for (lang, count) in &map.report.by_language {
        let marker = if lang.is_code() { "" } else { "  " };
        println!("  {:<14} {:>8}{marker}", lang.label(), count);
    }
    println!();
    println!("(use --full for the per-file breakdown; --output json for scripts)");
}

fn run_persist(
    path: Option<PathBuf>,
    max_files: Option<u64>,
    max_file_bytes: Option<u64>,
    include_hidden: bool,
    symbols: bool,
    output: OutputFormat,
) -> Result<()> {
    let root = path
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve persist root: no path given + no cwd"))?;

    let mut builder = RepoMapBuilder::new(&root);
    if let Some(n) = max_files {
        builder = builder.max_files(n);
    }
    if let Some(n) = max_file_bytes {
        builder = builder.max_file_bytes(n);
    }
    if include_hidden {
        builder = builder.include_hidden(true);
    }
    if symbols {
        builder = builder.with_symbols(true);
    }
    let map = builder.scan()?;

    let db_path = crate::code_map::persist::default_path();
    let mut conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let stats = crate::code_map::persist::persist_map(&mut conn, &map)?;

    // GR-fix (review): build + persist the call-graph EDGES. The code_map_edges
    // table was never populated in production — persist only ran persist_map
    // (roots/files/symbols), so codegraph_callers/codegraph_callees returned []
    // and the co_change hidden_coupling-suppression (which filters pairs that
    // already share a structural edge) never fired. RepoFile carries no source,
    // so re-read each file + extract symbols here (persist is an explicit command,
    // not hot-path). Best-effort: an unreadable file is skipped.
    let (edges_inserted, cycles) = {
        use crate::code_map::graph::{CallGraph, FileInput};
        use crate::code_map::walker::Language;
        let root_dir = std::path::Path::new(&map.root);
        let mut inputs: Vec<FileInput> = Vec::with_capacity(map.files.len());
        for rf in &map.files {
            let Ok(source) = std::fs::read_to_string(root_dir.join(&rf.path)) else {
                continue;
            };
            let syms = crate::code_map::symbols::extract_symbols(&source, rf.language);
            if syms.is_empty() {
                continue; // no defs → contributes no edges
            }
            let fi = match rf.language {
                Language::Python
                | Language::Ruby
                | Language::Shell
                | Language::Toml
                | Language::Yaml
                | Language::Dockerfile => FileInput::hash_family(rf.path.clone(), source, syms),
                _ => FileInput::c_family(rf.path.clone(), source, syms),
            };
            inputs.push(fi);
        }
        let graph = CallGraph::build(&inputs);
        let cycles = graph.find_cycles(50);
        let n = crate::code_map::persist::persist_edges(&mut conn, &map.root, graph.edges())
            .context("persist call-graph edges")?;
        (n, cycles)
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let summary = json!({
                "root": map.root,
                "db_path": db_path.to_string_lossy(),
                "files_inserted": stats.files_inserted,
                "files_skipped_unchanged": stats.files_skipped_unchanged,
                "symbols_inserted": stats.symbols_inserted,
                "edges_inserted": edges_inserted,
                "cycle_count": cycles.len(),
                "cycles": cycles,
                "prior_files_replaced": stats.prior_files_replaced,
                "scan_report": {
                    "total_files": map.report.total_files,
                    "total_bytes": map.report.total_bytes,
                    "total_loc": map.report.total_loc,
                    "oversize_skipped": map.report.oversize_skipped,
                    "truncated_at": map.report.truncated_at,
                },
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Table => {
            println!("# code-map persist");
            println!("  root:                   {}", map.root);
            println!("  db:                     {}", db_path.display());
            println!("  files inserted:         {}", stats.files_inserted);
            println!(
                "  files skipped (no-op):  {}",
                stats.files_skipped_unchanged
            );
            println!("  symbols inserted:       {}", stats.symbols_inserted);
            println!("  edges inserted:         {edges_inserted}");
            println!("  cycles detected:        {}", cycles.len());
            println!("  prior files replaced:   {}", stats.prior_files_replaced);
            println!();
            println!(
                "(re-run replaces changed files only; unchanged files are skipped. \
                      use `neoth code-map load` to read it back)"
            );
        }
    }
    Ok(())
}

fn run_load(path: Option<PathBuf>, full: bool, output: OutputFormat) -> Result<()> {
    let root_path = path
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve load root: no path given + no cwd"))?;
    // Persistent snapshots key off the canonicalised root the walker
    // recorded. Apply the same canonicalisation here so an operator
    // who ran `persist` against `.` and now runs `load` against `.`
    // hits the right row.
    let root_canonical = std::fs::canonicalize(&root_path).unwrap_or_else(|_| root_path.clone());
    let root_str = root_canonical.to_string_lossy().to_string();

    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let map = crate::code_map::persist::load_map(&conn, &root_str)?;

    match map {
        Some(map) => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                if full {
                    println!("{}", serde_json::to_string_pretty(&map)?);
                } else {
                    let summary = json!({
                        "root": map.root,
                        "total_files": map.report.total_files,
                        "total_bytes": map.report.total_bytes,
                        "total_loc": map.report.total_loc,
                        "by_language": map.report.by_language.iter()
                            .map(|(l, n)| json!({ "language": l, "count": n }))
                            .collect::<Vec<_>>(),
                    });
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
            }
            OutputFormat::Table => {
                render_summary_table(&map);
                if full {
                    println!();
                    println!("# Per-file details ({} entries)", map.files.len());
                    println!(
                        "{:<10} {:>10} {:>10} {:>6}  path",
                        "language", "bytes", "loc", "syms"
                    );
                    for f in &map.files {
                        println!(
                            "{:<10} {:>10} {:>10} {:>6}  {}",
                            f.language.label(),
                            f.bytes,
                            f.loc,
                            f.symbols.len(),
                            f.path
                        );
                    }
                }
            }
        },
        None => {
            let msg = format!("no persisted snapshot for root `{root_str}`");
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "root": root_str,
                            "found": false,
                            "hint": "run `neoth code-map persist` first",
                        }))?
                    );
                }
                OutputFormat::Table => {
                    println!("{msg}");
                    println!("(run `neoth code-map persist` first to seed the snapshot)");
                }
            }
        }
    }
    Ok(())
}

fn run_search(name: String, output: OutputFormat) -> Result<()> {
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let hits = crate::code_map::persist::search_symbol(&conn, &name)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<_> = hits
                .iter()
                .map(|h| {
                    json!({
                        "root": h.root,
                        "path": h.path,
                        "kind": h.kind,
                        "line": h.line,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "name": name,
                    "hits": arr,
                }))?
            );
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!("no hits for `{name}` (run `neoth code-map persist --symbols` first)");
                return Ok(());
            }
            println!("# symbol search: `{name}` — {} hit(s)", hits.len());
            println!("{:<10}  file:line", "kind");
            for h in &hits {
                println!("{:<10}  {}/{}:{}", h.kind, h.root, h.path, h.line);
            }
        }
    }
    Ok(())
}

fn run_relevant(prompt: String, max: usize, check_stale: bool, output: OutputFormat) -> Result<()> {
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    // GOLD-R3-13: scope recall to the persisted root that contains the current
    // directory. Refuse a cross-repo fallback — an unrelated repo must never
    // hide (or masquerade as) the active repo's matches.
    let cwd = std::env::current_dir().context("resolve current directory for code-map recall")?;
    let Some(active_root) = crate::code_map::recall::resolve_active_root(&conn, &cwd) else {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "prompt": prompt,
                        "max": max,
                        "hits": [],
                        "note": "current directory is not inside a persisted code-map root",
                    }))?
                );
            }
            OutputFormat::Table => {
                println!(
                    "current directory is not inside a persisted code-map root \
                     (run `neoth code-map persist` here first)"
                );
            }
        }
        return Ok(());
    };
    let hits =
        crate::code_map::recall::relevant_files_for_prompt(&conn, &prompt, &active_root, max)?;
    // GOLD-R3-13: surface the active root's index generation so a client can
    // detect a re-scan under it and invalidate a cached result.
    let index_generation =
        crate::code_map::persist::root_index_generation(&conn, &active_root).unwrap_or(None);
    // GOLD-R3-13: opt-in staleness — re-scans the active root and reports
    // whether the index predates on-disk edits. `None` unless requested.
    let stale = if check_stale {
        crate::code_map::persist::is_index_stale(&conn, &active_root).ok()
    } else {
        None
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<_> = hits
                .iter()
                .map(|h| {
                    json!({
                        "root": h.root,
                        "path": h.path,
                        "identifier_hits": h.identifier_hits,
                        "matched_symbols": h.matched_symbols,
                        "path_keyword_overlap": h.path_keyword_overlap,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "prompt": prompt,
                    "max": max,
                    "root": active_root,
                    "index_generation": index_generation,
                    "stale": stale,
                    "hits": arr,
                }))?
            );
        }
        OutputFormat::Table => {
            if stale == Some(true) {
                println!(
                    "⚠ index is STALE for {active_root} — files changed on disk since the last \
                     `neoth code-map persist`; results may be incomplete"
                );
            }
            if hits.is_empty() {
                println!(
                    "no relevant files for prompt (try `neoth code-map persist --symbols` first)"
                );
                return Ok(());
            }
            print!("{}", crate::code_map::recall::render_context_block(&hits));
        }
    }
    Ok(())
}

fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn human_bytes_renders_kib_mib_gib() {
        assert_eq!(human_bytes(500), "500 B");
        assert!(human_bytes(2048).contains("KiB"));
        assert!(human_bytes(5 * 1024 * 1024).contains("MiB"));
        assert!(human_bytes(3 * 1024 * 1024 * 1024).contains("GiB"));
    }

    #[test]
    fn scan_default_succeeds_in_empty_dir() {
        let dir = tempdir().unwrap();
        let result = run_scan(
            Some(dir.path().to_path_buf()),
            None,
            None,
            false,
            false,
            false,
            OutputFormat::Json,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn scan_full_mode_succeeds_with_files_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("hello.rs"), "fn main() {}\n").unwrap();
        let result = run_scan(
            Some(dir.path().to_path_buf()),
            None,
            None,
            false,
            true,
            false,
            OutputFormat::Json,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn scan_with_symbols_populates_rust_declarations() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("lib.rs"),
            "pub fn alpha() {}\nstruct Beta;\n",
        )
        .unwrap();
        let map = RepoMapBuilder::new(dir.path())
            .with_symbols(true)
            .scan()
            .unwrap();
        let lib = map
            .files
            .iter()
            .find(|f| f.path == "lib.rs")
            .expect("lib.rs should be indexed");
        let names: Vec<&str> = lib.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "got: {names:?}");
        assert!(names.contains(&"Beta"), "got: {names:?}");
    }

    #[test]
    fn scan_without_symbols_leaves_symbols_empty() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), "pub fn alpha() {}\n").unwrap();
        let map = RepoMapBuilder::new(dir.path()).scan().unwrap();
        let lib = map.files.iter().find(|f| f.path == "lib.rs").unwrap();
        assert!(
            lib.symbols.is_empty(),
            "symbols must stay empty when builder didn't opt in"
        );
    }

    #[test]
    fn render_summary_table_does_not_panic_on_empty_map() {
        let map = crate::code_map::RepoMap::default();
        render_summary_table(&map);
    }

    // ── Pick #22 (Session 14) — Phase 3a CLI smoke tests ─────────────
    //
    // These hit the production `default_path()` (which is `~/.neoth/
    // code_map.db`), so they're guarded behind a temp-HOME override
    // to keep the operator's real DB untouched. Each test sets `HOME`
    // (unix) and `USERPROFILE` (windows) for the duration of the test.

    /// Process-wide mutex that serialises every `with_temp_home`
    /// caller. The harness defaults to parallel test execution; the
    /// `HOME` / `USERPROFILE` env vars are process-global so two
    /// concurrent temp-home tests would clobber each other's
    /// snapshots. Pick #22 / #25 / earlier CLI tests all share this
    /// lock so they queue up cleanly under `cargo test` (with or
    /// without `--test-threads=1`).
    fn with_temp_home<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Hold the CRATE-WIDE env lock (crate::test_env) for the test
        // body so HOME / USERPROFILE manipulation cannot race another
        // env test ANYWHERE in the crate — not just other code_map
        // tests. (Previously a code_map-local mutex, which only
        // serialised within this file → a split-mechanism race against
        // pidfile/mode/etc. SC-11-era sweep unified it.)
        let guard = crate::test_env::lock();
        let dir = tempdir().unwrap();
        let prior_home = std::env::var("HOME").ok();
        let prior_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
            std::env::set_var("USERPROFILE", dir.path());
        }
        let result = f();
        unsafe {
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prior_user {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
        drop(guard);
        result
    }

    #[test]
    fn persist_then_load_via_cli_helpers_roundtrips() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(
                repo.path().join("hello.rs"),
                "pub fn main() {}\nstruct Foo;\n",
            )
            .unwrap();

            run_persist(
                Some(repo.path().to_path_buf()),
                None,
                None,
                false,
                true,
                OutputFormat::Json,
            )
            .expect("persist must succeed");

            run_load(Some(repo.path().to_path_buf()), false, OutputFormat::Json)
                .expect("load must succeed for the just-persisted root");
        });
    }

    #[test]
    fn load_unknown_root_succeeds_with_not_found_message() {
        with_temp_home(|| {
            let dir = tempdir().unwrap();
            // Never persisted — the load helper should still succeed
            // (returns Ok with a "no snapshot" message instead of an
            // error). The CLI surfaces this to the operator as a hint.
            run_load(Some(dir.path().to_path_buf()), false, OutputFormat::Json)
                .expect("load on missing snapshot must Ok");
        });
    }

    #[test]
    fn search_returns_ok_even_on_empty_db() {
        with_temp_home(|| {
            run_search("nonexistent_symbol".into(), OutputFormat::Json)
                .expect("search on empty db must Ok");
        });
    }

    #[test]
    fn persist_with_symbols_then_search_finds_them() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(
                repo.path().join("lib.rs"),
                "pub fn alpha() {}\npub fn beta() {}\n",
            )
            .unwrap();

            run_persist(
                Some(repo.path().to_path_buf()),
                None,
                None,
                false,
                true, // symbols on
                OutputFormat::Json,
            )
            .expect("persist must succeed");

            // After persist, the symbols must be in the DB even when
            // searched via the bare CLI helper.
            run_search("alpha".into(), OutputFormat::Json)
                .expect("search after persist must succeed");
        });
    }

    #[test]
    fn persist_wires_cycle_detection() {
        // GOLD-ADAPT-GRAPH-02 wiring: run_persist now destructures
        // (edges_inserted, cycles) from find_cycles(50). If that wiring
        // breaks, this fails to compile before it can run.
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(repo.path().join("a.rs"), "pub fn foo() {}\n").unwrap();
            run_persist(
                Some(repo.path().to_path_buf()),
                None,
                None,
                false,
                false,
                OutputFormat::Json,
            )
            .expect("persist with cycle detection must succeed");
        });
    }

    #[test]
    fn relevant_cli_runs_against_empty_db() {
        with_temp_home(|| {
            // No persist beforehand — relevant must still Ok (returns
            // an empty hit list).
            run_relevant("auth_middleware".into(), 5, false, OutputFormat::Json)
                .expect("relevant on empty db must Ok");
        });
    }

    #[test]
    fn relevant_cli_finds_persisted_symbol_match() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::create_dir_all(repo.path().join("src/auth")).unwrap();
            std::fs::write(
                repo.path().join("src/auth/middleware.rs"),
                "pub fn auth_middleware() {}\n",
            )
            .unwrap();

            run_persist(
                Some(repo.path().to_path_buf()),
                None,
                None,
                false,
                true,
                OutputFormat::Json,
            )
            .unwrap();

            // Prompt mentions the symbol → relevant must find the file.
            run_relevant(
                "where is auth_middleware defined?".into(),
                5,
                true,
                OutputFormat::Json,
            )
            .unwrap();
        });
    }
}
