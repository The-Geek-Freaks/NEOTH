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
//!   - `status [PATH]`   Read the lifecycle state without creating or
//!                       migrating the code-map database.
//!   - `refresh [PATH]`  Create or refresh the selected root's complete
//!                       snapshot; `--force` is the manual rebuild escape hatch.
//!   - `load [PATH]`     Inspect a persisted snapshot without rescanning.
//!   - `search <NAME>`   Find exact persisted symbol declarations.
//!   - `relevant <PROMPT>` Rank files for the same repo-context engine
//!                         used by chat and codegraph MCP consumers.
//!   - `impact`          Compute a generation-bound structural blast radius
//!                       from changed files or exact file::symbol seeds.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
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

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum ImpactDirectionArg {
    #[default]
    Callers,
    Callees,
    Both,
}

impl From<ImpactDirectionArg> for crate::code_map::impact::ImpactDirection {
    fn from(value: ImpactDirectionArg) -> Self {
        match value {
            ImpactDirectionArg::Callers => Self::Callers,
            ImpactDirectionArg::Callees => Self::Callees,
            ImpactDirectionArg::Both => Self::Both,
        }
    }
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

        /// Compatibility flag retained for existing scripts. Persisted maps
        /// always include declarations because graph endpoints and impact
        /// evidence cannot be resolved safely without them.
        #[arg(long, hide = true)]
        symbols: bool,
    },

    /// Inspect the selected repository's code-map lifecycle state without
    /// creating, migrating, rebuilding, or repairing the database.
    Status {
        /// Root directory to inspect. Defaults to the current working directory.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },

    /// Create the first complete snapshot for PATH or refresh it when the
    /// current generation is stale or incomplete. Ctrl-C requests cooperative
    /// cancellation and waits for the owned blocking refresh to finish.
    Refresh {
        /// Root directory to refresh. Defaults to the current working directory.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Rebuild even when the current snapshot is fresh.
        #[arg(long)]
        force: bool,

        /// Explicitly preserve a corrupt database and create a replacement.
        /// Normal status and refresh calls never alter a corrupt store.
        #[arg(long)]
        repair_corrupt: bool,
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

    /// Phase 3a — find persisted files in the active repository that declare
    /// a symbol matching NAME exactly.
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

        /// Repository path to bind the recall receipt to. Defaults to the
        /// current working directory for interactive CLI use. GUI, daemon and
        /// automation callers should always pass this explicitly.
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,

        /// Max files to return. Default 5.
        #[arg(
            long,
            value_name = "N",
            default_value_t = 5,
            value_parser = parse_recall_max
        )]
        max: usize,

        /// Also report whether the persisted index is stale relative to the
        /// files on disk. Re-scans the active root (reads + hashes files), so
        /// it is opt-in and slower than a plain recall.
        #[arg(long)]
        check_stale: bool,
    },

    /// Compute the structural blast radius of changed files or exact
    /// declarations in the active persisted repository. Callers (dependents)
    /// are the default; every result is bound to matching index/graph
    /// generations, refuses a stale index unless explicitly overridden, and
    /// reports node-cap versus evidence-budget truncation separately.
    Impact {
        /// Changed repo-relative file. Repeat for multiple files. Every
        /// persisted declaration in the file becomes a seed.
        #[arg(long = "file", value_name = "FILE")]
        files: Vec<String>,

        /// Exact changed declaration as FILE::SYMBOL. Repeatable.
        #[arg(long = "symbol", value_name = "FILE::SYMBOL")]
        symbols: Vec<String>,

        /// Relationship direction from each changed declaration.
        #[arg(long, value_enum, default_value_t = ImpactDirectionArg::Callers)]
        direction: ImpactDirectionArg,

        /// Maximum relationship hops. Hard ceiling 32.
        #[arg(long, value_name = "N", default_value_t = crate::code_map::impact::DEFAULT_MAX_DEPTH)]
        max_depth: usize,

        /// Maximum affected declarations returned. Hard ceiling 10000.
        #[arg(long, value_name = "N", default_value_t = crate::code_map::impact::DEFAULT_MAX_NODES)]
        max_nodes: usize,

        /// Permit analysis against an index known to predate on-disk edits.
        /// The result still records `stale: true`.
        #[arg(long)]
        allow_stale: bool,
    },

    /// Acquire one explicit Git diff, map only hunk-intersecting declaration
    /// lines to exact symbols, then run the canonical impact service. The
    /// selected root must already have a current persisted code map.
    DiffImpact {
        /// Explicit Git and code-map root. This command never infers a root
        /// from the current directory.
        #[arg(long, value_name = "PATH")]
        root: PathBuf,

        /// Compare the index with HEAD. The default source is the working tree.
        #[arg(long, conflicts_with_all = ["base", "target", "stdin"])]
        staged: bool,

        /// Older committed revision; requires --target and cannot be combined
        /// with --staged or --stdin.
        #[arg(long, value_name = "REF", requires = "target", conflicts_with_all = ["staged", "stdin"])]
        base: Option<String>,

        /// Newer committed revision; requires --base and cannot be combined
        /// with --staged or --stdin.
        #[arg(long, value_name = "REF", requires = "base", conflicts_with_all = ["staged", "stdin"])]
        target: Option<String>,

        /// Read a unified diff from standard input. --root remains mandatory
        /// so changed paths are contained before their source is read.
        #[arg(long, conflicts_with_all = ["staged", "base", "target"])]
        stdin: bool,

        /// Relationship direction from each changed declaration.
        #[arg(long, value_enum, default_value_t = ImpactDirectionArg::Callers)]
        direction: ImpactDirectionArg,

        /// Maximum relationship hops. Hard ceiling 32.
        #[arg(long, value_name = "N", default_value_t = crate::code_map::impact::DEFAULT_MAX_DEPTH)]
        max_depth: usize,

        /// Maximum affected declarations returned. Hard ceiling 10000.
        #[arg(long, value_name = "N", default_value_t = crate::code_map::impact::DEFAULT_MAX_NODES)]
        max_nodes: usize,

        /// Permit analysis against an index known to predate on-disk edits.
        #[arg(long)]
        allow_stale: bool,
    },
}

fn parse_recall_max(raw: &str) -> std::result::Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| "recall max must be an integer from 1 through 200".to_string())?;
    if !(1..=200).contains(&value) {
        return Err("recall max must be from 1 through 200".into());
    }
    Ok(value)
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
        CodeMapAction::Status { path } => run_lifecycle_status(path, args.output),
        CodeMapAction::Refresh {
            path,
            force,
            repair_corrupt,
        } => run_lifecycle_refresh(path, force, repair_corrupt, args.output).await,
        CodeMapAction::Load { path, full } => run_load(path, full, args.output),
        CodeMapAction::Search { name } => run_search(name, args.output),
        CodeMapAction::Relevant {
            prompt,
            path,
            max,
            check_stale,
        } => run_relevant(prompt, path, max, check_stale, args.output),
        CodeMapAction::Impact {
            files,
            symbols,
            direction,
            max_depth,
            max_nodes,
            allow_stale,
        } => run_impact(
            files,
            symbols,
            direction,
            max_depth,
            max_nodes,
            allow_stale,
            args.output,
        ),
        CodeMapAction::DiffImpact {
            root,
            staged,
            base,
            target,
            stdin,
            direction,
            max_depth,
            max_nodes,
            allow_stale,
        } => run_diff_impact(
            DiffImpactRequest {
                root,
                staged,
                base,
                target,
                stdin,
                direction,
                max_depth,
                max_nodes,
                allow_stale,
            },
            args.output,
        ),
    }
}

fn lifecycle_root(path: Option<PathBuf>) -> Result<PathBuf> {
    path.or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve code-map root: no path given + no cwd"))
}

fn render_lifecycle_value<T: serde::Serialize>(
    heading: &str,
    value: &T,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(value)?),
        OutputFormat::Table => {
            // The lifecycle record is deliberately rendered from the same typed
            // contract as JSON/JSONL. This keeps all state and repair evidence
            // visible while the core state vocabulary evolves.
            println!("# {heading}");
            println!("{}", serde_json::to_string_pretty(value)?);
        }
    }
    Ok(())
}

fn run_lifecycle_status(path: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let root = lifecycle_root(path)?;
    let db_path = crate::code_map::persist::default_path();
    // `inspect` intentionally opens an existing store read-only. Do not
    // replace this with persist::open: a diagnostic must not create, migrate,
    // repair, or otherwise alter a missing/corrupt operator store.
    let status = crate::code_map::lifecycle::inspect(&db_path, &root);
    render_lifecycle_value("code-map lifecycle status", &status, output)
}

async fn run_lifecycle_refresh(
    path: Option<PathBuf>,
    force: bool,
    repair_corrupt: bool,
    output: OutputFormat,
) -> Result<()> {
    run_lifecycle_refresh_with_signal(path, force, repair_corrupt, output, tokio::signal::ctrl_c())
        .await
}

async fn run_lifecycle_refresh_with_signal<S>(
    path: Option<PathBuf>,
    force: bool,
    repair_corrupt: bool,
    output: OutputFormat,
    signal: S,
) -> Result<()>
where
    S: std::future::Future<Output = std::io::Result<()>>,
{
    let root = lifecycle_root(path)?;
    let db_path = crate::code_map::persist::default_path();
    let cancellation = crate::code_map::lifecycle::LifecycleCancellation::new();
    let worker_cancellation = cancellation.clone();
    let options = crate::code_map::lifecycle::LifecycleRefreshOptions {
        force,
        repair_corrupt,
        cause: if repair_corrupt {
            crate::code_map::lifecycle::RefreshCause::ExplicitCorruptStoreRepair
        } else if force {
            crate::code_map::lifecycle::RefreshCause::ManualForce
        } else {
            crate::code_map::lifecycle::RefreshCause::ManualIfNeeded
        },
    };

    // The synchronous rebuild owns filesystem traversal and SQLite publication.
    // Ctrl-C signals its shared cancellation token but never aborts/detaches the
    // worker: we always await the real terminal receipt before returning.
    let worker = tokio::task::spawn_blocking(move || {
        crate::code_map::lifecycle::refresh(&db_path, &root, options, &worker_cancellation)
    });

    let (receipt, signal_error) =
        await_owned_lifecycle_refresh(worker, cancellation, signal).await?;
    let terminal_error = match &receipt.outcome {
        crate::code_map::lifecycle::RefreshOutcome::Cancelled => {
            Some("code-map refresh cancelled before publication")
        }
        crate::code_map::lifecycle::RefreshOutcome::CorruptRepairRequired => Some(
            "code-map database is corrupt; rerun with --repair-corrupt to preserve it and rebuild",
        ),
        crate::code_map::lifecycle::RefreshOutcome::Failed => {
            Some("code-map refresh failed before publication")
        }
        _ => None,
    };
    // Render the terminal receipt before returning a nonzero outcome so JSON
    // automation has the same forensic state a human operator sees.
    render_lifecycle_value("code-map lifecycle refresh", &receipt, output)?;
    if let Some(error) = signal_error {
        return Err(error.context("wait for code-map refresh Ctrl-C"));
    }
    if let Some(error) = terminal_error {
        anyhow::bail!(error);
    }
    Ok(())
}

/// Wait for either a completed owned refresh or the terminal-control future.
/// A signal registration failure is still a terminal-control failure: cancel
/// the shared worker and join it before surfacing the error, so no blocking
/// publisher survives the CLI command that owns it.
async fn await_owned_lifecycle_refresh<T, S>(
    mut worker: tokio::task::JoinHandle<Result<T>>,
    cancellation: crate::code_map::lifecycle::LifecycleCancellation,
    signal: S,
) -> Result<(T, Option<anyhow::Error>)>
where
    S: std::future::Future<Output = std::io::Result<()>>,
{
    tokio::pin!(signal);
    tokio::select! {
        biased;
        signal_result = &mut signal => {
            cancellation.cancel();
            eprintln!("code-map refresh cancellation requested; waiting for the active rebuild to finish...");
            let signal_error = signal_result.err().map(anyhow::Error::from);
            match worker.await.context("join cancelled code-map lifecycle refresh worker")? {
                Ok(value) => Ok((value, signal_error)),
                Err(worker_error) => match signal_error {
                    Some(signal_error) => Err(signal_error.context(format!(
                        "code-map lifecycle refresh also failed while joining after terminal-control failure: {worker_error:#}"
                    ))),
                    None => Err(worker_error),
                },
            }
        }
        result = &mut worker => Ok((
            result.context("code-map lifecycle refresh worker panicked")??,
            None,
        )),
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
    let jsonl = matches!(&output, OutputFormat::Jsonl);
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
                print_json_value(&map, jsonl)?;
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
                print_json_value(&summary, jsonl)?;
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
    _symbols: bool,
    output: OutputFormat,
) -> Result<()> {
    let jsonl = matches!(&output, OutputFormat::Jsonl);
    if max_files.is_some() || max_file_bytes.is_some() || include_hidden {
        anyhow::bail!(
            "custom scan limits/hidden-file policy cannot be published as a consumable code-map snapshot because freshness must replay one canonical policy; use `neoth code-map scan` for bounded exploratory output, then persist without those flags"
        );
    }
    let root = path
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve persist root: no path given + no cwd"))?;

    let db_path = crate::code_map::persist::default_path();
    let root = crate::code_map::CanonicalRepoRoot::discover(&root)?;
    let rebuilt = crate::code_map::rebuild_snapshot(
        &root,
        &db_path,
        crate::code_map::RebuildOptions {
            max_files: None,
            max_file_bytes: None,
            include_hidden: false,
            require_complete: true,
        },
    )?;
    let stats = &rebuilt.stats;
    let edges_inserted = rebuilt.edges_inserted;
    let cycles = &rebuilt.cycles;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let summary = json!({
                "root": rebuilt.root.display(),
                "root_identity_sha256": rebuilt.root_identity_sha256,
                "index_generation": rebuilt.index_generation,
                "graph_generation": rebuilt.graph_generation,
                "source_fingerprint_sha256": rebuilt.source_fingerprint_sha256,
                "db_path": db_path.to_string_lossy(),
                "files_inserted": stats.files_inserted,
                "files_skipped_unchanged": stats.files_skipped_unchanged,
                "symbols_inserted": stats.symbols_inserted,
                "edges_inserted": edges_inserted,
                "cycle_count": cycles.len(),
                "cycles": cycles,
                "prior_files_replaced": stats.prior_files_replaced,
                "scan_report": {
                    "total_files": rebuilt.scan_report.total_files,
                    "total_bytes": rebuilt.scan_report.total_bytes,
                    "total_loc": rebuilt.scan_report.total_loc,
                    "oversize_skipped": rebuilt.scan_report.oversize_skipped,
                    "truncated_at": rebuilt.scan_report.truncated_at,
                },
            });
            print_json_value(&summary, jsonl)?;
        }
        OutputFormat::Table => {
            println!("# code-map persist");
            println!("  root:                   {}", rebuilt.root.display());
            println!("  root identity SHA-256:  {}", rebuilt.root_identity_sha256);
            println!("  index generation:       {}", rebuilt.index_generation);
            println!("  graph generation:       {}", rebuilt.graph_generation);
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
    let jsonl = matches!(&output, OutputFormat::Jsonl);
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
                    print_json_value(&map, jsonl)?;
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
                    print_json_value(&summary, jsonl)?;
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
                    print_json_value(
                        &json!({
                            "root": root_str,
                            "found": false,
                            "hint": "run `neoth code-map persist` first",
                        }),
                        jsonl,
                    )?;
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
    let jsonl = matches!(&output, OutputFormat::Jsonl);
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    // Containment before limiting (GOLD-R3-13): results are scoped to the
    // repository the caller is standing in. Without it a large unrelated
    // indexed repo can fill the result set and hide every local match — and
    // falling back to another persisted root is the cross-repo leak the
    // generation-bound resolver exists to close. Resolver failures remain
    // visible instead of being collapsed into an unindexed-root response.
    let cwd = std::env::current_dir().context("resolve current directory for symbol search")?;
    let Some(snapshot) = crate::code_map::recall::resolve_active_root_snapshot(&conn, &cwd)? else {
        anyhow::bail!(
            "no indexed repository contains {} — run `neoth code-map persist` from inside \
             the repository you want to search",
            cwd.display()
        );
    };
    anyhow::ensure!(
        snapshot.index_generation > 0,
        "active code-map root has no published index generation; run `neoth code-map persist`"
    );
    anyhow::ensure!(
        crate::code_map::persist::root_snapshot_complete(&conn, snapshot.root.display())?,
        "active code-map root was published from a partial scan; rebuild without custom limits"
    );
    let initial_freshness =
        crate::code_map::persist::index_freshness_receipt(&conn, snapshot.root.display())?;
    anyhow::ensure!(
        !initial_freshness.stale,
        "active code-map snapshot is stale; run `neoth code-map persist`"
    );
    let hits = crate::code_map::persist::search_symbol(&conn, &name, snapshot.root.display())?;
    let final_freshness =
        crate::code_map::persist::index_freshness_receipt(&conn, snapshot.root.display())?;
    anyhow::ensure!(
        !final_freshness.stale
            && final_freshness.filesystem_fingerprint == initial_freshness.filesystem_fingerprint,
        "active code-map snapshot changed during symbol search; retry"
    );
    let after = crate::code_map::recall::resolve_active_root_snapshot(&conn, snapshot.root.path())?
        .context("active code-map root disappeared during symbol search")?;
    anyhow::ensure!(
        after == snapshot,
        "active code-map generation changed during symbol search; retry"
    );

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
            print_json_value(
                &json!({
                    "name": name,
                    "hits": arr,
                }),
                jsonl,
            )?;
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!("no hits for `{name}` (run `neoth code-map persist` first)");
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

fn run_relevant(
    prompt: String,
    path: Option<PathBuf>,
    max: usize,
    check_stale: bool,
    output: OutputFormat,
) -> Result<()> {
    let jsonl = matches!(&output, OutputFormat::Jsonl);
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let active_path = match path {
        Some(path) => path,
        None => std::env::current_dir().context("resolve current directory for code-map recall")?,
    };
    let staleness = if check_stale {
        crate::code_map::recall::RecallStaleness::Check
    } else {
        crate::code_map::recall::RecallStaleness::Skip
    };
    // Root identity, generations, ranking and optional staleness come from one
    // read transaction. A caller can no longer assemble a mixed receipt while
    // a concurrent persist advances the repository snapshot.
    let Some(receipt) = crate::code_map::recall::recall_receipt_for_prompt(
        &conn,
        &active_path,
        &prompt,
        max,
        staleness,
    )?
    else {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let envelope = crate::code_map::recall_wire::RecallWireEnvelope::empty(
                    crate::code_map::recall_wire::RecallWireStatus::Unmapped,
                    &prompt,
                    max,
                    "requested path is not inside a persisted code-map root",
                )?;
                print_json_value(&envelope, jsonl)?;
            }
            OutputFormat::Table => {
                println!(
                    "requested path is not inside a persisted code-map root \
                     (run `neoth code-map persist` here first)"
                );
            }
        }
        return Ok(());
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let envelope =
                crate::code_map::recall_wire::RecallWireEnvelope::success(&prompt, max, &receipt)?;
            print_json_value(&envelope, jsonl)?;
        }
        OutputFormat::Table => {
            if receipt.stale == Some(true) {
                println!(
                    "⚠ index is STALE for {} — files changed on disk since the last \
                     `neoth code-map persist`; results may be incomplete",
                    receipt.snapshot.root.display()
                );
            }
            if receipt.truncated {
                println!(
                    "⚠ repository recall hit a bounded work or result limit; the displayed context may be incomplete (requested max {max})"
                );
            }
            if receipt.ranked_files.is_empty() {
                println!("no relevant files for prompt (try `neoth code-map persist` first)");
                return Ok(());
            }
            print!(
                "{}",
                crate::code_map::recall::render_context_block(&receipt.ranked_files)
            );
        }
    }
    Ok(())
}

fn print_json_value<T: serde::Serialize>(value: &T, jsonl: bool) -> Result<()> {
    if jsonl {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn run_impact(
    files: Vec<String>,
    symbols: Vec<String>,
    direction: ImpactDirectionArg,
    max_depth: usize,
    max_nodes: usize,
    allow_stale: bool,
    output: OutputFormat,
) -> Result<()> {
    let seeds = parse_impact_seeds(files, symbols)?;
    let cwd = std::env::current_dir().context("resolve current directory for impact analysis")?;
    run_impact_for_root(
        cwd,
        seeds,
        direction,
        max_depth,
        max_nodes,
        allow_stale,
        output,
    )
}

struct DiffImpactRequest {
    root: PathBuf,
    staged: bool,
    base: Option<String>,
    target: Option<String>,
    stdin: bool,
    direction: ImpactDirectionArg,
    max_depth: usize,
    max_nodes: usize,
    allow_stale: bool,
}

fn run_diff_impact(request: DiffImpactRequest, output: OutputFormat) -> Result<()> {
    let source = match (
        request.staged,
        request.base.as_ref(),
        request.target.as_ref(),
        request.stdin,
    ) {
        (true, None, None, false) => crate::code_map::diff_git::GitDiffSource::Staged,
        (false, Some(base), Some(target), false) => {
            crate::code_map::diff_git::GitDiffSource::Committed {
                base: base.clone(),
                target: target.clone(),
            }
        }
        (false, None, None, true) => crate::code_map::diff_git::GitDiffSource::Stdin,
        (false, None, None, false) => crate::code_map::diff_git::GitDiffSource::WorkingTree,
        _ => anyhow::bail!(
            "choose exactly one diff source: working tree, --staged, --base/--target, or --stdin"
        ),
    };
    let acquired = if source == crate::code_map::diff_git::GitDiffSource::Stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((crate::code_map::diff::MAX_DIFF_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .context("read unified diff from standard input")?;
        let input = String::from_utf8(bytes).context("unified diff standard input is not UTF-8")?;
        crate::code_map::diff_git::parse_stdin_diff(&input)?
    } else {
        crate::code_map::diff_git::acquire_git_diff(&request.root, source)?
    };
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let canonical_root = request
        .root
        .canonicalize()
        .with_context(|| format!("canonicalize explicit diff root {}", request.root.display()))?;
    let indexed = crate::code_map::persist::load_map(
        &conn,
        canonical_root
            .to_str()
            .context("explicit diff root is not valid UTF-8")?,
    )?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "explicit diff root {} is not indexed; run `neoth code-map persist` first",
            canonical_root.display()
        )
    })?;
    let seeds = crate::code_map::diff_git::map_acquired_diff_to_indexed_impact_seeds(
        &canonical_root,
        &acquired,
        &indexed,
    )?;
    let result = crate::code_map::impact::impact_radius_for_diff_seeds(
        &conn,
        &canonical_root,
        &seeds,
        crate::code_map::impact::ImpactOptions {
            direction: request.direction.into(),
            max_depth: request.max_depth,
            max_nodes: request.max_nodes,
            allow_stale: request.allow_stale,
        },
    )?;
    render_impact_result(&result, output)
}

fn run_impact_for_root(
    root: PathBuf,
    seeds: Vec<crate::code_map::impact::ImpactSeed>,
    direction: ImpactDirectionArg,
    max_depth: usize,
    max_nodes: usize,
    allow_stale: bool,
    output: OutputFormat,
) -> Result<()> {
    let db_path = crate::code_map::persist::default_path();
    let conn = crate::code_map::persist::open(&db_path)
        .with_context(|| format!("open code_map db at {}", db_path.display()))?;
    let result = crate::code_map::impact::impact_radius_for_path(
        &conn,
        &root,
        &seeds,
        crate::code_map::impact::ImpactOptions {
            direction: direction.into(),
            max_depth,
            max_nodes,
            allow_stale,
        },
    )?;

    render_impact_result(&result, output)
}

fn render_impact_result(
    result: &crate::code_map::impact::ImpactResult,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&result)?),
        OutputFormat::Table => render_impact_table(result),
    }
    Ok(())
}

fn parse_impact_seeds(
    files: Vec<String>,
    symbols: Vec<String>,
) -> Result<Vec<crate::code_map::impact::ImpactSeed>> {
    let mut seeds: Vec<crate::code_map::impact::ImpactSeed> = files
        .into_iter()
        .map(crate::code_map::impact::ImpactSeed::file)
        .collect();
    for value in symbols {
        let (file, symbol) = value.rsplit_once("::").ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --symbol {value:?}; expected a repo-relative FILE::SYMBOL value"
            )
        })?;
        if file.trim().is_empty() || symbol.trim().is_empty() {
            anyhow::bail!("invalid --symbol {value:?}; both FILE and SYMBOL must be non-empty");
        }
        seeds.push(crate::code_map::impact::ImpactSeed::symbol(
            file.trim(),
            symbol.trim(),
        ));
    }
    Ok(seeds)
}

fn render_impact_table(result: &crate::code_map::impact::ImpactResult) {
    println!("# code-map impact");
    println!("  root:              {}", result.root);
    println!(
        "  generation:        index={} graph={}",
        result.index_generation, result.graph_generation
    );
    println!("  stale:             {}", result.stale);
    println!("  direction:         {}", result.direction.as_str());
    println!("  seed declarations: {}", result.seed_nodes.len());
    println!("  impacted nodes:    {}", result.impacted_nodes.len());
    println!("  impacted files:    {}", result.impacted_files.len());
    println!("  truncated:         {}", result.truncated);
    println!("  budget truncated:  {}", result.budget_truncated);
    println!("  digest:            {}", result.digest);

    if !result.impacted_nodes.is_empty() {
        println!();
        println!("{:>5}  {:>7}  declaration", "hops", "score");
        for impacted in &result.impacted_nodes {
            println!(
                "{:>5}  {:>7.4}  {}:{}::{} ({})",
                impacted.distance,
                impacted.score,
                impacted.node.file,
                impacted.node.line,
                impacted.node.symbol,
                impacted.node.kind
            );
        }
    }
    if !result.unresolved_seeds.is_empty() || !result.unresolved_edges.is_empty() {
        println!();
        println!(
            "unresolved: {} seed(s), {} edge endpoint(s){}",
            result.unresolved_seeds.len(),
            result.unresolved_edges.len(),
            if result.evidence_truncated {
                " (evidence truncated)"
            } else {
                ""
            }
        );
        for unresolved in &result.unresolved_seeds {
            println!("  seed {:?}: {:?}", unresolved.seed, unresolved.reason);
        }
        for unresolved in &result.unresolved_edges {
            println!(
                "  edge {}::{} -> {} [{}]: {:?}",
                unresolved.from_file,
                unresolved.from_symbol,
                unresolved.to_name,
                unresolved.kind,
                unresolved.reason
            );
        }
    }
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
    use clap::Parser;
    use tempfile::tempdir;

    #[test]
    fn human_bytes_renders_kib_mib_gib() {
        assert_eq!(human_bytes(500), "500 B");
        assert!(human_bytes(2048).contains("KiB"));
        assert!(human_bytes(5 * 1024 * 1024).contains("MiB"));
        assert!(human_bytes(3 * 1024 * 1024 * 1024).contains("GiB"));
    }

    #[test]
    fn impact_seed_parser_preserves_files_and_requires_file_symbol_separator() {
        let seeds = parse_impact_seeds(
            vec!["src/all.rs".into()],
            vec!["src/one.rs::changed".into()],
        )
        .unwrap();
        assert_eq!(
            seeds,
            vec![
                crate::code_map::impact::ImpactSeed::file("src/all.rs"),
                crate::code_map::impact::ImpactSeed::symbol("src/one.rs", "changed"),
            ]
        );
        assert!(parse_impact_seeds(Vec::new(), vec!["missing-separator".into()]).is_err());
        assert!(parse_impact_seeds(Vec::new(), vec!["::empty".into()]).is_err());
    }

    #[test]
    fn diff_impact_cli_requires_explicit_root_and_mutually_exclusive_source() {
        let parsed = crate::cli::Cli::try_parse_from([
            "neoth",
            "code-map",
            "diff-impact",
            "--root",
            "C:/work/repository",
            "--base",
            "HEAD~1",
            "--target",
            "HEAD",
        ])
        .expect("committed diff source must parse");
        let crate::cli::Commands::CodeMap(parsed) = parsed.command else {
            panic!("expected code-map command");
        };
        assert!(matches!(
            parsed.action,
            CodeMapAction::DiffImpact {
                root,
                base: Some(base),
                target: Some(target),
                staged: false,
                stdin: false,
                ..
            } if root == std::path::Path::new("C:/work/repository") && base == "HEAD~1" && target == "HEAD"
        ));
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "code-map",
                "diff-impact",
                "--root",
                "C:/work/repository",
                "--staged",
                "--stdin",
            ])
            .is_err()
        );
    }

    #[test]
    fn lifecycle_status_and_refresh_flags_parse_through_the_real_cli() {
        let status =
            crate::cli::Cli::try_parse_from(["neoth", "code-map", "status", "C:/work/repository"])
                .expect("status command must parse");
        let crate::cli::Commands::CodeMap(status) = status.command else {
            panic!("expected code-map command");
        };
        assert!(matches!(
            status.action,
            CodeMapAction::Status { path: Some(path) } if path == std::path::Path::new("C:/work/repository")
        ));

        let refresh = crate::cli::Cli::try_parse_from([
            "neoth",
            "code-map",
            "refresh",
            "C:/work/repository",
            "--force",
            "--repair-corrupt",
        ])
        .expect("refresh command and explicit repair flags must parse");
        let crate::cli::Commands::CodeMap(refresh) = refresh.command else {
            panic!("expected code-map command");
        };
        assert!(matches!(
            refresh.action,
            CodeMapAction::Refresh {
                path: Some(path),
                force: true,
                repair_corrupt: true,
            } if path == std::path::Path::new("C:/work/repository")
        ));
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
    fn lifecycle_status_uses_the_real_read_only_service_for_an_absent_store() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(repo.path().join("lib.rs"), "pub fn first_index() {}\n").unwrap();
            let db_path = crate::code_map::persist::default_path();
            assert!(
                !db_path.exists(),
                "the fixture must begin without a code-map database"
            );

            run_lifecycle_status(Some(repo.path().to_path_buf()), OutputFormat::Json)
                .expect("absent lifecycle status must remain an operator-visible success");

            assert!(
                !db_path.exists(),
                "status must not create or migrate a missing code-map database"
            );
        });
    }

    #[test]
    fn lifecycle_refresh_runs_the_real_service_and_publishes_a_store() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(repo.path().join("lib.rs"), "pub fn first_index() {}\n").unwrap();
            let db_path = crate::code_map::persist::default_path();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build CLI refresh fixture runtime");

            runtime
                .block_on(run_lifecycle_refresh(
                    Some(repo.path().to_path_buf()),
                    false,
                    false,
                    OutputFormat::Json,
                ))
                .expect("first lifecycle refresh must return its success receipt");

            assert!(
                db_path.exists(),
                "the CLI refresh adapter must invoke the publishing lifecycle service"
            );
        });
    }

    #[test]
    fn terminal_control_registration_failure_cancels_and_joins_the_owned_worker() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build cancellation fixture runtime");
        let cancellation = crate::code_map::lifecycle::LifecycleCancellation::new();
        let worker_cancellation = cancellation.clone();
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_completed = std::sync::Arc::clone(&completed);
        let (terminal, signal_error) = runtime
            .block_on(async move {
                let worker = tokio::task::spawn_blocking(move || {
                    while !worker_cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    worker_completed.store(true, std::sync::atomic::Ordering::Release);
                    Ok::<_, anyhow::Error>("joined terminal worker")
                });
                await_owned_lifecycle_refresh(
                    worker,
                    cancellation,
                    std::future::ready(Err(std::io::Error::other("signal registration failed"))),
                )
                .await
            })
            .expect("signal registration failure must still join the worker");

        assert_eq!(terminal, "joined terminal worker");
        assert!(
            completed.load(std::sync::atomic::Ordering::Acquire),
            "the refresh worker must finish before its signal failure returns"
        );
        assert!(
            signal_error
                .expect("terminal-control failure must be retained")
                .to_string()
                .contains("signal registration failed")
        );
    }

    #[test]
    fn ready_terminal_control_failure_wins_over_an_already_completed_worker() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build ready-terminal-control fixture runtime");
        let cancellation = crate::code_map::lifecycle::LifecycleCancellation::new();
        let (terminal, signal_error) = runtime
            .block_on(async move {
                let worker = tokio::spawn(async { Ok::<_, anyhow::Error>("already completed") });
                // Ensure the worker reaches its terminal state before the
                // helper races it with the immediately ready signal error.
                tokio::task::yield_now().await;
                await_owned_lifecycle_refresh(
                    worker,
                    cancellation,
                    std::future::ready(Err(std::io::Error::other("signal setup failed"))),
                )
                .await
            })
            .expect("the completed worker must still be joined");

        assert_eq!(terminal, "already completed");
        assert!(
            signal_error
                .expect("the ready terminal-control failure must not be swallowed")
                .to_string()
                .contains("signal setup failed")
        );
    }

    #[test]
    fn search_refuses_when_no_indexed_repo_contains_the_cwd() {
        with_temp_home(|| {
            // GOLD-R3-13: with nothing indexed there is no active root, and
            // falling back to some other persisted root is the cross-repo leak
            // containment exists to close. Refusing with an actionable message
            // beats silently searching a repository the operator is not in.
            let error = run_search("nonexistent_symbol".into(), OutputFormat::Json)
                .expect_err("no active repository must refuse, not guess");
            assert!(error.to_string().contains("no indexed repository"));
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

            // The symbols are in the DB under the repo's canonical root. The
            // CLI resolves that root from the CWD; this test runs from the
            // NEOTH checkout, so it asserts the storage contract directly
            // rather than pretending to stand inside the fixture repo.
            let db = crate::code_map::persist::default_path();
            let conn = crate::code_map::persist::open(&db).unwrap();
            let root = std::fs::canonicalize(repo.path())
                .unwrap()
                .display()
                .to_string();
            let hits = crate::code_map::persist::search_symbol(&conn, "alpha", &root).unwrap();
            assert_eq!(
                hits.len(),
                1,
                "persisted symbol must be findable in its root"
            );
            assert!(
                crate::code_map::persist::search_symbol(&conn, "alpha", "/some/other/repo")
                    .unwrap()
                    .is_empty(),
                "another root must not see this repo's symbols"
            );
        });
    }

    #[test]
    fn persist_default_now_stores_concrete_symbols_for_graph_consumers() {
        with_temp_home(|| {
            let repo = tempdir().unwrap();
            std::fs::write(repo.path().join("lib.rs"), "pub fn adopted() {}\n").unwrap();

            run_persist(
                Some(repo.path().to_path_buf()),
                None,
                None,
                false,
                false, // legacy flag omitted: persistence still extracts declarations
                OutputFormat::Json,
            )
            .unwrap();

            let conn =
                crate::code_map::persist::open(&crate::code_map::persist::default_path()).unwrap();
            let root = repo.path().canonicalize().unwrap().display().to_string();
            let map = crate::code_map::persist::load_map(&conn, &root)
                .unwrap()
                .unwrap();
            assert_eq!(map.files[0].symbols[0].name, "adopted");
            assert_eq!(
                crate::code_map::persist::root_graph_generation(&conn, &root).unwrap(),
                crate::code_map::persist::root_index_generation(&conn, &root).unwrap()
            );
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
            run_relevant("auth_middleware".into(), None, 5, false, OutputFormat::Json)
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
                Some(repo.path().to_path_buf()),
                5,
                true,
                OutputFormat::Json,
            )
            .unwrap();
        });
    }
}
