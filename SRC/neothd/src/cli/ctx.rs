//! `neoth ctx` — ctx-mode parity subcommand (Phase 26 R-19).
//!
//! Modes:
//!   `--search "<query>"`       hybrid BM25 → trigram → fuzzy search
//!   `--index <path>`           index a file (label = path stem)
//!   `--index-stdin --label X`  index stdin contents under explicit label
//!   `--stats`                  schema version + counts + latest_indexed_ts
//!   `--doctor`                 FTS5 + trigram tokenizer + WAL probe
//!   `--purge --label X`        delete one source
//!   `--purge --category X`     delete every source in a category
//!   `--purge --all`            wipe everything
//!
//! Output respects the global `--output` flag (table / json / jsonl).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::memory::ctx::{
    self, CtxDoctor, CtxHit, CtxStats, IndexReport, IndexRequest, PurgeScope,
};
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct CtxArgs {
    /// Run a hybrid search and print hits.
    #[arg(long, value_name = "QUERY", conflicts_with_all = ["index", "index_stdin", "stats", "doctor", "purge"])]
    pub search: Option<String>,

    /// Index a file from disk. The file path is recorded; label defaults to
    /// the file stem unless overridden with `--label`.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["search", "index_stdin", "stats", "doctor", "purge"])]
    pub index: Option<PathBuf>,

    /// Index whatever arrives on stdin. Requires `--label`.
    #[arg(long, conflicts_with_all = ["search", "index", "stats", "doctor", "purge"])]
    pub index_stdin: bool,

    /// Explicit label for `--index` / `--index-stdin`. Defaults to the file stem.
    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,

    /// Category bucket for the indexed source.
    #[arg(long, value_name = "CATEGORY")]
    pub category: Option<String>,

    /// Content type marker (prose / code / log / …). Defaults to "prose".
    #[arg(long, value_name = "TYPE", default_value = "prose")]
    pub content_type: String,

    /// Print schema + counts.
    #[arg(long, conflicts_with_all = ["search", "index", "index_stdin", "doctor", "purge"])]
    pub stats: bool,

    /// Run health probe (FTS5, trigram tokenizer, journal_mode).
    #[arg(long, conflicts_with_all = ["search", "index", "index_stdin", "stats", "purge"])]
    pub doctor: bool,

    /// Purge mode. Use with `--label`, `--category`, or `--all`.
    #[arg(long, conflicts_with_all = ["search", "index", "index_stdin", "stats", "doctor"])]
    pub purge: bool,

    /// Purge scope: every source. Mutually exclusive with `--label`/`--category`.
    #[arg(long, conflicts_with_all = ["label", "category"])]
    pub all: bool,

    /// GOLD-HR-10 — retrieve a CCR-cached original by its `[0-9a-f]{24}` key
    /// (the `<<ccr:KEY>>` marker the compression pipeline left inline). Pulls
    /// the byte-exact dropped block back from the persistent store.
    #[arg(long, value_name = "KEY", conflicts_with_all = ["search", "index", "index_stdin", "stats", "doctor", "purge", "savings"])]
    pub retrieve: Option<String>,

    /// GOLD-HR-10 — print cumulative token-compression savings (blocks
    /// compressed, bytes before/after, ratio).
    #[arg(long, conflicts_with_all = ["search", "index", "index_stdin", "stats", "doctor", "purge", "retrieve"])]
    pub savings: bool,

    /// Maximum hits returned by `--search`.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,

    /// Output format. Filled from the global `--output` flag by `cli::run`.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_ctx(args: CtxArgs) -> Result<()> {
    // GOLD-HR-10 — CCR retrieval + savings don't touch the views DB; handle
    // them first so they work even before any `ctx` indexing has happened.
    if let Some(key) = &args.retrieve {
        let dir = crate::context::compress::default_ccr_dir();
        let store = crate::context::compress::FileCcrStore::new(dir);
        match crate::context::compress::retrieve(&store, key) {
            Some(original) => {
                print!("{original}");
                return Ok(());
            }
            None => {
                anyhow::bail!(
                    "CCR key not found or expired: {key} (keys live ~5 min; \
                     the daemon must have produced the marker this session)"
                );
            }
        }
    }
    if args.savings {
        let dir = crate::context::compress::default_ccr_dir();
        let s = crate::context::compress::read_savings(&dir);
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "blocks": s.blocks,
                        "bytes_before": s.bytes_before,
                        "bytes_after": s.bytes_after,
                        "bytes_saved": s.bytes_saved(),
                        "ratio": s.ratio(),
                    })
                );
            }
            _ => {
                println!(
                    "compression savings: {} blocks · {} → {} bytes · {} saved ({:.1}%)",
                    s.blocks,
                    s.bytes_before,
                    s.bytes_after,
                    s.bytes_saved(),
                    s.ratio() * 100.0
                );
            }
        }
        return Ok(());
    }

    let path = store::default_path();
    let mut conn = store::open(&path).with_context(|| format!("open {}", path.display()))?;

    if let Some(query) = &args.search {
        info!(query = %query, "ctx search");
        let hits = ctx::search(&conn, query, args.limit)?;
        render_hits(&hits, args.output);
        return Ok(());
    }

    if let Some(path) = &args.index {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        let label = args
            .label
            .clone()
            .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| path.display().to_string());
        let req = IndexRequest {
            label,
            content,
            file_path: Some(path.display().to_string()),
            content_type: args.content_type.clone(),
            source_category: args.category.clone(),
            event_id: None,
        };
        let report = ctx::index_document(&mut conn, &req)?;
        render_report(&report, args.output);
        return Ok(());
    }

    if args.index_stdin {
        let label = args
            .label
            .clone()
            .context("--index-stdin requires --label")?;
        let mut buf = String::new();
        use tokio::io::AsyncReadExt;
        tokio::io::stdin().read_to_string(&mut buf).await?;
        let req = IndexRequest {
            label,
            content: buf,
            file_path: None,
            content_type: args.content_type.clone(),
            source_category: args.category.clone(),
            event_id: None,
        };
        let report = ctx::index_document(&mut conn, &req)?;
        render_report(&report, args.output);
        return Ok(());
    }

    if args.stats {
        let s = ctx::stats(&conn)?;
        render_stats(&s, args.output);
        return Ok(());
    }

    if args.doctor {
        let d = ctx::doctor(&conn)?;
        render_doctor(&d, args.output);
        return Ok(());
    }

    if args.purge {
        let n = if args.all {
            ctx::purge(&mut conn, PurgeScope::All)?
        } else if let Some(label) = &args.label {
            ctx::purge(&mut conn, PurgeScope::Source(label))?
        } else if let Some(cat) = &args.category {
            ctx::purge(&mut conn, PurgeScope::Category(cat))?
        } else {
            anyhow::bail!("--purge needs --label, --category, or --all");
        };
        println!("purged {n} source(s)");
        return Ok(());
    }

    anyhow::bail!(
        "ctx: pick one of --search / --index / --index-stdin / --stats / --doctor / --purge"
    );
}

fn render_hits(hits: &[CtxHit], output: OutputFormat) {
    match output {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string_pretty(hits) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for h in hits {
                if let Ok(s) = serde_json::to_string(h) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Table => {
            println!("# {} hit(s)", hits.len());
            for h in hits {
                let preview = h.content.chars().take(120).collect::<String>();
                let mode = match h.mode {
                    crate::memory::ctx::SearchMode::Bm25 => "bm25",
                    crate::memory::ctx::SearchMode::Trigram => "trigram",
                    crate::memory::ctx::SearchMode::Fuzzy => "fuzzy",
                };
                println!(
                    "  [{}] {} ({}): {}",
                    mode,
                    h.label,
                    if h.title.is_empty() {
                        "(no title)"
                    } else {
                        h.title.as_str()
                    },
                    preview
                );
            }
        }
    }
}

fn render_report(r: &IndexReport, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            if let Ok(s) = serde_json::to_string(r) {
                println!("{s}");
            }
        }
        OutputFormat::Table => {
            println!(
                "indexed `{}` — {} chunk(s), {} bytes",
                r.label, r.chunk_count, r.bytes
            );
        }
    }
}

fn render_stats(s: &CtxStats, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            if let Ok(s) = serde_json::to_string_pretty(s) {
                println!("{s}");
            }
        }
        OutputFormat::Table => {
            println!("schema_version    {}", s.schema_version);
            println!("sources           {}", s.sources_count);
            println!("chunks            {}", s.chunks_count);
            println!("vocabulary_terms  {}", s.vocabulary_terms);
            println!(
                "latest_indexed_ts {}",
                s.latest_indexed_ts
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into())
            );
        }
    }
}

fn render_doctor(d: &CtxDoctor, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            if let Ok(s) = serde_json::to_string_pretty(d) {
                println!("{s}");
            }
        }
        OutputFormat::Table => {
            println!("schema_version              {}", d.schema_version);
            println!("journal_mode                {}", d.journal_mode);
            println!("fts5_available              {}", d.fts5_available);
            println!(
                "trigram_tokenizer_available {}",
                d.trigram_tokenizer_available
            );
        }
    }
}
