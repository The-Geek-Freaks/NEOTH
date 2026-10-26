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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::memory::ctx::{
    self, CtxDoctor, CtxHit, CtxStats, IndexReport, IndexRequest, PurgeScope,
};
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct CtxArgs {
    /// Apply an explicit logical-document JSON request. Use "-" for stdin.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["logical_status", "logical_epoch", "search", "index", "index_stdin", "stats", "doctor", "purge", "retrieve", "savings", "label", "category", "all", "content_type", "limit"])]
    pub logical_request: Option<PathBuf>,

    /// Inspect one logical document's current source, revision and event.
    #[arg(long, value_name = "ID", conflicts_with_all = ["logical_request", "logical_epoch", "search", "index", "index_stdin", "stats", "doctor", "purge", "retrieve", "savings", "label", "category", "all", "content_type", "limit"])]
    pub logical_status: Option<String>,

    /// Read the current logical-document request epoch.
    #[arg(long, conflicts_with_all = ["logical_request", "logical_status", "search", "index", "index_stdin", "stats", "doctor", "purge", "retrieve", "savings", "label", "category", "all", "content_type", "limit"])]
    pub logical_epoch: bool,
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
    if args.logical_request.is_some() || args.logical_status.is_some() || args.logical_epoch {
        println!("{}", run_logical_mode(&args, &store::default_path()).await?);
        return Ok(());
    }
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
            document_provenance: None,
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
            document_provenance: None,
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
        "ctx: pick one of --search / --index / --index-stdin / --stats / --doctor / --purge / --logical-request / --logical-status / --logical-epoch"
    );
}

async fn read_logical_request<R: tokio::io::AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    reader
        .take(ctx::logical::MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= ctx::logical::MAX_REQUEST_BYTES,
        "logical request exceeds 10 MiB"
    );
    ctx::logical::validate_request(&bytes)?;
    Ok(bytes)
}

async fn run_logical_mode(args: &CtxArgs, store_path: &Path) -> Result<String> {
    if let Some(path) = &args.logical_request {
        let bytes = if path == Path::new("-") {
            read_logical_request(tokio::io::stdin()).await?
        } else {
            let file = tokio::fs::File::open(path)
                .await
                .with_context(|| format!("read logical request {}", path.display()))?;
            read_logical_request(file).await?
        };
        // No store creation or migration until the complete request passes preflight.
        let mut conn = store::open(store_path)?;
        let report = ctx::logical::apply(&mut conn, &bytes)?;
        let table = format!(
            "{} {}: source {}, revision {}, event {} (replayed={}, current={})",
            report.action,
            report.logical_document_id,
            report.source_id,
            report.content_revision_id,
            report.logical_event_id,
            report.replayed,
            report.is_current,
        );
        return render_logical(&report, args.output, &table);
    }
    if let Some(identity) = &args.logical_status {
        ctx::logical::validate_identity(identity)?;
        let conn = store::open(store_path)?;
        return match ctx::logical::status(&conn, identity)? {
            Some(status) => {
                let table = format!(
                    "{}: source {}, revision {}, event {}, epoch {}",
                    status.logical_document_id,
                    status.source_id,
                    status.content_revision_id,
                    status.current_event_id,
                    status.authorization_epoch,
                );
                render_logical(&status, args.output, &table)
            }
            None => render_logical(
                &serde_json::json!({"logical_document_id": identity, "found": false}),
                args.output,
                &format!("logical document {identity}: not found"),
            ),
        };
    }
    ensure!(args.logical_epoch, "missing logical ctx action");
    let conn = store::open(store_path)?;
    let epoch = ctx::logical::epoch(&conn)?;
    render_logical(
        &serde_json::json!({"epoch": epoch}),
        args.output,
        &format!("epoch: {epoch}"),
    )
}

fn render_logical<T: serde::Serialize>(
    value: &T,
    output: OutputFormat,
    table: &str,
) -> Result<String> {
    match output {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Jsonl => Ok(serde_json::to_string(value)?),
        OutputFormat::Table => Ok(table.to_owned()),
    }
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

#[cfg(test)]
mod logical_tests {
    use super::*;
    use clap::Parser;
    use serde_json::{Value, json};

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        ctx: CtxArgs,
    }

    fn args(words: &[&str]) -> CtxArgs {
        TestCli::try_parse_from(std::iter::once("ctx").chain(words.iter().copied()))
            .unwrap()
            .ctx
    }

    fn request() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "action": "register", "logical_document_id": "doc-1",
            "logical_event_id": "register-1", "authorization_epoch": 0,
            "index": {"label": "manual", "content": "retained document body"}
        }))
        .unwrap()
    }

    #[test]
    fn logical_cli_actions_allow_defaults_and_reject_explicit_conflicts() {
        let actions: [&[&str]; 3] = [
            &["--logical-request", "-"],
            &["--logical-status", "doc-1"],
            &["--logical-epoch"],
        ];
        let conflicts: [&[&str]; 14] = [
            &["--search", "query"],
            &["--index", "file"],
            &["--index-stdin"],
            &["--stats"],
            &["--doctor"],
            &["--purge"],
            &["--retrieve", "key"],
            &["--savings"],
            &["--label", "name"],
            &["--category", "docs"],
            &["--all"],
            &["--content-type", "prose"],
            &["--limit", "20"],
            &["--content-type", "code"],
        ];
        for action in actions {
            let parsed = args(action);
            assert_eq!(parsed.content_type, "prose");
            assert_eq!(parsed.limit, 20);
            for conflict in conflicts {
                let argv = std::iter::once("ctx")
                    .chain(action.iter().copied())
                    .chain(conflict.iter().copied());
                assert!(
                    TestCli::try_parse_from(argv).is_err(),
                    "{action:?} {conflict:?}"
                );
            }
        }
        for left in 0..actions.len() {
            for right in left + 1..actions.len() {
                let argv = std::iter::once("ctx")
                    .chain(actions[left].iter().copied())
                    .chain(actions[right].iter().copied());
                assert!(TestCli::try_parse_from(argv).is_err());
            }
        }
        assert_eq!(
            args(&["--logical-request", "-"]).logical_request,
            Some(PathBuf::from("-"))
        );
    }

    #[tokio::test]
    async fn logical_cli_stream_limit_accepts_exact_boundary_and_rejects_one_extra_byte() {
        let mut exact = request();
        exact.resize(ctx::logical::MAX_REQUEST_BYTES, b' ');
        assert_eq!(read_logical_request(exact.as_slice()).await.unwrap(), exact);
        exact.push(b' ');
        let error = read_logical_request(exact.as_slice())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("10 MiB"), "{error}");
    }

    #[tokio::test]
    async fn logical_cli_invalid_requests_and_identities_never_open_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("untouched").join("views.db");
        let file = dir.path().join("request.json");
        let mut selected = args(&["--logical-request", "placeholder"]);
        selected.logical_request = Some(file.clone());
        for bytes in [
            b"{bad".as_slice(),
            br#"{"action":"register","unexpected":true}"#.as_slice(),
        ] {
            std::fs::write(&file, bytes).unwrap();
            assert!(run_logical_mode(&selected, &db).await.is_err());
            assert!(!db.parent().unwrap().exists());
        }
        let selected = args(&["--logical-status", "invalid identity"]);
        assert!(run_logical_mode(&selected, &db).await.is_err());
        assert!(!db.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn logical_cli_file_request_status_epoch_and_replay_share_one_owner() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let file = dir.path().join("request.json");
        std::fs::write(&file, request()).unwrap();
        let mut selected = args(&["--logical-request", "placeholder"]);
        selected.logical_request = Some(file);
        selected.output = OutputFormat::Jsonl;
        let first = run_logical_mode(&selected, &db).await.unwrap();
        assert_eq!(first.lines().count(), 1);
        let first: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(first["replayed"], false);
        assert!(first["raw_container_sha256"].is_null());
        let replay: Value =
            serde_json::from_str(&run_logical_mode(&selected, &db).await.unwrap()).unwrap();
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["source_id"], first["source_id"]);

        let mut selected = args(&["--logical-status", "doc-1"]);
        selected.output = OutputFormat::Json;
        let status: Value =
            serde_json::from_str(&run_logical_mode(&selected, &db).await.unwrap()).unwrap();
        assert_eq!(status["current_event_id"], "register-1");
        assert_eq!(status["source_id"], first["source_id"]);
        selected.logical_status = Some("absent".into());
        selected.output = OutputFormat::Jsonl;
        let missing = run_logical_mode(&selected, &db).await.unwrap();
        assert_eq!(missing.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&missing).unwrap(),
            json!({"logical_document_id":"absent","found":false})
        );
        selected.output = OutputFormat::Table;
        assert_eq!(
            run_logical_mode(&selected, &db).await.unwrap(),
            "logical document absent: not found"
        );

        let mut selected = args(&["--logical-epoch"]);
        selected.output = OutputFormat::Jsonl;
        assert_eq!(
            run_logical_mode(&selected, &db).await.unwrap(),
            r#"{"epoch":0}"#
        );
    }
}
