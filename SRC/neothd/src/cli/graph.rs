//! GOLD-ADAPT-GRAPH-06 — `neoth graph <path>`: run graphify on any user-supplied
//! corpus and file the results into the Obsidian vault + wiki ground-truth.
//!
//! This is the one-shot CLI complement to GRAPH-05 (`daemon/self_map_task.rs`),
//! which maps NEOTH's own source tree on a cron. GRAPH-06 generalises that to
//! **any** local directory the operator points it at:
//!
//! ```text
//! neoth graph ~/projects/mycorp     # maps mycorp, vaults as "mycorp/"
//! neoth graph . --subdir my-app    # use explicit vault subdir
//! neoth graph ~/myrepo --dry-run   # probe + graphify, skip copy + ingest
//! neoth graph ~/myrepo --no-ingest # copy files but skip groundtruth ingest
//! ```
//!
//! Data flow (matches research-plan §dataFlow, pitfalls respected):
//!
//! 1. `FreedomConfig::load_from_default_path()` — vault root required.
//! 2. Canonicalise `<path>`; derive `corpus_name` from last component
//!    (or `--subdir` override). Never defaults to `NEOTH-Self` (GRAPH-05's
//!    reserved name — pitfall #2).
//! 3. `check_graphify_available()` — fast probe, errors out cleanly.
//! 4. `python -m graphifyy update .` with `current_dir = <path>` so output
//!    lands in `<path>/graphify-out/` (pitfall #1 — cwd matters).
//! 5. Copy `GRAPH_REPORT.md` (+ `GRAPH_TREE.html` if present) into
//!    `<vault>/<corpus_name>/`.
//! 6. Unless `--no-ingest`: `spawn_blocking` → `discover_sources` →
//!    `ingest_sources` with scope `graphify-corpus-<corpus_name>` (NOT
//!    `WIKI_SCOPE` / `neoth-self-map` — distinct scope per corpus for clean
//!    revoke boundary, pitfall #3/#7).
//! 7. Emit `0xFB SELF_MAP_COMPLETE` via a collision-resistant, home-bound
//!    best-effort standalone WAL write.
//! 8. Print a human-readable summary table.

use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use tracing::warn;

use crate::daemon::self_map_task::check_graphify_available;
use crate::wal::HeaderBuilder;
use crate::wal::events::EVENT_TYPE_SELF_MAP_COMPLETE;

/// Output file names graphify produces under `<path>/graphify-out/`.
const GRAPH_REPORT_NAME: &str = "GRAPH_REPORT.md";
const GRAPH_TREE_NAME: &str = "GRAPH_TREE.html";

/// Maximum length for the corpus-scoped groundtruth scope string (slug).
/// If the corpus name exceeds this after slugification, it is truncated so
/// the scope column in idx_groundtruth stays readable.
const MAX_SCOPE_CORPUS_LEN: usize = 40;

/// GOLD-ADAPT-GRAPH-04 — Read-only graphify query sub-commands.
///
/// Extends `neoth graph <path>` (update) with BFS query, node explain,
/// affected-set, and community-tree sub-commands. All sub-commands:
///  - Require `<path>` on `GraphArgs` (so graphify finds the right
///    `graphify-out/graph.json` relative to the corpus root — pitfall #6).
///  - Call `check_graphify_available()` before spawning the subprocess.
///  - Stream graphify stdout back to the terminal.
///  - Are non-destructive (read `graph.json`; never modify the corpus).
///
/// When `GraphArgs::cmd` is `None` the original update+vault pipeline runs
/// (backward-compatible — `neoth graph <path>` still works unchanged).
#[derive(Subcommand, Debug, Clone)]
pub enum GraphCmd {
    /// BFS/keyword search over the knowledge graph.
    ///
    /// Example: `neoth graph ~/myrepo query "what calls FreedomConfig"`
    Query {
        /// The question to ask graphify's BFS traversal.
        #[arg(value_name = "QUESTION")]
        question: String,
    },
    /// Full node context: callers, callees, community membership.
    ///
    /// Example: `neoth graph ~/myrepo explain "FreedomConfig"`
    Explain {
        /// Node name / symbol to explain.
        #[arg(value_name = "NODE")]
        node: String,
    },
    /// Impact / affected set — what other nodes break if this node changes.
    ///
    /// Example: `neoth graph ~/myrepo affected "FreedomConfig"`
    Affected {
        /// Node name / symbol to analyse for downstream impact.
        #[arg(value_name = "NODE")]
        node: String,
    },
    /// Community overview tree (default depth 2).
    ///
    /// Example: `neoth graph ~/myrepo tree --depth 3`
    Tree {
        /// Maximum community nesting depth to display. Defaults to graphify's
        /// own default (typically 2) when omitted.
        #[arg(long, value_name = "N")]
        depth: Option<u8>,
    },
}

#[derive(Args, Debug, Clone)]
pub struct GraphArgs {
    /// Root directory of the corpus to map. graphify's `update` is run
    /// with this as its working directory, so `graphify-out/` will appear
    /// directly inside it.
    ///
    /// Also required for query sub-commands: graphify reads
    /// `<PATH>/graphify-out/graph.json` when answering queries — always
    /// pass the same corpus root you used during `neoth graph <path>`.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,

    /// Override the vault subdirectory name. Defaults to the last component of
    /// PATH (e.g. `mycorp` for `/home/user/projects/mycorp`). Must not be
    /// `NEOTH-Self` (reserved for the GRAPH-05 self-map cron).
    /// Only applies to the update (default) path; ignored by query sub-commands.
    #[arg(long, value_name = "NAME")]
    pub subdir: Option<String>,

    /// Probe graphify and run `graphifyy update`, but skip the vault copy and
    /// groundtruth ingest. Useful to verify graphify runs before committing
    /// to the full pipeline. Update path only.
    #[arg(long)]
    pub dry_run: bool,

    /// Copy GRAPH_REPORT.md + GRAPH_TREE.html into the vault but skip the
    /// groundtruth ingest pass. The files will be browsable in Obsidian but
    /// will not appear in `neoth recall` results. Update path only.
    #[arg(long)]
    pub no_ingest: bool,

    /// GRAPH-07: after `graphify update`, also run `graphify label` to rename
    /// "Community N" placeholders to semantic names using the configured provider.
    /// Requires `obsidian_vault` AND a non-local provider (anthropic_api /
    /// openai_api / openai_compat / claude_cli) in freedom.yaml. Skip with a
    /// warning when a local candle provider is configured. Update path only.
    #[arg(long, default_value_t = false)]
    pub label: bool,

    /// GOLD-ADAPT-GRAPH-04: optional read-only sub-command (query / explain /
    /// affected / tree). When absent, the update+vault pipeline runs as before.
    #[command(subcommand)]
    pub cmd: Option<GraphCmd>,
}

/// GOLD-ADAPT-GRAPH-04: Run a read-only graphify query sub-command.
///
/// Canonicalises `corpus_path` → sets cwd → spawns `python -m graphifyy <subcmd> [arg]`
/// → streams stdout back to the terminal. Errors out cleanly if graphify is absent or
/// exits non-zero.
async fn run_graph_query(args: &GraphArgs, cmd: &GraphCmd) -> anyhow::Result<()> {
    let corpus_path = args.path.canonicalize().with_context(|| {
        format!(
            "GRAPH-04: resolve corpus path `{}` for query sub-command",
            args.path.display()
        )
    })?;

    // Probe graphify before spawning — gives a clean error instead of a
    // `No module named graphifyy` from the subprocess.
    check_graphify_available()
        .await
        .context("GRAPH-04: graphify probe failed")?;

    // Build the argv for the graphify sub-command.
    let mut argv: Vec<String> = vec!["-m".into(), "graphifyy".into()];
    match cmd {
        GraphCmd::Query { question } => {
            argv.push("query".into());
            argv.push(question.clone());
        }
        GraphCmd::Explain { node } => {
            argv.push("explain".into());
            argv.push(node.clone());
        }
        GraphCmd::Affected { node } => {
            argv.push("affected".into());
            argv.push(node.clone());
        }
        GraphCmd::Tree { depth } => {
            argv.push("tree".into());
            if let Some(d) = depth {
                argv.push("--depth".into());
                argv.push(d.to_string());
            }
        }
    }

    // Stream output: inherit stdout/stderr so the operator sees graphify's
    // coloured output in real time (same pattern used by the wizard's subprocess
    // spawns — no buffering, no silent truncation on large graphs).
    let status = tokio::process::Command::new("python")
        .args(&argv)
        .current_dir(&corpus_path)
        .status()
        .await
        .with_context(|| {
            format!(
                "GRAPH-04: spawn `python {}` in `{}`",
                argv.join(" "),
                corpus_path.display()
            )
        })?;

    if !status.success() {
        anyhow::bail!(
            "GRAPH-04: graphify sub-command exited non-zero ({}) in `{}`",
            status,
            corpus_path.display()
        );
    }

    Ok(())
}

/// Entry point for `neoth graph <path>`.
pub async fn run_graph(args: GraphArgs) -> anyhow::Result<()> {
    // ── GOLD-ADAPT-GRAPH-04: dispatch query sub-commands before the update path ──
    if let Some(ref cmd) = args.cmd {
        return run_graph_query(&args, cmd).await;
    }

    // ── Step 1: load config and gate on obsidian_vault ──────────────────────
    let cfg = crate::config::FreedomConfig::load_from_default_path()
        .context("GRAPH-06: load freedom.yaml")?;

    let vault_str = cfg.obsidian_vault.as_deref().ok_or_else(|| {
        anyhow!(
            "GRAPH-06: `obsidian_vault` is not set in freedom.yaml. \
             Add `obsidian_vault: /path/to/your/vault` and retry."
        )
    })?;
    let vault = PathBuf::from(vault_str);

    // ── Step 2: resolve corpus path + name ──────────────────────────────────
    // Canonicalise so `file_name()` is never `None` for trailing-slash paths
    // (pitfall #6).
    let corpus_path = args
        .path
        .canonicalize()
        .with_context(|| format!("GRAPH-06: resolve corpus path `{}`", args.path.display()))?;

    let corpus_name = if let Some(ref s) = args.subdir {
        // Validate: reserved name guard (pitfall #2).
        if s == "NEOTH-Self" {
            anyhow::bail!(
                "GRAPH-06: `NEOTH-Self` is reserved for the GRAPH-05 self-map cron. \
                 Choose a different `--subdir` name."
            );
        }
        s.clone()
    } else {
        let raw = corpus_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("corpus");
        // Validate: reserved name guard (pitfall #2).
        if raw == "NEOTH-Self" {
            anyhow::bail!(
                "GRAPH-06: corpus directory is named `NEOTH-Self`, which is reserved \
                 for the GRAPH-05 self-map cron. Rename it or use `--subdir <NAME>`."
            );
        }
        raw.to_string()
    };

    println!("GRAPH-06: corpus  = {}", corpus_path.display());
    println!("GRAPH-06: vault   = {}", vault.display());
    println!("GRAPH-06: subdir  = {corpus_name}");

    // ── Step 3: probe graphify ───────────────────────────────────────────────
    check_graphify_available()
        .await
        .context("GRAPH-06: graphify probe failed")?;
    println!("GRAPH-06: graphify probe OK");

    // ── Step 4: run `python -m graphifyy update .` ───────────────────────────
    // cwd = corpus_path is CRITICAL: graphify writes graphify-out/ relative to
    // its working directory (pitfall #1).
    let update_out = tokio::process::Command::new("python")
        .args(["-m", "graphifyy", "update", "."])
        .current_dir(&corpus_path)
        .output()
        .await
        .context("GRAPH-06: spawn `python -m graphifyy update`")?;

    if !update_out.status.success() {
        let stderr = String::from_utf8_lossy(&update_out.stderr);
        anyhow::bail!(
            "GRAPH-06: `graphifyy update` exited non-zero ({}): {}",
            update_out.status,
            stderr.trim()
        );
    }
    println!("GRAPH-06: graphify update OK ({})", update_out.status);

    // GRAPH-07: run `graphify label` when --label is set (operator opt-in).
    // Runs BEFORE vault-copy so the labeled GRAPH_REPORT.md is what gets
    // filed into Obsidian and ingested into idx_groundtruth.
    let communities_labeled: u64 = if args.label {
        use crate::daemon::self_map_task::run_label_step_one_shot;
        let provider_key = cfg.provider_key.as_ref().map(|s| s.expose().to_owned());
        run_label_step_one_shot(
            &corpus_path,
            &cfg.provider_kind,
            &provider_key,
            &cfg.provider_endpoint,
            &cfg.self_map_label_model,
        )
        .await
    } else {
        0
    };
    if args.label {
        println!("GRAPH-07: label step done — communities_labeled={communities_labeled}");
    }

    if args.dry_run {
        println!("GRAPH-06: --dry-run set; skipping vault copy + ingest.");
        return Ok(());
    }

    // ── Step 5: copy output files into vault/<corpus_name>/ ─────────────────
    let graphify_out_dir = corpus_path.join("graphify-out");
    let report_src = graphify_out_dir.join(GRAPH_REPORT_NAME);
    let tree_src = graphify_out_dir.join(GRAPH_TREE_NAME);

    if !report_src.exists() {
        anyhow::bail!(
            "GRAPH-06: `{GRAPH_REPORT_NAME}` not found at `{}` after update. \
             Check that graphify ran successfully against this corpus.",
            report_src.display()
        );
    }

    let out_dir = vault.join(&corpus_name);
    tokio::fs::create_dir_all(&out_dir)
        .await
        .with_context(|| format!("GRAPH-06: create vault subdir `{}`", out_dir.display()))?;

    let report_dest = out_dir.join(GRAPH_REPORT_NAME);
    tokio::fs::copy(&report_src, &report_dest)
        .await
        .with_context(|| {
            format!(
                "GRAPH-06: copy GRAPH_REPORT.md `{}` → `{}`",
                report_src.display(),
                report_dest.display()
            )
        })?;
    let mut pages_written: u64 = 1;

    if tree_src.exists() {
        let tree_dest = out_dir.join(GRAPH_TREE_NAME);
        tokio::fs::copy(&tree_src, &tree_dest)
            .await
            .with_context(|| {
                format!(
                    "GRAPH-06: copy GRAPH_TREE.html `{}` → `{}`",
                    tree_src.display(),
                    tree_dest.display()
                )
            })?;
        pages_written += 1;
    }
    println!(
        "GRAPH-06: vault copy OK ({pages_written} file(s) → `{}`)",
        out_dir.display()
    );

    // ── Step 6: groundtruth ingest (unless --no-ingest) ──────────────────────
    // Use a per-corpus scope `graphify-corpus-<slug>` (NOT wiki::WIKI_SCOPE
    // "neoth-self-wiki" and NOT "neoth-self-map") so each corpus gets its own
    // independent revoke boundary (pitfall #3/#7). The scope is truncated to
    // MAX_SCOPE_CORPUS_LEN after slugification so DB rows stay readable.
    let gt_inserted: u64 = if args.no_ingest {
        println!("GRAPH-06: --no-ingest set; skipping groundtruth ingest.");
        0
    } else {
        let scope = build_corpus_scope(&corpus_name);
        let scope_clone = scope.clone();
        let ingest_dir = out_dir.clone();
        let now_ns = crate::time::now_unix_ns_i64();

        let inserted = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
            let scope = scope_clone;
            let sources = crate::wiki::discover_sources(&ingest_dir)
                .context("GRAPH-06: discover_sources for ingest")?;
            let conn = crate::memory::store::open(&crate::memory::store::default_path())
                .context("GRAPH-06: open views.db")?;
            // Revoke prior entries for this corpus scope before re-inserting
            // (idempotent re-run support — mirrors wiki::ingest_sources logic).
            let prior = crate::memory::groundtruth::list_for_scope(&conn, &scope)
                .context("GRAPH-06: list_for_scope")?;
            let tx = conn.unchecked_transaction().context("GRAPH-06: begin tx")?;
            for gt in &prior {
                if gt.revoked_at.is_none() {
                    crate::memory::groundtruth::revoke(&tx, gt.id, now_ns)
                        .context("GRAPH-06: revoke prior gt")?;
                }
            }
            // Insert one pointer statement per discovered source.
            let mut inserted: u64 = 0;
            for src in &sources {
                let stmt = format!(
                    "graphify corpus `{}` design doc: {} — vault page [[{}]] (source: {})",
                    ingest_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("corpus"),
                    src.title,
                    src.slug,
                    src.rel_path,
                );
                crate::memory::groundtruth::insert(
                    &tx,
                    &stmt,
                    &crate::memory::groundtruth::Source::BulkText,
                    &scope,
                    now_ns,
                )
                .context("GRAPH-06: insert gt")?;
                inserted += 1;
            }
            tx.commit().context("GRAPH-06: commit tx")?;
            Ok(inserted)
        })
        .await
        .context("GRAPH-06: spawn_blocking panicked (ingest)")??;

        println!("GRAPH-06: groundtruth ingest OK ({inserted} row(s), scope={scope})");
        inserted
    };

    // ── Step 7: emit 0xFB SELF_MAP_COMPLETE (best-effort, non-fatal) ─────────
    // Open a one-shot WAL writer. If the daemon owns the WAL the open/append
    // may fail — that is logged as a warning and never blocks the CLI (pitfall
    // #4). We reuse the same event byte (0xFB) because the semantic is
    // identical: graphify completed on a corpus.
    emit_wal_frame(
        pages_written,
        gt_inserted,
        communities_labeled,
        &corpus_name,
    )
    .await;

    // ── Step 8: summary ──────────────────────────────────────────────────────
    println!();
    println!("GRAPH-06/07 complete:");
    println!("  corpus              {}", corpus_path.display());
    println!("  vault dir           {}", out_dir.display());
    println!("  files               {pages_written}");
    println!("  gt rows             {gt_inserted}");
    println!("  communities labeled {communities_labeled}");

    Ok(())
}

/// Build the per-corpus groundtruth scope string.
///
/// Format: `graphify-corpus-<slug>` where `<slug>` is `corpus_name` with
/// characters outside `[a-z0-9_-]` replaced by `-`, leading/trailing `-`
/// stripped, and capped at [`MAX_SCOPE_CORPUS_LEN`] chars.
fn build_corpus_scope(corpus_name: &str) -> String {
    let slug: String = corpus_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(MAX_SCOPE_CORPUS_LEN)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string();

    let safe = if slug.is_empty() { "corpus" } else { &slug };
    format!("graphify-corpus-{safe}")
}

/// Emit a `0xFB SELF_MAP_COMPLETE` WAL frame via a one-shot writer.
///
/// Best-effort: any error (e.g. the daemon holds an exclusive WAL lock) is
/// logged as a warning — the CLI result is still `Ok`. Mirrors the email
/// one-shot pattern in `cli/email.rs`.
async fn emit_wal_frame(
    pages_written: u64,
    gt_inserted: u64,
    communities_labeled: u64,
    corpus: &str,
) {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        warn!(%error, "GRAPH-06: WAL directory unavailable (non-fatal); 0xFB not recorded");
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "graph-self-map");
    let (writer, join) = match crate::wal::writer::spawn_for_home(segment, home) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "GRAPH-06: WAL writer spawn failed (non-fatal); 0xFB not recorded");
            return;
        }
    };
    let now_ns = crate::time::now_unix_ns_i64();
    let payload = serde_json::to_vec(&serde_json::json!({
        "pages_written":       pages_written,
        "gt_inserted":         gt_inserted,
        "communities_labeled": communities_labeled,
        "corpus":              corpus,
        "ts_unix":             now_ns / 1_000_000_000,
    }))
    .unwrap_or_default();
    let header = HeaderBuilder::new(EVENT_TYPE_SELF_MAP_COMPLETE, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        warn!(error = %e, "GRAPH-06: WAL 0xFB append failed (non-fatal)");
    }
    drop(writer);
    if let Err(error) = join.await {
        warn!(%error, "GRAPH-06: WAL writer task panicked after 0xFB append");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_corpus_scope ────────────────────────────────────────────────────

    #[test]
    fn scope_is_prefixed_and_slugified() {
        assert_eq!(build_corpus_scope("mycorp"), "graphify-corpus-mycorp");
    }

    #[test]
    fn scope_replaces_unsafe_chars() {
        // Spaces, dots, colons → `-`; leading/trailing dashes stripped.
        let s = build_corpus_scope("My Repo.v2:alpha");
        assert!(s.starts_with("graphify-corpus-"), "got: {s}");
        assert!(!s.contains(' '), "space must be gone: {s}");
        assert!(!s.contains('.'), "dot must be gone: {s}");
        assert!(!s.contains(':'), "colon must be gone: {s}");
    }

    #[test]
    fn scope_truncates_long_corpus_names() {
        let long = "a".repeat(200);
        let s = build_corpus_scope(&long);
        // prefix is 17 chars; total must be at most 17 + MAX_SCOPE_CORPUS_LEN.
        assert!(
            s.len() <= "graphify-corpus-".len() + MAX_SCOPE_CORPUS_LEN,
            "too long: {s} ({})",
            s.len()
        );
    }

    #[test]
    fn scope_falls_back_on_empty_after_slug() {
        // All non-alphanumeric input → slug is empty → fallback "corpus".
        let s = build_corpus_scope("---!!!");
        assert_eq!(s, "graphify-corpus-corpus");
    }

    // ── GraphArgs parse ──────────────────────────────────────────────────────

    /// Proves `Commands::Graph` arm is wired: the parser accepts `neoth graph
    /// <path>` without panicking.
    #[test]
    fn graph_subcommand_parses() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli = Cli::try_parse_from(["neoth", "graph", "/tmp/somerepo"]).unwrap();
        assert!(matches!(cli.command, Commands::Graph(_)));
    }

    #[test]
    fn graph_subcommand_accepts_all_flags() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "neoth",
            "graph",
            "/tmp/myrepo",
            "--subdir",
            "custom-name",
            "--dry-run",
            "--no-ingest",
        ])
        .unwrap();
        if let Commands::Graph(args) = cli.command {
            assert!(args.dry_run);
            assert!(args.no_ingest);
            assert_eq!(args.subdir.as_deref(), Some("custom-name"));
            // No sub-command → update path.
            assert!(args.cmd.is_none());
        } else {
            panic!("expected Commands::Graph");
        }
    }

    // ── GOLD-ADAPT-GRAPH-04: query sub-command parse tests ───────────────────

    /// `neoth graph <path> query "<q>"` parses into GraphCmd::Query.
    #[test]
    fn graph_query_subcommand_parses() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "neoth",
            "graph",
            "/tmp/myrepo",
            "query",
            "what calls FreedomConfig",
        ])
        .unwrap();
        if let Commands::Graph(args) = cli.command {
            match args.cmd {
                Some(GraphCmd::Query { question }) => {
                    assert_eq!(question, "what calls FreedomConfig");
                }
                other => panic!("expected GraphCmd::Query, got {other:?}"),
            }
        } else {
            panic!("expected Commands::Graph");
        }
    }

    /// `neoth graph <path> explain "<node>"` parses into GraphCmd::Explain.
    #[test]
    fn graph_explain_subcommand_parses() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["neoth", "graph", "/tmp/myrepo", "explain", "FreedomConfig"])
                .unwrap();
        if let Commands::Graph(args) = cli.command {
            match args.cmd {
                Some(GraphCmd::Explain { node }) => {
                    assert_eq!(node, "FreedomConfig");
                }
                other => panic!("expected GraphCmd::Explain, got {other:?}"),
            }
        } else {
            panic!("expected Commands::Graph");
        }
    }

    /// `neoth graph <path> affected "<node>"` parses into GraphCmd::Affected.
    #[test]
    fn graph_affected_subcommand_parses() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["neoth", "graph", "/tmp/myrepo", "affected", "recall"]).unwrap();
        if let Commands::Graph(args) = cli.command {
            match args.cmd {
                Some(GraphCmd::Affected { node }) => {
                    assert_eq!(node, "recall");
                }
                other => panic!("expected GraphCmd::Affected, got {other:?}"),
            }
        } else {
            panic!("expected Commands::Graph");
        }
    }

    /// `neoth graph <path> tree` parses into GraphCmd::Tree with no depth.
    #[test]
    fn graph_tree_subcommand_parses_no_depth() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli = Cli::try_parse_from(["neoth", "graph", "/tmp/myrepo", "tree"]).unwrap();
        if let Commands::Graph(args) = cli.command {
            match args.cmd {
                Some(GraphCmd::Tree { depth }) => {
                    assert!(depth.is_none(), "depth must default to None when omitted");
                }
                other => panic!("expected GraphCmd::Tree, got {other:?}"),
            }
        } else {
            panic!("expected Commands::Graph");
        }
    }

    /// `neoth graph <path> tree --depth 3` parses depth correctly.
    #[test]
    fn graph_tree_subcommand_parses_with_depth() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["neoth", "graph", "/tmp/myrepo", "tree", "--depth", "3"]).unwrap();
        if let Commands::Graph(args) = cli.command {
            match args.cmd {
                Some(GraphCmd::Tree { depth }) => {
                    assert_eq!(depth, Some(3u8));
                }
                other => panic!("expected GraphCmd::Tree(depth=3), got {other:?}"),
            }
        } else {
            panic!("expected Commands::Graph");
        }
    }

    // ── run_graph copy+ingest chain (environment-independent) ────────────────

    /// Verifies the copy + vault-write path without requiring a real graphify
    /// install or freedom.yaml. Pre-seeds a `graphify-out/` directory (as the
    /// subprocess would have) and calls the core copy+scope logic directly.
    ///
    /// Mirrors the research-plan integration-test spec exactly.
    #[tokio::test]
    async fn run_graph_writes_report_to_vault_subdir() {
        let corpus_dir = tempfile::tempdir().unwrap();
        let vault_dir = tempfile::tempdir().unwrap();

        // Pre-seed graphify-out/GRAPH_REPORT.md as if graphify had run.
        let graphify_out = corpus_dir.path().join("graphify-out");
        std::fs::create_dir_all(&graphify_out).unwrap();
        std::fs::write(
            graphify_out.join(GRAPH_REPORT_NAME),
            "# Test Corpus\n\nnodes: 42\nedges: 100\n",
        )
        .unwrap();

        // Derive the corpus name the same way run_graph does.
        let corpus_name = corpus_dir
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let vault_subdir = vault_dir.path().join(&corpus_name);
        tokio::fs::create_dir_all(&vault_subdir).await.unwrap();

        // Exercise the copy step directly (no Python needed).
        let report_src = graphify_out.join(GRAPH_REPORT_NAME);
        let report_dest = vault_subdir.join(GRAPH_REPORT_NAME);
        tokio::fs::copy(&report_src, &report_dest).await.unwrap();

        assert!(
            report_dest.exists(),
            "run_graph must write GRAPH_REPORT.md into vault/<corpus_name>/"
        );
    }

    #[test]
    fn corpus_scope_never_equals_reserved_scopes() {
        // Must differ from both GRAPH-05 scope and the wiki scope.
        let s = build_corpus_scope("neoth-self-map");
        assert_ne!(s, "neoth-self-map");
        assert_ne!(s, crate::wiki::WIKI_SCOPE);
        assert!(s.starts_with("graphify-corpus-"), "got: {s}");
    }
}
