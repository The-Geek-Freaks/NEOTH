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
//! neoth graph ~/myrepo --dry-run   # validate the plan; publishes and mutates nothing
//! neoth graph ~/myrepo --no-ingest # publish, then revoke this corpus's recall scope
//! ```
//!
//! Data flow (matches research-plan §dataFlow, pitfalls respected):
//!
//! 1. `FreedomConfig::load_from_default_path()` — vault root required.
//! 2. Canonicalise `<path>`; derive `corpus_name` from last component
//!    (or `--subdir` override). Never defaults to `NEOTH-Self` (GRAPH-05's
//!    reserved name — pitfall #2).
//! 3. `check_graphify_available()` — fast probe, errors out cleanly. The
//!    installed distribution is `graphifyy==0.8.41`; its isolated Python module
//!    is `python -I -m graphify`.
//! 4. `python -I -m graphify update .` with `current_dir = <path>` so output
//!    lands in `<path>/graphify-out/` (pitfall #1 — cwd matters).
//! 5. Rebuild the native symbol map + call graph from verified file bytes and
//!    atomically bind its index/graph generation.
//! 6. Validate/hash the Graphify artifacts and atomically publish an immutable
//!    generation below `<vault>/<corpus_name>/generations/`, advancing
//!    `CURRENT` only after the complete generation verifies.
//! 7. Commit the durable, scope-bound Graphify transaction: root-bound SQLite
//!    pointers, or for `--no-ingest` an atomic revocation of the matching prior
//!    Graphify recall scope after publication. Crash recovery resumes an
//!    unambiguous journal and fails closed for ambiguous legacy journals.
//! 8. Emit `0xFB SELF_MAP_COMPLETE` via a collision-resistant, home-bound,
//!    acknowledged standalone WAL write.
//! 9. Print the requested table/JSON summary.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::daemon::self_map_task::check_graphify_available;
use crate::wal::HeaderBuilder;
use crate::wal::events::EVENT_TYPE_SELF_MAP_COMPLETE;

const GRAPH_QUERY_STDOUT_CAP: usize = 8 * 1024 * 1024;
const GRAPH_QUERY_STDERR_CAP: usize = 256 * 1024;
const GRAPH_QUERY_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const GRAPH_UPDATE_STDOUT_CAP: usize = 2 * 1024 * 1024;
const GRAPH_UPDATE_STDERR_CAP: usize = 512 * 1024;
const GRAPH_UPDATE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// GOLD-ADAPT-GRAPH-04 — Read-only graphify query sub-commands.
///
/// Extends `neoth graph <path>` (update) with BFS query, node explain,
/// affected-set, and community-tree sub-commands. All sub-commands:
///  - Require `<path>` on `GraphArgs` (so graphify finds the right
///    `graphify-out/graph.json` relative to the corpus root — pitfall #6).
///  - Call `check_graphify_available()` before spawning the subprocess.
///  - Stream graphify stdout in table mode; capture it into a valid envelope
///    in JSON/JSONL mode.
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

    /// Validate the Graphify update plan without running Graphify, publishing,
    /// ingesting, or changing the corpus. Update path only.
    #[arg(long)]
    pub dry_run: bool,

    /// Publish a validated immutable generation, then atomically revoke the
    /// matching prior Graphify recall scope. The files remain browsable in
    /// Obsidian but no longer appear in `neoth recall`. Update path only.
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

    /// Injected from the global `--output` flag by the CLI dispatcher.
    #[clap(skip)]
    pub output: OutputFormat,
}

/// GOLD-ADAPT-GRAPH-04: Run a read-only graphify query sub-command.
///
/// Canonicalises `corpus_path` → sets cwd → spawns
/// `python -I -m graphify <subcmd> [arg]`
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
    // `No module named graphify` from the subprocess.
    // Resolve a single opaque interpreter capability before entering the
    // caller-controlled corpus directory. Every probe and Graphify child in
    // this operation reuses this identity-bound token.
    let runtime = crate::graphify_runner::GraphifyRuntime::discover("python")
        .await
        .context("GRAPH-04: resolve verified Graphify runtime")?;
    check_graphify_available(&runtime)
        .await
        .context("GRAPH-04: graphify probe failed")?;

    // Build the argv for the graphify sub-command.
    // `-I` prevents a corpus-owned `graphify.py`/package, PYTHONPATH, or
    // user-site package from shadowing the runtime which the probe validated.
    let mut argv: Vec<String> = vec!["-I".into(), "-m".into(), "graphify".into()];
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

    let limits = crate::graphify_runner::GraphifyRunLimits::new(
        "graph-query",
        GRAPH_QUERY_TIMEOUT,
        GRAPH_QUERY_STDOUT_CAP,
        GRAPH_QUERY_STDERR_CAP,
    )?;
    let output = crate::graphify_runner::run_graphify_process(
        crate::graphify_runner::GraphifyRunRequest::with_runtime(runtime, limits)
            .args(argv)
            .current_dir(&corpus_path),
    )
    .await
    .context("GRAPH-04: bounded Graphify query failed")?;

    match args.output {
        OutputFormat::Table => {
            let graphify_output = sanitize_graphify_table_output(&output.stdout);
            print!("{graphify_output}");
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            let graphify_output = String::from_utf8(output.stdout)
                .context("GRAPH-04: graphify query stdout was not valid UTF-8")?;
            let recall = match cmd {
                GraphCmd::Query { question } if !question.trim().is_empty() => {
                    let recall_corpus = corpus_path.clone();
                    let recall_question = question.clone();
                    Some(
                        tokio::task::spawn_blocking(move || {
                            graph_query_recall_envelope(&recall_corpus, &recall_question)
                        })
                        .await
                        .context("GRAPH-04: native recall task panicked")?
                        .context("GRAPH-04: native recall failed")?,
                    )
                }
                _ => None,
            };
            let envelope = serde_json::json!({
                "graphify_output": graphify_output,
                "recall": recall,
            });
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&envelope)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&envelope)?),
                OutputFormat::Table => unreachable!("table output handled above"),
            }
        }
    }

    Ok(())
}

fn sanitize_graphify_table_output(output: &[u8]) -> String {
    crate::security::redact::sanitize_tool_output(&String::from_utf8_lossy(output))
}

fn graph_query_recall_envelope(
    corpus_path: &std::path::Path,
    question: &str,
) -> anyhow::Result<crate::code_map::RecallWireEnvelope> {
    let db_path = crate::code_map::persist::default_path();
    graph_query_recall_envelope_at(&db_path, corpus_path, question)
}

fn graph_query_recall_envelope_at(
    db_path: &std::path::Path,
    corpus_path: &std::path::Path,
    question: &str,
) -> anyhow::Result<crate::code_map::RecallWireEnvelope> {
    const RECALL_MAX: usize = 5;
    let conn = crate::code_map::persist::open(db_path)
        .with_context(|| format!("GRAPH-04: open code-map database at {}", db_path.display()))?;
    let receipt = crate::code_map::recall::recall_receipt_for_prompt(
        &conn,
        corpus_path,
        question,
        RECALL_MAX,
        crate::code_map::recall::RecallStaleness::Check,
    )?;
    match receipt {
        Some(receipt) => {
            crate::code_map::RecallWireEnvelope::success(question, RECALL_MAX, &receipt)
        }
        None => crate::code_map::RecallWireEnvelope::empty(
            crate::code_map::RecallWireStatus::Unmapped,
            question,
            RECALL_MAX,
            "query corpus has no persisted native code-map snapshot",
        ),
    }
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
    run_graph_update(args, cfg).await
}

/// Update path with an already loaded configuration.
///
/// Keeping the configuration dependency injectable makes the `--dry-run`
/// contract testable without touching the operator's global NEOTH home.  More
/// importantly, the dry-run return below is deliberately before runtime
/// discovery, recovery, source indexing, and every persistence leaf.
async fn run_graph_update(
    args: GraphArgs,
    cfg: crate::config::FreedomConfig,
) -> anyhow::Result<()> {
    let table_output = matches!(args.output, OutputFormat::Table);

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
        if is_reserved_self_map_namespace(s) {
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
        if is_reserved_self_map_namespace(raw) {
            anyhow::bail!(
                "GRAPH-06: corpus directory is named `NEOTH-Self`, which is reserved \
                 for the GRAPH-05 self-map cron. Rename it or use `--subdir <NAME>`."
            );
        }
        raw.to_string()
    };

    // `--dry-run` is a plan-only operation. It intentionally runs after the
    // config/path/subdirectory validation necessary to describe the intended
    // destination, but before *any* Python/runtime probe, publication lease or
    // recovery, native code-map persistence, vault write, views SQLite access,
    // or completion WAL setup. Do not move this below the Graphify probe: a
    // dry-run must work on a machine where Graphify is not installed.
    if args.dry_run {
        return emit_dry_run_plan(&args, &corpus_path, &vault, &corpus_name);
    }

    if table_output {
        println!("GRAPH-06: corpus  = {}", corpus_path.display());
        println!("GRAPH-06: vault   = {}", vault.display());
        println!("GRAPH-06: subdir  = {corpus_name}");
    }

    // ── Step 3: probe graphify ───────────────────────────────────────────────
    // The opaque runtime is deliberately resolved before any Graphify child
    // inherits the corpus cwd.  Do not replace this with raw `python` calls:
    // the same token must bind probe, update, and optional labeling.
    let runtime = crate::graphify_runner::GraphifyRuntime::discover("python")
        .await
        .context("GRAPH-06: resolve verified Graphify runtime")?;
    check_graphify_available(&runtime)
        .await
        .context("GRAPH-06: graphify probe failed")?;
    if table_output {
        println!("GRAPH-06: graphify probe OK");
    }

    // Recovery runs before any native rebuild. A crashed publication is bound
    // to its existing persisted generation through a read-only attestation;
    // no database creation, migration, or generation advance is allowed on
    // that branch.
    let native_root = crate::code_map::CanonicalRepoRoot::discover(&corpus_path)?;
    let native_db = crate::code_map::persist::default_path();
    let fingerprint_root = native_root.clone();
    let pre_graphify_fingerprint = tokio::task::spawn_blocking(move || {
        crate::code_map::snapshot::stable_source_fingerprint(
            &fingerprint_root,
            crate::code_map::RebuildOptions::default(),
        )
    })
    .await
    .context("GRAPH-06: pre-Graphify source fingerprint task panicked")?
    .context("GRAPH-06: pre-Graphify source fingerprint failed")?;

    // Acquire the cross-process publication lease before Graphify is allowed
    // to rewrite graphify-out. A pending transaction is recovered under this
    // exact lease epoch; only a no-pending result returns the lease for the
    // new update → publish → SQLite → WAL sequence below.
    let recovery_vault = vault.clone();
    let recovery_root = native_root.clone();
    let recovery_native_db = native_db.clone();
    let recovery_db = crate::memory::store::default_path();
    let recovery_open = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let lease = crate::graphify_publish::acquire_graphify_publication_lease(
            &recovery_vault,
            &recovery_root,
        )?;
        let targets = crate::graphify_transaction::discover_graphify_recovery_targets(&lease)?;
        anyhow::ensure!(
            targets.len() <= 1,
            "GRAPH-06: multiple pending Graphify publication journals share one corpus identity"
        );
        let Some(corpus_dir) = targets.into_iter().next() else {
            return Ok((
                crate::graphify_transaction::GraphifyRecoveryOpen::NoPendingPublication(lease),
                None,
            ));
        };
        crate::graphify_transaction::preflight_graphify_recovery_scope_under_lease(
            &lease,
            &corpus_dir,
            crate::wiki::GraphifyIngestScope::Corpus,
        )?;
        let (_, receipt) =
            crate::graphify_publish::load_current_graphify_generation_receipt(&corpus_dir)?
                .context("GRAPH-06: recovery journal has no CURRENT receipt")?;
        let attestation = crate::code_map::snapshot::attest_existing_persisted_snapshot(
            &recovery_root,
            &recovery_native_db,
            crate::code_map::RebuildOptions::default(),
            &receipt.source_fingerprint_sha256,
            receipt.native_index_generation,
            receipt.native_graph_generation,
        )?;
        let conn = crate::memory::store::open(&recovery_db)
            .context("GRAPH-06: open views.db for Graphify recovery")?;
        let recovery = crate::graphify_transaction::open_graphify_transaction_recovery(
            &conn,
            lease,
            &attestation,
            &corpus_dir,
            crate::wiki::GraphifyIngestScope::Corpus,
        )?;
        Ok((recovery, Some(attestation)))
    })
    .await
    .context("GRAPH-06: Graphify lease/recovery task panicked")??;
    let (recovery_open, recovery_attestation) = recovery_open;
    let publication_lease = match recovery_open {
        crate::graphify_transaction::GraphifyRecoveryOpen::NoPendingPublication(lease) => lease,
        crate::graphify_transaction::GraphifyRecoveryOpen::Pending(recovery) => {
            let apply_snapshot =
                recovery_attestation.context("GRAPH-06: missing native recovery attestation")?;
            let completion_snapshot = apply_snapshot.clone();
            let apply_db = crate::memory::store::default_path();
            let recovery_wal = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let conn = crate::memory::store::open(&apply_db)
                    .context("GRAPH-06: open views.db for recovered Graphify transaction")?;
                recovery.apply_sqlite_phase(&conn, &apply_snapshot, crate::time::now_unix_ns_i64())
            })
            .await
            .context("GRAPH-06: recovered Graphify SQLite task panicked")??;
            let transaction_id = recovery_wal.transaction_id().as_str().to_owned();
            let receipt = recovery_wal.receipt().clone();
            let recovery_mode = match recovery_wal.ingest_mode() {
                crate::graphify_transaction::GraphifyIngestMode::Indexed => "recovered_indexed",
                crate::graphify_transaction::GraphifyIngestMode::SkippedAndRevoked => {
                    "published_unindexed"
                }
            };
            emit_wal_frame(
                u64::try_from(receipt.artifacts.len())?,
                0,
                "recovered",
                None,
                &transaction_id,
                recovery_mode,
                &completion_snapshot,
                &receipt,
            )
            .await
            .context("GRAPH-06: recovered completion WAL failed")?;
            tokio::task::spawn_blocking(move || recovery_wal.finish_after_durable_wal())
                .await
                .context("GRAPH-06: recovered Graphify finish task panicked")?
                .context("GRAPH-06: finish recovered Graphify transaction")?;
            if table_output {
                println!("GRAPH-06: recovered pending Graphify transaction {transaction_id}");
            }
            return Ok(());
        }
    };

    // ── Step 4: run `python -I -m graphify update .` ─────────────────────────
    // cwd = corpus_path is CRITICAL: graphify writes graphify-out/ relative to
    // its working directory (pitfall #1).
    let update_limits = crate::graphify_runner::GraphifyRunLimits::new(
        "graph-update",
        GRAPH_UPDATE_TIMEOUT,
        GRAPH_UPDATE_STDOUT_CAP,
        GRAPH_UPDATE_STDERR_CAP,
    )?;
    let update_out = crate::graphify_runner::run_graphify_process(
        crate::graphify_runner::GraphifyRunRequest::with_runtime(runtime.clone(), update_limits)
            .args(["-I", "-m", "graphify", "update", "."])
            .current_dir(&corpus_path),
    )
    .await
    .context("GRAPH-06: bounded `python -I -m graphify update` failed")?;
    if table_output {
        println!(
            "GRAPH-06: graphify update OK (stdout_bytes={}, stderr_bytes={})",
            update_out.stdout.len(),
            update_out.stderr.len()
        );
    }

    // GRAPH-07: run `graphify label` when --label is set (operator opt-in).
    // Runs BEFORE vault-copy so the labeled GRAPH_REPORT.md is what gets
    // filed into Obsidian and ingested into idx_groundtruth.
    let label_outcome = if args.label {
        use crate::daemon::self_map_task::run_label_step_one_shot;
        run_label_step_one_shot(
            &corpus_path,
            runtime.clone(),
            &cfg,
            &crate::config::FreedomConfig::default_neoth_home(),
            &cfg.self_map_label_model,
        )
        .await
        .context("GRAPH-07: explicitly requested label step failed")?
    } else {
        crate::daemon::self_map_task::LabelOutcome::disabled()
    };
    if args.label && table_output {
        match label_outcome.communities_labeled {
            Some(count) => println!("GRAPH-07: label step complete — communities_labeled={count}"),
            None => println!("GRAPH-07: label step complete — provider returned no count"),
        }
    }

    // GOLD-R3-13: Graphify output is complementary evidence. Completion is
    // permitted only after the native symbol map and call graph have been
    // rebuilt from verified bytes and atomically generation-bound.
    let native_snapshot = tokio::task::spawn_blocking(move || {
        crate::code_map::snapshot::rebuild_snapshot_scoped(
            &native_root,
            &native_db,
            crate::code_map::RebuildOptions::default(),
            &[],
            &[],
        )
    })
    .await
    .context("GRAPH-06: native code-map rebuild task panicked")?
    .context("GRAPH-06: native code-map rebuild failed")?;
    anyhow::ensure!(
        native_snapshot.snapshot().source_fingerprint_sha256 == pre_graphify_fingerprint,
        "GRAPH-06: corpus changed while Graphify was running; refusing mixed Graphify/native completion"
    );
    if table_output {
        println!(
            "GRAPH-R3-13: native code-map generation OK (index={}, graph={})",
            native_snapshot.snapshot().index_generation,
            native_snapshot.snapshot().graph_generation
        );
    }

    // ── Step 5: validate, hash, and atomically publish one immutable vault generation ──
    let publish_vault = vault.clone();
    let publish_subdir = corpus_name.clone();
    let publish_snapshot = native_snapshot.clone();
    let published = tokio::task::spawn_blocking(move || {
        crate::graphify_publish::prepare_graphify_publication(
            crate::graphify_publish::GraphifyPublishRequest {
                vault_root: &publish_vault,
                friendly_subdir: Some(&publish_subdir),
                native_snapshot: &publish_snapshot,
                ingest_mode: if args.no_ingest {
                    crate::graphify_publish::GraphifyPublicationIngestMode::SkippedAndRevoked
                } else {
                    crate::graphify_publish::GraphifyPublicationIngestMode::Indexed
                },
                ingest_scope: crate::wiki::GraphifyIngestScope::Corpus,
                lease: publication_lease,
            },
        )?
        .publish()
    })
    .await
    .context("GRAPH-06: Graphify publication task panicked")?
    .context("GRAPH-06: validate and publish Graphify vault generation")?;
    let pages_written = u64::try_from(published.receipt.artifacts.len())
        .context("GRAPH-06: artifact count does not fit u64")?;
    let out_dir = published.generation_dir.clone();
    let corpus_dir = published.corpus_dir.clone();
    if table_output {
        println!(
            "GRAPH-06: atomic vault generation OK ({pages_written} file(s) → `{}`)",
            out_dir.display()
        );
    }

    // ── Step 6: SQLite replacement/revoke under the still-held lease ────────
    // The transaction coordinator owns the only accepted graph-generation
    // ingest path. `--no-ingest` actively revokes the old scope rather than
    // leaving stale recall pointers behind.
    let transaction_mode = if args.no_ingest {
        crate::graphify_transaction::GraphifyIngestMode::SkippedAndRevoked
    } else {
        crate::graphify_transaction::GraphifyIngestMode::Indexed
    };
    let sqlite_snapshot = native_snapshot.clone();
    let pending = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let conn = crate::memory::store::open(&crate::memory::store::default_path())
            .context("GRAPH-06: open views.db for Graphify transaction")?;
        crate::graphify_transaction::apply_graphify_sqlite_phase(
            published,
            &conn,
            &sqlite_snapshot,
            crate::wiki::GraphifyIngestScope::Corpus,
            transaction_mode,
            crate::time::now_unix_ns_i64(),
        )
    })
    .await
    .context("GRAPH-06: Graphify SQLite transaction task panicked")??;
    let transaction_id = pending.transaction_id().as_str().to_owned();
    let receipt = pending.receipt().clone();
    let gt_inserted = match pending.outcome() {
        crate::graphify_transaction::GraphifyTransactionOutcome::Indexed { stats, .. } => {
            u64::try_from(stats.inserted).context("GRAPH-06: inserted count does not fit u64")?
        }
        crate::graphify_transaction::GraphifyTransactionOutcome::SkippedAndRevoked { .. } => 0,
    };
    let completion_status = publication_status(args.no_ingest);
    if table_output {
        if args.no_ingest {
            println!("GRAPH-06: --no-ingest revoked the prior Graphify recall scope.");
        } else {
            println!("GRAPH-06: groundtruth ingest OK ({gt_inserted} row(s)).");
        }
    }

    // ── Step 7: emit 0xFB SELF_MAP_COMPLETE ─────────────────────────────────
    // Completion is a durable contract, not a best-effort log line. If another
    // process owns the WAL or the append cannot be acknowledged, return an
    // error and never print/serialize a false `complete` summary.
    emit_wal_frame(
        pages_written,
        gt_inserted,
        label_outcome.status.as_str(),
        label_outcome.communities_labeled,
        &transaction_id,
        completion_status,
        &native_snapshot,
        &receipt,
    )
    .await
    .context("GRAPH-06: durable completion WAL failed")?;
    let _transaction_outcome =
        tokio::task::spawn_blocking(move || pending.finish_after_durable_wal())
            .await
            .context("GRAPH-06: Graphify transaction finish task panicked")?
            .context("GRAPH-06: finish Graphify transaction after completion WAL")?;

    // ── Step 8: summary ──────────────────────────────────────────────────────
    match args.output {
        OutputFormat::Table => {
            println!();
            println!("GRAPH-06/07 {completion_status}:");
            println!("  corpus              {}", corpus_path.display());
            println!("  vault corpus        {}", corpus_dir.display());
            println!("  vault generation    {}", out_dir.display());
            println!("  files               {pages_written}");
            println!("  gt rows             {gt_inserted}");
            println!("  label status         {}", label_outcome.status.as_str());
            println!(
                "  communities labeled {}",
                label_outcome
                    .communities_labeled
                    .map_or_else(|| "unknown".to_owned(), |count| count.to_string())
            );
            println!(
                "  native generation   index={} graph={}",
                native_snapshot.snapshot().index_generation,
                native_snapshot.snapshot().graph_generation
            );
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            let summary = serde_json::json!({
                "status": completion_status,
                "corpus": corpus_path,
                "vault_dir": out_dir,
                "vault_corpus_dir": corpus_dir,
                "pages_written": pages_written,
                "gt_inserted": gt_inserted,
                 "label_status": label_outcome.status.as_str(),
                 "communities_labeled": label_outcome.communities_labeled,
                 "root_identity_sha256": native_snapshot.snapshot().root_identity_sha256,
                 "source_fingerprint_sha256": native_snapshot.snapshot().source_fingerprint_sha256,
                 "index_generation": native_snapshot.snapshot().index_generation,
                "graph_generation": native_snapshot.snapshot().graph_generation,
                "graphify_generation": receipt,
            });
            if matches!(args.output, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("{}", serde_json::to_string(&summary)?);
            }
        }
    }

    Ok(())
}

fn is_reserved_self_map_namespace(name: &str) -> bool {
    name.eq_ignore_ascii_case(crate::daemon::self_map_task::DEFAULT_SUBDIR)
}

fn publication_status(no_ingest: bool) -> &'static str {
    if no_ingest {
        "published_unindexed"
    } else {
        "complete"
    }
}

/// Emit the complete, non-mutating update plan for `neoth graph --dry-run`.
///
/// This helper has no access to the Graphify runtime, database paths, leases,
/// or WAL. Keeping that boundary explicit prevents a future formatting change
/// from accidentally reintroducing a side effect into the dry-run path.
fn emit_dry_run_plan(
    args: &GraphArgs,
    corpus_path: &std::path::Path,
    vault: &std::path::Path,
    corpus_name: &str,
) -> anyhow::Result<()> {
    let intended_vault_corpus_dir = vault.join(corpus_name);
    let ingest_mode = if args.no_ingest {
        "skipped_and_revoked"
    } else {
        "indexed"
    };
    let label_status = if args.label { "planned" } else { "disabled" };

    match args.output {
        OutputFormat::Table => {
            println!("GRAPH-06: dry-run plan (no mutations performed)");
            println!("  corpus                 = {}", corpus_path.display());
            println!(
                "  intended vault corpus  = {}",
                intended_vault_corpus_dir.display()
            );
            println!("  graphify update         = planned (not run)");
            println!("  label                   = {label_status}");
            println!("  ingest                  = {ingest_mode}");
            println!("  mutations_performed     = false");
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            let summary = serde_json::json!({
                "status": "planned",
                "dry_run": true,
                "mutations_performed": false,
                "corpus": corpus_path,
                "vault": vault,
                "intended_vault_corpus_dir": intended_vault_corpus_dir,
                "graphify_update": "planned_not_run",
                "label_status": label_status,
                "ingest_mode": ingest_mode,
            });
            if matches!(args.output, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("{}", serde_json::to_string(&summary)?);
            }
        }
    }
    Ok(())
}

/// Emit a `0xFB SELF_MAP_COMPLETE` WAL frame via a one-shot writer.
///
async fn emit_wal_frame<S: crate::code_map::snapshot::CompanionSnapshotAttestation>(
    pages_written: u64,
    gt_inserted: u64,
    label_status: &str,
    communities_labeled: Option<u64>,
    transaction_id: &str,
    publication_status: &str,
    native_snapshot: &S,
    graphify_receipt: &crate::graphify_publish::GraphifyGenerationReceipt,
) -> anyhow::Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let (writer, completion) = tokio::task::spawn_blocking(move || {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir)
            .with_context(|| format!("GRAPH-06: create WAL directory {}", wal_dir.display()))?;
        let segment =
            crate::wal::writer::unique_standalone_segment_path(&wal_dir, "graph-self-map");
        crate::wal::writer::spawn_for_home_with_completion(segment, home)
            .context("GRAPH-06: spawn completion WAL writer")
    })
    .await
    .context("GRAPH-06: completion WAL setup task panicked")??;
    let now_ns = crate::time::now_unix_ns_i64();
    let payload = serde_json::to_vec(&serde_json::json!({
        "pages_written":       pages_written,
        "gt_inserted":         gt_inserted,
        "label_status":        label_status,
         "communities_labeled": communities_labeled,
         "graphify_transaction_id": transaction_id,
         "publication_status": publication_status,
         "root_identity_sha256": native_snapshot.root_identity_sha256(),
         "source_fingerprint_sha256": native_snapshot.source_fingerprint_sha256(),
        "index_generation":     native_snapshot.index_generation(),
        "graph_generation":     native_snapshot.graph_generation(),
        "graphify_generation": {
            "schema_version": graphify_receipt.schema_version,
            "corpus_id": graphify_receipt.corpus_id,
            "corpus_namespace": graphify_receipt.corpus_namespace,
            "generation_id": graphify_receipt.generation_id,
            "source_fingerprint_sha256": graphify_receipt.source_fingerprint_sha256,
            "native_index_generation": graphify_receipt.native_index_generation,
            "native_graph_generation": graphify_receipt.native_graph_generation,
            "artifacts": graphify_receipt.artifacts,
        },
        "ts_unix":             now_ns / 1_000_000_000,
    }))
    .context("GRAPH-06: serialize completion WAL payload")?;
    let header = HeaderBuilder::new(EVENT_TYPE_SELF_MAP_COMPLETE, &payload).build();
    let append_result = writer
        .append(header, payload)
        .await
        .map(|_| ())
        .context("GRAPH-06: append and durably acknowledge completion WAL frame");
    drop(writer);
    let completion_result = completion
        .wait()
        .await
        .context("GRAPH-06: finalize completion WAL writer");
    match (append_result, completion_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(append_error), Err(completion_error)) => Err(anyhow!(
            "GRAPH-06: WAL append and writer finalization both failed; \
             append={append_error:#}; finalization={completion_error:#}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_map_namespace_is_reserved_case_insensitively() {
        for alias in ["NEOTH-Self", "neoth-self", "NeOtH-SeLf"] {
            assert!(is_reserved_self_map_namespace(alias), "alias={alias}");
        }
        assert!(!is_reserved_self_map_namespace("NEOTH-Self-Other"));
    }

    #[test]
    fn table_output_strips_terminal_control_sequences() {
        let output = sanitize_graphify_table_output(
            b"safe\x1b]52;c;Y2xpcGJvYXJk\x07\x1b[2Jstill-safe\rhidden",
        );
        assert!(!output.contains('\x1b'));
        assert!(!output.contains("52;c;"));
        assert!(!output.contains('\r'));
        assert!(output.contains("safe"));
        assert!(output.contains("still-safe"));
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

    /// `--dry-run` must return before discovery/probing Graphify and before
    /// every stateful graph pipeline leaf. This is deliberately an end-to-end
    /// filesystem test: no Graphify interpreter is installed or faked, yet the
    /// plan succeeds and the pre-existing corpus output remains byte-for-byte
    /// unchanged while neither vault publication nor local DB/WAL-shaped
    /// output is created below the test roots.
    #[tokio::test]
    async fn graph_dry_run_is_plan_only_and_leaves_all_test_roots_unchanged() {
        let corpus = crate::test_env::canonical_tempdir().unwrap();
        let vault = crate::test_env::canonical_tempdir().unwrap();
        let graphify_out = corpus.path().join("graphify-out");
        std::fs::create_dir_all(&graphify_out).unwrap();
        let sentinel = graphify_out.join("sentinel.txt");
        let sentinel_bytes = b"pre-existing graphify output must survive dry-run\n";
        std::fs::write(&sentinel, sentinel_bytes).unwrap();

        let mut cfg = crate::config::FreedomConfig::default();
        cfg.obsidian_vault = Some(vault.path().display().to_string());
        let intended_subdir = "planned-corpus";
        run_graph_update(
            GraphArgs {
                path: corpus.path().to_path_buf(),
                subdir: Some(intended_subdir.to_owned()),
                dry_run: true,
                no_ingest: true,
                label: true,
                cmd: None,
                output: OutputFormat::Json,
            },
            cfg,
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&sentinel).unwrap(), sentinel_bytes);
        assert!(
            !vault.path().join(intended_subdir).exists(),
            "dry-run must not create a vault corpus/generation/CURRENT/journal"
        );
        for root in [corpus.path(), vault.path()] {
            for forbidden in ["code_map.db", "views.db", "wal"] {
                assert!(
                    !root.join(forbidden).exists(),
                    "dry-run must not create `{forbidden}` under {}",
                    root.display()
                );
            }
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

    #[test]
    fn no_ingest_uses_a_non_success_unindexed_publication_status() {
        assert_eq!(publication_status(true), "published_unindexed");
        assert_ne!(publication_status(true), "complete");
        assert_eq!(publication_status(false), "complete");
    }

    #[test]
    fn graph_query_recall_uses_typed_generation_bound_wire_receipt() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("lib.rs"), "pub fn auth_middleware() {}\n").unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        let rebuilt = crate::code_map::rebuild_snapshot(
            &root,
            &db,
            crate::code_map::RebuildOptions::default(),
        )
        .unwrap();

        let envelope =
            graph_query_recall_envelope_at(&db, repo.path(), "where is auth_middleware defined?")
                .unwrap();
        envelope.validate().unwrap();
        let receipt = envelope.receipt.expect("mapped query needs a receipt");
        assert_eq!(receipt.index_generation, rebuilt.index_generation);
        assert_eq!(receipt.graph_generation, rebuilt.graph_generation);
        assert!(
            receipt
                .hits
                .iter()
                .any(|hit| hit.path == "lib.rs" && hit.root == root.display())
        );
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

    /// Verifies the atomic vault-publication path without requiring a real graphify
    /// install or freedom.yaml. Pre-seeds a `graphify-out/` directory (as the
    /// subprocess would have) and calls the core copy+scope logic directly.
    ///
    /// Mirrors the research-plan integration-test spec exactly.
    #[test]
    fn run_graph_writes_report_to_vault_subdir() {
        let corpus_dir = crate::test_env::canonical_tempdir().unwrap();
        let vault_dir = crate::test_env::canonical_tempdir().unwrap();
        let database_dir = crate::test_env::canonical_tempdir().unwrap();
        std::fs::write(corpus_dir.path().join("lib.rs"), "pub fn mapped() {}\n").unwrap();

        // Pre-seed the complete nonblank Graphify evidence set as if graphify
        // had run. Publication intentionally rejects a partial report/tree
        // pair, because one immutable generation must represent one coherent
        // Graphify run.
        let graphify_out = corpus_dir.path().join("graphify-out");
        std::fs::create_dir_all(&graphify_out).unwrap();
        let report_contents = "# Test Corpus\n\nnodes: 42\nedges: 100\n";
        let tree_contents = "<!doctype html><title>Test Corpus tree</title><main>lib.rs</main>\n";
        std::fs::write(graphify_out.join("GRAPH_REPORT.md"), report_contents).unwrap();
        std::fs::write(graphify_out.join("GRAPH_TREE.html"), tree_contents).unwrap();

        // Derive the corpus name the same way run_graph does.
        let corpus_name = corpus_dir
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let root = crate::code_map::CanonicalRepoRoot::discover(corpus_dir.path()).unwrap();
        let snapshot = crate::code_map::snapshot::rebuild_snapshot_scoped(
            &root,
            &database_dir.path().join("code_map.db"),
            crate::code_map::RebuildOptions::default(),
            &[],
            &[],
        )
        .unwrap();
        let published = crate::graphify_publish::prepare_graphify_publication(
            crate::graphify_publish::GraphifyPublishRequest {
                vault_root: vault_dir.path(),
                friendly_subdir: Some(&corpus_name),
                native_snapshot: &snapshot,
                ingest_mode:
                    crate::graphify_publish::GraphifyPublicationIngestMode::SkippedAndRevoked,
                ingest_scope: crate::wiki::GraphifyIngestScope::Corpus,
                lease: crate::graphify_publish::acquire_graphify_publication_lease(
                    vault_dir.path(),
                    &snapshot.snapshot().root,
                )
                .unwrap(),
            },
        )
        .unwrap()
        .publish()
        .unwrap();
        let report_dest = published.generation_dir.join("GRAPH_REPORT.md");
        let tree_dest = published.generation_dir.join("GRAPH_TREE.html");

        assert_eq!(
            std::fs::read_to_string(&report_dest).unwrap(),
            report_contents,
            "run_graph must publish GRAPH_REPORT.md in the current immutable generation"
        );
        assert_eq!(
            std::fs::read_to_string(&tree_dest).unwrap(),
            tree_contents,
            "run_graph must publish GRAPH_TREE.html in the current immutable generation"
        );
        assert_eq!(
            published
                .receipt
                .artifacts
                .iter()
                .map(|artifact| (artifact.name.as_str(), artifact.bytes))
                .collect::<Vec<_>>(),
            vec![
                ("GRAPH_REPORT.md", report_contents.len() as u64),
                ("GRAPH_TREE.html", tree_contents.len() as u64),
            ],
            "the receipt must bind exactly the complete Graphify evidence set"
        );
        let current = crate::graphify_publish::read_current_graphify_pointer(&published.corpus_dir)
            .unwrap()
            .unwrap();
        assert_eq!(current.generation_id, published.receipt.generation_id);
        let (current_generation, current_receipt) =
            crate::graphify_publish::load_current_graphify_generation_receipt(
                &published.corpus_dir,
            )
            .unwrap()
            .unwrap();
        assert_eq!(current_generation, published.generation_dir);
        assert_eq!(current_receipt, published.receipt);
        assert_eq!(
            published.phase(),
            crate::graphify_publish::GraphifyTransactionPhase::CurrentPublished,
            "CURRENT must retain a recoverable transaction intent until ingest is resolved"
        );
        let journal_path = published
            .corpus_dir
            .join(crate::graphify_publish::GRAPHIFY_TRANSACTION_NAME);
        assert!(
            journal_path.is_file(),
            "the current publication must retain its durable transaction journal"
        );
        let mut published = published;
        published.mark_ingest_skipped().unwrap();
        assert_eq!(
            published.phase(),
            crate::graphify_publish::GraphifyTransactionPhase::IngestSkipped
        );
        published.finish().unwrap();
        assert!(
            !journal_path.exists(),
            "the journal must be removed only after the terminal transaction phase"
        );
    }
}
