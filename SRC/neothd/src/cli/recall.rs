//! `neoth recall <query>` — search the SQLite views for matching text.
//!
//! Runs the indexer once before querying so freshly-written WAL frames are
//! included. Output format follows the global `--output` flag.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::params;
use tracing::info;

use crate::config::FreedomConfig;
use crate::memory::{embeddings, indexer, store, tiers, views::EpisodeHit};
use crate::providers::clip_engine;

#[derive(Args, Debug, Clone)]
pub struct RecallArgs {
    /// Search string. Matched case-insensitively against episode text via
    /// LIKE. Optional when `--similar-to` is used instead.
    #[arg(default_value = "")]
    pub query: String,

    /// Max hits to return.
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Override the views.db path.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Override the WAL segment path the pre-query indexer scans.
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Skip the pre-query indexer pass — useful if `neoth serve` is already
    /// running and tailing the WAL.
    #[arg(long)]
    pub no_index_pass: bool,

    /// R-02 Phase 2: include dream-pipeline matches at the top of
    /// the result set. Scans `~/.neoth/dreams/*.jsonl` over the
    /// last `--dreams-lookback-days` days and prepends up to
    /// `--dreams-max-hits` dream rows matching the query.
    #[arg(long)]
    pub include_dreams: bool,

    /// How many days back to scan for matching dreams. Honoured
    /// only when `--include-dreams` is set.
    #[arg(long, default_value = "7")]
    pub dreams_lookback_days: u32,

    /// Max dream rows to prepend. Honoured only when
    /// `--include-dreams` is set.
    #[arg(long, default_value = "5")]
    pub dreams_max_hits: usize,

    /// Cross-modal similarity query — compute the CLIP embedding of the
    /// image at this path, then return the top-N cached embeddings by
    /// cosine similarity. Bypasses the text recall pipeline entirely.
    /// Requires `neoth models pull clip` to have already cached the
    /// checkpoint.
    #[arg(long, value_name = "PATH")]
    pub similar_to: Option<PathBuf>,

    /// Cross-modal text-to-image query — encode the prompt through the
    /// CLIP text tower, then look up the top-N similar embeddings.
    /// Mutually exclusive with `--similar-to`.
    #[arg(long, value_name = "TEXT")]
    pub similar_to_text: Option<String>,

    /// Optional kind filter for `--similar-to{,-text}`. Defaults to
    /// `image`. Use `any` to search across every stored kind.
    #[arg(long, value_name = "KIND", default_value = "image")]
    pub similar_kind: String,

    /// QM-18 citation-check: run the offline citation-extraction +
    /// contamination heuristics against the supplied text and report
    /// findings. Bypasses recall search entirely; no DB / no WAL /
    /// no network. Use `--citation-check -` to read from stdin.
    #[arg(long, value_name = "TEXT", conflicts_with_all = ["query", "similar_to", "similar_to_text"])]
    pub citation_check: Option<String>,

    /// GOLD-ADAPT-ODY-25 — search past session cards (title / ranked topics /
    /// one-line summary / opening+closing utterance) for this query and print
    /// the matching sessions ranked by relevance. NEOTH compresses transcripts
    /// into cards, so this finds *which session* discussed something rather than
    /// raw transcript lines. Bypasses episode recall entirely.
    #[arg(long, value_name = "TEXT", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check"])]
    pub sessions: Option<String>,

    /// GOLD-ADAPT-ODY-26 — render past sessions grouped into topic folders
    /// (assigned by the session-sort cron; ungrouped sessions listed below).
    /// Read-only view over the hindsight cards.
    #[arg(long, conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions"])]
    pub session_folders: bool,

    /// GOLD-ADAPT-MEM-09 — classify how much recall a query warrants (`skip` /
    /// `single` / `multi`) and print the verdict instead of searching. Lets an
    /// operator see why a trivial status/identity query would skip recall.
    #[arg(long, value_name = "TEXT", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions"])]
    pub classify: Option<String>,

    /// GOLD-ADAPT-MEM-08 — operator negative feedback: weaken the importance of
    /// the memory with this `event_id` (asymmetric Hebbian −0.10, floored at 0)
    /// across whichever tier holds it. Bypasses search.
    #[arg(long, value_name = "EVENT_ID", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify"])]
    pub downvote: Option<i64>,

    /// GOLD-ADAPT-JV-MEM-08 — explicit operator positive feedback: reinforce
    /// this memory and mark every existing association touching it successful.
    /// Bypasses search. Unlike ordinary recall, merely showing a result is not
    /// treated as proof that it was useful.
    #[arg(long, value_name = "EVENT_ID", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc", "bootstrap_assoc", "scorecard", "hubs", "communities", "transcript"])]
    pub upvote: Option<i64>,

    /// GOLD-ADAPT-MEM-06 — knowledge-graph query: print the entities reachable
    /// from this entity name within `--graph-depth` hops (BFS over the
    /// extracted entity/relation graph). Bypasses search.
    #[arg(long, value_name = "ENTITY", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote"])]
    pub graph: Option<String>,

    /// Max BFS hops for `--graph`. Default 2.
    #[arg(long, default_value = "2")]
    pub graph_depth: u32,

    /// GOLD-ADAPT-MEM-06 — extract entities + relations from this text via the
    /// configured provider and persist them into the knowledge graph (the
    /// ingest path). Bypasses search.
    #[arg(long, value_name = "TEXT", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph"])]
    pub extract: Option<String>,

    /// GOLD-ADAPT-MEM-07 — co-access association query: list the memories most
    /// frequently recalled ALONGSIDE this `event_id` (1-hop neighbourhood,
    /// ordered by link weight DESC). Bypasses search.
    #[arg(long, value_name = "EVENT_ID", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract"])]
    pub assoc: Option<i64>,

    /// GOLD-ADAPT-MEM-07b — one-shot: bootstrap co-access association edges from
    /// episode history (memories in the same time-window get a weak initial
    /// link), so a fresh install has associations before live recall accrues.
    /// Idempotent — safe to re-run (never touches existing edges).
    #[arg(long, conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc"])]
    pub bootstrap_assoc: bool,

    /// GOLD-ADAPT-MEM-15 — print the recall-quality scorecard over the most
    /// recent N recall outcomes (hit-rate / result-count / reinforcement-rate /
    /// tier mix / latency percentiles) instead of searching. `--scorecard 0`
    /// uses the default window (500).
    #[arg(long, value_name = "N", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc", "bootstrap_assoc"])]
    pub scorecard: Option<usize>,

    /// GOLD-ADAPT-GRAPH-01 — print the top N most-connected nodes in the
    /// association graph (highest link degree), one row per node: `event_id`
    /// and the number of distinct links touching it. Useful for finding
    /// "hub" memories that were co-recalled with many other memories.
    /// Bypasses search. Defaults to `--limit` for the result count.
    #[arg(long, conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc", "bootstrap_assoc", "scorecard", "communities"])]
    pub hubs: bool,

    /// GOLD-ADAPT-GRAPH-03 — detect communities in the association graph using
    /// one level of Louvain modularity optimisation and print each community
    /// (index, size, member node ids). Isolated nodes (no links) are omitted.
    /// Bypasses search.
    #[arg(long, conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc", "bootstrap_assoc", "scorecard", "hubs"])]
    pub communities: bool,

    /// GOLD-ADAPT-ODY-26 — FTS search over transcript turns (operator turns are
    /// source-exact; agent turns are secret/control-sanitized) with N
    /// before/after context rows. Persisted by `neoth chat` and `neoth serve`. Returns
    /// matching turns ranked by BM25, each with up to `--context-rows` turns of
    /// conversation context from the same session. Bypasses episode recall entirely.
    #[arg(long, value_name = "TEXT", conflicts_with_all = ["query", "similar_to", "similar_to_text", "citation_check", "sessions", "classify", "downvote", "graph", "extract", "assoc", "bootstrap_assoc", "scorecard", "hubs", "communities"])]
    pub transcript: Option<String>,

    /// GOLD-ADAPT-ODY-26 — number of turns to show before and after each
    /// transcript match (default 2). Only honoured when `--transcript` is set.
    #[arg(long, default_value = "2")]
    pub context_rows: usize,

    /// Populated from the global `--output` flag.
    #[arg(skip)]
    pub output: crate::cli::OutputFormat,
}

/// Result of the blocking recall task: the ranked rows plus the Hebbian
/// reinforcement records (event_id + frame) to audit on the async side.
type RecallTaskOutput = (Vec<EpisodeHit>, Vec<(i64, ReinforceFrame)>);

async fn apply_operator_memory_feedback(
    db_override: Option<&Path>,
    event_id: i64,
    success: bool,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    let db_path = db_override
        .map(Path::to_path_buf)
        .unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).context("open views.db")?;
    let now_ns = crate::time::now_unix_ns();
    let outcome = if success {
        tiers::hebbian_reinforce_across_tiers(&conn, event_id, now_ns)?
    } else {
        tiers::hebbian_weaken_across_tiers(&conn, event_id, tiers::HEBBIAN_HARMFUL_PENALTY, now_ns)?
    };
    let edge_feedback_count = if outcome.is_some() {
        crate::memory::assoc_graph::record_event_feedback(&conn, event_id, success)
            .context("record association-edge feedback")?
    } else {
        0
    };

    if let Some(outcome) = outcome {
        emit_reinforce_audit_frames(&[(
            event_id,
            ReinforceFrame {
                tier: outcome.tier.as_str().to_string(),
                old: outcome.old,
                new: outcome.new,
            },
        )])
        .await;
        match output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "event_id": event_id,
                    "feedback": if success { "useful" } else { "harmful" },
                    "found": true,
                    "tier": outcome.tier.as_str(),
                    "old": outcome.old,
                    "new": outcome.new,
                    "association_edges_updated": edge_feedback_count,
                })
            ),
            crate::cli::OutputFormat::Table => println!(
                "{} event {event_id}: importance {:.3} → {:.3} ({}, {} association edge(s) updated)",
                if success { "upvoted" } else { "downvoted" },
                outcome.old,
                outcome.new,
                outcome.tier.as_str(),
                edge_feedback_count,
            ),
        }
    } else {
        match output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "event_id": event_id,
                    "feedback": if success { "useful" } else { "harmful" },
                    "found": false,
                    "association_edges_updated": 0,
                })
            ),
            crate::cli::OutputFormat::Table => println!("no memory found for event {event_id}"),
        }
    }
    Ok(())
}

pub async fn run_recall(args: RecallArgs) -> Result<()> {
    // QM-18 citation-check short-circuit. No DB, no WAL, no network —
    // pure offline audit against the supplied text. `--citation-check -`
    // reads stdin so operators can pipe their drafts in.
    if let Some(text_arg) = args.citation_check.clone() {
        return run_citation_check(&text_arg, args.output).await;
    }

    // GOLD-ADAPT-ODY-25 session-card search short-circuit. Reads the on-disk
    // HindsightCards (no DB, no WAL, no network) and ranks them by query.
    if let Some(q) = args.sessions.clone() {
        return run_session_search(&q, args.limit, args.output);
    }

    // GOLD-ADAPT-ODY-26 topic-folder view short-circuit — the read side of
    // the session-sort cron (folder tags live on the cards' top_topics).
    if args.session_folders {
        let home = FreedomConfig::default_neoth_home();
        let cards = crate::memory::hindsight::list_cards(&home);
        print!("{}", crate::daemon::session_sort_cron::folders_view(&cards));
        return Ok(());
    }

    // GOLD-ADAPT-ODY-26 transcript FTS short-circuit. Opens views.db and
    // searches raw_turns_fts for the query, returning BM25-ranked results with
    // before/after context rows. No WAL scan, no episode recall.
    if let Some(q) = args.transcript.clone() {
        return run_transcript_search(&q, args.context_rows, args.limit, args.output);
    }

    // GOLD-ADAPT-MEM-09 recall-gate classification short-circuit (pure; no DB).
    if let Some(q) = args.classify.clone() {
        let tier = crate::memory::recall_gate::classify_recall_need(&q);
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({ "query": q, "tier": tier.as_str() })
                );
            }
            crate::cli::OutputFormat::Table => println!("recall tier: {}", tier.as_str()),
        }
        return Ok(());
    }

    // GOLD-ADAPT-MEM-06 knowledge-graph query short-circuit.
    if let Some(entity) = args.graph.clone() {
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        // MEM-14: the queried entity's own credibility (source_count) + merged
        // attributes head the result.
        let head = crate::memory::entities::get_entity(&conn, &entity)?;
        let neighbors = crate::memory::entities::get_neighbors(&conn, &entity, args.graph_depth)?;
        let attributes = head
            .as_ref()
            .map(|entity| {
                serde_json::from_str::<serde_json::Value>(&entity.attributes).with_context(|| {
                    format!("parse persisted attributes for entity `{}`", entity.name)
                })
            })
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({}));
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                let rows: Vec<_> = neighbors
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "name": n.name,
                            "depth": n.depth,
                            "via": n.via_relation,
                            "sources": n.source_count,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "entity": entity,
                        "source_count": head.as_ref().map(|e| e.source_count),
                        "attributes": attributes,
                        "neighbors": rows,
                    })
                );
            }
            crate::cli::OutputFormat::Table => {
                if let Some(e) = &head {
                    let attrs: std::collections::BTreeMap<String, String> =
                        serde_json::from_value(attributes.clone()).with_context(|| {
                            format!("decode persisted attributes for entity `{}`", e.name)
                        })?;
                    let attr_str = if attrs.is_empty() {
                        String::new()
                    } else {
                        let pairs: Vec<String> =
                            attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        format!(" [{}]", pairs.join(", "))
                    };
                    println!(
                        "entity '{}' ({} sources){}",
                        e.name, e.source_count, attr_str
                    );
                }
                if neighbors.is_empty() {
                    println!("no graph neighbours for '{entity}' (unknown entity or no relations)");
                } else {
                    println!(
                        "graph neighbours of '{entity}' (≤{} hops):",
                        args.graph_depth
                    );
                    for n in &neighbors {
                        let cred = if n.source_count > 1 {
                            format!(", {} sources", n.source_count)
                        } else {
                            String::new()
                        };
                        println!(
                            "  [{}] {} (via {}{})",
                            n.depth, n.name, n.via_relation, cred
                        );
                    }
                }
            }
        }
        return Ok(());
    }

    // GOLD-ADAPT-MEM-06 entity-extraction (ingest) short-circuit — run the
    // configured provider over the text + persist entities/relations.
    if let Some(text) = args.extract.clone() {
        let config = crate::config::FreedomConfig::load_from_default_path()
            .context("load freedom.yaml for entity extraction")?;
        let neoth_home = crate::config::FreedomConfig::default_neoth_home();
        // Validate the local sink before opening the mandatory provider-call
        // audit lifecycle. No fallible setup may return after the one-shot
        // writer is owned but before `finish`.
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        let provider = crate::providers::from_config_at(&config, &neoth_home)
            .await
            .context("build provider for entity extraction")?;
        let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
        let provider_audit =
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                config.autonomy_policy(),
                config.tokens.max_per_request,
            )
            .await?;
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            provider,
            provider_audit.authorizer(),
            default_model,
            "recall.entity_extract",
        );
        let now_unix = crate::time::now_unix_i64();
        let extracted =
            crate::memory::entities::extract_and_persist(&conn, &text, &provider, now_unix).await;
        provider_audit
            .finish(provider)
            .await
            .context("finalize entity-extraction provider-call audit WAL")?;
        let (ents, rels) = extracted?;
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({ "entities": ents, "relations": rels })
                );
            }
            crate::cli::OutputFormat::Table => {
                println!("knowledge graph: +{ents} entit(y/ies), +{rels} relation(s)")
            }
        }
        return Ok(());
    }

    // GOLD-ADAPT-JV-MEM-08 explicit operator feedback. Ordinary recall still
    // reinforces co-access/importance, but it is not falsely counted as an
    // outcome success. Only these explicit controls update the edge feedback
    // counters.
    if let Some(event_id) = args.upvote {
        return apply_operator_memory_feedback(args.db.as_deref(), event_id, true, args.output)
            .await;
    }
    if let Some(event_id) = args.downvote {
        return apply_operator_memory_feedback(args.db.as_deref(), event_id, false, args.output)
            .await;
    }

    // GOLD-ADAPT-MEM-07 — co-access association query short-circuit.
    if let Some(event_id) = args.assoc {
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        let hits = crate::memory::assoc_graph::associated(&conn, event_id, args.limit)
            .context("assoc_graph query")?;
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                let rows: Vec<_> = hits
                    .iter()
                    .map(|(eid, w)| serde_json::json!({ "event_id": eid, "weight": w }))
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({ "source_event_id": event_id, "associated": rows })
                );
            }
            crate::cli::OutputFormat::Table => {
                if hits.is_empty() {
                    println!("no association links for event {event_id}");
                } else {
                    println!("memories co-recalled with event {event_id} (by link weight):");
                    for (eid, w) in &hits {
                        println!("  event {eid} (weight {w:.2})");
                    }
                }
            }
        }
        return Ok(());
    }

    // GOLD-ADAPT-MEM-07b — co-occurrence bootstrap short-circuit (one-shot).
    if args.bootstrap_assoc {
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db for bootstrap")?;
        let now_unix = crate::time::now_unix_i64();
        let created = crate::memory::assoc_graph::bootstrap_co_occurrence(
            &conn,
            crate::memory::assoc_graph::DEFAULT_BOOTSTRAP_WINDOW_NS,
            now_unix,
        )
        .context("bootstrap_co_occurrence")?;
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                println!("{}", serde_json::json!({ "edges_created": created }));
            }
            crate::cli::OutputFormat::Table => {
                println!("bootstrap-assoc: {created} association edge(s) created");
            }
        }
        return Ok(());
    }

    // GOLD-ADAPT-MEM-15 recall-quality scorecard short-circuit. Reads the recent
    // recall-outcome + latency windows and renders the scorecard instead of
    // searching. No WAL, no network.
    if let Some(window) = args.scorecard {
        const DEFAULT_SCORECARD_WINDOW: usize = 500;
        let window = if window == 0 {
            DEFAULT_SCORECARD_WINDOW
        } else {
            window.min(5000)
        };
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        let card = store::recall_scorecard(&conn, window).context("compute recall scorecard")?;
        render_scorecard(&card, args.output);
        return Ok(());
    }

    // GOLD-ADAPT-GRAPH-01 — hub-ranking short-circuit: most-connected nodes
    // in the association graph by link degree.
    if args.hubs {
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        let hubs = crate::memory::assoc_graph::memory_hubs(&conn, args.limit)
            .context("memory_hubs query")?;
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                let rows: Vec<_> = hubs
                    .iter()
                    .map(|(id, deg)| serde_json::json!({ "event_id": id, "degree": deg }))
                    .collect();
                println!("{}", serde_json::json!({ "hubs": rows }));
            }
            crate::cli::OutputFormat::Table => {
                if hubs.is_empty() {
                    println!(
                        "no association links found (run `neoth recall --bootstrap-assoc` to seed)"
                    );
                } else {
                    println!("top {} memory hub(s) by association degree:", hubs.len());
                    for (id, deg) in &hubs {
                        println!("  event {id:>8}  degree {deg}");
                    }
                }
            }
        }
        return Ok(());
    }

    // GOLD-ADAPT-GRAPH-03 — Louvain community detection short-circuit.
    if args.communities {
        let db_path = args.db.clone().unwrap_or_else(store::default_path);
        let conn = store::open(&db_path).context("open views.db")?;
        let communities = crate::memory::assoc_graph::detect_communities(&conn)
            .context("detect_communities query")?;
        match args.output {
            crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
                let rows: Vec<_> = communities
                    .iter()
                    .enumerate()
                    .map(|(i, members)| {
                        serde_json::json!({
                            "community": i,
                            "size": members.len(),
                            "members": members,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!({ "communities": rows }));
            }
            crate::cli::OutputFormat::Table => {
                if communities.is_empty() {
                    println!(
                        "no communities found (run `neoth recall --bootstrap-assoc` to seed \
                         association links first)"
                    );
                } else {
                    println!("{} community/communities detected:", communities.len());
                    for (i, members) in communities.iter().enumerate() {
                        let ids: Vec<String> = members.iter().map(|id| id.to_string()).collect();
                        println!(
                            "  community {i:>3}  size {:>4}  members: {}",
                            members.len(),
                            ids.join(", ")
                        );
                    }
                }
            }
        }
        return Ok(());
    }

    let db_path = args.db.clone().unwrap_or_else(store::default_path);

    // Cross-modal similarity paths are their own short-circuits: text
    // recall ignores image embeddings + vice versa. We branch early so
    // the text-indexer pass + Hebbian reinforcement only run for
    // actual text queries.
    if args.similar_to.is_some() && args.similar_to_text.is_some() {
        anyhow::bail!("recall: `--similar-to` and `--similar-to-text` are mutually exclusive");
    }
    if let Some(image_path) = args.similar_to.as_ref() {
        let conn = store::open(&db_path).context("open views.db")?;
        return run_similar_to_image(&conn, image_path.clone(), &args).await;
    }
    if let Some(prompt) = args.similar_to_text.as_ref() {
        let conn = store::open(&db_path).context("open views.db")?;
        return run_similar_to_text(&conn, prompt.clone(), &args).await;
    }

    if args.query.trim().is_empty() {
        anyhow::bail!(
            "recall: query is empty. Pass a search string, or use \
             `--similar-to <image>` / `--similar-to-text \"…\"` for cross-modal search."
        );
    }

    let mut conn = store::open(&db_path).context("open views.db")?;

    if !args.no_index_pass {
        let wal_dir = FreedomConfig::default_wal_dir();
        let segment_path = args
            .wal_segment
            .clone()
            .unwrap_or_else(|| wal_dir.join("000001.wal"));
        // Rotation-aware: walks every `.wal` file in the WAL dir, not just
        // the seed. Daemons that rotated 000001 → 000002 → 000003 still
        // surface the freshest frames in recall.
        let indexed = indexer::replay_all_segments(&mut conn, &segment_path)
            .await
            .context("indexer pre-query pass")?;
        info!(frames_indexed = indexed, "recall: indexer caught up");
    }

    let now_ns: u64 = crate::time::now_unix_ns();

    // K-Perf-3 full (2026-05-22): wrap the 5-tier SQLite query block in
    // `spawn_blocking` so the async runtime worker isn't pinned on
    // rusqlite for the full multi-tier read pass. Each query is bounded
    // by `LIMIT` (~5ms typical, longer on cold caches / large tables);
    // the cumulative CPU+I/O time off the async worker was the Phase-3
    // performance regression the agent flagged.
    //
    // The Connection moves INTO the blocking task and stays there: both
    // the multi-tier read AND the Hebbian reinforcement writes run on the
    // blocking thread (GOLD-SEC-06), and only the computed rows +
    // reinforcement records cross back out. `move` semantics keep the
    // Connection's !Send constraint satisfied — it never crosses an async
    // await point while in scope.
    let query = args.query.clone();
    let limit = args.limit;
    // GOLD-ADAPT-MEM-03 budget-adaptive lane selection. Classified on the async
    // side (pure, no I/O) and moved into the blocking task. A genuinely-no-recall
    // query (status/identity/greeting) sheds the warm+cold scans; ordinary and
    // historical queries cover all available text tiers. GOLD-ADAPT-MEM-15: the
    // tier label is recorded with each recall outcome for the quality scorecard.
    let recall_tier = crate::memory::recall_gate::classify_recall_need(&query);
    let budget = crate::memory::recall_lanes::budget_for(recall_tier);
    let tier_str = recall_tier.as_str();
    let (rows, reinforcements) =
        tokio::task::spawn_blocking(move || -> Result<RecallTaskOutput> {
            // RECALL-METER-01: time the full multi-tier recall query.
            let recall_t0 = std::time::Instant::now();
            // GOLD-ADAPT-MEM-03 — Semantic lane (hot tier): FTS5/bm25 keyword
            // match, LIKE fallback. Hits stay in their native bm25-relevance
            // order so the lane's rank carries the keyword-match signal into the
            // RRF fusion below (previously this ordering was fetched then thrown
            // away when everything was re-sorted by composite_score alone).
            let hot = match recall_fts(&conn, &query, limit) {
                Ok(hits) if !hits.is_empty() => hits,
                Ok(_) => recall_like(&conn, &query, limit)?,
                Err(e) => {
                    tracing::debug!(error = %e, "FTS5 match failed, falling back to LIKE");
                    recall_like(&conn, &query, limit)?
                }
            };

            // Episodic lane (warm + cold tier-utility) — skipped for Skip-tier
            // queries (status/identity) to save the LIKE scans. Ranked in place
            // by composite_score FIRST so its within-lane rank carries the full
            // JV-MEM-05/07/09/14 signal (importance/trust/recency/access/length)
            // into the fusion.
            let mut episodic_lane: Vec<EpisodeHit> = Vec::new();
            if budget.episodic {
                let warm = recall_warm_like(&conn, &query, limit)?;
                let cold = recall_cold_like(&conn, &query, limit)?;
                episodic_lane.reserve(warm.len() + cold.len());
                episodic_lane.extend(warm);
                episodic_lane.extend(cold);
                let graph_degrees: std::collections::HashMap<i64, u32> = episodic_lane
                    .iter()
                    .filter_map(|hit| {
                        crate::memory::assoc_graph::event_degree(&conn, hit.event_id)
                            .ok()
                            .map(|degree| (hit.event_id, degree))
                    })
                    .collect();
                rank_in_place_with_degrees(&mut episodic_lane, now_ns, &graph_degrees);
            }

            let gt_rows = recall_groundtruth_like(&conn, &query, limit)?;

            // Late fusion: RRF across the Semantic + Episodic lanes, deduped by
            // text_hash (a hot hit and a warm summary of the same content
            // collapse to one). Semantic is weighted above Episodic. Groundtruth
            // is operator-asserted truth → prepended, never fused/scored.
            let mut lanes: Vec<crate::memory::recall_lanes::LaneResult> = Vec::with_capacity(2);
            lanes.push(crate::memory::recall_lanes::LaneResult {
                weight: crate::memory::recall_lanes::SEMANTIC_WEIGHT,
                hits: hot,
            });
            if !episodic_lane.is_empty() {
                lanes.push(crate::memory::recall_lanes::LaneResult {
                    weight: crate::memory::recall_lanes::EPISODIC_WEIGHT,
                    hits: episodic_lane,
                });
            }
            let fused = apply_community_stage(
                &conn,
                crate::memory::recall_lanes::fuse_lanes_scored(&lanes, limit),
                limit,
            );

            let mut rows: Vec<EpisodeHit> = Vec::with_capacity(gt_rows.len() + fused.len());
            rows.extend(gt_rows);
            rows.extend(fused);
            rows.truncate(limit);

            // RECALL-METER-01: record a best-effort latency sample for the
            // daemon recall-latency cron (MONITOR-03). A metering failure must
            // NEVER fail the recall — log at debug and move on.
            let latency_ms = recall_t0.elapsed().as_secs_f64() * 1000.0;
            let ts_unix = (now_ns / 1_000_000_000) as i64;
            if let Err(e) = store::record_recall_latency(&conn, ts_unix, latency_ms) {
                tracing::debug!(error = %e, "recall: latency sample not recorded");
            }

            // GOLD-SEC-06 / A-05+A-66: run the Hebbian reinforcement
            // writes (N synchronous SQLite UPDATEs) on THIS blocking
            // thread, not on the async caller. Previously the conn was
            // returned out and the loop hammered SQLite on the runtime
            // worker — the exact thread-pinning the spawn_blocking was
            // meant to avoid. Groundtruth rows are decay-immune (SPEC
            // GT-3) and skipped; each reinforce is best-effort.
            let mut reinforcements: Vec<(i64, ReinforceFrame)> = Vec::new();
            for h in &rows {
                let tier = match h.tier.as_str() {
                    "hot" => Some(tiers::Tier::Hot),
                    "warm" => Some(tiers::Tier::Warm),
                    "cold" => Some(tiers::Tier::Cold),
                    _ => None,
                };
                let Some(tier) = tier else { continue };
                match tiers::hebbian_reinforce_at_tier(&conn, tier, h.event_id, now_ns) {
                    Ok(Some(out)) => {
                        tracing::debug!(
                            event_id = h.event_id,
                            tier = out.tier.as_str(),
                            old = out.old,
                            new = out.new,
                            "hebbian reinforce on recall hit",
                        );
                        reinforcements.push((
                            h.event_id,
                            ReinforceFrame {
                                tier: out.tier.as_str().to_string(),
                                old: out.old,
                                new: out.new,
                            },
                        ));
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        event_id = h.event_id,
                        tier = tier.as_str(),
                        error = %e,
                        "reinforce failed",
                    ),
                }
                // JV-MEM-05 / JV-MEM-09: bump recall frequency in the hit's tier
                // table so the ranker can stretch the half-life (JV-MEM-05) and
                // re-promote a frequently-recalled aged row (JV-MEM-09). All tiers
                // now carry access_count. Best-effort; never fails the recall.
                if let Err(e) = store::increment_access_at_tier(&conn, tier, h.event_id) {
                    tracing::debug!(
                        event_id = h.event_id,
                        tier = tier.as_str(),
                        error = %e,
                        "access_count bump failed",
                    );
                }
            }

            // GOLD-ADAPT-MEM-15 — record this recall's outcome for the quality
            // scorecard (result count + reinforcement count + tier). Recorded
            // AFTER the reinforce loop so reinforcements.len() is final; the
            // latency sample above stays measured pre-reinforce (the MONITOR-03
            // p95 semantic is unchanged). Best-effort — never fails the recall.
            if let Err(e) = store::record_recall_event(
                &conn,
                ts_unix,
                rows.len() as u32,
                reinforcements.len() as u32,
                tier_str,
            ) {
                tracing::debug!(error = %e, "recall: scorecard event not recorded");
            }

            Ok((rows, reinforcements))
        })
        .await
        .context("recall query task panicked")??;

    // Phase 28a R-22 MT-3: Hebbian reinforce on EVERY recall hit (all
    // tiers) is computed inside the blocking task above (GOLD-SEC-06).
    // The ground-truth table is decay-immune (SPEC GT-3) so its rows are
    // skipped there. Here we only emit the audit frames — M-02 (Session
    // 24): `EVENT_TYPE_IMPORTANCE_REINFORCED` (0x93) so `neoth wal show
    // --type importance_reinforced` records CLI-path reinforcements too.
    // The WAL append is async, so it stays on the async side; best-effort
    // — a failure logs a warn but never aborts the recall reply.
    if !reinforcements.is_empty() {
        emit_reinforce_audit_frames(&reinforcements).await;
    }

    // R-02 Phase 2: optionally prepend dream-pipeline matches.
    // Dreams render to stdout BEFORE the episode rows so an
    // operator's "what happened this week" lands on the
    // compressed dream summaries first.
    if args.include_dreams {
        let home = crate::config::FreedomConfig::default_neoth_home();
        let dreams = crate::daemon::dreaming::seed_with_dreams(
            &home,
            &args.query,
            args.dreams_lookback_days,
            args.dreams_max_hits,
        );
        render_dreams(&dreams);
    }

    render(&rows, args.output, &args.query);

    // GOLD-ADAPT-MEM-06 Stage-3 — append knowledge-graph facts for any entity
    // the query names. Additive + best-effort: an unknown entity / empty graph
    // prints nothing, so the default flat-recall output is unchanged.
    append_graph_facts(&db_path, &args.query, args.output);

    // GOLD-ADAPT-MEM-07 — co-access association:
    //   (a) reinforce links among the top-K episodic results (these memories
    //       were surfaced together for one query — "fired together, wired
    //       together"), and
    //   (b) append the 1-hop neighbourhood as a [ASSOCIATED MEMORIES] block.
    // Outcome feedback is intentionally NOT inferred from exposure: only
    // explicit `--upvote`/`--downvote` updates success/failure counters.
    // All best-effort. The flat-recall output remains available unchanged.
    const ASSOC_TOP_K: usize = 6;
    let episodic_ids: Vec<i64> = rows
        .iter()
        .filter(|h| h.event_id > 0 && h.tier != "groundtruth")
        .map(|h| h.event_id)
        .take(ASSOC_TOP_K)
        .collect();
    if episodic_ids.len() >= 2
        && let Ok(conn) = store::open(&db_path)
    {
        let now_unix = crate::time::now_unix_i64();
        if let Err(e) =
            crate::memory::assoc_graph::reinforce_co_access(&conn, &episodic_ids, now_unix)
        {
            tracing::debug!(error = %e, "assoc_graph: co-access reinforce failed (non-fatal)");
        }
    }
    append_assoc_facts(&db_path, &episodic_ids, args.output);

    Ok(())
}

/// GOLD-ADAPT-MEM-07 Stage-4 — additive: append the 1-hop co-access
/// neighbourhood of the recall's top results as an `[ASSOCIATED MEMORIES]`
/// block. Table-mode only (JSON output stays the clean ranked array); dedups
/// against the ids already shown; best-effort (silent on any error). Never
/// reorders or replaces the primary recall result.
fn append_assoc_facts(
    db_path: &std::path::Path,
    result_ids: &[i64],
    output: crate::cli::OutputFormat,
) {
    if !matches!(output, crate::cli::OutputFormat::Table) || result_ids.is_empty() {
        return;
    }
    let Ok(conn) = store::open(db_path) else {
        return;
    };
    let mut seen: std::collections::HashSet<i64> = result_ids.iter().copied().collect();
    let mut lines: Vec<(i64, f64, String)> = Vec::new();
    for &eid in result_ids {
        let Ok(assoc) = crate::memory::assoc_graph::associated(&conn, eid, 5) else {
            continue;
        };
        for (other, weight) in assoc {
            if !seen.insert(other) {
                continue; // already shown in the primary result or already listed
            }
            let text: Option<String> = conn
                .query_row(
                    "SELECT text FROM idx_episode WHERE event_id = ?1",
                    rusqlite::params![other],
                    |r| r.get(0),
                )
                .ok()
                .or_else(|| {
                    conn.query_row(
                        "SELECT text FROM idx_longterm WHERE event_id = ?1",
                        rusqlite::params![other],
                        |r| r.get(0),
                    )
                    .ok()
                });
            if let Some(t) = text {
                let snippet: String = t.chars().take(80).collect();
                lines.push((other, weight, snippet));
            }
        }
    }
    if lines.is_empty() {
        return;
    }
    println!("\n[ASSOCIATED MEMORIES]");
    for (eid, w, snip) in lines {
        println!("  event {eid} (weight {w:.2}) — {snip}");
    }
}

/// MEM-06 Stage-3 — resolve the query (whole + per-word) as graph entities and
/// print a `[RELEVANT FACTS]` block for each match. Table output only (JSON
/// stays the pure search payload). Best-effort: any error prints nothing.
fn append_graph_facts(db_path: &std::path::Path, query: &str, output: crate::cli::OutputFormat) {
    if !matches!(output, crate::cli::OutputFormat::Table) {
        return;
    }
    let Ok(conn) = store::open(db_path) else {
        return;
    };
    let mut candidates: Vec<String> = vec![query.trim().to_string()];
    candidates.extend(
        query
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|w| w.chars().count() >= 3),
    );
    let mut seen = std::collections::HashSet::new();
    for cand in candidates {
        if cand.is_empty() || !seen.insert(cand.to_lowercase()) {
            continue;
        }
        if let Ok(neighbors) = crate::memory::entities::get_neighbors(&conn, &cand, 2)
            && !neighbors.is_empty()
        {
            print!(
                "\n{}",
                crate::memory::context_inject::build_facts_block(&cand, &neighbors)
            );
        }
    }
}

/// Render the dream rows ahead of the episode hits. Compact one-line
/// format so the output stays scannable.
fn render_dreams(dreams: &[crate::daemon::dreaming::Dream]) {
    if dreams.is_empty() {
        return;
    }
    println!("── dreams ──");
    for d in dreams {
        println!(
            "[{day}] {label}: {summary}",
            day = d.day,
            label = d.theme_label,
            summary = if d.summary.chars().count() > 160 {
                let mut s: String = d.summary.chars().take(160).collect();
                s.push('…');
                s
            } else {
                d.summary.clone()
            },
        );
    }
    println!("── episodes ──");
}

/// GOLD-ADAPT-MEM-15 — render the recall-quality scorecard. JSON output is the
/// full struct (for scripting); Table is a compact human summary.
fn render_scorecard(
    card: &crate::memory::store::RecallScorecard,
    output: crate::cli::OutputFormat,
) {
    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
            match serde_json::to_string_pretty(card) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("scorecard: serialize failed: {e}"),
            }
        }
        crate::cli::OutputFormat::Table => {
            let span = match (card.window_start_ts, card.window_end_ts) {
                (Some(a), Some(b)) => format!(
                    "{} → {}",
                    format_ts(a * 1_000_000_000),
                    format_ts(b * 1_000_000_000)
                ),
                _ => "no data".to_string(),
            };
            println!(
                "Recall Quality Scorecard (window: {}, {})",
                card.window, span
            );
            println!("──────────────────────────────────────────────────────────");
            println!(
                "Total recalls        : {:<6}  Data sufficient: {}",
                card.total_recalls,
                if card.data_sufficient {
                    "yes"
                } else {
                    "no (need ≥10 non-skip)"
                }
            );
            println!(
                "Hit rate             : {:>5.1}%  Empty rate     : {:>5.1}%",
                card.hit_rate * 100.0,
                card.empty_rate * 100.0
            );
            println!(
                "Mean result count    : {:>5.1}   Reinforcement  : {:>5.1}%",
                card.mean_result_count,
                card.reinforcement_rate * 100.0
            );
            println!(
                "Tier skip/single/multi: {:.1}% / {:.1}% / {:.1}%",
                card.tier_skip_pct, card.tier_single_pct, card.tier_multi_pct
            );
            println!(
                "Latency p50/p95/mean : {:.0}ms / {:.0}ms / {:.0}ms",
                card.latency_p50_ms, card.latency_p95_ms, card.latency_mean_ms
            );
        }
    }
}

/// Sort recall hits by composite ranking score, descending. Stable order so
/// ties fall back to the tier-local SQL ordering (ts_ns DESC / importance DESC).
#[cfg(test)]
fn rank_in_place(rows: &mut [EpisodeHit], now_ns: u64) {
    rank_in_place_with_degrees(rows, now_ns, &std::collections::HashMap::new());
}

fn rank_in_place_with_degrees(
    rows: &mut [EpisodeHit],
    now_ns: u64,
    graph_degrees: &std::collections::HashMap<i64, u32>,
) {
    const NS_PER_DAY: f64 = 86_400.0 * 1_000_000_000.0;
    rows.sort_by(|a, b| {
        let score_a = composite_score_with_degree(
            a,
            now_ns,
            NS_PER_DAY,
            graph_degrees.get(&a.event_id).copied().unwrap_or(0),
        );
        let score_b = composite_score_with_degree(
            b,
            now_ns,
            NS_PER_DAY,
            graph_degrees.get(&b.event_id).copied().unwrap_or(0),
        );
        // Reverse compare for descending order. NaN treated as smallest.
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

#[cfg(test)]
fn composite_score(h: &EpisodeHit, now_ns: u64, ns_per_day: f64) -> f64 {
    composite_score_with_degree(h, now_ns, ns_per_day, 0)
}

fn composite_score_with_degree(
    h: &EpisodeHit,
    now_ns: u64,
    ns_per_day: f64,
    graph_degree: u32,
) -> f64 {
    let age_tier = match h.tier.as_str() {
        "warm" => tiers::Tier::Warm,
        "cold" => tiers::Tier::Cold,
        _ => tiers::Tier::Hot,
    };
    let importance = h.importance.unwrap_or(0.5);
    let age_ns = now_ns.saturating_sub(h.ts_ns.max(0) as u64) as f64;
    let days_since = (age_ns / ns_per_day).max(0.0);
    // JV-MEM-09: a frequently-recalled, still-relevant aged row re-promotes to a
    // higher RANKING tier (without physically moving between the age tables) so it
    // ranks/decays like a fresher memory. JV-MEM-05: the access count also
    // stretches the recency half-life. Both no-op (age tier + access-naive curve)
    // when access_count is 0.
    let rank_tier = tiers::tier_for_by_access(age_tier, h.access_count, importance);
    let base = tiers::ranking_score_repromoted(
        importance,
        age_tier,
        rank_tier,
        days_since,
        h.access_count,
    );
    // JV-MEM-14: weight by source trust so operator-explicit memories outrank
    // lower-trust external chatter at equal relevance.
    let base = base * tiers::trust_weight(h.trust);
    // JV-MEM-02: source-weight provenance calibration — multiply in the
    // 3-table (ref/kind/backend) weight multiplier so memories with more
    // corroborating sources and better-verified provenance rank higher.
    let base = base
        * crate::memory::source_weight::weight_multiplier_for_hit(
            h.event_type,
            h.operator_id.as_deref(),
            h.trust,
            1, // source_count: default 1 per episode; fact merging will pass higher counts
        );
    // JV-MEM-07: length normalization — a gentle logarithmic penalty on verbose
    // entries so they don't win on raw keyword density. Entries at/below the
    // 300-char anchor are unpenalised (ratio clamped to 1 → log2(1)=0 → factor
    // 1); a 2×/4×/8×-anchor entry is scaled by 1/2 / 1/3 / 1/4. The factor is
    // always in (0, 1], so the score stays ≥ 0 and finite.
    const LEN_ANCHOR_CHARS: f64 = 300.0;
    let ratio = (h.text.chars().count() as f64 / LEN_ANCHOR_CHARS).max(1.0);
    let length_norm = 1.0 / (1.0 + ratio.log2());
    let base = base * length_norm;
    // JV-MEM-08: bounded out-degree component. `ln(1 + degree)` rewards real
    // hubs without letting a densely-connected import swamp textual relevance;
    // the factor saturates at +10% once degree reaches 32.
    const DEGREE_SATURATION: f64 = 32.0;
    const MAX_DEGREE_BOOST: f64 = 0.10;
    let degree_ratio =
        (graph_degree as f64).ln_1p().min(DEGREE_SATURATION.ln_1p()) / DEGREE_SATURATION.ln_1p();
    base * (1.0 + MAX_DEGREE_BOOST * degree_ratio)
}

/// FTS5 path. Uses MATCH with the raw query — FTS5 supports prefix (`foo*`),
/// phrase ("foo bar"), and boolean operators (AND/OR/NOT) out of the box.
/// BM25 ordering surfaces best matches first. ts_ns DESC is a tiebreaker.
fn recall_fts(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let mut stmt = conn.prepare(
        "SELECT e.event_id, e.event_type, e.ts_ns, e.text, e.text_hash, \
                e.channel, e.sender_id, e.operator_id, e.importance, e.access_count, e.trust \
         FROM idx_episode e \
         JOIN idx_episode_fts f ON f.rowid = e.event_id \
         WHERE idx_episode_fts MATCH ?1 \
         ORDER BY bm25(idx_episode_fts), e.ts_ns DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![query, limit as i64], hot_row_mapper)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// GOLD-WIRE-02: answer a conversational-recall prompt
/// ("Weißt du noch als wir über X geredet haben?" / "do you remember
/// when we talked about X?") straight from the local `idx_episode`
/// store — WITHOUT an LLM call.
///
/// Returns `Some(reply)` when the prompt matches a recall intent (the
/// reply is the formatted hits, or a localized "nothing found" line when
/// memory has no match); `None` when it's a normal prompt that should
/// fall through to the provider. Best-effort on the DB: any open/query
/// error → "nothing found", never an `Err` to the caller. Only a successful,
/// empty query emits the optional Babel true-miss signal; DB/worker failures
/// are explicitly not misclassified as misses.
pub(crate) async fn answer_conversational_recall(prompt: &str, db_path: &Path) -> Option<String> {
    let query = crate::recall::conversational::detect_recall_intent(prompt)?;
    const RECALL_LIMIT: usize = 5;
    // Run the synchronous rusqlite query off the async worker (mirrors the
    // main recall path's spawn_blocking, K-Perf-3). A JoinError degrades to
    // empty hits → the localized "nothing found" reply, preserving the
    // best-effort contract.
    let db_owned = db_path.to_path_buf();
    let topic = query.topic.clone();
    let hits = match tokio::task::spawn_blocking(move || {
        recall_episodes_checked(&db_owned, &topic, RECALL_LIMIT)
    })
    .await
    {
        Ok(Ok(hits)) => {
            if hits.is_empty() {
                crate::analytics::babel::signals::emit(
                    crate::analytics::babel::signals::SignalKind::MemoryRecallMiss,
                );
            }
            hits
        }
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "conversational recall failed; not counted as a miss");
            Vec::new()
        }
        Err(error) => {
            tracing::warn!(error = %error, "conversational recall worker failed; not counted as a miss");
            Vec::new()
        }
    };
    let reply =
        crate::recall::conversational::format_recall_reply(&hits, query.language, &query.topic);
    // This reply can bypass the provider and go straight to an external
    // channel. Treat every recalled byte as untrusted legacy data even when
    // the current write path is already sanitised.
    Some(crate::security::redact::sanitize_tool_output(&reply))
}

/// GOLD-WIRE-02b — channel-path recall authorization. Conversational recall
/// reads stored memory back OUT to the recipient; on the autonomous channel
/// surface (Telegram / WhatsApp / Slack) that is only safe to serve to the
/// **provable operator** — the sender whose resolved cross-channel
/// `human_uuid` equals the operator's PINNED uuid.
///
/// This is deliberately STRICTER than [`crate::memory::channel_weights::learn_factor`],
/// which trusts an *unpinned* operator on a solo install (`(_, None) => true`).
/// Learning silently weights a topic; recall DISCLOSES memory contents, so the
/// bar is higher: an unpinned operator (`operator_uuid == None`) or a sender
/// carrying no uuid yields `false`. A `false` result means the channel handler
/// does NOT short-circuit — the message falls through to the normal LLM turn
/// and no memory is read out. The CLI path (`run_chat_with`) needs no such gate:
/// it's a local TTY the operator already owns.
///
/// The scope is enforced HERE (at the recipient) rather than in the recall SQL
/// because the searchable conversational text lives in `RAW_TEXT`-derived
/// `idx_episode` rows that carry NO per-sender columns (`channel/sender_id/
/// operator_id` are NULL on those rows — see `memory/indexer.rs`). Gating at
/// the provable operator is therefore the only correct boundary; once it
/// passes, serving the operator their own memory is not a cross-surface leak.
pub(crate) fn channel_recall_authorized(
    sender_uuid: Option<&str>,
    operator_uuid: Option<&str>,
) -> bool {
    matches!((sender_uuid, operator_uuid), (Some(s), Some(o)) if s == o)
}

/// Hot-tier episode search for [`answer_conversational_recall`]: FTS5
/// first, LIKE fallback (mirrors the main recall path's hot-tier query).
/// Error-preserving search used to distinguish a real empty result from an
/// unavailable/corrupt store before emitting telemetry.
fn recall_episodes_checked(db_path: &Path, topic: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    if !db_path.exists() {
        anyhow::bail!("views.db does not exist");
    }
    let conn = store::open(db_path)?;
    match recall_fts(&conn, topic, limit) {
        Ok(hits) if !hits.is_empty() => Ok(hits),
        _ => recall_like(&conn, topic, limit),
    }
}

/// LIKE fallback (case-insensitive substring) over `idx_episode` (hot tier).
/// Used when FTS5 MATCH parses the query as empty (pure punctuation) or
/// returns zero rows for a partial word the FTS tokenizer split badly.
fn recall_like(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id, importance, access_count, trust \
         FROM idx_episode \
         WHERE text LIKE ?1 COLLATE NOCASE \
         ORDER BY ts_ns DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit as i64], hot_row_mapper)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// LIKE search over `idx_consolidated` (warm tier, 7-90d). Summary rows
/// (`kind = 'summary'`) have NULL event_id — `COALESCE(event_id, -id)`
/// gives them a stable negative id that cannot collide with any
/// `idx_episode.event_id` (which is always positive).
fn recall_warm_like(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT COALESCE(event_id, -id) AS event_id, \
                consolidated_ts AS ts_ns, text, text_hash, importance, access_count \
         FROM idx_consolidated \
         WHERE text LIKE ?1 COLLATE NOCASE \
         ORDER BY importance DESC, consolidated_ts DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit as i64], |r| {
            Ok(EpisodeHit {
                event_id: r.get(0)?,
                event_type: 0,
                ts_ns: r.get(1)?,
                text: r.get(2)?,
                text_hash: r.get(3)?,
                channel: None,
                sender_id: None,
                operator_id: None,
                tier: "warm".to_string(),
                importance: Some(r.get::<_, f64>(4)?),
                access_count: r.get::<_, i64>(5)? as u32,
                trust: 1,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// LIKE search over `idx_longterm` (cold tier, >90d Hebbian survivors).
fn recall_cold_like(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT event_id, promoted_ts AS ts_ns, text, text_hash, importance, access_count \
         FROM idx_longterm \
         WHERE text LIKE ?1 COLLATE NOCASE \
         ORDER BY importance DESC, promoted_ts DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit as i64], |r| {
            Ok(EpisodeHit {
                event_id: r.get(0)?,
                event_type: 0,
                ts_ns: r.get(1)?,
                text: r.get(2)?,
                text_hash: r.get(3)?,
                channel: None,
                sender_id: None,
                operator_id: None,
                tier: "cold".to_string(),
                importance: Some(r.get::<_, f64>(4)?),
                access_count: r.get::<_, i64>(5)? as u32,
                trust: 1,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// GRAPH-03 Stage-3 production seam shared by explicit `neoth recall` and the
/// Chat/Channel Block-D path. Only assignments for the already-ranked seed hits
/// are queried; after plurality selection, one bounded query loads members of
/// that community. A missing/old schema degrades to the original ranking.
fn apply_community_stage(
    conn: &Connection,
    scored: Vec<crate::memory::recall_lanes::ScoredHit>,
    limit: usize,
) -> Vec<EpisodeHit> {
    if scored.is_empty() || limit == 0 {
        return Vec::new();
    }

    let mut community_map = match load_community_assignments_for_hits(conn, &scored) {
        Ok(assignments) => assignments,
        Err(error) => {
            tracing::debug!(
                error = %error,
                "recall: scoped community assignment load failed (non-fatal)"
            );
            return scored.into_iter().map(|scored| scored.hit).collect();
        }
    };
    let Some(community_id) =
        crate::memory::recall_lanes::plurality_community_id(&scored, &community_map)
    else {
        return scored.into_iter().map(|scored| scored.hit).collect();
    };

    // The first `limit` rows may include the already-ranked representatives.
    // Fetch one additional result window so expansion can still fill a bounded
    // page after event-id/text-hash deduplication.
    let candidate_limit = limit.saturating_add(scored.len());
    let community_candidates = match load_community_members(conn, community_id, candidate_limit) {
        Ok(members) => members,
        Err(error) => {
            tracing::debug!(
                error = %error,
                community_id,
                "recall: community expansion load failed (non-fatal)"
            );
            Vec::new()
        }
    };
    for candidate in &community_candidates {
        community_map.insert(candidate.event_id, community_id);
    }

    crate::memory::recall_lanes::expand_and_boost_by_community(
        scored,
        community_candidates,
        &community_map,
        limit,
    )
}

fn load_community_assignments_for_hits(
    conn: &Connection,
    hits: &[crate::memory::recall_lanes::ScoredHit],
) -> Result<std::collections::HashMap<i64, i64>> {
    const SQLITE_ID_CHUNK: usize = 400;

    let ids: std::collections::BTreeSet<i64> =
        hits.iter().map(|scored| scored.hit.event_id).collect();
    let ids: Vec<i64> = ids.into_iter().collect();
    let mut assignments = std::collections::HashMap::with_capacity(ids.len());
    for chunk in ids.chunks(SQLITE_ID_CHUNK) {
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT node_id, community_id FROM idx_memory_communities \
             WHERE node_id IN ({placeholders}) ORDER BY node_id ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (node_id, community_id) = row?;
            assignments.insert(node_id, community_id);
        }
    }
    Ok(assignments)
}

/// GRAPH-03 Stage-3 expansion candidates for one persisted Louvain community.
///
/// Community assignments use the original positive WAL event id, so warm
/// summary rows (`event_id IS NULL`) cannot participate. The UNION covers the
/// same hot/warm/cold stores as normal recall and returns a deterministic,
/// bounded candidate set. Stage-3 performs the final event-id/text-hash dedup.
fn load_community_members(
    conn: &Connection,
    community_id: i64,
    limit: usize,
) -> Result<Vec<EpisodeHit>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT event_id, event_type, ts_ns, text, text_hash, channel, sender_id, \
                operator_id, tier, importance, access_count, trust \
         FROM ( \
             SELECT e.event_id, e.event_type, e.ts_ns, e.text, e.text_hash, \
                    e.channel, e.sender_id, e.operator_id, 'hot' AS tier, \
                    e.importance, e.access_count, e.trust, 0 AS tier_order \
             FROM idx_memory_communities c \
             JOIN idx_episode e ON e.event_id = c.node_id \
             WHERE c.community_id = ?1 \
             UNION ALL \
             SELECT w.event_id, 0 AS event_type, w.consolidated_ts AS ts_ns, \
                    w.text, w.text_hash, NULL AS channel, NULL AS sender_id, \
                    NULL AS operator_id, 'warm' AS tier, w.importance, \
                    w.access_count, 1 AS trust, 1 AS tier_order \
             FROM idx_memory_communities c \
             JOIN idx_consolidated w ON w.event_id = c.node_id \
             WHERE c.community_id = ?1 \
             UNION ALL \
             SELECT l.event_id, 0 AS event_type, l.promoted_ts AS ts_ns, \
                    l.text, l.text_hash, NULL AS channel, NULL AS sender_id, \
                    NULL AS operator_id, 'cold' AS tier, l.importance, \
                    l.access_count, 1 AS trust, 2 AS tier_order \
             FROM idx_memory_communities c \
             JOIN idx_longterm l ON l.event_id = c.node_id \
             WHERE c.community_id = ?1 \
         ) \
         ORDER BY event_id ASC, tier_order ASC, text_hash ASC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![community_id, limit as i64], |r| {
            Ok(EpisodeHit {
                event_id: r.get(0)?,
                event_type: r.get::<_, i64>(1)? as u8,
                ts_ns: r.get(2)?,
                text: r.get(3)?,
                text_hash: r.get(4)?,
                channel: r.get(5)?,
                sender_id: r.get(6)?,
                operator_id: r.get(7)?,
                tier: r.get(8)?,
                importance: Some(r.get::<_, f64>(9)?),
                access_count: r.get::<_, i64>(10)? as u32,
                trust: r.get::<_, i64>(11)? as u8,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// LIKE search over `idx_groundtruth` — operator-asserted facts that survive
/// every consolidation pass. Matches are returned as synthetic `EpisodeHit`
/// rows with `tier == "groundtruth"` so the recall surface treats them as a
/// distinct tier and the renderer can flag them visually. `revoked_at IS NULL`
/// filters tombstoned facts.
// GOLD-ADAPT-MEM-10: `pub(crate)` so the council Left (factual) hemisphere can
// lead its region-recall with operator-asserted ground-truth facts.
pub(crate) fn recall_groundtruth_like(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT id, statement, asserted_at \
         FROM idx_groundtruth \
         WHERE revoked_at IS NULL \
           AND fact_state = 'verified' \
           AND statement LIKE ?1 COLLATE NOCASE \
         ORDER BY asserted_at DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit as i64], |r| {
            let id: i64 = r.get(0)?;
            let statement: String = r.get(1)?;
            let asserted_at: i64 = r.get(2)?;
            let hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(statement.as_bytes()));
            Ok(EpisodeHit {
                event_id: id,
                event_type: 0,
                ts_ns: asserted_at,
                text: statement,
                text_hash: hash,
                channel: None,
                sender_id: None,
                operator_id: None,
                tier: "groundtruth".to_string(),
                // Ground-truth has no decaying importance score; surface
                // as `None` so the renderer skips the score column for
                // these rows (they always rank first by tier prepending,
                // not by composite score).
                importance: None,
                access_count: 0,
                // Ground-truth is operator-asserted → highest source trust.
                trust: 2,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// GOLD-ADAPT-JV-MEM-10 — one flagged contradiction rendered for prompt
/// injection: the two conflicting operator-asserted statements + the detector's
/// confidence. Distinct from [`crate::memory::contradiction::ContradictionRow`]
/// (which carries fact *ids*) — the recall renderer needs the statement TEXT.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContradictionLine {
    pub statement_a: String,
    pub statement_b: String,
    pub confidence: f32,
}

/// GOLD-ADAPT-JV-MEM-10 — three confidence-tiered recall lanes for layered
/// prompt injection, queried + ranked INDEPENDENTLY so the renderer can label
/// and order them by trust rather than flattening everything into one
/// undifferentiated block:
///   - `canonical`   — operator-asserted ground-truth facts (highest trust).
///   - `episodes`    — region-routed episodic recall (the prior flat lane).
///   - `contradictions` — prompt-relevant PENDING fact-conflicts (caution flag).
#[derive(Debug, Clone, Default)]
pub(crate) struct RecallOutput {
    pub canonical: Vec<EpisodeHit>,
    pub episodes: Vec<EpisodeHit>,
    pub contradictions: Vec<ContradictionLine>,
}

impl RecallOutput {
    /// True when no lane surfaced anything — the caller suppresses the whole
    /// Block::D section (same effect as a Skip-tier turn).
    pub(crate) fn is_empty(&self) -> bool {
        self.canonical.is_empty() && self.episodes.is_empty() && self.contradictions.is_empty()
    }

    /// Sanitise every memory-derived string before it can enter a provider
    /// prompt, CCR payload, or channel response. The underlying SQLite rows
    /// remain untouched so operator-owned source memory is not rewritten.
    fn sanitize_for_egress(mut self) -> Self {
        for hit in self.canonical.iter_mut().chain(self.episodes.iter_mut()) {
            hit.text = crate::security::redact::sanitize_tool_output(&hit.text);
        }
        for contradiction in &mut self.contradictions {
            contradiction.statement_a =
                crate::security::redact::sanitize_tool_output(&contradiction.statement_a);
            contradiction.statement_b =
                crate::security::redact::sanitize_tool_output(&contradiction.statement_b);
        }
        self
    }
}

/// Max pending contradictions surfaced into one prompt — operator-attention
/// items, kept tiny so a noisy ledger can't crowd out the actual recall.
const CONTRADICTION_LANE_LIMIT: usize = 3;

/// GOLD-ADAPT-JV-MEM-10 — populate the three recall lanes for `prompt`.
/// **Canonical:** [`recall_groundtruth_like`] (already `fact_state='verified'`
/// AND `revoked_at IS NULL` gated — candidate/deprecated facts never leak).
/// **Episodes:** [`crate::memory::region_router::run_routed_recall`] (the SAME
/// region-weighted call the flat Block::D path used, so no recall regression).
/// **Contradictions:** prompt-relevant pending pairs joined to their statement
/// text. Best-effort PER LANE — a lane query error yields an empty lane, never
/// an `Err`, so one bad lane can't suppress the others.
#[cfg(test)]
pub(crate) fn query_three_lanes(
    conn: &Connection,
    plan: &crate::memory::region_router::RouterPlan,
    prompt: &str,
    limit: usize,
) -> RecallOutput {
    let canonical = recall_groundtruth_like(conn, prompt, limit).unwrap_or_default();
    let episode_hits = crate::memory::region_router::run_routed_recall(conn, plan, prompt, limit)
        .unwrap_or_default();
    let episodes = apply_community_stage(
        conn,
        crate::memory::recall_lanes::score_ranked_hits(episode_hits),
        limit,
    );
    let contradictions =
        recall_pending_contradictions(conn, prompt, CONTRADICTION_LANE_LIMIT).unwrap_or_default();
    RecallOutput {
        canonical,
        episodes,
        contradictions,
    }
    .sanitize_for_egress()
}

/// Error-preserving variant for telemetry-sensitive callers. A "true miss"
/// is only observable when all three queries succeeded and returned empty;
/// collapsing a SQLite error into an empty lane would fabricate that signal.
pub(crate) fn query_three_lanes_checked(
    conn: &Connection,
    plan: &crate::memory::region_router::RouterPlan,
    prompt: &str,
    limit: usize,
) -> Result<RecallOutput> {
    let canonical = recall_groundtruth_like(conn, prompt, limit)?;
    let episode_hits = crate::memory::region_router::run_routed_recall(conn, plan, prompt, limit)?;
    let episodes = apply_community_stage(
        conn,
        crate::memory::recall_lanes::score_ranked_hits(episode_hits),
        limit,
    );
    let contradictions = recall_pending_contradictions(conn, prompt, CONTRADICTION_LANE_LIMIT)?;
    Ok(RecallOutput {
        canonical,
        episodes,
        contradictions,
    }
    .sanitize_for_egress())
}

/// Prompt-relevant PENDING contradictions, joined to both facts' statement text.
/// Surfaces only conflicts touching the current topic (a `LIKE` on EITHER
/// statement) so the model treats disputed facts with caution without drowning
/// every turn in the operator's whole unresolved-conflict backlog. Both facts
/// must be un-revoked. Highest-confidence first.
fn recall_pending_contradictions(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<ContradictionLine>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT a.statement, b.statement, c.confidence \
         FROM idx_contradictions c \
         JOIN idx_groundtruth a ON a.id = c.fact_a_id \
         JOIN idx_groundtruth b ON b.id = c.fact_b_id \
         WHERE c.decision = 'pending' \
           AND a.revoked_at IS NULL AND b.revoked_at IS NULL \
           AND (a.statement LIKE ?1 COLLATE NOCASE OR b.statement LIKE ?1 COLLATE NOCASE) \
         ORDER BY c.confidence DESC \
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit as i64], |r| {
            Ok(ContradictionLine {
                statement_a: r.get(0)?,
                statement_b: r.get(1)?,
                confidence: r.get::<_, f64>(2)? as f32,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn hot_row_mapper(r: &rusqlite::Row<'_>) -> rusqlite::Result<EpisodeHit> {
    Ok(EpisodeHit {
        event_id: r.get(0)?,
        event_type: r.get::<_, i64>(1)? as u8,
        ts_ns: r.get(2)?,
        text: r.get(3)?,
        text_hash: r.get(4)?,
        channel: r.get(5)?,
        sender_id: r.get(6)?,
        operator_id: r.get(7)?,
        tier: "hot".to_string(),
        importance: Some(r.get::<_, f64>(8)?),
        access_count: r.get::<_, i64>(9)? as u32,
        trust: r.get::<_, i64>(10)? as u8,
    })
}

// Required for the conn alias used above.
use rusqlite::Connection;

/// GOLD-ADAPT-ODY-26 — render transcript FTS results.
///
/// Opens `views.db`, calls `memory::transcript_store::search_turns`, and
/// renders the results. Table format: for each hit, a header line is printed,
/// then before-context rows (prefixed `  ^`), the matched row (prefixed `  *`),
/// and after-context rows (prefixed `  v`). JSON: structured array.
fn run_transcript_search(
    query: &str,
    context_rows: usize,
    limit: usize,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    use crate::cli::OutputFormat;
    let db_path = store::default_path();
    let conn = store::open(&db_path).context("open views.db for transcript search")?;
    let effective_limit = if limit == 0 { 20 } else { limit };
    let results =
        crate::memory::transcript_store::search_turns(&conn, query, context_rows, effective_limit)
            .context("transcript FTS search")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "session_id": r.matched.session_id,
                        "matched": {
                            "id": r.matched.id,
                            "role": r.matched.role,
                            "ts_unix": r.matched.ts_unix,
                            "text": r.matched.text,
                        },
                        "before": r.before.iter().map(|t| serde_json::json!({
                            "id": t.id, "role": t.role, "ts_unix": t.ts_unix, "text": t.text,
                        })).collect::<Vec<_>>(),
                        "after": r.after.iter().map(|t| serde_json::json!({
                            "id": t.id, "role": t.role, "ts_unix": t.ts_unix, "text": t.text,
                        })).collect::<Vec<_>>(),
                        "bm25_rank": r.bm25_rank,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            if results.is_empty() {
                println!("no transcript turns matched '{query}'");
                return Ok(());
            }
            for r in &results {
                println!(
                    "── [{}] session {} (bm25 {:.4}) ──",
                    r.matched.role, r.matched.session_id, r.bm25_rank
                );
                for b in &r.before {
                    println!("  ^ [{}] {}: {}", b.role, b.ts_unix, b.text);
                }
                println!(
                    "  * [{}] {}: {}",
                    r.matched.role, r.matched.ts_unix, r.matched.text
                );
                for a in &r.after {
                    println!("  v [{}] {}: {}", a.role, a.ts_unix, a.text);
                }
            }
        }
    }
    Ok(())
}

/// Image → embedding store similarity recall.
/// GOLD-ADAPT-ODY-25 — render the session-card keyword search.
fn run_session_search(query: &str, limit: usize, output: crate::cli::OutputFormat) -> Result<()> {
    use crate::cli::OutputFormat;
    let home = FreedomConfig::default_neoth_home();
    let cards = crate::memory::hindsight::list_cards(&home);
    let hits = crate::memory::session_search::search_session_cards(&cards, query, limit);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = hits
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "session_id": crate::security::redact::sanitize_tool_output(&h.card.session_id),
                        "display_name": h.card.display_name.as_deref().map(crate::security::redact::sanitize_tool_output),
                        "started_at_unix": h.card.started_at_unix,
                        "topics": h.card.top_topics.iter().map(|topic| crate::security::redact::sanitize_tool_output(topic)).collect::<Vec<_>>(),
                        "summary": crate::security::redact::sanitize_tool_output(&h.card.one_line_summary),
                        "score": h.score,
                        "matched_fields": h.matched_fields.iter().map(|field| crate::security::redact::sanitize_tool_output(field)).collect::<Vec<_>>(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!("no sessions matched '{query}'");
                return Ok(());
            }
            for h in &hits {
                let title = h
                    .card
                    .display_name
                    .as_deref()
                    .unwrap_or(&h.card.one_line_summary);
                let session_id = crate::security::redact::sanitize_tool_output(&h.card.session_id);
                let title = crate::security::redact::sanitize_tool_output(title);
                let matched_fields = h
                    .matched_fields
                    .iter()
                    .map(|field| crate::security::redact::sanitize_tool_output(field))
                    .collect::<Vec<_>>()
                    .join("+");
                println!(
                    "[{}] {} (score {}, matched {})",
                    session_id, title, h.score, matched_fields
                );
                if !h.card.top_topics.is_empty() {
                    let topics = h
                        .card
                        .top_topics
                        .iter()
                        .map(|topic| crate::security::redact::sanitize_tool_output(topic))
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("    topics: {topics}");
                }
            }
        }
    }
    Ok(())
}

/// QM-18 citation-check CLI surface. Reads text from `arg` directly,
/// or from stdin when `arg == "-"`. Runs `recall::citation_check::
/// audit_offline` + renders the verdict per the global `--output`
/// flag.
async fn run_citation_check(arg: &str, output: crate::cli::OutputFormat) -> Result<()> {
    use crate::recall::citation_check::{CitationVerdict, audit_offline};

    let text = if arg == "-" {
        let mut buf = String::new();
        use std::io::Read;
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read citation-check input from stdin")?;
        buf
    } else {
        arg.to_string()
    };

    let audit = audit_offline(&text);
    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&audit)?);
        }
        crate::cli::OutputFormat::Table => {
            println!("# citation-check: verdict = {}\n", audit.verdict.as_str());
            if audit.citations.is_empty() {
                println!("No structural citations extracted (DOI / arXiv / ISBN / publisher URL).");
            } else {
                println!("Extracted citations ({}):", audit.citations.len());
                for c in &audit.citations {
                    println!("  [{}] {}", c.kind.as_str(), c.normalised);
                }
            }
            println!();
            if audit.signals.is_empty() {
                println!("No contamination signals fired.");
            } else {
                println!("Contamination signals ({}):", audit.signals.len());
                for s in &audit.signals {
                    println!("  [{}] {}", s.kind, s.message);
                    if !s.citation_raw.is_empty() {
                        println!("      citation: {}", s.citation_raw);
                    }
                }
            }
            println!();
            match audit.verdict {
                CitationVerdict::Clean => {
                    println!(
                        "Verdict: CLEAN. No further action needed — citations look structurally \
                         valid. Live API lookup (Crossref/OpenAlex/SemanticScholar) ships when \
                         the outbound HTTP allowlist extends."
                    );
                }
                CitationVerdict::NeedsReview => {
                    println!(
                        "Verdict: NEEDS_REVIEW. Resolve every signal above before shipping the \
                         text. Tip: pair with `neoth recall \"<author year>\"` to find \
                         supporting context already in your memory."
                    );
                }
            }
        }
    }
    Ok(())
}

/// GOLD-WIRE-07 — resolve the HNSW snapshot path when the operator opted into
/// `memory.vector_index.backend: hnsw`, else `None` (brute-force). Missing
/// config uses the compiled brute-force default; malformed existing policy is
/// surfaced rather than silently changing the selected index backend.
fn configured_hnsw_path() -> Result<Option<std::path::PathBuf>> {
    let cfg = crate::config::FreedomConfig::load_from_default_path_or_default()?;
    Ok(match cfg.memory.vector_index.backend {
        crate::config::VectorBackend::Hnsw => Some(crate::memory::embeddings::hnsw_snapshot_path(
            &crate::config::FreedomConfig::default_neoth_home(),
        )),
        crate::config::VectorBackend::BruteForce => None,
    })
}

async fn run_similar_to_image(
    conn: &Connection,
    image_path: PathBuf,
    args: &RecallArgs,
) -> Result<()> {
    if !image_path.exists() {
        anyhow::bail!(
            "--similar-to: file does not exist: {}",
            image_path.display()
        );
    }
    let kind_filter = parse_kind_filter(&args.similar_kind);
    let query = compute_clip_image_query(&image_path)
        .await
        .with_context(|| {
            format!(
                "compute CLIP image embedding for {} \
             (did you `neoth models pull clip` first?)",
                image_path.display()
            )
        })?;
    // GOLD-WIRE-07: dispatch to the HNSW index when the operator opted in, the
    // snapshot exists, AND the corpus is past the brute-force ceiling (below it
    // a per-query cold HNSW load is slower than the scan). Brute-force
    // otherwise, and always for kind-scoped queries (HNSW is not kind-filterable).
    let hnsw = configured_hnsw_path()?.filter(|_| {
        embeddings::hnsw_beneficial_for_corpus(embeddings::count(conn).unwrap_or(0) as usize)
    });
    let hits =
        embeddings::find_similar_dispatch(conn, &query, kind_filter, args.limit, hnsw.as_deref())
            .context("similarity search")?;
    render_similarity(&hits, args.output, &image_path.display().to_string());
    Ok(())
}

/// Text → embedding store similarity recall.
async fn run_similar_to_text(conn: &Connection, prompt: String, args: &RecallArgs) -> Result<()> {
    if prompt.trim().is_empty() {
        anyhow::bail!("--similar-to-text: prompt is empty");
    }
    let kind_filter = parse_kind_filter(&args.similar_kind);
    let query = compute_clip_text_query(&prompt).await.with_context(|| {
        "compute CLIP text embedding \
         (did you `neoth models pull clip` first?)"
            .to_string()
    })?;
    // GOLD-WIRE-07: dispatch to the HNSW index when the operator opted in, the
    // snapshot exists, AND the corpus is past the brute-force ceiling (below it
    // a per-query cold HNSW load is slower than the scan). Brute-force
    // otherwise, and always for kind-scoped queries (HNSW is not kind-filterable).
    let hnsw = configured_hnsw_path()?.filter(|_| {
        embeddings::hnsw_beneficial_for_corpus(embeddings::count(conn).unwrap_or(0) as usize)
    });
    let hits =
        embeddings::find_similar_dispatch(conn, &query, kind_filter, args.limit, hnsw.as_deref())
            .context("similarity search")?;
    render_similarity(&hits, args.output, &format!("\"{prompt}\""));
    Ok(())
}

fn parse_kind_filter(s: &str) -> Option<&str> {
    match s {
        "any" | "" => None,
        other => Some(other),
    }
}

async fn compute_clip_image_query(image_path: &std::path::Path) -> Result<Vec<f32>> {
    let bytes =
        std::fs::read(image_path).with_context(|| format!("read {}", image_path.display()))?;
    let img = image::load_from_memory(&bytes).context("decode image")?;
    let rgb = img.to_rgb8();
    let width = rgb.width();
    let height = rgb.height();
    let engine = clip_engine::ClipEngine::new(None).await?;
    engine.embed_image(rgb.as_raw(), width, height).await
}

async fn compute_clip_text_query(prompt: &str) -> Result<Vec<f32>> {
    let engine = clip_engine::ClipEngine::new(None).await?;
    engine.embed_text(prompt).await
}

fn render_similarity(
    hits: &[embeddings::SimilarHit],
    output: crate::cli::OutputFormat,
    query_label: &str,
) {
    use crate::cli::OutputFormat;
    match output {
        OutputFormat::Json => {
            // Render Vec<SimilarHit> as JSON via a flat array.
            let rows: Vec<serde_json::Value> = hits
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "id": h.id,
                        "source_kind": h.source_kind,
                        "source_ref": h.source_ref,
                        "model": h.model,
                        "similarity": h.similarity,
                        "created_at": h.created_at,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&rows)
                    .expect("similarity rows contain only serializable values")
            );
        }
        OutputFormat::Jsonl => {
            for h in hits {
                let line = serde_json::json!({
                    "id": h.id,
                    "source_kind": h.source_kind,
                    "source_ref": h.source_ref,
                    "model": h.model,
                    "similarity": h.similarity,
                    "created_at": h.created_at,
                });
                println!("{line}");
            }
            println!(
                "{}",
                serde_json::json!({"neoth_stream":"done","count":hits.len()})
            );
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!(
                    "no embeddings similar to {query_label} — corpus may be empty or all dimensions mismatched"
                );
                return;
            }
            println!("# {} hit(s) similar to {query_label}", hits.len());
            for h in hits {
                println!(
                    "  [{sim:.4}] {kind:<14} {ref_}",
                    sim = h.similarity,
                    kind = h.source_kind,
                    ref_ = h.source_ref,
                );
            }
        }
    }
}

fn render(hits: &[EpisodeHit], output: crate::cli::OutputFormat, query: &str) {
    use crate::cli::OutputFormat;
    match output {
        OutputFormat::Jsonl => {
            for h in hits {
                let line =
                    serde_json::to_string(h).expect("EpisodeHit contains only serializable fields");
                println!("{line}");
            }
            println!(
                "{}",
                serde_json::json!({"neoth_stream":"done","count":hits.len()})
            );
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hits)
                    .expect("EpisodeHit contains only serializable fields")
            );
        }
        OutputFormat::Table => {
            if hits.is_empty() {
                println!("no hits for `{query}`");
                return;
            }
            println!("# {} hit(s) for `{query}`", hits.len());
            for h in hits {
                let when = format_ts(h.ts_ns);
                let chan = h.channel.as_deref().unwrap_or("-");
                println!("  [{when}] ({chan}) {}", h.text);
            }
        }
    }
}

fn format_ts(ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ns / 1_000_000_000;
    let nanos = (ns % 1_000_000_000) as u32;
    match DateTime::<Utc>::from_timestamp(secs, nanos) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("ts={secs}"),
    }
}

/// M-02 (Session 24): per-reinforcement payload for the audit
/// frame emitted by `emit_reinforce_audit_frames`. Mirrors the
/// daemon-path frame shape so `neoth wal show --type
/// importance_reinforced` renders CLI-recall reinforcements
/// identically to daemon-path reinforcements.
struct ReinforceFrame {
    tier: String,
    old: f64,
    new: f64,
}

/// M-02 (Session 24): close the tamper-evidence hole where CLI
/// `neoth recall` mutated row importance without emitting
/// `EVENT_TYPE_IMPORTANCE_REINFORCED` (0x93). Opens a short-lived
/// WAL writer (only when there's at least one reinforcement to
/// emit), writes one frame per reinforcement, drops the writer.
/// Best-effort throughout — failures log warn but never abort the
/// recall reply.
async fn emit_reinforce_audit_frames(events: &[(i64, ReinforceFrame)]) {
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    if let Err(e) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(
            error = %e,
            "M-02: WAL directory creation failed for IMPORTANCE_REINFORCED audit \
             frames — recall reply continues, audit chain has a hole"
        );
        return;
    }
    let segment_path =
        crate::wal::writer::unique_standalone_segment_path(&wal_dir, "recall-reinforce");
    let (writer, completion) =
        match crate::wal::writer::spawn_for_home_with_completion(segment_path, home) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "M-02: WAL writer spawn failed for IMPORTANCE_REINFORCED audit \
                     frames — recall reply continues, audit chain has a hole"
                );
                return;
            }
        };
    let now_unix = crate::time::now_unix_secs();
    for (event_id, frame) in events {
        let payload = serde_json::to_vec(&serde_json::json!({
            "source": "cli_recall",
            "event_id": event_id,
            "tier": frame.tier,
            "old_importance": frame.old,
            "new_importance": frame.new,
            "ts_unix": now_unix,
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_IMPORTANCE_REINFORCED,
            &payload,
        )
        .build();
        if let Err(e) = writer.try_append_sync(header, payload) {
            tracing::warn!(
                event_id = *event_id,
                error = %e,
                "M-02: IMPORTANCE_REINFORCED frame append failed (audit chain has a row gap)"
            );
        }
    }
    drop(writer);
    if let Err(e) = completion.wait().await {
        tracing::warn!(
            error = %e,
            "M-02: IMPORTANCE_REINFORCED audit WAL finalization failed \
             (recall reply continues, audit chain may have a tail gap)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_RAW_TEXT;
    use crate::wal::frame::encode_frame;
    use crate::wal::header::{CRC_LEN, HEADER_BODY_LEN, PREAMBLE_LEN};
    use crate::wal::segment_header::SegmentHeader;
    use crate::wal::{EventFlags, EventHeaderV2, EventId, Hlc, Importance, NodeId, SessionId};
    use tempfile::tempdir;
    use tokio::fs::write;

    fn raw_text_frame(id: u64, ts: u64, body: &str) -> Vec<u8> {
        let payload = body.as_bytes().to_vec();
        let header = EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE_RAW_TEXT,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload.len() + CRC_LEN) as u32,
            payload_len: payload.len() as u32,
            generation: 0,
            event_id: EventId(id),
            hlc: Hlc::new(ts, 0).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: crate::wal::types::WalScope::UNSET,
            category: crate::wal::types::WalCategory::UNSET,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: xxhash_rust::xxh3::xxh3_64(&payload),
        };
        encode_frame(&header, &payload)
    }

    #[tokio::test]
    async fn recall_finds_matching_text() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let db = dir.path().join("views.db");

        let mut bytes = Vec::new();
        let sh = SegmentHeader::new(0, 1, 0, 0, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        bytes.extend_from_slice(&raw_text_frame(
            1,
            1_700_000_000_000_000_001,
            "the wifi password is acme",
        ));
        bytes.extend_from_slice(&raw_text_frame(
            2,
            1_700_000_000_000_000_002,
            "nothing about the network",
        ));
        bytes.extend_from_slice(&raw_text_frame(
            3,
            1_700_000_000_000_000_003,
            "WiFi is down again",
        ));
        write(&seg, &bytes).await.unwrap();

        let args = RecallArgs {
            hubs: false,
            communities: false,
            query: "wifi".to_string(),
            limit: 10,
            db: Some(db.clone()),
            wal_segment: Some(seg.clone()),
            no_index_pass: false,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
            sessions: None,
            session_folders: false,
            transcript: None,
            context_rows: 2,
            classify: None,
            downvote: None,
            upvote: None,
            graph: None,
            graph_depth: 2,
            extract: None,
            assoc: None,
            bootstrap_assoc: false,
            scorecard: None,
            include_dreams: false,
            dreams_lookback_days: 7,
            dreams_max_hits: 5,
            output: crate::cli::OutputFormat::Table,
        };
        // The render goes to stdout in test; here we just need run_recall
        // to complete without error, and we re-query manually.
        run_recall(args).await.expect("run_recall");

        // Re-open db, count hits via LIKE %wifi% NOCASE = 2.
        let conn = store::open(&db).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_episode WHERE text LIKE '%wifi%' COLLATE NOCASE",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 2,
            "two of three episodes mention wifi (case-insensitive)"
        );
        let feedback: (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(feedback_success), 0), \
                        COALESCE(SUM(feedback_failure), 0) \
                 FROM idx_memory_links",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(
            feedback.0 >= 1,
            "normal recall still learns co-access edges"
        );
        assert_eq!(
            (feedback.1, feedback.2),
            (0, 0),
            "showing results is exposure, not explicit success/failure feedback"
        );
    }

    #[test]
    fn recall_warm_like_surfaces_warm_tier_rows_with_correct_tier_label() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        // One retained event + one summary (NULL event_id) — both contain "berlin".
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-04-01', 100, 'capital of Germany is Berlin', 'h1', 0.8, 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-04-02', NULL, 'Berlin summary block', 'h2', 0.5, 2, 0)",
            [],
        )
        .unwrap();

        let hits = recall_warm_like(&conn, "berlin", 10).expect("warm recall");

        assert_eq!(hits.len(), 2, "both warm rows surface");
        assert!(hits.iter().all(|h| h.tier == "warm"));
        // Retained row keeps its real event_id 100; summary gets -id (negative).
        let ids: Vec<i64> = hits.iter().map(|h| h.event_id).collect();
        assert!(ids.contains(&100), "retained event_id preserved");
        assert!(
            ids.iter().any(|&i| i < 0),
            "summary row has negative sentinel id"
        );
        // Importance comes through verbatim.
        assert!(hits.iter().any(|h| h.importance == Some(0.8)));
    }

    #[test]
    fn recall_cold_like_surfaces_cold_tier_rows_with_correct_tier_label() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        conn.execute(
            "INSERT INTO idx_longterm \
             (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
             VALUES (200, 'never forget the keys are under the mat', 'h', 0.9, 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_longterm \
             (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
             VALUES (201, 'random other event', 'h2', 0.3, 2, 0)",
            [],
        )
        .unwrap();

        let hits = recall_cold_like(&conn, "keys", 10).expect("cold recall");

        assert_eq!(hits.len(), 1, "only one cold row matches");
        assert_eq!(hits[0].tier, "cold");
        assert_eq!(hits[0].event_id, 200);
        assert_eq!(hits[0].importance, Some(0.9));
    }

    #[test]
    fn community_member_loader_covers_all_tiers_deterministically() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        conn.execute_batch(
            "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance) \
                 VALUES (300, 16, 30, 'hot member', 'hot-hash', 0.7); \
             INSERT INTO idx_consolidated \
                 (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
                 VALUES ('retained', '2026-04-01', 100, 'warm member', 'warm-hash', 0.8, 10, 0); \
             INSERT INTO idx_longterm \
                 (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
                 VALUES (200, 'cold member', 'cold-hash', 0.9, 20, 0); \
             INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance) \
                 VALUES (400, 16, 40, 'other community', 'other-hash', 0.6); \
             INSERT INTO idx_memory_communities (node_id, community_id) \
                 VALUES (300, 7), (100, 7), (200, 7), (400, 8);",
        )
        .unwrap();

        let hits = load_community_members(&conn, 7, 10).expect("community members");
        let ids: Vec<i64> = hits.iter().map(|hit| hit.event_id).collect();
        let tiers: Vec<&str> = hits.iter().map(|hit| hit.tier.as_str()).collect();

        assert_eq!(ids, vec![100, 200, 300]);
        assert_eq!(tiers, vec!["warm", "cold", "hot"]);
        assert_eq!(
            load_community_members(&conn, 7, 2).unwrap().len(),
            2,
            "candidate loading stays bounded"
        );
    }

    #[test]
    fn recall_groundtruth_like_returns_matching_active_facts() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (1, 'server IP is 192.0.2.1', 'manual', 'global', 1, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (2, 'never reboot server', 'manual', 'global', 2, NULL)",
            [],
        )
        .unwrap();
        // Revoked row must NOT surface even if it matches the query.
        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (3, 'old server fact', 'manual', 'global', 3, 100)",
            [],
        )
        .unwrap();

        let hits = recall_groundtruth_like(&conn, "server", 10).expect("gt recall");

        assert_eq!(hits.len(), 2, "active matches surface, revoked is hidden");
        assert!(hits.iter().all(|h| h.tier == "groundtruth"));
        assert!(hits.iter().all(|h| h.importance.is_none()));
        assert!(hits.iter().any(|h| h.event_id == 1));
        assert!(hits.iter().any(|h| h.event_id == 2));
        assert!(!hits.iter().any(|h| h.event_id == 3));
    }

    #[test]
    fn rank_in_place_orders_cross_tier_by_composite_score() {
        // Build three hits, one per tier, each freshly accessed (days_since=0).
        // Scores at days_since=0:
        //   hot  imp=0.50 → 0.50 * 1.00 = 0.50
        //   warm imp=0.80 → 0.80 * 0.85 = 0.68
        //   cold imp=0.90 → 0.90 * 0.60 = 0.54
        // Expected order: warm > cold > hot.
        let now_ns: u64 = 10 * 86_400 * 1_000_000_000;
        let mk = |tier: &str, imp: f64, ts_ns: i64| EpisodeHit {
            event_id: 1,
            event_type: 0,
            ts_ns,
            text: "x".to_string(),
            text_hash: "h".to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: tier.to_string(),
            importance: Some(imp),
            access_count: 0,
            trust: 1,
        };
        let mut rows = vec![
            mk("hot", 0.50, now_ns as i64),
            mk("warm", 0.80, now_ns as i64),
            mk("cold", 0.90, now_ns as i64),
        ];

        rank_in_place(&mut rows, now_ns);

        assert_eq!(rows[0].tier, "warm", "warm wins on composite score");
        assert_eq!(
            rows[1].tier, "cold",
            "cold beats hot at this importance gap"
        );
        assert_eq!(rows[2].tier, "hot");
    }

    #[test]
    fn association_degree_is_a_bounded_recall_score_component() {
        let now_ns: u64 = 10 * 86_400 * 1_000_000_000;
        let mk = |event_id: i64| EpisodeHit {
            event_id,
            event_type: 0,
            ts_ns: now_ns as i64,
            text: "same topic".to_string(),
            text_hash: format!("h-{event_id}"),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".to_string(),
            importance: Some(0.6),
            access_count: 0,
            trust: 1,
        };
        let mut rows = vec![mk(1), mk(2)];
        let degrees = std::collections::HashMap::from([(1, 0), (2, 32)]);
        rank_in_place_with_degrees(&mut rows, now_ns, &degrees);
        assert_eq!(rows[0].event_id, 2, "the graph hub receives the tie boost");

        let plain = composite_score(&rows[0], now_ns, 86_400.0 * 1_000_000_000.0);
        let boosted =
            composite_score_with_degree(&rows[0], now_ns, 86_400.0 * 1_000_000_000.0, 1_000);
        assert!(boosted > plain);
        assert!(
            boosted <= plain * 1.100_000_1,
            "degree must never boost a hit by more than ten percent"
        );
    }

    #[test]
    fn frequently_recalled_cold_row_repromotes_above_an_idle_peer() {
        // JV-MEM-09: two cold hits, same age + importance — the one with a high
        // recall access_count re-promotes to a Hot ranking WEIGHT and outranks the
        // idle peer. (Recency stays on the cold age-curve, so the old row isn't
        // punished by a hot tier's short half-life — that was the design trap.)
        const DAY: u64 = 86_400 * 1_000_000_000;
        let now_ns: u64 = 200 * DAY;
        let ts = (now_ns - 120 * DAY) as i64; // 120 days old → cold age tier
        let mk = |event_id: i64, access_count: u32| EpisodeHit {
            event_id,
            event_type: 0,
            ts_ns: ts,
            text: "shared topic".to_string(),
            text_hash: "h".to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "cold".to_string(),
            importance: Some(0.85),
            access_count,
            trust: 1,
        };
        let mut rows = vec![mk(1, 0), mk(2, 12)];
        rank_in_place(&mut rows, now_ns);
        assert_eq!(
            rows[0].event_id, 2,
            "the frequently-recalled cold row re-promotes and ranks first"
        );
        assert_eq!(rows[1].event_id, 1);
    }

    #[test]
    fn higher_trust_outranks_equal_lower_trust_peer() {
        // JV-MEM-14: two identical hot hits except source trust — the operator-
        // explicit (trust 2) one ranks above the medium (trust 1) one.
        let now_ns: u64 = 5 * 86_400 * 1_000_000_000;
        let mk = |event_id: i64, trust: u8| EpisodeHit {
            event_id,
            event_type: 1,
            ts_ns: now_ns as i64,
            text: "same topic".to_string(),
            text_hash: "h".to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".to_string(),
            importance: Some(0.6),
            access_count: 0,
            trust,
        };
        let mut rows = vec![mk(1, 1), mk(2, 2)];
        rank_in_place(&mut rows, now_ns);
        assert_eq!(rows[0].event_id, 2, "higher-trust hit ranks first");
        assert_eq!(rows[1].event_id, 1);
    }

    #[test]
    fn length_normalization_penalises_verbose_entries() {
        // JV-MEM-07: two hits with identical tier/importance/age but different
        // text length — the SHORTER ranks higher (verbose entries don't win on
        // raw keyword density; entries ≤ the 300-char anchor are unpenalised).
        let now_ns: u64 = 10 * 86_400 * 1_000_000_000;
        let mk = |id: i64, text: String| EpisodeHit {
            event_id: id,
            event_type: 0,
            ts_ns: now_ns as i64,
            text,
            text_hash: "h".to_string(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".to_string(),
            importance: Some(0.8),
            access_count: 0,
            trust: 1,
        };
        let mut rows = vec![
            mk(1, "x".repeat(1200)),         // verbose → length-penalised
            mk(2, "short note".to_string()), // short → unpenalised, outranks it
        ];
        rank_in_place(&mut rows, now_ns);
        assert_eq!(
            rows[0].event_id, 2,
            "the short entry outranks the verbose one"
        );
        assert_eq!(rows[1].event_id, 1);
    }

    #[tokio::test]
    async fn run_recall_rejects_empty_query_without_similar_to() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let _ = store::open(&db).unwrap();
        let args = RecallArgs {
            hubs: false,
            communities: false,
            query: "   ".to_string(), // whitespace-only treated as empty
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
            sessions: None,
            session_folders: false,
            transcript: None,
            context_rows: 2,
            classify: None,
            downvote: None,
            upvote: None,
            graph: None,
            graph_depth: 2,
            extract: None,
            assoc: None,
            bootstrap_assoc: false,
            scorecard: None,
            include_dreams: false,
            dreams_lookback_days: 7,
            dreams_max_hits: 5,
            output: crate::cli::OutputFormat::Json,
        };
        let err = run_recall(args).await.unwrap_err();
        assert!(
            err.to_string().contains("query is empty"),
            "expected empty-query bail, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_recall_rejects_both_similar_flags() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let _ = store::open(&db).unwrap();
        let args = RecallArgs {
            hubs: false,
            communities: false,
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("x.png")),
            similar_to_text: Some("sunset".to_string()),
            similar_kind: "image".to_string(),
            citation_check: None,
            sessions: None,
            session_folders: false,
            transcript: None,
            context_rows: 2,
            classify: None,
            downvote: None,
            upvote: None,
            graph: None,
            graph_depth: 2,
            extract: None,
            assoc: None,
            bootstrap_assoc: false,
            scorecard: None,
            include_dreams: false,
            dreams_lookback_days: 7,
            dreams_max_hits: 5,
            output: crate::cli::OutputFormat::Json,
        };
        let err = run_recall(args).await.unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "expected mutex bail, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_recall_similar_to_errors_when_image_missing() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let _ = store::open(&db).unwrap();
        let args = RecallArgs {
            hubs: false,
            communities: false,
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("not-a-file.png")),
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
            sessions: None,
            session_folders: false,
            transcript: None,
            context_rows: 2,
            classify: None,
            downvote: None,
            upvote: None,
            graph: None,
            graph_depth: 2,
            extract: None,
            assoc: None,
            bootstrap_assoc: false,
            scorecard: None,
            include_dreams: false,
            dreams_lookback_days: 7,
            dreams_max_hits: 5,
            output: crate::cli::OutputFormat::Json,
        };
        let err = run_recall(args).await.unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected missing-file bail, got: {err}"
        );
    }

    // ── V02-05 4-tier audit ───────────────────────────────────────────────
    //
    // Inserts a matching row into each of hot / warm / cold /
    // groundtruth, runs the same query that the production recall
    // path executes, and asserts every tier surfaces in the result.
    // Pins the v0.2 acceptance criterion that `neoth recall` is not
    // silently dropping a tier (e.g. a future refactor that forgets
    // to merge `cold` into the final rank-by-composite-score pass).

    #[tokio::test]
    async fn answer_conversational_recall_finds_seeded_episode_and_ignores_non_recall() {
        // GOLD-WIRE-02: a recall-intent prompt is answered from idx_episode;
        // a normal prompt returns None (falls through to the provider).
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        {
            let conn = store::open(&db).unwrap();
            conn.execute(
                "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (10, 1, 1700000000000000000, 'rust ist gut und schnell', 'h1', 0.5, 0)",
                [],
            )
            .unwrap();
        }

        // Recall intent → memory reply that quotes the seeded episode.
        let reply = answer_conversational_recall("Do you remember when we talked about rust?", &db)
            .await
            .expect("recall intent must produce a reply");
        assert!(reply.starts_with("Yes — "), "english template: {reply}");
        assert!(
            reply.contains("rust ist gut"),
            "reply must quote the episode: {reply}"
        );

        // Normal prompt → None → falls through to the provider unchanged.
        assert!(
            answer_conversational_recall("What is the capital of France?", &db)
                .await
                .is_none()
        );

        // Recall intent but no match → Some(localized "nothing found"), NOT None
        // (the short-circuit still fires; the operator learns the recall ran).
        let miss =
            answer_conversational_recall("Do you remember when we talked about zzzqqq?", &db)
                .await
                .expect("recall intent fires even with no hit");
        assert!(
            miss.contains("Nothing found"),
            "empty match → localized miss: {miss}"
        );
    }

    #[tokio::test]
    async fn conversational_channel_recall_sanitizes_legacy_episode_text() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let secret = concat!("sk-", "FAKE_TEST_CHANNEL_RECALL_AAAAAAAAAA");
        let legacy = format!(
            "rust memory sk-\x1b[31m{}\x1b[0m remains useful",
            &secret[3..]
        );
        {
            let conn = store::open(&db).unwrap();
            conn.execute(
                "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (11, 1, 1700000000000000001, ?1, 'safe-recall', 0.5, 0)",
                params![legacy],
            )
            .unwrap();
        }

        let reply = answer_conversational_recall("Do you remember when we talked about rust?", &db)
            .await
            .expect("recall intent must produce a channel-ready reply");
        assert!(reply.contains("rust memory"), "{reply}");
        assert!(reply.contains("[REDACTED:openai_key]"), "{reply}");
        assert!(!reply.contains(secret), "{reply}");
        assert!(!reply.contains('\x1b'), "{reply:?}");
    }

    #[tokio::test]
    async fn answer_conversational_recall_empty_db_returns_nothing_found_not_error() {
        // GOLD-WIRE-02 best-effort: a missing/empty views.db must not error —
        // the recall short-circuit still fires and renders "nothing found".
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.db");
        let reply = answer_conversational_recall(
            "weißt du noch als wir über rust geredet haben?",
            &missing,
        )
        .await
        .expect("recall intent fires regardless of DB state");
        assert!(
            reply.starts_with("Ich finde keine Erinnerung"),
            "german miss line: {reply}"
        );
    }

    // GOLD-WIRE-02b — channel recall is served ONLY to the provable operator
    // (sender uuid == pinned operator uuid). Stricter than learn_factor: an
    // unpinned operator or a sender with no uuid never authorizes recall.
    #[test]
    fn channel_recall_authorized_only_for_provable_operator() {
        // Sender's resolved uuid matches the pinned operator uuid → authorized.
        assert!(channel_recall_authorized(
            Some("op-uuid-1"),
            Some("op-uuid-1")
        ));
        // A different sender on the same channel → never gets the operator's memory.
        assert!(!channel_recall_authorized(
            Some("rando-uuid"),
            Some("op-uuid-1")
        ));
        // Operator uuid NOT pinned → recall is withheld from everyone on the
        // channel surface (deliberately stricter than channel-weights learning).
        assert!(!channel_recall_authorized(Some("op-uuid-1"), None));
        assert!(!channel_recall_authorized(None, None));
        // Sender carries no resolved uuid → cannot prove they're the operator.
        assert!(!channel_recall_authorized(None, Some("op-uuid-1")));
    }

    #[test]
    fn recall_four_tier_acceptance_every_tier_shows_up_in_results() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        // Single shared keyword across all four tiers — "neoth".
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (10, 1, 1700000000000000000, 'hot tier neoth fact', 'h-hot', 0.5, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_consolidated (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-04-01', 20, 'warm tier neoth summary', 'h-warm', 0.7, 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_longterm (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
             VALUES (30, 'cold tier neoth archive', 'h-cold', 0.9, 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (40, 'neoth ground truth fact', 'manual', 'global', 1, NULL)",
            [],
        )
        .unwrap();

        // Run each per-tier recall + merge as the production path does
        // (`run_recall` itself opens a fresh connection at the default
        // path; this test exercises the same composition functions
        // against the test DB).
        let hot = recall_like(&conn, "neoth", 10).expect("hot");
        let warm = recall_warm_like(&conn, "neoth", 10).expect("warm");
        let cold = recall_cold_like(&conn, "neoth", 10).expect("cold");
        let gt = recall_groundtruth_like(&conn, "neoth", 10).expect("gt");

        assert!(!hot.is_empty(), "hot tier must surface a match");
        assert!(!warm.is_empty(), "warm tier must surface a match");
        assert!(!cold.is_empty(), "cold tier must surface a match");
        assert!(!gt.is_empty(), "groundtruth tier must surface a match");

        // Composite merge: ground-truth prepended; episodic ranked.
        let mut episodic = Vec::new();
        episodic.extend(hot);
        episodic.extend(warm);
        episodic.extend(cold);
        rank_in_place(&mut episodic, 0);

        let mut rows = Vec::new();
        rows.extend(gt);
        rows.extend(episodic);

        let tiers_present: std::collections::HashSet<&str> =
            rows.iter().map(|h| h.tier.as_str()).collect();
        for required in &["hot", "warm", "cold", "groundtruth"] {
            assert!(
                tiers_present.contains(required),
                "tier `{required}` missing from merged result: tiers={tiers_present:?}"
            );
        }

        // Ground-truth must come FIRST in the merged result.
        assert_eq!(
            rows[0].tier, "groundtruth",
            "ground-truth must prepend the episodic ranking"
        );
    }

    #[tokio::test]
    async fn scorecard_short_circuit_runs_over_recorded_events() {
        // GOLD-ADAPT-MEM-15: seed a few recall-outcome samples, then run recall
        // in scorecard mode and assert it returns Ok (renders, no search/WAL).
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();
        for i in 0..12i64 {
            let tier = if i < 2 { "skip" } else { "single" };
            store::record_recall_event(&conn, i, if i < 2 { 0 } else { 4 }, 1, tier).unwrap();
        }
        store::record_recall_latency(&conn, 1, 25.0).unwrap();
        drop(conn);

        let args = RecallArgs {
            hubs: false,
            communities: false,
            query: String::new(),
            limit: 20,
            db: Some(db.clone()),
            wal_segment: None,
            no_index_pass: true,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
            sessions: None,
            session_folders: false,
            transcript: None,
            context_rows: 2,
            classify: None,
            downvote: None,
            upvote: None,
            graph: None,
            graph_depth: 2,
            extract: None,
            assoc: None,
            bootstrap_assoc: false,
            scorecard: Some(500),
            include_dreams: false,
            dreams_lookback_days: 7,
            dreams_max_hits: 5,
            output: crate::cli::OutputFormat::Json,
        };
        run_recall(args).await.expect("scorecard mode returns Ok");

        // Verify the underlying scorecard reflects the seeded events.
        let conn = store::open(&db).unwrap();
        let card = store::recall_scorecard(&conn, 500).unwrap();
        assert_eq!(card.total_recalls, 12);
        assert!(
            (card.hit_rate - 1.0).abs() < 1e-9,
            "all 10 non-skip returned rows"
        );
        assert!(card.data_sufficient);
    }

    // ── GOLD-ADAPT-JV-MEM-10 — three-lane recall ─────────────────────────

    #[test]
    fn query_three_lanes_populates_all_three_lanes() {
        use crate::memory::region_router::route_query;
        use crate::memory::store;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();
        // Episodes lane: an idx_episode row matching the prompt.
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1000, ?1, 'h', 0.7, 0)",
            params!["debugging the payment flow last week"],
        )
        .unwrap();
        // Canonical lane: a VERIFIED ground-truth fact matching the prompt.
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (10, ?1, 'op', 'global', 1000, 'verified')",
            params!["the payment provider is Stripe"],
        )
        .unwrap();
        // Contradiction lane: two verified facts + a PENDING contradiction; both
        // statements mention 'payment' so the prompt-relevance filter matches.
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (11, ?1, 'op', 'global', 1001, 'verified'), (12, ?2, 'op', 'global', 1002, 'verified')",
            params!["the payment retry limit is 3", "the payment retry limit is 5"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at, decision) \
             VALUES (11, 12, 0.9, 1003, 'pending')",
            [],
        )
        .unwrap();

        let plan = route_query("payment");
        let out = query_three_lanes(&conn, &plan, "payment", 5);
        assert!(
            out.canonical.iter().any(|h| h.text.contains("Stripe")),
            "canonical lane must surface the verified ground-truth fact"
        );
        assert!(
            !out.episodes.is_empty(),
            "episodes lane must surface the matching episode"
        );
        assert_eq!(
            out.contradictions.len(),
            1,
            "exactly one pending contradiction matches 'payment'"
        );
        let c = &out.contradictions[0];
        assert!(
            c.statement_a.contains("retry limit") && c.statement_b.contains("retry limit"),
            "contradiction JOIN must carry BOTH statements' text, not fact ids: {c:?}"
        );
        assert!((c.confidence - 0.9).abs() < 1e-4);
        assert!(!out.is_empty());
    }

    #[test]
    fn query_three_lanes_sanitizes_every_provider_bound_lane() {
        use crate::memory::region_router::route_query;
        use crate::memory::store;

        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let secret = concat!("sk-", "FAKE_TEST_LANES_AAAAAAAAAAAAAAAAA");
        let colored = format!("sk-\x1b[35m{}\x1b[0m", &secret[3..]);
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (30, 1, 1000, ?1, 'lane-episode', 0.7, 0)",
            params![format!("payment episode {colored}")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (31, ?1, 'op', 'global', 1000, 'verified'), \
                    (32, ?2, 'op', 'global', 1001, 'verified'), \
                    (33, ?3, 'op', 'global', 1002, 'verified')",
            params![
                format!("payment canonical {colored}"),
                format!("payment contradiction a {colored}"),
                format!("payment contradiction b {colored}"),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at, decision) \
             VALUES (32, 33, 0.9, 1003, 'pending')",
            [],
        )
        .unwrap();

        for output in [
            query_three_lanes(&conn, &route_query("payment"), "payment", 5),
            query_three_lanes_checked(&conn, &route_query("payment"), "payment", 5).unwrap(),
        ] {
            let mut rendered = output
                .canonical
                .iter()
                .chain(&output.episodes)
                .map(|hit| hit.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            for contradiction in &output.contradictions {
                rendered.push_str(&contradiction.statement_a);
                rendered.push_str(&contradiction.statement_b);
            }
            assert!(rendered.contains("payment"), "{rendered}");
            assert!(rendered.contains("[REDACTED:openai_key]"), "{rendered}");
            assert!(!rendered.contains(secret), "{rendered}");
            assert!(!rendered.contains('\x1b'), "{rendered:?}");
        }
    }

    #[test]
    fn query_three_lanes_excludes_unverified_facts_and_resolved_contradictions() {
        use crate::memory::region_router::route_query;
        use crate::memory::store;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();
        // A CANDIDATE (unverified) fact must NOT leak into the canonical lane.
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (1, ?1, 'omi', 'global', 1000, 'candidate')",
            params!["the widget color is teal"],
        )
        .unwrap();
        // A DISMISSED contradiction must NOT surface (only 'pending' does).
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (2, ?1, 'op', 'global', 1000, 'verified'), (3, ?2, 'op', 'global', 1000, 'verified')",
            params!["the widget color is red", "the widget color is blue"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at, decision) \
             VALUES (2, 3, 0.8, 1000, 'dismissed')",
            [],
        )
        .unwrap();
        let plan = route_query("widget color");
        let out = query_three_lanes(&conn, &plan, "widget color", 5);
        assert!(
            !out.canonical.iter().any(|h| h.text.contains("teal")),
            "a 'candidate' fact must NOT appear in the canonical lane (verified-only gate)"
        );
        assert!(
            out.canonical
                .iter()
                .any(|h| h.text.contains("red") || h.text.contains("blue")),
            "verified facts SHOULD populate the canonical lane"
        );
        assert!(
            out.contradictions.is_empty(),
            "a 'dismissed' contradiction must NOT surface (pending-only gate)"
        );
    }

    #[test]
    fn query_three_lanes_applies_graph03_expansion_on_chat_path() {
        use crate::memory::region_router::route_query;
        use crate::memory::store;

        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        conn.execute_batch(
            "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES \
                 (21, 1, 300, 'payment incident alpha', 'graph-a', 0.9, 0), \
                 (22, 1, 200, 'payment incident beta', 'graph-b', 0.8, 0), \
                 (23, 1, 100, 'deployment checklist learned nearby', 'graph-c', 0.7, 0); \
             INSERT INTO idx_memory_communities (node_id, community_id) \
             VALUES (21, 9), (22, 9), (23, 9);",
        )
        .unwrap();

        let out = query_three_lanes(&conn, &route_query("payment"), "payment", 5);
        assert!(
            out.episodes.iter().any(|hit| hit.event_id == 23),
            "Block-D production recall must expand the selected community beyond text matches"
        );
    }
}
