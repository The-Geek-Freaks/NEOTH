//! `neoth memory` — operator-facing view of the memory subsystem.
//!
//! Phase 25 R-14 (assembled NEOTH.md context inspection) +
//! Phase 28a R-22 MT-5 (tier filter + session-archive browse).
//!
//! Modes (mutually exclusive groups):
//!   `show [groundtruth_id]` inspect fact provenance + resolve episode backlinks
//!   `--show`  (default) print the assembled NEOTH.md blocks with attribution
//!   `--paths` list only the source paths, one per line
//!   `--size`  print total byte count + per-block breakdown
//!   `--tier <hot|warm|cold>`  filter recall by memory tier (R-22)
//!   `--archive <YYYY-MM-DD>`  list session MD files for one day (R-22)

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::operator_md::{BlockSource, assemble, render, total_bytes};

/// Memory tier selector for `--tier`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TierFilter {
    Hot,
    Warm,
    Cold,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MemoryAction {
    /// Inspect verified facts and resolve their episode provenance across hot,
    /// warm, and cold tiers. Pass an id to inspect one row in any lifecycle state.
    Show {
        /// Ground-truth id. Omit to show recent rows in every active trust state.
        id: Option<i64>,
        /// Restrict the default all-active operator inspection to verified rows.
        #[arg(long)]
        verified_only: bool,
    },
    /// Preview or confirm erasure of one complete typed communication profile.
    /// This is intentionally separate from topic forget because typed
    /// presentation evidence is not topic-addressable.
    EraseCommunicationProfile {
        /// Exact, case-sensitive pseudonymous handle from
        /// `neoth export --list-subjects`. Defaults to `operator`.
        #[arg(long, value_name = "SUBJECT")]
        subject: Option<String>,
        /// Required to erase. Without this flag the command is a dry-run.
        #[arg(long)]
        confirm: bool,
        /// Override `~/.neoth/` (primarily for isolated verification).
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct MemoryArgs {
    #[command(subcommand)]
    pub action: Option<MemoryAction>,

    /// Print the full assembled context with source-attribution headers.
    #[arg(long, conflicts_with_all = ["paths", "size", "tier", "archive"])]
    pub show: bool,

    /// Print only the source paths, one per line.
    #[arg(long, conflicts_with_all = ["show", "size", "tier", "archive"])]
    pub paths: bool,

    /// Print byte sizes per block and the total.
    #[arg(long, conflicts_with_all = ["show", "paths", "tier", "archive"])]
    pub size: bool,

    /// Filter recall by memory tier (Phase 28a R-22 MT-5).
    #[arg(long, value_enum, conflicts_with_all = ["show", "paths", "size", "archive", "forget"])]
    pub tier: Option<TierFilter>,

    /// List archived session MD files for the given day (YYYY-MM-DD).
    #[arg(long, value_name = "YYYY-MM-DD", conflicts_with_all = ["show", "paths", "size", "tier", "forget"])]
    pub archive: Option<String>,

    /// GDPR retroactive wipe — delete every row in hot/warm/long-term
    /// plus embeddings plus revoke ground-truth assertions where the
    /// text matches the topic (LIKE pattern, case-insensitive). Use
    /// `--confirm` to execute; without it the command dry-runs and
    /// prints what would be deleted.
    #[arg(
        long,
        value_name = "TOPIC",
        conflicts_with_all = ["show", "paths", "size", "tier", "archive"]
    )]
    pub forget: Option<String>,

    /// Required to actually execute `--forget`. Without it the
    /// command is a preview only.
    #[arg(long, requires = "forget")]
    pub confirm: bool,

    /// C-15: also physically redact matching frames in every WAL
    /// segment (zero the payload bytes, set `EventFlags::REDACTED`,
    /// recompute CRC, fsync). Operator-controlled GDPR-grade erasure;
    /// the default `--confirm` path only wipes the SQLite tiers + emits
    /// the TOMBSTONE_REQUESTED audit anchor. Requires `--confirm`.
    #[arg(long, requires = "confirm")]
    pub physical: bool,

    /// NN-MEM-01: pin a hot-tier episode by `event_id` so it becomes
    /// decay-immune — the daily consolidation pass skips its importance decay,
    /// so a critical-but-rarely-accessed memory can never fall below
    /// FORGET_FLOOR and be forgotten. Reverse with `--unpin`.
    #[arg(
        long,
        value_name = "EVENT_ID",
        conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "unpin"]
    )]
    pub pin: Option<i64>,

    /// NN-MEM-01: unpin a previously-pinned hot-tier episode by `event_id`
    /// (re-subjects it to the normal importance decay).
    #[arg(
        long,
        value_name = "EVENT_ID",
        conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "pin"]
    )]
    pub unpin: Option<i64>,

    /// Compute the fractal-dimension D_mem across the four memory
    /// tiers (EXP-FD-0 from `PLAN/FRACTAL_DIMENSION.md`). Pure read,
    /// no behaviour change. Prints the per-tier byte counts + the
    /// regressed log-log slope + an honest verdict on whether D_mem
    /// is meaningful for this operator's data.
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget"])]
    pub dimension: bool,

    /// GOLD-ADAPT-OH-10 — print the per-person relationship ranking (recency ×
    /// frequency × reciprocity × depth, clamped). Pure read of
    /// `~/.neoth/people.json`, no behaviour change. Honours `--limit` (default
    /// 20; `--limit 0` returns the full ranking).
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "pin", "unpin"])]
    pub people: bool,

    /// H2 — export the Hebbian association graph (idx_memory_links) as
    /// JSON for the GUI memory-graph view: episode nodes (label, tier,
    /// degree, louvain community) + weighted links. Read-only.
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "pin", "unpin", "people"])]
    pub graph: bool,

    /// Cap the strongest links exported by `--graph` (default 400).
    #[arg(long, default_value_t = 400)]
    pub graph_limit: usize,

    /// V10-08 — rebuild the HNSW embedding index from scratch by scanning
    /// all rows in `idx_embedding`. Writes the snapshot to
    /// `<neoth_home>/embeddings.hnsw`. Use after a database restore or when
    /// the snapshot is missing or corrupted. Safe to interrupt: the snapshot
    /// is written atomically (temp-file + rename).
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension"])]
    pub rebuild_index: bool,

    /// GOLD-ADAPT-MEMGRAPH-01 — backfill episode embeddings into idx_embedding
    /// for every hot-tier episode that has no embedding row yet. Runs outside
    /// the hot ingest path (which is sync-in-tx and cannot call async embed).
    /// Honours `--limit` (default 20; `--limit 0` = unbounded) and `--db`.
    /// No-ops cleanly when no embed provider is configured.
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "pin", "unpin", "people"])]
    pub embed_backfill: bool,

    /// GOLD-ADAPT-MEM-11 — print the 15-point per-subsystem memory pipeline
    /// scorecard. Reads `~/.neoth/views.db` live; honours `--db` and `--output`.
    /// Exit 0 when overall grade is C or above; exit 1 when below healthy
    /// threshold so scripts can gate on memory health.
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension", "rebuild_index", "pin", "unpin", "people", "embed_backfill"])]
    pub pipeline_scorecard: bool,

    /// Max rows for `--tier` recall or `memory show` provenance inspection.
    #[arg(long, default_value = "20", global = true)]
    pub limit: usize,

    /// Override the views.db path for tier/provenance inspection.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_memory(args: MemoryArgs) -> Result<()> {
    if let Some(action) = args.action.as_ref() {
        return match action {
            MemoryAction::Show { id, verified_only } => run_memory_show(&args, *id, *verified_only),
            MemoryAction::EraseCommunicationProfile {
                subject,
                confirm,
                home,
            } => {
                run_communication_profile_erasure(
                    &args,
                    subject.as_deref(),
                    *confirm,
                    home.as_deref(),
                )
                .await
            }
        };
    }

    // ── --tier and --archive land *before* operator_md assembly because
    //    they don't need the rules/memory file scan. Either query the
    //    views.db (tier) or sweep the archive dir (archive).
    if let Some(tier) = args.tier {
        return run_memory_tier(&args, tier).await;
    }
    if let Some(day) = args.archive.as_deref() {
        return run_memory_archive(&args, day).await;
    }
    if let Some(topic) = args.forget.clone() {
        return run_memory_forget(&args, &topic).await;
    }
    if let Some(event_id) = args.pin {
        return run_memory_pin(&args, event_id, true).await;
    }
    if let Some(event_id) = args.unpin {
        return run_memory_pin(&args, event_id, false).await;
    }
    if args.dimension {
        return run_memory_dimension(&args).await;
    }
    if args.people {
        return run_memory_people(&args);
    }
    if args.graph {
        return run_memory_graph(&args);
    }
    if args.rebuild_index {
        return run_memory_rebuild_index(&args).await;
    }
    if args.embed_backfill {
        return run_memory_embed_backfill(&args).await;
    }
    if args.pipeline_scorecard {
        return run_memory_pipeline_scorecard(&args).await;
    }

    let home = FreedomConfig::default_neoth_home();
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
    info!(home = %home.display(), cwd = %cwd.display(), "assembling operator context");

    let blocks = assemble(&home, &cwd, &[]).await?;
    if blocks.is_empty() {
        println!(
            "no operator context loaded (no ~/.neoth/NEOTH.md, no rules/, no memory/).\n\
             Create ~/.neoth/NEOTH.md to start."
        );
        return Ok(());
    }

    let want_paths = args.paths;
    let want_size = args.size;
    let want_show = args.show || (!want_paths && !want_size); // default → --show

    if want_paths {
        match args.output {
            OutputFormat::Jsonl => {
                for b in &blocks {
                    println!(
                        "{}",
                        serde_json::json!({
                            "source": source_label(b.source),
                            "path": b.path.display().to_string(),
                        })
                    );
                }
            }
            _ => {
                for b in &blocks {
                    println!("[{}] {}", source_label(b.source), b.path.display());
                }
            }
        }
        return Ok(());
    }

    if want_size {
        let total = total_bytes(&blocks);
        match args.output {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "total_bytes": total,
                    "blocks": blocks.iter().map(|b| serde_json::json!({
                        "source": source_label(b.source),
                        "path": b.path.display().to_string(),
                        "bytes": b.content.len(),
                    })).collect::<Vec<_>>(),
                }))?
            ),
            _ => {
                println!("{:<8} {:>8}  path", "source", "bytes");
                println!("{}", "-".repeat(70));
                for b in &blocks {
                    println!(
                        "{:<8} {:>8}  {}",
                        source_label(b.source),
                        b.content.len(),
                        b.path.display()
                    );
                }
                println!("{}", "-".repeat(70));
                println!("{:<8} {:>8}", "TOTAL", total);
            }
        }
        return Ok(());
    }

    // default + --show
    if want_show {
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", serde_json::to_string_pretty(&blocks)?);
            }
            _ => {
                println!("{}", render(&blocks));
            }
        }
    }
    Ok(())
}

fn source_label(s: BlockSource) -> &'static str {
    match s {
        BlockSource::Global => "global",
        BlockSource::Project => "project",
        BlockSource::Rule => "rule",
        BlockSource::Memory => "memory",
        BlockSource::SubDir => "subdir",
    }
}

#[derive(Debug, Serialize)]
struct EvidenceEpisode {
    event_id: i64,
    tier: String,
    text: String,
    ts_ns: i64,
}

#[derive(Debug, Serialize)]
struct MemoryShowRow {
    fact: crate::memory::groundtruth::GroundTruth,
    provenance_kind: &'static str,
    episode_evidence: Vec<EvidenceEpisode>,
    unresolved_episode_ids: Vec<i64>,
}

fn resolve_evidence_episode(
    conn: &rusqlite::Connection,
    event_id: i64,
) -> Result<Option<EvidenceEpisode>> {
    use rusqlite::OptionalExtension;

    conn.query_row(
        "SELECT tier, text, ts_ns FROM (\
             SELECT 'hot' AS tier, text, ts_ns, 0 AS tier_order \
             FROM idx_episode WHERE event_id = ?1 \
             UNION ALL \
             SELECT 'warm', text, consolidated_ts, 1 \
             FROM idx_consolidated WHERE event_id = ?1 \
             UNION ALL \
             SELECT 'cold', text, promoted_ts, 2 \
             FROM idx_longterm WHERE event_id = ?1\
         ) ORDER BY tier_order ASC LIMIT 1",
        rusqlite::params![event_id],
        |r| {
            Ok(EvidenceEpisode {
                event_id,
                tier: r.get(0)?,
                text: r.get(1)?,
                ts_ns: r.get(2)?,
            })
        },
    )
    .optional()
    .with_context(|| format!("resolve evidence episode {event_id}"))
}

fn load_memory_show_rows(
    conn: &rusqlite::Connection,
    id: Option<i64>,
    limit: usize,
    verified_only: bool,
) -> Result<Vec<MemoryShowRow>> {
    use crate::memory::groundtruth;

    let facts = if let Some(id) = id {
        vec![
            groundtruth::get(conn, id)?
                .ok_or_else(|| anyhow::anyhow!("ground-truth fact {id} not found"))?,
        ]
    } else {
        let query_limit = if limit == 0 { usize::MAX } else { limit };
        groundtruth::surface_for_recall(conn, query_limit, !verified_only)?
    };

    facts
        .into_iter()
        .map(|fact| {
            let evidence_ids: Vec<i64> = serde_json::from_str(&fact.evidence)
                .with_context(|| format!("ground-truth fact {} has malformed evidence", fact.id))?;
            let provenance_kind = if evidence_ids.is_empty() {
                "source-attribution"
            } else {
                "episode-backlinks"
            };
            let mut episode_evidence = Vec::with_capacity(evidence_ids.len());
            let mut unresolved_episode_ids = Vec::new();
            for event_id in evidence_ids {
                match resolve_evidence_episode(conn, event_id)? {
                    Some(evidence) => episode_evidence.push(evidence),
                    None => unresolved_episode_ids.push(event_id),
                }
            }
            Ok(MemoryShowRow {
                fact,
                provenance_kind,
                episode_evidence,
                unresolved_episode_ids,
            })
        })
        .collect()
}

/// `neoth memory show [groundtruth_id]` — NN-MEM-03 operator provenance path.
fn run_memory_show(args: &MemoryArgs, id: Option<i64>, verified_only: bool) -> Result<()> {
    use crate::memory::store;

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for memory show: {}", db_path.display()))?;
    let rows = load_memory_show_rows(&conn, id, args.limit, verified_only)?;

    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Jsonl => {
            for row in &rows {
                println!("{}", serde_json::to_string(row)?);
            }
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("no active verified ground-truth facts.");
                return Ok(());
            }
            println!("# {} ground-truth provenance row(s)", rows.len());
            for row in &rows {
                let fact = &row.fact;
                println!(
                    "  [{:>6}] {:<12} {:<22} {:<20} {}",
                    fact.id, fact.fact_state, fact.source, fact.scope, fact.statement
                );
                println!(
                    "           maturity={} confidence={:.3} confirmed={} provenance={}",
                    fact.maturity, fact.confidence, fact.confirmed_count, row.provenance_kind
                );
                println!("           sources={}", fact.source_weight);
                for evidence in &row.episode_evidence {
                    let preview = evidence
                        .text
                        .chars()
                        .take(100)
                        .collect::<String>()
                        .replace(['\n', '\r'], " ");
                    println!(
                        "           episode={} tier={} ts={}  {}",
                        evidence.event_id, evidence.tier, evidence.ts_ns, preview
                    );
                }
                if !row.unresolved_episode_ids.is_empty() {
                    println!(
                        "           unresolved_episode_ids={:?}",
                        row.unresolved_episode_ids
                    );
                }
            }
        }
    }
    Ok(())
}

/// `neoth memory --tier <hot|warm|cold>` — list rows from the matching
/// SQLite view ordered by importance × tier_weight (recency-penalised).
async fn run_memory_tier(args: &MemoryArgs, tier: TierFilter) -> Result<()> {
    use crate::memory::{store, tiers::Tier};
    use rusqlite::params;

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)?;

    let neoth_tier = match tier {
        TierFilter::Hot => Tier::Hot,
        TierFilter::Warm => Tier::Warm,
        TierFilter::Cold => Tier::Cold,
    };

    // Per-tier SELECTs: each view has its own column set, but all three
    // expose (event_id, text, importance, ts/access_ts) which is what the
    // operator wants to see.
    let rows: Vec<(i64, String, f64, i64)> = match neoth_tier {
        Tier::Hot => {
            let mut stmt = conn.prepare(
                "SELECT event_id, text, importance, ts_ns \
                 FROM idx_episode \
                 ORDER BY importance DESC, ts_ns DESC \
                 LIMIT ?1",
            )?;
            stmt.query_map(params![args.limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        }
        Tier::Warm => {
            let mut stmt = conn.prepare(
                "SELECT COALESCE(event_id, id), text, importance, consolidated_ts \
                 FROM idx_consolidated \
                 ORDER BY importance DESC, consolidated_ts DESC \
                 LIMIT ?1",
            )?;
            stmt.query_map(params![args.limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        }
        Tier::Cold => {
            let mut stmt = conn.prepare(
                "SELECT event_id, text, importance, promoted_ts \
                 FROM idx_longterm \
                 ORDER BY importance DESC, promoted_ts DESC \
                 LIMIT ?1",
            )?;
            stmt.query_map(params![args.limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        }
    };

    match args.output {
        OutputFormat::Json => {
            let json: Vec<_> = rows
                .iter()
                .map(|(id, text, imp, ts)| {
                    serde_json::json!({
                        "event_id": id,
                        "text": text,
                        "importance": imp,
                        "ts_ns": ts,
                        "tier": neoth_tier.as_str(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Jsonl => {
            for (id, text, imp, ts) in &rows {
                println!(
                    "{}",
                    serde_json::json!({
                        "event_id": id,
                        "text": text,
                        "importance": imp,
                        "ts_ns": ts,
                        "tier": neoth_tier.as_str(),
                    })
                );
            }
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("no {} tier events.", neoth_tier.as_str());
                return Ok(());
            }
            println!("# {} hit(s) in {} tier", rows.len(), neoth_tier.as_str());
            for (id, text, imp, _ts) in &rows {
                let preview: String = text.chars().take(80).collect();
                println!("  [{id:>10}] imp={imp:.3}  {preview}");
            }
        }
    }
    Ok(())
}

const COMMUNICATION_OPERATOR_SUBJECT: &str = "operator";
const COMMUNICATION_ERASE_COMMAND: &str = "neoth memory erase-communication-profile --confirm";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CommunicationProfileInventory {
    dimensions: usize,
    evidence_records: usize,
    declared_context_records: usize,
}

#[derive(Debug, serde::Serialize)]
struct CommunicationProfileErasureReport {
    dry_run: bool,
    confirmed: bool,
    subject_sha256: String,
    operator_subject: bool,
    state_file_present_before: bool,
    subject_present_before: bool,
    would_change: bool,
    changed: bool,
    dimensions: usize,
    evidence_records: usize,
    declared_context_records: usize,
    state_revision_before: u64,
    state_revision_after: Option<u64>,
    wal_audit_persisted: bool,
    audit_semantics: &'static str,
    topic_forget_affected: bool,
    confirm_with: Option<String>,
}

fn communication_profile_inventory(
    subject: Option<&crate::profile::communication::SubjectCommunicationProfile>,
) -> CommunicationProfileInventory {
    let Some(subject) = subject else {
        return CommunicationProfileInventory::default();
    };
    CommunicationProfileInventory {
        dimensions: subject
            .evidence
            .keys()
            .chain(subject.estimates.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        evidence_records: subject.evidence.values().map(Vec::len).sum(),
        declared_context_records: usize::from(subject.declared_context.is_some()),
    }
}

fn render_communication_profile_erasure(
    report: &CommunicationProfileErasureReport,
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(report)?),
        OutputFormat::Table => {
            let heading = if report.dry_run {
                "# Communication-profile erasure preview"
            } else {
                "# Communication-profile erasure complete"
            };
            println!("{heading}");
            println!(
                "  selected subject   : sha256:{} ({})",
                &report.subject_sha256[..report.subject_sha256.len().min(16)],
                if report.operator_subject {
                    "operator"
                } else {
                    "pseudonymous channel subject"
                }
            );
            println!(
                "  subject present    : {}",
                if report.subject_present_before {
                    "present"
                } else {
                    "absent"
                }
            );
            println!("  typed dimensions  : {}", report.dimensions);
            println!("  evidence records  : {}", report.evidence_records);
            println!("  context records   : {}", report.declared_context_records);
            if report.dry_run {
                println!("  would delete      : {}", report.would_change);
                println!(
                    "  No changes made. Confirm with {}.",
                    report.confirm_with.as_deref().unwrap_or("`--confirm`")
                );
            } else {
                println!("  subject deleted   : {}", report.changed);
                println!(
                    "  state revision    : {} -> {}",
                    report.state_revision_before,
                    report
                        .state_revision_after
                        .unwrap_or(report.state_revision_before)
                );
                println!("  WAL audit         : persisted metadata-only post-commit receipt");
            }
            println!(
                "  Topic forget remains separate because typed communication evidence is not topic-addressable."
            );
        }
    }
    Ok(())
}

async fn run_communication_profile_erasure(
    args: &MemoryArgs,
    subject_selector: Option<&str>,
    confirm: bool,
    home_override: Option<&std::path::Path>,
) -> Result<()> {
    let subject_id = subject_selector.unwrap_or(COMMUNICATION_OPERATOR_SUBJECT);
    crate::daemon::export::validate_communication_subject_selector(subject_id)?;
    let home = home_override
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let state_path = crate::profile::communication::state_path(&home);
    let state_file_present_before = state_path
        .try_exists()
        .with_context(|| format!("inspect communication profile at {}", state_path.display()))?;
    let before = crate::profile::communication::load_state(&home).with_context(|| {
        format!(
            "strictly load communication profile at {}",
            state_path.display()
        )
    })?;
    let subject = before.subjects.get(subject_id);
    if subject_selector.is_some() && subject.is_none() {
        anyhow::bail!(
            "selected communication-profile subject was not found; selectors are exact and case-sensitive"
        );
    }
    let subject_present_before = subject.is_some();
    let inventory = communication_profile_inventory(subject);
    let subject_sha256 = crate::daemon::export::communication_subject_sha256(subject_id);

    if !confirm {
        return render_communication_profile_erasure(
            &CommunicationProfileErasureReport {
                dry_run: true,
                confirmed: false,
                subject_sha256,
                operator_subject: subject_id == COMMUNICATION_OPERATOR_SUBJECT,
                state_file_present_before,
                subject_present_before,
                would_change: subject_present_before,
                changed: false,
                dimensions: inventory.dimensions,
                evidence_records: inventory.evidence_records,
                declared_context_records: inventory.declared_context_records,
                state_revision_before: before.revision,
                state_revision_after: None,
                wal_audit_persisted: false,
                audit_semantics: "none_dry_run",
                topic_forget_affected: false,
                confirm_with: Some(if subject_selector.is_some() {
                    "the same exact `--subject` selector plus `--confirm`".to_owned()
                } else {
                    format!("`{COMMUNICATION_ERASE_COMMAND}`")
                }),
            },
            &args.output,
        );
    }

    let changed = crate::profile::communication::forget_subject(&home, subject_id)
        .context("erase selected typed communication subject")?;
    let after = crate::profile::communication::load_state(&home)
        .context("reload communication profile after erasure")?;
    append_communication_subject_erasure_audit_at(&home, subject_id, changed, after.revision)
        .await?;
    render_communication_profile_erasure(
        &CommunicationProfileErasureReport {
            dry_run: false,
            confirmed: true,
            subject_sha256,
            operator_subject: subject_id == COMMUNICATION_OPERATOR_SUBJECT,
            state_file_present_before,
            subject_present_before,
            would_change: subject_present_before,
            changed,
            dimensions: inventory.dimensions,
            evidence_records: inventory.evidence_records,
            declared_context_records: inventory.declared_context_records,
            state_revision_before: before.revision,
            state_revision_after: Some(after.revision),
            wal_audit_persisted: true,
            audit_semantics: "metadata_only_post_commit_receipt",
            topic_forget_affected: false,
            confirm_with: None,
        },
        &args.output,
    )
}

fn communication_subject_erasure_audit_payload(
    subject_id: &str,
    changed: bool,
    state_revision: u64,
    ts_unix: i64,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "action_code": crate::cli::profile::CommunicationControlAction::ForgetSubject as u8,
        "changed": changed,
        "subject_sha256": crate::daemon::export::communication_subject_sha256(subject_id),
        "subject_revision_observed": Option::<u64>::None,
        "state_revision_observed": state_revision,
        "ts_unix": ts_unix,
    }))
    .context("serialize communication-subject erasure audit")
}

/// Append the required metadata-only post-commit receipt for the exact subject
/// selected by the DSAR command. The older profile CLI helper is intentionally
/// operator-only, so using it here would produce a false audit identity.
async fn append_communication_subject_erasure_audit_at(
    home: &std::path::Path,
    subject_id: &str,
    changed: bool,
    state_revision: u64,
) -> Result<()> {
    let payload = communication_subject_erasure_audit_payload(
        subject_id,
        changed,
        state_revision,
        crate::time::now_unix_i64(),
    )?;
    let subtype = crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8;
    let pidfile = home.join("neothd.pid");
    let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon ownership via {}", pidfile.display()))?
        .is_some();

    if daemon_live {
        crate::daemon::audit_rpc::try_post_audit_frame_with_subtype(
            home,
            crate::wal::events::EVENT_TYPE_EXTENDED,
            subtype,
            &payload,
        )
        .await
        .map_err(anyhow::Error::new)
        .context("running daemon refused required communication-subject erasure audit")?;
        return Ok(());
    }

    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create communication-subject WAL dir {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(
        &wal_dir,
        "communication-profile-control",
    );
    let (writer, join) = crate::wal::spawn_for_home(segment, home.to_path_buf())
        .context("spawn one-shot communication-subject control WAL writer")?;
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(subtype)
        .build();
    let append = writer
        .append(header, payload)
        .await
        .context("append required communication-subject erasure audit")
        .map(|_| ());
    drop(writer);
    let shutdown = join
        .await
        .context("join one-shot communication-subject control WAL writer");
    match (append, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(append), Err(shutdown)) => Err(anyhow::anyhow!(
            "{append:#}; additionally failed to close communication-subject audit WAL: {shutdown:#}"
        )),
    }
}

fn communication_profile_topic_forget_metadata() -> serde_json::Value {
    serde_json::json!({
        "subjects_deleted": 0,
        "topic_addressable": false,
        "reason": "typed_communication_evidence_is_not_topic_addressable",
        "erase_with": COMMUNICATION_ERASE_COMMAND,
    })
}

/// `neoth memory --forget <topic> [--confirm]` — GDPR cascade-delete.
///
/// Without `--confirm` this is a dry-run that prints what would be
/// deleted (operator sees the impact before committing). With
/// `--confirm` the deletion executes against the views.db; the
/// `memory::forget::forget_by_topic` handles the complete SQLite cascade,
/// installs an anti-resurrection sentinel atomically, and the confirmed path
/// writes a TOMBSTONE_REQUESTED WAL audit anchor. `--physical` additionally
/// redacts the matching payload bytes from WAL segments.
async fn run_memory_forget(args: &MemoryArgs, topic: &str) -> Result<()> {
    use crate::memory::{forget, store};
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for forget: {}", db_path.display()))?;

    if !args.confirm {
        let report = forget::preview_forget_by_topic(&conn, topic)?;
        let total = report.total();
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let body = serde_json::json!({
                    "dry_run": true,
                    "topic": topic,
                    "would_delete": {
                        "idx_episode": report.episode_rows,
                        "idx_consolidated": report.consolidated_rows,
                        "idx_longterm": report.longterm_rows,
                        "raw_turns": report.raw_turn_rows,
                        "idx_profile": report.profile_rows,
                        "idx_profile_pending": report.profile_pending_rows,
                        "idx_profile_outbox": report.profile_outbox_rows,
                        "idx_groundtruth_revoke": report.groundtruth_revoked,
                        "idx_embedding": report.embedding_rows,
                        "idx_entities": report.entity_rows,
                        "idx_relations": report.relation_rows,
                        "idx_memory_links": report.link_rows,
                        "idx_contradictions": report.contradiction_rows,
                        "idx_foreign_events": report.foreign_event_rows,
                        "people_json": report.people_rows,
                        "total": total,
                    },
                    "communication_profile": communication_profile_topic_forget_metadata(),
                    "confirm_with": "neoth memory --forget \"<topic>\" --confirm",
                });
                match args.output {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                    OutputFormat::Jsonl => println!("{}", serde_json::to_string(&body)?),
                    OutputFormat::Table => unreachable!(),
                }
            }
            OutputFormat::Table => {
                println!("# Forget dry-run for topic `{topic}`");
                println!("  idx_episode      : {} rows", report.episode_rows);
                println!("  idx_consolidated : {} rows", report.consolidated_rows);
                println!("  idx_longterm     : {} rows", report.longterm_rows);
                println!("  raw_turns        : {} rows", report.raw_turn_rows);
                println!("  idx_profile      : {} claims", report.profile_rows);
                println!("  idx_profile_pend : {} rows", report.profile_pending_rows);
                println!("  idx_profile_outb : {} rows", report.profile_outbox_rows);
                println!(
                    "  idx_groundtruth  : {} would be revoked",
                    report.groundtruth_revoked
                );
                println!("  idx_embedding    : {} vectors", report.embedding_rows);
                println!("  idx_entities     : {} nodes", report.entity_rows);
                println!("  idx_relations    : {} edges", report.relation_rows);
                println!("  idx_memory_links : {} links", report.link_rows);
                println!("  idx_contradict   : {} rows", report.contradiction_rows);
                println!(
                    "  idx_foreign_evt  : {} peer frames",
                    report.foreign_event_rows
                );
                println!("  people.json      : {} rows", report.people_rows);
                println!(
                    "  communication    : 0 subjects (not topic-addressable; erase with `{COMMUNICATION_ERASE_COMMAND}`)"
                );
                println!("  total            : {total}");
                println!();
                println!("  No changes made. Re-run with `--confirm` to execute.");
            }
        }
        return Ok(());
    }

    // Real run. Open a dedicated WAL segment under the operator's
    // WAL dir so the TOMBSTONE_REQUESTED audit frame lands in the
    // canonical audit log alongside other operator-state events.
    let now_unix = crate::time::now_unix_i64();
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir")?;
    let segment = wal_dir.join(format!("memory-forget-{now_unix}.wal"));
    let (writer, writer_join) =
        crate::wal::writer::spawn(segment.clone()).context("spawn WAL writer for tombstone")?;
    // `rusqlite::Connection` is Send but not Sync. Move it through the
    // audited async operation so no `&Connection` survives the WAL await.
    let (conn, report) =
        forget::forget_by_topic_with_audit(conn, topic, now_unix, "cli", &writer).await?;
    drop(writer);
    writer_join.await.context("join memory-forget WAL writer")?;
    // GR-005: the idx_embedding SQLite wipe inside forget does NOT touch the
    // on-disk HNSW snapshot — forgotten vectors stay searchable via the
    // cold-load path until a rebuild. Purge them by invalidating the old snapshot
    // first, then rebuilding it from the now-wiped SQLite. A rebuild failure is
    // surfaced, but recall remains privacy-safe because the stale snapshot is no
    // longer present. Acts only when embeddings were forgotten.
    if report.embedding_rows > 0 {
        let home = crate::config::FreedomConfig::default_neoth_home();
        if let Some(n) = crate::memory::embeddings::rebuild_snapshot_if_present(&conn, &home)? {
            info!(
                vectors = n,
                "GR-005: HNSW snapshot rebuilt after forget — forgotten embeddings purged from the searchable index"
            );
        }
    }
    info!(
        topic = topic,
        total = report.total(),
        episode = report.episode_rows,
        consolidated = report.consolidated_rows,
        longterm = report.longterm_rows,
        groundtruth = report.groundtruth_revoked,
        embedding = report.embedding_rows,
        profile = report.profile_rows,
        profile_pending = report.profile_pending_rows,
        profile_outbox = report.profile_outbox_rows,
        raw_turns = report.raw_turn_rows,
        entities = report.entity_rows,
        relations = report.relation_rows,
        memory_links = report.link_rows,
        contradictions = report.contradiction_rows,
        foreign_events = report.foreign_event_rows,
        people = report.people_rows,
        audit_segment = %segment.display(),
        "forget executed (TOMBSTONE_REQUESTED audit frame written)"
    );
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut body = serde_json::to_value(&report).context("serialize forget report")?;
            body.as_object_mut()
                .expect("ForgetReport serializes to an object")
                .insert(
                    "communication_profile".to_owned(),
                    communication_profile_topic_forget_metadata(),
                );
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&body)?),
                OutputFormat::Table => unreachable!(),
            }
        }
        OutputFormat::Table => {
            println!("# Forget complete for topic `{topic}`");
            println!("  idx_episode      : {} rows deleted", report.episode_rows);
            println!(
                "  idx_consolidated : {} rows deleted",
                report.consolidated_rows
            );
            println!("  idx_longterm     : {} rows deleted", report.longterm_rows);
            println!("  raw_turns        : {} rows deleted", report.raw_turn_rows);
            println!(
                "  idx_groundtruth  : {} revoked",
                report.groundtruth_revoked
            );
            // GR-100 — the profile rows were omitted, so the printed lines did
            // not sum to `total`. GOLD-SEC-28 added the two in-flight tables.
            println!("  idx_profile      : {} rows deleted", report.profile_rows);
            println!(
                "  idx_profile_pend : {} rows deleted",
                report.profile_pending_rows
            );
            println!(
                "  idx_profile_outb : {} rows deleted",
                report.profile_outbox_rows
            );
            println!(
                "  idx_embedding    : {} vectors wiped",
                report.embedding_rows
            );
            println!(
                "  idx_foreign_evt  : {} peer frames deleted",
                report.foreign_event_rows
            );
            println!("  idx_entities     : {} nodes deleted", report.entity_rows);
            println!(
                "  idx_relations    : {} edges deleted",
                report.relation_rows
            );
            println!("  idx_memory_links : {} links deleted", report.link_rows);
            println!(
                "  idx_contradict   : {} rows deleted",
                report.contradiction_rows
            );
            println!("  people.json      : {} rows deleted", report.people_rows);
            println!(
                "  communication    : 0 subjects deleted (not topic-addressable; erase with `{COMMUNICATION_ERASE_COMMAND}`)"
            );
            println!("  total            : {}", report.total());
        }
    }

    // C-15 physical erasure: scan every WAL segment + zero matching
    // payloads. Off by default — operator opts in via `--physical`.
    if args.physical {
        let redact_report = run_physical_redaction(&wal_dir, topic, now_unix).await?;
        info!(
            topic = topic,
            segments_touched = redact_report.segments_touched,
            frames_redacted = redact_report.frames_redacted,
            bytes_redacted = redact_report.bytes_redacted,
            "physical WAL redaction complete"
        );
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", serde_json::to_string_pretty(&redact_report)?);
            }
            OutputFormat::Table => {
                println!("\n# Physical WAL erasure for topic `{topic}`");
                println!("  segments scanned : {}", redact_report.segments_touched);
                println!("  frames redacted  : {}", redact_report.frames_redacted);
                println!("  bytes zeroed     : {}", redact_report.bytes_redacted);
                println!("  errors           : {}", redact_report.errors);
                if physical_erasure_incomplete(&redact_report) {
                    // GR-008 — do NOT claim success when a segment errored. An
                    // `errors > 0` means a segment REFUSED redaction (e.g. a
                    // sealed/compressed v2 segment — GOLD-ARCH-03b) so the data
                    // could persist, and/or a redaction-marker audit emit failed.
                    // Either way the GDPR erasure is NOT provably complete.
                    println!(
                        "  ⚠ INCOMPLETE: {} segment(s) errored — a sealed/compressed \
                         segment may have REFUSED redaction (the data could persist) \
                         and/or an audit marker failed. Physical erasure is NOT \
                         confirmed complete; see the warnings above + the audit log.",
                        redact_report.errors
                    );
                } else if redact_report.frames_redacted == 0 {
                    println!("  (no matching WAL frames — SQLite-only forget was sufficient)");
                } else {
                    println!(
                        "  GDPR-grade erasure: payload bytes physically zeroed + \
                         EventFlags::REDACTED set + CRC recomputed + fsync'd."
                    );
                }
            }
        }
        // GR-008 — fail loud: a `--physical` erasure that hit ANY error is not a
        // confirmed GDPR-grade wipe. Return a non-zero exit so an operator (or a
        // script) never mistakes a partial / refused redaction for success. The
        // report above is still printed (stdout) for diagnosis.
        if physical_erasure_incomplete(&redact_report) {
            anyhow::bail!(
                "physical WAL erasure for topic `{topic}` reported {} error(s) — erasure is \
                 INCOMPLETE / unconfirmed (a sealed segment may have refused redaction; see \
                 GOLD-ARCH-03b). Review the audit log; the affected data may still persist.",
                redact_report.errors
            );
        }
    }
    Ok(())
}

/// C-15 helper: walk every `.wal` segment under `wal_dir` + call
/// `wal::redact::scan_and_redact` with a topic-substring predicate.
/// After each segment that actually had frames redacted, emits a
/// `REDACTION_MARKER` (0xF3) WAL frame so future integrity verifiers
/// treat the HMAC mismatch on the redacted offsets as operator-
/// authorised rather than adversarial tampering.
///
/// Aggregates per-segment reports into one operator-readable summary.
///
/// Availability contract: the active writer intentionally holds its segment's
/// rewrite lock until rotation or shutdown. If that lock cannot be acquired,
/// this pass records an error and the `--physical` caller exits non-zero. It
/// must never skip the live segment and print a successful GDPR-erasure claim.
fn physical_redaction_audit_segment_path(wal_dir: &std::path::Path) -> std::path::PathBuf {
    crate::wal::writer::unique_standalone_segment_path(wal_dir, "memory-redact")
}

async fn run_physical_redaction(
    wal_dir: &std::path::Path,
    topic: &str,
    now_unix: i64,
) -> Result<PhysicalRedactSummary> {
    use crate::wal::redact;

    let mut summary = PhysicalRedactSummary::default();
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // WAL dir might not exist yet (fresh install, no daemon run).
            // Treat as zero-frames-redacted rather than an error.
            tracing::debug!(
                error = %e,
                wal_dir = %wal_dir.display(),
                "WAL dir absent; physical redaction is a no-op"
            );
            return Ok(summary);
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!("open WAL directory {} for redaction", wal_dir.display())
            });
        }
    };

    // Open a dedicated audit-only segment for the REDACTION_MARKER
    // frames. Same pattern as the TOMBSTONE_REQUESTED segment.
    std::fs::create_dir_all(wal_dir).context("create WAL dir for redaction audit")?;
    // Concurrent invocations can share the same `now_unix` second. A
    // deterministic name let their audit writers target one segment, which is
    // both a lock collision and an audit-integrity failure. Reuse the writer's
    // UUIDv7 standalone namespace; rotation remains namespace-safe.
    let audit_segment = physical_redaction_audit_segment_path(wal_dir);
    let (audit_writer, audit_join) = crate::wal::writer::spawn(audit_segment.clone())
        .context("spawn WAL writer for redaction audit")?;

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                tracing::warn!(
                    wal_dir = %wal_dir.display(),
                    error = %e,
                    "WAL directory entry could not be inspected; physical erasure is incomplete"
                );
                summary.errors += 1;
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        // Skip the audit segment itself so we don't redact our own
        // marker frames on a re-run.
        if path == audit_segment {
            continue;
        }
        let pred = redact::payload_contains_topic(topic);
        match redact::scan_and_redact(&path, pred) {
            Ok(report) => {
                summary.segments_touched += 1;
                summary.frames_redacted += report.frames_redacted_count() as u64;
                summary.bytes_redacted += report.bytes_redacted;
                summary.already_redacted_skipped += report.already_redacted as u64;
                // Emit one REDACTION_MARKER per segment that had >=1
                // frame redacted. Segments with zero matches stay
                // silent — no audit clutter.
                if !report.frames_redacted.is_empty() {
                    if let Err(e) = redact::emit_redaction_marker(
                        &audit_writer,
                        &path,
                        &report.frames_redacted,
                        report.bytes_redacted,
                        topic,
                        "cli",
                        now_unix,
                    )
                    .await
                    {
                        tracing::warn!(
                            segment = %path.display(),
                            error = %e,
                            "REDACTION_MARKER emission failed; segment is redacted but audit is incomplete"
                        );
                        summary.errors += 1;
                    } else {
                        summary.markers_emitted += 1;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    segment = %path.display(),
                    error = %e,
                    "WAL segment redaction failed; continuing with remaining segments"
                );
                summary.errors += 1;
            }
        }
    }

    drop(audit_writer);
    if let Err(e) = audit_join.await {
        tracing::warn!(
            audit_segment = %audit_segment.display(),
            error = %e,
            "redaction audit WAL writer task failed to join; audit completion is unconfirmed"
        );
        summary.errors += 1;
    }
    summary.audit_segment = Some(audit_segment.display().to_string());
    Ok(summary)
}

/// Operator-readable summary of a `--physical` redaction pass.
#[derive(Debug, Default, serde::Serialize)]
struct PhysicalRedactSummary {
    pub segments_touched: u64,
    pub frames_redacted: u64,
    pub bytes_redacted: u64,
    pub already_redacted_skipped: u64,
    pub errors: u64,
    /// Count of REDACTION_MARKER frames emitted (one per segment
    /// that had >=1 frame redacted). Operators reading the WAL audit
    /// log see this many marker frames documenting the wave.
    pub markers_emitted: u64,
    /// Path to the dedicated audit segment carrying every marker
    /// emitted in this redaction pass. None when no markers fired.
    pub audit_segment: Option<String>,
}

/// GR-008 — a `--physical` erasure is only a CONFIRMED success when no segment
/// errored. Any `errors > 0` means a segment refused redaction (e.g. a sealed /
/// compressed v2 segment — GOLD-ARCH-03b — whose data could still persist) or a
/// redaction-marker audit emit failed, so the GDPR-grade wipe is not provably
/// complete. The CLI must NOT print an affirmative "sufficient / GDPR-grade
/// erasure" message and must fail loud (non-zero exit) in that case.
fn physical_erasure_incomplete(summary: &PhysicalRedactSummary) -> bool {
    summary.errors > 0
}

/// `neoth memory --graph` — H2. Export the Hebbian association graph
/// for the GUI memory-graph view. Pure read over `idx_memory_links`
/// joined with the tier tables for labels: hot = idx_episode,
/// warm = idx_consolidated, cold = idx_longterm; a node whose id no
/// longer resolves anywhere is labelled by id (links outlive rows
/// until the decay pass prunes them).
fn memory_graph_label(label: &str) -> String {
    label
        .chars()
        .map(|character| match character {
            '\r' | '\n' => ' ',
            _ => character,
        })
        .take(80)
        .collect()
}

fn run_memory_graph(args: &MemoryArgs) -> Result<()> {
    use crate::memory::{assoc_graph, store};
    use std::collections::{BTreeSet, HashMap};

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for graph: {}", db_path.display()))?;

    let mut stmt = conn.prepare(
        "SELECT lo_id, hi_id, weight FROM idx_memory_links \
         WHERE weight > 0.0 ORDER BY weight DESC LIMIT ?1",
    )?;
    let edges: Vec<(i64, i64, f64)> = stmt
        .query_map([args.graph_limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut ids: BTreeSet<i64> = BTreeSet::new();
    let mut degree: HashMap<i64, u32> = HashMap::new();
    for (a, b, _) in &edges {
        ids.insert(*a);
        ids.insert(*b);
        *degree.entry(*a).or_default() += 1;
        *degree.entry(*b).or_default() += 1;
    }
    let communities = assoc_graph::louvain(&edges);
    let mut comm_of: HashMap<i64, usize> = HashMap::new();
    for (ci, group) in communities.iter().enumerate() {
        for id in group {
            comm_of.insert(*id, ci);
        }
    }

    // Label + tier per node. One-line label, capped at 80 chars.
    fn label_of(conn: &rusqlite::Connection, table: &str, id: i64) -> Option<String> {
        conn.query_row(
            &format!("SELECT text FROM {table} WHERE event_id = ?1"),
            [id],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }
    let nodes: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| {
            let (label, tier) = if let Some(t) = label_of(&conn, "idx_episode", *id) {
                (t, "hot")
            } else if let Some(t) = label_of(&conn, "idx_consolidated", *id) {
                (t, "warm")
            } else if let Some(t) = label_of(&conn, "idx_longterm", *id) {
                (t, "cold")
            } else {
                (format!("event {id}"), "fact")
            };
            let one_line = memory_graph_label(&label);
            serde_json::json!({
                "id": id,
                "label": one_line,
                "tier": tier,
                "degree": degree.get(id).copied().unwrap_or(0),
                "community": comm_of.get(id).copied().unwrap_or(0),
            })
        })
        .collect();

    let edges_json: Vec<serde_json::Value> = edges
        .iter()
        .map(|(a, b, w)| serde_json::json!({ "a": a, "b": b, "w": w }))
        .collect();
    let body = serde_json::json!({
        "nodes": nodes,
        "edges": edges_json,
        "communities": communities.len(),
    });
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{body}"),
        OutputFormat::Table => println!(
            "# memory graph — {} nodes, {} links, {} communities\n\
             # (use --output json for the full export)",
            ids.len(),
            edges.len(),
            communities.len()
        ),
    }
    Ok(())
}

/// `neoth memory --dimension` — EXP-FD-0. Compute D_mem across tiers.
async fn run_memory_dimension(args: &MemoryArgs) -> Result<()> {
    use crate::memory::{dimension, store};
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for dimension: {}", db_path.display()))?;
    let report = dimension::estimate(&conn)?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Table => {
            println!("# D_mem (EXP-FD-0)");
            println!();
            println!("  tier    rows       bytes");
            println!("  -----   --------   --------");
            for t in &report.tiers {
                println!("  {:<6}  {:>8}   {:>8}", t.tier, t.row_count, t.total_bytes);
            }
            println!();
            match (report.d_mem, report.r_squared) {
                (Some(d), Some(r2)) => {
                    println!("  D_mem  = {d:.3}");
                    println!("  R²     = {r2:.3}");
                }
                _ => println!("  D_mem  = (insufficient data)"),
            }
            println!();
            println!("  verdict: {}", report.honest_verdict);
        }
    }
    Ok(())
}

/// `neoth memory --people` — GOLD-ADAPT-OH-10. Print the per-person
/// relationship ranking (recency × frequency × reciprocity × depth, clamped).
/// Pure read of `~/.neoth/people.json`; `--limit 0` returns the full ranking.
fn run_memory_people(args: &MemoryArgs) -> Result<()> {
    use crate::memory::people;
    let home = FreedomConfig::default_neoth_home();
    let now_unix = crate::time::now_unix_secs();
    let ranked = people::top_people(&home, args.limit, now_unix);
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&ranked)?);
        }
        OutputFormat::Table => {
            if ranked.is_empty() {
                println!(
                    "no people recorded yet — the ranking fills in as in-scope contacts \
                     message you across channels (~/.neoth/people.json)."
                );
                return Ok(());
            }
            println!("# People ranking (GOLD-ADAPT-OH-10)");
            println!();
            println!("  score   seen(d)   msgs   who");
            println!("  -----   -------   ----   ---");
            for p in &ranked {
                let days = now_unix.saturating_sub(p.last_seen_unix) / 86_400;
                let who = p.display.clone().unwrap_or_else(|| p.person_key.clone());
                println!(
                    "  {:>5.3}   {:>7}   {:>4}   {} [{}]",
                    p.score, days, p.interaction_count as u64, who, p.channel
                );
            }
        }
    }
    Ok(())
}

/// `neoth memory --rebuild-index` — V10-08. Rebuild the HNSW embedding index
/// from scratch by scanning `idx_embedding` and persist to
/// `<neoth_home>/embeddings.hnsw`.
async fn run_memory_rebuild_index(args: &MemoryArgs) -> Result<()> {
    use crate::config::FreedomConfig;
    use crate::memory::{embeddings, store};

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for rebuild-index: {}", db_path.display()))?;

    // Snapshot lives one level up from the WAL dir, i.e. <neoth_home>/embeddings.hnsw.
    // GOLD-WIRE-07: resolve via the canonical helper so recall + rebuild agree.
    let neoth_home = FreedomConfig::default_neoth_home();
    let index_path = embeddings::hnsw_snapshot_path(&neoth_home);

    let n = tokio::task::spawn_blocking(move || embeddings::rebuild_index(&conn, &index_path))
        .await
        .context("spawn_blocking for rebuild_index")??;

    match args.output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "indexed": n,
                    "snapshot": neoth_home.join("embeddings.hnsw").display().to_string(),
                }))?
            );
        }
        crate::cli::OutputFormat::Table => {
            println!("# HNSW index rebuild complete");
            println!("  vectors indexed : {n}");
            println!(
                "  snapshot path   : {}",
                neoth_home.join("embeddings.hnsw").display()
            );
        }
    }
    Ok(())
}

/// GOLD-ADAPT-MEMGRAPH-01 consumer — `neoth memory --embed-backfill`.
///
/// Embeds every hot-tier episode that has no `idx_embedding` row yet, populating
/// the recall vector lane without touching the hot sync-in-tx ingest path.
/// Respects `--limit` (default 500 via `MemoryArgs::limit`; 0 = unbounded) and
/// `--db`. Best-effort: a provider failure on one episode skips that episode and
/// continues (mirroring the `embed_episode_text` contract).
async fn run_memory_embed_backfill(args: &MemoryArgs) -> Result<()> {
    use crate::memory::{embeddings, store};

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let mut conn = store::open(&db_path)
        .with_context(|| format!("open views.db for embed-backfill: {}", db_path.display()))?;

    // Resolve the embed provider from the operator's freedom.yaml.
    let config =
        FreedomConfig::load_from_default_path().context("load freedom.yaml for embed-backfill")?;
    let provider = match crate::providers::embed_provider_from_config(&config).await {
        Some(p) => p,
        None => {
            println!(
                "embeddings not configured (set inference embed model in freedom.yaml); nothing to backfill."
            );
            return Ok(());
        }
    };

    // Fetch un-embedded episodes: hot-tier rows with no matching idx_embedding row.
    let candidates = unembedded_episode_ids(&conn, args.limit)?;
    let total_candidates = candidates.len();
    if total_candidates == 0 {
        println!("all episodes already embedded; nothing to backfill.");
        return Ok(());
    }

    // Embed each candidate best-effort (failures are warned inside embed_episode_text).
    for (event_id, text) in &candidates {
        conn = embeddings::embed_episode_text(conn, *event_id, text, provider.as_ref()).await;
    }

    // Count how many were actually written vs already present (second-run idempotence).
    let remaining = unembedded_episode_ids(&conn, 0)?.len();
    let newly_embedded = total_candidates.saturating_sub(remaining);

    match args.output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "embedded": newly_embedded,
                    "skipped_already_embedded": 0,
                    "batch_size": total_candidates,
                }))?
            );
        }
        crate::cli::OutputFormat::Table => {
            println!(
                "embedded {newly_embedded} episode(s) ({} already embedded, skipped).",
                total_candidates.saturating_sub(newly_embedded)
            );
        }
    }
    Ok(())
}

/// Return up to `limit` hot-tier episodes with no corresponding `idx_embedding`
/// row (source_kind='episode'). `limit = 0` returns all.
///
/// Extracted as a named helper so tests can verify the shrink-after-embed behaviour
/// directly without wiring the full `run_memory` dispatch.
pub(crate) fn unembedded_episode_ids(
    conn: &rusqlite::Connection,
    limit: usize,
) -> Result<Vec<(i64, String)>> {
    let sql = if limit == 0 {
        "SELECT event_id, text FROM idx_episode \
         WHERE event_id NOT IN \
           (SELECT CAST(source_ref AS INTEGER) FROM idx_embedding WHERE source_kind = 'episode')"
            .to_string()
    } else {
        format!(
            "SELECT event_id, text FROM idx_episode \
             WHERE event_id NOT IN \
               (SELECT CAST(source_ref AS INTEGER) FROM idx_embedding WHERE source_kind = 'episode') \
             LIMIT {limit}"
        )
    };

    let mut stmt = conn
        .prepare(&sql)
        .context("prepare unembedded_episode_ids")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .context("query unembedded_episode_ids")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect unembedded_episode_ids")?;
    Ok(rows)
}

/// `neoth memory --pipeline-scorecard` — GOLD-ADAPT-MEM-11.
///
/// Reads the live views.db and prints the 15-point per-subsystem pipeline
/// scorecard. In Table mode each subsystem is one row (name | score% | grade).
/// In JSON/JSONL mode the full [`PipelineScorecard`] struct is emitted.
///
/// Returns `Ok(())` regardless of grade so the caller decides on exit code;
/// the `--pipeline-scorecard` subcommand exits 1 via a signal-error when the
/// overall grade is below C (HEALTHY_THRESHOLD) — same pattern as doctor.
async fn run_memory_pipeline_scorecard(args: &MemoryArgs) -> Result<()> {
    use crate::memory::{scorecard, store};

    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).with_context(|| {
        format!(
            "open views.db for pipeline-scorecard: {}",
            db_path.display()
        )
    })?;

    let now_unix = crate::time::now_unix_i64();
    let sc = scorecard::read_and_compute_pipeline_scorecard(&conn, now_unix)
        .with_context(|| "compute pipeline scorecard")?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&sc)?);
        }
        OutputFormat::Table => {
            println!(
                "# Memory pipeline scorecard (MEM-11) — overall: {} ({:.1}%)",
                sc.overall_grade,
                sc.overall_composite * 100.0,
            );
            println!();
            println!("  {:<32}  {:>7}  {:>5}", "subsystem", "score%", "grade");
            println!("  {}  {}  {}", "-".repeat(32), "-".repeat(7), "-".repeat(5));
            for sub in &sc.subsystems {
                println!(
                    "  {:<32}  {:>6.1}%  {:>5}",
                    sub.name,
                    sub.score * 100.0,
                    sub.grade,
                );
            }
            println!("  {}  {}  {}", "-".repeat(32), "-".repeat(7), "-".repeat(5));
            println!(
                "  {:<32}  {:>6.1}%  {:>5}",
                "OVERALL",
                sc.overall_composite * 100.0,
                sc.overall_grade,
            );
            println!();
            if sc.is_healthy {
                println!(
                    "  status: HEALTHY (grade {} >= C threshold)",
                    sc.overall_grade
                );
            } else {
                println!(
                    "  status: UNHEALTHY (grade {} < C threshold — inspect subsystems above)",
                    sc.overall_grade
                );
            }
        }
    }

    // Non-zero exit when unhealthy so scripts can gate: `neoth memory --pipeline-scorecard || alert`
    if !sc.is_healthy {
        anyhow::bail!(
            "memory pipeline scorecard: overall grade {} is below the healthy threshold (C)",
            sc.overall_grade
        );
    }
    Ok(())
}

/// `neoth memory --archive YYYY-MM-DD` — list session MD files for one day.
async fn run_memory_archive(args: &MemoryArgs, day: &str) -> Result<()> {
    use crate::memory::archive;
    let root = archive::default_archive_root();
    let files = archive::list_for_day(&root, day).await?;
    match args.output {
        OutputFormat::Json => {
            let v: Vec<_> = files
                .iter()
                .map(|p| serde_json::json!({"path": p.display().to_string()}))
                .collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        OutputFormat::Jsonl => {
            for p in &files {
                println!("{}", serde_json::json!({"path": p.display().to_string()}));
            }
        }
        OutputFormat::Table => {
            if files.is_empty() {
                println!("no archived sessions for {day}.");
                return Ok(());
            }
            println!("# {} session(s) for {day}", files.len());
            for p in &files {
                println!("  {}", p.display());
            }
        }
    }
    Ok(())
}

/// `neoth memory --pin <event_id>` / `--unpin <event_id>` — NN-MEM-01 toggle the
/// decay-immune flag on a hot-tier episode. A pinned episode is skipped by the
/// daily consolidation importance-decay pass, so a critical-but-rarely-accessed
/// memory can never fall below `FORGET_FLOOR` and be forgotten. Operates on
/// `idx_episode` (the hot tier) only; an `event_id` already consolidated to
/// warm/cold — or unknown — affects 0 rows and is reported as not-found rather
/// than erroring (a soft no-op).
async fn run_memory_pin(args: &MemoryArgs, event_id: i64, pinned: bool) -> Result<()> {
    use crate::memory::store;
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for pin: {}", db_path.display()))?;
    let affected = store::set_episode_pinned(&conn, event_id, pinned)
        .with_context(|| format!("set pinned={pinned} on event_id={event_id}"))?;
    let action = if pinned { "pinned" } else { "unpinned" };
    info!(event_id, pinned, affected, action, "memory pin toggled");
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "event_id": event_id,
                    "pinned": pinned,
                    "rows_affected": affected,
                    "found": affected > 0,
                }))?
            );
        }
        OutputFormat::Table => {
            if affected == 0 {
                println!(
                    "no hot-tier episode with event_id={event_id} \
                     (already consolidated to warm/cold, or unknown id)."
                );
            } else {
                println!("event_id={event_id} {action} (decay-immune={pinned}).");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn memory_graph_label_normalizes_cross_platform_line_endings_and_caps_length() {
        let label = format!("alpha\r\nbeta\ngamma\r{}", "x".repeat(100));
        let normalized = memory_graph_label(&label);
        assert!(
            !normalized
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        );
        assert!(normalized.starts_with("alpha  beta gamma "));
        assert_eq!(normalized.chars().count(), 80);
    }

    fn seed_communication_profile(
        home: &std::path::Path,
        subject_id: &str,
        session_id: &str,
        event_hash: [u8; 32],
    ) {
        use crate::profile::communication::{
            CommunicationScope, DirectnessPreference, PreferenceValue,
        };

        crate::profile::communication::set_explicit_preference(
            home,
            &crate::config::CommunicationProfileConfig::default(),
            subject_id,
            session_id,
            PreferenceValue::Directness(DirectnessPreference::Direct),
            event_hash,
            1_700_000_000,
            CommunicationScope::Global,
            false,
        )
        .unwrap();
    }

    fn seed_operator_communication_profile(home: &std::path::Path) {
        seed_communication_profile(
            home,
            COMMUNICATION_OPERATOR_SUBJECT,
            "private-session-id",
            [7; 32],
        );
    }

    fn pin_test_args(db: PathBuf, pin: Option<i64>, unpin: Option<i64>) -> MemoryArgs {
        MemoryArgs {
            action: None,
            show: false,
            paths: false,
            size: false,
            tier: None,
            archive: None,
            forget: None,
            graph: false,
            graph_limit: 400,
            confirm: false,
            physical: false,
            pin,
            unpin,
            dimension: false,
            people: false,
            rebuild_index: false,
            embed_backfill: false,
            pipeline_scorecard: false,
            limit: 20,
            db: Some(db),
            output: OutputFormat::Table,
        }
    }

    #[test]
    fn memory_show_subcommand_is_wired_and_resolves_episode_provenance() {
        use crate::cli::{Cli, Commands};
        use crate::memory::{groundtruth, store};
        use clap::Parser;

        let cli = Cli::try_parse_from(["neoth", "memory", "show", "--limit", "7"])
            .expect("memory show must be a real clap subcommand");
        let Commands::Memory(parsed) = cli.command else {
            panic!("expected memory command");
        };
        assert!(matches!(
            parsed.action,
            Some(MemoryAction::Show {
                id: None,
                verified_only: false
            })
        ));
        assert_eq!(parsed.limit, 7);

        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_episode(&conn, 71, "source episode");
        let fact_id = groundtruth::insert_with_evidence(
            &conn,
            "derived operator fact",
            &groundtruth::Source::OperatorRuntime,
            "global",
            123,
            &[71],
        )
        .unwrap();

        let rows = load_memory_show_rows(&conn, Some(fact_id), 20, false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provenance_kind, "episode-backlinks");
        assert_eq!(rows[0].episode_evidence.len(), 1);
        assert_eq!(rows[0].episode_evidence[0].event_id, 71);
        assert_eq!(rows[0].episode_evidence[0].tier, "hot");
        assert!(rows[0].unresolved_episode_ids.is_empty());

        let synthesis_id = groundtruth::insert_with_evidence(
            &conn,
            "candidate synthesis with provenance",
            &groundtruth::Source::Synthesis,
            "meta",
            124,
            &[71],
        )
        .unwrap();
        let all_active = load_memory_show_rows(&conn, None, 20, false).unwrap();
        assert!(
            all_active.iter().any(|row| row.fact.id == synthesis_id),
            "operator provenance inspection defaults to all active states"
        );
        let verified_only = load_memory_show_rows(&conn, None, 20, true).unwrap();
        assert!(
            verified_only.iter().all(|row| row.fact.id != synthesis_id),
            "--verified-only retains the recall trust boundary"
        );
    }

    #[test]
    fn communication_profile_erasure_subcommand_is_explicitly_confirmed() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;

        let cli = Cli::try_parse_from([
            "neoth",
            "memory",
            "erase-communication-profile",
            "--confirm",
            "--home",
            "C:/isolated-neoth",
        ])
        .unwrap();
        let Commands::Memory(args) = cli.command else {
            panic!("memory command expected")
        };
        let Some(MemoryAction::EraseCommunicationProfile {
            subject,
            confirm,
            home,
        }) = args.action
        else {
            panic!("communication-profile erasure action expected")
        };
        assert!(subject.is_none(), "omission must preserve operator default");
        assert!(confirm);
        assert_eq!(home, Some(PathBuf::from("C:/isolated-neoth")));

        let cli = Cli::try_parse_from([
            "neoth",
            "memory",
            "erase-communication-profile",
            "--subject",
            "native:matrix:AbC",
        ])
        .unwrap();
        let Commands::Memory(args) = cli.command else {
            panic!("memory command expected")
        };
        let Some(MemoryAction::EraseCommunicationProfile { subject, .. }) = args.action else {
            panic!("communication-profile erasure action expected")
        };
        assert_eq!(subject.as_deref(), Some("native:matrix:AbC"));
    }

    #[tokio::test]
    async fn selected_communication_subject_dry_runs_then_deletes_only_it_and_audits() {
        let home = tempdir().unwrap();
        seed_operator_communication_profile(home.path());
        let selected = "native:matrix:other-hash";
        seed_communication_profile(home.path(), selected, "other-private-session", [8; 32]);
        let before = crate::profile::communication::load_state(home.path()).unwrap();
        let args = MemoryArgs {
            output: OutputFormat::Table,
            ..Default::default()
        };

        run_communication_profile_erasure(&args, Some(selected), false, Some(home.path()))
            .await
            .unwrap();
        let dry_run_state = crate::profile::communication::load_state(home.path()).unwrap();
        assert!(dry_run_state.subjects.contains_key(selected));
        assert!(
            dry_run_state
                .subjects
                .contains_key(COMMUNICATION_OPERATOR_SUBJECT)
        );
        assert!(!home.path().join("wal").exists());

        run_communication_profile_erasure(&args, Some(selected), true, Some(home.path()))
            .await
            .unwrap();
        let after = crate::profile::communication::load_state(home.path()).unwrap();
        assert!(!after.subjects.contains_key(selected));
        assert!(after.subjects.contains_key(COMMUNICATION_OPERATOR_SUBJECT));
        assert_eq!(after.revision, before.revision + 1);

        let segments = std::fs::read_dir(home.path().join("wal"))
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("wal"))
            .collect::<Vec<_>>();
        assert_eq!(segments.len(), 1);
        let bytes = std::fs::read(&segments[0]).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let frame = crate::wal::frame::decode_frame(&bytes[segment_header.header_len()..]).unwrap();
        assert_eq!(
            frame.header.event_type,
            crate::wal::events::EVENT_TYPE_EXTENDED
        );
        assert_eq!(
            frame.header.event_subtype,
            crate::wal::events::ExtendedSubtype::CommunicationProfileControlled as u8
        );
        let payload_text = std::str::from_utf8(frame.payload).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        let keys = payload
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "action_code",
                "changed",
                "schema_version",
                "state_revision_observed",
                "subject_revision_observed",
                "subject_sha256",
                "ts_unix",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            payload["action_code"],
            crate::cli::profile::CommunicationControlAction::ForgetSubject as u8
        );
        assert_eq!(payload["changed"], true);
        assert_eq!(payload["state_revision_observed"], after.revision);
        assert!(payload["subject_revision_observed"].is_null());
        assert_eq!(
            payload["subject_sha256"],
            crate::daemon::export::communication_subject_sha256(selected)
        );
        for sensitive in [
            COMMUNICATION_OPERATOR_SUBJECT,
            selected,
            "private-session-id",
            "other-private-session",
            "direct",
            "adhd",
        ] {
            assert!(!payload_text.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn omitted_subject_keeps_backward_compatible_operator_erasure() {
        let home = tempdir().unwrap();
        seed_operator_communication_profile(home.path());
        let args = MemoryArgs {
            output: OutputFormat::Json,
            ..Default::default()
        };

        run_communication_profile_erasure(&args, None, true, Some(home.path()))
            .await
            .unwrap();
        assert!(
            !crate::profile::communication::load_state(home.path())
                .unwrap()
                .subjects
                .contains_key(COMMUNICATION_OPERATOR_SUBJECT)
        );
    }

    #[tokio::test]
    async fn explicit_unknown_or_case_mismatched_subject_fails_without_mutation_or_audit() {
        let home = tempdir().unwrap();
        seed_operator_communication_profile(home.path());
        let before = crate::profile::communication::load_state(home.path()).unwrap();
        let args = MemoryArgs::default();

        for selector in ["Operator", "unknown-subject"] {
            let error =
                run_communication_profile_erasure(&args, Some(selector), true, Some(home.path()))
                    .await
                    .unwrap_err();
            assert!(format!("{error:#}").contains("exact and case-sensitive"));
        }
        let after = crate::profile::communication::load_state(home.path()).unwrap();
        assert_eq!(after, before);
        assert!(!home.path().join("wal").exists());

        let error =
            run_communication_profile_erasure(&args, Some(" operator"), false, Some(home.path()))
                .await
                .unwrap_err();
        assert!(format!("{error:#}").contains("invalid communication-profile subject selector"));
    }

    #[test]
    fn topic_forget_never_erases_unaddressable_communication_profile() {
        let home = tempdir().unwrap();
        seed_operator_communication_profile(home.path());
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (811, 1, 1000, 'erase Acme topic', 'h', 0.5, 0)",
            [],
        )
        .unwrap();

        let report = crate::memory::forget::forget_by_topic(&conn, "Acme", 1_700_000_001).unwrap();
        assert_eq!(report.episode_rows, 1);
        assert!(
            crate::profile::communication::load_state(home.path())
                .unwrap()
                .subjects
                .contains_key(COMMUNICATION_OPERATOR_SUBJECT)
        );
        let metadata = communication_profile_topic_forget_metadata();
        assert_eq!(metadata["subjects_deleted"], 0);
        assert_eq!(metadata["topic_addressable"], false);
        assert_eq!(metadata["erase_with"], COMMUNICATION_ERASE_COMMAND);
    }

    #[test]
    fn memory_show_reports_source_attribution_and_missing_historical_backlinks() {
        use crate::memory::{groundtruth, store};

        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let direct_id = groundtruth::insert(
            &conn,
            "operator-attested fact",
            &groundtruth::Source::OperatorRuntime,
            "global",
            1,
        )
        .unwrap();
        let direct = load_memory_show_rows(&conn, Some(direct_id), 20, false).unwrap();
        assert_eq!(direct[0].provenance_kind, "source-attribution");

        insert_episode(&conn, 72, "temporary source");
        let derived_id = groundtruth::insert_with_evidence(
            &conn,
            "historical derived fact",
            &groundtruth::Source::OperatorRuntime,
            "global",
            2,
            &[72],
        )
        .unwrap();
        conn.execute("DELETE FROM idx_episode WHERE event_id = 72", [])
            .unwrap();
        let historical = load_memory_show_rows(&conn, Some(derived_id), 20, false).unwrap();
        assert!(historical[0].episode_evidence.is_empty());
        assert_eq!(historical[0].unresolved_episode_ids, vec![72]);
    }

    #[tokio::test]
    async fn pin_unpin_toggles_episode_decay_immunity() {
        use crate::memory::store;
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        {
            let conn = store::open(&db).unwrap();
            conn.execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (7, 1, 1000, 'critical fact', 'h', 0.9, 0)",
                [],
            )
            .unwrap();
        }
        let read_pinned = |id: i64| -> i64 {
            let conn = store::open(&db).unwrap();
            conn.query_row(
                "SELECT pinned FROM idx_episode WHERE event_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(read_pinned(7), 0, "starts unpinned");

        run_memory_pin(&pin_test_args(db.clone(), Some(7), None), 7, true)
            .await
            .unwrap();
        assert_eq!(read_pinned(7), 1, "after --pin the row is decay-immune");

        run_memory_pin(&pin_test_args(db.clone(), None, Some(7)), 7, false)
            .await
            .unwrap();
        assert_eq!(read_pinned(7), 0, "after --unpin the row decays again");

        // Unknown id is a soft no-op: no panic, no error, no row changed.
        run_memory_pin(&pin_test_args(db.clone(), Some(999), None), 999, true)
            .await
            .unwrap();
        assert_eq!(read_pinned(7), 0, "unrelated row untouched");
    }

    #[tokio::test]
    async fn physical_redaction_returns_zero_when_wal_dir_absent() {
        // Fresh install: WAL dir hasn't been created yet. Redaction
        // must be a no-op rather than a hard error so `--physical`
        // works on a pre-daemon-boot system.
        let dir = tempdir().unwrap();
        let wal_dir = dir.path().join("never_existed");
        let summary = run_physical_redaction(&wal_dir, "anything", 1700)
            .await
            .unwrap();
        assert_eq!(summary.segments_touched, 0);
        assert_eq!(summary.frames_redacted, 0);
        assert_eq!(summary.bytes_redacted, 0);
        assert_eq!(summary.errors, 0);
    }

    #[tokio::test]
    async fn physical_redaction_propagates_non_not_found_directory_errors() {
        // Only a genuinely absent WAL directory is a benign fresh-install
        // no-op. A configured path that cannot be enumerated must never turn
        // into a zero-error GDPR success report.
        let dir = tempdir().unwrap();
        let not_a_directory = dir.path().join("wal-is-a-file");
        std::fs::write(&not_a_directory, b"not a directory").unwrap();

        let error = run_physical_redaction(&not_a_directory, "anything", 1700)
            .await
            .expect_err("non-directory WAL root must fail closed");
        assert!(
            format!("{error:#}").contains("open WAL directory"),
            "error must identify the unreadable WAL root: {error:#}"
        );
    }

    #[tokio::test]
    async fn physical_redaction_skips_non_wal_files_in_dir() {
        // Operators occasionally drop notes / `.bak` files into
        // `~/.neoth/wal/`. The scanner must ignore them (no extension
        // mismatch errors crash the run).
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"not a wal").unwrap();
        std::fs::write(dir.path().join("000001.wal.bak"), b"backup").unwrap();
        let summary = run_physical_redaction(dir.path(), "topic", 1701)
            .await
            .unwrap();
        // No `.wal` files → nothing touched.
        assert_eq!(summary.segments_touched, 0);
        assert_eq!(summary.frames_redacted, 0);
    }

    #[test]
    fn physical_redaction_audit_segments_are_collision_resistant() {
        // Two operator invocations inside the same wall-clock second used to
        // target `memory-redact-{now_unix}.wal`. The second writer could collide
        // with the first and leave both the erasure result and its audit trail
        // incomplete. UUIDv7 standalone namespaces make the path unique while
        // preserving the normal `.wal` rotation contract.
        let dir = tempdir().unwrap();
        let first = physical_redaction_audit_segment_path(dir.path());
        let second = physical_redaction_audit_segment_path(dir.path());
        assert_ne!(
            first, second,
            "concurrent audit writers need distinct paths"
        );
        for path in [first, second] {
            assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("wal"));
            assert!(
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| stem.ends_with("-memory-redact-000001")),
                "audit segment must retain the standalone writer namespace: {}",
                path.display()
            );
        }
    }

    #[tokio::test]
    async fn physical_redaction_walks_real_wal_segment_end_to_end() {
        // Build a fresh WAL segment, write two frames (one matching),
        // run the redactor, verify the summary reports one redaction.
        use crate::wal::segment_header::SegmentHeader;
        use crate::wal::types::{EventFlags, EventId, Importance, NodeId, SessionId};
        use crate::wal::{HeaderBuilder, frame::encode_frame};

        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("000001.wal");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SegmentHeader::new(1, 1, 0, 0, [0u8; 16]).to_le_bytes());
        for payload in [b"unrelated frame".as_slice(), b"AcmeCorp data".as_slice()] {
            let h = HeaderBuilder::new(0x01, payload).build();
            bytes.extend_from_slice(&encode_frame(&h, payload));
            // Suppress unused-warning markers — these come from the
            // newtype constructors we reference transitively above.
            let _ = (
                EventFlags::empty(),
                EventId(0),
                Importance::new(0.5).unwrap(),
                SessionId([0u8; 16]),
                NodeId([0u8; 16]),
            );
        }
        std::fs::write(&seg_path, &bytes).unwrap();

        let summary = run_physical_redaction(dir.path(), "acmecorp", 1702)
            .await
            .unwrap();
        assert_eq!(summary.segments_touched, 1);
        assert_eq!(summary.frames_redacted, 1);
        assert_eq!(summary.bytes_redacted, "AcmeCorp data".len() as u64);
        assert_eq!(summary.errors, 0);
        // C-15 follow-up: REDACTION_MARKER must fire on segments that
        // actually had frames redacted.
        assert_eq!(summary.markers_emitted, 1, "one marker per touched segment");
        assert!(summary.audit_segment.is_some());
    }

    #[test]
    fn physical_erasure_incomplete_when_any_error() {
        // GR-008: a `--physical` pass with any errors (a segment that refused
        // redaction and/or a failed audit marker) is NOT a confirmed wipe — the
        // CLI must warn + fail loud, not print an affirmative success message.
        let clean = PhysicalRedactSummary {
            frames_redacted: 3,
            errors: 0,
            ..Default::default()
        };
        assert!(
            !physical_erasure_incomplete(&clean),
            "no errors → confirmed complete"
        );
        let errored = PhysicalRedactSummary {
            frames_redacted: 0,
            errors: 1,
            ..Default::default()
        };
        assert!(
            physical_erasure_incomplete(&errored),
            "a refused-redaction error must mark the erasure incomplete"
        );
    }

    #[tokio::test]
    async fn physical_redaction_emits_no_marker_when_no_frames_match() {
        // A segment that walks clean (no predicate matches) should
        // NOT emit a REDACTION_MARKER — no audit clutter for non-events.
        use crate::wal::segment_header::SegmentHeader;
        use crate::wal::{HeaderBuilder, frame::encode_frame};

        let dir = tempdir().unwrap();
        let seg_path = dir.path().join("clean.wal");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SegmentHeader::new(1, 1, 0, 0, [0u8; 16]).to_le_bytes());
        let p = b"completely unrelated frame body";
        let h = HeaderBuilder::new(0x01, p).build();
        bytes.extend_from_slice(&encode_frame(&h, p));
        std::fs::write(&seg_path, &bytes).unwrap();

        let summary = run_physical_redaction(dir.path(), "no-such-topic", 1703)
            .await
            .unwrap();
        assert_eq!(summary.segments_touched, 1);
        assert_eq!(summary.frames_redacted, 0);
        assert_eq!(summary.markers_emitted, 0, "no marker without redaction");
    }

    // ── GOLD-ADAPT-MEMGRAPH-01: embed_backfill tests ───────────────────────

    /// Minimal stub that always returns a fixed unit vector — no real inference
    /// backend needed in unit tests.
    struct FixedEmbed2d {
        x: f32,
        y: f32,
    }

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for FixedEmbed2d {
        fn name(&self) -> &'static str {
            "fixed-2d"
        }
        fn default_dim(&self) -> usize {
            2
        }
        async fn embed(
            &self,
            _req: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            let n = (self.x * self.x + self.y * self.y).sqrt();
            Ok(crate::providers::embed::EmbedResponse {
                vector: vec![self.x / n, self.y / n],
                model: "fixed-2d".to_string(),
                latency: std::time::Duration::ZERO,
            })
        }
    }

    fn insert_episode(conn: &rusqlite::Connection, event_id: i64, text: &str) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, ?3, ?4, 0.5, 0)",
            rusqlite::params![event_id, event_id * 1000, text, format!("h{event_id}")],
        )
        .unwrap();
    }

    /// Two episodes → backfill → both get idx_embedding rows.
    #[tokio::test]
    async fn embed_backfill_embeds_all_unembedded_episodes() {
        use crate::memory::{embeddings, store};

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let mut conn = store::open(&db_path).unwrap();
        insert_episode(&conn, 1, "first episode text");
        insert_episode(&conn, 2, "second episode text");

        // Both episodes start un-embedded.
        let before = unembedded_episode_ids(&conn, 0).unwrap();
        assert_eq!(before.len(), 2, "both episodes unembedded before backfill");

        let provider = FixedEmbed2d { x: 1.0, y: 0.0 };
        for (event_id, text) in &before {
            conn = embeddings::embed_episode_text(conn, *event_id, text, &provider).await;
        }

        let after = unembedded_episode_ids(&conn, 0).unwrap();
        assert_eq!(after.len(), 0, "no unembedded episodes after backfill");

        // Verify the rows exist in idx_embedding.
        for id in [1i64, 2] {
            let found: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM idx_embedding \
                     WHERE source_kind = 'episode' AND source_ref = ?1",
                    rusqlite::params![id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(found, "idx_embedding row missing for event_id={id}");
        }
    }

    /// Second backfill run after all episodes are already embedded → 0 newly embedded
    /// (idempotent, already-embedded rows are skipped by the NOT IN query).
    #[tokio::test]
    async fn embed_backfill_is_idempotent() {
        use crate::memory::{embeddings, store};

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let mut conn = store::open(&db_path).unwrap();
        insert_episode(&conn, 10, "some memory");

        let provider = FixedEmbed2d { x: 0.0, y: 1.0 };

        // First pass: embeds the episode.
        let pass1 = unembedded_episode_ids(&conn, 0).unwrap();
        assert_eq!(pass1.len(), 1);
        for (eid, text) in &pass1 {
            conn = embeddings::embed_episode_text(conn, *eid, text, &provider).await;
        }

        // Second pass: nothing left to embed.
        let pass2 = unembedded_episode_ids(&conn, 0).unwrap();
        assert_eq!(pass2.len(), 0, "idempotent: zero un-embedded on second run");
    }

    /// `unembedded_episode_ids` respects the `limit` cap.
    #[test]
    fn unembedded_episode_ids_respects_limit() {
        use crate::memory::store;

        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        for id in 1i64..=5 {
            insert_episode(&conn, id, "episode");
        }

        let all = unembedded_episode_ids(&conn, 0).unwrap();
        assert_eq!(all.len(), 5);

        let capped = unembedded_episode_ids(&conn, 3).unwrap();
        assert_eq!(capped.len(), 3, "limit=3 caps the result");
    }
}
