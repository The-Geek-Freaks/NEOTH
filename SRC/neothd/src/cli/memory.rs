//! `neoth memory` — operator-facing view of the memory subsystem.
//!
//! Phase 25 R-14 (assembled NEOTH.md context inspection) +
//! Phase 28a R-22 MT-5 (tier filter + session-archive browse).
//!
//! Modes (mutually exclusive groups):
//!   `--show`  (default) print the assembled NEOTH.md blocks with attribution
//!   `--paths` list only the source paths, one per line
//!   `--size`  print total byte count + per-block breakdown
//!   `--tier <hot|warm|cold>`  filter recall by memory tier (R-22)
//!   `--archive <YYYY-MM-DD>`  list session MD files for one day (R-22)

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
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

#[derive(Args, Debug, Clone)]
pub struct MemoryArgs {
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

    /// V10-08 — rebuild the HNSW embedding index from scratch by scanning
    /// all rows in `idx_embedding`. Writes the snapshot to
    /// `<neoth_home>/embeddings.hnsw`. Use after a database restore or when
    /// the snapshot is missing or corrupted. Safe to interrupt: the snapshot
    /// is written atomically (temp-file + rename).
    #[arg(long, conflicts_with_all = ["show", "paths", "size", "tier", "archive", "forget", "dimension"])]
    pub rebuild_index: bool,

    /// Max rows for `--tier` recall.
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Override the views.db path for `--tier`.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_memory(args: MemoryArgs) -> Result<()> {
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
    if args.rebuild_index {
        return run_memory_rebuild_index(&args).await;
    }

    let home = FreedomConfig::default_neoth_home();
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
    info!(home = %home.display(), cwd = %cwd.display(), "assembling operator context");

    let blocks = assemble(&home, &cwd).await?;
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
    }
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
                println!("  [{:>10}] imp={:.3}  {preview}", id, imp);
            }
        }
    }
    Ok(())
}

/// `neoth memory --forget <topic> [--confirm]` — GDPR cascade-delete.
///
/// Without `--confirm` this is a dry-run that prints what would be
/// deleted (operator sees the impact before committing). With
/// `--confirm` the deletion executes against the views.db; the
/// `memory::forget::forget_by_topic` function handles tier cascade +
/// ground-truth revocation + embedding wipe. WAL TOMBSTONE emission
/// is Phase 2 work — for now the audit row is a textual log entry on
/// the operator's terminal + the SQLite-side deletion is final.
async fn run_memory_forget(args: &MemoryArgs, topic: &str) -> Result<()> {
    use crate::memory::{forget, store};
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path)
        .with_context(|| format!("open views.db for forget: {}", db_path.display()))?;

    if !args.confirm {
        // Dry-run preview: COUNT matches per tier instead of DELETE.
        // Escape LIKE wildcards + ESCAPE so the preview matches the real
        // delete exactly (GOLD-SEC-04) — a `%` topic counts literal-`%`
        // rows, not the whole store.
        let pattern = format!("%{}%", crate::memory::escape_like(topic));
        let count = |sql: &str| -> i64 {
            conn.query_row(sql, rusqlite::params![&pattern], |r| r.get(0))
                .unwrap_or(0)
        };
        let ep =
            count("SELECT COUNT(*) FROM idx_episode WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'");
        let co = count(
            "SELECT COUNT(*) FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        );
        let lt = count(
            "SELECT COUNT(*) FROM idx_longterm WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        );
        let pr = count(
            "SELECT COUNT(*) FROM idx_profile \
             WHERE field COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                OR value_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        );
        let gt = count(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE revoked_at IS NULL AND statement COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        );
        let emb = count(
            "SELECT COUNT(*) FROM idx_embedding WHERE source_ref COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        );
        let total = ep + co + lt + pr + gt + emb;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let body = serde_json::json!({
                    "dry_run": true,
                    "topic": topic,
                    "would_delete": {
                        "idx_episode": ep,
                        "idx_consolidated": co,
                        "idx_longterm": lt,
                        "idx_profile": pr,
                        "idx_groundtruth_revoke": gt,
                        "idx_embedding": emb,
                        "total": total,
                    },
                    "confirm_with": "neoth memory --forget \"<topic>\" --confirm",
                });
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
            OutputFormat::Table => {
                println!("# Forget dry-run for topic `{topic}`");
                println!("  idx_episode      : {ep} rows");
                println!("  idx_consolidated : {co} rows");
                println!("  idx_longterm     : {lt} rows");
                println!("  idx_profile      : {pr} claims");
                println!("  idx_groundtruth  : {gt} would be revoked");
                println!("  idx_embedding    : {emb} vectors");
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
    let segment = wal_dir.join(format!("memory-forget-{}.wal", now_unix));
    let (writer, writer_join) =
        crate::wal::writer::spawn(segment.clone()).context("spawn WAL writer for tombstone")?;
    let report = forget::forget_by_topic_with_audit(&conn, topic, now_unix, "cli", &writer).await?;
    drop(writer);
    let _ = writer_join.await;
    // GR-005: the idx_embedding SQLite wipe inside forget does NOT touch the
    // on-disk HNSW snapshot — forgotten vectors stay searchable via the
    // cold-load path until a rebuild. Purge them by rebuilding the snapshot from
    // the now-wiped SQLite. Best-effort: a failure logs but doesn't fail the
    // forget (the SQLite truth is already erased; recall cold-loads from it / the
    // snapshot-refresh cron rebuilds later). Acts only when embeddings were forgotten.
    if report.embedding_rows > 0 {
        let home = crate::config::FreedomConfig::default_neoth_home();
        match crate::memory::embeddings::rebuild_snapshot_if_present(&conn, &home) {
            Ok(Some(n)) => info!(
                vectors = n,
                "GR-005: HNSW snapshot rebuilt after forget — forgotten embeddings purged from the searchable index"
            ),
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = %e,
                "GR-005: HNSW snapshot rebuild after forget failed; recall cold-loads from the (already-wiped) SQLite until the snapshot-refresh cron rebuilds it"
            ),
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
        audit_segment = %segment.display(),
        "forget executed (TOMBSTONE_REQUESTED audit frame written)"
    );
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Table => {
            println!("# Forget complete for topic `{topic}`");
            println!("  idx_episode      : {} rows deleted", report.episode_rows);
            println!(
                "  idx_consolidated : {} rows deleted",
                report.consolidated_rows
            );
            println!("  idx_longterm     : {} rows deleted", report.longterm_rows);
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
async fn run_physical_redaction(
    wal_dir: &std::path::Path,
    topic: &str,
    now_unix: i64,
) -> Result<PhysicalRedactSummary> {
    use crate::wal::redact;

    let mut summary = PhysicalRedactSummary::default();
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        Err(e) => {
            // WAL dir might not exist yet (fresh install, no daemon run).
            // Treat as zero-frames-redacted rather than an error.
            tracing::debug!(
                error = %e,
                wal_dir = %wal_dir.display(),
                "WAL dir absent; physical redaction is a no-op"
            );
            return Ok(summary);
        }
    };

    // Open a dedicated audit-only segment for the REDACTION_MARKER
    // frames. Same pattern as the TOMBSTONE_REQUESTED segment.
    std::fs::create_dir_all(wal_dir).context("create WAL dir for redaction audit")?;
    let audit_segment = wal_dir.join(format!("memory-redact-{}.wal", now_unix));
    let (audit_writer, audit_join) = crate::wal::writer::spawn(audit_segment.clone())
        .context("spawn WAL writer for redaction audit")?;

    for entry in entries.flatten() {
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
    let _ = audit_join.await;
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

    fn pin_test_args(db: PathBuf, pin: Option<i64>, unpin: Option<i64>) -> MemoryArgs {
        MemoryArgs {
            show: false,
            paths: false,
            size: false,
            tier: None,
            archive: None,
            forget: None,
            confirm: false,
            physical: false,
            pin,
            unpin,
            dimension: false,
            people: false,
            rebuild_index: false,
            limit: 20,
            db: Some(db),
            output: OutputFormat::Table,
        }
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
}
