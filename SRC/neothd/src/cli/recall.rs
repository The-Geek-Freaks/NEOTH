//! `neoth recall <query>` — search the SQLite views for matching text.
//!
//! Runs the indexer once before querying so freshly-written WAL frames are
//! included. Output format follows the global `--output` flag.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::params;
use tracing::info;

use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Populated from the global `--output` flag.
    #[arg(skip)]
    pub output: crate::cli::OutputFormat,
}

pub async fn run_recall(args: RecallArgs) -> Result<()> {
    // QM-18 citation-check short-circuit. No DB, no WAL, no network —
    // pure offline audit against the supplied text. `--citation-check -`
    // reads stdin so operators can pipe their drafts in.
    if let Some(text_arg) = args.citation_check.clone() {
        return run_citation_check(&text_arg, args.output).await;
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

    let now_ns: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    // K-Perf-3 full (2026-05-22): wrap the 5-tier SQLite query block in
    // `spawn_blocking` so the async runtime worker isn't pinned on
    // rusqlite for the full multi-tier read pass. Each query is bounded
    // by `LIMIT` (~5ms typical, longer on cold caches / large tables);
    // the cumulative CPU+I/O time off the async worker was the Phase-3
    // performance regression the agent flagged.
    //
    // The Connection moves INTO the blocking task and back OUT so the
    // Hebbian reinforcement pass below (which needs the conn + per-row
    // updates) can run on the async caller. `move` semantics keep the
    // Connection's !Send constraint satisfied — it never crosses an
    // async await point while in scope.
    let query = args.query.clone();
    let limit = args.limit;
    let (rows, conn) = tokio::task::spawn_blocking(move || -> Result<(Vec<EpisodeHit>, Connection)> {
        let hot = match recall_fts(&conn, &query, limit) {
            Ok(hits) if !hits.is_empty() => hits,
            Ok(_) => recall_like(&conn, &query, limit)?,
            Err(e) => {
                tracing::debug!(error = %e, "FTS5 match failed, falling back to LIKE");
                recall_like(&conn, &query, limit)?
            }
        };
        let warm = recall_warm_like(&conn, &query, limit)?;
        let cold = recall_cold_like(&conn, &query, limit)?;
        let gt_rows = recall_groundtruth_like(&conn, &query, limit)?;

        let mut episodic: Vec<EpisodeHit> =
            Vec::with_capacity(hot.len() + warm.len() + cold.len());
        episodic.extend(hot);
        episodic.extend(warm);
        episodic.extend(cold);
        rank_in_place(&mut episodic, now_ns);

        let mut rows: Vec<EpisodeHit> = Vec::with_capacity(gt_rows.len() + episodic.len());
        rows.extend(gt_rows);
        rows.extend(episodic);
        rows.truncate(limit);
        Ok((rows, conn))
    })
    .await
    .context("recall query task panicked")??;

    // Phase 28a R-22 MT-3: Hebbian reinforce on hot-tier hits.
    // Warm/cold rows live in different tables; reinforcement for those
    // tiers is a separate pass that the daemon's tail-indexer owns
    // (warm/cold reinforce is part of the daily consolidation cycle,
    // not per-recall). Soft-fails per row — a stale event_id returns
    // None and we move on. CLI path does not have a WAL writer; the
    // audit event (IMPORTANCE_REINFORCED 0x02) is emitted only on the
    // daemon path where the writer is available.
    for h in &rows {
        if h.tier != "hot" {
            continue;
        }
        match tiers::hebbian_reinforce_event(&conn, h.event_id, now_ns) {
            Ok(Some(out)) => tracing::debug!(
                event_id = h.event_id,
                tier = out.tier.as_str(),
                old = out.old,
                new = out.new,
                "hebbian reinforce on recall hit",
            ),
            Ok(None) => {}
            Err(e) => tracing::warn!(event_id = h.event_id, error = %e, "reinforce failed"),
        }
    }

    render(&rows, args.output, &args.query);
    Ok(())
}

/// Sort recall hits by composite ranking score, descending. Stable order so
/// ties fall back to the tier-local SQL ordering (ts_ns DESC / importance DESC).
fn rank_in_place(rows: &mut [EpisodeHit], now_ns: u64) {
    const NS_PER_DAY: f64 = 86_400.0 * 1_000_000_000.0;
    rows.sort_by(|a, b| {
        let score_a = composite_score(a, now_ns, NS_PER_DAY);
        let score_b = composite_score(b, now_ns, NS_PER_DAY);
        // Reverse compare for descending order. NaN treated as smallest.
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

fn composite_score(h: &EpisodeHit, now_ns: u64, ns_per_day: f64) -> f64 {
    let tier = match h.tier.as_str() {
        "warm" => tiers::Tier::Warm,
        "cold" => tiers::Tier::Cold,
        _ => tiers::Tier::Hot,
    };
    let importance = h.importance.unwrap_or(0.5);
    let age_ns = now_ns.saturating_sub(h.ts_ns.max(0) as u64) as f64;
    let days_since = (age_ns / ns_per_day).max(0.0);
    tiers::ranking_score(importance, tier, days_since)
}

/// FTS5 path. Uses MATCH with the raw query — FTS5 supports prefix (`foo*`),
/// phrase ("foo bar"), and boolean operators (AND/OR/NOT) out of the box.
/// BM25 ordering surfaces best matches first. ts_ns DESC is a tiebreaker.
fn recall_fts(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let mut stmt = conn.prepare(
        "SELECT e.event_id, e.event_type, e.ts_ns, e.text, e.text_hash, \
                e.channel, e.sender_id, e.operator_id, e.importance \
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

/// LIKE fallback (case-insensitive substring) over `idx_episode` (hot tier).
/// Used when FTS5 MATCH parses the query as empty (pure punctuation) or
/// returns zero rows for a partial word the FTS tokenizer split badly.
fn recall_like(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT event_id, event_type, ts_ns, text, text_hash, channel, sender_id, operator_id, importance \
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
                consolidated_ts AS ts_ns, text, text_hash, importance \
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
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// LIKE search over `idx_longterm` (cold tier, >90d Hebbian survivors).
fn recall_cold_like(conn: &Connection, query: &str, limit: usize) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT event_id, promoted_ts AS ts_ns, text, text_hash, importance \
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
fn recall_groundtruth_like(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<EpisodeHit>> {
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT id, statement, asserted_at \
         FROM idx_groundtruth \
         WHERE revoked_at IS NULL \
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
    })
}

// Required for the conn alias used above.
use rusqlite::Connection;

/// Image → embedding store similarity recall.
/// QM-18 citation-check CLI surface. Reads text from `arg` directly,
/// or from stdin when `arg == "-"`. Runs `recall::citation_check::
/// audit_offline` + renders the verdict per the global `--output`
/// flag.
async fn run_citation_check(arg: &str, output: crate::cli::OutputFormat) -> Result<()> {
    use crate::recall::citation_check::{audit_offline, CitationVerdict};

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
    let hits = embeddings::find_similar(conn, &query, kind_filter, args.limit)
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
    let hits = embeddings::find_similar(conn, &query, kind_filter, args.limit)
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
                serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into())
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
                if let Ok(line) = serde_json::to_string(h) {
                    println!("{line}");
                }
            }
            println!(
                "{}",
                serde_json::json!({"neoth_stream":"done","count":hits.len()})
            );
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hits).unwrap_or_else(|_| "[]".into())
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
            scope: 0,
            category: 0,
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
            query: "wifi".to_string(),
            limit: 10,
            db: Some(db.clone()),
            wal_segment: Some(seg.clone()),
            no_index_pass: false,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
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
    fn recall_groundtruth_like_returns_matching_active_facts() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = store::open(&db).unwrap();

        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (1, 'cube IP is 100.68.210.50', 'manual', 'global', 1, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (2, 'never reboot Cube', 'manual', 'global', 2, NULL)",
            [],
        )
        .unwrap();
        // Revoked row must NOT surface even if it matches the query.
        conn.execute(
            "INSERT INTO idx_groundtruth \
             (id, statement, source, scope, asserted_at, revoked_at) \
             VALUES (3, 'old cube fact', 'manual', 'global', 3, 100)",
            [],
        )
        .unwrap();

        let hits = recall_groundtruth_like(&conn, "cube", 10).expect("gt recall");

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

    #[tokio::test]
    async fn run_recall_rejects_empty_query_without_similar_to() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let _ = store::open(&db).unwrap();
        let args = RecallArgs {
            query: "   ".to_string(), // whitespace-only treated as empty
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
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
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("x.png")),
            similar_to_text: Some("sunset".to_string()),
            similar_kind: "image".to_string(),
            citation_check: None,
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
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("not-a-file.png")),
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
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
}
