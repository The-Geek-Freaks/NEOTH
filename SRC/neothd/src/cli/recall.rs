//! `neoth recall <query>` — search the SQLite views for matching text.
//!
//! Runs the indexer once before querying so freshly-written WAL frames are
//! included. Output format follows the global `--output` flag.

use std::path::{Path, PathBuf};

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

    /// Populated from the global `--output` flag.
    #[arg(skip)]
    pub output: crate::cli::OutputFormat,
}

/// Result of the blocking recall task: the ranked rows plus the Hebbian
/// reinforcement records (event_id + frame) to audit on the async side.
type RecallTaskOutput = (Vec<EpisodeHit>, Vec<(i64, ReinforceFrame)>);

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
    // The Connection moves INTO the blocking task and stays there: both
    // the multi-tier read AND the Hebbian reinforcement writes run on the
    // blocking thread (GOLD-SEC-06), and only the computed rows +
    // reinforcement records cross back out. `move` semantics keep the
    // Connection's !Send constraint satisfied — it never crosses an async
    // await point while in scope.
    let query = args.query.clone();
    let limit = args.limit;
    let (rows, reinforcements) = tokio::task::spawn_blocking(
        move || -> Result<RecallTaskOutput> {
            // RECALL-METER-01: time the full multi-tier recall query.
            let recall_t0 = std::time::Instant::now();
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

            Ok((rows, reinforcements))
        },
    )
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
    Ok(())
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
    let base =
        tiers::ranking_score_repromoted(importance, age_tier, rank_tier, days_since, h.access_count);
    // JV-MEM-14: weight by source trust so operator-explicit memories outrank
    // lower-trust external chatter at equal relevance.
    let base = base * tiers::trust_weight(h.trust);
    // JV-MEM-07: length normalization — a gentle logarithmic penalty on verbose
    // entries so they don't win on raw keyword density. Entries at/below the
    // 300-char anchor are unpenalised (ratio clamped to 1 → log2(1)=0 → factor
    // 1); a 2×/4×/8×-anchor entry is scaled by 1/2 / 1/3 / 1/4. The factor is
    // always in (0, 1], so the score stays ≥ 0 and finite.
    const LEN_ANCHOR_CHARS: f64 = 300.0;
    let ratio = (h.text.chars().count() as f64 / LEN_ANCHOR_CHARS).max(1.0);
    let length_norm = 1.0 / (1.0 + ratio.log2());
    base * length_norm
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
/// error → empty hits → "nothing found", never an `Err` — a recall miss
/// must not break the chat turn.
pub(crate) async fn answer_conversational_recall(prompt: &str, db_path: &Path) -> Option<String> {
    let query = crate::recall::conversational::detect_recall_intent(prompt)?;
    const RECALL_LIMIT: usize = 5;
    // Run the synchronous rusqlite query off the async worker (mirrors the
    // main recall path's spawn_blocking, K-Perf-3). A JoinError degrades to
    // empty hits → the localized "nothing found" reply, preserving the
    // best-effort contract.
    let db_owned = db_path.to_path_buf();
    let topic = query.topic.clone();
    let hits = tokio::task::spawn_blocking(move || {
        recall_episodes_best_effort(&db_owned, &topic, RECALL_LIMIT)
    })
    .await
    .unwrap_or_default();
    Some(crate::recall::conversational::format_recall_reply(
        &hits,
        query.language,
        &query.topic,
    ))
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
/// Best-effort — a missing DB or any query error yields an empty Vec so
/// the caller renders the localized "nothing found" reply instead of
/// failing the chat turn.
fn recall_episodes_best_effort(db_path: &Path, topic: &str, limit: usize) -> Vec<EpisodeHit> {
    if !db_path.exists() {
        return Vec::new();
    }
    let conn = match store::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "conversational recall: views.db open failed; empty hits");
            return Vec::new();
        }
    };
    match recall_fts(&conn, topic, limit) {
        Ok(hits) if !hits.is_empty() => hits,
        _ => recall_like(&conn, topic, limit).unwrap_or_default(),
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
                access_count: 0,
                // Ground-truth is operator-asserted → highest source trust.
                trust: 2,
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

/// Image → embedding store similarity recall.
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
/// `memory.vector_index.backend: hnsw`, else `None` (brute-force). Best-effort:
/// a missing/unparseable freedom.yaml falls back to brute-force (the safe
/// default), so recall never errors on a config problem.
fn configured_hnsw_path() -> Option<std::path::PathBuf> {
    let cfg = crate::config::FreedomConfig::load_from_default_path().ok()?;
    match cfg.memory.vector_index.backend {
        crate::config::VectorBackend::Hnsw => Some(crate::memory::embeddings::hnsw_snapshot_path(
            &crate::config::FreedomConfig::default_neoth_home(),
        )),
        crate::config::VectorBackend::BruteForce => None,
    }
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
    let hnsw = configured_hnsw_path().filter(|_| {
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
    let hnsw = configured_hnsw_path().filter(|_| {
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
    let segment_path = FreedomConfig::default_wal_dir().join("000001.wal");
    let (writer, _join) = match crate::wal::writer::spawn(segment_path) {
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
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
            query: "wifi".to_string(),
            limit: 10,
            db: Some(db.clone()),
            wal_segment: Some(seg.clone()),
            no_index_pass: false,
            similar_to: None,
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
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
            mk(1, "x".repeat(1200)),       // verbose → length-penalised
            mk(2, "short note".to_string()), // short → unpenalised, outranks it
        ];
        rank_in_place(&mut rows, now_ns);
        assert_eq!(rows[0].event_id, 2, "the short entry outranks the verbose one");
        assert_eq!(rows[1].event_id, 1);
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
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("x.png")),
            similar_to_text: Some("sunset".to_string()),
            similar_kind: "image".to_string(),
            citation_check: None,
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
            query: String::new(),
            limit: 5,
            db: Some(db),
            wal_segment: None,
            no_index_pass: true,
            similar_to: Some(dir.path().join("not-a-file.png")),
            similar_to_text: None,
            similar_kind: "image".to_string(),
            citation_check: None,
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
        let reply =
            answer_conversational_recall("Do you remember when we talked about rust?", &db)
                .await
                .expect("recall intent must produce a reply");
        assert!(reply.starts_with("Yes — "), "english template: {reply}");
        assert!(reply.contains("rust ist gut"), "reply must quote the episode: {reply}");

        // Normal prompt → None → falls through to the provider unchanged.
        assert!(
            answer_conversational_recall("What is the capital of France?", &db)
                .await
                .is_none()
        );

        // Recall intent but no match → Some(localized "nothing found"), NOT None
        // (the short-circuit still fires; the operator learns the recall ran).
        let miss = answer_conversational_recall("Do you remember when we talked about zzzqqq?", &db)
            .await
            .expect("recall intent fires even with no hit");
        assert!(miss.contains("Nothing found"), "empty match → localized miss: {miss}");
    }

    #[tokio::test]
    async fn answer_conversational_recall_empty_db_returns_nothing_found_not_error() {
        // GOLD-WIRE-02 best-effort: a missing/empty views.db must not error —
        // the recall short-circuit still fires and renders "nothing found".
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.db");
        let reply =
            answer_conversational_recall("weißt du noch als wir über rust geredet haben?", &missing)
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
        assert!(channel_recall_authorized(Some("op-uuid-1"), Some("op-uuid-1")));
        // A different sender on the same channel → never gets the operator's memory.
        assert!(!channel_recall_authorized(Some("rando-uuid"), Some("op-uuid-1")));
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
}
