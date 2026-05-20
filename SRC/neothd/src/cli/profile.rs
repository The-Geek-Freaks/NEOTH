//! `neoth profile` — read-only visibility into the user-profile state.
//!
//! Operators run the pipeline via channel ingress or `neoth chat` (when
//! the dispatch wires it up); this CLI surfaces the result. Pure read
//! against `idx_profile` — no writes, no LLM, no provider calls.
//!
//! Two actions:
//!   - `show [--field <path>]` lists every active claim (one row per
//!     field × extraction_id). With `--field`, filters to a single
//!     path (e.g. `identity.location`).
//!   - `summary` collapses to one row per field — the highest-confidence
//!     non-superseded claim per dot-path. Useful for "what does NEOTH
//!     think about me right now?".

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub action: ProfileAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProfileAction {
    /// List every active profile claim. With `--field`, filter to one
    /// dot-path. Limited to N rows for large profiles.
    Show {
        #[arg(long)]
        field: Option<String>,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// One row per field — highest-confidence non-superseded claim.
    /// This is what the extractor's `existing_profile_summary` input
    /// would render in the prompt to keep the LLM grounded.
    Summary,
    /// List redaction rows from `idx_profile_redactions` — fields the
    /// operator has marked `never_recreate` so the extractor pipeline
    /// can't re-introduce them. Active rows first, revoked rows next.
    Redactions,
    /// Mark a profile field as `never_recreate=true` so the extractor
    /// pipeline can't propose a new claim against it. GDPR-style
    /// redaction; pairs with `neoth memory --forget <topic>` (which
    /// also wipes existing rows). `--reason` is recorded for audit.
    Redact {
        /// Dot-path field, e.g. `identity.location`. Use `neoth profile
        /// show` to see what's currently in idx_profile.
        field: String,
        /// Operator note explaining why the redaction was added.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Revoke an existing redaction by id. The field becomes eligible
    /// for re-extraction again. `--id` is from `neoth profile redactions`.
    Unredact {
        /// Redaction row id (from `neoth profile redactions`).
        #[arg(long)]
        id: i64,
    },
    /// Manually drive the 6-stage profile pipeline. Pick a single
    /// trigger via `--trigger-event <id>` OR batch-run against the
    /// last N inbound events via `--last-n <count>`. Either flag is
    /// required (not both). `--last-n` is the cron-friendly mode:
    /// `0 */6 * * * neoth profile run --last-n 20` extracts from the
    /// last 20 inbound messages every six hours.
    Run {
        /// Event id from `idx_episode` to slice the conversation window
        /// around. Mutually exclusive with `--last-n`.
        #[arg(long, conflicts_with = "last_n")]
        trigger_event: Option<i64>,
        /// Run the pipeline against the most-recent N RAW_TEXT /
        /// CHANNEL_INGRESS events in `idx_episode`. Mutually exclusive
        /// with `--trigger-event`.
        #[arg(long, conflicts_with = "trigger_event")]
        last_n: Option<usize>,
        /// How many prior turn-pairs to include in the window. Default
        /// 2 matches `profile_learn.yaml`.
        #[arg(long, default_value = "2")]
        turns_back: u32,
        /// Optional path override for `profile_extensions.toml`. When
        /// omitted, the default operator path is loaded.
        #[arg(long)]
        extensions_file: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProfileRow {
    field: String,
    value_json: serde_json::Value,
    confidence: f64,
    applied_at: i64,
    extraction_id: String,
    superseded: bool,
}

pub async fn run_profile(args: ProfileArgs) -> Result<()> {
    let db_path = FreedomConfig::default_neoth_home().join("views.db");
    let conn = store::open(&db_path).context("open views.db")?;
    match args.action {
        ProfileAction::Show { field, limit } => {
            let rows = load_show(&conn, field.as_deref(), limit)?;
            render_show(&rows, &args.output)
        }
        ProfileAction::Summary => {
            let rows = load_summary(&conn)?;
            render_summary(&rows, &args.output)
        }
        ProfileAction::Redactions => {
            let rows = crate::profile::redaction::list_all(&conn)?;
            render_redactions(&rows, &args.output)
        }
        ProfileAction::Redact { field, reason } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let id = crate::profile::redaction::add(
                &conn,
                &field,
                true,
                reason.as_deref(),
                "operator",
                now,
            )
            .with_context(|| format!("add redaction for `{field}` (already redacted?)"))?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "redacted": true,
                        "id": id,
                        "field": field,
                        "reason": reason,
                    }))?
                ),
                OutputFormat::Table => println!(
                    "Redacted field `{field}` (id={id}).\n  \
                     Pair with `neoth memory --forget <topic>` to wipe \
                     existing rows. Run `neoth profile unredact --id {id}` to revoke."
                ),
            }
            Ok(())
        }
        ProfileAction::Unredact { id } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let changed = crate::profile::redaction::revoke(&conn, id, now)?;
            if !changed {
                anyhow::bail!(
                    "no active redaction with id={id} — already revoked or unknown id. \
                     Run `neoth profile redactions` to list."
                );
            }
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "unredacted": true,
                        "id": id,
                    }))?
                ),
                OutputFormat::Table => println!(
                    "Revoked redaction id={id}. \
                     The field becomes eligible for re-extraction on the next pipeline run."
                ),
            }
            Ok(())
        }
        ProfileAction::Run {
            trigger_event,
            last_n,
            turns_back,
            extensions_file,
        } => {
            // Resolve the event-id list before we open the pipeline
            // connection, so the operator sees the "no triggers found"
            // case as a clear error not a silent no-op.
            let triggers = match (trigger_event, last_n) {
                (Some(id), None) => vec![id],
                (None, Some(n)) => {
                    let ids = recent_inbound_event_ids(&conn, n)?;
                    if ids.is_empty() {
                        anyhow::bail!(
                            "no RAW_TEXT or CHANNEL_INGRESS events found in idx_episode — \
                             nothing to extract from. Send a message first."
                        );
                    }
                    ids
                }
                (None, None) => anyhow::bail!(
                    "`neoth profile run` requires either --trigger-event <id> or --last-n <count>"
                ),
                (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
            };
            drop(conn); // run_pipeline needs &mut Connection — reopen.
            run_pipeline_cli_batch(
                &db_path,
                &triggers,
                turns_back,
                extensions_file,
                &args.output,
            )
            .await
        }
    }
}

/// Pull the most-recent N RAW_TEXT + CHANNEL_INGRESS event ids from
/// `idx_episode`, newest first. Used by the `--last-n` cron-friendly
/// invocation path.
fn recent_inbound_event_ids(conn: &rusqlite::Connection, n: usize) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "SELECT event_id FROM idx_episode \
         WHERE event_type IN (?1, ?2) \
         ORDER BY ts_ns DESC LIMIT ?3",
    )?;
    let ids: Vec<i64> = stmt
        .query_map(
            rusqlite::params![
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                crate::wal::events::EVENT_TYPE_CHANNEL_INGRESS as i64,
                n as i64,
            ],
            |r| r.get(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect recent inbound event ids")?;
    Ok(ids)
}

async fn run_pipeline_cli_batch(
    db_path: &std::path::Path,
    triggers: &[i64],
    turns_back: u32,
    extensions_file: Option<std::path::PathBuf>,
    output: &OutputFormat,
) -> Result<()> {
    // Wire dependencies: provider from freedom.yaml, fresh WAL writer
    // pointed at a temp segment (the pipeline writes audit frames; we
    // append to the daemon's standard WAL dir so `neoth wal show`
    // surfaces them).
    let config = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    // CH-04: profile extraction is structured-fact extraction from
    // operator history — Left hemisphere (analytic/deductive). In Single
    // mode this is identical to `from_config`; in Triplet/Custom modes
    // the operator's per-role Left provider wins.
    let provider = crate::providers::from_config_for_role(
        &config,
        crate::config::inference::HemisphereRole::Left,
    )
    .await
    .context("build provider for profile.extract")?;

    let wal_dir = FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir")?;
    let segment = wal_dir.join(format!(
        "profile-run-{}.wal",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    ));
    let (writer, writer_join) =
        crate::wal::writer::spawn(segment.clone()).context("spawn WAL writer")?;

    let mut conn = store::open(db_path).context("reopen views.db for pipeline")?;
    let guard = crate::profile::claim_guard::ProfileClaimGuard::default();
    let extensions = match extensions_file {
        Some(path) => crate::profile::extension_registry::TypedExtensionRegistry::load_from(&path)
            .context("load extensions file")?,
        None => {
            crate::profile::extension_registry::TypedExtensionRegistry::load().unwrap_or_default()
        }
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut runs: Vec<(i64, crate::profile::PipelineRun)> = Vec::with_capacity(triggers.len());
    for &trigger_event in triggers {
        let result = crate::profile::run_pipeline(
            &mut conn,
            &writer,
            provider.as_ref(),
            trigger_event,
            turns_back,
            &guard,
            &extensions,
            now_unix,
        )
        .await;
        match result {
            Ok(run) => runs.push((trigger_event, run)),
            Err(e) => {
                // One trigger failed — log and continue with the rest
                // so a single misformed RAW_TEXT row doesn't kill the
                // whole batch.
                tracing::warn!(trigger_event, error = %e,
                    "profile pipeline failed for one trigger; continuing batch");
            }
        }
    }
    drop(writer);
    let _ = writer_join.await;

    let summary = summarise_runs(&runs);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "triggers_processed": runs.len(),
                    "summary": summary,
                    "runs": runs.iter().map(|(id, r)| serde_json::json!({
                        "trigger_event": id,
                        "status": run_status(r),
                        "detail": run_detail(r),
                    })).collect::<Vec<_>>(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "# Profile pipeline batch — {} triggers processed",
                runs.len()
            );
            println!(
                "  applied: {} | skipped: {} | total_claims_applied: {}",
                summary.applied_count, summary.skipped_count, summary.total_claims_applied,
            );
            for (id, run) in &runs {
                match run {
                    crate::profile::PipelineRun::Applied { outcome, .. } => {
                        println!(
                            "  trigger={id:<8} APPLIED claims={} idempotent={}",
                            outcome.claims_applied, outcome.idempotent_skip
                        );
                    }
                    crate::profile::PipelineRun::Skipped(reason) => {
                        println!("  trigger={id:<8} SKIPPED {reason}");
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct BatchSummary {
    applied_count: usize,
    skipped_count: usize,
    total_claims_applied: usize,
}

fn summarise_runs(runs: &[(i64, crate::profile::PipelineRun)]) -> BatchSummary {
    let mut s = BatchSummary {
        applied_count: 0,
        skipped_count: 0,
        total_claims_applied: 0,
    };
    for (_, r) in runs {
        match r {
            crate::profile::PipelineRun::Applied { outcome, .. } => {
                s.applied_count += 1;
                s.total_claims_applied += outcome.claims_applied;
            }
            crate::profile::PipelineRun::Skipped(_) => s.skipped_count += 1,
        }
    }
    s
}

fn run_status(r: &crate::profile::PipelineRun) -> &'static str {
    match r {
        crate::profile::PipelineRun::Applied { .. } => "applied",
        crate::profile::PipelineRun::Skipped(_) => "skipped",
    }
}

fn run_detail(r: &crate::profile::PipelineRun) -> serde_json::Value {
    match r {
        crate::profile::PipelineRun::Applied {
            outcome,
            validated_dropped,
        } => serde_json::json!({
            "claims_applied": outcome.claims_applied,
            "idempotent_skip": outcome.idempotent_skip,
            "validated_dropped_count": validated_dropped.len(),
        }),
        crate::profile::PipelineRun::Skipped(reason) => serde_json::json!({
            "reason": reason.to_string(),
        }),
    }
}

fn render_redactions(
    rows: &[crate::profile::redaction::Redaction],
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": rows.len(),
                    "redactions": rows,
                }))?
            );
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# Profile redactions\n  (none — no fields are marked never_recreate)");
                return Ok(());
            }
            println!("# Profile redactions ({} rows)", rows.len());
            for r in rows {
                let status = if r.is_active() { "ON " } else { "REV" };
                let reason = r.reason.as_deref().unwrap_or("(no reason)");
                println!(
                    "  {status}  {:<28}  asserted_by={} at={}  reason={reason}",
                    r.field, r.asserted_by, r.asserted_at,
                );
                if let Some(rev) = r.revoked_at {
                    println!("           revoked_at={rev}");
                }
            }
        }
    }
    Ok(())
}

fn load_show(
    conn: &rusqlite::Connection,
    field_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<ProfileRow>> {
    let (sql, _) = match field_filter {
        Some(_) => (
            "SELECT field, value_json, confidence, applied_at, extraction_id, superseded_at \
             FROM idx_profile \
             WHERE field = ?1 \
             ORDER BY applied_at DESC \
             LIMIT ?2",
            true,
        ),
        None => (
            "SELECT field, value_json, confidence, applied_at, extraction_id, superseded_at \
             FROM idx_profile \
             ORDER BY applied_at DESC \
             LIMIT ?1",
            false,
        ),
    };
    let mut stmt = conn.prepare(sql).context("prepare profile show")?;
    let rows: Vec<ProfileRow> = if let Some(f) = field_filter {
        stmt.query_map(rusqlite::params![f, limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect profile rows")?
    } else {
        stmt.query_map(rusqlite::params![limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect profile rows")?
    };
    Ok(rows)
}

fn load_summary(conn: &rusqlite::Connection) -> Result<Vec<ProfileRow>> {
    // Pick the highest-confidence non-superseded claim per field.
    let mut stmt = conn.prepare(
        "SELECT p.field, p.value_json, p.confidence, p.applied_at, p.extraction_id, p.superseded_at \
         FROM idx_profile p \
         JOIN ( \
             SELECT field, MAX(confidence) AS max_conf \
             FROM idx_profile \
             WHERE superseded_at IS NULL \
             GROUP BY field \
         ) m ON m.field = p.field AND m.max_conf = p.confidence \
         WHERE p.superseded_at IS NULL \
         ORDER BY p.field",
    )?;
    let rows: Vec<ProfileRow> = stmt
        .query_map([], map_row)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect profile summary rows")?;
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRow> {
    let value_json_str: String = r.get(1)?;
    let value: serde_json::Value =
        serde_json::from_str(&value_json_str).unwrap_or(serde_json::Value::Null);
    let superseded_at: Option<i64> = r.get(5)?;
    Ok(ProfileRow {
        field: r.get(0)?,
        value_json: value,
        confidence: r.get(2)?,
        applied_at: r.get(3)?,
        extraction_id: r.get(4)?,
        superseded: superseded_at.is_some(),
    })
}

fn render_show(rows: &[ProfileRow], output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": rows.len(),
                    "rows": rows,
                }))?
            );
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "# Profile\n  (no claims — the profile-extraction pipeline has not been run yet)"
                );
                return Ok(());
            }
            println!("# Profile claims ({} rows)", rows.len());
            for r in rows {
                let status = if r.superseded { "SUP" } else { "ON " };
                let val = format!("{}", r.value_json);
                let val_short: String = val.chars().take(60).collect();
                println!(
                    "  {status}  {:<28} conf={:.2}  val={val_short}",
                    r.field, r.confidence,
                );
                println!(
                    "         applied_at={}  extraction={}",
                    r.applied_at, r.extraction_id
                );
            }
        }
    }
    Ok(())
}

fn render_summary(rows: &[ProfileRow], output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": rows.len(),
                    "fields": rows,
                }))?
            );
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# Profile summary\n  (empty — no extracted claims yet)");
                return Ok(());
            }
            println!("# Profile summary ({} fields)", rows.len());
            for r in rows {
                println!(
                    "  {:<28} = {} (conf {:.2})",
                    r.field, r.value_json, r.confidence
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::tempdir;

    fn insert(
        conn: &rusqlite::Connection,
        field: &str,
        confidence: f64,
        applied_at: i64,
        ext: &str,
    ) {
        conn.execute(
            "INSERT INTO idx_profile \
             (extraction_id, event_id, field, value_json, confidence, evidence_event_ids, \
              guard_version, applied_at, superseded_at) \
             VALUES (?1, 0, ?2, ?3, ?4, '[]', '0.1.0', ?5, NULL)",
            params![
                ext,
                field,
                format!("\"{field}-value\""),
                confidence,
                applied_at
            ],
        )
        .unwrap();
    }

    #[test]
    fn load_show_returns_empty_on_empty_table() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let rows = load_show(&conn, None, 50).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn load_show_orders_by_applied_at_desc() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert(&conn, "skills.rust", 0.9, 100, "ext-1");
        insert(&conn, "skills.go", 0.8, 200, "ext-2");
        let rows = load_show(&conn, None, 50).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].field, "skills.go"); // newer first
        assert_eq!(rows[1].field, "skills.rust");
    }

    #[test]
    fn load_show_filters_by_field() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert(&conn, "skills.rust", 0.9, 100, "ext-1");
        insert(&conn, "skills.go", 0.8, 200, "ext-2");
        let rows = load_show(&conn, Some("skills.rust"), 50).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].field, "skills.rust");
    }

    #[test]
    fn load_summary_returns_highest_confidence_per_field() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert(&conn, "identity.x", 0.6, 100, "ext-1");
        insert(&conn, "identity.x", 0.9, 200, "ext-2");
        insert(&conn, "skills.rust", 0.7, 300, "ext-3");
        let rows = load_summary(&conn).unwrap();
        assert_eq!(rows.len(), 2);
        let identity = rows.iter().find(|r| r.field == "identity.x").unwrap();
        assert!((identity.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn load_summary_excludes_superseded_rows() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_profile (extraction_id, event_id, field, value_json, confidence, \
             evidence_event_ids, guard_version, applied_at, superseded_at) \
             VALUES ('ext-old', 0, 'identity.x', '\"old\"', 0.95, '[]', '0.1.0', 50, 100)",
            [],
        )
        .unwrap();
        insert(&conn, "identity.x", 0.5, 200, "ext-new");
        let rows = load_summary(&conn).unwrap();
        // Only the active row should survive; the superseded high-conf
        // row is hidden.
        assert_eq!(rows.len(), 1);
        assert!((rows[0].confidence - 0.5).abs() < 1e-6);
    }

    #[test]
    fn render_show_handles_empty_without_panicking() {
        render_show(&[], &OutputFormat::Json).unwrap();
        render_show(&[], &OutputFormat::Table).unwrap();
    }
}
