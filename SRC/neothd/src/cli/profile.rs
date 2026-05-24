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
    /// P-02 (Workstream B follow-up, Session 22) — manage profile
    /// presets that shape tone / verbosity / clarifying behaviour.
    ///
    /// Subcommands: `list` shows all 5 built-in presets with their
    /// operator-facing descriptions; `show <name>` decodes one preset
    /// into its `PresetData` (system_addendum + verbosity + formality
    /// + clarifying + trim_disclaimers); `apply <name>` writes the
    /// active-preset marker to `~/.neoth/profile/active_preset.txt`
    /// so chat dispatch can compose the system_addendum on next run.
    Preset {
        #[command(subcommand)]
        sub: PresetSub,
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

/// P-02 (Session 22) — subcommands under `neoth profile preset`.
/// Maps 1:1 to `profile::presets::ProfilePreset` operations.
#[derive(Subcommand, Debug, Clone)]
pub enum PresetSub {
    /// List every built-in preset with its operator-readable description.
    List,
    /// Show the decoded `PresetData` for one preset (system_addendum +
    /// verbosity + formality + ask_clarifying + trim_disclaimers).
    Show {
        /// Preset name. One of: lowkey / formal / deepdive / tutor / opsec.
        name: String,
    },
    /// Activate a preset. Writes the marker file at
    /// `~/.neoth/profile/active_preset.txt`; chat dispatch reads it on
    /// next run to compose the preset's `system_addendum` into the
    /// system prompt.
    Apply {
        /// Preset name. One of: lowkey / formal / deepdive / tutor / opsec.
        name: String,
    },
}

/// Relative path under `~/.neoth/` where the active preset name is
/// persisted. Single-line file, no trailing newline. Atomic-rename
/// write via `credentials::write_mode_0600` so the chat-side reader
/// can never observe a partial write.
pub const ACTIVE_PRESET_RELATIVE_PATH: &str = "profile/active_preset.txt";

/// Absolute path to the active-preset marker for a given home.
pub fn active_preset_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(ACTIVE_PRESET_RELATIVE_PATH)
}

/// Persist the active preset name to the marker file. Atomic via
/// `.txt.tmp` + rename. Mode 0600 on unix. Mirrors the pattern
/// `briefing_gate::record_last_active` ships for the last-active marker.
pub fn record_active_preset(
    home: &std::path::Path,
    preset: crate::profile::presets::ProfilePreset,
) -> Result<()> {
    let path = active_preset_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create parent dir for active_preset marker: {}",
                parent.display()
            )
        })?;
    }
    let bytes = preset.as_str().as_bytes().to_vec();
    let tmp = path.with_extension("txt.tmp");
    crate::config::credentials::write_mode_0600(&tmp, &bytes)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read the current active preset, if any. Returns `None` when the
/// marker file is missing / empty / contains an unknown preset name.
/// Chat dispatch treats `None` as "no preset active, ship default
/// system prompt unchanged".
pub fn load_active_preset(
    home: &std::path::Path,
) -> Option<crate::profile::presets::ProfilePreset> {
    let path = active_preset_path(home);
    let s = std::fs::read_to_string(&path).ok()?;
    crate::profile::presets::ProfilePreset::parse(s.trim())
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
        ProfileAction::Preset { sub } => run_preset_sub(sub, &args.output).await,
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

/// P-02 (Session 22) — dispatcher for `neoth profile preset ...`.
async fn run_preset_sub(sub: PresetSub, output: &OutputFormat) -> Result<()> {
    use crate::profile::presets::{ProfilePreset, apply_preset};

    let home = FreedomConfig::default_neoth_home();
    match sub {
        PresetSub::List => {
            #[derive(serde::Serialize)]
            struct Row {
                name: &'static str,
                description: &'static str,
                recommended: bool,
            }
            let rows: Vec<Row> = ProfilePreset::ALL
                .iter()
                .map(|p| Row {
                    name: p.as_str(),
                    description: p.description(),
                    recommended: matches!(p, ProfilePreset::Lowkey),
                })
                .collect();
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                OutputFormat::Table => {
                    let active = load_active_preset(&home);
                    println!("Profile presets:");
                    for row in &rows {
                        let active_tag = match active {
                            Some(p) if p.as_str() == row.name => " (active)",
                            _ => "",
                        };
                        let recommended = if row.recommended { "(recommended)" } else { "" };
                        println!("  {} {recommended}{active_tag}", row.name);
                        println!("    {}", row.description);
                    }
                    println!();
                    println!("Apply via `neoth profile preset apply <name>`.");
                }
            }
            Ok(())
        }
        PresetSub::Show { name } => {
            let preset = ProfilePreset::parse(&name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown preset `{name}`. Run `neoth profile preset list` for valid names."
                )
            })?;
            let data = apply_preset(preset);
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "preset": preset.as_str(),
                        "system_addendum": data.system_addendum,
                        "verbosity": format!("{:?}", data.verbosity),
                        "formality": format!("{:?}", data.formality),
                        "ask_clarifying": data.ask_clarifying,
                        "trim_disclaimers": data.trim_disclaimers,
                    }))?
                ),
                OutputFormat::Table => {
                    println!("Preset      : {}", preset.as_str());
                    println!("Verbosity   : {:?}", data.verbosity);
                    println!("Formality   : {:?}", data.formality);
                    println!("Clarifying  : {}", data.ask_clarifying);
                    println!("Trim disclaimers: {}", data.trim_disclaimers);
                    println!();
                    if data.system_addendum.is_empty() {
                        println!("System addendum: <empty>");
                    } else {
                        println!("System addendum:");
                        for line in data.system_addendum.lines() {
                            println!("  {line}");
                        }
                    }
                }
            }
            Ok(())
        }
        PresetSub::Apply { name } => {
            let preset = ProfilePreset::parse(&name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown preset `{name}`. Run `neoth profile preset list` for valid names."
                )
            })?;
            record_active_preset(&home, preset).with_context(|| {
                format!(
                    "persist active preset to {}",
                    active_preset_path(&home).display()
                )
            })?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "applied": true,
                        "preset": preset.as_str(),
                        "marker": active_preset_path(&home),
                    }))?
                ),
                OutputFormat::Table => println!(
                    "Active preset → {}. Marker: {}\n  \
                     Chat dispatch picks this up on next run. \
                     Re-run `neoth profile preset apply <other>` to switch.",
                    preset.as_str(),
                    active_preset_path(&home).display(),
                ),
            }
            Ok(())
        }
    }
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

    // ── P-02 (Session 22): preset marker round-trip ──────────────────

    use crate::profile::presets::ProfilePreset;

    #[test]
    fn active_preset_path_drift_guard() {
        assert_eq!(ACTIVE_PRESET_RELATIVE_PATH, "profile/active_preset.txt");
    }

    #[test]
    fn load_active_preset_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_active_preset(dir.path()).is_none());
    }

    #[test]
    fn record_then_load_round_trips_each_preset() {
        let dir = tempfile::tempdir().unwrap();
        for preset in ProfilePreset::ALL {
            record_active_preset(dir.path(), *preset).expect("record");
            let loaded = load_active_preset(dir.path()).expect("load");
            assert_eq!(loaded.as_str(), preset.as_str());
        }
    }

    #[test]
    fn record_overwrites_previous_preset() {
        let dir = tempfile::tempdir().unwrap();
        record_active_preset(dir.path(), ProfilePreset::Formal).unwrap();
        record_active_preset(dir.path(), ProfilePreset::Lowkey).unwrap();
        let loaded = load_active_preset(dir.path()).unwrap();
        assert_eq!(loaded.as_str(), "lowkey");
    }

    #[test]
    fn record_persists_via_atomic_tmp_then_rename() {
        // Drift guard — write goes via `.txt.tmp` sibling + rename. A
        // concurrent reader during persist sees OLD or NEW, never a
        // partial write. Detect by asserting the .tmp is gone after.
        let dir = tempfile::tempdir().unwrap();
        record_active_preset(dir.path(), ProfilePreset::Opsec).unwrap();
        let tmp = active_preset_path(dir.path()).with_extension("txt.tmp");
        assert!(
            !tmp.exists(),
            ".txt.tmp must be renamed away: {}",
            tmp.display()
        );
    }

    #[test]
    fn load_active_preset_returns_none_for_unknown_name() {
        // Corrupted marker (operator hand-edited the file with garbage)
        // → load returns None instead of crashing. Chat dispatch then
        // falls back to "no preset" without surfacing the error.
        let dir = tempfile::tempdir().unwrap();
        let path = active_preset_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not-a-real-preset-name").unwrap();
        assert!(load_active_preset(dir.path()).is_none());
    }
}
