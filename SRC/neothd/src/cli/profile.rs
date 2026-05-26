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
    /// ADV-03 item 4 Phase 6: list every profile delta the daemon
    /// queued in `idx_profile_pending` while running in tty-less
    /// mode. Operators resolve each row with `approve <extraction_id>`
    /// (write to `idx_profile`) or `decline <extraction_id>` (drop
    /// the row). `--limit` caps the output for terminals.
    Pending {
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// ADV-03 item 4 Phase 6: pop a pending row + run `apply_delta`
    /// against it. Emits `EVENT_TYPE_PROFILE_DELTA_APPROVED` (0xB6)
    /// + the regular `PROFILE_DELTA` (0xB0) frame for each claim.
    Approve {
        /// Extraction id from `neoth profile pending`. The string
        /// in the leftmost column.
        extraction_id: String,
    },
    /// ADV-03 item 4 Phase 6: drop a pending row + emit
    /// `EVENT_TYPE_PROFILE_DELTA_DECLINED` (0xB7) so the audit
    /// trail records the operator's no-decision. Optional
    /// `--reason` makes the audit frame self-explanatory at
    /// replay time.
    Decline {
        /// Extraction id from `neoth profile pending`.
        extraction_id: String,
        /// Optional one-line note recorded in the 0xB7 audit
        /// payload.
        #[arg(long)]
        reason: Option<String>,
    },
    /// ADV-03 item 4 Phase 6: explicit migration command for
    /// operators with a pre-Session-24 `freedom.yaml` that doesn't
    /// carry the `profile.require_approval` field. The serde
    /// default is `true` so they're already gated, but this command
    /// surfaces that fact + writes the field explicitly so the
    /// audit-trail of operator intent is unambiguous.
    MigrateRequireApproval {
        /// When set, force the value to `false` instead of `true` —
        /// for operators who explicitly DO NOT want the gate.
        #[arg(long)]
        disable: bool,
    },
    /// AR-05 (Session 24) — surface profile fields that have more
    /// than one active claim with mismatched `value_json`. Two
    /// claims for `identity.location` (`"Berlin"` vs `"Munich"`)
    /// both with `superseded_at IS NULL` is the canonical case the
    /// extractor produces when context windows disagree.
    ///
    /// Read-only; pairs with `conflicts-resolve` for the operator
    /// fix. Prerequisite for v0.9 G-02 (proactive surfacing of
    /// wrong self-knowledge) — G-02 must not fire while conflicts
    /// are unresolved or it'll volunteer the wrong claim.
    Conflicts {
        /// Cap on conflict groups returned. Each group is one field
        /// with N >= 2 mismatched active claims.
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// AR-05 (Session 24) — resolve a conflict by marking every
    /// active claim EXCEPT the chosen `extraction_id` as
    /// superseded. The kept row stays active; the others record
    /// `superseded_at = now_unix` so the audit trail shows which
    /// extraction won and when.
    ///
    /// Does NOT delete rows — the source claims remain queryable
    /// via `neoth profile show --field <field>` for forensic
    /// reasons (operator might want to revisit the decision after
    /// new evidence arrives).
    ConflictsResolve {
        /// Dot-path field with the conflict, e.g. `identity.location`.
        field: String,
        /// `extraction_id` of the claim to KEEP active. Every other
        /// active claim on this field gets `superseded_at = now`.
        #[arg(long)]
        keep: String,
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
        ProfileAction::Pending { limit } => run_pending_list(&conn, limit, &args.output),
        ProfileAction::Approve { extraction_id } => {
            drop(conn); // approve needs a fresh &mut connection.
            run_pending_approve(&db_path, &extraction_id, &args.output).await
        }
        ProfileAction::Decline {
            extraction_id,
            reason,
        } => {
            drop(conn);
            run_pending_decline(&db_path, &extraction_id, reason.as_deref(), &args.output).await
        }
        ProfileAction::MigrateRequireApproval { disable } => {
            run_migrate_require_approval(disable, &args.output)
        }
        ProfileAction::Conflicts { limit } => run_conflicts_list(&conn, limit, &args.output),
        ProfileAction::ConflictsResolve { field, keep } => {
            run_conflicts_resolve(&conn, &field, &keep, &args.output)
        }
    }
}

// ── AR-05 (Session 24) profile conflict detection + resolution ────────────

/// One field with more than one active claim that disagree on
/// `value_json`. Surfaced by [`run_conflicts_list`]; resolved by
/// [`run_conflicts_resolve`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConflictGroup {
    pub field: String,
    pub claims: Vec<ConflictClaim>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConflictClaim {
    pub extraction_id: String,
    pub value_json: serde_json::Value,
    pub confidence: f64,
    pub applied_at: i64,
}

/// AR-05 — scan `idx_profile` for any `field` with more than one
/// active (`superseded_at IS NULL`) row whose `value_json` strings
/// disagree. Sorts results by `(field asc, applied_at desc within
/// each group)` so the most-recent claim per field is the top entry.
///
/// Pure helper — split out from the CLI handler so the test path
/// asserts on the data, not on stdout. Limit caps the group count
/// (not the claim count per group), matching what an operator wants
/// to see in one terminal screen.
pub fn detect_conflicts(conn: &rusqlite::Connection, limit: usize) -> Result<Vec<ConflictGroup>> {
    // SQL pulls every active row, grouped by field. The "disagree"
    // check lives in Rust because SQLite has no `JSON_DISTINCT_GROUP`
    // and a stringly-typed compare on value_json catches the canonical
    // operator-facing case ("Berlin" vs "Munich") without needing to
    // parse the JSON.
    let mut stmt = conn.prepare(
        "SELECT field, extraction_id, value_json, confidence, applied_at \
         FROM idx_profile \
         WHERE superseded_at IS NULL \
         ORDER BY field ASC, applied_at DESC",
    )?;
    let rows: Vec<(String, String, String, f64, i64)> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, f64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);

    let mut groups: Vec<ConflictGroup> = Vec::new();
    let mut current_field: Option<String> = None;
    let mut current_claims: Vec<ConflictClaim> = Vec::new();

    let flush =
        |field: Option<String>, claims: Vec<ConflictClaim>, groups: &mut Vec<ConflictGroup>| {
            let Some(field) = field else {
                return;
            };
            // Only emit groups where ≥ 2 claims disagree on value_json.
            // Identical-value duplicates are not conflicts — they're just
            // the extractor re-affirming the same fact, which is healthy.
            let distinct: std::collections::HashSet<String> =
                claims.iter().map(|c| c.value_json.to_string()).collect();
            if claims.len() >= 2 && distinct.len() >= 2 {
                groups.push(ConflictGroup { field, claims });
            }
        };

    for (field, extraction_id, value_json, confidence, applied_at) in rows {
        if current_field.as_deref() != Some(field.as_str()) {
            flush(
                current_field.take(),
                std::mem::take(&mut current_claims),
                &mut groups,
            );
            current_field = Some(field);
        }
        let value: serde_json::Value = serde_json::from_str(&value_json)
            .unwrap_or_else(|_| serde_json::Value::String(value_json.clone()));
        current_claims.push(ConflictClaim {
            extraction_id,
            value_json: value,
            confidence,
            applied_at,
        });
        if groups.len() >= limit {
            break;
        }
    }
    flush(current_field, current_claims, &mut groups);
    groups.truncate(limit);
    Ok(groups)
}

fn run_conflicts_list(
    conn: &rusqlite::Connection,
    limit: usize,
    output: &OutputFormat,
) -> Result<()> {
    let groups = detect_conflicts(conn, limit)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&groups)?);
        }
        OutputFormat::Table => {
            if groups.is_empty() {
                println!(
                    "No active profile conflicts. Every field has at most one active claim \
                     (or all duplicates agree on value)."
                );
                return Ok(());
            }
            println!(
                "# {} conflict group(s) — operator action required",
                groups.len(),
            );
            for g in &groups {
                println!("\n  field: {}", g.field);
                for c in &g.claims {
                    println!(
                        "    extraction={ext}  value={val}  conf={conf:.2}  applied_at={ts}",
                        ext = c.extraction_id,
                        val = c.value_json,
                        conf = c.confidence,
                        ts = c.applied_at,
                    );
                }
            }
            println!(
                "\nResolve with: `neoth profile conflicts-resolve <field> --keep <extraction_id>`",
            );
        }
    }
    Ok(())
}

/// AR-05 — supersede every active claim on `field` except the row
/// whose `extraction_id` matches `keep`. Returns the number of rows
/// superseded so the caller can verify the operator actually changed
/// state (a typo'd `keep` value supersedes everything, which is a
/// clear bug signal).
pub fn resolve_conflict(
    conn: &rusqlite::Connection,
    field: &str,
    keep_extraction_id: &str,
    now_unix: i64,
) -> Result<usize> {
    let kept_count: i64 = conn.query_row(
        "SELECT count(*) FROM idx_profile \
         WHERE field = ?1 \
         AND extraction_id = ?2 \
         AND superseded_at IS NULL",
        rusqlite::params![field, keep_extraction_id],
        |r| r.get(0),
    )?;
    if kept_count == 0 {
        anyhow::bail!(
            "no active claim found on field `{field}` with extraction_id `{keep_extraction_id}` \
             — refusing to supersede every claim. Run `neoth profile conflicts` to see valid ids.",
        );
    }
    let n = conn.execute(
        "UPDATE idx_profile SET superseded_at = ?1 \
         WHERE field = ?2 \
         AND extraction_id != ?3 \
         AND superseded_at IS NULL",
        rusqlite::params![now_unix, field, keep_extraction_id],
    )?;
    Ok(n)
}

fn run_conflicts_resolve(
    conn: &rusqlite::Connection,
    field: &str,
    keep_extraction_id: &str,
    output: &OutputFormat,
) -> Result<()> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let superseded = resolve_conflict(conn, field, keep_extraction_id, now_unix)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "field": field,
                    "keep_extraction_id": keep_extraction_id,
                    "superseded": superseded,
                    "now_unix": now_unix,
                }),
            );
        }
        OutputFormat::Table => {
            println!(
                "Resolved conflict on `{field}` — kept `{keep_extraction_id}`, \
                 superseded {superseded} row(s) at unix {now_unix}.",
            );
        }
    }
    Ok(())
}

// ── ADV-03 item 4 Phase 6: pending / approve / decline / migrate ─────────

fn run_pending_list(
    conn: &rusqlite::Connection,
    limit: usize,
    output: &OutputFormat,
) -> Result<()> {
    let rows = crate::profile::approval_gate::list_pending(conn, limit)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "extraction_id": r.extraction_id,
                        "claim_count": r.claim_count,
                        "created_at_unix": r.created_at_unix,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No pending profile deltas. Operator-confirmation gate is idle.");
            } else {
                println!(
                    "{:<32} {:>8} {:>18}",
                    "extraction_id", "claims", "created_at_unix"
                );
                for r in &rows {
                    println!(
                        "{:<32} {:>8} {:>18}",
                        r.extraction_id, r.claim_count, r.created_at_unix
                    );
                }
                println!();
                println!(
                    "Resolve with `neoth profile approve <extraction_id>` or \
                     `decline <extraction_id> [--reason ...]`."
                );
            }
        }
    }
    Ok(())
}

async fn run_pending_approve(
    db_path: &std::path::Path,
    extraction_id: &str,
    output: &OutputFormat,
) -> Result<()> {
    let mut conn = crate::memory::store::open(db_path).context("open views.db")?;
    let row = match crate::profile::approval_gate::pop_pending(&conn, extraction_id)? {
        Some(r) => r,
        None => {
            anyhow::bail!(
                "no pending row for extraction_id={extraction_id} \
                 (already resolved or typo?)"
            );
        }
    };
    // Decode the parked delta + push through the existing apply_delta
    // path. The delete inside pop_pending already happened; if
    // apply_delta fails the operator can re-extract — the queued
    // row's purpose was the gate, not durability.
    let delta: crate::profile::delta::ProfileDelta =
        serde_json::from_str(&row.delta_json).context("decode parked delta_json")?;

    // Spin up a fresh WAL writer for the apply call. Heavy but
    // bounded — operators run approve interactively from a tty
    // session, not in a hot loop.
    let segment_path = crate::config::FreedomConfig::default_wal_dir().join("000001.wal");
    let (writer, _join) =
        crate::wal::writer::spawn(segment_path).context("spawn WAL writer for approve")?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Emit the 0xB6 audit frame BEFORE apply_delta — so a crash mid-
    // apply leaves a clear "operator approved this delta" record
    // even when the row writes to idx_profile didn't all land.
    let approved_payload = crate::profile::approval_gate::approved_payload(
        extraction_id,
        row.claim_count as usize,
        now_unix,
    );
    let header = crate::wal::HeaderBuilder::new(
        crate::profile::approval_gate::APPROVED_EVENT,
        &approved_payload,
    )
    .build();
    let _ = writer.try_append_sync(header, approved_payload);

    let outcome = crate::profile::apply::apply_delta(&mut conn, &writer, &delta, now_unix as i64)
        .await
        .context("apply approved delta")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "extraction_id": extraction_id,
                    "approved": true,
                    "claims_applied": outcome.claims_applied,
                    "claims_reinforced": outcome.claims_reinforced,
                    "claims_superseded": outcome.claims_superseded,
                    "now_unix": now_unix,
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "approved extraction_id={extraction_id}: applied={}, \
                 reinforced={}, superseded={}",
                outcome.claims_applied, outcome.claims_reinforced, outcome.claims_superseded,
            );
        }
    }
    Ok(())
}

async fn run_pending_decline(
    db_path: &std::path::Path,
    extraction_id: &str,
    reason: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let conn = crate::memory::store::open(db_path).context("open views.db")?;
    let row = match crate::profile::approval_gate::pop_pending(&conn, extraction_id)? {
        Some(r) => r,
        None => {
            anyhow::bail!(
                "no pending row for extraction_id={extraction_id} \
                 (already resolved or typo?)"
            );
        }
    };

    let segment_path = crate::config::FreedomConfig::default_wal_dir().join("000001.wal");
    let (writer, _join) =
        crate::wal::writer::spawn(segment_path).context("spawn WAL writer for decline")?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = crate::profile::approval_gate::declined_payload(
        extraction_id,
        row.claim_count as usize,
        now_unix,
        reason,
    );
    let header =
        crate::wal::HeaderBuilder::new(crate::profile::approval_gate::DECLINED_EVENT, &payload)
            .build();
    let _ = writer.try_append_sync(header, payload);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "extraction_id": extraction_id,
                    "declined": true,
                    "reason": reason,
                    "now_unix": now_unix,
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "declined extraction_id={extraction_id} (reason: {})",
                reason.unwrap_or("<none>"),
            );
        }
    }
    Ok(())
}

fn run_migrate_require_approval(disable: bool, output: &OutputFormat) -> Result<()> {
    use crate::config::FreedomConfig;
    let path = FreedomConfig::default_path();
    if !path.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {} — run `neoth init` first",
            path.display()
        );
    }
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let target_value = if disable { "false" } else { "true" };

    // Idempotent surgical edit: scan for an existing
    // `require_approval:` line under `profile:` and rewrite. If
    // absent, append the line at the end of the profile block (we
    // detect the block by the bare `profile:` header — operators
    // hand-editing yaml use that convention).
    let already_set_pattern = format!("require_approval: {target_value}");
    if raw.contains(&already_set_pattern) {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "migrated": false,
                        "reason": "already-set",
                        "value": target_value,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("profile.require_approval is already {target_value}. No change written.");
            }
        }
        return Ok(());
    }

    // Two cases: (a) field already present with the OTHER value
    // (flip it), (b) field absent (insert).
    let updated = if raw.contains("require_approval:") {
        // Flip existing line — match either spelling: `true` or `false`.
        raw.replace(
            "require_approval: true",
            &format!("require_approval: {target_value}"),
        )
        .replace(
            "require_approval: false",
            &format!("require_approval: {target_value}"),
        )
    } else if raw.contains("\nprofile:\n") || raw.starts_with("profile:\n") {
        // Insert under the existing profile: header.
        let needle = "profile:\n";
        raw.replacen(
            needle,
            &format!("profile:\n  require_approval: {target_value}\n"),
            1,
        )
    } else {
        // No profile: block at all — append one. Conservative since
        // hand-edited freedom.yaml is rare and we want the migration
        // to never destroy operator content.
        format!(
            "{}\nprofile:\n  require_approval: {target_value}\n",
            raw.trim_end(),
        )
    };

    std::fs::write(&path, updated.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "migrated": true,
                    "field": "profile.require_approval",
                    "value": target_value,
                    "path": path.display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "wrote profile.require_approval={target_value} to {}",
                path.display()
            );
        }
    }
    Ok(())
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
            // ADV-03 Phase 5: None preserves pre-gate behaviour
            // for the `neoth profile run` admin command.
            None,
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

    // ── AR-01 (Session 24) preset_addendum round-trip integration ────
    //
    // Pin the full chat-dispatch wiring without spinning up an actual
    // chat session: write the marker → read it back → derive the
    // addendum → pass it into `build_enriched_request` and assert the
    // composed system prompt contains the preset's instruction text.
    // Pre-fix this whole chain ran only at daemon boot; the test
    // regression-guards the "every turn" semantics.

    #[test]
    fn ar_01_full_round_trip_runtime_preset_lands_in_enriched_system() {
        use crate::pipeline::{EnrichmentInputs, build_enriched_request};
        use crate::profile::presets::{ProfilePreset, apply_preset};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        record_active_preset(home, ProfilePreset::Formal).expect("record FORMAL");

        // Mirror the cli/chat.rs + cli/serve.rs wiring exactly.
        let preset_addendum = load_active_preset(home)
            .map(|p| apply_preset(p).system_addendum)
            .filter(|s| !s.is_empty())
            .expect("FORMAL has a non-empty addendum");

        let out = build_enriched_request(EnrichmentInputs {
            prompt: "draft an email",
            operator_context: Some("Be brief."),
            preset_addendum: Some(&preset_addendum),
            explicit_system: None,
            repo_context_block: None,
            skill_system_prompt: None,
            used_skill_id: None,
            mcp_catalogue: None,
            persona_override: None,
        });

        let system = out.system.expect("system layered");
        assert!(
            system.contains("formal register"),
            "FORMAL addendum must appear verbatim in the system prompt: {system}",
        );
        // Order check: operator_context first, then preset_addendum.
        let op_pos = system.find("Be brief.").expect("operator block present");
        let preset_pos = system
            .find("formal register")
            .expect("preset block present");
        assert!(
            op_pos < preset_pos,
            "operator_context must layer before preset_addendum",
        );
    }

    #[test]
    fn ar_01_lowkey_preset_yields_no_addendum_layer() {
        // LOWKEY's `system_addendum` is an empty string by design —
        // the chat dispatch must `filter(!is_empty())` it out so the
        // enricher doesn't introduce a stray blank line between
        // operator_context and explicit_system.
        use crate::pipeline::{EnrichmentInputs, build_enriched_request};
        use crate::profile::presets::{ProfilePreset, apply_preset};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        record_active_preset(home, ProfilePreset::Lowkey).expect("record LOWKEY");

        let preset_addendum = load_active_preset(home)
            .map(|p| apply_preset(p).system_addendum)
            .filter(|s| !s.is_empty());
        assert!(
            preset_addendum.is_none(),
            "LOWKEY's empty addendum must be filtered out",
        );

        let out = build_enriched_request(EnrichmentInputs {
            prompt: "p",
            operator_context: Some("op"),
            preset_addendum: preset_addendum.as_deref(),
            explicit_system: Some("user"),
            repo_context_block: None,
            skill_system_prompt: None,
            used_skill_id: None,
            mcp_catalogue: None,
            persona_override: None,
        });
        // Exact "op\n\nuser" — no third blank line between them.
        assert_eq!(out.system.as_deref(), Some("op\n\nuser"));
    }

    #[test]
    fn ar_01_mid_session_apply_immediately_swaps_addendum() {
        // The actual bug AR-01 fixes: a mid-session
        // `neoth profile preset apply <name>` previously needed a
        // daemon restart to take effect. The marker file + per-turn
        // load means the next call to load_active_preset already
        // sees the new preset.
        use crate::profile::presets::{ProfilePreset, apply_preset};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        record_active_preset(home, ProfilePreset::Tutor).expect("record TUTOR");
        let first = load_active_preset(home)
            .map(|p| apply_preset(p).system_addendum)
            .unwrap();
        assert!(first.contains("tutor"));

        // Operator runs `neoth profile preset apply opsec` mid-session.
        record_active_preset(home, ProfilePreset::Opsec).expect("flip to OPSEC");
        let second = load_active_preset(home)
            .map(|p| apply_preset(p).system_addendum)
            .unwrap();
        assert!(
            second.to_lowercase().contains("pentester"),
            "OPSEC addendum must take effect on next load, got {second}",
        );
        assert_ne!(first, second, "addendum must actually change");
    }

    // ── ADV-03 item 4 Phase 6: pending/approve/decline/migrate CLI tests ───

    /// Test-only migrate helper that targets an explicit yaml path
    /// instead of `FreedomConfig::default_path()` — keeps the test
    /// off the global HOME / USERPROFILE env vars (Session 24 env-
    /// mutation refactor pattern).
    fn migrate_require_approval_at_path(
        yaml_path: &std::path::Path,
        disable: bool,
    ) -> Result<bool> {
        let raw = std::fs::read_to_string(yaml_path)?;
        let target_value = if disable { "false" } else { "true" };
        let already = format!("require_approval: {target_value}");
        if raw.contains(&already) {
            return Ok(false);
        }
        let updated = if raw.contains("require_approval:") {
            raw.replace(
                "require_approval: true",
                &format!("require_approval: {target_value}"),
            )
            .replace(
                "require_approval: false",
                &format!("require_approval: {target_value}"),
            )
        } else if raw.contains("\nprofile:\n") || raw.starts_with("profile:\n") {
            raw.replacen(
                "profile:\n",
                &format!("profile:\n  require_approval: {target_value}\n"),
                1,
            )
        } else {
            format!(
                "{}\nprofile:\n  require_approval: {target_value}\n",
                raw.trim_end()
            )
        };
        std::fs::write(yaml_path, updated.as_bytes())?;
        Ok(true)
    }

    #[test]
    fn migrate_require_approval_writes_field_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Existing freedom.yaml with profile block but no require_approval.
        std::fs::write(
            &path,
            "operator_id: tester\nprovider_kind: claude_cli\nprofile:\n  learn_enabled: false\n",
        )
        .unwrap();

        let wrote = migrate_require_approval_at_path(&path, false).unwrap();
        assert!(wrote, "first call must write the field");
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("require_approval: true"),
            "yaml must carry require_approval: true after migrate, got: {after}"
        );
    }

    #[test]
    fn migrate_require_approval_disable_flag_writes_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "profile:\n  learn_enabled: false\n").unwrap();
        let wrote = migrate_require_approval_at_path(&path, true).unwrap();
        assert!(wrote);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("require_approval: false"));
        assert!(
            !after.contains("require_approval: true"),
            "must not have left both spellings: {after}"
        );
    }

    #[test]
    fn migrate_require_approval_is_idempotent_when_already_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "profile:\n  require_approval: true\n  learn_enabled: false\n",
        )
        .unwrap();
        let wrote = migrate_require_approval_at_path(&path, false).unwrap();
        assert!(!wrote, "noop when value already matches target");
        let after = std::fs::read_to_string(&path).unwrap();
        // Untouched — no new line, no duplicate field.
        assert_eq!(
            after.matches("require_approval:").count(),
            1,
            "must not duplicate the field on noop"
        );
    }

    #[test]
    fn migrate_require_approval_flips_existing_value() {
        // disable=true  → target value = "false"
        // disable=false → target value = "true"
        let dir = tempfile::tempdir().unwrap();

        // Case 1: yaml has false, migrate with disable=true (target=false)
        // → noop because already at target.
        let path_a = dir.path().join("a.yaml");
        std::fs::write(
            &path_a,
            "profile:\n  require_approval: false\n  learn_enabled: false\n",
        )
        .unwrap();
        let wrote = migrate_require_approval_at_path(&path_a, true).unwrap();
        assert!(!wrote, "already false, target false (disable=true) → noop");

        // Case 2: yaml has false, migrate with disable=false (target=true)
        // → flip false → true.
        let path_b = dir.path().join("b.yaml");
        std::fs::write(
            &path_b,
            "profile:\n  require_approval: false\n  learn_enabled: false\n",
        )
        .unwrap();
        let wrote2 = migrate_require_approval_at_path(&path_b, false).unwrap();
        assert!(wrote2, "false → true (disable=false) must rewrite");
        let after = std::fs::read_to_string(&path_b).unwrap();
        assert!(after.contains("require_approval: true"));
        assert!(!after.contains("require_approval: false"));
    }

    #[test]
    fn migrate_require_approval_creates_profile_block_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        // freedom.yaml with no profile: block at all.
        std::fs::write(&path, "operator_id: tester\nprovider_kind: claude_cli\n").unwrap();
        let wrote = migrate_require_approval_at_path(&path, false).unwrap();
        assert!(wrote);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("profile:\n  require_approval: true"));
        // Original lines preserved.
        assert!(after.contains("operator_id: tester"));
        assert!(after.contains("provider_kind: claude_cli"));
    }

    #[test]
    fn pending_list_helper_renders_empty_db_cleanly() {
        // Exercises the read-only list path via approval_gate::
        // list_pending directly — no CLI output capture needed.
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let rows = crate::profile::approval_gate::list_pending(&conn, 10).unwrap();
        assert!(rows.is_empty(), "fresh db has no pending rows");
    }

    #[test]
    fn pending_list_helper_returns_inserted_row() {
        use crate::profile::approval_gate::{insert_pending, list_pending};
        use crate::profile::delta::{ProfileDelta, RawClaim};
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let delta = ProfileDelta {
            extraction_id: "ext-cli-test-1".into(),
            conversation_hash: "h".into(),
            claims: vec![RawClaim {
                field: "identity.role".into(),
                value_json: serde_json::json!("dev"),
                confidence: 0.9,
                reasoning: "operator said so".into(),
                evidence_event_ids: vec![1],
            }],
            ..Default::default()
        };
        insert_pending(&conn, &delta, 100).unwrap();
        let rows = list_pending(&conn, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extraction_id, "ext-cli-test-1");
        assert_eq!(rows[0].claim_count, 1);
    }

    // ── AR-05 (Session 24) profile conflicts ──────────────────────────

    /// Insert helper variant that lets the AR-05 tests parametrise the
    /// `value_json` literal — the `insert` helper above uses a fixed
    /// `"<field>-value"` template which makes conflict detection
    /// trivial-by-design (every claim disagrees). We want EXPLICIT
    /// agree/disagree shapes.
    fn insert_with_value(
        conn: &rusqlite::Connection,
        field: &str,
        value_json: &str,
        confidence: f64,
        applied_at: i64,
        extraction_id: &str,
    ) {
        conn.execute(
            "INSERT INTO idx_profile \
             (extraction_id, event_id, field, value_json, confidence, evidence_event_ids, \
              guard_version, applied_at, superseded_at) \
             VALUES (?1, 0, ?2, ?3, ?4, '[]', '0.1.0', ?5, NULL)",
            params![extraction_id, field, value_json, confidence, applied_at],
        )
        .unwrap();
    }

    #[test]
    fn ar_05_no_conflicts_when_table_empty() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let groups = super::detect_conflicts(&conn, 50).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn ar_05_no_conflicts_when_every_field_has_one_claim() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(&conn, "identity.location", "\"Berlin\"", 0.9, 100, "ext-1");
        insert_with_value(&conn, "skills.rust", "\"expert\"", 0.95, 200, "ext-2");
        let groups = super::detect_conflicts(&conn, 50).unwrap();
        assert!(groups.is_empty(), "single-claim fields are not conflicts");
    }

    #[test]
    fn ar_05_identical_duplicates_are_not_conflicts() {
        // Two extractions agreeing on value_json is the extractor
        // re-affirming a known fact, not a disagreement.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(&conn, "identity.location", "\"Berlin\"", 0.9, 100, "ext-1");
        insert_with_value(&conn, "identity.location", "\"Berlin\"", 0.95, 200, "ext-2");
        let groups = super::detect_conflicts(&conn, 50).unwrap();
        assert!(groups.is_empty(), "agreeing duplicates are healthy");
    }

    #[test]
    fn ar_05_detects_canonical_disagreement() {
        // Two extractions disagree on identity.location → conflict.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(
            &conn,
            "identity.location",
            "\"Berlin\"",
            0.7,
            100,
            "ext-old",
        );
        insert_with_value(
            &conn,
            "identity.location",
            "\"Munich\"",
            0.9,
            200,
            "ext-new",
        );
        insert_with_value(&conn, "skills.rust", "\"expert\"", 0.95, 300, "ext-skill");

        let groups = super::detect_conflicts(&conn, 50).unwrap();
        assert_eq!(groups.len(), 1, "exactly one field conflicts");
        let g = &groups[0];
        assert_eq!(g.field, "identity.location");
        assert_eq!(g.claims.len(), 2);
        // Ordered by applied_at DESC — newest first.
        assert_eq!(g.claims[0].extraction_id, "ext-new");
        assert_eq!(g.claims[1].extraction_id, "ext-old");
    }

    #[test]
    fn ar_05_superseded_rows_excluded_from_conflict_detection() {
        // Even when value_json disagrees, a superseded row is not a
        // live claim — it must not surface as a conflict.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_profile \
             (extraction_id, event_id, field, value_json, confidence, evidence_event_ids, \
              guard_version, applied_at, superseded_at) \
             VALUES ('ext-old', 0, 'identity.location', '\"Berlin\"', 0.7, '[]', '0.1.0', 100, 99999)",
            [],
        )
        .unwrap();
        insert_with_value(
            &conn,
            "identity.location",
            "\"Munich\"",
            0.9,
            200,
            "ext-new",
        );
        let groups = super::detect_conflicts(&conn, 50).unwrap();
        assert!(
            groups.is_empty(),
            "superseded rows must not generate conflicts"
        );
    }

    #[test]
    fn ar_05_resolve_conflict_supersedes_others_and_keeps_chosen() {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(
            &conn,
            "identity.location",
            "\"Berlin\"",
            0.7,
            100,
            "ext-old",
        );
        insert_with_value(
            &conn,
            "identity.location",
            "\"Munich\"",
            0.9,
            200,
            "ext-new",
        );
        insert_with_value(
            &conn,
            "identity.location",
            "\"Hamburg\"",
            0.5,
            50,
            "ext-stale",
        );

        let n = super::resolve_conflict(&conn, "identity.location", "ext-new", 999).unwrap();
        assert_eq!(n, 2, "two losers must be superseded");

        // ext-new still active; ext-old + ext-stale superseded at 999.
        let active: Vec<(String, Option<i64>)> = conn
            .prepare(
                "SELECT extraction_id, superseded_at FROM idx_profile \
                 WHERE field = 'identity.location' ORDER BY extraction_id ASC",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(active.len(), 3);
        for (ext, superseded) in active {
            match ext.as_str() {
                "ext-new" => assert!(superseded.is_none(), "kept row stays active"),
                _ => assert_eq!(superseded, Some(999), "loser superseded at the chosen ts"),
            }
        }

        // Detect-pass after resolve: zero conflicts.
        let after = super::detect_conflicts(&conn, 50).unwrap();
        assert!(
            after.is_empty(),
            "resolved conflict must disappear from detection"
        );
    }

    #[test]
    fn ar_05_resolve_refuses_unknown_extraction_id() {
        // Safety contract: typing the wrong `keep` value must NOT
        // supersede every claim on the field. Operator gets a clear
        // error + the table is left alone.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(
            &conn,
            "identity.location",
            "\"Berlin\"",
            0.7,
            100,
            "ext-old",
        );
        insert_with_value(
            &conn,
            "identity.location",
            "\"Munich\"",
            0.9,
            200,
            "ext-new",
        );

        let r = super::resolve_conflict(&conn, "identity.location", "ext-typo", 999);
        assert!(r.is_err(), "unknown extraction_id must Err");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(
            msg.contains("ext-typo") && msg.contains("no active claim"),
            "error must surface the typo + the contract: {msg}",
        );

        // Both rows still active (no accidental sweep).
        let active: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile \
                 WHERE field = 'identity.location' AND superseded_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 2);
    }

    #[test]
    fn ar_05_resolve_no_op_when_only_one_active_claim() {
        // Edge case: operator runs resolve on a field that's not in
        // conflict. The keep row exists + active, no losers to
        // supersede → returns 0 + leaves state unchanged.
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        insert_with_value(&conn, "skills.rust", "\"expert\"", 0.95, 100, "ext-1");
        let n = super::resolve_conflict(&conn, "skills.rust", "ext-1", 999).unwrap();
        assert_eq!(n, 0, "no losers to supersede");
    }
}
