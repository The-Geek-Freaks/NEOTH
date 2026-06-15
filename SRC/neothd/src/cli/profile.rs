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
    /// UX-04 — show the active *behavioural* knobs (the resolved
    /// preset's verbosity / formality / clarifying / disclaimer-trim
    /// plus the autonomy level), each with the concrete command or
    /// file to change it. Complements `show` (which lists profile
    /// *claims*); this is "how is NEOTH tuned + how do I retune it?".
    Knobs,
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
    /// P-10 Phase-3 — emit the one-shot `PROFILE_BASELINE_SNAPSHOT`
    /// (`0xB3`) drift anchor: a SHA-256 digest of every active profile
    /// claim, written once to the WAL so future drift queries diff
    /// against it. Exactly-once — a second run bails when a prior `0xB3`
    /// frame is already in the WAL. Refuses while the daemon is live
    /// (single-writer safety).
    SeedBaseline {
        /// Build + print the snapshot payload without writing the WAL frame.
        #[arg(long)]
        dry_run: bool,
    },
    /// HO-09 / V1x-03 — profile baseline DRIFT detection. Compare the
    /// current active claim set against a baseline (an operator-captured
    /// working baseline, else the `0xB3` migration anchor) and report
    /// what was added / removed / retained + a drift ratio.
    ///
    /// Subcommands: `report` (default) shows the drift; `baseline`
    /// (re)captures the working baseline to "now"; `reset` clears the
    /// working baseline so `report` falls back to the `0xB3` anchor.
    Drift {
        #[command(subcommand)]
        sub: Option<DriftSub>,
    },
}

/// HO-09 — subcommands under `neoth profile drift`.
#[derive(Subcommand, Debug, Clone)]
pub enum DriftSub {
    /// Compare current claims against the baseline + print the drift
    /// report. Flags when the drift ratio exceeds
    /// `freedom.yaml::drift_alert.threshold`. This is the default action.
    Report,
    /// (Re)capture the operator-resettable working baseline to the
    /// current active claim set. Overwrites any prior working baseline.
    Baseline,
    /// Clear the working baseline file. The next `report` falls back to
    /// the immutable `0xB3` migration anchor (if one exists).
    Reset,
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
        ProfileAction::Knobs => {
            let home = FreedomConfig::default_neoth_home();
            // Active preset → its tuning matrix. None (never applied) →
            // LOWKEY, the recommended default the daemon falls back to.
            let active =
                load_active_preset(&home).unwrap_or(crate::profile::presets::ProfilePreset::Lowkey);
            // Autonomy is a freedom.yaml knob; default Standard when the
            // config is unreadable (matches AutonomyLevel::default()).
            let autonomy = FreedomConfig::load_from_default_path()
                .map(|c| c.autonomy)
                .unwrap_or_default();
            let rows = knob_rows(active, autonomy);
            render_knobs(&rows, &args.output);
            Ok(())
        }
        ProfileAction::Redactions => {
            let rows = crate::profile::redaction::list_all(&conn)?;
            render_redactions(&rows, &args.output)
        }
        ProfileAction::Redact { field, reason } => {
            let now = crate::time::now_unix_i64();
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
            let now = crate::time::now_unix_i64();
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
        ProfileAction::SeedBaseline { dry_run } => {
            drop(conn); // seed-baseline opens its own read connection.
            run_seed_baseline(&db_path, dry_run, &args.output).await
        }
        ProfileAction::Drift { sub } => {
            drop(conn); // drift opens its own read connection.
            run_drift(&db_path, sub.unwrap_or(DriftSub::Report), &args.output).await
        }
    }
}

// ── P-10 Phase-3: PROFILE_BASELINE_SNAPSHOT (0xB3) seed ────────────────────

/// Scan every `*.wal` segment for a prior `0xB3 PROFILE_BASELINE_SNAPSHOT`
/// frame; return its `snapshot_id` if found. Backs the exactly-once gate
/// (`Some` = a baseline was already emitted). Best-effort: unreadable
/// segments / undecodable frames are skipped.
///
/// NOTE: deliberately NOT unified with [`scan_for_baseline_snapshot_full`]
/// despite the near-identical walk. The two have different strictness
/// requirements: the exactly-once GATE must detect ANY `0xB3` frame by id
/// alone (lenient `Value.get("snapshot_id")`, tolerant of minimal/legacy
/// payloads), while the drift FULL scanner needs every field to
/// deserialize a complete `BaselineSnapshot`. Collapsing the id-scanner
/// onto the strict full-deserialize would make the gate miss a partial
/// frame and wrongly permit a second baseline emit.
fn scan_for_prior_baseline_snapshot(wal_dir: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(wal_dir).ok()?;
    let mut segments: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();
    for path in segments {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        let found = if hdr.is_compressed() {
            match crate::wal::compress::decompress_frames(body) {
                Ok(d) => find_baseline_snapshot_id(&d),
                Err(_) => None,
            }
        } else {
            find_baseline_snapshot_id(body)
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Walk one (decompressed) segment body; return the `snapshot_id` of the
/// first `0xB3` frame found. Lenient — extracts the id field from any JSON
/// payload so the exactly-once gate catches partial/legacy frames too.
/// Tail-tolerant: stops at the first torn frame.
fn find_baseline_snapshot_id(frames: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match crate::wal::frame::decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(dec.payload) {
                if let Some(id) = v.get("snapshot_id").and_then(|s| s.as_str()) {
                    return Some(id.to_string());
                }
            }
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    None
}

/// Emit the one-shot `0xB3 PROFILE_BASELINE_SNAPSHOT` drift anchor.
///
/// Reads every active `idx_profile` claim, hashes each, and writes a
/// single WAL frame carrying the digest set + a UUID-v7 snapshot id.
/// Exactly-once: bails if a prior `0xB3` frame already exists. Refuses
/// while the daemon owns the segment (single-writer safety). `--dry-run`
/// prints the payload and emits nothing.
async fn run_seed_baseline(
    db_path: &std::path::Path,
    dry_run: bool,
    output: &OutputFormat,
) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();

    // Exactly-once gate — scan the WAL for a prior baseline first.
    let prior = scan_for_prior_baseline_snapshot(&wal_dir);
    crate::profile::baseline_snapshot::ensure_exactly_once(prior.as_deref())
        .context("seed-baseline aborted (a baseline snapshot already exists)")?;

    // Collect every active claim's hash in a stable order. Shares the
    // single SQL+hash implementation with the drift path so the baseline
    // anchor and the drift comparison can never diverge.
    let claim_hashes = current_active_claim_hashes(db_path)?;
    let claim_count = claim_hashes.len();

    let now_unix = crate::time::now_unix_i64();
    let snapshot_id = uuid::Uuid::now_v7().to_string();
    let snapshot = crate::profile::baseline_snapshot::BaselineSnapshot::new(
        &snapshot_id,
        claim_hashes,
        None,
        env!("CARGO_PKG_VERSION"),
        now_unix,
    );
    let payload = snapshot
        .to_payload()
        .context("serialise BaselineSnapshot")?;

    if dry_run {
        println!("{}", String::from_utf8_lossy(&payload));
        return Ok(());
    }

    // Single-writer safety: never open a 2nd writer on a segment the
    // live daemon owns. The operator stops the daemon, runs seed-baseline,
    // restarts — a one-time onboarding/migration action.
    if let Ok(Some(pid)) =
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile())
    {
        anyhow::bail!(
            "neoth daemon is live (pid {pid}); stop it before `profile seed-baseline` \
             so the one-shot 0xB3 frame doesn't race the daemon's WAL writer"
        );
    }

    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL dir {}", wal_dir.display()))?;
    let seg = wal_dir.join("000001.wal");
    let (writer, writer_join) =
        crate::wal::writer::spawn(seg).context("spawn WAL writer for seed-baseline")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
        &payload,
    )
    .importance(1.0)
    .build();
    writer
        .append(header, payload)
        .await
        .context("emit 0xB3 PROFILE_BASELINE_SNAPSHOT")?;
    drop(writer);
    let _ = writer_join.await;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "snapshot_id": snapshot_id,
                    "claim_count": claim_count,
                    "seeded_at_ts_unix": now_unix,
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "seeded profile baseline: snapshot_id={snapshot_id} claim_count={claim_count}"
            );
        }
    }
    Ok(())
}

// ── HO-09 / V1x-03: profile baseline DRIFT detection ──────────────────────

/// SHA-256 hash every active `idx_profile` claim (stable `field ASC`
/// order). Mirrors the claim-collection in [`run_seed_baseline`] so the
/// drift comparison hashes claims identically to the baseline anchor.
pub(crate) fn current_active_claim_hashes(db_path: &std::path::Path) -> Result<Vec<String>> {
    let conn = store::open(db_path).context("open views.db")?;
    let mut stmt = conn
        .prepare(
            "SELECT value_json FROM idx_profile WHERE superseded_at IS NULL ORDER BY field ASC",
        )
        .context("prepare active-claim query")?;
    let values: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .context("query active claims")?
        .filter_map(|r| r.ok())
        .collect();
    Ok(values
        .iter()
        .map(|v| crate::profile::baseline_snapshot::BaselineSnapshot::hash_claim(v))
        .collect())
}

/// Scan the WAL for the `0xB3` migration anchor and return the FULL
/// [`BaselineSnapshot`] (not just the id `scan_for_prior_baseline_snapshot`
/// returns) so drift can diff against its `claim_hashes`.
pub(crate) fn scan_for_baseline_snapshot_full(
    wal_dir: &std::path::Path,
) -> Option<crate::profile::baseline_snapshot::BaselineSnapshot> {
    let mut segments: Vec<std::path::PathBuf> = std::fs::read_dir(wal_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();
    for seg in segments {
        let Ok(bytes) = std::fs::read(&seg) else {
            continue;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        let found = if hdr.is_compressed() {
            match crate::wal::compress::decompress_frames(body) {
                Ok(d) => find_baseline_snapshot_full(&d),
                Err(_) => None,
            }
        } else {
            find_baseline_snapshot_full(body)
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Walk one (decompressed) segment body; deserialize the first `0xB3`
/// frame's payload into a full [`BaselineSnapshot`]. Tail-tolerant.
fn find_baseline_snapshot_full(
    frames: &[u8],
) -> Option<crate::profile::baseline_snapshot::BaselineSnapshot> {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match crate::wal::frame::decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT {
            if let Ok(snap) = serde_json::from_slice::<
                crate::profile::baseline_snapshot::BaselineSnapshot,
            >(dec.payload)
            {
                return Some(snap);
            }
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    None
}

/// HO-09b — resolve the drift baseline (operator working baseline first,
/// else the immutable `0xB3` migration anchor) and compute drift against
/// the current active claim set. Returns `Ok(None)` when no baseline
/// exists yet (fresh install) so the daemon drift-alert cron skips
/// silently rather than erroring. The returned `String` is the baseline
/// source tag (`"working/<src>"` / `"anchor/<snapshot_id>"`), matching
/// `neoth profile drift report`. Shared seam so the CLI report path and
/// the cron resolve the baseline identically. `wal_dir` is explicit so
/// the cron + tests can inject it (production passes
/// `FreedomConfig::default_wal_dir()`, i.e. `home/wal`).
pub(crate) fn compute_drift_against_baseline(
    home: &std::path::Path,
    db_path: &std::path::Path,
    wal_dir: &std::path::Path,
) -> Result<Option<(crate::profile::baseline_diff::DriftReport, String)>> {
    use crate::profile::baseline_diff::{compute_drift, load_drift_baseline};
    let (baseline_hashes, source) =
        match load_drift_baseline(home).context("load working drift baseline")? {
            Some(b) => (b.claim_hashes, format!("working/{}", b.source)),
            None => match scan_for_baseline_snapshot_full(wal_dir) {
                Some(s) => (s.claim_hashes, format!("anchor/{}", s.snapshot_id)),
                None => return Ok(None),
            },
        };
    let current = current_active_claim_hashes(db_path)?;
    Ok(Some((compute_drift(&baseline_hashes, &current), source)))
}

/// HO-09 — `neoth profile drift {report, baseline, reset}`.
async fn run_drift(db_path: &std::path::Path, sub: DriftSub, output: &OutputFormat) -> Result<()> {
    use crate::profile::baseline_diff::{DriftBaseline, reset_drift_baseline, save_drift_baseline};
    let home = FreedomConfig::default_neoth_home();
    let now_unix = crate::time::now_unix_i64();

    match sub {
        DriftSub::Baseline => {
            let hashes = current_active_claim_hashes(db_path)?;
            let count = hashes.len();
            let baseline =
                DriftBaseline::new("manual", hashes, env!("CARGO_PKG_VERSION"), now_unix);
            save_drift_baseline(&home, &baseline).context("write working drift baseline")?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "action": "baseline",
                        "source": "manual",
                        "claim_count": count,
                        "captured_at_ts_unix": now_unix,
                    }))?
                ),
                OutputFormat::Table => {
                    println!("captured working drift baseline: claim_count={count} (source=manual)")
                }
            }
            Ok(())
        }
        DriftSub::Reset => {
            let removed = reset_drift_baseline(&home).context("reset working drift baseline")?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "action": "reset",
                        "removed": removed,
                    }))?
                ),
                OutputFormat::Table => {
                    if removed {
                        println!(
                            "cleared working drift baseline; `drift report` now falls back to \
                             the 0xB3 migration anchor"
                        );
                    } else {
                        println!("no working drift baseline to clear (already absent)");
                    }
                }
            }
            Ok(())
        }
        DriftSub::Report => {
            // Baseline resolution + drift computation via the shared seam
            // (working baseline → 0xB3 anchor fallback) — the exact same
            // path the daemon drift-alert cron uses, so the two can never
            // diverge on what the baseline is.
            let (report, source) = match compute_drift_against_baseline(
                &home,
                db_path,
                &FreedomConfig::default_wal_dir(),
            )? {
                Some(x) => x,
                None => anyhow::bail!(
                    "no baseline to compare against. Capture one with \
                     `neoth profile drift baseline` (resettable working baseline) or \
                     `neoth profile seed-baseline` (the one-shot 0xB3 migration anchor)."
                ),
            };
            let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
            let threshold = cfg.drift_alert.threshold;
            let alerting = cfg.drift_alert.enabled;
            let over = report.is_over(threshold);
            let flagged = alerting && over;

            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "action": "report",
                        "baseline_source": source,
                        "baseline_count": report.baseline_count,
                        "current_count": report.current_count,
                        "added": report.added,
                        "removed": report.removed,
                        "retained": report.retained,
                        "drift_ratio": report.drift_ratio(),
                        "threshold": threshold,
                        "alert_enabled": alerting,
                        "over_threshold": over,
                        "flagged": flagged,
                    }))?
                ),
                OutputFormat::Table => {
                    println!("profile drift report (baseline: {source})");
                    println!(
                        "  baseline claims: {}   current claims: {}   retained: {}",
                        report.baseline_count, report.current_count, report.retained
                    );
                    println!(
                        "  added: {}   removed: {}   drift ratio: {:.3} (threshold {:.3})",
                        report.added.len(),
                        report.removed.len(),
                        report.drift_ratio(),
                        threshold
                    );
                    if flagged {
                        println!(
                            "  ALERT: drift {:.3} exceeds threshold {:.3} — review with \
                             `neoth profile show`, then re-anchor via `neoth profile drift baseline`",
                            report.drift_ratio(),
                            threshold
                        );
                    } else if over {
                        println!(
                            "  (over threshold {threshold:.3}, but drift_alert.enabled = false — \
                             informational only)"
                        );
                    }
                }
            }
            Ok(())
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
    let now_unix = crate::time::now_unix_i64();
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

    let now_unix = crate::time::now_unix_secs();

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
    if let Err(e) = writer.try_append_sync(header, approved_payload) {
        tracing::warn!(
            error = %e,
            extraction_id,
            "WAL append of APPROVED profile-delta audit frame failed"
        );
    }

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
    let now_unix = crate::time::now_unix_secs();
    let payload = crate::profile::approval_gate::declined_payload(
        extraction_id,
        row.claim_count as usize,
        now_unix,
        reason,
    );
    let header =
        crate::wal::HeaderBuilder::new(crate::profile::approval_gate::DECLINED_EVENT, &payload)
            .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(
            error = %e,
            extraction_id,
            "WAL append of DECLINED profile-delta audit frame failed"
        );
    }

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

/// GOLD-ARCH-20: structured `profile.require_approval` edit on a freedom.yaml
/// document. Replaces the old `String::replace` surgery, which matched the
/// `require_approval:` token globally — it flipped values inside YAML comments
/// (`# require_approval: true`), corrupted a same-named key in any other
/// section, and on a CRLF file the `"\nprofile:\n"` needle missed, appending a
/// DUPLICATE `profile:` block (invalid YAML, silently). This parses into a
/// `serde_yaml::Value` tree and edits exactly `root.profile.require_approval`,
/// so comments can't false-match, the key is scoped to the profile section, and
/// CRLF is handled by the YAML parser.
///
/// Returns `Ok(None)` when the field already equals `target` (no write needed),
/// `Ok(Some(updated_yaml))` when the caller should write the new document.
/// Comments are NOT preserved — the same accepted tradeoff as the shipped
/// `config::presets::apply_preset_to_freedom_yaml` round-trip; the wizard never
/// writes comments into freedom.yaml.
fn set_require_approval_yaml(raw: &str, target: bool) -> Result<Option<String>> {
    let mut root: serde_yaml::Value =
        serde_yaml::from_str(raw).context("parse freedom.yaml as YAML")?;
    let mapping = root
        .as_mapping_mut()
        .context("freedom.yaml root is not a YAML mapping")?;

    // Get-or-insert the profile block (project idiom: see
    // config::presets::ensure_council_block).
    let profile_key = serde_yaml::Value::from("profile");
    if mapping
        .get(&profile_key)
        .and_then(|v| v.as_mapping())
        .is_none()
    {
        mapping.insert(
            profile_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let profile_map = mapping
        .get_mut(&profile_key)
        .and_then(|v| v.as_mapping_mut())
        .context("freedom.yaml profile: is not a mapping")?;

    let approval_key = serde_yaml::Value::from("require_approval");
    if profile_map.get(&approval_key).and_then(|v| v.as_bool()) == Some(target) {
        return Ok(None);
    }
    profile_map.insert(approval_key, serde_yaml::Value::Bool(target));

    let updated = serde_yaml::to_string(&root).context("re-serialize freedom.yaml")?;
    Ok(Some(updated))
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
    let target = !disable;
    let target_value = if disable { "false" } else { "true" };

    let updated = match set_require_approval_yaml(&raw, target)? {
        None => {
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
                    println!(
                        "profile.require_approval is already {target_value}. No change written."
                    );
                }
            }
            return Ok(());
        }
        Some(updated) => updated,
    };

    // Atomic write — `.tmp` + rename (same pattern as config::presets::apply),
    // so a crash mid-write can never leave freedom.yaml truncated/corrupt.
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, updated.as_bytes())
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename into {}", path.display()))?;

    // Post-write verify: re-parse the written file as a full FreedomConfig and
    // confirm the field actually landed. A structured edit should never produce
    // a file that fails to parse or carries the wrong value — fail loudly if it
    // somehow does, since this gates approval behaviour.
    let written =
        std::fs::read_to_string(&path).with_context(|| format!("re-read {}", path.display()))?;
    let cfg: FreedomConfig = serde_yaml::from_str(&written)
        .context("post-write parse of freedom.yaml failed — file may be corrupt")?;
    anyhow::ensure!(
        cfg.profile.require_approval == target,
        "post-write verify failed: expected require_approval={target}, got {}",
        cfg.profile.require_approval
    );

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
        crate::time::now_unix_secs(),
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
    let now_unix = crate::time::now_unix_secs();

    let mut runs: Vec<(i64, crate::profile::PipelineRun)> = Vec::with_capacity(triggers.len());
    for &trigger_event in triggers {
        let result = crate::profile::run_pipeline(
            crate::profile::PipelineConn::Owned(&mut conn),
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
            false, // ADV-07: CLI batch run, not a mirror-recovery turn
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
                /// The operator's currently-active behavioural preset (the
                /// `active_preset.txt` marker). Lets the GUI selector mark it.
                active: bool,
            }
            let active = load_active_preset(&home);
            let rows: Vec<Row> = ProfilePreset::ALL
                .iter()
                .map(|p| Row {
                    name: p.as_str(),
                    description: p.description(),
                    recommended: matches!(p, ProfilePreset::Lowkey),
                    active: active.is_some_and(|a| a.as_str() == p.as_str()),
                })
                .collect();
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                OutputFormat::Table => {
                    println!("Profile presets:");
                    for row in &rows {
                        let active_tag = if row.active { " (active)" } else { "" };
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

// ── UX-04: behavioural-knobs view ──────────────────────────────────────────

/// One operator-facing behavioural knob: its current value + the
/// concrete command/file to change it. No fictional `neoth config set`
/// — the hints point at the real mechanism (preset apply / freedom.yaml).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnobRow {
    pub knob: &'static str,
    pub value: String,
    pub change_hint: String,
}

fn verbosity_str(v: crate::profile::presets::Verbosity) -> &'static str {
    use crate::profile::presets::Verbosity::*;
    match v {
        Terse => "terse",
        Normal => "normal",
        Detailed => "detailed",
    }
}

fn formality_str(f: crate::profile::presets::Formality) -> &'static str {
    use crate::profile::presets::Formality::*;
    match f {
        Casual => "casual",
        Professional => "professional",
        Strict => "strict",
    }
}

/// Build the behavioural-knob rows from the resolved preset + autonomy.
/// Pure — the four tuning knobs are PRESET-BUNDLED (they move together
/// when the operator applies a preset), so their change-hint points at
/// `neoth profile preset apply`; autonomy is an independent freedom.yaml
/// knob.
pub fn knob_rows(
    active: crate::profile::presets::ProfilePreset,
    autonomy: crate::permissions::AutonomyLevel,
) -> Vec<KnobRow> {
    let d = crate::profile::presets::apply_preset(active);
    let preset_hint =
        "change: `neoth profile preset apply <lowkey|formal|deepdive|tutor|opsec>`".to_string();
    let bundled = "(bundled with the active preset)".to_string();
    vec![
        KnobRow {
            knob: "preset",
            value: active.as_str().to_string(),
            change_hint: preset_hint,
        },
        KnobRow {
            knob: "verbosity",
            value: verbosity_str(d.verbosity).to_string(),
            change_hint: bundled.clone(),
        },
        KnobRow {
            knob: "formality",
            value: formality_str(d.formality).to_string(),
            change_hint: bundled.clone(),
        },
        KnobRow {
            knob: "ask_clarifying",
            value: d.ask_clarifying.to_string(),
            change_hint: bundled.clone(),
        },
        KnobRow {
            knob: "trim_disclaimers",
            value: d.trim_disclaimers.to_string(),
            change_hint: bundled,
        },
        KnobRow {
            knob: "autonomy",
            value: autonomy.as_str().to_string(),
            change_hint:
                "change: edit ~/.neoth/freedom.yaml → `autonomy: <strict|standard|elevated|full>`"
                    .to_string(),
        },
    ]
}

fn render_knobs(rows: &[KnobRow], output: &OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let arr: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "knob": r.knob,
                        "value": r.value,
                        "change_hint": r.change_hint,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".to_string())
            );
        }
        OutputFormat::Table => {
            println!("Behavioural knobs (how NEOTH is tuned):\n");
            for r in rows {
                println!("  {:<17} {:<14} {}", r.knob, r.value, r.change_hint);
            }
            println!(
                "\nThe four preset knobs move together — apply a different preset to retune them."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    // ── UX-04 knob_rows ────────────────────────────────────────────
    // `ProfilePreset` is already in scope via `use super::*`; only
    // `AutonomyLevel` needs importing here.
    use crate::permissions::AutonomyLevel;

    #[test]
    fn knob_rows_reflects_lowkey_preset() {
        let rows = knob_rows(ProfilePreset::Lowkey, AutonomyLevel::Standard);
        let get = |k: &str| rows.iter().find(|r| r.knob == k).unwrap();
        assert_eq!(get("preset").value, "lowkey");
        assert_eq!(get("verbosity").value, "terse");
        assert_eq!(get("formality").value, "casual");
        assert_eq!(get("ask_clarifying").value, "false");
        assert_eq!(get("trim_disclaimers").value, "false");
        assert_eq!(get("autonomy").value, "standard");
    }

    #[test]
    fn knob_rows_reflects_deepdive_and_opsec_deltas() {
        let dd = knob_rows(ProfilePreset::Deepdive, AutonomyLevel::Elevated);
        let dd_get = |k: &str| dd.iter().find(|r| r.knob == k).unwrap();
        assert_eq!(dd_get("verbosity").value, "detailed");
        assert_eq!(dd_get("ask_clarifying").value, "true");
        assert_eq!(dd_get("autonomy").value, "elevated");

        let op = knob_rows(ProfilePreset::Opsec, AutonomyLevel::Full);
        let op_get = |k: &str| op.iter().find(|r| r.knob == k).unwrap();
        assert_eq!(op_get("trim_disclaimers").value, "true");
        assert_eq!(op_get("autonomy").value, "full");
    }

    #[test]
    fn knob_rows_hints_reference_real_mechanisms_not_config_set() {
        // No fictional `neoth config set`; hints point at the real
        // preset-apply command + freedom.yaml.
        let rows = knob_rows(ProfilePreset::Lowkey, AutonomyLevel::Standard);
        let preset = rows.iter().find(|r| r.knob == "preset").unwrap();
        assert!(preset.change_hint.contains("neoth profile preset apply"));
        let autonomy = rows.iter().find(|r| r.knob == "autonomy").unwrap();
        assert!(autonomy.change_hint.contains("freedom.yaml"));
        for r in &rows {
            assert!(
                !r.change_hint.contains("neoth config set"),
                "no fictional config-set command in `{}` hint",
                r.knob
            );
        }
    }
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
            moral_core: None,
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
            moral_core: None,
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
        match set_require_approval_yaml(&raw, !disable)? {
            None => Ok(false),
            Some(updated) => {
                std::fs::write(yaml_path, updated.as_bytes())?;
                Ok(true)
            }
        }
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
        assert!(after.contains("require_approval: true"));
        // Original lines preserved.
        assert!(after.contains("operator_id: tester"));
        assert!(after.contains("provider_kind: claude_cli"));
    }

    #[test]
    fn migrate_require_approval_ignores_value_in_comment() {
        // GOLD-ARCH-20: the old String::replace matched the token inside YAML
        // comments. A comment carrying the target value must NOT make the
        // migration a silent no-op when the real field is absent.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "# require_approval: true is the secure default\nprofile:\n  learn_enabled: false\n",
        )
        .unwrap();
        let wrote = migrate_require_approval_at_path(&path, false).unwrap();
        assert!(wrote, "comment must not be mistaken for the live field");
        let after = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&after).unwrap();
        assert!(
            cfg.profile.require_approval,
            "the real profile.require_approval must be set true, got: {after}"
        );
    }

    #[test]
    fn migrate_require_approval_handles_crlf_without_duplicate_profile_block() {
        // GOLD-ARCH-20: on a CRLF file the old `"\nprofile:\n"` needle missed
        // and appended a SECOND profile: block (invalid YAML). The structured
        // edit must produce a single, parseable profile section.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: tester\r\nprofile:\r\n  learn_enabled: false\r\n",
        )
        .unwrap();
        let wrote = migrate_require_approval_at_path(&path, true).unwrap();
        assert!(wrote);
        let after = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::FreedomConfig = serde_yaml::from_str(&after).unwrap();
        assert!(!cfg.profile.require_approval, "disable=true → false");
        assert_eq!(
            after.matches("profile:").count(),
            1,
            "exactly one profile block, no CRLF-induced duplicate: {after}"
        );
    }

    #[test]
    fn migrate_require_approval_does_not_corrupt_other_section_same_key() {
        // GOLD-ARCH-20: a `require_approval:` key in an UNRELATED section must
        // stay untouched — the edit is scoped to profile.require_approval.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "some_other:\n  require_approval: false\nprofile:\n  learn_enabled: false\n",
        )
        .unwrap();
        let wrote = migrate_require_approval_at_path(&path, false).unwrap();
        assert!(wrote);
        let after = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&after).unwrap();
        assert_eq!(
            root["some_other"]["require_approval"].as_bool(),
            Some(false),
            "unrelated section's require_approval must be untouched: {after}"
        );
        assert_eq!(
            root["profile"]["require_approval"].as_bool(),
            Some(true),
            "profile.require_approval must be set true: {after}"
        );
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

    // ── P-10 seed-baseline (0xB3) scan ─────────────────────────────────

    #[test]
    fn baseline_scan_returns_none_for_empty_dir() {
        let dir = tempdir().unwrap();
        assert!(scan_for_prior_baseline_snapshot(dir.path()).is_none());
    }

    #[tokio::test]
    async fn baseline_scan_finds_emitted_snapshot_id() {
        // Write a real 0xB3 frame to a temp segment via the WAL writer,
        // then assert the scan extracts its snapshot_id — exercises the
        // full segment-header + frame-walk + JSON-extract path.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (w, join) = crate::wal::writer::spawn(seg).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "snapshot_id": "0192f000-baseline-test",
            "claim_count": 2,
        }))
        .unwrap();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT,
            &payload,
        )
        .build();
        w.append(header, payload).await.unwrap();
        drop(w);
        let _ = join.await;
        assert_eq!(
            scan_for_prior_baseline_snapshot(dir.path()).as_deref(),
            Some("0192f000-baseline-test")
        );
    }

    #[tokio::test]
    async fn baseline_scan_ignores_non_baseline_frames() {
        // A segment carrying only a non-0xB3 frame yields None — the
        // exactly-once gate must not trip on unrelated events.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (w, join) = crate::wal::writer::spawn(seg).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({"x": 1})).unwrap();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_RAW_TEXT, &payload)
                .build();
        w.append(header, payload).await.unwrap();
        drop(w);
        let _ = join.await;
        assert!(scan_for_prior_baseline_snapshot(dir.path()).is_none());
    }
}
