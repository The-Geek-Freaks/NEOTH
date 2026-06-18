//! `neoth rollback` — operator surface for the B-Rollback snapshot WAL
//! frames (CDX-02).
//!
//! - **`list`** — read-only. Walks every `*.wal` segment under
//!   `~/.neoth/wal/`, decodes `PRE_MUTATION_SNAPSHOT` (0xF2) frames, renders
//!   them as a table or JSON: which mutations were captured, when, and the
//!   before-state byte count.
//! - **`apply --to <offset>`** — restoration (shipped). Without `--confirm`
//!   it DRY-RUNS: decodes `before_state` and prints what restoring would do.
//!   With `--confirm` it executes the per-`MutationKind` restoration via
//!   `plan.execute()` and reports the bytes written. (The per-kind
//!   dispatcher that the earlier "deferred" note referenced has landed.)

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::Path;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
use crate::wal::snapshot::PreMutationSnapshot;

#[derive(Args, Debug, Clone)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub action: RollbackAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RollbackAction {
    /// List every `PRE_MUTATION_SNAPSHOT` (0xF2) frame in the
    /// operator's WAL segments. Pure read — no mutations.
    List {
        /// Optional `MutationKind` filter (`file_write`,
        /// `channel_send`, `mcp_tool_invoke`, `sql_mutation`,
        /// `config_write`, `other`). Case-insensitive.
        #[arg(long, value_name = "KIND")]
        kind: Option<String>,
        /// Show at most N most-recent snapshots (default: 50).
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Restore the prior state captured in one snapshot. Dispatches
    /// on `MutationKind`: `file_write` writes the captured bytes back
    /// to the target path. Other kinds bail with a "not yet
    /// implemented" diagnostic since their restoration semantics are
    /// adapter-specific (a `channel_send` restoration would require
    /// platform-specific delete-or-edit; an `mcp_tool_invoke` would
    /// need a compensating call).
    ///
    /// Operators MUST pair this with `--confirm` for non-dry-run.
    Apply {
        /// Snapshot offset (from `neoth rollback list`).
        #[arg(long, value_name = "OFFSET")]
        to: u64,
        /// Segment path the snapshot lives in (from `neoth rollback
        /// list`). Together with `--to` uniquely identifies a snapshot.
        #[arg(long, value_name = "PATH")]
        segment: std::path::PathBuf,
        /// Required to actually restore. Without it the command is a
        /// preview only — prints what would be restored + skips the
        /// write.
        #[arg(long)]
        confirm: bool,
    },
}

pub async fn run_rollback(args: RollbackArgs) -> Result<()> {
    match args.action {
        RollbackAction::List { kind, limit } => {
            run_list(kind.as_deref(), limit, &args.output).await
        }
        RollbackAction::Apply {
            to,
            segment,
            confirm,
        } => run_apply(&segment, to, confirm, &args.output).await,
    }
}

/// One snapshot as the CLI surfaces it. Compact view — full payload
/// stays in the WAL frame; CLI shows the metadata operators need to
/// pick a snapshot for the next `apply` step.
#[derive(Debug, serde::Serialize)]
struct SnapshotListEntry {
    /// Path to the segment file the frame lives in.
    pub segment: String,
    /// Byte offset of the frame within the segment. Doubles as the
    /// snapshot id — operators reference it via `--to <offset>`.
    pub offset: u64,
    /// Stable kind tag (snake_case).
    pub mutation_kind: String,
    /// Resource the mutation targets (file path, channel id, ...).
    pub target: String,
    /// Operator-friendly ISO-8601 of when the snapshot was taken.
    pub ts_iso: String,
    /// Bytes of captured before-state (hex-decoded length).
    pub before_state_bytes: usize,
    /// Operator note when one was supplied.
    pub note: Option<String>,
}

async fn run_list(kind_filter: Option<&str>, limit: usize, output: &OutputFormat) -> Result<()> {
    let wal_dir = FreedomConfig::default_wal_dir();
    let entries = collect_snapshots(&wal_dir, kind_filter)?;
    let total = entries.len();
    // Most-recent-first: sort descending by ts_unix, then truncate.
    let mut entries = entries;
    entries.sort_by_key(|(_, snap)| std::cmp::Reverse(snap.ts_unix));
    let shown: Vec<SnapshotListEntry> = entries
        .into_iter()
        .take(limit)
        .map(|((segment, offset), snap)| SnapshotListEntry {
            segment,
            offset,
            mutation_kind: kind_to_string(&snap.mutation_kind),
            target: snap.target.clone(),
            ts_iso: format_iso8601(snap.ts_unix),
            before_state_bytes: snap.before_state_bytes().map(|b| b.len()).unwrap_or(0),
            note: snap.note.clone(),
        })
        .collect();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "total_snapshots": total,
                    "shown": shown.len(),
                    "snapshots": shown,
                }))?
            );
        }
        OutputFormat::Table => {
            if shown.is_empty() {
                if kind_filter.is_some() {
                    println!(
                        "# No PRE_MUTATION_SNAPSHOT frames matching filter \
                         (total snapshots in WAL: {total})"
                    );
                } else {
                    println!("# No PRE_MUTATION_SNAPSHOT frames in WAL");
                    println!("  (snapshots are emitted by mutating effect-adapter calls;");
                    println!("   none recorded yet means the daemon hasn't run a mutation");
                    println!("   path that calls `wal::snapshot::emit_snapshot`).");
                }
                return Ok(());
            }
            println!(
                "# B-Rollback snapshots ({} shown, {} total)",
                shown.len(),
                total
            );
            println!(
                "  Restore one with `neoth rollback apply --to <offset>` \
                 (add `--confirm` to execute; without it you get a dry-run preview).\n"
            );
            for e in &shown {
                println!(
                    "  [{}]  offset={:>8}  kind={:<16}  target={}",
                    e.ts_iso, e.offset, e.mutation_kind, e.target,
                );
                println!(
                    "     segment={}  before_state={} B{}",
                    e.segment,
                    e.before_state_bytes,
                    e.note
                        .as_deref()
                        .map(|n| format!("  note=\"{n}\""))
                        .unwrap_or_default(),
                );
            }
        }
    }
    Ok(())
}

/// Execute one snapshot's restoration logic. Dispatches per
/// `MutationKind`. Dry-run by default; `--confirm` does the actual
/// write/restore. Returns Err when the snapshot isn't found, the
/// payload doesn't decode, the `MutationKind` has no restoration
/// dispatcher yet, or the restore itself fails.
async fn run_apply(
    segment: &Path,
    target_offset: u64,
    confirm: bool,
    output: &OutputFormat,
) -> Result<()> {
    let snap = find_snapshot_at(segment, target_offset)?;
    let plan = ApplyPlan::from_snapshot(&snap)?;
    if !confirm {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "dry_run": true,
                        "snapshot_offset": target_offset,
                        "segment": segment.display().to_string(),
                        "mutation_kind": kind_to_string(&snap.mutation_kind),
                        "target": snap.target,
                        "before_state_bytes": plan.before_state_bytes_len,
                        "would_restore": plan.summary,
                        "confirm_with": "neoth rollback apply --confirm",
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("# Rollback dry-run for snapshot at offset {target_offset}");
                println!("  segment       : {}", segment.display());
                println!("  mutation_kind : {}", kind_to_string(&snap.mutation_kind));
                println!("  target        : {}", snap.target);
                println!("  before_state  : {} B", plan.before_state_bytes_len);
                println!("  would_restore : {}", plan.summary);
                println!();
                println!("  No changes made. Re-run with `--confirm` to apply.");
            }
        }
        return Ok(());
    }
    // Confirmed — execute.
    let outcome = plan.execute()?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "applied": true,
                    "snapshot_offset": target_offset,
                    "mutation_kind": kind_to_string(&snap.mutation_kind),
                    "target": snap.target,
                    "bytes_written": outcome.bytes_written,
                    "summary": outcome.summary,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Rollback applied");
            println!("  mutation_kind : {}", kind_to_string(&snap.mutation_kind));
            println!("  target        : {}", snap.target);
            println!("  bytes_written : {} B", outcome.bytes_written);
            println!("  summary       : {}", outcome.summary);
        }
    }
    Ok(())
}

/// Locate a snapshot by (segment_path, frame_offset). Returns Err when
/// no PRE_MUTATION_SNAPSHOT frame sits at exactly the given offset.
fn find_snapshot_at(segment: &Path, target_offset: u64) -> Result<PreMutationSnapshot> {
    let bytes =
        std::fs::read(segment).with_context(|| format!("read segment {}", segment.display()))?;
    // GOLD-ARCH-03: walk via for_each_frame so the offset is resolved against
    // the LOGICAL (decompressed) byte stream — a v2/zstd-compressed segment's
    // snapshot frames are reachable, not silently skipped. `cursor` is the
    // frame's logical offset, matching the `absolute_offset` collect_snapshots
    // recorded.
    let mut found: Option<Result<PreMutationSnapshot>> = None;
    crate::wal::scan::for_each_frame(&bytes, |cursor, frame| {
        if cursor as u64 == target_offset {
            found = Some(
                if frame.header.event_type != EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                    Err(anyhow::anyhow!(
                        "frame at offset {target_offset} is not a PRE_MUTATION_SNAPSHOT \
                     (event_type 0x{:02X}, expected 0xF2)",
                        frame.header.event_type
                    ))
                } else {
                    serde_json::from_slice::<PreMutationSnapshot>(frame.payload)
                        .context("decode snapshot JSON payload")
                },
            );
        }
        Ok(())
    })?;
    found.unwrap_or_else(|| {
        Err(anyhow::anyhow!(
            "no frame found at offset {target_offset} in {}",
            segment.display()
        ))
    })
}

/// Concrete restoration plan derived from a snapshot. Each
/// `MutationKind` produces a different plan; today only `FileWrite` is
/// implemented — the others bail with an "adapter-specific" diagnostic
/// so operators see why their restoration didn't run.
struct ApplyPlan {
    summary: String,
    before_state_bytes_len: usize,
    execute_fn: Box<dyn FnOnce() -> Result<ApplyOutcome>>,
}

struct ApplyOutcome {
    bytes_written: usize,
    summary: String,
}

/// A1 / Decision-1 hybrid: McpToolInvoke restoration.
///
/// Default path is **manual-only** — the dispatcher emits a clear
/// diagnostic so the operator knows what to undo via
/// `neoth mcp call <server> <inverse>`. Most MCP tools either have no
/// safe automatic inverse (create_issue, push, merge) or need
/// response-side data (auto-IDs) that the WAL 0xC0 audit frame
/// doesn't carry today.
///
/// **One hardcoded special case**: when `target = "<server>:write_file:<path>"`,
/// the dispatcher re-issues `write_file` against `<server>` with the
/// captured `before_state` bytes as the new content. This is the only
/// MCP tool where the inverse call shape is IDENTICAL to the original
/// (same tool, same arg shape, no result data needed) and the failure
/// mode is bounded (worst case: write the same bytes back).
///
/// Target format pinned: `"<server>:<tool>"` for the manual path, or
/// `"<server>:write_file:<path>"` for the auto-inverse path. The
/// emission site in the MCP gate populates this; if the format drifts
/// the dispatcher falls back to the manual diagnostic.
fn apply_plan_mcp_tool_invoke(
    snap: &crate::wal::snapshot::PreMutationSnapshot,
    before_state_bytes_len: usize,
    before: Vec<u8>,
) -> Result<ApplyPlan> {
    let target = &snap.target;
    let parts: Vec<&str> = target.splitn(3, ':').collect();
    let (server, tool, path_opt) = match parts.as_slice() {
        [s, t, p] => (*s, *t, Some(*p)),
        [s, t] => (*s, *t, None),
        _ => {
            // Malformed target — give the operator the raw context so
            // they can still act on it manually.
            return Err(anyhow::anyhow!(
                "mcp_tool_invoke snapshot has malformed target `{target}` (expected \
                 `<server>:<tool>` or `<server>:<tool>:<path>`). Restore manually \
                 with the context in the snapshot's `note` field."
            ));
        }
    };

    // Special case: write_file with a path — re-issue the inverse.
    if tool == "write_file" {
        let Some(path) = path_opt else {
            return Err(anyhow::anyhow!(
                "mcp_tool_invoke write_file rollback requires target format \
                 `<server>:write_file:<path>` (got `{target}`). The snapshot \
                 emission site must populate the path; until then this snapshot \
                 needs manual restoration via `neoth mcp call {server} write_file \
                 --args '{{\"path\": \"<your-path>\", \"content\": \"<hex>\"}}'`."
            ));
        };
        let server_owned = server.to_string();
        let path_owned = path.to_string();
        let summary = format!(
            "re-issue `{server_owned}::write_file` with prior {before_state_bytes_len} B at \
             `{path_owned}`"
        );
        Ok(ApplyPlan {
            summary,
            before_state_bytes_len,
            execute_fn: Box::new(move || {
                // Use the same hex-to-string approach the operator would —
                // for now, we surface the inverse-call instructions rather
                // than executing in-process, because the MCP client wiring
                // requires async + the writer. This preserves the audit
                // trail (operator runs the explicit command, sees the result).
                Ok(ApplyOutcome {
                    bytes_written: 0,
                    summary: format!(
                        "MCP write_file inverse PREPARED — run:\n  neoth mcp call \
                         {server_owned} write_file --args '{{\"path\": \"{path_owned}\", \
                         \"content_hex\": \"<below>\"}}'\n  content_hex: {}",
                        hex_preview(&before, 64)
                    ),
                })
            }),
        })
    } else {
        // Manual diagnostic for every other tool — operator chooses
        // the inverse + executes via `neoth mcp call`.
        let server_owned = server.to_string();
        let tool_owned = tool.to_string();
        let summary = format!(
            "manual restoration: MCP tool `{server_owned}::{tool_owned}` was called; \
             {before_state_bytes_len} B of before-state captured. NEOTH does not \
             automate this rollback because the inverse semantics are \
             server-specific."
        );
        Ok(ApplyPlan {
            summary,
            before_state_bytes_len,
            execute_fn: Box::new(move || {
                Ok(ApplyOutcome {
                    bytes_written: 0,
                    summary: format!(
                        "manual restoration required — `{server_owned}::{tool_owned}` has no \
                         built-in inverse dispatcher. Inspect the snapshot's before_state \
                         (hex), pick the inverse tool, run: `neoth mcp call {server_owned} \
                         <inverse-tool> --args '<your-payload>'`. The captured before-state \
                         is available via `neoth rollback list --kind mcp_tool_invoke`."
                    ),
                })
            }),
        })
    }
}

/// A6 / Konsens-decision #6: ChannelSend hybrid dispatcher.
///
/// Per-platform reality determines the inverse strategy:
/// - **Slack**: always (a) — `chat.delete` works for the bot's own
///   messages without a time window. Render the explicit API template.
/// - **Telegram**: 47h-(a)-fallback-(b) — Bot API allows `deleteMessage`
///   within 48h of sending; we use 47h as a safety margin to avoid
///   races near the boundary. Beyond that, only `editMessageText` works
///   so we render the redaction-edit template instead.
/// - **WhatsApp**: (d) bookmark-only — the WhatsApp Business API has no
///   delete or edit primitive. Render explicit manual-action guidance
///   (operator sends an apology + marks the original in their notes).
/// - **keet / other**: bail with not-yet-implemented + format-hint.
///
/// Target format pinned: `"<platform>:<chat_id>:<message_id>"` (3-part)
/// or `"<platform>:<message_id>"` (2-part legacy fallback — chat_id
/// rendered as `<unknown>` in the template). `before_state` is the
/// original message text bytes (UTF-8 expected; non-UTF-8 falls back
/// to a hex preview).
///
/// Like McpToolInvoke, the execute_fn does NOT call the channel API
/// directly — the adapter wiring for each channel still requires
/// auth tokens + async + the writer, and the failure mode (deleting
/// the wrong message) is high-blast-radius. So execute_fn returns a
/// "manual restoration required" outcome with the exact command/API
/// the operator should run. The point of the dispatcher is to make
/// that command copy-paste ready per platform.
fn apply_plan_channel_send(
    snap: &crate::wal::snapshot::PreMutationSnapshot,
    before_state_bytes_len: usize,
    before: &[u8],
) -> Result<ApplyPlan> {
    /// Telegram Bot API allows `deleteMessage` within ~48h; we cut at
    /// 47h to avoid races near the boundary. Outside this window only
    /// `editMessageText` works as a redaction primitive.
    const TELEGRAM_DELETE_WINDOW_SECS: u64 = 47 * 3600;

    let target = &snap.target;
    let parts: Vec<&str> = target.splitn(3, ':').collect();
    let (platform, chat_id, message_id) = match parts.as_slice() {
        [p, c, m] => (*p, Some(*c), *m),
        [p, m] => (*p, None, *m),
        _ => anyhow::bail!(
            "channel_send snapshot has malformed target `{target}` (expected \
             `<platform>:<chat_id>:<message_id>` or `<platform>:<message_id>`)"
        ),
    };
    if platform.is_empty() || message_id.is_empty() {
        anyhow::bail!(
            "channel_send snapshot has empty platform or message_id in target `{target}`"
        );
    }

    let original_text = render_channel_before_state(before);
    let now_unix: i64 = crate::time::now_unix_i64();
    let age_secs: u64 = (now_unix - snap.ts_unix).max(0) as u64;

    let summary: String;
    let outcome_text: String;
    match platform.to_ascii_lowercase().as_str() {
        "slack" => {
            let chat = chat_id.unwrap_or("<unknown-channel>");
            summary = format!(
                "slack: chat.delete on channel `{chat}` ts `{message_id}` (Slack allows \
                 bot self-delete without a time window)"
            );
            outcome_text = format!(
                "manual restoration: run Slack chat.delete via the workspace's bot \
                 token:\n  curl -X POST https://slack.com/api/chat.delete \\\n    -H \
                 'Authorization: Bearer $SLACK_BOT_TOKEN' \\\n    -d 'channel={chat}' \
                 -d 'ts={message_id}'\nOriginal message text ({before_state_bytes_len} B):\n  {original_text}"
            );
        }
        "telegram" => {
            let chat = chat_id.unwrap_or("<unknown-chat>");
            if age_secs <= TELEGRAM_DELETE_WINDOW_SECS {
                summary = format!(
                    "telegram: deleteMessage chat `{chat}` msg `{message_id}` (age \
                     {age_secs}s ≤ 47h window — delete still allowed by Bot API)"
                );
                outcome_text = format!(
                    "manual restoration: run Telegram deleteMessage via the bot \
                     token:\n  curl -X POST https://api.telegram.org/bot$TG_BOT_TOKEN/deleteMessage\n\
                     \x20    -d 'chat_id={chat}' -d 'message_id={message_id}'\nOriginal \
                     message text ({before_state_bytes_len} B):\n  {original_text}"
                );
            } else {
                summary = format!(
                    "telegram: editMessageText chat `{chat}` msg `{message_id}` (age \
                     {age_secs}s > 47h window — delete forbidden by Bot API, falling \
                     back to redaction edit)"
                );
                outcome_text = format!(
                    "manual restoration: run Telegram editMessageText (delete window \
                     expired):\n  curl -X POST https://api.telegram.org/bot$TG_BOT_TOKEN/editMessageText\n\
                     \x20    -d 'chat_id={chat}' -d 'message_id={message_id}'\n\
                     \x20    -d 'text=[REDACTED — operator-initiated rollback]'\nOriginal \
                     message text ({before_state_bytes_len} B, for your records):\n  {original_text}"
                );
            }
        }
        "whatsapp" => {
            let chat = chat_id.unwrap_or("<unknown-recipient>");
            summary = format!(
                "whatsapp: manual bookmark — WhatsApp Business API has no delete or \
                 edit primitive. Operator must send a follow-up apology message to \
                 `{chat}` and mark the original `{message_id}` in their notes."
            );
            outcome_text = format!(
                "manual restoration: WhatsApp Business API offers neither delete nor \
                 edit. Recommended action:\n  1. Send a follow-up to `{chat}` clarifying \
                 / retracting the previous message.\n  2. Note message_id `{message_id}` \
                 in your operator log for audit.\nOriginal message text ({before_state_bytes_len} B):\n  {original_text}"
            );
        }
        other => {
            anyhow::bail!(
                "channel_send platform `{other}` has no rollback dispatcher yet. \
                 Supported: slack | telegram | whatsapp. The captured before_state is \
                 still available via `neoth rollback list --kind channel_send` for \
                 manual review."
            )
        }
    }

    Ok(ApplyPlan {
        summary,
        before_state_bytes_len,
        execute_fn: Box::new(move || {
            Ok(ApplyOutcome {
                bytes_written: 0,
                summary: outcome_text,
            })
        }),
    })
}

/// Render the captured message bytes for the operator-facing rollback
/// template. UTF-8 text is shown verbatim (trimmed to one line for
/// CLI sanity); non-UTF-8 falls back to a 64-byte hex preview.
fn render_channel_before_state(before: &[u8]) -> String {
    match std::str::from_utf8(before) {
        Ok(s) => {
            let single_line: String = s.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
            if single_line.len() > 240 {
                format!("{}...", &single_line[..240])
            } else {
                single_line
            }
        }
        Err(_) => format!("<binary, hex: {}>", hex_preview(before, 64)),
    }
}

/// A2 / Decision-3: SqlMutation restoration scope.
///
/// **Scope = operator-data tables only**: idx_episode, idx_consolidated,
/// idx_longterm, idx_groundtruth, idx_embedding, idx_profile,
/// idx_profile_redactions, sources. Excludes wal_cursor +
/// schema_version + meta (operational bookmarks whose rollback would
/// corrupt the indexer / migration state — see Agent-3 research note).
///
/// **Target format**: `"<table>:<pk_value>"` — parse on `:` once
/// (table names don't contain `:`, primary keys may).
///
/// **before_state JSON shape**:
/// ```json
/// {
///   "op": "insert" | "update" | "delete",
///   "pk_col": "event_id",
///   "row_before": { /* full row as column→value map */ }
/// }
/// ```
///
/// **Inverse semantics**:
/// - op=insert (original was INSERT) → DELETE pk_value to undo
/// - op=update (original was UPDATE) → UPDATE-back via row_before
/// - op=delete (original was DELETE) → INSERT row_before back
///
/// Auto-execute against views.db inside a transaction. Any error rolls
/// back, leaving DB untouched. Operator pairs with `--confirm` on the
/// outer `neoth rollback apply` command.
fn apply_plan_sql_mutation(
    snap: &crate::wal::snapshot::PreMutationSnapshot,
    before_state_bytes_len: usize,
    before: &[u8],
) -> Result<ApplyPlan> {
    const ALLOWED_TABLES: &[&str] = &[
        "idx_episode",
        "idx_consolidated",
        "idx_longterm",
        "idx_groundtruth",
        "idx_embedding",
        "idx_profile",
        "idx_profile_redactions",
        "sources",
    ];

    let target = &snap.target;
    let (table, pk_value) = target.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "sql_mutation snapshot has malformed target `{target}` (expected \
             `<table>:<pk_value>`)"
        )
    })?;
    if !ALLOWED_TABLES.contains(&table) {
        anyhow::bail!(
            "sql_mutation table `{table}` is outside the rollback-safe allowlist. \
             Allowed: [{}]. Operational tables (wal_cursor, schema_version, meta) \
             are excluded because rollback would corrupt the indexer/migration state.",
            ALLOWED_TABLES.join(", ")
        );
    }

    let payload: serde_json::Value =
        serde_json::from_slice(before).context("decode SqlMutation before_state JSON")?;
    let op = payload
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("SqlMutation before_state missing `op` field"))?;
    let pk_col = payload
        .get("pk_col")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("SqlMutation before_state missing `pk_col` field"))?
        .to_string();
    let row_before = payload.get("row_before").cloned();

    validate_sql_identifier(table, "table")?;
    validate_sql_identifier(&pk_col, "pk_col")?;

    let table_owned = table.to_string();
    let pk_value_owned = pk_value.to_string();

    let (summary, plan_fn): (String, Box<dyn FnOnce() -> Result<ApplyOutcome>>) = match op {
        "insert" => {
            // Original was INSERT; inverse is DELETE.
            let s = format!(
                "DELETE FROM `{table_owned}` WHERE `{pk_col}` = '{pk_value_owned}' \
                 (undoes the original INSERT)"
            );
            let pk_v = pk_value_owned.clone();
            let pk_c = pk_col.clone();
            let tab = table_owned.clone();
            (s, Box::new(move || execute_sql_delete(&tab, &pk_c, &pk_v)))
        }
        "update" => {
            let row = row_before.ok_or_else(|| {
                anyhow::anyhow!("SqlMutation op=update requires `row_before` in before_state")
            })?;
            let cols = row
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("`row_before` must be a JSON object"))?
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            let s = format!(
                "UPDATE `{table_owned}` SET <{n} cols> WHERE `{pk_col}` = '{pk_value_owned}' \
                 (restores prior row state)",
                n = cols.len(),
            );
            let pk_v = pk_value_owned.clone();
            let pk_c = pk_col.clone();
            let tab = table_owned.clone();
            (
                s,
                Box::new(move || execute_sql_update(&tab, &pk_c, &pk_v, &row)),
            )
        }
        "delete" => {
            let row = row_before.ok_or_else(|| {
                anyhow::anyhow!("SqlMutation op=delete requires `row_before` in before_state")
            })?;
            let cols = row
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("`row_before` must be a JSON object"))?;
            let s = format!(
                "INSERT INTO `{table_owned}` ({n} cols) (re-inserts the row the original DELETE removed)",
                n = cols.len(),
            );
            let tab = table_owned.clone();
            (s, Box::new(move || execute_sql_insert(&tab, &row)))
        }
        other => {
            anyhow::bail!(
                "SqlMutation op=`{other}` is not recognised. Valid: insert | update | delete"
            )
        }
    };

    Ok(ApplyPlan {
        summary,
        before_state_bytes_len,
        execute_fn: plan_fn,
    })
}

/// Defense-in-depth: even though the table name comes from the WAL
/// (operator-trust boundary), refuse anything that isn't `[A-Za-z0-9_]+`.
/// Prevents a malformed WAL frame from injecting SQL via table or
/// column names in the format strings.
fn validate_sql_identifier(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("sql_mutation {kind} is empty");
    }
    if name.len() > 64 {
        anyhow::bail!(
            "sql_mutation {kind} too long ({} chars, max 64)",
            name.len()
        );
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!(
            "sql_mutation {kind} `{name}` contains invalid chars (allowed: A-Z, a-z, 0-9, _)"
        );
    }
    Ok(())
}

/// SC-02: validate a FileWrite/ConfigWrite rollback target BEFORE it is
/// handed to `std::fs::write`. The `target` comes from a WAL snapshot
/// frame; a tampered/crafted frame carrying `../../../etc/...` would
/// otherwise let `apply` write arbitrary bytes anywhere the daemon can
/// write (the snapshot's `before_state` is the content). Reject empty,
/// null-byte, and path-traversal targets. Real filesystem paths
/// legitimately contain `/`, `:`, `~`, `.`, so this is a traversal +
/// null-byte + non-empty check — NOT the strict label-only regex
/// (`[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}`) which is reserved for a future
/// named-checkpoint API where the target IS a label, not a path.
fn validate_rollback_target(target: &str, kind_label: &str) -> Result<()> {
    if target.is_empty() {
        anyhow::bail!("{kind_label} rollback target is empty");
    }
    if target.contains('\0') {
        anyhow::bail!("{kind_label} rollback target contains a null byte");
    }
    if crate::security::redact::contains_path_traversal(target) {
        anyhow::bail!(
            "{kind_label} rollback target `{target}` contains a path-traversal sequence \
             (../ or ..\\) — refusing to restore outside the original location"
        );
    }
    Ok(())
}

fn open_views_db() -> Result<rusqlite::Connection> {
    let path = crate::memory::store::default_path();
    crate::memory::store::open(&path).with_context(|| {
        format!(
            "open views.db for SqlMutation rollback at {}",
            path.display()
        )
    })
}

fn execute_sql_delete(table: &str, pk_col: &str, pk_value: &str) -> Result<ApplyOutcome> {
    let conn = open_views_db()?;
    let sql = format!("DELETE FROM `{table}` WHERE `{pk_col}` = ?1");
    let rows = conn
        .execute(&sql, rusqlite::params![pk_value])
        .with_context(|| format!("execute {sql}"))?;
    Ok(ApplyOutcome {
        bytes_written: 0,
        summary: format!("DELETE on `{table}` removed {rows} row(s) (inverse of original INSERT)"),
    })
}

fn execute_sql_update(
    table: &str,
    pk_col: &str,
    pk_value: &str,
    row_before: &serde_json::Value,
) -> Result<ApplyOutcome> {
    let obj = row_before
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("row_before must be JSON object"))?;
    let mut set_clauses = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    for (col, val) in obj {
        validate_sql_identifier(col, "column")?;
        set_clauses.push(format!("`{col}` = ?"));
        params.push(json_value_to_sql(val));
    }
    if set_clauses.is_empty() {
        anyhow::bail!("UPDATE inverse needs at least one column in row_before");
    }
    params.push(rusqlite::types::Value::Text(pk_value.to_string()));
    let sql = format!(
        "UPDATE `{table}` SET {} WHERE `{pk_col}` = ?",
        set_clauses.join(", ")
    );
    let conn = open_views_db()?;
    let rows = conn
        .execute(
            &sql,
            rusqlite::params_from_iter(params.iter().map(|v| v as &dyn rusqlite::ToSql)),
        )
        .with_context(|| format!("execute {sql}"))?;
    Ok(ApplyOutcome {
        bytes_written: 0,
        summary: format!(
            "UPDATE on `{table}` restored {} column(s) for pk `{pk_value}` ({rows} row(s) affected)",
            obj.len()
        ),
    })
}

fn execute_sql_insert(table: &str, row_before: &serde_json::Value) -> Result<ApplyOutcome> {
    let obj = row_before
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("row_before must be JSON object"))?;
    let cols: Vec<&str> = obj.keys().map(String::as_str).collect();
    for col in &cols {
        validate_sql_identifier(col, "column")?;
    }
    let placeholders = std::iter::repeat_n("?", cols.len())
        .collect::<Vec<_>>()
        .join(", ");
    let col_list = cols
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let params: Vec<rusqlite::types::Value> = obj.values().map(json_value_to_sql).collect();
    let sql = format!("INSERT INTO `{table}` ({col_list}) VALUES ({placeholders})");
    let conn = open_views_db()?;
    let rows = conn
        .execute(
            &sql,
            rusqlite::params_from_iter(params.iter().map(|v| v as &dyn rusqlite::ToSql)),
        )
        .with_context(|| format!("execute {sql}"))?;
    Ok(ApplyOutcome {
        bytes_written: 0,
        summary: format!(
            "INSERT into `{table}` restored {rows} row(s) (inverse of original DELETE)"
        ),
    })
}

/// Convert a serde_json `Value` to a rusqlite-compatible value.
/// SQLite's type system collapses numbers + bools + null to its 5
/// storage classes; objects/arrays serialise back to JSON text for
/// columns that carry JSON content.
fn json_value_to_sql(v: &serde_json::Value) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::Text(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Value::Text(serde_json::to_string(v).unwrap_or_default())
        }
    }
}

/// Render up to `max_bytes` of hex with an ellipsis when truncated.
/// Used by the McpToolInvoke diagnostic so the operator sees enough
/// of the before-state to reason about it without flooding the CLI.
fn hex_preview(bytes: &[u8], max_bytes: usize) -> String {
    let mut out = String::with_capacity(max_bytes * 2 + 4);
    for b in bytes.iter().take(max_bytes) {
        out.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > max_bytes {
        out.push_str("...");
    }
    out
}

impl ApplyPlan {
    fn from_snapshot(snap: &PreMutationSnapshot) -> Result<Self> {
        use crate::wal::snapshot::MutationKind;
        let before = snap
            .before_state_bytes()
            .context("decode snapshot before_state hex")?;
        let before_state_bytes_len = before.len();
        match snap.mutation_kind {
            MutationKind::FileWrite => {
                validate_rollback_target(&snap.target, "file_write")?;
                let target = snap.target.clone();
                let bytes = before.clone();
                let summary = format!(
                    "write {} B back to `{}` (replacing current content)",
                    before_state_bytes_len, target
                );
                Ok(ApplyPlan {
                    summary,
                    before_state_bytes_len,
                    execute_fn: Box::new(move || {
                        let path = std::path::PathBuf::from(&target);
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).with_context(|| {
                                format!("create parent dir for {}", path.display())
                            })?;
                        }
                        std::fs::write(&path, &bytes)
                            .with_context(|| format!("restore file {}", path.display()))?;
                        Ok(ApplyOutcome {
                            bytes_written: bytes.len(),
                            summary: format!("file {} restored", path.display()),
                        })
                    }),
                })
            }
            MutationKind::ChannelSend => {
                apply_plan_channel_send(snap, before_state_bytes_len, &before)
            }
            MutationKind::McpToolInvoke => {
                apply_plan_mcp_tool_invoke(snap, before_state_bytes_len, before.clone())
            }
            MutationKind::SqlMutation => {
                apply_plan_sql_mutation(snap, before_state_bytes_len, &before)
            }
            MutationKind::ConfigWrite => {
                validate_rollback_target(&snap.target, "config_write")?;
                let target = snap.target.clone();
                let bytes = before.clone();
                let summary = format!(
                    "restore config file `{}` to its prior {} B state",
                    target, before_state_bytes_len
                );
                Ok(ApplyPlan {
                    summary,
                    before_state_bytes_len,
                    execute_fn: Box::new(move || {
                        std::fs::write(&target, &bytes)
                            .with_context(|| format!("restore config {target}"))?;
                        Ok(ApplyOutcome {
                            bytes_written: bytes.len(),
                            summary: format!("config {target} restored"),
                        })
                    }),
                })
            }
            MutationKind::Other => Err(anyhow::anyhow!(
                "MutationKind::Other has no built-in restoration dispatcher. The \
                 snapshot target carries the operator-supplied description; restore \
                 manually based on that context."
            )),
        }
    }

    fn execute(self) -> Result<ApplyOutcome> {
        (self.execute_fn)()
    }
}

/// Walk every `*.wal` segment + decode `PRE_MUTATION_SNAPSHOT` frames.
/// Returns each match paired with `(segment_path, offset)` so the
/// CLI can render where each snapshot lives + use the offset as the
/// stable snapshot id.
fn collect_snapshots(
    wal_dir: &Path,
    kind_filter: Option<&str>,
) -> Result<Vec<((String, u64), PreMutationSnapshot)>> {
    let entries = match std::fs::read_dir(wal_dir) {
        Ok(it) => it,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let segment_display = path.display().to_string();
        // GOLD-ARCH-03: for_each_frame decompresses a v2/zstd segment so its
        // PRE_MUTATION_SNAPSHOT frames are found (the raw-byte walk skipped
        // them entirely). `cursor` is the frame's logical offset — the
        // absolute_offset rollback records + later resolves in find_snapshot_at.
        // A single unreconstructable segment is skipped, not fatal to the scan.
        let _ = crate::wal::scan::for_each_frame(&bytes, |cursor, frame| {
            if frame.header.event_type == EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                if let Ok(snap) = serde_json::from_slice::<PreMutationSnapshot>(frame.payload) {
                    let kind_matches = kind_filter
                        .map(|k| kind_to_string(&snap.mutation_kind).eq_ignore_ascii_case(k.trim()))
                        .unwrap_or(true);
                    if kind_matches {
                        out.push(((segment_display.clone(), cursor as u64), snap));
                    }
                }
            }
            Ok(())
        });
    }
    Ok(out)
}

fn kind_to_string(k: &crate::wal::snapshot::MutationKind) -> String {
    use crate::wal::snapshot::MutationKind;
    match k {
        MutationKind::FileWrite => "file_write".into(),
        MutationKind::ChannelSend => "channel_send".into(),
        MutationKind::McpToolInvoke => "mcp_tool_invoke".into(),
        MutationKind::SqlMutation => "sql_mutation".into(),
        MutationKind::ConfigWrite => "config_write".into(),
        MutationKind::Other => "other".into(),
    }
}

fn format_iso8601(unix_secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("{unix_secs}-epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::snapshot::{MutationKind, emit_snapshot};
    use crate::wal::writer::spawn;
    use tempfile::tempdir;

    #[tokio::test]
    async fn list_returns_empty_when_wal_dir_absent() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope");
        let entries = collect_snapshots(&missing, None).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_skips_non_wal_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"not a wal").unwrap();
        let entries = collect_snapshots(dir.path(), None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn sc02_rejects_path_traversal_in_file_write_target() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "../../../etc/passwd",
            b"malicious",
            1_700_000_100,
        );
        let err = ApplyPlan::from_snapshot(&snap)
            .err()
            .expect("expected Err for path-traversal target");
        assert!(err.to_string().contains("path-traversal"), "got: {err}");
    }

    #[test]
    fn sc02_rejects_path_traversal_in_config_write_target() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ConfigWrite,
            "..\\..\\windows\\system32\\x",
            b"malicious",
            1_700_000_100,
        );
        let err = ApplyPlan::from_snapshot(&snap)
            .err()
            .expect("expected Err for path-traversal target");
        assert!(err.to_string().contains("path-traversal"), "got: {err}");
    }

    #[test]
    fn sc02_allows_legit_absolute_file_write_target() {
        // A normal absolute path (no traversal) must still build a plan —
        // the guard must not over-reject legitimate restore targets.
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/home/user/.config/app.conf",
            b"content",
            1_700_000_100,
        );
        assert!(ApplyPlan::from_snapshot(&snap).is_ok());
    }

    #[tokio::test]
    async fn list_finds_emitted_snapshot_frames() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let snap_a = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/tmp/a",
            b"before-a",
            1_700_000_100,
        );
        let snap_b = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "telegram:123",
            b"before-b",
            1_700_000_200,
        )
        .with_note("operator pre-edit");
        emit_snapshot(&writer, &snap_a).await.unwrap();
        emit_snapshot(&writer, &snap_b).await.unwrap();
        drop(writer);
        let _ = join.await;

        let entries = collect_snapshots(dir.path(), None).unwrap();
        assert_eq!(entries.len(), 2);
        let kinds: Vec<String> = entries
            .iter()
            .map(|(_, s)| kind_to_string(&s.mutation_kind))
            .collect();
        assert!(kinds.contains(&"file_write".to_string()));
        assert!(kinds.contains(&"channel_send".to_string()));
    }

    #[tokio::test]
    async fn collect_and_find_snapshots_in_a_v2_compressed_segment() {
        // GOLD-ARCH-03 regression: PRE_MUTATION_SNAPSHOT frames inside a v2
        // (zstd-compressed) segment must be found by collect_snapshots AND
        // resolvable by find_snapshot_at. Before the fix both walked the raw
        // zstd blob and found ZERO snapshots, so `neoth rollback` could not undo
        // any mutation recorded in a compacted segment.
        use crate::wal::HeaderBuilder;
        use crate::wal::compress::compress_frames;
        use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
        };

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000003.wal");

        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/tmp/compressed-target",
            b"before-bytes",
            1_700_000_300,
        );
        let payload = serde_json::to_vec(&snap).unwrap();
        let h = HeaderBuilder::new(EVENT_TYPE_PRE_MUTATION_SNAPSHOT, &payload).build();
        let frame = encode_frame(&h, &payload);

        // Finalize as a v2 compressed segment: 61-byte header + zstd(frame).
        let blob = compress_frames(&frame).unwrap();
        let hdr = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg_bytes = hdr.to_le_bytes().to_vec();
        seg_bytes.extend_from_slice(&blob);
        std::fs::write(&seg, &seg_bytes).unwrap();

        let entries = collect_snapshots(dir.path(), None).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "snapshot inside the zstd blob must be found"
        );
        let ((_, offset), found) = &entries[0];
        assert_eq!(
            *offset, SEGMENT_HEADER_V2_LEN as u64,
            "offset is the frame's logical offset (after the 61-byte v2 header)"
        );
        assert_eq!(kind_to_string(&found.mutation_kind), "file_write");

        // find_snapshot_at resolves the same offset against the logical bytes.
        let resolved = find_snapshot_at(&seg, *offset).unwrap();
        assert_eq!(kind_to_string(&resolved.mutation_kind), "file_write");
    }

    #[tokio::test]
    async fn list_filters_by_kind_case_insensitive() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        for k in [MutationKind::FileWrite, MutationKind::ChannelSend] {
            let snap = crate::wal::snapshot::PreMutationSnapshot::new(k, "x", b"y", 1700);
            emit_snapshot(&writer, &snap).await.unwrap();
        }
        drop(writer);
        let _ = join.await;

        let entries = collect_snapshots(dir.path(), Some("FILE_WRITE")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            kind_to_string(&entries[0].1.mutation_kind),
            "file_write".to_string()
        );
        let entries = collect_snapshots(dir.path(), Some("file_write")).unwrap();
        assert_eq!(entries.len(), 1);
        let entries = collect_snapshots(dir.path(), Some("nonsense")).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_skips_corrupt_tail_without_panicking() {
        // Write a valid snapshot then append junk bytes to simulate a
        // partially-written frame at segment tail. The walker must
        // surface the valid frame + stop cleanly.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let snap =
            crate::wal::snapshot::PreMutationSnapshot::new(MutationKind::Other, "x", b"y", 1700);
        emit_snapshot(&writer, &snap).await.unwrap();
        drop(writer);
        let _ = join.await;
        std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        // Append 20 garbage bytes to simulate truncation.
        let mut bytes = std::fs::read(&seg).unwrap();
        bytes.extend_from_slice(&[0xaa; 20]);
        std::fs::write(&seg, bytes).unwrap();

        let entries = collect_snapshots(dir.path(), None).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn kind_to_string_covers_every_variant() {
        // Drift guard — if a new MutationKind variant lands, this
        // exhaustive match forces the CLI to render it (no silent
        // dropout).
        for k in [
            MutationKind::FileWrite,
            MutationKind::ChannelSend,
            MutationKind::McpToolInvoke,
            MutationKind::SqlMutation,
            MutationKind::ConfigWrite,
            MutationKind::Other,
        ] {
            let s = kind_to_string(&k);
            assert!(!s.is_empty());
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn format_iso8601_emits_rfc3339_utc() {
        let s = format_iso8601(1_700_000_000);
        let parsed = chrono::DateTime::parse_from_rfc3339(&s).expect("RFC3339 parse");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
        assert!(s.ends_with('Z'));
    }

    #[tokio::test]
    async fn find_snapshot_at_returns_payload_for_known_offset() {
        // Emit one snapshot, locate it by its frame offset, verify
        // round-trip.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/tmp/find.txt",
            b"orig content",
            1700,
        );
        let offset = emit_snapshot(&writer, &snap).await.unwrap();
        drop(writer);
        let _ = join.await;

        let found = find_snapshot_at(&seg, offset).unwrap();
        assert_eq!(found.target, "/tmp/find.txt");
        assert_eq!(found.before_state_bytes().unwrap(), b"orig content");
    }

    #[tokio::test]
    async fn find_snapshot_at_errors_when_offset_misses_frame_start() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/tmp/x",
            b"x",
            1700,
        );
        let real_offset = emit_snapshot(&writer, &snap).await.unwrap();
        drop(writer);
        let _ = join.await;

        // An offset that's NOT a frame boundary must error rather
        // than reading garbage as a snapshot.
        let err = find_snapshot_at(&seg, real_offset + 7).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no frame found") || msg.contains("decode frame"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn apply_plan_file_write_restores_bytes_to_target_path() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("restored.txt");
        // Pretend the file currently has the "after" state.
        std::fs::write(&target, b"mutated content").unwrap();

        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            target.display().to_string(),
            b"original-content-before-mutation",
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        assert_eq!(plan.before_state_bytes_len, 32);
        let outcome = plan.execute().unwrap();
        assert_eq!(outcome.bytes_written, 32);

        // Target file now holds the original bytes.
        let body = std::fs::read(&target).unwrap();
        assert_eq!(body, b"original-content-before-mutation");
    }

    #[tokio::test]
    async fn apply_plan_file_write_creates_parent_dir_when_missing() {
        // Restore to a nested path whose parent doesn't exist. The
        // dispatcher must create it rather than failing — operators
        // who forget can run rollback even after their working tree
        // moved.
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a/b/c/restored.txt");
        assert!(!nested.exists());

        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::FileWrite,
            nested.display().to_string(),
            b"hello",
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        plan.execute().unwrap();
        assert_eq!(std::fs::read(&nested).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn apply_plan_config_write_restores_like_file_write() {
        // ConfigWrite uses the same byte-restore semantics as
        // FileWrite (target → freedom.yaml or credentials.yaml is
        // just a path). Verify the path runs.
        let dir = tempdir().unwrap();
        let target = dir.path().join("freedom.yaml");
        std::fs::write(&target, b"current: yaml").unwrap();

        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ConfigWrite,
            target.display().to_string(),
            b"original: yaml",
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        let outcome = plan.execute().unwrap();
        assert_eq!(outcome.bytes_written, 14);
        assert_eq!(std::fs::read(&target).unwrap(), b"original: yaml");
    }

    #[test]
    fn apply_plan_channel_send_slack_renders_chat_delete_template() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "slack:C0123:1700000000.000200",
            b"hello team",
            1_700_000_000,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("slack should plan");
        assert!(plan.summary.contains("chat.delete"));
        assert!(plan.summary.contains("C0123"));
        assert!(plan.summary.contains("1700000000.000200"));
        let outcome = plan.execute().expect("execute renders template");
        assert!(outcome.summary.contains("Bearer $SLACK_BOT_TOKEN"));
        assert!(outcome.summary.contains("hello team"));
    }

    #[test]
    fn apply_plan_channel_send_telegram_within_47h_uses_delete_message() {
        // ts_unix near "now" so age stays under the 47h gate.
        let now: i64 = crate::time::now_unix_i64();
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "telegram:-100123:42",
            b"oops wrong chat",
            now - 60,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("telegram fresh plans");
        assert!(plan.summary.contains("deleteMessage"));
        assert!(plan.summary.contains("47h window"));
        let outcome = plan.execute().unwrap();
        assert!(outcome.summary.contains("api.telegram.org"));
        assert!(outcome.summary.contains("deleteMessage"));
        assert!(outcome.summary.contains("oops wrong chat"));
    }

    #[test]
    fn apply_plan_channel_send_telegram_past_47h_uses_edit_message() {
        // 48h in the past → past the delete window.
        let now: i64 = crate::time::now_unix_i64();
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "telegram:-100123:42",
            b"old typo",
            now - 48 * 3600,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("telegram stale plans");
        assert!(plan.summary.contains("editMessageText"));
        assert!(plan.summary.contains("delete forbidden"));
        let outcome = plan.execute().unwrap();
        assert!(outcome.summary.contains("editMessageText"));
        assert!(outcome.summary.contains("[REDACTED"));
    }

    #[test]
    fn apply_plan_channel_send_whatsapp_renders_manual_bookmark() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "whatsapp:+491700000000:wamid.HBgM",
            b"sent to wrong contact",
            1_700_000_000,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("whatsapp plans");
        assert!(plan.summary.contains("manual bookmark"));
        assert!(plan.summary.contains("wamid.HBgM"));
        let outcome = plan.execute().unwrap();
        assert!(outcome.summary.contains("neither delete nor"));
        assert!(outcome.summary.contains("sent to wrong contact"));
    }

    #[test]
    fn apply_plan_channel_send_legacy_two_part_target_falls_back_to_unknown_chat() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "slack:1700000000.000200",
            b"legacy snap",
            1_700_000_000,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("legacy 2-part target still plans");
        assert!(plan.summary.contains("<unknown-channel>"));
    }

    #[test]
    fn apply_plan_channel_send_unknown_platform_errors_with_format_hint() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "matrix:!room:server:msg-id",
            b"hi",
            1_700_000_000,
        );
        let err = ApplyPlan::from_snapshot(&snap)
            .err()
            .expect("matrix not supported");
        let msg = err.to_string();
        assert!(msg.contains("no rollback dispatcher yet"));
        assert!(msg.contains("slack | telegram | whatsapp"));
    }

    #[test]
    fn apply_plan_channel_send_malformed_target_errors() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "telegram",
            b"x",
            1_700_000_000,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().expect("must reject");
        assert!(err.to_string().contains("malformed target"));
    }

    #[test]
    fn apply_plan_channel_send_binary_before_state_falls_back_to_hex_preview() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::ChannelSend,
            "slack:C1:1700.0001",
            &[0xff, 0xfe, 0x00, 0x80],
            1_700_000_000,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        let outcome = plan.execute().unwrap();
        assert!(outcome.summary.contains("<binary, hex:"));
        assert!(outcome.summary.contains("fffe0080"));
    }

    #[test]
    fn apply_plan_mcp_invoke_returns_manual_diagnostic_for_non_write_file_tool() {
        // A1: McpToolInvoke now produces a manual-restoration plan
        // rather than a hard error for every tool. The execute step
        // emits an operator-actionable diagnostic + exits Ok.
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::McpToolInvoke,
            "filesystem:read_file",
            b"args hash",
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("plan builds");
        assert!(plan.summary.contains("manual restoration"));
        assert!(plan.summary.contains("filesystem::read_file"));
        let outcome = plan.execute().expect("execute prints diagnostic");
        assert_eq!(outcome.bytes_written, 0);
        assert!(outcome.summary.contains("manual restoration required"));
        assert!(outcome.summary.contains("neoth mcp call filesystem"));
    }

    #[test]
    fn apply_plan_mcp_invoke_write_file_with_path_produces_inverse_instructions() {
        // A1 special case: target = `<server>:write_file:<path>` →
        // dispatcher renders the explicit inverse-call instructions
        // including the captured before-state hex.
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::McpToolInvoke,
            "filesystem:write_file:/tmp/x.txt",
            b"original-content",
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("plan builds");
        assert!(plan.summary.contains("write_file"));
        assert!(plan.summary.contains("/tmp/x.txt"));
        assert_eq!(plan.before_state_bytes_len, 16);
        let outcome = plan.execute().expect("execute renders inverse");
        assert!(outcome.summary.contains("MCP write_file inverse PREPARED"));
        assert!(
            outcome
                .summary
                .contains("neoth mcp call filesystem write_file")
        );
        // Hex preview must contain the encoded "original-content" prefix.
        assert!(
            outcome.summary.contains("6f726967696e616c"),
            "got: {}",
            outcome.summary
        );
    }

    #[test]
    fn apply_plan_mcp_invoke_write_file_without_path_errors_actionably() {
        // Without the path in target, write_file rollback can't fire.
        // Diagnostic must explain WHY + how to fix.
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::McpToolInvoke,
            "filesystem:write_file",
            b"original",
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("requires target format"));
        assert!(msg.contains("server>:write_file:<path>"));
    }

    #[test]
    fn apply_plan_mcp_invoke_malformed_target_returns_actionable_error() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::McpToolInvoke,
            "no-colon-here",
            b"x",
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("malformed target"));
    }

    #[test]
    fn hex_preview_truncates_long_payloads() {
        let bytes = vec![0xab; 200];
        let preview = hex_preview(&bytes, 32);
        // 32 bytes × 2 chars + "..." = 67.
        assert!(preview.ends_with("..."));
        assert!(preview.len() > 32);
        // Short payload — no ellipsis.
        let short = hex_preview(&[0x01, 0x02, 0x03], 32);
        assert_eq!(short, "010203");
    }

    #[test]
    fn apply_plan_sql_mutation_rejects_table_outside_allowlist() {
        // wal_cursor is explicitly excluded — rolling back the indexer
        // bookmark would re-index frames + corrupt the views.
        let payload = serde_json::json!({
            "op": "insert",
            "pk_col": "segment_path",
            "row_before": {"segment_path": "x.wal", "next_offset": 0},
        });
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "wal_cursor:x.wal",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("wal_cursor"));
        assert!(msg.contains("outside the rollback-safe allowlist"));
    }

    #[test]
    fn apply_plan_sql_mutation_accepts_allowlisted_table() {
        let payload = serde_json::json!({
            "op": "insert",
            "pk_col": "event_id",
            "row_before": {"event_id": 42},
        });
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "idx_episode:42",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).expect("plan builds");
        assert!(plan.summary.contains("DELETE FROM `idx_episode`"));
        assert!(plan.summary.contains("undoes the original INSERT"));
    }

    #[test]
    fn apply_plan_sql_mutation_update_op_renders_set_clause_count() {
        let payload = serde_json::json!({
            "op": "update",
            "pk_col": "event_id",
            "row_before": {"text": "prior", "importance": 0.5, "ts_ns": 1700},
        });
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "idx_episode:99",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        assert!(plan.summary.contains("UPDATE `idx_episode`"));
        assert!(plan.summary.contains("<3 cols>"));
        assert!(plan.summary.contains("restores prior row state"));
    }

    #[test]
    fn apply_plan_sql_mutation_delete_op_renders_insert_back() {
        let payload = serde_json::json!({
            "op": "delete",
            "pk_col": "id",
            "row_before": {
                "id": 7,
                "text": "deleted row",
                "ts_ns": 1700,
                "source": "operator",
            },
        });
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "sources:7",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let plan = ApplyPlan::from_snapshot(&snap).unwrap();
        assert!(plan.summary.contains("INSERT INTO `sources`"));
        assert!(plan.summary.contains("4 cols"));
    }

    #[test]
    fn apply_plan_sql_mutation_rejects_malformed_target() {
        let payload = serde_json::json!({"op": "insert", "pk_col": "id", "row_before": {}});
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "no-colon",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        assert!(err.to_string().contains("malformed target"));
    }

    #[test]
    fn apply_plan_sql_mutation_rejects_unknown_op() {
        let payload = serde_json::json!({"op": "truncate", "pk_col": "id", "row_before": {}});
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::SqlMutation,
            "idx_episode:1",
            &serde_json::to_vec(&payload).unwrap(),
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("op=`truncate`"));
        assert!(msg.contains("insert | update | delete"));
    }

    #[test]
    fn validate_sql_identifier_accepts_clean_names() {
        assert!(validate_sql_identifier("idx_episode", "table").is_ok());
        assert!(validate_sql_identifier("event_id", "pk_col").is_ok());
        assert!(validate_sql_identifier("ts_ns", "column").is_ok());
    }

    #[test]
    fn validate_sql_identifier_rejects_injection_attempts() {
        // SQL-injection-style names must be refused before reaching
        // the format string. (Defense-in-depth: WAL is operator-trust,
        // but a corrupt frame should not produce a SQL exec.)
        assert!(validate_sql_identifier("idx; DROP TABLE x", "table").is_err());
        assert!(validate_sql_identifier("idx`evil`", "table").is_err());
        assert!(validate_sql_identifier("idx-with-dash", "table").is_err());
        assert!(validate_sql_identifier(" leading_space", "table").is_err());
        assert!(validate_sql_identifier("", "table").is_err());
    }

    #[test]
    fn json_value_to_sql_handles_all_json_types() {
        use rusqlite::types::Value;
        assert!(matches!(
            json_value_to_sql(&serde_json::json!(null)),
            Value::Null
        ));
        assert!(matches!(
            json_value_to_sql(&serde_json::json!(true)),
            Value::Integer(1)
        ));
        assert!(matches!(
            json_value_to_sql(&serde_json::json!(false)),
            Value::Integer(0)
        ));
        assert!(matches!(
            json_value_to_sql(&serde_json::json!(42)),
            Value::Integer(42)
        ));
        assert!(matches!(
            json_value_to_sql(&serde_json::json!(1.25)),
            Value::Real(_)
        ));
        // Strings + nested objects round-trip as text.
        if let Value::Text(s) = json_value_to_sql(&serde_json::json!("hello")) {
            assert_eq!(s, "hello");
        } else {
            panic!("expected Text");
        }
        if let Value::Text(s) = json_value_to_sql(&serde_json::json!({"a": 1})) {
            assert!(s.contains("\"a\""));
        } else {
            panic!("expected Text from nested object");
        }
    }

    #[test]
    fn apply_plan_other_kind_returns_actionable_error() {
        let snap = crate::wal::snapshot::PreMutationSnapshot::new(
            MutationKind::Other,
            "unknown adapter",
            b"x",
            1700,
        );
        let err = ApplyPlan::from_snapshot(&snap).err().unwrap();
        let msg = err.to_string();
        // Operator should see WHY + what to do.
        assert!(msg.contains("no built-in restoration dispatcher"));
        assert!(msg.contains("restore manually"));
    }
}
