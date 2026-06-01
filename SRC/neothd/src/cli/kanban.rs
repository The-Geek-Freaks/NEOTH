//! `neoth kanban` — operator-facing CLI for the V11 coding workflow.
//!
//! Pick #5a per `PLAN/SPEC_coding_workflow.md` build order. Wires
//! Pick #2 store CRUD + Pick #3 classifier + Pick #7 feed parser
//! into 8 subcommands operators actually use:
//!
//! - `list`             — active sessions in this `~/.neoth/views.db`
//! - `show <session>`   — every task in a session, grouped by status
//! - `task <task>`      — one task's detail + comment thread
//! - `move <task> <st>` — change a task's status column
//! - `assign <t> <h>`   — bind a task to a hemisphere + (optional) worker
//! - `comment <t> "..."` — append an operator-side comment
//! - `archive <s>`      — close a session (status=done or abandoned)
//! - `watch`            — scan the WAL for kanban frames, render activity feed
//!
//! Read-only paths run against `views.db` directly. Mutating paths
//! call into `coding::store::*`. The watch command walks every
//! `~/.neoth/wal/*.wal` segment, filters frames via
//! `coding::feed::is_kanban_event`, and renders through
//! `coding::feed::parse_kanban_payload`. No daemon required — the
//! CLI works against a backup tarball's wal/ + views.db.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::coding::feed::{FeedEntry, is_kanban_event, parse_kanban_payload};
use crate::coding::store;
use crate::coding::types::{
    Hemisphere, KanbanSession, KanbanSessionId, KanbanTask, KanbanTaskId, SessionStatus, TaskStatus,
};
use crate::config::FreedomConfig;
use crate::memory::store as memstore;
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::SEGMENT_HEADER_LEN;

#[derive(Args, Debug, Clone)]
pub struct KanbanArgs {
    #[command(subcommand)]
    pub action: KanbanAction,
    /// Override the `views.db` path. Defaults to `~/.neoth/views.db`.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum KanbanAction {
    /// List active sessions (not archived).
    List {
        /// Include archived + done sessions in the listing.
        #[arg(long)]
        all: bool,
    },
    /// Show every task in a session grouped by status column.
    Show { session_id: i64 },
    /// Show one task's detail + its comment thread.
    Task { task_id: i64 },
    /// Move a task between status columns.
    Move {
        task_id: i64,
        /// Target status: `backlog` / `todo` / `in_progress` / `review` /
        /// `done` / `blocked` / `archived`.
        status: String,
    },
    /// Assign a task to a hemisphere + optional worker provider.
    Assign {
        task_id: i64,
        /// `left` / `right` / `cerebellum` / `unassigned`.
        hemisphere: String,
        #[arg(long)]
        worker: Option<String>,
    },
    /// Append a comment to a task.
    Comment {
        task_id: i64,
        body: String,
        /// Comment author label. Defaults to `operator`.
        #[arg(long, default_value = "operator")]
        author: String,
    },
    /// Archive a session (status=done or abandoned).
    Archive {
        session_id: i64,
        #[arg(long, default_value = "done")]
        status: String,
        #[arg(long)]
        summary: Option<String>,
    },
    /// V11 Pick #10 — review a REVIEW-status task. Default mode is
    /// "check only" (`--check`, prints whether the task is auto-
    /// promotable + the blocker reason if not). `--promote` actually
    /// transitions REVIEW → DONE when `test_summary.all_green()` is
    /// true. `--all <session_id>` sweeps every REVIEW task in a
    /// session in one pass.
    Review {
        /// Task id to check / promote. Omit when using `--all`.
        task_id: Option<i64>,
        /// Promote the task (or every eligible task in a session)
        /// when the auto-promote check passes. Without this flag,
        /// the command runs in check-only mode + prints the verdict
        /// without touching state.
        #[arg(long)]
        promote: bool,
        /// Sweep every REVIEW task in a session instead of one task.
        #[arg(long, value_name = "SESSION_ID")]
        all: Option<i64>,
    },
    /// Scan the WAL directory for kanban event frames + render the
    /// activity feed. Default is one-shot (print the last `limit`
    /// entries + exit). `--follow` keeps the process attached to the
    /// directory + tails new frames as the WAL writer lands them,
    /// rescanning every `--interval-ms`. Exits on Ctrl+C.
    Watch {
        /// Override the WAL directory. Defaults to `~/.neoth/wal`.
        #[arg(long)]
        wal_dir: Option<PathBuf>,
        /// Print at most this many entries (newest-last). In `--follow`
        /// mode this caps the initial backlog dump; subsequent deltas
        /// are not capped because each tick's delta is typically tiny.
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Stream new kanban frames as the WAL writer lands them.
        /// Re-scans the WAL directory every `--interval-ms` + prints
        /// only entries newer than the last printed frame's HLC
        /// timestamp. Exits cleanly on Ctrl+C.
        #[arg(long, default_value_t = false)]
        follow: bool,
        /// Re-scan cadence in milliseconds for `--follow`. Default
        /// 1500ms — close to operator real-time without hammering the
        /// disk during an idle session. Ignored without `--follow`.
        #[arg(long, default_value_t = 1500)]
        interval_ms: u64,
    },
}

pub async fn run_kanban(args: KanbanArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(memstore::default_path);
    match args.action {
        KanbanAction::List { all } => {
            let conn = open_views_db(&db_path)?;
            run_list(&conn, all, args.output)
        }
        KanbanAction::Show { session_id } => {
            let conn = open_views_db(&db_path)?;
            run_show(&conn, KanbanSessionId(session_id), args.output)
        }
        KanbanAction::Task { task_id } => {
            let conn = open_views_db(&db_path)?;
            run_task_detail(&conn, KanbanTaskId(task_id), args.output)
        }
        KanbanAction::Move { task_id, status } => {
            let conn = open_views_db(&db_path)?;
            run_move(&conn, KanbanTaskId(task_id), &status)
        }
        KanbanAction::Assign {
            task_id,
            hemisphere,
            worker,
        } => {
            let conn = open_views_db(&db_path)?;
            run_assign(&conn, KanbanTaskId(task_id), &hemisphere, worker.as_deref())
        }
        KanbanAction::Comment {
            task_id,
            body,
            author,
        } => {
            let conn = open_views_db(&db_path)?;
            run_comment(&conn, KanbanTaskId(task_id), &author, &body)
        }
        KanbanAction::Archive {
            session_id,
            status,
            summary,
        } => {
            let conn = open_views_db(&db_path)?;
            run_archive(
                &conn,
                KanbanSessionId(session_id),
                &status,
                summary.as_deref(),
            )
        }
        KanbanAction::Watch {
            wal_dir,
            limit,
            follow,
            interval_ms,
        } => {
            let dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);
            if follow {
                run_watch_follow(&dir, limit, interval_ms, args.output).await
            } else {
                run_watch(&dir, limit, args.output)
            }
        }
        KanbanAction::Review {
            task_id,
            promote,
            all,
        } => {
            let conn = open_views_db(&db_path)?;
            run_review(&conn, task_id, promote, all)
        }
    }
}

/// Open views.db + ensure the `idx_kanban_*` schema is present. This
/// runs the schema initializer idempotently every call so first-time
/// CLI use against a fresh views.db lands the tables on demand
/// without requiring a `neoth init` re-run.
fn open_views_db(path: &std::path::Path) -> Result<Connection> {
    let conn = memstore::open(path).context("open views.db")?;
    store::ensure_schema(&conn).context("ensure kanban schema")?;
    Ok(conn)
}

// ── Subcommand handlers ────────────────────────────────────────────────────

fn run_list(conn: &Connection, all: bool, output: OutputFormat) -> Result<()> {
    let sessions = select_sessions(conn, all)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Always emit a JSON array (possibly empty) so the
            // neothd-gui binding can parse the same shape whether or
            // not the operator has run `neoth code` yet.
            println!(
                "{}",
                serde_json::to_string(&sessions).context("serialise sessions")?
            );
            return Ok(());
        }
        OutputFormat::Table => {}
    }
    if sessions.is_empty() {
        println!("(no kanban sessions)");
        return Ok(());
    }
    let id_col = "ID";
    let created_col = "CREATED";
    let status_col = "STATUS";
    let prompt_col = "PROMPT";
    println!("{id_col:>5}  {created_col:<20}  {status_col:<10}  {prompt_col}");
    for s in &sessions {
        let prompt_preview: String = s.prompt.chars().take(60).collect();
        println!(
            "{:>5}  {:<20}  {:<10}  {}",
            s.session_id.raw(),
            format_ts_short(s.created_ns),
            s.status.as_str(),
            prompt_preview,
        );
    }
    Ok(())
}

fn run_show(conn: &Connection, session_id: KanbanSessionId, output: OutputFormat) -> Result<()> {
    let session = store::get_session(conn, session_id)?
        .ok_or_else(|| anyhow!("session {} not found", session_id.raw()))?;
    let tasks = store::list_tasks_for_session(conn, session_id)?;

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        // Combined envelope so `neothd-gui` gets the full board state in
        // one subprocess call. Schema:
        //   { "session": KanbanSession, "tasks": [KanbanTask] }
        let body = serde_json::json!({
            "session": session,
            "tasks": tasks,
        });
        println!(
            "{}",
            serde_json::to_string(&body).context("serialise session+tasks")?
        );
        return Ok(());
    }

    println!(
        "Session #{}  ({})",
        session.session_id.raw(),
        session.status.as_str()
    );
    println!("  Created  : {}", format_ts_short(session.created_ns));
    println!("  Channel  : {}", session.source_channel);
    println!(
        "  Operator : {}",
        session.operator_id.as_deref().unwrap_or("-")
    );
    println!("  Prompt   : {}", session.prompt);
    if let Some(summary) = session.summary.as_ref() {
        println!("  Summary  : {summary}");
    }
    println!();

    if tasks.is_empty() {
        println!("(no tasks in this session yet)");
        return Ok(());
    }

    print_kanban_board(&tasks);
    Ok(())
}

fn run_task_detail(conn: &Connection, task_id: KanbanTaskId, output: OutputFormat) -> Result<()> {
    let task = select_one_task(conn, task_id)?;
    let comments = store::list_comments_for_task(conn, task_id)?;

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        // Combined envelope so the GUI detail-pane reads task + its
        // comment thread in one subprocess hop. Schema:
        //   { "task": KanbanTask, "comments": [KanbanComment] }
        let body = serde_json::json!({
            "task": task,
            "comments": comments,
        });
        println!(
            "{}",
            serde_json::to_string(&body).context("serialise task+comments")?
        );
        return Ok(());
    }

    println!(
        "Task #{}  [{}]  ({})",
        task.task_id.raw(),
        task.task_type,
        task.status.as_str()
    );
    println!("  Title       : {}", task.title);
    if let Some(desc) = task.description.as_ref() {
        println!("  Description : {desc}");
    }
    println!("  Hemisphere  : {}", task.hemisphere.as_str());
    if let Some(w) = task.worker.as_ref() {
        println!("  Worker      : {w}");
    }
    if let Some(p) = task.parent_task_id {
        println!("  Parent      : #{}", p.raw());
    }
    println!("  Created     : {}", format_ts_short(task.created_ns));
    if let Some(s) = task.started_ns {
        println!("  Started     : {}", format_ts_short(s));
    }
    if let Some(c) = task.completed_ns {
        println!("  Completed   : {}", format_ts_short(c));
    }
    if let Some(eta) = task.eta_ns {
        println!("  ETA         : {eta} ns");
    }
    if let Some(p) = task.patch_path.as_ref() {
        println!("  Patch       : {}", p.display());
    }
    if let Some(ts) = task.test_summary.as_ref() {
        println!(
            "  Tests       : added={} passing={} failing={} skipped={}",
            ts.added, ts.passing, ts.failing, ts.skipped,
        );
    }
    println!();

    if comments.is_empty() {
        println!("(no comments yet)");
    } else {
        println!("Comments ({}):", comments.len());
        for c in &comments {
            println!(
                "  [{}] {}: {}",
                format_ts_short(c.created_ns),
                c.author,
                c.body,
            );
        }
    }
    Ok(())
}

fn run_move(conn: &Connection, task_id: KanbanTaskId, raw_status: &str) -> Result<()> {
    let status = TaskStatus::from_wire(raw_status).ok_or_else(|| {
        anyhow!(
            "unknown status {raw_status:?} — valid: backlog / todo / in_progress / \
             review / done / blocked / archived"
        )
    })?;
    let now_ns = now_unix_ns();
    store::patch_task_status(conn, task_id, status, now_ns)?;
    println!("task #{} → {}", task_id.raw(), status.as_str());
    Ok(())
}

fn run_assign(
    conn: &Connection,
    task_id: KanbanTaskId,
    raw_hemi: &str,
    worker: Option<&str>,
) -> Result<()> {
    let hemi = Hemisphere::from_wire(raw_hemi).ok_or_else(|| {
        anyhow!("unknown hemisphere {raw_hemi:?} — valid: left / right / cerebellum / unassigned")
    })?;
    store::patch_task_hemisphere(conn, task_id, hemi, worker, None)?;
    println!(
        "task #{} → hemisphere={} worker={}",
        task_id.raw(),
        hemi.as_str(),
        worker.unwrap_or("(none)"),
    );
    Ok(())
}

fn run_comment(conn: &Connection, task_id: KanbanTaskId, author: &str, body: &str) -> Result<()> {
    if body.trim().is_empty() {
        anyhow::bail!("comment body cannot be empty");
    }
    let now_ns = now_unix_ns();
    let id = store::insert_comment(conn, task_id, now_ns, author, body)?;
    println!("comment #{id} appended to task #{}", task_id.raw());
    Ok(())
}

fn run_archive(
    conn: &Connection,
    session_id: KanbanSessionId,
    raw_status: &str,
    summary: Option<&str>,
) -> Result<()> {
    let status = SessionStatus::from_wire(raw_status).ok_or_else(|| {
        anyhow!("unknown session status {raw_status:?} — valid: done / abandoned / review / running / planning")
    })?;
    if !status.is_terminal() {
        anyhow::bail!(
            "archive requires a terminal status (done or abandoned), got {}",
            status.as_str()
        );
    }
    store::archive_session(conn, session_id, status, summary, None)?;
    println!(
        "session #{} archived ({})",
        session_id.raw(),
        status.as_str()
    );
    Ok(())
}

/// Pick #10 review handler — check OR promote ONE task by id, OR
/// sweep every REVIEW task in a session via `--all`. Mutual
/// exclusion: `task_id` xor `--all` must be supplied.
fn run_review(
    conn: &Connection,
    task_id: Option<i64>,
    promote: bool,
    all: Option<i64>,
) -> Result<()> {
    use crate::coding::review::{ReviewBlocker, auto_promote_session, check_auto_promotable};

    if let Some(session_raw) = all {
        let session_id = KanbanSessionId(session_raw);
        if !promote {
            // Dry-run sweep: print per-task verdict without mutating.
            let tasks = store::list_tasks_for_session(conn, session_id)?;
            let mut promotable = 0usize;
            let mut blocked = 0usize;
            for t in &tasks {
                if t.status != TaskStatus::Review {
                    continue;
                }
                match check_auto_promotable(t) {
                    Ok(()) => {
                        println!("  #{:>4}  ✓ auto-promotable", t.task_id.raw());
                        promotable += 1;
                    }
                    Err(b) => {
                        println!("  #{:>4}  ✗ {}", t.task_id.raw(), b.as_str());
                        blocked += 1;
                    }
                }
            }
            println!();
            println!(
                "session #{}: {promotable} auto-promotable, {blocked} blocked",
                session_id.raw(),
            );
            return Ok(());
        }
        let now_ns = now_unix_ns();
        let promoted = auto_promote_session(conn, session_id, now_ns)?;
        println!(
            "session #{}: {promoted} task(s) promoted REVIEW → DONE",
            session_id.raw(),
        );
        return Ok(());
    }

    let task_id = task_id.ok_or_else(|| {
        anyhow!("neoth kanban review: provide either <task_id> or `--all <session_id>`")
    })?;
    let tid = KanbanTaskId(task_id);
    let task = select_one_task(conn, tid)?;

    match check_auto_promotable(&task) {
        Ok(()) => {
            if promote {
                let now_ns = now_unix_ns();
                store::patch_task_status(conn, tid, TaskStatus::Done, now_ns)?;
                println!("task #{task_id} promoted REVIEW → DONE");
            } else {
                println!("task #{task_id}: ✓ auto-promotable (run with --promote to apply)");
            }
        }
        Err(b) => {
            // NotInReview is an operator-input error: bail with exit
            // code instead of silently printing.
            if matches!(b, ReviewBlocker::NotInReview) {
                anyhow::bail!(
                    "task #{task_id} is not in REVIEW (status: {})",
                    task.status.as_str(),
                );
            }
            println!("task #{task_id}: ✗ blocked — {}", b.as_str());
        }
    }
    Ok(())
}

fn run_watch(wal_dir: &PathBuf, limit: usize, output: OutputFormat) -> Result<()> {
    let entries = scan_wal_dir_for_kanban_feed(wal_dir, limit)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Always emit a JSON array (possibly empty) so the GUI's
            // subprocess binding can parse the same shape whether or
            // not any kanban frame has landed yet.
            println!(
                "{}",
                serde_json::to_string(&entries).context("serialise feed entries")?
            );
            return Ok(());
        }
        OutputFormat::Table => {}
    }
    if entries.is_empty() {
        println!("(no kanban frames in {})", wal_dir.display());
        return Ok(());
    }
    for entry in &entries {
        println!("{}", entry.format());
    }
    Ok(())
}

// ── GUI warm-channel board assembly (B — persistent-stdio-stream) ───────────
//
// The `neoth gui-stream` subcommand (cli/gui_stream.rs) calls
// `assemble_gui_board` once per `board` request over a held-open
// connection, collapsing what the GUI previously did via FOUR cold
// subprocess spawns per 2s tick (`kanban list` → `kanban show` →
// `kanban watch` → `hemispheres show`) into one in-process query.

/// One task row in the GUI board snapshot. Field names + types mirror
/// the GUI's `CodingTaskJson` (`task_id` / `title` / `hemisphere` /
/// `status`) so the warm-channel payload deserialises into the same
/// board buckets the legacy subprocess path produced.
#[derive(Debug, serde::Serialize)]
pub(crate) struct GuiBoardTask {
    pub task_id: i64,
    pub title: String,
    pub hemisphere: String,
    pub status: String,
}

/// Full board snapshot returned for a `board` request. Read-only — no
/// mutation flows through the warm channel (mutations stay as the
/// existing gated `kanban move/review/...` subprocess calls, preserving
/// the CommandSource privilege ceiling from ADV-09/ADV-15).
#[derive(Debug, serde::Serialize)]
pub(crate) struct GuiBoardSnapshot {
    pub summary: String,
    pub cerebellum_bound: bool,
    pub tasks: Vec<GuiBoardTask>,
    pub feed: Vec<FeedEntry>,
}

/// Assemble the GUI board snapshot server-side against the warm
/// (held-open) `views.db` connection. Mirrors
/// `neothd-gui::fetch_kanban_board_snapshot` exactly: latest active
/// session (newest-first), its tasks, the WAL-derived activity feed,
/// and the cerebellum-bound bit — so the warm path is equivalent to
/// the legacy 4-subprocess path.
pub(crate) fn assemble_gui_board(
    conn: &Connection,
    wal_dir: &std::path::Path,
    cfg: &FreedomConfig,
) -> Result<GuiBoardSnapshot> {
    let cerebellum_bound = cerebellum_is_bound(cfg);
    // Latest active session — `select_sessions(.., false)` is
    // newest-first, so `.next()` mirrors the GUI's `.into_iter().next()`.
    let sessions = select_sessions(conn, false)?;
    let Some(latest) = sessions.into_iter().next() else {
        return Ok(GuiBoardSnapshot {
            summary: "No active session. Run `neoth code \"...\"` in your terminal, then refresh."
                .to_string(),
            cerebellum_bound,
            tasks: Vec::new(),
            feed: Vec::new(),
        });
    };
    let tasks = store::list_tasks_for_session(conn, latest.session_id)?
        .into_iter()
        .map(|t| GuiBoardTask {
            task_id: t.task_id.raw(),
            title: t.title,
            hemisphere: t.hemisphere.as_str().to_string(),
            status: t.status.as_str().to_string(),
        })
        .collect();
    // Feed is best-effort: a WAL-scan failure degrades to an empty feed
    // rather than failing the whole board (mirrors the GUI's behaviour).
    let feed = scan_wal_dir_for_kanban_feed(&wal_dir.to_path_buf(), 50).unwrap_or_default();
    Ok(GuiBoardSnapshot {
        summary: format!(
            "Session #{}  [{}]   {}",
            latest.session_id.raw(),
            latest.status.as_str(),
            latest.prompt,
        ),
        cerebellum_bound,
        tasks,
        feed,
    })
}

/// Cerebellum-bound determination, mirroring `neothd-gui`'s
/// `probe_cerebellum_bound` reading of `hemispheres show`: a single-mode
/// fallback (any `provider_kind`) binds every role; in per-role mode the
/// Cerebellum slot must carry a provider. Reports the real bit — the
/// fail-safe-to-true policy on probe failure is the GUI's concern.
fn cerebellum_is_bound(cfg: &FreedomConfig) -> bool {
    if cfg.provider_kind.is_some() {
        return true;
    }
    cfg.inference
        .slot_for(crate::config::inference::HemisphereRole::Cerebellum)
        .provider
        .is_some()
}

/// `--follow` live tail: print the backlog up to `limit`, then loop
/// re-scanning every `interval_ms` and printing entries strictly newer
/// than the last printed `ts_ns`. Exits cleanly on Ctrl+C. The pure
/// delta-filter logic lives in [`filter_new_entries`] so the loop is
/// thin + the filtering rule is unit-testable without spinning up
/// tokio or writing real WAL segments.
///
/// Output modes:
///   - `Table`: each new entry rendered with `FeedEntry::format`.
///   - `Json` / `Jsonl`: each new entry serialised as one JSON object
///     per line (true JSONL during tail — caller can pipe to `jq -c`
///     without buffering).
async fn run_watch_follow(
    wal_dir: &PathBuf,
    initial_limit: usize,
    interval_ms: u64,
    output: OutputFormat,
) -> Result<()> {
    use std::io::Write;
    use tokio::time::{Duration, sleep};

    // Floor the interval so a `--interval-ms 0` typo can't pin a CPU
    // to 100% spinning on the WAL directory. 100ms is well below any
    // operator-perceptible delay (kanban frames land at human-scale
    // cadence — a worker minute, not a disk-write microsecond).
    let interval = Duration::from_millis(interval_ms.max(100));

    // Initial backlog dump — same shape as one-shot so the operator
    // sees the session-so-far before the tail begins.
    let initial = scan_wal_dir_for_kanban_feed(wal_dir, initial_limit)?;
    let json_mode = matches!(output, OutputFormat::Json | OutputFormat::Jsonl);
    if initial.is_empty() {
        if !json_mode {
            // Table-mode hint so the operator knows the tail is live
            // even when no frames exist yet.
            println!("(no kanban frames in {} yet — waiting…)", wal_dir.display());
        }
    } else {
        for entry in &initial {
            print_feed_entry(entry, json_mode)?;
        }
    }
    let mut last_seen_ts_ns = initial.last().map(|e| e.ts_ns);
    // Always flush after the backlog dump so the operator's terminal
    // shows immediately — the tail loop below polls every interval so
    // unflushed stdout would otherwise wait the full interval.
    let _ = std::io::stdout().flush();

    // Race ctrl_c against the tail tick. On Windows ctrl_c() handles
    // CTRL_C_EVENT + CTRL_BREAK_EVENT; on Unix it handles SIGINT.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                // Quiet exit — no goodbye line in JSONL mode so the
                // downstream pipe sees a clean EOF without a trailing
                // non-JSON marker.
                if !json_mode {
                    println!();
                    println!("(tail stopped)");
                }
                return Ok(());
            }
            _ = sleep(interval) => {
                // Re-scan with a generous cap (10k) — we only print
                // the delta after filter_new_entries so the operator
                // never sees the backlog twice. Cap exists purely as
                // a panic-room ceiling for catastrophic WAL growth
                // mid-tail.
                let scanned = scan_wal_dir_for_kanban_feed(wal_dir, 10_000)?;
                let deltas = filter_new_entries(scanned, last_seen_ts_ns);
                if let Some(latest) = deltas.last() {
                    last_seen_ts_ns = Some(latest.ts_ns);
                }
                for entry in &deltas {
                    print_feed_entry(entry, json_mode)?;
                }
                if !deltas.is_empty() {
                    let _ = std::io::stdout().flush();
                }
            }
        }
    }
}

/// Pure delta-filter. `entries` is the full re-scan result sorted by
/// `ts_ns` ascending (per `scan_wal_dir_for_kanban_feed`'s contract).
/// Returns every entry strictly newer than `last_seen_ts_ns`, in the
/// same order. When `last_seen_ts_ns` is `None` (cursor not yet set —
/// first scan returned empty), every entry counts as new.
///
/// Ties on identical `ts_ns` are intentionally treated as "already
/// seen" rather than re-printed. The WAL writer's HLC component is
/// monotonic so identical-ns collisions only happen across processes;
/// inside one process the per-tick delta is unambiguous.
fn filter_new_entries(entries: Vec<FeedEntry>, last_seen_ts_ns: Option<u64>) -> Vec<FeedEntry> {
    match last_seen_ts_ns {
        None => entries,
        Some(cursor) => entries.into_iter().filter(|e| e.ts_ns > cursor).collect(),
    }
}

/// Render one feed entry per the active output mode. Extracted so the
/// initial backlog dump + the per-tick delta print share one rule.
fn print_feed_entry(entry: &FeedEntry, json_mode: bool) -> Result<()> {
    if json_mode {
        // One JSON per line — true JSONL during tail so downstream
        // pipes (`jq -c`, log forwarders, etc.) get a record-per-line
        // contract instead of one giant array that never closes.
        println!(
            "{}",
            serde_json::to_string(entry).context("serialise feed entry")?
        );
    } else {
        println!("{}", entry.format());
    }
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Select sessions newest-first. When `include_all` is false, archived
/// sessions are hidden so `neoth kanban list` shows only what's still
/// actionable.
fn select_sessions(conn: &Connection, include_all: bool) -> Result<Vec<KanbanSession>> {
    let mut stmt = conn
        .prepare(
            "SELECT session_id, created_ns, prompt, prompt_hash, source_channel, \
                    operator_id, status, artifact_path, summary \
             FROM idx_kanban_session ORDER BY created_ns DESC",
        )
        .context("prepare select_sessions")?;
    let rows = stmt
        .query_map([], |row| {
            let raw_status: String = row.get(6)?;
            let status = SessionStatus::from_wire(&raw_status).unwrap_or(SessionStatus::Abandoned);
            let artifact_path: Option<String> = row.get(7)?;
            Ok(KanbanSession {
                session_id: KanbanSessionId(row.get(0)?),
                created_ns: row.get::<_, i64>(1)? as u64,
                prompt: row.get(2)?,
                prompt_hash: row.get(3)?,
                source_channel: row.get(4)?,
                operator_id: row.get(5)?,
                status,
                artifact_path: artifact_path.map(PathBuf::from),
                summary: row.get(8)?,
            })
        })
        .context("query select_sessions")?;
    let all: Vec<KanbanSession> = rows.collect::<rusqlite::Result<_>>()?;
    if include_all {
        Ok(all)
    } else {
        Ok(all
            .into_iter()
            .filter(|s| !s.status.is_terminal())
            .collect())
    }
}

/// Single-row fetch. Returned for the `task` subcommand. Errors when
/// the id is missing so the operator gets a clear "task #N not found"
/// instead of an empty stdout.
fn select_one_task(conn: &Connection, task_id: KanbanTaskId) -> Result<KanbanTask> {
    let mut stmt = conn
        .prepare(
            "SELECT task_id, session_id, status, title, description, task_type, \
                    hemisphere, worker, parent_task_id, created_ns, started_ns, \
                    eta_ns, completed_ns, patch_path, test_summary \
             FROM idx_kanban_task WHERE task_id = ?1",
        )
        .context("prepare select_one_task")?;
    let mut rows = stmt
        .query_map([task_id.raw()], decode_task_row)
        .context("query select_one_task")?;
    match rows.next() {
        Some(Ok(t)) => Ok(t),
        Some(Err(e)) => Err(e.into()),
        None => Err(anyhow!("task #{} not found", task_id.raw())),
    }
}

fn decode_task_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KanbanTask> {
    let raw_status: String = row.get(2)?;
    let raw_hemi: String = row.get(6)?;
    let test_summary_json: Option<String> = row.get(14)?;
    Ok(KanbanTask {
        task_id: KanbanTaskId(row.get(0)?),
        session_id: KanbanSessionId(row.get(1)?),
        status: TaskStatus::from_wire(&raw_status).unwrap_or(TaskStatus::Blocked),
        title: row.get(3)?,
        description: row.get(4)?,
        task_type: row.get(5)?,
        hemisphere: Hemisphere::from_wire(&raw_hemi).unwrap_or(Hemisphere::Unassigned),
        worker: row.get(7)?,
        parent_task_id: row.get::<_, Option<i64>>(8)?.map(KanbanTaskId),
        created_ns: row.get::<_, i64>(9)? as u64,
        started_ns: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
        eta_ns: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
        completed_ns: row.get::<_, Option<i64>>(12)?.map(|v| v as u64),
        patch_path: row.get::<_, Option<String>>(13)?.map(PathBuf::from),
        test_summary: test_summary_json.and_then(|s| serde_json::from_str(&s).ok()),
    })
}

/// Render a kanban-style ASCII board grouping tasks by status. Pure
/// formatter — easier to unit test than the full session view. The
/// columns match the Twitter image: BACKLOG / TODO / IN_PROGRESS /
/// REVIEW / DONE. Blocked + Archived go to a tail line because the
/// image doesn't show them as primary columns.
fn print_kanban_board(tasks: &[KanbanTask]) {
    let columns: [(&str, TaskStatus); 5] = [
        ("BACKLOG", TaskStatus::Backlog),
        ("TODO", TaskStatus::Todo),
        ("IN_PROGRESS", TaskStatus::InProgress),
        ("REVIEW", TaskStatus::Review),
        ("DONE", TaskStatus::Done),
    ];
    for (label, status) in &columns {
        let in_col: Vec<&KanbanTask> = tasks.iter().filter(|t| t.status == *status).collect();
        if in_col.is_empty() {
            continue;
        }
        println!("## {label}");
        for t in &in_col {
            let worker = t.worker.as_deref().unwrap_or("-");
            println!(
                "  #{:>4}  [{:>8}]  {:<11}  {:<14}  {}",
                t.task_id.raw(),
                t.task_type,
                t.hemisphere.as_str(),
                worker,
                t.title,
            );
        }
        println!();
    }
    // Blocked + Archived footer line for visibility without inflating
    // the main board.
    let extras: Vec<&KanbanTask> = tasks
        .iter()
        .filter(|t| matches!(t.status, TaskStatus::Blocked | TaskStatus::Archived))
        .collect();
    if !extras.is_empty() {
        println!("## Other states");
        for t in &extras {
            println!(
                "  #{:>4}  [{:>8}]  ({})  {}",
                t.task_id.raw(),
                t.task_type,
                t.status.as_str(),
                t.title,
            );
        }
    }
}

/// Walk every `.wal` file in `wal_dir`, decode frames, filter to
/// kanban event codes, parse payloads into `FeedEntry`. Returns the
/// last `limit` entries sorted by `ts_ns` ascending so the operator
/// sees the freshest at the bottom (matches `tail` muscle memory).
fn scan_wal_dir_for_kanban_feed(wal_dir: &PathBuf, limit: usize) -> Result<Vec<FeedEntry>> {
    if !wal_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<FeedEntry> = Vec::new();
    let read_dir =
        std::fs::read_dir(wal_dir).with_context(|| format!("read_dir {}", wal_dir.display()))?;
    let mut segments: Vec<PathBuf> = read_dir
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x == "wal")
        })
        .map(|e| e.path())
        .collect();
    segments.sort();
    for seg in &segments {
        if let Ok(bytes) = std::fs::read(seg) {
            scan_segment_bytes(&bytes, &mut entries);
        }
    }
    entries.sort_by_key(|e| e.ts_ns);
    let total = entries.len();
    if total > limit {
        entries.drain(0..total - limit);
    }
    Ok(entries)
}

/// Walk one segment's frame stream, appending any kanban entries to
/// `out`. Bad frames are skipped silently — operators use `neoth wal
/// stats <seg>` to surface corruption, the kanban feed prioritises
/// readability.
fn scan_segment_bytes(bytes: &[u8], out: &mut Vec<FeedEntry>) {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return;
    }
    let mut cursor = SEGMENT_HEADER_LEN;
    while cursor < bytes.len() {
        match decode_frame(&bytes[cursor..]) {
            Ok(dec) => {
                let total = dec.header.total_len as usize;
                if total == 0 {
                    break;
                }
                if is_kanban_event(dec.header.event_type) {
                    let ts = dec.header.hlc.physical_ns();
                    if let Some(entry) =
                        parse_kanban_payload(dec.header.event_type, ts, dec.payload)
                    {
                        out.push(entry);
                    }
                }
                cursor += total;
            }
            Err(_) => break,
        }
    }
}

fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// HH:MM:SS UTC — same format the feed parser uses for its lines, so
/// the operator sees consistent timestamps across `list`/`show`/`watch`.
fn format_ts_short(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = memstore::open(&path).expect("open views.db");
        store::ensure_schema(&conn).expect("ensure schema");
        (dir, conn)
    }

    #[test]
    fn list_includes_only_active_by_default() {
        let (_dir, conn) = fresh_db();
        // Two sessions: one active, one done.
        let s_active = store::insert_session(&conn, 1, "active prompt", "h1", "cli", None).unwrap();
        let s_done = store::insert_session(&conn, 2, "done prompt", "h2", "cli", None).unwrap();
        store::archive_session(&conn, s_done, SessionStatus::Done, None, None).unwrap();

        let visible = select_sessions(&conn, false).unwrap();
        let active_only: Vec<i64> = visible.iter().map(|s| s.session_id.raw()).collect();
        assert!(active_only.contains(&s_active.raw()));
        assert!(
            !active_only.contains(&s_done.raw()),
            "done session must be hidden when --all is not set"
        );

        let all = select_sessions(&conn, true).unwrap();
        let all_ids: Vec<i64> = all.iter().map(|s| s.session_id.raw()).collect();
        assert!(
            all_ids.contains(&s_done.raw()),
            "--all must surface archived"
        );
    }

    #[test]
    fn move_changes_status_and_stamps_started_ns() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        run_move(&conn, t, "in_progress").expect("move ok");
        let task = select_one_task(&conn, t).unwrap();
        assert_eq!(task.status, TaskStatus::InProgress);
        assert!(task.started_ns.is_some());
    }

    #[test]
    fn move_rejects_unknown_status() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        let err = run_move(&conn, t, "ready").unwrap_err();
        assert!(err.to_string().contains("unknown status"), "got {err}");
    }

    #[test]
    fn assign_sets_hemisphere_and_worker() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        run_assign(&conn, t, "left", Some("local_qwen")).expect("assign ok");
        let task = select_one_task(&conn, t).unwrap();
        assert_eq!(task.hemisphere, Hemisphere::Left);
        assert_eq!(task.worker.as_deref(), Some("local_qwen"));
    }

    #[test]
    fn assign_rejects_unknown_hemisphere() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        let err = run_assign(&conn, t, "middle", None).unwrap_err();
        assert!(err.to_string().contains("unknown hemisphere"));
    }

    #[test]
    fn comment_rejects_empty_body() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        let err = run_comment(&conn, t, "operator", "   \n\t  ").unwrap_err();
        assert!(err.to_string().contains("empty"));

        // Real body succeeds + appends.
        run_comment(&conn, t, "operator", "looks good").expect("comment ok");
        let comments = store::list_comments_for_task(&conn, t).unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].body, "looks good");
    }

    #[test]
    fn archive_rejects_non_terminal_status() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();

        let err = run_archive(&conn, s, "planning", None).unwrap_err();
        assert!(
            err.to_string().contains("terminal"),
            "non-terminal archive must error: {err}"
        );
    }

    #[test]
    fn archive_accepts_terminal_and_writes_summary() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        run_archive(&conn, s, "done", Some("All clean")).expect("archive");
        let fetched = store::get_session(&conn, s).unwrap().unwrap();
        assert_eq!(fetched.status, SessionStatus::Done);
        assert_eq!(fetched.summary.as_deref(), Some("All clean"));
    }

    #[test]
    fn watch_returns_empty_when_no_segments_present() {
        // Empty directory → no feed entries, no error.
        let dir = tempdir().unwrap();
        let entries = scan_wal_dir_for_kanban_feed(&dir.path().to_path_buf(), 100).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn watch_returns_empty_when_dir_missing() {
        // Non-existent directory must NOT error (operator might run
        // watch before any session has been opened).
        let missing = std::env::temp_dir().join(format!(
            "neoth-kanban-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let entries = scan_wal_dir_for_kanban_feed(&missing, 100).unwrap();
        assert!(entries.is_empty());
    }

    fn entry_at(ts_ns: u64) -> FeedEntry {
        FeedEntry {
            ts_ns,
            event_type: 0x70,
            actor: "left".into(),
            message: format!("entry at {ts_ns}"),
        }
    }

    #[test]
    fn filter_new_entries_returns_all_when_cursor_unset() {
        // No prior cursor → every entry counts as new (first scan
        // returned empty → cursor is None → tail dumps initial batch).
        let entries = vec![entry_at(100), entry_at(200), entry_at(300)];
        let out = filter_new_entries(entries.clone(), None);
        assert_eq!(out.len(), 3);
        assert_eq!(out, entries);
    }

    #[test]
    fn filter_new_entries_drops_entries_at_or_before_cursor() {
        // Cursor at 200 → entry at 100 + 200 are not new; 300 is.
        let entries = vec![entry_at(100), entry_at(200), entry_at(300)];
        let out = filter_new_entries(entries, Some(200));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ts_ns, 300);
    }

    #[test]
    fn filter_new_entries_returns_empty_when_no_new_frames() {
        // Cursor caught up to the latest entry → next tick has nothing
        // to print.
        let entries = vec![entry_at(100), entry_at(200), entry_at(300)];
        let out = filter_new_entries(entries, Some(300));
        assert!(out.is_empty());
    }

    #[test]
    fn filter_new_entries_preserves_input_ordering() {
        // Pure filter must NOT reorder — caller relies on
        // scan_wal_dir_for_kanban_feed's ts-asc contract.
        let entries = vec![entry_at(10), entry_at(20), entry_at(30), entry_at(40)];
        let out = filter_new_entries(entries, Some(15));
        let timestamps: Vec<u64> = out.iter().map(|e| e.ts_ns).collect();
        assert_eq!(timestamps, vec![20, 30, 40]);
    }

    #[test]
    fn filter_new_entries_handles_empty_input() {
        // Empty re-scan with a live cursor → empty delta, no panic.
        let out = filter_new_entries(Vec::new(), Some(500));
        assert!(out.is_empty());
    }

    #[test]
    fn task_detail_errors_on_missing_id() {
        let (_dir, conn) = fresh_db();
        let err = select_one_task(&conn, KanbanTaskId(404)).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn list_json_output_emits_serializable_array() {
        // GUI's subprocess binding parses this — pin that the wire form
        // round-trips through serde so a field rename surfaces here, not
        // in the operator's settings panel.
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "prompt", "hash", "cli", Some("demo-user")).unwrap();
        store::insert_task(&conn, s, 10, "Task title", None, "ui", None).unwrap();

        let sessions = select_sessions(&conn, false).unwrap();
        let json = serde_json::to_string(&sessions).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.is_array(), "list output must be a JSON array");
        let entry = &parsed.as_array().unwrap()[0];
        assert_eq!(entry["prompt"], "prompt");
        assert_eq!(entry["source_channel"], "cli");
    }

    #[test]
    fn show_json_envelope_contains_session_and_tasks() {
        // Pin the `{session, tasks}` envelope — the Slint binding keys
        // off these two field names. A drift here breaks the GUI silently
        // because Slint just sees an empty model.
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "build a thing", "hash", "cli", None).unwrap();
        store::insert_task(&conn, s, 10, "Task A", None, "ui", None).unwrap();
        store::insert_task(&conn, s, 11, "Task B", None, "test", None).unwrap();

        let session = store::get_session(&conn, s).unwrap().unwrap();
        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let envelope = serde_json::json!({ "session": session, "tasks": tasks });
        let body = serde_json::to_string(&envelope).expect("serialise envelope");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        assert!(parsed["session"].is_object());
        assert_eq!(parsed["session"]["prompt"], "build a thing");
        assert!(parsed["tasks"].is_array());
        assert_eq!(parsed["tasks"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["tasks"][0]["title"], "Task A");
    }

    #[test]
    fn task_detail_json_envelope_contains_task_and_comments() {
        // GUI detail-pane reads `{task, comments}` in one subprocess
        // hop. Pin the wire form so a serde rename surfaces here,
        // not in the operator's UI.
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "Sample", Some("desc"), "ui", None).unwrap();
        store::insert_comment(&conn, t, 20, "operator", "looks good").unwrap();
        store::insert_comment(&conn, t, 30, "left", "test added").unwrap();

        let task = select_one_task(&conn, t).unwrap();
        let comments = store::list_comments_for_task(&conn, t).unwrap();
        let envelope = serde_json::json!({"task": task, "comments": comments});
        let body = serde_json::to_string(&envelope).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        assert!(parsed["task"].is_object());
        assert_eq!(parsed["task"]["title"], "Sample");
        assert_eq!(parsed["task"]["description"], "desc");
        assert!(parsed["comments"].is_array());
        assert_eq!(parsed["comments"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["comments"][0]["author"], "operator");
        assert_eq!(parsed["comments"][1]["body"], "test added");
    }

    #[test]
    fn watch_json_output_serialises_feed_entries() {
        // GUI's right-rail subprocess binding parses this — pin the
        // wire format. FeedEntry must round-trip ts_ns + event_type
        // + actor + message as a flat JSON object so a Slint Model
        // can read the four fields without nested traversal.
        let entry = FeedEntry {
            ts_ns: 86_400_000_000_000, // 1970-01-02T00:00:00Z
            event_type: 0x73,
            actor: "left".to_string(),
            message: "Patch generated for toggle component".to_string(),
        };
        let json = serde_json::to_string(&[entry]).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.is_array(), "watch output must be a JSON array");
        let row = &parsed.as_array().unwrap()[0];
        assert_eq!(row["ts_ns"], 86_400_000_000_000u64);
        assert_eq!(row["event_type"], 0x73);
        assert_eq!(row["actor"], "left");
        assert_eq!(row["message"], "Patch generated for toggle component");
    }

    #[test]
    fn format_ts_short_uses_hms_columns() {
        assert_eq!(format_ts_short(0), "00:00:00");
        let twelve_thirty_four_56 = 12 * 3600 + 34 * 60 + 56;
        assert_eq!(
            format_ts_short(twelve_thirty_four_56 * 1_000_000_000),
            "12:34:56"
        );
    }
}
