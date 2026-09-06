//! Sqlite schema + CRUD for the kanban coding workflow.
//!
//! Pick #1 (2026-05-19) shipped `ensure_schema`. Pick #2 (this file)
//! adds the session/task/comment CRUD surface so the decomposer +
//! dispatcher (Picks #4-6) have a working store to write into.
//!
//! Every mutating function is **parameterized** — operator prompt
//! bodies + worker output land in TEXT columns via `params![...]`, never
//! via `format!`. Per `rules/rust/security.md` SQL Injection
//! Prevention.
//!
//! Lifecycle invariants the API enforces (not just SQL constraints):
//! - `patch_task_status(InProgress)` stamps `started_ns` if NULL.
//! - `patch_task_status(Done)` stamps `completed_ns` if NULL.
//! - `attach_task_artifact` is callable any time but typically pairs
//!   with `patch_task_status(Review)` or `(Done)`.
//! - `archive_session` writes summary + status='done'/'abandoned' but
//!   does NOT cascade-archive tasks — the orchestrator decides whether
//!   in-progress work moves to `Archived` or `Done` first.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::broadcast;

use super::CodingCodeMapReceipt;
use super::types::{
    Hemisphere, KanbanComment, KanbanSession, KanbanSessionId, KanbanTask, KanbanTaskId,
    SessionStatus, TaskDep, TaskEvent, TaskStatus, TestSummary,
};
use crate::coding::feed::FeedEntry;

const CODE_MAP_RECEIPT_STORAGE_SCHEMA: &str = "neoth.coding.code_map_receipt_storage.v1";

/// On-disk receipt form. Sources occur once in `first`; a repair differs only
/// in its attempt number and provider-prompt commitment, so duplicating the
/// full provenance would waste most of the bounded session column.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCodeMapReceiptHistory {
    schema: String,
    first: CodingCodeMapReceipt,
    repair: Option<CompactRepairCodeMapReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactRepairCodeMapReceipt {
    attempt: u8,
    provider_prompt_sha256: String,
}

impl PersistedCodeMapReceiptHistory {
    fn first(receipt: CodingCodeMapReceipt) -> Self {
        Self {
            schema: CODE_MAP_RECEIPT_STORAGE_SCHEMA.to_owned(),
            first: receipt,
            repair: None,
        }
    }

    fn receipts(&self) -> Result<Vec<CodingCodeMapReceipt>> {
        self.validate()?;
        let mut receipts = vec![self.first.clone()];
        if let Some(repair) = &self.repair {
            let mut reconstructed = self.first.clone();
            reconstructed.attempt = repair.attempt;
            reconstructed.provider_prompt_sha256 = repair.provider_prompt_sha256.clone();
            reconstructed
                .validate()
                .context("validate reconstructed repair receipt")?;
            ensure_repair_basis_matches(&self.first, &reconstructed)?;
            receipts.push(reconstructed);
        }
        Ok(receipts)
    }

    fn append_repair(&mut self, repair: &CodingCodeMapReceipt) -> Result<()> {
        anyhow::ensure!(
            self.repair.is_none(),
            "code-map receipt history already has its repair attempt"
        );
        ensure_repair_basis_matches(&self.first, repair)?;
        anyhow::ensure!(
            repair.attempt == 2,
            "second code-map receipt must be attempt two"
        );
        self.repair = Some(CompactRepairCodeMapReceipt {
            attempt: repair.attempt,
            provider_prompt_sha256: repair.provider_prompt_sha256.clone(),
        });
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema == CODE_MAP_RECEIPT_STORAGE_SCHEMA,
            "unsupported code-map receipt storage schema"
        );
        self.first
            .validate()
            .context("validate first stored code-map receipt")?;
        anyhow::ensure!(
            self.first.attempt == 1,
            "stored first code-map receipt must be attempt one"
        );
        if let Some(repair) = &self.repair {
            anyhow::ensure!(
                repair.attempt == 2,
                "stored compact repair must be attempt two"
            );
            anyhow::ensure!(
                is_lowercase_sha256(&repair.provider_prompt_sha256),
                "stored compact repair provider-prompt digest is not lowercase SHA-256"
            );
        }
        Ok(())
    }
}

/// Create (if missing) the three coding-workflow tables in `views.db`:
/// `idx_kanban_session`, `idx_kanban_task`, `idx_kanban_comment`.
///
/// Idempotent — the daemon calls this at startup. `CREATE TABLE IF NOT
/// EXISTS` so a daemon upgraded mid-flight does not refuse to start
/// when the tables already exist.
///
/// Indexes are co-created so the dispatcher's lookups (status filter,
/// session-scoped task list) stay index-backed from frame one.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_SQL)
        .context("create idx_kanban_* tables in views.db")?;
    ensure_code_map_receipts_column(conn)?;
    Ok(())
}

/// Upgrade installations created before code-map receipt persistence. The
/// receipt array belongs to its session, so deleting a session automatically
/// erases its receipt history and archival cannot orphan it.
fn ensure_code_map_receipts_column(conn: &Connection) -> Result<()> {
    if has_code_map_receipts_column(conn)? {
        return Ok(());
    }

    // SQLite has no `ADD COLUMN IF NOT EXISTS`. A concurrent startup can win
    // the small check/alter race; re-read the schema and only accept that exact
    // already-applied migration, never an arbitrary ALTER failure.
    match conn.execute(
        "ALTER TABLE idx_kanban_session ADD COLUMN code_map_receipts TEXT",
        [],
    ) {
        Ok(_) => Ok(()),
        Err(_error) if has_code_map_receipts_column(conn)? => Ok(()),
        Err(error) => Err(error).context("add idx_kanban_session.code_map_receipts"),
    }
}

fn has_code_map_receipts_column(conn: &Connection) -> Result<bool> {
    let mut columns = conn
        .prepare("PRAGMA table_info(idx_kanban_session)")
        .context("inspect idx_kanban_session columns")?;
    columns
        .query_map([], |row| row.get::<_, String>(1))
        .context("query idx_kanban_session columns")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect idx_kanban_session columns")
        .map(|columns| columns.iter().any(|name| name == "code_map_receipts"))
}

/// Persist an immutable first/repair pair of code-map receipts on a session.
///
/// Attempt one is the only legal first write. Attempt two is the only legal
/// continuation and must use the exact same original selection and submitted
/// context basis as attempt one; only its provider-prompt commitment differs.
/// The compare-and-swap update protects that rule even if another connection
/// writes the row after our read.
pub fn record_code_map_receipt(
    conn: &Connection,
    session_id: KanbanSessionId,
    receipt: &CodingCodeMapReceipt,
) -> Result<()> {
    receipt
        .validate()
        .context("validate incoming code-map receipt")?;
    anyhow::ensure!(
        receipt.session_id == session_id.raw(),
        "code-map receipt session_id does not match target session"
    );

    let tx = conn
        .unchecked_transaction()
        .context("begin code-map receipt transaction")?;
    let prior = read_bounded_code_map_receipt_column(&tx, session_id, "load existing")?;

    let persisted = match prior.as_deref() {
        None => {
            validate_next_code_map_receipt(&[], receipt)?;
            PersistedCodeMapReceiptHistory::first(receipt.clone())
        }
        Some(raw) => {
            let mut persisted = decode_code_map_receipt_history(raw, session_id)?;
            let receipts = persisted.receipts()?;
            validate_next_code_map_receipt(&receipts, receipt)?;
            persisted.append_repair(receipt)?;
            persisted
        }
    };
    persisted.validate()?;
    let receipts = persisted.receipts()?;
    let encoded =
        serde_json::to_string(&persisted).context("serialize code-map receipt history")?;
    anyhow::ensure!(
        encoded.len() <= super::code_map_receipt::MAX_CODE_MAP_RECEIPT_BYTES,
        "serialized code-map receipt array exceeds persistence bound"
    );

    let changed = match prior.as_deref() {
        None => tx.execute(
            "UPDATE idx_kanban_session SET code_map_receipts = ?1 \
             WHERE session_id = ?2 AND code_map_receipts IS NULL",
            params![encoded, session_id.raw()],
        ),
        Some(raw) => tx.execute(
            "UPDATE idx_kanban_session SET code_map_receipts = ?1 \
             WHERE session_id = ?2 AND code_map_receipts = ?3",
            params![encoded, session_id.raw(), raw],
        ),
    }
    .context("compare-and-swap code-map receipt array")?;
    anyhow::ensure!(
        changed == 1,
        "code-map receipt write lost compare-and-swap race"
    );

    let readback = read_bounded_code_map_receipt_column(&tx, session_id, "read back")?
        .ok_or_else(|| anyhow::anyhow!("code-map receipt readback unexpectedly became NULL"))?;
    anyhow::ensure!(readback == encoded, "code-map receipt readback mismatch");
    let decoded = decode_code_map_receipt_history(&readback, session_id)?.receipts()?;
    anyhow::ensure!(
        decoded == receipts,
        "code-map receipt decoded readback mismatch"
    );
    tx.commit().context("commit code-map receipt transaction")?;
    Ok(())
}

/// Load the complete immutable receipt history for an existing session.
/// Corrupt JSON and semantically invalid records are explicit errors; callers
/// never receive an empty list as a fallback for corrupted persisted state.
pub fn load_code_map_receipts(
    conn: &Connection,
    session_id: KanbanSessionId,
) -> Result<Vec<CodingCodeMapReceipt>> {
    let stored = read_bounded_code_map_receipt_column(conn, session_id, "load")?;
    match stored {
        None => Ok(Vec::new()),
        Some(raw) => decode_code_map_receipt_history(&raw, session_id)?.receipts(),
    }
}

/// Read the receipt column without letting rusqlite eagerly materialize an
/// arbitrary SQLite value into a Rust `String`. SQLite can store a BLOB in a
/// TEXT-affinity column, and a corrupt database can hold an arbitrarily large
/// value; both are rejected while still borrowed from SQLite.
fn read_bounded_code_map_receipt_column(
    conn: &Connection,
    session_id: KanbanSessionId,
    operation: &str,
) -> Result<Option<String>> {
    let mut statement = conn
        .prepare("SELECT code_map_receipts FROM idx_kanban_session WHERE session_id = ?1")
        .with_context(|| format!("{operation} code-map receipt column"))?;
    let mut rows = statement
        .query(params![session_id.raw()])
        .with_context(|| format!("{operation} code-map receipt query"))?;
    let row = rows
        .next()
        .with_context(|| format!("{operation} code-map receipt row"))?;
    let row = row.ok_or_else(|| {
        anyhow::anyhow!(
            "{}: no row for session_id={}",
            if operation == "load" {
                "load_code_map_receipts"
            } else {
                "record_code_map_receipt"
            },
            session_id.raw()
        )
    })?;
    match row
        .get_ref(0)
        .with_context(|| format!("{operation} code-map receipt value"))?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => {
            anyhow::ensure!(
                !bytes.is_empty()
                    && bytes.len() <= super::code_map_receipt::MAX_CODE_MAP_RECEIPT_BYTES,
                "stored code-map receipt array has invalid byte length"
            );
            let value = std::str::from_utf8(bytes)
                .context("stored code-map receipt text is not valid UTF-8")?;
            Ok(Some(value.to_owned()))
        }
        _ => anyhow::bail!("stored code-map receipt column must be TEXT or NULL"),
    }
}

fn decode_code_map_receipt_history(
    raw: &str,
    session_id: KanbanSessionId,
) -> Result<PersistedCodeMapReceiptHistory> {
    anyhow::ensure!(
        !raw.is_empty() && raw.len() <= super::code_map_receipt::MAX_CODE_MAP_RECEIPT_BYTES,
        "stored code-map receipt array has invalid byte length"
    );
    let history: PersistedCodeMapReceiptHistory =
        serde_json::from_str(raw).context("decode stored code-map receipt history")?;
    history.validate()?;
    anyhow::ensure!(
        history.first.session_id == session_id.raw(),
        "stored code-map receipt belongs to another session"
    );
    Ok(history)
}

fn validate_next_code_map_receipt(
    prior: &[CodingCodeMapReceipt],
    next: &CodingCodeMapReceipt,
) -> Result<()> {
    match prior {
        [] => anyhow::ensure!(
            next.attempt == 1,
            "first code-map receipt must be attempt one"
        ),
        [first] => {
            anyhow::ensure!(
                next.attempt == 2,
                "second code-map receipt must be attempt two"
            );
            ensure_repair_basis_matches(first, next)?;
        }
        _ => anyhow::bail!("code-map receipt history already has its repair attempt"),
    }
    Ok(())
}

fn ensure_repair_basis_matches(
    first: &CodingCodeMapReceipt,
    repair: &CodingCodeMapReceipt,
) -> Result<()> {
    anyhow::ensure!(
        first.session_id == repair.session_id
            && first.operator_prompt_sha256 == repair.operator_prompt_sha256
            && first.assembled_context_sha256 == repair.assembled_context_sha256
            && first.submitted_context_sha256 == repair.submitted_context_sha256
            && first.submitted_context_bytes == repair.submitted_context_bytes
            && first.context_truncated == repair.context_truncated
            && first.sources == repair.sources,
        "repair code-map receipt changed its original context basis"
    );
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

/// Schema-DDL string. Held as a `pub(crate)` constant so tests can
/// build in-memory fixtures with the same definition.
pub(crate) const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS idx_kanban_session (
    session_id     INTEGER PRIMARY KEY,
    created_ns     INTEGER NOT NULL,
    prompt         TEXT NOT NULL,
    prompt_hash    TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    operator_id    TEXT,
    status         TEXT NOT NULL,
    artifact_path  TEXT,
    summary        TEXT,
    code_map_receipts TEXT
);
CREATE INDEX IF NOT EXISTS idx_kanban_session_created
    ON idx_kanban_session (created_ns DESC);
CREATE INDEX IF NOT EXISTS idx_kanban_session_status
    ON idx_kanban_session (status);

CREATE TABLE IF NOT EXISTS idx_kanban_task (
    task_id        INTEGER PRIMARY KEY,
    session_id     INTEGER NOT NULL REFERENCES idx_kanban_session(session_id),
    status         TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT,
    task_type      TEXT NOT NULL,
    hemisphere     TEXT NOT NULL DEFAULT 'unassigned',
    worker         TEXT,
    parent_task_id INTEGER REFERENCES idx_kanban_task(task_id),
    created_ns     INTEGER NOT NULL,
    started_ns     INTEGER,
    eta_ns         INTEGER,
    completed_ns   INTEGER,
    patch_path     TEXT,
    test_summary   TEXT
);
CREATE INDEX IF NOT EXISTS idx_kanban_task_session
    ON idx_kanban_task (session_id);
CREATE INDEX IF NOT EXISTS idx_kanban_task_status
    ON idx_kanban_task (status);
CREATE INDEX IF NOT EXISTS idx_kanban_task_hemisphere
    ON idx_kanban_task (hemisphere);

CREATE TABLE IF NOT EXISTS idx_kanban_comment (
    comment_id   INTEGER PRIMARY KEY,
    task_id      INTEGER NOT NULL REFERENCES idx_kanban_task(task_id),
    author       TEXT NOT NULL,
    body         TEXT NOT NULL,
    created_ns   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kanban_comment_task
    ON idx_kanban_comment (task_id, created_ns ASC);

CREATE TABLE IF NOT EXISTS idx_kanban_task_event (
    event_id     INTEGER PRIMARY KEY,
    task_id      INTEGER NOT NULL REFERENCES idx_kanban_task(task_id),
    event_type   INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    created_ns   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kanban_task_event_task
    ON idx_kanban_task_event (task_id, created_ns ASC);
CREATE INDEX IF NOT EXISTS idx_kanban_task_event_created
    ON idx_kanban_task_event (created_ns ASC);

CREATE TABLE IF NOT EXISTS idx_kanban_task_dep (
    dep_id              INTEGER PRIMARY KEY,
    task_id             INTEGER NOT NULL,
    depends_on_task_id  INTEGER NOT NULL,
    created_ns          INTEGER NOT NULL,
    UNIQUE(task_id, depends_on_task_id) ON CONFLICT IGNORE
);
CREATE INDEX IF NOT EXISTS idx_kanban_task_dep_task
    ON idx_kanban_task_dep (task_id);
";

// ── Session CRUD ───────────────────────────────────────────────────────────

/// Open a new coding session for an operator prompt. Returns the
/// `session_id` assigned by sqlite's rowid mechanism. Initial status
/// is `Planning` — the decomposer flips to `Running` after at least
/// one task lands.
pub fn insert_session(
    conn: &Connection,
    created_ns: u64,
    prompt: &str,
    prompt_hash: &str,
    source_channel: &str,
    operator_id: Option<&str>,
) -> Result<KanbanSessionId> {
    conn.execute(
        "INSERT INTO idx_kanban_session \
         (created_ns, prompt, prompt_hash, source_channel, operator_id, status) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            created_ns as i64,
            prompt,
            prompt_hash,
            source_channel,
            operator_id,
            SessionStatus::Planning.as_str(),
        ],
    )
    .context("insert idx_kanban_session row")?;
    Ok(KanbanSessionId(conn.last_insert_rowid()))
}

/// Fetch one session by id. Returns `Ok(None)` for unknown ids — the
/// caller decides whether absence is an error.
pub fn get_session(
    conn: &Connection,
    session_id: KanbanSessionId,
) -> Result<Option<KanbanSession>> {
    conn.query_row(
        "SELECT session_id, created_ns, prompt, prompt_hash, source_channel, \
                operator_id, status, artifact_path, summary \
         FROM idx_kanban_session WHERE session_id = ?1",
        params![session_id.raw()],
        row_to_session,
    )
    .optional()
    .context("select idx_kanban_session row")
}

/// Update session status + final artifact + summary in one shot. Used
/// when Cerebellum finalises a session (status=done) or the operator
/// abandons mid-flight (status=abandoned).
pub fn archive_session(
    conn: &Connection,
    session_id: KanbanSessionId,
    status: SessionStatus,
    summary: Option<&str>,
    artifact_path: Option<&PathBuf>,
) -> Result<()> {
    let path_str = artifact_path.map(|p| p.to_string_lossy().into_owned());
    let n = conn
        .execute(
            "UPDATE idx_kanban_session \
             SET status = ?1, summary = ?2, artifact_path = ?3 \
             WHERE session_id = ?4",
            params![status.as_str(), summary, path_str, session_id.raw()],
        )
        .context("update idx_kanban_session row")?;
    if n == 0 {
        anyhow::bail!(
            "archive_session: no row for session_id={}",
            session_id.raw()
        );
    }
    Ok(())
}

/// HO-02 (Session 28) — abandon every `idx_kanban_session` row that's
/// been stuck in `Planning` status for longer than `stale_after_ns`.
/// Returns the number of rows touched.
///
/// Why this matters: Cerebellum opens a session row + decomposes via
/// LLM before flipping to `Running`. If the dispatcher crashes (or
/// the daemon is restarted) mid-decompose, that session sits in
/// Planning forever — `neoth kanban list` shows it as actionable, but
/// no worker will pick it up. The reaper sweeps these on dispatcher
/// startup so the operator sees a clean slate.
///
/// Default cut-off is `1 hour` (3_600 * 1_000_000_000 ns) — well past
/// the longest legitimate decompose (Cerebellum LLM call + JSON parse
/// + per-task insert; even on cold local Qwen this completes inside
/// 90s). Operator-tunable via the caller (no freedom.yaml knob yet —
/// add when an operator hits a false-positive abandon).
///
/// Marks the row with the canonical `summary` "stale planning session
/// reaped on startup" so an operator running `neoth kanban show <id>`
/// after the fact sees why their old planning attempt vanished. The
/// `Abandoned` terminal status means `neoth kanban list` (without
/// `--all`) hides it from the actionable view.
pub fn reap_stale_planning_sessions(
    conn: &Connection,
    now_ns: u64,
    stale_after_ns: u64,
) -> Result<usize> {
    let cut_off = now_ns.saturating_sub(stale_after_ns) as i64;
    let n = conn
        .execute(
            "UPDATE idx_kanban_session \
             SET status = ?1, summary = ?2 \
             WHERE status = ?3 AND created_ns <= ?4",
            params![
                SessionStatus::Abandoned.as_str(),
                "stale planning session reaped on startup",
                SessionStatus::Planning.as_str(),
                cut_off,
            ],
        )
        .context("update idx_kanban_session for stale-planning reap")?;
    Ok(n)
}

/// GOLD-TASK-04 — reap crash-stranded `InProgress` TASK rows on startup.
///
/// The dispatcher transitions a task `Backlog → InProgress` (stamping
/// `started_ns`) BEFORE running `worker.execute()`. A daemon crash /
/// power loss mid-execute strands that row in `InProgress` forever: the
/// stale-planning reaper only sweeps SESSION rows (and a session never
/// leaves `Planning` until a terminal `archive_session`, so its tasks
/// are the orphans), and `worker_watch` only fires while the daemon is
/// alive. This sweep moves any `InProgress` task whose `started_ns` is
/// older than `stale_after_ns` to `Blocked` — the dispatcher's own
/// "couldn't finish" terminal (`TaskStatus` has no `Abandoned`), so the
/// operator can re-queue it. With GOLD-TASK-02a's 300s per-worker
/// timeout a live task is `InProgress` for minutes, never hours, so a
/// 1-hour cut-off (the caller's) never false-reaps a running dispatch.
///
/// `started_ns` is always set for `InProgress` (patch_task_status
/// `COALESCE(started_ns, now)`); a NULL would simply not match `<=` and
/// stay untouched. Best-effort, log-only at the call site (no WAL writer
/// — mirrors the stale-planning reaper's hygiene-not-audit contract).
pub fn reap_stale_inprogress_tasks(
    conn: &Connection,
    now_ns: u64,
    stale_after_ns: u64,
) -> Result<usize> {
    let cut_off = now_ns.saturating_sub(stale_after_ns) as i64;
    let n = conn
        .execute(
            "UPDATE idx_kanban_task \
             SET status = ?1 \
             WHERE status = ?2 AND started_ns <= ?3",
            params![
                TaskStatus::Blocked.as_str(),
                TaskStatus::InProgress.as_str(),
                cut_off,
            ],
        )
        .context("update idx_kanban_task for stale-inprogress reap")?;
    Ok(n)
}

/// QU-10b / SP-A1 — distinct session ids that still have at least one
/// `Backlog` task, ascending. The `task_executor` controller loop drives
/// each so pending work created outside a one-shot `neoth code "..."`
/// (a deferred dispatch, or tasks added to an existing session) still
/// gets picked up. Read-only.
pub fn sessions_with_backlog_tasks(conn: &Connection) -> Result<Vec<KanbanSessionId>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT session_id FROM idx_kanban_task \
             WHERE status = ?1 ORDER BY session_id ASC",
        )
        .context("prepare sessions-with-backlog query")?;
    let ids = stmt
        .query_map(params![TaskStatus::Backlog.as_str()], |row| {
            Ok(KanbanSessionId(row.get::<_, i64>(0)?))
        })
        .context("query sessions-with-backlog")?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

// ── Task CRUD ──────────────────────────────────────────────────────────────

/// Insert one task row for the given session. Initial status is
/// `Backlog`, hemisphere is `Unassigned`. The classifier + dispatcher
/// fill those in later via `patch_task_hemisphere` + `patch_task_status`.
#[allow(clippy::too_many_arguments)]
pub fn insert_task(
    conn: &Connection,
    session_id: KanbanSessionId,
    created_ns: u64,
    title: &str,
    description: Option<&str>,
    task_type: &str,
    parent_task_id: Option<KanbanTaskId>,
) -> Result<KanbanTaskId> {
    conn.execute(
        "INSERT INTO idx_kanban_task \
         (session_id, status, title, description, task_type, hemisphere, \
          parent_task_id, created_ns) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            session_id.raw(),
            TaskStatus::Backlog.as_str(),
            title,
            description,
            task_type,
            Hemisphere::Unassigned.as_str(),
            parent_task_id.map(|t| t.raw()),
            created_ns as i64,
        ],
    )
    .context("insert idx_kanban_task row")?;
    Ok(KanbanTaskId(conn.last_insert_rowid()))
}

/// Move a task between columns. The 5 status transitions documented in
/// the SPEC (Backlog→Todo→InProgress→Review→Done) all flow through
/// here; Blocked + Archived are valid targets from any non-terminal
/// state.
///
/// Side effects:
/// - Moving to `InProgress` stamps `started_ns` when previously NULL.
/// - Moving to `Done` stamps `completed_ns` when previously NULL.
/// - Reverse moves do NOT clear timestamps — the audit chain preserves
///   the original `started_ns` even if a task gets bounced back to TODO.
pub fn patch_task_status(
    conn: &Connection,
    task_id: KanbanTaskId,
    new_status: TaskStatus,
    now_ns: u64,
) -> Result<()> {
    let now_i64 = now_ns as i64;
    let n = match new_status {
        TaskStatus::InProgress => conn.execute(
            "UPDATE idx_kanban_task \
             SET status = ?1, started_ns = COALESCE(started_ns, ?2) \
             WHERE task_id = ?3",
            params![new_status.as_str(), now_i64, task_id.raw()],
        ),
        TaskStatus::Done => conn.execute(
            "UPDATE idx_kanban_task \
             SET status = ?1, completed_ns = COALESCE(completed_ns, ?2) \
             WHERE task_id = ?3",
            params![new_status.as_str(), now_i64, task_id.raw()],
        ),
        _ => conn.execute(
            "UPDATE idx_kanban_task SET status = ?1 WHERE task_id = ?2",
            params![new_status.as_str(), task_id.raw()],
        ),
    }
    .context("update idx_kanban_task status")?;
    if n == 0 {
        anyhow::bail!("patch_task_status: no row for task_id={}", task_id.raw());
    }
    Ok(())
}

/// Assign a task to a hemisphere + worker. Called by the classifier
/// (`hemisphere`) and dispatcher (`worker` provider name + `eta_ns`
/// estimate). All three fields update together so the operator's
/// kanban-view never shows a half-assigned task.
pub fn patch_task_hemisphere(
    conn: &Connection,
    task_id: KanbanTaskId,
    hemisphere: Hemisphere,
    worker: Option<&str>,
    eta_ns: Option<u64>,
) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE idx_kanban_task \
             SET hemisphere = ?1, worker = ?2, eta_ns = ?3 \
             WHERE task_id = ?4",
            params![
                hemisphere.as_str(),
                worker,
                eta_ns.map(|v| v as i64),
                task_id.raw(),
            ],
        )
        .context("update idx_kanban_task hemisphere/worker")?;
    if n == 0 {
        anyhow::bail!(
            "patch_task_hemisphere: no row for task_id={}",
            task_id.raw()
        );
    }
    Ok(())
}

/// Pick #6 Phase 4-pre (2026-05-21): append a retry strategy hint to
/// the task's description. Used by the dispatcher's retry path —
/// the worker reads the appended hint on the next attempt.
///
/// `description` is stored verbatim (no JSON wrapping) so the next
/// worker invocation sees the hint as part of the prompt. NULL
/// previous description is replaced with the hint alone.
pub fn append_task_description_hint(
    conn: &Connection,
    task_id: KanbanTaskId,
    hint: &str,
) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE idx_kanban_task \
             SET description = COALESCE(description || char(10), '') || ?1 \
             WHERE task_id = ?2",
            params![hint, task_id.raw()],
        )
        .context("append retry hint to task description")?;
    if n == 0 {
        anyhow::bail!(
            "append_task_description_hint: no row for task_id={}",
            task_id.raw()
        );
    }
    Ok(())
}

/// Attach the patch file + test outcome a worker reported. Test summary
/// is serialised as JSON for forward-compat — adding fields stays
/// non-breaking for existing rows.
pub fn attach_task_artifact(
    conn: &Connection,
    task_id: KanbanTaskId,
    patch_path: Option<&PathBuf>,
    test_summary: Option<TestSummary>,
) -> Result<()> {
    let path_str = patch_path.map(|p| p.to_string_lossy().into_owned());
    let summary_json = match test_summary {
        Some(s) => Some(serde_json::to_string(&s).context("serialise test summary")?),
        None => None,
    };
    let n = conn
        .execute(
            "UPDATE idx_kanban_task \
             SET patch_path = ?1, test_summary = ?2 \
             WHERE task_id = ?3",
            params![path_str, summary_json, task_id.raw()],
        )
        .context("update idx_kanban_task artifacts")?;
    if n == 0 {
        anyhow::bail!("attach_task_artifact: no row for task_id={}", task_id.raw());
    }
    Ok(())
}

/// All tasks for a session, ordered by `task_id` ASC (insertion order
/// = decomposition order). The GUI's 5-column view groups by `status`
/// after this call returns.
pub fn list_tasks_for_session(
    conn: &Connection,
    session_id: KanbanSessionId,
) -> Result<Vec<KanbanTask>> {
    let mut stmt = conn
        .prepare(
            "SELECT task_id, session_id, status, title, description, task_type, \
                    hemisphere, worker, parent_task_id, created_ns, started_ns, \
                    eta_ns, completed_ns, patch_path, test_summary \
             FROM idx_kanban_task WHERE session_id = ?1 ORDER BY task_id ASC",
        )
        .context("prepare list_tasks_for_session")?;
    let rows = stmt
        .query_map(params![session_id.raw()], row_to_task)
        .context("query list_tasks_for_session")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect kanban tasks")
}

/// GOLD-HON-18 (A-41 / C-33) — Backlog-only tasks for a session, ascending.
/// The `status` filter is pushed into SQL so the dispatcher's batch picker
/// reads only the rows it can act on, rather than fetching every task and
/// discarding non-Backlog ones in Rust (the linear-scan concern carried
/// forward from the deleted `pick_next_backlog_task`).
pub fn list_backlog_tasks_for_session(
    conn: &Connection,
    session_id: KanbanSessionId,
) -> Result<Vec<KanbanTask>> {
    let mut stmt = conn
        .prepare(
            "SELECT task_id, session_id, status, title, description, task_type, \
                    hemisphere, worker, parent_task_id, created_ns, started_ns, \
                    eta_ns, completed_ns, patch_path, test_summary \
             FROM idx_kanban_task WHERE session_id = ?1 AND status = ?2 ORDER BY task_id ASC",
        )
        .context("prepare list_backlog_tasks_for_session")?;
    let rows = stmt
        .query_map(
            params![session_id.raw(), TaskStatus::Backlog.as_str()],
            row_to_task,
        )
        .context("query list_backlog_tasks_for_session")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect backlog kanban tasks")
}

// ── Comment CRUD ───────────────────────────────────────────────────────────

/// Append one comment to a task. Comments are append-only — there is
/// no `patch_comment` / `delete_comment` in v0.1 because the audit
/// chain rests on the assumption that comments are immutable once
/// written (operator-side edit lands as a SECOND comment with the new
/// body, not an in-place rewrite).
pub fn insert_comment(
    conn: &Connection,
    task_id: KanbanTaskId,
    created_ns: u64,
    author: &str,
    body: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO idx_kanban_comment (task_id, author, body, created_ns) \
         VALUES (?1, ?2, ?3, ?4)",
        params![task_id.raw(), author, body, created_ns as i64],
    )
    .context("insert idx_kanban_comment row")?;
    Ok(conn.last_insert_rowid())
}

/// All comments on a task, oldest-first. The GUI's per-task pane reads
/// this verbatim into the comment thread.
pub fn list_comments_for_task(
    conn: &Connection,
    task_id: KanbanTaskId,
) -> Result<Vec<KanbanComment>> {
    let mut stmt = conn
        .prepare(
            "SELECT comment_id, task_id, author, body, created_ns \
             FROM idx_kanban_comment WHERE task_id = ?1 \
             ORDER BY created_ns ASC, comment_id ASC",
        )
        .context("prepare list_comments_for_task")?;
    let rows = stmt
        .query_map(params![task_id.raw()], row_to_comment)
        .context("query list_comments_for_task")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect kanban comments")
}

// ── Task events (GOLD-ADAPT-HERMES-08) ────────────────────────────────────

/// Append one row to `idx_kanban_task_event`. Called by every mutation
/// function that changes observable task state (status, comment, dep
/// edge). The `tx` broadcast sender notifies connected SSE subscribers
/// immediately — best-effort (`let _ =` so a lagging/absent subscriber
/// never blocks the mutation).
pub fn insert_task_event(
    conn: &Connection,
    task_id: i64,
    event_type: u8,
    payload_json: &str,
    created_ns: u64,
    tx: Option<&broadcast::Sender<FeedEntry>>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO idx_kanban_task_event (task_id, event_type, payload, created_ns) \
         VALUES (?1, ?2, ?3, ?4)",
        params![task_id, event_type as i64, payload_json, created_ns as i64],
    )
    .context("insert idx_kanban_task_event row")?;
    if let Some(tx) = tx {
        let entry = FeedEntry {
            ts_ns: created_ns,
            event_type,
            actor: "system".to_string(),
            message: payload_json.to_string(),
        };
        let _ = tx.send(entry);
    }
    Ok(())
}

/// All task events for one task, oldest-first. The SSE server streams
/// these as the initial snapshot when a client connects.
pub fn list_task_events(conn: &Connection, task_id: i64) -> Result<Vec<TaskEvent>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, task_id, event_type, payload, created_ns \
             FROM idx_kanban_task_event WHERE task_id = ?1 \
             ORDER BY created_ns ASC, event_id ASC",
        )
        .context("prepare list_task_events")?;
    let rows = stmt
        .query_map(params![task_id], |row| {
            Ok(TaskEvent {
                event_id: row.get(0)?,
                task_id: row.get(1)?,
                event_type: row.get::<_, i64>(2)? as u8,
                payload_json: row.get(3)?,
                created_ns: row.get::<_, i64>(4)? as u64,
            })
        })
        .context("query list_task_events")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect task events")
}

/// All task events across all tasks, oldest-first. Used by the SSE
/// server's initial snapshot for the global `/kanban/events` stream.
pub fn list_all_task_events(conn: &Connection) -> Result<Vec<TaskEvent>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, task_id, event_type, payload, created_ns \
             FROM idx_kanban_task_event ORDER BY created_ns ASC, event_id ASC",
        )
        .context("prepare list_all_task_events")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TaskEvent {
                event_id: row.get(0)?,
                task_id: row.get(1)?,
                event_type: row.get::<_, i64>(2)? as u8,
                payload_json: row.get(3)?,
                created_ns: row.get::<_, i64>(4)? as u64,
            })
        })
        .context("query list_all_task_events")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect all task events")
}

// ── Task dependencies (GOLD-ADAPT-HERMES-08) ──────────────────────────────

/// Add a dependency edge: `task_id` must wait for `depends_on_task_id`
/// to reach a terminal state. `UNIQUE … ON CONFLICT IGNORE` means a
/// duplicate insert is silently ignored — idempotent by design.
pub fn insert_task_dep(
    conn: &Connection,
    task_id: i64,
    depends_on_task_id: i64,
    created_ns: u64,
    tx: Option<&broadcast::Sender<FeedEntry>>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO idx_kanban_task_dep (task_id, depends_on_task_id, created_ns) \
         VALUES (?1, ?2, ?3)",
        params![task_id, depends_on_task_id, created_ns as i64],
    )
    .context("insert idx_kanban_task_dep row")?;
    let payload_json = serde_json::json!({
        "task_id": task_id,
        "depends_on_task_id": depends_on_task_id,
        "ts": created_ns,
    })
    .to_string();
    insert_task_event(
        conn,
        task_id,
        crate::wal::events::EVENT_TYPE_KANBAN_TASK_DEP_ADDED,
        &payload_json,
        created_ns,
        tx,
    )
}

/// Remove a dependency edge. No-op when the edge does not exist.
pub fn remove_task_dep(
    conn: &Connection,
    task_id: i64,
    depends_on_task_id: i64,
    created_ns: u64,
    tx: Option<&broadcast::Sender<FeedEntry>>,
) -> Result<()> {
    conn.execute(
        "DELETE FROM idx_kanban_task_dep \
         WHERE task_id = ?1 AND depends_on_task_id = ?2",
        params![task_id, depends_on_task_id],
    )
    .context("delete idx_kanban_task_dep row")?;
    let payload_json = serde_json::json!({
        "task_id": task_id,
        "depends_on_task_id": depends_on_task_id,
        "ts": created_ns,
    })
    .to_string();
    insert_task_event(
        conn,
        task_id,
        crate::wal::events::EVENT_TYPE_KANBAN_TASK_DEP_REMOVED,
        &payload_json,
        created_ns,
        tx,
    )
}

/// All prerequisite task_ids for the given task. The dispatcher uses
/// this to gate dispatch: a task with unresolved deps stays Backlog.
pub fn list_deps_for_task(conn: &Connection, task_id: i64) -> Result<Vec<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT depends_on_task_id FROM idx_kanban_task_dep \
             WHERE task_id = ?1 ORDER BY dep_id ASC",
        )
        .context("prepare list_deps_for_task")?;
    let rows = stmt
        .query_map(params![task_id], |row| row.get::<_, i64>(0))
        .context("query list_deps_for_task")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect task dep ids")
}

/// All `TaskDep` rows for a task with full struct data.
pub fn list_full_deps_for_task(conn: &Connection, task_id: i64) -> Result<Vec<TaskDep>> {
    let mut stmt = conn
        .prepare(
            "SELECT dep_id, task_id, depends_on_task_id, created_ns \
             FROM idx_kanban_task_dep WHERE task_id = ?1 ORDER BY dep_id ASC",
        )
        .context("prepare list_full_deps_for_task")?;
    let rows = stmt
        .query_map(params![task_id], |row| {
            Ok(TaskDep {
                dep_id: row.get(0)?,
                task_id: row.get(1)?,
                depends_on_task_id: row.get(2)?,
                created_ns: row.get::<_, i64>(3)? as u64,
            })
        })
        .context("query list_full_deps_for_task")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect task deps")
}

// ── Row → struct helpers ───────────────────────────────────────────────────
//
// `query_map` row closures live here so `list_tasks_for_session` /
// `list_comments_for_task` / `get_session` share one decoder per table.
// The column order MUST match the SELECT — keep them in sync.

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<KanbanSession> {
    let raw_status: String = row.get(6)?;
    Ok(KanbanSession {
        session_id: KanbanSessionId(row.get(0)?),
        created_ns: row.get::<_, i64>(1)? as u64,
        prompt: row.get(2)?,
        prompt_hash: row.get(3)?,
        source_channel: row.get(4)?,
        operator_id: row.get(5)?,
        status: SessionStatus::from_wire(&raw_status).unwrap_or(SessionStatus::Abandoned),
        artifact_path: row.get::<_, Option<String>>(7)?.map(PathBuf::from),
        summary: row.get(8)?,
    })
}

fn row_to_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<KanbanTask> {
    let raw_status: String = row.get(2)?;
    let raw_hemi: String = row.get(6)?;
    let test_summary_json: Option<String> = row.get(14)?;
    let test_summary = test_summary_json.and_then(|s| serde_json::from_str::<TestSummary>(&s).ok());
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
        test_summary,
    })
}

fn row_to_comment(row: &rusqlite::Row<'_>) -> rusqlite::Result<KanbanComment> {
    Ok(KanbanComment {
        comment_id: row.get(0)?,
        task_id: KanbanTaskId(row.get(1)?),
        author: row.get(2)?,
        body: row.get(3)?,
        created_ns: row.get::<_, i64>(4)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::code_map_receipt::{
        CodeMapCaller, CodeMapContextKind, CodeMapContextSource, CodeMapSelectedFile,
        MAX_CODE_MAP_RECEIPT_BYTES, MAX_CODE_MAP_SOURCE_BYTES, PreparedCodeMapContext,
    };

    fn open_memory_db() -> Connection {
        Connection::open_in_memory().expect("open in-memory sqlite")
    }

    fn receipt_context() -> PreparedCodeMapContext {
        PreparedCodeMapContext::new(
            "file: src/lib.rs\nsymbol: entrypoint".to_owned(),
            vec![CodeMapContextSource {
                kind: CodeMapContextKind::TargetedRecall,
                root: "C:/repo".to_owned(),
                root_identity: "volume:repo".to_owned(),
                index_generation: 9,
                graph_generation: 9,
                stale: false,
                selection_truncated: false,
                metadata_redacted: false,
                selected_files: vec![CodeMapSelectedFile {
                    path: "src/lib.rs".to_owned(),
                    symbols: vec!["entrypoint".to_owned()],
                }],
                callers: vec![CodeMapCaller {
                    target_symbol: "entrypoint".to_owned(),
                    caller_symbol: "main".to_owned(),
                    caller_path: "src/main.rs".to_owned(),
                }],
            }],
        )
        .unwrap()
    }

    fn receipt(
        context: &PreparedCodeMapContext,
        session_id: KanbanSessionId,
        attempt: u8,
        provider_prompt: &str,
    ) -> CodingCodeMapReceipt {
        context
            .receipt(
                session_id,
                attempt,
                "operator request",
                context.text(),
                provider_prompt,
            )
            .unwrap()
    }

    fn near_source_budget_context() -> PreparedCodeMapContext {
        let mut source = CodeMapContextSource {
            kind: CodeMapContextKind::TargetedRecall,
            root: "C:/repo".to_owned(),
            root_identity: "volume:repo".to_owned(),
            index_generation: 9,
            graph_generation: 9,
            stale: false,
            selection_truncated: false,
            metadata_redacted: false,
            selected_files: vec![CodeMapSelectedFile {
                path: "src/lib.rs".to_owned(),
                symbols: Vec::new(),
            }],
            callers: Vec::new(),
        };
        let target = MAX_CODE_MAP_SOURCE_BYTES - 1_024;
        while serde_json::to_vec(&source).unwrap().len() < target {
            let ordinal = source.selected_files[0].symbols.len();
            source.selected_files[0]
                .symbols
                .push(format!("selected_symbol_{ordinal}_{}", "a".repeat(480)));
        }
        let encoded = serde_json::to_vec(&source).unwrap();
        assert!(encoded.len() >= target);
        assert!(encoded.len() <= MAX_CODE_MAP_SOURCE_BYTES);
        PreparedCodeMapContext::new("context".to_owned(), vec![source]).unwrap()
    }

    #[test]
    fn ensure_schema_creates_three_tables() {
        let conn = open_memory_db();
        ensure_schema(&conn).expect("schema applies");

        // sqlite_master is the canonical "what tables exist" view.
        let mut names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name LIKE 'idx_kanban_%' \
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                "idx_kanban_comment".to_string(),
                "idx_kanban_session".to_string(),
                "idx_kanban_task".to_string(),
                "idx_kanban_task_dep".to_string(),
                "idx_kanban_task_event".to_string(),
            ],
            "all five kanban tables must exist after ensure_schema"
        );
    }

    #[test]
    fn ensure_schema_is_idempotent() {
        // The daemon calls ensure_schema at startup. Running it twice
        // (process restart while the file already has the tables)
        // must NOT error. `CREATE TABLE IF NOT EXISTS` carries this,
        // but pin it explicitly so a future migration doesn't drop
        // the IF NOT EXISTS clause silently.
        let conn = open_memory_db();
        ensure_schema(&conn).expect("first apply");
        ensure_schema(&conn).expect("second apply MUST succeed (idempotent)");
        ensure_schema(&conn).expect("third apply MUST succeed");
    }

    #[test]
    fn ensure_schema_migrates_old_session_table_with_nullable_receipt_column() {
        let conn = open_memory_db();
        conn.execute_batch(
            "CREATE TABLE idx_kanban_session (
                session_id INTEGER PRIMARY KEY,
                created_ns INTEGER NOT NULL,
                prompt TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                source_channel TEXT NOT NULL,
                operator_id TEXT,
                status TEXT NOT NULL,
                artifact_path TEXT,
                summary TEXT
            );",
        )
        .unwrap();

        ensure_schema(&conn).unwrap();
        assert!(has_code_map_receipts_column(&conn).unwrap());
        let nullable: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('idx_kanban_session') \
                 WHERE name = 'code_map_receipts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            nullable, 0,
            "old sessions must migrate with a NULL receipt field"
        );
    }

    #[test]
    fn receipts_survive_archive_and_require_matching_repair_basis() {
        let conn = prepared_db();
        let session_id = insert_session(&conn, 1, "prompt", "hash", "cli", None).unwrap();
        let context = receipt_context();
        let first = receipt(&context, session_id, 1, "provider first");
        record_code_map_receipt(&conn, session_id, &first).unwrap();
        archive_session(&conn, session_id, SessionStatus::Done, Some("done"), None).unwrap();
        assert_eq!(
            load_code_map_receipts(&conn, session_id).unwrap(),
            vec![first.clone()]
        );

        let altered =
            PreparedCodeMapContext::new("different context".to_owned(), context.sources().to_vec())
                .unwrap();
        let mismatch = receipt(&altered, session_id, 2, "provider mismatch");
        assert!(record_code_map_receipt(&conn, session_id, &mismatch).is_err());

        let repair = receipt(
            &context,
            session_id,
            2,
            "provider repair includes bad output",
        );
        record_code_map_receipt(&conn, session_id, &repair).unwrap();
        assert_eq!(
            load_code_map_receipts(&conn, session_id).unwrap(),
            vec![first, repair]
        );
    }

    #[test]
    fn near_source_budget_is_stored_once_and_reconstructs_repair() {
        let conn = prepared_db();
        let session_id = insert_session(&conn, 1, "prompt", "hash", "cli", None).unwrap();
        let context = near_source_budget_context();
        let source_bytes = serde_json::to_vec(&context.sources()[0]).unwrap().len();
        assert!(source_bytes >= MAX_CODE_MAP_SOURCE_BYTES - 1_024);

        let first = receipt(&context, session_id, 1, "provider first");
        record_code_map_receipt(&conn, session_id, &first).unwrap();
        let repair = receipt(&context, session_id, 2, "provider repair");
        record_code_map_receipt(&conn, session_id, &repair).unwrap();

        let stored: String = conn
            .query_row(
                "SELECT code_map_receipts FROM idx_kanban_session WHERE session_id = ?1",
                params![session_id.raw()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored.len() <= MAX_CODE_MAP_RECEIPT_BYTES);
        assert_eq!(
            stored.match_indices("\"sources\"").count(),
            1,
            "compact repair storage must not duplicate selected-source evidence"
        );
        let persisted: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(persisted["schema"], CODE_MAP_RECEIPT_STORAGE_SCHEMA);
        assert_eq!(persisted["first"]["sources"].as_array().unwrap().len(), 1);
        assert!(
            persisted["repair"].get("sources").is_none(),
            "repair stores only changing commitments"
        );
        assert_eq!(
            load_code_map_receipts(&conn, session_id).unwrap(),
            vec![first, repair]
        );
    }

    #[test]
    fn receipt_store_rejects_missing_session_and_corruption_without_fallback() {
        let conn = prepared_db();
        let context = receipt_context();
        let missing = KanbanSessionId(404);
        assert!(
            record_code_map_receipt(&conn, missing, &receipt(&context, missing, 1, "p")).is_err()
        );
        assert!(load_code_map_receipts(&conn, missing).is_err());

        let session_id = insert_session(&conn, 1, "prompt", "hash", "cli", None).unwrap();
        conn.execute(
            "UPDATE idx_kanban_session SET code_map_receipts = 'not-json' WHERE session_id = ?1",
            params![session_id.raw()],
        )
        .unwrap();
        assert!(load_code_map_receipts(&conn, session_id).is_err());
        assert!(
            record_code_map_receipt(&conn, session_id, &receipt(&context, session_id, 1, "p"))
                .is_err()
        );
    }

    #[test]
    fn receipt_store_rejects_oversized_blob_and_nul_text_before_copying_values() {
        let conn = prepared_db();
        let context = receipt_context();

        let oversized = insert_session(&conn, 1, "prompt", "hash", "cli", None).unwrap();
        conn.execute(
            "UPDATE idx_kanban_session \
             SET code_map_receipts = CAST(zeroblob(?1) AS TEXT) WHERE session_id = ?2",
            params![MAX_CODE_MAP_RECEIPT_BYTES as i64 + 1, oversized.raw()],
        )
        .unwrap();
        assert!(load_code_map_receipts(&conn, oversized).is_err());
        assert!(
            record_code_map_receipt(&conn, oversized, &receipt(&context, oversized, 1, "p"))
                .is_err()
        );

        let blob = insert_session(&conn, 2, "prompt", "hash", "cli", None).unwrap();
        conn.execute(
            "UPDATE idx_kanban_session SET code_map_receipts = zeroblob(4) WHERE session_id = ?1",
            params![blob.raw()],
        )
        .unwrap();
        assert!(load_code_map_receipts(&conn, blob).is_err());
        assert!(record_code_map_receipt(&conn, blob, &receipt(&context, blob, 1, "p")).is_err());

        let nul_text = insert_session(&conn, 3, "prompt", "hash", "cli", None).unwrap();
        conn.execute(
            "UPDATE idx_kanban_session \
             SET code_map_receipts = CAST(zeroblob(4) AS TEXT) WHERE session_id = ?1",
            params![nul_text.raw()],
        )
        .unwrap();
        assert!(load_code_map_receipts(&conn, nul_text).is_err());
        assert!(
            record_code_map_receipt(&conn, nul_text, &receipt(&context, nul_text, 1, "p")).is_err()
        );
    }

    #[test]
    fn task_session_fk_blocks_orphan_inserts() {
        // FK is declared but sqlite needs `PRAGMA foreign_keys=ON` to
        // enforce it. Pin that with the pragma set, an orphan insert
        // is rejected — the dispatcher relies on this to abort tasks
        // whose session vanished mid-flight.
        let conn = open_memory_db();
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable FK enforcement");
        ensure_schema(&conn).expect("schema applies");

        let result = conn.execute(
            "INSERT INTO idx_kanban_task \
             (task_id, session_id, status, title, task_type, created_ns) \
             VALUES (1, 999, 'backlog', 'orphan', 'ui', 1)",
            [],
        );
        assert!(
            result.is_err(),
            "orphan task insert (session_id=999 missing) must be FK-rejected"
        );
    }

    #[test]
    fn comment_task_fk_blocks_orphan_comments() {
        let conn = open_memory_db();
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable FK");
        ensure_schema(&conn).expect("schema applies");

        let result = conn.execute(
            "INSERT INTO idx_kanban_comment \
             (comment_id, task_id, author, body, created_ns) \
             VALUES (1, 42, 'cerebellum', 'hi', 1)",
            [],
        );
        assert!(
            result.is_err(),
            "orphan comment insert (task_id=42 missing) must be FK-rejected"
        );
    }

    fn prepared_db() -> Connection {
        let conn = open_memory_db();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        ensure_schema(&conn).expect("schema applies");
        conn
    }

    // ── Session CRUD round-trip ─────────────────────────────────────────────

    #[test]
    fn insert_session_assigns_rowid_and_get_session_round_trips() {
        let conn = prepared_db();
        let id = insert_session(
            &conn,
            1_700_000_000_000_000_000,
            "Add dark mode toggle to settings",
            "deadbeefcafebabe",
            "cli",
            Some("sam"),
        )
        .expect("insert session");
        assert!(
            id.raw() > 0,
            "sqlite rowid must be assigned non-zero on insert"
        );

        let fetched = get_session(&conn, id).expect("get_session").expect("row");
        assert_eq!(fetched.session_id, id);
        assert_eq!(fetched.prompt, "Add dark mode toggle to settings");
        assert_eq!(fetched.prompt_hash, "deadbeefcafebabe");
        assert_eq!(fetched.source_channel, "cli");
        assert_eq!(fetched.operator_id.as_deref(), Some("sam"));
        assert_eq!(fetched.status, SessionStatus::Planning);
        assert!(fetched.summary.is_none());
        assert!(fetched.artifact_path.is_none());
    }

    #[test]
    fn get_session_returns_none_for_unknown_id() {
        let conn = prepared_db();
        let result = get_session(&conn, KanbanSessionId(9999)).expect("query");
        assert!(
            result.is_none(),
            "unknown session_id must surface as Ok(None), not error"
        );
    }

    #[test]
    fn archive_session_updates_status_and_summary() {
        let conn = prepared_db();
        let id = insert_session(&conn, 1_700_000_000, "p", "h", "cli", None).unwrap();
        let artifact = PathBuf::from("/tmp/session_42/final.patch");
        archive_session(
            &conn,
            id,
            SessionStatus::Done,
            Some("All 4 tasks done. Patch ready to merge."),
            Some(&artifact),
        )
        .expect("archive");

        let s = get_session(&conn, id).unwrap().unwrap();
        assert_eq!(s.status, SessionStatus::Done);
        assert_eq!(
            s.summary.as_deref(),
            Some("All 4 tasks done. Patch ready to merge.")
        );
        assert_eq!(s.artifact_path, Some(artifact));
    }

    #[test]
    fn archive_session_errors_on_missing_session() {
        let conn = prepared_db();
        let result = archive_session(
            &conn,
            KanbanSessionId(404),
            SessionStatus::Abandoned,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "archive of missing session must error, not silently no-op"
        );
    }

    // ── Task CRUD round-trip ────────────────────────────────────────────────

    #[test]
    fn insert_task_assigns_rowid_and_list_returns_it() {
        let conn = prepared_db();
        let session = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();

        let t1 = insert_task(
            &conn,
            session,
            10,
            "Add toggle UI in settings",
            Some("Add a `<input type=\"checkbox\">` to the settings panel"),
            "ui",
            None,
        )
        .expect("insert task 1");
        let t2 = insert_task(&conn, session, 11, "Save preference", None, "store", None)
            .expect("insert task 2");
        let t3 = insert_task(&conn, session, 12, "Add tests", None, "tests", Some(t1))
            .expect("insert task 3 with parent");

        assert!(
            t1.raw() < t2.raw() && t2.raw() < t3.raw(),
            "ascending rowids"
        );

        let tasks = list_tasks_for_session(&conn, session).expect("list");
        assert_eq!(tasks.len(), 3, "all 3 tasks must surface");
        assert_eq!(tasks[0].task_id, t1);
        assert_eq!(tasks[0].title, "Add toggle UI in settings");
        assert_eq!(tasks[0].status, TaskStatus::Backlog, "initial status");
        assert_eq!(tasks[0].hemisphere, Hemisphere::Unassigned);
        assert!(tasks[0].started_ns.is_none());
        assert!(tasks[0].completed_ns.is_none());
        assert_eq!(tasks[2].parent_task_id, Some(t1), "parent link preserved");
    }

    #[test]
    fn patch_task_status_stamps_started_ns_on_first_in_progress() {
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        patch_task_status(&conn, t, TaskStatus::InProgress, 555).expect("first move");
        let tasks = list_tasks_for_session(&conn, s).unwrap();
        assert_eq!(tasks[0].status, TaskStatus::InProgress);
        assert_eq!(tasks[0].started_ns, Some(555));

        // Bounce back to Todo, then forward to InProgress with a DIFFERENT
        // timestamp. started_ns MUST stick to the first stamp — audit chain
        // preserves the actual start time across reassignments.
        patch_task_status(&conn, t, TaskStatus::Todo, 600).expect("bounce");
        patch_task_status(&conn, t, TaskStatus::InProgress, 777).expect("second move");
        let tasks = list_tasks_for_session(&conn, s).unwrap();
        assert_eq!(
            tasks[0].started_ns,
            Some(555),
            "started_ns is COALESCE-stamped — second InProgress does NOT overwrite"
        );
    }

    #[test]
    fn patch_task_status_stamps_completed_ns_on_done() {
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        patch_task_status(&conn, t, TaskStatus::InProgress, 100).expect("in progress");
        patch_task_status(&conn, t, TaskStatus::Review, 200).expect("review");
        patch_task_status(&conn, t, TaskStatus::Done, 300).expect("done");

        let tasks = list_tasks_for_session(&conn, s).unwrap();
        assert_eq!(tasks[0].status, TaskStatus::Done);
        assert_eq!(tasks[0].started_ns, Some(100));
        assert_eq!(tasks[0].completed_ns, Some(300));
    }

    #[test]
    fn patch_task_status_errors_on_missing_task() {
        let conn = prepared_db();
        let result = patch_task_status(&conn, KanbanTaskId(999), TaskStatus::InProgress, 1);
        assert!(
            result.is_err(),
            "patch of missing task must error, not silently no-op"
        );
    }

    #[test]
    fn list_backlog_tasks_for_session_filters_in_sql() {
        // GOLD-HON-18: the status filter lives in SQL, so only Backlog rows
        // come back — never a fetch-all + Rust scan over every task.
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let backlog = insert_task(&conn, s, 10, "backlog-task", None, "ui", None).unwrap();
        let moved = insert_task(&conn, s, 20, "moved-task", None, "ui", None).unwrap();
        patch_task_status(&conn, moved, TaskStatus::InProgress, 100).expect("move off backlog");

        let only_backlog = list_backlog_tasks_for_session(&conn, s).unwrap();
        assert_eq!(only_backlog.len(), 1, "only the Backlog task is returned");
        assert_eq!(only_backlog[0].task_id, backlog);
        assert_eq!(only_backlog[0].status, TaskStatus::Backlog);
        // Sanity: the unfiltered list still has both rows.
        assert_eq!(list_tasks_for_session(&conn, s).unwrap().len(), 2);
    }

    #[test]
    fn patch_task_hemisphere_assigns_worker_and_eta() {
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        patch_task_hemisphere(
            &conn,
            t,
            Hemisphere::Left,
            Some("local_qwen"),
            Some(60_000_000_000),
        )
        .expect("assign");
        let tasks = list_tasks_for_session(&conn, s).unwrap();
        assert_eq!(tasks[0].hemisphere, Hemisphere::Left);
        assert_eq!(tasks[0].worker.as_deref(), Some("local_qwen"));
        assert_eq!(tasks[0].eta_ns, Some(60_000_000_000));
    }

    #[test]
    fn attach_task_artifact_serialises_test_summary_as_json() {
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();
        let patch = PathBuf::from("/tmp/task_42.patch");
        let summary = TestSummary {
            added: 5,
            total: 5,
            passing: 5,
            failing: 0,
            skipped: 0,
            applied: false,
        };

        attach_task_artifact(&conn, t, Some(&patch), Some(summary)).expect("attach");
        let tasks = list_tasks_for_session(&conn, s).unwrap();
        assert_eq!(tasks[0].patch_path, Some(patch));
        let got = tasks[0].test_summary.expect("test_summary populated");
        assert_eq!(got.added, 5);
        assert!(got.all_green());
    }

    // ── Comment CRUD round-trip ─────────────────────────────────────────────

    #[test]
    fn insert_comment_round_trips_and_lists_in_order() {
        let conn = prepared_db();
        let s = insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();

        let c1 = insert_comment(&conn, t, 100, "cerebellum", "Good test coverage!").expect("c1");
        let c2 = insert_comment(
            &conn,
            t,
            200,
            "right",
            "Consider edge case when system theme changes",
        )
        .expect("c2");
        let c3 =
            insert_comment(&conn, t, 300, "left", "Added handling for theme sync").expect("c3");

        assert!(c1 < c2 && c2 < c3, "monotonic comment_id");

        let comments = list_comments_for_task(&conn, t).expect("list");
        assert_eq!(comments.len(), 3);
        assert_eq!(comments[0].body, "Good test coverage!");
        assert_eq!(comments[0].author, "cerebellum");
        assert_eq!(comments[1].author, "right");
        assert_eq!(comments[2].author, "left");
        assert_eq!(comments[2].created_ns, 300);
    }

    #[test]
    fn list_comments_for_task_returns_empty_for_unknown_task() {
        let conn = prepared_db();
        let comments = list_comments_for_task(&conn, KanbanTaskId(404)).expect("query");
        assert!(comments.is_empty());
    }

    // ── SQL injection regression ────────────────────────────────────────────

    #[test]
    fn user_input_is_parameter_bound_not_string_interpolated() {
        // A malicious prompt that closes the quote + injects DROP TABLE
        // must NOT execute the DROP. rusqlite::params binds the string
        // as a value — pin that the schema survives.
        let conn = prepared_db();
        let nasty = "x'); DROP TABLE idx_kanban_task; --";
        let id =
            insert_session(&conn, 1, nasty, "h", "cli", None).expect("insert with sql-ish payload");
        let fetched = get_session(&conn, id).unwrap().unwrap();
        assert_eq!(
            fetched.prompt, nasty,
            "payload must be stored verbatim, not parsed as SQL"
        );

        // Schema MUST still have idx_kanban_task. If the DROP had run,
        // the next insert would fail.
        let _ = insert_task(&conn, id, 1, "still works", None, "ui", None)
            .expect("idx_kanban_task survived — SQL injection blocked");
    }

    #[test]
    fn indexes_are_co_created() {
        // Without these the dispatcher's per-session task list scans
        // the whole table. Index presence is part of the schema
        // contract, not a "nice to have". Pin all five.
        let conn = open_memory_db();
        ensure_schema(&conn).expect("schema applies");
        let mut names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='index' AND name LIKE 'idx_kanban_%' \
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        names.sort();
        assert!(
            names.contains(&"idx_kanban_session_created".to_string()),
            "session created index must exist"
        );
        assert!(
            names.contains(&"idx_kanban_session_status".to_string()),
            "session status index must exist"
        );
        assert!(
            names.contains(&"idx_kanban_task_session".to_string()),
            "task→session index must exist"
        );
        assert!(
            names.contains(&"idx_kanban_task_status".to_string()),
            "task status index must exist"
        );
        assert!(
            names.contains(&"idx_kanban_task_hemisphere".to_string()),
            "task hemisphere index must exist"
        );
        assert!(
            names.contains(&"idx_kanban_comment_task".to_string()),
            "comment→task index must exist"
        );
    }

    // ── HO-02 (Session 28): stale-planning reaper ──────────────────

    const STALE_CUTOFF_NS: u64 = 3_600 * 1_000_000_000;

    #[test]
    fn reaper_abandons_planning_session_older_than_cutoff() {
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        // Insert a planning session created 2 hours ago — must be reaped.
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let created_ns: u64 = now_ns - 2 * 3600 * 1_000_000_000;
        let session_id =
            insert_session(&conn, created_ns, "old prompt", "h1", "cli", None).unwrap();
        let n = reap_stale_planning_sessions(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 1);
        let fetched = get_session(&conn, session_id).unwrap().unwrap();
        assert_eq!(fetched.status, SessionStatus::Abandoned);
        assert_eq!(
            fetched.summary.as_deref(),
            Some("stale planning session reaped on startup")
        );
    }

    #[test]
    fn reaper_leaves_fresh_planning_session_untouched() {
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        // Planning session created 1 minute ago — fresh, must NOT be
        // reaped (someone might be decomposing it right now).
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let created_ns: u64 = now_ns - 60 * 1_000_000_000;
        let session_id =
            insert_session(&conn, created_ns, "fresh prompt", "h2", "cli", None).unwrap();
        let n = reap_stale_planning_sessions(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 0);
        let fetched = get_session(&conn, session_id).unwrap().unwrap();
        assert_eq!(fetched.status, SessionStatus::Planning);
    }

    #[test]
    fn reaper_ignores_already_running_or_done_sessions() {
        // Sweep MUST be `status = Planning`-scoped — a running or done
        // session past the cut-off is NOT a leak, it's just history.
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let created_ns: u64 = now_ns - 2 * 3600 * 1_000_000_000;
        let s_planning = insert_session(&conn, created_ns, "p1", "h1", "cli", None).unwrap();
        let s_done = insert_session(&conn, created_ns, "p2", "h2", "cli", None).unwrap();
        archive_session(&conn, s_done, SessionStatus::Done, None, None).unwrap();
        let n = reap_stale_planning_sessions(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        // Only the planning row gets reaped — the done row stays Done.
        assert_eq!(n, 1);
        assert_eq!(
            get_session(&conn, s_planning).unwrap().unwrap().status,
            SessionStatus::Abandoned
        );
        assert_eq!(
            get_session(&conn, s_done).unwrap().unwrap().status,
            SessionStatus::Done
        );
    }

    #[test]
    fn reaper_returns_zero_on_empty_db() {
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let n = reap_stale_planning_sessions(&conn, 1_000_000_000, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 0);
    }

    // ── GOLD-TASK-04: stale-InProgress task reaper ─────────────────

    #[test]
    fn inprogress_reaper_blocks_task_started_before_cutoff() {
        // A task left InProgress by a crashed dispatch (started 2h ago)
        // is swept to Blocked so the operator can re-queue it.
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let started_ns: u64 = now_ns - 2 * 3600 * 1_000_000_000;
        let session_id = insert_session(&conn, started_ns, "p", "h", "cli", None).unwrap();
        let task_id = insert_task(&conn, session_id, started_ns, "t", None, "ui", None).unwrap();
        patch_task_status(&conn, task_id, TaskStatus::InProgress, started_ns).unwrap();
        let n = reap_stale_inprogress_tasks(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 1);
        let task = list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[test]
    fn inprogress_reaper_leaves_fresh_task_running() {
        // Started 1 min ago — a live dispatch (worker.execute is capped
        // at 300s by TASK-02a), must NOT be reaped.
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let started_ns: u64 = now_ns - 60 * 1_000_000_000;
        let session_id = insert_session(&conn, started_ns, "p", "h", "cli", None).unwrap();
        let task_id = insert_task(&conn, session_id, started_ns, "t", None, "ui", None).unwrap();
        patch_task_status(&conn, task_id, TaskStatus::InProgress, started_ns).unwrap();
        let n = reap_stale_inprogress_tasks(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 0);
        let task = list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::InProgress);
    }

    #[test]
    fn inprogress_reaper_ignores_non_inprogress_tasks() {
        // A Backlog task (never started, started_ns NULL) past the
        // cut-off is NOT a leak — only InProgress rows are swept.
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let now_ns: u64 = 10 * 3600 * 1_000_000_000;
        let old_ns: u64 = now_ns - 5 * 3600 * 1_000_000_000;
        let session_id = insert_session(&conn, old_ns, "p", "h", "cli", None).unwrap();
        insert_task(&conn, session_id, old_ns, "still-backlog", None, "ui", None).unwrap();
        let n = reap_stale_inprogress_tasks(&conn, now_ns, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 0);
        let task = list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Backlog);
    }

    #[test]
    fn reaper_handles_now_smaller_than_cutoff_without_panic() {
        // Edge: a fresh-install clock that hasn't ticked yet — `now`
        // is smaller than `stale_after`. saturating_sub keeps the
        // cut-off at 0 + no rows match (every created_ns is > 0).
        let conn = open_memory_db();
        ensure_schema(&conn).unwrap();
        let _ = insert_session(&conn, 5_000, "p", "h", "cli", None).unwrap();
        let n = reap_stale_planning_sessions(&conn, 100, STALE_CUTOFF_NS).unwrap();
        assert_eq!(n, 0);
    }
}
