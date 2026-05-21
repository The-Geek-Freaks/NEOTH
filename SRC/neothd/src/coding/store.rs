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
use rusqlite::{Connection, OptionalExtension, params};

use super::types::{
    Hemisphere, KanbanComment, KanbanSession, KanbanSessionId, KanbanTask, KanbanTaskId,
    SessionStatus, TaskStatus, TestSummary,
};

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
    Ok(())
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
    summary        TEXT
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

    fn open_memory_db() -> Connection {
        Connection::open_in_memory().expect("open in-memory sqlite")
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
            ],
            "all three kanban tables must exist after ensure_schema"
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
            Some("alex"),
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
        assert_eq!(fetched.operator_id.as_deref(), Some("alex"));
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
}
