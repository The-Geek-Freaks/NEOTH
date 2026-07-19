//! GOLD-ADAPT-ODY-26 — Transcript FTS with before/after context rows.
//!
//! Persists every operator turn and sanitised agent turn into
//! `views.db:raw_turns` and
//! exposes FTS5 search with before/after context rows via
//! `neoth recall --transcript <query>`.
//!
//! ## Architecture
//!
//! - `raw_turns` — append-only table; one row per turn.
//! - `raw_turns_fts` — FTS5 content-linked virtual table (porter unicode61
//!   tokeniser). Kept in sync via INSERT/DELETE/UPDATE triggers (same pattern
//!   as `idx_episode_fts` in `memory/store.rs`).
//! - `insert_turn` — cheap synchronous insert called best-effort from every
//!   write site (chat.rs one-shot + serve_pipeline.rs channel handler). Never
//!   fails the caller: errors are `log::warn`-only.
//! - `search_turns` — FTS5 MATCH + BM25 ranking + per-match context-row window.
//!
//! Schema is v21 — `SCHEMA_VERSION` was bumped from 20 in `memory/store.rs`
//! and the migration is registered in `memory/migrations/mod.rs`.

use std::borrow::Cow;

use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use tracing::warn;

// ── Structs ────────────────────────────────────────────────────────────────

/// A single turn row stored in the legacy-named `raw_turns` table. Operator
/// rows are source-exact; agent rows are sanitized before new persistence and
/// again on egress for legacy databases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptRow {
    pub id: i64,
    pub session_id: String,
    /// `"operator"` or `"agent"`.
    pub role: String,
    /// Unix-seconds timestamp of the turn.
    pub ts_unix: i64,
    pub text: String,
}

/// One FTS5 hit with its before/after context rows (same session, ordered by
/// `id` which is monotonically increasing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptSearchResult {
    /// The row that matched the FTS5 query.
    pub matched: TranscriptRow,
    /// Up to N rows from the same session with `id < matched.id` (oldest
    /// first, so the natural conversation order is preserved when iterating
    /// before → matched → after).
    pub before: Vec<TranscriptRow>,
    /// Up to N rows from the same session with `id > matched.id` (oldest
    /// first).
    pub after: Vec<TranscriptRow>,
    /// BM25 rank from FTS5 (lower magnitude = better match in SQLite's
    /// negated-score convention; stored as-is for caller transparency).
    pub bm25_rank: f64,
}

// ── Write path ─────────────────────────────────────────────────────────────

/// Insert one turn into `raw_turns`. The FTS5 trigger fires automatically,
/// keeping `raw_turns_fts` in sync.
///
/// Returns the new `rowid` (`raw_turns.id`). Callers that do not need the id
/// can discard the return value.
///
/// Best-effort: callers should log-warn on error and never propagate it into
/// the main flow.
pub fn insert_turn(
    conn: &Connection,
    session_id: &str,
    role: &str,
    ts_unix: i64,
    text: &str,
) -> rusqlite::Result<i64> {
    // Operator text is the user's source record and remains byte-identical.
    // Agent text is generated/external output: strip terminal controls and
    // credentials before the FTS trigger makes it durable and searchable.
    let persisted_text = if role == "agent" {
        Cow::Owned(crate::security::redact::sanitize_tool_output(text))
    } else {
        Cow::Borrowed(text)
    };
    conn.execute(
        "INSERT INTO raw_turns (session_id, role, ts_unix, text) VALUES (?1, ?2, ?3, ?4)",
        params![session_id, role, ts_unix, persisted_text.as_ref()],
    )?;
    Ok(conn.last_insert_rowid())
}

// ── Read path ──────────────────────────────────────────────────────────────

/// Sanitise a raw query string so it is safe to pass to FTS5 MATCH.
///
/// Keeps alphanumerics, space, `_`, and `-`; strips everything else
/// (especially `"`, `*`, `(`, `)`). Every remaining term is emitted as an
/// FTS5 phrase, so bareword operators (`AND`, `OR`, `NOT`, `NEAR`) and hyphens
/// are searched literally instead of being parsed as query syntax. Tokens
/// without an alphanumeric character are dropped because they cannot produce
/// an FTS token. Adjacent phrases retain the previous implicit-AND behaviour.
fn sanitize_fts_query(q: &str) -> String {
    q.chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '-')
        .collect::<String>()
        .split_whitespace()
        .filter(|term| term.chars().any(char::is_alphanumeric))
        .map(|term| format!("\"{term}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Search `raw_turns_fts` for `query`, returning up to `limit` hits ranked by
/// BM25. Each hit includes up to `context_rows` turns before and after it
/// within the same session (ordered by `id` ascending so natural conversation
/// flow is preserved).
///
/// Returns an empty `Vec` when the query sanitises to nothing or when there
/// are no matching rows.
pub fn search_turns(
    conn: &Connection,
    query: &str,
    context_rows: usize,
    limit: usize,
) -> rusqlite::Result<Vec<TranscriptSearchResult>> {
    let clean = sanitize_fts_query(query);
    if clean.is_empty() {
        return Ok(Vec::new());
    }

    // --- Step 1: FTS5 MATCH to get matching raw_turn ids + BM25 rank.
    //
    // `raw_turns_fts` is content-linked (content='raw_turns', content_rowid='id'),
    // so `rowid` inside the FTS virtual table equals `raw_turns.id`.
    // `bm25(raw_turns_fts)` returns a negative score (lower = better); ORDER BY
    // ASC puts the best matches first.
    let effective_limit = limit.max(1);
    let mut stmt = conn.prepare(
        "SELECT r.id, r.session_id, r.role, r.ts_unix, r.text, \
                bm25(raw_turns_fts) AS rank \
         FROM raw_turns_fts \
         JOIN raw_turns AS r ON r.id = raw_turns_fts.rowid \
         WHERE raw_turns_fts MATCH ?1 \
         ORDER BY rank ASC \
         LIMIT ?2",
    )?;
    let hits: Vec<(TranscriptRow, f64)> = stmt
        .query_map(params![clean, effective_limit as i64], |row| {
            Ok((row_mapper(row)?, row.get::<_, f64>(5)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    if hits.is_empty() {
        return Ok(Vec::new());
    }

    // --- Step 2: for each matched row fetch N before + N after rows.
    let ctx_limit = context_rows as i64;

    let mut before_stmt = conn.prepare(
        "SELECT id, session_id, role, ts_unix, text \
         FROM raw_turns \
         WHERE session_id = ?1 AND id < ?2 \
         ORDER BY id DESC \
         LIMIT ?3",
    )?;

    let mut after_stmt = conn.prepare(
        "SELECT id, session_id, role, ts_unix, text \
         FROM raw_turns \
         WHERE session_id = ?1 AND id > ?2 \
         ORDER BY id ASC \
         LIMIT ?3",
    )?;

    let mut results = Vec::with_capacity(hits.len());
    for (matched, bm25_rank) in hits {
        // Before: comes back DESC (newest-to-oldest); reverse to chronological.
        let mut before: Vec<TranscriptRow> = before_stmt
            .query_map(
                params![matched.session_id, matched.id, ctx_limit],
                row_mapper,
            )?
            .collect::<rusqlite::Result<_>>()?;
        before.reverse();

        // After: already ASC (oldest-to-newest).
        let after: Vec<TranscriptRow> = after_stmt
            .query_map(
                params![matched.session_id, matched.id, ctx_limit],
                row_mapper,
            )?
            .collect::<rusqlite::Result<_>>()?;

        results.push(TranscriptSearchResult {
            matched,
            before,
            after,
            bm25_rank,
        });
    }

    Ok(results)
}

fn row_mapper(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscriptRow> {
    let role: String = row.get(2)?;
    let text: String = row.get(4)?;
    Ok(TranscriptRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        role: role.clone(),
        ts_unix: row.get(3)?,
        // Defence-in-depth for databases created before agent-turn write
        // sanitisation. The source row remains untouched; only egress is
        // filtered. Operator source text deliberately stays raw.
        text: if role == "agent" {
            crate::security::redact::sanitize_tool_output(&text)
        } else {
            text
        },
    })
}

/// Read one session's canonical visible transcript without creating or
/// migrating the database. GUI/history consumers use this instead of parsing
/// archive markdown or guessing from hindsight summaries. Agent text is
/// re-sanitised by [`row_mapper`] so legacy rows cannot leak on egress.
pub fn read_session_turns_at(
    db_path: &std::path::Path,
    session_id: &str,
) -> rusqlite::Result<Vec<TranscriptRow>> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let has_raw_turns = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'raw_turns')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !has_raw_turns {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, session_id, role, ts_unix, text \
         FROM raw_turns WHERE session_id = ?1 ORDER BY id ASC",
    )?;
    stmt.query_map([session_id], row_mapper)?.collect()
}

/// Read the latest canonical visible turn for each requested session in one
/// read-only database connection. Missing sessions are intentionally absent:
/// legacy hindsight cards predate `raw_turns` and must render an empty preview,
/// never a fabricated summary/closing utterance.
pub fn read_latest_turns_at(
    db_path: &std::path::Path,
    session_ids: &[String],
) -> rusqlite::Result<std::collections::BTreeMap<String, TranscriptRow>> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let has_raw_turns = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'raw_turns')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !has_raw_turns {
        return Ok(std::collections::BTreeMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, session_id, role, ts_unix, text \
         FROM raw_turns WHERE session_id = ?1 ORDER BY id DESC",
    )?;
    let mut out = std::collections::BTreeMap::new();
    for session_id in session_ids {
        let mut rows = stmt.query([session_id])?;
        while let Some(row) = rows.next()? {
            let candidate = row_mapper(row)?;
            // A persisted empty/ANSI-only final row is not visible UI content.
            // Match the live-preview contract by walking backwards to the
            // first row that remains non-empty after canonical sanitisation.
            if crate::security::redact::sanitize_tool_output(&candidate.text)
                .split_whitespace()
                .next()
                .is_some()
            {
                out.insert(session_id.clone(), candidate);
                break;
            }
        }
    }
    Ok(out)
}

// ── Best-effort helper used by call sites ──────────────────────────────────

/// Best-effort wrapper: inserts a turn and logs a warning on failure.
/// Never panics. Used by `cli/chat.rs` and `cli/serve_pipeline.rs` so they
/// do not need to handle the error themselves.
pub fn insert_turn_best_effort(
    conn: &Connection,
    session_id: &str,
    role: &str,
    ts_unix: i64,
    text: &str,
) {
    if let Err(e) = insert_turn(conn, session_id, role, ts_unix, text) {
        warn!(
            session_id = %session_id,
            role = %role,
            error = %e,
            "ODY-26: raw_turns insert failed (best-effort, ignoring)"
        );
    }
}

// ── Forget cascade (GDPR right-to-erasure) ─────────────────────────────────

/// Delete every raw turn whose `text` matches the `LIKE` pattern
/// (case-insensitive, `ESCAPE '\'`). The `raw_turns_ad` AFTER DELETE trigger
/// fires per row, keeping `raw_turns_fts` in sync — so `neoth recall
/// --transcript <topic>` stops surfacing the turn immediately. Returns the
/// number of turn rows deleted.
///
/// `like_pattern` is the already-built `%escaped_topic%` pattern produced by
/// `forget_by_topic` (the topic is escaped via `crate::memory::escape_like`
/// so a topic of `%`/`_` matches literally). Wired into the forget cascade in
/// `memory/forget.rs`; without it a forgotten topic stayed fully searchable in
/// the raw transcript (the ODY-26 table was added after forget.rs and never
/// cascaded — a right-to-erasure hole).
pub fn forget_turns_like(conn: &Connection, like_pattern: &str) -> rusqlite::Result<i64> {
    let n = conn.execute(
        "DELETE FROM raw_turns WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        params![like_pattern],
    )?;
    Ok(n as i64)
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn open_test_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = store::open(&path).unwrap();
        (dir, conn)
    }

    // ── GOLD-ADAPT-ODY-26 integration test ───────────────────────────────

    /// Exercises: schema creation → insert_turn trigger chain
    /// (raw_turns → raw_turns_fts auto-index) → search_turns FTS5 MATCH
    /// → context-row windowing. Structurally identical to how the CLI
    /// consumer in recall.rs invokes the same two functions — if this
    /// test is green, the CLI wire works correctly.
    #[test]
    fn recall_transcript_surfaces_match_with_before_after_context() {
        let (_dir, conn) = open_test_db();

        insert_turn(
            &conn,
            "sess-abc",
            "operator",
            100,
            "how do I configure the webhook manager",
        )
        .unwrap();
        insert_turn(
            &conn,
            "sess-abc",
            "agent",
            101,
            "set webhook.enabled to true in freedom.yaml",
        )
        .unwrap();
        insert_turn(
            &conn,
            "sess-abc",
            "operator",
            102,
            "what about the SSRF guard",
        )
        .unwrap(); // match target
        insert_turn(
            &conn,
            "sess-abc",
            "agent",
            103,
            "it blocks RFC-1918 and CGNAT ranges",
        )
        .unwrap();
        insert_turn(&conn, "sess-abc", "operator", 104, "thanks").unwrap();

        let results = search_turns(&conn, "SSRF guard", 2, 10).unwrap();
        assert_eq!(results.len(), 1, "exactly one hit for 'SSRF guard'");

        let hit = &results[0];
        assert!(
            hit.matched.text.to_lowercase().contains("ssrf"),
            "matched text must contain 'ssrf', got: {}",
            hit.matched.text
        );

        // Two context rows before (rows 1+2, older than row 3).
        assert_eq!(
            hit.before.len(),
            2,
            "expected 2 before-context rows, got: {:?}",
            hit.before.iter().map(|r| &r.text).collect::<Vec<_>>()
        );
        // Two context rows after (rows 4+5, newer than row 3).
        assert_eq!(
            hit.after.len(),
            2,
            "expected 2 after-context rows, got: {:?}",
            hit.after.iter().map(|r| &r.text).collect::<Vec<_>>()
        );

        // Before rows must be older (lower ts) than the match.
        for b in &hit.before {
            assert!(
                b.ts_unix < hit.matched.ts_unix,
                "before row ts {} must be < match ts {}",
                b.ts_unix,
                hit.matched.ts_unix
            );
        }
        // After rows must be newer (higher ts) than the match.
        for a in &hit.after {
            assert!(
                a.ts_unix > hit.matched.ts_unix,
                "after row ts {} must be > match ts {}",
                a.ts_unix,
                hit.matched.ts_unix
            );
        }
        // Before rows in chronological order (oldest first).
        if hit.before.len() >= 2 {
            assert!(
                hit.before[0].ts_unix < hit.before[1].ts_unix,
                "before rows must be chronological"
            );
        }
    }

    #[test]
    fn search_turns_returns_empty_for_blank_query() {
        let (_dir, conn) = open_test_db();
        insert_turn(&conn, "s1", "operator", 1, "hello world").unwrap();
        let r = search_turns(&conn, "   ", 2, 10).unwrap();
        assert!(r.is_empty(), "blank query must return empty");
    }

    #[test]
    fn search_turns_returns_empty_when_no_rows() {
        let (_dir, conn) = open_test_db();
        let r = search_turns(&conn, "anything", 2, 10).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn lf_p1_20_readonly_session_egress_is_ordered_and_resanitizes_legacy_agent_rows() {
        let (dir, conn) = open_test_db();
        insert_turn(&conn, "sidebar-a", "operator", 10, "first").unwrap();
        let legacy_secret = format!(
            "legacy {}",
            concat!("sk-", "proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        );
        conn.execute(
            "INSERT INTO raw_turns (session_id, role, ts_unix, text) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["sidebar-a", "agent", 11, legacy_secret],
        )
        .unwrap();
        drop(conn);

        let rows = read_session_turns_at(&dir.path().join("views.db"), "sidebar-a").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text, "first");
        assert!(rows[1].text.contains("[REDACTED:openai_key]"));
        assert!(!rows[1].text.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"));
    }

    #[test]
    fn lf_p1_20_latest_turns_keep_sessions_isolated_and_omit_legacy_missing_cards() {
        let (dir, conn) = open_test_db();
        insert_turn(&conn, "sidebar-a", "operator", 10, "A old").unwrap();
        insert_turn(&conn, "sidebar-b", "operator", 20, "B only").unwrap();
        insert_turn(&conn, "sidebar-a", "agent", 30, "A latest").unwrap();
        drop(conn);

        let ids = vec![
            "sidebar-a".to_string(),
            "sidebar-b".to_string(),
            "legacy-without-turns".to_string(),
        ];
        let latest = read_latest_turns_at(&dir.path().join("views.db"), &ids).unwrap();
        assert_eq!(latest["sidebar-a"].text, "A latest");
        assert_eq!(latest["sidebar-b"].text, "B only");
        assert!(!latest.contains_key("legacy-without-turns"));
    }

    #[test]
    fn lf_p1_20_latest_turns_skip_empty_and_control_only_tail_rows() {
        let (dir, conn) = open_test_db();
        insert_turn(&conn, "sidebar-a", "operator", 10, "visible operator turn").unwrap();
        insert_turn(&conn, "sidebar-a", "agent", 20, "   \n\t").unwrap();
        insert_turn(&conn, "sidebar-a", "agent", 30, "\u{1b}[31m\u{1b}[0m").unwrap();
        drop(conn);

        let latest =
            read_latest_turns_at(&dir.path().join("views.db"), &["sidebar-a".to_string()]).unwrap();
        assert_eq!(latest["sidebar-a"].text, "visible operator turn");
        assert_eq!(latest["sidebar-a"].ts_unix, 10);
    }

    #[test]
    fn lf_p1_20_readonly_legacy_database_without_raw_turns_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        Connection::open(&path).unwrap();
        assert!(read_session_turns_at(&path, "legacy").unwrap().is_empty());
        assert!(
            read_latest_turns_at(&path, &["legacy".to_string()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn search_turns_context_capped_by_available_rows() {
        let (_dir, conn) = open_test_db();
        // Only one row total — match it, expect 0 before + 0 after.
        insert_turn(&conn, "s2", "operator", 200, "unique term zorbaxylite").unwrap();
        let results = search_turns(&conn, "zorbaxylite", 2, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].before.is_empty(), "no before rows");
        assert!(results[0].after.is_empty(), "no after rows");
    }

    #[test]
    fn search_turns_respects_session_boundary_for_context() {
        let (_dir, conn) = open_test_db();
        // Two sessions; context rows must not cross the session boundary.
        insert_turn(&conn, "sess-A", "operator", 10, "session A row 1").unwrap();
        insert_turn(&conn, "sess-A", "agent", 11, "session A row 2").unwrap();
        insert_turn(
            &conn,
            "sess-B",
            "operator",
            12,
            "session B unique target quux",
        )
        .unwrap();
        insert_turn(&conn, "sess-B", "agent", 13, "session B row 2").unwrap();

        let results = search_turns(&conn, "quux", 5, 10).unwrap();
        assert_eq!(results.len(), 1);
        let hit = &results[0];
        // Before context must only contain sess-B rows (none available before this row).
        assert!(
            hit.before.iter().all(|r| r.session_id == "sess-B"),
            "before context must not cross session boundary"
        );
    }

    #[test]
    fn insert_turn_fts_is_searchable_immediately() {
        let (_dir, conn) = open_test_db();
        insert_turn(
            &conn,
            "s3",
            "agent",
            500,
            "the FTS5 trigger fires immediately",
        )
        .unwrap();
        let r = search_turns(&conn, "trigger fires", 0, 5).unwrap();
        assert_eq!(r.len(), 1, "FTS index must be available right after insert");
    }

    #[test]
    fn agent_turn_is_sanitized_before_persistence_and_remains_searchable() {
        let (_dir, conn) = open_test_db();
        let secret = concat!("sk-", "FAKE_TEST_TRANSCRIPT_AAAAAAAAAAAAAA");
        let colored = format!("useful diagnosis sk-\x1b[31m{}\x1b[0m", &secret[3..]);

        let id = insert_turn(&conn, "safe-agent", "agent", 501, &colored).unwrap();
        let stored: String = conn
            .query_row("SELECT text FROM raw_turns WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(stored.contains("useful diagnosis"), "{stored}");
        assert!(stored.contains("[REDACTED:openai_key]"), "{stored}");
        assert!(!stored.contains(secret), "{stored}");
        assert!(!stored.contains('\x1b'), "{stored:?}");

        let hits = search_turns(&conn, "useful diagnosis", 0, 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched.text, stored);
    }

    #[test]
    fn operator_turn_remains_byte_identical_in_source_store() {
        let (_dir, conn) = open_test_db();
        let operator_text = concat!(
            "operator supplied sk-",
            "FAKE_TEST_OPERATOR_AAAAAAAAAAAAAA\x1b[31m verbatim"
        );
        let id = insert_turn(&conn, "raw-operator", "operator", 502, operator_text).unwrap();
        let stored: String = conn
            .query_row("SELECT text FROM raw_turns WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(stored, operator_text);
        let hits = search_turns(&conn, "operator supplied", 0, 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched.text, operator_text);
    }

    #[test]
    fn legacy_agent_row_is_sanitized_on_egress_without_rewriting_source() {
        let (_dir, conn) = open_test_db();
        let secret = concat!("sk-", "FAKE_TEST_LEGACY_AAAAAAAAAAAAAAAAA");
        let legacy = format!("legacy searchable sk-\x1b[36m{}\x1b[0m", &secret[3..]);
        conn.execute(
            "INSERT INTO raw_turns (session_id, role, ts_unix, text) VALUES (?1, 'agent', 503, ?2)",
            params!["legacy-agent", legacy],
        )
        .unwrap();

        let hits = search_turns(&conn, "legacy searchable", 0, 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].matched.text.contains("[REDACTED:openai_key]"));
        assert!(!hits[0].matched.text.contains(secret));
        assert!(!hits[0].matched.text.contains('\x1b'));

        let stored: String = conn
            .query_row(
                "SELECT text FROM raw_turns WHERE session_id = 'legacy-agent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, legacy, "legacy source row must not be rewritten");
    }

    #[test]
    fn insert_turn_best_effort_does_not_panic_on_bad_role() {
        // role CHECK constraint will reject an invalid value — best-effort must
        // not propagate or panic.
        let (_dir, conn) = open_test_db();
        // This will be rejected by the CHECK(role IN ('operator','agent')) constraint.
        // best-effort wrapper must swallow it.
        insert_turn_best_effort(&conn, "s4", "invalid_role", 0, "text");
        // If we reach here without panic the test passes.
    }

    #[test]
    fn sanitize_strips_fts_special_chars() {
        let clean = sanitize_fts_query("hello \"world\" AND (foo OR bar)*");
        // User-provided syntax is removed; generated quotes make every token
        // literal, including FTS5's uppercase bareword operators.
        assert!(!clean.contains('*'));
        assert!(!clean.contains('('));
        assert!(!clean.contains(')'));
        assert_eq!(clean, "\"hello\" \"world\" \"AND\" \"foo\" \"OR\" \"bar\"");
    }

    #[test]
    fn fts_bareword_operators_and_hyphens_never_raise_match_errors() {
        let (_dir, conn) = open_test_db();
        insert_turn(
            &conn,
            "fts-operators",
            "operator",
            1,
            "not near foo and bar alpha beta",
        )
        .unwrap();

        for query in ["NOT", "OR", "NEAR", "foo AND", "alpha-beta", "-"] {
            let result = search_turns(&conn, query, 0, 10);
            assert!(
                result.is_ok(),
                "query {query:?} must not reach FTS as syntax: {result:?}"
            );
        }
        assert!(
            search_turns(&conn, "-", 0, 10).unwrap().is_empty(),
            "a punctuation-only query sanitises to an empty result"
        );
    }
}
