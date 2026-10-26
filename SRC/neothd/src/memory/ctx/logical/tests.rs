use super::*;
use crate::memory::{ctx, store};
use rusqlite::types::Value as SqlValue;
use serde_json::{Value, json};

fn wire(doc: &str, event: &str, label: &str, content: &str, epoch: i64) -> Value {
    json!({"action":"register","logical_document_id":doc,"logical_event_id":event,
        "authorization_epoch":epoch,"index":{"label":label,"content":content,
        "file_path":"old/document.md","source_category":"documents"}})
}

fn effect(conn: &mut Connection, request: &Value) -> Result<LogicalReport> {
    apply(conn, &serde_json::to_vec(request).unwrap())
}

fn guard(report: &LogicalReport) -> Value {
    json!({"source_id":report.source_id,"content_revision_id":report.content_revision_id,
        "current_event_id":report.current_event_id})
}

fn revise(report: &LogicalReport, event: &str, content: &str) -> Value {
    let mut value = wire(
        &report.logical_document_id,
        event,
        &report.label,
        content,
        report.authorization_epoch,
    );
    value["action"] = json!("revise");
    value["expected"] = guard(report);
    value
}

fn rename(report: &LogicalReport, event: &str, label: &str) -> Value {
    json!({"action":"metadata_rename","logical_document_id":report.logical_document_id,
        "logical_event_id":event,"authorization_epoch":report.authorization_epoch,
        "expected":guard(report),"new_label":label,"new_file_path":"moved/document.md"})
}

fn rows(conn: &Connection, query: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = conn.prepare(query).unwrap();
    let count = stmt.column_count();
    stmt.query_map([], |row| {
        (0..count)
            .map(|column| row.get(column))
            .collect::<rusqlite::Result<Vec<SqlValue>>>()
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

fn snapshot(conn: &Connection) -> Vec<Vec<Vec<SqlValue>>> {
    [
        "sources",
        "chunks",
        "chunks_trigram",
        "vocabulary",
        "logical_documents",
        "logical_document_events",
        "ctx_logical_state",
        "sqlite_sequence",
    ]
    .iter()
    .map(|table| rows(conn, &format!("SELECT * FROM {table} ORDER BY rowid")))
    .collect()
}

#[test]
fn logical_register_revise_rename_and_historical_replay_keep_one_current_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("views.db");
    let mut conn = store::open(&path).unwrap();
    let registration = wire("doc", "registered", "manual", "obsoletequartz", 0);
    let first = effect(&mut conn, &registration).unwrap();
    let before_replay = snapshot(&conn);
    let replayed = effect(&mut conn, &registration).unwrap();
    assert!(replayed.replayed && replayed.is_current);
    assert_eq!(replayed.source_id, first.source_id);
    assert_eq!(snapshot(&conn), before_replay);

    let revision = revise(&first, "revised", "currentzircon");
    let second = effect(&mut conn, &revision).unwrap();
    assert_ne!(second.source_id, first.source_id);
    assert_ne!(second.content_revision_id, first.content_revision_id);
    assert!(ctx::search(&conn, "obsoletequartz", 10).unwrap().is_empty());
    assert_eq!(ctx::search(&conn, "currentzircon", 10).unwrap().len(), 1);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM sources", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM vocabulary WHERE term='obsoletequartz'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let historical = effect(&mut conn, &registration).unwrap();
    assert!(historical.replayed && !historical.is_current);
    assert_eq!(historical.source_id, first.source_id);
    assert_eq!(historical.current_event_id, "revised");

    let before_bodies = rows(
        &conn,
        "SELECT rowid,source_id,content FROM chunks ORDER BY rowid",
    );
    let before_trigrams = rows(
        &conn,
        "SELECT rowid,source_id,content FROM chunks_trigram ORDER BY rowid",
    );
    let before_vocab = rows(&conn, "SELECT * FROM vocabulary ORDER BY term");
    let moved = effect(&mut conn, &rename(&second, "moved", "manual-renamed")).unwrap();
    assert_eq!(moved.source_id, second.source_id);
    assert_eq!(moved.content_revision_id, second.content_revision_id);
    assert_eq!(moved.previous_label.as_deref(), Some("manual"));
    assert_eq!(moved.previous_file_path.as_deref(), Some("old/document.md"));
    assert_eq!(
        rows(
            &conn,
            "SELECT rowid,source_id,content FROM chunks ORDER BY rowid"
        ),
        before_bodies
    );
    assert_eq!(
        rows(
            &conn,
            "SELECT rowid,source_id,content FROM chunks_trigram ORDER BY rowid"
        ),
        before_trigrams
    );
    assert_eq!(
        rows(&conn, "SELECT * FROM vocabulary ORDER BY term"),
        before_vocab
    );
    for table in ["chunks", "chunks_trigram"] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT count(*) FROM {table} WHERE file_path='moved/document.md'"),
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            second.chunk_count as i64
        );
    }
    let historical = effect(&mut conn, &revision).unwrap();
    assert!(historical.replayed && !historical.is_current);
    assert_eq!(historical.current_event_id, "moved");
    drop(conn);
    let conn = store::open(&path).unwrap();
    let reopened = status(&conn, "doc").unwrap().unwrap();
    assert_eq!(reopened.current_event_id, "moved");
    assert_eq!(reopened.label, "manual-renamed");
    assert_eq!(
        conn.query_row("SELECT count(*) FROM logical_document_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn logical_conflicting_event_label_and_legacy_replacement_preserve_every_projection() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let registration = wire("doc", "registered", "manual", "retainedquartz", 0);
    let first = effect(&mut conn, &registration).unwrap();
    effect(
        &mut conn,
        &wire("other", "other-event", "occupied", "otherzircon", 0),
    )
    .unwrap();
    let before = snapshot(&conn);
    let mut changed_event = registration.clone();
    changed_event["index"]["file_path"] = json!("different/path");
    let mut changed_owner = registration.clone();
    changed_owner["logical_document_id"] = json!("third");
    let mut colliding_revision = revise(&first, "collision", "newtext");
    colliding_revision["index"]["label"] = json!("occupied");
    for request in [
        changed_event,
        changed_owner,
        colliding_revision,
        rename(&first, "rename-collision", "occupied"),
    ] {
        assert!(effect(&mut conn, &request).is_err());
        assert_eq!(snapshot(&conn), before);
    }
    let legacy = ctx::IndexRequest {
        label: "manual".into(),
        content: "unauthorized replacement".into(),
        file_path: None,
        content_type: "prose".into(),
        source_category: None,
        event_id: None,
        document_provenance: None,
    };
    assert!(ctx::index_document(&mut conn, &legacy).is_err());
    assert_eq!(snapshot(&conn), before);
}

#[test]
fn logical_two_connections_reject_stale_guard_even_when_content_revision_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("views.db");
    let mut left = store::open(&path).unwrap();
    let mut right = store::open(&path).unwrap();
    let first = effect(
        &mut left,
        &wire("doc", "registered", "manual", "same content", 0),
    )
    .unwrap();
    let first_rename = rename(&first, "first-move", "moved");
    let second_rename = rename(&first, "second-move", "stale");
    let moved = effect(&mut left, &first_rename).unwrap();
    assert_eq!(moved.source_id, first.source_id);
    assert_eq!(moved.content_revision_id, first.content_revision_id);
    let before = snapshot(&left);
    let error = effect(&mut right, &second_rename).unwrap_err().to_string();
    assert!(error.contains("current-state guard"), "{error}");
    assert_eq!(snapshot(&right), before);
    assert_eq!(
        status(&right, "doc").unwrap().unwrap().current_event_id,
        "first-move"
    );
}

#[test]
fn logical_receipt_and_rename_failures_roll_back_source_fts_vocabulary_and_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let first = effect(
        &mut conn,
        &wire("doc", "registered", "manual", "retainedquartz", 0),
    )
    .unwrap();
    let before = snapshot(&conn);
    conn.execute_batch(
        "CREATE TRIGGER refuse_logical_receipt BEFORE INSERT ON logical_document_events
         BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;",
    )
    .unwrap();
    let error = effect(
        &mut conn,
        &revise(&first, "failed-revision", "replacedzircon"),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("injected receipt failure"),
        "{error:#}"
    );
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch(
        "DROP TRIGGER refuse_logical_receipt;
        CREATE TRIGGER refuse_logical_move BEFORE UPDATE OF current_event_id ON logical_documents
        BEGIN SELECT RAISE(ABORT,'injected move failure'); END;",
    )
    .unwrap();
    let error = effect(&mut conn, &rename(&first, "failed-move", "moved")).unwrap_err();
    assert!(
        error.to_string().contains("injected move failure"),
        "{error:#}"
    );
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch("DROP TRIGGER refuse_logical_move")
        .unwrap();
    let accepted = effect(
        &mut conn,
        &revise(&first, "failed-revision", "replacedzircon"),
    )
    .unwrap();
    assert!(!accepted.replayed);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM logical_document_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn logical_source_category_and_all_purge_reject_old_replay_without_resurrection() {
    for mode in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        let registration = wire("doc", "registered", "manual", "retainedquartz", 0);
        effect(&mut conn, &registration).unwrap();
        let scope = match mode {
            0 => ctx::PurgeScope::Source("manual"),
            1 => ctx::PurgeScope::Category("documents"),
            _ => ctx::PurgeScope::All,
        };
        assert_eq!(ctx::purge(&mut conn, scope).unwrap(), 1);
        assert_eq!(epoch(&conn).unwrap(), 1);
        assert!(status(&conn, "doc").unwrap().is_none());
        for table in [
            "sources",
            "chunks",
            "chunks_trigram",
            "vocabulary",
            "logical_documents",
            "logical_document_events",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let purged = snapshot(&conn);
        let error = effect(&mut conn, &registration).unwrap_err().to_string();
        assert!(
            error.contains("stale logical authorization epoch"),
            "{error}"
        );
        assert_eq!(snapshot(&conn), purged);
        assert_eq!(ctx::purge(&mut conn, ctx::PurgeScope::All).unwrap(), 0);
        assert_eq!(epoch(&conn).unwrap(), 1);
    }
}

#[test]
fn logical_purge_epoch_write_failure_and_exhaustion_roll_back_all_deleted_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    effect(
        &mut conn,
        &wire("doc", "registered", "manual", "retainedquartz", 0),
    )
    .unwrap();
    let before = snapshot(&conn);
    conn.execute_batch(
        "CREATE TRIGGER refuse_logical_epoch BEFORE UPDATE ON ctx_logical_state
        BEGIN SELECT RAISE(ABORT,'injected epoch failure'); END;",
    )
    .unwrap();
    assert!(ctx::purge(&mut conn, ctx::PurgeScope::All).is_err());
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch("DROP TRIGGER refuse_logical_epoch")
        .unwrap();
    conn.execute("UPDATE ctx_logical_state SET epoch=?1", [i64::MAX])
        .unwrap();
    let exhausted = snapshot(&conn);
    assert!(ctx::purge(&mut conn, ctx::PurgeScope::Source("manual")).is_err());
    assert_eq!(snapshot(&conn), exhausted);
}
