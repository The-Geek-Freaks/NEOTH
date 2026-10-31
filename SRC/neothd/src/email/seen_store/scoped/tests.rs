use super::*;
use crate::email::seen_store;
use crate::memory::store;

fn email(uid: &str, message_id: Option<&str>) -> InboundEmail {
    InboundEmail {
        uid: uid.to_owned(),
        from: "sender@example.com".into(),
        from_domain: "example.com".into(),
        subject: "subject".into(),
        body: "body".into(),
        attachment_filenames: vec![],
        message_id: message_id.map(str::to_owned),
        auth_results: None,
    }
}

fn identity(user: &str, mail: &InboundEmail, epoch: u32) -> Identity {
    Identity::inbox("imap.example.com", 993, user, mail, epoch).unwrap()
}

fn db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE idx_email_seen (
            dedup_key TEXT PRIMARY KEY, imap_uid TEXT, first_seen_unix INTEGER NOT NULL
        );",
    )
    .unwrap();
    conn.execute_batch(seen_store::SCOPED_SCHEMA_SQL).unwrap();
    conn
}

#[test]
fn scoped_completion_separates_accounts_hosts_ports_and_case_sensitive_users() {
    let conn = db();
    let mail = email("1", Some("<same@example.com>"));
    let alice = identity("alice", &mail, 1);
    mark(&conn, &alice, Purpose::Ingest, 100).unwrap();
    for (host, port, user) in [
        ("imap.example.com", 993, "bob"),
        ("imap.example.com", 993, "Alice"),
        ("other.example.com", 993, "alice"),
        ("imap.example.com", 1993, "alice"),
    ] {
        let other = Identity::inbox(host, port, user, &mail, 1).unwrap();
        assert_eq!(state(&conn, &other, Purpose::Ingest).unwrap(), SeenState::Unseen);
    }
    let normalized = Identity::inbox("IMAP.Example.COM.", 993, "alice", &mail, 2).unwrap();
    assert_eq!(state(&conn, &normalized, Purpose::Ingest).unwrap(), SeenState::Seen);
    let expected = crate::wal::paperless_post_receipts::mail_unit_sha256(
        "imap.example.com", 993, "alice", "message-id:<same@example.com>",
    );
    assert_eq!(alice.unit_sha256, expected);
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 0);
}

#[test]
fn scoped_uid_reuse_requires_current_epoch_and_preserves_message_id_identity() {
    let conn = db();
    let no_id = email("7", None);
    let old = identity("alice", &no_id, 11);
    mark(&conn, &old, Purpose::Ingest, 100).unwrap();
    let replacement = identity("alice", &no_id, 12);
    assert_eq!(state(&conn, &replacement, Purpose::Ingest).unwrap(), SeenState::Unseen);
    assert_eq!(identity("alice", &email("7", Some("")), 11).unit_sha256, old.unit_sha256);
    assert!(Identity::inbox("host", 993, "alice", &no_id, 0).is_err());
    assert!(Identity::inbox("host", 993, "alice", &email("", None), 1).is_err());
    for (host, port, user) in [("", 993, "a"), ("...", 993, "a"), ("host", 0, "a"), ("host", 993, "")] {
        assert!(Identity::inbox(host, port, user, &no_id, 1).is_err());
    }
    let first = identity("alice", &email("1", Some("<stable>")), 11);
    let moved = identity("alice", &email("99", Some("<stable>")), 12);
    assert_eq!(first.unit_sha256, moved.unit_sha256);
}

#[test]
fn scoped_triage_never_completes_ingest_and_ingest_never_completes_triage() {
    let conn = db();
    let id = identity("alice", &email("7", None), 11);
    mark(&conn, &id, Purpose::Triage, 100).unwrap();
    assert_eq!(state(&conn, &id, Purpose::Triage).unwrap(), SeenState::Seen);
    assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::Unseen);
    let second = identity("alice", &email("8", None), 11);
    mark(&conn, &second, Purpose::Ingest, 100).unwrap();
    assert_eq!(state(&conn, &second, Purpose::Triage).unwrap(), SeenState::Unseen);
    mark(&conn, &id, Purpose::Ingest, 200).unwrap();
    assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::Seen);
}

#[test]
fn scoped_legacy_ambiguity_survives_explicit_retriage_without_ingest_authority() {
    let conn = db();
    for mail in [email("7", None), email("8", Some("<legacy>"))] {
        seen_store::mark_seen(&conn, mail.dedup_key(), Some(&mail.uid), 10).unwrap();
        for user in ["alice", "bob"] {
            let id = identity(user, &mail, 99);
            assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::LegacyAmbiguous);
            assert!(mark(&conn, &id, Purpose::Ingest, 100).is_err());
            mark(&conn, &id, Purpose::Triage, 100).unwrap();
            assert_eq!(state(&conn, &id, Purpose::Triage).unwrap(), SeenState::Seen);
            assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::LegacyAmbiguous);
        }
    }
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 2);
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM idx_email_seen_scoped WHERE purpose='ingest'", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn scoped_query_and_write_errors_never_become_unseen_or_completed() {
    let conn = db();
    let id = identity("alice", &email("7", None), 11);
    conn.execute_batch(
        "CREATE TRIGGER fail_completion BEFORE INSERT ON idx_email_seen_scoped
         BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    ).unwrap();
    assert!(mark(&conn, &id, Purpose::Ingest, 100).is_err());
    assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::Unseen);
    conn.execute_batch(
        "DROP TRIGGER fail_completion;
         CREATE TRIGGER ignore_completion BEFORE INSERT ON idx_email_seen_scoped
         BEGIN SELECT RAISE(IGNORE); END;",
    ).unwrap();
    assert!(mark(&conn, &id, Purpose::Ingest, 100).is_err());
    assert!(mark(&conn, &id, Purpose::Triage, 100).is_err());
    conn.execute("DROP TABLE idx_email_seen_scoped", []).unwrap();
    assert!(state(&conn, &id, Purpose::Ingest).is_err());
    assert!(mark(&conn, &id, Purpose::Triage, 100).is_err());
}

#[test]
fn scoped_completion_reopens_idempotently_without_rewriting_first_timestamp() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("7", None), 11);
    {
        let conn = store::open(&path).unwrap();
        mark(&conn, &id, Purpose::Ingest, 100).unwrap();
    }
    let conn = store::open(&path).unwrap();
    assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::Seen);
    mark(&conn, &id, Purpose::Ingest, 200).unwrap();
    let rows: (i64, i64) = conn.query_row(
        "SELECT COUNT(*), MIN(first_seen_unix) FROM idx_email_seen_scoped", [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(rows, (1, 100));
}

fn old_database(path: &std::path::Path) -> Connection {
    let conn = store::open(path).unwrap();
    seen_store::mark_seen(&conn, "<legacy>", Some("7"), 10).unwrap();
    conn.execute_batch(
        "DROP TABLE idx_email_seen_scoped;
         UPDATE meta SET value='52' WHERE key='schema_version';",
    ).unwrap();
    conn
}

#[test]
fn scoped_v52_migration_preserves_legacy_bytes_without_claiming_an_account() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    drop(old_database(&path));
    let conn = store::open(&path).unwrap();
    let row: (String, String, i64) = conn.query_row(
        "SELECT dedup_key, imap_uid, first_seen_unix FROM idx_email_seen", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).unwrap();
    assert_eq!(row, ("<legacy>".into(), "7".into(), 10));
    let id = identity("alice", &email("7", Some("<legacy>")), 11);
    assert_eq!(state(&conn, &id, Purpose::Ingest).unwrap(), SeenState::LegacyAmbiguous);
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM idx_email_seen_scoped", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn scoped_v52_migration_rejects_colliding_schema_without_adopting_rows() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let conn = old_database(&path);
    conn.execute_batch("CREATE VIEW IDX_EMAIL_SEEN_SCOPED AS SELECT 1 AS value;").unwrap();
    drop(conn);
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let version: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
    assert_eq!(version, "52");
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 1);
}

#[test]
fn scoped_v52_migration_rolls_back_table_and_stamp_then_retries() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let conn = old_database(&path);
    conn.execute_batch(
        "CREATE TRIGGER fail_stamp BEFORE INSERT ON meta
         WHEN NEW.key='schema_version' AND NEW.value='53'
         BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    ).unwrap();
    drop(conn);
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='idx_email_seen_scoped'", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
    let version: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
    assert_eq!(version, "52");
    conn.execute("DROP TRIGGER fail_stamp", []).unwrap();
    drop(conn);
    let conn = store::open(&path).unwrap();
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 1);
}
