use super::*;
use crate::email::seen_store;
use crate::memory::store;

fn email(uid: &str, message_id: Option<&str>) -> InboundEmail {
    InboundEmail {
        uid: uid.to_owned(),
        from: "sender@example.com".into(),
        from_domain: Some("example.com".into()),
        subject: "subject".into(),
        body: "body".into(),
        attachment_filenames: vec![],
        message_id: message_id.map(str::to_owned),
        auth_results: None,
    }
}

fn target_context() -> DeliveryContext {
    DeliveryContext::new(
        Some("/vault"),
        "NEOTH",
        Some("https://paperless.example"),
        true,
        true,
    )
    .unwrap()
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
fn vault_receipt_context_distinguishes_legacy_absent_replaced_and_exact_directory() {
    for legacy in [true, false] {
        let conn = db();
        let mail = email("1", Some("<vault@example.com>"));
        let unit = identity("alice", &mail, 1);
        let fingerprint = "a".repeat(64);
        let previous = if legacy { target_context() } else { target_context().with_vault_directory(Some(&fingerprint)).unwrap() };
        mark(&conn, &unit, Completion::Delivery(&previous), 100).unwrap();
        let current = target_context().with_vault_directory(Some(&fingerprint)).unwrap();
        assert_eq!(state(&conn, &unit, Purpose::Ingest, Some(&current)).unwrap(), if legacy { SeenState::ContextConflict } else { SeenState::Seen });
        for observed in [None, Some("b".repeat(64))] {
            let changed = target_context().with_vault_directory(observed.as_deref()).unwrap();
            assert_eq!(state(&conn, &unit, Purpose::Ingest, Some(&changed)).unwrap(), SeenState::ContextConflict);
        }
    }
    assert!(target_context().with_vault_directory(Some("invalid")).is_err());
}

#[test]
fn authenticated_paperless_context_never_reopens_legacy_or_other_principal_delivery() {
    let endpoint = "https://paperless.example/api/documents/post_document/";
    for legacy in [true, false] {
        let conn = db();
        let mail = email("1", Some("<principal@example.com>"));
        let unit = identity("alice", &mail, 1);
        let previous = if legacy {
            target_context()
        } else {
            target_context()
                .with_authenticated_paperless_principal(endpoint, 17)
                .unwrap()
        };
        mark(&conn, &unit, Completion::Delivery(&previous), 100).unwrap();
        let matching = target_context()
            .with_authenticated_paperless_principal(endpoint, 17)
            .unwrap();
        assert_eq!(
            state(&conn, &unit, Purpose::Ingest, Some(&matching)).unwrap(),
            if legacy {
                SeenState::ContextConflict
            } else {
                SeenState::Seen
            }
        );
        let other = target_context()
            .with_authenticated_paperless_principal(endpoint, 29)
            .unwrap();
        assert_eq!(
            state(&conn, &unit, Purpose::Ingest, Some(&other)).unwrap(),
            SeenState::ContextConflict
        );
        assert!(mark(&conn, &unit, Completion::Delivery(&other), 101).is_err());
        assert_eq!(
            state(&conn, &unit, Purpose::Ingest, Some(&previous)).unwrap(),
            SeenState::Seen
        );
    }
    assert!(
        target_context()
            .with_authenticated_paperless_principal(endpoint, 0)
            .is_err()
    );
}

#[test]
fn scoped_completion_separates_accounts_hosts_ports_and_case_sensitive_users() {
    let conn = db();
    let mail = email("1", Some("<same@example.com>"));
    let alice = identity("alice", &mail, 1);
    mark(&conn, &alice, Completion::Delivery(&target_context()), 100).unwrap();
    for (host, port, user) in [
        ("imap.example.com", 993, "bob"),
        ("imap.example.com", 993, "Alice"),
        ("other.example.com", 993, "alice"),
        ("imap.example.com", 1993, "alice"),
    ] {
        let other = Identity::inbox(host, port, user, &mail, 1).unwrap();
        assert_eq!(
            state(&conn, &other, Purpose::Ingest, Some(&target_context())).unwrap(),
            SeenState::Unseen
        );
    }
    let normalized = Identity::inbox("IMAP.Example.COM.", 993, "alice", &mail, 2).unwrap();
    assert_eq!(
        state(&conn, &normalized, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Seen
    );
    let expected = crate::wal::paperless_post_receipts::mail_unit_sha256(
        "imap.example.com",
        993,
        "alice",
        "message-id:<same@example.com>",
    );
    assert_eq!(alice.unit_sha256, expected);
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 0);
}

#[test]
fn scoped_uid_reuse_requires_current_epoch_and_preserves_message_id_identity() {
    let conn = db();
    let no_id = email("7", None);
    let old = identity("alice", &no_id, 11);
    mark(&conn, &old, Completion::Delivery(&target_context()), 100).unwrap();
    let replacement = identity("alice", &no_id, 12);
    assert_eq!(
        state(
            &conn,
            &replacement,
            Purpose::Ingest,
            Some(&target_context())
        )
        .unwrap(),
        SeenState::Unseen
    );
    assert_eq!(
        identity("alice", &email("7", Some("")), 11).unit_sha256,
        old.unit_sha256
    );
    assert!(Identity::inbox("host", 993, "alice", &no_id, 0).is_err());
    assert!(Identity::inbox("host", 993, "alice", &email("", None), 1).is_err());
    for (host, port, user) in [
        ("", 993, "a"),
        ("...", 993, "a"),
        ("host", 0, "a"),
        ("host", 993, ""),
    ] {
        assert!(Identity::inbox(host, port, user, &no_id, 1).is_err());
    }
    let first = identity("alice", &email("1", Some("<stable>")), 11);
    let moved = identity("alice", &email("99", Some("<stable>")), 12);
    assert_eq!(first.unit_sha256, moved.unit_sha256);
    assert_eq!(first.input_sha256, moved.input_sha256);
    mark(&conn, &first, Completion::Delivery(&target_context()), 200).unwrap();
    assert_eq!(
        state(&conn, &moved, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Seen
    );
}

#[test]
fn scoped_triage_never_completes_ingest_and_ingest_never_completes_triage() {
    let conn = db();
    let id = identity("alice", &email("7", None), 11);
    mark(&conn, &id, Completion::Triage, 100).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Triage, None).unwrap(),
        SeenState::Seen
    );
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Unseen
    );
    let second = identity("alice", &email("8", None), 11);
    mark(&conn, &second, Completion::Delivery(&target_context()), 100).unwrap();
    assert_eq!(
        state(&conn, &second, Purpose::Triage, None).unwrap(),
        SeenState::Unseen
    );
    mark(&conn, &id, Completion::Delivery(&target_context()), 200).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Seen
    );
}

#[test]
fn scoped_legacy_ambiguity_survives_explicit_retriage_without_ingest_authority() {
    let conn = db();
    for mail in [email("7", None), email("8", Some("<legacy>"))] {
        seen_store::mark_seen(&conn, mail.dedup_key(), Some(&mail.uid), 10).unwrap();
        for user in ["alice", "bob"] {
            let id = identity(user, &mail, 99);
            assert_eq!(
                state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
                SeenState::LegacyAmbiguous
            );
            assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 100).is_err());
            mark(&conn, &id, Completion::Triage, 100).unwrap();
            assert_eq!(
                state(&conn, &id, Purpose::Triage, None).unwrap(),
                SeenState::Seen
            );
            assert_eq!(
                state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
                SeenState::LegacyAmbiguous
            );
        }
    }
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 2);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_email_seen_scoped WHERE purpose='ingest'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn scoped_query_and_write_errors_never_become_unseen_or_completed() {
    let conn = db();
    let id = identity("alice", &email("7", None), 11);
    conn.execute_batch(
        "CREATE TRIGGER fail_completion BEFORE INSERT ON idx_email_seen_scoped
         BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    )
    .unwrap();
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 100).is_err());
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Unseen
    );
    conn.execute_batch(
        "DROP TRIGGER fail_completion;
         CREATE TRIGGER ignore_completion BEFORE INSERT ON idx_email_seen_scoped
         BEGIN SELECT RAISE(IGNORE); END;",
    )
    .unwrap();
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 100).is_err());
    assert!(mark(&conn, &id, Completion::Triage, 100).is_err());
    conn.execute_batch(
        "DROP TRIGGER ignore_completion;
         CREATE TRIGGER alter_completion AFTER INSERT ON idx_email_seen_scoped
         WHEN NEW.purpose='ingest'
         BEGIN UPDATE idx_email_seen_scoped SET context_sha256=printf('%064d',0)
         WHERE unit_sha256=NEW.unit_sha256 AND purpose=NEW.purpose; END;",
    )
    .unwrap();
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 100).is_err());
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::ContextConflict
    );
    conn.execute("DROP TABLE idx_email_seen_scoped", [])
        .unwrap();
    assert!(state(&conn, &id, Purpose::Ingest, Some(&target_context())).is_err());
    assert!(mark(&conn, &id, Completion::Triage, 100).is_err());
}

#[test]
fn scoped_completion_reopens_idempotently_without_rewriting_first_timestamp() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("7", None), 11);
    {
        let conn = store::open(&path).unwrap();
        mark(&conn, &id, Completion::Delivery(&target_context()), 100).unwrap();
    }
    let conn = store::open(&path).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Seen
    );
    mark(&conn, &id, Completion::Delivery(&target_context()), 200).unwrap();
    let rows: (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), MIN(first_seen_unix) FROM idx_email_seen_scoped",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (1, 100));
}

fn old_database(path: &std::path::Path) -> Connection {
    let conn = store::open(path).unwrap();
    seen_store::mark_seen(&conn, "<legacy>", Some("7"), 10).unwrap();
    conn.execute_batch(
        "DROP TABLE idx_email_seen_scoped;
         UPDATE meta SET value='52' WHERE key='schema_version';",
    )
    .unwrap();
    conn
}

#[test]
fn scoped_v52_migration_preserves_legacy_bytes_without_claiming_an_account() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    drop(old_database(&path));
    let conn = store::open(&path).unwrap();
    let row: (String, String, i64) = conn
        .query_row(
            "SELECT dedup_key, imap_uid, first_seen_unix FROM idx_email_seen",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("<legacy>".into(), "7".into(), 10));
    let id = identity("alice", &email("7", Some("<legacy>")), 11);
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::LegacyAmbiguous
    );
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM idx_email_seen_scoped", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn scoped_v52_migration_rejects_colliding_schema_without_adopting_rows() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let conn = old_database(&path);
    conn.execute_batch("CREATE VIEW IDX_EMAIL_SEEN_SCOPED AS SELECT 1 AS value;")
        .unwrap();
    drop(conn);
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
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
    )
    .unwrap();
    drop(conn);
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='idx_email_seen_scoped'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, "52");
    conn.execute("DROP TRIGGER fail_stamp", []).unwrap();
    drop(conn);
    let conn = store::open(&path).unwrap();
    assert_eq!(seen_store::seen_count(&conn).unwrap(), 1);
}

#[test]
fn input_bound_completion_rejects_every_changed_field_without_rewriting() {
    let conn = db();
    let mut original = email("1", Some("<input@example.com>"));
    original.body = format!("{}a", "x".repeat(512));
    original.attachment_filenames = vec!["a.txt".into(), "b.txt".into()];
    let id = identity("alice", &original, 1);
    mark(&conn, &id, Completion::Delivery(&target_context()), 100).unwrap();
    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.from = "other@example.com".into();
    variants.push(changed);
    let mut changed = original.clone();
    changed.from_domain = None;
    variants.push(changed);
    let mut changed = original.clone();
    changed.from_domain = Some("other.example".into());
    variants.push(changed);
    let mut changed = original.clone();
    changed.subject.push_str(" changed");
    variants.push(changed);
    let mut changed = original.clone();
    changed.body = format!("{}b", "x".repeat(512));
    variants.push(changed);
    let mut changed = original.clone();
    changed.attachment_filenames.reverse();
    variants.push(changed);
    let mut changed = original.clone();
    changed.attachment_filenames.push("c.txt".into());
    variants.push(changed);
    let mut changed = original.clone();
    changed.auth_results = Some("mx.example; dkim=pass".into());
    variants.push(changed);
    for changed in variants {
        let other = identity("alice", &changed, 1);
        assert_eq!(other.unit_sha256, id.unit_sha256);
        assert_ne!(other.input_sha256, id.input_sha256);
        assert_eq!(
            state(&conn, &other, Purpose::Ingest, Some(&target_context())).unwrap(),
            SeenState::InputConflict
        );
        assert!(mark(&conn, &other, Completion::Delivery(&target_context()), 200).is_err());
        assert_eq!(
            state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
            SeenState::Seen
        );
    }
    let row: (String, i64) = conn.query_row(
        "SELECT input_sha256, first_seen_unix FROM idx_email_seen_scoped WHERE purpose='ingest'",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!(row, (id.input_sha256, 100));
}

fn schema_53_fixture(path: &std::path::Path, unit: &str) {
    let conn = store::open(path).unwrap();
    conn.execute_batch(
        "ALTER TABLE idx_email_seen_scoped DROP COLUMN context_sha256;
         ALTER TABLE idx_email_seen_scoped DROP COLUMN completion_kind;
         ALTER TABLE idx_email_seen_scoped DROP COLUMN input_sha256;
         UPDATE meta SET value='53' WHERE key='schema_version';",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO idx_email_seen_scoped (unit_sha256,purpose,first_seen_unix)
         VALUES (?1,'ingest',100)",
        [unit],
    )
    .unwrap();
}

#[test]
fn input_v53_migration_preserves_unbound_rows_and_rejects_invalid_digests() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<legacy-input>")), 1);
    schema_53_fixture(&path, &id.unit_sha256);
    let conn = store::open(&path).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::LegacyAmbiguous
    );
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 200).is_err());
    mark(&conn, &id, Completion::Triage, 300).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Triage, None).unwrap(),
        SeenState::Seen
    );
    for invalid in [
        "".to_string(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        format!("{}z", "a".repeat(63)),
    ] {
        assert!(
            conn.execute(
                "UPDATE idx_email_seen_scoped SET input_sha256=?1 WHERE purpose='ingest'",
                [invalid],
            )
            .is_err()
        );
    }
    let row: (String, i64, Option<String>) = conn.query_row(
        "SELECT (SELECT value FROM meta WHERE key='schema_version'),first_seen_unix,input_sha256
         FROM idx_email_seen_scoped WHERE unit_sha256=?1 AND purpose='ingest'",
        [&id.unit_sha256], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!(row, (store::SCHEMA_VERSION.to_string(), 100, None));
}

#[test]
fn input_v53_column_collision_preserves_version_and_rows() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<collision>")), 1);
    {
        let conn = store::open(&path).unwrap();
        mark(&conn, &id, Completion::Delivery(&target_context()), 100).unwrap();
        conn.execute("UPDATE meta SET value='53' WHERE key='schema_version'", [])
            .unwrap();
    }
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let row: (String, i64, String) = conn.query_row(
        "SELECT (SELECT value FROM meta WHERE key='schema_version'),first_seen_unix,input_sha256
         FROM idx_email_seen_scoped WHERE unit_sha256=?1 AND purpose='ingest'",
        [&id.unit_sha256], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!(row, ("53".into(), 100, id.input_sha256));
}

#[test]
fn input_v53_stamp_failure_rolls_back_column_and_retries_without_adoption() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<rollback>")), 1);
    schema_53_fixture(&path, &id.unit_sha256);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_version_54 BEFORE INSERT ON meta
             WHEN NEW.key='schema_version' AND NEW.value='54'
             BEGIN SELECT RAISE(ABORT,'fixture'); END;",
        )
        .unwrap();
    }
    assert!(store::open(&path).is_err());
    {
        let conn = Connection::open(&path).unwrap();
        let row: (String,i64) = conn.query_row(
            "SELECT (SELECT value FROM meta WHERE key='schema_version'),
             (SELECT COUNT(*) FROM pragma_table_info('idx_email_seen_scoped') WHERE name='input_sha256')",
            [], |r| Ok((r.get(0)?,r.get(1)?)),
        ).unwrap();
        assert_eq!(row, ("53".into(), 0));
        conn.execute_batch("DROP TRIGGER fail_version_54;").unwrap();
    }
    let conn = store::open(&path).unwrap();
    let row: (String, i64, Option<String>) = conn.query_row(
        "SELECT (SELECT value FROM meta WHERE key='schema_version'),first_seen_unix,input_sha256
         FROM idx_email_seen_scoped WHERE unit_sha256=?1 AND purpose='ingest'",
        [&id.unit_sha256], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!(row, (store::SCHEMA_VERSION.to_string(), 100, None));
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 200).is_err());
}

#[test]
fn input_conflicting_concurrent_marks_cannot_adopt_the_winner() {
    use std::sync::{Arc, Barrier};
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    drop(store::open(&path).unwrap());
    let first = email("1", Some("<race>"));
    let mut second = first.clone();
    second.body.push_str(" changed");
    let first_id = identity("alice", &first, 1);
    let second_id = identity("alice", &second, 1);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [
        (identity("alice", &first, 1), 100_i64),
        (identity("alice", &second, 1), 200_i64),
    ]
    .into_iter()
    .map(|(id, timestamp)| {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let conn = Connection::open(path).unwrap();
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            barrier.wait();
            mark(
                &conn,
                &id,
                Completion::Delivery(&target_context()),
                timestamp,
            )
            .is_ok()
        })
    })
    .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|success| **success).count(), 1);
    let (winner, loser, timestamp) = if results[0] {
        (&first_id, &second_id, 100)
    } else {
        (&second_id, &first_id, 200)
    };
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        state(&conn, winner, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::Seen
    );
    assert_eq!(
        state(&conn, loser, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::InputConflict
    );
    let row: (String, i64) = conn
        .query_row(
            "SELECT input_sha256,first_seen_unix FROM idx_email_seen_scoped WHERE purpose='ingest'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, (winner.input_sha256.clone(), timestamp));
}

#[test]
fn delivery_target_drift_keeps_original_completion_without_adoption() {
    let conn = db();
    let id = identity("alice", &email("1", Some("<targets>")), 1);
    let original = target_context();
    mark(&conn, &id, Completion::Delivery(&original), 100).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&original)).unwrap(),
        SeenState::Seen
    );
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, None).unwrap(),
        SeenState::ContextConflict
    );
    let variants = [
        DeliveryContext::new(
            Some("/other"),
            "NEOTH",
            Some("https://paperless.example"),
            true,
            true,
        )
        .unwrap(),
        DeliveryContext::new(None, "NEOTH", Some("https://paperless.example"), true, true).unwrap(),
        DeliveryContext::new(
            Some("/vault"),
            "other",
            Some("https://paperless.example"),
            true,
            true,
        )
        .unwrap(),
        DeliveryContext::new(
            Some("/vault"),
            "NEOTH",
            Some("https://other.example"),
            true,
            true,
        )
        .unwrap(),
        DeliveryContext::new(Some("/vault"), "NEOTH", None, true, true).unwrap(),
        DeliveryContext::new(Some("/vault"), "NEOTH", Some(""), true, true).unwrap(),
        DeliveryContext::new(
            Some("/vault"),
            "NEOTH",
            Some("https://paperless.example"),
            false,
            false,
        )
        .unwrap(),
        DeliveryContext::new(
            Some("/vault"),
            "NEOTH",
            Some("https://paperless.example"),
            true,
            false,
        )
        .unwrap(),
    ];
    for changed in variants {
        assert_eq!(
            state(&conn, &id, Purpose::Ingest, Some(&changed)).unwrap(),
            SeenState::ContextConflict
        );
        assert!(mark(&conn, &id, Completion::Delivery(&changed), 200).is_err());
    }
    assert!(DeliveryContext::new(None, "NEOTH", None, false, true).is_err());
    assert_eq!(
        DeliveryContext::new(None, "first", None, false, false)
            .unwrap()
            .sha256,
        DeliveryContext::new(None, "second", None, false, false)
            .unwrap()
            .sha256
    );
    let row: (String, String, i64) = conn.query_row(
        "SELECT completion_kind,context_sha256,first_seen_unix FROM idx_email_seen_scoped WHERE purpose='ingest'",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(row, ("delivery".into(), original.sha256, 100));
}

#[test]
fn quarantine_completion_ignores_target_drift_without_becoming_delivery() {
    let conn = db();
    let mail = email("1", Some("<quarantine>"));
    let id = identity("alice", &mail, 1);
    mark(&conn, &id, Completion::Quarantine, 100).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, None).unwrap(),
        SeenState::Seen
    );
    let targets = target_context();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&targets)).unwrap(),
        SeenState::Seen
    );
    assert!(mark(&conn, &id, Completion::Delivery(&targets), 200).is_err());
    mark(&conn, &id, Completion::Quarantine, 300).unwrap();
    let row: (String, Option<String>, i64) = conn.query_row(
        "SELECT completion_kind,context_sha256,first_seen_unix FROM idx_email_seen_scoped WHERE unit_sha256=?1 AND purpose='ingest'",
        [&id.unit_sha256], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).unwrap();
    assert_eq!(row, ("quarantine".into(), None, 100));
    let mut changed = mail;
    changed.body.push_str(" changed");
    assert_eq!(
        state(
            &conn,
            &identity("alice", &changed, 1),
            Purpose::Ingest,
            Some(&targets)
        )
        .unwrap(),
        SeenState::InputConflict
    );
    let delivered = identity("alice", &email("2", Some("<delivered>")), 1);
    mark(&conn, &delivered, Completion::Delivery(&targets), 100).unwrap();
    assert!(mark(&conn, &delivered, Completion::Quarantine, 200).is_err());
}

fn schema_54_fixture(path: &std::path::Path, id: &Identity) {
    let conn = store::open(path).unwrap();
    conn.execute_batch(
        "ALTER TABLE idx_email_seen_scoped DROP COLUMN context_sha256;
         ALTER TABLE idx_email_seen_scoped DROP COLUMN completion_kind;
         UPDATE meta SET value='54' WHERE key='schema_version';",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO idx_email_seen_scoped (unit_sha256,purpose,first_seen_unix,input_sha256) VALUES (?1,'ingest',100,?2)",
        rusqlite::params![id.unit_sha256, id.input_sha256],
    ).unwrap();
}

#[test]
fn delivery_v54_migration_retains_unknown_disposition_and_rejects_invalid_pairs() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<v54>")), 1);
    schema_54_fixture(&path, &id);
    let conn = store::open(&path).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::LegacyAmbiguous
    );
    assert!(mark(&conn, &id, Completion::Delivery(&target_context()), 200).is_err());
    assert!(mark(&conn, &id, Completion::Quarantine, 200).is_err());
    mark(&conn, &id, Completion::Triage, 200).unwrap();
    let row: (String, i64, Option<String>, Option<String>) = conn.query_row(
        "SELECT input_sha256,first_seen_unix,completion_kind,context_sha256 FROM idx_email_seen_scoped WHERE purpose='ingest'",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).unwrap();
    assert_eq!(row, (id.input_sha256.clone(), 100, None, None));
    for sql in [
        "UPDATE idx_email_seen_scoped SET completion_kind='delivery' WHERE purpose='ingest'",
        "UPDATE idx_email_seen_scoped SET completion_kind='other' WHERE purpose='ingest'",
        "UPDATE idx_email_seen_scoped SET context_sha256=printf('%064d',0) WHERE purpose='ingest'",
        "UPDATE idx_email_seen_scoped SET completion_kind='quarantine',context_sha256=printf('%064d',0) WHERE purpose='ingest'",
        "UPDATE idx_email_seen_scoped SET completion_kind='delivery',context_sha256='bad' WHERE purpose='ingest'",
    ] {
        assert!(conn.execute_batch(sql).is_err());
    }
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::LegacyAmbiguous
    );
}

#[test]
fn delivery_v54_column_collision_preserves_version_and_input() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<collision54>")), 1);
    schema_54_fixture(&path, &id);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("ALTER TABLE idx_email_seen_scoped ADD COLUMN CONTEXT_SHA256 TEXT;")
            .unwrap();
    }
    assert!(store::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    let row: (String,String,i64) = conn.query_row(
        "SELECT (SELECT value FROM meta WHERE key='schema_version'),input_sha256,first_seen_unix FROM idx_email_seen_scoped",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).unwrap();
    assert_eq!(row, ("54".into(), id.input_sha256, 100));
}

#[test]
fn delivery_v54_stamp_failure_rolls_back_both_columns_before_retry() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    let id = identity("alice", &email("1", Some("<rollback54>")), 1);
    schema_54_fixture(&path, &id);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_version_55 BEFORE INSERT ON meta
             WHEN NEW.key='schema_version' AND NEW.value='55'
             BEGIN SELECT RAISE(ABORT,'fixture'); END;",
        )
        .unwrap();
    }
    assert!(store::open(&path).is_err());
    {
        let conn = Connection::open(&path).unwrap();
        let row: (String, i64, String) = conn.query_row(
            "SELECT (SELECT value FROM meta WHERE key='schema_version'),
             (SELECT COUNT(*) FROM pragma_table_info('idx_email_seen_scoped') WHERE name IN ('completion_kind','context_sha256')),
             input_sha256 FROM idx_email_seen_scoped",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).unwrap();
        assert_eq!(row, ("54".into(), 0, id.input_sha256.clone()));
        conn.execute_batch("DROP TRIGGER fail_version_55;").unwrap();
    }
    let conn = store::open(&path).unwrap();
    assert_eq!(
        state(&conn, &id, Purpose::Ingest, Some(&target_context())).unwrap(),
        SeenState::LegacyAmbiguous
    );
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, store::SCHEMA_VERSION.to_string());
}

#[test]
fn competing_delivery_targets_cannot_adopt_the_first_completion() {
    use std::sync::{Arc, Barrier};
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("views.db");
    drop(store::open(&path).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = ["/first", "/second"]
        .into_iter()
        .map(|vault| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let conn = Connection::open(path).unwrap();
                conn.busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let id = identity("alice", &email("1", Some("<target-race>")), 1);
                let context =
                    DeliveryContext::new(Some(vault), "NEOTH", None, false, false).unwrap();
                barrier.wait();
                (
                    mark(&conn, &id, Completion::Delivery(&context), 100).is_ok(),
                    context,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(success, _)| *success).count(), 1);
    let conn = Connection::open(&path).unwrap();
    let id = identity("alice", &email("1", Some("<target-race>")), 1);
    for (success, context) in results {
        assert_eq!(
            state(&conn, &id, Purpose::Ingest, Some(&context)).unwrap(),
            if success {
                SeenState::Seen
            } else {
                SeenState::ContextConflict
            }
        );
    }
}
