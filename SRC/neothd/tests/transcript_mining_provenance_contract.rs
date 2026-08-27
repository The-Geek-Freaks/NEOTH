//! Behavioral contracts for GOLD-LF-P1-08 stages 1–3a only.
//!
//! The migration module owns the v35/v36 fixture and rollback coverage because
//! its table builders are deliberately private. This external test opens the
//! real fresh v37 database and exercises the installed SQLite contract. The
//! source-level negative contracts remain additive: schema reservation must
//! not accidentally create runtime mining authority or retain raw text.

use neothd::memory::store;
use rusqlite::Connection;

fn fresh_v37_connection() -> (tempfile::TempDir, Connection) {
    let home = tempfile::tempdir().expect("temporary v37 views directory");
    let connection =
        store::open(&home.path().join("views.db")).expect("open fresh v37 views database");
    (home, connection)
}

fn insert_fresh_witnessed_raw_turn(connection: &Connection) {
    connection
        .execute_batch(
            r#"
            INSERT INTO raw_turns
                (session_id, role, ts_unix, text, transcript_mining_authority_epoch,
                 transcript_mining_raw_frame_plan_epoch)
            VALUES ('stage3a-session', 'operator', 1, 'stage3a raw text', 1, 1);
            INSERT INTO transcript_mining_modern_raw_witness
                (raw_turn_id, subject_sha256, raw_role, source_kind, witnessed_at_unix)
            VALUES (1, zeroblob(32), 'operator', 'operator_raw_text_v1', 1);
            "#,
        )
        .expect("seed only a fresh witnessed raw turn");
}

fn assert_rejected_with(connection: &Connection, sql: &str, expected_reason: &str) {
    let error = connection
        .execute(sql, [])
        .expect_err("ordinary SQLite mutation must be rejected")
        .to_string();
    assert!(
        error.contains(expected_reason),
        "expected rejection containing {expected_reason:?}, got: {error}",
    );
}

#[test]
fn fresh_v37_database_reserves_plan_payload_and_all_proof_states() {
    let (_home, connection) = fresh_v37_connection();
    let schema_version: String = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .expect("fresh schema version");
    assert_eq!(schema_version, "37");

    for table in [
        "transcript_mining_provenance",
        "transcript_mining_modern_raw_witness",
        "transcript_mining_raw_frame_plan",
        "transcript_mining_delete_context",
        "transcript_mining_wal_outbox",
        "transcript_mining_revocation_receipts",
    ] {
        let table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("inspect installed P1-08 table");
        assert_eq!(table_count, 1, "fresh v37 must install {table}");
    }
    let reservation_gate_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'trigger' AND name = 'transcript_mining_plan_stage3a_reserved'",
            [],
            |row| row.get(0),
        )
        .expect("inspect Stage-3a plan reservation gate");
    assert_eq!(reservation_gate_count, 1);

    insert_fresh_witnessed_raw_turn(&connection);

    // Keep the deferred provenance FK open while invoking the admission gate.
    // Without the Stage-3a gate this INSERT would succeed at statement time,
    // so its exact error proves the gate rather than a later FK check.
    connection
        .execute_batch("BEGIN")
        .expect("begin ordinary plan admission probe");
    assert_rejected_with(
        &connection,
        "INSERT INTO transcript_mining_raw_frame_plan
                    (frame_plan_id, provenance_id, lifecycle_id, raw_turn_id,
                     raw_event_type, raw_event_subtype, planned_wal_format_version,
                     planned_event_schema_version, planned_event_id,
                     planned_hlc_physical_ns, planned_hlc_logical, planned_header,
                     planned_header_sha256, planned_at_unix)
                 VALUES ('ordinary-plan', 'ordinary-provenance', 'ordinary-lifecycle', 1,
                         1, 0, 2, 4, zeroblob(8), zeroblob(8), 0,
                         CAST('secret' AS BLOB) || zeroblob(90), zeroblob(32), 1)",
        "stage 3a reserves raw frame plan creation for authenticated attestation",
    );
    connection
        .execute_batch("ROLLBACK")
        .expect("rollback ordinary plan admission probe");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM transcript_mining_raw_frame_plan",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count reserved plans"),
        0,
    );

    assert_rejected_with(
        &connection,
        "INSERT INTO transcript_mining_provenance
                    (provenance_id, lifecycle_id, raw_turn_id, raw_session_sha256,
                     raw_text_sha256, raw_role, source_kind, retention, lifecycle,
                     created_at_unix, expires_at_unix)
                 VALUES ('active-provenance', 'active-lifecycle', 1, zeroblob(32),
                         zeroblob(32), 'operator', 'operator_raw_text_v1', 'hours24',
                         'active', 1, 4000000000)",
        "provenance requires a fresh planned raw frame",
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM transcript_mining_provenance",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("confirm no active provenance was persisted"),
        0,
    );
    assert_rejected_with(
        &connection,
        "INSERT INTO transcript_mining_wal_outbox
                    (outbox_id, provenance_id, lifecycle_id, logical_subtype, event_subtype,
                     payload, payload_sha256, enqueued_at_unix)
                 VALUES ('pending-bound', 'ordinary-provenance', 'ordinary-lifecycle',
                         'bound', 40, CAST('secret' AS BLOB), zeroblob(32), 1)",
        "bound outbox requires verified live binding",
    );
    assert_rejected_with(
        &connection,
        "INSERT INTO transcript_mining_wal_outbox
                    (outbox_id, provenance_id, lifecycle_id, logical_subtype, event_subtype,
                     payload, payload_sha256, state, enqueued_at_unix, delivered_at_unix,
                     delivered_frame_sha256)
                 VALUES ('delivered-bound', 'ordinary-provenance', 'ordinary-lifecycle',
                         'bound', 40, CAST('secret' AS BLOB), zeroblob(32), 'delivered',
                         1, 2, zeroblob(32))",
        "bound outbox requires verified live binding",
    );
    assert_rejected_with(
        &connection,
        "INSERT INTO transcript_mining_wal_outbox
                    (outbox_id, provenance_id, lifecycle_id, logical_subtype, event_subtype,
                     payload, payload_sha256, bound_payload_sha256,
                     revocation_receipt_id, enqueued_at_unix)
                 VALUES ('revoked-bound', 'ordinary-provenance', 'ordinary-lifecycle',
                         'revoked', 41, CAST('secret' AS BLOB), zeroblob(32), zeroblob(32),
                         'missing-receipt', 1)",
        "revoked outbox requires terminal receipt and delivered binding",
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM transcript_mining_wal_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count reserved outbox rows"),
        0,
    );
}

#[test]
fn provenance_prerequisite_is_modern_sealed_and_not_a_producer() {
    let provenance = include_str!("../src/memory/transcript_mining_provenance.rs");
    let memory_mod = include_str!("../src/memory/mod.rs");
    let events = include_str!("../src/wal/events.rs");

    assert!(memory_mod.contains("pub(crate) mod transcript_mining_provenance;"));
    assert!(provenance.contains("struct AuthenticatedMiningSubject(Sha256Digest);"));
    assert!(provenance.contains("#[serde(deny_unknown_fields)]"));
    assert!(provenance.contains("TranscriptMiningBoundV1"));
    assert!(provenance.contains("TranscriptMiningRevokedV1"));
    assert!(provenance.contains("MAX_TRANSCRIPT_MINING_PAYLOAD_BYTES"));
    assert!(events.contains("TranscriptMiningBound = 0x28"));
    assert!(events.contains("TranscriptMiningRevoked = 0x29"));

    for premature_authority in [
        "pub(crate) fn append",
        "pub(crate) fn produce",
        "pub(crate) fn activate",
        "pub(crate) fn mine",
    ] {
        assert!(
            !provenance.contains(premature_authority),
            "stages 1-3a must not expose runtime authority: {premature_authority}",
        );
    }
}

#[test]
fn migration_contract_keeps_legacy_unbound_and_raw_text_out_of_provenance() {
    let migration = include_str!("../src/memory/migrations/mod.rs");
    let store = include_str!("../src/memory/store.rs");

    fn provenance_table(source: &str) -> &str {
        source
            .split("CREATE TABLE IF NOT EXISTS transcript_mining_provenance (")
            .nth(1)
            .and_then(|after_table| after_table.split(") STRICT;").next())
            .expect("transcript provenance table must remain present and STRICT")
    }

    fn normalized_column(table: &str, column: &str) -> Option<String> {
        table
            .lines()
            .map(str::trim)
            .find(|line| {
                line.strip_prefix(column)
                    .and_then(|suffix| suffix.chars().next())
                    .is_some_and(char::is_whitespace)
            })
            .map(|line| {
                line.trim_end_matches(',')
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
    }

    assert!(migration.contains("from: 35,"));
    assert!(migration.contains("to: 36,"));
    assert!(migration.contains("fn migration_v35_to_v36"));
    assert!(migration.contains("from: 36,"));
    assert!(migration.contains("to: 37,"));
    assert!(migration.contains("fn migration_v36_to_v37"));
    assert!(migration.contains("CREATE TABLE IF NOT EXISTS transcript_mining_provenance"));
    assert!(migration.contains("transcript_mining_raw_turn_deleted"));
    assert!(
        migration.contains("WHERE raw_turn_id = OLD.id AND lifecycle IN ('pending', 'active')")
    );
    assert!(store.contains("pub const SCHEMA_VERSION: i64 = 37;"));
    assert!(store.contains("CREATE TABLE IF NOT EXISTS transcript_mining_wal_outbox"));

    let migration_provenance = provenance_table(migration);
    let store_provenance = provenance_table(store);
    let digest_column = "raw_text_sha256";
    let expected_digest_definition =
        "raw_text_sha256 BLOB NOT NULL CHECK(length(raw_text_sha256) = 32)";
    assert_eq!(
        normalized_column(migration_provenance, digest_column).as_deref(),
        Some(expected_digest_definition),
        "migration must retain only a fixed-size text digest"
    );
    assert_eq!(
        normalized_column(store_provenance, digest_column).as_deref(),
        Some(expected_digest_definition),
        "fresh-store schema must agree with the migration digest contract"
    );
    for provenance in [migration_provenance, store_provenance] {
        assert!(
            normalized_column(provenance, "text").is_none(),
            "provenance records must never retain raw transcript text"
        );
    }
}
