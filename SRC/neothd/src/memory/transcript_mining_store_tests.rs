use super::*;

use crate::cli::chat::LocalChatCommunicationSubject;
use crate::config::memory::TranscriptMiningRetention;
use crate::wal::events::{EVENT_TYPE_EXTENDED, EVENT_TYPE_RAW_TEXT};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;
use crate::wal::writer::{WalWriterHandle, spawn_for_home};
use tempfile::TempDir;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_secs() as i64
}

fn make_home() -> TempDir {
    let home = tempfile::tempdir().expect("temporary NEOTH home");
    std::fs::create_dir_all(home.path().join("wal")).expect("create WAL directory");
    home
}

fn ingress(home: &std::path::Path) -> AuthenticatedLocalIngress {
    AuthenticatedLocalIngress::from_local_chat(
        &LocalChatCommunicationSubject::for_test(),
        home,
        TranscriptMiningRetention::Hours24,
    )
    .expect("authenticated local ingress")
}

fn open_store(home: &std::path::Path) -> TranscriptMiningStore {
    let conn = crate::memory::store::open(&home.join("views.db")).expect("open views database");
    TranscriptMiningStore::open(conn, ingress(home)).expect("open transcript mining store")
}

fn start_writer(
    home: &std::path::Path,
    name: &str,
) -> (WalWriterHandle, tokio::task::JoinHandle<()>) {
    let stem = name.strip_suffix(".wal").unwrap_or(name);
    spawn_for_home(
        home.join("wal").join(format!("{stem}-000001.wal")),
        home.to_path_buf(),
    )
    .expect("spawn production WAL writer")
}

async fn stop_writer(writer: WalWriterHandle, join: tokio::task::JoinHandle<()>) {
    drop(writer);
    join.await.expect("WAL writer task completes");
}

async fn activate(
    store: &mut TranscriptMiningStore,
    writer: &WalWriterHandle,
    home: &std::path::Path,
    session: &str,
    text: &str,
    now: i64,
) -> i64 {
    let raw = store
        .prepare_operator_raw_birth(session, text, now)
        .expect("prepare modern raw birth");
    let raw_turn_id = raw.raw_turn_id();
    let raw_receipt = writer
        .append_planned_raw_text_once(home, raw.raw_descriptor().expect("raw descriptor"))
        .await
        .expect("append planned RAW exactly once");
    let bound = match store
        .record_raw_receipt(&raw, &raw_receipt, now)
        .expect("record authenticated RAW receipt")
    {
        RawReceiptResolution::Bound(bound) => bound,
        RawReceiptResolution::ExpiredCancelled => panic!("fresh RAW must not be expired"),
    };
    let bound_receipt = writer
        .append_planned_mining_outbox_once(
            home,
            bound.bound_descriptor().expect("bound descriptor"),
        )
        .await
        .expect("append planned Bound exactly once");
    store
        .record_bound_receipt(&bound, &bound_receipt, now)
        .expect("record authenticated Bound receipt");
    assert!(
        store
            .active_binding_is_usable(raw_turn_id, now)
            .expect("check active binding"),
        "the fully attested binding must be usable"
    );
    raw_turn_id
}

fn count_mining_frames(home: &std::path::Path) -> (usize, usize) {
    let mut raws = 0;
    let mut bounds = 0;
    for entry in std::fs::read_dir(home.join("wal")).expect("read WAL directory") {
        let path = entry.expect("WAL directory entry").path();
        if path.extension().and_then(|v| v.to_str()) != Some("wal") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read WAL segment");
        let header = parse_segment_header(&bytes).expect("parse WAL segment header");
        let mut cursor = header.header_len();
        while cursor < bytes.len() {
            let frame = decode_frame(&bytes[cursor..]).expect("decode complete WAL frame");
            if frame.header.event_type == EVENT_TYPE_RAW_TEXT {
                raws += 1;
            }
            if frame.header.event_type == EVENT_TYPE_EXTENDED && frame.header.event_subtype == 0x28
            {
                bounds += 1;
            }
            cursor += frame.header.total_len as usize;
        }
    }
    (raws, bounds)
}

async fn deliver_revocations(
    store: &mut TranscriptMiningStore,
    writer: &WalWriterHandle,
    home: &std::path::Path,
    now: i64,
) -> usize {
    let pending = store
        .prepare_pending_revocations(now)
        .expect("prepare authenticated revocations");
    let count = pending.len();
    for item in pending {
        let receipt = writer
            .append_planned_mining_outbox_once(home, item.revoked_descriptor().unwrap())
            .await
            .unwrap();
        store.record_revoked_receipt(&item, &receipt, now).unwrap();
    }
    count
}

#[tokio::test]
async fn ordinary_connection_cannot_change_delivered_wal_location_receipt() {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path(), "receipt-location.wal");
    let now = now_unix();
    let raw_id = activate(
        &mut store,
        &writer,
        home.path(),
        "receipt-session",
        "retained input",
        now,
    )
    .await;
    let ordinary = crate::memory::store::open(&home.path().join("views.db")).unwrap();
    for (column, replacement) in [
        ("delivered_receipt_location_sha256", "zeroblob(32)"),
        ("delivered_receipt_location_sha256", "NULL"),
        ("delivered_frame_sha256", "NULL"),
    ] {
        let sql = format!(
            "UPDATE transcript_mining_wal_outbox SET {column}={replacement} WHERE logical_subtype='bound'"
        );
        assert!(
            ordinary.execute(&sql, []).is_err(),
            "ordinary receipt mutation must fail: {column}={replacement}"
        );
        assert!(store.active_binding_is_usable(raw_id, now).unwrap());
    }
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), now + 86_400).await,
        1
    );
    assert!(ordinary.execute("UPDATE transcript_mining_wal_outbox SET delivered_receipt_location_sha256=zeroblob(32) WHERE logical_subtype='revoked'", []).is_err());
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn previously_active_expiry_delivers_one_revocation_and_is_not_resurrected() {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path(), "active-expiry.wal");
    let now = now_unix();
    let raw_id = activate(
        &mut store,
        &writer,
        home.path(),
        "expiry-session",
        "retained input",
        now,
    )
    .await;
    let expiry = now + 86_400;
    assert!(!store.active_binding_is_usable(raw_id, expiry).unwrap());
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), expiry).await,
        1
    );
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), expiry + 1).await,
        0
    );
    let terminal: (String,String) = store.conn.query_row(
        "SELECT lifecycle,terminal_cause FROM transcript_mining_provenance WHERE raw_turn_id=?1",
        [raw_id], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(terminal, ("revoked".into(), "retention_expired".into()));
    let ordinary = crate::memory::store::open(&home.path().join("views.db")).unwrap();
    assert!(
        ordinary
            .execute(
                "UPDATE transcript_mining_provenance SET lifecycle='active' WHERE raw_turn_id=?1",
                [raw_id]
            )
            .is_err()
    );
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn bound_written_before_expiry_but_acknowledged_late_requires_one_revocation() {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path(), "late-bound.wal");
    let now = now_unix();
    let raw = store
        .prepare_operator_raw_birth("late-session", "late receipt", now)
        .unwrap();
    let receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().unwrap())
        .await
        .unwrap();
    let RawReceiptResolution::Bound(bound) = store.record_raw_receipt(&raw, &receipt, now).unwrap()
    else {
        panic!("fresh bound missing")
    };
    let receipt = writer
        .append_planned_mining_outbox_once(home.path(), bound.bound_descriptor().unwrap())
        .await
        .unwrap();
    let expiry = bound.expires_at_unix();
    store
        .record_bound_receipt(&bound, &receipt, expiry)
        .unwrap();
    assert!(
        !store
            .active_binding_is_usable(raw.raw_turn_id(), expiry)
            .unwrap()
    );
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), expiry).await,
        1
    );
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), expiry + 1).await,
        0
    );
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn raw_ack_after_expiry_cancels_without_ever_preparing_a_bound_frame() {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path(), "raw-expiry.wal");
    let now = now_unix();
    let raw = store
        .prepare_operator_raw_birth("raw-expiry", "raw persistence remains", now)
        .unwrap();
    let receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        store
            .record_raw_receipt(&raw, &receipt, raw.expires_at_unix())
            .unwrap(),
        RawReceiptResolution::ExpiredCancelled
    ));
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), raw.expires_at_unix()).await,
        0
    );
    let count: i64 = store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM transcript_mining_wal_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    store
        .conn
        .execute("DELETE FROM raw_turns WHERE id=?1", [raw.raw_turn_id()])
        .unwrap();
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn expired_bound_absence_releases_exact_lease_and_can_never_append_later() {
    let home = make_home();
    let mut store = open_store(home.path());
    let (writer, join) = start_writer(home.path(), "bound-absence.wal");
    // A retained checkpoint with fifteen seconds left in its finite window.
    // Use the real writer clock so every later append sees the same expiry.
    let issued = now_unix() - 86_400 + 15;
    let raw = store
        .prepare_operator_raw_birth("absence", "operator input", issued)
        .unwrap();
    let receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().unwrap())
        .await
        .unwrap();
    let RawReceiptResolution::Bound(bound) =
        store.record_raw_receipt(&raw, &receipt, issued).unwrap()
    else {
        panic!("checkpoint unexpectedly expired")
    };
    let wait_seconds = (bound.expires_at_unix() - now_unix()).max(0) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait_seconds)).await;
    let failure = writer
        .append_planned_mining_outbox_once(home.path(), bound.bound_descriptor().unwrap())
        .await
        .unwrap_err();
    let crate::wal::TranscriptMiningOnceError::ExpiredAbsent(proof) = failure else {
        panic!("expected authenticated expiry absence")
    };
    store.record_expired_bound_absence(&bound, &proof).unwrap();
    assert!(matches!(
        writer
            .append_planned_mining_outbox_once(home.path(), bound.bound_descriptor().unwrap())
            .await,
        Err(crate::wal::TranscriptMiningOnceError::ExpiredAbsent(_))
    ));
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), now_unix()).await,
        0
    );
    assert_eq!(count_mining_frames(home.path()), (1, 0));
    store
        .conn
        .execute("DELETE FROM raw_turns WHERE id=?1", [raw.raw_turn_id()])
        .unwrap();
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn fresh_birth_is_modern_and_direct_sql_cannot_create_or_advance_mining_state() {
    let home = make_home();
    let (writer, join) = start_writer(home.path(), "birth-000001.wal");
    let now = now_unix();
    let mut store = open_store(home.path());
    let raw = store
        .prepare_operator_raw_birth("birth-session", "operator text", now)
        .expect("prepare fresh birth");

    let epochs: (i64, i64) = store
        .conn
        .query_row(
            "SELECT transcript_mining_authority_epoch,transcript_mining_raw_frame_plan_epoch FROM raw_turns WHERE id=?1",
            [raw.raw_turn_id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read birth epochs");
    assert_eq!(
        epochs,
        (1, 1),
        "fresh birth must never originate legacy epochs"
    );

    assert!(
        store
            .conn
            .execute(
                "UPDATE transcript_mining_raw_frame_plan SET state='verified' WHERE raw_turn_id=?1",
                [raw.raw_turn_id()],
            )
            .is_err(),
        "ordinary SQL cannot verify a RAW plan"
    );
    assert!(
        store
            .conn
            .execute(
                "UPDATE transcript_mining_provenance SET lifecycle='active' WHERE raw_turn_id=?1",
                [raw.raw_turn_id()],
            )
            .is_err(),
        "ordinary SQL cannot activate a binding"
    );
    assert!(
        store
            .conn
            .execute("DELETE FROM raw_turns WHERE id=?1", [raw.raw_turn_id()])
            .is_err(),
        "RAW deletion is busy while its append lease remains pending"
    );

    let raw_receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().expect("raw descriptor"))
        .await
        .expect("append planned RAW");
    let bound = match store
        .record_raw_receipt(&raw, &raw_receipt, now)
        .expect("record RAW receipt")
    {
        RawReceiptResolution::Bound(bound) => bound,
        RawReceiptResolution::ExpiredCancelled => panic!("fresh RAW unexpectedly expired"),
    };
    assert!(
        store
            .conn
            .execute(
                "UPDATE transcript_mining_wal_outbox SET state='delivered',delivered_at_unix=?1 WHERE logical_subtype='bound'",
                [now],
            )
            .is_err(),
        "ordinary SQL cannot deliver a Bound outbox entry"
    );
    assert!(
        store
            .conn
            .execute(
                "INSERT OR REPLACE INTO transcript_mining_wal_outbox SELECT * FROM transcript_mining_wal_outbox",
                [],
            )
            .is_err(),
        "OR REPLACE cannot replace a pending Bound outbox entry"
    );
    assert_eq!(bound.raw_turn_id(), raw.raw_turn_id());
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn unknown_raw_ack_restarts_from_descriptor_without_duplicate_raw_then_activates_once() {
    let home = make_home();
    let now = now_unix();
    let (writer, join) = start_writer(home.path(), "raw-000001.wal");
    let mut store = open_store(home.path());
    let raw = store
        .prepare_operator_raw_birth("raw-restart", "one physical raw", now)
        .expect("prepare RAW");
    let raw_turn_id = raw.raw_turn_id();
    let receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().expect("raw descriptor"))
        .await
        .expect("append RAW before acknowledgement is lost");
    drop(store);
    stop_writer(writer, join).await;

    let mut resumed_store = open_store(home.path());
    let resumed = resumed_store
        .resume_pending(now)
        .expect("resume pending RAW");
    assert_eq!(resumed.len(), 1);
    let recovered_raw = match resumed.into_iter().next().expect("one pending operation") {
        PendingMiningOperation::Raw(raw) => raw,
        PendingMiningOperation::Bound(_) => panic!("lost RAW acknowledgement must resume RAW"),
    };
    assert_eq!(recovered_raw.raw_turn_id(), raw_turn_id);
    let (writer, join) = start_writer(home.path(), "raw-000002.wal");
    let replayed_receipt = writer
        .append_planned_raw_text_once(
            home.path(),
            recovered_raw
                .raw_descriptor()
                .expect("recovered RAW descriptor"),
        )
        .await
        .expect("reuse persisted RAW receipt");
    assert_eq!(receipt.frame_sha256(), replayed_receipt.frame_sha256());
    let bound = match resumed_store
        .record_raw_receipt(&recovered_raw, &replayed_receipt, now)
        .expect("resolve reused RAW receipt")
    {
        RawReceiptResolution::Bound(bound) => bound,
        RawReceiptResolution::ExpiredCancelled => panic!("fresh resumed RAW unexpectedly expired"),
    };
    let bound_receipt = writer
        .append_planned_mining_outbox_once(
            home.path(),
            bound.bound_descriptor().expect("bound descriptor"),
        )
        .await
        .expect("append Bound receipt");
    resumed_store
        .record_bound_receipt(&bound, &bound_receipt, now)
        .expect("activate after resumed RAW receipt");
    assert!(
        resumed_store
            .active_binding_is_usable(raw_turn_id, now)
            .unwrap()
    );
    let operators: i64 = resumed_store
        .conn
        .query_row(
            "SELECT count(*) FROM raw_turns WHERE role='operator'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(operators, 1, "restart must not create another operator row");
    stop_writer(writer, join).await;
    assert_eq!(count_mining_frames(home.path()), (1, 1));
}

#[tokio::test]
async fn unknown_bound_ack_restarts_from_descriptor_and_reuses_one_0x28_frame() {
    let home = make_home();
    let now = now_unix();
    let (writer, join) = start_writer(home.path(), "bound-000001.wal");
    let mut store = open_store(home.path());
    let raw = store
        .prepare_operator_raw_birth("bound-restart", "one physical Bound", now)
        .expect("prepare RAW");
    let raw_receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().unwrap())
        .await
        .unwrap();
    let bound = match store.record_raw_receipt(&raw, &raw_receipt, now).unwrap() {
        RawReceiptResolution::Bound(bound) => bound,
        RawReceiptResolution::ExpiredCancelled => panic!("fresh RAW unexpectedly expired"),
    };
    let original_receipt = writer
        .append_planned_mining_outbox_once(home.path(), bound.bound_descriptor().unwrap())
        .await
        .expect("append Bound before acknowledgement is lost");
    let raw_turn_id = bound.raw_turn_id();
    drop(store);
    stop_writer(writer, join).await;

    let mut resumed_store = open_store(home.path());
    let resumed = resumed_store
        .resume_pending(now)
        .expect("resume pending Bound");
    assert_eq!(resumed.len(), 1);
    let recovered_bound = match resumed.into_iter().next().unwrap() {
        PendingMiningOperation::Bound(bound) => bound,
        PendingMiningOperation::Raw(_) => panic!("lost Bound acknowledgement must resume Bound"),
    };
    let (writer, join) = start_writer(home.path(), "bound-000002.wal");
    let replayed_receipt = writer
        .append_planned_mining_outbox_once(home.path(), recovered_bound.bound_descriptor().unwrap())
        .await
        .expect("reuse persisted Bound receipt");
    assert_eq!(
        original_receipt.frame_sha256(),
        replayed_receipt.frame_sha256()
    );
    resumed_store
        .record_bound_receipt(&recovered_bound, &replayed_receipt, now)
        .expect("activate from reused Bound receipt");
    assert!(
        resumed_store
            .active_binding_is_usable(raw_turn_id, now)
            .unwrap()
    );
    stop_writer(writer, join).await;
    assert_eq!(count_mining_frames(home.path()), (1, 1));
}

#[tokio::test]
async fn raw_deletion_revokes_active_binding_and_cross_row_bound_corruption_cannot_authorize() {
    let home = make_home();
    let now = now_unix();
    let (writer, join) = start_writer(home.path(), "corruption-000001.wal");
    let mut store = open_store(home.path());
    let first = activate(
        &mut store,
        &writer,
        home.path(),
        "first",
        "first operator turn",
        now,
    )
    .await;
    let second = activate(
        &mut store,
        &writer,
        home.path(),
        "second",
        "second operator turn",
        now,
    )
    .await;

    // Explicit corruption fixture: bypass the immutable-SQL guard only to prove
    // that read-side authorization binds the SQL receipt to this exact raw row.
    store
        .conn
        .execute_batch("DROP TRIGGER transcript_mining_outbox_binding_immutable;")
        .expect("remove immutable guard for corruption fixture");
    store
        .conn
        .execute(
            "UPDATE transcript_mining_wal_outbox
             SET payload=(SELECT payload FROM transcript_mining_wal_outbox WHERE provenance_id=(SELECT provenance_id FROM transcript_mining_provenance WHERE raw_turn_id=?1)),
                 payload_sha256=(SELECT payload_sha256 FROM transcript_mining_wal_outbox WHERE provenance_id=(SELECT provenance_id FROM transcript_mining_provenance WHERE raw_turn_id=?1))
             WHERE provenance_id=(SELECT provenance_id FROM transcript_mining_provenance WHERE raw_turn_id=?2)",
            [first, second],
        )
        .expect("fabricate cross-row Bound payload in SQLite");
    assert!(
        !store.active_binding_is_usable(second, now).unwrap(),
        "a Bound receipt for another raw row cannot authorize this raw row"
    );

    store
        .conn
        .execute("DELETE FROM raw_turns WHERE id=?1", [first])
        .expect("delete an active RAW after its delivery leases settle");
    assert!(
        !store.active_binding_is_usable(first, now).unwrap(),
        "raw deletion immediately makes its prior active binding unusable"
    );
    let terminal: (String, String) = store
        .conn
        .query_row(
            "SELECT lifecycle,terminal_cause FROM transcript_mining_provenance WHERE raw_turn_id=?1",
            [first],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read terminal provenance");
    assert_eq!(
        terminal,
        ("revoked".to_owned(), "raw_turn_deleted".to_owned())
    );
    let receipts: i64 = store
        .conn
        .query_row(
            "SELECT count(*) FROM transcript_mining_revocation_receipts WHERE raw_turn_id=?1 AND revocation='raw_turn_deleted'",
            [first],
            |row| row.get(0),
        )
        .expect("read required revocation receipt");
    assert_eq!(
        receipts, 1,
        "raw deletion must leave one required revocation receipt pending WAL delivery"
    );
    // Simulate damaged raw-plan bookkeeping after deletion. The immutable,
    // authenticated Bound and local delete receipt still require revocation.
    store
        .conn
        .execute_batch("DROP TRIGGER transcript_mining_plan_stage3b_transition;")
        .unwrap();
    store.conn.execute(
        "UPDATE transcript_mining_raw_frame_plan SET state='planned',raw_frame_sha256=NULL,raw_frame_delivered_at_unix=NULL WHERE raw_turn_id=?1",
        [first],
    ).unwrap();
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), now + 1).await,
        1
    );
    assert_eq!(
        deliver_revocations(&mut store, &writer, home.path(), now + 2).await,
        0
    );
    drop(store);
    stop_writer(writer, join).await;
}

#[tokio::test]
async fn archived_hmac_subject_recovers_lost_raw_ack_after_key_rotation() {
    let home = make_home();
    let now = now_unix();
    let (writer, join) = start_writer(home.path(), "archived-subject-000001.wal");
    let mut store = open_store(home.path());
    let raw = store
        .prepare_operator_raw_birth("archived-subject", "old HMAC subject", now)
        .expect("prepare RAW under the original HMAC key");
    let raw_turn_id = raw.raw_turn_id();
    let initial_receipt = writer
        .append_planned_raw_text_once(home.path(), raw.raw_descriptor().unwrap())
        .await
        .expect("persist RAW before its acknowledgement is lost");
    drop(store);
    stop_writer(writer, join).await;

    let archive = home.path().join("wal").join("hmac.key.1700000000.archive");
    crate::cli::security::rotate_hmac_key_with_audit(
        home.path(),
        &home.path().join("wal").join("hmac.key"),
        &[0x91; 32],
        crate::cli::security::HmacKeyMutationMode::RotateExisting,
        Some(archive.clone()),
    )
    .await
    .expect("audit and archive the original HMAC key");
    assert!(archive.is_file(), "rotation must retain the old verifier");

    let mut recovered_store = open_store(home.path());
    let pending = recovered_store
        .resume_pending(now)
        .expect("archived HMAC verifier accepts the persisted subject");
    assert_eq!(pending.len(), 1);
    let recovered_raw = match pending.into_iter().next().unwrap() {
        PendingMiningOperation::Raw(raw) => raw,
        PendingMiningOperation::Bound(_) => panic!("lost RAW acknowledgement must resume RAW"),
    };
    assert_eq!(recovered_raw.raw_turn_id(), raw_turn_id);

    let (writer, join) = start_writer(home.path(), "archived-subject-000002.wal");
    let replayed_receipt = writer
        .append_planned_raw_text_once(home.path(), recovered_raw.raw_descriptor().unwrap())
        .await
        .expect("scan the old-key frame through the archived verifier");
    assert_eq!(
        initial_receipt.frame_sha256(),
        replayed_receipt.frame_sha256()
    );
    let bound = match recovered_store
        .record_raw_receipt(&recovered_raw, &replayed_receipt, now)
        .expect("record recovered RAW receipt")
    {
        RawReceiptResolution::Bound(bound) => bound,
        RawReceiptResolution::ExpiredCancelled => {
            panic!("fresh recovered RAW unexpectedly expired")
        }
    };
    let bound_receipt = writer
        .append_planned_mining_outbox_once(home.path(), bound.bound_descriptor().unwrap())
        .await
        .expect("append recovered Bound");
    recovered_store
        .record_bound_receipt(&bound, &bound_receipt, now)
        .expect("activate archived-subject recovery");
    assert!(
        recovered_store
            .active_binding_is_usable(raw_turn_id, now)
            .unwrap()
    );
    stop_writer(writer, join).await;
    assert_eq!(count_mining_frames(home.path()), (1, 1));
}
