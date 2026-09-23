//! Durable-store fixtures. `mod.rs` wires this file once the OpenRaft pin lands.

use super::raft_types::{BudgetSnapshotData, MAX_BUDGET_SNAPSHOT_BYTES};
use super::state_machine::BudgetLedger;
use super::store::open;
use super::types::{BudgetClusterConfig, BudgetCommand, BudgetGrantId, BudgetReply, ReserveBudget};
use crate::cluster::membership::{StableNodeId, TransportIdentity};
use openraft::storage::{RaftLogStorage, RaftStateMachine};
use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership, StoredMembership, Vote};
use std::collections::BTreeMap;
use std::io::SeekFrom;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

fn ledger(cluster_id: &str, cap: u64) -> BudgetLedger {
    let voters = ["11", "22", "33"]
        .into_iter()
        .map(|byte| {
            (
                StableNodeId::parse(byte.repeat(32)).unwrap(),
                TransportIdentity::parse(format!("transport-{byte}")).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    BudgetLedger::new(
        BudgetClusterConfig::new(cluster_id.to_owned(), 7, voters, cap, 20_260_923).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn restart_reloads_vote_and_never_silently_resets_frozen_store() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let mut first = open(&path, ledger("cluster-a", 100)).unwrap();
    let vote = Vote::new_committed(9, 2);
    first.save_vote(&vote).await.unwrap();
    drop(first);

    let mut recovered = open(&path, ledger("cluster-a", 100)).unwrap();
    assert_eq!(Some(vote), recovered.read_vote().await.unwrap());
    drop(recovered);

    assert!(
        open(&path, ledger("cluster-a", 101)).is_err(),
        "a changed cap must leave the existing store unavailable, never reset it"
    );

    let mut unchanged = open(&path, ledger("cluster-a", 100)).unwrap();
    assert_eq!(Some(vote), unchanged.read_vote().await.unwrap());
}

#[test]
fn corrupt_deserialized_ledger_stays_unavailable_without_reset() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let store = open(&path, ledger("cluster-a", 100)).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let corrupt = br#"{"config":null,"grants":{}}"#.to_vec();
    conn.execute(
        "UPDATE raft_state SET ledger = ?1 WHERE singleton = 1",
        [&corrupt],
    )
    .unwrap();
    drop(conn);

    assert!(open(&path, ledger("cluster-a", 100)).is_err());
    let conn = rusqlite::Connection::open(path).unwrap();
    let retained: Vec<u8> = conn
        .query_row(
            "SELECT ledger FROM raft_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        corrupt, retained,
        "recovery failure cannot overwrite evidence with a fresh ledger"
    );
}

#[test]
fn missing_config_marker_rejects_durable_vote_evidence() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let store = open(&path, ledger("cluster-a", 100)).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("DELETE FROM raft_meta WHERE key = 'frozen-config'", [])
        .unwrap();
    conn.execute("DELETE FROM raft_state", []).unwrap();
    conn.execute(
        "INSERT INTO raft_meta(key, value) VALUES(?1, ?2)",
        rusqlite::params![
            "vote",
            br#"{\"leader_id\":{\"term\":9,\"node_id\":2},\"committed\":true}"#.to_vec()
        ],
    )
    .unwrap();
    assert!(open(&path, ledger("cluster-a", 100)).is_err());
    let retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM raft_meta WHERE key = 'vote'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        1, retained,
        "config-less durable vote evidence must never be reset"
    );
}

#[tokio::test]
async fn snapshot_stream_refuses_growth_past_hard_limit() {
    let mut snapshot = BudgetSnapshotData::empty();
    snapshot
        .seek(SeekFrom::Start(MAX_BUDGET_SNAPSHOT_BYTES as u64))
        .await
        .unwrap();
    assert!(snapshot.write_all(&[1]).await.is_err());
    assert!(BudgetSnapshotData::from_bytes(vec![0; MAX_BUDGET_SNAPSHOT_BYTES + 1]).is_err());
}

#[tokio::test]
async fn snapshot_stream_seek_past_eof_reads_empty_without_panicking() {
    let mut snapshot = BudgetSnapshotData::empty();
    snapshot.seek(SeekFrom::Start(128)).await.unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(
        0,
        tokio::io::AsyncReadExt::read(&mut snapshot, &mut byte)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn applied_index_ledger_and_snapshot_survive_one_restart_together() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let membership_log = LogId::new(CommittedLeaderId::new(8, 1), 1);
    let log = LogId::new(CommittedLeaderId::new(8, 1), 2);
    let initial = ledger("cluster-a", 100);
    let command = BudgetCommand::Reserve(ReserveBudget {
        grant_id: BudgetGrantId("018f47ab-7b4a-7c6d-8e9f-0123456789ab".into()),
        provider_intent_id: "intent-atomic".into(),
        request_fingerprint: "ab".repeat(32),
        scope_hash: initial.config().scope_hash.clone(),
        reserved_usd_nanos: 11,
        utc_window: 20_260_923,
    });
    let initial_membership = Membership::from(initial.config().raft_voters());
    let mut store = open(&path, initial).unwrap();
    let reply = store
        .apply([
            Entry {
                log_id: membership_log,
                payload: EntryPayload::Membership(initial_membership),
            },
            Entry {
                log_id: log.clone(),
                payload: EntryPayload::Normal(command),
            },
        ])
        .await
        .unwrap();
    assert!(matches!(
        reply.as_slice(),
        [BudgetReply::Rejected(_), BudgetReply::Reserved(_)]
    ));
    let snapshot = store.build_snapshot().await.unwrap();
    let snapshot_id = snapshot.meta.snapshot_id.clone();
    drop(store);

    let mut recovered = open(&path, ledger("cluster-a", 100)).unwrap();
    assert_eq!(
        Some(log.clone()),
        recovered.applied_state().await.unwrap().0
    );
    assert_eq!(
        snapshot_id,
        recovered
            .get_current_snapshot()
            .await
            .unwrap()
            .unwrap()
            .meta
            .snapshot_id
    );
    drop(recovered);

    let conn = rusqlite::Connection::open(path).unwrap();
    let ledger: BudgetLedger = serde_json::from_slice(
        &conn
            .query_row(
                "SELECT ledger FROM raft_state WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(ledger.grants.contains_key(&BudgetGrantId(
        "018f47ab-7b4a-7c6d-8e9f-0123456789ab".into()
    )));
}

#[test]
fn schema_uses_wal_full_sync_and_keeps_one_snapshot_slot() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let store = open(&path, ledger("cluster-a", 100)).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let sync: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!("wal", mode.to_ascii_lowercase());
    assert_eq!(
        2, sync,
        "SQLite FULL synchronous mode is required for Raft acknowledgements"
    );
    let snapshots: i64 = conn
        .query_row("SELECT COUNT(*) FROM raft_snapshot", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        0, snapshots,
        "snapshot replacement is a bounded singleton slot"
    );
}

#[tokio::test]
async fn truncation_and_purge_keep_the_log_boundary_durable() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("budget-raft.db");
    let initial = ledger("cluster-a", 100);
    let store = open(&path, initial.clone()).unwrap();
    drop(store);
    let log = LogId::new(CommittedLeaderId::new(4, 1), 1);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO raft_log(log_index, term, entry) VALUES(?1, ?2, ?3)",
        rusqlite::params![1_i64, 4_i64, vec![0_u8]],
    )
    .unwrap();
    drop(conn);

    let mut store = open(&path, ledger("cluster-a", 100)).unwrap();
    store.truncate(log.clone()).await.unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM raft_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        0, count,
        "truncate removes the inclusive conflict suffix atomically"
    );
    conn.execute(
        "INSERT INTO raft_log(log_index, term, entry) VALUES(?1, ?2, ?3)",
        rusqlite::params![1_i64, 4_i64, vec![0_u8]],
    )
    .unwrap();
    conn.execute(
        "UPDATE raft_state SET last_applied = ?1 WHERE singleton = 1",
        [serde_json::to_vec(&log).unwrap()],
    )
    .unwrap();
    let membership = StoredMembership::new(
        Some(log.clone()),
        Membership::from(initial.config().raft_voters()),
    );
    conn.execute(
        "UPDATE raft_state SET membership = ?1 WHERE singleton = 1",
        [serde_json::to_vec(&membership).unwrap()],
    )
    .unwrap();
    drop(conn);

    let mut store = open(&path, ledger("cluster-a", 100)).unwrap();
    assert!(
        store
            .purge(LogId::new(CommittedLeaderId::new(4, 1), 2))
            .await
            .is_err()
    );
    store.purge(log).await.unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM raft_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        0, count,
        "purge advances the durable boundary and deletes its inclusive prefix together"
    );
}
