//! Durable OpenRaft 0.9.25 storage for the budget authority.
//!
//! Every SQLite write runs on the blocking pool behind one semaphore. The
//! semaphore is shared by log-reader, log-store and state-machine clones:
//! OpenRaft requires serialized vote/log I/O, and a budget reply cannot become
//! visible before the transaction containing its applied index commits.

use super::raft_types::{BudgetSnapshotData, BudgetTypeConfig, MAX_BUDGET_SNAPSHOT_BYTES};
use super::state_machine::BudgetLedger;
use super::types::{BudgetClusterConfig, BudgetReply, BudgetRejection};
use anyhow::{anyhow, bail, Context, Result};
use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader,
    RaftSnapshotBuilder, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

const META_VOTE: &str = "vote";
const META_COMMITTED: &str = "committed";
const META_PURGED: &str = "purged";
const META_CONFIG: &str = "frozen-config";
const STATE_ROW: i64 = 1;
const SNAPSHOT_ROW: i64 = 1;

type RaftEntry = Entry<BudgetTypeConfig>;
type RaftSnapshot = SnapshotMeta<u64, openraft::BasicNode>;

/// A cloneable value given to OpenRaft as both its log store and state machine.
/// It intentionally has no cached mutable ledger: SQLite is recovery truth.
#[derive(Clone)]
pub struct BudgetRaftStore {
    db: Arc<std::sync::Mutex<Connection>>,
    io: Arc<Semaphore>,
}

impl std::fmt::Debug for BudgetRaftStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BudgetRaftStore").finish_non_exhaustive()
    }
}

/// Opens a durable store, or creates a pristine store for `initial`.
/// Existing metadata must match the frozen config exactly. Corrupt/missing
/// applied state is an error; this function never treats it as a new database.
pub fn open(path: &Path, initial: BudgetLedger) -> Result<BudgetRaftStore> {
    initial.validate().map_err(|error| anyhow!("initial budget ledger violates frozen configuration invariants: {error:?}"))?;
    let mut conn = Connection::open(path)
        .with_context(|| format!("open budget raft store {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS raft_meta (
             key TEXT PRIMARY KEY NOT NULL,
             value BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS raft_log (
             log_index INTEGER PRIMARY KEY NOT NULL CHECK(log_index >= 0),
             term INTEGER NOT NULL CHECK(term >= 0),
             entry BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS raft_state (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
             last_applied BLOB,
             membership BLOB NOT NULL,
             ledger BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS raft_snapshot (
             singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
             metadata BLOB NOT NULL,
             snapshot BLOB NOT NULL
         ) STRICT;
         COMMIT;",
    )?;

    let config = to_json(initial.config()).context("encode frozen budget config")?;
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM raft_meta WHERE key = ?1", [META_CONFIG], |row| row.get(0))
        .optional()?;
    match stored {
        Some(blob) => {
            let existing: BudgetClusterConfig = from_json(&blob).context("decode frozen budget config")?;
            if existing != *initial.config() || blob != config {
                bail!("budget raft frozen configuration does not match existing store");
            }
            let ledger: Option<Vec<u8>> = conn
                .query_row("SELECT ledger FROM raft_state WHERE singleton = ?1", [STATE_ROW], |row| row.get(0))
                .optional()?;
            let recovered: BudgetLedger = from_json(&ledger.ok_or_else(|| anyhow!("budget raft config exists but applied ledger is absent"))?)
                .context("decode persisted budget ledger")?;
            recovered.validate().map_err(|error| anyhow!("persisted budget ledger violates recovery invariants: {error:?}"))?;
            if recovered.config() != initial.config() {
                bail!("persisted ledger configuration does not match frozen store config");
            }
            let _ = state(&conn)?;
            validate_persisted_snapshot(&conn, initial.config())?;
        }
        None => {
            let log_count: i64 = conn.query_row("SELECT COUNT(*) FROM raft_log", [], |row| row.get(0))?;
            let state_exists: Option<i64> = conn.query_row(
                "SELECT singleton FROM raft_state WHERE singleton = ?1", [STATE_ROW], |row| row.get(0),
            ).optional()?;
            let meta_count: i64 = conn.query_row("SELECT COUNT(*) FROM raft_meta", [], |row| row.get(0))?;
            let snapshot_count: i64 = conn.query_row("SELECT COUNT(*) FROM raft_snapshot", [], |row| row.get(0))?;
            let legacy_hard_state: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'raft_hard_state'", [], |row| row.get(0),
            )?;
            let legacy_hard_values: i64 = if legacy_hard_state == 0 { 0 } else {
                conn.query_row("SELECT COUNT(*) FROM raft_hard_state WHERE vote IS NOT NULL OR committed_log IS NOT NULL", [], |row| row.get(0))?
            };
            let legacy_applied: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'raft_applied'", [], |row| row.get(0),
            )?;
            let legacy_applied_values: i64 = if legacy_applied == 0 { 0 } else {
                conn.query_row("SELECT COUNT(*) FROM raft_applied WHERE last_applied IS NOT NULL OR grants IS NOT NULL", [], |row| row.get(0))?
            };
            if log_count != 0 || state_exists.is_some() || meta_count != 0 || snapshot_count != 0 || legacy_hard_values != 0 || legacy_applied_values != 0 {
                bail!("budget raft store has durable state but no frozen configuration marker");
            }
            let tx = conn.transaction()?;
            tx.execute("INSERT INTO raft_meta(key, value) VALUES(?1, ?2)", params![META_CONFIG, config])?;
            tx.execute(
                "INSERT INTO raft_state(singleton, last_applied, membership, ledger) VALUES(?1, NULL, ?2, ?3)",
                params![STATE_ROW, to_json(&StoredMembership::<u64, openraft::BasicNode>::default())?, to_json(&initial)?],
            )?;
            tx.commit()?;
        }
    }
    Ok(BudgetRaftStore { db: Arc::new(std::sync::Mutex::new(conn)), io: Arc::new(Semaphore::new(1)) })
}

impl BudgetRaftStore {
    async fn blocking<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let permit = self.io.clone().acquire_owned().await.context("budget raft I/O semaphore closed")?;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut conn = db.lock().map_err(|_| anyhow!("budget raft SQLite mutex poisoned"))?;
            f(&mut conn)
        }).await.map_err(|e| anyhow!("budget raft SQLite task failed: {e}"))?
    }

    async fn storage<T, F>(&self, subject: ErrorSubject<u64>, verb: ErrorVerb, f: F) -> Result<T, StorageError<u64>>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.blocking(f).await.map_err(|e| StorageError::IO { source: StorageIOError::new(subject, verb, e) })
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>> { Ok(serde_json::to_vec(value)?) }
fn from_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> { Ok(serde_json::from_slice(bytes)?) }
fn sql_index(index: u64) -> Result<i64> { Ok(i64::try_from(index).map_err(|_| anyhow!("raft index exceeds SQLite INTEGER range"))?) }

fn read_meta<T: DeserializeOwned>(conn: &Connection, key: &str) -> Result<Option<T>> {
    let bytes: Option<Vec<u8>> = conn.query_row("SELECT value FROM raft_meta WHERE key = ?1", [key], |row| row.get(0)).optional()?;
    bytes.map(|value| from_json(&value)).transpose()
}

fn write_meta<T: Serialize>(tx: &Transaction<'_>, key: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO raft_meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, to_json(value)?],
    )?;
    Ok(())
}

fn state(conn: &Connection) -> Result<(Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>, BudgetLedger)> {
    let (last, membership, ledger): (Option<Vec<u8>>, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT last_applied, membership, ledger FROM raft_state WHERE singleton = ?1", [STATE_ROW],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let ledger: BudgetLedger = from_json(&ledger)?;
    ledger.validate().map_err(|error| anyhow!("persisted budget ledger violates recovery invariants: {error:?}"))?;
    let last = last.map(|bytes| from_json(&bytes)).transpose()?;
    let membership = from_json(&membership)?;
    validate_membership(ledger.config(), &last, &membership)?;
    Ok((last, membership, ledger))
}

fn save_state(tx: &Transaction<'_>, last: &Option<LogId<u64>>, membership: &StoredMembership<u64, openraft::BasicNode>, ledger: &BudgetLedger) -> Result<()> {
    validate_membership(ledger.config(), last, membership)?;
    tx.execute(
        "UPDATE raft_state SET last_applied = ?2, membership = ?3, ledger = ?4 WHERE singleton = ?1",
        params![STATE_ROW, last.as_ref().map(to_json).transpose()?, to_json(membership)?, to_json(ledger)?],
    )?;
    Ok(())
}

fn validate_membership(
    config: &BudgetClusterConfig,
    last_applied: &Option<LogId<u64>>,
    stored: &StoredMembership<u64, openraft::BasicNode>,
) -> Result<()> {
    let membership = stored.membership();
    let pristine = last_applied.is_none()
        && stored.log_id().is_none()
        && membership.get_joint_config().is_empty()
        && membership.nodes().next().is_none();
    if pristine {
        return Ok(());
    }
    let membership_log = stored
        .log_id()
        .as_ref()
        .ok_or_else(|| anyhow!("non-pristine budget membership has no log id"))?;
    let applied = last_applied
        .as_ref()
        .ok_or_else(|| anyhow!("non-pristine budget membership has no applied index"))?;
    if membership_log.index > applied.index {
        bail!("budget membership is newer than applied state");
    }
    let expected = config.raft_voters();
    let expected_ids = expected.keys().copied().collect::<std::collections::BTreeSet<_>>();
    let actual_configs = membership.get_joint_config();
    if actual_configs.len() != 1 || actual_configs[0] != expected_ids {
        bail!("budget membership is dynamic, joint, or has an unexpected voter set");
    }
    let actual_nodes = membership
        .nodes()
        .map(|(id, node)| (*id, node.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    if actual_nodes != expected {
        bail!("budget membership nodes do not match canonical frozen voter ids");
    }
    Ok(())
}

fn validate_persisted_snapshot(conn: &Connection, config: &BudgetClusterConfig) -> Result<()> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn.query_row(
        "SELECT metadata, snapshot FROM raft_snapshot WHERE singleton = ?1",
        [SNAPSHOT_ROW],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let Some((metadata, bytes)) = row else { return Ok(()); };
    if bytes.len() > MAX_BUDGET_SNAPSHOT_BYTES {
        bail!("persisted budget raft snapshot exceeds byte bound");
    }
    let meta: RaftSnapshot = from_json(&metadata)?;
    let (last, membership, ledger): (Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>, BudgetLedger) = from_json(&bytes)?;
    ledger.validate().map_err(|error| anyhow!("persisted budget raft snapshot violates recovery invariants: {error:?}"))?;
    validate_membership(config, &last, &membership)?;
    if last != meta.last_log_id || membership != meta.last_membership || ledger.config() != config {
        bail!("persisted budget raft snapshot does not match durable metadata/configuration");
    }
    Ok(())
}

impl RaftLogReader<BudgetTypeConfig> for BudgetRaftStore {
    async fn try_get_log_entries<RB>(&mut self, range: RB) -> Result<Vec<RaftEntry>, StorageError<u64>>
    where RB: RangeBounds<u64> + Clone + Debug + openraft::OptionalSend {
        let lower = match range.start_bound() { Bound::Included(v) => *v, Bound::Excluded(v) => v.saturating_add(1), Bound::Unbounded => 0 };
        let upper = match range.end_bound() { Bound::Included(v) => v.checked_add(1), Bound::Excluded(v) => Some(*v), Bound::Unbounded => None };
        self.storage(ErrorSubject::Logs, ErrorVerb::Read, move |conn| {
            let mut entries = Vec::new();
            match upper {
                Some(end) => {
                    let mut statement = conn.prepare("SELECT entry FROM raft_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index ASC")?;
                    let mut rows = statement.query(params![sql_index(lower)?, sql_index(end)?])?;
                    while let Some(row) = rows.next()? { entries.push(from_json(&row.get::<_, Vec<u8>>(0)?)?); }
                }
                None => {
                    let mut statement = conn.prepare("SELECT entry FROM raft_log WHERE log_index >= ?1 ORDER BY log_index ASC")?;
                    let mut rows = statement.query(params![sql_index(lower)?])?;
                    while let Some(row) = rows.next()? { entries.push(from_json(&row.get::<_, Vec<u8>>(0)?)?); }
                }
            }
            Ok(entries)
        }).await
    }
}

impl RaftLogStorage<BudgetTypeConfig> for BudgetRaftStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<BudgetTypeConfig>, StorageError<u64>> {
        self.storage(ErrorSubject::Logs, ErrorVerb::Read, |conn| {
            let purged: Option<LogId<u64>> = read_meta(conn, META_PURGED)?;
            let bytes: Option<Vec<u8>> = conn.query_row("SELECT entry FROM raft_log ORDER BY log_index DESC LIMIT 1", [], |row| row.get(0)).optional()?;
            let last_log_id = bytes.map(|b| from_json::<RaftEntry>(&b).map(|e| e.log_id)).transpose()?.or_else(|| purged.clone());
            Ok(LogState { last_purged_log_id: purged, last_log_id })
        }).await
    }
    async fn get_log_reader(&mut self) -> Self::LogReader { self.clone() }
    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let vote = vote.clone();
        self.storage(ErrorSubject::Vote, ErrorVerb::Write, move |conn| { let tx = conn.transaction()?; write_meta(&tx, META_VOTE, &vote)?; tx.commit()?; Ok(()) }).await
    }
    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> { self.storage(ErrorSubject::Vote, ErrorVerb::Read, |conn| read_meta(conn, META_VOTE)).await }
    async fn save_committed(&mut self, committed: Option<LogId<u64>>) -> Result<(), StorageError<u64>> {
        self.storage(ErrorSubject::Store, ErrorVerb::Write, move |conn| { let tx = conn.transaction()?; write_meta(&tx, META_COMMITTED, &committed)?; tx.commit()?; Ok(()) }).await
    }
    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> { self.storage(ErrorSubject::Store, ErrorVerb::Read, |conn| read_meta(conn, META_COMMITTED)).await }
    async fn append<I>(&mut self, entries: I, callback: LogFlushed<BudgetTypeConfig>) -> Result<(), StorageError<u64>>
    where I: IntoIterator<Item = RaftEntry> + openraft::OptionalSend, I::IntoIter: openraft::OptionalSend {
        let entries: Vec<_> = entries.into_iter().collect();
        let persisted = self.storage(ErrorSubject::Logs, ErrorVerb::Write, move |conn| {
            let tx = conn.transaction()?;
            let purged: Option<LogId<u64>> = read_meta(&tx, META_PURGED)?;
            let last: Option<Vec<u8>> = tx.query_row("SELECT entry FROM raft_log ORDER BY log_index DESC LIMIT 1", [], |row| row.get(0)).optional()?;
            let mut previous = last.map(|b| from_json::<RaftEntry>(&b).map(|e| e.log_id)).transpose()?.or(purged.clone());
            for entry in &entries {
                if purged.as_ref().is_some_and(|p| entry.log_id.index <= p.index) { bail!("append would restore a purged Raft log"); }
                if let Some(prev) = &previous { if entry.log_id.index > prev.index.saturating_add(1) { bail!("Raft append would leave a log hole"); } }
                previous = Some(entry.log_id.clone());
            }
            for entry in entries {
                tx.execute(
                    "INSERT INTO raft_log(log_index, term, entry) VALUES(?1, ?2, ?3)
                     ON CONFLICT(log_index) DO UPDATE SET term = excluded.term, entry = excluded.entry",
                    params![sql_index(entry.log_id.index)?, sql_index(entry.log_id.leader_id.term)?, to_json(&entry)?],
                )?;
            }
            tx.commit()?; Ok(())
        }).await;
        match persisted { Ok(()) => { callback.log_io_completed(Ok(())); Ok(()) }, Err(error) => { callback.log_io_completed(Err(std::io::Error::other(error.to_string()))); Err(error) } }
    }
    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.storage(ErrorSubject::Logs, ErrorVerb::Delete, move |conn| {
            let (applied, _, _) = state(conn)?;
            if applied.as_ref().is_some_and(|last| last.index >= log_id.index) { bail!("would truncate an applied Raft log"); }
            let tx = conn.transaction()?; tx.execute("DELETE FROM raft_log WHERE log_index >= ?1", [sql_index(log_id.index)?])?; tx.commit()?; Ok(())
        }).await
    }
    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.storage(ErrorSubject::Logs, ErrorVerb::Delete, move |conn| {
            let (applied, _, _) = state(conn)?;
            if applied.as_ref().is_none_or(|last| last.index < log_id.index) { bail!("would purge a non-applied Raft log"); }
            let tx = conn.transaction()?;
            let old: Option<LogId<u64>> = read_meta(&tx, META_PURGED)?;
            if old.as_ref().is_some_and(|previous| previous.index > log_id.index) { bail!("would move last-purged Raft log backwards"); }
            write_meta(&tx, META_PURGED, &log_id)?;
            tx.execute("DELETE FROM raft_log WHERE log_index <= ?1", [sql_index(log_id.index)?])?;
            tx.commit()?; Ok(())
        }).await
    }
}

impl RaftStateMachine<BudgetTypeConfig> for BudgetRaftStore {
    type SnapshotBuilder = Self;
    async fn applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>), StorageError<u64>> {
        self.storage(ErrorSubject::StateMachine, ErrorVerb::Read, |conn| { let (last, membership, _) = state(conn)?; Ok((last, membership)) }).await
    }
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<BudgetReply>, StorageError<u64>>
    where I: IntoIterator<Item = RaftEntry> + openraft::OptionalSend, I::IntoIter: openraft::OptionalSend {
        let entries: Vec<_> = entries.into_iter().collect();
        self.storage(ErrorSubject::StateMachine, ErrorVerb::Write, move |conn| {
            let tx = conn.transaction()?;
            let (mut last, mut membership, mut ledger) = state(&tx)?;
            let mut replies = Vec::with_capacity(entries.len());
            for entry in entries {
                if last.as_ref().is_some_and(|previous| entry.log_id.index != previous.index.saturating_add(1)) { bail!("would apply a non-consecutive Raft log"); }
                let reply = match entry.payload {
                    EntryPayload::Blank => BudgetReply::Rejected(BudgetRejection::InvalidConfig),
                    EntryPayload::Normal(command) => ledger.apply(entry.log_id.leader_id.term, entry.log_id.index, command),
                    EntryPayload::Membership(config) => { membership = StoredMembership::new(Some(entry.log_id.clone()), config); BudgetReply::Rejected(BudgetRejection::InvalidConfig) }
                };
                last = Some(entry.log_id); replies.push(reply);
            }
            ledger.validate().map_err(|error| anyhow!("committed budget ledger transition violates invariants: {error:?}"))?;
            save_state(&tx, &last, &membership, &ledger)?;
            tx.commit()?; Ok(replies)
        }).await
    }
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder { self.clone() }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<BudgetSnapshotData>, StorageError<u64>> {
        Ok(Box::new(BudgetSnapshotData::empty()))
    }
    async fn install_snapshot(&mut self, meta: &RaftSnapshot, snapshot: Box<BudgetSnapshotData>) -> Result<(), StorageError<u64>> {
        let meta = meta.clone(); let bytes = snapshot.into_inner();
        self.storage(ErrorSubject::Snapshot(Some(meta.signature())), ErrorVerb::Write, move |conn| {
            if bytes.len() > MAX_BUDGET_SNAPSHOT_BYTES { bail!("received budget raft snapshot exceeds byte bound"); }
            let (last, membership, ledger): (Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>, BudgetLedger) = from_json(&bytes).context("decode budget raft snapshot")?;
            if last != meta.last_log_id || membership != meta.last_membership { bail!("budget raft snapshot metadata does not match state"); }
            ledger.validate().map_err(|error| anyhow!("budget raft snapshot violates recovery invariants: {error:?}"))?;
            validate_membership(ledger.config(), &last, &membership)?;
            let (_, _, current_ledger) = state(conn)?;
            if ledger.config() != current_ledger.config() { bail!("budget raft snapshot frozen configuration does not match this store"); }
            let tx = conn.transaction()?; save_state(&tx, &last, &membership, &ledger)?;
            tx.execute("INSERT INTO raft_snapshot(singleton, metadata, snapshot) VALUES(?1, ?2, ?3) ON CONFLICT(singleton) DO UPDATE SET metadata = excluded.metadata, snapshot = excluded.snapshot", params![SNAPSHOT_ROW, to_json(&meta)?, bytes])?;
            tx.commit()?; Ok(())
        }).await
    }
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<BudgetTypeConfig>>, StorageError<u64>> {
        self.storage(ErrorSubject::Snapshot(None), ErrorVerb::Read, |conn| {
            let row: Option<(Vec<u8>, Vec<u8>)> = conn.query_row("SELECT metadata, snapshot FROM raft_snapshot WHERE singleton = ?1", [SNAPSHOT_ROW], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
            row.map(|(metadata, bytes)| {
                if bytes.len() > MAX_BUDGET_SNAPSHOT_BYTES { bail!("persisted budget raft snapshot exceeds byte bound"); }
                let meta: RaftSnapshot = from_json(&metadata)?;
                let (last, membership, ledger): (Option<LogId<u64>>, StoredMembership<u64, openraft::BasicNode>, BudgetLedger) = from_json(&bytes)?;
                let (_, _, current_ledger) = state(conn)?;
                ledger.validate().map_err(|error| anyhow!("persisted budget raft snapshot violates recovery invariants: {error:?}"))?;
                validate_membership(ledger.config(), &last, &membership)?;
                if last != meta.last_log_id || membership != meta.last_membership || ledger.config() != current_ledger.config() {
                    bail!("persisted budget raft snapshot does not match durable metadata/configuration");
                }
                Ok(Snapshot {
                    meta,
                    snapshot: Box::new(BudgetSnapshotData::from_bytes(bytes)
                        .context("persisted budget raft snapshot exceeds byte bound")?),
                })
            }).transpose()
        }).await
    }
}

impl RaftSnapshotBuilder<BudgetTypeConfig> for BudgetRaftStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<BudgetTypeConfig>, StorageError<u64>> {
        self.storage(ErrorSubject::Snapshot(None), ErrorVerb::Write, |conn| {
            let (last, membership, ledger) = state(conn)?;
            let bytes = to_json(&(last.clone(), membership.clone(), ledger))?;
            if bytes.len() > MAX_BUDGET_SNAPSHOT_BYTES { bail!("built budget raft snapshot exceeds byte bound"); }
            let snapshot_id = match &last { Some(log) => format!("budget-{}-{}", log.leader_id.term, log.index), None => "budget-empty".to_owned() };
            let meta = SnapshotMeta { last_log_id: last, last_membership: membership, snapshot_id };
            let tx = conn.transaction()?;
            tx.execute("INSERT INTO raft_snapshot(singleton, metadata, snapshot) VALUES(?1, ?2, ?3) ON CONFLICT(singleton) DO UPDATE SET metadata = excluded.metadata, snapshot = excluded.snapshot", params![SNAPSHOT_ROW, to_json(&meta)?, &bytes])?;
            tx.commit()?;
            Ok(Snapshot {
                meta,
                snapshot: Box::new(BudgetSnapshotData::from_bytes(bytes)
                    .context("built budget raft snapshot exceeds byte bound")?),
            })
        }).await
    }
}
