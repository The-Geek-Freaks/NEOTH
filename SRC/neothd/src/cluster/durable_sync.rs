//! Durable, transport-independent cluster synchronization.
//!
//! A peer's scan cursor is committed only after an authenticated ACK for the
//! exact `(origin, sequence, content digest)` tuple. The pending wire frame and
//! its next cursor are stored in `views.db`, so disconnects and process
//! restarts replay byte-for-byte without skipping an event.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::PeerPubkey;
use super::gossip::GossipPolicy;
use super::gossip_wire::{
    GossipAcceptance, GossipAck, GossipFrame, GroundTruthSnapshot, MAX_VECTOR_CLOCK_PEERS,
    MemorySnapshot, SYNC_ENVELOPE_VERSION, SYNC_PROTOCOL_VERSION, SyncContent, SyncEnvelope,
    VectorClock,
};
use super::wal_sync::{
    GossipWalCursor, ReplicationClass, SharedGossipState, classify_event_ext,
    gossip_payload_event_meta, gossip_payload_timestamp_unix, is_replicable_ext,
    read_gossipable_batch,
};

const MAX_MEMORY_TEXT_BYTES: usize = 1_048_576;
const MAX_STABLE_CONTENT_ID_BYTES: usize = 128;
pub const SYNC_REQUEST_TTL_SECS: i64 = 15 * 60;
pub const SYNC_REQUEST_RETRY_SECS: i64 = 2;
const SYNC_REQUEST_POLL_LIMIT: i64 = 32;

#[derive(Clone, Debug)]
pub struct DurableMeshSync {
    db_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFrame {
    pub frame: GossipFrame,
    pub replayed_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundAckOutcome {
    Applied,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundCommit {
    Committed(GossipAck),
    Duplicate(GossipAck),
    /// A pre-v31 receipt proves the content was committed but carries no
    /// canonical frame binding. It may be ACKed for delivery progress, but it
    /// must never authorize a causal-frontier merge.
    DuplicateUnbound(GossipAck),
    Gap {
        expected: u64,
        received: u64,
    },
    Dropped(GossipAcceptance),
}

impl InboundCommit {
    pub fn ack(&self) -> Option<&GossipAck> {
        match self {
            Self::Committed(ack) | Self::Duplicate(ack) | Self::DuplicateUnbound(ack) => Some(ack),
            Self::Gap { .. } | Self::Dropped(_) => None,
        }
    }
}

/// Mirror a frame into the live observability state only when the durable
/// receive state machine proves that the exact frame is already committed.
/// The authoritative frontier is merged inside the SQLite transaction;
/// `Duplicate` is included so a restarted runtime mirror can catch up without
/// weakening the persist-before-ACK contract.
pub fn merge_frontier_after_durable_commit(
    state: &SharedGossipState,
    frame: &GossipFrame,
    outcome: &InboundCommit,
) -> bool {
    if !matches!(
        outcome,
        InboundCommit::Committed(_) | InboundCommit::Duplicate(_)
    ) {
        return false;
    }
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .commit_authenticated_inbound(frame);
    true
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MeshPeerStatus {
    pub peer_pk: String,
    pub cursor_segment: Option<String>,
    pub cursor_offset: u64,
    pub acked_origin_seq: u64,
    pub pending_origin_seq: Option<u64>,
    pub pending_attempts: Option<u64>,
    pub inbound_next_expected_seq: Option<u64>,
    pub request_state: Option<String>,
    pub request_requested_at: Option<i64>,
    pub request_updated_at: Option<i64>,
    pub request_expires_at: Option<i64>,
    pub request_send_attempts: Option<u64>,
    pub request_last_error: Option<String>,
}

/// Durable receipt for a local operator-requested accelerated peer catch-up.
/// One row per paired peer coalesces repeated clicks without creating an
/// unbounded command queue. The daemon is the only consumer with a transport
/// handle; CLI and GUI processes can only enqueue this exact peer identity.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MeshSyncRequest {
    pub operation: &'static str,
    pub peer_pk: String,
    pub state: String,
    pub requested_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
    pub last_attempt_at: Option<i64>,
    pub send_attempts: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VectorFrontierEntry {
    pub peer_pk: String,
    pub counter: u64,
}

/// One durable content divergence detected while materializing mesh frames.
/// Digests are hex encoded at this boundary so CLI/GUI consumers never need
/// to interpret SQLite blobs.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MeshConflict {
    pub id: i64,
    pub content_id: String,
    pub incumbent_origin: String,
    pub incoming_origin: String,
    pub incumbent_sha256: String,
    pub incoming_sha256: String,
    pub policy: String,
    pub observed_at: i64,
    pub resolved_at: Option<i64>,
    pub preferred_origin: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MeshConflictResolution {
    pub operation: &'static str,
    pub content_id: String,
    pub preferred_origin: String,
    pub resolved_count: usize,
    pub unresolved_remaining: usize,
}

#[derive(Clone, Debug)]
struct OutboundState {
    cursor: GossipWalCursor,
}

#[derive(Clone, Debug)]
struct PendingRow {
    origin_seq: u64,
    content_sha256: [u8; 32],
    wire_frame: Vec<u8>,
    next_cursor_segment: Option<PathBuf>,
    next_cursor_offset: usize,
}

impl DurableMeshSync {
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Load an exact pending frame or stage the next WAL event for one peer.
    /// Staging stores the pending frame and next cursor atomically; it does not
    /// advance the acknowledged cursor.
    pub async fn prepare_peer_frame(
        &self,
        peer: &PeerPubkey,
        origin: &PeerPubkey,
        wal_dir: &Path,
        policy: &GossipPolicy,
        state: &SharedGossipState,
    ) -> Result<Option<PreparedFrame>> {
        let db_path = self.db_path.clone();
        let peer_for_load = peer.clone();
        let origin_for_load = origin.clone();
        let wal_dir_owned = wal_dir.to_path_buf();
        let loaded = tokio::task::spawn_blocking(move || -> Result<_> {
            let conn = crate::memory::store::open(&db_path)
                .with_context(|| format!("open durable mesh DB {}", db_path.display()))?;
            if let Some(pending) = load_pending(&conn, &peer_for_load)? {
                let frame = validate_pending(&pending, &origin_for_load)?;
                validate_pending_cursor(&pending, &wal_dir_owned)?;
                return Ok((
                    Some(PreparedFrame {
                        frame,
                        replayed_pending: true,
                    }),
                    None,
                ));
            }
            let state = load_outbound_state(&conn, &peer_for_load, &wal_dir_owned)?;
            Ok((None, Some(state)))
        })
        .await
        .context("durable mesh state loader panicked")??;

        let (pending, outbound_state) = loaded;
        if let Some(prepared) = pending {
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .commit_outbound(&prepared.frame);
            return Ok(Some(prepared));
        }
        let mut cursor = outbound_state
            .expect("state loader returns cursor when no pending frame exists")
            .cursor;
        let frames = read_gossipable_batch(wal_dir, &mut cursor, policy, 1)
            .await
            .context("durable mesh WAL scan failed closed")?;
        let Some((event_type, raw)) = frames.into_iter().next() else {
            let db_path = self.db_path.clone();
            let peer = peer.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut conn = crate::memory::store::open(&db_path)?;
                persist_idle_cursor(&mut conn, &peer, &cursor)
            })
            .await
            .context("durable mesh idle-cursor task panicked")??;
            return Ok(None);
        };

        let event_subtype = gossip_payload_event_meta(&raw)
            .map(|(_, subtype)| subtype)
            .context("durable mesh scanner returned a malformed WAL frame")?;
        ensure!(
            is_replicable_ext(event_type, event_subtype, policy),
            "durable mesh scanner crossed the replication ACL"
        );
        let db_path = self.db_path.clone();
        let peer = peer.clone();
        let origin = origin.clone();
        let policy = policy.clone();
        let prepared = tokio::task::spawn_blocking(move || -> Result<Option<PreparedFrame>> {
            let mut conn = crate::memory::store::open(&db_path)?;
            stage_frame(
                &mut conn,
                &peer,
                &origin,
                event_type,
                event_subtype,
                &raw,
                &cursor,
                &policy,
            )
            .map(Some)
        })
        .await
        .context("durable mesh frame-staging task panicked")??;
        if let Some(prepared) = prepared.as_ref() {
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .commit_outbound(&prepared.frame);
        }
        Ok(prepared)
    }

    pub fn record_send_attempt(&self, peer: &PeerPubkey) -> Result<()> {
        let conn = crate::memory::store::open(&self.db_path)?;
        let changed = conn.execute(
            "UPDATE mesh_sync_outbound_pending SET attempts = attempts + 1 WHERE peer_pk = ?1",
            [peer.as_str()],
        )?;
        ensure!(
            changed == 1,
            "no pending mesh frame for peer {}",
            peer.as_str()
        );
        Ok(())
    }

    /// Apply an ACK from the authenticated peer. Only an exact match advances
    /// the cursor; duplicate ACKs are idempotent and mismatches fail closed.
    pub fn acknowledge_outbound(
        &self,
        authenticated_peer: &PeerPubkey,
        local_origin: &PeerPubkey,
        ack: &GossipAck,
    ) -> Result<OutboundAckOutcome> {
        let mut conn = crate::memory::store::open(&self.db_path)?;
        acknowledge_outbound_on_conn(&mut conn, authenticated_peer, local_origin, ack)
    }

    /// Persist one inbound frame and return an ACK only after SQLite commits.
    pub fn persist_inbound(
        &self,
        authenticated_peer: &PeerPubkey,
        frame: &GossipFrame,
        policy: &GossipPolicy,
    ) -> Result<InboundCommit> {
        let mut conn = crate::memory::store::open(&self.db_path)?;
        persist_inbound_on_conn(&mut conn, authenticated_peer, frame, policy)
    }

    pub fn list_status(&self, peer_filter: Option<&str>) -> Result<Vec<MeshPeerStatus>> {
        let conn = crate::memory::store::open(&self.db_path)?;
        list_status_on_conn(&conn, peer_filter)
    }

    /// Enqueue (or restart) an accelerated catch-up for one already-paired
    /// peer. Repeated requests coalesce into the peer's primary-key row.
    pub fn request_sync(&self, peer: &PeerPubkey, now: i64) -> Result<MeshSyncRequest> {
        ensure!(now > 0, "mesh sync request timestamp must be positive");
        let mut conn = crate::memory::store::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Terminal receipts are useful briefly for GUI feedback, but never
        // grow without bound across long-lived installations.
        tx.execute(
            "DELETE FROM mesh_sync_requests WHERE state IN ('complete','expired') AND updated_at < ?1",
            [now.saturating_sub(24 * 60 * 60)],
        )?;
        let expires_at = now
            .checked_add(SYNC_REQUEST_TTL_SECS)
            .context("mesh sync request expiry overflow")?;
        tx.execute(
            "INSERT INTO mesh_sync_requests \
             (peer_pk,requested_at,expires_at,state,updated_at,last_attempt_at,send_attempts,last_error) \
             VALUES (?1,?2,?3,'queued',?2,NULL,0,NULL) \
             ON CONFLICT(peer_pk) DO UPDATE SET \
               requested_at=excluded.requested_at, expires_at=excluded.expires_at, \
               state='queued', updated_at=excluded.updated_at, last_attempt_at=NULL, \
               send_attempts=0, last_error=NULL",
            params![peer.as_str(), now, expires_at],
        )?;
        let receipt = load_sync_request_on_conn(&tx, peer)?
            .context("mesh sync request vanished before commit")?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Return requests due for another daemon-owned send attempt. This method
    /// also expires stale rows transactionally, so a stopped/offline peer is
    /// reported honestly instead of remaining queued forever.
    pub fn due_sync_requests(&self, now: i64) -> Result<Vec<MeshSyncRequest>> {
        ensure!(now > 0, "mesh sync request poll timestamp must be positive");
        let mut conn = crate::memory::store::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE mesh_sync_requests SET state='expired', updated_at=?1, \
             last_error='request expired before the peer caught up' \
             WHERE state IN ('queued','active','waiting_peer') AND expires_at <= ?1",
            [now],
        )?;
        let retry_before = now.saturating_sub(SYNC_REQUEST_RETRY_SECS);
        let requests = list_due_sync_requests_on_conn(&tx, now, retry_before)?;
        tx.commit()?;
        Ok(requests)
    }

    pub fn mark_sync_request_waiting(
        &self,
        peer: &PeerPubkey,
        now: i64,
        error: &str,
    ) -> Result<()> {
        update_sync_request_on_conn(
            &crate::memory::store::open(&self.db_path)?,
            peer,
            now,
            "waiting_peer",
            false,
            Some(error),
        )
    }

    pub fn mark_sync_request_sent(&self, peer: &PeerPubkey, now: i64) -> Result<()> {
        update_sync_request_on_conn(
            &crate::memory::store::open(&self.db_path)?,
            peer,
            now,
            "active",
            true,
            None,
        )
    }

    pub fn mark_sync_request_complete(&self, peer: &PeerPubkey, now: i64) -> Result<()> {
        update_sync_request_on_conn(
            &crate::memory::store::open(&self.db_path)?,
            peer,
            now,
            "complete",
            false,
            None,
        )
    }

    /// Read the authoritative durable causal frontier in stable peer-id order.
    pub fn list_vector_frontier(&self) -> Result<Vec<VectorFrontierEntry>> {
        let conn = crate::memory::store::open(&self.db_path)?;
        Ok(load_vector_frontier(&conn)?
            .clocks
            .into_iter()
            .map(|(peer, counter)| VectorFrontierEntry {
                peer_pk: peer.as_str().to_string(),
                counter,
            })
            .collect())
    }

    /// List the newest typed conflicts. The default operator surface excludes
    /// acknowledged rows; `include_resolved` is for forensic history.
    pub fn list_conflicts(
        &self,
        content_id: Option<&str>,
        limit: usize,
        include_resolved: bool,
    ) -> Result<Vec<MeshConflict>> {
        ensure!(
            (1..=1_000).contains(&limit),
            "conflict limit must be 1..=1000"
        );
        if let Some(content_id) = content_id {
            ensure!(
                !content_id.trim().is_empty(),
                "conflict content_id must not be empty"
            );
            ensure!(
                content_id.len() <= MAX_STABLE_CONTENT_ID_BYTES,
                "conflict content_id exceeds {MAX_STABLE_CONTENT_ID_BYTES} bytes"
            );
        }
        let conn = crate::memory::store::open(&self.db_path)?;
        list_conflicts_on_conn(&conn, content_id, limit, include_resolved)
    }

    pub fn unresolved_conflict_count(&self) -> Result<usize> {
        let conn = crate::memory::store::open(&self.db_path)?;
        unresolved_conflict_count_on_conn(&conn, None)
    }

    /// Acknowledge every currently-known divergence for one stable content id.
    /// The preferred origin must exist in the canonical materialized ledger.
    /// Existing conflict rows remain as forensic history; a future digest pair
    /// creates a fresh unresolved row and becomes visible again.
    pub fn resolve_conflicts(
        &self,
        content_id: &str,
        preferred_origin: &str,
    ) -> Result<MeshConflictResolution> {
        ensure!(
            !content_id.trim().is_empty(),
            "conflict content_id must not be empty"
        );
        ensure!(
            content_id.len() <= MAX_STABLE_CONTENT_ID_BYTES,
            "conflict content_id exceeds {MAX_STABLE_CONTENT_ID_BYTES} bytes"
        );
        ensure!(
            !preferred_origin.trim().is_empty(),
            "preferred origin must not be empty"
        );
        let mut conn = crate::memory::store::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let origin_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mesh_sync_materialized \
             WHERE content_id = ?1 AND origin_peer_pk = ?2)",
            params![content_id, preferred_origin],
            |row| row.get(0),
        )?;
        ensure!(
            origin_exists,
            "preferred origin `{preferred_origin}` has no materialized `{content_id}` content"
        );
        let resolved_at = crate::time::now_unix_i64();
        let resolved_count = tx.execute(
            "UPDATE mesh_sync_conflicts \
             SET resolved_at = ?1, preferred_origin = ?2 \
             WHERE content_id = ?3 AND resolved_at IS NULL",
            params![resolved_at, preferred_origin, content_id],
        )?;
        ensure!(
            resolved_count > 0,
            "no unresolved mesh conflicts for `{content_id}`"
        );
        let unresolved_remaining = unresolved_conflict_count_on_conn(&tx, Some(content_id))?;
        tx.commit()?;
        Ok(MeshConflictResolution {
            operation: "cluster.conflicts.resolve",
            content_id: content_id.to_string(),
            preferred_origin: preferred_origin.to_string(),
            resolved_count,
            unresolved_remaining,
        })
    }
}

fn list_conflicts_on_conn(
    conn: &Connection,
    content_id: Option<&str>,
    limit: usize,
    include_resolved: bool,
) -> Result<Vec<MeshConflict>> {
    let mut statement = conn.prepare(
        "SELECT id, content_id, incumbent_origin, incoming_origin, incumbent_sha256, \
                incoming_sha256, policy, observed_at, resolved_at, preferred_origin \
         FROM mesh_sync_conflicts \
         WHERE (?1 IS NULL OR content_id = ?1) \
           AND (?2 = 1 OR resolved_at IS NULL) \
         ORDER BY observed_at DESC, id DESC LIMIT ?3",
    )?;
    type RawConflict = (
        i64,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        i64,
        Option<i64>,
        Option<String>,
    );
    let rows = statement
        .query_map(
            params![
                content_id,
                if include_resolved { 1_i64 } else { 0_i64 },
                limit as i64
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<RawConflict>>>()?;
    rows.into_iter()
        .map(
            |(
                id,
                content_id,
                incumbent_origin,
                incoming_origin,
                incumbent_sha256,
                incoming_sha256,
                policy,
                observed_at,
                resolved_at,
                preferred_origin,
            )| {
                ensure!(id > 0, "invalid mesh conflict id {id}");
                let incumbent_sha256 =
                    digest_from_vec(incumbent_sha256, "conflict incumbent_sha256")?;
                let incoming_sha256 = digest_from_vec(incoming_sha256, "conflict incoming_sha256")?;
                ensure!(
                    resolved_at.is_some() == preferred_origin.is_some(),
                    "incomplete mesh conflict resolution for id {id}"
                );
                Ok(MeshConflict {
                    id,
                    content_id,
                    incumbent_origin,
                    incoming_origin,
                    incumbent_sha256: hex::encode(incumbent_sha256),
                    incoming_sha256: hex::encode(incoming_sha256),
                    policy,
                    observed_at,
                    resolved_at,
                    preferred_origin,
                })
            },
        )
        .collect()
}

fn unresolved_conflict_count_on_conn(conn: &Connection, content_id: Option<&str>) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM mesh_sync_conflicts \
         WHERE resolved_at IS NULL AND (?1 IS NULL OR content_id = ?1)",
        [content_id],
        |row| row.get(0),
    )?;
    Ok(nonnegative_usize(count, "mesh conflict count")?)
}

fn load_pending(conn: &Connection, peer: &PeerPubkey) -> Result<Option<PendingRow>> {
    let row = conn
        .query_row(
            "SELECT origin_seq, content_sha256, wire_frame, next_cursor_segment, next_cursor_offset \
             FROM mesh_sync_outbound_pending WHERE peer_pk = ?1",
            [peer.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .context("load pending durable mesh frame")?;

    row.map(
        |(origin_seq, content_sha256, wire_frame, next_cursor_segment, next_cursor_offset)| {
            Ok(PendingRow {
                origin_seq: positive_u64(origin_seq, "pending origin_seq")?,
                content_sha256: digest_from_vec(content_sha256, "pending content_sha256")?,
                wire_frame,
                next_cursor_segment: next_cursor_segment.map(PathBuf::from),
                next_cursor_offset: nonnegative_usize(
                    next_cursor_offset,
                    "pending next_cursor_offset",
                )?,
            })
        },
    )
    .transpose()
}

fn validate_pending(pending: &PendingRow, origin: &PeerPubkey) -> Result<GossipFrame> {
    let frame: GossipFrame = serde_json::from_slice(&pending.wire_frame)
        .context("corrupt durable mesh pending wire_frame")?;
    ensure!(
        frame.protocol_version == SYNC_PROTOCOL_VERSION,
        "pending mesh protocol version {} is not {}",
        frame.protocol_version,
        SYNC_PROTOCOL_VERSION
    );
    ensure!(frame.origin == *origin, "pending mesh origin mismatch");
    ensure!(
        frame.event_seq == pending.origin_seq,
        "pending mesh sequence mismatch"
    );
    ensure!(
        frame.content_sha256 == pending.content_sha256,
        "pending mesh digest mismatch"
    );
    ensure!(
        frame.content_sha256 == frame.envelope.content_sha256(),
        "pending mesh envelope digest mismatch"
    );
    ensure!(
        frame.vector_clock.get(origin) > 0,
        "pending mesh vector clock is missing its origin slot"
    );
    ensure!(
        frame.vector_clock.clocks.len() <= MAX_VECTOR_CLOCK_PEERS,
        "pending mesh vector clock exceeds the bounded peer limit"
    );
    Ok(frame)
}

fn canonical_frame_sha256(frame: &GossipFrame) -> Result<[u8; 32]> {
    let canonical = serde_json::to_vec(frame).context("serialize canonical mesh frame binding")?;
    Ok(Sha256::digest(canonical).into())
}

fn load_vector_frontier(conn: &Connection) -> Result<VectorClock> {
    let mut stmt =
        conn.prepare("SELECT peer_pk,counter FROM mesh_sync_vector_frontier ORDER BY peer_pk ASC")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut clocks = BTreeMap::new();
    for row in rows {
        let (peer, counter) = row?;
        ensure!(
            !peer.is_empty(),
            "durable vector frontier contains an empty peer id"
        );
        ensure!(
            clocks.len() < MAX_VECTOR_CLOCK_PEERS,
            "durable vector frontier exceeds the bounded peer limit"
        );
        clocks.insert(
            PeerPubkey::new(peer),
            positive_u64(counter, "durable vector frontier counter")?,
        );
    }
    Ok(VectorClock { clocks })
}

fn persist_vector_frontier(conn: &Connection, frontier: &VectorClock) -> Result<()> {
    ensure!(
        frontier.clocks.len() <= MAX_VECTOR_CLOCK_PEERS,
        "durable vector frontier exceeds the bounded peer limit"
    );
    conn.execute("DELETE FROM mesh_sync_vector_frontier", [])?;
    for (peer, counter) in &frontier.clocks {
        ensure!(
            !peer.as_str().is_empty(),
            "vector frontier peer id is empty"
        );
        ensure!(*counter > 0, "vector frontier counter must be positive");
        conn.execute(
            "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES (?1,?2)",
            params![peer.as_str(), i64::try_from(*counter)?],
        )?;
    }
    Ok(())
}

fn seed_legacy_local_counter(
    conn: &Connection,
    origin: &PeerPubkey,
    frontier: &mut VectorClock,
) -> Result<()> {
    let legacy_max: i64 = conn.query_row(
        "SELECT COALESCE(MAX(origin_seq),0) FROM mesh_sync_local_events",
        [],
        |row| row.get(0),
    )?;
    let legacy_max = u64::try_from(legacy_max).context("legacy local mesh sequence is negative")?;
    if legacy_max > frontier.get(origin) {
        ensure!(
            frontier.clocks.contains_key(origin) || frontier.clocks.len() < MAX_VECTOR_CLOCK_PEERS,
            "durable vector frontier is full; cannot admit local origin {}",
            origin.as_str()
        );
        frontier.clocks.insert(origin.clone(), legacy_max);
    }
    Ok(())
}

fn merge_vector_frontier(
    conn: &Connection,
    authenticated_origin: &PeerPubkey,
    incoming: &VectorClock,
) -> Result<VectorClock> {
    ensure!(
        incoming.clocks.len() <= MAX_VECTOR_CLOCK_PEERS,
        "inbound mesh vector clock exceeds the bounded peer limit"
    );
    ensure!(
        incoming
            .clocks
            .iter()
            .all(|(peer, counter)| !peer.as_str().is_empty() && *counter > 0),
        "inbound mesh vector clock contains an invalid slot"
    );
    let mut frontier = load_vector_frontier(conn)?;
    let origin_counter = incoming.get(authenticated_origin);
    ensure!(
        origin_counter > 0,
        "inbound mesh vector clock is missing its authenticated origin"
    );
    // The transport-authenticated origin is authoritative and must never be
    // silently dropped at capacity. Explicitly reject a 257th direct identity
    // rather than evicting a potentially-local clock slot. Third-party slots
    // are causal claims only: they may advance an already-authenticated key but
    // cannot invent a new identity, and never participate in authentication,
    // ACK, policy, or conflict decisions.
    ensure!(
        frontier.clocks.contains_key(authenticated_origin)
            || frontier.clocks.len() < MAX_VECTOR_CLOCK_PEERS,
        "durable vector frontier is full; cannot admit authenticated origin {}",
        authenticated_origin.as_str()
    );
    frontier
        .clocks
        .entry(authenticated_origin.clone())
        .and_modify(|counter| *counter = (*counter).max(origin_counter))
        .or_insert(origin_counter);
    for (peer, incoming_counter) in &incoming.clocks {
        if peer == authenticated_origin {
            continue;
        }
        if let Some(counter) = frontier.clocks.get_mut(peer) {
            *counter = (*counter).max(*incoming_counter);
        }
    }
    persist_vector_frontier(conn, &frontier)?;
    Ok(frontier)
}

fn validate_pending_cursor(pending: &PendingRow, wal_dir: &Path) -> Result<()> {
    let segment = pending
        .next_cursor_segment
        .as_ref()
        .context("pending mesh frame has no next WAL segment")?;
    ensure!(
        segment.parent() == Some(wal_dir),
        "corrupt pending mesh cursor escapes WAL directory: {}",
        segment.display()
    );
    validate_cursor_target(segment, pending.next_cursor_offset)
}

fn validate_cursor_target(segment: &Path, offset: usize) -> Result<()> {
    ensure!(
        segment
            .extension()
            .is_some_and(|extension| extension == "wal"),
        "durable mesh cursor does not target a WAL segment: {}",
        segment.display()
    );
    let raw = std::fs::read(segment)
        .with_context(|| format!("read durable mesh cursor segment {}", segment.display()))?;
    crate::wal::segment_header::parse_segment_header(&raw)
        .with_context(|| format!("validate durable mesh cursor segment {}", segment.display()))?;
    let (header_len, logical) = crate::wal::compaction::logical_segment_bytes(&raw)
        .with_context(|| format!("reconstruct mesh cursor segment {}", segment.display()))?;
    let body = logical.get(header_len..).with_context(|| {
        format!(
            "durable mesh cursor segment {} is shorter than its header",
            segment.display()
        )
    })?;
    ensure!(
        offset <= body.len(),
        "durable mesh cursor offset {offset} exceeds logical segment length {}",
        body.len()
    );
    Ok(())
}

fn load_outbound_state(
    conn: &Connection,
    peer: &PeerPubkey,
    wal_dir: &Path,
) -> Result<OutboundState> {
    let row = conn
        .query_row(
            "SELECT cursor_segment, cursor_offset, acked_origin_seq, acked_content_sha256 \
             FROM mesh_sync_outbound WHERE peer_pk = ?1",
            [peer.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;
    let (segment, offset) = match row {
        Some((segment, offset, acked_seq, acked_digest)) => {
            let offset = nonnegative_usize(offset, "outbound cursor_offset")?;
            let acked_seq = nonnegative_u64(acked_seq, "outbound acked_origin_seq")?;
            match (acked_seq, acked_digest) {
                (0, None) => {}
                (0, Some(_)) => bail!("corrupt mesh cursor has a digest without an ACK"),
                (_, Some(digest)) => {
                    let _ = digest_from_vec(digest, "outbound acked_content_sha256")?;
                }
                (_, None) => bail!("corrupt mesh cursor is missing its ACK digest"),
            }
            let segment = segment.map(PathBuf::from);
            if let Some(path) = &segment {
                ensure!(
                    path.parent() == Some(wal_dir),
                    "corrupt mesh cursor escapes WAL directory: {}",
                    path.display()
                );
                validate_cursor_target(path, offset)?;
            } else {
                ensure!(offset == 0, "mesh cursor without a segment has an offset");
            }
            (segment, offset)
        }
        // A new peer must replay the sorted WAL from the oldest segment. If we
        // seeded it at the active segment, newer state would receive a lower
        // origin sequence and an older wrapped event could later win LWW.
        None => (None, 0),
    };
    Ok(OutboundState {
        cursor: GossipWalCursor { segment, offset },
    })
}

fn persist_idle_cursor(
    conn: &mut Connection,
    peer: &PeerPubkey,
    cursor: &GossipWalCursor,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let pending: i64 = tx.query_row(
        "SELECT count(*) FROM mesh_sync_outbound_pending WHERE peer_pk = ?1",
        [peer.as_str()],
        |row| row.get(0),
    )?;
    ensure!(
        pending == 0,
        "pending frame appeared while persisting idle cursor"
    );
    tx.execute(
        "INSERT INTO mesh_sync_outbound (peer_pk, cursor_segment, cursor_offset, updated_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(peer_pk) DO UPDATE SET cursor_segment=excluded.cursor_segment, \
         cursor_offset=excluded.cursor_offset, updated_at=excluded.updated_at",
        params![
            peer.as_str(),
            cursor
                .segment
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            i64::try_from(cursor.offset).context("mesh cursor offset exceeds SQLite i64")?,
            crate::time::now_unix_i64(),
        ],
    )?;
    tx.commit().context("commit idle durable mesh cursor")
}

#[allow(clippy::too_many_arguments)]
fn stage_frame(
    conn: &mut Connection,
    peer: &PeerPubkey,
    origin: &PeerPubkey,
    event_type: u8,
    event_subtype: u8,
    raw: &[u8],
    next_cursor: &GossipWalCursor,
    policy: &GossipPolicy,
) -> Result<PreparedFrame> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(pending) = load_pending(&tx, peer)? {
        let frame = validate_pending(&pending, origin)?;
        tx.commit()?;
        return Ok(PreparedFrame {
            frame,
            replayed_pending: true,
        });
    }
    ensure!(
        is_replicable_ext(event_type, event_subtype, policy),
        "attempted to stage a forbidden mesh event"
    );
    let timestamp_unix = gossip_payload_timestamp_unix(raw)
        .context("stage durable mesh frame: malformed WAL timestamp")?;
    let envelope =
        materialize_envelope(&tx, event_type, event_subtype, raw, timestamp_unix, policy)?;
    let digest = envelope.content_sha256();
    // Seed from pre-v6 destination-local sequences before inserting this new
    // frame. Reading the migration baseline after the insert would count the
    // current event once as legacy state and then tick it a second time,
    // starting a fresh node-global frontier at 2 instead of 1.
    let mut vector_clock = load_vector_frontier(&tx)?;
    seed_legacy_local_counter(&tx, origin, &mut vector_clock)?;
    ensure!(
        vector_clock.clocks.contains_key(origin)
            || vector_clock.clocks.len() < MAX_VECTOR_CLOCK_PEERS,
        "durable vector frontier is full; cannot admit local origin {}",
        origin.as_str()
    );
    ensure!(
        vector_clock.tick(origin),
        "node-global mesh vector counter exhausted"
    );
    let existing = tx
        .query_row(
            "SELECT origin_seq,envelope FROM mesh_sync_local_events \
             WHERE peer_pk=?1 AND content_sha256=?2",
            params![peer.as_str(), digest.as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let origin_seq = match existing {
        Some((seq, stored_envelope)) => {
            let stored: SyncEnvelope = serde_json::from_slice(&stored_envelope)
                .context("corrupt durable local mesh envelope")?;
            ensure!(
                stored == envelope,
                "local mesh digest maps to a different canonical envelope"
            );
            positive_u64(seq, "local mesh origin_seq")?
        }
        None => {
            let next: i64 = tx.query_row(
                "SELECT COALESCE(MAX(origin_seq), 0) + 1 FROM mesh_sync_local_events WHERE peer_pk=?1",
                [peer.as_str()],
                |row| row.get(0),
            )?;
            let seq = positive_u64(next, "next local mesh origin_seq")?;
            let envelope_bytes = serde_json::to_vec(&envelope)?;
            tx.execute(
                "INSERT INTO mesh_sync_local_events \
                 (peer_pk, origin_seq, content_sha256, envelope, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![
                    peer.as_str(),
                    i64::try_from(seq)?,
                    digest.as_slice(),
                    envelope_bytes,
                    crate::time::now_unix_i64(),
                ],
            )?;
            seq
        }
    };
    persist_vector_frontier(&tx, &vector_clock)?;
    let frame = GossipFrame {
        protocol_version: SYNC_PROTOCOL_VERSION,
        vector_clock,
        origin: origin.clone(),
        event_seq: origin_seq,
        content_sha256: digest,
        timestamp_unix,
        tag: super::gossip::GossipTag::Replicate,
        payload: raw.to_vec(),
        envelope,
    };
    let wire = serde_json::to_vec(&frame)?;
    tx.execute(
        "INSERT OR IGNORE INTO mesh_sync_outbound \
         (peer_pk, cursor_segment, cursor_offset, updated_at) VALUES (?1, NULL, 0, ?2)",
        params![peer.as_str(), crate::time::now_unix_i64()],
    )?;
    tx.execute(
        "INSERT INTO mesh_sync_outbound_pending \
         (peer_pk, origin_seq, content_sha256, wire_frame, next_cursor_segment, \
          next_cursor_offset, attempts, created_at) VALUES (?1,?2,?3,?4,?5,?6,0,?7)",
        params![
            peer.as_str(),
            i64::try_from(origin_seq)?,
            digest.as_slice(),
            wire,
            next_cursor
                .segment
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            i64::try_from(next_cursor.offset).context("mesh cursor offset exceeds SQLite i64")?,
            crate::time::now_unix_i64(),
        ],
    )?;
    tx.commit()
        .context("commit durable outbound pending frame")?;
    Ok(PreparedFrame {
        frame,
        replayed_pending: false,
    })
}

fn materialize_envelope(
    conn: &Connection,
    event_type: u8,
    event_subtype: u8,
    raw: &[u8],
    updated_at_unix: i64,
    policy: &GossipPolicy,
) -> Result<SyncEnvelope> {
    let decoded = crate::wal::frame::decode_frame(raw)
        .context("materialize durable mesh envelope: decode WAL frame")?;
    ensure!(
        decoded.header.total_len as usize == raw.len()
            && decoded.header.event_type == event_type
            && decoded.header.event_subtype == event_subtype,
        "materialize durable mesh envelope: outer/inner WAL metadata mismatch"
    );
    let content = match event_type {
        0x90..=0x92 => {
            let event_id = json_i64(decoded.payload, "event_id")?;
            SyncContent::Memory(load_memory_snapshot(conn, event_id)?)
        }
        0x98 => {
            let id = json_i64(decoded.payload, "id")?;
            SyncContent::GroundTruth(load_ground_truth_snapshot(conn, id)?)
        }
        _ => match classify_event_ext(event_type, event_subtype) {
            ReplicationClass::RawIngressGated => {
                ensure!(
                    policy.replicate_raw_ingress,
                    "raw mesh replication is disabled"
                );
                SyncContent::RawPrivate {
                    event_type,
                    wal_frame: raw.to_vec(),
                }
            }
            ReplicationClass::Replicate => SyncContent::Metadata {
                event_type,
                event_subtype,
                wal_frame: raw.to_vec(),
            },
            ReplicationClass::DoNotGossip => bail!("forbidden event cannot be materialized"),
        },
    };
    let content_id = match &content {
        SyncContent::Memory(snapshot) => snapshot.stable_id.clone(),
        SyncContent::GroundTruth(snapshot) => snapshot.stable_id.clone(),
        SyncContent::Metadata { wal_frame, .. } => {
            format!(
                "metadata:{}",
                hex_digest(Sha256::digest(wal_frame).as_slice())
            )
        }
        SyncContent::RawPrivate { wal_frame, .. } => {
            format!("raw:{}", hex_digest(Sha256::digest(wal_frame).as_slice()))
        }
    };
    Ok(SyncEnvelope {
        version: SYNC_ENVELOPE_VERSION,
        content_id,
        updated_at_unix,
        content,
    })
}

fn load_memory_snapshot(conn: &Connection, event_id: i64) -> Result<MemorySnapshot> {
    type MemoryRow = (String, String, i64, f64, i64, i64, &'static str);
    let hot = conn
        .query_row(
            "SELECT text,text_hash,ts_ns,importance,last_access_ts,access_count FROM idx_episode WHERE event_id=?1",
            [event_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, "hot")),
        )
        .optional()?;
    let warm = if hot.is_none() {
        conn.query_row(
            "SELECT text,text_hash,consolidated_ts,importance,last_access_ts,access_count FROM idx_consolidated WHERE event_id=?1 ORDER BY id DESC LIMIT 1",
            [event_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, "warm")),
        )
        .optional()?
    } else {
        None
    };
    let cold = if hot.is_none() && warm.is_none() {
        conn.query_row(
            "SELECT text,text_hash,promoted_ts,importance,last_access_ts,access_count FROM idx_longterm WHERE event_id=?1",
            [event_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, "cold")),
        )
        .optional()?
    } else {
        None
    };
    let (text, text_hash, ts_ns, importance, last_access_ts, access_count, tier): MemoryRow = hot
        .or(warm)
        .or(cold)
        .with_context(|| format!("memory event {event_id} has no materializable content row"))?;
    ensure!(
        access_count >= 0,
        "negative memory access_count for event {event_id}"
    );
    let stable_id = format!("memory:{}", hex_digest(&Sha256::digest(text.as_bytes())));
    Ok(MemorySnapshot {
        stable_id,
        text,
        text_hash,
        tier: tier.to_string(),
        ts_ns,
        importance_micros: score_micros(importance, "memory importance")?,
        last_access_ts,
        access_count: u64::try_from(access_count)?,
    })
}

fn load_ground_truth_snapshot(conn: &Connection, id: i64) -> Result<GroundTruthSnapshot> {
    let row = conn
        .query_row(
            "SELECT statement,source,scope,asserted_at,revoked_at,fact_state,source_weight, \
                    confidence,evidence,maturity,confirmed_count \
             FROM idx_groundtruth WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, f64>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?
        .with_context(|| format!("ground-truth event {id} has no materializable content row"))?;
    ensure!(
        !row.1.trim().is_empty() && row.1.len() <= 256,
        "invalid local ground-truth source"
    );
    let source_weight: BTreeMap<String, u32> = serde_json::from_str(&row.6)
        .context("invalid local ground-truth source_weight provenance")?;
    ensure!(
        source_weight.len() <= 64
            && source_weight
                .iter()
                .all(|(source, count)| !source.trim().is_empty()
                    && source.len() <= 256
                    && *count > 0),
        "invalid local ground-truth source_weight provenance"
    );
    let evidence_ids: Vec<i64> =
        serde_json::from_str(&row.8).context("invalid local ground-truth evidence provenance")?;
    ensure!(
        evidence_ids.len() <= crate::memory::groundtruth::MAX_EVIDENCE_BACKLINKS,
        "ground-truth evidence exceeds the canonical limit"
    );
    let mut seen_evidence = HashSet::with_capacity(evidence_ids.len());
    let mut evidence_content_ids = Vec::with_capacity(evidence_ids.len());
    for evidence_id in evidence_ids {
        ensure!(evidence_id > 0, "invalid ground-truth evidence row id");
        let stable_id = load_memory_snapshot(conn, evidence_id)?.stable_id;
        if seen_evidence.insert(stable_id.clone()) {
            evidence_content_ids.push(stable_id);
        }
    }
    let confirmed_count =
        u32::try_from(row.10).context("invalid local ground-truth confirmed_count")?;
    ensure!(
        row.9 == crate::memory::groundtruth::maturity_for(confirmed_count),
        "ground-truth maturity/confirmation count mismatch"
    );
    let mut identity = row.2.as_bytes().to_vec();
    identity.push(0);
    identity.extend_from_slice(row.0.as_bytes());
    ensure!(
        matches!(
            row.5.as_str(),
            "raw" | "candidate" | "verified" | "superseded" | "contradicted" | "deprecated"
        ),
        "invalid local ground-truth state"
    );
    ensure!(
        matches!(row.9.as_str(), "emerging" | "working" | "stable"),
        "invalid local ground-truth maturity"
    );
    Ok(GroundTruthSnapshot {
        stable_id: format!("ground_truth:{}", hex_digest(&Sha256::digest(identity))),
        statement: row.0,
        source: row.1,
        scope: row.2,
        asserted_at: row.3,
        revoked_at: row.4,
        fact_state: row.5,
        source_weight,
        confidence_micros: score_micros(row.7, "ground-truth confidence")?,
        evidence_content_ids,
        maturity: row.9,
        confirmed_count,
    })
}

fn acknowledge_outbound_on_conn(
    conn: &mut Connection,
    authenticated_peer: &PeerPubkey,
    local_origin: &PeerPubkey,
    ack: &GossipAck,
) -> Result<OutboundAckOutcome> {
    ensure!(
        ack.protocol_version == SYNC_PROTOCOL_VERSION,
        "old or unknown mesh ACK protocol"
    );
    ensure!(ack.origin == *local_origin, "mesh ACK origin mismatch");
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let pending = tx
        .query_row(
            "SELECT origin_seq,content_sha256,next_cursor_segment,next_cursor_offset \
             FROM mesh_sync_outbound_pending WHERE peer_pk=?1",
            [authenticated_peer.as_str()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((seq, digest, next_segment, next_offset)) = pending else {
        let known = tx
            .query_row(
                "SELECT content_sha256 FROM mesh_sync_local_events WHERE peer_pk=?1 AND origin_seq=?2",
                params![authenticated_peer.as_str(), i64::try_from(ack.origin_seq)?],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let known = known.context("mesh ACK has no pending or known exact event")?;
        ensure!(
            digest_from_vec(known, "known local mesh digest")? == ack.content_sha256,
            "duplicate mesh ACK digest mismatch"
        );
        tx.commit()?;
        return Ok(OutboundAckOutcome::Duplicate);
    };
    ensure!(
        positive_u64(seq, "pending ACK sequence")? == ack.origin_seq,
        "mesh ACK sequence mismatch"
    );
    ensure!(
        digest_from_vec(digest, "pending ACK digest")? == ack.content_sha256,
        "mesh ACK content digest mismatch"
    );
    ensure!(next_offset >= 0, "corrupt pending mesh next cursor offset");
    let updated = tx.execute(
        "UPDATE mesh_sync_outbound SET cursor_segment=?2,cursor_offset=?3, \
         acked_origin_seq=MAX(acked_origin_seq,?4), \
         acked_content_sha256=CASE WHEN ?4 >= acked_origin_seq THEN ?5 ELSE acked_content_sha256 END, \
         updated_at=?6 WHERE peer_pk=?1",
        params![
            authenticated_peer.as_str(),
            next_segment,
            next_offset,
            i64::try_from(ack.origin_seq)?,
            ack.content_sha256.as_slice(),
            crate::time::now_unix_i64(),
        ],
    )?;
    ensure!(
        updated == 1,
        "pending mesh ACK has no durable outbound cursor row"
    );
    let deleted = tx.execute(
        "DELETE FROM mesh_sync_outbound_pending WHERE peer_pk=?1",
        [authenticated_peer.as_str()],
    )?;
    ensure!(
        deleted == 1,
        "pending mesh frame vanished during ACK commit"
    );
    tx.commit().context("commit exact durable mesh ACK")?;
    Ok(OutboundAckOutcome::Applied)
}

pub(crate) fn persist_inbound_on_conn(
    conn: &mut Connection,
    authenticated_peer: &PeerPubkey,
    frame: &GossipFrame,
    policy: &GossipPolicy,
) -> Result<InboundCommit> {
    ensure!(
        frame.vector_clock.clocks.len() <= MAX_VECTOR_CLOCK_PEERS,
        "inbound mesh vector clock exceeds the bounded peer limit"
    );
    ensure!(
        frame.origin == *authenticated_peer,
        "authenticated mesh origin mismatch"
    );
    ensure!(
        frame.event_seq > 0,
        "inbound mesh sequence must be positive"
    );
    ensure!(
        frame.vector_clock.get(authenticated_peer) > 0,
        "inbound mesh vector clock is missing its origin slot"
    );
    let now = crate::time::now_unix_i64();
    let replay_budget = super::gossip::ReplayBudget::from_policy(policy);
    let preliminary = frame.evaluate_acceptance(&replay_budget, now, false);
    if !matches!(preliminary, GossipAcceptance::Accept) {
        return Ok(InboundCommit::Dropped(preliminary));
    }
    let (event_type, event_subtype) = gossip_payload_event_meta(&frame.payload)
        .context("inbound mesh payload is not one exact canonical WAL frame")?;
    ensure!(
        gossip_payload_timestamp_unix(&frame.payload) == Some(frame.timestamp_unix),
        "inbound mesh timestamp does not match WAL source"
    );
    if !is_replicable_ext(event_type, event_subtype, policy) {
        return Ok(InboundCommit::Dropped(
            GossipAcceptance::DroppedDoNotGossipTag,
        ));
    }
    validate_content_shape(frame, event_type, event_subtype, policy)?;
    let frame_sha256 = canonical_frame_sha256(frame)?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let next = tx
        .query_row(
            "SELECT next_expected_seq,last_content_sha256 FROM mesh_sync_inbound WHERE origin_peer_pk=?1",
            [authenticated_peer.as_str()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?;
    let expected = match next {
        Some((seq, last_digest)) => {
            let seq = positive_u64(seq, "inbound next_expected_seq")?;
            if let Some(digest) = last_digest {
                let _ = digest_from_vec(digest, "inbound last_content_sha256")?;
            }
            seq
        }
        None => 1,
    };
    if frame.event_seq > expected {
        tx.commit()?;
        return Ok(InboundCommit::Gap {
            expected,
            received: frame.event_seq,
        });
    }
    let ack = GossipAck {
        protocol_version: SYNC_PROTOCOL_VERSION,
        origin: frame.origin.clone(),
        origin_seq: frame.event_seq,
        content_sha256: frame.content_sha256,
    };
    if frame.event_seq < expected {
        let receipt = tx
            .query_row(
                "SELECT content_sha256,frame_sha256 FROM mesh_sync_inbound_receipts \
                  WHERE origin_peer_pk=?1 AND origin_seq=?2",
                params![authenticated_peer.as_str(), i64::try_from(frame.event_seq)?],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?
            .context("old mesh sequence has no durable receipt")?;
        ensure!(
            digest_from_vec(receipt.0, "duplicate inbound receipt digest")? == frame.content_sha256,
            "replayed mesh sequence carries different content"
        );
        let Some(stored_frame_sha256) = receipt.1 else {
            tx.commit()?;
            return Ok(InboundCommit::DuplicateUnbound(ack));
        };
        ensure!(
            digest_from_vec(stored_frame_sha256, "duplicate inbound frame binding")?
                == frame_sha256,
            "replayed mesh sequence carries a different canonical frame"
        );
        merge_vector_frontier(&tx, authenticated_peer, &frame.vector_clock)?;
        tx.commit()?;
        return Ok(InboundCommit::Duplicate(ack));
    }

    let store_content = !raw_frame_matches_forget_tombstone(&tx, event_type, &frame.payload)?;
    tx.execute(
        "INSERT INTO mesh_sync_inbound_receipts \
          (origin_peer_pk,origin_seq,content_sha256,frame_sha256,content_stored,committed_at) \
          VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            authenticated_peer.as_str(),
            i64::try_from(frame.event_seq)?,
            frame.content_sha256.as_slice(),
            frame_sha256.as_slice(),
            if store_content { 1_i64 } else { 0_i64 },
            now,
        ],
    )?;
    if store_content {
        let envelope_bytes = serde_json::to_vec(&frame.envelope)?;
        tx.execute(
            "INSERT INTO idx_foreign_events \
             (origin_peer_pk,origin_seq,event_type,payload,received_at,envelope_version,content_sha256,content_kind,content_payload) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                authenticated_peer.as_str(),
                i64::try_from(frame.event_seq)?,
                i64::from(event_type),
                &frame.payload,
                now,
                i64::from(frame.envelope.version),
                frame.content_sha256.as_slice(),
                frame.envelope.content.kind(),
                &envelope_bytes,
            ],
        )?;
        materialize_inbound(&tx, authenticated_peer, frame, &envelope_bytes, now)?;
    }
    tx.execute(
        "INSERT INTO mesh_sync_inbound \
         (origin_peer_pk,next_expected_seq,last_content_sha256,updated_at) VALUES (?1,?2,?3,?4) \
         ON CONFLICT(origin_peer_pk) DO UPDATE SET next_expected_seq=excluded.next_expected_seq, \
         last_content_sha256=excluded.last_content_sha256,updated_at=excluded.updated_at",
        params![
            authenticated_peer.as_str(),
            i64::try_from(
                frame
                    .event_seq
                    .checked_add(1)
                    .context("mesh sequence overflow")?
            )?,
            frame.content_sha256.as_slice(),
            now,
        ],
    )?;
    merge_vector_frontier(&tx, authenticated_peer, &frame.vector_clock)?;
    tx.commit().context("commit inbound durable mesh content")?;
    Ok(InboundCommit::Committed(ack))
}

fn validate_content_shape(
    frame: &GossipFrame,
    event_type: u8,
    event_subtype: u8,
    policy: &GossipPolicy,
) -> Result<()> {
    ensure!(
        frame.envelope.version == SYNC_ENVELOPE_VERSION,
        "unknown mesh envelope version"
    );
    ensure!(
        frame.envelope.updated_at_unix == frame.timestamp_unix,
        "mesh envelope timestamp does not match WAL source"
    );
    match (&frame.envelope.content, event_type) {
        (SyncContent::Memory(snapshot), 0x90..=0x92) => {
            ensure!(
                snapshot.text.len() <= MAX_MEMORY_TEXT_BYTES,
                "memory text exceeds the 1 MiB cluster limit"
            );
            ensure!(
                snapshot.stable_id.len() <= MAX_STABLE_CONTENT_ID_BYTES,
                "memory stable id exceeds the cluster limit"
            );
            ensure!(
                snapshot.importance_micros <= 1_000_000,
                "memory importance exceeds canonical range"
            );
            ensure!(
                snapshot.ts_ns >= 0 && snapshot.last_access_ts >= 0,
                "memory timestamp is outside the canonical range"
            );
            ensure!(
                matches!(snapshot.tier.as_str(), "hot" | "warm" | "cold"),
                "unknown canonical memory tier"
            );
            ensure!(
                snapshot.stable_id.starts_with("memory:"),
                "invalid stable memory id"
            );
            let expected = format!(
                "memory:{}",
                hex_digest(&Sha256::digest(snapshot.text.as_bytes()))
            );
            ensure!(
                snapshot.stable_id == expected,
                "memory stable id/content mismatch"
            );
            ensure!(
                frame.envelope.content_id == snapshot.stable_id,
                "memory envelope content_id mismatch"
            );
        }
        (SyncContent::GroundTruth(snapshot), 0x98) => {
            ensure!(
                !snapshot.statement.trim().is_empty()
                    && !snapshot.source.trim().is_empty()
                    && snapshot.source.len() <= 256
                    && !snapshot.scope.trim().is_empty(),
                "invalid canonical ground-truth identity/provenance"
            );
            ensure!(
                snapshot.asserted_at >= 0
                    && snapshot.revoked_at.is_none_or(|timestamp| timestamp >= 0),
                "ground-truth timestamp is outside the canonical range"
            );
            ensure!(
                snapshot.confidence_micros <= 1_000_000,
                "ground-truth confidence exceeds canonical range"
            );
            ensure!(
                matches!(
                    snapshot.fact_state.as_str(),
                    "raw" | "candidate" | "verified" | "superseded" | "contradicted" | "deprecated"
                ),
                "unknown canonical ground-truth state"
            );
            ensure!(
                matches!(
                    snapshot.maturity.as_str(),
                    "emerging" | "working" | "stable"
                ),
                "unknown canonical ground-truth maturity"
            );
            ensure!(
                snapshot.maturity
                    == crate::memory::groundtruth::maturity_for(snapshot.confirmed_count),
                "ground-truth maturity/confirmation count mismatch"
            );
            ensure!(
                snapshot.source_weight.len() <= 64
                    && snapshot.source_weight.iter().all(|(source, count)| !source
                        .trim()
                        .is_empty()
                        && source.len() <= 256
                        && *count > 0),
                "invalid canonical ground-truth source provenance"
            );
            let evidence: HashSet<&str> = snapshot
                .evidence_content_ids
                .iter()
                .map(String::as_str)
                .collect();
            ensure!(
                snapshot.evidence_content_ids.len()
                    <= crate::memory::groundtruth::MAX_EVIDENCE_BACKLINKS
                    && evidence.len() == snapshot.evidence_content_ids.len()
                    && snapshot
                        .evidence_content_ids
                        .iter()
                        .all(|content_id| is_canonical_memory_id(content_id)),
                "invalid canonical ground-truth evidence provenance"
            );
            let mut identity = snapshot.scope.as_bytes().to_vec();
            identity.push(0);
            identity.extend_from_slice(snapshot.statement.as_bytes());
            let expected = format!("ground_truth:{}", hex_digest(&Sha256::digest(identity)));
            ensure!(
                snapshot.stable_id == expected,
                "ground-truth stable id/content mismatch"
            );
            ensure!(
                frame.envelope.content_id == snapshot.stable_id,
                "ground-truth envelope content_id mismatch"
            );
        }
        (
            SyncContent::RawPrivate {
                event_type: inner,
                wal_frame,
            },
            _,
        ) => {
            ensure!(
                policy.replicate_raw_ingress,
                "raw private mesh content is disabled"
            );
            ensure!(
                *inner == event_type && wal_frame == &frame.payload,
                "raw private envelope mismatch"
            );
            ensure!(
                matches!(
                    classify_event_ext(event_type, event_subtype),
                    ReplicationClass::RawIngressGated
                ),
                "raw private envelope used for non-raw event"
            );
            let expected = format!("raw:{}", hex_digest(&Sha256::digest(wal_frame)));
            ensure!(
                frame.envelope.content_id == expected,
                "raw private envelope content_id mismatch"
            );
        }
        (
            SyncContent::Metadata {
                event_type: inner,
                event_subtype: sub,
                wal_frame,
            },
            _,
        ) => {
            ensure!(
                *inner == event_type && *sub == event_subtype && wal_frame == &frame.payload,
                "metadata envelope mismatch"
            );
            ensure!(
                matches!(
                    classify_event_ext(event_type, event_subtype),
                    ReplicationClass::Replicate
                ),
                "metadata envelope used for non-metadata event"
            );
            let expected = format!("metadata:{}", hex_digest(&Sha256::digest(wal_frame)));
            ensure!(
                frame.envelope.content_id == expected,
                "metadata envelope content_id mismatch"
            );
        }
        _ => bail!("mesh content kind does not match WAL event type"),
    }
    Ok(())
}

fn materialize_inbound(
    tx: &rusqlite::Transaction<'_>,
    origin: &PeerPubkey,
    frame: &GossipFrame,
    envelope_bytes: &[u8],
    now: i64,
) -> Result<()> {
    let current = tx
        .query_row(
            "SELECT origin_seq,content_sha256 FROM mesh_sync_materialized \
             WHERE origin_peer_pk=?1 AND content_id=?2",
            params![origin.as_str(), &frame.envelope.content_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((current_seq, current_digest)) = current {
        let current_digest = digest_from_vec(current_digest, "materialized content digest")?;
        ensure!(
            positive_u64(current_seq, "materialized origin_seq")? < frame.event_seq
                || current_digest == frame.content_sha256,
            "non-monotonic same-origin materialized update"
        );
        if current_digest != frame.content_sha256 {
            insert_conflict(
                tx,
                &frame.envelope.content_id,
                origin.as_str(),
                origin.as_str(),
                current_digest,
                frame.content_sha256,
                "ordered_origin_lww",
                now,
            )?;
        }
    }
    let mut stmt = tx.prepare(
        "SELECT origin_peer_pk,content_sha256 FROM mesh_sync_materialized \
         WHERE content_id=?1 AND origin_peer_pk<>?2 ORDER BY origin_peer_pk",
    )?;
    let others = stmt
        .query_map(params![&frame.envelope.content_id, origin.as_str()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);
    for (other_origin, other_digest) in others {
        let other_digest = digest_from_vec(other_digest, "cross-origin materialized digest")?;
        if other_digest != frame.content_sha256 {
            insert_conflict(
                tx,
                &frame.envelope.content_id,
                &other_origin,
                origin.as_str(),
                other_digest,
                frame.content_sha256,
                "cross_origin_typed_conflict",
                now,
            )?;
        }
    }
    tx.execute(
        "INSERT INTO mesh_sync_materialized \
         (origin_peer_pk,content_id,origin_seq,content_sha256,content_kind,content_payload,updated_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7) \
         ON CONFLICT(origin_peer_pk,content_id) DO UPDATE SET origin_seq=excluded.origin_seq, \
         content_sha256=excluded.content_sha256,content_kind=excluded.content_kind, \
         content_payload=excluded.content_payload,updated_at=excluded.updated_at",
        params![
            origin.as_str(),
            &frame.envelope.content_id,
            i64::try_from(frame.event_seq)?,
            frame.content_sha256.as_slice(),
            frame.envelope.content.kind(),
            envelope_bytes,
            frame.envelope.updated_at_unix,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_conflict(
    tx: &rusqlite::Transaction<'_>,
    content_id: &str,
    origin_a: &str,
    origin_b: &str,
    digest_a: [u8; 32],
    digest_b: [u8; 32],
    policy: &str,
    observed_at: i64,
) -> Result<()> {
    let (first_origin, first_digest, second_origin, second_digest) = if origin_a <= origin_b {
        (origin_a, digest_a, origin_b, digest_b)
    } else {
        (origin_b, digest_b, origin_a, digest_a)
    };
    tx.execute(
        "INSERT OR IGNORE INTO mesh_sync_conflicts \
         (content_id,incumbent_origin,incoming_origin,incumbent_sha256,incoming_sha256,policy,observed_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            content_id,
            first_origin,
            second_origin,
            first_digest.as_slice(),
            second_digest.as_slice(),
            policy,
            observed_at,
        ],
    )?;
    Ok(())
}

fn raw_frame_matches_forget_tombstone(
    conn: &Connection,
    event_type: u8,
    payload: &[u8],
) -> Result<bool> {
    if classify_event_ext(event_type, 0) != ReplicationClass::RawIngressGated {
        return Ok(false);
    }
    for topic in crate::memory::forget::active_tombstone_topics(conn)? {
        if crate::memory::forget::foreign_frame_contains_topic(payload, event_type, &topic)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn list_status_on_conn(
    conn: &Connection,
    peer_filter: Option<&str>,
) -> Result<Vec<MeshPeerStatus>> {
    let mut stmt = conn.prepare(
        "WITH peers(peer_pk) AS (\
             SELECT peer_pk FROM mesh_sync_outbound UNION \
             SELECT peer_pk FROM mesh_sync_outbound_pending UNION \
             SELECT origin_peer_pk FROM mesh_sync_inbound UNION \
             SELECT peer_pk FROM mesh_sync_requests\
         ) \
         SELECT p.peer_pk,o.cursor_segment,COALESCE(o.cursor_offset,0),COALESCE(o.acked_origin_seq,0), \
                q.origin_seq,q.attempts,i.next_expected_seq, \
                CASE WHEN r.state IN ('queued','active','waiting_peer') AND r.expires_at <= ?2 \
                     THEN 'expired' ELSE r.state END, \
                r.requested_at,r.updated_at,r.expires_at,r.send_attempts,r.last_error \
         FROM peers p LEFT JOIN mesh_sync_outbound o ON o.peer_pk=p.peer_pk \
         LEFT JOIN mesh_sync_outbound_pending q ON q.peer_pk=p.peer_pk \
         LEFT JOIN mesh_sync_inbound i ON i.origin_peer_pk=p.peer_pk \
         LEFT JOIN mesh_sync_requests r ON r.peer_pk=p.peer_pk \
         WHERE (?1 IS NULL OR p.peer_pk=?1) ORDER BY p.peer_pk",
    )?;
    let rows = stmt.query_map(params![peer_filter, crate::time::now_unix_i64()], |r| {
        let cursor_offset = nonnegative_u64(r.get::<_, i64>(2)?, "status cursor_offset")?;
        let acked = nonnegative_u64(r.get::<_, i64>(3)?, "status acked_origin_seq")?;
        let pending = r
            .get::<_, Option<i64>>(4)?
            .map(|v| positive_u64(v, "status pending_origin_seq"))
            .transpose()?;
        let attempts = r
            .get::<_, Option<i64>>(5)?
            .map(|v| nonnegative_u64(v, "status pending_attempts"))
            .transpose()?;
        let inbound = r
            .get::<_, Option<i64>>(6)?
            .map(|v| positive_u64(v, "status inbound_next_expected_seq"))
            .transpose()?;
        let request_send_attempts = r
            .get::<_, Option<i64>>(11)?
            .map(|v| nonnegative_u64(v, "status request_send_attempts"))
            .transpose()?;
        Ok(MeshPeerStatus {
            peer_pk: r.get(0)?,
            cursor_segment: r.get(1)?,
            cursor_offset,
            acked_origin_seq: acked,
            pending_origin_seq: pending,
            pending_attempts: attempts,
            inbound_next_expected_seq: inbound,
            request_state: r.get(7)?,
            request_requested_at: r.get(8)?,
            request_updated_at: r.get(9)?,
            request_expires_at: r.get(10)?,
            request_send_attempts,
            request_last_error: r.get(12)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("read durable mesh status")
}

fn load_sync_request_on_conn(
    conn: &Connection,
    peer: &PeerPubkey,
) -> Result<Option<MeshSyncRequest>> {
    conn.query_row(
        "SELECT peer_pk,state,requested_at,expires_at,updated_at,last_attempt_at,send_attempts,last_error \
         FROM mesh_sync_requests WHERE peer_pk=?1",
        [peer.as_str()],
        map_sync_request_row,
    )
    .optional()
    .context("load durable mesh sync request")
}

fn list_due_sync_requests_on_conn(
    conn: &Connection,
    now: i64,
    retry_before: i64,
) -> Result<Vec<MeshSyncRequest>> {
    let mut statement = conn.prepare(
        "SELECT peer_pk,state,requested_at,expires_at,updated_at,last_attempt_at,send_attempts,last_error \
         FROM mesh_sync_requests \
         WHERE state IN ('queued','active','waiting_peer') AND expires_at > ?1 \
           AND (last_attempt_at IS NULL OR last_attempt_at <= ?2) \
         ORDER BY COALESCE(last_attempt_at,0) ASC, requested_at ASC, peer_pk ASC \
         LIMIT ?3",
    )?;
    Ok(statement
        .query_map(
            params![now, retry_before, SYNC_REQUEST_POLL_LIMIT],
            map_sync_request_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn map_sync_request_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MeshSyncRequest> {
    let send_attempts = nonnegative_u64(row.get(6)?, "mesh sync request send_attempts")?;
    Ok(MeshSyncRequest {
        operation: "cluster.request-sync",
        peer_pk: row.get(0)?,
        state: row.get(1)?,
        requested_at: row.get(2)?,
        expires_at: row.get(3)?,
        updated_at: row.get(4)?,
        last_attempt_at: row.get(5)?,
        send_attempts,
        last_error: row.get(7)?,
    })
}

fn update_sync_request_on_conn(
    conn: &Connection,
    peer: &PeerPubkey,
    now: i64,
    state: &str,
    increment_sent: bool,
    error: Option<&str>,
) -> Result<()> {
    ensure!(
        now > 0,
        "mesh sync request update timestamp must be positive"
    );
    let error = error.map(|value| value.chars().take(240).collect::<String>());
    let changed = conn.execute(
        "UPDATE mesh_sync_requests SET state=?2,updated_at=?3,last_attempt_at=?3, \
         send_attempts=send_attempts + ?4,last_error=?5 \
         WHERE peer_pk=?1 AND state IN ('queued','active','waiting_peer') AND expires_at > ?3",
        params![
            peer.as_str(),
            state,
            now,
            if increment_sent { 1_i64 } else { 0_i64 },
            error,
        ],
    )?;
    ensure!(
        changed == 1,
        "no active mesh sync request for peer {}",
        peer.as_str()
    );
    Ok(())
}

fn json_i64(payload: &[u8], field: &str) -> Result<i64> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .context("decode materialized mesh WAL payload")?
        .get(field)
        .and_then(serde_json::Value::as_i64)
        .with_context(|| format!("mesh WAL payload has no integer `{field}`"))
}

fn score_micros(value: f64, label: &str) -> Result<u32> {
    ensure!(
        value.is_finite() && (0.0..=1.0).contains(&value),
        "invalid {label}: {value}"
    );
    Ok((value * 1_000_000.0).round() as u32)
}

fn positive_u64(value: i64, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| conversion_error(label))
}

fn nonnegative_u64(value: i64, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| conversion_error(label))
}

fn nonnegative_usize(value: i64, label: &str) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|_| conversion_error(label))
}

fn digest_from_vec(value: Vec<u8>, label: &str) -> rusqlite::Result<[u8; 32]> {
    value.try_into().map_err(|_| conversion_error(label))
}

fn conversion_error(label: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Integer,
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupt durable mesh value: {label}"),
        )
        .into(),
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    use std::fmt::Write as _;
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_canonical_memory_id(content_id: &str) -> bool {
    content_id.strip_prefix("memory:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> (tempfile::TempDir, PathBuf, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db_path).unwrap();
        (dir, db_path, conn)
    }

    #[test]
    fn sync_request_coalesces_and_tracks_bounded_progress() {
        let (_dir, db_path, conn) = open_test_db();
        let sync = DurableMeshSync::new(db_path);
        let peer = PeerPubkey::new("a".repeat(64));
        let now = 1_900_000_000;

        let queued = sync.request_sync(&peer, now).unwrap();
        assert_eq!(queued.state, "queued");
        assert_eq!(queued.send_attempts, 0);
        assert_eq!(sync.due_sync_requests(now).unwrap(), vec![queued.clone()]);

        sync.mark_sync_request_sent(&peer, now + 1).unwrap();
        assert!(sync.due_sync_requests(now + 2).unwrap().is_empty());
        assert_eq!(sync.due_sync_requests(now + 3).unwrap().len(), 1);

        let long_error = "peer offline 🦀".repeat(40);
        sync.mark_sync_request_waiting(&peer, now + 3, &long_error)
            .unwrap();
        let waiting = load_sync_request_on_conn(&conn, &peer).unwrap().unwrap();
        assert_eq!(waiting.state, "waiting_peer");
        assert_eq!(waiting.send_attempts, 1);
        assert!(waiting.last_error.unwrap().chars().count() <= 240);

        let restarted = sync.request_sync(&peer, now + 4).unwrap();
        assert_eq!(restarted.state, "queued");
        assert_eq!(restarted.send_attempts, 0);
        assert!(restarted.last_error.is_none());
        sync.mark_sync_request_complete(&peer, now + 5).unwrap();
        assert!(sync.due_sync_requests(now + 10).unwrap().is_empty());
        let status = sync.list_status(Some(peer.as_str())).unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].request_state.as_deref(), Some("complete"));

        for table in ["mesh_sync_outbound", "mesh_sync_outbound_pending"] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "request queue must not mutate {table}");
        }
    }

    #[test]
    fn sync_request_status_expires_without_a_running_consumer() {
        let (_dir, db_path, _conn) = open_test_db();
        let sync = DurableMeshSync::new(db_path);
        let peer = PeerPubkey::new("b".repeat(64));
        sync.request_sync(&peer, 1).unwrap();

        let status = sync.list_status(Some(peer.as_str())).unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].request_state.as_deref(), Some("expired"));
        assert_eq!(
            status[0].request_expires_at,
            Some(1 + SYNC_REQUEST_TTL_SECS)
        );
    }

    fn canonical_wal(event_type: u8, payload: &[u8]) -> Vec<u8> {
        let header = crate::wal::HeaderBuilder::new(event_type, payload).build();
        crate::wal::frame::encode_frame(&header, payload)
    }

    fn metadata_frame(origin: &str, sequence: u64, marker: &str) -> GossipFrame {
        let payload = canonical_wal(0x94, format!(r#"{{"marker":"{marker}"}}"#).as_bytes());
        let timestamp_unix = gossip_payload_timestamp_unix(&payload).unwrap();
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: format!("metadata:{}", hex_digest(&Sha256::digest(&payload))),
            updated_at_unix: timestamp_unix,
            content: SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload.clone(),
            },
        };
        let origin = PeerPubkey::new(origin);
        let mut vector_clock = VectorClock::new();
        vector_clock.clocks.insert(origin.clone(), sequence);
        GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock,
            origin,
            event_seq: sequence,
            content_sha256: envelope.content_sha256(),
            timestamp_unix,
            tag: crate::cluster::gossip::GossipTag::Replicate,
            payload,
            envelope,
        }
    }

    fn memory_frame(origin: &str, sequence: u64, importance_micros: u32) -> GossipFrame {
        let payload = canonical_wal(0x90, br#"{"event_id":42}"#);
        let timestamp_unix = gossip_payload_timestamp_unix(&payload).unwrap();
        let text = "shared canonical memory".to_string();
        let stable_id = format!("memory:{}", hex_digest(&Sha256::digest(text.as_bytes())));
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: stable_id.clone(),
            updated_at_unix: timestamp_unix,
            content: SyncContent::Memory(MemorySnapshot {
                stable_id,
                text,
                text_hash: "semantic-hash".into(),
                tier: "hot".into(),
                ts_ns: 123,
                importance_micros,
                last_access_ts: 120,
                access_count: 4,
            }),
        };
        let origin = PeerPubkey::new(origin);
        let mut vector_clock = VectorClock::new();
        vector_clock.clocks.insert(origin.clone(), sequence);
        GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock,
            origin,
            event_seq: sequence,
            content_sha256: envelope.content_sha256(),
            timestamp_unix,
            tag: super::super::gossip::GossipTag::Replicate,
            payload,
            envelope,
        }
    }

    fn stage_metadata(
        conn: &mut Connection,
        peer: &PeerPubkey,
        origin: &PeerPubkey,
        next_offset: usize,
    ) -> PreparedFrame {
        let raw = canonical_wal(0x94, br#"{"event_count":1}"#);
        stage_frame(
            conn,
            peer,
            origin,
            0x94,
            0,
            &raw,
            &GossipWalCursor {
                segment: Some(PathBuf::from("wal/000002.wal")),
                offset: next_offset,
            },
            &GossipPolicy::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn restart_resumes_exact_pending_frame() {
        use crate::wal::segment_header::SegmentHeader;

        let (dir, db_path, conn) = open_test_db();
        let peer = PeerPubkey::new("peer-a");
        let origin = PeerPubkey::new("origin");
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let mut bytes = SegmentHeader::new(1, 1, 1, 1, [1; 16])
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&canonical_wal(0x94, br#"{"event_count":1}"#));
        std::fs::write(&segment, bytes).unwrap();
        drop(conn);
        let state = std::sync::Arc::new(std::sync::Mutex::new(
            super::super::wal_sync::GossipState::new(),
        ));

        let first = DurableMeshSync::new(&db_path)
            .prepare_peer_frame(&peer, &origin, &wal_dir, &GossipPolicy::default(), &state)
            .await
            .unwrap()
            .unwrap();
        assert!(!first.replayed_pending);
        let first_wire = serde_json::to_vec(&first.frame).unwrap();
        state
            .lock()
            .unwrap()
            .vc
            .clocks
            .insert(PeerPubkey::new("remote-after-send"), 44);

        let replay = DurableMeshSync::new(&db_path)
            .prepare_peer_frame(&peer, &origin, &wal_dir, &GossipPolicy::default(), &state)
            .await
            .unwrap()
            .unwrap();
        assert!(replay.replayed_pending);
        assert_eq!(serde_json::to_vec(&replay.frame).unwrap(), first_wire);
        let conn = crate::memory::store::open(&db_path).unwrap();
        assert_eq!(
            load_vector_frontier(&conn).unwrap().get(&origin),
            first.frame.vector_clock.get(&origin),
            "pending replay must not tick durable vector time"
        );
    }

    #[test]
    fn destination_sequences_are_independent_from_node_global_vector_time() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let peer_a = PeerPubkey::new("peer-a");
        let peer_b = PeerPubkey::new("peer-b");
        let origin = PeerPubkey::new("origin");
        let raw = canonical_wal(0x94, br#"{"event_count":1}"#);
        let first = stage_frame(
            &mut conn,
            &peer_a,
            &origin,
            0x94,
            0,
            &raw,
            &GossipWalCursor {
                segment: Some(PathBuf::from("wal/000002.wal")),
                offset: 55,
            },
            &GossipPolicy::default(),
        )
        .unwrap();
        let second = stage_frame(
            &mut conn,
            &peer_b,
            &origin,
            0x94,
            0,
            &raw,
            &GossipWalCursor {
                segment: Some(PathBuf::from("wal/000002.wal")),
                offset: 55,
            },
            &GossipPolicy::default(),
        )
        .unwrap();

        assert_eq!(first.frame.event_seq, 1);
        assert_eq!(second.frame.event_seq, 1);
        assert_eq!(first.frame.vector_clock.get(&origin), 1);
        assert_eq!(second.frame.vector_clock.get(&origin), 2);
        assert_eq!(load_vector_frontier(&conn).unwrap().get(&origin), 2);
    }

    #[test]
    fn vector_frontier_listing_is_sorted_and_survives_reopen() {
        let (_dir, db_path, conn) = open_test_db();
        conn.execute(
            "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES ('z-peer',2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES ('a-peer',7)",
            [],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            DurableMeshSync::new(db_path)
                .list_vector_frontier()
                .unwrap(),
            vec![
                VectorFrontierEntry {
                    peer_pk: "a-peer".into(),
                    counter: 7,
                },
                VectorFrontierEntry {
                    peer_pk: "z-peer".into(),
                    counter: 2,
                },
            ]
        );
    }

    #[test]
    fn full_frontier_rejects_new_local_origin_without_evicting_causal_state() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let peer = PeerPubkey::new("peer-a");
        let origin = PeerPubkey::new("origin");
        let retained_remote = PeerPubkey::new("a-retained-remote");
        conn.execute(
            "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES (?1,77)",
            [retained_remote.as_str()],
        )
        .unwrap();
        for index in 0..(MAX_VECTOR_CLOCK_PEERS - 1) {
            conn.execute(
                "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES (?1,1)",
                [format!("remote-{index:04}")],
            )
            .unwrap();
        }

        let raw = canonical_wal(0x94, br#"{"event_count":1}"#);
        let error = stage_frame(
            &mut conn,
            &peer,
            &origin,
            0x94,
            0,
            &raw,
            &GossipWalCursor {
                segment: Some(PathBuf::from("wal/000002.wal")),
                offset: 55,
            },
            &GossipPolicy::default(),
        );
        let error = error.unwrap_err();
        assert!(error.to_string().contains("cannot admit local origin"));

        let frontier = load_vector_frontier(&conn).unwrap();
        assert_eq!(frontier.clocks.len(), MAX_VECTOR_CLOCK_PEERS);
        assert_eq!(frontier.get(&origin), 0);
        assert_eq!(frontier.get(&retained_remote), 77);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM mesh_sync_local_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0,
            "capacity failure must roll back local staging"
        );
    }

    #[test]
    fn full_frontier_explicitly_rejects_a_257th_authenticated_origin() {
        let (_dir, _db_path, mut conn) = open_test_db();
        for index in 0..MAX_VECTOR_CLOCK_PEERS {
            conn.execute(
                "INSERT INTO mesh_sync_vector_frontier (peer_pk,counter) VALUES (?1,1)",
                [format!("remote-{index:04}")],
            )
            .unwrap();
        }
        let origin = PeerPubkey::new("zz-new-authenticated-origin");
        let frame = metadata_frame(origin.as_str(), 1, "full-frontier-origin");
        let error = persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot admit authenticated origin")
        );

        let frontier = load_vector_frontier(&conn).unwrap();
        assert_eq!(frontier.clocks.len(), MAX_VECTOR_CLOCK_PEERS);
        assert_eq!(frontier.get(&origin), 0);
        let receipts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mesh_sync_inbound_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipts, 0, "capacity rejection must roll back content too");
    }

    #[test]
    fn first_v6_send_seeds_local_clock_from_legacy_destination_sequences() {
        let (_dir, _db_path, mut conn) = open_test_db();
        conn.execute(
            "INSERT INTO mesh_sync_local_events \
             (peer_pk,origin_seq,content_sha256,envelope,created_at) \
             VALUES ('legacy-destination',9,zeroblob(32),X'7B7D',1)",
            [],
        )
        .unwrap();
        let origin = PeerPubkey::new("local-v6-origin");
        let prepared = stage_metadata(&mut conn, &PeerPubkey::new("new-destination"), &origin, 55);
        assert_eq!(prepared.frame.event_seq, 1);
        assert_eq!(prepared.frame.vector_clock.get(&origin), 10);
    }

    #[test]
    fn durable_frontier_survives_restart_and_runtime_mirror_is_post_commit() {
        let (_dir, db_path, mut conn) = open_test_db();
        let origin = PeerPubkey::new("peer-a");
        let observed = PeerPubkey::new("peer-observed-by-a");
        let invented = PeerPubkey::new("invented-third-party");
        let mut frame = metadata_frame(origin.as_str(), 1, "frontier");
        frame.vector_clock.clocks.insert(observed.clone(), 8);
        frame.vector_clock.clocks.insert(invented.clone(), 999);
        let state = std::sync::Arc::new(std::sync::Mutex::new(
            super::super::wal_sync::GossipState::new(),
        ));
        let observed_direct = metadata_frame(observed.as_str(), 1, "direct-observed");
        let observed_commit = persist_inbound_on_conn(
            &mut conn,
            &observed,
            &observed_direct,
            &GossipPolicy::default(),
        )
        .unwrap();
        assert!(merge_frontier_after_durable_commit(
            &state,
            &observed_direct,
            &observed_commit
        ));
        assert_eq!(state.lock().unwrap().vc.get(&observed), 1);

        let dropped = InboundCommit::Dropped(GossipAcceptance::DroppedOutsideReplayBudget);
        assert!(!merge_frontier_after_durable_commit(
            &state, &frame, &dropped
        ));
        assert_eq!(state.lock().unwrap().vc.get(&observed), 1);

        let committed =
            persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default()).unwrap();
        assert!(matches!(committed, InboundCommit::Committed(_)));
        assert_eq!(load_vector_frontier(&conn).unwrap().get(&observed), 8);
        assert_eq!(load_vector_frontier(&conn).unwrap().get(&invented), 0);
        assert_eq!(
            state.lock().unwrap().vc.get(&observed),
            1,
            "SQLite COMMIT alone must not mutate a different runtime state"
        );
        assert!(merge_frontier_after_durable_commit(
            &state, &frame, &committed
        ));
        assert_eq!(state.lock().unwrap().vc.get(&observed), 8);

        let duplicate =
            persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default()).unwrap();
        assert!(matches!(duplicate, InboundCommit::Duplicate(_)));
        let rebuilt = std::sync::Arc::new(std::sync::Mutex::new(
            super::super::wal_sync::GossipState::new(),
        ));
        let observed_duplicate = persist_inbound_on_conn(
            &mut conn,
            &observed,
            &observed_direct,
            &GossipPolicy::default(),
        )
        .unwrap();
        assert!(merge_frontier_after_durable_commit(
            &rebuilt,
            &observed_direct,
            &observed_duplicate
        ));
        assert!(merge_frontier_after_durable_commit(
            &rebuilt, &frame, &duplicate
        ));
        assert_eq!(rebuilt.lock().unwrap().vc.get(&observed), 8);

        drop(conn);
        let mut restarted = crate::memory::store::open(&db_path).unwrap();
        assert_eq!(load_vector_frontier(&restarted).unwrap().get(&observed), 8);
        let outbound = stage_metadata(
            &mut restarted,
            &PeerPubkey::new("destination-after-restart"),
            &PeerPubkey::new("local-node"),
            66,
        );
        assert_eq!(outbound.frame.event_seq, 1);
        assert_eq!(outbound.frame.vector_clock.get(&observed), 8);
        assert_eq!(
            outbound
                .frame
                .vector_clock
                .get(&PeerPubkey::new("local-node")),
            1
        );
    }

    #[test]
    fn duplicate_with_mutated_third_party_clock_is_rejected() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let origin = PeerPubkey::new("peer-a");
        let observed = PeerPubkey::new("peer-observed-by-a");
        let observed_direct = metadata_frame(observed.as_str(), 1, "direct-before-retry");
        assert!(matches!(
            persist_inbound_on_conn(
                &mut conn,
                &observed,
                &observed_direct,
                &GossipPolicy::default(),
            )
            .unwrap(),
            InboundCommit::Committed(_)
        ));
        let mut frame = metadata_frame(origin.as_str(), 1, "bound-retry");
        frame.vector_clock.clocks.insert(observed.clone(), 8);
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default(),).unwrap(),
            InboundCommit::Committed(_)
        ));

        let mut poisoned_retry = frame;
        poisoned_retry.vector_clock.clocks.insert(observed, 9_999);
        let error = persist_inbound_on_conn(
            &mut conn,
            &origin,
            &poisoned_retry,
            &GossipPolicy::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("different canonical frame"),
            "unexpected error: {error:#}"
        );
        assert_eq!(
            load_vector_frontier(&conn)
                .unwrap()
                .get(&PeerPubkey::new("peer-observed-by-a")),
            8,
            "rejected duplicate must not mutate durable causal state"
        );
    }

    #[test]
    fn oversized_inbound_vector_clock_fails_before_commit() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let origin = PeerPubkey::new("peer-a");
        let mut frame = metadata_frame(origin.as_str(), 1, "oversized-clock");
        for index in 0..MAX_VECTOR_CLOCK_PEERS {
            frame
                .vector_clock
                .clocks
                .insert(PeerPubkey::new(format!("claimed-{index:04}")), 1);
        }
        assert_eq!(frame.vector_clock.clocks.len(), MAX_VECTOR_CLOCK_PEERS + 1);
        let error = persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default())
            .unwrap_err();
        assert!(error.to_string().contains("bounded peer limit"));
        let receipts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mesh_sync_inbound_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipts, 0);
        assert!(load_vector_frontier(&conn).unwrap().clocks.is_empty());
    }

    #[test]
    fn legacy_unbound_duplicate_is_acked_without_frontier_merge() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let origin = PeerPubkey::new("peer-a");
        let frame = metadata_frame(origin.as_str(), 1, "legacy-receipt");
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default(),).unwrap(),
            InboundCommit::Committed(_)
        ));
        conn.execute(
            "UPDATE mesh_sync_inbound_receipts SET frame_sha256 = NULL",
            [],
        )
        .unwrap();

        let duplicate =
            persist_inbound_on_conn(&mut conn, &origin, &frame, &GossipPolicy::default()).unwrap();
        assert!(matches!(duplicate, InboundCommit::DuplicateUnbound(_)));
        let state = std::sync::Arc::new(std::sync::Mutex::new(
            super::super::wal_sync::GossipState::new(),
        ));
        assert!(!merge_frontier_after_durable_commit(
            &state, &frame, &duplicate
        ));
        assert!(state.lock().unwrap().vc.clocks.is_empty());
    }

    #[test]
    fn queue_failure_does_not_advance_cursor() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let peer = PeerPubkey::new("peer-a");
        let origin = PeerPubkey::new("origin");
        stage_metadata(&mut conn, &peer, &origin, 77);
        let cursor: i64 = conn
            .query_row(
                "SELECT cursor_offset FROM mesh_sync_outbound WHERE peer_pk=?1",
                [peer.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, 0, "queue/send without ACK cannot advance cursor");
        assert!(load_pending(&conn, &peer).unwrap().is_some());
    }

    #[test]
    fn db_failure_produces_no_ack_and_rolls_back() {
        let (_dir, _db_path, mut conn) = open_test_db();
        conn.execute_batch("DROP TABLE mesh_sync_inbound_receipts;")
            .unwrap();
        let frame = metadata_frame("peer-a", 1, "db-fail");
        let result = persist_inbound_on_conn(
            &mut conn,
            &PeerPubkey::new("peer-a"),
            &frame,
            &GossipPolicy::default(),
        );
        assert!(result.is_err(), "DB failure must not manufacture an ACK");
        let count: i64 = conn
            .query_row("SELECT count(*) FROM mesh_sync_inbound", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, 0,
            "failed transaction must not advance inbound state"
        );
    }

    #[test]
    fn duplicate_ack_is_idempotent() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let peer = PeerPubkey::new("peer-a");
        let origin = PeerPubkey::new("origin");
        let prepared = stage_metadata(&mut conn, &peer, &origin, 77);
        let ack = GossipAck {
            protocol_version: SYNC_PROTOCOL_VERSION,
            origin: origin.clone(),
            origin_seq: prepared.frame.event_seq,
            content_sha256: prepared.frame.content_sha256,
        };
        assert_eq!(
            acknowledge_outbound_on_conn(&mut conn, &peer, &origin, &ack).unwrap(),
            OutboundAckOutcome::Applied
        );
        assert_eq!(
            acknowledge_outbound_on_conn(&mut conn, &peer, &origin, &ack).unwrap(),
            OutboundAckOutcome::Duplicate
        );
        let cursor: i64 = conn
            .query_row(
                "SELECT cursor_offset FROM mesh_sync_outbound WHERE peer_pk=?1",
                [peer.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, 77);
    }

    #[test]
    fn out_of_order_gap_is_deterministic_and_has_no_ack() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let frame = metadata_frame("peer-a", 2, "gap");
        let result = persist_inbound_on_conn(
            &mut conn,
            &PeerPubkey::new("peer-a"),
            &frame,
            &GossipPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            result,
            InboundCommit::Gap {
                expected: 1,
                received: 2,
            }
        );
        assert!(result.ack().is_none());
    }

    #[test]
    fn partial_batch_resumes_at_first_gap() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let peer = PeerPubkey::new("peer-a");
        let one = metadata_frame(peer.as_str(), 1, "one");
        let two = metadata_frame(peer.as_str(), 2, "two");
        let three = metadata_frame(peer.as_str(), 3, "three");
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &peer, &one, &GossipPolicy::default()).unwrap(),
            InboundCommit::Committed(_)
        ));
        assert_eq!(
            persist_inbound_on_conn(&mut conn, &peer, &three, &GossipPolicy::default()).unwrap(),
            InboundCommit::Gap {
                expected: 2,
                received: 3,
            }
        );
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &peer, &two, &GossipPolicy::default()).unwrap(),
            InboundCommit::Committed(_)
        ));
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &peer, &three, &GossipPolicy::default()).unwrap(),
            InboundCommit::Committed(_)
        ));
    }

    #[test]
    fn independent_peers_have_independent_sequences_and_cursors() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let origin = PeerPubkey::new("origin");
        let peer_a = PeerPubkey::new("peer-a");
        let peer_b = PeerPubkey::new("peer-b");
        let a = stage_metadata(&mut conn, &peer_a, &origin, 11);
        let b = stage_metadata(&mut conn, &peer_b, &origin, 22);
        assert_eq!(a.frame.event_seq, 1);
        assert_eq!(b.frame.event_seq, 1);
        let ack = GossipAck {
            protocol_version: SYNC_PROTOCOL_VERSION,
            origin: origin.clone(),
            origin_seq: a.frame.event_seq,
            content_sha256: a.frame.content_sha256,
        };
        acknowledge_outbound_on_conn(&mut conn, &peer_a, &origin, &ack).unwrap();
        assert!(load_pending(&conn, &peer_a).unwrap().is_none());
        assert!(load_pending(&conn, &peer_b).unwrap().is_some());
    }

    #[test]
    fn tampered_digest_and_authenticated_peer_mismatch_are_rejected() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let mut frame = metadata_frame("peer-a", 1, "tamper");
        frame.content_sha256[0] ^= 0xff;
        let outcome = persist_inbound_on_conn(
            &mut conn,
            &PeerPubkey::new("peer-a"),
            &frame,
            &GossipPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            outcome,
            InboundCommit::Dropped(GossipAcceptance::DroppedContentDigest)
        );
        let valid = metadata_frame("peer-a", 1, "auth");
        assert!(
            persist_inbound_on_conn(
                &mut conn,
                &PeerPubkey::new("peer-b"),
                &valid,
                &GossipPolicy::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn oversized_memory_snapshot_is_rejected_before_persistence() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let mut frame = memory_frame("peer-a", 1, 500_000);
        let SyncContent::Memory(snapshot) = &mut frame.envelope.content else {
            unreachable!("memory fixture")
        };
        snapshot.text = "x".repeat(MAX_MEMORY_TEXT_BYTES + 1);
        snapshot.stable_id = format!(
            "memory:{}",
            hex_digest(&Sha256::digest(snapshot.text.as_bytes()))
        );
        frame.envelope.content_id = snapshot.stable_id.clone();
        frame.content_sha256 = frame.envelope.content_sha256();

        let error = persist_inbound_on_conn(
            &mut conn,
            &PeerPubkey::new("peer-a"),
            &frame,
            &GossipPolicy::default(),
        )
        .expect_err("oversized peer memory must fail before any durable insert");
        assert!(error.to_string().contains("1 MiB cluster limit"));
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn full_content_roundtrip_and_conflicts_are_typed() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let a1 = memory_frame("peer-a", 1, 500_000);
        let b1 = memory_frame("peer-b", 1, 700_000);
        let a2 = memory_frame("peer-a", 2, 900_000);
        for frame in [&a1, &b1, &a2] {
            let origin = frame.origin.clone();
            assert!(matches!(
                persist_inbound_on_conn(&mut conn, &origin, frame, &GossipPolicy::default())
                    .unwrap(),
                InboundCommit::Committed(_)
            ));
        }
        let payload: Vec<u8> = conn
            .query_row(
                "SELECT content_payload FROM idx_foreign_events WHERE origin_peer_pk='peer-a' AND origin_seq=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let roundtrip: SyncEnvelope = serde_json::from_slice(&payload).unwrap();
        assert_eq!(roundtrip, a2.envelope);
        let ordered: i64 = conn
            .query_row(
                "SELECT count(*) FROM mesh_sync_conflicts WHERE policy='ordered_origin_lww'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let cross: i64 = conn
            .query_row(
                "SELECT count(*) FROM mesh_sync_conflicts WHERE policy='cross_origin_typed_conflict'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ordered, 1);
        assert!(cross >= 1);
    }

    #[test]
    fn conflict_resolution_is_persisted_and_new_digest_pairs_reopen() {
        let (_dir, db_path, mut conn) = open_test_db();
        let a1 = memory_frame("peer-a", 1, 500_000);
        let b1 = memory_frame("peer-b", 1, 700_000);
        let content_id = a1.envelope.content_id.clone();
        for frame in [&a1, &b1] {
            assert!(matches!(
                persist_inbound_on_conn(&mut conn, &frame.origin, frame, &GossipPolicy::default())
                    .unwrap(),
                InboundCommit::Committed(_)
            ));
        }
        drop(conn);

        let sync = DurableMeshSync::new(&db_path);
        let open = sync.list_conflicts(Some(&content_id), 100, false).unwrap();
        assert!(!open.is_empty());
        assert!(open.iter().all(|row| row.resolved_at.is_none()));
        let receipt = sync.resolve_conflicts(&content_id, "peer-a").unwrap();
        assert_eq!(receipt.operation, "cluster.conflicts.resolve");
        assert!(receipt.resolved_count > 0);
        assert_eq!(receipt.unresolved_remaining, 0);
        assert!(
            sync.list_conflicts(Some(&content_id), 100, false)
                .unwrap()
                .is_empty()
        );
        let history = sync.list_conflicts(Some(&content_id), 100, true).unwrap();
        assert!(history.iter().all(|row| {
            row.resolved_at.is_some() && row.preferred_origin.as_deref() == Some("peer-a")
        }));
        assert!(sync.resolve_conflicts(&content_id, "peer-a").is_err());

        let mut conn = crate::memory::store::open(&db_path).unwrap();
        let b2 = memory_frame("peer-b", 2, 800_000);
        assert!(matches!(
            persist_inbound_on_conn(&mut conn, &b2.origin, &b2, &GossipPolicy::default()).unwrap(),
            InboundCommit::Committed(_)
        ));
        drop(conn);
        assert!(sync.unresolved_conflict_count().unwrap() > 0);
    }

    #[test]
    fn conflict_resolution_rejects_an_origin_without_materialized_content() {
        let (_dir, db_path, mut conn) = open_test_db();
        let a1 = memory_frame("peer-a", 1, 500_000);
        let b1 = memory_frame("peer-b", 1, 700_000);
        let content_id = a1.envelope.content_id.clone();
        for frame in [&a1, &b1] {
            persist_inbound_on_conn(&mut conn, &frame.origin, frame, &GossipPolicy::default())
                .unwrap();
        }
        drop(conn);

        let sync = DurableMeshSync::new(db_path);
        let error = sync
            .resolve_conflicts(&content_id, "peer-not-present")
            .unwrap_err();
        assert!(error.to_string().contains("has no materialized"));
        assert!(sync.unresolved_conflict_count().unwrap() > 0);
    }

    #[test]
    fn ground_truth_roundtrip_preserves_portable_provenance_without_peer_ids() {
        let (_source_dir, _source_db, source) = open_test_db();
        let evidence_text = "portable mesh evidence";
        source
            .execute(
                "INSERT INTO idx_episode \
                 (event_id,event_type,ts_ns,text,text_hash,importance,last_access_ts,access_count) \
                 VALUES (42,1,100,?1,'evidence-hash',0.8,101,3)",
                [evidence_text],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO idx_groundtruth \
                 (id,statement,source,scope,asserted_at,fact_state,source_weight,confidence, \
                  evidence,maturity,confirmed_count) \
                 VALUES (7,'Mesh content is durable','operator-runtime','global',90,'verified', \
                         '{\"nmap-scan\":1,\"operator-runtime\":2}',0.9,'[42]','stable',5)",
                [],
            )
            .unwrap();
        let inner = br#"{"id":7,"ts":100}"#;
        let header = crate::wal::HeaderBuilder::new(0x98, inner).build();
        let raw = crate::wal::frame::encode_frame(&header, inner);
        let timestamp = gossip_payload_timestamp_unix(&raw).unwrap();
        let envelope =
            materialize_envelope(&source, 0x98, 0, &raw, timestamp, &GossipPolicy::default())
                .unwrap();
        let SyncContent::GroundTruth(snapshot) = &envelope.content else {
            panic!("0x98 must materialize a ground-truth snapshot");
        };
        assert_eq!(snapshot.source, "operator-runtime");
        assert_eq!(snapshot.source_weight["operator-runtime"], 2);
        assert_eq!(snapshot.confirmed_count, 5);
        assert_eq!(snapshot.evidence_content_ids.len(), 1);
        assert_eq!(
            snapshot.evidence_content_ids[0],
            format!(
                "memory:{}",
                hex_digest(&Sha256::digest(evidence_text.as_bytes()))
            )
        );
        assert!(
            snapshot
                .evidence_content_ids
                .iter()
                .all(|content_id| content_id != "42" && !content_id.ends_with(":42")),
            "peer-local evidence row ids must not cross the mesh"
        );

        let origin = PeerPubkey::new("peer-a");
        let mut vector_clock = VectorClock::new();
        vector_clock.clocks.insert(origin.clone(), 1);
        let frame = GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock,
            origin: origin.clone(),
            event_seq: 1,
            content_sha256: envelope.content_sha256(),
            timestamp_unix: timestamp,
            tag: super::super::gossip::GossipTag::Replicate,
            payload: raw,
            envelope: envelope.clone(),
        };
        let (_target_dir, _target_db, mut target) = open_test_db();
        assert!(matches!(
            persist_inbound_on_conn(&mut target, &origin, &frame, &GossipPolicy::default())
                .unwrap(),
            InboundCommit::Committed(_)
        ));
        let stored: Vec<u8> = target
            .query_row(
                "SELECT content_payload FROM idx_foreign_events WHERE origin_peer_pk='peer-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<SyncEnvelope>(&stored).unwrap(),
            envelope
        );
    }

    #[test]
    fn old_protocol_is_rejected_cleanly_without_state() {
        let (_dir, _db_path, mut conn) = open_test_db();
        let mut frame = metadata_frame("peer-a", 1, "old-protocol");
        frame.protocol_version = SYNC_PROTOCOL_VERSION - 1;
        let result = persist_inbound_on_conn(
            &mut conn,
            &PeerPubkey::new("peer-a"),
            &frame,
            &GossipPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            result,
            InboundCommit::Dropped(GossipAcceptance::DroppedProtocolVersion {
                received: SYNC_PROTOCOL_VERSION - 1,
            })
        );
        let count: i64 = conn
            .query_row("SELECT count(*) FROM mesh_sync_inbound", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn corrupt_startup_cursor_fails_closed() {
        let (dir, _db_path, conn) = open_test_db();
        conn.execute(
            "INSERT INTO mesh_sync_outbound (peer_pk,cursor_segment,cursor_offset,updated_at) VALUES ('peer-a','outside/evil.wal',0,0)",
            [],
        )
        .unwrap();
        let wal_dir = dir.path().join("wal");
        let result = load_outbound_state(&conn, &PeerPubkey::new("peer-a"), &wal_dir);
        assert!(result.is_err());
    }
}
