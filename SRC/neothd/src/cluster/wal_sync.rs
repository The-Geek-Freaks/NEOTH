//! SL-01b — cluster WAL gossip: the band-filter ACL + anti-entropy state.
//!
//! Makes the shipped-but-dormant gossip primitives ([`super::gossip`] +
//! [`super::gossip_wire`]) LIVE on the cluster transport. Scope (gremium-locked
//! `d7ca0144`):
//!
//! - **Band-filter ACL** ([`classify_event`]): the security boundary. Maps each
//!   WAL `event_type` to `Replicate` / `RawIngressGated` / `DoNotGossip`.
//!   **Default-deny** — any unrecognised code is `DoNotGossip`. This is what
//!   keeps a gossip broadcast from ever leaking permissions, profile PII,
//!   consent, raw conversation text, or WAL-structure events to a peer.
//! - **Production send/receive/persist** ([`super::durable_sync`]): both
//!   peeroxide and iroh use one SQLite-backed state machine. It stages one exact
//!   frame per destination, accepts only contiguous authenticated sequences,
//!   commits canonical content and receipts atomically, and advances a cursor
//!   only on the receiver's exact post-commit ACK.
//! - **Causal frontier** is durably stored by [`super::durable_sync`] and
//!   updated in the same SQLite transactions that stage outbound or commit
//!   inbound frames. [`GossipState`] is only the shared runtime observability
//!   mirror; it is never the source of truth. Legacy restore helpers remain for
//!   old exports and focused policy tests.
//! - **Restore** ([`apply_restore_envelope`]): canonical memory and ground-truth
//!   snapshots allocate receiver-local ids through a durable origin/content
//!   map. A peer-local numeric id is never guessed.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use rusqlite::OptionalExtension as _;

use super::PeerPubkey;
use super::gossip::{GossipPolicy, GossipTag, ReplayBudget};
use super::gossip_wire::{
    GossipAcceptance, GossipFrame, GroundTruthSnapshot, SYNC_ENVELOPE_VERSION,
    SYNC_PROTOCOL_VERSION, SyncContent, SyncEnvelope, VectorClock,
};
use super::heartbeat::{FrameBody, FrameKind, WireFrame};
use super::peer_streams::PeerStreamRegistry;
use crate::wal::writer::WalWriterHandle;

/// Gossip anti-entropy tick interval. A peer offline > ReplayBudget re-pairs;
/// 30s keeps convergence prompt without flooding the bounded outbound queue.
const GOSSIP_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// How a WAL event_type may cross the cluster boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationClass {
    /// Non-PII cluster/coherence event — replicate by default.
    Replicate,
    /// Carries operator/user PII — replicate ONLY when the operator opts in via
    /// `GossipPolicy::replicate_raw_ingress`.
    RawIngressGated,
    /// NEVER leaves this node (secrets, permissions, profile, consent,
    /// WAL-structure, local lifecycle, or any unrecognised code).
    DoNotGossip,
}

/// The band-filter ACL. **Default-deny**, and deliberately NARROW: an event
/// only replicates if its payload is verified (against `wal/events.rs`) to carry
/// ZERO secrets, PII, network topology, or operator config. The receiver drops
/// the payload (ingestion deferred), so the only thing crossing the wire is the
/// raw frame bytes — which is exactly what this ACL bounds.
///
/// **Replicate** — payloads are pure ids / importance scores / counts / version
/// strings (verified):
/// - `0x90` EPISODE_CONSOLIDATED, `0x91` EPISODE_PROMOTED, `0x92`
///   EPISODE_ARCHIVED, `0x94` CONSOLIDATION_PASS — `{event_id, importance, ts}`
///   / aggregate counts, NO content.
/// - `0x98` GROUNDTRUTH_REVOKED — `{id, ts}`.
/// - `0x13` UPDATE_RAN — `{component, old_version, new_version, status}` (clean
///   capability-negotiation signal).
///
/// **RawIngressGated** (off unless `replicate_raw_ingress`): raw text / provider
/// / channel frames (PII).
///
/// **DoNotGossip (everything else)** — including, by DELIBERATE security
/// decision (SL-01b review HIGH/LOW findings):
/// - the whole `0xE0..=0xEF` cluster band: `0xE6` PEER_CONFIRMED carries the
///   peer `addr` + operator `autonomy_level`; `0xE0`/`0xE9` carry peer pubkeys
///   (topology). Cross-node topology sync needs an explicit SANITISED shape — a
///   v1.0 feature, never a raw-frame gossip default.
/// - `0x12` INSTALLER_RAN (`login_state` reveals CLI auth status), `0x93`
///   IMPORTANCE_REINFORCED (`query_hash` reveals which recall queries hit
///   memory), `0x97` GROUNDTRUTH_ADDED (`source` may name a foreign agent),
///   `0x40..=0x46` cron (`0x42` JOB_FAILED `error` may carry provider context).
/// - permissions `0xA*`, profile `0xB*`, consent `0x65`, WAL-structure `0xF*`,
///   daemon lifecycle, and any unrecognised code.
pub fn classify_event(event_type: u8) -> ReplicationClass {
    use ReplicationClass::*;
    match event_type {
        // Memory-tier transitions — pure {event_id, importance, ts} / aggregate
        // counts (NO content; 0x93 excluded — it carries query_hash).
        0x90 | 0x91 | 0x92 | 0x94 => Replicate,
        // Ground-truth REVOKED — {id, ts} only (0x97 ADDED excluded: it carries
        // a `source` label).
        0x98 => Replicate,
        // Version state — {component, versions, status}, clean capability signal
        // (0x12 INSTALLER_RAN excluded: it carries login_state).
        0x13 => Replicate,
        // PII — gated behind the operator's raw-ingress opt-in (default off).
        raw if crate::wal::events::is_raw_ingress_event(raw) => RawIngressGated,
        // Default-deny everything else: the entire 0xE* cluster band (addr /
        // autonomy / pubkey topology), permissions 0xA*, profile 0xB*, consent
        // 0x65, WAL-structure 0xF*, cron, lifecycle, and unknown codes.
        _ => DoNotGossip,
    }
}

/// Resolve the ACL against the operator's policy: is this event_type allowed to
/// cross the cluster boundary right now?
pub fn is_replicable(event_type: u8, policy: &GossipPolicy) -> bool {
    match classify_event(event_type) {
        ReplicationClass::Replicate => true,
        ReplicationClass::RawIngressGated => policy.replicate_raw_ingress,
        ReplicationClass::DoNotGossip => false,
    }
}

/// Subtype byte for `SwarmResourceSnapshot` EXTENDED frames (event_type=0x00).
///
/// A peer-emitted resource snapshot uses this subtype on the gossip wire so
/// [`classify_event_ext`] can gate it for replication while keeping
/// `LocalSnapshot` (subtype 0x04, written only to the local WAL) out of the
/// gossip band. Matches `crate::wal::events::ExtendedSubtype::SwarmResourceSnapshot`.
pub const SWARM_SNAPSHOT_SUBTYPE: u8 = 0x03;

/// Extended band-filter ACL that keys on `(event_type, event_subtype)`.
///
/// For `EVENT_TYPE_EXTENDED` (0x00) frames the top-level byte alone cannot
/// distinguish a peer-emitted `SwarmResourceSnapshot` (subtype 0x03) from a
/// locally-written `LocalSnapshot` (subtype 0x04). This function applies the
/// subtype gate so ONLY the former crosses the gossip wire.
///
/// - `(0x00, 0x03)` → `Replicate` (SwarmResourceSnapshot — peer resource data)
/// - `(0x00, _)` → `DoNotGossip` (LocalSnapshot and any future 0x00/* subtypes)
/// - other types → delegated to [`classify_event`] (the non-EXTENDED ACL)
pub fn classify_event_ext(event_type: u8, event_subtype: u8) -> ReplicationClass {
    if event_type == 0x00 {
        if event_subtype == SWARM_SNAPSHOT_SUBTYPE {
            ReplicationClass::Replicate
        } else {
            ReplicationClass::DoNotGossip
        }
    } else {
        classify_event(event_type)
    }
}

/// Like [`is_replicable`] but keys on `(event_type, event_subtype)`.
///
/// Use on both the emit and receive paths wherever the subtype byte is
/// available — [`collect_gossipable_frames`], [`GossipState::build_outbound`],
/// [`GossipState::accept_inbound`].
pub fn is_replicable_ext(event_type: u8, event_subtype: u8, policy: &GossipPolicy) -> bool {
    match classify_event_ext(event_type, event_subtype) {
        ReplicationClass::Replicate => true,
        ReplicationClass::RawIngressGated => policy.replicate_raw_ingress,
        ReplicationClass::DoNotGossip => false,
    }
}

/// Per-node anti-entropy state. In-memory for SL-01b (rebuilds from inbound
/// frames via `merge` after a restart; persistence is a follow-on once
/// ingestion lands and replays become meaningful).
#[derive(Debug, Default)]
pub struct GossipState {
    /// This node's logical-time view (advanced on each outbound frame, merged
    /// on each accepted inbound frame).
    pub vc: VectorClock,
    /// Dedup table: origin peer → bounded set of stable payload identities.
    seen: HashMap<PeerPubkey, SeenEvents>,
    /// Most recently committed identity per peer, for observability only. It
    /// is not a high-water gate because SHA-derived identities are unordered.
    latest_seen: HashMap<PeerPubkey, u64>,
}

/// The one bounded runtime mirror shared by an active carrier's receive and
/// send paths. Durable sync is authoritative; this mirror exists for live
/// observability and compatibility helpers only.
pub type SharedGossipState = Arc<Mutex<GossipState>>;

const SEEN_EVENTS_PER_PEER: usize = 16_384;

#[derive(Debug, Default)]
struct SeenEvents {
    ids: HashSet<u64>,
    order: VecDeque<u64>,
}

impl SeenEvents {
    fn contains(&self, event_seq: u64) -> bool {
        self.ids.contains(&event_seq)
    }

    fn insert(&mut self, event_seq: u64) {
        if !self.ids.insert(event_seq) {
            return;
        }
        self.order.push_back(event_seq);
        if self.order.len() > SEEN_EVENTS_PER_PEER
            && let Some(evicted) = self.order.pop_front()
        {
            self.ids.remove(&evicted);
        }
    }
}

impl GossipState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an outbound [`GossipFrame`] for a local WAL frame, or `None` when
    /// the event is NOT replicable (the send-side band-filter ACL). `self_id`
    /// is this node's cluster identity (`PairedPeer::pub_key_hex`).
    ///
    /// `event_subtype` must be 0 for all non-EXTENDED (`event_type != 0x00`)
    /// frames; for EXTENDED frames pass the subtype byte (e.g.
    /// [`SWARM_SNAPSHOT_SUBTYPE`] for a peer snapshot gossip frame).
    pub fn build_outbound(
        &mut self,
        self_id: &PeerPubkey,
        event_type: u8,
        event_subtype: u8,
        payload: Vec<u8>,
        timestamp_unix: i64,
        policy: &GossipPolicy,
    ) -> Option<GossipFrame> {
        if !is_replicable_ext(event_type, event_subtype, policy) {
            return None;
        }
        if !self.vc.tick(self_id) {
            return None;
        }
        let event_seq = self.vc.get(self_id);
        use sha2::Digest as _;
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: format!(
                "metadata:{}",
                restore_hex_digest(&sha2::Sha256::digest(&payload))
            ),
            updated_at_unix: timestamp_unix,
            content: SyncContent::Metadata {
                event_type,
                event_subtype,
                wal_frame: payload.clone(),
            },
        };
        let content_sha256 = envelope.content_sha256();
        Some(GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock: self.vc.clone(),
            origin: self_id.clone(),
            event_seq,
            content_sha256,
            timestamp_unix,
            tag: GossipTag::Replicate,
            payload,
            envelope,
        })
    }

    /// Receiver-side decision for an inbound [`GossipFrame`]. Runs:
    ///   1. `evaluate_acceptance` (tag replicable / within budget / not dup),
    ///   2. defence-in-depth band re-check on the payload's OWN event_type
    ///      (`payload_event_type`; a buggy/malicious sender could tag a
    ///      DoNotGossip event as Replicate).
    /// `payload_event_type` is `None` when the caller couldn't decode the inner
    /// WAL header — treated as un-trusted ⇒ dropped.
    ///
    /// CHECK-ONLY (G02-CLUSTER-02 persist-then-dedup): `Accept` mutates
    /// NOTHING. The caller persists the payload first and calls
    /// [`Self::commit_inbound`] only after the DB write is confirmed —
    /// recording the dedup identity (and merging the sender's VC) before
    /// persistence made a failed INSERT a permanent loss: the peer's
    /// anti-entropy considered the event delivered and never re-sent it.
    ///
    /// `payload_event_subtype` is the subtype byte (WAL header byte 3) for
    /// EXTENDED frames, or `None` / `Some(0)` for all other event types.
    pub fn accept_inbound(
        &mut self,
        frame: &GossipFrame,
        payload_event_type: Option<u8>,
        payload_event_subtype: Option<u8>,
        policy: &GossipPolicy,
        now_ts_unix: i64,
    ) -> GossipAcceptance {
        let budget = ReplayBudget::from_policy(policy);
        let already_seen = self
            .seen
            .get(&frame.origin)
            .is_some_and(|seen| seen.contains(frame.event_seq));
        let verdict = frame.evaluate_acceptance(&budget, now_ts_unix, already_seen);
        if !matches!(verdict, GossipAcceptance::Accept) {
            return verdict;
        }
        // Defence-in-depth: the emit-side ACL should already have dropped a
        // non-replicable event, but re-classify the payload's real event_type
        // (+ subtype for EXTENDED frames) so a mis-tagged frame can't smuggle
        // a DoNotGossip band across.
        match payload_event_type {
            Some(et) => {
                let sub = payload_event_subtype.unwrap_or(0);
                if !is_replicable_ext(et, sub, policy) {
                    return GossipAcceptance::DroppedDoNotGossipTag;
                }
            }
            None => return GossipAcceptance::DroppedDoNotGossipTag,
        }
        GossipAcceptance::Accept
    }

    /// Commit an accepted-AND-persisted inbound frame: record the stable dedup
    /// identity + converge the VC. Call ONLY after the foreign event is
    /// durably stored (`ingest_foreign_event` returned `Ok`). Idempotent for
    /// the same frame (re-inserting the same seq / re-merging the same VC is
    /// a no-op), so a duplicate arriving before the first commit lands is
    /// harmless — the DB's `INSERT OR IGNORE` on (origin, seq) absorbs it.
    pub fn commit_inbound(&mut self, frame: &GossipFrame) {
        self.seen
            .entry(frame.origin.clone())
            .or_default()
            .insert(frame.event_seq);
        self.latest_seen
            .insert(frame.origin.clone(), frame.event_seq);
        self.vc.merge(&frame.vector_clock);
    }

    /// Mirror a production durable commit without allowing one paired peer to
    /// invent transitive identities. The authenticated frame origin may enter;
    /// third-party slots only advance identities already known to this mirror.
    pub fn commit_authenticated_inbound(&mut self, frame: &GossipFrame) {
        self.seen
            .entry(frame.origin.clone())
            .or_default()
            .insert(frame.event_seq);
        self.latest_seen
            .insert(frame.origin.clone(), frame.event_seq);
        let origin_counter = frame.vector_clock.get(&frame.origin);
        if !self.vc.clocks.contains_key(&frame.origin)
            && self.vc.clocks.len() == super::gossip_wire::MAX_VECTOR_CLOCK_PEERS
        {
            // The durable transaction already made the authoritative admission
            // decision. This runtime-only mirror may be stale, but it must never
            // evict an existing (possibly local) causal slot to imitate that
            // decision. Leave the new origin absent until the mirror is hydrated
            // from durable state; dedup observability above still advances.
            return;
        }
        self.vc
            .clocks
            .entry(frame.origin.clone())
            .and_modify(|counter| *counter = (*counter).max(origin_counter))
            .or_insert(origin_counter);
        for (peer, incoming_counter) in &frame.vector_clock.clocks {
            if peer == &frame.origin {
                continue;
            }
            if let Some(counter) = self.vc.clocks.get_mut(peer) {
                *counter = (*counter).max(*incoming_counter);
            }
        }
    }

    /// Record a newly durably staged outbound frame in the shared frontier.
    /// The frame is an authoritative bounded snapshot loaded and committed by
    /// durable sync, so it can hydrate the runtime mirror exactly after restart.
    pub fn commit_outbound(&mut self, frame: &GossipFrame) {
        self.vc = frame.vector_clock.clone();
    }

    /// Highest applied seq for a peer (observability).
    pub fn last_seen_seq(&self, origin: &PeerPubkey) -> Option<u64> {
        self.latest_seen.get(origin).copied()
    }
}

/// Decode the canonical WAL frame metadata carried by every gossip payload.
///
/// This is deliberately shared by both transports. Reading fixed bytes from
/// the payload used to interpret the 4-byte `NEOT` preamble as the event type
/// and silently rejected normal WAL frames. Full decoding also verifies the
/// declared frame length and CRC before the receive-side ACL trusts the type.
pub fn gossip_payload_event_meta(payload: &[u8]) -> Option<(u8, u8)> {
    let decoded = crate::wal::frame::decode_frame(payload).ok()?;
    if decoded.header.total_len as usize != payload.len() {
        return None;
    }
    Some((decoded.header.event_type, decoded.header.event_subtype))
}

/// Original WAL event time used by the replay-budget gate. Retries must not
/// stamp `now`, otherwise an old frame can be refreshed indefinitely and evade
/// the operator's bounded replay window.
pub fn gossip_payload_timestamp_unix(payload: &[u8]) -> Option<i64> {
    let decoded = crate::wal::frame::decode_frame(payload).ok()?;
    if decoded.header.total_len as usize != payload.len() {
        return None;
    }
    i64::try_from(decoded.header.hlc.physical_ns() / 1_000_000_000).ok()
}

/// Walk an uncompressed WAL segment BODY from `from_offset`, collecting up to
/// `max` REPLICABLE canonical frames as `(event_type, raw_frame_bytes)`. Returns the
/// collected frames + the new cursor (advanced past every frame walked, so the
/// next tick continues from there). Stops cleanly on a torn/short tail.
///
/// Pure — no IO. The shared directory walker reconstructs each live or sealed
/// segment into logical frame bytes, strips the segment header, and calls this
/// on the body.
///
/// GOLD-ARCH-03 audit: intentionally NOT migrated to `wal::scan::for_each_frame`.
/// Gossip needs the RAW on-wire frame bytes + a resumable cursor, and the caller
/// (`read_gossipable_batch`) already derives the correct versioned
/// `header_len()` and reconstructs compressed/encrypted sealed segments through
/// `wal::compaction::logical_segment_bytes`. The format-awareness lives in the
/// caller; this stays a pure logical-body walk.
pub fn collect_gossipable_frames(
    body: &[u8],
    from_offset: usize,
    policy: &GossipPolicy,
    max: usize,
) -> (Vec<(u8, Vec<u8>)>, usize) {
    let mut out = Vec::new();
    let mut cursor = from_offset.min(body.len());
    while cursor < body.len() && out.len() < max {
        // `decode_frame` accepts a slice containing later frames, then uses the
        // first header's declared length for CRC and payload boundaries.
        // Any torn/corrupt tail stops the cursor before untrusted bytes.
        let decoded = match crate::wal::frame::decode_frame(&body[cursor..]) {
            Ok(decoded) => decoded,
            Err(_) => break,
        };
        let total_len = decoded.header.total_len as usize;
        if total_len == 0 || cursor.saturating_add(total_len) > body.len() {
            break;
        }
        let event_type = decoded.header.event_type;
        let event_subtype = decoded.header.event_subtype;
        // Use ext classifier so SwarmResourceSnapshot (0x00/0x03) is included
        // and LocalSnapshot (0x00/0x04) is correctly excluded.
        if is_replicable_ext(event_type, event_subtype, policy) {
            out.push((event_type, body[cursor..cursor + total_len].to_vec()));
        }
        cursor += total_len;
    }
    (out, cursor)
}

/// Crash-safe anti-entropy cursor across the complete local WAL history.
///
/// The cursor is intentionally transport-independent. Both peeroxide and iroh
/// walk the same sorted segment set, including sealed compressed/encrypted
/// segments reconstructed through the canonical WAL reader. Stable payload
/// identities make every wrap-around retry idempotent at the receiver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GossipWalCursor {
    pub(crate) segment: Option<PathBuf>,
    pub(crate) offset: usize,
}

/// Read the next bounded anti-entropy batch without blocking Tokio's executor
/// on file IO, decompression, or sealed-segment decryption.
pub async fn read_gossipable_batch(
    wal_dir: &std::path::Path,
    cursor: &mut GossipWalCursor,
    policy: &GossipPolicy,
    max: usize,
) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
    let wal_dir = wal_dir.to_path_buf();
    let mut next_cursor = cursor.clone();
    let policy = policy.clone();
    let (frames, next_cursor) = tokio::task::spawn_blocking(move || {
        let frames = collect_gossipable_from_wal_dir(&wal_dir, &mut next_cursor, &policy, max);
        (frames, next_cursor)
    })
    .await
    .context("cluster anti-entropy WAL scan task panicked")?;
    let frames = frames?;
    *cursor = next_cursor;
    Ok(frames)
}

fn collect_gossipable_from_wal_dir(
    wal_dir: &std::path::Path,
    cursor: &mut GossipWalCursor,
    policy: &GossipPolicy,
    max: usize,
) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
    if max == 0 {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(wal_dir).with_context(|| {
        format!(
            "cluster anti-entropy cannot read WAL directory {}",
            wal_dir.display()
        )
    })?;
    let mut segments = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| {
                format!(
                    "cluster anti-entropy cannot enumerate WAL directory {}",
                    wal_dir.display()
                )
            })?
            .path();
        if path.extension().is_some_and(|ext| ext == "wal") {
            segments.push(path);
        }
    }
    segments.sort();
    if segments.is_empty() {
        *cursor = GossipWalCursor::default();
        return Ok(Vec::new());
    }

    let start_index = match cursor.segment.as_ref() {
        Some(current) => segments
            .iter()
            .position(|path| path == current)
            .with_context(|| {
                format!(
                    "cluster anti-entropy cursor segment {} no longer exists; refusing an implicit full-history rescan",
                    current.display()
                )
            })?,
        None => 0,
    };
    let start_offset = if cursor.segment.as_ref() == Some(&segments[start_index]) {
        cursor.offset
    } else {
        0
    };
    let mut out = Vec::new();

    for index in start_index..segments.len() {
        let path = &segments[index];
        let offset = if index == start_index {
            start_offset
        } else {
            0
        };
        let raw = std::fs::read(path).with_context(|| {
            format!(
                "cluster anti-entropy cannot read segment {}",
                path.display()
            )
        })?;
        crate::wal::segment_header::parse_segment_header(&raw).with_context(|| {
            format!(
                "cluster anti-entropy rejected segment header {}",
                path.display()
            )
        })?;
        let (header_len, logical) = crate::wal::compaction::logical_segment_bytes(&raw)
            .with_context(|| {
                format!(
                    "cluster anti-entropy cannot reconstruct segment {}",
                    path.display()
                )
            })?;
        let body = logical.get(header_len..).with_context(|| {
            format!(
                "cluster anti-entropy segment {} is shorter than its header ({header_len} > {})",
                path.display(),
                logical.len()
            )
        })?;
        let remaining = max.saturating_sub(out.len());
        let (mut frames, next_offset) = collect_gossipable_frames(body, offset, policy, remaining);
        out.append(&mut frames);

        if next_offset < body.len() {
            // A live writer may currently have a torn tail; a sealed segment
            // may be corrupt. In either case retain the exact unread offset.
            cursor.segment = Some(path.clone());
            cursor.offset = next_offset;
            return Ok(out);
        }

        // A completely decoded segment advances monotonically. At the final
        // segment retain its exact EOF as the sentinel: wrapping to segment 0
        // would replay the complete WAL forever after exhaustion.
        cursor.segment = Some(path.clone());
        cursor.offset = body.len();
        if let Some(next) = segments.get(index + 1) {
            cursor.segment = Some(next.clone());
            cursor.offset = 0;
        }
        if out.len() >= max {
            return Ok(out);
        }
    }
    Ok(out)
}

/// Protocol-v6 peeroxide send path. Every
/// [`GOSSIP_TICK_INTERVAL`] it advances through the complete WAL history,
/// band-filters replicable frames, stages one exact durable [`GossipFrame`] per
/// destination, and queues it to paired peers. Read-only consumer of
/// the WAL (NOT a write hook
/// — the per-peer read loop is read-to-completion and can't take an append
/// callback). Returns the task handle so the daemon can abort it on shutdown.
///
/// `self_id` is the transport-authenticated stable node identity (peeroxide
/// Noise public key or iroh EndpointId). The receive path binds the envelope
/// origin back to that authenticated key before accepting it.
pub fn spawn_gossip_tick(
    peer_streams: Arc<PeerStreamRegistry>,
    segment_path: PathBuf,
    writer: Arc<WalWriterHandle>,
    state: SharedGossipState,
    self_id: PeerPubkey,
    reload_controller: Arc<crate::config::reload::ReloadController>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // The seed path's parent is the segment directory. The shared cursor
        // advances through every live and sealed segment, so rollover cannot
        // create an unsynchronised historical gap or wrap into old history.
        let wal_dir = segment_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let db_path = wal_dir
            .parent()
            .map(|home| home.join("views.db"))
            .unwrap_or_else(|| PathBuf::from("views.db"));
        let durable = super::durable_sync::DurableMeshSync::new(db_path);
        let mut ticker = tokio::time::interval(GOSSIP_TICK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            // No peers ⇒ nothing to gossip; don't even read the segment.
            if peer_streams.peer_count() == 0 {
                continue;
            }
            let policy = reload_controller.gossip_policy();
            let mut queued = 0usize;
            for peer_pk in peer_streams.connected_peers() {
                let peer = PeerPubkey::new(peer_pk.clone());
                match durable
                    .prepare_peer_frame(&peer, &self_id, &wal_dir, &policy, &state)
                    .await
                {
                    Ok(Some(prepared)) => {
                        let wf = WireFrame {
                            kind: FrameKind::Gossip,
                            sequence: prepared.frame.event_seq,
                            sent_unix_ms: now_unix_ms(),
                            peer_id: self_id.as_str().to_string(),
                            body: FrameBody::Gossip(Box::new(prepared.frame)),
                        };
                        if peer_streams.send_to(&peer_pk, wf).is_ok() {
                            queued += 1;
                            if let Err(error) = durable.record_send_attempt(&peer) {
                                tracing::warn!(%error, peer = %peer_pk, "mesh send queued but attempt counter could not be recorded");
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, peer = %peer_pk, "durable mesh prepare failed closed");
                    }
                }
            }
            if queued > 0 {
                emit_gossip_sent_wal(&writer, queued, peer_streams.peer_count());
            }
        }
    })
}

fn emit_gossip_sent_wal(writer: &WalWriterHandle, frame_count: usize, peer_count: usize) {
    let payload = serde_json::json!({
        "frame_count": frame_count,
        "peer_count": peer_count,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_CLUSTER_GOSSIP_SENT,
        &payload,
    )
    .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::debug!(error = %e, "gossip tick: 0xED audit append failed");
    }
}

fn now_unix_secs() -> i64 {
    crate::time::now_unix_i64()
}

fn now_unix_ms() -> u64 {
    crate::time::now_unix_ms()
}

// ── Foreign event ingest surface (G-02 CLUSTER-01) ───────────────────────────

/// Maximum skew tolerated between a foreign event's `received_at` timestamp
/// and the local wall clock. Rejects frames with clock-skewed or crafted
/// timestamps without touching the opaque payload bytes.
const FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS: i64 = 300; // 5 minutes

/// Maximum age (in seconds) accepted for a foreign event's `received_at`.
/// Frames older than this are replays, corrupted, or from a stalled peer.
const FOREIGN_EVENT_MAX_AGE_SECS: i64 = 86_400; // 24 hours

/// Persist one accepted gossip frame into `idx_foreign_events`.
///
/// Called from the `GossipAcceptance::Accept` arm in
/// `cluster::hyperswarm::peer_connect_outbound` after
/// `GossipState::accept_inbound` has passed the band-filter ACL and dedup
/// gate. The UNIQUE constraint on `(origin_peer_pk, origin_seq)` makes the
/// INSERT idempotent: a re-gossiped frame silently no-ops (conflict
/// resolution v0 per the module doc).
///
/// Consent / pairing guarantee: `accept_inbound` is only reachable from the
/// authenticated peer session loop in `hyperswarm`, which has already cleared
/// the Noise handshake and (for inbound delegation) the `is_paired` registry
/// check. Foreign events are therefore from known-paired peers by the time
/// this fn is called.
///
/// Foreign events are NEVER mixed into `idx_episode` or `idx_groundtruth`
/// — they are a separate, queryable surface. See `list_foreign_events`.
pub fn ingest_foreign_event(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    origin_seq: u64,
    event_type: u8,
    payload: &[u8],
    received_at: i64,
) -> anyhow::Result<()> {
    // FOREIGN-IDX: reject absurd timestamps before touching the DB.
    // `received_at` is always `now_unix_i64()` at the call site; a peer
    // cannot inject this value, but a clock-skewed or buggy local clock
    // could produce garbage. Guard both directions.
    let now = crate::time::now_unix_i64();
    anyhow::ensure!(
        received_at <= now + FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS,
        "ingest_foreign_event: received_at ({received_at}) is more than \
         {FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS}s in the future (now={now}); \
         peer={origin_peer_pk} seq={origin_seq}"
    );
    anyhow::ensure!(
        received_at >= now - FOREIGN_EVENT_MAX_AGE_SECS,
        "ingest_foreign_event: received_at ({received_at}) is more than \
         {FOREIGN_EVENT_MAX_AGE_SECS}s in the past (now={now}); \
         peer={origin_peer_pk} seq={origin_seq}"
    );

    // Anti-resurrection boundary for operator-forgotten topics. Raw/PII bands
    // are the only gossip payloads that can carry arbitrary text. Validate the
    // canonical frame even when no tombstone exists, then terminally drop a
    // matching frame before it reaches the queryable foreign backup surface.
    // Registry/decode failures propagate (fail closed); returning Ok for a
    // deliberate tombstone drop lets the receiver record its dedup identity
    // instead of retrying the same forbidden bytes forever.
    if classify_event(event_type) == ReplicationClass::RawIngressGated {
        let (inner_event_type, _) = gossip_payload_event_meta(payload)
            .context("ingest_foreign_event: malformed raw gossip WAL frame")?;
        anyhow::ensure!(
            inner_event_type == event_type,
            "ingest_foreign_event: outer/inner event type mismatch (outer=0x{event_type:02X}, inner=0x{inner_event_type:02X})"
        );
        for topic in crate::memory::forget::active_tombstone_topics(conn)? {
            if crate::memory::forget::foreign_frame_contains_topic(payload, event_type, &topic)? {
                tracing::info!(
                    peer = origin_peer_pk,
                    seq = origin_seq,
                    event_type = format_args!("0x{event_type:02X}"),
                    "foreign raw gossip dropped by local forget tombstone"
                );
                return Ok(());
            }
        }
    }
    conn.execute(
        "INSERT OR IGNORE INTO idx_foreign_events \
         (origin_peer_pk, origin_seq, event_type, payload, received_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            origin_peer_pk,
            origin_seq as i64,
            event_type as i64,
            payload,
            received_at,
        ],
    )
    .map(|_| ())
    .with_context(|| format!("ingest_foreign_event: insert {origin_peer_pk}/{origin_seq} failed"))
}

/// DES-13 — one accepted gossip frame queued for durable persistence.
/// Both cluster transports (hyperswarm + iroh) submit these; a single
/// [`spawn_foreign_persist_writer`] task owns the DB connection and drains
/// them. Keeps the blocking DB open OFF the transport hot-path (a sync
/// `open`-per-frame inside a tokio task starves the runtime — panel finding).
#[derive(Debug)]
pub struct ForeignPersistJob {
    pub authenticated_peer: PeerPubkey,
    pub frame: GossipFrame,
    pub policy: GossipPolicy,
    pub reply: tokio::sync::oneshot::Sender<
        std::result::Result<super::durable_sync::InboundCommit, String>,
    >,
}

/// Sender half handed to a transport's accept path. A full/closed channel
/// returns a non-ACK verdict; the origin retains its exact pending frame and
/// retries without advancing its cursor.
pub type ForeignPersistTx = tokio::sync::mpsc::Sender<ForeignPersistJob>;

/// DES-13 — spawn the single foreign-event DB writer. Returns the sender
/// (give to the transport's `gossip_handler`) + the JoinHandle (the daemon
/// keeps it alive and drops the sender on shutdown → the loop ends). The
/// connection is opened lazily inside the blocking task (rusqlite
/// `Connection` is `!Send`). Every job gets its commit result over a oneshot;
/// transports emit an ACK only for a post-commit `Committed`/`Duplicate` result.
pub fn spawn_foreign_persist_writer(
    db_path: std::path::PathBuf,
) -> (ForeignPersistTx, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ForeignPersistJob>(256);
    let handle = tokio::task::spawn_blocking(move || {
        let mut conn = match crate::memory::store::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, db = %db_path.display(),
                    "foreign-persist writer: cannot open views.db — foreign events will NOT be backed up");
                return;
            }
        };
        while let Some(job) = rx.blocking_recv() {
            let result = super::durable_sync::persist_inbound_on_conn(
                &mut conn,
                &job.authenticated_peer,
                &job.frame,
                &job.policy,
            )
            .map_err(|error| error.to_string());
            if result.is_err() {
                tracing::warn!(peer = %job.authenticated_peer.as_str(), seq = job.frame.event_seq,
                    "foreign-persist writer: durable commit failed (ACK withheld)");
            }
            let _ = job.reply.send(result);
        }
        tracing::debug!("foreign-persist writer: sender dropped, loop exited");
    });
    (tx, handle)
}

/// A single row from `idx_foreign_events`.
#[derive(Debug, Clone)]
pub struct ForeignEventRow {
    pub id: i64,
    pub origin_peer_pk: String,
    pub origin_seq: u64,
    pub event_type: u8,
    pub payload: Vec<u8>,
    pub received_at: i64,
    pub envelope_version: u16,
    pub content_sha256: Option<[u8; 32]>,
    pub content_payload: Option<Vec<u8>>,
}

/// Query `idx_foreign_events` with an optional peer filter.
///
/// When `origin_filter` is `Some(pk_hex)` only events from that peer are
/// returned. Results are ordered by `(origin_peer_pk, received_at DESC)`,
/// capped at `limit`.
///
/// CLI wire for the orchestrator — example usage:
/// ```rust,ignore
/// let conn = memory::store::open(&home.join("views.db"))?;
/// let rows = cluster::wal_sync::list_foreign_events(&conn, None, 50)?;
/// for r in rows {
///     println!("{} seq={} et=0x{:02X}", r.origin_peer_pk, r.origin_seq, r.event_type);
/// }
/// ```
pub fn list_foreign_events(
    conn: &rusqlite::Connection,
    origin_filter: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<ForeignEventRow>> {
    let sql = match origin_filter {
        Some(_) => {
            "SELECT id, origin_peer_pk, origin_seq, event_type, payload, received_at, \
                    envelope_version, content_sha256, content_payload \
             FROM idx_foreign_events \
             WHERE origin_peer_pk = ?1 \
             ORDER BY received_at DESC \
             LIMIT ?2"
        }
        None => {
            "SELECT id, origin_peer_pk, origin_seq, event_type, payload, received_at, \
                    envelope_version, content_sha256, content_payload \
             FROM idx_foreign_events \
             ORDER BY received_at DESC \
             LIMIT ?1"
        }
    };

    // rusqlite doesn't support binding Optional cleanly for positional params
    // in a single prepared statement shape, so branch on the two shapes.
    let rows: Vec<ForeignEventRow> = if let Some(pk) = origin_filter {
        let mut stmt = conn
            .prepare(sql)
            .context("list_foreign_events: prepare filtered")?;
        stmt.query_map(rusqlite::params![pk, limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list_foreign_events: query filtered")?
    } else {
        let mut stmt = conn
            .prepare(sql)
            .context("list_foreign_events: prepare unfiltered")?;
        stmt.query_map(rusqlite::params![limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list_foreign_events: query unfiltered")?
    };
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ForeignEventRow> {
    let origin_seq =
        u64::try_from(r.get::<_, i64>(2)?).map_err(|error| foreign_row_conversion(2, error))?;
    let event_type =
        u8::try_from(r.get::<_, i64>(3)?).map_err(|error| foreign_row_conversion(3, error))?;
    let envelope_version =
        u16::try_from(r.get::<_, i64>(6)?).map_err(|error| foreign_row_conversion(6, error))?;
    let content_sha256 = r
        .get::<_, Option<Vec<u8>>>(7)?
        .map(|digest| {
            digest
                .try_into()
                .map_err(|_| foreign_row_conversion(7, "content digest is not 32 bytes"))
        })
        .transpose()?;
    Ok(ForeignEventRow {
        id: r.get(0)?,
        origin_peer_pk: r.get(1)?,
        origin_seq,
        event_type,
        payload: r.get(4)?,
        received_at: r.get(5)?,
        envelope_version,
        content_sha256,
        content_payload: r.get(8)?,
    })
}

fn foreign_row_conversion(
    column: usize,
    error: impl std::fmt::Display + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Integer,
        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()).into(),
    )
}

// ---------------------------------------------------------------------------
// DES-13-AUTO-RESTORE-01 — per-row restore engine
// ---------------------------------------------------------------------------

/// Per-row outcome reported by [`apply_restore_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// A local row was found and updated.
    Applied,
    /// Row was evaluated but not written (see [`RestoreSkipReason`]).
    Skipped(RestoreSkipReason),
}

/// Why a single restore row was skipped without a local write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreSkipReason {
    /// No matching local row (episode or groundtruth) — cannot restore.
    LocalRowMissing,
    /// Local state is already at or above peer state — idempotent.
    Idempotent,
    /// Groundtruth row already has `revoked_at IS NOT NULL`.
    AlreadyRevoked,
    /// Groundtruth row has `fact_state = 'contradicted'` — closed fact, skip.
    Contradicted,
    /// Replicate-class aggregate event (0x94 / 0x13) with no local apply effect.
    NoiseEventType,
    /// DoNotGossip event type — should not appear in a valid same-origin export.
    DoNotGossip,
    /// WAL frame decode failed or outer/inner event_type mismatch.
    MalformedPayload,
    /// Inner JSON payload failed to deserialize.
    MalformedInnerPayload,
}

impl std::fmt::Display for RestoreSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalRowMissing => f.write_str("local row missing"),
            Self::Idempotent => f.write_str("idempotent (already applied or local >= peer)"),
            Self::AlreadyRevoked => f.write_str("already revoked"),
            Self::Contradicted => f.write_str("contradicted (closed fact)"),
            Self::NoiseEventType => f.write_str("noise event type (aggregate, no apply effect)"),
            Self::DoNotGossip => f.write_str("DoNotGossip event type in export"),
            Self::MalformedPayload => f.write_str("malformed WAL frame or event_type mismatch"),
            Self::MalformedInnerPayload => f.write_str("malformed inner JSON payload"),
        }
    }
}

/// Restore one canonical v5 mesh envelope without interpreting a peer-local
/// SQLite id. The durable `(origin, content_id) -> local row` map allocates a
/// local id once and is the only route used for later updates.
pub fn apply_restore_envelope(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    origin_seq: u64,
    envelope: &SyncEnvelope,
    expected_digest: [u8; 32],
    dry_run: bool,
) -> anyhow::Result<RestoreOutcome> {
    use rusqlite::OptionalExtension as _;
    use sha2::{Digest as _, Sha256};

    anyhow::ensure!(
        origin_seq > 0,
        "canonical mesh restore sequence must be positive"
    );
    anyhow::ensure!(
        envelope.version == SYNC_ENVELOPE_VERSION,
        "unsupported canonical mesh envelope version {}",
        envelope.version
    );
    anyhow::ensure!(
        envelope.content_sha256() == expected_digest,
        "canonical mesh restore digest mismatch"
    );

    let (kind, stable_id) = match &envelope.content {
        SyncContent::Memory(snapshot) => {
            anyhow::ensure!(
                snapshot.importance_micros <= 1_000_000,
                "invalid memory importance"
            );
            anyhow::ensure!(
                snapshot.ts_ns >= 0 && snapshot.last_access_ts >= 0,
                "invalid memory timestamp"
            );
            anyhow::ensure!(
                matches!(snapshot.tier.as_str(), "hot" | "warm" | "cold"),
                "invalid memory tier"
            );
            let expected = format!(
                "memory:{}",
                restore_hex_digest(&Sha256::digest(snapshot.text.as_bytes()))
            );
            anyhow::ensure!(
                snapshot.stable_id == expected,
                "canonical memory id mismatch"
            );
            ("memory", snapshot.stable_id.as_str())
        }
        SyncContent::GroundTruth(snapshot) => {
            anyhow::ensure!(
                !snapshot.statement.trim().is_empty()
                    && !snapshot.source.trim().is_empty()
                    && snapshot.source.len() <= 256
                    && !snapshot.scope.trim().is_empty(),
                "invalid ground-truth identity/provenance"
            );
            anyhow::ensure!(
                snapshot.asserted_at >= 0
                    && snapshot.revoked_at.is_none_or(|timestamp| timestamp >= 0),
                "invalid ground-truth timestamp"
            );
            anyhow::ensure!(
                snapshot.confidence_micros <= 1_000_000,
                "invalid ground-truth confidence"
            );
            anyhow::ensure!(
                matches!(
                    snapshot.fact_state.as_str(),
                    "raw" | "candidate" | "verified" | "superseded" | "contradicted" | "deprecated"
                ),
                "invalid ground-truth state"
            );
            anyhow::ensure!(
                matches!(
                    snapshot.maturity.as_str(),
                    "emerging" | "working" | "stable"
                ),
                "invalid ground-truth maturity"
            );
            anyhow::ensure!(
                snapshot.maturity
                    == crate::memory::groundtruth::maturity_for(snapshot.confirmed_count),
                "ground-truth maturity/confirmation count mismatch"
            );
            anyhow::ensure!(
                snapshot.source_weight.len() <= 64
                    && snapshot.source_weight.iter().all(|(source, count)| !source
                        .trim()
                        .is_empty()
                        && source.len() <= 256
                        && *count > 0),
                "invalid ground-truth source provenance"
            );
            let evidence: HashSet<&str> = snapshot
                .evidence_content_ids
                .iter()
                .map(String::as_str)
                .collect();
            anyhow::ensure!(
                snapshot.evidence_content_ids.len()
                    <= crate::memory::groundtruth::MAX_EVIDENCE_BACKLINKS
                    && evidence.len() == snapshot.evidence_content_ids.len()
                    && snapshot
                        .evidence_content_ids
                        .iter()
                        .all(|content_id| restore_is_canonical_memory_id(content_id)),
                "invalid ground-truth evidence provenance"
            );
            let mut identity = snapshot.scope.as_bytes().to_vec();
            identity.push(0);
            identity.extend_from_slice(snapshot.statement.as_bytes());
            let expected = format!(
                "ground_truth:{}",
                restore_hex_digest(&Sha256::digest(identity))
            );
            anyhow::ensure!(
                snapshot.stable_id == expected,
                "canonical ground-truth id mismatch"
            );
            ("ground_truth", snapshot.stable_id.as_str())
        }
        SyncContent::Metadata { .. } => {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::NoiseEventType));
        }
        SyncContent::RawPrivate { .. } => {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::DoNotGossip));
        }
    };
    anyhow::ensure!(
        envelope.content_id == stable_id,
        "canonical mesh content_id does not match stable snapshot id"
    );

    let mapping = conn
        .query_row(
            "SELECT local_kind,local_row_id,last_origin_seq,content_sha256 \
             FROM mesh_sync_restore_map WHERE origin_peer_pk=?1 AND content_id=?2",
            rusqlite::params![origin_peer_pk, envelope.content_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((mapped_kind, local_id, last_seq, last_digest)) = &mapping {
        anyhow::ensure!(
            mapped_kind == kind,
            "canonical restore kind changed for stable id"
        );
        anyhow::ensure!(
            *local_id > 0 && *last_seq > 0,
            "corrupt canonical restore map"
        );
        if u64::try_from(*last_seq)? > origin_seq {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent));
        }
        if u64::try_from(*last_seq)? == origin_seq {
            anyhow::ensure!(
                last_digest.as_slice() == expected_digest.as_slice(),
                "same canonical restore sequence carries a different digest"
            );
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent));
        }
    }
    if dry_run {
        return Ok(RestoreOutcome::Applied);
    }

    const SAVEPOINT: &str = "neoth_canonical_mesh_restore";
    conn.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
    let result = (|| -> anyhow::Result<()> {
        let ground_truth_fields = match &envelope.content {
            SyncContent::GroundTruth(snapshot) => Some(prepare_ground_truth_restore_fields(
                conn,
                origin_peer_pk,
                &envelope.content_id,
                snapshot,
            )?),
            _ => None,
        };
        let local_row_id = match (&envelope.content, &mapping) {
            (SyncContent::Memory(snapshot), existing) => {
                let local_id = match existing {
                    Some((_, local_id, _, _)) => *local_id,
                    None => {
                        let current_max: i64 = conn.query_row(
                            "SELECT COALESCE(MAX(event_id),0) FROM ( \
                                 SELECT event_id FROM idx_episode UNION ALL \
                                 SELECT event_id FROM idx_consolidated WHERE event_id IS NOT NULL UNION ALL \
                                 SELECT event_id FROM idx_longterm \
                             )",
                            [],
                            |row| row.get(0),
                        )?;
                        current_max
                            .checked_add(1)
                            .filter(|next| *next > 0)
                            .context("local memory id space exhausted")?
                    }
                };

                // The stable mapping owns one receiver-local event id. Move it
                // transactionally between tiers instead of flattening every
                // restored snapshot into hot memory.
                conn.execute("DELETE FROM idx_episode WHERE event_id=?1", [local_id])?;
                conn.execute("DELETE FROM idx_consolidated WHERE event_id=?1", [local_id])?;
                conn.execute("DELETE FROM idx_longterm WHERE event_id=?1", [local_id])?;
                let importance = f64::from(snapshot.importance_micros) / 1_000_000.0;
                let access_count = i64::try_from(snapshot.access_count)?;
                match snapshot.tier.as_str() {
                    "hot" => {
                        conn.execute(
                            "INSERT INTO idx_episode \
                             (event_id,event_type,ts_ns,text,text_hash,importance,last_access_ts,access_count,trust) \
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,2)",
                            rusqlite::params![
                                local_id,
                                i64::from(crate::wal::events::EVENT_TYPE_RAW_TEXT),
                                snapshot.ts_ns,
                                snapshot.text,
                                snapshot.text_hash,
                                importance,
                                snapshot.last_access_ts,
                                access_count,
                            ],
                        )?;
                    }
                    "warm" => {
                        use chrono::{DateTime, Utc};
                        let day = DateTime::<Utc>::from_timestamp(
                            snapshot.ts_ns.div_euclid(1_000_000_000),
                            0,
                        )
                        .context("canonical warm-memory timestamp is out of range")?
                        .format("%Y-%m-%d")
                        .to_string();
                        conn.execute(
                            "INSERT INTO idx_consolidated \
                             (kind,day,event_id,text,text_hash,importance,consolidated_ts,last_access_ts,access_count) \
                             VALUES ('retained',?1,?2,?3,?4,?5,?6,?7,?8)",
                            rusqlite::params![
                                day,
                                local_id,
                                snapshot.text,
                                snapshot.text_hash,
                                importance,
                                snapshot.ts_ns,
                                snapshot.last_access_ts,
                                access_count,
                            ],
                        )?;
                    }
                    "cold" => {
                        conn.execute(
                            "INSERT INTO idx_longterm \
                             (event_id,text,text_hash,importance,promoted_ts,last_access_ts,archive_path,access_count) \
                             VALUES (?1,?2,?3,?4,?5,?6,NULL,?7)",
                            rusqlite::params![
                                local_id,
                                snapshot.text,
                                snapshot.text_hash,
                                importance,
                                snapshot.ts_ns,
                                snapshot.last_access_ts,
                                access_count,
                            ],
                        )?;
                    }
                    _ => unreachable!("memory tier validated before restore"),
                }
                local_id
            }
            (SyncContent::GroundTruth(snapshot), Some((_, local_id, _, _))) => {
                let (source, source_weight, evidence) = ground_truth_fields
                    .as_ref()
                    .context("missing canonical ground-truth restore fields")?;
                let changed = conn.execute(
                    "UPDATE idx_groundtruth SET statement=?2,source=?3,scope=?4,asserted_at=?5, \
                     revoked_at=?6,fact_state=?7,source_weight=?8,confidence=?9,evidence=?10, \
                     maturity=?11,confirmed_count=?12 WHERE id=?1",
                    rusqlite::params![
                        local_id,
                        snapshot.statement,
                        source,
                        snapshot.scope,
                        snapshot.asserted_at,
                        snapshot.revoked_at,
                        snapshot.fact_state,
                        source_weight,
                        f64::from(snapshot.confidence_micros) / 1_000_000.0,
                        evidence,
                        snapshot.maturity,
                        i64::from(snapshot.confirmed_count),
                    ],
                )?;
                anyhow::ensure!(changed == 1, "mapped local ground-truth row is missing");
                *local_id
            }
            (SyncContent::GroundTruth(snapshot), None) => {
                let (source, source_weight, evidence) = ground_truth_fields
                    .as_ref()
                    .context("missing canonical ground-truth restore fields")?;
                conn.execute(
                    "INSERT INTO idx_groundtruth \
                     (statement,source,scope,asserted_at,revoked_at,fact_state,source_weight, \
                      confidence,evidence,maturity,confirmed_count) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    rusqlite::params![
                        snapshot.statement,
                        source,
                        snapshot.scope,
                        snapshot.asserted_at,
                        snapshot.revoked_at,
                        snapshot.fact_state,
                        source_weight,
                        f64::from(snapshot.confidence_micros) / 1_000_000.0,
                        evidence,
                        snapshot.maturity,
                        i64::from(snapshot.confirmed_count),
                    ],
                )?;
                conn.last_insert_rowid()
            }
            (SyncContent::Metadata { .. } | SyncContent::RawPrivate { .. }, _) => unreachable!(),
        };
        conn.execute(
            "INSERT INTO mesh_sync_restore_map \
             (origin_peer_pk,content_id,local_kind,local_row_id,last_origin_seq,content_sha256,restored_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7) \
             ON CONFLICT(origin_peer_pk,content_id) DO UPDATE SET \
             local_kind=excluded.local_kind,local_row_id=excluded.local_row_id, \
             last_origin_seq=excluded.last_origin_seq,content_sha256=excluded.content_sha256, \
             restored_at=excluded.restored_at",
            rusqlite::params![
                origin_peer_pk,
                envelope.content_id,
                kind,
                local_row_id,
                i64::try_from(origin_seq)?,
                expected_digest.as_slice(),
                crate::time::now_unix_i64(),
            ],
        )?;
        if matches!(&envelope.content, SyncContent::Memory(_)) {
            resolve_restored_memory_evidence(
                conn,
                origin_peer_pk,
                &envelope.content_id,
                local_row_id,
            )?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch(&format!("RELEASE SAVEPOINT {SAVEPOINT}"))?;
            Ok(RestoreOutcome::Applied)
        }
        Err(error) => {
            let _ = conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT {SAVEPOINT}"));
            let _ = conn.execute_batch(&format!("RELEASE SAVEPOINT {SAVEPOINT}"));
            Err(error)
        }
    }
}

fn prepare_ground_truth_restore_fields(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    ground_truth_content_id: &str,
    snapshot: &GroundTruthSnapshot,
) -> anyhow::Result<(String, String, String)> {
    let source = format!("mesh:{origin_peer_pk}:{}", snapshot.source);
    let source_weight: BTreeMap<String, u32> = snapshot
        .source_weight
        .iter()
        .map(|(source, count)| (format!("mesh:{origin_peer_pk}:{source}"), *count))
        .collect();
    let source_weight = serde_json::to_string(&source_weight)
        .context("serialize canonical ground-truth source provenance")?;

    conn.execute(
        "DELETE FROM mesh_sync_restore_evidence \
         WHERE origin_peer_pk=?1 AND ground_truth_content_id=?2",
        rusqlite::params![origin_peer_pk, ground_truth_content_id],
    )?;
    let mut local_evidence = Vec::with_capacity(snapshot.evidence_content_ids.len());
    for (position, evidence_content_id) in snapshot.evidence_content_ids.iter().enumerate() {
        let mapping = conn
            .query_row(
                "SELECT local_kind,local_row_id FROM mesh_sync_restore_map \
                 WHERE origin_peer_pk=?1 AND content_id=?2",
                rusqlite::params![origin_peer_pk, evidence_content_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let local_row_id = match mapping {
            Some((kind, local_row_id)) => {
                anyhow::ensure!(
                    kind == "memory" && local_row_id > 0,
                    "canonical evidence mapping has the wrong kind or id"
                );
                anyhow::ensure!(
                    local_memory_row_exists(conn, local_row_id)?,
                    "canonical evidence mapping points to a missing memory row"
                );
                local_evidence.push(local_row_id);
                Some(local_row_id)
            }
            None => None,
        };
        conn.execute(
            "INSERT INTO mesh_sync_restore_evidence \
             (origin_peer_pk,ground_truth_content_id,evidence_position,evidence_content_id,local_row_id) \
             VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                origin_peer_pk,
                ground_truth_content_id,
                i64::try_from(position)?,
                evidence_content_id,
                local_row_id,
            ],
        )?;
    }
    let evidence = serde_json::to_string(&local_evidence)
        .context("serialize receiver-local ground-truth evidence")?;
    Ok((source, source_weight, evidence))
}

fn resolve_restored_memory_evidence(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    evidence_content_id: &str,
    local_row_id: i64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        local_memory_row_exists(conn, local_row_id)?,
        "restored evidence mapping points to a missing memory row"
    );
    let mut statement = conn.prepare(
        "SELECT DISTINCT ground_truth_content_id FROM mesh_sync_restore_evidence \
         WHERE origin_peer_pk=?1 AND evidence_content_id=?2 \
         ORDER BY ground_truth_content_id",
    )?;
    let ground_truth_ids = statement
        .query_map(
            rusqlite::params![origin_peer_pk, evidence_content_id],
            |row| row.get::<_, String>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    if ground_truth_ids.is_empty() {
        return Ok(());
    }
    conn.execute(
        "UPDATE mesh_sync_restore_evidence SET local_row_id=?3 \
         WHERE origin_peer_pk=?1 AND evidence_content_id=?2",
        rusqlite::params![origin_peer_pk, evidence_content_id, local_row_id],
    )?;
    for ground_truth_content_id in ground_truth_ids {
        refresh_restored_ground_truth_evidence(conn, origin_peer_pk, &ground_truth_content_id)?;
    }
    Ok(())
}

fn refresh_restored_ground_truth_evidence(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    ground_truth_content_id: &str,
) -> anyhow::Result<()> {
    let (kind, local_ground_truth_id) = conn
        .query_row(
            "SELECT local_kind,local_row_id FROM mesh_sync_restore_map \
             WHERE origin_peer_pk=?1 AND content_id=?2",
            rusqlite::params![origin_peer_pk, ground_truth_content_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .context("canonical evidence references an unrestored ground-truth row")?;
    anyhow::ensure!(
        kind == "ground_truth" && local_ground_truth_id > 0,
        "canonical evidence target mapping has the wrong kind or id"
    );
    let mut statement = conn.prepare(
        "SELECT local_row_id FROM mesh_sync_restore_evidence \
         WHERE origin_peer_pk=?1 AND ground_truth_content_id=?2 AND local_row_id IS NOT NULL \
         ORDER BY evidence_position",
    )?;
    let evidence = statement
        .query_map(
            rusqlite::params![origin_peer_pk, ground_truth_content_id],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    let evidence = serde_json::to_string(&evidence)
        .context("serialize resolved receiver-local ground-truth evidence")?;
    let changed = conn.execute(
        "UPDATE idx_groundtruth SET evidence=?2 WHERE id=?1",
        rusqlite::params![local_ground_truth_id, evidence],
    )?;
    anyhow::ensure!(
        changed == 1,
        "canonical evidence target ground-truth row is missing"
    );
    Ok(())
}

fn local_memory_row_exists(conn: &rusqlite::Connection, local_row_id: i64) -> anyhow::Result<bool> {
    conn.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM idx_episode WHERE event_id=?1 UNION ALL \
             SELECT 1 FROM idx_consolidated WHERE event_id=?1 UNION ALL \
             SELECT 1 FROM idx_longterm WHERE event_id=?1 \
         )",
        [local_row_id],
        |row| row.get(0),
    )
    .context("validate receiver-local memory evidence row")
}

fn restore_hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn restore_is_canonical_memory_id(content_id: &str) -> bool {
    content_id.strip_prefix("memory:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Apply a single restored foreign frame to local recall surfaces.
///
/// # Parameters
/// - `origin_peer_pk` / `origin_seq` — durable event identity used to make
///   multiplicative 0x92 decay exactly-once across restore invocations.
/// - `event_type` — the parsed `event_type` byte from the export JSONL line.
/// - `payload_bytes` — the full WAL frame bytes (base64-decoded from `payload_b64`).
/// - `received_at` — the `received_at` timestamp from the export line (used for
///   groundtruth revocation timestamp).
/// - `dry_run` — when `true`, full conflict evaluation runs but no SQL writes are
///   performed and no audit events are written.
///
/// # Conflict matrix (DES-13-AUTO-RESTORE-01 §3)
///
/// | event_type | effect | skip conditions |
/// |---|---|---|
/// | 0x90 / 0x91 | `MAX(importance, peer)` on local episode | Missing / Idempotent |
/// | 0x92 | `* 0.5, floor DECAY_FLOOR` on local episode | Missing / Idempotent marker |
/// | 0x98 | SET `revoked_at` on local groundtruth | Missing / AlreadyRevoked / Contradicted |
/// | 0x94 / 0x13 | no local effect (aggregate / capability) | NoiseEventType |
/// | 0x97 / 0x93 / 0x12 / other DoNotGossip | reject | DoNotGossip |
///
/// # Savepoints
/// The caller may wrap each call in a per-row savepoint so one error does not
/// roll back the restore session. The 0x92 branch additionally nests its own
/// savepoint so the decay and durable idempotency marker commit atomically.
pub fn apply_restore_frame(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    origin_seq: u64,
    event_type: u8,
    payload_bytes: &[u8],
    received_at: i64,
    dry_run: bool,
) -> anyhow::Result<RestoreOutcome> {
    if event_type != crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED {
        return apply_restore_frame_inner(conn, event_type, payload_bytes, received_at, dry_run);
    }

    // 0x92 is multiplicative, so local-value comparison cannot make retries
    // idempotent. Bind it to the durable gossip identity instead. Dry-runs
    // only read an existing marker table and never create schema.
    if dry_run {
        if restore_decay_was_applied(conn, origin_peer_pk, origin_seq)? {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent));
        }
        return apply_restore_frame_inner(conn, event_type, payload_bytes, received_at, true);
    }

    // Keep the decay and its marker in one transaction, including for callers
    // that do not provide their own per-row savepoint.
    const SAVEPOINT: &str = "neoth_restore_decay_marker";
    conn.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))
        .context("restore decay: open marker savepoint")?;
    let result = (|| {
        ensure_restore_decay_markers(conn)?;
        if restore_decay_was_applied(conn, origin_peer_pk, origin_seq)? {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent));
        }
        let outcome =
            apply_restore_frame_inner(conn, event_type, payload_bytes, received_at, false)?;
        if outcome == RestoreOutcome::Applied {
            mark_restore_decay_applied(conn, origin_peer_pk, origin_seq)?;
        }
        Ok(outcome)
    })();
    match result {
        Ok(outcome) => {
            conn.execute_batch(&format!("RELEASE SAVEPOINT {SAVEPOINT}"))
                .context("restore decay: commit marker savepoint")?;
            Ok(outcome)
        }
        Err(error) => {
            let _ = conn.execute_batch(&format!(
                "ROLLBACK TO SAVEPOINT {SAVEPOINT}; RELEASE SAVEPOINT {SAVEPOINT}"
            ));
            Err(error)
        }
    }
}

const RESTORE_DECAY_MARKERS_TABLE: &str = "cluster_restore_decay_applied";

fn ensure_restore_decay_markers(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"CREATE TABLE IF NOT EXISTS cluster_restore_decay_applied (
               origin_peer_pk TEXT NOT NULL,
               origin_seq INTEGER NOT NULL,
               applied_at INTEGER NOT NULL,
               PRIMARY KEY (origin_peer_pk, origin_seq)
           ) WITHOUT ROWID"#,
    )
    .context("restore decay: ensure idempotency markers")
}

fn restore_decay_was_applied(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    origin_seq: u64,
) -> anyhow::Result<bool> {
    let table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [RESTORE_DECAY_MARKERS_TABLE],
            |row| row.get(0),
        )
        .context("restore decay: inspect marker schema")?;
    if !table_exists {
        return Ok(false);
    }
    let origin_seq = i64::try_from(origin_seq).context("restore decay: origin_seq exceeds i64")?;
    conn.query_row(
        r#"SELECT EXISTS(
               SELECT 1 FROM cluster_restore_decay_applied
               WHERE origin_peer_pk = ?1 AND origin_seq = ?2
           )"#,
        rusqlite::params![origin_peer_pk, origin_seq],
        |row| row.get(0),
    )
    .context("restore decay: read idempotency marker")
}

fn mark_restore_decay_applied(
    conn: &rusqlite::Connection,
    origin_peer_pk: &str,
    origin_seq: u64,
) -> anyhow::Result<()> {
    let origin_seq = i64::try_from(origin_seq).context("restore decay: origin_seq exceeds i64")?;
    conn.execute(
        r#"INSERT INTO cluster_restore_decay_applied
           (origin_peer_pk, origin_seq, applied_at) VALUES (?1, ?2, ?3)"#,
        rusqlite::params![origin_peer_pk, origin_seq, crate::time::now_unix_i64()],
    )
    .context("restore decay: persist idempotency marker")?;
    Ok(())
}

fn apply_restore_frame_inner(
    conn: &rusqlite::Connection,
    event_type: u8,
    payload_bytes: &[u8],
    received_at: i64,
    dry_run: bool,
) -> anyhow::Result<RestoreOutcome> {
    use crate::cluster::foreign_indexer::{
        BoostOutcome, EpisodeArchivedPayload, EpisodeConsolidatedPayload, EpisodePromotedPayload,
        GroundtruthRevokeOutcome, GroundtruthRevokedPayload, apply_episode_boost,
        apply_episode_decay_sql, apply_groundtruth_revoke,
    };
    use crate::wal::events::{
        EVENT_TYPE_CONSOLIDATION_PASS, EVENT_TYPE_EPISODE_ARCHIVED,
        EVENT_TYPE_EPISODE_CONSOLIDATED, EVENT_TYPE_EPISODE_PROMOTED,
        EVENT_TYPE_GROUNDTRUTH_REVOKED, EVENT_TYPE_UPDATE_RAN,
    };

    // Noise / DoNotGossip guard: no need to decode the frame for these.
    match classify_event(event_type) {
        ReplicationClass::DoNotGossip => {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::DoNotGossip));
        }
        ReplicationClass::Replicate
            if event_type == EVENT_TYPE_CONSOLIDATION_PASS
                || event_type == EVENT_TYPE_UPDATE_RAN =>
        {
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::NoiseEventType));
        }
        _ => {}
    }

    // Decode the WAL frame; outer event_type must match inner header.
    let decoded = match crate::wal::frame::decode_frame(payload_bytes) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                event_type = event_type,
                error = %e,
                "restore: WAL frame decode failed"
            );
            return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedPayload));
        }
    };
    if decoded.header.event_type != event_type {
        tracing::warn!(
            outer = event_type,
            inner = decoded.header.event_type,
            "restore: event_type mismatch between export line and WAL frame header"
        );
        return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedPayload));
    }
    let inner = decoded.payload;

    match event_type {
        EVENT_TYPE_EPISODE_CONSOLIDATED => {
            let p: EpisodeConsolidatedPayload = match serde_json::from_slice(inner) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "restore: malformed 0x90 payload");
                    return Ok(RestoreOutcome::Skipped(
                        RestoreSkipReason::MalformedInnerPayload,
                    ));
                }
            };
            match apply_episode_boost(conn, p.event_id, p.importance, dry_run)? {
                BoostOutcome::Applied => Ok(RestoreOutcome::Applied),
                BoostOutcome::Idempotent => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent))
                }
                BoostOutcome::Missing => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing))
                }
            }
        }
        EVENT_TYPE_EPISODE_PROMOTED => {
            let p: EpisodePromotedPayload = match serde_json::from_slice(inner) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "restore: malformed 0x91 payload");
                    return Ok(RestoreOutcome::Skipped(
                        RestoreSkipReason::MalformedInnerPayload,
                    ));
                }
            };
            match apply_episode_boost(conn, p.event_id, p.to_importance, dry_run)? {
                BoostOutcome::Applied => Ok(RestoreOutcome::Applied),
                BoostOutcome::Idempotent => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::Idempotent))
                }
                BoostOutcome::Missing => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing))
                }
            }
        }
        EVENT_TYPE_EPISODE_ARCHIVED => {
            let p: EpisodeArchivedPayload = match serde_json::from_slice(inner) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "restore: malformed 0x92 payload");
                    return Ok(RestoreOutcome::Skipped(
                        RestoreSkipReason::MalformedInnerPayload,
                    ));
                }
            };
            if dry_run {
                let exists: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM idx_episode WHERE event_id = ?1",
                        [p.event_id],
                        |r| r.get(0),
                    )
                    .context("restore dry-run: check episode existence")?;
                return Ok(if exists == 0 {
                    RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing)
                } else {
                    RestoreOutcome::Applied
                });
            }
            let found = apply_episode_decay_sql(conn, p.event_id)?;
            Ok(if found {
                RestoreOutcome::Applied
            } else {
                RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing)
            })
        }
        EVENT_TYPE_GROUNDTRUTH_REVOKED => {
            let p: GroundtruthRevokedPayload = match serde_json::from_slice(inner) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "restore: malformed 0x98 payload");
                    return Ok(RestoreOutcome::Skipped(
                        RestoreSkipReason::MalformedInnerPayload,
                    ));
                }
            };
            if dry_run {
                // Still run the full conflict check — just skip the write.
                let row = conn.query_row(
                    "SELECT revoked_at, fact_state FROM idx_groundtruth WHERE id = ?1",
                    [p.id],
                    |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)),
                );
                return Ok(match row {
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("restore dry-run 0x98: {e}"));
                    }
                    Ok((Some(_), _)) => RestoreOutcome::Skipped(RestoreSkipReason::AlreadyRevoked),
                    Ok((None, fs)) if fs == "contradicted" => {
                        RestoreOutcome::Skipped(RestoreSkipReason::Contradicted)
                    }
                    Ok((None, _)) => RestoreOutcome::Applied,
                });
            }
            match apply_groundtruth_revoke(conn, p.id, received_at)? {
                GroundtruthRevokeOutcome::Applied => Ok(RestoreOutcome::Applied),
                GroundtruthRevokeOutcome::Missing => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing))
                }
                GroundtruthRevokeOutcome::AlreadyRevoked => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::AlreadyRevoked))
                }
                GroundtruthRevokeOutcome::Contradicted => {
                    Ok(RestoreOutcome::Skipped(RestoreSkipReason::Contradicted))
                }
            }
        }
        _ => {
            // RawIngressGated land here — shouldn't appear in a same-origin
            // export, but treat gracefully.
            Ok(RestoreOutcome::Skipped(RestoreSkipReason::DoNotGossip))
        }
    }
}

/// Derive the stable local node pubkey from the cluster passphrase stored in
/// `home/credentials.yaml`. Returns `Ok(None)` when no cluster identity is
/// configured (no passphrase or no cluster name in freedom.yaml). Existing
/// invalid policy/credential stores are surfaced.
///
/// The pubkey is the 64-character lowercase hex encoding of the 32-byte
/// `ClusterKey` (HMAC of the passphrase). This is the same value stored in
/// `origin_peer_pk` when this node exports its own foreign events.
pub fn local_node_pubkey(home: &std::path::Path) -> anyhow::Result<Option<String>> {
    let (config, credentials) =
        crate::config::load_optional_runtime_config_pair_from_path(&home.join("freedom.yaml"))?;
    let Some(identity) = crate::cluster::identity::resolve_cluster_identity(
        &config.unwrap_or_default(),
        &credentials,
    ) else {
        return Ok(None);
    };
    let hex = identity
        .key
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(Some(hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── The security core: the band-filter ACL truth table ──────────────────

    #[test]
    fn dangerous_bands_never_gossip_by_default() {
        let p = GossipPolicy::default();
        // Permissions / autonomy / lease (0xA0..=0xAF) — local security state.
        for et in 0xA0u8..=0xAF {
            assert!(
                !is_replicable(et, &p),
                "permission band 0x{et:02X} must not gossip"
            );
        }
        // Profile band (0xB0..=0xBF) — operator PII.
        for et in 0xB0u8..=0xBF {
            assert!(
                !is_replicable(et, &p),
                "profile band 0x{et:02X} must not gossip"
            );
        }
        // Consent + WAL-structure + operator/system band.
        for et in [0x65u8, 0xF0, 0xF1, 0xF2, 0xF3, 0xFF] {
            assert!(!is_replicable(et, &p), "0x{et:02X} must not gossip");
        }
        // Daemon lifecycle BOOT/SHUTDOWN/rollover/compaction.
        for et in [0x10u8, 0x11, 0x14, 0x15] {
            assert!(
                !is_replicable(et, &p),
                "lifecycle 0x{et:02X} must not gossip"
            );
        }
        // The ENTIRE cluster band is DoNotGossip: 0xE6 PEER_CONFIRMED leaks
        // addr + autonomy_level, 0xE0/0xE9 leak peer pubkeys (topology), and
        // 0xEA..=0xEF are local/audit (anti-amplification). (SL-01b review HIGH.)
        for et in 0xE0u8..=0xEF {
            assert_eq!(
                classify_event(et),
                ReplicationClass::DoNotGossip,
                "cluster band 0x{et:02X} must not gossip (topology/config/audit)"
            );
        }
        // Specific leak-carriers verified out of the Replicate set.
        for et in [0x12u8, 0x93, 0x97] {
            assert_eq!(
                classify_event(et),
                ReplicationClass::DoNotGossip,
                "0x{et:02X} carries login_state/query_hash/source — must not gossip"
            );
        }
        // Cron band carries error context (0x42) — defer the whole band.
        for et in 0x40u8..=0x46 {
            assert_eq!(classify_event(et), ReplicationClass::DoNotGossip);
        }
    }

    #[test]
    fn raw_ingress_is_gated_off_by_default_on_by_opt_in() {
        let mut p = GossipPolicy::default();
        for et in [0x01u8, 0x20, 0x21, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38] {
            assert_eq!(classify_event(et), ReplicationClass::RawIngressGated);
            assert!(!is_replicable(et, &p), "PII 0x{et:02X} default-off");
        }
        p.replicate_raw_ingress = true;
        for et in [0x01u8, 0x20, 0x32] {
            assert!(is_replicable(et, &p), "PII 0x{et:02X} on after opt-in");
        }
    }

    #[test]
    fn safe_bands_replicate() {
        let p = GossipPolicy::default();
        // The narrow, payload-verified Replicate set (pure ids/scores/counts/version).
        for et in [0x90u8, 0x91, 0x92, 0x94, 0x98, 0x13] {
            assert!(is_replicable(et, &p), "safe 0x{et:02X} should replicate");
        }
    }

    /// Build the same canonical frame bytes that the WAL writer places in an
    /// active segment body.
    fn fake_frame(event_type: u8) -> Vec<u8> {
        let payload = format!("event-{event_type:02x}").into_bytes();
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        crate::wal::frame::encode_frame(&header, &payload)
    }

    #[test]
    fn collect_gossipable_filters_by_band_and_advances_cursor() {
        let p = GossipPolicy::default();
        let mut body = Vec::new();
        body.extend_from_slice(&fake_frame(0x90)); // replicable (memory-tier transition)
        body.extend_from_slice(&fake_frame(0xA0)); // NOT (permission)
        body.extend_from_slice(&fake_frame(0x91)); // replicable (episode promoted)
        let (frames, new_off) = collect_gossipable_frames(&body, 0, &p, 16);
        assert_eq!(frames.len(), 2, "only the 2 replicable frames collected");
        assert_eq!(frames[0].0, 0x90);
        assert_eq!(frames[1].0, 0x91);
        assert_eq!(
            new_off,
            body.len(),
            "cursor advanced past ALL frames walked"
        );
    }

    #[test]
    fn collect_gossipable_respects_max_and_torn_tail() {
        let p = GossipPolicy::default();
        let mut body = Vec::new();
        body.extend_from_slice(&fake_frame(0x90));
        body.extend_from_slice(&fake_frame(0x91));
        let complete_len = body.len();
        // Append a torn (short) header tail.
        body.extend_from_slice(&[0u8; 10]);
        let (frames, _off) = collect_gossipable_frames(&body, 0, &p, 1);
        assert_eq!(frames.len(), 1, "max=1 caps collection");
        // From a from_offset past the two full frames, the torn tail stops cleanly.
        let (rest, _) = collect_gossipable_frames(&body, complete_len, &p, 16);
        assert!(rest.is_empty(), "torn tail yields nothing, no panic");
    }

    #[tokio::test]
    async fn anti_entropy_exhaustion_never_wraps_and_sees_new_segments() {
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeader, SegmentHeaderV2};

        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("000001.wal");
        let second = dir.path().join("000002.wal");

        let mut live = SegmentHeader::new(1, 1, 1, 1, [1; 16])
            .to_le_bytes()
            .to_vec();
        live.extend_from_slice(&fake_frame(0x90));
        std::fs::write(&first, live).unwrap();

        let sealed_frame = fake_frame(0x91);
        let mut sealed = SegmentHeaderV2::new(1, 2, 2, 2, [1; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        sealed.extend_from_slice(&compress_frames(&sealed_frame).unwrap());
        std::fs::write(&second, sealed).unwrap();

        let policy = GossipPolicy::default();
        let mut cursor = GossipWalCursor::default();
        let first_batch = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1)
            .await
            .unwrap();
        let second_batch = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1)
            .await
            .unwrap();
        let retry_batch = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1)
            .await
            .unwrap();

        assert_eq!(first_batch[0].0, 0x90);
        assert_eq!(second_batch[0].0, 0x91);
        assert!(
            retry_batch.is_empty(),
            "an exhausted cursor must not wrap into already acknowledged history"
        );
        let exhausted = cursor.clone();
        let still_empty = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1)
            .await
            .unwrap();
        assert!(still_empty.is_empty());
        assert_eq!(
            cursor, exhausted,
            "idle retries keep the exact EOF sentinel"
        );

        let third = dir.path().join("000003.wal");
        let mut appended = SegmentHeader::new(1, 3, 3, 3, [1; 16])
            .to_le_bytes()
            .to_vec();
        appended.extend_from_slice(&fake_frame(0x92));
        std::fs::write(third, appended).unwrap();
        let appended_batch = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1)
            .await
            .unwrap();
        assert_eq!(appended_batch[0].0, 0x92);
    }

    #[tokio::test]
    async fn anti_entropy_missing_cursor_segment_fails_closed_without_rescan() {
        use crate::wal::segment_header::SegmentHeader;

        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("000002.wal");
        let mut body = SegmentHeader::new(1, 2, 2, 2, [1; 16])
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&fake_frame(0x90));
        std::fs::write(existing, body).unwrap();
        let mut cursor = GossipWalCursor {
            segment: Some(dir.path().join("000001.wal")),
            offset: 77,
        };
        let before = cursor.clone();

        let error = read_gossipable_batch(dir.path(), &mut cursor, &GossipPolicy::default(), 8)
            .await
            .expect_err("a missing durable cursor target must not reset to segment zero");
        assert!(
            error
                .to_string()
                .contains("refusing an implicit full-history rescan")
        );
        assert_eq!(cursor, before);
    }

    #[tokio::test]
    async fn anti_entropy_corruption_fails_closed_without_cursor_advance() {
        use crate::wal::segment_header::SegmentHeader;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.wal");
        std::fs::write(&path, b"not-a-segment").unwrap();
        let policy = GossipPolicy::default();
        let mut cursor = GossipWalCursor::default();
        let before = cursor.clone();

        let result = read_gossipable_batch(dir.path(), &mut cursor, &policy, 1).await;
        assert!(result.is_err());
        assert_eq!(cursor, before, "invalid segment must not move the cursor");

        let frame = fake_frame(0x90);
        let mut torn = SegmentHeader::new(1, 1, 1, 1, [1; 16])
            .to_le_bytes()
            .to_vec();
        torn.extend_from_slice(&frame);
        torn.extend_from_slice(&[0_u8; 10]);
        std::fs::write(&path, torn).unwrap();

        let first = read_gossipable_batch(dir.path(), &mut cursor, &policy, 2)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        let stopped = cursor.clone();
        let second = read_gossipable_batch(dir.path(), &mut cursor, &policy, 2)
            .await
            .unwrap();
        assert!(second.is_empty());
        assert_eq!(
            cursor, stopped,
            "torn tail must retain its exact unread offset"
        );
    }

    #[test]
    fn canonical_gossip_metadata_rejects_crc_or_trailing_bytes() {
        let frame = fake_frame(0x90);
        assert_eq!(gossip_payload_event_meta(&frame), Some((0x90, 0)));

        let mut corrupt = frame.clone();
        corrupt[100] ^= 0x01;
        assert_eq!(gossip_payload_event_meta(&corrupt), None);

        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(gossip_payload_event_meta(&trailing), None);
    }

    #[test]
    fn unknown_codes_default_deny() {
        let p = GossipPolicy::default();
        for et in [0x7Fu8, 0x50, 0x99, 0xC0, 0xD0] {
            assert_eq!(classify_event(et), ReplicationClass::DoNotGossip);
            assert!(!is_replicable(et, &p));
        }
    }

    // ── send / receive state ────────────────────────────────────────────────

    fn self_pk() -> PeerPubkey {
        PeerPubkey::new("aa11")
    }

    fn test_gossip_frame(
        vector_clock: VectorClock,
        origin: PeerPubkey,
        event_seq: u64,
        timestamp_unix: i64,
        payload: Vec<u8>,
    ) -> GossipFrame {
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: format!("test:{event_seq}"),
            updated_at_unix: timestamp_unix,
            content: SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload.clone(),
            },
        };
        GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock,
            origin,
            event_seq,
            content_sha256: envelope.content_sha256(),
            timestamp_unix,
            tag: GossipTag::Replicate,
            payload,
            envelope,
        }
    }

    #[test]
    fn build_outbound_drops_non_replicable_returns_some_for_safe() {
        let p = GossipPolicy::default();
        let mut st = GossipState::new();
        // A permission event is never wrapped.
        assert!(
            st.build_outbound(&self_pk(), 0xA0, 0, vec![1, 2, 3], 1000, &p)
                .is_none()
        );
        // A cluster-topology event (0xE6 leaks addr/autonomy) is NOT wrapped.
        assert!(
            st.build_outbound(&self_pk(), 0xE6, 0, vec![9], 1000, &p)
                .is_none()
        );
        // A verified-clean memory-tier transition is wrapped + VC advances.
        let f = st
            .build_outbound(&self_pk(), 0x90, 0, vec![9], 1000, &p)
            .expect("safe event wraps");
        assert_eq!(f.origin, self_pk());
        assert_ne!(f.event_seq, 0);
        assert_eq!(f.tag, GossipTag::Replicate);
        assert!(f.vector_clock.get(&self_pk()) >= 1);
        let retry = st
            .build_outbound(&self_pk(), 0x90, 0, vec![9], 1000, &p)
            .expect("same frame remains replicable");
        assert!(
            retry.event_seq > f.event_seq,
            "ephemeral builder stays monotonic"
        );
    }

    #[test]
    fn classify_event_ext_distinguishes_swarm_snapshot_from_local_snapshot() {
        let p = GossipPolicy::default();
        // 0x00/0x03 = SwarmResourceSnapshot → Replicate (the gossip-wire subtype).
        assert_eq!(
            classify_event_ext(0x00, SWARM_SNAPSHOT_SUBTYPE),
            ReplicationClass::Replicate,
            "SwarmResourceSnapshot (0x00/0x03) must be Replicate"
        );
        assert!(
            is_replicable_ext(0x00, SWARM_SNAPSHOT_SUBTYPE, &p),
            "SwarmResourceSnapshot must pass the ACL gate"
        );
        // 0x00/0x04 = LocalSnapshot → DoNotGossip (written locally, never replicated).
        assert_eq!(
            classify_event_ext(0x00, 0x04),
            ReplicationClass::DoNotGossip,
            "LocalSnapshot (0x00/0x04) must NOT replicate"
        );
        assert!(
            !is_replicable_ext(0x00, 0x04, &p),
            "LocalSnapshot must be rejected by the ACL gate"
        );
        // All other 0x00/* subtypes are DoNotGossip by default-deny.
        for sub in [0x00u8, 0x01, 0x02, 0x05, 0xFF] {
            assert_eq!(
                classify_event_ext(0x00, sub),
                ReplicationClass::DoNotGossip,
                "unknown EXTENDED subtype 0x{sub:02X} must DoNotGossip"
            );
        }
        // Non-EXTENDED types delegate to classify_event — no regression.
        assert!(
            is_replicable_ext(0x90, 0, &p),
            "0x90 still replicates via classify_event"
        );
        assert!(
            !is_replicable_ext(0xA0, 0, &p),
            "0xA0 still DoNotGossip via classify_event"
        );
    }

    #[test]
    fn accept_inbound_dedups_and_band_rechecks() {
        let p = GossipPolicy::default();
        let mut st = GossipState::new();
        let peer = PeerPubkey::new("bb22");
        let mut sender_vc = VectorClock::new();
        sender_vc.tick(&peer);
        let frame = test_gossip_frame(sender_vc, peer.clone(), 5, 2_000_000_000, vec![0]);
        let now = 2_000_000_001;
        // First arrival of a replicable-band event ⇒ Accept. CHECK-ONLY:
        // nothing is recorded until the caller confirms persistence
        // (G02-CLUSTER-02 persist-then-dedup).
        assert_eq!(
            st.accept_inbound(&frame, Some(0x90), None, &p, now),
            GossipAcceptance::Accept
        );
        assert_eq!(
            st.last_seen_seq(&peer),
            None,
            "accept_inbound must NOT record the identity before commit"
        );
        // Re-delivery BEFORE commit is still Accept (DB INSERT OR IGNORE
        // absorbs the double-persist) — the crash-window contract.
        assert_eq!(
            st.accept_inbound(&frame, Some(0x90), None, &p, now),
            GossipAcceptance::Accept
        );
        // After confirmed persistence the caller commits: dedup identity + VC.
        st.commit_inbound(&frame);
        assert_eq!(st.last_seen_seq(&peer), Some(5));
        assert!(st.vc.get(&peer) >= 1, "receiver VC converged on sender");
        // Re-delivery (<= last seq) after commit ⇒ duplicate drop.
        assert!(matches!(
            st.accept_inbound(&frame, Some(0x90), None, &p, now),
            GossipAcceptance::DroppedDuplicate { .. }
        ));
        let mut unseen_lower_identity = frame.clone();
        unseen_lower_identity.event_seq = 4;
        assert_eq!(
            st.accept_inbound(&unseen_lower_identity, Some(0x90), None, &p, now),
            GossipAcceptance::Accept,
            "unordered stable identities must use set membership, not a numeric high-water"
        );
        // Defence-in-depth: a frame whose payload is actually a DoNotGossip
        // band (mis-tagged) is dropped even though the GossipTag says Replicate.
        let mut vc2 = VectorClock::new();
        vc2.tick(&peer);
        let smuggle = test_gossip_frame(vc2, peer.clone(), 6, 2_000_000_000, vec![0]);
        assert_eq!(
            st.accept_inbound(&smuggle, Some(0xA0), None, &p, now),
            GossipAcceptance::DroppedDoNotGossipTag,
            "a payload in the permissions band must be dropped on receive"
        );
        // A SwarmResourceSnapshot (0x00/0x03) must be accepted — the key
        // correctness assertion for GOLD-FEAT-06 gossip-piggyback.
        let mut vc3 = VectorClock::new();
        vc3.tick(&peer);
        let snap_frame = test_gossip_frame(vc3, peer.clone(), 7, 2_000_000_000, vec![0]);
        assert_eq!(
            st.accept_inbound(
                &snap_frame,
                Some(0x00),
                Some(SWARM_SNAPSHOT_SUBTYPE),
                &p,
                now
            ),
            GossipAcceptance::Accept,
            "SwarmResourceSnapshot (0x00/0x03) must be accepted by the receive ACL"
        );
        // LocalSnapshot (0x00/0x04) must be dropped even from a trusted peer.
        let mut vc4 = VectorClock::new();
        vc4.tick(&peer);
        let local_snap_frame = test_gossip_frame(vc4, peer.clone(), 8, 2_000_000_000, vec![0]);
        assert_eq!(
            st.accept_inbound(&local_snap_frame, Some(0x00), Some(0x04), &p, now),
            GossipAcceptance::DroppedDoNotGossipTag,
            "LocalSnapshot (0x00/0x04) must be rejected — it is local-only"
        );
    }

    #[test]
    fn accepted_gossip_frame_advances_local_clock_past_peer_causal_frontier() {
        // GOLD-WIRE-09: on Accept the receive path merges the WHOLE inbound
        // frame's vector clock (the peer's causal frontier), not just the
        // origin entry — so the local clock converges onto everything the peer
        // had observed and, having its own prior events, causally dominates it.
        use crate::cluster::gossip_wire::VcOrdering;
        let policy = GossipPolicy::default();
        let mut st = GossipState::new();
        // Local progresses on its own first (under a DISTINCT id, not any
        // frontier peer), so a correct merge leaves the local clock strictly
        // AFTER (not merely Equal to) the peer frontier.
        let local = PeerPubkey::new("local99");
        st.vc.tick(&local);
        st.vc.tick(&local);

        // A frame from peer-a carrying a multi-node frontier {a:3, b:2, c:1}.
        let pa = PeerPubkey::new("aa11");
        let pb = PeerPubkey::new("bb22");
        let pc = PeerPubkey::new("cc33");
        let mut frontier = VectorClock::new();
        for _ in 0..3 {
            frontier.tick(&pa);
        }
        for _ in 0..2 {
            frontier.tick(&pb);
        }
        frontier.tick(&pc);
        let frame = test_gossip_frame(frontier.clone(), pa.clone(), 7, 2_000_000_000, vec![0]);
        let now = 2_000_000_001;
        assert_eq!(
            st.accept_inbound(&frame, Some(0x90), None, &policy, now),
            GossipAcceptance::Accept
        );
        // VC merge happens at commit (post-persist), not at accept.
        st.commit_inbound(&frame);
        // Every entry of the peer's frontier is now covered by the local clock.
        assert!(st.vc.get(&pa) >= 3);
        assert!(st.vc.get(&pb) >= 2);
        assert!(st.vc.get(&pc) >= 1);
        // And because the local node also had its own events, the local clock
        // now causally dominates (advances PAST) the peer's frontier.
        assert_eq!(
            st.vc.compare(&frontier),
            VcOrdering::After,
            "after accept the local clock must advance past the peer's causal frontier"
        );
    }

    #[test]
    fn authenticated_commit_never_evicts_a_full_live_frontier() {
        let mut state = GossipState::new();
        let retained_local = PeerPubkey::new("zz-local");
        state.vc.clocks.insert(retained_local.clone(), 77);
        for index in 0..(crate::cluster::gossip_wire::MAX_VECTOR_CLOCK_PEERS - 1) {
            state
                .vc
                .clocks
                .insert(PeerPubkey::new(format!("peer-{index:03}")), 1);
        }
        let origin = PeerPubkey::new("new-authenticated-origin");
        let mut incoming = VectorClock::new();
        assert!(incoming.tick(&origin));
        let frame = test_gossip_frame(incoming, origin.clone(), 9, 2_000_000_000, vec![0]);

        state.commit_authenticated_inbound(&frame);

        assert_eq!(
            state.vc.clocks.len(),
            crate::cluster::gossip_wire::MAX_VECTOR_CLOCK_PEERS
        );
        assert_eq!(state.vc.get(&retained_local), 77);
        assert_eq!(state.vc.get(&origin), 0);
        assert_eq!(state.last_seen_seq(&origin), Some(9));
    }

    // ── Foreign event ingest (G-02 CLUSTER-01) ─────────────────────────────

    /// Open an in-memory SQLite db with the idx_foreign_events schema for
    /// testing without touching the full `memory::store` migration stack.
    fn open_foreign_events_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS idx_foreign_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                origin_peer_pk  TEXT    NOT NULL,
                origin_seq      INTEGER NOT NULL,
                event_type      INTEGER NOT NULL,
                payload         BLOB    NOT NULL,
                received_at     INTEGER NOT NULL,
                envelope_version INTEGER NOT NULL DEFAULT 0,
                content_sha256  BLOB,
                content_kind    TEXT,
                content_payload BLOB,
                UNIQUE (origin_peer_pk, origin_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
                ON idx_foreign_events (origin_peer_pk, received_at DESC);
            CREATE TABLE IF NOT EXISTS idx_profile_redactions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                field            TEXT NOT NULL,
                never_recreate   INTEGER NOT NULL DEFAULT 1,
                reason           TEXT,
                asserted_by      TEXT NOT NULL,
                asserted_at      INTEGER NOT NULL,
                revoked_at       INTEGER
            );
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn migration_creates_foreign_events_table() {
        // The migration fn creates the table; verify it is queryable after.
        let conn = open_foreign_events_db();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "fresh table is empty");
    }

    #[tokio::test]
    async fn foreign_persist_writer_ingests_submitted_jobs() {
        use sha2::{Digest as _, Sha256};

        // DES-13: the channel-based writer opens a real views.db, drains jobs,
        // and persists them — verified end-to-end without a live cluster.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let (tx, handle) = spawn_foreign_persist_writer(db.clone());
        let inner = br#"{"event_count":1}"#;
        let header = crate::wal::HeaderBuilder::new(0x94, inner).build();
        let payload = crate::wal::frame::encode_frame(&header, inner);
        let timestamp = gossip_payload_timestamp_unix(&payload).unwrap();
        let origin = PeerPubkey::new("aaaa1111");
        let frame = test_gossip_frame(
            VectorClock::new(),
            origin.clone(),
            1,
            timestamp,
            payload.clone(),
        );
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: format!("metadata:{}", restore_hex_digest(&Sha256::digest(&payload))),
            updated_at_unix: timestamp,
            content: SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload,
            },
        };
        let frame = GossipFrame {
            content_sha256: envelope.content_sha256(),
            envelope,
            ..frame
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(ForeignPersistJob {
            authenticated_peer: origin.clone(),
            frame: frame.clone(),
            policy: GossipPolicy::default(),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(matches!(
            reply_rx.await.unwrap().unwrap(),
            crate::cluster::durable_sync::InboundCommit::Committed(_)
        ));
        // A re-delivered (duplicate) frame must be an idempotent no-op.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(ForeignPersistJob {
            authenticated_peer: origin,
            frame,
            policy: GossipPolicy::default(),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(matches!(
            reply_rx.await.unwrap().unwrap(),
            crate::cluster::durable_sync::InboundCommit::Duplicate(_)
        ));
        drop(tx); // closes the channel → the blocking loop exits
        handle.await.unwrap();

        let conn = crate::memory::store::open(&db).unwrap();
        let rows = list_foreign_events(&conn, Some("aaaa1111"), 10).unwrap();
        assert_eq!(rows.len(), 1, "duplicate (pk,seq) collapses to one row");
        assert_eq!(rows[0].origin_seq, 1);
        assert_eq!(rows[0].event_type, 0x94);
    }

    #[test]
    fn canonical_restore_allocates_and_reuses_local_ids_without_guessing() {
        use sha2::{Digest as _, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let text = "restorable canonical memory".to_string();
        let stable_id = format!(
            "memory:{}",
            restore_hex_digest(&Sha256::digest(text.as_bytes()))
        );
        let build = |tier: &str, importance_micros, last_access_ts| SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: stable_id.clone(),
            updated_at_unix: 1_700_000_000,
            content: SyncContent::Memory(crate::cluster::gossip_wire::MemorySnapshot {
                stable_id: stable_id.clone(),
                text: text.clone(),
                text_hash: "restore-hash".into(),
                tier: tier.into(),
                ts_ns: 1_700_000_000_000_000_000,
                importance_micros,
                last_access_ts,
                access_count: 9,
            }),
        };
        let first = build("hot", 600_000, 1_699_000_000_000_000_000);
        assert_eq!(
            apply_restore_envelope(&conn, "origin-a", 1, &first, first.content_sha256(), false,)
                .unwrap(),
            RestoreOutcome::Applied
        );
        let local_id: i64 = conn
            .query_row(
                "SELECT local_row_id FROM mesh_sync_restore_map WHERE origin_peer_pk='origin-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            apply_restore_envelope(&conn, "origin-a", 1, &first, first.content_sha256(), false,)
                .unwrap(),
            RestoreOutcome::Skipped(RestoreSkipReason::Idempotent)
        );
        let second = build("warm", 900_000, 1_699_500_000_000_000_000);
        assert_eq!(
            apply_restore_envelope(
                &conn,
                "origin-a",
                2,
                &second,
                second.content_sha256(),
                false,
            )
            .unwrap(),
            RestoreOutcome::Applied
        );
        let (mapped_id, importance, last_access): (i64, f64, i64) = conn
            .query_row(
                "SELECT m.local_row_id,e.importance,e.last_access_ts FROM mesh_sync_restore_map m \
                 JOIN idx_consolidated e ON e.event_id=m.local_row_id WHERE m.origin_peer_pk='origin-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(mapped_id, local_id, "updates must use the durable mapping");
        assert!((importance - 0.9).abs() < f64::EPSILON);
        assert_eq!(last_access, 1_699_500_000_000_000_000);
        let hot_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_episode WHERE event_id=?1",
                [local_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hot_count, 0, "tier transition must remove the hot row");

        let third = build("cold", 950_000, 1_699_900_000_000_000_000);
        assert_eq!(
            apply_restore_envelope(&conn, "origin-a", 3, &third, third.content_sha256(), false,)
                .unwrap(),
            RestoreOutcome::Applied
        );
        let (cold_id, cold_importance, cold_access): (i64, f64, i64) = conn
            .query_row(
                "SELECT event_id,importance,last_access_ts FROM idx_longterm WHERE event_id=?1",
                [local_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(cold_id, local_id);
        assert!((cold_importance - 0.95).abs() < f64::EPSILON);
        assert_eq!(cold_access, 1_699_900_000_000_000_000);
        let warm_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_consolidated WHERE event_id=?1",
                [local_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(warm_count, 0, "tier transition must remove the warm row");
    }

    #[test]
    fn canonical_ground_truth_restore_roundtrips_without_peer_local_id() {
        use sha2::{Digest as _, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let statement = "The release contract is deterministic".to_string();
        let scope = "global".to_string();
        let mut identity = scope.as_bytes().to_vec();
        identity.push(0);
        identity.extend_from_slice(statement.as_bytes());
        let stable_id = format!(
            "ground_truth:{}",
            restore_hex_digest(&Sha256::digest(identity))
        );
        let evidence_text = "portable evidence for the release contract".to_string();
        let evidence_stable_id = format!(
            "memory:{}",
            restore_hex_digest(&Sha256::digest(evidence_text.as_bytes()))
        );
        let build = |revoked_at, confidence_micros| SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: stable_id.clone(),
            updated_at_unix: 1_700_000_000,
            content: SyncContent::GroundTruth(crate::cluster::gossip_wire::GroundTruthSnapshot {
                stable_id: stable_id.clone(),
                statement: statement.clone(),
                source: "operator-runtime".into(),
                scope: scope.clone(),
                asserted_at: 1_699_000_000,
                revoked_at,
                fact_state: "verified".into(),
                source_weight: BTreeMap::from([
                    ("operator-runtime".to_string(), 2),
                    ("nmap-scan".to_string(), 1),
                ]),
                confidence_micros,
                evidence_content_ids: vec![evidence_stable_id.clone()],
                maturity: "stable".into(),
                confirmed_count: 5,
            }),
        };
        let first = build(None, 800_000);
        apply_restore_envelope(&conn, "origin-a", 1, &first, first.content_sha256(), false)
            .unwrap();
        let local_id: i64 = conn
            .query_row(
                "SELECT local_row_id FROM mesh_sync_restore_map WHERE origin_peer_pk='origin-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let unresolved_evidence: String = conn
            .query_row(
                "SELECT evidence FROM idx_groundtruth WHERE id=?1",
                [local_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            unresolved_evidence, "[]",
            "an unresolved stable evidence id must never be guessed as a peer-local row id"
        );

        let evidence = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: evidence_stable_id.clone(),
            updated_at_unix: 1_700_000_001,
            content: SyncContent::Memory(crate::cluster::gossip_wire::MemorySnapshot {
                stable_id: evidence_stable_id.clone(),
                text: evidence_text,
                text_hash: "portable-evidence-hash".into(),
                tier: "hot".into(),
                ts_ns: 1_700_000_001_000_000_000,
                importance_micros: 900_000,
                last_access_ts: 1_700_000_001_000_000_000,
                access_count: 1,
            }),
        };
        apply_restore_envelope(
            &conn,
            "origin-a",
            2,
            &evidence,
            evidence.content_sha256(),
            false,
        )
        .unwrap();
        let evidence_local_id: i64 = conn
            .query_row(
                "SELECT local_row_id FROM mesh_sync_restore_map \
                 WHERE origin_peer_pk='origin-a' AND content_id=?1",
                [&evidence.content_id],
                |row| row.get(0),
            )
            .unwrap();
        let second = build(Some(1_701_000_000), 700_000);
        apply_restore_envelope(
            &conn,
            "origin-a",
            3,
            &second,
            second.content_sha256(),
            false,
        )
        .unwrap();
        let restored: (String, String, String, Option<i64>, f64, String, String, i64) = conn
            .query_row(
                "SELECT statement,source,scope,revoked_at,confidence,source_weight,evidence,confirmed_count \
                 FROM idx_groundtruth WHERE id=?1",
                [local_id],
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
                    ))
                },
            )
            .unwrap();
        assert_eq!(restored.0, statement);
        assert_eq!(restored.1, "mesh:origin-a:operator-runtime");
        assert_eq!(restored.2, scope);
        assert_eq!(restored.3, Some(1_701_000_000));
        assert!((restored.4 - 0.7).abs() < f64::EPSILON);
        assert_eq!(
            restored.5,
            r#"{"mesh:origin-a:nmap-scan":1,"mesh:origin-a:operator-runtime":2}"#
        );
        assert_eq!(restored.6, format!("[{evidence_local_id}]"));
        assert_eq!(restored.7, 5);
    }

    #[test]
    fn ingest_foreign_event_stores_row_and_idempotent_on_duplicate() {
        let conn = open_foreign_events_db();
        let pk = "aabbccdd";
        let seq = 7u64;
        let et = 0x90u8;
        let payload = b"test-payload";
        let ts = crate::time::now_unix_i64();

        // First ingest succeeds.
        ingest_foreign_event(&conn, pk, seq, et, payload, ts).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);

        // Second ingest of same (peer, seq) — idempotent, still 1 row.
        ingest_foreign_event(&conn, pk, seq, et, b"different-payload", ts).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "double-ingest same (peer,seq) must remain 1 row");
    }

    #[test]
    fn raw_foreign_ingest_honours_active_forget_tombstone() {
        let conn = open_foreign_events_db();
        conn.execute(
            "INSERT INTO idx_profile_redactions \
             (field, never_recreate, asserted_by, asserted_at) \
             VALUES ('_tombstone.berlin', 1, 'cli', 1)",
            [],
        )
        .unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "channel": "chat",
            "text": "Back in BERLIN"
        }))
        .unwrap();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_RAW_TEXT, &payload)
                .build();
        let frame = crate::wal::frame::encode_frame(&header, &payload);
        ingest_foreign_event(
            &conn,
            "peer",
            7,
            crate::wal::events::EVENT_TYPE_RAW_TEXT,
            &frame,
            crate::time::now_unix_i64(),
        )
        .unwrap();

        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "forgotten raw peer text must not be persisted");
    }

    #[test]
    fn raw_foreign_ingest_keeps_unrelated_text_and_rejects_bad_crc() {
        let conn = open_foreign_events_db();
        conn.execute(
            "INSERT INTO idx_profile_redactions \
             (field, never_recreate, asserted_by, asserted_at) \
             VALUES ('_tombstone.berlin', 1, 'cli', 1)",
            [],
        )
        .unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({"text": "Hamburg"})).unwrap();
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_RAW_TEXT, &payload)
                .build();
        let frame = crate::wal::frame::encode_frame(&header, &payload);
        ingest_foreign_event(
            &conn,
            "peer",
            8,
            crate::wal::events::EVENT_TYPE_RAW_TEXT,
            &frame,
            crate::time::now_unix_i64(),
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        let mut corrupt = frame;
        corrupt[100] ^= 1;
        assert!(
            ingest_foreign_event(
                &conn,
                "peer",
                9,
                crate::wal::events::EVENT_TYPE_RAW_TEXT,
                &corrupt,
                crate::time::now_unix_i64(),
            )
            .is_err()
        );
    }

    #[test]
    fn ingest_foreign_event_rejects_far_future_timestamp() {
        let conn = open_foreign_events_db();
        let now = crate::time::now_unix_i64();
        let far_future = now + FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS + 1;
        let result = ingest_foreign_event(&conn, "pk", 1, 0x90, b"pay", far_future);
        assert!(result.is_err(), "far-future received_at must be rejected");
    }

    #[test]
    fn ingest_foreign_event_rejects_ancient_timestamp() {
        let conn = open_foreign_events_db();
        let now = crate::time::now_unix_i64();
        let ancient = now - FOREIGN_EVENT_MAX_AGE_SECS - 1;
        let result = ingest_foreign_event(&conn, "pk", 1, 0x90, b"pay", ancient);
        assert!(result.is_err(), "ancient received_at must be rejected");
    }

    #[test]
    fn ingest_foreign_event_accepts_within_skew_window() {
        let conn = open_foreign_events_db();
        let now = crate::time::now_unix_i64();
        // Near — but a safe 2s INSIDE — each edge. `ingest_foreign_event`
        // re-samples the wall clock, so a value exactly on the boundary flips to
        // rejected if a whole second ticks between here and the guard (integer
        // seconds). The 2s margin keeps the accept-path assertion deterministic.
        let near_future = now + FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS - 2;
        ingest_foreign_event(&conn, "pk1", 1, 0x90, b"pay", near_future)
            .expect("within-skew future ts must be accepted");
        let near_past = now - FOREIGN_EVENT_MAX_AGE_SECS + 2;
        ingest_foreign_event(&conn, "pk2", 1, 0x90, b"pay", near_past)
            .expect("within-age past ts must be accepted");
    }

    #[test]
    fn list_foreign_events_unfiltered_and_filtered() {
        let conn = open_foreign_events_db();
        let pk_a = "aaa111";
        let pk_b = "bbb222";
        let now = crate::time::now_unix_i64();

        ingest_foreign_event(&conn, pk_a, 1, 0x90, b"pa1", now).unwrap();
        ingest_foreign_event(&conn, pk_a, 2, 0x91, b"pa2", now).unwrap();
        ingest_foreign_event(&conn, pk_b, 1, 0x90, b"pb1", now).unwrap();

        // Unfiltered — all 3 rows.
        let all = list_foreign_events(&conn, None, 100).unwrap();
        assert_eq!(all.len(), 3, "unfiltered returns all rows");

        // Filtered to pk_a — 2 rows.
        let for_a = list_foreign_events(&conn, Some(pk_a), 100).unwrap();
        assert_eq!(for_a.len(), 2, "filtered to pk_a returns 2 rows");
        assert!(for_a.iter().all(|r| r.origin_peer_pk == pk_a));

        // Limit caps result set.
        let limited = list_foreign_events(&conn, None, 1).unwrap();
        assert_eq!(limited.len(), 1, "limit=1 returns 1 row");

        // Row fields are round-tripped correctly.
        let row = for_a.iter().find(|r| r.origin_seq == 1).unwrap();
        assert_eq!(row.event_type, 0x90u8);
        assert_eq!(row.payload, b"pa1");
    }
}
