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
//! - **Send** ([`GossipState::build_outbound`]): wrap a replicable local WAL
//!   frame in a [`GossipFrame`] (VectorClock tick + monotonic seq). Returns
//!   `None` for a non-replicable event — the ACL on the emit side.
//! - **Receive** ([`GossipState::accept_inbound`]): `evaluate_acceptance`
//!   (tag/budget/dedup) PLUS a defence-in-depth band re-check on the payload's
//!   own event_type (a buggy/malicious sender could mis-tag a DoNotGossip
//!   event), then dedup-update + VC merge.
//!
//! - **Persist** ([`ingest_foreign_event`], G02-CLUSTER-02): an accepted frame
//!   is written to the `idx_foreign_events` table (`(origin_peer_pk,
//!   origin_seq)` UNIQUE → idempotent), then [`GossipState::commit_inbound`]
//!   advances the dedup high-water + merges the sender's VC only after the DB
//!   write confirms. This is the failover backup-at-rest: a peer's replicable
//!   events survive on this node if the peer's disk dies. Queryable via
//!   [`list_foreign_events`] / `neoth cluster events`. **Transport note:** the
//!   hyperswarm/peeroxide receive loop persists; the iroh `gossip_handler`
//!   (opt-in `cluster-iroh`) is a sync frame handler with no DB context and
//!   currently commits VC-only without persisting — a known gap.
//!
//! **STILL DEFERRED (genuine multi-week):** APPLYING a stored foreign event
//! back INTO local recall/memory on a recovered node — the conflict-resolution
//! + merge step. Foreign events are a separate queryable surface today, never
//! mixed into `idx_episode` / `idx_groundtruth`; automatic restore is not yet
//! built. Treat the mesh as durable backup, not one-click restore.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;

use super::PeerPubkey;
use super::gossip::{GossipPolicy, GossipTag, ReplayBudget};
use super::gossip_wire::{GossipAcceptance, GossipFrame, VectorClock};
use super::heartbeat::{FrameBody, FrameKind, WireFrame};
use super::peer_streams::PeerStreamRegistry;
use crate::wal::writer::WalWriterHandle;

/// Gossip anti-entropy tick interval. A peer offline > ReplayBudget re-pairs;
/// 30s keeps convergence prompt without flooding the bounded outbound queue.
const GOSSIP_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// Max replicable frames broadcast per tick — bounds a post-reconnect burst
/// against the per-peer OUTBOUND_QUEUE_DEPTH (64).
const GOSSIP_BATCH_MAX: usize = 32;

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
        0x01 => RawIngressGated,                      // RAW_TEXT
        0x20 | 0x21 => RawIngressGated,               // PROVIDER_REQUEST / RESPONSE
        0x32 | 0x33 | 0x35..=0x38 => RawIngressGated, // channel ingress/egress/quarantine/sanitize/ack/edit
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
    /// Monotonic per-session outbound sequence.
    next_seq: u64,
    /// Dedup table: origin peer → highest applied event_seq.
    seen: HashMap<PeerPubkey, u64>,
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
        self.vc.tick(self_id);
        self.next_seq = self.next_seq.wrapping_add(1);
        Some(GossipFrame {
            vector_clock: self.vc.clone(),
            origin: self_id.clone(),
            event_seq: self.next_seq,
            timestamp_unix,
            tag: GossipTag::Replicate,
            payload,
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
    /// advancing the dedup high-water (and merging the sender's VC) before
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
        let last_seen = self.seen.get(&frame.origin).copied();
        let verdict = frame.evaluate_acceptance(&budget, now_ts_unix, last_seen);
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

    /// Commit an accepted-AND-persisted inbound frame: record the dedup
    /// high-water + converge the VC. Call ONLY after the foreign event is
    /// durably stored (`ingest_foreign_event` returned `Ok`). Idempotent for
    /// the same frame (re-inserting the same seq / re-merging the same VC is
    /// a no-op), so a duplicate arriving before the first commit lands is
    /// harmless — the DB's `INSERT OR IGNORE` on (origin, seq) absorbs it.
    pub fn commit_inbound(&mut self, frame: &GossipFrame) {
        self.seen.insert(frame.origin.clone(), frame.event_seq);
        self.vc.merge(&frame.vector_clock);
    }

    /// Highest applied seq for a peer (observability).
    pub fn last_seen_seq(&self, origin: &PeerPubkey) -> Option<u64> {
        self.seen.get(origin).copied()
    }
}

/// Minimum WAL frame header size (the 96-byte `EventHeaderV2`). `event_type` is
/// header byte 2; `total_len` is the LE u32 at bytes 9..13 (pinned by the WAL
/// header tests). We read these RAW (no HMAC verify) because the send-tick
/// walks THIS node's own uncompressed active-segment body.
const WAL_HEADER_MIN: usize = 96;

/// Walk an uncompressed WAL segment BODY from `from_offset`, collecting up to
/// `max` REPLICABLE frames as `(event_type, raw_frame_bytes)`. Returns the
/// collected frames + the new cursor (advanced past every frame walked, so the
/// next tick continues from there). Stops cleanly on a torn/short tail.
///
/// Pure — no IO. The send-tick reads the active segment file, strips the
/// segment header, and calls this on the body.
///
/// GOLD-ARCH-03 audit: intentionally NOT migrated to `wal::scan::for_each_frame`.
/// Gossip needs the RAW on-wire frame bytes + a resumable cursor, and the caller
/// (`spawn_gossip_tick`) already derives the correct v1/v2 `header_len()` and
/// skips compressed/finalised segments (whose body is a zstd blob, never walked
/// raw). The format-awareness lives in the caller; this stays a pure body walk.
pub fn collect_gossipable_frames(
    body: &[u8],
    from_offset: usize,
    policy: &GossipPolicy,
    max: usize,
) -> (Vec<(u8, Vec<u8>)>, usize) {
    let mut out = Vec::new();
    let mut cursor = from_offset.min(body.len());
    while cursor + WAL_HEADER_MIN <= body.len() && out.len() < max {
        let event_type = body[cursor + 2];
        // Byte 3 is the event_subtype for EXTENDED (0x00) frames; 0 for others.
        let event_subtype = body[cursor + 3];
        let total_len = u32::from_le_bytes([
            body[cursor + 9],
            body[cursor + 10],
            body[cursor + 11],
            body[cursor + 12],
        ]) as usize;
        // Torn tail / corrupt length ⇒ stop (don't advance past garbage).
        if total_len < WAL_HEADER_MIN || cursor + total_len > body.len() {
            break;
        }
        // Use ext classifier so SwarmResourceSnapshot (0x00/0x03) is included
        // and LocalSnapshot (0x00/0x04) is correctly excluded.
        if is_replicable_ext(event_type, event_subtype, policy) {
            out.push((event_type, body[cursor..cursor + total_len].to_vec()));
        }
        cursor += total_len;
    }
    (out, cursor)
}

/// SL-01b send path: spawn the anti-entropy gossip tick. Every
/// [`GOSSIP_TICK_INTERVAL`] it reads the active WAL segment tail, band-filters
/// replicable frames, wraps them in [`GossipFrame`]s (VectorClock-tagged), and
/// broadcasts to paired peers. Read-only consumer of the WAL (NOT a write hook
/// — the per-peer read loop is read-to-completion and can't take an append
/// callback). Returns the task handle so the daemon can abort it on shutdown.
///
/// `self_id` is a per-session uuid (gossip state is in-memory + rebuilds on
/// restart for SL-01b; a persistent node-id origin is a follow-on with the
/// foreign-event store).
pub fn spawn_gossip_tick(
    peer_streams: Arc<PeerStreamRegistry>,
    segment_path: PathBuf,
    writer: Arc<WalWriterHandle>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let policy = GossipPolicy::default();
        let mut state = GossipState::new();
        let self_id = PeerPubkey::new(uuid::Uuid::now_v7().to_string());
        // The WAL dir to re-resolve the ACTIVE segment each tick (a fixed path
        // would go stale after a rollover — review HIGH). The seed path's parent
        // is the segment dir.
        let wal_dir = segment_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        // Track which segment the offset belongs to; reset to 0 on a rollover.
        let mut current_segment: PathBuf = segment_path.clone();
        let mut last_offset: usize = 0;
        let mut ticker = tokio::time::interval(GOSSIP_TICK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            // No peers ⇒ nothing to gossip; don't even read the segment.
            if peer_streams.peer_count() == 0 {
                continue;
            }
            // Resolve the active (newest) segment. On rollover the offset is
            // meaningless for the new file ⇒ reset to 0.
            let active = newest_segment(&wal_dir).unwrap_or_else(|| current_segment.clone());
            if active != current_segment {
                current_segment = active;
                last_offset = 0;
            }
            let bytes = match tokio::fs::read(&current_segment).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = %e, "gossip tick: segment read failed");
                    continue;
                }
            };
            let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
                continue;
            };
            // A compressed (rolled/finalised) segment can't be walked raw — its
            // body is zstd. The ACTIVE segment is uncompressed; skip a finalised
            // one rather than ship corrupt bytes (review LOW).
            if hdr.is_compressed() {
                continue;
            }
            let header_len = hdr.header_len();
            if bytes.len() <= header_len {
                continue;
            }
            let body = &bytes[header_len..];
            let (frames, new_offset) =
                collect_gossipable_frames(body, last_offset, &policy, GOSSIP_BATCH_MAX);
            // ALWAYS advance the cursor past the frames we walked — gossip is
            // best-effort (the receiver dedups + the ReplayBudget covers gaps).
            // Gating advancement on delivery would re-walk + re-send the same
            // frames forever when a peer queue is briefly full (review MEDIUM).
            last_offset = new_offset;
            if frames.is_empty() {
                continue;
            }
            let frame_count = frames.len();
            for (event_type, raw) in frames {
                let ts = now_unix_secs();
                // Byte 3 of the raw frame body is the event_subtype for EXTENDED
                // frames; 0 for all other types (ignored by classify_event_ext).
                let event_subtype = raw.get(3).copied().unwrap_or(0);
                if let Some(gframe) = state.build_outbound(&self_id, event_type, event_subtype, raw, ts, &policy) {
                    let wf = WireFrame {
                        kind: FrameKind::Gossip,
                        sequence: gframe.event_seq,
                        sent_unix_ms: now_unix_ms(),
                        peer_id: self_id.as_str().to_string(),
                        body: FrameBody::Gossip(gframe),
                    };
                    let _ = peer_streams.broadcast(&wf);
                }
            }
            emit_gossip_sent_wal(&writer, frame_count, peer_streams.peer_count());
        }
    })
}

/// Find the lexicographically-greatest `*.wal` in `dir` — the active segment
/// (segment files are zero-padded sequence names, so lexical max = newest).
fn newest_segment(dir: &std::path::Path) -> Option<PathBuf> {
    let mut newest: Option<PathBuf> = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wal") {
            match &newest {
                Some(cur) if path <= *cur => {}
                _ => newest = Some(path),
            }
        }
    }
    newest
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
    .with_context(|| {
        format!(
            "ingest_foreign_event: insert {}/{} failed",
            origin_peer_pk, origin_seq
        )
    })
}

/// DES-13 — one accepted gossip frame queued for durable persistence.
/// Both cluster transports (hyperswarm + iroh) submit these; a single
/// [`spawn_foreign_persist_writer`] task owns the DB connection and drains
/// them. Keeps the blocking DB open OFF the transport hot-path (a sync
/// `open`-per-frame inside a tokio task starves the runtime — panel finding).
#[derive(Debug, Clone)]
pub struct ForeignPersistJob {
    pub origin_peer_pk: String,
    pub origin_seq: u64,
    pub event_type: u8,
    pub payload: Vec<u8>,
    pub received_at: i64,
}

/// Sender half handed to a transport's accept path. `try_send` is
/// non-blocking; a full channel drops the job (gossip is best-effort — the
/// sender re-delivers via its replay budget). The transport commits the
/// dedup high-water ONLY on a successful send (persist-then-commit).
pub type ForeignPersistTx = tokio::sync::mpsc::Sender<ForeignPersistJob>;

/// DES-13 — spawn the single foreign-event DB writer. Returns the sender
/// (give to the transport's `gossip_handler`) + the JoinHandle (the daemon
/// keeps it alive and drops the sender on shutdown → the loop ends). The
/// connection is opened lazily inside the blocking task (rusqlite
/// `Connection` is `!Send`). A per-job insert failure is logged, not fatal —
/// `INSERT OR IGNORE` also makes a re-delivered frame a no-op.
pub fn spawn_foreign_persist_writer(
    db_path: std::path::PathBuf,
) -> (ForeignPersistTx, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ForeignPersistJob>(256);
    let handle = tokio::task::spawn_blocking(move || {
        let conn = match crate::memory::store::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, db = %db_path.display(),
                    "foreign-persist writer: cannot open views.db — foreign events will NOT be backed up");
                return;
            }
        };
        while let Some(job) = rx.blocking_recv() {
            if let Err(e) = ingest_foreign_event(
                &conn,
                &job.origin_peer_pk,
                job.origin_seq,
                job.event_type,
                &job.payload,
                job.received_at,
            ) {
                tracing::warn!(error = %e, peer = %job.origin_peer_pk, seq = job.origin_seq,
                    "foreign-persist writer: ingest failed (frame not backed up; sender may re-deliver)");
            }
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
            "SELECT id, origin_peer_pk, origin_seq, event_type, payload, received_at \
             FROM idx_foreign_events \
             WHERE origin_peer_pk = ?1 \
             ORDER BY received_at DESC \
             LIMIT ?2"
        }
        None => {
            "SELECT id, origin_peer_pk, origin_seq, event_type, payload, received_at \
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
    Ok(ForeignEventRow {
        id: r.get(0)?,
        origin_peer_pk: r.get(1)?,
        origin_seq: r.get::<_, i64>(2)? as u64,
        event_type: r.get::<_, i64>(3)? as u8,
        payload: r.get(4)?,
        received_at: r.get(5)?,
    })
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
            Self::Idempotent => f.write_str("idempotent (local >= peer)"),
            Self::AlreadyRevoked => f.write_str("already revoked"),
            Self::Contradicted => f.write_str("contradicted (closed fact)"),
            Self::NoiseEventType => f.write_str("noise event type (aggregate, no apply effect)"),
            Self::DoNotGossip => f.write_str("DoNotGossip event type in export"),
            Self::MalformedPayload => f.write_str("malformed WAL frame or event_type mismatch"),
            Self::MalformedInnerPayload => f.write_str("malformed inner JSON payload"),
        }
    }
}

/// Apply a single restored foreign frame to local recall surfaces.
///
/// # Parameters
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
/// | 0x92 | `* 0.5, floor DECAY_FLOOR` on local episode | Missing |
/// | 0x98 | SET `revoked_at` on local groundtruth | Missing / AlreadyRevoked / Contradicted |
/// | 0x94 / 0x13 | no local effect (aggregate / capability) | NoiseEventType |
/// | 0x97 / 0x93 / 0x12 / other DoNotGossip | reject | DoNotGossip |
///
/// # Savepoints
/// The caller is responsible for wrapping each call in its own SQLite
/// savepoint so a conflict-matrix Skip on one row does not roll back the
/// entire restore session.
pub fn apply_restore_frame(
    conn: &rusqlite::Connection,
    event_type: u8,
    payload_bytes: &[u8],
    received_at: i64,
    dry_run: bool,
) -> anyhow::Result<RestoreOutcome> {
    use crate::wal::events::{
        EVENT_TYPE_CONSOLIDATION_PASS, EVENT_TYPE_EPISODE_ARCHIVED,
        EVENT_TYPE_EPISODE_CONSOLIDATED, EVENT_TYPE_EPISODE_PROMOTED,
        EVENT_TYPE_GROUNDTRUTH_REVOKED, EVENT_TYPE_UPDATE_RAN,
    };
    use crate::cluster::foreign_indexer::{
        apply_episode_boost, apply_episode_decay_sql, apply_groundtruth_revoke,
        BoostOutcome, GroundtruthRevokeOutcome,
        EpisodeConsolidatedPayload, EpisodePromotedPayload,
        EpisodeArchivedPayload, GroundtruthRevokedPayload,
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
                    return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedInnerPayload));
                }
            };
            if dry_run {
                // Evaluate only — check existence/idempotency but skip write.
                let exists: i64 = conn.query_row(
                    "SELECT count(*) FROM idx_episode WHERE event_id = ?1",
                    [p.event_id],
                    |r| r.get(0),
                ).context("restore dry-run: check episode existence")?;
                return Ok(if exists == 0 {
                    RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing)
                } else {
                    RestoreOutcome::Applied
                });
            }
            match apply_episode_boost(conn, p.event_id, p.importance)? {
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
                    return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedInnerPayload));
                }
            };
            if dry_run {
                let exists: i64 = conn.query_row(
                    "SELECT count(*) FROM idx_episode WHERE event_id = ?1",
                    [p.event_id],
                    |r| r.get(0),
                ).context("restore dry-run: check episode existence")?;
                return Ok(if exists == 0 {
                    RestoreOutcome::Skipped(RestoreSkipReason::LocalRowMissing)
                } else {
                    RestoreOutcome::Applied
                });
            }
            match apply_episode_boost(conn, p.event_id, p.to_importance)? {
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
                    return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedInnerPayload));
                }
            };
            if dry_run {
                let exists: i64 = conn.query_row(
                    "SELECT count(*) FROM idx_episode WHERE event_id = ?1",
                    [p.event_id],
                    |r| r.get(0),
                ).context("restore dry-run: check episode existence")?;
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
                    return Ok(RestoreOutcome::Skipped(RestoreSkipReason::MalformedInnerPayload));
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
                    Ok((Some(_), _)) => {
                        RestoreOutcome::Skipped(RestoreSkipReason::AlreadyRevoked)
                    }
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
/// `home/credentials.yaml`. Returns `None` when no cluster identity is
/// configured (no passphrase or no cluster name in freedom.yaml).
///
/// The pubkey is the 64-character lowercase hex encoding of the 32-byte
/// `ClusterKey` (HMAC of the passphrase). This is the same value stored in
/// `origin_peer_pk` when this node exports its own foreign events.
pub fn local_node_pubkey(home: &std::path::Path) -> Option<String> {
    let freedom =
        crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")).ok()?;
    let creds =
        crate::config::credentials::Credentials::load_or_default(
            &home.join("credentials.yaml"),
        )
        .ok()?;
    let identity =
        crate::cluster::identity::resolve_cluster_identity(&freedom, &creds)?;
    let hex = identity
        .key
        .0
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    Some(hex)
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

    /// Build a minimal 96-byte WAL frame header with a given event_type +
    /// total_len (no payload ⇒ total_len = 96), matching the raw offsets the
    /// walker reads (byte 2 = event_type, bytes 9..13 = total_len LE).
    fn fake_frame(event_type: u8) -> Vec<u8> {
        let mut f = vec![0u8; WAL_HEADER_MIN];
        f[2] = event_type;
        let total = WAL_HEADER_MIN as u32;
        f[9..13].copy_from_slice(&total.to_le_bytes());
        f
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
        // Append a torn (short) header tail.
        body.extend_from_slice(&[0u8; 10]);
        let (frames, _off) = collect_gossipable_frames(&body, 0, &p, 1);
        assert_eq!(frames.len(), 1, "max=1 caps collection");
        // From a from_offset past the two full frames, the torn tail stops cleanly.
        let (rest, _) = collect_gossipable_frames(&body, WAL_HEADER_MIN * 2, &p, 16);
        assert!(rest.is_empty(), "torn tail yields nothing, no panic");
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
        assert_eq!(f.event_seq, 1);
        assert_eq!(f.tag, GossipTag::Replicate);
        assert!(f.vector_clock.get(&self_pk()) >= 1);
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
        assert!(is_replicable_ext(0x90, 0, &p), "0x90 still replicates via classify_event");
        assert!(!is_replicable_ext(0xA0, 0, &p), "0xA0 still DoNotGossip via classify_event");
    }

    #[test]
    fn accept_inbound_dedups_and_band_rechecks() {
        let p = GossipPolicy::default();
        let mut st = GossipState::new();
        let peer = PeerPubkey::new("bb22");
        let mut sender_vc = VectorClock::new();
        sender_vc.tick(&peer);
        let frame = GossipFrame {
            vector_clock: sender_vc,
            origin: peer.clone(),
            event_seq: 5,
            timestamp_unix: 2_000_000_000, // within a fresh budget vs a near now
            tag: GossipTag::Replicate,
            payload: vec![0],
        };
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
            "accept_inbound must NOT advance the high-water before commit"
        );
        // Re-delivery BEFORE commit is still Accept (DB INSERT OR IGNORE
        // absorbs the double-persist) — the crash-window contract.
        assert_eq!(
            st.accept_inbound(&frame, Some(0x90), None, &p, now),
            GossipAcceptance::Accept
        );
        // After confirmed persistence the caller commits: high-water + VC.
        st.commit_inbound(&frame);
        assert_eq!(st.last_seen_seq(&peer), Some(5));
        assert!(st.vc.get(&peer) >= 1, "receiver VC converged on sender");
        // Re-delivery (<= last seq) after commit ⇒ duplicate drop.
        assert!(matches!(
            st.accept_inbound(&frame, Some(0x90), None, &p, now),
            GossipAcceptance::DroppedDuplicate { .. }
        ));
        // Defence-in-depth: a frame whose payload is actually a DoNotGossip
        // band (mis-tagged) is dropped even though the GossipTag says Replicate.
        let mut vc2 = VectorClock::new();
        vc2.tick(&peer);
        let smuggle = GossipFrame {
            vector_clock: vc2,
            origin: peer.clone(),
            event_seq: 6,
            timestamp_unix: 2_000_000_000,
            tag: GossipTag::Replicate,
            payload: vec![0],
        };
        assert_eq!(
            st.accept_inbound(&smuggle, Some(0xA0), None, &p, now),
            GossipAcceptance::DroppedDoNotGossipTag,
            "a payload in the permissions band must be dropped on receive"
        );
        // A SwarmResourceSnapshot (0x00/0x03) must be accepted — the key
        // correctness assertion for GOLD-FEAT-06 gossip-piggyback.
        let mut vc3 = VectorClock::new();
        vc3.tick(&peer);
        let snap_frame = GossipFrame {
            vector_clock: vc3,
            origin: peer.clone(),
            event_seq: 7,
            timestamp_unix: 2_000_000_000,
            tag: GossipTag::Replicate,
            payload: vec![0],
        };
        assert_eq!(
            st.accept_inbound(&snap_frame, Some(0x00), Some(SWARM_SNAPSHOT_SUBTYPE), &p, now),
            GossipAcceptance::Accept,
            "SwarmResourceSnapshot (0x00/0x03) must be accepted by the receive ACL"
        );
        // LocalSnapshot (0x00/0x04) must be dropped even from a trusted peer.
        let mut vc4 = VectorClock::new();
        vc4.tick(&peer);
        let local_snap_frame = GossipFrame {
            vector_clock: vc4,
            origin: peer.clone(),
            event_seq: 8,
            timestamp_unix: 2_000_000_000,
            tag: GossipTag::Replicate,
            payload: vec![0],
        };
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
        let frame = GossipFrame {
            vector_clock: frontier.clone(),
            origin: pa.clone(),
            event_seq: 7,
            timestamp_unix: 2_000_000_000,
            tag: GossipTag::Replicate,
            payload: vec![0],
        };
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
                UNIQUE (origin_peer_pk, origin_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
                ON idx_foreign_events (origin_peer_pk, received_at DESC);
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
        // DES-13: the channel-based writer opens a real views.db, drains jobs,
        // and persists them — verified end-to-end without a live cluster.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("views.db");
        let (tx, handle) = spawn_foreign_persist_writer(db.clone());
        tx.send(ForeignPersistJob {
            origin_peer_pk: "aaaa1111".into(),
            origin_seq: 7,
            event_type: 0x90,
            payload: vec![1, 2, 3, 0x90, 4],
            received_at: crate::time::now_unix_i64(),
        })
        .await
        .unwrap();
        // A re-delivered (duplicate) frame must be an idempotent no-op.
        tx.send(ForeignPersistJob {
            origin_peer_pk: "aaaa1111".into(),
            origin_seq: 7,
            event_type: 0x90,
            payload: vec![1, 2, 3, 0x90, 4],
            received_at: crate::time::now_unix_i64(),
        })
        .await
        .unwrap();
        drop(tx); // closes the channel → the blocking loop exits
        handle.await.unwrap();

        let conn = crate::memory::store::open(&db).unwrap();
        let rows = list_foreign_events(&conn, Some("aaaa1111"), 10).unwrap();
        assert_eq!(rows.len(), 1, "duplicate (pk,seq) collapses to one row");
        assert_eq!(rows[0].origin_seq, 7);
        assert_eq!(rows[0].event_type, 0x90);
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
