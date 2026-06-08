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
//! **DEFERRED (genuine multi-week):** APPLYING an accepted foreign WAL frame
//! into local memory. The local WAL is an HMAC-chained per-node log with no
//! origin-tagged foreign-event store; ingesting a peer's event needs a new
//! `idx_foreign_events` table + a foreign indexer + conflict resolution. Until
//! then the receiver audits + converges VectorClocks and DROPS the payload —
//! real, observable anti-entropy, not an SC-04 no-op gate.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use super::gossip::{GossipPolicy, GossipTag, ReplayBudget};
use super::gossip_wire::{GossipAcceptance, GossipFrame, PeerId, VectorClock};
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
        0x01 => RawIngressGated,             // RAW_TEXT
        0x20 | 0x21 => RawIngressGated,      // PROVIDER_REQUEST / RESPONSE
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
    seen: HashMap<PeerId, u64>,
}

impl GossipState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an outbound [`GossipFrame`] for a local WAL frame, or `None` when
    /// the event is NOT replicable (the send-side band-filter ACL). `self_id`
    /// is this node's cluster identity (`PairedPeer::pub_key_hex`).
    pub fn build_outbound(
        &mut self,
        self_id: &PeerId,
        event_type: u8,
        payload: Vec<u8>,
        timestamp_unix: i64,
        policy: &GossipPolicy,
    ) -> Option<GossipFrame> {
        if !is_replicable(event_type, policy) {
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
    ///      DoNotGossip event as Replicate),
    /// and on `Accept` updates the dedup table + merges the sender's VC.
    /// `payload_event_type` is `None` when the caller couldn't decode the inner
    /// WAL header — treated as un-trusted ⇒ dropped.
    pub fn accept_inbound(
        &mut self,
        frame: &GossipFrame,
        payload_event_type: Option<u8>,
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
        // so a mis-tagged frame can't smuggle a DoNotGossip band across.
        match payload_event_type {
            Some(et) if is_replicable(et, policy) => {}
            _ => return GossipAcceptance::DroppedDoNotGossipTag,
        }
        // Accept: record dedup high-water + converge the VC.
        self.seen.insert(frame.origin.clone(), frame.event_seq);
        self.vc.merge(&frame.vector_clock);
        GossipAcceptance::Accept
    }

    /// Highest applied seq for a peer (observability).
    pub fn last_seen_seq(&self, origin: &PeerId) -> Option<u64> {
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
        let total_len =
            u32::from_le_bytes([body[cursor + 9], body[cursor + 10], body[cursor + 11], body[cursor + 12]])
                as usize;
        // Torn tail / corrupt length ⇒ stop (don't advance past garbage).
        if total_len < WAL_HEADER_MIN || cursor + total_len > body.len() {
            break;
        }
        if is_replicable(event_type, policy) {
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
        let self_id = PeerId::new(uuid::Uuid::now_v7().to_string());
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
                if let Some(gframe) = state.build_outbound(&self_id, event_type, raw, ts, &policy) {
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
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
            assert!(!is_replicable(et, &p), "permission band 0x{et:02X} must not gossip");
        }
        // Profile band (0xB0..=0xBF) — operator PII.
        for et in 0xB0u8..=0xBF {
            assert!(!is_replicable(et, &p), "profile band 0x{et:02X} must not gossip");
        }
        // Consent + WAL-structure + operator/system band.
        for et in [0x65u8, 0xF0, 0xF1, 0xF2, 0xF3, 0xFF] {
            assert!(!is_replicable(et, &p), "0x{et:02X} must not gossip");
        }
        // Daemon lifecycle BOOT/SHUTDOWN/rollover/compaction.
        for et in [0x10u8, 0x11, 0x14, 0x15] {
            assert!(!is_replicable(et, &p), "lifecycle 0x{et:02X} must not gossip");
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
        assert_eq!(new_off, body.len(), "cursor advanced past ALL frames walked");
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

    fn self_pk() -> PeerId {
        PeerId::new("aa11")
    }

    #[test]
    fn build_outbound_drops_non_replicable_returns_some_for_safe() {
        let p = GossipPolicy::default();
        let mut st = GossipState::new();
        // A permission event is never wrapped.
        assert!(st.build_outbound(&self_pk(), 0xA0, vec![1, 2, 3], 1000, &p).is_none());
        // A cluster-topology event (0xE6 leaks addr/autonomy) is NOT wrapped.
        assert!(st.build_outbound(&self_pk(), 0xE6, vec![9], 1000, &p).is_none());
        // A verified-clean memory-tier transition is wrapped + VC advances.
        let f = st
            .build_outbound(&self_pk(), 0x90, vec![9], 1000, &p)
            .expect("safe event wraps");
        assert_eq!(f.origin, self_pk());
        assert_eq!(f.event_seq, 1);
        assert_eq!(f.tag, GossipTag::Replicate);
        assert!(f.vector_clock.get(&self_pk()) >= 1);
    }

    #[test]
    fn accept_inbound_dedups_and_band_rechecks() {
        let p = GossipPolicy::default();
        let mut st = GossipState::new();
        let peer = PeerId::new("bb22");
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
        // First arrival of a replicable-band event ⇒ Accept + VC converges.
        assert_eq!(
            st.accept_inbound(&frame, Some(0x90), &p, now),
            GossipAcceptance::Accept
        );
        assert_eq!(st.last_seen_seq(&peer), Some(5));
        assert!(st.vc.get(&peer) >= 1, "receiver VC converged on sender");
        // Re-delivery (<= last seq) ⇒ duplicate drop.
        assert!(matches!(
            st.accept_inbound(&frame, Some(0x90), &p, now),
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
            st.accept_inbound(&smuggle, Some(0xA0), &p, now),
            GossipAcceptance::DroppedDoNotGossipTag,
            "a payload in the permissions band must be dropped on receive"
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
        let local = PeerId::new("local99");
        st.vc.tick(&local);
        st.vc.tick(&local);

        // A frame from peer-a carrying a multi-node frontier {a:3, b:2, c:1}.
        let pa = PeerId::new("aa11");
        let pb = PeerId::new("bb22");
        let pc = PeerId::new("cc33");
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
            st.accept_inbound(&frame, Some(0x90), &policy, now),
            GossipAcceptance::Accept
        );
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
}
