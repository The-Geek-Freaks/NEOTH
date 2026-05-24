//! Cluster C-1 (Session 21, 2026-05-23) — Pears-transport peer discovery.
//!
//! Wraps [`crate::channels::pears_bridge::PearsBridge`] for cluster peer
//! announce + lookup via dedicated Pears topics. Operator opt-in via
//! `freedom.yaml::cluster.transport = "pears"` (default `disabled`).
//!
//! ## Wire shape
//!
//! Each NEOTH node announces itself on a deterministic topic derived from
//! the operator's `cluster_id`:
//!
//! ```text
//!   topic = sha256("neoth.cluster." + cluster_id)
//!   payload = { pubkey, role, capabilities[], announced_unix_ts }
//! ```
//!
//! Peers subscribe to the same topic + collect the announce payloads into
//! a peer registry. The election layer ([`super::pears_election`]) consumes
//! the registry's current set to pick the orchestrator.
//!
//! ## QUELLEN provenance — watchdog + restart limits
//!
//! Adopts the recovery state-machine pattern from
//! `QUELLEN/openclaw/extensions/bonjour/src/advertiser.ts`:
//!   - `STUCK_ANNOUNCING_MS` — 20s grace for slow LANs (the openclaw
//!     comment notes "Real-world LAN announce phase typically takes
//!     12-13s on Mac/iOS networks. The previous 8s threshold was
//!     triggering false-positive teardowns…").
//!   - `MAX_CONSECUTIVE_RESTARTS` — 3 attempts then disable advertiser
//!     permanently (operator-visible warn).
//!   - `RESTART_WINDOW_MS` + `MAX_RESTARTS_IN_WINDOW` — bound total
//!     restarts even if `consecutive` keeps resetting between flaps.
//!
//! ## Status (UNTESTED against live `pear`)
//!
//! Per the Session 21 agent panel verdict, the cluster transport built on
//! PearsBridge MUST be operator-verified against a live `pear` runtime
//! before promotion to a default channel. This module's surface compiles,
//! is unit-tested, but the actual peer-announce HTTP round-trip + the
//! topic-subscription wire format are projections — the operator needs to
//! K-3.5-pair Keet against their phone, then verify that
//! `PearsPeerDiscovery::announce_self()` lands the announce payload on a
//! Pears topic that other NEOTH nodes can subscribe to. Until then,
//! [`bootstrap_pears_cluster`] emits an UNTESTED warn the first time the
//! operator flips `cluster.transport = "pears"`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::pears_election::{Election, PeerPubkey, elect_orchestrator};
use crate::channels::pears_bridge::{PearsBridge, PostMessageRequest};

/// Watchdog interval — how often the supervisor checks the announcer
/// state. Aligned with `openclaw/extensions/bonjour/src/advertiser.ts`
/// `WATCHDOG_INTERVAL_MS = 5_000`.
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// Grace window for an in-flight announce before the watchdog flags it
/// stuck. Aligned with openclaw's `STUCK_ANNOUNCING_MS = 20_000` — the
/// openclaw comment captures why a shorter timeout caused false-positive
/// teardowns on real LANs.
pub const STUCK_ANNOUNCING: Duration = Duration::from_secs(20);

/// Maximum consecutive restart attempts before the advertiser is
/// disabled permanently for this daemon lifetime. From openclaw's
/// `MAX_CONSECUTIVE_RESTARTS = 3`.
pub const MAX_CONSECUTIVE_RESTARTS: u32 = 3;

/// Window over which `MAX_RESTARTS_IN_WINDOW` applies. From openclaw's
/// `RESTART_WINDOW_MS = 30 * 60_000` (30 minutes).
pub const RESTART_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Bound on total restarts inside `RESTART_WINDOW`. From openclaw's
/// `MAX_RESTARTS_IN_WINDOW = 5` — a flapping advertiser that briefly
/// reaches "announced" between failures resets the consecutive counter,
/// so the window-based cap is the second safety net.
pub const MAX_RESTARTS_IN_WINDOW: u32 = 5;

/// Announce payload emitted on the cluster topic. Mirror of the WAL
/// `CLUSTER_PEER_CONNECTED` (0xE0) shape so an audit replay
/// reconstructs the same struct from disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncePayload {
    pub pubkey: String,
    /// Operator-facing role label. Today either `"leader"` (the
    /// orchestrator-elected peer) or `"follower"`. Future: per-
    /// hemisphere capabilities + special roles (e.g. `"archive"`).
    #[serde(default)]
    pub role: String,
    /// Capabilities the peer advertises. Today empty; future Phase
    /// 5 surfaces (cluster.capability_filter) consume this for
    /// request routing.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Unix seconds at announce-write time. Drives the "is this peer
    /// still alive?" heuristic — peers whose last announce is older
    /// than `STALE_PEER` are considered Left.
    pub announced_unix_ts: u64,
}

/// Peers older than this without re-announcing are dropped from the
/// registry. 2× the announce period so a single missed heartbeat
/// doesn't evict a peer.
pub const STALE_PEER: Duration = Duration::from_secs(60);

/// Watchdog state for the announcer. State machine adapted from openclaw's
/// `BONJOUR_ANNOUNCED_STATE` / `isAdvertisingInProgressState` distinctions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnouncerState {
    /// Initial state before the first announce attempt.
    Idle,
    /// Announce HTTP request in flight.
    Announcing,
    /// Last announce returned 2xx; reset consecutive-restart counter.
    Announced,
    /// Announce failed; supervisor will recreate up to the restart cap.
    Failed,
    /// Restart cap hit; advertiser is permanently off for this daemon
    /// lifetime. Operator gets a warn line + flips
    /// `freedom.yaml::cluster.transport = "disabled"` to clear.
    DisabledByRecoveryCap,
}

impl AnnouncerState {
    /// True when the state counts as healthy — the watchdog resets its
    /// counters here.
    pub fn is_healthy(self) -> bool {
        matches!(self, AnnouncerState::Announced)
    }

    /// True when the state means "give up + tell operator". Surfaced
    /// so callers can `if state.is_terminal() { return; }` from their
    /// supervisor loops without matching every variant.
    pub fn is_terminal(self) -> bool {
        matches!(self, AnnouncerState::DisabledByRecoveryCap)
    }
}

/// Local view of the live peer set. Wraps a `BTreeSet<PeerPubkey>` so
/// the election function can consume it directly + a parallel map of
/// last-announce timestamps for staleness eviction. Operations on the
/// registry are async-safe via the surrounding `Arc<Mutex<>>` in
/// [`PearsPeerDiscovery`].
#[derive(Clone, Debug, Default)]
pub struct PeerRegistry {
    /// Live peer pubkeys.
    pub peers: BTreeSet<PeerPubkey>,
    /// `(pubkey, last_announce_unix_ts)`. Sorted by pubkey for
    /// deterministic eviction order during sweeps.
    pub last_seen: std::collections::BTreeMap<PeerPubkey, u64>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an inbound announce. Returns `true` when the pubkey was
    /// new (caller emits a WAL `CLUSTER_PEER_CONNECTED` frame), `false`
    /// when it was already present (just a heartbeat refresh).
    pub fn record_announce(&mut self, payload: &AnnouncePayload) -> bool {
        let pk = PeerPubkey(payload.pubkey.clone());
        let was_new = self.peers.insert(pk.clone());
        self.last_seen.insert(pk, payload.announced_unix_ts);
        was_new
    }

    /// Drop peers whose last announce is older than `STALE_PEER`. Returns
    /// the evicted pubkeys so the caller can emit
    /// `CLUSTER_PEER_DISCONNECTED` frames.
    pub fn sweep_stale(&mut self, now_unix_ts: u64) -> Vec<PeerPubkey> {
        let stale_threshold = now_unix_ts.saturating_sub(STALE_PEER.as_secs());
        let evicted: Vec<PeerPubkey> = self
            .last_seen
            .iter()
            .filter(|(_, ts)| **ts < stale_threshold)
            .map(|(pk, _)| pk.clone())
            .collect();
        for pk in &evicted {
            self.peers.remove(pk);
            self.last_seen.remove(pk);
        }
        evicted
    }

    /// Current peer count (cheap, no allocation).
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// True when no peers have ever announced. Useful for the
    /// "solo operator + cluster mode on" boot diagnostic.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// PearsBridge-backed cluster peer discovery. Wraps the announce/lookup
/// HTTP calls + the watchdog state machine.
pub struct PearsPeerDiscovery {
    bridge: Arc<PearsBridge>,
    local_pubkey: PeerPubkey,
    cluster_topic: String,
    registry: Arc<Mutex<PeerRegistry>>,
}

impl PearsPeerDiscovery {
    /// Construct a new discovery client. `cluster_id` is the operator-
    /// chosen cluster name from `freedom.yaml::cluster.id` — same value
    /// every node in the same cluster uses. `local_pubkey` is the
    /// announcer's own identity (32-byte hex string).
    pub fn new(
        bridge: Arc<PearsBridge>,
        cluster_id: impl AsRef<str>,
        local_pubkey: impl Into<String>,
    ) -> Self {
        let topic = derive_cluster_topic(cluster_id.as_ref());
        Self {
            bridge,
            local_pubkey: PeerPubkey(local_pubkey.into()),
            cluster_topic: topic,
            registry: Arc::new(Mutex::new(PeerRegistry::new())),
        }
    }

    pub fn local_pubkey(&self) -> &PeerPubkey {
        &self.local_pubkey
    }

    pub fn cluster_topic(&self) -> &str {
        &self.cluster_topic
    }

    pub fn registry(&self) -> Arc<Mutex<PeerRegistry>> {
        Arc::clone(&self.registry)
    }

    /// Announce the local node to the cluster topic. Returns the new
    /// election outcome computed against the current peer set (which
    /// may not include the local pubkey yet if no remote node has
    /// re-broadcast the announce).
    ///
    /// The announce is a single HTTP POST through PearsBridge; errors
    /// surface as anyhow::Error so the caller decides retry vs
    /// supervisor restart.
    pub async fn announce_self(&self) -> Result<Election> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = AnnouncePayload {
            pubkey: self.local_pubkey.0.clone(),
            role: "follower".to_string(),
            capabilities: Vec::new(),
            announced_unix_ts: now,
        };
        let text = serde_json::to_string(&payload)
            .context("serialise AnnouncePayload as JSON for Pears post")?;
        let body = PostMessageRequest {
            text,
            attachment_b64: None,
            attachment_mime: None,
        };
        self.bridge
            .post_message(&self.cluster_topic, &body)
            .await
            .map_err(|e| anyhow::anyhow!("pears announce post failed: {e}"))?;
        debug!(
            topic = %self.cluster_topic,
            pubkey = %self.local_pubkey.as_str(),
            "Pears cluster: announced self"
        );

        // Record the local pubkey in the registry too — the local node
        // doesn't necessarily get its own announce echo, so seed the
        // registry directly so the election sees a non-empty set.
        let mut reg = self.registry.lock().await;
        reg.record_announce(&payload);
        Ok(elect_orchestrator(&reg.peers, &self.local_pubkey))
    }

    /// Apply an inbound announce payload (received from the Pears topic
    /// subscription — wiring lands in K-3.5b / cluster-subscribe-loop).
    /// Returns the post-update election.
    pub async fn handle_inbound_announce(&self, payload: AnnouncePayload) -> Election {
        let mut reg = self.registry.lock().await;
        let was_new = reg.record_announce(&payload);
        if was_new {
            info!(
                pubkey = %payload.pubkey,
                role = %payload.role,
                "Pears cluster: peer joined"
            );
        }
        elect_orchestrator(&reg.peers, &self.local_pubkey)
    }

    /// Sweep stale peers + return the new election. Caller drives this
    /// periodically (every `STALE_PEER / 2` is a reasonable cadence) so
    /// the registry doesn't carry zombie peers that stopped announcing
    /// without a clean Left event.
    pub async fn sweep_and_elect(&self, now_unix_ts: u64) -> (Vec<PeerPubkey>, Election) {
        let mut reg = self.registry.lock().await;
        let evicted = reg.sweep_stale(now_unix_ts);
        if !evicted.is_empty() {
            info!(count = evicted.len(), "Pears cluster: evicted stale peers");
        }
        let election = elect_orchestrator(&reg.peers, &self.local_pubkey);
        (evicted, election)
    }
}

/// Restart-supervisor state. Tracks consecutive restarts +
/// rolling-window restarts so the announcer can be permanently
/// disabled per the openclaw bonjour pattern.
///
/// Lives outside the PearsPeerDiscovery struct so callers can persist /
/// reset / observe the supervisor independently of the HTTP client.
#[derive(Clone, Debug, Default)]
pub struct SupervisorState {
    pub state: AnnouncerStateMachine,
    pub consecutive_restarts: u32,
    pub restart_timestamps_unix: Vec<u64>,
}

impl SupervisorState {
    /// Record a successful announce — resets the failure counters.
    /// No-op when the state machine is already `DisabledByRecoveryCap`:
    /// the disable is sticky for the daemon lifetime (operator must
    /// edit `freedom.yaml::cluster.transport` + restart to clear),
    /// matching the openclaw bonjour "permanently disabled" semantics.
    pub fn record_success(&mut self) {
        if self.state.current.is_terminal() {
            return;
        }
        self.state.transition(AnnouncerState::Announced);
        self.consecutive_restarts = 0;
    }

    /// Record an announce failure. Returns `false` when the supervisor
    /// has hit the restart cap + permanently disabled the announcer.
    pub fn record_failure(&mut self, now_unix_ts: u64) -> bool {
        self.state.transition(AnnouncerState::Failed);
        self.consecutive_restarts += 1;
        // Trim timestamps older than the rolling window.
        let cutoff = now_unix_ts.saturating_sub(RESTART_WINDOW.as_secs());
        self.restart_timestamps_unix.retain(|t| *t >= cutoff);
        self.restart_timestamps_unix.push(now_unix_ts);

        let too_many_consecutive = self.consecutive_restarts > MAX_CONSECUTIVE_RESTARTS;
        let too_many_in_window = self.restart_timestamps_unix.len() as u32 > MAX_RESTARTS_IN_WINDOW;
        if too_many_consecutive || too_many_in_window {
            self.state.transition(AnnouncerState::DisabledByRecoveryCap);
            warn!(
                consecutive = self.consecutive_restarts,
                in_window = self.restart_timestamps_unix.len(),
                "Pears cluster announcer disabled after restart cap. Set \
                 freedom.yaml::cluster.transport = \"disabled\" + restart \
                 the daemon to clear."
            );
            return false;
        }
        true
    }
}

/// Wrapper around `AnnouncerState` with a transition log so operator
/// `neoth doctor` can dump the recent state history.
#[derive(Clone, Debug)]
pub struct AnnouncerStateMachine {
    pub current: AnnouncerState,
    pub history: Vec<AnnouncerState>,
}

impl Default for AnnouncerStateMachine {
    fn default() -> Self {
        Self {
            current: AnnouncerState::Idle,
            history: Vec::new(),
        }
    }
}

impl AnnouncerStateMachine {
    pub fn transition(&mut self, next: AnnouncerState) {
        if self.current != next {
            self.history.push(self.current);
            self.current = next;
        }
    }
}

/// Operator-facing topic derivation. Stable across daemon restarts +
/// cross-platform. Uses sha256 hex prefix so the topic length is
/// predictable + readable in operator logs.
pub fn derive_cluster_topic(cluster_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"neoth.cluster.");
    h.update(cluster_id.as_bytes());
    let bytes = h.finalize();
    // 32-byte sha256 → 64 hex chars. Truncate to 32 hex chars so
    // the topic stays a manageable string in operator logs while
    // keeping >> than birthday-collision-safe entropy.
    let mut s = String::with_capacity(32);
    for b in bytes.iter().take(16) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(pk: &str, ts: u64) -> AnnouncePayload {
        AnnouncePayload {
            pubkey: pk.into(),
            role: "follower".into(),
            capabilities: vec![],
            announced_unix_ts: ts,
        }
    }

    // ── PeerRegistry ─────────────────────────────────────────────────

    #[test]
    fn record_announce_returns_true_for_new_pubkey() {
        let mut reg = PeerRegistry::new();
        let new = reg.record_announce(&payload("alex", 100));
        assert!(new);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn record_announce_returns_false_on_duplicate_pubkey() {
        let mut reg = PeerRegistry::new();
        reg.record_announce(&payload("alex", 100));
        let dup = reg.record_announce(&payload("alex", 200));
        assert!(!dup);
        assert_eq!(reg.len(), 1);
        // Last-seen should bump to the newer timestamp.
        assert_eq!(reg.last_seen.get(&PeerPubkey("alex".into())), Some(&200));
    }

    #[test]
    fn sweep_stale_evicts_only_peers_past_stale_threshold() {
        let mut reg = PeerRegistry::new();
        reg.record_announce(&payload("fresh", 1000));
        reg.record_announce(&payload("stale", 900)); // 100s before now
        let now = 1000 + STALE_PEER.as_secs() + 1;
        let evicted = reg.sweep_stale(now);
        assert_eq!(evicted.len(), 2); // both fresh + stale are past now-STALE
        // Re-check with a smaller delta.
        let mut reg2 = PeerRegistry::new();
        reg2.record_announce(&payload("fresh", 1000));
        reg2.record_announce(&payload("stale", 100));
        let now2 = 1000 + 1; // fresh is current, stale is way past
        let evicted2 = reg2.sweep_stale(now2);
        assert_eq!(evicted2.len(), 1);
        assert_eq!(evicted2[0].as_str(), "stale");
        assert!(reg2.peers.contains(&PeerPubkey("fresh".into())));
    }

    #[test]
    fn sweep_stale_returns_empty_when_no_peers_expired() {
        let mut reg = PeerRegistry::new();
        reg.record_announce(&payload("alex", 1000));
        let evicted = reg.sweep_stale(1001);
        assert!(evicted.is_empty());
        assert_eq!(reg.len(), 1);
    }

    // ── derive_cluster_topic ────────────────────────────────────────

    #[test]
    fn derive_topic_is_deterministic_across_calls() {
        let a = derive_cluster_topic("my-cluster");
        let b = derive_cluster_topic("my-cluster");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_topic_differs_per_cluster_id() {
        let a = derive_cluster_topic("alpha");
        let b = derive_cluster_topic("bravo");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_topic_is_32_hex_chars() {
        let t = derive_cluster_topic("my-cluster");
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── AnnouncerStateMachine ───────────────────────────────────────

    #[test]
    fn state_machine_records_history_on_transition() {
        let mut m = AnnouncerStateMachine::default();
        assert_eq!(m.current, AnnouncerState::Idle);
        m.transition(AnnouncerState::Announcing);
        m.transition(AnnouncerState::Announced);
        assert_eq!(m.current, AnnouncerState::Announced);
        assert_eq!(
            m.history,
            vec![AnnouncerState::Idle, AnnouncerState::Announcing]
        );
    }

    #[test]
    fn state_machine_skips_self_transitions() {
        let mut m = AnnouncerStateMachine::default();
        m.transition(AnnouncerState::Idle); // no-op
        m.transition(AnnouncerState::Idle); // no-op
        assert!(m.history.is_empty());
    }

    #[test]
    fn state_is_healthy_only_for_announced() {
        assert!(!AnnouncerState::Idle.is_healthy());
        assert!(!AnnouncerState::Announcing.is_healthy());
        assert!(AnnouncerState::Announced.is_healthy());
        assert!(!AnnouncerState::Failed.is_healthy());
        assert!(!AnnouncerState::DisabledByRecoveryCap.is_healthy());
    }

    #[test]
    fn state_is_terminal_only_for_disabled_by_recovery_cap() {
        assert!(!AnnouncerState::Idle.is_terminal());
        assert!(!AnnouncerState::Failed.is_terminal());
        assert!(AnnouncerState::DisabledByRecoveryCap.is_terminal());
    }

    // ── SupervisorState — openclaw bonjour restart-cap pattern ───────

    #[test]
    fn supervisor_success_resets_consecutive_failure_counter() {
        let mut sup = SupervisorState::default();
        sup.record_failure(1000);
        sup.record_failure(1001);
        assert_eq!(sup.consecutive_restarts, 2);
        sup.record_success();
        assert_eq!(sup.consecutive_restarts, 0);
        assert_eq!(sup.state.current, AnnouncerState::Announced);
    }

    #[test]
    fn supervisor_three_consecutive_failures_keep_announcer_active() {
        // Adopting openclaw's MAX_CONSECUTIVE_RESTARTS = 3 — the
        // 3rd failure is still under the cap (the comparison is
        // strict > 3).
        let mut sup = SupervisorState::default();
        for ts in 1000..1003 {
            let still_active = sup.record_failure(ts);
            assert!(still_active, "failure {ts} must keep announcer active");
        }
        assert_eq!(sup.consecutive_restarts, 3);
        assert!(!sup.state.current.is_terminal());
    }

    #[test]
    fn supervisor_four_consecutive_failures_disables_announcer_permanently() {
        let mut sup = SupervisorState::default();
        for ts in 1000..1003 {
            let _ = sup.record_failure(ts);
        }
        // The 4th failure hits > MAX_CONSECUTIVE_RESTARTS (3).
        let still_active = sup.record_failure(1003);
        assert!(!still_active, "4th consecutive failure must trip the cap");
        assert_eq!(sup.state.current, AnnouncerState::DisabledByRecoveryCap);
        assert!(sup.state.current.is_terminal());
    }

    #[test]
    fn supervisor_window_cap_trips_even_when_consecutive_resets() {
        // openclaw bonjour comment: "A flapping advertiser can briefly
        // reach 'announced' between probing failures, which resets the
        // consecutive counter. Bound total restarts too."
        //
        // Adopt the same safety net — fail/success/fail/success...
        // pattern should still trip the window cap after
        // MAX_RESTARTS_IN_WINDOW.
        let mut sup = SupervisorState::default();
        let mut active = true;
        for ts in 1000..1006 {
            active = sup.record_failure(ts);
            sup.record_success(); // simulate a flap that briefly recovers
        }
        // After 6 failures inside the 30-min window, the cap trips
        // even though consecutive_restarts kept resetting.
        assert!(!active);
        assert_eq!(sup.state.current, AnnouncerState::DisabledByRecoveryCap);
    }

    #[test]
    fn supervisor_old_timestamps_outside_window_dont_count() {
        let mut sup = SupervisorState::default();
        // Old failures from "yesterday" (3 hours ago) shouldn't
        // contribute to the window cap.
        let old = 1000;
        let now_far_future = old + RESTART_WINDOW.as_secs() * 2;
        for ts in old..old + 5 {
            let _ = sup.record_failure(ts);
            sup.record_success();
        }
        // Reset state by recording a success, then fail far in the future.
        let active = sup.record_failure(now_far_future);
        assert!(
            active,
            "old timestamps outside RESTART_WINDOW shouldn't count toward window cap"
        );
    }

    // ── AnnouncePayload serde ─────────────────────────────────────────

    #[test]
    fn announce_payload_round_trips_through_json() {
        let p = AnnouncePayload {
            pubkey: "abc123".into(),
            role: "leader".into(),
            capabilities: vec!["embeddings".into(), "vision".into()],
            announced_unix_ts: 1_700_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: AnnouncePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn announce_payload_missing_optional_fields_defaults_cleanly() {
        // role + capabilities are #[serde(default)] — older daemons
        // may emit a leaner payload + newer ones must accept it.
        let json = r#"{"pubkey":"xyz","announced_unix_ts":12345}"#;
        let p: AnnouncePayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.pubkey, "xyz");
        assert!(p.role.is_empty());
        assert!(p.capabilities.is_empty());
    }

    // ── PearsPeerDiscovery integration ───────────────────────────────

    #[tokio::test]
    async fn discovery_seeds_topic_from_cluster_id() {
        let bridge = Arc::new(PearsBridge::local().unwrap());
        let disc = PearsPeerDiscovery::new(bridge, "my-cluster", "abc123");
        assert_eq!(disc.cluster_topic().len(), 32);
        assert_eq!(disc.local_pubkey().as_str(), "abc123");
    }

    #[tokio::test]
    async fn handle_inbound_announce_records_peer_and_returns_election() {
        let bridge = Arc::new(PearsBridge::local().unwrap());
        let disc = PearsPeerDiscovery::new(bridge, "my-cluster", "alex");
        let e = disc.handle_inbound_announce(payload("bob", 100)).await;
        assert_eq!(e.peer_count, 1);
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("bob"));
        // alex isn't in the registry yet (no announce_self call), so
        // local_is_orchestrator stays false.
        assert!(!e.local_is_orchestrator);
    }

    #[tokio::test]
    async fn sweep_and_elect_evicts_then_returns_new_election() {
        let bridge = Arc::new(PearsBridge::local().unwrap());
        let disc = PearsPeerDiscovery::new(bridge, "my-cluster", "alex");
        let _ = disc.handle_inbound_announce(payload("alex", 100)).await;
        let _ = disc.handle_inbound_announce(payload("bob", 100)).await;
        let _ = disc.handle_inbound_announce(payload("carol", 5_000)).await;

        let now = 5_001;
        let (evicted, e) = disc.sweep_and_elect(now).await;
        // alex + bob were at ts=100; now - STALE_PEER (60s) = 4941. Both stale.
        assert_eq!(evicted.len(), 2);
        assert_eq!(e.peer_count, 1);
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("carol"));
    }

    #[tokio::test]
    async fn announce_self_fails_cleanly_against_offline_bridge() {
        // The bridge points at an unbound port; announce MUST surface
        // an error rather than panic. Supervisor caller decides retry.
        let bridge = Arc::new(PearsBridge::new("http://127.0.0.1:65430").unwrap());
        let disc = PearsPeerDiscovery::new(bridge, "my-cluster", "alex");
        let result = disc.announce_self().await;
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("pears announce post failed"), "msg: {msg}");
    }
}
